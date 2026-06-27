//! AWS CloudTrail S3 ingester — bounded-window, allowlist-driven, partition-ready.
//!
//! Anything older/wider than the window stays in Athena (the partition-projected
//! deep-search hatch — see `backend/athena/cloudtrail_partition_projected.sql`).

use std::collections::HashMap;

use anyhow::Context;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::Client;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use diesel::prelude::*;
use flate2::read::GzDecoder;
use futures::stream::{self, StreamExt};
use log::{error, info, warn};
use serde_json::Value;
use std::io::Read;
use tokio_util::sync::CancellationToken;

use crate::db::model::CloudtrailEventInsert;
use crate::db::DbPool;
use crate::misc::config::CloudtrailConfig;
use crate::service::ingest::{
    advance_watermark, get_watermark, record_run_error, SOURCE_CLOUDTRAIL,
};

/// Consecutive failed sweeps before the loop escalates from a per-sweep `error!`
/// to a single louder `warn!` — the backend counterpart to the console's red
/// "stalled" indicator, so the two can't disagree silently (≈3× the poll
/// interval at the 300s default).
const STALL_WARN_AFTER_SWEEPS: u32 = 3;

/// Wall-clock cadence for the mid-sweep watermark heartbeat + progress log. A long
/// backfill can spend many minutes inside a single account (or even a single
/// day-prefix), so progress is checkpointed on elapsed time rather than per
/// account/day — the console badge then tracks the sweep in near real time and a
/// restart resumes within ~this window of the last processed object.
const HEARTBEAT_SECS: u64 = 15;

/// When a budget-bounded sweep still has backlog (it hit `max_objects_per_run`),
/// re-sweep after this short delay instead of idling the full poll interval — so a
/// backfill catches up continuously and the console shows steady progress, then
/// settles back to the poll interval once drained.
const BACKFILL_RESWEEP: std::time::Duration = std::time::Duration::from_secs(5);

/// Reserved key inside the per-prefix cursor map holding the account prefix the
/// next sweep should *start* at — the rotating account cursor. The global object
/// budget is consumed in account order, so without this a single high-volume
/// account at the front would eat the whole budget every sweep and starve the
/// rest; rotation walks the budget window across all accounts. Prefixed `__` so
/// it can never collide with a real `<region>/YYYY/MM/DD/` day-prefix, and
/// excluded from the `last_object_key` max (see `max_object_key`).
const RESUME_ACCOUNT_KEY: &str = "__resume_account__";

/// Divisor that derives a default per-account cap from the global budget when
/// `max_objects_per_account` is left at 0 — i.e. spread each sweep's budget across
/// at least this many accounts so no single one monopolises it.
const DEFAULT_ACCOUNT_FANOUT: i64 = 8;

/// `ingest_watermarks.source` key for the web-identity chain-resolution pass's
/// incremental `created_at` watermark. A dedicated row (not the `cloudtrail` ingest
/// row) so it can't perturb the sweep's cursor map; invisible to the console SOURCES
/// list (that's derived from the `ssumgmt_events` view, not watermark rows), like the
/// `siem`/`guardduty` loop-health rows already parked there. See `resolve_webidentity_chains`.
const WEBID_WATERMARK_SOURCE: &str = "cloudtrail_webid";

/// Lag (minutes) subtracted from the `max(created_at)` snapshot when advancing the
/// web-identity watermark, so a row whose default `now()` `created_at` predates its
/// (later-committing) transaction isn't skipped — the next pass re-scans this small overlap.
const WEBID_WATERMARK_LAG_MINS: i64 = 5;

/// Built-in SIEM-relevant `eventName` allowlist used when
/// `SSU__CLOUDTRAIL__EVENT_ALLOWLIST` is empty.
pub fn default_allowlist() -> Vec<String> {
    [
        "ConsoleLogin",
        "AssumeRole",
        "AssumeRoleWithSAML",
        "AssumeRoleWithWebIdentity",
        "GetSessionToken",
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateAccessKey",
        "CreateUser",
        "DeleteUser",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "AddUserToGroup",
        "CreateRole",
        "DeleteRole",
        "PutBucketPolicy",
        "PutBucketAcl",
        "DeleteBucketPolicy",
        "CreatePolicy",
        "CreatePolicyVersion",
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice",
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Entry point: an initial sweep, then poll on the configured interval until the
/// cancellation token fires. Spawned onto the shared `async_worker` runtime.
pub async fn run(cancel: CancellationToken, conf: CloudtrailConfig, pool: DbPool) {
    if conf.bucket.is_empty() || conf.prefix.is_empty() {
        error!("cloudtrail ingest enabled but bucket/prefix unset — not starting");
        return;
    }

    let shared = {
        let base = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(conf.region.clone()));
        if conf.assume_role_arn.is_empty() {
            base.load().await
        } else {
            // Cross-account hop: the pod's role assumes a role in the bucket's
            // account before reading. AssumeRoleProvider (not a one-shot STS call)
            // so the long-running loop's ~1h creds auto-refresh.
            let provider =
                aws_config::sts::AssumeRoleProvider::builder(conf.assume_role_arn.clone())
                    .session_name(conf.assume_role_session_name.clone())
                    .region(Region::new(conf.region.clone()))
                    .build()
                    .await;
            base.credentials_provider(provider).load().await
        }
    };
    let client = Client::new(&shared);

    let allowlist: Vec<String> = {
        let configured: Vec<String> = conf
            .event_allowlist
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if configured.is_empty() {
            default_allowlist()
        } else {
            configured
        }
    };

    let interval = std::time::Duration::from_secs(conf.poll_interval_secs.max(30));
    info!(
        "cloudtrail ingest starting :: bucket={} prefix={} window_days={} allowlist={} interval={}s assume_role={}",
        conf.bucket, conf.prefix, conf.window_days, allowlist.len(), interval.as_secs(),
        if conf.assume_role_arn.is_empty() { "none" } else { conf.assume_role_arn.as_str() }
    );

    // Wall-clock throttle for the web-identity chain resolution (see below). Seed
    // it so the first sweep still runs the pass once on startup.
    let resolve_interval = std::time::Duration::from_secs(conf.webidentity_resolve_interval_secs);
    let mut last_resolve: Option<std::time::Instant> = None;

    let mut consecutive_failures: u32 = 0;
    loop {
        // Heartbeat at sweep *start* (not just on completion/error) so an
        // alive-but-idle — or a hung — loop is still visible in logs. The absence
        // of this line is the tell that the loop isn't running at all (ingest
        // disabled, or you're reading an API-only replica's logs), which is the
        // usual cause of a "stalled" console badge with no matching backend log.
        info!(
            "cloudtrail sweep starting :: bucket={} window_days={}",
            conf.bucket, conf.window_days
        );
        let mut more_backlog = false;
        match run_once(&cancel, &client, &conf, &allowlist, &pool).await {
            Ok(budget_hit) => {
                consecutive_failures = 0;
                more_backlog = budget_hit;
            }
            Err(e) => {
                consecutive_failures += 1;
                error!(
                    "cloudtrail sweep failed (consecutive={}): {:#}",
                    consecutive_failures, e
                );
                if consecutive_failures == STALL_WARN_AFTER_SWEEPS {
                    warn!(
                        "cloudtrail ingest stalled: {} consecutive failed sweeps — console shows 'stalled'; last error: {:#}",
                        consecutive_failures, e
                    );
                }
                let pool = pool.clone();
                let msg = format!("{:#}", e);
                let _ = tokio::task::spawn_blocking(move || {
                    let mut conn = pool.get().context("pool get")?;
                    record_run_error(&mut conn, SOURCE_CLOUDTRAIL, &msg).context("record error")
                })
                .await;
            }
        }

        // Resolve web-identity role chains: upgrade opaque IRSA-session actors to the
        // originating service-account / subject recorded on their mint events.
        // Idempotent, off the hot path; non-fatal on error.
        //
        // Throttled on wall-clock (`webidentity_resolve_interval_secs`), not run after
        // every sweep: the pass scans the whole window twice over unindexable `raw #>>`
        // extractions (~tens of seconds), so firing it each ~90s during a continuous
        // backfill nearly doubles cycle time for no benefit (the subjects aren't
        // time-critical mid-backfill). The throttle is independent of sweep cadence and
        // backlog; `0` disables it (run every sweep, the legacy behaviour).
        let due = match last_resolve {
            None => true, // first sweep — resolve once on startup
            Some(t) => t.elapsed() >= resolve_interval,
        };
        if due {
            last_resolve = Some(std::time::Instant::now());
            let pool = pool.clone();
            let window = conf.window_days;
            match tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
                let mut conn = pool.get().context("pool get")?;
                resolve_webidentity_chains(&mut conn, window)
            })
            .await
            {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => info!(
                    "cloudtrail: resolved {} web-identity chain actor(s) to subject",
                    n
                ),
                Ok(Err(e)) => warn!(
                    "cloudtrail web-identity chain resolution failed (non-fatal): {:#}",
                    e
                ),
                Err(e) => warn!(
                    "cloudtrail web-identity chain resolution join error: {:#}",
                    e
                ),
            }
        }

        // A budget-bounded sweep that still has backlog re-sweeps promptly rather
        // than idling the full poll interval, so catch-up is continuous; once
        // drained (no budget hit) it settles back to `interval`.
        let next = if more_backlog {
            BACKFILL_RESWEEP
        } else {
            interval
        };
        tokio::select! {
            _ = cancel.cancelled() => { info!("stopping cloudtrail ingest"); break; }
            _ = tokio::time::sleep(next) => {}
        }
    }
}

/// One full sweep over the trailing window. Newest day first so the freshest
/// data ingests first; the per-sweep object budget then bounds how far back a
/// single sweep reaches, with subsequent sweeps continuing via the cursors.
#[tracing::instrument(name = "cloudtrail.sweep", skip_all, fields(bucket = %conf.bucket, window_days = conf.window_days))]
async fn run_once(
    cancel: &CancellationToken,
    client: &Client,
    conf: &CloudtrailConfig,
    allowlist: &[String],
    pool: &DbPool,
) -> anyhow::Result<bool> {
    let started = std::time::Instant::now();
    let now = Utc::now();
    let floor = now - Duration::days(conf.window_days.max(1));

    // Load + parse the per-prefix cursor map from the watermark.
    let mut cursors = load_cursors(pool).await?;

    let base = conf.prefix.trim_end_matches('/').to_string();
    let mut accounts = list_common_prefixes(client, &conf.bucket, &format!("{}/", base)).await?;
    // Stable order so the rotating account cursor resolves deterministically
    // across sweeps even if S3 returns prefixes in a different order.
    accounts.sort();

    let budget = conf.max_objects_per_run;
    // Per-account fairness cap (see `RESUME_ACCOUNT_KEY`): bound a single account's
    // share of one sweep so a high-volume account can't consume the whole global
    // budget. 0 → derive from the global budget; no global budget → unbounded.
    let per_account_cap: i64 = if conf.max_objects_per_account > 0 {
        conf.max_objects_per_account
    } else if budget > 0 {
        (budget / DEFAULT_ACCOUNT_FANOUT).max(1)
    } else {
        0
    };

    // Resume the rotation at the account where the previous budget-bounded sweep
    // stopped (wrapping around), so the budget walks across all accounts instead of
    // restarting at account 0 every sweep and starving everything after the first.
    let n = accounts.len();
    let start_idx = cursors
        .get(RESUME_ACCOUNT_KEY)
        .and_then(|a| accounts.iter().position(|x| x == a))
        .unwrap_or(0);

    info!(
        "cloudtrail sweep :: discovered {} account prefixes under {} (window_days={}, budget={}, per_account_cap={}, start_idx={})",
        n, base, conf.window_days.max(1),
        if budget > 0 { budget.to_string() } else { "unbounded".to_string() },
        if per_account_cap > 0 { per_account_cap.to_string() } else { "unbounded".to_string() },
        start_idx,
    );

    let mut objects_total: i64 = 0;
    let mut events_total: i64 = 0;
    let mut sweep_max_event_at: Option<DateTime<Utc>> = None;
    let mut budget_hit = false;
    let mut resume_account: Option<String> = None;
    let mut last_beat = started;

    'sweep: for step in 0..n {
        // Shutdown check between accounts: a sweep walks hundreds of account
        // prefixes (tens of thousands of S3 round-trips), so without this the
        // process can't exit until the whole sweep finishes. Committed cursors are
        // already durable, so stopping here just resumes mid-sweep next time.
        if cancel.is_cancelled() {
            info!(
                "cloudtrail sweep interrupted by shutdown after {} account(s)",
                step
            );
            break 'sweep;
        }
        let account_idx = (start_idx + step) % n;
        let account_prefix = &accounts[account_idx];
        let region_root = format!("{}CloudTrail/", account_prefix);
        let regions = list_common_prefixes(client, &conf.bucket, &region_root).await?;
        // Objects this account has consumed this sweep — capped by `per_account_cap`.
        let mut account_objects: i64 = 0;
        // New rows this account applied this sweep. Paired with `account_objects`
        // it exposes the per-account scanned-vs-inserted ratio in the heartbeat —
        // a low applied/objects ratio at a fixed account prefix across sweeps is
        // the signature of duplicate-grinding (re-fetching already-ingested
        // objects), as opposed to genuinely new data (~1 applied per object).
        let mut account_applied: i64 = 0;

        // Enumerate this account's `<region>/YYYY/MM/DD/` day-prefixes, then LIST
        // them all *concurrently*. Once fetching is caught up the dominant cost is
        // serial LIST latency over hundreds of mostly-empty prefixes (a full sweep
        // is tens of thousands of round-trips), so listing in parallel is the big
        // win; the actual fetch/commit below stays sequential per prefix to keep
        // the budget/cap/cursor accounting deterministic. Newest day first so the
        // freshest data ingests first and a budget break drops the oldest backlog.
        let day_prefixes: Vec<String> = regions
            .iter()
            .flat_map(|region_prefix| {
                (0..conf.window_days.max(1)).map(move |day| {
                    let date = now.date_naive() - Duration::days(day);
                    format!("{}{}/", region_prefix, date.format("%Y/%m/%d"))
                })
            })
            .collect();

        let mut listed: Vec<(String, Vec<String>)> = stream::iter(day_prefixes)
            .map(|day_prefix| {
                let client = client.clone();
                let bucket = conf.bucket.clone();
                let start_after = cursors.get(&day_prefix).cloned();
                async move {
                    match list_objects(&client, &bucket, &day_prefix, start_after.as_deref()).await
                    {
                        Ok(keys) => (day_prefix, keys),
                        Err(e) => {
                            // A transient LIST failure skips this prefix for the
                            // sweep (its cursor isn't advanced, so it's retried next
                            // sweep) rather than failing the whole pass. A systemic
                            // failure (bad creds/region) trips the region LIST above
                            // first, which propagates and records the run error.
                            warn!(
                                "cloudtrail list {} failed (skipped this sweep): {:#}",
                                day_prefix, e
                            );
                            (day_prefix, Vec::new())
                        }
                    }
                }
            })
            .buffer_unordered(conf.workers.max(1))
            .collect()
            .await;

        // Drop empties and order newest day-prefix first (lexical desc == time desc).
        listed.retain(|(_, keys)| !keys.is_empty());
        listed.sort_by(|a, b| b.0.cmp(&a.0));

        'account: for (day_prefix, mut keys) in listed {
            // A single high-volume account can hold many non-empty day-prefixes;
            // check between each so shutdown is bounded to one prefix fetch+commit.
            if cancel.is_cancelled() {
                break 'sweep;
            }
            keys.sort();

            // Global per-sweep object budget — the hard ceiling. On exhaustion,
            // remember this account so the next sweep resumes here (its backlog
            // isn't drained), then stop.
            if budget > 0 {
                let remaining = (budget - objects_total).max(0) as usize;
                if remaining == 0 {
                    info!("cloudtrail sweep hit max_objects_per_run={} — stopping early (more backlog pending)", budget);
                    budget_hit = true;
                    resume_account = Some(account_prefix.clone());
                    break 'sweep;
                }
                keys.truncate(remaining);
            }

            // Per-account fairness cap — once this account has had its slice,
            // move on to the next account so the remaining budget is shared.
            if per_account_cap > 0 {
                let remaining_acct = (per_account_cap - account_objects).max(0) as usize;
                if remaining_acct == 0 {
                    break 'account;
                }
                if keys.len() > remaining_acct {
                    keys.truncate(remaining_acct);
                }
            }

            // Process the prefix in object-batches of `batch_size` keys rather than
            // fetching+committing the whole prefix at once. A single high-volume
            // account/day-prefix can hold tens of thousands of objects → millions of
            // events; committing those in one transaction spikes memory, opens a
            // multi-minute txn, and — because the cursor + heartbeat only persist
            // *after* the commit — hides progress from the console (the watermark
            // stops ticking, the badge reads "stalled") and re-fetches the whole
            // prefix from scratch on a mid-prefix restart. Batching bounds all three:
            // short txns, a cursor advanced every `batch_size` objects (so a restart
            // resumes mid-prefix), and a heartbeat that keeps ticking inside a fat
            // prefix. Concurrency is unchanged — `fetch_prefix` still fans the batch's
            // GETs out across `workers`. `keys` is already budget/cap-truncated above,
            // so chunking preserves the per-sweep accounting exactly.
            let batch = conf.batch_size.max(1);
            for chunk in keys.chunks(batch) {
                // Shutdown is now bounded to one batch fetch+commit, not a whole
                // fat prefix; committed cursors are durable so we resume here next time.
                if cancel.is_cancelled() {
                    break 'sweep;
                }

                let (events, cursor, max_event_at, scanned) =
                    fetch_prefix(client, &conf.bucket, chunk, conf, allowlist, floor).await;

                objects_total += scanned as i64;
                account_objects += scanned as i64;
                if let Some(m) = max_event_at {
                    sweep_max_event_at = Some(sweep_max_event_at.map_or(m, |x| x.max(m)));
                }

                // Nothing fetched — the chunk's first key failed. Can't advance the
                // cursor past it, so stop the prefix; next sweep retries from the
                // unchanged cursor.
                if cursor.is_none() {
                    break;
                }

                let applied = commit_prefix(pool, &day_prefix, events, cursor.clone()).await?;
                events_total += applied;
                account_applied += applied;
                if let Some(c) = cursor {
                    cursors.insert(day_prefix.clone(), c);
                }

                // Wall-clock checkpoint: persist the cursor map + bump `last_run_at`
                // (clearing any stale error) every HEARTBEAT_SECS, regardless of how
                // the work falls across accounts/days/batches. Keying on elapsed time
                // — not on account/day boundaries — means the console tracks a long
                // backfill continuously and fires even before a budget break (which
                // exits via `break 'sweep` and would otherwise skip a per-account
                // checkpoint). Counters stay zero here; the cumulative totals are
                // applied once in `finalize_sweep` to avoid double-counting.
                if last_beat.elapsed().as_secs() >= HEARTBEAT_SECS {
                    if let Err(e) = heartbeat(pool, &cursors, sweep_max_event_at).await {
                        warn!("cloudtrail watermark heartbeat failed (non-fatal): {:#}", e);
                    }
                    info!(
                        "cloudtrail sweep progress :: account {} (idx {}, order {}/{}) :: this-account objects={} applied={} :: cumulative objects={} events={} elapsed={}s",
                        account_prefix.trim_end_matches('/'), account_idx, step + 1, n,
                        account_objects, account_applied,
                        objects_total, events_total, started.elapsed().as_secs(),
                    );
                    last_beat = std::time::Instant::now();
                }

                // A partial fetch (an object failed mid-chunk) halted at the last good
                // key; don't advance to the next chunk or we'd skip the failed key.
                // The cursor is parked at the last good key → next sweep resumes there.
                if scanned < chunk.len() {
                    break;
                }
            }
        }
    }

    // Prune cursors for day-prefixes now outside the window. Then record the
    // rotating account cursor: on a budget break, resume at the stopped account
    // next sweep; on a full clean pass, clear it so the next sweep starts fresh at
    // account 0. Persist the sweep totals + cursor map + newest event time.
    prune_cursors(&mut cursors, floor);
    match &resume_account {
        Some(acct) => {
            cursors.insert(RESUME_ACCOUNT_KEY.to_string(), acct.clone());
        }
        None => {
            cursors.remove(RESUME_ACCOUNT_KEY);
        }
    }
    finalize_sweep(
        pool,
        &cursors,
        objects_total,
        events_total,
        sweep_max_event_at,
    )
    .await?;

    info!(
        "cloudtrail sweep complete :: objects={} events_applied={} accounts={} elapsed={}s{}",
        objects_total,
        events_total,
        n,
        started.elapsed().as_secs(),
        if budget_hit {
            " (budget hit — more backlog pending, re-sweeping soon)"
        } else {
            ""
        }
    );
    Ok(budget_hit)
}

/// List the immediate `CommonPrefixes` under `prefix` (delimiter `/`) — used to
/// discover accounts then regions without enumerating their contents.
async fn list_common_prefixes(
    client: &Client,
    bucket: &str,
    prefix: &str,
) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut req = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix)
            .delimiter("/");
        if let Some(t) = &token {
            req = req.continuation_token(t);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("list common prefixes {}", prefix))?;
        for cp in resp.common_prefixes() {
            if let Some(p) = cp.prefix() {
                out.push(p.to_string());
            }
        }
        if resp.is_truncated().unwrap_or(false) {
            token = resp.next_continuation_token().map(|s| s.to_string());
            if token.is_none() {
                break;
            }
        } else {
            break;
        }
    }
    Ok(out)
}

/// List object keys under a day-prefix, after `start_after` (the persisted
/// per-prefix cursor). Skips directory markers.
async fn list_objects(
    client: &Client,
    bucket: &str,
    prefix: &str,
    start_after: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut req = client.list_objects_v2().bucket(bucket).prefix(prefix);
        if token.is_none() {
            if let Some(sa) = start_after {
                req = req.start_after(sa);
            }
        }
        if let Some(t) = &token {
            req = req.continuation_token(t);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("list objects {}", prefix))?;
        for obj in resp.contents() {
            if let Some(k) = obj.key() {
                if k.ends_with('/') {
                    continue;
                }
                // Defensive: start_after already excludes <= cursor on page 1.
                if let Some(sa) = start_after {
                    if k <= sa {
                        continue;
                    }
                }
                out.push(k.to_string());
            }
        }
        if resp.is_truncated().unwrap_or(false) {
            token = resp.next_continuation_token().map(|s| s.to_string());
            if token.is_none() {
                break;
            }
        } else {
            break;
        }
    }
    Ok(out)
}

/// Download + decode + map every object for one day-prefix concurrently, then
/// derive the resume cursor as the lexical max of the *contiguous successfully
/// processed* prefix — we never advance past an object that failed to fetch, so
/// it is retried next sweep (the inserts that did succeed are dedup-safe).
// No per-prefix span: this is called once per day-prefix per account (~1759 per
// sweep), which floods the `cloudtrail.sweep` trace and is expensive to export
// for no readable benefit. The aggregate lives on `cloudtrail.sweep`; per-prefix
// hot-path profiling is better served by the pprof endpoint (see CLAUDE.md).
async fn fetch_prefix(
    client: &Client,
    bucket: &str,
    keys: &[String],
    conf: &CloudtrailConfig,
    allowlist: &[String],
    floor: DateTime<Utc>,
) -> (
    Vec<CloudtrailEventInsert>,
    Option<String>,
    Option<DateTime<Utc>>,
    usize,
) {
    let results: Vec<(String, anyhow::Result<Vec<CloudtrailEventInsert>>)> =
        stream::iter(keys.to_vec())
            .map(|key| {
                let client = client.clone();
                let bucket = bucket.to_string();
                let allow = allowlist.to_vec();
                let mgmt_only = conf.management_events_only;
                async move {
                    let r = fetch_object(&client, &bucket, &key, allow, mgmt_only, floor).await;
                    (key, r)
                }
            })
            .buffer_unordered(conf.workers.max(1))
            .collect()
            .await;

    // Reassemble in lexical (== time) order; stop the cursor at the first failure.
    let mut by_key: HashMap<String, anyhow::Result<Vec<CloudtrailEventInsert>>> =
        results.into_iter().collect();
    let mut events = Vec::new();
    let mut cursor: Option<String> = None;
    let mut max_event_at: Option<DateTime<Utc>> = None;
    let mut scanned = 0usize;

    for key in keys {
        match by_key.remove(key) {
            Some(Ok(mut evs)) => {
                scanned += 1;
                for e in &evs {
                    max_event_at = Some(max_event_at.map_or(e.event_time, |x| x.max(e.event_time)));
                }
                events.append(&mut evs);
                cursor = Some(key.clone());
            }
            Some(Err(e)) => {
                warn!(
                    "cloudtrail object {} failed, halting prefix at last good key: {:#}",
                    key, e
                );
                break;
            }
            None => break,
        }
    }
    (events, cursor, max_event_at, scanned)
}

/// Download one gzipped CloudTrail object (`{"Records":[...]}`) and map the
/// allowlisted management events to insert rows. The S3 GET is async; the
/// gz-decode + JSON-parse + record mapping (the CPU-bound half) is handed to
/// `spawn_blocking` so that up to `workers` objects decoding at once don't starve
/// the async executor threads. An undecodable object is logged and skipped
/// (returns empty) rather than failing the sweep.
async fn fetch_object(
    client: &Client,
    bucket: &str,
    key: &str,
    allowlist: Vec<String>,
    management_only: bool,
    floor: DateTime<Utc>,
) -> anyhow::Result<Vec<CloudtrailEventInsert>> {
    let obj = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .with_context(|| format!("get object {}", key))?;
    let bytes = obj
        .body
        .collect()
        .await
        .with_context(|| format!("read body {}", key))?
        .into_bytes()
        .to_vec();

    let key_owned = key.to_string();
    tokio::task::spawn_blocking(move || {
        decode_and_map(bytes, &key_owned, &allowlist, management_only, floor)
    })
    .await
    .with_context(|| format!("decode task join {}", key))?
}

/// CPU-bound half of `fetch_object`: gunzip → JSON-parse → allowlist/management
/// filter → map to insert rows. Synchronous by design — invoked under
/// `spawn_blocking` so the decode/parse never runs on an async runtime thread.
fn decode_and_map(
    bytes: Vec<u8>,
    key: &str,
    allowlist: &[String],
    management_only: bool,
    floor: DateTime<Utc>,
) -> anyhow::Result<Vec<CloudtrailEventInsert>> {
    let mut decoder = GzDecoder::new(&bytes[..]);
    let mut text = String::new();
    if let Err(e) = decoder.read_to_string(&mut text) {
        warn!("skipping undecodable cloudtrail object {}: {}", key, e);
        return Ok(Vec::new());
    }

    let doc: Value = serde_json::from_str(&text).with_context(|| format!("parse json {}", key))?;
    let records = match doc.get("Records").and_then(|r| r.as_array()) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let now = Utc::now();
    let mut out = Vec::new();
    for rec in records {
        let event_name = rec.get("eventName").and_then(Value::as_str).unwrap_or("");
        if !allowlist.iter().any(|a| a == event_name) {
            continue;
        }
        let category = rec.get("eventCategory").and_then(Value::as_str);
        let is_management = category.map(|c| c == "Management").unwrap_or_else(|| {
            rec.get("managementEvent")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        });
        if management_only && !is_management {
            continue;
        }
        let event_time = match rec
            .get("eventTime")
            .and_then(Value::as_str)
            .and_then(parse_event_time)
        {
            Some(t) => t,
            None => continue,
        };
        if event_time < floor {
            continue;
        }
        let event_id = match rec.get("eventID").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => continue,
        };

        let identity = derive_identity(rec);
        out.push(CloudtrailEventInsert {
            event_id,
            event_time,
            event_name: event_name.to_string(),
            event_source: rec
                .get("eventSource")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            aws_region: str_field(rec, "awsRegion"),
            recipient_account_id: str_field(rec, "recipientAccountId"),
            user_identity_account_id: rec
                .get("userIdentity")
                .and_then(|u| u.get("accountId"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            principal_arn: identity.principal_arn,
            principal_type: identity.principal_type,
            principal_name: identity.principal_name,
            assumed_role_arn: identity.assumed_role_arn,
            identity_source: identity.identity_source,
            source_ip: str_field(rec, "sourceIPAddress"),
            user_agent: str_field(rec, "userAgent"),
            error_code: str_field(rec, "errorCode"),
            read_only: rec.get("readOnly").and_then(Value::as_bool),
            management_event: Some(is_management),
            s3_object_key: Some(key.to_string()),
            raw: rec.clone(),
            created_at: now,
        });
    }
    Ok(out)
}

/// The identity block derived from a CloudTrail record's `userIdentity` (plus the
/// STS request/response for federated calls). Shared by the live ingest mapping
/// and the historical backfill (`backfill_identity`) so the two can't drift.
pub(crate) struct DerivedIdentity {
    pub principal_name: Option<String>,
    pub principal_arn: Option<String>,
    pub principal_type: Option<String>,
    pub assumed_role_arn: Option<String>,
    pub identity_source: Option<String>,
}

/// Derive the canonical actor + provenance from one CloudTrail record. Never
/// fabricates — every field is `None` when the underlying data is absent.
pub(crate) fn derive_identity(rec: &Value) -> DerivedIdentity {
    let ui = rec.get("userIdentity");
    DerivedIdentity {
        principal_name: principal_name(rec),
        principal_arn: ui
            .and_then(|u| u.get("arn"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        principal_type: ui
            .and_then(|u| u.get("type"))
            .and_then(Value::as_str)
            .map(str::to_string),
        assumed_role_arn: assumed_role_arn(rec),
        identity_source: identity_source(rec),
    }
}

/// Normalize the human/principal name for the row's `actor`. Order matters: an
/// assumed-role *session name* (the SSO email, or a role-session string) beats the
/// issuer role name, so SSO logins attribute to the person rather than to
/// `AWSReservedSSO_...`. Never fabricates a name.
fn principal_name(rec: &Value) -> Option<String> {
    let ui = rec.get("userIdentity")?;

    // 1. Explicit userName — IAM users, and the OIDC subject for WebIdentityUser
    //    (kept as the actor so object-id reconciliation can later stitch it).
    if let Some(n) = ui
        .get("userName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return Some(n.to_string());
    }

    // 2. Assumed-role session name. For SSO this is the user's email, for an IRSA
    //    session whose mint recorded a subject it's the service account — prefer it
    //    over the issuer role name. But when the session name is an STS/SDK-generated
    //    *opaque token* (numeric, 32-hex, or an SDK session prefix) it identifies
    //    nothing, so represent the actor as the role-session base (the assumed-role
    //    ARN with the volatile token stripped) — NOT the token (a fake per-assumption
    //    principal) and NOT the bare role name (a role is a capability, not an actor).
    //    The web-identity correlation pass (`resolve_webidentity_chains`) later
    //    upgrades these to the originating subject when a mint event links them.
    if ui.get("type").and_then(Value::as_str) == Some("AssumedRole") {
        if let Some(sn) = session_name(ui) {
            if is_opaque_session_name(&sn) {
                if let Some(base) = role_session_base(ui) {
                    return Some(base);
                }
                // No ARN to derive a base from — fall through to the issuer fallbacks.
            } else {
                return Some(sn);
            }
        }
    }

    // 3. Issuer role name (last resort for assumed roles without a session name).
    if let Some(n) = ui
        .get("sessionContext")
        .and_then(|s| s.get("sessionIssuer"))
        .and_then(|s| s.get("userName"))
        .and_then(Value::as_str)
    {
        return Some(n.to_string());
    }

    // 4. Root.
    if ui.get("type").and_then(Value::as_str) == Some("Root") {
        return Some("root".to_string());
    }

    // 5. ARN tail (general fallback).
    ui.get("arn")
        .and_then(Value::as_str)
        .map(|arn| arn.rsplit(['/', ':']).next().unwrap_or(arn).to_string())
}

/// The assumed-role session name: the ARN tail after the last `/`, or the
/// `principalId` suffix after the last `:`. Prefers whichever looks like a person
/// (contains `@`), so an SSO email wins over an opaque session string.
fn session_name(ui: &Value) -> Option<String> {
    let arn_tail = ui
        .get("arn")
        .and_then(Value::as_str)
        .and_then(|a| a.rsplit('/').next())
        .filter(|s| !s.is_empty());
    let pid_tail = ui
        .get("principalId")
        .and_then(Value::as_str)
        .and_then(|p| p.rsplit(':').next())
        .filter(|s| !s.is_empty());
    if let Some(e) = arn_tail.filter(|s| s.contains('@')) {
        return Some(e.to_string());
    }
    if let Some(e) = pid_tail.filter(|s| s.contains('@')) {
        return Some(e.to_string());
    }
    arn_tail.or(pid_tail).map(str::to_string)
}

/// True when an assumed-role session name carries no actor identity: an
/// STS/SDK-autogenerated token rather than a person or workload. Observed shapes in
/// the trail: pure-numeric (the Go SDK nanosecond stamp, e.g. `1234567890123456789`,
/// minted for IRSA assumptions with no supplied `roleSessionName`), 32-char hex (a
/// UUID without dashes, set by deploy/CI tooling), and known SDK session prefixes
/// (`botocore-session-…`, `aws-sdk-…`). Such a value is unique per assumption and
/// would otherwise scatter one workload's activity across many bogus "actors".
fn is_opaque_session_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let all_digits = name.bytes().all(|b| b.is_ascii_digit());
    let hex32 = name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit());
    let sdk_prefix = name.starts_with("botocore-session-")
        || name.starts_with("aws-sdk-")
        || name.starts_with("aws-go-sdk-");
    all_digits || hex32 || sdk_prefix
}

fn role_session_base(ui: &Value) -> Option<String> {
    let arn = ui
        .get("arn")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let base = arn.rsplit_once('/').map(|(head, _)| head).unwrap_or(arn);
    if base.is_empty() {
        None
    } else {
        Some(base.to_string())
    }
}

/// The IAM role identity in play, preferring the stable role ARN. For assumed-role
/// events that's the session issuer's role ARN; for STS `AssumeRole*` calls it's
/// the requested role ARN, else the returned assumed-role ARN. None when absent.
fn assumed_role_arn(rec: &Value) -> Option<String> {
    let issuer = rec
        .get("userIdentity")
        .and_then(|u| u.get("sessionContext"))
        .and_then(|s| s.get("sessionIssuer"))
        .and_then(|s| s.get("arn"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if let Some(arn) = issuer {
        return Some(arn.to_string());
    }
    let requested = rec
        .get("requestParameters")
        .and_then(|p| p.get("roleArn"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if let Some(arn) = requested {
        return Some(arn.to_string());
    }
    rec.get("responseElements")
        .and_then(|r| r.get("assumedRoleUser"))
        .and_then(|a| a.get("arn"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn identity_source(rec: &Value) -> Option<String> {
    let ui = rec.get("userIdentity")?;
    let ty = ui.get("type").and_then(Value::as_str);

    // Federated / web-identity → the OIDC provider host (e.g. Azure AD's
    // sts.windows.net/<tenant>, or an EKS cluster's oidc.eks.<region>.amazonaws.com),
    // parsed from the provider ARN. The ARN sits at the top level on the
    // `AssumeRoleWithWebIdentity` call itself (`identityProvider`); on the *downstream*
    // events of an IRSA session it instead lives under
    // `sessionContext.webIdFederationData.federatedProvider`, so consult both —
    // otherwise a chained workload event degrades to a bland `assumedrole`.
    let provider = ui
        .get("identityProvider")
        .and_then(Value::as_str)
        .or_else(|| {
            ui.get("sessionContext")
                .and_then(|s| s.get("webIdFederationData"))
                .and_then(|w| w.get("federatedProvider"))
                .and_then(Value::as_str)
        })
        .filter(|s| !s.is_empty());
    if ty == Some("WebIdentityUser")
        || provider
            .map(|p| p.contains("oidc-provider"))
            .unwrap_or(false)
    {
        if let Some(host) = provider.and_then(oidc_host) {
            return Some(format!("oidc:{}", host));
        }
        return Some("oidc".to_string());
    }

    // AWS SSO assumed role.
    let issuer_name = ui
        .get("sessionContext")
        .and_then(|s| s.get("sessionIssuer"))
        .and_then(|s| s.get("userName"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if ty == Some("AssumedRole") && issuer_name.starts_with("AWSReservedSSO_") {
        return Some("aws-sso".to_string());
    }

    // Otherwise the raw AWS identity type, lowercased (iamuser/root/awsservice…).
    ty.map(|t| t.to_lowercase())
}

/// Extract `host[/tenant]` from an OIDC-provider ARN such as
/// `arn:aws:iam::123:oidc-provider/sts.windows.net/<tenant>/`.
fn oidc_host(provider_arn: &str) -> Option<String> {
    let after = provider_arn.split("oidc-provider/").nth(1)?;
    let trimmed = after.trim_end_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ---- historical backfill ---------------------------------------------------

const BACKFILL_BATCH: i64 = 5000;

#[derive(QueryableByName)]
struct BackfillRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    event_id: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    event_time: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    raw: Value,
}

/// One-shot historical backfill of the identity-context columns
/// (`principal_name`, `assumed_role_arn`, `identity_source`) for rows ingested
/// before identity derivation existed. Pre-migration rows have `identity_source IS NULL`, so this
/// targets exactly them and is a no-op once complete. Spawned once at startup
/// (only on the ingest role); recomputes via the same `derive_identity` as the
/// live mapping, so the corrected SSO/web-identity attribution applies to history
/// too. Logged, never fatal.
pub async fn backfill_identity(cancel: CancellationToken, pool: DbPool) {
    match backfill_identity_inner(&cancel, &pool).await {
        Ok(0) => info!("cloudtrail backfill_identity: nothing to backfill"),
        Ok(n) => info!("cloudtrail backfill_identity: updated {} legacy rows", n),
        Err(e) => warn!("cloudtrail backfill_identity failed (non-fatal): {:#}", e),
    }
    // Second pass: normalize rows ingested *before* the
    // opaque-session fix, where an assumed-role session's `principal_name` is still
    // the raw STS/SDK token. These already have `identity_source` set, so the NULL
    // backfill above never touches them. Re-point them at the role-session base so
    // history matches the live mapping (and `resolve_webidentity_chains` can later
    // upgrade the IRSA subset to a subject — it joins on `principal_arn`, not name).
    match backfill_opaque_sessions_inner(&cancel, &pool).await {
        Ok(0) => info!("cloudtrail backfill_identity: no opaque-session rows to normalize"),
        Ok(n) => info!("cloudtrail backfill_identity: normalized {} opaque-session principal(s) to role-session base", n),
        Err(e) => warn!("cloudtrail opaque-session normalization failed (non-fatal): {:#}", e),
    }
    // Third pass: populate the new `user_identity_account_id` column from the
    // raw event's `userIdentity.accountId` for rows ingested before the column existed.
    // `recipient_account_id` needs no backfill — the ingester has always written it.
    match backfill_caller_account_inner(&cancel, &pool).await {
        Ok(0) => info!("cloudtrail backfill_identity: no caller-account rows to backfill"),
        Ok(n) => info!(
            "cloudtrail backfill_identity: populated user_identity_account_id on {} row(s)",
            n
        ),
        Err(e) => warn!(
            "cloudtrail caller-account backfill failed (non-fatal): {:#}",
            e
        ),
    }
}

/// Chunked + idempotent: each pass loads up to `BACKFILL_BATCH` still-NULL rows,
/// recomputes identity, and UPDATEs them by PK in one transaction. `identity_source`
/// is written via `COALESCE(.., '')` so a row with no derivable source still leaves
/// NULL behind it — guaranteeing forward progress and clean termination rather than
/// reselecting the same batch forever. Cancellation-aware between batches.
async fn backfill_identity_inner(cancel: &CancellationToken, pool: &DbPool) -> anyhow::Result<i64> {
    let mut total = 0i64;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let pool = pool.clone();
        let updated = tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
            let mut conn = pool.get().context("pool get")?;
            let rows: Vec<BackfillRow> = diesel::sql_query(
                "SELECT event_id, event_time, raw FROM cloudtrail_events \
                 WHERE identity_source IS NULL ORDER BY event_time DESC LIMIT $1",
            )
            .bind::<diesel::sql_types::BigInt, _>(BACKFILL_BATCH)
            .load(&mut conn)
            .context("load backfill batch")?;
            if rows.is_empty() {
                return Ok(0);
            }
            let n = rows.len() as i64;
            conn.transaction::<_, anyhow::Error, _>(|conn| {
                for r in &rows {
                    let id = derive_identity(&r.raw);
                    diesel::sql_query(
                        "UPDATE cloudtrail_events SET \
                           principal_name   = $1, \
                           assumed_role_arn = $2, \
                           identity_source  = COALESCE($3, '') \
                         WHERE event_id = $4 AND event_time = $5",
                    )
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                        id.principal_name.clone(),
                    )
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                        id.assumed_role_arn.clone(),
                    )
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                        id.identity_source.clone(),
                    )
                    .bind::<diesel::sql_types::Text, _>(&r.event_id)
                    .bind::<diesel::sql_types::Timestamptz, _>(r.event_time)
                    .execute(conn)
                    .context("update backfill row")?;
                }
                Ok(())
            })?;
            Ok(n)
        })
        .await
        .context("join")??;

        if updated == 0 {
            break;
        }
        total += updated;
        info!(
            "cloudtrail backfill_identity: {} rows updated so far",
            total
        );
    }
    Ok(total)
}

/// Historical normalization of opaque assumed-role session principals to the
/// role-session base — the bulk counterpart to the `derive_identity` branch that
/// strips a volatile session token (see `is_opaque_session_name`/`role_session_base`).
///
/// Targets rows whose `principal_name` is still a raw STS/SDK token (pure-numeric,
/// 32-hex, or a known SDK session prefix) **and** whose `principal_arn` is an
/// assumed-role ARN carrying a token to strip. The SQL `regexp_replace(.., '/[^/]*$', '')`
/// is exactly `role_session_base` (drop everything after the last `/`). Set-based
/// (not a per-row re-derive) so it terminates deterministically: the
/// `IS DISTINCT FROM` guard means a normalized row drops out of the filter and is
/// never reselected — no risk of looping on a degenerate row whose re-derived name
/// would still be opaque. Chunked by `ctid` to bound lock duration, cancellation-aware
/// between batches, idempotent, never fatal. Web-identity subjects (`system:service...`)
/// aren't opaque, so already-resolved rows are left untouched.
async fn backfill_opaque_sessions_inner(
    cancel: &CancellationToken,
    pool: &DbPool,
) -> anyhow::Result<i64> {
    let mut total = 0i64;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let pool = pool.clone();
        let updated = tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
            let mut conn = pool.get().context("pool get")?;
            let n = diesel::sql_query(
                "WITH candidates AS ( \
                   SELECT ctid FROM cloudtrail_events \
                   WHERE principal_arn LIKE 'arn:aws:sts::%:assumed-role/%/%' \
                     AND principal_name IS NOT NULL \
                     AND ( \
                       principal_name ~ '^[0-9]+$' \
                       OR principal_name ~ '^[0-9a-fA-F]{32}$' \
                       OR principal_name LIKE 'botocore-session-%' \
                       OR principal_name LIKE 'aws-sdk-%' \
                       OR principal_name LIKE 'aws-go-sdk-%' \
                     ) \
                     AND principal_name IS DISTINCT FROM regexp_replace(principal_arn, '/[^/]*$', '') \
                   LIMIT $1 \
                 ) \
                 UPDATE cloudtrail_events t \
                 SET principal_name = regexp_replace(t.principal_arn, '/[^/]*$', '') \
                 FROM candidates c WHERE t.ctid = c.ctid",
            )
            .bind::<diesel::sql_types::BigInt, _>(BACKFILL_BATCH)
            .execute(&mut conn)
            .context("normalize opaque-session batch")? as i64;
            Ok(n)
        })
        .await
        .context("join")??;

        if updated == 0 {
            break;
        }
        total += updated;
        info!(
            "cloudtrail backfill_identity: {} opaque-session rows normalized so far",
            total
        );
    }
    Ok(total)
}

/// Populate `user_identity_account_id` from `raw #>> '{userIdentity,accountId}'`
/// for rows ingested before the column existed. Set-based (no per-row re-derive), chunked
/// by `ctid` to bound lock duration, cancellation-aware between batches. The
/// `user_identity_account_id IS NULL AND raw #>> … IS NOT NULL` guard makes it both
/// terminate (a populated row drops out of the filter) and idempotent (a re-run is a
/// no-op). Rows whose raw event carries no `userIdentity.accountId` stay NULL forever,
/// so they're not reselected. Never fatal.
async fn backfill_caller_account_inner(
    cancel: &CancellationToken,
    pool: &DbPool,
) -> anyhow::Result<i64> {
    let mut total = 0i64;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let pool = pool.clone();
        let updated = tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
            let mut conn = pool.get().context("pool get")?;
            let n = diesel::sql_query(
                "WITH candidates AS ( \
                   SELECT ctid FROM cloudtrail_events \
                   WHERE user_identity_account_id IS NULL \
                     AND raw #>> '{userIdentity,accountId}' IS NOT NULL \
                   ORDER BY event_time \
                   LIMIT $1 \
                 ) \
                 UPDATE cloudtrail_events t \
                 SET user_identity_account_id = t.raw #>> '{userIdentity,accountId}' \
                 FROM candidates c WHERE t.ctid = c.ctid",
            )
            .bind::<diesel::sql_types::BigInt, _>(BACKFILL_BATCH)
            .execute(&mut conn)
            .context("backfill caller-account batch")? as i64;
            Ok(n)
        })
        .await
        .context("join")??;

        if updated == 0 {
            break;
        }
        total += updated;
        info!(
            "cloudtrail backfill_identity: {} caller-account rows populated so far",
            total
        );
    }
    Ok(total)
}

#[tracing::instrument(name = "cloudtrail.webid_resolve", skip_all, fields(window_days = window_days))]
fn resolve_webidentity_chains(conn: &mut PgConnection, window_days: i64) -> anyhow::Result<usize> {
    let floor = Utc::now() - Duration::days(window_days.max(1));

    // Snapshot the new high-water insertion time *before* doing the work, minus a small
    // lag (see doc comment). NULL → empty table, nothing to do.
    #[derive(QueryableByName)]
    struct Snap {
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
        w: Option<DateTime<Utc>>,
    }
    let w_new = diesel::sql_query(
        "SELECT max(created_at) - ($1 || ' minutes')::interval AS w FROM cloudtrail_events",
    )
    .bind::<diesel::sql_types::Text, _>(WEBID_WATERMARK_LAG_MINS.to_string())
    .get_result::<Snap>(conn)
    .context("snapshot webid watermark")?
    .w;
    let Some(w_new) = w_new else {
        return Ok(0);
    };

    // Previous watermark — default epoch (first run → full bootstrap pass).
    let w = get_watermark(conn, WEBID_WATERMARK_SOURCE)
        .context("read webid watermark")?
        .and_then(|wm| wm.last_event_at)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"));

    let n = conn.transaction::<usize, anyhow::Error, _>(|conn| {
        // (1) Harvest new mints (created_at > W) into the cache, then fan each
        // newly-cached/changed session out to all its downstream rows (any age) via the
        // principal_arn index. A data-modifying CTE: the INSERT…ON CONFLICT…RETURNING
        // yields exactly the sessions whose subject is new or changed (unchanged
        // conflicts are filtered by the WHERE, so not returned → no needless fan-out).
        // Catches a downstream row ingested before its mint.
        let n1 = diesel::sql_query(
            "WITH new_maps AS ( \
               INSERT INTO webidentity_session_subjects (session_arn, subject) \
               SELECT session_arn, subject FROM ( \
                 SELECT raw #>> '{responseElements,assumedRoleUser,arn}' AS session_arn, \
                        max(raw #>> '{responseElements,subjectFromWebIdentityToken}') AS subject \
                 FROM cloudtrail_events \
                 WHERE event_name = 'AssumeRoleWithWebIdentity' \
                   AND event_time >= $1 \
                   AND created_at > $2 \
                   AND raw #>> '{responseElements,subjectFromWebIdentityToken}' IS NOT NULL \
                   AND raw #>> '{responseElements,assumedRoleUser,arn}' IS NOT NULL \
                 GROUP BY 1 \
               ) s \
               ON CONFLICT (session_arn) DO UPDATE SET subject = EXCLUDED.subject, updated_at = now() \
                 WHERE webidentity_session_subjects.subject IS DISTINCT FROM EXCLUDED.subject \
               RETURNING session_arn, subject \
             ) \
             UPDATE cloudtrail_events d \
             SET principal_name = nm.subject \
             FROM new_maps nm \
             WHERE d.principal_arn = nm.session_arn \
               AND d.event_time >= $1 \
               AND d.event_name <> 'AssumeRoleWithWebIdentity' \
               AND d.principal_name IS DISTINCT FROM nm.subject",
        )
        .bind::<diesel::sql_types::Timestamptz, _>(floor)
        .bind::<diesel::sql_types::Timestamptz, _>(w)
        .execute(conn)
        .context("resolve web-identity chains (harvest + fan-out)")?;

        // (2) Apply the cache to new downstream rows (created_at > W) — a PK lookup into
        // the cache, scanned via idx_cloudtrail_created_at. The normal case (downstream
        // ingested after its mint, which is already cached).
        let n2 = diesel::sql_query(
            "UPDATE cloudtrail_events d \
             SET principal_name = m.subject \
             FROM webidentity_session_subjects m \
             WHERE d.principal_arn = m.session_arn \
               AND d.created_at > $2 \
               AND d.event_time >= $1 \
               AND d.event_name <> 'AssumeRoleWithWebIdentity' \
               AND d.principal_name IS DISTINCT FROM m.subject",
        )
        .bind::<diesel::sql_types::Timestamptz, _>(floor)
        .bind::<diesel::sql_types::Timestamptz, _>(w)
        .execute(conn)
        .context("resolve web-identity chains (apply cache to new downstream)")?;

        // Prune dead cache entries (older than 2× window — ephemeral session ARNs whose
        // downstream rows have aged out), keeping the cache bounded.
        diesel::sql_query(
            "DELETE FROM webidentity_session_subjects \
             WHERE updated_at < now() - (($1 || ' days')::interval * 2)",
        )
        .bind::<diesel::sql_types::Text, _>(window_days.max(1).to_string())
        .execute(conn)
        .context("prune webid session cache")?;

        // Advance the watermark in the same txn. Direct UPSERT (not `advance_watermark`)
        // so this internal bookkeeping row doesn't fire a console progress push.
        diesel::sql_query(
            "INSERT INTO ingest_watermarks \
               (source, last_event_at, last_run_at, objects_scanned, events_applied) \
             VALUES ($1, $2, now(), 0, 0) \
             ON CONFLICT (source) DO UPDATE SET \
               last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at), \
               last_run_at   = now()",
        )
        .bind::<diesel::sql_types::Text, _>(WEBID_WATERMARK_SOURCE)
        .bind::<diesel::sql_types::Timestamptz, _>(w_new)
        .execute(conn)
        .context("advance webid watermark")?;

        Ok(n1 + n2)
    })?;
    Ok(n)
}

fn str_field(rec: &Value, key: &str) -> Option<String> {
    rec.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parse_event_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

// ---- watermark / cursor persistence ---------------------------------------

async fn load_cursors(pool: &DbPool) -> anyhow::Result<HashMap<String, String>> {
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<HashMap<String, String>> {
        let mut conn = pool.get().context("pool get")?;
        let wm = get_watermark(&mut conn, SOURCE_CLOUDTRAIL).context("get watermark")?;
        let cursors = wm
            .and_then(|w| w.last_cursor)
            .and_then(|c| serde_json::from_str::<HashMap<String, String>>(&c).ok())
            .unwrap_or_default();
        Ok(cursors)
    })
    .await
    .context("join")?
}

/// Insert one day-prefix's events (chunked, dedup) and return the applied count.
/// The cursor advance happens in `finalize_sweep` so a single watermark write
/// carries the whole sweep's cursor map; the inserts here are independently
/// idempotent, so a crash before finalize simply re-lists from the old cursor.
// No per-prefix span (see `fetch_prefix`): one per committed day-prefix per
// account is sweep-trace noise. The aggregate lives on `cloudtrail.sweep`.
async fn commit_prefix(
    pool: &DbPool,
    _prefix: &str,
    events: Vec<CloudtrailEventInsert>,
    _cursor: Option<String>,
) -> anyhow::Result<i64> {
    if events.is_empty() {
        return Ok(0);
    }
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
        let mut conn = pool.get().context("pool get")?;
        let mut applied = 0i64;
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            // CloudtrailEventInsert has 19 columns; Postgres caps a statement at
            // 65535 bind parameters, so a chunk must stay under 65535/19 ≈ 3449
            // rows. 3000 keeps headroom (the old 4000 overflowed once a prefix
            // produced ≥3450 events in one commit — surfaced when the
            // assumed_role_arn/identity_source columns were added).
            for chunk in events.chunks(3000) {
                applied += diesel::insert_into(crate::schema::cloudtrail_events::table)
                    .values(chunk)
                    .on_conflict_do_nothing()
                    .execute(conn)
                    .context("insert cloudtrail_events")? as i64;
            }
            Ok(())
        })?;
        Ok(applied)
    })
    .await
    .context("join")?
}

/// Mid-sweep heartbeat: persist the current cursor map + newest event time and
/// bump `last_run_at` (clearing any stale `last_run_error`) without touching the
/// cumulative counters — those are applied once in `finalize_sweep`. This is what
/// makes a long backfill visible to the console and resumable across a restart.
async fn heartbeat(
    pool: &DbPool,
    cursors: &HashMap<String, String>,
    max_event_at: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    let cursor_json = serde_json::to_string(cursors).unwrap_or_else(|_| "{}".to_string());
    let last_object_key = max_object_key(cursors);
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = pool.get().context("pool get")?;
        advance_watermark(
            &mut conn,
            SOURCE_CLOUDTRAIL,
            last_object_key,
            max_event_at,
            Some(cursor_json),
            0,
            0,
        )
        .context("heartbeat watermark")
    })
    .await
    .context("join")?
}

async fn finalize_sweep(
    pool: &DbPool,
    cursors: &HashMap<String, String>,
    objects: i64,
    events: i64,
    max_event_at: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    let cursor_json = serde_json::to_string(cursors).unwrap_or_else(|_| "{}".to_string());
    let last_object_key = max_object_key(cursors);
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = pool.get().context("pool get")?;
        advance_watermark(
            &mut conn,
            SOURCE_CLOUDTRAIL,
            last_object_key,
            max_event_at,
            Some(cursor_json),
            objects,
            events,
        )
        .context("advance watermark")
    })
    .await
    .context("join")?
}

/// Newest object key across the day-prefix cursors, excluding reserved control
/// keys (e.g. `RESUME_ACCOUNT_KEY`) whose values are account prefixes, not object
/// keys — so the watermark's `last_object_key` reflects real ingested objects.
fn max_object_key(cursors: &HashMap<String, String>) -> Option<String> {
    cursors
        .iter()
        .filter(|(k, _)| !k.starts_with("__"))
        .map(|(_, v)| v.clone())
        .max()
}

/// Drop cursor entries for day-prefixes whose date is older than the window
/// floor, so the map cannot grow without bound across long-running deployments.
fn prune_cursors(cursors: &mut HashMap<String, String>, floor: DateTime<Utc>) {
    let floor_date = floor.date_naive();
    cursors.retain(|prefix, _| match extract_prefix_date(prefix) {
        Some(d) => d >= floor_date,
        None => true,
    });
}

/// Pull the `YYYY/MM/DD` date out of a `.../<region>/YYYY/MM/DD/` cursor key.
fn extract_prefix_date(prefix: &str) -> Option<NaiveDate> {
    let parts: Vec<&str> = prefix.trim_end_matches('/').split('/').collect();
    if parts.len() < 3 {
        return None;
    }
    let n = parts.len();
    let y: i32 = parts[n - 3].parse().ok()?;
    let m: u32 = parts[n - 2].parse().ok()?;
    let d: u32 = parts[n - 1].parse().ok()?;
    NaiveDate::from_ymd_opt(y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Synthetic SSO ConsoleLogin (assumed-role). The role-session name carries the
    /// user's email — `alice@dfds.com`, a stand-in, not a real principal.
    fn sso_login() -> Value {
        json!({
            "eventName": "ConsoleLogin",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAEXAMPLESSO0000001:alice@dfds.com",
                "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_CloudAdmin_0123456789abcdef/alice@dfds.com",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "arn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_CloudAdmin_0123456789abcdef",
                        "userName": "AWSReservedSSO_CloudAdmin_0123456789abcdef"
                    }
                }
            }
        })
    }

    /// Azure-AD-federated `AssumeRoleWithWebIdentity` — the actor is the opaque
    /// OIDC subject; provider + assumed role live elsewhere in the record.
    fn web_identity() -> Value {
        json!({
            "eventName": "AssumeRoleWithWebIdentity",
            "requestParameters": {
                "roleArn": "arn:aws:iam::234567890123:role/ExampleAppS3Access-PROD",
                "roleSessionName": "ExampleAppSession"
            },
            "responseElements": {
                "assumedRoleUser": {
                    "arn": "arn:aws:sts::234567890123:assumed-role/ExampleAppS3Access-PROD/ExampleAppSession"
                }
            },
            "userIdentity": {
                "type": "WebIdentityUser",
                "userName": "22222222-2222-2222-2222-222222222222",
                "identityProvider": "arn:aws:iam::234567890123:oidc-provider/sts.windows.net/11111111-1111-1111-1111-111111111111/"
            }
        })
    }

    #[test]
    fn sso_login_attributes_to_person_not_role() {
        let id = derive_identity(&sso_login());
        assert_eq!(id.principal_name.as_deref(), Some("alice@dfds.com"));
        assert_eq!(
            id.assumed_role_arn.as_deref(),
            Some("arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_CloudAdmin_0123456789abcdef"),
        );
        assert_eq!(id.identity_source.as_deref(), Some("aws-sso"));
    }

    fn irsa_chained_assume_role() -> Value {
        json!({
            "eventName": "AssumeRole",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROAEXAMPLEIRSA000001:1234567890123456789",
                "arn": "arn:aws:sts::345678901234:assumed-role/eks-staging-example-external-dns/1234567890123456789",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "arn": "arn:aws:iam::345678901234:role/eks-staging-example-external-dns",
                        "userName": "eks-staging-example-external-dns"
                    },
                    "webIdFederationData": {
                        "federatedProvider": "arn:aws:iam::345678901234:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF"
                    }
                }
            }
        })
    }

    #[test]
    fn opaque_session_resolves_to_role_session_base_not_token_or_role() {
        let id = derive_identity(&irsa_chained_assume_role());
        // The actor is the role-session base — neither the volatile token nor the
        // bare role name masquerading as a principal.
        assert_eq!(
            id.principal_name.as_deref(),
            Some("arn:aws:sts::345678901234:assumed-role/eks-staging-example-external-dns"),
        );
        // Provenance still points at the IAM role + the EKS OIDC provider.
        assert_eq!(
            id.assumed_role_arn.as_deref(),
            Some("arn:aws:iam::345678901234:role/eks-staging-example-external-dns"),
        );
        assert_eq!(
            id.identity_source.as_deref(),
            Some("oidc:oidc.eks.eu-west-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF"),
        );
    }

    #[test]
    fn opaque_session_name_detection() {
        assert!(is_opaque_session_name("1234567890123456789")); // Go SDK numeric
        assert!(is_opaque_session_name("71f4c55c9a6043cbbe67f767953dff14")); // 32-hex
        assert!(is_opaque_session_name("botocore-session-1781097095"));
        assert!(!is_opaque_session_name("alice@dfds.com"));
        assert!(!is_opaque_session_name(
            "system:serviceaccount:external-dns:external-dns"
        ));
        assert!(!is_opaque_session_name("ExampleAppSession"));
    }

    #[test]
    fn web_identity_keeps_subject_and_surfaces_provider_and_role() {
        let id = derive_identity(&web_identity());
        assert_eq!(
            id.principal_name.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
        assert_eq!(
            id.identity_source.as_deref(),
            Some("oidc:sts.windows.net/11111111-1111-1111-1111-111111111111"),
        );
        assert_eq!(
            id.assumed_role_arn.as_deref(),
            Some("arn:aws:iam::234567890123:role/ExampleAppS3Access-PROD"),
        );
    }
}
