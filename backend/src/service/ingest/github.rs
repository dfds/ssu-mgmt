//! GitHub Enterprise audit-log ingester.
//!
//! Ports `gh-member-activity-api/internal/github/audit.go`: page the enterprise
//! audit-log REST endpoint (`GET /enterprises/{ent}/audit-log`) oldest-first
//! (`order=asc`) from a `since` floor, following the `Link: rel="next"` cursor,
//! and map entries to `github_audit_events` (dedup on `document_id`).
//!
//! The endpoint needs a **classic PAT with `read:audit_log`** (App installation
//! tokens cannot call it) — so we use `reqwest` directly rather than a typed
//! client. Resume is by the `since` date floor (= max(now-window, watermark))
//! plus the `document_id` dedup, which is robust even though audit-log cursors
//! can expire. REST retention is bounded (~90–180 days); long-term coverage via
//! the GitHub→S3 audit stream is out of scope

use anyhow::{anyhow, Context};
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use log::{info, warn};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::StatusCode;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::db::model::GithubAuditEventInsert;
use crate::db::DbPool;
use crate::misc::config::GithubConfig;
use crate::service::ingest::{advance_watermark, get_watermark, record_run_error, SOURCE_GITHUB};

/// Pages folded into one commit transaction before checkpointing the watermark.
const FLUSH_PAGES: u32 = 25;
/// Cap on how many times a single page waits out a rate-limit reset.
const RATE_LIMIT_MAX_WAITS: u32 = 6;
/// Consecutive failed sweeps before the loop escalates from a per-sweep `error!`
/// to a single louder `warn!` — the backend counterpart to the console's red
/// "stalled" indicator (≈3× the poll interval at the 300s default).
const STALL_WARN_AFTER_SWEEPS: u32 = 3;

pub async fn run(cancel: CancellationToken, conf: GithubConfig, pool: DbPool) {
    if conf.enterprise.is_empty() || conf.audit_pat.is_empty() {
        log::error!("github ingest enabled but enterprise/audit_pat unset — not starting");
        return;
    }

    let client = match build_client(&conf) {
        Ok(c) => c,
        Err(e) => {
            log::error!("github ingest client build failed: {:#}", e);
            return;
        }
    };

    let interval = std::time::Duration::from_secs(conf.poll_interval_secs.max(30));
    info!(
        "github audit-log ingest starting :: enterprise={} backfill_window_days={} interval={}s",
        conf.enterprise, conf.backfill_window_days, interval.as_secs()
    );

    let mut consecutive_failures: u32 = 0;
    loop {
        // run_once logs "github audit-log backfill starting :: since=" at the top
        // of every sweep — that line is the per-sweep heartbeat; its absence is the
        // tell that the loop isn't running at all.
        match run_once(&client, &conf, &pool, &cancel).await {
            Ok(()) => consecutive_failures = 0,
            Err(e) => {
                consecutive_failures += 1;
                log::error!("github audit-log sweep failed (consecutive={}): {:#}", consecutive_failures, e);
                if consecutive_failures == STALL_WARN_AFTER_SWEEPS {
                    warn!(
                        "github ingest stalled: {} consecutive failed sweeps — console shows 'stalled'; last error: {:#}",
                        consecutive_failures, e
                    );
                }
                let pool = pool.clone();
                let msg = format!("{:#}", e);
                let _ = tokio::task::spawn_blocking(move || {
                    let mut conn = pool.get().context("pool get")?;
                    record_run_error(&mut conn, SOURCE_GITHUB, &msg).context("record error")
                })
                .await;
            }
        }

        tokio::select! {
            _ = cancel.cancelled() => { info!("stopping github ingest"); break; }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

fn build_client(conf: &GithubConfig) -> anyhow::Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
    headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));
    headers.insert(USER_AGENT, HeaderValue::from_static("ssu-mgmt-audit-ingest"));
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", conf.audit_pat)).context("auth header")?;
    auth.set_sensitive(true);
    headers.insert(AUTHORIZATION, auth);
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .context("build reqwest client")
}

#[tracing::instrument(name = "github.sweep", skip_all)]
async fn run_once(
    client: &reqwest::Client,
    conf: &GithubConfig,
    pool: &DbPool,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    // Resume floor: max(now - window, persisted watermark). The endpoint's
    // `phrase=created:>=DATE` is day-granular, so we floor to the date.
    let watermark = {
        let pool = pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<DateTime<Utc>>> {
            let mut conn = pool.get().context("pool get")?;
            Ok(get_watermark(&mut conn, SOURCE_GITHUB)?.and_then(|w| w.last_event_at))
        })
        .await
        .context("join")??
    };
    let window_floor = Utc::now() - Duration::days(conf.backfill_window_days.max(1));
    let since = watermark.map(|w| w.max(window_floor)).unwrap_or(window_floor);
    let since_date = since.format("%Y-%m-%d").to_string();

    let base = conf.api_base_url.trim_end_matches('/');
    let mut url = format!(
        "{}/enterprises/{}/audit-log?phrase=created:>={}&include=all&order=asc&per_page=100",
        base, conf.enterprise, since_date
    );

    info!("github audit-log backfill starting :: since={}", since_date);

    let mut page: u32 = 0;
    let mut batch: Vec<GithubAuditEventInsert> = Vec::new();
    let mut batch_max_event_at: Option<DateTime<Utc>> = None;
    let mut total_applied: i64 = 0;

    loop {
        if cancel.is_cancelled() {
            break;
        }
        let (entries, next) = fetch_page(client, &url, cancel).await?;
        page += 1;

        for entry in &entries {
            let row = match map_entry(entry) {
                Some(r) => r,
                None => continue,
            };
            batch_max_event_at = Some(batch_max_event_at.map_or(row.event_time, |x| x.max(row.event_time)));
            batch.push(row);
        }

        if page % FLUSH_PAGES == 0 {
            total_applied += flush(pool, std::mem::take(&mut batch), batch_max_event_at.take()).await?;
            info!("github audit-log progress :: page={} applied={}", page, total_applied);
        }

        match next {
            Some(n) => url = n,
            None => break,
        }
    }

    total_applied += flush(pool, batch, batch_max_event_at).await?;
    info!("github audit-log sweep complete :: pages={} events_applied={}", page, total_applied);
    Ok(())
}

/// Fetch one audit-log page, waiting out primary/secondary rate limits up to
/// `RATE_LIMIT_MAX_WAITS` times. Returns the parsed entries and the next page
/// URL (from the `Link` header `rel="next"`), if any.
async fn fetch_page(
    client: &reqwest::Client,
    url: &str,
    cancel: &CancellationToken,
) -> anyhow::Result<(Vec<Value>, Option<String>)> {
    let mut waits = 0u32;
    loop {
        let resp = client.get(url).send().await.context("audit-log request")?;
        let status = resp.status();

        if status.is_success() {
            let next = parse_next_link(resp.headers());
            let entries: Vec<Value> = resp.json().await.context("decode audit-log page")?;
            return Ok((entries, next));
        }

        // Primary (403/429 with remaining=0) and secondary rate limits → wait.
        let retryable = status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS;
        if retryable {
            if waits >= RATE_LIMIT_MAX_WAITS {
                return Err(anyhow!("rate limit still in effect after {} waits (status {})", waits, status));
            }
            let sleep = rate_limit_sleep(resp.headers());
            warn!("github audit-log rate limited, waiting {}s (attempt {})", sleep.as_secs(), waits + 1);
            tokio::select! {
                _ = cancel.cancelled() => return Err(anyhow!("cancelled during rate-limit wait")),
                _ = tokio::time::sleep(sleep) => {}
            }
            waits += 1;
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("audit-log request failed: {} :: {}", status, body));
    }
}

/// Compute how long to wait for the rate-limit window to reset, from
/// `retry-after` (seconds) or `x-ratelimit-reset` (unix epoch). Caps at 5 min.
fn rate_limit_sleep(headers: &HeaderMap) -> std::time::Duration {
    let cap = std::time::Duration::from_secs(300);
    if let Some(ra) = headers.get("retry-after").and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok()) {
        return std::time::Duration::from_secs(ra).min(cap);
    }
    if let Some(reset) = headers.get("x-ratelimit-reset").and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<i64>().ok()) {
        let now = Utc::now().timestamp();
        if reset > now {
            return std::time::Duration::from_secs((reset - now) as u64).min(cap);
        }
    }
    std::time::Duration::from_secs(60)
}

/// Extract the `rel="next"` URL from a GitHub `Link` header.
fn parse_next_link(headers: &HeaderMap) -> Option<String> {
    let link = headers.get(reqwest::header::LINK)?.to_str().ok()?;
    for part in link.split(',') {
        let segs: Vec<&str> = part.split(';').collect();
        if segs.iter().any(|s| s.trim() == "rel=\"next\"") {
            let raw = segs[0].trim();
            return raw.strip_prefix('<').and_then(|s| s.strip_suffix('>')).map(str::to_string);
        }
    }
    None
}

async fn flush(
    pool: &DbPool,
    events: Vec<GithubAuditEventInsert>,
    max_event_at: Option<DateTime<Utc>>,
) -> anyhow::Result<i64> {
    if events.is_empty() && max_event_at.is_none() {
        return Ok(0);
    }
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
        let mut conn = pool.get().context("pool get")?;
        let objects = events.len() as i64;
        let mut applied = 0i64;
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            for chunk in events.chunks(4000) {
                applied += diesel::insert_into(crate::schema::github_audit_events::table)
                    .values(chunk)
                    .on_conflict_do_nothing()
                    .execute(conn)
                    .context("insert github_audit_events")? as i64;
            }
            advance_watermark(conn, SOURCE_GITHUB, None, max_event_at, None, objects, applied)
                .context("advance watermark")?;
            Ok(())
        })?;
        Ok(applied)
    })
    .await
    .context("join")?
}

pub(crate) fn map_entry(entry: &Value) -> Option<GithubAuditEventInsert> {
    let event_time = entry_time(entry)?;
    let document_id = match entry.get("_document_id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return None,
    };
    Some(GithubAuditEventInsert {
        document_id,
        event_time,
        action: entry.get("action").and_then(Value::as_str).unwrap_or("").to_string(),
        actor: str_field(entry, "actor"),
        actor_id: entry.get("actor_id").map(num_or_str).filter(|s| !s.is_empty()),
        org: str_field(entry, "org"),
        repo: str_field(entry, "repo"),
        source_ip: str_field(entry, "actor_ip"),
        user_agent: str_field(entry, "user_agent"),
        raw: entry.clone(),
        created_at: Utc::now(),
    })
}

pub(crate) fn entry_time(entry: &Value) -> Option<DateTime<Utc>> {
    // GitHub emits @timestamp / created_at as ms-since-epoch.
    for key in ["@timestamp", "created_at"] {
        if let Some(v) = entry.get(key) {
            if let Some(ms) = v.as_i64() {
                return DateTime::from_timestamp_millis(ms);
            }
            if let Some(s) = v.as_str() {
                if let Ok(d) = DateTime::parse_from_rfc3339(s) {
                    return Some(d.with_timezone(&Utc));
                }
                if let Ok(ms) = s.parse::<i64>() {
                    return DateTime::from_timestamp_millis(ms);
                }
            }
        }
    }
    None
}

pub(crate) fn str_field(entry: &Value, key: &str) -> Option<String> {
    entry.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

pub(crate) fn num_or_str(v: &Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| {
        if v.is_number() { v.to_string() } else { String::new() }
    })
}
