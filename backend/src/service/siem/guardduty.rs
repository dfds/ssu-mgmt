use std::collections::HashMap;

use anyhow::Context;
use aws_sdk_guardduty::config::Region;
use aws_sdk_guardduty::types::{Condition, FindingCriteria, OrderBy, SortCriteria};
use aws_sdk_guardduty::Client;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz};
use log::{error, info};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::db::DbPool;
use crate::misc::config::GuarddutyConfig;
use crate::service::ingest::{
    advance_watermark, get_watermark, record_run_error, SOURCE_GUARDDUTY,
};

/// Entry point: initial sweep then poll on the configured interval.
pub async fn run(cancel: CancellationToken, conf: GuarddutyConfig, pool: DbPool) {
    let regions: Vec<String> = conf
        .regions
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if regions.is_empty() {
        error!("guardduty enabled but no regions configured — not starting");
        return;
    }

    let shared = load_aws_config(&conf, &regions[0]).await;
    let interval = std::time::Duration::from_secs(conf.interval_secs.max(60));
    info!(
        "guardduty ingest starting :: regions={:?} interval={}s assume_role={}",
        regions,
        interval.as_secs(),
        if conf.assume_role_arn.is_empty() {
            "none"
        } else {
            conf.assume_role_arn.as_str()
        }
    );

    loop {
        if let Err(e) = run_once(&shared, &regions, &pool, conf.backfill_window_days, &cancel).await
        {
            error!("guardduty sweep failed: {:#}", e);
            let pool = pool.clone();
            let msg = format!("{:#}", e);
            let _ = tokio::task::spawn_blocking(move || {
                let mut conn = pool.get().context("pool get")?;
                record_run_error(&mut conn, SOURCE_GUARDDUTY, &msg).context("record error")
            })
            .await;
        }

        tokio::select! {
            _ = cancel.cancelled() => { info!("stopping guardduty ingest"); break; }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// Build the shared AWS config the regional GuardDuty clients are derived from.
async fn load_aws_config(conf: &GuarddutyConfig, region: &str) -> aws_config::SdkConfig {
    let base = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region.to_string()));
    if conf.assume_role_arn.is_empty() {
        return base.load().await;
    }
    let provider = aws_config::sts::AssumeRoleProvider::builder(conf.assume_role_arn.clone())
        .session_name(conf.assume_role_session_name.clone())
        .region(Region::new(region.to_string()))
        .build()
        .await;
    base.credentials_provider(provider).load().await
}

#[tracing::instrument(name = "guardduty.sweep", skip_all, fields(n_regions = regions.len()))]
async fn run_once(
    shared: &aws_config::SdkConfig,
    regions: &[String],
    pool: &DbPool,
    backfill_window_days: i64,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let since = {
        let pool = pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<DateTime<Utc>>> {
            let mut conn = pool.get().context("pool get")?;
            Ok(get_watermark(&mut conn, SOURCE_GUARDDUTY)?.and_then(|w| w.last_event_at))
        })
        .await
        .context("join")??
    };

    // First run (no watermark) would otherwise fetch *every* finding the detector
    // has ever held — on an org delegated-admin/aggregator that is the whole org's
    // history, which OOMs the pod. Floor the cold-start scan to a bounded lookback;
    // once a watermark exists, use it instead. `<= 0` keeps the old unbounded scan.
    let effective_since = since.or_else(|| {
        (backfill_window_days > 0).then(|| Utc::now() - Duration::days(backfill_window_days))
    });
    if since.is_none() {
        match effective_since {
            Some(floor) => info!(
                "guardduty cold start: no watermark, bounding first sweep to updatedAt >= {} ({}d lookback)",
                floor, backfill_window_days
            ),
            None => info!("guardduty cold start: no watermark and backfill_window_days <= 0 — unbounded scan"),
        }
    }

    let mut total = 0usize;
    let mut max_updated: Option<DateTime<Utc>> = since;
    for region in regions {
        if cancel.is_cancelled() {
            break;
        }
        let span = tracing::info_span!(
            "guardduty.region",
            otel.kind = "client",
            peer.service = "guardduty",
            region = %region
        );
        let (applied, latest): (usize, Option<DateTime<Utc>>) = async {
            let conf = aws_sdk_guardduty::config::Builder::from(shared)
                .region(Region::new(region.clone()))
                .build();
            let client = Client::from_conf(conf);

            let detectors = client
                .list_detectors()
                .send()
                .await
                .with_context(|| format!("list detectors {}", region))?;
            let mut region_total = 0usize;
            let mut region_latest: Option<DateTime<Utc>> = None;
            for detector_id in detectors.detector_ids() {
                let (applied, latest) =
                    sweep_detector(&client, detector_id, region, effective_since, pool, cancel)
                        .await?;
                region_total += applied;
                region_latest = max_opt(region_latest, latest);
            }
            Ok::<_, anyhow::Error>((region_total, region_latest))
        }
        .instrument(span)
        .await?;
        total += applied;
        max_updated = max_opt(max_updated, latest);
    }

    if max_updated != since {
        let pool = pool.clone();
        let last = max_updated;
        let applied = total as i64;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut conn = pool.get().context("pool get")?;
            advance_watermark(&mut conn, SOURCE_GUARDDUTY, None, last, None, 0, applied)
                .context("advance watermark")
        })
        .await
        .context("join")??;
    }

    info!("guardduty sweep complete :: findings_applied={}", total);
    Ok(())
}

/// Newest of two optional timestamps (treats `None` as -inf).
fn max_opt(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) => Some(x),
        (None, b) => b,
    }
}

async fn sweep_detector(
    client: &Client,
    detector_id: &str,
    region: &str,
    since: Option<DateTime<Utc>>,
    pool: &DbPool,
    cancel: &CancellationToken,
) -> anyhow::Result<(usize, Option<DateTime<Utc>>)> {
    let criteria = since.map(|s| {
        let cond = Condition::builder()
            .greater_than_or_equal(s.timestamp_millis())
            .build();
        let mut crit: HashMap<String, Condition> = HashMap::new();
        crit.insert("updatedAt".to_string(), cond);
        FindingCriteria::builder().set_criterion(Some(crit)).build()
    });
    let sort = SortCriteria::builder()
        .attribute_name("updatedAt")
        .order_by(OrderBy::Asc)
        .build();

    // Stream page-by-page and flush each page immediately rather than accumulating
    // the detector's *entire* finding set in memory first. On an org delegated-admin
    // detector the full set is hundreds of thousands of findings — buffering it all
    // (ids + mapped rows) is what OOMs the pod. ListFindings returns at most 50 IDs
    // per page, so peak memory here is one page (≤50 findings), regardless of how
    // large the (bounded) lookback window is.
    let mut applied = 0usize;
    let mut max_updated_at: Option<DateTime<Utc>> = None;
    let mut next_token: Option<String> = None;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let listed = client
            .list_findings()
            .detector_id(detector_id)
            .set_finding_criteria(criteria.clone())
            .sort_criteria(sort.clone())
            .set_next_token(next_token.clone())
            .send()
            .await
            .with_context(|| format!("list findings {}", detector_id))?;
        let ids: Vec<String> = listed.finding_ids().to_vec();
        let page_token = listed
            .next_token()
            .filter(|t| !t.is_empty())
            .map(str::to_string);

        // GetFindings accepts at most 50 finding IDs per request; a ListFindings page
        // is already ≤50, but chunk defensively in case that ever changes.
        let mut rows: Vec<FindingRow> = Vec::new();
        for chunk in ids.chunks(50) {
            let got = client
                .get_findings()
                .detector_id(detector_id)
                .set_finding_ids(Some(chunk.to_vec()))
                .send()
                .await
                .with_context(|| format!("get findings {}", detector_id))?;

            for f in got.findings() {
                let id = match f.id() {
                    Some(id) => id.to_string(),
                    None => continue,
                };
                let severity = f.severity().unwrap_or(0.0);
                let archived = f.service().and_then(|s| s.archived()).unwrap_or(false);
                let status = if archived { "resolved" } else { "open" };
                let (first_seen, last_seen) = finding_window(f);
                let updated_at = f
                    .updated_at()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&Utc));
                max_updated_at = max_opt(max_updated_at, updated_at);
                rows.push(FindingRow {
                    fingerprint: format!("guardduty:{}", id),
                    severity: severity_label(severity).to_string(),
                    title: f.title().unwrap_or("GuardDuty finding").to_string(),
                    description: f.description().map(str::to_string),
                    first_seen,
                    last_seen,
                    event_count: f.service().and_then(|s| s.count()).unwrap_or(1) as i64,
                    status,
                    evidence: serde_json::json!({
                        "type": f.r#type(),
                        "severity": severity,
                        "region": region,
                        "account_id": f.account_id(),
                        "archived": archived,
                    }),
                });
            }
        }

        // Flush this page immediately, then advance to the next page. Peak memory
        // stays at one page (≤50 findings) rather than the detector's whole set.
        if rows.is_empty() {
            match page_token {
                Some(t) => {
                    next_token = Some(t);
                    continue;
                }
                None => break,
            }
        }
        let count = rows.len();
        let pool = pool.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = pool.get().context("pool get")?;
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            for r in &rows {
                diesel::sql_query(
                    "INSERT INTO alerts (fingerprint, rule_id, severity, title, description, actor_id, source, first_seen, last_seen, event_count, status, evidence, resolved_by, resolved_at, updated_at) \
                     VALUES ($1, 'guardduty', $2, $3, $4, NULL, 'guardduty', $5, $6, $7, $8, $9, \
                             CASE WHEN $8 = 'resolved' THEN 'guardduty' ELSE NULL END, \
                             CASE WHEN $8 = 'resolved' THEN now() ELSE NULL END, now()) \
                     ON CONFLICT (fingerprint) DO UPDATE SET \
                       last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen), event_count = EXCLUDED.event_count, \
                       severity = EXCLUDED.severity, description = EXCLUDED.description, evidence = EXCLUDED.evidence, \
                       status = CASE \
                                  WHEN $8 = 'resolved' THEN 'resolved' \
                                  WHEN alerts.status = 'resolved' AND alerts.resolved_by IN ('auto','guardduty') THEN 'open' \
                                  ELSE alerts.status END, \
                       resolved_by = CASE \
                                  WHEN $8 = 'resolved' THEN COALESCE(alerts.resolved_by, 'guardduty') \
                                  WHEN alerts.status = 'resolved' AND alerts.resolved_by IN ('auto','guardduty') THEN NULL \
                                  ELSE alerts.resolved_by END, \
                       resolved_at = CASE \
                                  WHEN $8 = 'resolved' THEN COALESCE(alerts.resolved_at, now()) \
                                  WHEN alerts.status = 'resolved' AND alerts.resolved_by IN ('auto','guardduty') THEN NULL \
                                  ELSE alerts.resolved_at END, \
                       updated_at = now()",
                )
                .bind::<Text, _>(&r.fingerprint)
                .bind::<Text, _>(&r.severity)
                .bind::<Text, _>(&r.title)
                .bind::<Nullable<Text>, _>(r.description.as_ref())
                .bind::<Timestamptz, _>(r.first_seen)
                .bind::<Timestamptz, _>(r.last_seen)
                .bind::<BigInt, _>(r.event_count)
                .bind::<Text, _>(r.status)
                .bind::<diesel::sql_types::Jsonb, _>(&r.evidence)
                .execute(conn)
                .context("upsert guardduty alert")?;
            }
            Ok(())
        })
    })
    .await
    .context("join")??;
        applied += count;

        match page_token {
            Some(t) => next_token = Some(t),
            None => break,
        }
    }

    Ok((applied, max_updated_at))
}

struct FindingRow {
    fingerprint: String,
    severity: String,
    title: String,
    description: Option<String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    event_count: i64,
    status: &'static str,
    evidence: serde_json::Value,
}

/// GuardDuty severity (0–10) → our 3-tier label.
fn severity_label(s: f64) -> &'static str {
    if s >= 7.0 {
        "high"
    } else if s >= 4.0 {
        "medium"
    } else {
        "low"
    }
}

/// Resolve a finding's first/last seen from `service.event_first_seen/last_seen`
/// (ISO8601 strings), falling back to created/updated, then now.
fn finding_window(f: &aws_sdk_guardduty::types::Finding) -> (DateTime<Utc>, DateTime<Utc>) {
    let parse = |s: Option<&str>| {
        s.and_then(|x| DateTime::parse_from_rfc3339(x).ok())
            .map(|d| d.with_timezone(&Utc))
    };
    let svc = f.service();
    let first = parse(svc.and_then(|s| s.event_first_seen()))
        .or_else(|| parse(f.created_at()))
        .unwrap_or_else(Utc::now);
    let last = parse(svc.and_then(|s| s.event_last_seen()))
        .or_else(|| parse(f.updated_at()))
        .unwrap_or_else(Utc::now);
    (first, last)
}
