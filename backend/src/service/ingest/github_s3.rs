use anyhow::Context;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::Client;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use flate2::read::GzDecoder;
use futures::stream::{self, StreamExt};
use log::{error, info, warn};
use serde_json::Value;
use std::io::Read;
use tokio_util::sync::CancellationToken;

use crate::db::model::GithubAuditEventInsert;
use crate::db::DbPool;
use crate::misc::config::GithubS3Config;
use crate::service::ingest::github::map_entry;
use crate::service::ingest::{
    advance_watermark, get_watermark, record_run_error, SOURCE_GITHUB_S3,
};

const STALL_WARN_AFTER_SWEEPS: u32 = 3;

pub async fn run(cancel: CancellationToken, conf: GithubS3Config, pool: DbPool) {
    if conf.bucket.is_empty() {
        error!("github-s3 ingest enabled but bucket unset — not starting");
        return;
    }

    let shared = {
        let base = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(conf.region.clone()));
        if conf.assume_role_arn.is_empty() {
            base.load().await
        } else {
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

    let interval = std::time::Duration::from_secs(conf.poll_interval_secs.max(30));
    info!(
        "github-s3 ingest starting :: bucket={} prefix={} interval={}s assume_role={}",
        conf.bucket,
        conf.prefix,
        interval.as_secs(),
        if conf.assume_role_arn.is_empty() {
            "none"
        } else {
            conf.assume_role_arn.as_str()
        }
    );

    let mut consecutive_failures: u32 = 0;
    loop {
        info!(
            "github-s3 sweep starting :: bucket={} prefix={}",
            conf.bucket, conf.prefix
        );
        match run_once(&client, &conf, &pool).await {
            Ok(()) => consecutive_failures = 0,
            Err(e) => {
                consecutive_failures += 1;
                error!(
                    "github-s3 sweep failed (consecutive={}): {:#}",
                    consecutive_failures, e
                );
                if consecutive_failures == STALL_WARN_AFTER_SWEEPS {
                    warn!(
                        "github-s3 ingest stalled: {} consecutive failed sweeps — console shows 'stalled'; last error: {:#}",
                        consecutive_failures, e
                    );
                }
                let pool = pool.clone();
                let msg = format!("{:#}", e);
                let _ = tokio::task::spawn_blocking(move || {
                    let mut conn = pool.get().context("pool get")?;
                    record_run_error(&mut conn, SOURCE_GITHUB_S3, &msg).context("record error")
                })
                .await;
            }
        }

        tokio::select! {
            _ = cancel.cancelled() => { info!("stopping github-s3 ingest"); break; }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

#[tracing::instrument(name = "github_s3.sweep", skip_all)]
async fn run_once(client: &Client, conf: &GithubS3Config, pool: &DbPool) -> anyhow::Result<()> {
    let start_after = load_cursor(pool).await?;

    let prefix = conf.prefix.trim_start_matches('/');
    let mut keys = list_objects(client, &conf.bucket, prefix, start_after.as_deref()).await?;
    keys.sort();
    // Skip GitHub's connectivity-probe marker objects (`.../_check`).
    keys.retain(|k| !is_marker_key(k));
    if keys.is_empty() {
        return Ok(());
    }

    // Backfill throttle: bound how many objects a single sweep downloads.
    if conf.max_objects_per_run > 0 {
        keys.truncate(conf.max_objects_per_run as usize);
    }

    let (events, cursor, max_event_at, scanned) =
        fetch_keys(client, &conf.bucket, &keys, conf.workers).await;
    if events.is_empty() && cursor.is_none() {
        return Ok(());
    }

    let applied = commit(pool, events, cursor.clone(), max_event_at, scanned as i64).await?;
    info!(
        "github-s3 sweep complete :: objects={} events_applied={} cursor={}",
        scanned,
        applied,
        cursor.as_deref().unwrap_or("-")
    );
    Ok(())
}

async fn list_objects(
    client: &Client,
    bucket: &str,
    prefix: &str,
    start_after: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut req = client.list_objects_v2().bucket(bucket);
        if !prefix.is_empty() {
            req = req.prefix(prefix);
        }
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

async fn fetch_keys(
    client: &Client,
    bucket: &str,
    keys: &[String],
    workers: usize,
) -> (
    Vec<GithubAuditEventInsert>,
    Option<String>,
    Option<DateTime<Utc>>,
    usize,
) {
    let results: Vec<(String, anyhow::Result<Vec<GithubAuditEventInsert>>)> =
        stream::iter(keys.to_vec())
            .map(|key| {
                let client = client.clone();
                let bucket = bucket.to_string();
                async move {
                    let r = fetch_object(&client, &bucket, &key).await;
                    (key, r)
                }
            })
            .buffer_unordered(workers.max(1))
            .collect()
            .await;

    let mut by_key: std::collections::HashMap<String, anyhow::Result<Vec<GithubAuditEventInsert>>> =
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
                    "github-s3 object {} failed, halting sweep at last good key: {:#}",
                    key, e
                );
                break;
            }
            None => break,
        }
    }
    (events, cursor, max_event_at, scanned)
}

async fn fetch_object(
    client: &Client,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Vec<GithubAuditEventInsert>> {
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
        .into_bytes();

    let text = if is_gzipped(key) {
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut s = String::new();
        if let Err(e) = decoder.read_to_string(&mut s) {
            warn!("skipping undecodable github-s3 object {}: {}", key, e);
            return Ok(Vec::new());
        }
        s
    } else {
        match String::from_utf8(bytes.to_vec()) {
            Ok(s) => s,
            Err(e) => {
                warn!("skipping non-utf8 github-s3 object {}: {}", key, e);
                return Ok(Vec::new());
            }
        }
    };

    let mut out = Vec::new();
    let mut parsed_any = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        parsed_any = true;
        if let Some(row) = map_entry(&entry) {
            out.push(row);
        }
    }

    // Fallback: a whole-blob JSON array rather than NDJSON.
    if !parsed_any {
        if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(text.trim()) {
            for entry in &arr {
                if let Some(row) = map_entry(entry) {
                    out.push(row);
                }
            }
        }
    }

    Ok(out)
}

fn is_gzipped(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.ends_with(".gz") || lower.ends_with(".gzip")
}

fn is_marker_key(key: &str) -> bool {
    let base = key.rsplit('/').next().unwrap_or(key);
    base == "_check"
}

// ---- watermark / cursor persistence ---------------------------------------

async fn load_cursor(pool: &DbPool) -> anyhow::Result<Option<String>> {
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<Option<String>> {
        let mut conn = pool.get().context("pool get")?;
        let wm = get_watermark(&mut conn, SOURCE_GITHUB_S3).context("get watermark")?;
        Ok(wm.and_then(|w| w.last_object_key))
    })
    .await
    .context("join")?
}

async fn commit(
    pool: &DbPool,
    events: Vec<GithubAuditEventInsert>,
    cursor: Option<String>,
    max_event_at: Option<DateTime<Utc>>,
    objects: i64,
) -> anyhow::Result<i64> {
    let pool = pool.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
        let mut conn = pool.get().context("pool get")?;
        let mut applied = 0i64;
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            for chunk in events.chunks(4000) {
                applied += diesel::insert_into(crate::schema::github_audit_events::table)
                    .values(chunk)
                    .on_conflict_do_nothing()
                    .execute(conn)
                    .context("insert github_audit_events")? as i64;
            }
            advance_watermark(
                conn,
                SOURCE_GITHUB_S3,
                cursor,
                max_event_at,
                None,
                objects,
                applied,
            )
            .context("advance watermark")?;
            Ok(())
        })?;
        Ok(applied)
    })
    .await
    .context("join")?
}
