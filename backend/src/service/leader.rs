use std::sync::Arc;

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Double, Text};
use log::{error, info, warn};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use crate::db::DbPool;
use crate::misc::config::Config;

const LEASE_SCOPE: &str = "worker-leader";

#[derive(QueryableByName)]
struct FenceRow {
    #[diesel(sql_type = BigInt)]
    fence_token: i64,
}

fn holder_id() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "local".to_owned());
    format!("{}-{}", host, std::process::id())
}

pub fn spawn(rt: Arc<Runtime>, conf: Config, pool: DbPool, global_cancel: CancellationToken) {
    if !conf.worker.leader_election {
        info!("worker leader election disabled — spawning singleton workers directly");
        spawn_singleton_workers(&rt, &conf, &pool, &global_cancel);
        return;
    }

    std::thread::spawn(move || election_loop(rt, conf, pool, global_cancel));
}

fn election_loop(rt: Arc<Runtime>, conf: Config, pool: DbPool, global_cancel: CancellationToken) {
    let me = holder_id();
    let ttl = conf.worker.lease_ttl_secs;
    let renew_secs = conf.worker.lease_renew_secs;
    let retry_secs = conf.worker.lease_retry_secs;
    info!(
        "worker leader election starting (holder={me}, ttl={ttl}s, renew={renew_secs}s, retry={retry_secs}s)"
    );

    loop {
        if global_cancel.is_cancelled() {
            return;
        }

        match try_acquire(&pool, &me, ttl) {
            Ok(Some(token)) => {
                info!("acquired worker lease (token={token}) — this replica is the worker leader");
                let leader_cancel = global_cancel.child_token();
                spawn_singleton_workers(&rt, &conf, &pool, &leader_cancel);

                loop {
                    if sleep_interruptible(&global_cancel, renew_secs) {
                        leader_cancel.cancel();
                        match release(&pool, &me, token) {
                            Ok(_) => info!("released worker lease on shutdown"),
                            Err(e) => warn!("failed to release worker lease on shutdown: {e:#}"),
                        }
                        return;
                    }
                    match renew(&pool, &me, token, ttl) {
                        Ok(true) => {} // still leader
                        Ok(false) => {
                            warn!("worker lease lost (superseded) — relinquishing workers");
                            leader_cancel.cancel();
                            break;
                        }
                        Err(e) => {
                            error!("worker lease renew failed: {e:#} — relinquishing workers");
                            leader_cancel.cancel();
                            break;
                        }
                    }
                }
                if sleep_interruptible(&global_cancel, retry_secs) {
                    return;
                }
            }
            Ok(None) => {
                if sleep_interruptible(&global_cancel, retry_secs) {
                    return;
                }
            }
            Err(e) => {
                error!("worker lease acquire failed: {e:#} — retrying in {retry_secs}s");
                if sleep_interruptible(&global_cancel, retry_secs) {
                    return;
                }
            }
        }
    }
}

fn spawn_singleton_workers(rt: &Arc<Runtime>, conf: &Config, pool: &DbPool, cancel: &CancellationToken) {
    if conf.enable_cloudtrail_ingest {
        info!("CloudTrail ingest enabled");
        rt.spawn(crate::service::ingest::cloudtrail::run(
            cancel.clone(),
            conf.cloudtrail.clone(),
            pool.clone(),
        ));
        rt.spawn(crate::service::ingest::cloudtrail::backfill_identity(
            cancel.clone(),
            pool.clone(),
        ));
    } else {
        info!("CloudTrail ingest disabled");
    }

    if conf.enable_github_ingest {
        info!("GitHub ingest enabled");
        rt.spawn(crate::service::ingest::github::run(
            cancel.clone(),
            conf.github.clone(),
            pool.clone(),
        ));
    } else {
        info!("GitHub ingest disabled");
    }

    if conf.enable_github_s3_ingest {
        info!("GitHub S3 ingest enabled");
        rt.spawn(crate::service::ingest::github_s3::run(
            cancel.clone(),
            conf.github_s3.clone(),
            pool.clone(),
        ));
    } else {
        info!("GitHub S3 ingest disabled");
    }

    if conf.enable_siem_derivation {
        info!("SIEM derivation enabled");
        rt.spawn(crate::service::siem::run(
            cancel.clone(),
            conf.clone(),
            pool.clone(),
        ));
    } else {
        info!("SIEM derivation disabled");
    }

    if conf.enable_guardduty {
        info!("GuardDuty ingest enabled");
        rt.spawn(crate::service::siem::guardduty::run(
            cancel.clone(),
            conf.guardduty.clone(),
            pool.clone(),
        ));
    } else {
        info!("GuardDuty ingest disabled");
    }

    if conf.enable_retention {
        info!("Retention prune enabled");
        rt.spawn(crate::service::retention::run(
            cancel.clone(),
            conf.retention.clone(),
            pool.clone(),
        ));
    } else {
        info!("Retention prune disabled");
    }

    rt.spawn(crate::service::timeline::run(
        cancel.clone(),
        conf.timeline.rollup_interval_secs,
        pool.clone(),
    ));
}

fn try_acquire(pool: &DbPool, holder: &str, ttl_secs: u64) -> Result<Option<i64>> {
    const SQL: &str = "\
        INSERT INTO leader_leases AS l (scope, holder_id, fence_token, acquired_at, renewed_at, expires_at) \
        VALUES ($1, $2, 1, now(), now(), now() + ($3 * interval '1 second')) \
        ON CONFLICT (scope) DO UPDATE SET \
          holder_id = EXCLUDED.holder_id, \
          fence_token = l.fence_token + 1, \
          acquired_at = now(), \
          renewed_at = now(), \
          expires_at = now() + ($3 * interval '1 second') \
        WHERE l.expires_at < now() OR l.holder_id = EXCLUDED.holder_id \
        RETURNING fence_token";
    let mut conn = pool.get().context("pool get")?;
    let rows: Vec<FenceRow> = diesel::sql_query(SQL)
        .bind::<Text, _>(LEASE_SCOPE)
        .bind::<Text, _>(holder)
        .bind::<Double, _>(ttl_secs as f64)
        .get_results(&mut conn)
        .context("lease acquire")?;
    Ok(rows.into_iter().next().map(|r| r.fence_token))
}

fn renew(pool: &DbPool, holder: &str, token: i64, ttl_secs: u64) -> Result<bool> {
    const SQL: &str = "\
        UPDATE leader_leases SET renewed_at = now(), expires_at = now() + ($3 * interval '1 second') \
        WHERE scope = $1 AND holder_id = $2 AND fence_token = $4 \
        RETURNING fence_token";
    let mut conn = pool.get().context("pool get")?;
    let rows: Vec<FenceRow> = diesel::sql_query(SQL)
        .bind::<Text, _>(LEASE_SCOPE)
        .bind::<Text, _>(holder)
        .bind::<Double, _>(ttl_secs as f64)
        .bind::<BigInt, _>(token)
        .get_results(&mut conn)
        .context("lease renew")?;
    Ok(!rows.is_empty())
}

fn release(pool: &DbPool, holder: &str, token: i64) -> Result<()> {
    const SQL: &str =
        "DELETE FROM leader_leases WHERE scope = $1 AND holder_id = $2 AND fence_token = $3";
    let mut conn = pool.get().context("pool get")?;
    diesel::sql_query(SQL)
        .bind::<Text, _>(LEASE_SCOPE)
        .bind::<Text, _>(holder)
        .bind::<BigInt, _>(token)
        .execute(&mut conn)
        .context("lease release")?;
    Ok(())
}

fn sleep_interruptible(cancel: &CancellationToken, secs: u64) -> bool {
    for _ in 0..secs {
        if cancel.is_cancelled() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    cancel.is_cancelled()
}
