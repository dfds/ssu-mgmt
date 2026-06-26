use anyhow::Context;
use diesel::{Connection, RunQueryDsl};
use log::{error, info, warn};
use tokio_util::sync::CancellationToken;

use crate::db::DbPool;
use crate::misc::config::RetentionConfig;

struct PruneTarget {
    label: &'static str,
    sql: &'static str,
    days: i64,
}

pub async fn run(cancel: CancellationToken, conf: RetentionConfig, pool: DbPool) {
    let interval = std::time::Duration::from_secs(conf.interval_secs.max(60));
    info!(
        "retention prune worker starting :: interval={}s cloudtrail={}d github={}d selfservice={}d derived={}d ssumgmt={}d batch={}",
        interval.as_secs(),
        conf.cloudtrail_days,
        conf.github_days,
        conf.selfservice_days,
        conf.derived_days,
        conf.ssumgmt_days,
        conf.batch_size,
    );

    loop {
        sweep(&cancel, &conf, &pool).await;

        tokio::select! {
            _ = cancel.cancelled() => { info!("stopping retention prune worker"); break; }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

async fn sweep(cancel: &CancellationToken, conf: &RetentionConfig, pool: &DbPool) {
    let batch = conf.batch_size.max(1);
    let targets = [
        PruneTarget {
            label: "cloudtrail_events",
            sql: "DELETE FROM cloudtrail_events AS t USING ( \
                    SELECT ctid FROM cloudtrail_events \
                    WHERE event_time < now() - make_interval(days => $1::int) \
                    ORDER BY event_time LIMIT $2 \
                  ) c WHERE t.ctid = c.ctid",
            days: conf.cloudtrail_days,
        },
        PruneTarget {
            label: "github_audit_events",
            sql: "DELETE FROM github_audit_events AS t USING ( \
                    SELECT ctid FROM github_audit_events \
                    WHERE event_time < now() - make_interval(days => $1::int) \
                    ORDER BY event_time LIMIT $2 \
                  ) c WHERE t.ctid = c.ctid",
            days: conf.github_days,
        },
        PruneTarget {
            label: "audit_records_selfservice",
            sql: "DELETE FROM audit_records_selfservice AS t USING ( \
                    SELECT ctid FROM audit_records_selfservice \
                    WHERE \"timestamp\" < (now() AT TIME ZONE 'utc') - make_interval(days => $1::int) \
                    ORDER BY \"timestamp\" LIMIT $2 \
                  ) c WHERE t.ctid = c.ctid",
            days: conf.selfservice_days,
        },
        PruneTarget {
            label: "ssumgmt_audit",
            sql: "DELETE FROM ssumgmt_audit AS t USING ( \
                    SELECT ctid FROM ssumgmt_audit \
                    WHERE ts < now() - make_interval(days => $1::int) \
                    ORDER BY ts LIMIT $2 \
                  ) c WHERE t.ctid = c.ctid",
            days: conf.ssumgmt_days,
        },
        PruneTarget {
            label: "sessions",
            sql: "DELETE FROM sessions AS t USING ( \
                    SELECT ctid FROM sessions \
                    WHERE last_seen_at < now() - make_interval(days => $1::int) \
                    ORDER BY last_seen_at LIMIT $2 \
                  ) c WHERE t.ctid = c.ctid",
            days: conf.derived_days,
        },
        PruneTarget {
            label: "anomalies",
            sql: "DELETE FROM anomalies AS t USING ( \
                    SELECT ctid FROM anomalies \
                    WHERE event_time < now() - make_interval(days => $1::int) \
                    ORDER BY event_time LIMIT $2 \
                  ) c WHERE t.ctid = c.ctid",
            days: conf.derived_days,
        },
        PruneTarget {
            label: "alerts(resolved)",
            sql: "DELETE FROM alerts AS t USING ( \
                    SELECT ctid FROM alerts \
                    WHERE status = 'resolved' \
                      AND resolved_at < now() - make_interval(days => $1::int) \
                    ORDER BY resolved_at LIMIT $2 \
                  ) c WHERE t.ctid = c.ctid",
            days: conf.derived_days,
        },
    ];

    for target in targets {
        if cancel.is_cancelled() {
            break;
        }
        if target.days <= 0 {
            info!("retention: {} disabled (days={})", target.label, target.days);
            continue;
        }
        match prune(cancel, pool, &target, batch).await {
            Ok(0) => info!("retention: {} already within {}d window", target.label, target.days),
            Ok(n) => info!("retention: {} pruned {} rows older than {}d", target.label, n, target.days),
            Err(e) => error!("retention: {} prune failed: {:#}", target.label, e),
        }
    }
}

async fn prune(
    cancel: &CancellationToken,
    pool: &DbPool,
    target: &PruneTarget,
    batch: i64,
) -> anyhow::Result<i64> {
    let mut total = 0i64;
    loop {
        if cancel.is_cancelled() {
            warn!("retention: {} interrupted by shutdown after {} rows", target.label, total);
            break;
        }
        let pool = pool.clone();
        let sql = target.sql;
        let days = target.days;
        let deleted = tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
            let mut conn = pool.get().context("pool get")?;
            conn.transaction::<i64, anyhow::Error, _>(|conn| {
                diesel::sql_query("SET LOCAL statement_timeout = '60s'")
                    .execute(conn)
                    .context("set statement_timeout")?;
                let n = diesel::sql_query(sql)
                    .bind::<diesel::sql_types::BigInt, _>(days)
                    .bind::<diesel::sql_types::BigInt, _>(batch)
                    .execute(conn)
                    .context("prune chunk")? as i64;
                Ok(n)
            })
        })
        .await
        .context("join")??;

        if deleted == 0 {
            break;
        }
        total += deleted;
    }
    Ok(total)
}
