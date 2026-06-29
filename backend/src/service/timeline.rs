use anyhow::Context;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Text, Timestamptz};
use diesel::PgConnection;
use log::{error, info};
use tokio_util::sync::CancellationToken;

use crate::db::DbPool;
use crate::service::ingest::get_watermark;

const TIMELINE_WATERMARK_SOURCE: &str = "timeline_hourly";
const TIMELINE_SAFETY_MARGIN_MINS: i64 = 15;
const MAX_TIMELINE_STEP_HOURS: i64 = 3;

pub async fn run(cancel: CancellationToken, interval_secs: u64, pool: DbPool) {
    info!("timeline rollup maintainer started (interval={interval_secs}s)");
    let interval = std::time::Duration::from_secs(interval_secs.max(1));

    loop {
        maintain(&pool).await;

        tokio::select! {
            _ = cancel.cancelled() => {
                info!("timeline rollup maintainer stopping");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

#[tracing::instrument(name = "timeline.maintain", skip_all)]
async fn maintain(pool: &DbPool) {
    let pool = pool.clone();
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = crate::db::conn(&pool).map_err(anyhow::Error::from)?;
        maintain_blocking(&mut conn)
    })
    .await;

    match res {
        Ok(Ok(())) => info!("timeline rollup maintained"),
        Ok(Err(e)) => error!("timeline rollup maintenance failed: {e:#}"),
        Err(e) => error!("timeline rollup maintenance task join error: {e}"),
    }
}

fn maintain_blocking(conn: &mut PgConnection) -> anyhow::Result<()> {
    let now = Utc::now();
    let target = now - Duration::minutes(TIMELINE_SAFETY_MARGIN_MINS);

    let w = get_watermark(conn, TIMELINE_WATERMARK_SOURCE)
        .context("read timeline watermark")?
        .and_then(|wm| wm.last_event_at)
        .unwrap_or(target);
    let boundary = target.min(w + Duration::hours(MAX_TIMELINE_STEP_HOURS));

    conn.transaction::<_, anyhow::Error, _>(|conn| {
        diesel::sql_query(
            "INSERT INTO event_timeline_hourly (bucket, source, count) \
             SELECT bucket, source, count(*)::bigint FROM ( \
               SELECT date_trunc('hour', s.timestamp) AT TIME ZONE 'UTC' AS bucket, \
                      'selfservice'::text AS source \
                 FROM audit_records_selfservice s \
                 WHERE s.created_at > $1 AT TIME ZONE 'UTC' AND s.created_at <= $2 AT TIME ZONE 'UTC' \
               UNION ALL \
               SELECT date_trunc('hour', c.event_time AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', 'cloudtrail' \
                 FROM cloudtrail_events c WHERE c.created_at > $1 AND c.created_at <= $2 \
               UNION ALL \
               SELECT date_trunc('hour', g.event_time AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', 'github' \
                 FROM github_audit_events g WHERE g.created_at > $1 AND g.created_at <= $2 \
               UNION ALL \
               SELECT date_trunc('hour', a.ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', 'ssu-mgmt' \
                 FROM ssumgmt_audit a WHERE a.created_at > $1 AND a.created_at <= $2 \
             ) x GROUP BY bucket, source \
             ON CONFLICT (bucket, source) DO UPDATE SET \
               count = event_timeline_hourly.count + EXCLUDED.count",
        )
        .bind::<Timestamptz, _>(w)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("fold timeline rollup window")?;

        diesel::sql_query(
            "INSERT INTO ingest_watermarks \
               (source, last_event_at, last_run_at, objects_scanned, events_applied) \
             VALUES ($1, $2, now(), 0, 0) \
             ON CONFLICT (source) DO UPDATE SET \
               last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at), \
               last_run_at   = now()",
        )
        .bind::<Text, _>(TIMELINE_WATERMARK_SOURCE)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("advance timeline watermark")?;
        Ok(())
    })
}
