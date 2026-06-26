use diesel::RunQueryDsl;
use log::{error, info};
use tokio_util::sync::CancellationToken;

use crate::db::DbPool;

/// Run the refresh loop until cancelled. Refreshes once on startup, then every
/// `interval_secs`.
pub async fn run(cancel: CancellationToken, interval_secs: u64, pool: DbPool) {
    info!("timeline rollup refresher started (interval={interval_secs}s)");
    let interval = std::time::Duration::from_secs(interval_secs.max(1));

    loop {
        refresh(&pool).await;

        tokio::select! {
            _ = cancel.cancelled() => {
                info!("timeline rollup refresher stopping");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// One concurrent refresh, off the async runtime (it's a blocking pooled query).
#[tracing::instrument(name = "timeline.refresh", skip_all)]
async fn refresh(pool: &DbPool) {
    let pool = pool.clone();
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<()> {
        let mut conn = pool.get().map_err(|e| {
            diesel::result::Error::QueryBuilderError(Box::new(std::io::Error::other(e.to_string())))
        })?;
        diesel::sql_query("REFRESH MATERIALIZED VIEW CONCURRENTLY event_timeline_daily")
            .execute(&mut conn)?;
        Ok(())
    })
    .await;

    match res {
        Ok(Ok(())) => info!("timeline rollup refreshed"),
        Ok(Err(e)) => error!("timeline rollup refresh failed: {e}"),
        Err(e) => error!("timeline rollup refresh task join error: {e}"),
    }
}
