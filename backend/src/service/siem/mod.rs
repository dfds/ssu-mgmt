pub mod actors;
pub mod alerts;
pub mod anomalies;
pub mod geoip;
pub mod grants;
pub mod guardduty;
pub mod risk;
pub mod sessions;
pub mod travel;

use anyhow::Context;
use log::{error, info};
use tokio_util::sync::CancellationToken;

use crate::db::DbPool;
use crate::misc::config::Config;
use crate::service::ingest::{advance_watermark, record_run_error, SOURCE_SIEM};
use crate::service::siem::geoip::GeoIp;

/// Entry point: an initial pass, then recompute on the configured interval until
/// cancelled. Spawned onto the shared `async_worker` runtime.
pub async fn run(cancel: CancellationToken, conf: Config, pool: DbPool) {
    let geoip = GeoIp::load(&conf.geoip.db_path);
    let interval = std::time::Duration::from_secs(conf.siem.interval_secs.max(60));
    info!(
        "siem derivation starting :: interval={}s window_days={} geoip={} roster={}",
        interval.as_secs(),
        conf.siem.window_days,
        geoip.enabled(),
        !conf.selfservice.base_url.is_empty(),
    );

    loop {
        if let Err(e) = run_pass(&cancel, &conf, &pool, &geoip).await {
            error!("siem derivation pass failed: {:#}", e);
            let pool = pool.clone();
            let msg = format!("{:#}", e);
            let _ = tokio::task::spawn_blocking(move || {
                let mut conn = pool.get().context("pool get")?;
                record_run_error(&mut conn, SOURCE_SIEM, &msg).context("record error")
            })
            .await;
        }

        tokio::select! {
            _ = cancel.cancelled() => { info!("stopping siem derivation"); break; }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// One full derivation pass.
#[tracing::instrument(name = "siem.pass", skip_all, fields(window_days = conf.siem.window_days))]
async fn run_pass(
    cancel: &CancellationToken,
    conf: &Config,
    pool: &DbPool,
    geoip: &GeoIp,
) -> anyhow::Result<()> {
    let roster = actors::fetch_roster(&conf.selfservice).await;

    let pool = pool.clone();
    let conf = conf.clone();
    let geoip = geoip.clone();
    let cancel = cancel.clone();
    let pass_span = tracing::Span::current();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let _pass = pass_span.enter();
        let mut conn = pool.get().context("pool get")?;

        macro_rules! bail_if_cancelled {
            () => {
                if cancel.is_cancelled() {
                    info!("siem pass interrupted by shutdown — abandoning remaining stages");
                    return Ok(());
                }
            };
        }

        let n_actors = tracing::info_span!("siem.actors")
            .in_scope(|| actors::reconcile(&mut conn, &roster, conf.siem.window_days))
            .context("reconcile actors")?;
        bail_if_cancelled!();
        let n_grants = tracing::info_span!("siem.grants")
            .in_scope(|| grants::derive(&mut conn, conf.siem.window_days))
            .context("derive grants")?;
        bail_if_cancelled!();
        let n_sessions = tracing::info_span!("siem.sessions")
            .in_scope(|| sessions::derive(&mut conn, &geoip, conf.siem.window_days))
            .context("derive sessions")?;
        bail_if_cancelled!();
        // Anomalies feed the risk `w_anomalies` factor, so detect before scoring.
        let n_anomalies = tracing::info_span!("siem.anomalies")
            .in_scope(|| anomalies::detect(&mut conn, &conf.siem))
            .context("detect anomalies")?;
        bail_if_cancelled!();
        let n_risk = tracing::info_span!("siem.risk")
            .in_scope(|| risk::compute(&mut conn, &conf.risk, &conf.siem))
            .context("compute risk")?;
        bail_if_cancelled!();
        let n_alerts = tracing::info_span!("siem.alerts")
            .in_scope(|| alerts::evaluate(&mut conn, &conf.siem))
            .context("evaluate alerts")?;
        bail_if_cancelled!();
        // Impossible-travel is a geo-correlated alert; no-op without GeoLite2.
        let n_travel = tracing::info_span!("siem.travel")
            .in_scope(|| travel::detect(&mut conn, &geoip, &conf.siem))
            .context("detect impossible travel")?;

        info!(
            "siem pass complete :: actors={} grants={} sessions={} anomalies={} risk_scored={} alerts={} travel={}",
            n_actors, n_grants, n_sessions, n_anomalies, n_risk, n_alerts, n_travel
        );

        // Health/heartbeat row (also clears any prior error).
        advance_watermark(&mut conn, SOURCE_SIEM, None, None, None, n_actors as i64, n_alerts as i64)
            .context("advance siem watermark")?;
        Ok(())
    })
    .await
    .context("join")?
}
