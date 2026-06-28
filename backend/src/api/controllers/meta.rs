use crate::misc::config::load_conf;
use crate::service::siem::anomalies::{
    DAILY_COUNTS_SAFETY_MARGIN_MINS, IDENTITY_CONTEXT_WATERMARK_LAG_MINS,
};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

#[derive(Serialize)]
struct CacheClass {
    /// How often the backing cache/derived table is recomputed.
    refresh_secs: u64,
    /// Worst-case lag behind live (refresh cadence + any watermark margin).
    max_stale_secs: u64,
}

#[derive(Serialize)]
struct CacheMeta {
    siem_interval_secs: u64,
    timeline_rollup_secs: u64,
    guardduty_interval_secs: u64,
    /// Keyed by the `CacheClass` strings the frontend's `<CacheBadge kind>` uses.
    caches: std::collections::BTreeMap<&'static str, CacheClass>,
}

pub fn routes() -> Router {
    Router::new().route("/", get(handler))
}

async fn handler() -> Json<CacheMeta> {
    let conf = load_conf().unwrap();
    let siem = conf.siem.interval_secs.max(60);
    let timeline = conf.timeline.rollup_interval_secs;
    let guardduty = conf.guardduty.interval_secs;
    let daily_margin = DAILY_COUNTS_SAFETY_MARGIN_MINS as u64 * 60;
    let identity_margin = IDENTITY_CONTEXT_WATERMARK_LAG_MINS as u64 * 60;

    let mut caches = std::collections::BTreeMap::new();
    caches.insert(
        "siem",
        CacheClass {
            refresh_secs: siem,
            max_stale_secs: siem,
        },
    );
    caches.insert(
        "entity_stats",
        CacheClass {
            refresh_secs: siem,
            max_stale_secs: siem + daily_margin,
        },
    );
    caches.insert(
        "identity_context",
        CacheClass {
            refresh_secs: siem,
            max_stale_secs: siem + identity_margin,
        },
    );
    caches.insert(
        "timeline",
        CacheClass {
            refresh_secs: timeline,
            max_stale_secs: timeline,
        },
    );
    caches.insert(
        "guardduty",
        CacheClass {
            refresh_secs: guardduty,
            max_stale_secs: guardduty,
        },
    );

    Json(CacheMeta {
        siem_interval_secs: siem,
        timeline_rollup_secs: timeline,
        guardduty_interval_secs: guardduty,
        caches,
    })
}
