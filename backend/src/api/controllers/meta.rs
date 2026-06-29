use crate::db::DbPool;
use crate::misc::config::load_conf;
use crate::service::ingest::get_watermark;
use crate::service::siem::anomalies::{
    DAILY_COUNTS_SAFETY_MARGIN_MINS, DAILY_COUNTS_WATERMARK_SOURCE, FIRST_SEEN_WATERMARK_SOURCE,
    IDENTITY_CONTEXT_WATERMARK_LAG_MINS, IDENTITY_CONTEXT_WATERMARK_SOURCE,
};
use crate::service::siem::sessions::SESSIONS_WATERMARK_SOURCE;
use crate::service::timeline::TIMELINE_WATERMARK_SOURCE;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use diesel::PgConnection;
use serde::Serialize;

#[derive(Serialize)]
struct WatermarkLag {
    label: &'static str,
    last_event_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct CacheClass {
    /// How often the backing cache/derived table is recomputed.
    refresh_secs: u64,
    /// Worst-case lag behind live (refresh cadence + any watermark margin).
    max_stale_secs: u64,
    /// Live `last_event_at` of the backing watermark(s); the frontend turns these
    /// into a current-lag line. Empty for caches with no watermark (e.g. guardduty).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    watermarks: Vec<WatermarkLag>,
}

#[derive(Serialize)]
struct CacheMeta {
    siem_interval_secs: u64,
    timeline_rollup_secs: u64,
    guardduty_interval_secs: u64,
    /// Keyed by the `CacheClass` strings the frontend's `<CacheBadge kind>` uses.
    caches: std::collections::BTreeMap<&'static str, CacheClass>,
}

pub fn routes(pool: DbPool) -> Router {
    Router::new().route("/", get(handler)).with_state(pool)
}

#[derive(Default)]
struct WmSnapshot {
    first_seen: Option<DateTime<Utc>>,
    daily_counts: Option<DateTime<Utc>>,
    sessions: Option<DateTime<Utc>>,
    identity_context: Option<DateTime<Utc>>,
    timeline: Option<DateTime<Utc>>,
}

fn read_watermarks(conn: &mut PgConnection) -> WmSnapshot {
    let at = |conn: &mut PgConnection, src: &str| {
        get_watermark(conn, src)
            .ok()
            .flatten()
            .and_then(|w| w.last_event_at)
    };
    WmSnapshot {
        first_seen: at(conn, FIRST_SEEN_WATERMARK_SOURCE),
        daily_counts: at(conn, DAILY_COUNTS_WATERMARK_SOURCE),
        sessions: at(conn, SESSIONS_WATERMARK_SOURCE),
        identity_context: at(conn, IDENTITY_CONTEXT_WATERMARK_SOURCE),
        timeline: at(conn, TIMELINE_WATERMARK_SOURCE),
    }
}

async fn handler(State(pool): State<DbPool>) -> Json<CacheMeta> {
    let conf = load_conf().unwrap();
    let siem = conf.siem.interval_secs.max(60);
    let timeline = conf.timeline.rollup_interval_secs;
    let guardduty = conf.guardduty.interval_secs;
    let daily_margin = DAILY_COUNTS_SAFETY_MARGIN_MINS as u64 * 60;
    let identity_margin = IDENTITY_CONTEXT_WATERMARK_LAG_MINS as u64 * 60;

    let wm = tokio::task::spawn_blocking(move || {
        crate::db::conn(&pool)
            .map(|mut conn| read_watermarks(&mut conn))
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();

    let mut caches = std::collections::BTreeMap::new();
    caches.insert(
        "siem",
        CacheClass {
            refresh_secs: siem,
            max_stale_secs: siem,
            watermarks: vec![
                WatermarkLag {
                    label: "first-seen",
                    last_event_at: wm.first_seen,
                },
                WatermarkLag {
                    label: "daily-counts",
                    last_event_at: wm.daily_counts,
                },
                WatermarkLag {
                    label: "sessions",
                    last_event_at: wm.sessions,
                },
            ],
        },
    );
    caches.insert(
        "entity_stats",
        CacheClass {
            refresh_secs: siem,
            max_stale_secs: siem + daily_margin,
            watermarks: vec![WatermarkLag {
                label: "live",
                last_event_at: wm.daily_counts,
            }],
        },
    );
    caches.insert(
        "identity_context",
        CacheClass {
            refresh_secs: siem,
            max_stale_secs: siem + identity_margin,
            watermarks: vec![WatermarkLag {
                label: "live",
                last_event_at: wm.identity_context,
            }],
        },
    );
    caches.insert(
        "timeline",
        CacheClass {
            refresh_secs: timeline,
            max_stale_secs: timeline,
            watermarks: vec![WatermarkLag {
                label: "live",
                last_event_at: wm.timeline,
            }],
        },
    );
    caches.insert(
        "guardduty",
        CacheClass {
            refresh_secs: guardduty,
            max_stale_secs: guardduty,
            watermarks: vec![],
        },
    );

    Json(CacheMeta {
        siem_interval_secs: siem,
        timeline_rollup_secs: timeline,
        guardduty_interval_secs: guardduty,
        caches,
    })
}
