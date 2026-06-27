use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use axum_extra::extract::Query;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Nullable, Text, Timestamptz};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::model::{Alert, Anomaly, IngestHealth};
use crate::db::DbPool;

pub fn routes(pool: DbPool) -> Router {
    Router::new()
        .route("/timeline", axum::routing::get(timeline_handler))
        .route("/ingest-health", axum::routing::get(ingest_health_handler))
        .route("/kpis", axum::routing::get(kpis_handler))
        .route("/alerts", axum::routing::get(alerts_handler))
        .route("/anomalies", axum::routing::get(anomalies_handler))
        .route("/sources", axum::routing::get(sources_handler))
        .route(
            "/actors-by-risk",
            axum::routing::get(actors_by_risk_handler),
        )
        .with_state(pool)
}

// --- KPIs ------------------------------------------------------------------

#[derive(QueryableByName)]
struct KpiRow {
    #[diesel(sql_type = BigInt)]
    failed_auth_24h: i64,
    #[diesel(sql_type = BigInt)]
    deactivated_24h: i64,
    #[diesel(sql_type = BigInt)]
    critical_alerts: i64,
    #[diesel(sql_type = BigInt)]
    open_alerts: i64,
    #[diesel(sql_type = BigInt)]
    actors_tracked: i64,
    #[diesel(sql_type = BigInt)]
    high_risk_actors: i64,
    #[diesel(sql_type = BigInt)]
    active_sessions: i64,
    #[diesel(sql_type = BigInt)]
    guardduty_open: i64,
    #[diesel(sql_type = BigInt)]
    anomalies_24h: i64,
}

/// Build the overview KPI payload on a pooled connection. Shared by the HTTP
/// handler and the WebSocket progress push so the tile shapes stay in one place.
/// `guardduty` is `null` ("no data") unless the GuardDuty ingester has run
/// cleanly — never a fabricated zero.
pub(crate) fn load_kpis(conn: &mut PgConnection) -> anyhow::Result<serde_json::Value> {
    let since = Utc::now() - Duration::hours(24);
    let k: KpiRow = diesel::sql_query(
        "SELECT \
           (  (SELECT count(*) FROM cloudtrail_events WHERE error_code IS NOT NULL AND event_time >= $1) \
            + (SELECT count(*) FROM ssumgmt_audit WHERE status = 'failure' AND ts >= $1)) AS failed_auth_24h, \
           (SELECT count(*) FROM cloudtrail_events WHERE event_name IN ('DeleteUser','DeleteLoginProfile','DeactivateMFADevice') AND event_time >= $1) AS deactivated_24h, \
           (SELECT count(*) FROM alerts WHERE status IN ('open','acked') AND severity = 'critical') AS critical_alerts, \
           (SELECT count(*) FROM alerts WHERE status = 'open') AS open_alerts, \
           (SELECT count(*) FROM actors) AS actors_tracked, \
           (SELECT count(*) FROM risk_scores WHERE score >= 60) AS high_risk_actors, \
           (SELECT count(*) FROM sessions WHERE status = 'active') AS active_sessions, \
           (SELECT count(*) FROM alerts WHERE source = 'guardduty' AND status IN ('open','acked')) AS guardduty_open, \
           (SELECT count(*) FROM anomalies WHERE event_time >= $1) AS anomalies_24h",
    )
    .bind::<Timestamptz, _>(since)
    .get_result(conn)?;

    let gd_available: i64 = diesel::sql_query(
        "SELECT count(*) AS n FROM ingest_watermarks WHERE source = 'guardduty' AND last_run_at IS NOT NULL AND last_run_error IS NULL",
    )
    .get_result::<CountRow>(conn)?
    .n;

    Ok(json!({
        "failed_auth_24h": k.failed_auth_24h,
        "deactivated_24h": k.deactivated_24h,
        "guardduty": if gd_available > 0 { json!(k.guardduty_open) } else { json!(null) },
        "anomalies": k.anomalies_24h,
        "critical_alerts": k.critical_alerts,
        "open_alerts": k.open_alerts,
        "actors_tracked": k.actors_tracked,
        "high_risk_actors": k.high_risk_actors,
        "active_sessions": k.active_sessions,
    }))
}

/// Overview KPI tiles. `guardduty` is `null` ("no data") unless the GuardDuty
/// ingester has actually run cleanly — never a fabricated zero. `anomalies/24h`
/// is now live.
async fn kpis_handler(State(pool): State<DbPool>) -> Response {
    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "overview.kpis"
    );
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let _g = span.enter();
        let mut conn = pool.get()?;
        load_kpis(&mut conn)
    })
    .await;

    match res {
        Ok(Ok(payload)) => Json(payload).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {}", e),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    n: i64,
}

// --- Alerts feed -----------------------------------------------------------

#[derive(Deserialize)]
pub struct AlertsParams {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Paginated alerts response: the requested page of rows plus the total count of
/// rows matching the same facets (so the console can render "X–Y of Z").
#[derive(Serialize)]
pub struct AlertsResponse {
    pub rows: Vec<Alert>,
    pub total: i64,
}

/// Load the most recent alerts (newest by `last_seen`), unfiltered. Shared by the
/// WebSocket progress push; the HTTP handler adds optional severity/status facets.
pub(crate) fn load_overview_alerts(
    conn: &mut PgConnection,
    limit: i64,
) -> diesel::QueryResult<Vec<Alert>> {
    use crate::schema::alerts::dsl as a;
    a::alerts
        .order(a::last_seen.desc())
        .limit(limit)
        .select(Alert::as_select())
        .load(conn)
}

async fn alerts_handler(
    State(pool): State<DbPool>,
    Query(params): Query<AlertsParams>,
) -> Response {
    use crate::schema::alerts::dsl as a;
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0).max(0);
    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "overview.alerts"
    );
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<AlertsResponse> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;

        // The page of rows (newest-first, limit/offset).
        let mut q = a::alerts.into_boxed();
        if let Some(s) = &params.severity {
            q = q.filter(a::severity.eq(s.clone()));
        }
        if let Some(s) = &params.status {
            q = q.filter(a::status.eq(s.clone()));
        }
        let rows = q
            .order(a::last_seen.desc())
            .limit(limit)
            .offset(offset)
            .select(Alert::as_select())
            .load(&mut conn)?;

        // The total under the same facets (unaffected by limit/offset).
        let mut cq = a::alerts.into_boxed();
        if let Some(s) = &params.severity {
            cq = cq.filter(a::severity.eq(s.clone()));
        }
        if let Some(s) = &params.status {
            cq = cq.filter(a::status.eq(s.clone()));
        }
        let total: i64 = cq.count().get_result(&mut conn)?;

        Ok(AlertsResponse { rows, total })
    })
    .await;

    match res {
        Ok(Ok(resp)) => Json(resp).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {}", e),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}

// --- Anomalies feed / timeline markers -------------------------------------

#[derive(Deserialize)]
pub struct AnomaliesParams {
    pub kind: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<i64>,
}

/// Anomalies in a window, newest first. Backs both the overview anomaly feed and
/// the timeline markers (each row carries `event_time` for x-positioning).
/// Defaults to the trailing 24h when no `from` is given.
async fn anomalies_handler(
    State(pool): State<DbPool>,
    Query(params): Query<AnomaliesParams>,
) -> Response {
    use crate::schema::anomalies::dsl as an;
    let limit = params.limit.unwrap_or(200).clamp(1, 1000);
    let from = match params.from.as_deref().map(parse_ts).transpose() {
        Ok(v) => v.unwrap_or_else(|| Utc::now() - Duration::hours(24)),
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let to = match params.to.as_deref().map(parse_ts).transpose() {
        Ok(v) => v.unwrap_or_else(Utc::now),
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "overview.anomalies"
    );
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<Vec<Anomaly>> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;
        let mut q = an::anomalies
            .filter(an::event_time.ge(from))
            .filter(an::event_time.le(to))
            .into_boxed();
        if let Some(k) = params.kind {
            q = q.filter(an::kind.eq(k));
        }
        q.order(an::event_time.desc())
            .limit(limit)
            .select(Anomaly::as_select())
            .load(&mut conn)
    })
    .await;

    match res {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {}", e),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}

// --- Sources breakdown -----------------------------------------------------

#[derive(QueryableByName, Serialize)]
struct SourceRow {
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = BigInt)]
    total: i64,
    #[diesel(sql_type = BigInt)]
    failures: i64,
}

/// Per-source event volume + failure count over the trailing 7 days, backing the
/// overview "sources breakdown + fail rate" panel.
async fn sources_handler(State(pool): State<DbPool>) -> Response {
    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "overview.sources",
        db.statement = tracing::field::Empty
    );
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<Vec<SourceRow>> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;
        let since = Utc::now() - Duration::days(7);
        let sources_sql = "SELECT source, count(*) AS total, count(*) FILTER (WHERE status = 'failure') AS failures \
             FROM ssumgmt_events WHERE ts >= $1 GROUP BY source ORDER BY total DESC";
        span.record("db.statement", sources_sql);
        diesel::sql_query(sources_sql)
        .bind::<Timestamptz, _>(since)
        .load(&mut conn)
    })
    .await;

    match res {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {}", e),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}

// --- Actors by risk --------------------------------------------------------

#[derive(Deserialize)]
pub struct ActorsByRiskParams {
    pub limit: Option<i64>,
}

#[derive(QueryableByName, Serialize)]
struct ActorRiskRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    email: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    team: Option<String>,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Array<Nullable<Text>>)]
    origins: Vec<Option<String>>,
    #[diesel(sql_type = Array<Nullable<Text>>)]
    sources: Vec<Option<String>>,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    score: i32,
    #[diesel(sql_type = Text)]
    label: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_active: Option<DateTime<Utc>>,
}

async fn actors_by_risk_handler(
    State(pool): State<DbPool>,
    Query(params): Query<ActorsByRiskParams>,
) -> Response {
    let limit = params.limit.unwrap_or(10).clamp(1, 100);
    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "overview.actors_by_risk",
        db.statement = tracing::field::Empty
    );
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<Vec<ActorRiskRow>> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;
        let actors_sql = "SELECT a.id, a.display_name, a.email, a.team, a.kind, a.origins, a.sources, r.score, r.label, a.last_active \
             FROM risk_scores r JOIN actors a ON a.id = r.actor_id \
             ORDER BY r.score DESC, a.last_active DESC NULLS LAST LIMIT $1";
        span.record("db.statement", actors_sql);
        diesel::sql_query(actors_sql)
        .bind::<BigInt, _>(limit)
        .load(&mut conn)
    })
    .await;

    match res {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {}", e),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}

/// Load every source's ingest-health row, ordered by source. Shared by the
/// WebSocket progress push.
pub(crate) fn load_ingest_health(
    conn: &mut PgConnection,
) -> diesel::QueryResult<Vec<IngestHealth>> {
    use crate::schema::ingest_watermarks::dsl as w;
    w::ingest_watermarks
        .order(w::source.asc())
        .select(IngestHealth::as_select())
        .load(conn)
}

/// Per-source ingest-health — the `ingest_watermarks` rows, surfaced in the
/// console header as freshness/stall indicators.
async fn ingest_health_handler(State(pool): State<DbPool>) -> Response {
    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "overview.ingest_health"
    );
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<Vec<IngestHealth>> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;
        load_ingest_health(&mut conn)
    })
    .await;

    match res {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {}", e),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct TimelineParams {
    /// Bucket granularity: `minute`, `hour`, or `day`. Defaults to `hour`.
    pub bucket: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(QueryableByName, Serialize)]
struct TimelineRow {
    #[diesel(sql_type = Timestamptz)]
    bucket: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(Serialize)]
struct TimelineResponse {
    bucket: String,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    rows: Vec<TimelineRow>,
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .map(|n| DateTime::from_naive_utc_and_offset(n, Utc))
        })
        .map_err(|e| format!("invalid timestamp {}: {}", s, e))
}

async fn timeline_handler(
    State(pool): State<DbPool>,
    Query(params): Query<TimelineParams>,
) -> Response {
    // Allowlist the bucket granularity — it is interpolated into date_trunc, so
    // it must never be attacker-controlled free text.
    let bucket = match params.bucket.as_deref().unwrap_or("hour") {
        b @ ("minute" | "hour" | "day") => b.to_owned(),
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid bucket: {}", other),
            )
                .into_response()
        }
    };

    let now = Utc::now();
    let from = match params.from.as_deref().map(parse_ts).transpose() {
        Ok(v) => v.unwrap_or(now - Duration::hours(24)),
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let to = match params.to.as_deref().map(parse_ts).transpose() {
        Ok(v) => v.unwrap_or(now),
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let bucket_for_query = bucket.clone();
    let span = tracing::info_span!("db.query", otel.kind = "client", db.system = "postgresql", op ="overview.timeline", bucket = %bucket, db.statement = tracing::field::Empty);
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<Vec<TimelineRow>> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;
        const ROLLUP_HOUR_THRESHOLD: i64 = 48;
        if bucket_for_query == "day" {
            let day_sql = "SELECT bucket, source, count \
                 FROM event_timeline_daily \
                 WHERE bucket >= date_trunc('day', $1 AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' \
                   AND bucket <= $2 \
                 ORDER BY bucket ASC";
            span.record("db.statement", day_sql);
            diesel::sql_query(day_sql)
                .bind::<Timestamptz, _>(from)
                .bind::<Timestamptz, _>(to)
                .load::<TimelineRow>(&mut conn)
        } else if bucket_for_query == "hour"
            && (to - from) > Duration::hours(ROLLUP_HOUR_THRESHOLD)
        {
            // Wide hour windows (7d) read the hourly rollup — ~168 pre-aggregated
            // rows per source instead of a ~4s live aggregate over the union view.
            let hour_sql = "SELECT bucket, source, count \
                 FROM event_timeline_hourly \
                 WHERE bucket >= date_trunc('hour', $1 AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' \
                   AND bucket <= $2 \
                 ORDER BY bucket ASC";
            span.record("db.statement", hour_sql);
            diesel::sql_query(hour_sql)
                .bind::<Timestamptz, _>(from)
                .bind::<Timestamptz, _>(to)
                .load::<TimelineRow>(&mut conn)
        } else {
            // Narrow minute/hour windows (24h) — cheap enough to count live, and
            // finer/fresher than the rollup can express.
            let fine_sql = "SELECT date_trunc($1, ts) AS bucket, source, count(*) AS count \
                 FROM ssumgmt_events \
                 WHERE ts >= $2 AND ts <= $3 \
                 GROUP BY 1, 2 \
                 ORDER BY 1 ASC";
            span.record("db.statement", fine_sql);
            diesel::sql_query(fine_sql)
                .bind::<Text, _>(bucket_for_query)
                .bind::<Timestamptz, _>(from)
                .bind::<Timestamptz, _>(to)
                .load::<TimelineRow>(&mut conn)
        }
    })
    .await;

    match res {
        Ok(Ok(rows)) => Json(TimelineResponse {
            bucket,
            from,
            to,
            rows,
        })
        .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {}", e),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}
