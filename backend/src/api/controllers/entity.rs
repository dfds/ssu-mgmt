//! Entity / Inspect API (plan §7). `GET /entity/{id}` fans an actor's identity,
//! risk (with the explainable `components` breakdown), stats, sessions, grants,
//! and recent activity into one payload; `GET /entity/{id}/timeline` returns that
//! actor's per-source activity buckets. Events are attributed to the canonical
//! actor via `actor_aliases`, so any source's raw identifier resolves.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use axum_extra::extract::Query;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Text, Timestamptz};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::model::{Actor, Anomaly, Grant, RiskScore, Session, SsuMgmtEvent};
use crate::db::DbPool;

pub fn routes(pool: DbPool) -> Router {
    Router::new()
        .route("/:id", axum::routing::get(entity_handler))
        .route("/:id/activity", axum::routing::get(activity_handler))
        .route("/:id/timeline", axum::routing::get(timeline_handler))
        .with_state(pool)
}

#[derive(QueryableByName)]
struct StatsRow {
    #[diesel(sql_type = BigInt)]
    events_24h: i64,
    #[diesel(sql_type = BigInt)]
    events_7d: i64,
    #[diesel(sql_type = BigInt)]
    failed_7d: i64,
    #[diesel(sql_type = BigInt)]
    sessions: i64,
    #[diesel(sql_type = BigInt)]
    priv_grants: i64,
    #[diesel(sql_type = BigInt)]
    activity_total: i64,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    n: i64,
}

#[derive(QueryableByName)]
struct IdentityContextRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    identity_source: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    assumed_role_arn: Option<String>,
}

async fn entity_handler(State(pool): State<DbPool>, Path(id): Path<String>) -> Response {
    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "entity.bundle",
        entity.id = %id
    );
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<serde_json::Value>> {
        let _g = span.enter();
        use crate::schema::actors::dsl as ad;
        use crate::schema::grants::dsl as gd;
        use crate::schema::sessions::dsl as sd;
        let mut conn = pool.get()?;
        
        let q = |op: &'static str, stmt: &'static str| {
            tracing::info_span!(
                "db.query",
                otel.kind = "client",
                db.system = "postgresql",
                op = op,
                entity.id = %id,
                db.statement = stmt
            )
        };

        let actor: Option<Actor> = q("entity.actor", "SELECT * FROM actors WHERE id = $1")
            .in_scope(|| ad::actors.find(&id).select(Actor::as_select()).first(&mut conn).optional())?;
        let actor = match actor {
            Some(a) => a,
            None => return Ok(None),
        };

        let risk: Option<RiskScore> = q("entity.risk", "SELECT * FROM risk_scores WHERE id = $1").in_scope(|| {
            use crate::schema::risk_scores::dsl as rd;
            rd::risk_scores.find(&id).select(RiskScore::as_select()).first(&mut conn).optional()
        })?;

        let sessions: Vec<Session> = q(
            "entity.sessions",
            "SELECT * FROM sessions WHERE actor_id = $1 ORDER BY last_seen_at DESC LIMIT 25",
        )
        .in_scope(|| {
            sd::sessions
                .filter(sd::actor_id.eq(&id))
                .order(sd::last_seen_at.desc())
                .limit(25)
                .select(Session::as_select())
                .load(&mut conn)
        })?;

        let grants: Vec<Grant> = q(
            "entity.grants",
            "SELECT * FROM grants WHERE actor_id = $1 ORDER BY granted_at DESC NULLS LAST LIMIT 100",
        )
        .in_scope(|| {
            gd::grants
                .filter(gd::actor_id.eq(&id))
                .order(gd::granted_at.desc().nulls_last())
                .limit(100)
                .select(Grant::as_select())
                .load(&mut conn)
        })?;

        let anomalies: Vec<Anomaly> = q(
            "entity.anomalies",
            "SELECT * FROM anomalies WHERE actor_id = $1 ORDER BY event_time DESC LIMIT 25",
        )
        .in_scope(|| {
            use crate::schema::anomalies::dsl as nd;
            nd::anomalies
                .filter(nd::actor_id.eq(&id))
                .order(nd::event_time.desc())
                .limit(25)
                .select(Anomaly::as_select())
                .load(&mut conn)
        })?;

        let activity_sql = "SELECT e.source, e.uid, e.ts, e.actor, e.action, e.resource, e.source_ip, e.level, e.status, e.raw, e.role, e.identity_source, e.account_id, e.caller_account_id \
             FROM actor_aliases aa CROSS JOIN LATERAL ( \
                 SELECT e.source, e.uid, e.ts, e.actor, e.action, e.resource, e.source_ip, e.level, e.status, e.raw, e.role, e.identity_source, e.account_id, e.caller_account_id \
                 FROM ssumgmt_events e WHERE e.actor = aa.alias ORDER BY e.ts DESC LIMIT 50 \
             ) e \
             WHERE aa.actor_id = $1 ORDER BY e.ts DESC LIMIT 50";
        let activity: Vec<SsuMgmtEvent> = q("entity.activity", activity_sql).in_scope(|| {
            diesel::sql_query(activity_sql).bind::<Text, _>(&id).load(&mut conn)
        })?;

        let stats_sql =
            "SELECT \
               (SELECT COALESCE(sum(h.cnt), 0) FROM actor_daily_counts dc \
                  JOIN actor_aliases aa ON aa.alias = dc.actor \
                  CROSS JOIN LATERAL unnest(dc.hourly) WITH ORDINALITY AS h(cnt, idx) \
                  WHERE aa.actor_id = $1 \
                    AND dc.day >= ((now() AT TIME ZONE 'UTC')::date - 1) \
                    AND (dc.day::timestamp + make_interval(hours => (idx - 1)::int)) >= ((now() AT TIME ZONE 'UTC') - interval '24 hours'))::bigint AS events_24h, \
               (SELECT COALESCE(sum(dc.n), 0) FROM actor_daily_counts dc \
                  JOIN actor_aliases aa ON aa.alias = dc.actor \
                  WHERE aa.actor_id = $1 AND dc.day >= ((now() AT TIME ZONE 'UTC')::date - 6))::bigint AS events_7d, \
               (SELECT COALESCE(sum(dc.failed), 0) FROM actor_daily_counts dc \
                  JOIN actor_aliases aa ON aa.alias = dc.actor \
                  WHERE aa.actor_id = $1 AND dc.day >= ((now() AT TIME ZONE 'UTC')::date - 6))::bigint AS failed_7d, \
               (SELECT count(*) FROM sessions WHERE actor_id = $1) AS sessions, \
               (SELECT count(*) FROM grants WHERE actor_id = $1 AND privileged AND revoked_at IS NULL) AS priv_grants, \
               (SELECT COALESCE(sum(dc.n), 0) FROM actor_daily_counts dc \
                  JOIN actor_aliases aa ON aa.alias = dc.actor \
                  WHERE aa.actor_id = $1)::bigint AS activity_total";
        let stats: StatsRow = q("entity.stats", stats_sql)
            .in_scope(|| diesel::sql_query(stats_sql).bind::<Text, _>(&id).get_result(&mut conn))?;
        

        let ctx_sql =
            "SELECT identity_source, assumed_role_arn FROM ( \
                 SELECT c.identity_source AS identity_source, c.assumed_role_arn AS assumed_role_arn, \
                        max(c.last_ts) AS last_ts \
                 FROM actor_identity_context c JOIN actor_aliases aa ON aa.alias = c.actor \
                 WHERE aa.actor_id = $1 \
                 GROUP BY c.identity_source, c.assumed_role_arn \
             ) z ORDER BY last_ts DESC LIMIT 200";
        let ctx_rows: Vec<IdentityContextRow> = q("entity.identity_context", ctx_sql)
            .in_scope(|| diesel::sql_query(ctx_sql).bind::<Text, _>(&id).load(&mut conn))?;
        let mut id_sources: Vec<String> = Vec::new();
        let mut assumed_roles: Vec<String> = Vec::new();
        for r in &ctx_rows {
            if let Some(s) = r.identity_source.as_deref().filter(|s| !s.is_empty()) {
                if !id_sources.iter().any(|x| x == s) {
                    id_sources.push(s.to_string());
                }
            }
            if let Some(role) = r.assumed_role_arn.as_deref().filter(|s| !s.is_empty()) {
                if !assumed_roles.iter().any(|x| x == role) {
                    assumed_roles.push(role.to_string());
                }
            }
        }

        Ok(Some(json!({
            "identity": actor,
            "risk": risk,
            "stats": {
                "events_24h": stats.events_24h,
                "events_7d": stats.events_7d,
                "failed_7d": stats.failed_7d,
                "sessions": stats.sessions,
                "privileged_grants": stats.priv_grants,
            },
            "identity_context": {
                "sources": id_sources,
                "roles": assumed_roles,
            },
            "sessions": sessions,
            "grants": grants,
            "anomalies": anomalies,
            "activity": activity,
            "activity_total": stats.activity_total,
        })))
    })
    .await;

    match res {
        Ok(Ok(Some(v))) => Json(v).into_response(),
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, "actor not found").into_response(),
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
pub struct ActivityParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Paginated activity for one actor (the inspect page's ACTIVITY pane). Same
/// alias-unioned join as the `/entity/:id` bundle, but with limit/offset and a
/// total so the page can browse past the bundled first 50.
async fn activity_handler(
    State(pool): State<DbPool>,
    Path(id): Path<String>,
    Query(params): Query<ActivityParams>,
) -> Response {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0).max(0);

    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "entity.activity",
        entity.id = %id,
        db.statement = tracing::field::Empty
    );
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<serde_json::Value> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;

        // Same per-alias LATERAL as the bundle, with limit/offset. The inner LIMIT is
        // limit+offset so each alias yields enough rows for the outer offset to page.
        let activity_sql = "SELECT e.source, e.uid, e.ts, e.actor, e.action, e.resource, e.source_ip, e.level, e.status, e.raw, e.role, e.identity_source, e.account_id, e.caller_account_id \
             FROM actor_aliases aa CROSS JOIN LATERAL ( \
                 SELECT e.source, e.uid, e.ts, e.actor, e.action, e.resource, e.source_ip, e.level, e.status, e.raw, e.role, e.identity_source, e.account_id, e.caller_account_id \
                 FROM ssumgmt_events e WHERE e.actor = aa.alias ORDER BY e.ts DESC LIMIT ($2 + $3) \
             ) e \
             WHERE aa.actor_id = $1 ORDER BY e.ts DESC LIMIT $2 OFFSET $3";
        span.record("db.statement", activity_sql);
        let rows: Vec<SsuMgmtEvent> = diesel::sql_query(activity_sql)
        .bind::<Text, _>(&id)
        .bind::<BigInt, _>(limit)
        .bind::<BigInt, _>(offset)
        .load(&mut conn)?;

        // Total from the actor_daily_counts cache (all-history sum) rather than a
        // full count over the union view. Like the bundle's activity_total, this can
        // exceed the paginatable rows if retention later prunes events.
        let total: CountRow = diesel::sql_query(
            "SELECT COALESCE(sum(dc.n), 0)::bigint AS n FROM actor_daily_counts dc \
             JOIN actor_aliases aa ON aa.alias = dc.actor WHERE aa.actor_id = $1",
        )
        .bind::<Text, _>(&id)
        .get_result(&mut conn)?;

        Ok(json!({ "rows": rows, "total": total.n }))
    })
    .await;

    match res {
        Ok(Ok(v)) => Json(v).into_response(),
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
    Path(id): Path<String>,
    Query(params): Query<TimelineParams>,
) -> Response {
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
        Ok(v) => v.unwrap_or(now - Duration::days(7)),
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let to = match params.to.as_deref().map(parse_ts).transpose() {
        Ok(v) => v.unwrap_or(now),
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "entity.timeline",
        db.statement = tracing::field::Empty
    );
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<Vec<TimelineRow>> {
        let _g = span.enter();
        let mut conn = crate::db::conn(&pool)?;
        let timeline_sql =
            "SELECT date_trunc($1, e.ts) AS bucket, e.source AS source, count(*) AS count \
             FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
             WHERE aa.actor_id = $2 AND e.ts >= $3 AND e.ts <= $4 \
             GROUP BY 1, 2 ORDER BY 1 ASC";
        span.record("db.statement", timeline_sql);
        diesel::sql_query(timeline_sql)
            .bind::<Text, _>(bucket)
            .bind::<Text, _>(id)
            .bind::<Timestamptz, _>(from)
            .bind::<Timestamptz, _>(to)
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
