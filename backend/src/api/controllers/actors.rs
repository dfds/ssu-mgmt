use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use axum_extra::extract::Query;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Nullable, Text, Timestamptz};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

pub fn routes(pool: DbPool) -> Router {
    Router::new()
        .route("/", axum::routing::get(actors_handler))
        .with_state(pool)
}

#[derive(Deserialize)]
pub struct ActorsParams {
    /// Substring over id / email / display_name / team.
    pub q: Option<String>,
    /// Exact `kind` facet (person|service|unresolved).
    pub kind: Option<String>,
    /// One origin taxonomy value (kubernetes|azure-ad|aws|github|selfservice|unknown).
    pub origin: Option<String>,
    /// `risk` (default) | `recent` | `name`.
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(QueryableByName, Serialize)]
struct ActorListRow {
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
    #[diesel(sql_type = Nullable<diesel::sql_types::Integer>)]
    score: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    label: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    first_seen: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_active: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    total: i64,
}

#[derive(Serialize)]
struct ActorsPage {
    rows: Vec<ActorListRow>,
    total: i64,
}

async fn actors_handler(
    State(pool): State<DbPool>,
    Query(params): Query<ActorsParams>,
) -> Response {
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0).max(0);
    let kind = params.kind.unwrap_or_default();
    let origin = params.origin.unwrap_or_default();
    // ILIKE pattern; empty `q` → `%%` matches everything (the `$N = '' OR …` guard
    // would also work, but keeping the bind uniform is simpler).
    let q_pat = format!("%{}%", params.q.unwrap_or_default());
    let order = match params.sort.as_deref() {
        Some("recent") => "a.last_active DESC NULLS LAST",
        Some("name") => "COALESCE(a.display_name, a.id) ASC",
        _ => "r.score DESC NULLS LAST, a.last_active DESC NULLS LAST",
    };

    let where_clause = "WHERE ($1 = '' OR a.kind = $1) \
         AND ($2 = '' OR $2 = ANY(a.origins)) \
         AND ($3 = '%%' OR a.id ILIKE $3 OR a.email ILIKE $3 OR a.display_name ILIKE $3 OR a.team ILIKE $3)";

    let rows_sql = format!(
        "SELECT a.id, a.display_name, a.email, a.team, a.kind, a.origins, a.sources, \
                r.score, r.label, a.first_seen, a.last_active \
         FROM actors a LEFT JOIN risk_scores r ON r.actor_id = a.id \
         {where_clause} \
         ORDER BY {order} LIMIT $4 OFFSET $5"
    );
    let count_sql = format!(
        "SELECT count(*)::bigint AS total \
         FROM actors a LEFT JOIN risk_scores r ON r.actor_id = a.id \
         {where_clause}"
    );

    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<ActorsPage> {
        let mut conn = pool.get().unwrap();
        let rows: Vec<ActorListRow> = diesel::sql_query(rows_sql)
            .bind::<Text, _>(&kind)
            .bind::<Text, _>(&origin)
            .bind::<Text, _>(&q_pat)
            .bind::<BigInt, _>(limit)
            .bind::<BigInt, _>(offset)
            .load(&mut conn)?;
        let total: i64 = diesel::sql_query(count_sql)
            .bind::<Text, _>(&kind)
            .bind::<Text, _>(&origin)
            .bind::<Text, _>(&q_pat)
            .get_result::<CountRow>(&mut conn)?
            .total;
        Ok(ActorsPage { rows, total })
    })
    .await;

    match res {
        Ok(Ok(page)) => Json(page).into_response(),
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
