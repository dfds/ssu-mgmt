use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use axum_extra::extract::Query;
use diesel::pg::Pg;
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Double, Text, Timestamptz};
use serde::{Deserialize, Serialize};

use super::query_ast::{self, Bind, Node};
use crate::db::model::SsuMgmtEvent;
use crate::db::DbPool;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 500;

const DEFAULT_COUNT_CAP: i64 = 10_000;

pub fn routes(pool: DbPool) -> Router {
    Router::new()
        .route("/", axum::routing::get(query_handler))
        .route("/export.csv", axum::routing::get(export_handler))
        .with_state(pool)
}

#[derive(Deserialize)]
pub struct QueryParams {
    /// URL-encoded JSON of a `query_ast::Node`. Absent/empty → match everything.
    pub ast: Option<String>,
    /// Direct facets (equality) — only meaningful for sources that populate them.
    pub status: Option<String>,
    pub source: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Max rows the count scans before reporting `N+`. Defaults to
    /// `DEFAULT_COUNT_CAP`; `0`/negative → unbounded (exact) count.
    pub count_cap: Option<i64>,
    /// Result ordering. `order_by` is a field name mapped through a closed
    /// allowlist to a column; `order_dir` is `asc`/`desc`. Absent → `ts DESC`.
    pub order_by: Option<String>,
    pub order_dir: Option<String>,
    pub count: Option<bool>,
}

#[derive(Serialize)]
pub struct QueryResponse {
    pub rows: Vec<SsuMgmtEvent>,
    /// `None` (JSON `null`) when the count was skipped (pagination); otherwise
    /// the row count, clamped to the cap when `total_capped`.
    pub total: Option<i64>,
    pub total_capped: bool,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    total: i64,
}

/// The compiled WHERE clause + the ordered binds it references. Shared by the
/// rows query and the count query; the rows query appends LIMIT/OFFSET binds.
struct Compiled {
    where_sql: String,
    binds: Vec<Bind>,
}

fn compile_params(params: &QueryParams) -> Result<Compiled, String> {
    let mut binds: Vec<Bind> = Vec::new();
    let mut clauses: Vec<String> = Vec::new();

    if let Some(s) = params.source.as_deref().filter(|s| !s.is_empty()) {
        binds.push(Bind::Text(s.to_owned()));
        clauses.push(format!("source = ${}", binds.len()));
    }
    if let Some(s) = params.status.as_deref().filter(|s| !s.is_empty()) {
        binds.push(Bind::Text(s.to_owned()));
        clauses.push(format!("status = ${}", binds.len()));
    }
    if let Some(f) = params.from.as_deref().filter(|s| !s.is_empty()) {
        binds.push(Bind::Ts(query_ast::parse_ts(f)?));
        clauses.push(format!("ts >= ${}", binds.len()));
    }
    if let Some(t) = params.to.as_deref().filter(|s| !s.is_empty()) {
        binds.push(Bind::Ts(query_ast::parse_ts(t)?));
        clauses.push(format!("ts <= ${}", binds.len()));
    }

    if let Some(ast) = params
        .ast
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let node: Node = serde_json::from_str(ast).map_err(|e| format!("bad ast: {}", e))?;
        clauses.push(query_ast::compile(&node, &mut binds)?);
    }

    let where_sql = if clauses.is_empty() {
        "TRUE".to_string()
    } else {
        clauses.join(" AND ")
    };
    Ok(Compiled { where_sql, binds })
}

const SELECT_COLS: &str = "source, uid, ts, actor, action, resource, source_ip, \
                           level, status, raw, role, identity_source, account_id, \
                           caller_account_id";

fn order_column(field: &str) -> Option<&'static str> {
    Some(match field.to_lowercase().as_str() {
        "actor" => "actor",
        "source" => "source",
        "action" => "action",
        "resource" => "resource",
        "ip" => "source_ip",
        "status" => "status",
        "level" => "level",
        "uid" => "uid",
        "role" => "role",
        "idsource" => "identity_source",
        "account" => "account_id",
        "calleraccount" => "caller_account_id",
        "ts" => "ts",
        _ => return None,
    })
}

fn order_by_clause(order_by: Option<&str>, order_dir: Option<&str>) -> Result<String, String> {
    let Some(field) = order_by.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok("ts DESC, uid".to_string());
    };
    let col = order_column(field).ok_or_else(|| format!("cannot order by `{}`", field))?;
    let dir = match order_dir.map(|s| s.trim().to_lowercase()).as_deref() {
        Some("asc") | None => "ASC",
        Some("desc") => "DESC",
        Some(other) => return Err(format!("invalid order direction `{}`", other)),
    };
    if col == "ts" {
        Ok(format!("ts {}, uid", dir))
    } else {
        Ok(format!("{} {} NULLS LAST, ts DESC, uid", col, dir))
    }
}

fn apply_binds<'a>(
    mut q: diesel::query_builder::BoxedSqlQuery<'a, Pg, diesel::query_builder::SqlQuery>,
    binds: Vec<Bind>,
) -> diesel::query_builder::BoxedSqlQuery<'a, Pg, diesel::query_builder::SqlQuery> {
    for b in binds {
        q = match b {
            Bind::Text(s) => q.bind::<Text, _>(s),
            Bind::Double(d) => q.bind::<Double, _>(d),
            Bind::BigInt(n) => q.bind::<BigInt, _>(n),
            Bind::TextArray(a) => q.bind::<Array<Text>, _>(a),
            Bind::Ts(t) => q.bind::<Timestamptz, _>(t),
        };
    }
    q
}

async fn query_handler(State(pool): State<DbPool>, Query(params): Query<QueryParams>) -> Response {
    let compiled = match compile_params(&params) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0).max(0);
    let count_cap = params.count_cap.unwrap_or(DEFAULT_COUNT_CAP);
    let skip_count = params.count == Some(false);
    let order_sql = match order_by_clause(params.order_by.as_deref(), params.order_dir.as_deref()) {
        Ok(o) => o,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "query.search",
        db.statement = tracing::field::Empty
    );
    let res = tokio::task::spawn_blocking(
        move || -> diesel::QueryResult<(Vec<SsuMgmtEvent>, Option<i64>, bool)> {
            let _g = span.enter();
            let mut conn = pool.get().unwrap();
            let Compiled { where_sql, binds } = compiled;

            let mut row_binds = binds.clone();
            row_binds.push(Bind::BigInt(limit));
            let limit_idx = row_binds.len();
            row_binds.push(Bind::BigInt(offset));
            let offset_idx = row_binds.len();
            let rows_sql = format!(
                "SELECT {cols} FROM ssumgmt_events WHERE {where_sql} \
             ORDER BY {order_sql} LIMIT ${limit_idx} OFFSET ${offset_idx}",
                cols = SELECT_COLS,
            );
            span.record("db.statement", rows_sql.as_str());
            let rows: Vec<SsuMgmtEvent> =
                apply_binds(diesel::sql_query(rows_sql).into_boxed::<Pg>(), row_binds)
                    .load(&mut conn)?;

            let (total, total_capped) = if skip_count {
                (None, false)
            } else if count_cap > 0 {
                let count_sql = format!(
                    "SELECT count(*)::bigint AS total FROM \
                 (SELECT 1 FROM ssumgmt_events WHERE {where_sql} LIMIT {cap}) sub",
                    cap = count_cap + 1,
                );
                let counted: i64 =
                    apply_binds(diesel::sql_query(count_sql).into_boxed::<Pg>(), binds)
                        .get_result::<CountRow>(&mut conn)?
                        .total;
                if counted > count_cap {
                    (Some(count_cap), true)
                } else {
                    (Some(counted), false)
                }
            } else {
                let count_sql = format!(
                    "SELECT count(*)::bigint AS total FROM ssumgmt_events WHERE {where_sql}"
                );
                let counted: i64 =
                    apply_binds(diesel::sql_query(count_sql).into_boxed::<Pg>(), binds)
                        .get_result::<CountRow>(&mut conn)?
                        .total;
                (Some(counted), false)
            };

            Ok((rows, total, total_capped))
        },
    )
    .await;

    match res {
        Ok(Ok((rows, total, total_capped))) => Json(QueryResponse {
            rows,
            total,
            total_capped,
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

async fn export_handler(State(pool): State<DbPool>, Query(params): Query<QueryParams>) -> Response {
    let compiled = match compile_params(&params) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let order_sql = match order_by_clause(params.order_by.as_deref(), params.order_dir.as_deref()) {
        Ok(o) => o,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let span = tracing::info_span!(
        "db.query",
        otel.kind = "client",
        db.system = "postgresql",
        op = "query.export",
        db.statement = tracing::field::Empty
    );
    let res = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let _g = span.enter();
        let mut conn = pool.get().map_err(|e| e.to_string())?;
        let Compiled { where_sql, binds } = compiled;

        let rows_sql = format!(
            "SELECT {cols} FROM ssumgmt_events WHERE {where_sql} ORDER BY {order_sql}",
            cols = SELECT_COLS
        );
        span.record("db.statement", rows_sql.as_str());
        let rows: Vec<SsuMgmtEvent> =
            apply_binds(diesel::sql_query(rows_sql).into_boxed::<Pg>(), binds)
                .load(&mut conn)
                .map_err(|e| e.to_string())?;

        let mut wtr = csv::Writer::from_writer(vec![]);
        wtr.write_record([
            "source",
            "uid",
            "ts",
            "actor",
            "action",
            "resource",
            "source_ip",
            "level",
            "status",
            "role",
            "identity_source",
            "account_id",
            "caller_account_id",
            "raw",
        ])
        .map_err(|e| e.to_string())?;

        for r in rows {
            let raw = r.raw.as_ref().map(|v| v.to_string()).unwrap_or_default();
            wtr.write_record([
                r.source,
                r.uid,
                r.ts.to_rfc3339(),
                r.actor.unwrap_or_default(),
                r.action,
                r.resource.unwrap_or_default(),
                r.source_ip.unwrap_or_default(),
                r.level,
                r.status,
                r.role.unwrap_or_default(),
                r.identity_source.unwrap_or_default(),
                r.account_id.unwrap_or_default(),
                r.caller_account_id.unwrap_or_default(),
                raw,
            ])
            .map_err(|e| e.to_string())?;
        }

        wtr.into_inner().map_err(|e| e.to_string())
    })
    .await;

    match res {
        Ok(Ok(bytes)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/csv; charset=utf-8"),
            );
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"ssumgmt_events.csv\""),
            );
            (StatusCode::OK, headers, bytes).into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {}", e),
        )
            .into_response(),
    }
}
