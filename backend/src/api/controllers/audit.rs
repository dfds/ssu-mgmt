use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use axum_extra::extract::Query;
use chrono::NaiveDateTime;
use diesel::dsl::sql;
use diesel::pg::Pg;
use diesel::prelude::*;
use diesel::sql_types::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::model::AuditRecordsSelfservice;
use crate::misc::config::load_conf;
use crate::schema::audit_records_selfservice as audit;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 500;

pub fn routes() -> Router {
    Router::new()
        .route("/", axum::routing::get(list_handler))
        .route("/export.csv", axum::routing::get(export_handler))
        .route("/:id", axum::routing::get(get_handler))
}

#[derive(Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub message_id: String,
    pub created_at: NaiveDateTime,
    pub timestamp: NaiveDateTime,
    #[serde(rename = "type")]
    pub record_type: String,
    pub principal: String,
    pub action: String,
    pub method: String,
    pub path: String,
    pub service: String,
    pub request_data: Option<Value>,
}

impl From<AuditRecordsSelfservice> for AuditEntry {
    fn from(r: AuditRecordsSelfservice) -> Self {
        Self {
            id: r.id,
            message_id: r.message_id,
            created_at: r.created_at,
            timestamp: r.timestamp,
            record_type: r.record_type,
            principal: r.principal,
            action: r.action,
            method: r.method,
            path: r.path,
            service: r.service,
            request_data: r.request_data,
        }
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub rule: Vec<String>,
    #[serde(default)]
    pub r#match: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub rows: Vec<AuditEntry>,
    pub total: i64,
}

#[derive(Clone, Copy, Debug)]
enum Field {
    Principal,
    Service,
    Action,
    Method,
    Path,
    Type,
}

impl Field {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "principal" => Some(Self::Principal),
            "service" => Some(Self::Service),
            "action" => Some(Self::Action),
            "method" => Some(Self::Method),
            "path" => Some(Self::Path),
            "type" => Some(Self::Type),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Equals,
    NotEquals,
    Contains,
    NotContains,
}

impl Op {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "equals" => Some(Self::Equals),
            "not_equals" => Some(Self::NotEquals),
            "contains" => Some(Self::Contains),
            "not_contains" => Some(Self::NotContains),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct Rule {
    field: Field,
    op: Op,
    value: String,
}

#[derive(Clone, Copy, Debug)]
enum MatchMode {
    All,
    Any,
}

fn parse_rules(raw: &[String]) -> Result<Vec<Rule>, String> {
    raw.iter()
        .map(|s| {
            let mut parts = s.splitn(3, ':');
            let field = parts.next().ok_or_else(|| format!("rule missing field: {}", s))?;
            let op = parts.next().ok_or_else(|| format!("rule missing op: {}", s))?;
            let value = parts.next().ok_or_else(|| format!("rule missing value: {}", s))?;
            Ok(Rule {
                field: Field::parse(field).ok_or_else(|| format!("unknown field: {}", field))?,
                op: Op::parse(op).ok_or_else(|| format!("unknown op: {}", op))?,
                value: value.to_owned(),
            })
        })
        .collect()
}

fn parse_ts(s: &str) -> Result<NaiveDateTime, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.naive_utc())
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .map_err(|e| format!("invalid timestamp {}: {}", s, e))
}

type BoxedSelect<'a> = audit::BoxedQuery<'a, Pg>;

fn apply_rule<'a>(q: BoxedSelect<'a>, r: &Rule, any: bool) -> BoxedSelect<'a> {
    use diesel::BoolExpressionMethods;
    use diesel::TextExpressionMethods;
    let v = r.value.clone();

    macro_rules! apply {
        ($col:expr) => {{
            let col = $col;
            match r.op {
                Op::Equals => {
                    if any { q.or_filter(col.eq(v)) } else { q.filter(col.eq(v)) }
                }
                Op::NotEquals => {
                    if any { q.or_filter(col.ne(v)) } else { q.filter(col.ne(v)) }
                }
                Op::Contains => {
                    let pat = format!("%{}%", v);
                    if any { q.or_filter(col.ilike(pat)) } else { q.filter(col.ilike(pat)) }
                }
                Op::NotContains => {
                    let pat = format!("%{}%", v);
                    if any { q.or_filter(col.not_ilike(pat)) } else { q.filter(col.not_ilike(pat)) }
                }
            }
        }};
    }

    match r.field {
        Field::Principal => apply!(audit::principal),
        Field::Service => apply!(audit::service),
        Field::Action => apply!(audit::action),
        Field::Method => apply!(audit::method),
        Field::Path => apply!(audit::path),
        Field::Type => apply!(audit::type_),
    }
}

fn build_query<'a>(
    rules: &[Rule],
    mode: MatchMode,
    from: Option<NaiveDateTime>,
    to: Option<NaiveDateTime>,
) -> BoxedSelect<'a> {
    let mut q = audit::table.into_boxed::<Pg>();
    if let Some(f) = from {
        q = q.filter(audit::created_at.ge(f));
    }
    if let Some(t) = to {
        q = q.filter(audit::created_at.le(t));
    }
    let any = matches!(mode, MatchMode::Any);
    for r in rules {
        q = apply_rule(q, r, any);
    }
    q
}

async fn list_handler(Query(params): Query<ListQuery>) -> Response {
    let rules = match parse_rules(&params.rule) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let mode = match params.r#match.as_deref() {
        Some("any") => MatchMode::Any,
        _ => MatchMode::All,
    };
    let from = match params.from.as_deref().map(parse_ts).transpose() {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let to = match params.to.as_deref().map(parse_ts).transpose() {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0).max(0);

    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<(Vec<AuditRecordsSelfservice>, i64)> {
        let conf = load_conf().unwrap();
        let mut conn = crate::db::get_db_conn(&conf.db).unwrap();

        let rows: Vec<AuditRecordsSelfservice> = build_query(&rules, mode, from, to)
            .order(audit::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load(&mut conn)?;

        let total: i64 = build_query(&rules, mode, from, to)
            .select(sql::<BigInt>("count(*)"))
            .first(&mut conn)?;

        Ok((rows, total))
    })
    .await;

    match res {
        Ok(Ok((rows, total))) => {
            let rows: Vec<AuditEntry> = rows.into_iter().map(Into::into).collect();
            Json(ListResponse { rows, total }).into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {}", e)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("task join error: {}", e)).into_response(),
    }
}

async fn get_handler(Path(id): Path<i64>) -> Response {
    let res = tokio::task::spawn_blocking(move || -> diesel::QueryResult<Option<AuditRecordsSelfservice>> {
        let conf = load_conf().unwrap();
        let mut conn = crate::db::get_db_conn(&conf.db).unwrap();
        audit::table
            .filter(audit::id.eq(id))
            .first::<AuditRecordsSelfservice>(&mut conn)
            .optional()
    })
    .await;

    match res {
        Ok(Ok(Some(row))) => Json::<AuditEntry>(row.into()).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {}", e)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("task join error: {}", e)).into_response(),
    }
}

async fn export_handler(Query(params): Query<ListQuery>) -> Response {
    let rules = match parse_rules(&params.rule) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let mode = match params.r#match.as_deref() {
        Some("any") => MatchMode::Any,
        _ => MatchMode::All,
    };
    let from = match params.from.as_deref().map(parse_ts).transpose() {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let to = match params.to.as_deref().map(parse_ts).transpose() {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let res = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        let conf = load_conf().unwrap();
        let mut conn = crate::db::get_db_conn(&conf.db).map_err(|e| e.to_string())?;
        let rows: Vec<AuditRecordsSelfservice> = build_query(&rules, mode, from, to)
            .order(audit::created_at.desc())
            .load(&mut conn)
            .map_err(|e| e.to_string())?;

        let mut wtr = csv::Writer::from_writer(vec![]);
        wtr.write_record([
            "id", "created_at", "timestamp", "type", "principal", "service", "action", "method", "path", "message_id", "request_data",
        ])
        .map_err(|e| e.to_string())?;

        for r in rows {
            let req_data = r
                .request_data
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_default();
            wtr.write_record([
                r.id.to_string(),
                r.created_at.to_string(),
                r.timestamp.to_string(),
                r.record_type,
                r.principal,
                r.service,
                r.action,
                r.method,
                r.path,
                r.message_id,
                req_data,
            ])
            .map_err(|e| e.to_string())?;
        }

        wtr.into_inner().map_err(|e| e.to_string())
    })
    .await;

    match res {
        Ok(Ok(bytes)) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"audit.csv\""),
            );
            (StatusCode::OK, headers, bytes).into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("task join error: {}", e)).into_response(),
    }
}
