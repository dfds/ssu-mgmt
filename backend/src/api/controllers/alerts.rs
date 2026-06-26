use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json, Router};
use serde_json::{json, Value};

use crate::db::DbPool;
use crate::service::siem::alerts;

#[derive(Clone, Copy, Debug)]
enum Action {
    Ack,
    Resolve,
    Unack,
    Unresolve,
}

pub fn routes(pool: DbPool) -> Router {
    Router::new()
        .route("/:id/ack", axum::routing::post(ack_handler))
        .route("/:id/resolve", axum::routing::post(resolve_handler))
        .route("/:id/unack", axum::routing::post(unack_handler))
        .route("/:id/unresolve", axum::routing::post(unresolve_handler))
        .with_state(pool)
}

/// Resolve the acting principal from AAD-style claims, preferring human-readable
/// identifiers over the object id.
fn principal_of(claims: Option<&Value>) -> String {
    let c = match claims {
        Some(c) => c,
        None => return "unknown".to_string(),
    };
    for key in ["preferred_username", "upn", "email", "unique_name", "oid", "sub"] {
        if let Some(s) = c.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    "unknown".to_string()
}

async fn ack_handler(State(pool): State<DbPool>, claims: Option<Extension<Value>>, Path(id): Path<i64>) -> Response {
    triage(pool, id, principal_of(claims.as_ref().map(|e| &e.0)), Action::Ack).await
}

async fn resolve_handler(State(pool): State<DbPool>, claims: Option<Extension<Value>>, Path(id): Path<i64>) -> Response {
    triage(pool, id, principal_of(claims.as_ref().map(|e| &e.0)), Action::Resolve).await
}

async fn unack_handler(State(pool): State<DbPool>, claims: Option<Extension<Value>>, Path(id): Path<i64>) -> Response {
    triage(pool, id, principal_of(claims.as_ref().map(|e| &e.0)), Action::Unack).await
}

async fn unresolve_handler(State(pool): State<DbPool>, claims: Option<Extension<Value>>, Path(id): Path<i64>) -> Response {
    triage(pool, id, principal_of(claims.as_ref().map(|e| &e.0)), Action::Unresolve).await
}

async fn triage(pool: DbPool, id: i64, who: String, action: Action) -> Response {
    let span = tracing::info_span!("db.query", otel.kind = "client", db.system = "postgresql", op ="alerts.transition", action = ?action, alert_id = id);
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
        let _g = span.enter();
        let mut conn = pool.get()?;
        match action {
            Action::Ack => alerts::ack(&mut conn, id, &who),
            Action::Resolve => alerts::resolve(&mut conn, id, &who),
            Action::Unack => alerts::unack(&mut conn, id, &who),
            Action::Unresolve => alerts::unresolve(&mut conn, id, &who),
        }
    })
    .await;

    let not_applicable = match action {
        Action::Ack | Action::Resolve => "alert not found or already resolved",
        Action::Unack => "alert not found or not acknowledged",
        Action::Unresolve => "alert not found or not resolved",
    };
    match res {
        Ok(Ok(0)) => (StatusCode::NOT_FOUND, not_applicable).into_response(),
        Ok(Ok(_)) => Json(json!({ "ok": true })).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {}", e)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("task join error: {}", e)).into_response(),
    }
}
