use crate::api::WebSharedState;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tower_layer::Layer;

/// Resolve the acting principal from AAD-style claims (inserted by `auth_oauth`),
/// preferring human-readable identifiers over the object id. Shared by the alert
/// triage handlers and the `audit_usage` self-audit middleware. Returns `"unknown"`
/// when no claims are present (e.g. auth disabled).
pub fn principal_of(claims: Option<&Value>) -> String {
    let c = match claims {
        Some(c) => c,
        None => return "unknown".to_string(),
    };
    for key in [
        "preferred_username",
        "upn",
        "email",
        "unique_name",
        "oid",
        "sub",
    ] {
        if let Some(s) = c.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    "unknown".to_string()
}

pub async fn auth_oauth(
    State(state): State<WebSharedState>,
    OriginalUri(uri): OriginalUri,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Public bypass: OIDC bootstrap endpoint must be reachable without a token.
    if uri.path() == "/api/auth/config" {
        return next.run(request).await;
    }

    // The progress WebSocket can't send an Authorization header (browsers don't
    // allow custom headers on `new WebSocket()`); it carries its bearer token in
    // the WS subprotocol instead and authenticates inside its own handler.
    if uri.path() == "/api/progress/ws" {
        return next.run(request).await;
    }

    let token = match request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
    {
        Some(t) if !t.is_empty() => t.to_owned(),
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let auth_svc = state
        .jwt_validator
        .layer(Value::default())
        .auths
        .first()
        .unwrap()
        .clone();
    let valid = auth_svc.check_auth(&token).await;

    match valid {
        Ok(token_data) => {
            request.extensions_mut().insert(token_data.claims);
        }
        Err(_) => {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let response = next.run(request).await;
    response
}

/// Middleware: verifies the validated JWT claims (inserted by `auth_oauth`)
/// contain the given role under the standard AAD `roles` array claim.
///
/// When `api_enable_auth` is false, the check is bypassed for parity with the
/// outer auth middleware. Attach via `from_fn_with_state(role_str, role_check)`.
pub async fn role_check(
    State(role): State<&'static str>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let conf = crate::misc::config::load_conf().unwrap();
    if !conf.api_enable_auth {
        return next.run(req).await;
    }

    let allowed = req
        .extensions()
        .get::<Value>()
        .and_then(|c| c.get("roles"))
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().any(|v| v.as_str() == Some(role)))
        .unwrap_or(false);

    if allowed {
        next.run(req).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}
