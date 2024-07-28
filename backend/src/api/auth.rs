use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use crate::api::WebSharedState;
use tower_layer::Layer;

pub async fn auth_oauth(State(state) : State<WebSharedState>, OriginalUri(uri): OriginalUri, request: Request<Body>, next: Next) -> Response {
    let mut token = "".to_owned();
    let auth_header = request.headers().get("authorization");
    if auth_header.is_some() {
        token = auth_header.unwrap().to_str().unwrap().replace("Bearer ", "").to_owned();
    } else {
        let jar = axum_extra::extract::cookie::CookieJar::from_headers(request.headers());
        let cookie_token = jar.get("ssu_token");
        if cookie_token.is_some() {
            token = cookie_token.unwrap().value().to_string();
        }
    }

    if state.asset_auth_regex.is_match(uri.path()) {
        let response = next.run(request).await;
        return response;
    }

    let is_api = uri.path().contains("/api");

    if token.eq("") {
        if is_api {
            return StatusCode::UNAUTHORIZED.into_response();
        } else {
            let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
            resp.headers_mut().insert("location", "/auth/".parse().unwrap());

            return resp
        }
    }

    let auth_svc = state.jwt_validator.layer(Value::default()).auths.first().unwrap().clone();
    let valid = auth_svc.check_auth(&token).await;

    if valid.is_err() {
        if is_api {
            return StatusCode::UNAUTHORIZED.into_response();
        } else {
            let mut resp = StatusCode::TEMPORARY_REDIRECT.into_response();
            resp.headers_mut().insert("location", "/auth/".parse().unwrap());

            return resp
        }
    }

    let response = next.run(request).await;
    response
}