mod auth;
mod controllers;
mod misc;

use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jwt_authorizer::{Authorizer, IntoLayer, JwtAuthorizer, Validation};
use jwt_authorizer::layer::AuthorizationLayer;
use log::{info, trace};
use regex::Regex;
use serde_json::Value;
use tokio::net::TcpListener;
use crate::api::controllers::add_controllers;
use crate::misc::config::load_conf;

pub fn start_server(shutdown : seqtf_bootstrap::shutdown::Shutdown, listen_addr : String) {
    std::thread::spawn(move || {
        let _s = shutdown.clone();
        info!("Starting API server");
        info!("Listening on: {}", listen_addr);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("api_server_worker")
            .enable_all()
            .build().expect("Unable to create API server pool");

        runtime.block_on(async move {
            let conf = load_conf().unwrap();
            let mut validation = Validation::default();
            validation.aud = Some(vec![conf.auth.aud]);
            validation.iss = Some(vec![conf.auth.issuer]);
            let jwt_validator : Authorizer<Value> = JwtAuthorizer::from_oidc(&conf.auth.oidc_url).validation(validation).build().await.unwrap();
            let x = jwt_validator.into_layer();
            let web_state = Arc::new(WebState::new(x, conf.cache_implementation));

            let app = axum::Router::new()
                .nest("/api", api_router(web_state.clone()))
                .layer(axum::middleware::from_fn(default_headers));

            let listener = TcpListener::bind(listen_addr.as_str()).await.unwrap();
            axum::serve(listener, app).with_graceful_shutdown(shutdown.exit)
                .await.unwrap();
        });
    });
}

pub fn api_router(state : WebSharedState) -> axum::Router {
    let mut routes = axum::Router::new();

    routes = routes
        .route("/global/stats", axum::routing::get(misc::get_stats))
        .fallback(axum::routing::any(api_fallback));

    routes = add_controllers(routes, state.clone());

    routes = auth_middleware(routes, state);

    routes
}

async fn api_fallback() -> impl IntoResponse {
    StatusCode::NOT_FOUND
}

pub async fn default_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert("server", "ssu-mgmt".parse().unwrap());
    response
}

pub fn auth_middleware(mut router: axum::Router, state : WebSharedState) -> axum::Router {
    let conf = load_conf().unwrap();
    if conf.api_enable_auth {
        router = router.layer(axum::middleware::from_fn_with_state(state, auth::auth_oauth));
    }

    router
}

pub type WebSharedState = Arc<WebState>;

#[derive(Clone)]
pub struct WebState {
    pub jwt_validator : AuthorizationLayer<Value>,
    pub asset_auth_regex : Regex,
}

impl WebState {
    pub fn new(layer : AuthorizationLayer<Value>, cache_implementation : String) -> Self {
        let re = Regex::new(r"\/assets\/(auth-.*.js|.*.css|relativeTime.*.js)").unwrap();

        Self {
            jwt_validator: layer,
            asset_auth_regex: re,
        }
    }
}