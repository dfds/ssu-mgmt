mod auth;
mod controllers;
mod static_files;

use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jwt_authorizer::{Authorizer, IntoLayer, JwtAuthorizer, Validation};
use jwt_authorizer::layer::AuthorizationLayer;
use log::{info, trace};
use serde_json::Value;
use tokio::net::TcpListener;
use crate::api::controllers::add_controllers;
use crate::misc::config::load_conf;
use crate::misc::health::HealthState;
use crate::misc::services::ServicesShared;

pub fn start_server(shutdown : seqtf_bootstrap::shutdown::Shutdown, ss: ServicesShared, listen_addr : String) {
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
            let db_pool = ss.read().unwrap().get_service_clone::<crate::db::DbPool>().expect("db pool not registered");
            let web_state = Arc::new(WebState::new(x, conf.cache_implementation, db_pool));

            let trace_layer = tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|req: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!(
                        "http.request",
                        otel.kind = "server",
                        otel.name = tracing::field::Empty,
                        http.request.method = %req.method(),
                        method = %req.method(),
                        path = %req.uri().path(),
                    )
                });

            let app = axum::Router::new()
                .nest("/api", api_router(web_state.clone()))
                .fallback_service(static_files::router())
                .layer(axum::middleware::from_fn(default_headers))
                .layer(trace_layer);

            let listener = TcpListener::bind(listen_addr.as_str()).await.unwrap();

            {
                let hs = ss.read().unwrap().get_service_clone::<HealthState>().unwrap();
                hs.checks.write().unwrap().insert("api_ready".to_owned(), true);
                hs.refresh_ready();
            }
            axum::serve(listener, app).with_graceful_shutdown(shutdown.exit)
                .await.unwrap();
        });
    });
}

pub fn api_router(state : WebSharedState) -> axum::Router {
    let mut routes = axum::Router::new();

    routes = routes
        .route("/auth/config", axum::routing::get(controllers::auth_config::handler))
        .fallback(axum::routing::any(api_fallback));

    routes = routes.nest("/progress", controllers::progress::routes(state.clone()));

    routes = add_controllers(routes, state.clone());

    routes = routes.route_layer(axum::middleware::from_fn(record_otel_route));

    routes = auth_middleware(routes, state);

    routes
}

async fn record_otel_route(req: Request<Body>, next: Next) -> Response {
    if let Some(mp) = req.extensions().get::<axum::extract::MatchedPath>() {
        let name = format!("{} {}", req.method(), mp.as_str());
        tracing::Span::current().record("otel.name", name.as_str());
    }
    next.run(req).await
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
    pub db_pool : crate::db::DbPool,
}

impl WebState {
    pub fn new(layer : AuthorizationLayer<Value>, _cache_implementation : String, db_pool : crate::db::DbPool) -> Self {
        Self {
            jwt_validator: layer,
            db_pool,
        }
    }
}
