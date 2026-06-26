mod auth;
mod controllers;
mod static_files;

use std::sync::Arc;
use axum::body::Body;
use axum::extract::{MatchedPath, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use crossbeam::channel::Sender;
use jwt_authorizer::{Authorizer, IntoLayer, JwtAuthorizer, Validation};
use jwt_authorizer::layer::AuthorizationLayer;
use log::{info, trace};
use serde_json::Value;
use tokio::net::TcpListener;
use crate::api::controllers::add_controllers;
use crate::db::model::SsuMgmtAuditInsert;
use crate::misc::config::load_conf;
use crate::misc::health::HealthState;
use crate::misc::services::ServicesShared;
use crate::service::bg::Message;

pub fn start_server(shutdown : seqtf_bootstrap::shutdown::Shutdown, ss: ServicesShared, listen_addr : String) {
    std::thread::spawn(move || {
        let _s = shutdown.clone();
        info!("Starting API server");
        info!("Listening on: {}", listen_addr);

        let rt_conf = load_conf().unwrap().runtime;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("api_server_worker")
            .worker_threads(crate::misc::runtime::worker_threads(rt_conf.api_worker_threads))
            // Handlers run DB queries via spawn_blocking; the pool caps real concurrency
            // (default 10), so a small blocking pool is plenty.
            .max_blocking_threads(rt_conf.api_max_blocking_threads)
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
            let audit_tx = ss.read().unwrap().get_service_clone::<Sender<Message>>().expect("bg sender not registered");
            let audit_exclude: Vec<String> = conf.audit.exclude_prefixes
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let web_state = Arc::new(WebState::new(x, conf.cache_implementation, db_pool, audit_tx, conf.audit.enabled, audit_exclude));

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

    // Self-audit: record the service's own API usage. Added INNER to the auth layer
    // (auth is applied last → outermost), so by the time `audit_usage` runs the JWT
    // claims are already in request extensions (principal) and `role_check` is inner
    // to it (a 403 propagates back out and is recorded as a failed attempt).
    routes = routes.route_layer(axum::middleware::from_fn_with_state(state.clone(), audit_usage));

    routes = auth_middleware(routes, state);

    routes
}

/// Map the HTTP method + matched-path template to a stable, low-cardinality action
/// string. Uses the route template (e.g. `/api/entity/:id`), never the concrete URI,
/// so the action set stays bounded. The `alert.*` strings match the action labels the
/// former `write_triage_audit` wrote, for continuity with backfilled triage rows.
fn action_for(method: &str, template: &str) -> String {
    // Strip the `/api` prefix and any trailing slash from a nested `/` root route.
    let t = template.strip_prefix("/api").unwrap_or(template);
    let t = t.strip_suffix('/').filter(|s| !s.is_empty()).unwrap_or(t);
    let action = match (method, t) {
        ("GET", "/query") => "query.search",
        ("GET", "/query/export.csv") => "query.export_csv",
        ("GET", "/entity/:id") => "entity.inspect",
        ("GET", "/entity/:id/activity") => "entity.activity",
        ("GET", "/entity/:id/timeline") => "entity.timeline",
        ("GET", "/graph") => "graph.view",
        ("GET", "/actors") => "actors.list",
        ("POST", "/alerts/:id/ack") => "alert.ack",
        ("POST", "/alerts/:id/resolve") => "alert.resolve",
        ("POST", "/alerts/:id/unack") => "alert.unack",
        ("POST", "/alerts/:id/unresolve") => "alert.unresolve",
        _ => return format!("{} {}", method.to_lowercase(), t),
    };
    action.to_string()
}

/// Middleware: record every intentful authenticated API call as a `ssu-mgmt`-source
/// audit event (the tool audits its own usage). Reads the principal/method/template
/// before the handler, the status after, and hands a row to the bg batch writer over
/// a non-blocking channel send — no DB work on the request hot path.
async fn audit_usage(State(state): State<WebSharedState>, req: Request<Body>, next: Next) -> Response {
    if !state.audit_enabled {
        return next.run(req).await;
    }

    // Only matched routes carry a MatchedPath (route_layer skips 404s); bail otherwise.
    let template = match req.extensions().get::<MatchedPath>() {
        Some(mp) => mp.as_str().to_string(),
        None => return next.run(req).await,
    };

    // Exclude high-volume polling + the auth/progress bypasses by template prefix.
    if state.audit_exclude.iter().any(|p| template.starts_with(p.as_str())) {
        return next.run(req).await;
    }

    let method = req.method().to_string();
    let query = req.uri().query().map(|q| q.to_string());
    let principal = crate::api::auth::principal_of(req.extensions().get::<Value>());
    let source_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());

    let resp = next.run(req).await;

    let code = resp.status().as_u16();
    let (status, level) = if code < 400 {
        ("success", "info")
    } else if code < 500 {
        ("failure", "warn")
    } else {
        ("failure", "error")
    };
    let now = chrono::Utc::now();
    let row = SsuMgmtAuditInsert {
        message_id: uuid::Uuid::new_v4().to_string(),
        ts: now,
        actor: Some(principal),
        action: action_for(&method, &template),
        method: Some(method),
        path: Some(template),
        status_code: Some(code as i32),
        status: status.to_string(),
        level: level.to_string(),
        source_ip,
        role: None,
        request_data: Some(serde_json::json!({ "status_code": code, "query": query })),
        created_at: now,
    };
    // Non-blocking; the bg writer batches + inserts. Drop silently if the channel is
    // gone (shutdown) — auditing must never fail a request.
    let _ = state.audit_tx.send(Message::SelfAudit(row));

    resp
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
    /// Channel to the bg batch writer for self-audit rows (source `ssu-mgmt`).
    pub audit_tx : Sender<Message>,
    /// Master switch for self-audit (`SSU__AUDIT__ENABLED`).
    pub audit_enabled : bool,
    /// Matched-path template prefixes excluded from self-audit (polling endpoints,
    /// auth-config/progress bypasses). Shared read-only across requests.
    pub audit_exclude : Arc<Vec<String>>,
}

impl WebState {
    pub fn new(
        layer : AuthorizationLayer<Value>,
        _cache_implementation : String,
        db_pool : crate::db::DbPool,
        audit_tx : Sender<Message>,
        audit_enabled : bool,
        audit_exclude : Vec<String>,
    ) -> Self {
        Self {
            jwt_validator: layer,
            db_pool,
            audit_tx,
            audit_enabled,
            audit_exclude: Arc::new(audit_exclude),
        }
    }
}
