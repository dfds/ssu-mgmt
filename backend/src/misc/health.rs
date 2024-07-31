use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Acquire, Release};
use axum::extract::State;
use axum::http::StatusCode;
use jwt_authorizer::{Authorizer, JwtAuthorizer, Validation};
use log::info;
use serde_json::Value;
use tokio::net::TcpListener;
use crate::api::{api_router, WebState};
use crate::misc::config::load_conf;
use crate::misc::services::{Services, ServicesShared};

pub fn start_health(shutdown : seqtf_bootstrap::shutdown::Shutdown, ss: ServicesShared, listen_addr : String) {
    let hs = ss.read().unwrap().get_service::<HealthState>().unwrap();

    let _hs = hs.clone();
    std::thread::spawn(move || {
        let _s = shutdown.clone();
        info!("Health endpoint listening on: {}", listen_addr);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("api_server_worker")
            .enable_all()
            .build().expect("Unable to create API server pool");

        runtime.block_on(async move {
            let conf = load_conf().unwrap();

            let app = axum::Router::new()
                .route("/health", axum::routing::get(health))
                .route("/ready", axum::routing::get(readiness))
                .route("/live", axum::routing::get(liveness))
                .with_state(_hs.deref().clone())
                .layer(axum::middleware::from_fn(crate::api::default_headers));

            let listener = TcpListener::bind(listen_addr.as_str()).await.unwrap();
            axum::serve(listener, app).with_graceful_shutdown(shutdown.exit)
                .await.unwrap();
        });
    });
}

#[derive(Clone)]
pub struct HealthState {
    inner: Inner,
    pub checks : Arc<RwLock<HashMap<String, bool>>>
}

#[derive(Clone)]
struct Inner {
    healthy : Arc<AtomicBool>,
    ready : Arc<AtomicBool>,
    live : Arc<AtomicBool>,
}

impl HealthState {
    pub fn is_healthy(&self) -> bool {
        self.inner.healthy.load(Acquire)
    }

    pub fn is_ready(&self) -> bool {
        self.inner.ready.load(Acquire)
    }

    pub fn is_live(&self) -> bool {
        self.inner.live.load(Acquire)
    }

    pub fn refresh_all(&self) {
        let mut ready = true;
        let ready_keys = vec!["api_ready"];

        for key in ready_keys {
            if *self.checks.read().unwrap().get(key).unwrap_or(&false) == false {
                ready = false;
            }
        }

        self.refresh_healthy();
        self.refresh_ready();
        self.refresh_live();
    }

    pub fn refresh_healthy(&self) {
        self.inner.healthy.store(true, Release);
    }

    pub fn refresh_ready(&self) {
        let mut ready = true;
        let ready_keys = vec!["api_ready"];

        for key in ready_keys {
            if *self.checks.read().unwrap().get(key).unwrap_or(&false) == false {
                ready = false;
            }
        }

        self.inner.ready.store(ready, Release);
    }

    pub fn refresh_live(&self) {
        self.inner.live.store(true, Release);
    }

    pub fn new() -> Self {
        Self {
            inner: Inner {
                healthy: Arc::new(AtomicBool::new(false)),
                ready: Arc::new(AtomicBool::new(false)),
                live: Arc::new(AtomicBool::new(false)),
            },
            checks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

pub async fn health(State(state) : State<HealthState>) -> (StatusCode) {
    if state.is_healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub async fn readiness(State(state) : State<HealthState>) -> (StatusCode) {
    if state.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub async fn liveness(State(state) : State<HealthState>) -> (StatusCode) {
    if state.is_live() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}