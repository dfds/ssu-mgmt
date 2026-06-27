mod api;
mod db;
mod messaging;
mod misc;
pub mod schema;
mod service;

// Use jemalloc instead of glibc malloc — see the dependency note in Cargo.toml. This is
// the primary fix for the production OOM (glibc arena fragmentation that never shrinks).
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use crate::api::{api_router, start_server, WebState};
use crate::messaging::offset_tracker::new_offset_tracker;
use crate::misc::config::load_conf;
use crate::misc::health::{start_health, HealthState};
use dashmap::DashMap;
use jwt_authorizer::{Authorizer, JwtAuthorizer, Validation};
use log::info;
use seqtf_bootstrap::bootstrap;
use serde_json::Value;
use std::sync::Arc;
use tokio::net::TcpListener;

// `main` only orchestrates setup then blocks on the shutdown signal — it does no async
// work itself (the API/health/worker runtimes each own a dedicated multi-thread runtime on
// their own thread). A multi-thread runtime here would spawn one worker thread per *host*
// core for nothing, so use a single-thread runtime.
#[tokio::main(flavor = "multi_thread", worker_threads = 6)]
async fn main() {
    let conf = load_conf().unwrap();
    let mut builder = bootstrap("ssu_mgmt".to_owned())
        .enable_logging(true)
        // .set_log_directives(vec!["ssu_mgmt::messaging=info".to_owned()])
        .set_log_level(seqtf_bootstrap::logging::get_trace_level(&conf.log_level).unwrap())
        .enable_metrics(format!(
            "{}:{}",
            conf.metrics_listen_address, conf.metrics_port
        ))
        .enable_shutdown_signal(true);
    if conf.tracing.enable {
        let protocol = match conf.tracing.protocol.to_lowercase().as_str() {
            "http" | "http-proto" | "httpproto" => seqtf_bootstrap::OtlpProtocol::HttpProto,
            _ => seqtf_bootstrap::OtlpProtocol::Grpc,
        };
        let headers: Vec<(String, String)> = conf
            .tracing
            .otlp_headers
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect();
        let mut resource_attributes: Vec<(String, String)> = Vec::new();
        if !conf.tracing.namespace.trim().is_empty() {
            resource_attributes.push((
                "service.namespace".to_owned(),
                conf.tracing.namespace.trim().to_owned(),
            ));
        }
        if !conf.tracing.environment.trim().is_empty() {
            resource_attributes.push((
                "deployment.environment".to_owned(),
                conf.tracing.environment.trim().to_owned(),
            ));
            resource_attributes.push((
                "deployment.environment.name".to_owned(),
                conf.tracing.environment.trim().to_owned(),
            ));
        }
        resource_attributes.extend(
            conf.tracing
                .resource_attributes
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned())),
        );
        builder = builder.enable_otlp(seqtf_bootstrap::OtlpOptions {
            endpoint: conf.tracing.otlp_endpoint.clone(),
            protocol,
            sample_ratio: conf.tracing.sample_ratio,
            service_name: conf.tracing.service_name.clone(),
            service_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            headers,
            resource_attributes,
        });
    }
    let bs_resp = builder.build().activate();
    // Held until shutdown; `.shutdown()` flushes the final span batch (see end of main).
    let tracing_guard = bs_resp.tracing;
    // Held until shutdown; `.shutdown()` flushes the final span batch (see end of main).
    info!("launching ssu-mgmt");
    info!("log level: {}", conf.log_level);
    if conf.tracing.enable {
        info!(
            "OTLP tracing enabled → {} ({})",
            conf.tracing.otlp_endpoint, conf.tracing.protocol
        );
        let header_names: Vec<&str> = conf
            .tracing
            .otlp_headers
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, _)| k.trim())
            .collect();
        if !header_names.is_empty() {
            info!("OTLP auth headers configured: {}", header_names.join(", "));
        }
        let mut attrs: Vec<String> = Vec::new();
        if !conf.tracing.namespace.trim().is_empty() {
            attrs.push(format!(
                "service.namespace={}",
                conf.tracing.namespace.trim()
            ));
        }
        if !conf.tracing.environment.trim().is_empty() {
            attrs.push(format!(
                "deployment.environment={}",
                conf.tracing.environment.trim()
            ));
        }
        attrs.extend(
            conf.tracing
                .resource_attributes
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned()),
        );
        if !attrs.is_empty() {
            info!("OTLP resource attributes: {}", attrs.join(", "));
        }
    }

    db::init(&conf.db).unwrap();

    let db_pool = db::build_pool(&conf.db);

    let ss = misc::services::init();
    ss.write()
        .unwrap()
        .add_service::<db::DbPool>(db_pool.clone());

    service::ingest::init_progress_hub();

    // bg channel created here (before start_server) so the API server can grab the
    // sender for self-audit; the bg writer + Context wiring below reuse it.
    let (bg_s, bg_r) = crossbeam::channel::unbounded::<service::bg::Message>();
    ss.write().unwrap().add_service(bg_s.clone());

    let cancel_signal = bs_resp.shutdown_signal.unwrap();
    if conf.enable_api {
        info!("API server enabled");
        start_server(
            cancel_signal.clone(),
            ss.clone(),
            format!("{}:{}", conf.api_listen_address, conf.api_port),
        );
    } else {
        info!("API server disabled");
    }
    start_health(
        cancel_signal.clone(),
        ss.clone(),
        format!("{}:{}", conf.health_listen_address, conf.health_port),
    );

    // async setup
    let async_worker_runtime_cancel_token = tokio_util::sync::CancellationToken::new();
    let aw_rt_cancel_token = async_worker_runtime_cancel_token.clone();

    if conf.enable_api {
        service::progress_relay::spawn(conf.db.clone(), async_worker_runtime_cancel_token.clone());
    }

    let cs = cancel_signal.clone();
    let wg = crossbeam::sync::WaitGroup::new();
    let aw_wg = wg.clone();

    // bg setup (channel `bg_s`/`bg_r` created earlier so the API can self-audit).
    let offset_tracker = new_offset_tracker();
    ss.write().unwrap().add_service(offset_tracker.clone());

    // bg work
    service::bg::start(
        cs.clone(),
        bg_s.clone(),
        bg_r.clone(),
        offset_tracker.clone(),
        db_pool.clone(),
    );

    let ingest_pool = db_pool.clone();

    let context = misc::context::Context {
        offset_tracker: offset_tracker.clone(),
        bg_sender: bg_s.clone(),
        bg_receiver: bg_r.clone(),
    };
    ss.write()
        .unwrap()
        .add_named_service(context.clone(), messaging::SS_CONTEXT_NAME);

    // async bg work
    std::thread::spawn(move || {
        let wg = aw_wg;
        let async_worker_runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .thread_name("async_worker")
                .worker_threads(crate::misc::runtime::worker_threads(
                    conf.runtime.worker_worker_threads,
                ))
                // Bounds the spawn_blocking pool (default 512). The workers' blocking work is
                // concurrent gz-decode (≤ cloudtrail `workers`) + Diesel DB ops (≤ pool size),
                // so the default 32 is ample and keeps thread stacks + arenas from exploding.
                .max_blocking_threads(conf.runtime.worker_max_blocking_threads)
                .enable_all()
                .build()
                .expect("Unable to create async worker pool"),
        );
        let aw_rt = async_worker_runtime.clone();

        std::thread::spawn(move || {
            // event consumer
            if conf.enable_messaging_ingest {
                info!("Messaging ingest enabled");
                aw_rt.spawn(messaging::start_messaging(
                    aw_rt_cancel_token.clone(),
                    ss.clone(),
                ));
            } else {
                info!("Messaging ingest disabled");
            }

            service::leader::spawn(
                aw_rt.clone(),
                conf.clone(),
                ingest_pool.clone(),
                aw_rt_cancel_token.clone(),
            );
        });

        cs.wait();
        std::thread::sleep(std::time::Duration::from_secs(3));
    });

    cancel_signal.wait();
    async_worker_runtime_cancel_token.cancel();
    wg.wait();

    // Flush any spans still buffered in the OTLP batch processor before exit.
    if let Some(guard) = tracing_guard {
        info!("flushing OTLP tracer");
        guard.shutdown();
    }
}
