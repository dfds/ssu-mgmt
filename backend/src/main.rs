mod misc;
mod api;
mod messaging;
mod service;
pub mod schema;
mod db;

use std::sync::Arc;
use dashmap::DashMap;
use jwt_authorizer::{Authorizer, JwtAuthorizer, Validation};
use log::info;
use seqtf_bootstrap::bootstrap;
use serde_json::Value;
use tokio::net::TcpListener;
use crate::api::{api_router, start_server, WebState};
use crate::messaging::offset_tracker::new_offset_tracker;
use crate::misc::config::load_conf;
use crate::misc::health::{HealthState, start_health};

#[tokio::main]
async fn main() {
    let conf = load_conf().unwrap();
    let bs_resp = bootstrap("ssu_mgmt".to_owned())
        .enable_logging(true)
        // .set_log_directives(vec!["ssu_mgmt::messaging=info".to_owned()])
        .set_log_level(seqtf_bootstrap::logging::get_trace_level(&conf.log_level).unwrap())
        .enable_metrics(format!("{}:{}", conf.metrics_listen_address, conf.metrics_port))
        .enable_shutdown_signal(true)
        .build()
        .activate();
    info!("launching ssu-mgmt");
    info!("log level: {}", conf.log_level);

    db::init(&conf.db).unwrap();

    let ss = misc::services::init();
    let cancel_signal = bs_resp.shutdown_signal.unwrap();
    start_server(cancel_signal.clone(), ss.clone(), format!("{}:{}", conf.api_listen_address, conf.api_port));
    start_health(cancel_signal.clone(), ss.clone(),format!("{}:{}", conf.health_listen_address, conf.health_port) );

    // async setup
    let async_worker_runtime_cancel_token = tokio_util::sync::CancellationToken::new();
    let aw_rt_cancel_token = async_worker_runtime_cancel_token.clone();
    let cs = cancel_signal.clone();
    let wg = crossbeam::sync::WaitGroup::new();
    let aw_wg = wg.clone();

    // bg setup
    let (bg_s, bg_r) = crossbeam::channel::unbounded::<service::bg::Message>();
    let offset_tracker = new_offset_tracker();
    ss.write().unwrap().add_service(offset_tracker.clone());

    // bg work
    service::bg::start(cs.clone(), bg_s.clone(), bg_r.clone(), offset_tracker.clone());

    let context = misc::context::Context {
        offset_tracker: offset_tracker.clone(),
        bg_sender: bg_s.clone(),
        bg_receiver: bg_r.clone(),
    };
    ss.write().unwrap().add_named_service(context.clone(), messaging::SS_CONTEXT_NAME);

    // async bg work
    std::thread::spawn(move || {
        let wg = aw_wg;
        let async_worker_runtime = Arc::new(tokio::runtime::Builder::new_multi_thread()
            .thread_name("async_worker")
            .enable_all()
            .build().expect("Unable to create async worker pool"));
        let aw_rt = async_worker_runtime.clone();

        std::thread::spawn(move || {
            // event consumer
            if conf.enable_messaging_ingest {
                info!("Messaging ingest enabled");
                aw_rt.spawn(messaging::start_messaging(aw_rt_cancel_token.clone(), ss.clone()));
            } else {
                info!("Messaging ingest disabled");
            }
        });

        cs.wait();
        std::thread::sleep(std::time::Duration::from_secs(3));
    });

    cancel_signal.wait();
    async_worker_runtime_cancel_token.cancel();
    wg.wait();
}
