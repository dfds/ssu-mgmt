use crate::api::{api_router, WebState};
use crate::misc::config::load_conf;
use crate::misc::services::{Services, ServicesShared};
use axum::extract::State;
use axum::http::StatusCode;
use jwt_authorizer::{Authorizer, JwtAuthorizer, Validation};
use log::info;
use serde_json::Value;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Acquire, Release};
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;

pub fn start_health(
    shutdown: seqtf_bootstrap::shutdown::Shutdown,
    ss: ServicesShared,
    listen_addr: String,
) {
    let hs = ss.read().unwrap().get_service::<HealthState>().unwrap();

    let _hs = hs.clone();
    std::thread::spawn(move || {
        let _s = shutdown.clone();
        info!("Health endpoint listening on: {}", listen_addr);

        let rt_conf = load_conf().unwrap().runtime;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("health_worker")
            .worker_threads(crate::misc::runtime::worker_threads(
                rt_conf.health_worker_threads,
            ))
            .max_blocking_threads(rt_conf.health_max_blocking_threads)
            .enable_all()
            .build()
            .expect("Unable to create health server pool");

        runtime.block_on(async move {
            let conf = load_conf().unwrap();

            let mut app = axum::Router::new()
                .route("/health", axum::routing::get(health))
                .route("/ready", axum::routing::get(readiness))
                .route("/live", axum::routing::get(liveness))
                // Always-on, cheap, read-only memory snapshot on the internal health
                // server. Poll at ~1s to watch RSS climb in real time (Prometheus is
                // too coarse) and to separate a real app-side leak (jemalloc
                // `allocated` rising) from allocator retention (`resident`/`retained`
                // rising while `allocated` is flat). See `mem_stats`.
                .route("/debug/mem", axum::routing::get(mem_stats));

            if conf.profiling.enable {
                info!("pprof profiling endpoint enabled at /debug/pprof/profile");
                app = app.merge(pprof_routes(conf.profiling.clone()));
            }

            let app = app
                .with_state(_hs.deref().clone())
                .layer(axum::middleware::from_fn(crate::api::default_headers));

            let listener = TcpListener::bind(listen_addr.as_str()).await.unwrap();
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown.exit)
                .await
                .unwrap();
        });
    });
}

#[derive(Clone)]
pub struct HealthState {
    inner: Inner,
    pub checks: Arc<RwLock<HashMap<String, bool>>>,
}

#[derive(Clone)]
struct Inner {
    healthy: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    live: Arc<AtomicBool>,
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

pub async fn health(State(state): State<HealthState>) -> (StatusCode) {
    if state.is_healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub async fn readiness(State(state): State<HealthState>) -> (StatusCode) {
    if state.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub async fn liveness(State(state): State<HealthState>) -> (StatusCode) {
    if state.is_live() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

// ---- /debug/mem : memory snapshot -----------------------------------------
//
// Returns process RSS (what the cgroup OOM-killer actually counts) alongside
// jemalloc's own counters. Cheap and read-only — safe to poll every second:
//
//   while :; do curl -s localhost:9001/debug/mem; echo; sleep 1; done
//
// Reading the two numbers together is the diagnostic:
//   - `rss_bytes` is the kernel's view (drives the OOM kill).
//   - jemalloc `allocated` = bytes the application actually holds. If this
//     climbs unbounded → a real leak in app data structures.
//   - `resident`/`retained` climbing while `allocated` is flat → the allocator
//     is holding freed pages back from the OS (decay/fragmentation), not a leak.
async fn mem_stats() -> axum::Json<Value> {
    axum::Json(serde_json::json!({
        "rss_bytes": proc_rss_bytes(),
        "rss_peak_bytes": proc_status_field("VmHWM"),
        "vm_size_bytes": proc_status_field("VmSize"),
        "jemalloc": jemalloc_stats(),
    }))
}

/// Current RSS, read as `VmRSS` from `/proc/self/status`. Linux-only; `None`
/// elsewhere (e.g. macOS dev). This is the number the cgroup OOM-killer sees.
fn proc_rss_bytes() -> Option<u64> {
    proc_status_field("VmRSS")
}

/// Read a `VmXxx:` field (kB) from `/proc/self/status`, returned as bytes.
/// Linux-only; `None` elsewhere.
fn proc_status_field(field: &str) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix(field) {
                // e.g. "VmRSS:\t  123456 kB"
                let kb: u64 = rest
                    .trim_start_matches(':')
                    .trim()
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = field;
        None
    }
}

/// jemalloc's internal counters. `epoch::advance()` must be called first to
/// refresh the cached stats, otherwise every read returns the boot-time values.
/// `allocated` = live application bytes; `active`/`resident`/`retained`/`mapped`
/// describe what the allocator holds from the OS.
fn jemalloc_stats() -> Value {
    #[cfg(not(target_env = "msvc"))]
    {
        use tikv_jemalloc_ctl::{epoch, stats};
        // Refresh the snapshot; if it fails the reads below just return the stale
        // (or zero) values — still better than nothing.
        let _ = epoch::advance();
        serde_json::json!({
            "allocated_bytes": stats::allocated::read().ok(),
            "active_bytes": stats::active::read().ok(),
            "resident_bytes": stats::resident::read().ok(),
            "retained_bytes": stats::retained::read().ok(),
            "mapped_bytes": stats::mapped::read().ok(),
            "metadata_bytes": stats::metadata::read().ok(),
        })
    }
    #[cfg(target_env = "msvc")]
    {
        Value::Null
    }
}

// ---- on-demand pprof CPU profiler -----------------------------------------
//
// `GET /debug/pprof/profile?seconds=N&hz=M&format=svg|pb` samples the whole
// process for N seconds and returns a flamegraph SVG (or pprof protobuf for
// `go tool pprof`). Mounted on the internal health server only. pprof uses
// SIGPROF — only one profiler can run process-wide, so a second concurrent
// request is rejected with 409.

use axum::extract::Query;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

/// One profiler may run at a time (SIGPROF is process-global). Acquired in the
/// handler, released inside the blocking task so it tracks the profiler's real
/// lifetime even if the client disconnects mid-profile.
static PROFILING_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Deserialize)]
struct ProfileParams {
    seconds: Option<u64>,
    hz: Option<i32>,
    format: Option<String>,
}

fn pprof_routes(cfg: crate::misc::config::ProfilingConfig) -> axum::Router<HealthState> {
    let profile_cfg = cfg.clone();
    axum::Router::new()
        .route(
            "/debug/pprof/profile",
            axum::routing::get(move |q: Query<ProfileParams>| pprof_profile(q, profile_cfg.clone())),
        )
        .route(
            "/debug/pprof",
            axum::routing::get(move || {
                let cfg = cfg.clone();
                async move {
                    format!(
                        "pprof CPU profiler\n\nGET /debug/pprof/profile?seconds=N&hz=M&format=svg|pb\n  seconds  sampling duration (default {}, max {})\n  hz       sampling frequency (default {})\n  format   svg (flamegraph, default) | pb (pprof protobuf for `go tool pprof`)\n\nOnly one profile may run at a time (409 if busy).\n",
                        cfg.default_seconds, cfg.max_seconds, cfg.default_hz,
                    )
                }
            }),
        )
}

async fn pprof_profile(
    Query(p): Query<ProfileParams>,
    cfg: crate::misc::config::ProfilingConfig,
) -> Response {
    // Reject if a profile is already running (SIGPROF is single-instance).
    if PROFILING_ACTIVE
        .compare_exchange(false, true, std::sync::atomic::Ordering::AcqRel, Acquire)
        .is_err()
    {
        return (
            StatusCode::CONFLICT,
            "a profile is already running; retry once it finishes\n",
        )
            .into_response();
    }

    let seconds = p
        .seconds
        .unwrap_or(cfg.default_seconds)
        .clamp(1, cfg.max_seconds.max(1));
    let hz = p.hz.unwrap_or(cfg.default_hz).clamp(1, 1000);
    let format = p.format.unwrap_or_else(|| "svg".to_owned());

    // The whole profile runs on a blocking thread: `pprof::ProfilerGuard` is
    // `!Send` and must not cross an `.await`. The SIGPROF sampler still covers
    // every thread in the process regardless of where this runs. The flag is
    // released here (Drop) so it tracks the profiler's actual lifetime.
    let result = tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, &'static str), String> {
        struct ActiveGuard;
        impl Drop for ActiveGuard {
            fn drop(&mut self) {
                PROFILING_ACTIVE.store(false, Release);
            }
        }
        let _active = ActiveGuard;

        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(hz)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .map_err(|e| format!("profiler start failed: {e}"))?;

        std::thread::sleep(std::time::Duration::from_secs(seconds));

        let report = guard
            .report()
            .build()
            .map_err(|e| format!("report build failed: {e}"))?;

        match format.as_str() {
            "pb" | "proto" | "pprof" => {
                use pprof::protos::Message;
                let profile = report
                    .pprof()
                    .map_err(|e| format!("pprof encode failed: {e}"))?;
                let bytes = profile
                    .write_to_bytes()
                    .map_err(|e| format!("protobuf serialize failed: {e}"))?;
                Ok((bytes, "application/octet-stream"))
            }
            _ => {
                let mut buf = Vec::new();
                report
                    .flamegraph(&mut buf)
                    .map_err(|e| format!("flamegraph render failed: {e}"))?;
                Ok((buf, "image/svg+xml"))
            }
        }
    })
    .await;

    match result {
        Ok(Ok((bytes, content_type))) => {
            ([(axum::http::header::CONTENT_TYPE, content_type)], bytes).into_response()
        }
        Ok(Err(msg)) => {
            // The blocking task ran (so the ActiveGuard already reset the flag).
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{msg}\n")).into_response()
        }
        Err(join_err) => {
            // The blocking task panicked before its Drop guard ran in the normal
            // path — reset defensively so the endpoint isn't wedged.
            PROFILING_ACTIVE.store(false, Release);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("profiling task failed: {join_err}\n"),
            )
                .into_response()
        }
    }
}
