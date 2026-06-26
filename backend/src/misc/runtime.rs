//! Tokio runtime sizing helpers.
//!
//! `tokio::runtime::Builder::new_multi_thread()` defaults `worker_threads` to
//! `std::thread::available_parallelism()`, which on Linux reads CPU *affinity* — not the
//! cgroup CPU *limit* (CFS quota). A Kubernetes `limits.cpu` does not pin affinity, so on a
//! large node every runtime would spawn one worker thread per *host* core (e.g. 32) while
//! the pod is only allowed ~3 cores. Each thread also seeds its own allocator arena and
//! carries a ~2 MB stack, so the over-subscription both throttles (CFS) and bloats RSS.
//!
//! These helpers clamp the worker count to a sane cap (never more than the host actually
//! has), so thread counts stay bounded regardless of node size.

/// Worker threads for a runtime, clamped to `cap` (and to the host's real parallelism so a
/// tiny node still uses fewer). Always at least 1.
pub fn worker_threads(cap: usize) -> usize {
    let avail = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    avail.min(cap).max(1)
}
