//! Live wiring of the RPC breaker into the real RPC request path — a **feed
//! adapter into the universal [`fuse`](crate::fuse) box**.
//!
//! The RPC server's per-request validation seam (the same place the IP rate
//! limiter runs, `rpc::server`) calls [`on_request`] on every non-preflight
//! request with the request's declared body size. This module keeps a small
//! rolling window (request count + largest body seen) and runs the pure
//! [`rpc_breaker`](crate::rpc_breaker) detector each request, feeding the result
//! to the one process-wide fuse box ([`crate::fuse::observe`]) under
//! [`BreakerSurface::Rpc`].
//!
//! **Observe-mode: it logs, it does not throttle.** The IP rate limiter already
//! enforces; this is the *fuse-box view* of RPC health (so one snapshot covers
//! every surface, with the shared recovery machine). Node-local, no consensus
//! effect, gated OFF by default (`rpc-breaker` + `breaker-recovery`).
//!
//! **Scope.** Global request-rate (`RequestFlood`) and body-size
//! (`OversizePayload`) are observed for real from the window + the request's
//! `Content-Length`. Per-client share, expensive-method, in-flight concurrency,
//! and unauth-probe signals need deeper RPC-layer accounting (the IP limiter owns
//! per-client today) and are left non-tripping here — documented follow-ups, the
//! same pattern as the mempool / p2p feeds. Thresholds are env-configurable
//! telemetry bounds, not enforcement. See `docs/design/cip-circuit-breakers.md`.

use std::sync::Mutex;
use std::time::Instant;

use crate::breaker_recovery::{BreakerState, BreakerSurface};
use crate::fuse::{self, FaultReport};
use crate::rpc_breaker::{detect, RpcObservation};

struct Window {
    start: Instant,
    requests: u32,
    max_body: usize,
}

static WINDOW: Mutex<Option<Window>> = Mutex::new(None);

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Called on every non-preflight RPC request with its declared body size
/// (`Content-Length`, 0 if absent). Rolls the observation window, runs the RPC
/// breaker through the shared fuse box, and returns the new breaker state.
pub fn on_request(body_bytes: usize) -> BreakerState {
    let interval_secs = env_u64("COINCYNC_RPC_BREAKER_INTERVAL_SECS", 10);
    let max_requests = env_u32("COINCYNC_RPC_BREAKER_MAX_REQUESTS", 10_000);
    let max_body = env_usize("COINCYNC_RPC_BREAKER_MAX_BODY_BYTES", 10 * 1024 * 1024);

    let (requests, max_body_seen) = {
        let mut guard = WINDOW.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let w = guard.get_or_insert_with(|| Window { start: now, requests: 0, max_body: 0 });
        if now.duration_since(w.start).as_secs() >= interval_secs {
            // New window.
            w.start = now;
            w.requests = 0;
            w.max_body = 0;
        }
        w.requests = w.requests.saturating_add(1);
        w.max_body = w.max_body.max(body_bytes);
        (w.requests, w.max_body)
    };

    let obs = RpcObservation {
        requests_this_interval: requests,
        max_requests_per_interval: max_requests,
        // Per-client share is owned by the IP rate limiter today — non-tripping.
        worst_client_requests: 0,
        max_per_client_requests: u32::MAX,
        // Expensive-method / in-flight accounting is a follow-up — non-tripping.
        expensive_calls: 0,
        max_expensive_calls: u32::MAX,
        in_flight: 0,
        max_in_flight: usize::MAX,
        max_body_bytes_seen: max_body_seen,
        max_body_bytes: max_body,
        unauth_sensitive_attempts: 0,
    };
    let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
    fuse::observe(BreakerSurface::Rpc, &report)
}

/// The current live RPC breaker state from the shared box.
pub fn state() -> Option<BreakerState> {
    fuse::surface_state(BreakerSurface::Rpc)
}

/// Reset the window and the RPC breaker in the shared box (test isolation).
pub fn reset() {
    *WINDOW.lock().unwrap_or_else(|p| p.into_inner()) = None;
    fuse::reset_surface(BreakerSurface::Rpc);
}
