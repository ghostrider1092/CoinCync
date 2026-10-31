//! Live wiring of the mempool circuit breaker into the real admission path —
//! a **feed adapter into the universal [`fuse`](crate::fuse) box**.
//!
//! `Mempool::admit_after_checks` (the single admission chokepoint) calls
//! [`on_admission`] on every successful admit, passing the **real** post-admit
//! mempool count and byte footprint. This module runs the pure
//! [`mempool_breaker`](crate::mempool_breaker) detector on that real state and
//! feeds the result to the one process-wide fuse box
//! ([`crate::fuse::observe`]) under [`BreakerSurface::Mempool`]. The breaker
//! STATE lives in the shared box (one source of truth, one snapshot); only the
//! per-window arrival counter is local here, because arrival-rate is a feed
//! concern, not box state.
//!
//! **Observe-mode: it logs, it does not throttle.** The wire-in is pure
//! observability on real mempool state — it never changes admission behavior,
//! is node-local (no consensus effect, cannot fork), and the whole thing is
//! gated OFF by default (`mempool-breaker` + `breaker-recovery`). Enforcement
//! (actually shedding) would be a later, explicit step.
//!
//! Caps are env-configurable for operability; defaults are production values.
//! See `docs/design/cip-circuit-breakers.md`.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::breaker_recovery::{BreakerState, BreakerSurface};
use crate::fuse::{self, FaultReport};
use crate::mempool_breaker::{detect, MempoolObservation};

/// Per-window arrival counter (feed-local; the breaker state itself is in the
/// shared fuse box).
static ARRIVALS: AtomicU32 = AtomicU32::new(0);

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Called on every successful mempool admission with the REAL post-admission
/// mempool count + byte footprint. Runs the breaker through the shared fuse box
/// and returns the new breaker state.
pub fn on_admission(pending_count: usize, pending_bytes: usize) -> BreakerState {
    let max_count = env_usize("COINCYNC_MEMPOOL_BREAKER_MAX_COUNT", 50_000);
    let max_bytes = env_usize("COINCYNC_MEMPOOL_BREAKER_MAX_BYTES", 300_000_000);
    let max_arrivals = env_u32("COINCYNC_MEMPOOL_BREAKER_MAX_ARRIVALS", 1_000_000);

    let arrivals = ARRIVALS.fetch_add(1, Ordering::Relaxed).saturating_add(1);

    let obs = MempoolObservation {
        pending_count,
        max_count,
        pending_bytes,
        max_bytes,
        arrivals_this_interval: arrivals,
        max_arrivals_per_interval: max_arrivals,
        // Per-peer / dust accounting isn't available at this chokepoint; leave
        // them non-tripping here (the P2P breaker owns per-peer flood).
        worst_peer_arrivals: 0,
        max_per_peer_arrivals: u32::MAX,
        dust_arrivals: 0,
        max_dust: u32::MAX,
    };
    let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
    fuse::observe(BreakerSurface::Mempool, &report)
}

/// The current live mempool breaker state from the shared box, or `None` if the
/// surface isn't installed.
pub fn state() -> Option<BreakerState> {
    fuse::surface_state(BreakerSurface::Mempool)
}

/// Reset the mempool feed (fresh arrival window) and its breaker in the shared
/// box (test isolation).
pub fn reset() {
    ARRIVALS.store(0, Ordering::Relaxed);
    fuse::reset_surface(BreakerSurface::Mempool);
}
