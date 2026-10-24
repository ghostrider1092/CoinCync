//! Live wiring of the block-integrity breaker into the real block-connect path —
//! a **feed adapter into the universal [`fuse`](crate::fuse) box**.
//!
//! `Blockchain::process_block` calls [`on_block_connected`] after a block is
//! accepted onto the main chain (`Accepted` / `AcceptedFork` / `AcceptedReorg`),
//! passing the REAL post-apply UTXO-set counters it reads from the public
//! accessors (`total_outputs_ever`, `active_output_count`,
//! `reorg_disconnects_total`). The feed runs the pure
//! [`block_integrity_breaker`](crate::block_integrity_breaker) detector on that
//! state and feeds the result to the one process-wide fuse box
//! ([`crate::fuse::observe`]) under [`BreakerSurface::BlockIntegrity`].
//!
//! The feed is placed in `process_block` — the single wrapper every block-ingest
//! caller (sync, mining submit, RPC submit) passes through — and runs AFTER
//! `add_block` has returned, reading only public accessors. The tuned, lock-held
//! apply body is never edited: the seam is the connector, not the heart.
//!
//! **Scope.** The cheap, O(1) counter invariants are checked for real:
//! monotonic `total_outputs_ever` (remembered across calls here), availability
//! non-underflow, and `live_set <= ever`. The UTXO-root match is NOT checked —
//! recomputing the whole-set commitment every connect is O(set) and belongs to
//! the Rung-2 activation (an incremental accumulator); `committed_utxo_root` is
//! left `None` here so that check is inert. **Observe-mode, Latch policy**: a
//! detected corruption trips the (shared-box) breaker and logs — it does NOT
//! reject the block. Isolating a block is consensus and stays a coordinated,
//! post-audit activation. Node-local, gated OFF by default
//! (`block-integrity-breaker` + `breaker-recovery`). See
//! `docs/design/cip-circuit-breakers.md`.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::block_integrity_breaker::{detect, IntegrityObservation};
use crate::breaker_recovery::{BreakerState, BreakerSurface};
use crate::fuse::{self, FaultReport};
use crate::primitives::Hash;

/// Last `total_outputs_ever` observed, for the monotonicity check (feed-local;
/// the breaker state itself lives in the shared fuse box). `u64::MAX` sentinel =
/// "no observation yet" so the first real connect never false-trips.
static PREV_EVER: AtomicU64 = AtomicU64::new(u64::MAX);

/// Called after a block is accepted onto the main chain, with the REAL post-apply
/// UTXO-set counters. Runs the integrity breaker through the shared fuse box and
/// returns the new breaker state.
pub fn on_block_connected(
    total_outputs_ever: u64,
    reorg_disconnects_total: u64,
    output_count: u64,
) -> BreakerState {
    let prev = PREV_EVER.load(Ordering::Relaxed);
    // First observation: seed prev = current so the monotonic check is a no-op.
    let prev_total_outputs_ever = if prev == u64::MAX { total_outputs_ever } else { prev };

    let obs = IntegrityObservation {
        prev_total_outputs_ever,
        total_outputs_ever,
        reorg_disconnects_total,
        output_count,
        // Whole-set commitment is O(set) — not computed per-connect here; the
        // root-match check is an activation concern (Rung-2 accumulator).
        computed_utxo_root: Hash::zero(),
        committed_utxo_root: None,
    };
    let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));

    // Per-connect observation trace (debug): proves the feed runs on every real
    // block connect, healthy or not. The shared fuse box still logs only state
    // TRANSITIONS (at warn); this is the "it's observing" heartbeat.
    tracing::debug!(
        target: "breaker.block_integrity",
        "block-integrity observed: ever={} live={} disconnects={} -> {}",
        total_outputs_ever,
        output_count,
        reorg_disconnects_total,
        if report.faulty { format!("FAULT {:?}", report.faults) } else { "healthy".to_string() }
    );

    // Remember the max ever-seen (monotonic) so a transient backwards reading
    // trips once rather than being silently adopted as the new baseline.
    PREV_EVER.store(prev_total_outputs_ever.max(total_outputs_ever), Ordering::Relaxed);

    fuse::observe(BreakerSurface::BlockIntegrity, &report)
}

/// The current live block-integrity breaker state from the shared box.
pub fn state() -> Option<BreakerState> {
    fuse::surface_state(BreakerSurface::BlockIntegrity)
}

/// Reset the feed (forget the monotonic baseline) and the breaker in the shared
/// box (test isolation).
pub fn reset() {
    PREV_EVER.store(u64::MAX, Ordering::Relaxed);
    fuse::reset_surface(BreakerSurface::BlockIntegrity);
}
