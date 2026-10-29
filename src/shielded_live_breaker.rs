//! Live wiring of the shielded-pool breaker into the real block-connect path —
//! a **feed adapter into the universal [`fuse`](crate::fuse) box** for
//! [`BreakerSurface::Shielded`].
//!
//! `Blockchain::process_block` calls [`on_block_connected`] after a block is
//! accepted, passing the REAL post-apply shielded pool value (from
//! `SparkPoolStore::pool_value`). The feed runs the pure
//! [`shielded_circuit_breaker`](crate::shielded_circuit_breaker) detector and
//! feeds the result to the one process-wide fuse box under
//! [`BreakerSurface::Shielded`].
//!
//! **Scope (honest).** Only `PoolNegative` (`pool_value < 0`, the
//! "no inflation across the veil" floor, `CYNC-SHLD-001`) is soundly observable
//! from current store state. The `InflationCeiling` check needs gross shield-in
//! tracking, and `BalanceMismatch` needs an INDEPENDENT `Σ(−value_balance)` to
//! cross-check against `pool_value` — neither is tracked yet, and both only
//! matter once the shielded pool is ACTIVATED (post-audit; it is gated off,
//! activation height `u64::MAX`, so `pool_value` is 0 at launch). They are kept
//! provably inert here (never false-trip) rather than fed guessed inputs, and
//! the per-block double-spend / proof-invalid flags are the pre-apply validator's
//! job. When shielded activates, this adapter grows the missing inputs.
//!
//! **Observe-mode, Latch policy**, gated OFF by default (`shielded-breaker` +
//! `breaker-recovery`). The arm gate is in `process_block`, default-off. See
//! docs/design/breaker-arm-switch.md.

use crate::breaker_recovery::{BreakerState, BreakerSurface};
use crate::fuse::{self, FaultReport};
use crate::shielded_circuit_breaker::{detect, PoolObservation};

/// Called after a block is accepted onto the main chain, with the REAL
/// post-apply shielded pool value. Runs the shielded breaker through the shared
/// fuse box and returns the new breaker state.
pub fn on_block_connected(pool_value: i128) -> BreakerState {
    let obs = PoolObservation {
        pool_value,
        // Inert until shielded activation (post-audit): `total_shielded_in`
        // (gross shield-in) and an independent `expected_from_balance` are not
        // tracked yet. Set so `InflationCeiling` (pool_value > this) and
        // `BalanceMismatch` (pool_value != this) cannot fire — only PoolNegative
        // is live. Not a hidden tautology: documented as a pending-activation gap.
        total_shielded_in: pool_value.max(0),
        expected_from_balance: pool_value,
        duplicate_linking_tag: false,
        proof_verify_failed: false,
        supply_divergence: false,
    };
    let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
    tracing::debug!(
        target: "breaker.shielded",
        "shielded pool observed: value={} -> {}",
        pool_value,
        if report.faulty { format!("FAULT {:?}", report.faults) } else { "healthy".to_string() }
    );
    fuse::observe(BreakerSurface::Shielded, &report)
}

/// The current live shielded breaker state from the shared box.
pub fn state() -> Option<BreakerState> {
    fuse::surface_state(BreakerSurface::Shielded)
}

/// Reset the breaker in the shared box (test isolation).
pub fn reset() {
    fuse::reset_surface(BreakerSurface::Shielded);
}
