//! Live wiring of the supply breaker into the real block-connect path — a
//! **feed adapter into the universal [`fuse`](crate::fuse) box** for
//! [`BreakerSurface::Supply`].
//!
//! `Blockchain::process_block` calls [`on_block_connected`] after a block is
//! accepted onto the main chain, passing the REAL post-apply supply counters it
//! reads from its own stats (`total_supply`, `total_burned`) plus the scheduled
//! ceiling (`emission::supply::cumulative_emission`). The feed runs the pure
//! [`supply_breaker`](crate::supply_breaker) detector and feeds the result to
//! the one process-wide fuse box under [`BreakerSurface::Supply`].
//!
//! **Scope.** This sentinel observes the AGGREGATE supply state: circulating
//! supply (`emitted − burned`) must not go negative and must not exceed the
//! scheduled ceiling. The per-block `OverEmission` invariant (coinbase ≤ reward
//! + fees) is already enforced by the locked validator (M4 / `CYNC-EMIT-001`),
//! so the per-block observation fields are left neutral here — the sentinel is a
//! second, independent watch over the running total, not a re-implementation of
//! the validator. `circulating` is constructed from the same `emitted`/`burned`
//! the identity check reads, so `CirculatingMismatch` cannot false-trip.
//!
//! **Observe-mode, Latch policy**, gated OFF by default (`supply-breaker` +
//! `breaker-recovery`). The arm gate (`fuse::enforce_trips`) lives in
//! `process_block` and is default-off (`fuse::default_arm_height` = `u64::MAX`);
//! isolating a block on a supply fault is a coordinated, activation-gated
//! decision. See docs/design/breaker-arm-switch.md.

use crate::breaker_recovery::{BreakerState, BreakerSurface};
use crate::fuse::{self, FaultReport};
use crate::supply_breaker::{detect, SupplyObservation};

/// Called after a block is accepted onto the main chain, with the REAL
/// post-apply gross emitted supply, burned total, and height. Runs the supply
/// breaker through the shared fuse box and returns the new breaker state.
pub fn on_block_connected(total_supply: u128, total_burned: u128, height: u64) -> BreakerState {
    let circulating = total_supply as i128 - total_burned as i128;
    let max_supply = crate::emission::supply::cumulative_emission(height) as i128;
    let obs = SupplyObservation {
        // Per-block emission is the locked validator's job (CYNC-EMIT-001); these
        // stay neutral so `OverEmission` (coinbase_payout > allowed + fees) never
        // fires here — the sentinel watches the AGGREGATE state below.
        coinbase_payout: 0,
        allowed_emission: 0,
        block_fees: 0,
        total_emitted: total_supply as i128,
        total_burned: total_burned as i128,
        // == total_emitted − total_burned by construction, so CirculatingMismatch
        // cannot false-trip; NegativeSupply / SupplyCeilingExceeded are the live checks.
        circulating,
        max_supply,
        committed_supply: None,
    };
    let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
    tracing::debug!(
        target: "breaker.supply",
        "supply observed: emitted={} burned={} circulating={} ceiling={} -> {}",
        total_supply,
        total_burned,
        circulating,
        max_supply,
        if report.faulty { format!("FAULT {:?}", report.faults) } else { "healthy".to_string() }
    );
    fuse::observe(BreakerSurface::Supply, &report)
}

/// The current live supply breaker state from the shared box.
pub fn state() -> Option<BreakerState> {
    fuse::surface_state(BreakerSurface::Supply)
}

/// Reset the breaker in the shared box (test isolation).
pub fn reset() {
    fuse::reset_surface(BreakerSurface::Supply);
}
