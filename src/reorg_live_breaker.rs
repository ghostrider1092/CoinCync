//! Live wiring of the reorg / finality breaker into the real reorg-accept path —
//! a **feed adapter into the universal [`fuse`](crate::fuse) box**.
//!
//! When `Blockchain::add_block` has decided a competing fork wins and is about to
//! perform the switch, it calls [`on_reorg`] with the REAL decision values it has
//! already computed — reorg depth, the network's max safe depth, the fork-point
//! height, and the competing/active cumulative work. The feed runs the pure
//! [`reorg_breaker`](crate::reorg_breaker) detector and feeds the result to the
//! one process-wide fuse box ([`crate::fuse::observe`]) under
//! [`BreakerSurface::Reorg`].
//!
//! The call is a single gated, side-effect-free line at the decision site (it
//! reads locals the apply already computed and mutates no chain state) — the same
//! shape as the existing gated finality block there.
//!
//! **Scope.** `DeepReorg` (depth > max safe) and `BelowFinalized` (fork point at
//! or below the finality floor) mirror the chain's own primary reorg gates, so
//! this is chain-consistent defense-in-depth: by the time a reorg is accepted the
//! chain's gates have passed, so a trip here would mean the breaker and the gate
//! *disagree* — itself the signal worth having. The churn and work-ratio ceilings
//! are left non-tripping by default (reorg-rate tracking is a follow-up; a
//! work-ratio policy ceiling is operator-set via env), so no threshold is
//! invented. **Observe-mode, AutoReset policy** (the danger passes once the honest
//! chain settles). Node-local telemetry; refusing a reorg is consensus and stays a
//! coordinated, post-audit activation. Gated OFF by default (`reorg-breaker` +
//! `breaker-recovery`). See `docs/design/cip-circuit-breakers.md`.

use crate::breaker_recovery::{BreakerState, BreakerSurface};
use crate::fuse::{self, FaultReport};
use crate::reorg_breaker::{detect, ReorgObservation};

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Competing-chain work as a percentage of the active chain's work, clamped to
/// `u32` (e.g. 400 = 4x). Saturating so a huge ratio reads as the ceiling, not a
/// wrap. `0` active work (genesis edge) reports 100%.
fn work_ratio_pct(incoming: u128, active: u128) -> u32 {
    if active == 0 {
        return 100;
    }
    let pct = incoming.saturating_mul(100) / active;
    pct.min(u32::MAX as u128) as u32
}

/// Called at the reorg-accept decision with the REAL computed values. Runs the
/// reorg breaker through the shared fuse box and returns the new breaker state.
pub fn on_reorg(
    reorg_depth: u64,
    max_safe_depth: u64,
    fork_point_height: u64,
    finalized_height: u64,
    incoming_work: u128,
    active_work: u128,
) -> BreakerState {
    let obs = ReorgObservation {
        reorg_depth,
        max_safe_depth,
        fork_point_height,
        finalized_height,
        // Reorg-rate tracking is a follow-up; non-tripping here.
        reorgs_in_window: 0,
        max_reorgs_in_window: u32::MAX,
        incoming_work_ratio_pct: work_ratio_pct(incoming_work, active_work),
        // No invented policy ceiling — operator-set, default non-tripping.
        max_work_ratio_pct: env_u32("COINCYNC_REORG_MAX_WORK_RATIO_PCT", u32::MAX),
    };
    let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
    fuse::observe(BreakerSurface::Reorg, &report)
}

/// The current live reorg breaker state from the shared box.
pub fn state() -> Option<BreakerState> {
    fuse::surface_state(BreakerSurface::Reorg)
}

/// Reset the reorg breaker in the shared box (test isolation).
pub fn reset() {
    fuse::reset_surface(BreakerSurface::Reorg);
}
