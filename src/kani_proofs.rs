//! Kani proof harnesses for top-level helpers (constants module).
//!
//! Lives outside `src/constants.rs` because that file is locked by
//! `critical_files.lock` — adding proofs to it would require a
//! constitutional refresh on every proof change. Sibling-file pattern
//! lets the proof suite evolve without touching the locked file.
//!
//! See `src/emission/kani_proofs.rs` for the same pattern applied to
//! the emission curve, and `docs/security/KANI_SETUP.md` for the full
//! tooling install + run instructions.

#![cfg(kani)]

use crate::constants::{
    activity_bonus_rate, min_output_age_at_height, MIN_OUTPUT_AGE, MIN_OUTPUT_AGE_HARDFORK_HEIGHT,
    MIN_OUTPUT_AGE_POST_FORK,
};

/// **Binary switch**: `min_output_age_at_height` returns exactly one
/// of the two configured values for any height. Any third or
/// interpolated value would be a consensus break -- two nodes near
/// the fork would disagree on whether a transaction is valid.
#[kani::proof]
fn proof_min_output_age_is_binary() {
    let height: u64 = kani::any();
    let result = min_output_age_at_height(height);
    assert!(result == MIN_OUTPUT_AGE || result == MIN_OUTPUT_AGE_POST_FORK);
}

/// **Post-fork value applies at and above the activation height**.
/// Validators that miss this branch fork off the chain at activation.
#[kani::proof]
fn proof_min_output_age_post_fork() {
    let height: u64 = kani::any();
    kani::assume(height >= MIN_OUTPUT_AGE_HARDFORK_HEIGHT);
    assert_eq!(min_output_age_at_height(height), MIN_OUTPUT_AGE_POST_FORK);
}

/// **Activity bonus is bounded** between the base floor (100 bps =
/// 1%) and the documented cap (1000 bps = 10%) for any blocks-mined
/// count. Downstream miner-reward math relies on this bound; an
/// off-by-one would silently overpay miners.
#[kani::proof]
fn proof_activity_bonus_bounded() {
    let blocks: u64 = kani::any();
    let bonus = activity_bonus_rate(blocks);
    assert!(bonus >= 100, "bonus below base floor");
    assert!(bonus <= 1000, "bonus above documented cap");
}
