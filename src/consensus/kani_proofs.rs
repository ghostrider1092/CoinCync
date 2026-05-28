//! Kani proof harnesses for consensus helper functions.
//!
//! Targets the pure helpers in `fee_market.rs` and `difficulty.rs`
//! that the block validator depends on. Proving these gives audit-
//! grade certainty that the rules the validator enforces actually
//! say what the operator thinks they say -- e.g., a miner cannot
//! craft a fee distribution that loses one atomic unit to rounding,
//! a congestion bucket cannot return an unexpected multiplier, etc.
//!
//! Lives in a sibling file (not in the locked `validation.rs` /
//! `difficulty.rs` / `fee_market.rs`) so proof changes don't force
//! `critical_files.lock` refreshes.
//!
//! Run from WSL Ubuntu:
//!
//! ```bash
//! scripts/kani-check.sh
//! cargo kani --harness consensus::kani_proofs::proof_distribute_fee_conservation
//! ```

#![cfg(kani)]

use crate::consensus::fee_market::{
    calculate_fee, congestion_multiplier, distribute_fee, is_congested,
};
use crate::consensus::difficulty::{max_target, target_to_difficulty};
use crate::primitives::Amount;

// ─── Fee market ────────────────────────────────────────────────────

/// **Bucket discreteness**: `congestion_multiplier` returns one of
/// exactly four values: 100, 150, 200, 300. No interpolation. A
/// fifth value would mean a validator and a wallet computing the
/// same fee at the same congestion level disagree -- silent fork.
#[kani::proof]
fn proof_congestion_multiplier_is_one_of_four() {
    let pct: u64 = kani::any();
    let m = congestion_multiplier(pct);
    assert!(m == 100 || m == 150 || m == 200 || m == 300);
}

/// **Bucket monotonicity**: higher congestion never lowers the
/// multiplier. A reversed bucket would create a fee-discount
/// at higher congestion -- a clear consensus bug.
#[kani::proof]
fn proof_congestion_multiplier_monotonic() {
    let a: u64 = kani::any();
    let b: u64 = kani::any();
    kani::assume(a <= b);
    assert!(congestion_multiplier(a) <= congestion_multiplier(b));
}

/// **No panic on any input**: `calculate_fee` must not panic
/// for any (tx_size, congestion_pct) pair. The implementation
/// uses saturating arithmetic; this proves the saturation bounds
/// cover the full input space.
#[kani::proof]
fn proof_calculate_fee_no_panic() {
    let tx_size: usize = kani::any();
    let congestion_pct: u64 = kani::any();
    let _fee = calculate_fee(tx_size, congestion_pct);
}

/// **Zero-size tx has zero fee**. Boundary case that downstream
/// fee-validation code assumes.
#[kani::proof]
fn proof_calculate_fee_zero_size() {
    let congestion_pct: u64 = kani::any();
    let fee = calculate_fee(0, congestion_pct);
    assert_eq!(fee.as_atomic(), 0);
}

/// **Fee-distribution conservation**: `to_miner + burned + to_protocol`
/// MUST equal `total` for any input. The implementation comment
/// (A8-DIST-01) calls this out as load-bearing: independent
/// truncation of all three buckets historically lost up to 2
/// atomic units. This proof forecloses any future regression.
#[kani::proof]
fn proof_distribute_fee_conservation() {
    let total_atomic: u64 = kani::any();
    let congested: bool = kani::any();
    let dist = distribute_fee(Amount::from_atomic(total_atomic), congested);
    let sum = (dist.to_miner.as_atomic() as u128)
        + (dist.burned.as_atomic() as u128)
        + (dist.to_protocol.as_atomic() as u128);
    assert_eq!(sum, total_atomic as u128);
    assert!(dist.is_valid());
}

/// **Article II floor**: `to_protocol` is ALWAYS zero, regardless
/// of total or congestion. Constitution Article II forbids any
/// fee routing to a developer / foundation / protocol address.
#[kani::proof]
fn proof_distribute_fee_no_protocol_tax() {
    let total_atomic: u64 = kani::any();
    let congested: bool = kani::any();
    let dist = distribute_fee(Amount::from_atomic(total_atomic), congested);
    assert_eq!(dist.to_protocol.as_atomic(), 0);
}

/// **`is_congested` matches the threshold constant**. Proves the
/// comparison direction (>=, not >) hasn't been silently flipped.
#[kani::proof]
fn proof_is_congested_threshold_match() {
    let pct: u64 = kani::any();
    let congested = is_congested(pct);
    // Pull the constant via the public API at the threshold boundary.
    let at_threshold = is_congested(crate::constants::CONGESTION_THRESHOLD);
    let below_threshold =
        is_congested(crate::constants::CONGESTION_THRESHOLD.saturating_sub(1));
    assert!(at_threshold);
    assert!(!below_threshold);
    // Above threshold => congested; below => not.
    if pct >= crate::constants::CONGESTION_THRESHOLD {
        assert!(congested);
    } else {
        assert!(!congested);
    }
}

// ─── Difficulty ────────────────────────────────────────────────────

/// **Max target maps to difficulty 1**. `max_target()` is the
/// easiest possible target (all 0xFF), which by definition is
/// difficulty 1. A different value here would mean the difficulty
/// scale itself has shifted -- a hash that was valid at the old
/// scale could be invalid at the new one, instant fork.
#[kani::proof]
fn proof_max_target_is_difficulty_one() {
    let max = max_target();
    let diff = target_to_difficulty(&max);
    // u128::MAX / u128::MAX = 1 (the implementation uses the upper
    // 128 bits, which are all 0xFF in max_target, so the divisor is
    // u128::MAX). Result is 1.
    assert_eq!(diff, 1);
}
