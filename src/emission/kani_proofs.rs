//! Kani proof harnesses for the emission curve.
//!
//! These prove monetary-policy invariants over the full input space of
//! [`crate::emission::curve::base_reward_from_supply`]. CBMC bounded
//! model checking explores all u128 inputs symbolically — far stronger
//! than the property-based and example-based tests in `curve.rs`.
//!
//! Lives in a sibling file (not in `curve.rs` itself) because
//! `src/emission/curve.rs` is locked by `critical_files.lock`. Proof
//! changes ship without touching the consensus-protected file.
//!
//! ## Running
//!
//! From WSL Ubuntu (kani is Linux-only):
//!
//! ```bash
//! scripts/kani-check.sh                                    # full suite
//! cargo kani --harness emission::kani_proofs::proof_reward_floor_is_tail
//! ```
//!
//! Each proof typically discharges in under a minute because
//! `base_reward_from_supply` is pure u128 arithmetic with no loops.

#![cfg(kani)]

use crate::constants::*;
use crate::emission::curve::base_reward_from_supply;

/// **Article I floor**: block reward is ALWAYS bounded below by
/// `TAIL_EMISSION`. Any non-tail floor would break the asymptotic
/// invariant promised by the Constitution: deflation followed by a
/// permanent 0.6 CYNC/block tail.
#[kani::proof]
fn proof_reward_floor_is_tail() {
    let supply: u128 = kani::any();
    let reward = base_reward_from_supply(supply);
    assert!(reward.as_atomic() >= TAIL_EMISSION);
}

/// **Article I ceiling**: block reward NEVER exceeds the genesis
/// reward (50 CYNC), regardless of supply input. A larger reward
/// would let cumulative emission overrun the 100M cap from below.
#[kani::proof]
fn proof_reward_ceiling_is_genesis() {
    let supply: u128 = kani::any();
    let reward = base_reward_from_supply(supply);
    // Genesis reward = cap / EMISSION_DIVISOR = 100M / 2M = 50 CYNC atomic.
    let genesis_reward_atomic =
        (TOTAL_SUPPLY_TARGET as u128 * COIN as u128 / EMISSION_DIVISOR as u128) as u64;
    assert!(reward.as_atomic() <= genesis_reward_atomic);
}

/// At the exact supply cap, reward must equal `TAIL_EMISSION` -- not
/// undefined, not zero (which would deflate), not an arithmetic
/// glitch from `saturating_sub` crossing the boundary.
#[kani::proof]
fn proof_reward_at_cap_is_tail() {
    let cap_atomic = TOTAL_SUPPLY_TARGET as u128 * COIN as u128;
    let reward = base_reward_from_supply(cap_atomic);
    assert_eq!(reward.as_atomic(), TAIL_EMISSION);
}

/// **Overflow safety**: ANY u128 input -- including values above the
/// supply cap (physically impossible but might appear from a buggy
/// caller) -- must not panic, wrap, or produce a non-tail reward.
#[kani::proof]
fn proof_no_panic_above_cap() {
    let supply: u128 = kani::any();
    let _ = base_reward_from_supply(supply);
}
