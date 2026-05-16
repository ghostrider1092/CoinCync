//! # Tier 14 — Hybrid Reorg Defense Tests (H-16 Resolution)
//!
//! Tests the three-tier MESS-style reorg defense:
//! - Tier 1 (≤10 blocks): unconditional if more work
//! - Tier 2 (11-100 blocks): exponential cost multiplier
//! - Tier 3 (>100 blocks): hard reject
//!
//! These tests verify the economic model makes 51% attacks infeasible
//! while allowing legitimate network partition recovery.

use coincync::chain::{
    evaluate_reorg_acceptability, max_reorg_depth,
    BOOTSTRAP_MESS_HEIGHT, REORG_UNCONDITIONAL_DEPTH, MESS_EXPONENT_DIVISOR,
};

// All tests run at post-bootstrap height so the Tier-2 MESS path is
// actually exercised (current_height >= BOOTSTRAP_MESS_HEIGHT). The
// signature gained current_height after this test was written; the
// fix is purely additive — pass POST_BOOTSTRAP to every call site.
// Tier-1 (depth <= 10) returns before the bootstrap check, so the
// current_height value doesn't affect Tier-1 cases; passing a
// post-bootstrap value keeps Tier-2 tests honest without changing
// Tier-1 / Tier-3 semantics.
const POST_BOOTSTRAP: u64 = BOOTSTRAP_MESS_HEIGHT + 1;

// =============================================================================
// TIER 1: Shallow reorgs (≤ 10 blocks) — unconditional acceptance
// =============================================================================

#[test]
fn tier1_shallow_reorg_accepted_with_more_work() {
    // Depth 5, fork has more work → accepted (normal Nakamoto rule)
    let result = evaluate_reorg_acceptability(5, 1000, 999, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Shallow reorg with more work must be accepted: {:?}", result);
}

#[test]
fn tier1_shallow_reorg_rejected_with_less_work() {
    // Depth 5, fork has LESS work → rejected
    let result = evaluate_reorg_acceptability(5, 999, 1000, POST_BOOTSTRAP);
    assert!(result.is_err(), "Shallow reorg with less work must be rejected");
}

#[test]
fn tier1_depth_10_is_unconditional() {
    // Exactly at the boundary — still unconditional
    let result = evaluate_reorg_acceptability(REORG_UNCONDITIONAL_DEPTH, 1001, 1000, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Depth {} must still be unconditional", REORG_UNCONDITIONAL_DEPTH);
}

#[test]
fn tier1_equal_work_rejected() {
    // Equal work = no switch (defender advantage)
    let result = evaluate_reorg_acceptability(5, 1000, 1000, POST_BOOTSTRAP);
    assert!(result.is_err(), "Equal work must not trigger reorg (defender advantage)");
}

// =============================================================================
// TIER 2: Medium reorgs (11-100 blocks) — exponential cost multiplier
// =============================================================================

#[test]
fn tier2_depth_11_requires_more_than_just_more_work() {
    // At depth 11, exponent = (11-10)/20 = 0, so multiplier = 2^0 = 1
    // Still just needs more work (but barely in MESS territory)
    let result = evaluate_reorg_acceptability(11, 1001, 1000, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Depth 11 with slightly more work should pass (multiplier=1)");
}

#[test]
fn tier2_depth_30_requires_2x_work() {
    // At depth 30, exponent = (30-10)/20 = 1, multiplier = 2^1 = 2
    // Fork needs > 2x honest work
    let honest = 1000u128;
    let required = honest * 2; // 2000

    // Just below threshold — rejected
    let result = evaluate_reorg_acceptability(30, required, honest, POST_BOOTSTRAP);
    assert!(result.is_err(), "Depth 30 with exactly 2x work must be rejected (needs >2x)");

    // Above threshold — accepted
    let result = evaluate_reorg_acceptability(30, required + 1, honest, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Depth 30 with >2x work must be accepted");
}

#[test]
fn tier2_depth_50_requires_4x_work() {
    // At depth 50, exponent = (50-10)/20 = 2, multiplier = 2^2 = 4
    let honest = 1000u128;
    let required = honest * 4;

    let result = evaluate_reorg_acceptability(50, required, honest, POST_BOOTSTRAP);
    assert!(result.is_err(), "Depth 50 with exactly 4x must be rejected");

    let result = evaluate_reorg_acceptability(50, required + 1, honest, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Depth 50 with >4x must be accepted");
}

#[test]
fn tier2_depth_70_requires_8x_work() {
    // At depth 70, exponent = (70-10)/20 = 3, multiplier = 2^3 = 8
    let honest = 1000u128;
    let required = honest * 8;

    let result = evaluate_reorg_acceptability(70, required, honest, POST_BOOTSTRAP);
    assert!(result.is_err(), "Depth 70 with exactly 8x must be rejected");

    let result = evaluate_reorg_acceptability(70, required + 1, honest, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Depth 70 with >8x must be accepted");
}

#[test]
fn tier2_depth_90_requires_16x_work() {
    // At depth 90, exponent = (90-10)/20 = 4, multiplier = 2^4 = 16
    let honest = 1000u128;
    let required = honest * 16;

    let result = evaluate_reorg_acceptability(90, required, honest, POST_BOOTSTRAP);
    assert!(result.is_err(), "Depth 90 with exactly 16x must be rejected");

    let result = evaluate_reorg_acceptability(90, required + 1, honest, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Depth 90 with >16x must be accepted");
}

#[test]
fn tier2_economics_rental_attack_infeasible() {
    // Scenario: Attacker rents hashrate for a 50-block reorg.
    // Honest chain has been mining for those 50 blocks at difficulty D.
    // Honest cumulative work ≈ 50 * D.
    // Attacker needs > 4 * (50 * D) = 200 * D to succeed.
    // That means 4x the network hashrate for 50 blocks (8.3 hours at 2min/block).
    // Rental cost at 4x hashrate for 8.3 hours makes the attack economically insane.
    let d = 1_000_000_000u128; // representative difficulty
    let honest_work = 50 * d;
    let attacker_work = 50 * d; // attacker mines same blocks at same rate (1x hashrate)

    let result = evaluate_reorg_acceptability(50, attacker_work, honest_work, POST_BOOTSTRAP);
    assert!(
        result.is_err(),
        "51% attacker with 1x hashrate for 50 blocks must be rejected by MESS! \
         Without MESS, this attack would succeed (more work by time alone)."
    );

    // Even 2x hashrate isn't enough at depth 50
    let attacker_2x = 50 * d * 2;
    let result = evaluate_reorg_acceptability(50, attacker_2x, honest_work, POST_BOOTSTRAP);
    assert!(
        result.is_err(),
        "51% attacker with 2x hashrate for 50 blocks must STILL be rejected (needs 4x)"
    );
}

// =============================================================================
// TIER 3: Deep reorgs (> 100 blocks) — absolute rejection
// =============================================================================

#[test]
fn tier3_depth_101_hard_rejected() {
    let max = max_reorg_depth();
    // Even with infinite work, past max depth is rejected
    let result = evaluate_reorg_acceptability(max + 1, u128::MAX, 1, POST_BOOTSTRAP);
    assert!(
        result.is_err(),
        "Depth {} (> max {}) must be hard-rejected regardless of work",
        max + 1, max
    );
}

#[test]
fn tier3_beyond_max_hard_rejected() {
    // Testnet max is 1000, mainnet max is 100. Test beyond both.
    let max = max_reorg_depth();
    let result = evaluate_reorg_acceptability(max + 1, u128::MAX, 1, POST_BOOTSTRAP);
    assert!(result.is_err(), "Depth {} (> max {}) must be hard-rejected", max + 1, max);
}

#[test]
fn tier3_depth_max_u64_hard_rejected() {
    let result = evaluate_reorg_acceptability(u64::MAX, u128::MAX, 1, POST_BOOTSTRAP);
    assert!(result.is_err(), "Depth u64::MAX must be hard-rejected without overflow");
}

// =============================================================================
// EDGE CASES
// =============================================================================

#[test]
fn edge_zero_depth_accepted() {
    // Depth 0 = same height, more work → accepted
    let result = evaluate_reorg_acceptability(0, 1001, 1000, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Depth 0 with more work must be accepted");
}

#[test]
fn edge_honest_work_zero() {
    // At genesis, honest work is 0. Any fork work should be accepted for shallow reorgs.
    let result = evaluate_reorg_acceptability(5, 1, 0, POST_BOOTSTRAP);
    assert!(result.is_ok(), "Fork with work=1 vs honest=0 must be accepted");
}

#[test]
fn edge_overflow_resistance() {
    // Large numbers shouldn't panic
    let result = evaluate_reorg_acceptability(50, u128::MAX, u128::MAX / 2, POST_BOOTSTRAP);
    // At depth 50 with multiplier 4: required = (MAX/2) * 4 which saturates to MAX
    // fork_work = MAX > saturated value? Depends on saturation behavior
    // Key: doesn't panic
    let _ = result;
}

#[test]
fn constants_are_sane() {
    assert_eq!(REORG_UNCONDITIONAL_DEPTH, 10, "Unconditional depth must be 10");
    assert_eq!(MESS_EXPONENT_DIVISOR, 20, "MESS divisor must be 20");
    assert!(max_reorg_depth() >= 100, "Max reorg depth must be at least 100");
}
