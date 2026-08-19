//! Layer-4 differential oracle for the emission schedule.
//!
//! The consensus reward `calculate_block_reward(h)` evaluates
//! `base_reward_from_supply(estimate_supply_at_height(h))`, where
//! `estimate_supply_at_height` integrates the asymptotic issuance curve with
//! COARSE adaptive steps (10 / 100 / 1_000 / 10_000 blocks). This file builds an
//! INDEPENDENT block-by-block (step = 1) reference integral of the same spec
//! formula and diffs the two, and asserts the structural invariants any correct
//! emission curve must hold. It is a genuine oracle: the reference shares none of
//! the production code's stepping approximation, and the spec formula is
//! reimplemented here from first principles rather than called from the crate.
//!
//! What it would catch: a non-monotone (inflationary) step-boundary jump, an
//! over-emission vs the ideal curve, a broken tail floor, a formula/rounding
//! error, or an overflow/panic at extreme heights.

use coincync::emission::calculate_block_reward;
use coincync::emission::curve::base_reward_from_supply;

// Spec constants (imported so the test tracks any constant change, but the
// FORMULA below is reimplemented independently of the production code).
use coincync::constants::{COIN, EMISSION_DIVISOR, TAIL_EMISSION, TOTAL_SUPPLY_TARGET};

fn cap_atomic() -> u128 {
    TOTAL_SUPPLY_TARGET as u128 * COIN as u128
}

/// Independent reimplementation of the canonical spec formula
/// `reward = max(TAIL_EMISSION, (cap - mined) / EMISSION_DIVISOR)`.
fn ref_reward_at_supply(supply: u128) -> u64 {
    let remaining = cap_atomic().saturating_sub(supply);
    let reward = remaining / EMISSION_DIVISOR as u128;
    reward.max(TAIL_EMISSION as u128) as u64
}

/// True block-by-block (step = 1) supply integral. `rewards[h]` is the reward
/// paid AT height `h`, computed against the exact supply accumulated over the
/// preceding `h` blocks — no coarse stepping. This is the oracle the production
/// coarse estimate is measured against.
fn true_rewards(blocks: u64) -> Vec<u64> {
    let mut rewards = Vec::with_capacity(blocks as usize);
    let mut supply: u128 = 0;
    for _ in 0..blocks {
        let r = ref_reward_at_supply(supply);
        rewards.push(r);
        supply += r as u128;
    }
    rewards
}

/// The production spec-formula implementation must match the independent
/// reference across the entire supply domain, including the boundaries and the
/// past-the-cap defensive region.
#[test]
fn spec_formula_matches_independent_reference_across_supply_domain() {
    let cap = cap_atomic();
    let mut samples: Vec<u128> = vec![
        0,
        1,
        COIN as u128,
        cap / 4,
        cap / 2,
        (cap / 4) * 3,
        cap - 1,
        cap,
        cap + 1,
        u128::MAX / 2,
        u128::MAX,
    ];
    // Uniform sweep across [0, cap].
    for i in 0..=200u128 {
        samples.push((cap / 200) * i);
    }
    for s in samples {
        let real = base_reward_from_supply(s).as_atomic();
        let reference = ref_reward_at_supply(s);
        assert_eq!(
            real, reference,
            "base_reward_from_supply({s}) = {real} disagrees with the independent \
             spec formula {reference}"
        );
    }
}

/// Emission must be monotone non-increasing in height — every mined coin makes
/// the next slightly harder. A reward that ever INCREASES with height is an
/// inflation blip; the estimate's step-size changes (at 10k / 100k / 1M) are the
/// likeliest place for such a bug, so those boundaries are sampled densely.
#[test]
fn height_reward_is_monotone_nonincreasing_incl_step_boundaries() {
    let mut heights: Vec<u64> = Vec::new();
    let mut h = 0u64;
    while h <= 12_000_000 {
        heights.push(h);
        h += 25_000;
    }
    for boundary in [10_000u64, 100_000, 1_000_000] {
        for d in (boundary - 25)..=(boundary + 25) {
            heights.push(d);
        }
    }
    heights.sort_unstable();
    heights.dedup();

    let mut prev = calculate_block_reward(heights[0]).as_atomic();
    for &hh in &heights[1..] {
        let r = calculate_block_reward(hh).as_atomic();
        assert!(
            r <= prev,
            "emission INCREASED with height: reward({hh}) = {r} > previous {prev}. \
             A non-monotone emission curve mints more per block as the chain grows \
             — most likely a step-boundary artifact in estimate_supply_at_height."
        );
        prev = r;
    }
}

/// Every block reward must lie in `[TAIL_EMISSION, genesis_reward]`.
#[test]
fn height_reward_is_bounded() {
    let genesis = 50 * COIN; // 100M / 2M = 50 CYNC at supply 0
    for h in [
        0u64, 1, 100, 10_000, 100_000, 1_000_000, 5_000_000, 12_000_000, 50_000_000,
    ] {
        let r = calculate_block_reward(h).as_atomic();
        assert!(
            r >= TAIL_EMISSION,
            "reward({h}) = {r} fell below the tail floor {TAIL_EMISSION}"
        );
        assert!(
            r <= genesis,
            "reward({h}) = {r} exceeded the genesis reward {genesis}"
        );
    }
}

/// The coarse production estimate must never OVER-emit relative to the exact
/// block-by-block curve (over-emission = inflation beyond the intended schedule),
/// and it must stay close to it (the code documents ~0.1% supply accuracy). We
/// compare against the true step=1 reward and require `real <= true` with the
/// under-emission gap bounded well under 1%.
#[test]
fn coarse_estimate_never_over_emits_and_stays_close() {
    // Below the tail onset (~8.8M blocks) so both curves are on the asymptotic
    // part; 2M blocks of step=1 iteration is fast.
    const N: u64 = 2_000_000;
    let truth = true_rewards(N);

    let mut max_gap_num: u128 = 0; // max (true - real) * 1_000_000 / true, tracked as ppm
    for h in (0..N).step_by(9_973) {
        // 9_973 is prime → samples don't align to any step boundary
        let real = calculate_block_reward(h).as_atomic();
        let tru = truth[h as usize];
        assert!(
            real <= tru,
            "OVER-EMISSION: coarse reward({h}) = {real} exceeds the exact curve's {tru} \
             — the estimate is minting more than the ideal schedule allows"
        );
        if tru > 0 {
            let ppm = ((tru - real) as u128 * 1_000_000) / tru as u128;
            if ppm > max_gap_num {
                max_gap_num = ppm;
            }
        }
    }
    // The stepping under-emits by at most a small fraction; assert < 1% (10_000 ppm).
    assert!(
        max_gap_num < 10_000,
        "coarse estimate under-emits by {max_gap_num} ppm vs the exact curve — \
         larger than the documented ~0.1% approximation error"
    );
    println!("coarse-vs-exact max reward under-emission gap: {max_gap_num} ppm");
}

/// The tail floor must be reached at large heights and held there forever.
#[test]
fn tail_emission_reached_and_held() {
    // Deep in the asymptote, the formula drops below the tail and the floor
    // takes over. 50M blocks is comfortably past the ~8.8M-block tail onset.
    for h in [50_000_000u64, 100_000_000, 500_000_000, u64::MAX / 2, u64::MAX] {
        let r = calculate_block_reward(h).as_atomic();
        assert_eq!(
            r, TAIL_EMISSION,
            "reward({h}) = {r} must be exactly the tail floor {TAIL_EMISSION} deep in the tail"
        );
    }
}

/// Extreme heights must not panic or overflow (the tail fast-path exists to keep
/// `estimate_supply_at_height(u64::MAX)` from looping ~1.8e15 times).
#[test]
fn no_panic_or_overflow_at_extreme_heights() {
    for h in [u64::MAX, u64::MAX - 1, u64::MAX / 3, 1_000_000_000_000] {
        let r = calculate_block_reward(h).as_atomic();
        assert!(r >= TAIL_EMISSION, "reward({h}) = {r} below tail");
    }
}

/// Anchor: the height-based consensus reward at genesis is exactly 50 CYNC.
#[test]
fn genesis_reward_is_50_cync() {
    assert_eq!(
        calculate_block_reward(0).as_atomic(),
        50 * COIN,
        "genesis (height 0) reward must be 50 CYNC"
    );
}
