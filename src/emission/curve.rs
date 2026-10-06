//! Asymptotic emission curve — 100M CYNC is the asymptote (soft target), NOT a hard cap.
//!
//! One line of code determines all of monetary policy:
//!
//! ```text
//! reward = max(TAIL_EMISSION, (100M - already_mined) / 2,000,000)
//! ```
//!
//! No eras. No halvings. No activation heights. Every coin that's mined
//! makes the next one slightly harder to earn — the way scarcity should
//! work. 100M is the asymptote (soft target) of the issuance formula, NOT a
//! hard cap: the perpetual 0.6 CYNC/block tail floor (`reward.max(TAIL_EMISSION)`)
//! means total emitted supply crosses 100M and keeps growing past it forever.
//!
//! At day one: 50 CYNC/block.
//! As supply grows, rewards decay smoothly.
//! When the formula drops below 0.6 CYNC, tail emission takes over.
//! Tail emission + 30% fee burn = self-sustaining forever.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `EmissionPhase` + `name`** — INVARIANT: exactly three display phases
//!   (Distribution / Mature / Tail), each mapping to a stable string. THREAT:
//!   an explorer/label drift misreporting monetary regime. TESTS:
//!   `emission_phase_name_maps_all_variants`.
//! - **§2 `emission_phase`** — INVARIANT: classifies by the estimated reward at
//!   height — Tail at ≤ `TAIL_EMISSION`, Mature at ≤ 10·COIN, else Distribution;
//!   always consistent with the reward the estimate produces. THREAT: a phase
//!   label inconsistent with the actual subsidy. TESTS: `emission_phase_at_genesis`,
//!   `emission_phase_mature_and_tail_transitions`.
//! - **§3 `base_reward_from_supply` (canonical consensus reward)** — INVARIANT:
//!   `reward = max(TAIL_EMISSION, (cap − supply)/EMISSION_DIVISOR)`; the u128
//!   `saturating_sub` means supply ≥ cap yields the tail floor, never a wrap or a
//!   sub-tail value. THREAT: over-emission above the 100M asymptote, or an
//!   underflow at/above the cap dropping reward below the perpetual 0.6 CYNC floor.
//!   TESTS: `genesis_reward_is_50_cync`, `reward_at_half_supply`,
//!   `reward_at_75_percent_supply`, `tail_emission_kicks_in`,
//!   `reward_never_below_tail`.
//! - **§4 `base_reward` / `block_reward` (height-based)** — INVARIANT: reward is
//!   monotone non-increasing in height, starts at 50 CYNC at height 0, and never
//!   panics for any `u64` height. THREAT: overflow/panic on a large RPC-supplied
//!   height. TESTS: `height_based_estimate_starts_at_50`, `reward_decays_over_time`,
//!   `no_overflow_on_large_heights`, `base_reward_u64_max_is_o1_tail_fast_path`;
//!   external oracle: `tests/emission_reference_oracle.rs` (spec-formula /
//!   monotonicity / never-over-emit suite).
//! - **§5 `estimate_supply_at_height` (adaptive-step integrator)** — INVARIANT:
//!   result never exceeds `cap_atomic` (`.min(cap)`), stays within ~0.1% of a
//!   block-by-block integration, and the tail fast-path returns in O(1) once the
//!   asymptotic curve drops below `TAIL_EMISSION`. THREAT: `base_reward(u64::MAX)`
//!   DoS — a ~1.8e15-iteration loop if a height is routed in unbounded (fixed
//!   2026-06-03). TESTS: `estimate_supply_adaptive_step_accuracy_across_boundaries`,
//!   `estimate_supply_never_exceeds_cap`, `base_reward_u64_max_is_o1_tail_fast_path`.
//! - **§6 `estimate_reward_at_height`** — INVARIANT: mirrors the §3 formula on the
//!   §5 supply estimate and is likewise floored at `TAIL_EMISSION`; used only for
//!   phase classification. THREAT: a phase estimate diverging from the reward
//!   formula. TESTS: `emission_phase_mature_and_tail_transitions` (drives all three
//!   phase branches through this estimate).

use crate::constants::*;
use crate::primitives::Amount;

/// Emission phases for display/reporting purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionPhase {
    /// Early distribution — reward is high, supply is low.
    Distribution,
    /// Mature — reward has declined significantly.
    Mature,
    /// Tail — reward has hit the 0.6 CYNC floor.
    Tail,
}

impl EmissionPhase {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Distribution => "Distribution",
            Self::Mature => "Mature",
            Self::Tail => "Tail",
        }
    }
}

/// Determine the emission phase from a block height.
///
/// Uses a rough supply estimate to classify. The actual reward
/// is computed by [`base_reward`] using cumulative supply from
/// the chain state; this function uses a simplified estimate
/// for display purposes only.
pub fn emission_phase(height: u64) -> EmissionPhase {
    // Rough estimate: integrate the asymptotic curve.
    // At ~50% of cap emitted, we're "Mature".
    // When estimated reward drops below tail, we're in "Tail".
    let estimated_reward = estimate_reward_at_height(height);
    if estimated_reward <= TAIL_EMISSION {
        EmissionPhase::Tail
    } else if estimated_reward <= 10 * COIN {
        EmissionPhase::Mature
    } else {
        EmissionPhase::Distribution
    }
}

/// Calculate the base block reward from cumulative supply.
///
/// This is the canonical reward function used by consensus:
///     reward = max(TAIL_EMISSION, (cap - supply) / EMISSION_DIVISOR)
///
/// `cumulative_supply_atomic` is in atomic units (u128 because
/// 100M CYNC × 10^12 atomic/CYNC = 10^20, which overflows u64).
pub fn base_reward_from_supply(cumulative_supply_atomic: u128) -> Amount {
    let cap_atomic = TOTAL_SUPPLY_TARGET as u128 * COIN as u128;
    let remaining = cap_atomic.saturating_sub(cumulative_supply_atomic);
    let reward = remaining / EMISSION_DIVISOR as u128;

    // Floor at tail emission
    let reward = reward.max(TAIL_EMISSION as u128);
    Amount::from_atomic(reward as u64)
}

/// Calculate block reward by height (estimated, for use when cumulative
/// supply is not available — e.g., block template building, explorer
/// display, tests).
///
/// Uses numerical integration of the asymptotic curve to estimate
/// cumulative supply at the given height, then applies the formula.
/// This is an approximation — the consensus-critical path should use
/// [`base_reward_from_supply`] with actual chain state.
pub fn base_reward(height: u64) -> Amount {
    let supply_estimate = estimate_supply_at_height(height); // u128
    base_reward_from_supply(supply_estimate)
}

/// Compatibility wrapper — returns raw atomic units.
pub fn block_reward(height: u64) -> u64 {
    base_reward(height).as_atomic()
}

/// Estimate cumulative supply at a given height by numerically integrating
/// the asymptotic curve in steps.
///
/// Uses larger steps for efficiency — exact to within ~0.1% for any height.
fn estimate_supply_at_height(height: u64) -> u128 {
    if height == 0 {
        return 0;
    }

    let cap_atomic = TOTAL_SUPPLY_TARGET as u128 * COIN as u128;
    let mut supply: u128 = 0;
    let mut h: u64 = 0;

    // Use adaptive step sizes for efficiency
    let step = if height > 1_000_000 {
        10_000
    } else if height > 100_000 {
        1_000
    } else if height > 10_000 {
        100
    } else {
        10
    };

    while h < height {
        let remaining = cap_atomic.saturating_sub(supply);
        let asymptotic_reward = remaining / EMISSION_DIVISOR as u128;
        let reward = asymptotic_reward.max(TAIL_EMISSION as u128);

        // Fast path: once the asymptotic curve drops below the TAIL
        // floor, every subsequent block pays exactly TAIL — there's
        // no point iterating block-by-block through the tail regime.
        // Without this, `estimate_supply_at_height(u64::MAX)` loops
        // for ~1.8e15 iterations (DoS surface if a height is ever
        // routed in from RPC without bounds). With it, the tail
        // contribution is computed in a single multiply + return.
        // Discovered during 2026-06-03 critical-file review.
        if asymptotic_reward < TAIL_EMISSION as u128 {
            let remaining_blocks = (height - h) as u128;
            supply =
                supply.saturating_add((TAIL_EMISSION as u128).saturating_mul(remaining_blocks));
            break;
        }

        let blocks_in_step = ((height - h) as u128).min(step as u128);
        supply += reward * blocks_in_step;
        h += blocks_in_step as u64;
    }

    supply.min(cap_atomic)
}

/// Estimate the reward at a given height (for phase classification).
fn estimate_reward_at_height(height: u64) -> u64 {
    let supply = estimate_supply_at_height(height);
    let cap_atomic = TOTAL_SUPPLY_TARGET as u128 * COIN as u128;
    let remaining = cap_atomic.saturating_sub(supply);
    let reward = remaining / EMISSION_DIVISOR as u128;
    reward.max(TAIL_EMISSION as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_reward_is_50_cync() {
        // At supply 0: reward = 100M / 2M = 50 CYNC
        let reward = base_reward_from_supply(0);
        assert_eq!(
            reward.as_atomic(),
            50 * COIN,
            "genesis reward must be 50 CYNC"
        );
    }

    #[test]
    fn reward_at_half_supply() {
        // At 50M mined: reward = 50M / 2M = 25 CYNC
        let supply_50m = 50_000_000u128 * COIN as u128;
        let reward = base_reward_from_supply(supply_50m);
        assert_eq!(
            reward.as_atomic(),
            25 * COIN,
            "reward at 50M supply must be 25 CYNC"
        );
    }

    #[test]
    fn reward_at_75_percent_supply() {
        // At 75M mined: reward = 25M / 2M = 12.5 CYNC
        let supply_75m = 75_000_000u128 * COIN as u128;
        let reward = base_reward_from_supply(supply_75m);
        assert_eq!(
            reward.as_atomic(),
            12_500_000_000_000,
            "reward at 75M supply must be 12.5 CYNC"
        );
    }

    #[test]
    fn tail_emission_kicks_in() {
        // At supply near cap, reward should be TAIL_EMISSION
        let supply_near_cap = 99_999_000u128 * COIN as u128;
        let reward = base_reward_from_supply(supply_near_cap);
        assert_eq!(
            reward.as_atomic(),
            TAIL_EMISSION,
            "reward near cap must be tail emission (0.6 CYNC)"
        );
    }

    #[test]
    fn reward_never_below_tail() {
        // Even at supply > cap (impossible but defensive)
        let reward = base_reward_from_supply(u128::MAX);
        assert_eq!(reward.as_atomic(), TAIL_EMISSION);
    }

    #[test]
    fn reward_decays_over_time() {
        let r0 = base_reward(0).as_atomic();
        let r_1yr = base_reward(BLOCKS_PER_YEAR).as_atomic();
        let r_5yr = base_reward(BLOCKS_PER_YEAR * 5).as_atomic();
        let r_10yr = base_reward(BLOCKS_PER_YEAR * 10).as_atomic();

        assert!(r0 > r_1yr, "genesis {} > year 1 {}", r0, r_1yr);
        assert!(r_1yr > r_5yr, "year 1 {} > year 5 {}", r_1yr, r_5yr);
        assert!(r_5yr > r_10yr, "year 5 {} > year 10 {}", r_5yr, r_10yr);
    }

    #[test]
    fn height_based_estimate_starts_at_50() {
        let r = base_reward(0).as_atomic();
        assert_eq!(r, 50 * COIN, "height 0 reward must be 50 CYNC");
    }

    #[test]
    fn emission_phase_at_genesis() {
        assert_eq!(emission_phase(0), EmissionPhase::Distribution);
    }

    #[test]
    fn no_overflow_on_large_heights() {
        // Test with a very large but not infinite height
        let _ = base_reward(10_000_000);
        // Direct supply test with max u128
        let _ = base_reward_from_supply(u128::MAX);
    }

    /// Independent block-by-block (step=1) reference integrator, mirroring
    /// `estimate_supply_at_height` exactly but with no adaptive stepping. Used
    /// to bound the accuracy of the coarse adaptive-step estimate.
    fn reference_supply_step1(height: u64) -> u128 {
        if height == 0 {
            return 0;
        }
        let cap_atomic = TOTAL_SUPPLY_TARGET as u128 * COIN as u128;
        let mut supply: u128 = 0;
        let mut h: u64 = 0;
        while h < height {
            let remaining = cap_atomic.saturating_sub(supply);
            let asymptotic_reward = remaining / EMISSION_DIVISOR as u128;
            let reward = asymptotic_reward.max(TAIL_EMISSION as u128);
            if asymptotic_reward < TAIL_EMISSION as u128 {
                let remaining_blocks = (height - h) as u128;
                supply = supply
                    .saturating_add((TAIL_EMISSION as u128).saturating_mul(remaining_blocks));
                break;
            }
            supply += reward;
            h += 1;
        }
        supply.min(cap_atomic)
    }

    #[test]
    fn base_reward_u64_max_is_o1_tail_fast_path() {
        // 2026-06-03 DoS fix: base_reward(u64::MAX) must NOT iterate ~1.8e15
        // blocks. The tail fast-path returns in O(1). Assert it both returns
        // promptly AND equals the tail floor.
        let start = std::time::Instant::now();
        let reward = base_reward(u64::MAX);
        let elapsed = start.elapsed();
        assert_eq!(
            reward.as_atomic(),
            TAIL_EMISSION,
            "base_reward(u64::MAX) must equal tail emission"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "base_reward(u64::MAX) must return promptly via the tail fast-path, took {:?}",
            elapsed
        );
    }

    #[test]
    fn estimate_supply_adaptive_step_accuracy_across_boundaries() {
        // The adaptive stepping (10 / 100 / 1000 / 10000 by height band) must
        // stay within the stated ~0.1% of an exact block-by-block integration,
        // including just past each step-size boundary (10k / 100k).
        for &height in &[10_100u64, 50_000, 99_999, 100_500, 250_000] {
            let est = estimate_supply_at_height(height);
            let reference = reference_supply_step1(height);
            let diff = est.abs_diff(reference);
            // within 0.1%: diff / reference <= 0.001  <=>  diff * 1000 <= reference
            assert!(
                diff.saturating_mul(1000) <= reference.max(1),
                "height {}: estimate {} deviates from reference {} by more than 0.1% (diff {})",
                height,
                est,
                reference,
                diff
            );
        }
    }

    #[test]
    fn estimate_supply_never_exceeds_cap() {
        // Invariant: the `.min(cap_atomic)` clamp guarantees the estimate never
        // exceeds the cap for any height, including the tail-saturating extremes.
        let cap_atomic = TOTAL_SUPPLY_TARGET as u128 * COIN as u128;
        for &height in &[
            0u64,
            1,
            10_000,
            1_000_000,
            10_000_000,
            100_000_000,
            u64::MAX,
        ] {
            assert!(
                estimate_supply_at_height(height) <= cap_atomic,
                "estimate at height {} exceeded cap {}",
                height,
                cap_atomic
            );
        }
    }

    #[test]
    fn emission_phase_mature_and_tail_transitions() {
        // Only the Distribution branch is covered elsewhere. Exercise the
        // Mature (reward <= 10 CYNC) and Tail (reward <= TAIL_EMISSION)
        // branches, and assert the phase is always consistent with the reward
        // the estimate produces at that height.
        let mut saw_mature = false;
        let mut saw_tail = false;
        for &height in &[
            1_000_000u64,
            3_000_000,
            4_000_000,
            6_000_000,
            9_000_000,
            12_000_000,
            20_000_000,
            50_000_000,
        ] {
            let reward = base_reward(height).as_atomic();
            let phase = emission_phase(height);
            let expected = if reward <= TAIL_EMISSION {
                EmissionPhase::Tail
            } else if reward <= 10 * COIN {
                EmissionPhase::Mature
            } else {
                EmissionPhase::Distribution
            };
            assert_eq!(
                phase, expected,
                "phase at height {} inconsistent with reward {}",
                height, reward
            );
            match phase {
                EmissionPhase::Mature => saw_mature = true,
                EmissionPhase::Tail => saw_tail = true,
                EmissionPhase::Distribution => {}
            }
        }
        assert!(saw_mature, "expected at least one height to classify as Mature");
        assert!(saw_tail, "expected at least one height to classify as Tail");
    }

    #[test]
    fn emission_phase_name_maps_all_variants() {
        assert_eq!(EmissionPhase::Distribution.name(), "Distribution");
        assert_eq!(EmissionPhase::Mature.name(), "Mature");
        assert_eq!(EmissionPhase::Tail.name(), "Tail");
    }
}
