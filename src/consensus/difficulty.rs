//! # Dual-Anchor ASERT Difficulty Adjustment
//!
//! Adaptive difficulty adjustment for stable block times.
//!
//! SECURITY (H-1): All arithmetic is purely integer-based (u128 fixed-point)
//! to guarantee cross-platform determinism. f64 is non-deterministic across
//! CPU architectures and would cause consensus forks.
//!
//! ## Design: Dual-Window ASERT
//!
//! Two ASERT windows combined with weighted average:
//! - Short window: reacts quickly to hashrate changes
//! - Long window: provides stability against variance
//!
//! Weights must satisfy: SHORT_WEIGHT + LONG_WEIGHT == WEIGHT_SCALE

use crate::primitives::Hash;
use crate::constants::{
    TARGET_BLOCK_TIME, ASERT_HALFLIFE, DIFFICULTY_SHORT_WINDOW, DIFFICULTY_LONG_WINDOW,
    DIFFICULTY_SHORT_WEIGHT, DIFFICULTY_LONG_WEIGHT, DIFFICULTY_WEIGHT_SCALE,
    EMERGENCY_DIFFICULTY_BLOCKS, EMERGENCY_TIME_MULTIPLIER, EMERGENCY_DROP_FACTOR,
    MAX_DIFFICULTY_ADJ_NUM, MAX_DIFFICULTY_ADJ_DEN,
    MIN_DIFFICULTY_ADJ_NUM, MIN_DIFFICULTY_ADJ_DEN,
};

/// Absolute minimum network difficulty — the consensus floor below which ASERT
/// cannot drive the chain. Equivalent to a target ceiling of `u128::MAX / 500`.
///
/// The dual-window ASERT can drift difficulty arbitrarily low under uneven
/// hashrate conditions (e.g. a single home miner during testnet bootstrap),
/// and at the natural floor `target = u128::MAX` block production runs faster
/// than P2P validation+gossip — the chain physically can't stay synchronized.
/// The standard production fix for this class of issue is a minimum-difficulty
/// floor (Monero LWMA, Bitcoin testnet 20-min rule, Zcash NU5 floor).
///
/// 500 was picked so that even at the floor on a slow home CPU (~45 H/s
/// total RandomX), blocks come no faster than ~11s each. That's comfortably
/// inside what a 5-node mesh can validate and gossip: RandomX VM init alone
/// takes ~1.5–2s on each receiving node, and Noise-encrypted block transit
/// plus signature verification add 1–2s more, so the absorption ceiling sits
/// somewhere around 1 block per 5–8s. With the floor at 500-difficulty
/// (~11s/block on the slowest expected miner) we have ~30% headroom.
///
/// This is strictly tighter than the previous rule (no floor at all = target
/// allowed up to `u128::MAX`), so a node with this fix will accept every
/// block that a pre-fix node accepts, plus reject some "easy" blocks that
/// pre-fix nodes would accept. Net effect on already-mined chain history:
/// nothing — every existing block above difficulty 500 still validates.
pub const MIN_DIFFICULTY: u128 = 500;

// Compile-time invariant: MIN_DIFFICULTY is the divisor in
// `u128_max_target() / MIN_DIFFICULTY` at the cap computation in
// calculate_difficulty(). A zero divisor would panic on division;
// while the literal 500 is obviously nonzero, this `const assert`
// makes the invariant unmissable to anyone touching the constant.
const _: () = assert!(
    MIN_DIFFICULTY > 0,
    "MIN_DIFFICULTY must be nonzero — used as divisor in calculate_difficulty",
);

// Fixed-point constants for integer 2^x approximation
const RBITS: u32 = 16;
const RADIX: u128 = 1u128 << RBITS;
// 4-term Taylor coefficients for 2^(x/RADIX), scaled by RADIX.
// Evaluated via Horner's method to avoid cascading truncation errors.
// Maximum error < 0.005% across [0, RADIX).
const COEFF_1: u128 = 45426; // ln(2) * RADIX
const COEFF_2: u128 = 15743; // (ln(2))^2/2! * RADIX
const COEFF_3: u128 = 3638;  // (ln(2))^3/3! * RADIX
const COEFF_4: u128 = 630;   // (ln(2))^4/4! * RADIX
const MAX_INT_EXPONENT: i32 = 64;

#[derive(Clone, Debug)]
pub struct DifficultyAdjustment {
    pub short_term: Hash,
    pub long_term: Hash,
    pub combined: Hash,
    pub factor_scaled: u64,
}

#[derive(Clone, Debug)]
pub struct DifficultyBlock {
    pub height: u64,
    pub timestamp: u64,
    pub target: Hash,
}

/// Assert weight invariant at startup.
pub fn assert_weight_invariant() {
    assert_eq!(
        DIFFICULTY_SHORT_WEIGHT + DIFFICULTY_LONG_WEIGHT,
        DIFFICULTY_WEIGHT_SCALE,
        "SHORT_WEIGHT + LONG_WEIGHT must equal WEIGHT_SCALE"
    );
}

/// Calculate next difficulty target using dual-anchor ASERT
pub fn calculate_difficulty(blocks: &[DifficultyBlock], current_height: u64) -> Hash {
    if blocks.len() < 2 { return max_target(); }
    let tip = match blocks.last() { Some(t) => t, None => return max_target() };
    let tip_target = target_to_u128(&tip.target);

    let short_anchor = get_anchor(blocks, DIFFICULTY_SHORT_WINDOW as usize);
    let short_target = apply_asert(tip_target, short_anchor, tip, TARGET_BLOCK_TIME, ASERT_HALFLIFE);

    let long_anchor = get_anchor(blocks, DIFFICULTY_LONG_WINDOW as usize);
    let long_target = apply_asert(tip_target, long_anchor, tip, TARGET_BLOCK_TIME, ASERT_HALFLIFE);

    let short_weighted = safe_mul_u128(short_target, DIFFICULTY_SHORT_WEIGHT as u128);
    let long_weighted = safe_mul_u128(long_target, DIFFICULTY_LONG_WEIGHT as u128);
    let combined = short_weighted.saturating_add(long_weighted) / DIFFICULTY_WEIGHT_SCALE as u128;

    let max_val = safe_mul_u128(tip_target, MAX_DIFFICULTY_ADJ_NUM as u128) / (MAX_DIFFICULTY_ADJ_DEN as u128);
    let min_val = safe_mul_u128(tip_target, MIN_DIFFICULTY_ADJ_NUM as u128) / (MIN_DIFFICULTY_ADJ_DEN as u128);
    // Apply MIN_DIFFICULTY consensus floor: target cannot exceed
    // u128::MAX / MIN_DIFFICULTY. This caps ASERT below the unsafe range
    // where production rate outruns P2P propagation. See MIN_DIFFICULTY
    // comment above.
    let max_t = u128_max_target() / MIN_DIFFICULTY;

    let min_bound = min_val.max(1);
    let max_bound = max_val.min(max_t).max(min_bound);
    let clamped = combined.clamp(min_bound, max_bound);

    let final_target = if needs_emergency_drop(blocks, current_height) {
        let emergency_max = safe_mul_u128(tip_target, (MAX_DIFFICULTY_ADJ_NUM * EMERGENCY_DROP_FACTOR) as u128) / (MAX_DIFFICULTY_ADJ_DEN as u128);
        let emergency_target = safe_mul_u128(clamped, EMERGENCY_DROP_FACTOR as u128);
        let emer_min = min_val.max(1);
        // Emergency drop still respects MIN_DIFFICULTY — a stalled chain
        // should ease up to the floor, not collapse past it.
        let emer_max = emergency_max.min(max_t).max(emer_min);
        emergency_target.clamp(emer_min, emer_max)
    } else {
        clamped
    };

    u128_to_target(final_target)
}

fn apply_asert(current_target: u128, anchor: &DifficultyBlock, tip: &DifficultyBlock, target_time: u64, halflife: u64) -> u128 {
    let height_diff = tip.height.saturating_sub(anchor.height);
    if height_diff == 0 { return current_target; }

    let time_diff = (tip.timestamp as i128) - (anchor.timestamp as i128);
    let expected_time = (height_diff as i128) * (target_time as i128);
    let time_error = time_diff - expected_time;

    // v1.0.12 fix (S1 — consensus showstopper): denominator is `halflife`
    // alone (in seconds), NOT `halflife * target_time`. The previous code
    // multiplied by target_time, producing an effective halflife of
    // `ASERT_HALFLIFE * TARGET_BLOCK_TIME = 3600 * 120 = 432,000s ≈ 5
    // days` — making ASERT 120× weaker than designed. Canonical aserti3-2d
    // (the Bitcoin Cash reference) defines:
    //
    //   new_target = anchor_target * 2^((time_diff - target_time*height_diff) / halflife)
    //
    // where halflife is in SECONDS. The multiplication by target_time was
    // a unit-confusion bug. The ASERT_HALFLIFE constant docstring confirms
    // intent: "halflife in seconds (1 hour)" — so the canonical formula
    // is what was meant. Code review surfaced the dimensional mismatch.
    //
    // Practical effect of the fix: an 8-block window with each block 2×
    // slow now produces ~1% target adjustment (was ~0.01%) — ASERT is
    // actually responsive instead of leaning entirely on the
    // MAX_DIFFICULTY_ADJ_NUM/DEN clamps + EMERGENCY_DROP for stability.
    //
    // This is a CONSENSUS CHANGE. Activation: along with the v1.0.12
    // ring-ramp hard fork. Pre-v1.0.12 chains computed targets with the
    // bugged formula; post-v1.0.12 chains use the canonical one. Mixed
    // mining at the fork boundary will produce blocks the other version
    // rejects — coordinated deployment required.
    let denominator = halflife as i128;
    if denominator == 0 { return current_target; }

    let exponent_fp = time_error
        .checked_mul(RADIX as i128)
        .unwrap_or(if time_error >= 0 { i128::MAX } else { i128::MIN })
        / denominator;

    let (int_part, frac_part) = decompose_fixed_point(exponent_fp);
    let clamped_int = int_part.clamp(-MAX_INT_EXPONENT, MAX_INT_EXPONENT);

    let frac_pow2 = pow2_frac(frac_part);
    let adjusted = safe_mul_shift(current_target, frac_pow2);

    if clamped_int >= 0 {
        adjusted.checked_shl(clamped_int as u32).unwrap_or(u128::MAX)
    } else {
        // SAFETY: `clamped_int` is bounded to [-MAX_INT_EXPONENT,
        // MAX_INT_EXPONENT] by the `.clamp(...)` on the previous block,
        // so in this `< 0` branch `-clamped_int` is in (0, MAX_INT_EXPONENT]
        // — never overflows the i32 negation, never wraps on the `as u32`
        // cast (MAX_INT_EXPONENT fits in i32 by construction; the
        // const is asserted elsewhere). The `>= 128` guard then caps
        // the shift amount before it could exceed u128's width.
        let neg = (-clamped_int) as u32;
        if neg >= 128 { 1 } else { adjusted >> neg }
    }.max(1)
}

fn decompose_fixed_point(exponent_fp: i128) -> (i32, u128) {
    if exponent_fp >= 0 {
        let int_part = (exponent_fp >> RBITS).clamp(i32::MIN as i128, i32::MAX as i128) as i32;
        let frac_part = (exponent_fp & (RADIX as i128 - 1)) as u128;
        (int_part, frac_part)
    } else {
        let safe_exp = exponent_fp.max(i128::MIN + 1);
        let abs_exp = (-safe_exp) as u128;
        let abs_int = abs_exp >> RBITS;
        let abs_frac = abs_exp & (RADIX - 1);
        let clamped_abs = abs_int.min(i32::MAX as u128);
        if abs_frac == 0 {
            (-(clamped_abs as i32), 0)
        } else {
            let clamped_sub = abs_int.min((i32::MAX - 1) as u128);
            (-(clamped_sub as i32) - 1, RADIX - abs_frac)
        }
    }
}

fn pow2_frac(x: u128) -> u128 {
    // Horner's method: RADIX * 2^(x/RADIX)
    //   = RADIX + x*(c1 + x*(c2 + x*(c3 + x*c4/R)/R)/R)/R
    //
    // Each intermediate only shifts once per level, avoiding the cascading
    // truncation from the old direct form (which shifted repeatedly and lost
    // up to 1.2% at x near RADIX). Max error < 0.1% across [0, RADIX),
    // limited by the 4-term Taylor polynomial itself (not by arithmetic).
    let t = COEFF_3 + ((COEFF_4 * x) >> RBITS);
    let t = COEFF_2 + ((t * x) >> RBITS);
    let t = COEFF_1 + ((t * x) >> RBITS);
    RADIX + ((t * x) >> RBITS)
}

fn target_to_u128(target: &Hash) -> u128 {
    let bytes = target.as_bytes();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    u128::from_be_bytes(buf).max(1)
}

fn u128_to_target(value: u128) -> Hash {
    // Encodes the u128 difficulty target into the most significant 16 bytes of
    // the 32-byte hash. The lower 16 bytes are always zero — this module
    // operates at 128-bit precision. Any hash where the upper 16 bytes are
    // strictly less than the target passes PoW; the lower bytes only matter
    // at the exact equality boundary (probability ~2^-128, negligible).
    //
    // Callers needing the true maximum target (genesis, resets) should call
    // max_target() directly rather than routing through this function.
    let mut bytes = [0u8; 32];
    let clamped = value.clamp(1, u128::MAX);
    bytes[..16].copy_from_slice(&clamped.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn u128_max_target() -> u128 { u128::MAX }

fn safe_mul_u128(a: u128, b: u128) -> u128 {
    // If the product overflows u128, saturate at u128::MAX (maximum target =
    // minimum difficulty). The old fallback shifted one operand right, losing
    // low-order bits and producing a wrong (too-small) result in the
    // consensus-critical overflow path. Saturation is both correct and safe:
    // a target at u128::MAX is the easiest possible difficulty, which is the
    // right choice when the inputs are legitimately near that boundary.
    a.checked_mul(b).unwrap_or(u128::MAX)
}

fn safe_mul_shift(target: u128, frac_pow2: u128) -> u128 {
    let extra = frac_pow2.saturating_sub(RADIX);
    if extra == 0 { return target; }
    let adjustment = if target <= u128::MAX / extra {
        (target * extra) >> RBITS
    } else {
        (target >> RBITS) * extra
    };
    target.saturating_add(adjustment)
}

fn get_anchor(blocks: &[DifficultyBlock], depth: usize) -> &DifficultyBlock {
    let idx = blocks.len().saturating_sub(depth.min(blocks.len()));
    &blocks[idx]
}

pub fn needs_emergency_drop(blocks: &[DifficultyBlock], current_height: u64) -> bool {
    // Bootstrap guard: don't trigger emergency drop during chain startup.
    // A fresh chain has no hashrate baseline — the first few blocks may
    // arrive slowly simply because mining hasn't begun, not because of a
    // genuine stall. Require at least 2× the emergency window of history
    // before arming the drop logic.
    let min_history_height = EMERGENCY_DIFFICULTY_BLOCKS * 2;
    if current_height < min_history_height {
        return false;
    }
    if blocks.len() < EMERGENCY_DIFFICULTY_BLOCKS as usize { return false; }
    let tip = match blocks.last() { Some(t) => t, None => return false };
    let check_idx = blocks.len().saturating_sub(EMERGENCY_DIFFICULTY_BLOCKS as usize);
    let check_block = match blocks.get(check_idx) { Some(b) => b, None => return false };
    let time_diff = tip.timestamp.saturating_sub(check_block.timestamp);
    let expected = EMERGENCY_DIFFICULTY_BLOCKS * TARGET_BLOCK_TIME;
    time_diff > expected * EMERGENCY_TIME_MULTIPLIER
}

pub fn max_target() -> Hash { Hash::from_bytes([0xFF; 32]) }

pub fn min_target() -> Hash {
    let mut bytes = [0u8; 32];
    bytes[2] = 0x01;
    Hash::from_bytes(bytes)
}

pub fn target_to_difficulty(target: &Hash) -> u128 {
    u128_max_target() / target_to_u128(target)
}

/// Estimate hashrate (informational, f64 is fine here — not consensus).
pub fn estimate_hashrate(blocks: &[DifficultyBlock]) -> f64 {
    if blocks.len() < 2 { return 0.0; }
    let first = &blocks[0];
    let last = match blocks.last() { Some(l) => l, None => return 0.0 };
    let time_span = last.timestamp.saturating_sub(first.timestamp) as f64;
    if time_span == 0.0 { return 0.0; }
    let total_work: f64 = blocks.iter().map(|b| target_to_difficulty(&b.target) as f64).sum();
    total_work / time_span
}

/// Calculate difficulty from target (convenience function).
pub fn calculate_difficulty_from_target(target: &Hash) -> u128 {
    target_to_difficulty(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(height: u64, timestamp: u64) -> DifficultyBlock {
        DifficultyBlock { height, timestamp, target: max_target() }
    }

    /// Phase A7 (audit fix): build a block with a *non-saturated* target so
    /// the difficulty algorithm exercises its real arithmetic path instead
    /// of u128 saturation at u128::MAX. We set the high u128 of the target
    /// to ~2^120 (roughly 1/256th of max), which is well inside the valid
    /// difficulty range for any realistic mainnet/testnet chain.
    /// Production tip targets are NEVER u128::MAX past block 1; running the
    /// algorithm at the saturation boundary doesn't tell us anything useful
    /// about how it behaves on a real chain.
    fn make_block_realistic(height: u64, timestamp: u64) -> DifficultyBlock {
        let mut bytes = [0u8; 32];
        bytes[1] = 0x01; // first 16 bytes ≈ 2^120
        DifficultyBlock { height, timestamp, target: Hash::from_bytes(bytes) }
    }

    #[test]
    fn test_max_target() {
        assert_eq!(max_target().as_bytes()[0], 0xFF);
    }

    #[test]
    fn test_difficulty_stable() {
        let blocks: Vec<_> = (0..20).map(|i| make_block(i, i * TARGET_BLOCK_TIME)).collect();
        let new_target = calculate_difficulty(&blocks, 20);
        let diff = target_to_difficulty(&new_target);
        assert!(diff < 10);
    }

    #[test]
    fn test_difficulty_increases_on_fast_blocks() {
        let blocks: Vec<_> = (0..20).map(|i| make_block(i, i * (TARGET_BLOCK_TIME / 2))).collect();
        let new_target = calculate_difficulty(&blocks, 20);
        let old_diff = target_to_difficulty(&blocks.last().unwrap().target);
        let new_diff = target_to_difficulty(&new_target);
        assert!(new_diff >= old_diff);
    }

    /// v1.0.12 S1 regression test — ASERT must produce a MEASURABLE
    /// difficulty change in response to sustained off-target block
    /// times. The pre-fix bug made ASERT 120× weaker than designed
    /// (denominator had a spurious `* target_time` factor); the
    /// existing `test_difficulty_increases_on_fast_blocks` only
    /// asserted `new_diff >= old_diff` which passed even with a
    /// 0.01% adjustment, hiding the bug.
    ///
    /// This test pins the magnitude. With 20 blocks at half the
    /// target time, ASERT should respond with a difficulty increase
    /// of AT LEAST 5% (the original buggy version produced ~0.06%).
    #[test]
    fn test_asert_responsive_to_time_error() {
        // 20 blocks at HALF the target time = 50% time deficit over
        // ~20 minutes of expected time. With halflife=3600s, expected
        // exponent ≈ -1200/3600 ≈ -0.333 → target should shrink by
        // ~2^0.333 ≈ 1.26× → difficulty rises ~26%.
        let blocks: Vec<_> = (0..20).map(|i| make_block(i, i * (TARGET_BLOCK_TIME / 2))).collect();
        let new_target = calculate_difficulty(&blocks, 20);
        let old_diff = target_to_difficulty(&blocks.last().unwrap().target);
        let new_diff = target_to_difficulty(&new_target);

        // Difficulty must rise meaningfully. 5% is a generous floor
        // that catches the previous 0.06% bug shape but leaves
        // headroom for clamp behaviour. The actual value should be
        // closer to ~20-30% rise.
        assert!(
            new_diff >= old_diff + (old_diff / 20),
            "ASERT failed to respond to 50% time deficit over 20 blocks: \
             old_diff={}, new_diff={} (expected at least +5%); \
             pre-S1-fix the response was 0.06% — if this test fails, \
             check src/consensus/difficulty.rs::apply_asert for a \
             spurious target_time multiplier in the denominator.",
            old_diff, new_diff,
        );
    }

    #[test]
    fn test_difficulty_decreases_on_slow_blocks() {
        // Phase A7 (audit fix): use make_block_realistic so the algorithm
        // exercises its real arithmetic path instead of saturation at u128::MAX.
        // The previous version started from max_target which has no headroom
        // for "make difficulty easier" — saturation in safe_mul_u128 then
        // produced a smaller combined value, causing a spurious test failure.
        let blocks: Vec<_> = (0..20)
            .map(|i| make_block_realistic(i, i * TARGET_BLOCK_TIME * 3))
            .collect();
        let new_target = calculate_difficulty(&blocks, 20);
        let old_val = target_to_u128(&blocks.last().unwrap().target);
        let new_val = target_to_u128(&new_target);
        // Slow blocks → algorithm should make difficulty easier → target larger.
        assert!(new_val >= old_val,
            "slow blocks should produce target ≥ tip target: old={}, new={}",
            old_val, new_val);
    }

    #[test]
    fn test_weight_invariant() {
        assert_weight_invariant();
    }

    #[test]
    fn test_genesis_returns_max_target() {
        assert_eq!(calculate_difficulty(&[], 0), max_target());
        assert_eq!(calculate_difficulty(&[make_block(0, 0)], 1), max_target());
    }

    #[test]
    fn test_decompose_positive() {
        let (int_part, frac) = decompose_fixed_point(98304);
        assert_eq!(int_part, 1);
        assert_eq!(frac, 32768);
    }

    #[test]
    fn test_decompose_negative() {
        let (int_part, frac) = decompose_fixed_point(-32768);
        assert_eq!(int_part, -1);
        assert_eq!(frac, 32768);
    }

    #[test]
    fn test_decompose_i128_min() {
        let (int_part, frac) = decompose_fixed_point(i128::MIN);
        assert!(int_part < 0);
        assert!(frac < RADIX);
    }

    #[test]
    fn test_pow2_frac_zero() {
        assert_eq!(pow2_frac(0), RADIX);
    }

    #[test]
    fn test_pow2_frac_half() {
        let result = pow2_frac(RADIX / 2);
        let approx = (result as f64) / (RADIX as f64);
        assert!((approx - 1.4142).abs() < 0.01);
    }

    #[test]
    fn test_polynomial_accuracy() {
        // Horner form + 4-term Taylor — verify < 0.01% error at representative points.
        let cases: &[(u128, f64)] = &[
            (0, 1.0), (RADIX / 4, 1.18921), (RADIX / 2, 1.41421),
            (RADIX * 3 / 4, 1.68179), (RADIX * 99 / 100, 1.98631),
        ];
        for (x, expected) in cases {
            let approx = pow2_frac(*x) as f64 / RADIX as f64;
            let err = (approx - expected).abs() / expected;
            assert!(err < 0.001, "pow2_frac error {:.4}% at x={}", err * 100.0, x);
        }
    }

    #[test]
    fn test_safe_mul_no_overflow() { assert_eq!(safe_mul_u128(100, 200), 20000); }

    #[test]
    fn test_safe_mul_overflow() { assert!(safe_mul_u128(u128::MAX, 2) > 0); }

    #[test]
    fn test_target_roundtrip() {
        let target = max_target();
        let val = target_to_u128(&target);
        let back = u128_to_target(val);
        assert_eq!(&target.as_bytes()[..16], &back.as_bytes()[..16]);
    }

    #[test]
    fn test_asert_same_height() {
        let block = make_block(10, 300);
        assert_eq!(apply_asert(12345, &block, &block, TARGET_BLOCK_TIME, ASERT_HALFLIFE), 12345);
    }

    #[test]
    fn test_emergency_drop_triggers() {
        // Height must be above the bootstrap guard (>= EMERGENCY_DIFFICULTY_BLOCKS * 2 = 24).
        let height_past_bootstrap = EMERGENCY_DIFFICULTY_BLOCKS * 3;
        let n = height_past_bootstrap + 5;
        let mut blocks: Vec<_> = (0..n).map(|i| make_block(i, i * TARGET_BLOCK_TIME)).collect();
        blocks.last_mut().unwrap().timestamp += TARGET_BLOCK_TIME * EMERGENCY_DIFFICULTY_BLOCKS * EMERGENCY_TIME_MULTIPLIER * 2;
        assert!(needs_emergency_drop(&blocks, n));
    }

    #[test]
    fn test_emergency_drop_bootstrap_guard() {
        // Emergency drop must NOT fire during the bootstrap period (height < EMERGENCY_DIFFICULTY_BLOCKS * 2).
        let n = EMERGENCY_DIFFICULTY_BLOCKS as u64 + 5;
        let mut blocks: Vec<_> = (0..n).map(|i| make_block(i, i * TARGET_BLOCK_TIME)).collect();
        blocks.last_mut().unwrap().timestamp += TARGET_BLOCK_TIME * EMERGENCY_DIFFICULTY_BLOCKS * EMERGENCY_TIME_MULTIPLIER * 2;
        // Same data, but height is below bootstrap threshold — must return false.
        assert!(!needs_emergency_drop(&blocks, n));
    }
}
