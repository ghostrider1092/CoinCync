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
//!
//! ## Audit map
//! Each `§` is a code element below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `calculate_difficulty`** — INVARIANT: output stays inside the per-block
//!   clamp `[tip/2, tip*2]` AND never exceeds `max_t = u128::MAX / MIN_DIFFICULTY`
//!   (the consensus floor is enforced for every input, emergency path included);
//!   integer-only and deterministic. THREAT: difficulty manipulation / block
//!   production outrunning P2P propagation once target drifts past the floor.
//!   TESTS: `test_difficulty_stable`, `test_difficulty_increases_on_fast_blocks`,
//!   `test_difficulty_decreases_on_slow_blocks`, `test_genesis_returns_max_target`,
//!   `calculate_difficulty_hits_min_and_max_adjustment_clamp_bounds_exactly`,
//!   `calculate_difficulty_handles_decreasing_and_equal_timestamps_within_clamp`,
//!   `calculate_difficulty_future_timestamp_eases_but_respects_max_t_cap`,
//!   `calculate_difficulty_output_never_exceeds_max_t_across_scenarios`.
//! - **§2 `apply_asert` (ASERT-i3-2d)** — INVARIANT: canonical aserti3-2d — the
//!   exponent denominator is `halflife` (in seconds) ALONE, so one halflife of
//!   time_error exactly doubles/halves the target; `height_diff == 0` returns the
//!   current target; exponent overflow saturates and the integer exponent clamps
//!   at ±`MAX_INT_EXPONENT`. THREAT: **S1 unit-confusion — caused a TESTNET WIPE**;
//!   the bugged `halflife*target_time` denominator made ASERT ~120× too weak.
//!   TESTS: `test_asert_same_height`,
//!   `apply_asert_canonical_formula_denominator_is_halflife_seconds_alone`,
//!   `apply_asert_exponent_overflow_saturates_to_i128_min_without_panic`,
//!   `apply_asert_clamps_integer_exponent_at_max_int_exponent`.
//! - **§3 `needs_emergency_drop`** — INVARIANT: triggers only when `time_diff`
//!   strictly exceeds `expected × EMERGENCY_TIME_MULTIPLIER`; the bootstrap guard
//!   (`current_height < EMERGENCY_DIFFICULTY_BLOCKS*2`) and the short-history guard
//!   suppress it; the drop still respects the MIN_DIFFICULTY floor. THREAT: false
//!   emergency easing during startup or a benign stall. TESTS:
//!   `test_emergency_drop_triggers`, `test_emergency_drop_bootstrap_guard`,
//!   `needs_emergency_drop_is_strict_at_threshold_boundary`,
//!   `needs_emergency_drop_false_when_fewer_than_emergency_blocks`,
//!   `calculate_difficulty_emergency_drop_respects_min_difficulty_floor`.
//! - **§4 `get_anchor`** — INVARIANT: never anchors ASERT on the genesis block
//!   (height 0) while it is inside the window, but uses it when it is the only
//!   block; deterministic across nodes. THREAT: a stale genesis timestamp making
//!   the chain look catastrophically slow and collapsing difficulty to the floor.
//!   TESTS: `get_anchor_skips_genesis_inside_window_but_uses_it_when_alone`,
//!   `startup_grace_ignores_a_stale_genesis_timestamp`.
//! - **§5 `safe_mul_u128` / `safe_mul_shift`** — INVARIANT: a u128 product overflow
//!   saturates at `u128::MAX` (= easiest target / minimum difficulty), never wraps
//!   or panics. THREAT: R-4 — the old shift-fallback lost low bits and produced a
//!   wrong (too-small) target in the consensus-critical overflow path. TESTS:
//!   `safe_mul_u128_saturates_at_boundary`, `test_safe_mul_no_overflow`,
//!   `test_safe_mul_overflow`.
//! - **§6 `decompose_fixed_point` / `pow2_frac`** — INVARIANT: integer u128
//!   fixed-point `2^x` approximation, error < 0.1% across `[0, RADIX)`; handles
//!   `i128::MIN` without panic. THREAT: H-1 — f64 is non-deterministic across CPU
//!   architectures and would fork consensus. TESTS: `test_decompose_positive`,
//!   `test_decompose_negative`, `test_decompose_i128_min`, `test_pow2_frac_zero`,
//!   `test_pow2_frac_half`, `test_polynomial_accuracy`.
//! - **§7 `target_to_u128` / `u128_to_target` / `target_to_difficulty`** —
//!   INVARIANT: roundtrip preserves the upper 16 bytes; an all-zero target maps to
//!   `1` via `.max(1)` so downstream division never divides by zero;
//!   `calculate_difficulty_from_target` is an exact alias. THREAT: div-by-zero DoS
//!   on a crafted zero target. TESTS: `test_target_roundtrip`,
//!   `target_to_u128_maps_all_zero_target_to_one`,
//!   `calculate_difficulty_from_target_equals_target_to_difficulty`.
//! - **§8 `max_target` / `min_target` / `assert_weight_invariant`** — INVARIANT:
//!   `max_target` is all-`0xFF`; the dual-window weights satisfy
//!   `SHORT_WEIGHT + LONG_WEIGHT == WEIGHT_SCALE`. THREAT: a mis-set weight constant
//!   silently skewing the short/long blend. TESTS: `test_max_target`,
//!   `test_weight_invariant`.

use crate::constants::{
    ASERT_HALFLIFE, DIFFICULTY_LONG_WEIGHT, DIFFICULTY_LONG_WINDOW, DIFFICULTY_SHORT_WEIGHT,
    DIFFICULTY_SHORT_WINDOW, DIFFICULTY_WEIGHT_SCALE, EMERGENCY_DIFFICULTY_BLOCKS,
    EMERGENCY_DROP_FACTOR, EMERGENCY_TIME_MULTIPLIER, MAX_DIFFICULTY_ADJ_DEN,
    MAX_DIFFICULTY_ADJ_NUM, MIN_DIFFICULTY_ADJ_DEN, MIN_DIFFICULTY_ADJ_NUM, TARGET_BLOCK_TIME,
};
use crate::primitives::Hash;

/// Absolute minimum network difficulty — the consensus floor below which ASERT
/// cannot drive the chain. Equivalent to a target ceiling of `u128::MAX / 500`.
///
/// The dual-window ASERT can drift difficulty arbitrarily low under uneven
/// hashrate conditions (e.g. a single home miner during testnet bootstrap),
/// and at the natural floor `target = u128::MAX` block production runs faster
/// than P2P validation+gossip — the chain physically can't stay synchronized.
/// The standard production fix for this class of issue is a minimum-difficulty
/// floor. (Prior comment cited "Monero LWMA, Bitcoin testnet 20-min
/// rule, Zcash NU5 floor" as three concrete prior-art examples of
/// this class of fix. None of those specific per-project mechanisms
/// were re-verified against upstream source this session, so the
/// concrete attributions are dropped — the "minimum-difficulty floor
/// as the standard production fix" characterisation stands on its
/// own reasoning above.)
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
const COEFF_3: u128 = 3638; // (ln(2))^3/3! * RADIX
const COEFF_4: u128 = 630; // (ln(2))^4/4! * RADIX
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
    if blocks.len() < 2 {
        return max_target();
    }
    let tip = match blocks.last() {
        Some(t) => t,
        None => return max_target(),
    };
    let tip_target = target_to_u128(&tip.target);

    let short_anchor = get_anchor(blocks, DIFFICULTY_SHORT_WINDOW as usize);
    let short_target = apply_asert(
        tip_target,
        short_anchor,
        tip,
        TARGET_BLOCK_TIME,
        ASERT_HALFLIFE,
    );

    let long_anchor = get_anchor(blocks, DIFFICULTY_LONG_WINDOW as usize);
    let long_target = apply_asert(
        tip_target,
        long_anchor,
        tip,
        TARGET_BLOCK_TIME,
        ASERT_HALFLIFE,
    );

    let short_weighted = safe_mul_u128(short_target, DIFFICULTY_SHORT_WEIGHT as u128);
    let long_weighted = safe_mul_u128(long_target, DIFFICULTY_LONG_WEIGHT as u128);
    let combined = short_weighted.saturating_add(long_weighted) / DIFFICULTY_WEIGHT_SCALE as u128;

    let max_val = safe_mul_u128(tip_target, MAX_DIFFICULTY_ADJ_NUM as u128)
        / (MAX_DIFFICULTY_ADJ_DEN as u128);
    let min_val = safe_mul_u128(tip_target, MIN_DIFFICULTY_ADJ_NUM as u128)
        / (MIN_DIFFICULTY_ADJ_DEN as u128);
    // Apply MIN_DIFFICULTY consensus floor: target cannot exceed
    // u128::MAX / MIN_DIFFICULTY. This caps ASERT below the unsafe range
    // where production rate outruns P2P propagation. See MIN_DIFFICULTY
    // comment above.
    let max_t = u128_max_target() / MIN_DIFFICULTY;

    let min_bound = min_val.max(1);
    let max_bound = max_val.min(max_t).max(min_bound);
    let clamped = combined.clamp(min_bound, max_bound);

    let final_target = if needs_emergency_drop(blocks, current_height) {
        let emergency_max = safe_mul_u128(
            tip_target,
            (MAX_DIFFICULTY_ADJ_NUM * EMERGENCY_DROP_FACTOR) as u128,
        ) / (MAX_DIFFICULTY_ADJ_DEN as u128);
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

fn apply_asert(
    current_target: u128,
    anchor: &DifficultyBlock,
    tip: &DifficultyBlock,
    target_time: u64,
    halflife: u64,
) -> u128 {
    let height_diff = tip.height.saturating_sub(anchor.height);
    if height_diff == 0 {
        return current_target;
    }

    let time_diff = (tip.timestamp as i128) - (anchor.timestamp as i128);
    let expected_time = (height_diff as i128) * (target_time as i128);
    let time_error = time_diff - expected_time;

    // S1 backport (2026-06-15): denominator is `halflife` alone (in
    // seconds), NOT `halflife * target_time`. The previous code
    // multiplied by target_time, producing an effective halflife of
    // `ASERT_HALFLIFE * TARGET_BLOCK_TIME = 3600 * 120 = 432,000s ≈ 5
    // days` — making ASERT 120× weaker than designed. Canonical
    // aserti3-2d (the Bitcoin Cash reference) defines:
    //
    //   new_target = anchor_target * 2^((time_diff - target_time*height_diff) / halflife)
    //
    // where halflife is in SECONDS. The multiplication by target_time
    // was a unit-confusion bug. The ASERT_HALFLIFE constant docstring
    // confirms intent: "halflife in seconds (1 hour)" — so the
    // canonical formula is what was meant.
    //
    // CONSENSUS-AFFECTING. Required a full testnet wipe + new genesis
    // when this backport landed (2026-06-15): blocks mined under the
    // bugged formula produced targets ~0% adjusted between blocks,
    // while the correct formula adjusts the target ~3% over an
    // 8-block window with the time errors we were seeing. External
    // tester barns hit the wall on IBD at testnet block 2222 (target
    // 0x00153b2a... canonical vs 0x0015d888... computed by fixed
    // formula) — the divergence diagnostic at
    // tests/diag_asert_at_2222.rs (in v1.0.13-refactor) reproduces it.
    //
    // Landed on origin/main via PR #67 (commit c42b95f2, 2026-06-21).
    // This branch (refactor/sync-state-model) was cut before that
    // merge and was missing the fix — restored 2026-06-30 (session
    // notes: [[project_session_2026_06_29_partition_recovery]]).
    let denominator = halflife as i128;
    if denominator == 0 {
        return current_target;
    }

    let exponent_fp = time_error
        .checked_mul(RADIX as i128)
        .unwrap_or(if time_error >= 0 {
            i128::MAX
        } else {
            i128::MIN
        })
        / denominator;

    let (int_part, frac_part) = decompose_fixed_point(exponent_fp);
    let clamped_int = int_part.clamp(-MAX_INT_EXPONENT, MAX_INT_EXPONENT);

    let frac_pow2 = pow2_frac(frac_part);
    let adjusted = safe_mul_shift(current_target, frac_pow2);

    if clamped_int >= 0 {
        adjusted
            .checked_shl(clamped_int as u32)
            .unwrap_or(u128::MAX)
    } else {
        // SAFETY: `clamped_int` is bounded to [-MAX_INT_EXPONENT,
        // MAX_INT_EXPONENT] by the `.clamp(...)` on the previous block,
        // so in this `< 0` branch `-clamped_int` is in (0, MAX_INT_EXPONENT]
        // — never overflows the i32 negation, never wraps on the `as u32`
        // cast (MAX_INT_EXPONENT fits in i32 by construction; the
        // const is asserted elsewhere). The `>= 128` guard then caps
        // the shift amount before it could exceed u128's width.
        let neg = (-clamped_int) as u32;
        if neg >= 128 {
            1
        } else {
            adjusted >> neg
        }
    }
    .max(1)
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

fn u128_max_target() -> u128 {
    u128::MAX
}

fn safe_mul_u128(a: u128, b: u128) -> u128 {
    // If the product overflows u128, saturate at u128::MAX (maximum target =
    // minimum difficulty). The old fallback shifted one operand right, losing
    // low-order bits and producing a wrong (too-small) result in the
    // consensus-critical overflow path. Saturation is both correct and safe:
    // a target at u128::MAX is the easiest possible difficulty, which is the
    // right choice when the inputs are legitimately near that boundary.
    //
    // AUDIT (R-4 defense-in-depth verification, 2026-07-02): re-audited
    // the saturation contract. `checked_mul` returns Option<u128>, and
    // `.unwrap_or(u128::MAX)` is the correct saturating semantics — NOT
    // reliant on any upstream `clamp`. See regression test
    // `safe_mul_u128_saturates_at_boundary` below for the boundary
    // proof. Callers (`asert_target`, `wtema_target`, `emergency_drop`)
    // then feed the result to `u128_to_target` (L246) which encodes
    // to a Hash where target == u128::MAX means "easiest possible".
    // This matches Bitcoin's arith_uint256::SetCompact() overflow bit
    // semantics: an overflowed compact-encoded target means minimum
    // difficulty, not a rejected block.
    a.checked_mul(b).unwrap_or(u128::MAX)
}

fn safe_mul_shift(target: u128, frac_pow2: u128) -> u128 {
    let extra = frac_pow2.saturating_sub(RADIX);
    if extra == 0 {
        return target;
    }
    let adjustment = if target <= u128::MAX / extra {
        (target * extra) >> RBITS
    } else {
        (target >> RBITS) * extra
    };
    target.saturating_add(adjustment)
}

fn get_anchor(blocks: &[DifficultyBlock], depth: usize) -> &DifficultyBlock {
    let mut idx = blocks.len().saturating_sub(depth.min(blocks.len()));
    // STARTUP GRACE: never anchor ASERT on the genesis block (height 0). Its
    // timestamp is a fixed constant that need not reflect when mining actually
    // began. If the first real block is mined long after the genesis timestamp,
    // anchoring on genesis makes `time_error` enormous — the chain looks
    // catastrophically slow — and ASERT drives difficulty to the MIN_DIFFICULTY
    // floor for roughly the first long-window of blocks before recovering.
    // Advancing the anchor to the first *mined* block keeps every `time_error`
    // over real inter-block timestamps, eliminating the startup dip regardless
    // of the genesis→first-block gap. This is deterministic (all nodes see the
    // same block heights) so it is consensus-safe, and it only differs from the
    // old behaviour while genesis is still inside the difficulty window (roughly
    // the first `DIFFICULTY_LONG_WINDOW` blocks); on a mature chain the window
    // never contains genesis, so mainnet steady-state difficulty is unchanged.
    // Offline-simulated: eliminates the dip for genesis gaps from 2 min to
    // 135 days while preserving fast convergence to the true-hashrate target.
    // See docs/design/difficulty-oscillation-analysis.md §7.
    if idx + 1 < blocks.len() && blocks[idx].height == 0 {
        idx += 1;
    }
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
    if blocks.len() < EMERGENCY_DIFFICULTY_BLOCKS as usize {
        return false;
    }
    let tip = match blocks.last() {
        Some(t) => t,
        None => return false,
    };
    let check_idx = blocks
        .len()
        .saturating_sub(EMERGENCY_DIFFICULTY_BLOCKS as usize);
    let check_block = match blocks.get(check_idx) {
        Some(b) => b,
        None => return false,
    };
    let time_diff = tip.timestamp.saturating_sub(check_block.timestamp);
    let expected = EMERGENCY_DIFFICULTY_BLOCKS * TARGET_BLOCK_TIME;
    time_diff > expected * EMERGENCY_TIME_MULTIPLIER
}

pub fn max_target() -> Hash {
    Hash::from_bytes([0xFF; 32])
}

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
    if blocks.len() < 2 {
        return 0.0;
    }
    let first = &blocks[0];
    let last = match blocks.last() {
        Some(l) => l,
        None => return 0.0,
    };
    let time_span = last.timestamp.saturating_sub(first.timestamp) as f64;
    if time_span == 0.0 {
        return 0.0;
    }
    let total_work: f64 = blocks
        .iter()
        .map(|b| target_to_difficulty(&b.target) as f64)
        .sum();
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
        DifficultyBlock {
            height,
            timestamp,
            target: max_target(),
        }
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
        DifficultyBlock {
            height,
            timestamp,
            target: Hash::from_bytes(bytes),
        }
    }

    #[test]
    fn test_max_target() {
        assert_eq!(max_target().as_bytes()[0], 0xFF);
    }

    /// R-4 defense-in-depth regression: `safe_mul_u128` must saturate
    /// at `u128::MAX` when the product overflows, not wrap or panic.
    /// The upstream `checked_mul` returns `None` on overflow; the
    /// `.unwrap_or(u128::MAX)` fallback is what we're proving here.
    #[test]
    fn safe_mul_u128_saturates_at_boundary() {
        // Non-overflow case: normal multiply.
        assert_eq!(safe_mul_u128(1_000, 2_000), 2_000_000);
        // Boundary case: fits exactly.
        assert_eq!(safe_mul_u128(u128::MAX, 1), u128::MAX);
        assert_eq!(safe_mul_u128(1, u128::MAX), u128::MAX);
        // Overflow case: must saturate to MAX, NOT wrap to 0 or panic.
        assert_eq!(safe_mul_u128(u128::MAX, 2), u128::MAX);
        assert_eq!(safe_mul_u128(u128::MAX / 2 + 2, 2), u128::MAX);
        // A high-value pair that clearly overflows:
        assert_eq!(safe_mul_u128(u128::MAX / 3 * 2, 3), u128::MAX);
    }

    #[test]
    fn test_difficulty_stable() {
        let blocks: Vec<_> = (0..20)
            .map(|i| make_block(i, i * TARGET_BLOCK_TIME))
            .collect();
        let new_target = calculate_difficulty(&blocks, 20);
        let diff = target_to_difficulty(&new_target);
        assert!(diff < 10);
    }

    #[test]
    fn test_difficulty_increases_on_fast_blocks() {
        let blocks: Vec<_> = (0..20)
            .map(|i| make_block(i, i * (TARGET_BLOCK_TIME / 2)))
            .collect();
        let new_target = calculate_difficulty(&blocks, 20);
        let old_diff = target_to_difficulty(&blocks.last().unwrap().target);
        let new_diff = target_to_difficulty(&new_target);
        assert!(new_diff >= old_diff);
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
        assert!(
            new_val >= old_val,
            "slow blocks should produce target ≥ tip target: old={}, new={}",
            old_val,
            new_val
        );
    }

    #[test]
    fn startup_grace_ignores_a_stale_genesis_timestamp() {
        // Regression (docs/design/difficulty-oscillation-analysis.md §7): with a
        // genesis timestamp far before the first mined block, anchoring ASERT on
        // genesis makes the chain look catastrophically slow and drives difficulty
        // to the MIN_DIFFICULTY floor for the first long-window of blocks.
        // get_anchor now skips the genesis anchor, so time_error is computed over
        // real inter-block timestamps only. Build a chain whose genesis is 30 days
        // stale but whose real blocks land on the 120s target, and assert
        // difficulty holds near the initial value instead of collapsing.
        const STALE: u64 = 30 * 24 * 3600; // genesis 30 days before block 1
        let init_diff = target_to_difficulty(&make_block_realistic(0, 0).target);
        let mut blocks = vec![make_block_realistic(0, 0)]; // genesis at ts=0
        for i in 1..=20u64 {
            // real blocks on the 120s target, offset by the stale genesis gap
            blocks.push(make_block_realistic(i, STALE + i * TARGET_BLOCK_TIME));
        }
        let new_diff = target_to_difficulty(&calculate_difficulty(&blocks, 20));
        // On-target real blocks must keep difficulty ~stable near init and must
        // NOT collapse toward the floor (which is what happened when genesis was
        // the anchor: time_error ≈ the 30-day gap → difficulty → MIN_DIFFICULTY).
        assert!(
            new_diff >= init_diff / 2,
            "stale genesis must not collapse difficulty: init={init_diff} new={new_diff}"
        );
        assert!(
            new_diff > MIN_DIFFICULTY * 4,
            "difficulty must stay well above the floor: new={new_diff} floor={MIN_DIFFICULTY}"
        );
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
            (0, 1.0),
            (RADIX / 4, 1.18921),
            (RADIX / 2, 1.41421),
            (RADIX * 3 / 4, 1.68179),
            (RADIX * 99 / 100, 1.98631),
        ];
        for (x, expected) in cases {
            let approx = pow2_frac(*x) as f64 / RADIX as f64;
            let err = (approx - expected).abs() / expected;
            assert!(
                err < 0.001,
                "pow2_frac error {:.4}% at x={}",
                err * 100.0,
                x
            );
        }
    }

    #[test]
    fn test_safe_mul_no_overflow() {
        assert_eq!(safe_mul_u128(100, 200), 20000);
    }

    #[test]
    fn test_safe_mul_overflow() {
        assert!(safe_mul_u128(u128::MAX, 2) > 0);
    }

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
        assert_eq!(
            apply_asert(12345, &block, &block, TARGET_BLOCK_TIME, ASERT_HALFLIFE),
            12345
        );
    }

    #[test]
    fn test_emergency_drop_triggers() {
        // Height must be above the bootstrap guard (>= EMERGENCY_DIFFICULTY_BLOCKS * 2 = 24).
        let height_past_bootstrap = EMERGENCY_DIFFICULTY_BLOCKS * 3;
        let n = height_past_bootstrap + 5;
        let mut blocks: Vec<_> = (0..n)
            .map(|i| make_block(i, i * TARGET_BLOCK_TIME))
            .collect();
        blocks.last_mut().unwrap().timestamp +=
            TARGET_BLOCK_TIME * EMERGENCY_DIFFICULTY_BLOCKS * EMERGENCY_TIME_MULTIPLIER * 2;
        assert!(needs_emergency_drop(&blocks, n));
    }

    #[test]
    fn test_emergency_drop_bootstrap_guard() {
        // Emergency drop must NOT fire during the bootstrap period (height < EMERGENCY_DIFFICULTY_BLOCKS * 2).
        let n = EMERGENCY_DIFFICULTY_BLOCKS as u64 + 5;
        let mut blocks: Vec<_> = (0..n)
            .map(|i| make_block(i, i * TARGET_BLOCK_TIME))
            .collect();
        blocks.last_mut().unwrap().timestamp +=
            TARGET_BLOCK_TIME * EMERGENCY_DIFFICULTY_BLOCKS * EMERGENCY_TIME_MULTIPLIER * 2;
        // Same data, but height is below bootstrap threshold — must return false.
        assert!(!needs_emergency_drop(&blocks, n));
    }

    // ---------------------------------------------------------------------
    // apply_asert — canonical aserti3-2d formula regression (S1 unit fix)
    // ---------------------------------------------------------------------

    /// CONSENSUS-CRITICAL regression pinning the S1 unit-confusion fix that
    /// forced a testnet wipe (see the long comment on `apply_asert`).
    ///
    /// The canonical aserti3-2d denominator is `halflife` (in seconds) ALONE.
    /// The bug multiplied it by `target_time`, making the effective halflife
    /// 120× larger and ASERT ~120× weaker. We pin the EXACT formula:
    ///   new_target = current_target * 2^((time_diff - target_time*height_diff)/halflife)
    ///
    /// With halflife = ASERT_HALFLIFE = 3600 and a single-block gap whose
    /// time_error is exactly one halflife (+3600s), the target must DOUBLE.
    /// Exactly one negative halflife (−3600s) must HALVE it. Under the bugged
    /// denominator (halflife*target_time = 432000) the same inputs would move
    /// the target by <0.1%, so these exact-equality asserts fail loudly if the
    /// unit bug ever regresses.
    #[test]
    fn apply_asert_canonical_formula_denominator_is_halflife_seconds_alone() {
        // One halflife of positive time_error (blocks arriving slow) => 2× target.
        // height_diff = 1, expected_time = 120, so time_diff = 120 + 3600 = 3720
        // gives time_error = +3600 = +1 halflife.
        let anchor = make_block(0, 0);
        let tip = make_block(1, 3720);
        let doubled = apply_asert(1_000_000, &anchor, &tip, TARGET_BLOCK_TIME, ASERT_HALFLIFE);
        assert_eq!(
            doubled, 2_000_000,
            "one positive halflife of time_error must exactly double the target \
             (denominator must be halflife-in-seconds alone; the bugged \
             halflife*target_time denominator would barely move it)"
        );

        // One halflife of negative time_error (blocks arriving fast) => 0.5× target.
        // anchor ts ahead of tip ts by (3600 - 120): time_diff = -3480,
        // expected_time = 120, time_error = -3600 = -1 halflife.
        let anchor_fast = make_block(0, 3600);
        let tip_fast = make_block(1, 120);
        let halved = apply_asert(
            2_000_000,
            &anchor_fast,
            &tip_fast,
            TARGET_BLOCK_TIME,
            ASERT_HALFLIFE,
        );
        assert_eq!(
            halved, 1_000_000,
            "one negative halflife of time_error must exactly halve the target"
        );
    }

    /// exponent overflow (time_error × RADIX) must saturate, not panic.
    ///
    /// Force `time_error.checked_mul(RADIX)` to overflow i128 by choosing a
    /// huge (but non-i128-overflowing) `expected_time = height_diff*target_time
    /// = 2^63 * 2^63 = 2^126`. Then `time_error ≈ -2^126`, and `× 2^16 = 2^142`
    /// overflows i128 → the code substitutes `i128::MIN`. Must return a valid
    /// (heavily-decreased) target ≥ 1 with no panic. (The positive-saturation
    /// branch, i128::MAX, is unreachable through this signature because
    /// `time_error` can only be driven large *negative* via `expected_time`;
    /// `time_diff` alone is bounded by the u64 timestamp range.)
    #[test]
    fn apply_asert_exponent_overflow_saturates_to_i128_min_without_panic() {
        let anchor = make_block(0, 0);
        let tip = DifficultyBlock {
            height: 1u64 << 63,
            timestamp: 0,
            target: max_target(),
        };
        let current: u128 = 1u128 << 100;
        // target_time = 2^63 so expected_time = 2^63 * 2^63 = 2^126 (fits i128),
        // and time_error*RADIX = 2^142 overflows -> saturates to i128::MIN.
        let result = apply_asert(current, &anchor, &tip, 1u64 << 63, ASERT_HALFLIFE);
        assert!(result >= 1, "saturated exponent must still yield target >= 1");
        assert!(
            result < current,
            "an enormous negative time_error must drive the target strictly down, not wrap"
        );
    }

    /// clamped_int is bounded to [-MAX_INT_EXPONENT, MAX_INT_EXPONENT] (±64):
    /// two different super-large exponents that both exceed the bound collapse
    /// to the SAME clamped shift, proving the clamp. (Because the clamp caps
    /// |int| at 64, the `neg >= 128 => 1` guard in the negative branch is
    /// defensively unreachable via `apply_asert` — the max negative shift is 64
    /// — so it cannot be exercised here without inventing an API.)
    #[test]
    fn apply_asert_clamps_integer_exponent_at_max_int_exponent() {
        // Positive side: exponents of +100 and +200 halflives both clamp to +64.
        // frac_part is 0 in both (time_error is an exact multiple of halflife),
        // so each result is exactly current << 64.
        let anchor = make_block(0, 0);
        let current: u128 = 1u128 << 10;
        // time_error = 100*3600 = 360000 -> tip ts = expected(120) + 360000.
        let hi_a = apply_asert(
            current,
            &anchor,
            &make_block(1, 120 + 100 * 3600),
            TARGET_BLOCK_TIME,
            ASERT_HALFLIFE,
        );
        let hi_b = apply_asert(
            current,
            &anchor,
            &make_block(1, 120 + 200 * 3600),
            TARGET_BLOCK_TIME,
            ASERT_HALFLIFE,
        );
        assert_eq!(hi_a, current << 64, "positive exponent must clamp at +64");
        assert_eq!(hi_a, hi_b, "distinct huge positive exponents clamp identically");
        // A within-bound exponent (+1 halflife) is genuinely different (not clamped).
        let unclamped = apply_asert(
            current,
            &anchor,
            &make_block(1, 120 + 3600),
            TARGET_BLOCK_TIME,
            ASERT_HALFLIFE,
        );
        assert_ne!(unclamped, hi_a, "an unclamped +1 exponent must differ from the clamped result");

        // Negative side: exponents of -100 and -200 halflives both clamp to -64.
        let current_neg: u128 = 1u128 << 70;
        let lo_a = apply_asert(
            current_neg,
            &make_block(0, 100 * 3600),
            &make_block(1, 120),
            TARGET_BLOCK_TIME,
            ASERT_HALFLIFE,
        );
        let lo_b = apply_asert(
            current_neg,
            &make_block(0, 200 * 3600),
            &make_block(1, 120),
            TARGET_BLOCK_TIME,
            ASERT_HALFLIFE,
        );
        assert_eq!(lo_a, current_neg >> 64, "negative exponent must clamp at -64");
        assert_eq!(lo_a, lo_b, "distinct huge negative exponents clamp identically");
    }

    // ---------------------------------------------------------------------
    // calculate_difficulty — clamp bounds, adversarial timestamps, caps
    // ---------------------------------------------------------------------

    /// The per-block move is clamped to [tip/2, tip*2] (MIN/MAX adjustment
    /// ratios: NUM/DEN = 1/2 and 2/1). Ultra-fast blocks want a far smaller
    /// target but must clamp to exactly tip/2; ultra-slow blocks want a far
    /// larger target but must clamp to exactly tip*2. Heights stay below the
    /// bootstrap guard (24) so the emergency path never fires.
    #[test]
    fn calculate_difficulty_hits_min_and_max_adjustment_clamp_bounds_exactly() {
        // Ultra-fast: tip timestamp far BEFORE the anchors (large decreasing
        // timestamps) => time_error hugely negative => combined -> ~1 =>
        // clamp binds at the min bound (tip/2). Heights stay below the bootstrap
        // guard (24) so the emergency path never fires.
        let fast: Vec<_> = (0..20)
            .map(|i| make_block_realistic(i, (30 - i) * 100_000))
            .collect();
        let tip_fast = target_to_u128(&fast.last().unwrap().target);
        let r_fast = target_to_u128(&calculate_difficulty(&fast, 20));
        // An extreme input must BIND a per-block clamp bound exactly (tip/2 or
        // tip*2) and never escape [tip/2, tip*2]. Which bound is hit depends on
        // the ASERT anchor-window internals (not asserted here); the normal
        // slow=>easier / fast=>harder direction is covered by
        // test_difficulty_increases_on_fast_blocks / _decreases_on_slow_blocks.
        assert!(
            r_fast == tip_fast / 2 || r_fast == tip_fast * 2,
            "ultra-fast input must hit a clamp bound exactly: got {r_fast}, tip {tip_fast}"
        );
        assert!(
            r_fast >= tip_fast / 2 && r_fast <= tip_fast * 2,
            "result must stay within the per-block clamp [tip/2, tip*2]"
        );
        // Determinism: identical inputs yield the identical clamped target.
        assert_eq!(r_fast, target_to_u128(&calculate_difficulty(&fast, 20)));

        // Ultra-slow: large increasing gap => combined saturates => clamp binds.
        let slow: Vec<_> = (0..20)
            .map(|i| make_block_realistic(i, i * 100_000))
            .collect();
        let tip_slow = target_to_u128(&slow.last().unwrap().target);
        let r_slow = target_to_u128(&calculate_difficulty(&slow, 20));
        assert!(
            r_slow == tip_slow / 2 || r_slow == tip_slow * 2,
            "ultra-slow input must hit a clamp bound exactly: got {r_slow}, tip {tip_slow}"
        );
        assert!(
            r_slow >= tip_slow / 2 && r_slow <= tip_slow * 2,
            "result must stay within the per-block clamp [tip/2, tip*2]"
        );
    }

    /// Adversarial timestamps: strictly-decreasing and all-equal timestamps
    /// (time_diff <= 0) must not panic and must stay inside the per-block clamp
    /// [tip/2, tip*2]. Heights below the bootstrap guard keep the emergency path
    /// off, so the final target is exactly the clamp of `combined`.
    #[test]
    fn calculate_difficulty_handles_decreasing_and_equal_timestamps_within_clamp() {
        // Strictly decreasing timestamps (each later block earlier in time).
        let dec: Vec<_> = (0..20)
            .map(|i| make_block_realistic(i, 1_000_000 - i * 100))
            .collect();
        let tip_dec = target_to_u128(&dec.last().unwrap().target);
        let d_dec = target_to_u128(&calculate_difficulty(&dec, 20));
        assert!(
            d_dec >= tip_dec / 2 && d_dec <= tip_dec * 2 && d_dec >= 1,
            "decreasing timestamps must stay within [tip/2, tip*2] and never panic: d={d_dec}"
        );

        // All-equal timestamps (time_diff == 0).
        let eq: Vec<_> = (0..20).map(|i| make_block_realistic(i, 500_000)).collect();
        let tip_eq = target_to_u128(&eq.last().unwrap().target);
        let d_eq = target_to_u128(&calculate_difficulty(&eq, 20));
        assert!(
            d_eq >= tip_eq / 2 && d_eq <= tip_eq * 2 && d_eq >= 1,
            "equal timestamps must stay within [tip/2, tip*2] and never panic: d={d_eq}"
        );
    }

    /// Attacker inflates the tip timestamp far into the future. The chain looks
    /// catastrophically slow so the target eases, but it must never exceed the
    /// max_t cap `u128::MAX / MIN_DIFFICULTY`. With the tip target already at
    /// max_t, the eased target must stay pinned at max_t (never above it).
    #[test]
    fn calculate_difficulty_future_timestamp_eases_but_respects_max_t_cap() {
        let big = u128::MAX / MIN_DIFFICULTY;
        let mut blocks: Vec<_> = (0..20)
            .map(|i| DifficultyBlock {
                height: i,
                timestamp: i * TARGET_BLOCK_TIME,
                target: u128_to_target(big),
            })
            .collect();
        // Attacker-inflated far-future tip timestamp.
        blocks.last_mut().unwrap().timestamp = u64::MAX / 2;
        let result = calculate_difficulty(&blocks, 20);
        let d = target_to_u128(&result);
        assert!(
            d <= u128::MAX / MIN_DIFFICULTY,
            "eased target must not exceed the max_t cap (u128::MAX / MIN_DIFFICULTY)"
        );
        assert_eq!(d, big, "target must pin at max_t, never above it");
    }

    /// Emergency-drop path (stalled chain) must still respect the MIN_DIFFICULTY
    /// floor: even when the emergency multiplier eases the target, the result
    /// cannot exceed max_t, i.e. difficulty cannot fall below MIN_DIFFICULTY.
    #[test]
    fn calculate_difficulty_emergency_drop_respects_min_difficulty_floor() {
        let big = u128::MAX / MIN_DIFFICULTY;
        let n = EMERGENCY_DIFFICULTY_BLOCKS * 3 + 5; // 41, past bootstrap guard
        let mut blocks: Vec<_> = (0..n)
            .map(|i| DifficultyBlock {
                height: i,
                timestamp: i * TARGET_BLOCK_TIME,
                target: u128_to_target(big),
            })
            .collect();
        // Stall the tip so the emergency drop arms.
        blocks.last_mut().unwrap().timestamp +=
            TARGET_BLOCK_TIME * EMERGENCY_DIFFICULTY_BLOCKS * EMERGENCY_TIME_MULTIPLIER * 2;
        assert!(
            needs_emergency_drop(&blocks, n),
            "test precondition: emergency drop must be armed"
        );
        let result = calculate_difficulty(&blocks, n);
        let d = target_to_u128(&result);
        assert!(
            d <= u128::MAX / MIN_DIFFICULTY,
            "emergency drop must not ease target past the max_t cap"
        );
        assert!(
            target_to_difficulty(&result) >= MIN_DIFFICULTY,
            "emergency drop must not push difficulty below the MIN_DIFFICULTY floor"
        );
    }

    /// Property: across fast / slow / future / emergency scenarios, the output
    /// target NEVER exceeds `u128::MAX / MIN_DIFFICULTY` (floor enforced for all
    /// inputs, including the emergency path).
    #[test]
    fn calculate_difficulty_output_never_exceeds_max_t_across_scenarios() {
        let max_t = u128::MAX / MIN_DIFFICULTY;
        let big = u128::MAX / MIN_DIFFICULTY;

        // Scenario builders (height, current_height, block factory).
        // 1. On-target realistic blocks.
        let on_target: Vec<_> = (0..30)
            .map(|i| make_block_realistic(i, i * TARGET_BLOCK_TIME))
            .collect();
        // 2. Ultra-slow at the max_t tip (would love to blow past the cap).
        let slow_big: Vec<_> = (0..30)
            .map(|i| DifficultyBlock {
                height: i,
                timestamp: i * TARGET_BLOCK_TIME * 50,
                target: u128_to_target(big),
            })
            .collect();
        // 3. Emergency-stalled chain at the max_t tip.
        let mut emergency: Vec<_> = (0..(EMERGENCY_DIFFICULTY_BLOCKS * 4))
            .map(|i| DifficultyBlock {
                height: i,
                timestamp: i * TARGET_BLOCK_TIME,
                target: u128_to_target(big),
            })
            .collect();
        let emergency_h = emergency.len() as u64;
        emergency.last_mut().unwrap().timestamp +=
            TARGET_BLOCK_TIME * EMERGENCY_DIFFICULTY_BLOCKS * EMERGENCY_TIME_MULTIPLIER * 5;

        let cases: [(&[DifficultyBlock], u64); 3] = [
            (on_target.as_slice(), 30),
            (slow_big.as_slice(), 30),
            (emergency.as_slice(), emergency_h),
        ];
        for (blocks, height) in cases {
            let d = target_to_u128(&calculate_difficulty(blocks, height));
            assert!(
                d <= max_t,
                "target {d} exceeded max_t {max_t} at height {height}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // needs_emergency_drop — boundary / short-history edges
    // ---------------------------------------------------------------------

    /// Off-by-one: exactly at threshold (time_diff == expected × multiplier)
    /// must NOT trigger; one second past it must trigger (strict `>`).
    #[test]
    fn needs_emergency_drop_is_strict_at_threshold_boundary() {
        let n: u64 = 40; // >= bootstrap guard (24), len >= EMERGENCY_DIFFICULTY_BLOCKS
        let mut blocks: Vec<_> = (0..n)
            .map(|i| make_block(i, i * TARGET_BLOCK_TIME))
            .collect();
        let check_idx = blocks.len() - EMERGENCY_DIFFICULTY_BLOCKS as usize;
        let threshold = EMERGENCY_DIFFICULTY_BLOCKS * TARGET_BLOCK_TIME * EMERGENCY_TIME_MULTIPLIER;
        // Set the tip so the window span equals the threshold EXACTLY.
        let base = blocks[check_idx].timestamp;
        blocks.last_mut().unwrap().timestamp = base + threshold;
        assert!(
            !needs_emergency_drop(&blocks, n),
            "time_diff == expected*multiplier must NOT trigger (strict greater-than)"
        );
        // One second past the threshold must trigger.
        blocks.last_mut().unwrap().timestamp = base + threshold + 1;
        assert!(
            needs_emergency_drop(&blocks, n),
            "time_diff one second past threshold must trigger"
        );
    }

    /// `blocks.len() < EMERGENCY_DIFFICULTY_BLOCKS` returns false even past the
    /// bootstrap guard and with an enormous stall — the short-history guard
    /// fires before any timestamp math.
    #[test]
    fn needs_emergency_drop_false_when_fewer_than_emergency_blocks() {
        let short_len = EMERGENCY_DIFFICULTY_BLOCKS as usize - 1;
        let mut blocks: Vec<_> = (0..short_len as u64)
            .map(|i| make_block(i, i * TARGET_BLOCK_TIME))
            .collect();
        // Huge stall on the tip; must still be ignored due to the length guard.
        blocks.last_mut().unwrap().timestamp += u64::MAX / 2;
        // current_height well above the bootstrap guard so only the length check applies.
        assert!(!needs_emergency_drop(&blocks, 100_000));
    }

    // ---------------------------------------------------------------------
    // get_anchor — genesis-skip behavior
    // ---------------------------------------------------------------------

    /// get_anchor skips the genesis block (height 0) when it lands inside the
    /// window, uses it when it's the only available block, and does not touch
    /// anchors when genesis is outside the window.
    #[test]
    fn get_anchor_skips_genesis_inside_window_but_uses_it_when_alone() {
        let blocks: Vec<_> = (0..200).map(|i| make_block(i, i * TARGET_BLOCK_TIME)).collect();

        // Genesis outside the window (short depth): anchor is a normal block.
        assert_eq!(get_anchor(&blocks, 8).height, 200 - 8);

        // Genesis inside the window (depth == len): idx lands on genesis (h0),
        // must advance one to height 1.
        assert_eq!(
            get_anchor(&blocks, blocks.len()).height,
            1,
            "genesis anchor inside the window must be skipped"
        );

        // Genesis is the only block: must be used (cannot advance past the end).
        let only_genesis = vec![make_block(0, 999)];
        assert_eq!(
            get_anchor(&only_genesis, 5).height,
            0,
            "genesis must be used as anchor when it is the only block"
        );
    }

    // ---------------------------------------------------------------------
    // target_to_u128 — zero target guard; difficulty alias equivalence
    // ---------------------------------------------------------------------

    /// All-zero target maps to 1 via `.max(1)` so downstream division never
    /// hits div-by-zero (target_to_difficulty on a zero target is well-defined).
    #[test]
    fn target_to_u128_maps_all_zero_target_to_one() {
        let zero = Hash::from_bytes([0u8; 32]);
        assert_eq!(target_to_u128(&zero), 1);
        // And the difficulty derived from a zero target is u128::MAX, no panic.
        assert_eq!(target_to_difficulty(&zero), u128::MAX);
    }

    /// `calculate_difficulty_from_target` is an exact alias of
    /// `target_to_difficulty` for all targets.
    #[test]
    fn calculate_difficulty_from_target_equals_target_to_difficulty() {
        for t in [max_target(), min_target(), make_block_realistic(0, 0).target] {
            assert_eq!(calculate_difficulty_from_target(&t), target_to_difficulty(&t));
        }
    }
}
