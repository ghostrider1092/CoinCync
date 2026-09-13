//! # Wallet-side fee estimation
//!
//! Estimates transaction size and fee so the wallet charges exactly what the
//! block validator will require. Divergence here rejects otherwise-honest txs.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `estimate_tx_size`** — INVARIANT: size is a deterministic, conservative
//!   (`×2` margin) function of input/output/ring counts, monotonic in each.
//!   THREAT: under-estimate → fee too low → validator rejects the tx.
//!   TESTS: `estimate_tx_size_is_within_expected_range`,
//!   `scaled_fee_is_monotonic_in_input_output_and_ring_counts`.
//! - **§2 `scaled_fee`** — INVARIANT: `fee == size·MIN_FEE_PER_BYTE·mult/100` with
//!   saturating integer math (no overflow, no f64 drift) and monotone in size.
//!   THREAT: wallet estimate vs validator divergence → honest txs rejected.
//!   TESTS: `scaled_fee_is_monotonic_in_input_output_and_ring_counts`.
//! - **§3 `FeeMultiplier::from_f64`** — INVARIANT: multiplier is clamped to
//!   `[1.0, 100.0]`; NaN and negatives collapse to the neutral 1.0 floor.
//!   THREAT: NaN/negative multiplier panics or produces a zero/absurd fee.
//!   TESTS: `fee_multiplier_nan_falls_back_to_neutral_one`,
//!   `fee_multiplier_negative_zero_and_huge_are_clamped`.
//! - **§4 `calculate_fee`** — INVARIANT: unscaled fee at a height is
//!   `size·MIN_FEE_PER_BYTE` and always strictly positive for a real tx.
//!   THREAT: zero fee → tx rejected as underpaying. TESTS: `calculate_fee_is_non_zero`.
//! - **§5 `estimate_fee_with_multiplier`** — INVARIANT: ring size is bound to
//!   `ring_size_at_height`, so the estimate matches what the validator charges.
//!   THREAT: stale/wrong ring size → fee mismatch → rejection.
//!   TESTS: `fee_multiplier_nan_falls_back_to_neutral_one`,
//!   `fee_multiplier_negative_zero_and_huge_are_clamped`.

use crate::constants::{ring_size_at_height, MIN_FEE_PER_BYTE};
use crate::primitives::Amount;

const FEE_MULTIPLIER_SCALE: u64 = 100;
const MAX_FEE_MULTIPLIER_HUNDREDTHS: u64 = 10_000;
const MIN_FEE_MULTIPLIER: f64 = 1.0;

const TX_BASE_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const BORSH_VEC_PREFIX_BYTES: usize = 4;
const RING_MEMBER_BYTES: usize = 64;
const ENCRYPTED_AMOUNT_ESTIMATE_BYTES: usize = 12;
const VIEW_TAG_BYTES: usize = 1;
const OPTIONAL_LOCK_HEIGHT_BYTES: usize = 9;
const RANGE_PROOF_BASE_BYTES: usize = 672;
const RANGE_PROOF_PER_OUTPUT_BYTES: usize = 64;
const CONSERVATIVE_SIZE_MARGIN: usize = 2;

#[derive(Clone, Copy)]
pub(super) struct FeeMultiplier(u64);

impl FeeMultiplier {
    pub(super) fn from_f64(value: f64) -> Self {
        let value = if value.is_nan() {
            MIN_FEE_MULTIPLIER
        } else {
            value
        };
        let hundredths = (value.max(MIN_FEE_MULTIPLIER) * FEE_MULTIPLIER_SCALE as f64)
            .min(MAX_FEE_MULTIPLIER_HUNDREDTHS as f64) as u64;
        Self(hundredths)
    }
}

pub(super) fn scaled_fee(
    input_count: usize,
    output_count: usize,
    ring_size: usize,
    multiplier: FeeMultiplier,
) -> Amount {
    Amount::from_atomic(
        (estimate_tx_size(input_count, output_count, ring_size) as u64)
            .saturating_mul(MIN_FEE_PER_BYTE)
            .saturating_mul(multiplier.0)
            / FEE_MULTIPLIER_SCALE,
    )
}

/// Estimate transaction size in bytes.
pub fn estimate_tx_size(input_count: usize, output_count: usize, ring_size: usize) -> usize {
    let input_size = KEY_BYTES
        + BORSH_VEC_PREFIX_BYTES
        + RING_MEMBER_BYTES * ring_size
        + KEY_BYTES
        + KEY_BYTES
        + KEY_BYTES
        + BORSH_VEC_PREFIX_BYTES
        + KEY_BYTES * ring_size
        + KEY_BYTES
        + KEY_BYTES;
    let output_size = KEY_BYTES
        + KEY_BYTES
        + KEY_BYTES
        + ENCRYPTED_AMOUNT_ESTIMATE_BYTES
        + VIEW_TAG_BYTES
        + OPTIONAL_LOCK_HEIGHT_BYTES;
    let range_proof = RANGE_PROOF_BASE_BYTES + RANGE_PROOF_PER_OUTPUT_BYTES * output_count;

    (TX_BASE_BYTES + input_count * input_size + output_count * output_size + range_proof)
        * CONSERVATIVE_SIZE_MARGIN
}

#[allow(dead_code)]
pub fn calculate_fee(input_count: usize, output_count: usize, current_height: u64) -> Amount {
    let ring_size = ring_size_at_height(current_height);
    let size = estimate_tx_size(input_count, output_count, ring_size);
    Amount::from_atomic(size as u64 * MIN_FEE_PER_BYTE)
}

pub fn estimate_fee_with_multiplier(
    input_count: usize,
    output_count: usize,
    current_height: u64,
    fee_multiplier: f64,
) -> Amount {
    let ring_size = ring_size_at_height(current_height);
    scaled_fee(
        input_count,
        output_count,
        ring_size,
        FeeMultiplier::from_f64(fee_multiplier),
    )
}
