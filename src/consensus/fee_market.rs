//! # Fee Calculation for CoinCync 1.0
//!
//! Simple, direct fee calculation - no unnecessary abstraction.
//! Fees are based on transaction size and network congestion.

use crate::primitives::Amount;
// L-1 FIX: Removed dead imports FEE_PROTOCOL_*_PERCENT (protocol fee is always 0).
use crate::constants::{
    CONGESTION_THRESHOLD, FEE_BURN_CONGESTED_PERCENT, FEE_BURN_NORMAL_PERCENT,
    FEE_MINER_CONGESTED_PERCENT, FEE_MINER_NORMAL_PERCENT, MAX_BLOCK_SIZE, MIN_FEE_PER_BYTE,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

// =============================================================================
// CORE FEE CALCULATION
// =============================================================================

/// Calculate fee for a transaction.
///
/// `congestion_pct` is block fullness as an integer percentage (0–100),
/// matching the integer arithmetic used by the block validator:
/// `congestion_pct = (block_size * 100) / MAX_BLOCK_SIZE`. Using the same
/// integer thresholds eliminates the f64 boundary mismatch that caused
/// wallet-estimated fees to occasionally be rejected.
pub fn calculate_fee(tx_size: usize, congestion_pct: u64) -> Amount {
    let multiplier = congestion_multiplier(congestion_pct);
    // Use saturating arithmetic to prevent overflow.
    let base_fee = (tx_size as u64).saturating_mul(MIN_FEE_PER_BYTE);
    let fee = base_fee.saturating_mul(multiplier) / 100;
    Amount::from_atomic(fee)
}

/// Calculate fee with priority boost.
#[allow(dead_code)]
pub fn calculate_priority_fee(tx_size: usize, congestion_pct: u64, priority: f64) -> Amount {
    let base = calculate_fee(tx_size, congestion_pct);
    // SECURITY (A5-FEE-01): Clamp priority and use saturating arithmetic to prevent
    // overflow when priority is very large (e.g. f64::MAX).
    let clamped_priority = priority.clamp(0.0, 100.0);
    let multiplier = ((clamped_priority * 100.0).min(10000.0)) as u64;
    let boost = base.as_atomic().saturating_mul(multiplier) / 100;
    Amount::from_atomic(base.as_atomic().saturating_add(boost))
}

/// Get congestion multiplier as an integer scaled by 100 (100 = ×1.0, 300 = ×3.0).
///
/// Thresholds match the block validator's integer congestion check exactly:
/// `congestion_pct = (block_size * 100) / MAX_BLOCK_SIZE`. Using f64 thresholds
/// here previously caused boundary divergence between wallet estimates and
/// validator decisions.
pub fn congestion_multiplier(congestion_pct: u64) -> u64 {
    if congestion_pct < 50 {
        100 // ×1.0 — normal
    } else if congestion_pct < 75 {
        150 // ×1.5 — moderate
    } else if congestion_pct < 90 {
        200 // ×2.0 — high
    } else {
        300 // ×3.0 — severe
    }
}

/// Calculate congestion level as integer percentage (0–100) from recent block sizes.
///
/// SECURITY (A7-CONG-01): Uses u64 saturating fold instead of `.sum::<usize>()`.
/// On 32-bit targets `usize` is 32 bits — a few hundred blocks of ~2 MB each
/// would overflow, producing a near-zero average and hiding real congestion.
/// u64 saturating fold is correct on all platforms.
#[allow(dead_code)]
pub fn calculate_congestion(recent_block_sizes: &[usize]) -> u64 {
    if recent_block_sizes.is_empty() {
        return 0;
    }
    let total: u64 = recent_block_sizes
        .iter()
        .fold(0u64, |acc, &s| acc.saturating_add(s as u64));
    let avg = total / recent_block_sizes.len() as u64;
    ((avg * 100) / MAX_BLOCK_SIZE as u64).min(100)
}

/// Check if network is congested (congestion_pct is integer 0–100).
pub fn is_congested(congestion_pct: u64) -> bool {
    congestion_pct >= CONGESTION_THRESHOLD
}

// =============================================================================
// FEE DISTRIBUTION
// =============================================================================

/// How fees are split between miner, burn, and protocol
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct FeeDistribution {
    pub total: Amount,
    pub to_miner: Amount,
    pub burned: Amount,
    pub to_protocol: Amount,
}

/// Calculate fee distribution
///
/// SECURITY (A8-DIST-01): `to_protocol` is computed as the exact remainder
/// `fee - to_miner - burned` instead of `fee * protocol_pct / 100`.
/// Independent truncation of all three buckets can lose up to 2 atomic units
/// due to integer division. Computing the last bucket as the remainder
/// guarantees `to_miner + burned + to_protocol == total` with zero rounding loss.
pub fn distribute_fee(total: Amount, congested: bool) -> FeeDistribution {
    // Phase A7-2 (audit fix): u64 multiplication overflows when fee approaches
    // u64::MAX/60 ≈ 3.07×10^17 atomic units (~307,000 CYNC). A malicious miner
    // could craft a block with `total_fees` near that boundary, triggering an
    // arithmetic overflow panic in release builds. Use u128 intermediate so
    // even fee == u64::MAX × 60 ≤ 2^70 fits comfortably.
    //
    // The result fits in u64 because `fee * pct / 100 ≤ fee` for pct ≤ 100.
    // We assert that explicitly via .min(fee) to make the invariant readable.
    let fee = total.as_atomic();
    let fee_u128 = fee as u128;

    let (miner_pct, _burn_pct) = if congested {
        (FEE_MINER_CONGESTED_PERCENT, FEE_BURN_CONGESTED_PERCENT)
    } else {
        (FEE_MINER_NORMAL_PERCENT, FEE_BURN_NORMAL_PERCENT)
    };

    // The 2026-07-01 audit noted the comment above promised `.min(fee)`
    // as a defense-in-depth clamp but the code didn't apply it — a
    // silent doc/code drift. Restored here: if a future constant edit
    // ever bumps FEE_MINER_*_PERCENT above 100 (there's a compile-time
    // assert on the burn side but not the miner side), the clamp
    // prevents the u128→u64 truncation from wrapping into a nonsense
    // value silently.
    let to_miner = ((fee_u128 * miner_pct as u128 / 100) as u64).min(fee);
    // Remainder goes to burn — guarantees exact sum with zero rounding loss.
    // No protocol fee (Constitution Article II: 0% dev tax).
    let burned = fee - to_miner;
    let to_protocol = 0u64;

    FeeDistribution {
        total,
        to_miner: Amount::from_atomic(to_miner),
        burned: Amount::from_atomic(burned),
        to_protocol: Amount::from_atomic(to_protocol),
    }
}

impl FeeDistribution {
    /// Verify distribution adds up correctly.
    ///
    /// SECURITY (A6-FEE-VALID): Tolerance is exactly 0.  Because `distribute_fee`
    /// computes `to_protocol` as the remainder, the sum is always exact.  The old
    /// tolerance of 3 masked bugs where all three buckets were truncated
    /// independently.  u128 arithmetic prevents wrapping overflow in release mode.
    pub fn is_valid(&self) -> bool {
        let sum = self.to_miner.as_atomic() as u128
            + self.burned.as_atomic() as u128
            + self.to_protocol.as_atomic() as u128;
        let total = self.total.as_atomic() as u128;
        sum == total
    }
}

// =============================================================================
// BLOCK FEE STATS (for auditing)
// =============================================================================

/// Summary of fees in a block
#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockFeeStats {
    pub height: u64,
    pub tx_count: usize,
    pub total_fees: Amount,
    pub total_burned: Amount,
    pub avg_fee_per_byte: u64,
    pub was_congested: bool,
}

/// Calculate block fee statistics
///
/// SECURITY (A9-STATS-01): Uses u64 saturating fold for both `total` and
/// `total_size` instead of `.sum()`.  This prevents overflow on 32-bit targets
/// (usize) and avoids wrapping on extreme fee values (u64).
#[allow(dead_code)]
pub fn block_fee_stats(
    height: u64,
    tx_fees: &[(Amount, usize)], // (fee, size)
    congested: bool,
) -> BlockFeeStats {
    if tx_fees.is_empty() {
        return BlockFeeStats {
            height,
            ..Default::default()
        };
    }

    let total: u64 = tx_fees
        .iter()
        .fold(0u64, |acc, (f, _)| acc.saturating_add(f.as_atomic()));
    let total_size: u64 = tx_fees
        .iter()
        .fold(0u64, |acc, (_, s)| acc.saturating_add(*s as u64));

    let burn_pct = if congested {
        FEE_BURN_CONGESTED_PERCENT
    } else {
        FEE_BURN_NORMAL_PERCENT
    };

    // Phase A7-2 (audit fix): same u128 promotion as distribute_fee. The
    // saturating_add for `total` above means total can be u64::MAX, and
    // `u64::MAX * 40` overflows in release mode causing a panic. With u128
    // intermediates, the multiplication is bounded by 2^70 << u128::MAX.
    let total_burned = ((total as u128) * (burn_pct as u128) / 100) as u64;

    BlockFeeStats {
        height,
        tx_count: tx_fees.len(),
        total_fees: Amount::from_atomic(total),
        total_burned: Amount::from_atomic(total_burned),
        avg_fee_per_byte: if total_size > 0 {
            total / total_size
        } else {
            0
        },
        was_congested: congested,
    }
}

// =============================================================================
// RE-EXPORTS FOR BACKWARDS COMPATIBILITY
// =============================================================================

// Alias kept for backwards compatibility. Note: this is a plain data struct,
// not a cryptographic proof. The name "AuditProof" was misleading — it has
// no zero-knowledge or binding property. Use FeeDistribution directly in new code.
pub use FeeDistribution as FeeDistributionSnapshot;

/// Fee tier (simple enum, no complex logic)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeTier {
    Economy,
    Standard,
    Priority,
}

impl FeeTier {
    pub fn multiplier(&self) -> f64 {
        match self {
            FeeTier::Economy => 1.0,
            FeeTier::Standard => 1.5,
            FeeTier::Priority => 2.5,
        }
    }
}

/// Simple fee context.
/// `congestion_pct` is integer block fullness (0–100), matching the validator.
#[derive(Clone, Debug, Default)]
pub struct FeeContext {
    pub congestion_pct: u64,
}

/// Simple fee estimate
#[derive(Clone, Debug)]
pub struct FeeEstimate {
    pub fee: Amount,
    pub tier: FeeTier,
}

/// Wallet-side fee estimation helper.
///
/// Wraps the module-level functions with a cached congestion value so callers
/// don't have to thread the congestion parameter through every call.
/// `congestion_pct` is integer block fullness (0–100).
pub struct FeeCalculator {
    pub congestion_pct: u64,
}

impl FeeCalculator {
    pub fn new(context: FeeContext) -> Self {
        FeeCalculator {
            congestion_pct: context.congestion_pct,
        }
    }

    pub fn estimate(&self, tx_size: usize, tier: FeeTier) -> FeeEstimate {
        let base = calculate_fee(tx_size, self.congestion_pct);
        let fee_f64 = base.as_atomic() as f64 * tier.multiplier();
        let fee_u64 = if fee_f64.is_finite() && fee_f64 >= 0.0 {
            (fee_f64.min(u64::MAX as f64)) as u64
        } else {
            base.as_atomic() // fallback to unscaled base fee
        };
        let fee = Amount::from_atomic(fee_u64);
        FeeEstimate { fee, tier }
    }

    pub fn distribute(&self, total: Amount) -> FeeDistribution {
        distribute_fee(total, is_congested(self.congestion_pct))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_fee() {
        // At 0% congestion, multiplier = 100 → fee = size * MIN_FEE_PER_BYTE * 100 / 100
        let fee = calculate_fee(1000, 0);
        assert_eq!(fee.as_atomic(), 1000 * MIN_FEE_PER_BYTE);
    }

    #[test]
    fn test_congestion_multiplier() {
        assert_eq!(congestion_multiplier(0), 100); // ×1.0
        assert_eq!(congestion_multiplier(49), 100); // still ×1.0 (below 50)
        assert_eq!(congestion_multiplier(50), 150); // ×1.5
        assert_eq!(congestion_multiplier(74), 150); // still ×1.5
        assert_eq!(congestion_multiplier(75), 200); // ×2.0
        assert_eq!(congestion_multiplier(89), 200); // still ×2.0
        assert_eq!(congestion_multiplier(90), 300); // ×3.0 (congested)
        assert_eq!(congestion_multiplier(100), 300); // ×3.0
    }

    #[test]
    fn test_fee_distribution() {
        let dist = distribute_fee(Amount::from_atomic(1_000_000), false);
        assert!(dist.is_valid());
        assert!(dist.to_miner > dist.burned);
    }

    #[test]
    fn test_zero_size_block_fee() {
        // A zero-size transaction should produce zero fee
        let fee = calculate_fee(0, 0);
        assert_eq!(fee.as_atomic(), 0);
        // Even under severe congestion, zero size = zero fee
        let fee_congested = calculate_fee(0, 95);
        assert_eq!(fee_congested.as_atomic(), 0);
    }

    /// `calculate_fee` uses chained `saturating_mul`. Verify the saturating
    /// path is reachable AND saturates cleanly (no panic, no negative,
    /// no wrap) at extreme inputs. Order matters: `base_fee = tx_size *
    /// MIN_FEE_PER_BYTE` saturates first, then `base_fee * multiplier`
    /// saturates again, then `/100` divides the saturated value. The
    /// final result is bounded at `u64::MAX / 100`.
    #[test]
    fn test_calculate_fee_saturating_extremes() {
        // tx_size at usize::MAX (the worst input we can construct).
        // Even multiplied by MIN_FEE_PER_BYTE and the max ×3 multiplier,
        // the chained saturating ops must not panic and must return a
        // value ≤ u64::MAX/100.
        let fee = calculate_fee(usize::MAX, 100);
        assert!(fee.as_atomic() <= u64::MAX / 100);
        // Single-byte tx at zero congestion: exact MIN_FEE_PER_BYTE
        // (the ×100/100 round-trip cancels).
        assert_eq!(calculate_fee(1, 0).as_atomic(), MIN_FEE_PER_BYTE);
        // congestion_pct ≥100 (above table top) collapses to the ×3 bucket
        // — confirm no out-of-table panic.
        let _ = calculate_fee(1000, 200);
        let _ = calculate_fee(1000, u64::MAX);
    }

    /// Verify that distribute_fee produces an exact sum for every edge case.
    /// Because to_protocol is computed as the remainder, the sum must be exact
    /// (tolerance 0) regardless of rounding in the miner/burn buckets.
    #[test]
    fn distribution_sum_exact() {
        // Edge cases: 0, 1, 2, 3, small primes, large values, u64::MAX-ish
        let test_values: Vec<u64> = vec![
            0,
            1,
            2,
            3,
            7,
            99,
            100,
            101,
            999,
            1_000_000,
            1_000_000_001,
            u64::MAX / 100,
            u64::MAX / 2,
        ];

        for &val in &test_values {
            for congested in [false, true] {
                let dist = distribute_fee(Amount::from_atomic(val), congested);
                assert!(
                    dist.is_valid(),
                    "distribution_sum_exact failed for val={}, congested={}",
                    val,
                    congested
                );
                // Also verify the raw arithmetic matches exactly
                let sum = dist.to_miner.as_atomic()
                    + dist.burned.as_atomic()
                    + dist.to_protocol.as_atomic();
                assert_eq!(
                    sum, val,
                    "raw sum mismatch for val={}, congested={}",
                    val, congested
                );
            }
        }
    }

    /// Verify that calculate_congestion doesn't overflow on 32-bit targets.
    /// With 1000 blocks of MAX_BLOCK_SIZE each, the total exceeds u32::MAX.
    #[test]
    fn congestion_no_overflow() {
        let sizes: Vec<usize> = vec![MAX_BLOCK_SIZE; 1000];
        let congestion_pct = calculate_congestion(&sizes);
        // avg == MAX_BLOCK_SIZE, so congestion should be exactly 100%
        assert_eq!(congestion_pct, 100);
    }

    /// Verify that block_fee_stats doesn't overflow when summing many large fees.
    #[test]
    fn block_fee_stats_no_overflow() {
        // 5000 txs each with a near-max fee and large size
        let big_fee = Amount::from_atomic(u64::MAX / 10_000);
        let big_size = MAX_BLOCK_SIZE;
        let tx_fees: Vec<(Amount, usize)> = vec![(big_fee, big_size); 5000];

        let stats = block_fee_stats(42, &tx_fees, false);
        // Should not panic from overflow; total_fees is capped by saturating add
        assert_eq!(stats.tx_count, 5000);
        assert_eq!(stats.height, 42);
        assert!(stats.total_fees.as_atomic() > 0);
    }
}
