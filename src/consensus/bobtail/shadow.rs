//! Shadow difficulty from the share-informed hashrate (Observe-only, gated).
//!
//! The dense share stream ([`super::hashrate`]) yields a hashrate estimate with
//! ~`C_SHARE·K` (≈60×) the samples of block intervals. This module turns that
//! estimate into a **shadow difficulty** and compares it, side by side, with the
//! live block-based (ASERT) difficulty — so the Observe phase can show that a
//! share-informed retarget would track real hashrate with far less lag and noise,
//! BEFORE any change to the hash-locked `difficulty.rs`. Pure measurement; the
//! actual retarget change is the gated, post-audit step.

use crate::consensus::work_from_target;
use crate::constants::TARGET_BLOCK_TIME;
use crate::primitives::Hash;

/// Difficulty implied by a hashrate: the expected hashes per block,
/// `hashrate · TARGET_BLOCK_TIME` (floored at 1).
pub fn shadow_difficulty(hashrate: f64) -> f64 {
    (hashrate * TARGET_BLOCK_TIME as f64).max(1.0)
}

/// The target a share-informed retarget would set for `hashrate`
/// (`max_target / shadow_difficulty`), clamped to the u64 difficulty domain.
pub fn shadow_target(hashrate: f64) -> Hash {
    let d = shadow_difficulty(hashrate).min(u64::MAX as f64) as u64;
    Hash::from_difficulty(d)
}

/// Side-by-side of the live block-based (ASERT) difficulty and the
/// share-informed shadow difficulty, for Observe comparison.
#[derive(Clone, Debug)]
pub struct DifficultyShadow {
    /// Difficulty of the live ASERT target (`work(asert_target)`).
    pub block_difficulty: u128,
    /// Difficulty implied by the share-hashrate estimate.
    pub share_difficulty: f64,
    /// Shares in the hashrate window — the sampling-density advantage.
    pub share_samples: usize,
}

impl DifficultyShadow {
    pub fn new(asert_target: &Hash, share_hashrate: f64, share_samples: usize) -> Self {
        Self {
            block_difficulty: work_from_target(asert_target),
            share_difficulty: shadow_difficulty(share_hashrate),
            share_samples,
        }
    }

    /// share/block difficulty ratio (≈1 at agreement; the share estimate reacts
    /// faster, so it leads the ASERT difficulty when hashrate shifts).
    pub fn ratio(&self) -> f64 {
        if self.block_difficulty == 0 {
            return 0.0;
        }
        self.share_difficulty / self.block_difficulty as f64
    }

    /// Fraction of the block-based estimator's std the share-based one achieves,
    /// given `block_samples` blocks in the same window (std ∝ 1/√N). Smaller is
    /// smoother; `1 / noise_fraction` is the "× tighter" factor.
    pub fn noise_fraction(&self, block_samples: u64) -> f64 {
        super::hashrate::std_ratio_vs_blocks(self.share_samples as u64, block_samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_is_hashrate_times_block_time() {
        assert_eq!(shadow_difficulty(1000.0), 1000.0 * TARGET_BLOCK_TIME as f64);
        assert_eq!(shadow_difficulty(0.0), 1.0, "floored at 1");
    }

    #[test]
    fn shadow_target_inverts_difficulty() {
        // A higher hashrate ⇒ higher difficulty ⇒ a smaller (harder) target.
        let t_lo = shadow_target(100.0);
        let t_hi = shadow_target(10_000.0);
        assert!(t_hi < t_lo, "more hashrate ⇒ harder target");
    }

    #[test]
    fn ratio_is_one_at_agreement_and_tracks_divergence() {
        let target = Hash::from_difficulty(1_000);
        let block_diff = work_from_target(&target) as f64;
        // Pick the hashrate whose shadow difficulty equals the block difficulty.
        let hr = block_diff / TARGET_BLOCK_TIME as f64;
        let s = DifficultyShadow::new(&target, hr, 60);
        assert!((s.ratio() - 1.0).abs() < 1e-6, "agree ⇒ ratio ≈ 1");
        // Double the hashrate ⇒ the share difficulty leads ~2×.
        let s2 = DifficultyShadow::new(&target, hr * 2.0, 60);
        assert!((s2.ratio() - 2.0).abs() < 1e-6);
    }

    #[test]
    fn noise_fraction_reflects_density() {
        let s = DifficultyShadow::new(&Hash::from_difficulty(1000), 100.0, 60);
        // 60 share samples vs 1 block sample ⇒ √60 ≈ 7.7× tighter.
        assert!((1.0 / s.noise_fraction(1) - 60f64.sqrt()).abs() < 1e-6);
    }
}
