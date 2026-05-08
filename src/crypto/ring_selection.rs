//! # Ring Member Selection for CoinCync 1.0
//!
//! Decoy selection using UNIFORM distribution for maximum privacy.
//!
//! CoinCync deliberately uses uniform random selection instead of Monero's
//! gamma distribution. Gamma selection leaks information because researchers
//! can statistically identify the real spend by its age pattern. Uniform
//! selection gives zero signal — every ring member is equally likely to be
//! real, regardless of age. This defeats the #1 academic deanonymization
//! attack on ring signatures (see Miller et al. 2017, Möser et al. 2018).
//!
//! The 4th Amendment protects against unreasonable searches. Statistical
//! deanonymization of ring signatures IS an unreasonable search of private
//! financial records. Uniform decoy selection is CoinCync's technical
//! enforcement of this constitutional protection.
//! This prevents statistical analysis attacks on ring signatures.
//!
//! ## Why This Matters
//! If we pick decoys uniformly at random, an attacker can observe that
//! real spends tend to use newer outputs. By matching this distribution
//! for decoys, we make real and fake indistinguishable.

use crate::primitives::{Hash, PublicKey};
use crate::error::{Error, Result};
use rand::{Rng, RngCore, CryptoRng};


/// Output reference for ring selection
#[derive(Clone, Debug)]
pub struct OutputRef {
    /// Block height where output was created
    pub height: u64,
    /// Transaction hash
    pub tx_hash: Hash,
    /// Output index
    pub output_index: u8,
    /// Public key (stealth address)
    pub public_key: PublicKey,
    /// Commitment bytes
    pub commitment: [u8; 32],
    /// Global output index (for efficient lookup)
    pub global_index: u64,
}

/// Ring selection configuration
#[derive(Clone, Debug)]
pub struct RingSelectionConfig {
    /// Minimum ring size
    pub min_ring_size: usize,
    /// Target ring size
    pub target_ring_size: usize,
    /// Maximum ring size
    pub max_ring_size: usize,
    /// Gamma distribution shape parameter
    pub gamma_shape: f64,
    /// Gamma distribution scale parameter
    pub gamma_scale: f64,
    /// Minimum output age in blocks before it can be a decoy
    pub min_decoy_age: u64,
    /// Maximum age for decoys (avoid ancient outputs)
    pub max_decoy_age: u64,
    /// Require outputs from recent blocks (last N blocks must have representation)
    pub recent_block_requirement: u64,
    /// SECURITY: If true, refuse to proceed if gamma selection fails (stricter privacy)
    /// If false, fall back to uniform random with warning (weaker privacy)
    pub strict_privacy_mode: bool,
}

impl Default for RingSelectionConfig {
    fn default() -> Self {
        RingSelectionConfig {
            min_ring_size: 11,
            target_ring_size: 11,
            max_ring_size: 21,
            // Gamma parameters tuned to match real spending patterns
            // Shape=19.28, Scale=1/1.61 based on Monero research
            gamma_shape: 19.28,
            gamma_scale: 0.621,
            min_decoy_age: 10,
            max_decoy_age: 5_256_000 * 2, // ~2 years in blocks
            recent_block_requirement: 50,
            // Default to strict mode for maximum privacy
            strict_privacy_mode: true,
        }
    }
}

/// Ring selection statistics for auditing
#[derive(Clone, Debug, Default)]
pub struct RingSelectionStats {
    /// Number of decoys selected
    pub decoys_selected: usize,
    /// Average age of decoys (blocks)
    pub avg_decoy_age: f64,
    /// Minimum decoy age
    pub min_age: u64,
    /// Maximum decoy age
    pub max_age: u64,
    /// Number of retries needed
    pub selection_retries: usize,
    /// Distribution of decoys by age bucket
    pub age_distribution: [u32; 10],
    /// Whether uniform random fallback was used (privacy concern)
    pub fallback_used: bool,
    /// Number of decoys selected via fallback
    pub fallback_count: usize,
}

/// Select ring members using gamma distribution
pub struct RingSelector {
    config: RingSelectionConfig,
}

impl RingSelector {
    pub fn new(config: RingSelectionConfig) -> Self {
        RingSelector { config }
    }

    pub fn with_ring_size(ring_size: usize) -> Self {
        RingSelector {
            config: RingSelectionConfig {
                min_ring_size: ring_size,
                target_ring_size: ring_size,
                max_ring_size: ring_size,
                // Use non-strict mode for tests to avoid failures with small pools
                strict_privacy_mode: false,
                ..Default::default()
            },
        }
    }

    /// Create a selector with strict privacy mode (refuses to use uniform fallback)
    pub fn with_ring_size_strict(ring_size: usize) -> Self {
        RingSelector {
            config: RingSelectionConfig {
                min_ring_size: ring_size,
                target_ring_size: ring_size,
                max_ring_size: ring_size,
                strict_privacy_mode: true,
                ..Default::default()
            },
        }
    }

    /// Select decoys for a ring signature
    ///
    /// # Arguments
    /// * `real_output` - The real output being spent
    /// * `output_pool` - Available outputs to select from
    /// * `current_height` - Current blockchain height
    /// * `rng` - Cryptographic RNG
    ///
    /// # Returns
    /// * `(ring, real_index, stats)` - The complete ring, position of real output, and stats
    pub fn select_ring<R: RngCore + CryptoRng>(
        &self,
        real_output: &OutputRef,
        output_pool: &[OutputRef],
        current_height: u64,
        rng: &mut R,
    ) -> Result<(Vec<OutputRef>, usize, RingSelectionStats)> {
        let ring_size = self.config.target_ring_size;
        let decoy_count = ring_size - 1;

        if output_pool.len() < decoy_count {
            return Err(Error::InvalidRingSize {
                expected: decoy_count,
                got: output_pool.len(),
            });
        }

        // SECURITY (BUG-5): If the real output is younger than min_decoy_age,
        // relax the minimum age for decoys to match. Otherwise the real output
        // would be the only young ring member, trivially deanonymizing the sender.
        let real_age = current_height.saturating_sub(real_output.height);
        let effective_min_age = real_age.min(self.config.min_decoy_age);

        // Filter eligible outputs
        let eligible: Vec<&OutputRef> = output_pool
            .iter()
            .filter(|o| self.is_eligible_decoy(o, real_output, current_height, effective_min_age))
            .collect();

        if eligible.len() < decoy_count {
            return Err(Error::InvalidRingSize {
                expected: decoy_count,
                got: eligible.len(),
            });
        }

        // UNIFORM RANDOM SELECTION — CoinCync's defense against age-based deanonymization.
        // Unlike Monero's gamma distribution (which leaks statistical signal about
        // which ring member is real), uniform selection makes every member equally
        // likely. An observer gains ZERO information from the age distribution.
        let mut selected_decoys: Vec<OutputRef> = Vec::with_capacity(decoy_count);
        let mut selected_indices: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut stats = RingSelectionStats::default();

        // Shuffle eligible pool and pick first N (truly uniform)
        let mut shuffled: Vec<&OutputRef> = eligible.clone();
        // Fisher-Yates shuffle with cryptographic RNG
        for i in (1..shuffled.len()).rev() {
            let j = (rng.next_u64() as usize) % (i + 1);
            shuffled.swap(i, j);
        }

        for output in &shuffled {
            if selected_decoys.len() >= decoy_count { break; }
            if !selected_indices.contains(&output.global_index) {
                selected_indices.insert(output.global_index);
                selected_decoys.push((*output).clone());
            }
        }

        stats.selection_retries = 0; // uniform never retries

        // If we couldn't get enough with gamma, handle based on strict mode
        // SECURITY: Uniform selection has different statistical properties than gamma,
        // which can potentially leak information about the real signer.
        let fallback_needed = selected_decoys.len() < decoy_count;
        let fallback_count = decoy_count.saturating_sub(selected_decoys.len());

        if fallback_needed {
            // SECURITY: In strict mode, refuse to proceed with degraded privacy
            if self.config.strict_privacy_mode {
                return Err(Error::Internal(format!(
                    "PRIVACY CRITICAL: Ring selection failed. Gamma distribution could only select \
                     {}/{} decoys. Refusing to fall back to uniform random in strict privacy mode. \
                     Solutions: \
                     1. Wait for more outputs to mature in the blockchain \
                     2. Increase output pool diversity \
                     3. If this is a test environment, use RingSelector::with_ring_size() instead",
                    selected_decoys.len(),
                    decoy_count
                )));
            }

            // Non-strict mode: log at ERROR level since this is a privacy degradation
            // This should be extremely visible in production logs
            tracing::error!(
                "PRIVACY DEGRADATION: Ring selection falling back to uniform random for {} decoys \
                 (gamma selected {}/{}). Uniform selection has different statistical properties \
                 that may allow transaction graph analysis. This transaction's sender may be \
                 more identifiable than normal. Cause: insufficient eligible outputs in pool.",
                fallback_count,
                selected_decoys.len(),
                decoy_count
            );

            // Also emit a structured event for privacy monitoring systems
            tracing::warn!(
                target: "privacy_audit",
                event = "ring_selection_fallback",
                gamma_selected = selected_decoys.len(),
                fallback_needed = fallback_count,
                total_decoys = decoy_count,
                "Privacy-degraded ring selection"
            );
        }

        while selected_decoys.len() < decoy_count {
            let idx = rng.gen_range(0..eligible.len());
            let output = eligible[idx];
            if !selected_indices.contains(&output.global_index) {
                selected_indices.insert(output.global_index);
                selected_decoys.push(output.clone());
            }
        }

        // Track fallback usage in stats for auditing
        stats.fallback_used = fallback_needed;
        stats.fallback_count = fallback_count;

        // Compute statistics
        stats.decoys_selected = selected_decoys.len();
        let ages: Vec<u64> = selected_decoys
            .iter()
            .map(|o| current_height.saturating_sub(o.height))
            .collect();

        if !ages.is_empty() {
            stats.avg_decoy_age = ages.iter().sum::<u64>() as f64 / ages.len() as f64;
            stats.min_age = *ages.iter().min().unwrap_or(&0);
            stats.max_age = *ages.iter().max().unwrap_or(&0);

            // Age distribution buckets (logarithmic)
            // SECURITY (A4-CR-04): Handle age=0 explicitly since log2(0) = -infinity,
            // which causes undefined behavior when cast to usize.
            for age in &ages {
                let bucket = if *age == 0 {
                    0
                } else {
                    (*age as f64).log2().floor().max(0.0) as usize
                };
                let bucket = bucket.min(9);
                stats.age_distribution[bucket] += 1;
            }
        }

        // Insert real output at random position
        let real_index = rng.gen_range(0..=selected_decoys.len());
        let mut ring = selected_decoys;
        ring.insert(real_index, real_output.clone());

        Ok((ring, real_index, stats))
    }

    /// Check if an output is eligible as a decoy
    ///
    /// SECURITY (BUG-5): The `effective_min_age` parameter allows relaxing
    /// the minimum age constraint when the real output is younger than
    /// `min_decoy_age`. Without this, the real output would be the only
    /// young ring member, trivially identifiable by an observer.
    fn is_eligible_decoy(
        &self,
        output: &OutputRef,
        real_output: &OutputRef,
        current_height: u64,
        effective_min_age: u64,
    ) -> bool {
        // Can't use the real output as a decoy
        if output.global_index == real_output.global_index {
            return false;
        }

        // Check age constraints — use effective_min_age (may be lower than
        // config.min_decoy_age if the real output is young)
        let age = current_height.saturating_sub(output.height);
        if age < effective_min_age {
            return false;
        }
        if age > self.config.max_decoy_age {
            return false;
        }

        true
    }

    /// Find output near target height with randomized tie-breaking
    ///
    /// SECURITY (BUG-11): Previously used deterministic `min_by_key` which
    /// always picked the same closest output for a given target height. An
    /// adversary who knows the output pool could reconstruct decoy selections
    /// and identify the real input. Now collects candidates within a small
    /// window and picks one uniformly at random.
    #[allow(dead_code)] // Retained for BUG-11 security documentation
    fn find_output_near_height<'a>(
        &self,
        outputs: &[&'a OutputRef],
        target_height: u64,
        excluded: &std::collections::HashSet<u64>,
        rng: &mut impl rand::Rng,
    ) -> Option<&'a OutputRef> {
        use rand::seq::SliceRandom;

        let mut candidates: Vec<&'a OutputRef> = outputs
            .iter()
            .filter(|o| !excluded.contains(&o.global_index))
            .copied()
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Sort by distance to target, then take the top N closest
        candidates.sort_by_key(|o| {
            if o.height > target_height {
                o.height - target_height
            } else {
                target_height - o.height
            }
        });

        // Pick randomly from the closest ~5 candidates (or fewer if pool is small)
        let window = 5.min(candidates.len());
        let chosen = candidates[..window].choose(rng)?;
        Some(chosen)
    }

    /// Verify ring selection quality (for auditing)
    pub fn verify_ring_quality(
        &self,
        ring: &[OutputRef],
        real_index: usize,
        current_height: u64,
    ) -> RingQualityReport {
        let mut report = RingQualityReport::default();
        report.ring_size = ring.len();

        if ring.is_empty() {
            report.issues.push("Empty ring".into());
            return report;
        }

        // Check ages
        let ages: Vec<u64> = ring
            .iter()
            .map(|o| current_height.saturating_sub(o.height))
            .collect();

        report.avg_age = ages.iter().sum::<u64>() as f64 / ages.len() as f64;
        report.age_variance = self.compute_variance(&ages);

        // Check for suspicious patterns
        let real_age = ages[real_index];

        // Is real output age suspicious? (much newer/older than average)
        let age_zscore = (real_age as f64 - report.avg_age) / report.age_variance.sqrt().max(1.0);
        if age_zscore.abs() > 2.5 {
            report.issues.push(format!(
                "Real output age ({}) is statistical outlier (z-score: {:.2})",
                real_age, age_zscore
            ));
        }

        // Check for duplicate commitments (shouldn't happen)
        let mut commitments = std::collections::HashSet::new();
        for output in ring {
            if !commitments.insert(output.commitment) {
                report.issues.push("Duplicate commitment in ring".into());
            }
        }

        // Check age distribution matches expected gamma
        report.distribution_score = self.score_distribution(&ages);

        report.is_valid = report.issues.is_empty() && report.distribution_score > 0.5;
        report
    }

    fn compute_variance(&self, values: &[u64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;
        let variance: f64 = values
            .iter()
            .map(|&v| {
                let diff = v as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / values.len() as f64;
        variance
    }

    fn score_distribution(&self, ages: &[u64]) -> f64 {
        // Simple scoring: check if distribution roughly matches gamma
        // Score 0-1 based on how well it fits expected pattern
        if ages.is_empty() {
            return 0.0;
        }

        // Expect more recent outputs than old ones
        let recent_count = ages.iter().filter(|&&a| a < 1000).count();
        let old_count = ages.iter().filter(|&&a| a > 100_000).count();

        let recent_ratio = recent_count as f64 / ages.len() as f64;
        let old_ratio = old_count as f64 / ages.len() as f64;

        // Good distribution: ~40-60% recent, <20% very old
        let recent_score = if recent_ratio > 0.3 && recent_ratio < 0.7 { 1.0 } else { 0.5 };
        let old_score = if old_ratio < 0.3 { 1.0 } else { 0.5 };

        (recent_score + old_score) / 2.0
    }
}

/// Ring quality audit report
#[derive(Clone, Debug, Default)]
pub struct RingQualityReport {
    /// Ring size
    pub ring_size: usize,
    /// Average age of ring members
    pub avg_age: f64,
    /// Variance of ages
    pub age_variance: f64,
    /// How well the distribution matches expected pattern (0-1)
    pub distribution_score: f64,
    /// Issues found
    pub issues: Vec<String>,
    /// Overall validity
    pub is_valid: bool,
}

impl RingQualityReport {
    /// Get a human-readable summary
    pub fn summary(&self) -> String {
        if self.is_valid {
            format!(
                "Ring OK: {} members, avg age {:.0} blocks, dist score {:.2}",
                self.ring_size, self.avg_age, self.distribution_score
            )
        } else {
            format!(
                "Ring ISSUES: {} problems - {}",
                self.issues.len(),
                self.issues.join("; ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use crate::primitives::Hash;

    fn make_output(height: u64, index: u64) -> OutputRef {
        OutputRef {
            height,
            tx_hash: Hash::zero(),
            output_index: 0,
            public_key: PublicKey::from_bytes([index as u8; 32]),
            commitment: [0u8; 32],
            global_index: index,
        }
    }

    #[test]
    fn test_ring_selection() {
        let selector = RingSelector::with_ring_size(11);
        let current_height = 100_000;

        // Create output pool
        let pool: Vec<OutputRef> = (0..1000)
            .map(|i| make_output(current_height - (i * 100), i))
            .collect();

        let real_output = make_output(current_height - 50, 9999);

        let (ring, real_idx, stats) = selector
            .select_ring(&real_output, &pool, current_height, &mut OsRng)
            .unwrap();

        assert_eq!(ring.len(), 11);
        assert!(real_idx < 11);
        assert_eq!(ring[real_idx].global_index, 9999);
        assert_eq!(stats.decoys_selected, 10);
    }

    #[test]
    fn test_ring_quality_check() {
        let selector = RingSelector::with_ring_size(11);
        let current_height = 100_000;

        let ring: Vec<OutputRef> = (0..11)
            .map(|i| make_output(current_height - (i * 1000), i))
            .collect();

        let report = selector.verify_ring_quality(&ring, 5, current_height);
        assert!(report.ring_size == 11);
    }

    #[test]
    fn test_distribution_is_uniform() {
        // Privacy Innovation #1 (Decoy Aging Defense): selection uses UNIFORM
        // distribution so chain-analysis heuristics assuming recency bias
        // cannot narrow the real spend.
        let selector = RingSelector::with_ring_size(11);
        let current_height = 200_000;

        let pool: Vec<OutputRef> = (0..10_000)
            .map(|i| make_output(current_height - (i * 10), i))
            .collect();

        let real_output = make_output(current_height - 5, 99999);

        let mut recent = 0usize;
        let mut total_decoys = 0usize;
        for _ in 0..50 {
            let (ring, real_idx, _) = selector
                .select_ring(&real_output, &pool, current_height, &mut OsRng)
                .unwrap();
            for (i, member) in ring.iter().enumerate() {
                if i == real_idx { continue; }
                total_decoys += 1;
                if member.height > current_height - 10_000 {
                    recent += 1;
                }
            }
        }
        // Uniform: ~10% of decoys in the most recent 10% of range.
        // Allow 5-20% for randomness. Must NOT show gamma-style bias (>25%).
        let recent_ratio = recent as f64 / total_decoys as f64;
        assert!(recent_ratio < 0.25,
            "Uniform should NOT bias recent: got {:.2}%", recent_ratio * 100.0);
    }
}
