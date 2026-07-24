//! # Ring Member Selection for CoinCync 1.0
//!
//! This module is the ring **assembler**: given a candidate decoy pool it
//! chooses the final ring members and the real output's position, drawing
//! **uniformly from the pool it is given**.
//!
//! The age distribution that actually hides the real spend is applied
//! **upstream at the source** (`src/storage/utxos.rs::select_decoys`), which
//! age-matches decoys to the real-spend law via a population-wide **gamma**
//! distribution (`DECOY_GAMMA_SHAPE`). Real spends are overwhelmingly recent,
//! so uniform selection over all history would leave the recent real input as
//! the young outlier in its ring — the output-age regression attack in the
//! traceability literature (Miller et al. 2017, Möser et al. 2018). Age-matching
//! removes that signal for the common case.
//!
//! This assembler therefore draws uniformly *from the already-gamma-shaped
//! pool*. Re-imposing a distribution here would double-bias it, and shuffling a
//! pool cannot add an age distribution the pool does not already carry. See the
//! decision history in `src/storage/utxos.rs::select_decoys` (uniform on
//! 2026-07-02, reversed to gamma 2026-07-24 by owner + co-founder).
//!
//! ## Constitutional note
//!
//! Article III (Mandatory Privacy): statistical deanonymization of ring
//! signatures is an unreasonable search of private financial records, and decoy
//! age-matching is the technical enforcement of that protection. The accepted
//! residual — a genuinely old real output remains an age outlier — is closed
//! only by the long-term large-ring / zero-knowledge upgrade, not by decoy
//! tuning.

use crate::error::{Error, Result};
use crate::primitives::PublicKey;
use rand::seq::index;
use rand::{CryptoRng, Rng, RngCore};

/// Output reference for ring selection
#[derive(Clone, Copy, Debug)]
pub struct OutputRef<'a> {
    /// Block height where output was created
    pub height: u64,
    /// Public key (stealth address)
    pub public_key: &'a PublicKey,
    /// Commitment bytes
    pub commitment: &'a [u8; 32],
}

impl<'a> OutputRef<'a> {
    pub fn new(height: u64, public_key: &'a PublicKey, commitment: &'a [u8; 32]) -> Self {
        Self {
            height,
            public_key,
            commitment,
        }
    }
}

/// Keeps ring-size policy and sampling bound to the same unique output set.
#[derive(Debug)]
pub struct RingSelectionPool<'a> {
    outputs: Vec<OutputRef<'a>>,
}

impl<'a> RingSelectionPool<'a> {
    pub fn new(outputs: impl IntoIterator<Item = OutputRef<'a>>) -> Self {
        let mut seen_public_keys = std::collections::HashSet::new();
        let outputs = outputs
            .into_iter()
            .filter(|output| seen_public_keys.insert(*output.public_key.as_bytes()))
            .collect();
        Self { outputs }
    }

    pub fn len(&self) -> usize {
        self.outputs.len()
    }
}

/// Configuration for ring/decoy selection.
#[derive(Clone, Debug)]
pub struct RingSelectionConfig {
    /// Target ring size
    pub target_ring_size: usize,
    /// Minimum output age in blocks before it can be a decoy
    pub min_decoy_age: u64,
    /// Maximum age for decoys (avoid ancient outputs)
    pub max_decoy_age: u64,
}

impl Default for RingSelectionConfig {
    fn default() -> Self {
        RingSelectionConfig {
            target_ring_size: 11,
            min_decoy_age: 10,
            max_decoy_age: 5_256_000 * 2, // ~2 years in blocks
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
    /// Distribution of decoys by age bucket
    pub age_distribution: [u32; 10],
}

/// Select ring members using UNIFORM decoy selection over the eligible pool.
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
                target_ring_size: ring_size,
                ..Default::default()
            },
        }
    }

    /// Select decoys for a ring signature
    ///
    /// # Arguments
    /// * `real_public_key` - The real output's public key
    /// * `real_height` - The height where the real output was created
    /// * `output_pool` - Available outputs to select from
    /// * `current_height` - Current blockchain height
    /// * `rng` - Cryptographic RNG
    ///
    /// # Returns
    /// * `(decoys, real_position, stats)` - Selected decoys, insertion position, and stats
    pub fn select_decoys<'a, R: RngCore + CryptoRng>(
        &self,
        real_public_key: &PublicKey,
        real_height: u64,
        output_pool: &RingSelectionPool<'a>,
        current_height: u64,
        rng: &mut R,
    ) -> Result<(Vec<OutputRef<'a>>, usize, RingSelectionStats)> {
        let ring_size = self.config.target_ring_size;

        // T3F1 fix (2026-07-05): reject ring_size < 2 explicitly so the
        // next line `let decoy_count = ring_size - 1;` cannot underflow
        // when a caller passes ring_size = 0. In release mode with
        // default wrapping arithmetic, `0usize - 1` produces
        // `usize::MAX`, which then makes the pool-size check on the
        // following line trivially fail with the misleading error
        // `InvalidRingSize { expected: usize::MAX, got: <pool.len()> }`.
        // A ring_size of 1 (which does not underflow) is also rejected
        // here because a single-member "ring" provides no anonymity
        // set. Reachable only via test-helper `with_ring_size(0)` or
        // a hand-constructed `RingSelectionConfig`; not attacker-
        // controllable at consensus.
        if ring_size < 2 {
            return Err(Error::InvalidRingSize {
                expected: 2,
                got: ring_size,
            });
        }
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
        //
        // AUDIT (R-22 fix, 2026-07-03): surgical implementation. Count
        // the number of pool outputs within age±FUZZ of the real
        // output. If it's below a safety threshold, emit a LOUD warn
        // so the caller (and ops via log aggregation) sees the
        // privacy degradation. We do NOT hard-fail the selection,
        // because that would break small-pool testnets and early-
        // chain scenarios where age spread is legitimately narrow.
        // The warn IS the signal — it tells the operator "this ring
        // is likely to leak the real spend via age analysis, defer
        // the tx until more age-similar outputs exist."
        let real_age = current_height.saturating_sub(real_height);
        let effective_min_age = real_age.min(self.config.min_decoy_age);
        const AGE_FUZZ_BLOCKS: u64 = 3;
        let age_similar_count = output_pool
            .outputs
            .iter()
            .filter(|o| {
                let o_age = current_height.saturating_sub(o.height);
                o_age.abs_diff(real_age) <= AGE_FUZZ_BLOCKS
                    && o.public_key.as_bytes() != real_public_key.as_bytes()
            })
            .count();
        let age_similar_advisory = (decoy_count / 3).max(1);
        if age_similar_count < age_similar_advisory {
            tracing::warn!(
                target: "crypto::ring_selection::R22",
                real_age = real_age,
                age_similar_count = age_similar_count,
                advisory_threshold = age_similar_advisory,
                decoy_count = decoy_count,
                "R-22: real output has {} age-similar peers in pool (advisory ≥{}). \
                 Ring signature will still be constructed, but a chain \
                 analyst can identify the youngest ring member as the \
                 real spend. Defer this tx until more outputs at similar \
                 age exist, or accept the reduced anonymity.",
                age_similar_count, age_similar_advisory
            );
        }

        // Filter eligible outputs.
        //
        // Deduplication prevents repeated pool entries from giving one output
        // multiple chances of inclusion and weakening the anonymity set.
        let eligible: Vec<&OutputRef<'a>> = output_pool
            .outputs
            .iter()
            .filter(|o| {
                self.is_eligible_decoy(o, real_public_key, current_height, effective_min_age)
            })
            .collect();

        if eligible.len() < decoy_count {
            return Err(Error::InvalidRingSize {
                expected: decoy_count,
                got: eligible.len(),
            });
        }

        // Sampling indices preserves a uniform distribution without allocating
        // and shuffling a second vector proportional to the eligible pool.
        let selected_decoys: Vec<OutputRef<'a>> = index::sample(rng, eligible.len(), decoy_count)
            .iter()
            .map(|i| *eligible[i])
            .collect();
        let mut stats = RingSelectionStats::default();

        stats.decoys_selected = selected_decoys.len();
        let ages: Vec<u64> = selected_decoys
            .iter()
            .map(|o| current_height.saturating_sub(o.height))
            .collect();

        if !ages.is_empty() {
            stats.avg_decoy_age = ages.iter().sum::<u64>() as f64 / ages.len() as f64;
            stats.min_age = *ages.iter().min().unwrap_or(&0);
            stats.max_age = *ages.iter().max().unwrap_or(&0);

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

        let real_position = rng.gen_range(0..ring_size);

        Ok((selected_decoys, real_position, stats))
    }

    /// Check if an output is eligible as a decoy
    ///
    /// SECURITY (BUG-5): The `effective_min_age` parameter allows relaxing
    /// the minimum age constraint when the real output is younger than
    /// `min_decoy_age`. Without this, the real output would be the only
    /// young ring member, trivially identifiable by an observer.
    fn is_eligible_decoy(
        &self,
        output: &OutputRef<'_>,
        real_public_key: &PublicKey,
        current_height: u64,
        effective_min_age: u64,
    ) -> bool {
        // Can't use the real output as a decoy
        if output.public_key.as_bytes() == real_public_key.as_bytes() {
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

    /// Verify ring selection quality (for auditing)
    pub fn verify_ring_quality(
        &self,
        ring: &[OutputRef<'_>],
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
            if !commitments.insert(*output.commitment) {
                report.issues.push("Duplicate commitment in ring".into());
            }
        }

        // AUDIT (2026-07-01): removed the `distribution_score` computation
        // and the `... && distribution_score > 0.5` gate. `score_distribution`
        // (see below) was inherited from the pre-2026-06-03 gamma-selection
        // era and grades toward a "more recent than old" pattern. That is
        // the OPPOSITE of what CoinCync's uniform decoy selection produces:
        // uniform selection over a wide-age pool yields ~equal mass across
        // buckets, so `score_distribution` returns ~0.5, and the gate then
        // flags every correctly-uniform ring as `is_valid = false`. The
        // dead-gamma logic contradicted the design comment at the top of
        // this file (see the 4th-Amendment / Möser-attack rationale).
        //
        // `is_valid` now reflects only the checks that are consistent with
        // uniform selection: no per-ring issues (empty ring, duplicate
        // commitments) and no z-score outlier on the real output's age.
        // `distribution_score` stays at its Default (0.0) so serialized
        // reports keep the same field shape.
        report.is_valid = report.issues.is_empty();
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

    // AUDIT (2026-07-01): removed `score_distribution`. Original body scored
    // rings toward a gamma-style "more recent than old" pattern inherited
    // from the pre-2026-06-03 gamma-selection code. That grading rejects
    // exactly the uniform distribution CoinCync now targets by design. The
    // only caller was the `is_valid` gate above, which has also been
    // reworked to not depend on any distribution-shape heuristic.
    // Restoring a shape check for the uniform era would need a chi-squared
    // or KS test against the eligible pool's age histogram, not a hand-
    // tuned recent/old cutoff — out of scope for this pass, and unused
    // anyway (no external consumer reads `distribution_score`).
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
    use rand::{rngs::StdRng, SeedableRng};

    #[derive(Clone)]
    struct OwnedOutput {
        height: u64,
        public_key: PublicKey,
        commitment: [u8; 32],
    }

    impl OwnedOutput {
        fn as_ref(&self) -> OutputRef<'_> {
            OutputRef::new(self.height, &self.public_key, &self.commitment)
        }
    }

    fn make_output(height: u64, index: u64) -> OwnedOutput {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&index.to_le_bytes());
        OwnedOutput {
            height,
            public_key: PublicKey::from_bytes(bytes),
            commitment: bytes,
        }
    }

    fn output_pool(outputs: &[OwnedOutput]) -> RingSelectionPool<'_> {
        RingSelectionPool::new(outputs.iter().map(OwnedOutput::as_ref))
    }

    #[test]
    fn test_ring_selection() {
        let selector = RingSelector::with_ring_size(11);
        let current_height = 100_000;

        let pool_storage: Vec<OwnedOutput> = (0..1000)
            .map(|i| make_output(current_height - (i * 100), i))
            .collect();
        let pool = output_pool(&pool_storage);

        let real_output = make_output(current_height - 50, 9999);
        let mut rng = StdRng::seed_from_u64(1);

        let (decoys, real_position, stats) = selector
            .select_decoys(
                &real_output.public_key,
                real_output.height,
                &pool,
                current_height,
                &mut rng,
            )
            .unwrap();

        assert_eq!(decoys.len(), 10);
        assert!(real_position < 11);
        assert_eq!(stats.decoys_selected, 10);
        assert!(decoys
            .iter()
            .all(|output| { output.public_key.as_bytes() != real_output.public_key.as_bytes() }));
        let unique_public_keys = decoys
            .iter()
            .map(|output| *output.public_key.as_bytes())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique_public_keys.len(), decoys.len());
    }

    #[test]
    fn test_ring_quality_check() {
        let selector = RingSelector::with_ring_size(11);
        let current_height = 100_000;

        let ring_storage: Vec<OwnedOutput> = (0..11)
            .map(|i| make_output(current_height - (i * 1000), i))
            .collect();
        let ring = output_pool(&ring_storage);

        let report = selector.verify_ring_quality(&ring.outputs, 5, current_height);
        assert!(report.ring_size == 11);
    }

    #[test]
    fn test_distribution_is_uniform() {
        // Privacy Innovation #1 (Decoy Aging Defense): selection uses UNIFORM
        // distribution so chain-analysis heuristics assuming recency bias
        // cannot narrow the real spend.
        let selector = RingSelector::with_ring_size(11);
        let current_height = 200_000;

        let pool_storage: Vec<OwnedOutput> = (0..10_000)
            .map(|i| make_output(current_height - (i * 10), i))
            .collect();
        let pool = output_pool(&pool_storage);

        let real_output = make_output(current_height - 5, 99999);
        let mut rng = StdRng::seed_from_u64(2);

        let mut recent = 0usize;
        let mut total_decoys = 0usize;
        for _ in 0..50 {
            let (decoys, _, _) = selector
                .select_decoys(
                    &real_output.public_key,
                    real_output.height,
                    &pool,
                    current_height,
                    &mut rng,
                )
                .unwrap();
            for member in decoys {
                total_decoys += 1;
                if member.height > current_height - 10_000 {
                    recent += 1;
                }
            }
        }
        // Uniform: ~10% of decoys in the most recent 10% of range.
        // Allow 5-20% for randomness. Must NOT show gamma-style bias (>25%).
        let recent_ratio = recent as f64 / total_decoys as f64;
        assert!(
            recent_ratio < 0.25,
            "Uniform should NOT bias recent: got {:.2}%",
            recent_ratio * 100.0
        );
    }

    #[test]
    fn duplicate_public_keys_pool_rejected_structurally() {
        let selector = RingSelector::with_ring_size(11);
        let current_height = 100_000;
        let mut pool_storage = Vec::new();
        for i in 0u64..3 {
            for _ in 0..5 {
                pool_storage.push(make_output(current_height - 1_000 - i, i));
            }
        }
        let pool = output_pool(&pool_storage);
        let real_output = make_output(current_height - 50, 9999);
        let mut rng = StdRng::seed_from_u64(3);

        let result = selector.select_decoys(
            &real_output.public_key,
            real_output.height,
            &pool,
            current_height,
            &mut rng,
        );

        assert!(matches!(
            result,
            Err(Error::InvalidRingSize {
                expected: 10,
                got: 3
            })
        ));
    }

    #[test]
    fn full_public_key_distinguishes_shared_u64_prefixes() {
        let selector = RingSelector::with_ring_size(11);
        let current_height = 100_000;
        let pool_storage: Vec<OwnedOutput> = (0u64..10)
            .map(|suffix| {
                let mut bytes = [0x5a; 32];
                bytes[8..16].copy_from_slice(&suffix.to_le_bytes());
                OwnedOutput {
                    height: current_height - 1_000,
                    public_key: PublicKey::from_bytes(bytes),
                    commitment: bytes,
                }
            })
            .collect();
        let pool = output_pool(&pool_storage);
        let real_output = make_output(current_height - 50, 9999);
        let mut rng = StdRng::seed_from_u64(4);

        let (decoys, _, _) = selector
            .select_decoys(
                &real_output.public_key,
                real_output.height,
                &pool,
                current_height,
                &mut rng,
            )
            .unwrap();

        assert_eq!(decoys.len(), 10);
    }
}
