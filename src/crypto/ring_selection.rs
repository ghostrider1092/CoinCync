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
/// Configuration for ring/decoy selection.
///
/// AUDIT (2026-07-02 Wave 16 doc-drift cleanup): removed dead `gamma_shape`
/// and `gamma_scale` fields. They were carry-over from the pre-uniform
/// implementation, still declared on the struct + populated in Default,
/// but grep-verified zero readers anywhere in the tree. Their presence
/// suggested to future auditors that the config controlled a gamma
/// distribution, which contradicts the module-header design comment
/// (uniform-only, see L3–L22). Their default values were also stale
/// Monero-derived numbers.
///
/// The `strict_privacy_mode` docstring was also stale — it described
/// pre-uniform "fall back to gamma" semantics. Actual behavior post-
/// Wave 1 is documented in the current comment: reject-on-pool-
/// shortfall (strict) vs allow-uniform-with-replacement (relaxed).
#[derive(Clone, Debug)]
pub struct RingSelectionConfig {
    /// Minimum ring size
    pub min_ring_size: usize,
    /// Target ring size
    pub target_ring_size: usize,
    /// Maximum ring size
    pub max_ring_size: usize,
    /// Minimum output age in blocks before it can be a decoy
    pub min_decoy_age: u64,
    /// Maximum age for decoys (avoid ancient outputs)
    pub max_decoy_age: u64,
    /// Require outputs from recent blocks (last N blocks must have representation)
    pub recent_block_requirement: u64,
    /// SECURITY: eligible-pool-shortfall behavior.
    ///
    /// If `true` (strict): if the uniform shuffle can't fill the ring from
    /// the deduped eligible pool, reject the ring build. Better to surface
    /// the shortfall to the operator than silently ship a smaller anonymity
    /// set. This is the default and the recommended production setting.
    ///
    /// If `false` (relaxed): fall back to uniform-with-replacement — allow
    /// the same output to appear more than once in the ring, still uniform
    /// but with reduced anonymity-set diversity. Emits an ERROR-level log +
    /// a structured `privacy_audit` event so the degradation is visible.
    /// Only appropriate for test rigs or extreme pool-exhaustion scenarios.
    ///
    /// Prior version's docstring described "fall back to uniform random with
    /// warning" as the *relaxed* mode, framing uniform as WEAKER privacy —
    /// that framing was written before the Wave 1 gamma → uniform switch
    /// and had the polarity inverted (uniform IS the constitutional design;
    /// gamma is the Möser-2018-attackable form). Fixed 2026-07-02.
    pub strict_privacy_mode: bool,
}

impl Default for RingSelectionConfig {
    fn default() -> Self {
        RingSelectionConfig {
            min_ring_size: 11,
            target_ring_size: 11,
            max_ring_size: 21,
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
    /// Whether the uniform-with-replacement fallback fired due to eligible-
    /// pool shortfall. Signals a reduced-anonymity-set ring — still uniform
    /// draws, but the same output may appear more than once. Privacy-audit
    /// event is emitted at ERROR level; monitoring should page on this.
    ///
    /// AUDIT (2026-07-02): stale comment cleanup. Prior text ("uniform random
    /// fallback was used (privacy concern)") was written before the Wave 1
    /// gamma→uniform switch and implied that uniform ITSELF was the concern.
    /// It's not — uniform is the constitutional design. The concern is
    /// specifically the *with-replacement* variant, which fires only on
    /// pool-shortfall.
    pub fallback_used: bool,
    /// Number of decoys selected via fallback
    pub fallback_count: usize,
}

/// Select ring members using UNIFORM decoy selection over the eligible pool.
///
/// AUDIT (2026-07-02): docstring corrected. Prior text ("Select ring members
/// using gamma distribution") was directly contradicted by the module-level
/// design comment at L3–L22 (uniform-only) AND by the implementation
/// (Fisher-Yates uniform shuffle). Same class of docstring drift as the
/// storage/utxos.rs gamma → uniform Wave 15 fix — this one was inside the
/// design-correct module but the docstring hadn't been updated.
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
        let real_age = current_height.saturating_sub(real_output.height);
        let effective_min_age = real_age.min(self.config.min_decoy_age);
        const AGE_FUZZ_BLOCKS: u64 = 3;
        let age_similar_count = output_pool
            .iter()
            .filter(|o| {
                let o_age = current_height.saturating_sub(o.height);
                o_age.abs_diff(real_age) <= AGE_FUZZ_BLOCKS
                    && o.global_index != real_output.global_index
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
        // AUDIT (R-23 fix, 2026-07-02): the pre-fix code collected without
        // deduplicating by global_index. If a caller (buggy scanner,
        // adversarial RPC response) sent the same OutputRef twice — same
        // (tx_hash, output_index, global_index) — the eligible pool
        // contained duplicates and the Fisher-Yates shuffle at L254 could
        // pick the same one twice with non-uniform probability. Uniform
        // ring selection is our PRIMARY defense against age-based
        // deanonymisation (see module header); a caller-controllable
        // non-uniformity is a hard privacy break. We now dedup by
        // global_index BEFORE the eligibility filter — this normalises
        // input from any source (mempool scan, DB query, caller-supplied
        // fixture) to the same uniform-eligible distribution.
        let mut seen_indices = std::collections::HashSet::new();
        let eligible: Vec<&OutputRef> = output_pool
            .iter()
            .filter(|o| seen_indices.insert(o.global_index))
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
        // Fisher-Yates shuffle with cryptographic RNG.
        //
        // AUDIT (2026-07-01): switched from `rng.next_u64() as usize % (i+1)`
        // to `rng.gen_range(0..=i)`. The old modulo-based index has
        // modulo bias: when `(i+1)` doesn't divide `2^usize::BITS`, values
        // near 0 are slightly more likely than values near `i`. For the
        // ring-selection privacy claim ("every ring member is equally
        // likely to be the real spend"), any bias in the shuffle
        // permutation weakens the guarantee. `gen_range` performs
        // rejection sampling internally and is unbiased. The rest of this
        // file already uses `gen_range` (see the fallback loop at ~L278
        // and the real-index insertion at ~L317); this brings the
        // shuffle in line.
        for i in (1..shuffled.len()).rev() {
            let j = rng.gen_range(0..=i);
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

        // 2026-06-03 docs-correctness fix: the prior version of this function
        // used a gamma distribution for decoy selection. CoinCync switched to
        // uniform shuffle (see the module-level comment at line ~3-22 for the
        // 4th-Amendment / Möser-attack rationale). The Fisher-Yates shuffle
        // above is the actual selection mechanism; "fallback" here means the
        // shuffle exhausted the eligible pool without filling the ring,
        // which can only happen when `eligible.len() < decoy_count + duplicates`
        // (the duplicate filter at line ~209 reads from `global_index`).
        //
        // The strict-mode error and the privacy-audit log previously
        // referenced "Gamma distribution could only select…" — stale text
        // inherited from the gamma-era code that mis-described why
        // selection failed and pointed engineers at the wrong fix. The
        // failure cause is *eligible pool too small*, not a distribution
        // problem. Messages updated accordingly.
        let fallback_needed = selected_decoys.len() < decoy_count;
        let fallback_count = decoy_count.saturating_sub(selected_decoys.len());

        if fallback_needed {
            // SECURITY: In strict mode, refuse to proceed with degraded privacy.
            if self.config.strict_privacy_mode {
                return Err(Error::Internal(format!(
                    "PRIVACY CRITICAL: Ring selection failed. Uniform shuffle could only fill \
                     {}/{} decoys from the eligible pool (after dedup by global_index). \
                     Refusing to retry with looser constraints in strict privacy mode — that \
                     would reduce the anonymity set without surfacing it to the operator. \
                     Solutions: \
                     1. Wait for more outputs to mature in the blockchain \
                     2. Increase output pool diversity by raising max_decoy_age \
                     3. If this is a test environment, use RingSelector::with_ring_size() instead",
                    selected_decoys.len(),
                    decoy_count
                )));
            }

            // Non-strict mode: log at ERROR level since this is a privacy degradation.
            // This should be extremely visible in production logs.
            tracing::error!(
                "PRIVACY DEGRADATION: Ring selection eligible-pool shortfall — \
                 uniform shuffle filled {}/{} decoy slots; retrying with replacement \
                 sampling for the remaining {} slots. The retry MAY reuse outputs \
                 already present elsewhere in the same eligible pool, which can \
                 reduce anonymity-set diversity. Cause: insufficient eligible \
                 outputs in pool (raise max_decoy_age or wait for chain to mature).",
                selected_decoys.len(),
                decoy_count,
                fallback_count
            );

            // Also emit a structured event for privacy monitoring systems.
            tracing::warn!(
                target: "privacy_audit",
                event = "ring_selection_fallback",
                shuffle_selected = selected_decoys.len(),
                fallback_needed = fallback_count,
                total_decoys = decoy_count,
                "Privacy-degraded ring selection (eligible-pool shortfall)"
            );
        }

        // R-24 fix (2026-07-02): the prior code had TWO bugs.
        //
        // Bug 1 (livelock): fallback loop kept the same
        // `!selected_indices.contains(...)` dedup check that the
        // shuffle above already failed on. If the eligible pool has
        // fewer unique global_indices than `decoy_count`, every
        // subsequent draw hits an already-selected index, the branch
        // is skipped, and the loop spins forever. The docstring
        // (L305-308) explicitly says "retry with replacement
        // sampling for the remaining {} slots" — the code did NOT
        // implement replacement sampling; it implemented the same
        // no-replacement sampling that had just failed.
        //
        // Bug 2 (no bounded retry): even if bug 1 is fixed, an
        // adversary who can force `eligible.len() == 0` (impossible
        // via the L221 guard, but defense-in-depth) would still
        // infinite-loop. We cap at MAX_FALLBACK_ITERS regardless
        // and return an Internal error rather than spin.
        //
        // The docstring's "with replacement" language means the SAME
        // OutputRef can appear TWICE in the ring — the decoy is
        // duplicated. Anonymity-set size drops accordingly, which is
        // WHY the tracing::error above logs it as
        // "PRIVACY DEGRADATION", not a warn. Strict-mode callers
        // already returned above; only permissive callers reach here.
        if fallback_needed && !eligible.is_empty() {
            const MAX_FALLBACK_ITERS: usize = 10_000;
            let mut iters = 0usize;
            while selected_decoys.len() < decoy_count {
                if iters >= MAX_FALLBACK_ITERS {
                    return Err(Error::Internal(format!(
                        "ring-selection fallback loop exceeded {} iterations without \
                         filling {}/{} decoys — eligible pool has {} outputs. This \
                         is a defense-in-depth guard; if you're seeing it, either \
                         `eligible` was mutated during selection (bug) or a caller \
                         requested a ring larger than any realistic pool.",
                        MAX_FALLBACK_ITERS,
                        selected_decoys.len(),
                        decoy_count,
                        eligible.len()
                    )));
                }
                let idx = rng.gen_range(0..eligible.len());
                let output = eligible[idx];
                // WITH-REPLACEMENT semantics — deliberately DO NOT
                // consult selected_indices. Duplicates are the
                // documented cost of fallback; the privacy_audit log
                // above tells the operator this happened.
                selected_indices.insert(output.global_index);
                selected_decoys.push(output.clone());
                iters += 1;
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

    /// R-24 + R-23 regression: prior code's fallback loop
    /// livelocked when the eligible pool's unique-global_index count
    /// was smaller than `decoy_count`.
    ///
    /// After R-23 (2026-07-02) landed, duplicate global_index entries
    /// in the input pool are DEDUPED before the eligibility filter,
    /// so this specific pathological input now bails early with
    /// `InvalidRingSize` — the fallback loop is unreachable via this
    /// path, which is a stronger guarantee than the R-24 bounded
    /// retry. We keep the R-24 fix in place as defense-in-depth for
    /// any future code path that could reach the fallback (e.g. an
    /// unlikely eligibility filter that leaves n < decoy_count
    /// outputs but doesn't fail the L280 guard); the test below now
    /// verifies the R-23 pre-dedup structural rejection.
    #[test]
    fn duplicate_global_indices_pool_rejected_structurally() {
        let selector = RingSelector::with_ring_size(11);
        let current_height = 100_000;
        let mut pool: Vec<OutputRef> = Vec::new();
        for i in 0u64..3 {
            for _ in 0..5 {
                pool.push(make_output(current_height - 1_000 - i, i));
            }
        }
        let real_output = make_output(current_height - 50, 9999);

        // Terminate in bounded time either way — this is a
        // regression guard against a future re-introduction of the
        // livelock.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = selector.select_ring(&real_output, &pool, current_height, &mut OsRng);
            let _ = tx.send(result);
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("regression: ring selection did not terminate within 5s");

        // R-23 causes this to fail with InvalidRingSize instead of
        // reaching the fallback path.
        assert!(matches!(result, Err(Error::InvalidRingSize { .. })),
            "R-23: duplicate-global_index pool must be rejected structurally, got {:?}", result);
    }
}
