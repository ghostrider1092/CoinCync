//! Parallel Bulletproofs verification
//!
//! Verifies multiple range proofs in parallel for faster block validation.

use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::crypto::cache::{global_cache, proof_cache_key};

/// Proof verification task
pub struct ProofTask {
    /// Commitment data
    pub commitment: [u8; 32],
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Optional identifier (e.g., tx hash + output index)
    pub id: Option<String>,
}

impl ProofTask {
    /// Create new task
    pub fn new(commitment: [u8; 32], proof_data: Vec<u8>) -> Self {
        ProofTask {
            commitment,
            proof_data,
            id: None,
        }
    }

    /// With identifier
    pub fn with_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    /// Compute cache key
    pub fn cache_key(&self) -> [u8; 32] {
        proof_cache_key(&self.proof_data, &self.commitment)
    }
}

/// Parallel proof verification result
#[derive(Clone, Debug)]
pub struct ParallelVerifyResult {
    /// Total proofs
    pub total: usize,
    /// Valid proofs
    pub valid: usize,
    /// Invalid proofs
    pub invalid: usize,
    /// Cached (skipped)
    pub cached: usize,
    /// Invalid proof indices
    pub invalid_indices: Vec<usize>,
    /// Verification time in milliseconds
    pub time_ms: u64,
    /// Proofs per second
    pub proofs_per_second: f64,
}

impl ParallelVerifyResult {
    /// All valid?
    pub fn all_valid(&self) -> bool {
        self.invalid == 0
    }
}

/// Parallel Bulletproof verifier
pub struct ParallelProofVerifier {
    /// Pending proofs
    proofs: Vec<ProofTask>,
    /// Use verification cache
    use_cache: bool,
    /// Minimum batch size for parallel processing
    parallel_threshold: usize,
    /// Statistics
    stats: VerifierStats,
}

/// Verifier statistics
#[derive(Debug, Default)]
pub struct VerifierStats {
    pub total_verified: AtomicU64,
    pub cache_hits: AtomicU64,
    pub total_time_ms: AtomicU64,
}

impl Clone for VerifierStats {
    fn clone(&self) -> Self {
        VerifierStats {
            total_verified: AtomicU64::new(self.total_verified.load(Ordering::Relaxed)),
            cache_hits: AtomicU64::new(self.cache_hits.load(Ordering::Relaxed)),
            total_time_ms: AtomicU64::new(self.total_time_ms.load(Ordering::Relaxed)),
        }
    }
}

impl ParallelProofVerifier {
    /// Create new verifier
    pub fn new() -> Self {
        ParallelProofVerifier {
            proofs: Vec::new(),
            use_cache: true,
            parallel_threshold: 2, // Parallelize if 2+ proofs
            stats: VerifierStats::default(),
        }
    }

    /// Create without caching
    pub fn without_cache() -> Self {
        ParallelProofVerifier {
            proofs: Vec::new(),
            use_cache: false,
            parallel_threshold: 2,
            stats: VerifierStats::default(),
        }
    }

    /// Add proof task
    pub fn add(&mut self, task: ProofTask) {
        self.proofs.push(task);
    }

    /// Add multiple proofs
    pub fn add_all(&mut self, tasks: Vec<ProofTask>) {
        self.proofs.extend(tasks);
    }

    /// Get pending count
    pub fn pending(&self) -> usize {
        self.proofs.len()
    }

    /// Clear pending
    pub fn clear(&mut self) {
        self.proofs.clear();
    }

    /// Verify all proofs in parallel
    pub fn verify_all(&mut self) -> ParallelVerifyResult {
        let start = Instant::now();
        let total = self.proofs.len();

        if total == 0 {
            return ParallelVerifyResult {
                total: 0,
                valid: 0,
                invalid: 0,
                cached: 0,
                invalid_indices: Vec::new(),
                time_ms: 0,
                proofs_per_second: 0.0,
            };
        }

        let cache = if self.use_cache { Some(global_cache()) } else { None };

        // Check cache first
        let mut cache_results: Vec<Option<bool>> = Vec::with_capacity(total);
        let mut cached_count = 0usize;

        for proof in &self.proofs {
            if let Some(c) = cache {
                let key = proof.cache_key();
                if let Some(valid) = c.check_bulletproof(&key) {
                    cache_results.push(Some(valid));
                    cached_count += 1;
                    continue;
                }
            }
            cache_results.push(None);
        }

        // Verify uncached proofs
        let uncached_indices: Vec<usize> = cache_results.iter()
            .enumerate()
            .filter(|(_, r)| r.is_none())
            .map(|(i, _)| i)
            .collect();

        let verification_results: Vec<(usize, bool)> = if uncached_indices.len() >= self.parallel_threshold {
            // Parallel verification
            uncached_indices.par_iter()
                .map(|&i| {
                    let valid = Self::verify_single(&self.proofs[i]);
                    (i, valid)
                })
                .collect()
        } else {
            // Sequential verification
            uncached_indices.iter()
                .map(|&i| {
                    let valid = Self::verify_single(&self.proofs[i]);
                    (i, valid)
                })
                .collect()
        };

        // FIX: Build HashMap for O(1) lookup instead of O(n) Vec::find() per proof.
        // The old code called .find() per uncached proof inside the merge loop —
        // for a 5000-tx block that's 25 million comparisons.
        let verification_map: std::collections::HashMap<usize, bool> = verification_results
            .into_iter()
            .collect();

        // Merge results and update cache
        let mut valid_count = 0usize;
        let mut invalid_count = 0usize;
        let mut invalid_indices = Vec::new();

        for (i, cached) in cache_results.iter().enumerate() {
            let is_valid = if let Some(v) = cached {
                *v
            } else {
                let result = verification_map.get(&i).copied().unwrap_or(false);

                // Cache result
                if let Some(c) = cache {
                    let key = self.proofs[i].cache_key();
                    c.cache_bulletproof(key, result);
                }

                result
            };

            if is_valid {
                valid_count += 1;
            } else {
                invalid_count += 1;
                invalid_indices.push(i);
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;
        let proofs_per_second = if elapsed_ms > 0 {
            (total as f64 * 1000.0) / elapsed_ms as f64
        } else {
            total as f64 * 1000.0
        };

        // Update stats
        self.stats.total_verified.fetch_add(total as u64, Ordering::Relaxed);
        self.stats.cache_hits.fetch_add(cached_count as u64, Ordering::Relaxed);
        self.stats.total_time_ms.fetch_add(elapsed_ms, Ordering::Relaxed);

        // Clear processed proofs
        self.proofs.clear();

        ParallelVerifyResult {
            total,
            valid: valid_count,
            invalid: invalid_count,
            cached: cached_count,
            invalid_indices,
            time_ms: elapsed_ms,
            proofs_per_second,
        }
    }

    /// Verify a single proof
    fn verify_single(task: &ProofTask) -> bool {
        use crate::crypto::{RangeProof, PedersenCommitment, verify_range_proof};

        // Parse proof
        let proof = match RangeProof::from_bytes(&task.proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // SECURITY (A6-COMMITMENT): Use checked deserialization to reject invalid curve
        // points. Unchecked from_bytes could accept non-Ristretto bytes, breaking the
        // homomorphic balance equation and potentially enabling inflation.
        let commitment = match PedersenCommitment::from_bytes_checked(task.commitment) {
            Some(c) => c,
            None => return false,
        };

        // Verify
        verify_range_proof(&commitment, &proof)
    }

    /// Get verification statistics
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.stats.total_verified.load(Ordering::Relaxed),
            self.stats.cache_hits.load(Ordering::Relaxed),
            self.stats.total_time_ms.load(Ordering::Relaxed),
        )
    }
}

impl Default for ParallelProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify proofs for a block in parallel
pub fn verify_block_proofs(
    outputs: &[(crate::primitives::Hash, u8, [u8; 32], Vec<u8>)],
) -> ParallelVerifyResult {
    let mut verifier = ParallelProofVerifier::new();

    for (tx_hash, idx, commitment, proof_data) in outputs {
        let mut task = ProofTask::new(*commitment, proof_data.clone());
        task.id = Some(format!("{}:{}", hex::encode(tx_hash.as_bytes()), idx));
        verifier.add(task);
    }

    verifier.verify_all()
}

/// Aggregated proof verification (verify multiple outputs with one proof)
pub struct AggregatedProofVerifier {
    /// Commitments for aggregated proof
    commitments: Vec<[u8; 32]>,
    /// Aggregated proof data
    proof_data: Option<Vec<u8>>,
}

impl AggregatedProofVerifier {
    /// Create new aggregated verifier
    pub fn new() -> Self {
        AggregatedProofVerifier {
            commitments: Vec::new(),
            proof_data: None,
        }
    }

    /// Add commitment
    pub fn add_commitment(&mut self, commitment: [u8; 32]) {
        self.commitments.push(commitment);
    }

    /// Set proof data
    pub fn set_proof(&mut self, proof: Vec<u8>) {
        self.proof_data = Some(proof);
    }

    /// Verify aggregated proof
    pub fn verify(&self) -> bool {
        use crate::crypto::{RangeProof, PedersenCommitment, verify_range_proofs};

        let proof_data = match &self.proof_data {
            Some(p) => p,
            None => return false,
        };

        if self.commitments.is_empty() {
            return false;
        }

        // Parse proof
        let proof = match RangeProof::from_bytes(proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // SECURITY (A6-COMMITMENT): Use checked deserialization for all commitments
        let commitments: Vec<PedersenCommitment> = match self.commitments.iter()
            .map(|c| PedersenCommitment::from_bytes_checked(*c))
            .collect::<Option<Vec<_>>>() {
            Some(c) => c,
            None => return false, // Invalid commitment bytes detected
        };

        // Verify aggregated proof
        verify_range_proofs(&commitments, &proof)
    }
}

impl Default for AggregatedProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_verifier_empty() {
        let mut verifier = ParallelProofVerifier::new();
        let result = verifier.verify_all();
        assert_eq!(result.total, 0);
        assert!(result.all_valid());
    }

    #[test]
    fn test_proof_task() {
        let task = ProofTask::new([1u8; 32], vec![0u8; 100])
            .with_id("test-proof".into());

        assert_eq!(task.id, Some("test-proof".into()));
        assert_eq!(task.commitment, [1u8; 32]);
    }

    #[test]
    fn test_empty_batch() {
        let mut verifier = ParallelProofVerifier::new();
        let result = verifier.verify_all();
        assert_eq!(result.total, 0);
        assert_eq!(result.valid, 0);
        assert_eq!(result.invalid, 0);
        assert!(result.all_valid(), "Empty batch should be considered valid");
    }
}
