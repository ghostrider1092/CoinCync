//! Batch signature verification for improved throughput
//!
//! Verifies multiple ring signatures in parallel using rayon.

use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::crypto::cache::{global_cache, ring_sig_statement_cache_key};

/// Result of batch verification
#[derive(Clone, Debug)]
pub struct BatchVerifyResult {
    /// Number of signatures verified
    pub total: usize,
    /// Number valid
    pub valid: usize,
    /// Number invalid
    pub invalid: usize,
    /// Number cached (skipped verification)
    pub cached: usize,
    /// Indices of invalid signatures
    pub invalid_indices: Vec<usize>,
    /// Verification time in milliseconds
    pub time_ms: u64,
}

impl BatchVerifyResult {
    /// Check if all signatures are valid
    pub fn all_valid(&self) -> bool {
        self.invalid == 0
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.valid as f64 / self.total as f64
    }
}

/// Signature data for batch verification
pub struct SignatureData {
    /// Message being signed
    pub message: Vec<u8>,
    /// Serialized signature
    pub signature: Vec<u8>,
    /// Ring members (serialized public keys and commitments)
    pub ring_data: Vec<u8>,
    /// Pseudo output commitment
    pub pseudo_output: [u8; 32],
}

impl SignatureData {
    /// Includes every verification input so a cached result cannot be reused
    /// for a different ring or pseudo-output.
    pub fn cache_key(&self) -> [u8; 32] {
        ring_sig_statement_cache_key(
            &self.message,
            &self.signature,
            &self.ring_data,
            &self.pseudo_output,
        )
    }
}

/// Batch verifier for ring signatures
pub struct BatchVerifier {
    /// Pending signatures to verify
    signatures: Vec<SignatureData>,
    /// Use cache
    use_cache: bool,
    /// Parallel threshold (use parallel if more than this)
    parallel_threshold: usize,
}

impl BatchVerifier {
    /// Create new batch verifier
    pub fn new() -> Self {
        BatchVerifier {
            signatures: Vec::new(),
            use_cache: true,
            parallel_threshold: 4,
        }
    }

    /// Create without caching
    pub fn without_cache() -> Self {
        BatchVerifier {
            signatures: Vec::new(),
            use_cache: false,
            parallel_threshold: 4,
        }
    }

    /// Add signature to batch
    pub fn add(&mut self, sig: SignatureData) {
        self.signatures.push(sig);
    }

    /// Add multiple signatures
    pub fn add_all(&mut self, sigs: Vec<SignatureData>) {
        self.signatures.extend(sigs);
    }

    /// Get pending count
    pub fn pending_count(&self) -> usize {
        self.signatures.len()
    }

    /// Clear pending signatures
    pub fn clear(&mut self) {
        self.signatures.clear();
    }

    /// Verify all signatures in batch
    ///
    /// Uses parallel verification for large batches and caching for speedup.
    pub fn verify_all(&self) -> BatchVerifyResult {
        use std::time::Instant;
        let start = Instant::now();

        if self.signatures.is_empty() {
            return BatchVerifyResult {
                total: 0,
                valid: 0,
                invalid: 0,
                cached: 0,
                invalid_indices: Vec::new(),
                time_ms: 0,
            };
        }

        let cache = if self.use_cache { Some(global_cache()) } else { None };
        let total = self.signatures.len();

        let mut cached_results: Vec<Option<bool>> = Vec::with_capacity(total);
        let mut cached_count = 0usize;

        for sig in &self.signatures {
            if let Some(c) = cache {
                let key = sig.cache_key();
                if let Some(valid) = c.check_ring_sig(&key) {
                    cached_results.push(Some(valid));
                    cached_count += 1;
                    continue;
                }
            }
            cached_results.push(None);
        }

        let verify = |(i, sig): (usize, &SignatureData)| match cached_results[i] {
            Some(valid) => valid,
            None => Self::verify_single(sig),
        };

        let results: Vec<bool> = if total - cached_count > self.parallel_threshold {
            self.signatures.par_iter()
                .enumerate()
                .map(verify)
                .collect()
        } else {
            self.signatures.iter()
                .enumerate()
                .map(verify)
                .collect()
        };

        let mut invalid_indices = Vec::new();

        for (i, is_valid) in results.into_iter().enumerate() {
            if cached_results[i].is_none() {
                if let Some(c) = cache {
                    let key = self.signatures[i].cache_key();
                    c.cache_ring_sig(key, is_valid);
                }
            }

            if !is_valid {
                invalid_indices.push(i);
            }
        }

        let invalid = invalid_indices.len();

        BatchVerifyResult {
            total,
            valid: total - invalid,
            invalid,
            cached: cached_count,
            invalid_indices,
            time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Verify a single signature
    ///
    /// Deserializes the ring data and signature, then calls the actual CLSAG
    /// verification function.
    fn verify_single(sig: &SignatureData) -> bool {
        use crate::crypto::clsag::{ClsagSignature, RingMember, clsag_verify};
        use crate::crypto::curve::Commitment;

        // Parse the signature
        let clsag_sig = match ClsagSignature::from_bytes(&sig.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Parse the ring members from ring_data
        // Ring data format: Vec<RingMember> serialized with borsh
        let ring: Vec<RingMember> = match borsh::from_slice(&sig.ring_data) {
            Ok(r) => r,
            Err(_) => return false,
        };

        if ring.is_empty() {
            return false;
        }

        // Parse pseudo output commitment
        let pseudo_output = match Commitment::from_bytes(sig.pseudo_output) {
            Some(c) => c,
            None => return false,
        };

        // R-29 fix (2026-07-02): defense-in-depth reject identity
        // `pseudo_output`. `Commitment::from_bytes` accepts the identity
        // point (0-encoded compressed Ristretto is a valid decode).
        // If the caller supplies an identity pseudo_output, then in the
        // CLSAG verify's aggregate `mu_c * (C_i - C')`, C' is identity
        // and drops out — collapsing to `mu_c * C_i`. R-1 fixes the
        // clsag_verify side to reject identity `C_i`, but relying on
        // that downstream check is fragile: batch-verify is a
        // second-verification layer used by mempool + block validation
        // where DEFENSIVE early-out is cheaper than trusting the
        // downstream check. Reject at this layer too.
        use curve25519_dalek::traits::Identity;
        use curve25519_dalek::ristretto::RistrettoPoint;
        if pseudo_output.as_point().as_point() == &RistrettoPoint::identity() {
            return false;
        }

        // Call actual CLSAG verification
        clsag_verify(&sig.message, &ring, &pseudo_output, &clsag_sig)
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Parallel transaction validator.
///
/// AUDIT (2026-07-01): removed the `workers: usize` and `_use_cache: bool`
/// fields plus the `with_workers()` builder. Both fields were dead:
///
/// - `workers` was stored on construction but never used. The par_iter()
///   calls below hit rayon's *global* thread pool; the field only fooled
///   callers into thinking `.with_workers(1)` would run single-threaded.
///   Wiring it up correctly would require `rayon::ThreadPoolBuilder` per
///   call, which allocates a fresh pool each time and defeats the point.
///   For anything more nuanced than "use the global pool," callers should
///   build their own scoped pool.
///
/// - `_use_cache` was named with a leading underscore, marking it as
///   deliberately-unread by the compiler-suppression convention, but it
///   still occupied space and lied about a capability the type doesn't
///   have. Batch-level caching lives in `BatchVerifier` (see `use_cache`
///   there), not here.
///
/// The remaining struct is a zero-sized handle whose whole job is to hang
/// two methods off a nameable type — kept because both methods are part
/// of the re-exported crypto surface (`crypto::mod` line 131).
pub struct ParallelTxValidator;

impl ParallelTxValidator {
    /// Create new validator
    pub fn new() -> Self {
        ParallelTxValidator
    }

    /// Validate transactions in parallel
    ///
    /// Returns indices of invalid transactions.
    pub fn validate_transactions<F>(&self, txs: &[crate::transaction::Transaction], validate_fn: F) -> Vec<usize>
    where
        F: Fn(&crate::transaction::Transaction) -> bool + Sync,
    {
        if txs.is_empty() {
            return Vec::new();
        }

        // Parallel validation on rayon's global thread pool.
        let invalid: Vec<usize> = txs.par_iter()
            .enumerate()
            .filter(|(_, tx)| !validate_fn(tx))
            .map(|(i, _)| i)
            .collect();

        invalid
    }

    /// Validate and return valid transactions
    pub fn filter_valid<F>(&self, txs: Vec<crate::transaction::Transaction>, validate_fn: F) -> Vec<crate::transaction::Transaction>
    where
        F: Fn(&crate::transaction::Transaction) -> bool + Sync,
    {
        if txs.is_empty() {
            return Vec::new();
        }

        txs.into_par_iter()
            .filter(|tx| validate_fn(tx))
            .collect()
    }
}

impl Default for ParallelTxValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for batch verification
#[derive(Debug, Default)]
pub struct VerificationStats {
    /// Total verifications
    pub total: AtomicUsize,
    /// Cache hits
    pub cache_hits: AtomicUsize,
    /// Cache misses
    pub cache_misses: AtomicUsize,
    /// Valid signatures
    pub valid: AtomicUsize,
    /// Invalid signatures
    pub invalid: AtomicUsize,
}

impl Clone for VerificationStats {
    fn clone(&self) -> Self {
        VerificationStats {
            total: AtomicUsize::new(self.total.load(Ordering::Relaxed)),
            cache_hits: AtomicUsize::new(self.cache_hits.load(Ordering::Relaxed)),
            cache_misses: AtomicUsize::new(self.cache_misses.load(Ordering::Relaxed)),
            valid: AtomicUsize::new(self.valid.load(Ordering::Relaxed)),
            invalid: AtomicUsize::new(self.invalid.load(Ordering::Relaxed)),
        }
    }
}

impl VerificationStats {
    /// Record a verification
    pub fn record(&self, cached: bool, valid: bool) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if cached {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
        if valid {
            self.valid.fetch_add(1, Ordering::Relaxed);
        } else {
            self.invalid.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        hits as f64 / total as f64
    }

    /// Get snapshot of stats
    pub fn snapshot(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.total.load(Ordering::Relaxed),
            self.cache_hits.load(Ordering::Relaxed),
            self.cache_misses.load(Ordering::Relaxed),
            self.valid.load(Ordering::Relaxed),
            self.invalid.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_signature_data() -> SignatureData {
        use crate::crypto::clsag::{clsag_sign, RingMember};
        use crate::crypto::curve::{Commitment, SecretScalar};
        use rand::rngs::OsRng;

        let secret = SecretScalar::random(&mut OsRng);
        let real_blinding = SecretScalar::random(&mut OsRng);
        let pseudo_blinding = SecretScalar::random(&mut OsRng);
        let real_commitment = Commitment::commit(1_000, &real_blinding);
        let pseudo_output = Commitment::commit(1_000, &pseudo_blinding);
        let blinding_diff =
            SecretScalar::from_scalar(real_blinding.as_scalar() - pseudo_blinding.as_scalar());
        let ring = vec![
            RingMember::new(secret.to_public(), real_commitment),
            RingMember::new(
                SecretScalar::random(&mut OsRng).to_public(),
                Commitment::commit(1_000, &SecretScalar::random(&mut OsRng)),
            ),
        ];
        let message = b"batch cache statement regression".to_vec();
        let signature = clsag_sign(
            &message,
            &ring,
            0,
            &secret,
            &blinding_diff,
            &pseudo_output,
            &mut OsRng,
        )
        .unwrap()
        .to_bytes()
        .unwrap();

        SignatureData {
            message,
            signature,
            ring_data: borsh::to_vec(&ring).unwrap(),
            pseudo_output: pseudo_output.to_bytes(),
        }
    }

    #[test]
    fn test_batch_verify_empty() {
        let verifier = BatchVerifier::new();
        let result = verifier.verify_all();
        assert_eq!(result.total, 0);
        assert!(result.all_valid());
    }

    #[test]
    fn test_batch_result() {
        let result = BatchVerifyResult {
            total: 10,
            valid: 9,
            invalid: 1,
            cached: 3,
            invalid_indices: vec![5],
            time_ms: 100,
        };

        assert!(!result.all_valid());
        assert!((result.success_rate() - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_parallel_validator() {
        // Empty input path must return an empty vec without touching rayon.
        // Post-2026-07-01: ParallelTxValidator is a zero-sized handle;
        // there's nothing else to introspect here.
        let validator = ParallelTxValidator::new();
        let invalid = validator.validate_transactions(&[], |_| true);
        assert!(invalid.is_empty());
    }

    #[test]
    fn test_concurrent_batch() {
        let mut verifier = BatchVerifier::without_cache();

        // Add 12 dummy signatures (all will fail verification, testing the batch pipeline)
        for i in 0..12 {
            verifier.add(SignatureData {
                message: format!("msg-{}", i).into_bytes(),
                signature: vec![0u8; 64],
                ring_data: vec![0u8; 32],
                pseudo_output: [0u8; 32],
            });
        }

        assert_eq!(verifier.pending_count(), 12);
        let result = verifier.verify_all();
        assert_eq!(result.total, 12);
        // All should be processed (invalid since they're dummy data)
        assert_eq!(result.valid + result.invalid, 12);
    }

    #[test]
    fn cache_does_not_reuse_result_for_different_pseudo_output() {
        let valid = valid_signature_data();
        let cached_message = valid.message.clone();
        let cached_signature = valid.signature.clone();
        let cached_ring = valid.ring_data.clone();
        let cached_pseudo_output = valid.pseudo_output;

        let mut first = BatchVerifier::new();
        first.add(valid);
        let first_result = first.verify_all();
        assert_eq!(first_result.valid, 1);
        assert_eq!(first_result.cached, 0);

        let mut different_statement = BatchVerifier::new();
        different_statement.add(SignatureData {
            message: cached_message.clone(),
            signature: cached_signature.clone(),
            ring_data: cached_ring.clone(),
            pseudo_output: cached_pseudo_output,
        });
        different_statement.add(SignatureData {
            message: cached_message,
            signature: cached_signature,
            ring_data: cached_ring,
            pseudo_output: [0u8; 32],
        });
        let second_result = different_statement.verify_all();

        assert_eq!(second_result.cached, 1);
        assert_eq!(second_result.valid, 1);
        assert_eq!(second_result.invalid, 1);
        assert_eq!(second_result.invalid_indices, vec![1]);
    }
}
