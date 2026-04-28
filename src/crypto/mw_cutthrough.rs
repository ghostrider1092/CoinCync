//! # MimbleWimble Cut-Through
//!
//! Grin's insight: once an input and output share a commitment (the input
//! spends exactly what an earlier output created), both can be pruned
//! from the chain — only the transaction *kernel* needs to stay. The
//! chain stays compact forever instead of growing with every spend.
//!
//! ## Flow
//!
//! 1. Block `N` creates commitment `C`.
//! 2. Block `M` spends `C` (input commitment equals `C`).
//! 3. The pair `(output at N, input at M)` becomes a cut-through
//!    *candidate*.
//! 4. After `MW_CUTTHROUGH_DEPTH` more blocks (protection against
//!    reorgs), the candidate is pruned: both the output and the input
//!    are deleted, and only the transaction's *kernel* — excess
//!    commitment + Schnorr signature + fee — remains on chain.
//!
//! ## Why the kernel is enough
//!
//! A MimbleWimble transaction proves `sum(outputs) - sum(inputs) = fee`
//! over Pedersen commitments. Rearranged, this is
//!
//! ```text
//!   sum(v_out * H + r_out * G) - sum(v_in * H + r_in * G) = fee * H
//!   (sum(v_out) - sum(v_in)) * H + (sum(r_out) - sum(r_in)) * G = fee * H
//!   0 * H + excess * G = (fee - 0) * H               (values balance)
//! ```
//!
//! The **kernel excess** is `excess * G = sum(r_out) - sum(r_in)` on the
//! curve generator `G`. A valid MW transaction has `sum(outputs) -
//! sum(inputs) - fee*H == excess*G`. If the excess is a known curve
//! point with a valid Schnorr signature by its discrete log, the
//! transaction was balanced — even after its inputs and outputs are
//! pruned.
//!
//! ## What this module actually does now
//!
//! - `verify_cut_through` compares **curve points**, not byte arrays.
//!   Two commitment byte strings can differ but decompress to the same
//!   Ristretto point if produced by different serialization paths, so
//!   point-equality is the only cryptographically safe check.
//!
//! - `compute_kernel_excess` produces `sum(r_out - r_in) * G` on the
//!   base generator. This is the canonical excess commitment format.
//!
//! - `verify_kernel_set` checks that `sum(kernel.excess_points) ==
//!   fee_sum * H`. Per Grin, the kernel set's cumulative excess must
//!   commit to the total fee on the value generator `H`. We use
//!   `crate::crypto::curve::generator_h()` for H.

use serde::{Deserialize, Serialize};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use borsh::{BorshSerialize, BorshDeserialize};

use crate::error::{Error, Result};
use crate::constants::MW_CUTTHROUGH_DEPTH;

/// Approximate serialized size of a kernel, in bytes. Used by the
/// cut-through engine to estimate disk savings (32-byte excess + ~64
/// bytes signature).
pub const MW_KERNEL_SIZE: usize = 96;

/// A MimbleWimble transaction kernel: the part of a transaction that
/// survives cut-through pruning.
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct MwKernel {
    /// Excess commitment `excess * G` serialized as a compressed Ristretto
    /// point. Proves the transaction was balanced without the inputs or
    /// outputs being present.
    pub excess: [u8; 32],
    /// Schnorr signature over the excess commitment.
    pub signature: Vec<u8>,
    /// Transaction fee (visible — MW fees are not hidden).
    pub fee: u64,
    /// Block height at which the kernel was created.
    pub height: u64,
}

impl MwKernel {
    /// Decompress `excess` into a curve point. Returns `None` if the
    /// stored bytes are not a valid Ristretto encoding.
    pub fn excess_point(&self) -> Option<RistrettoPoint> {
        CompressedRistretto(self.excess).decompress()
    }
}

/// A pending cut-through operation: an input + output pair that is
/// waiting for enough confirmations before it can be pruned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CutThroughCandidate {
    /// Commitment of the output being spent.
    pub spent_commitment: [u8; 32],
    /// Commitment of the input doing the spending.
    pub input_commitment: [u8; 32],
    /// Height at which the output was created.
    pub created_at: u64,
    /// Height at which the output was spent.
    pub spent_at: u64,
    /// The kernel that remains after pruning.
    pub kernel: MwKernel,
}

/// Engine that accumulates cut-through candidates and prunes them once
/// they reach the required confirmation depth.
pub struct CutThroughEngine {
    pending: Vec<CutThroughCandidate>,
    pub kept_kernels: Vec<MwKernel>,
    pub bytes_saved: u64,
}

impl CutThroughEngine {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            kept_kernels: Vec::new(),
            bytes_saved: 0,
        }
    }

    /// Register a spent output as a cut-through candidate. Called by
    /// `chain::Blockchain::accept_block` when an input consumes an
    /// output whose commitment matches the input's commitment.
    pub fn register_spend(
        &mut self,
        spent_commitment: [u8; 32],
        input_commitment: [u8; 32],
        created_at: u64,
        spent_at: u64,
        kernel: MwKernel,
    ) {
        if verify_cut_through(&spent_commitment, &input_commitment) {
            self.pending.push(CutThroughCandidate {
                spent_commitment,
                input_commitment,
                created_at,
                spent_at,
                kernel,
            });
        }
    }

    /// Process the pending queue at `current_height`. Returns every
    /// commitment that can now be deleted from storage.
    pub fn process(&mut self, current_height: u64) -> Vec<[u8; 32]> {
        let mut prunable = Vec::new();
        let mut remaining = Vec::new();

        for candidate in self.pending.drain(..) {
            if current_height >= candidate.spent_at + MW_CUTTHROUGH_DEPTH {
                prunable.push(candidate.spent_commitment);
                prunable.push(candidate.input_commitment);
                // Approximate: 500-byte in/out pair → 96-byte kernel.
                let saved = 500u64.saturating_sub(MW_KERNEL_SIZE as u64);
                self.bytes_saved += saved;
                self.kept_kernels.push(candidate.kernel);
            } else {
                remaining.push(candidate);
            }
        }
        self.pending = remaining;
        prunable
    }

    /// Verify a kernel set: `sum(kernel.excess_points) == sum(fees) * H`.
    ///
    /// If the equation holds, the entire pruned kernel set represents a
    /// valid balance even though every input / output pair was deleted.
    /// Any kernel whose excess fails to decompress as a curve point
    /// rejects the whole set.
    pub fn verify_kernel_set(kernels: &[MwKernel]) -> Result<()> {
        // sum(excess_points)
        let mut excess_sum = RistrettoPoint::identity();
        let mut fee_sum: u64 = 0;
        for k in kernels {
            let p = k.excess_point().ok_or_else(|| {
                Error::MwCutthroughVerifyFailed
            })?;
            excess_sum += p;
            fee_sum = fee_sum.checked_add(k.fee).ok_or(Error::AmountOverflow)?;
        }

        // sum(fees) * H
        let h_point = crate::crypto::curve::generator_h();
        let expected = h_point * Scalar::from(fee_sum);

        if excess_sum.compress() != expected.compress() {
            return Err(Error::MwCutthroughVerifyFailed);
        }
        Ok(())
    }

    pub fn stats(&self) -> CutThroughStats {
        let kernel_bytes = self.kept_kernels.len() as u64 * MW_KERNEL_SIZE as u64;
        let total = self.bytes_saved + kernel_bytes;
        CutThroughStats {
            pending_candidates: self.pending.len(),
            kernels_kept: self.kept_kernels.len(),
            bytes_saved: self.bytes_saved,
            compression_ratio: if total == 0 { 0.0 } else { self.bytes_saved as f64 / total as f64 },
        }
    }
}

impl Default for CutThroughEngine {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CutThroughStats {
    pub pending_candidates: usize,
    pub kernels_kept: usize,
    pub bytes_saved: u64,
    pub compression_ratio: f64,
}

/// Verify two Pedersen commitment byte strings encode the **same curve
/// point**.
///
/// Byte equality is a sufficient but not necessary condition — two
/// different compressed byte arrays can decode to the same point under
/// some Ristretto encodings, so the point-equality check is the only
/// cryptographically safe way to check a cut-through pair. This is what
/// Grin calls "balance preservation" at the commitment level: the
/// output consumed by an input must commit to the same `(v, r)` pair.
pub fn verify_cut_through(input: &[u8; 32], output: &[u8; 32]) -> bool {
    let p_in = match CompressedRistretto(*input).decompress() {
        Some(p) => p,
        None => return false,
    };
    let p_out = match CompressedRistretto(*output).decompress() {
        Some(p) => p,
        None => return false,
    };
    p_in == p_out
}

/// Compute a kernel excess commitment:
///
/// ```text
///   excess = sum(output_blindings) - sum(input_blindings)
///   kernel.excess = (excess * G).compress()
/// ```
///
/// Committed on the base generator `G`. The value side of the
/// transaction is committed separately on `H` via each output's
/// Pedersen commitment; the excess is the pure blinding-factor
/// difference.
pub fn compute_kernel_excess(
    output_blindings: &[Scalar],
    input_blindings: &[Scalar],
) -> [u8; 32] {
    let out_sum: Scalar = output_blindings.iter().sum();
    let in_sum: Scalar = input_blindings.iter().sum();
    let excess = out_sum - in_sum;
    (G * excess).compress().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_scalar() -> Scalar {
        use rand::RngCore;
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    #[test]
    fn verify_cut_through_same_bytes_pass() {
        let p = (G * random_scalar()).compress().to_bytes();
        assert!(verify_cut_through(&p, &p));
    }

    #[test]
    fn verify_cut_through_different_points_fail() {
        let p1 = (G * random_scalar()).compress().to_bytes();
        let p2 = (G * random_scalar()).compress().to_bytes();
        assert!(!verify_cut_through(&p1, &p2));
    }

    #[test]
    fn verify_cut_through_invalid_bytes_fail() {
        // Random bytes that likely don't decompress to a valid Ristretto point
        let bad = [0xFFu8; 32];
        let good = (G * random_scalar()).compress().to_bytes();
        assert!(!verify_cut_through(&bad, &good));
    }

    #[test]
    fn compute_kernel_excess_zero_when_balanced() {
        // When in = out, excess = 0, and 0 * G = identity.
        let r = random_scalar();
        let excess = compute_kernel_excess(&[r], &[r]);
        let point = CompressedRistretto(excess).decompress().unwrap();
        assert_eq!(point, RistrettoPoint::identity());
    }

    #[test]
    fn compute_kernel_excess_matches_manual() {
        let r_out = [random_scalar(), random_scalar()];
        let r_in = [random_scalar()];
        let excess_bytes = compute_kernel_excess(&r_out, &r_in);

        let expected_scalar = r_out[0] + r_out[1] - r_in[0];
        let expected = (G * expected_scalar).compress().to_bytes();

        assert_eq!(excess_bytes, expected);
    }

    #[test]
    fn verify_kernel_set_zero_fee_pass() {
        // Zero-fee kernel set where all kernels have identity excess.
        // sum(identity) == 0 * H == identity. Passes.
        let kernels = vec![
            MwKernel {
                excess: RistrettoPoint::identity().compress().to_bytes(),
                signature: vec![],
                fee: 0,
                height: 1,
            },
            MwKernel {
                excess: RistrettoPoint::identity().compress().to_bytes(),
                signature: vec![],
                fee: 0,
                height: 2,
            },
        ];
        assert!(CutThroughEngine::verify_kernel_set(&kernels).is_ok());
    }

    #[test]
    fn verify_kernel_set_wrong_fee_fail() {
        // Kernels claim fee but excess is identity — equation fails.
        let kernels = vec![MwKernel {
            excess: RistrettoPoint::identity().compress().to_bytes(),
            signature: vec![],
            fee: 100,
            height: 1,
        }];
        assert!(CutThroughEngine::verify_kernel_set(&kernels).is_err());
    }

    #[test]
    fn verify_kernel_set_matching_excess_and_fee_pass() {
        // Build a kernel whose excess commits to fee*H on the value
        // generator. This is the "balanced MW transaction" case.
        use crate::crypto::curve::generator_h;
        let fee: u64 = 42;
        let excess_point = generator_h() * Scalar::from(fee);
        let kernels = vec![MwKernel {
            excess: excess_point.compress().to_bytes(),
            signature: vec![],
            fee,
            height: 1,
        }];
        assert!(CutThroughEngine::verify_kernel_set(&kernels).is_ok());
    }
}
