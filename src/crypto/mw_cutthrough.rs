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

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use serde::{Deserialize, Serialize};

use crate::constants::MW_CUTTHROUGH_DEPTH;
use crate::error::{Error, Result};

/// Approximate serialized size of a kernel, in bytes. Used by the
/// cut-through engine to estimate disk savings (32-byte excess + ~64
/// bytes signature).
pub const MW_KERNEL_SIZE: usize = 96;

/// A MimbleWimble transaction kernel: the part of a transaction that
/// survives cut-through pruning.
///
/// AUDIT (R-31 note, 2026-07-02): the `excess` field is a raw
/// `[u8; 32]` — the type system does NOT validate that the bytes
/// decode to a canonical Ristretto point. Deserialization from
/// `borsh`/`serde` will accept ANY 32-byte string, including
/// non-canonical encodings. Validation is DEFERRED to the caller
/// via `MwKernel::excess_point()`, which decompresses and returns
/// `None` on failure. Consensus paths that use this kernel
/// (cut-through commit, kernel-set aggregation) MUST call
/// `excess_point()` and short-circuit on `None` before treating
/// the kernel as spendable. Failing to validate at this layer
/// admits kernels that survive gossip + storage but fail
/// aggregation later, potentially causing a partition where some
/// nodes accepted the kernel and others rejected it.
///
/// A future audit iteration should introduce a `ValidatedMwKernel`
/// newtype whose constructor runs the decompression check,
/// eliminating the per-caller discipline. Deferred because it
/// changes the on-wire type and requires migration for existing
/// stored kernels.
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct MwKernel {
    /// Excess commitment `excess * G` serialized as a compressed Ristretto
    /// point. Proves the transaction was balanced without the inputs or
    /// outputs being present.
    ///
    /// NOT VALIDATED at deserialization — call [`MwKernel::excess_point`]
    /// before using the kernel in consensus code.
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

    /// R-31 SURGICAL FIX (2026-07-03): validate + upgrade to a
    /// `ValidatedMwKernel`. Consensus paths MUST call this and
    /// operate on the returned newtype rather than the raw
    /// `MwKernel`. The type system then structurally guarantees
    /// that no downstream fn accepts an unvalidated kernel.
    pub fn validate(self) -> Option<ValidatedMwKernel> {
        // Run every documented validation predicate for MwKernel.
        // For v1.0 that's:
        //   - `excess` decodes to a canonical Ristretto point.
        // (fee / height / signature are validated separately by the
        // consensus rules that consume the ValidatedMwKernel; the
        // newtype is a proof-of-having-checked-the-basic-shape.)
        let _pt = self.excess_point()?;
        Some(ValidatedMwKernel { inner: self })
    }
}

/// A `MwKernel` whose `excess` field has been proven to decode to
/// a canonical Ristretto point. Only constructible via
/// [`MwKernel::validate`]. Consensus code should accept this type
/// instead of the raw `MwKernel` where the excess-canonicity
/// invariant matters.
///
/// AUDIT (R-31 surgical fix, 2026-07-03): the pre-fix contract was
/// "callers MUST call excess_point() before treating as spendable"
/// — pure discipline, no type-level enforcement, and easy to
/// forget. The newtype eliminates the discipline requirement.
#[derive(Debug, Clone)]
pub struct ValidatedMwKernel {
    inner: MwKernel,
}

impl ValidatedMwKernel {
    /// Borrow the underlying raw kernel. Consensus writers can
    /// safely persist this — the invariant survives serialization
    /// because the excess-bytes are unchanged on the wire; the
    /// downstream READER must call `validate()` again when it
    /// re-loads from disk to re-establish the newtype.
    pub fn as_kernel(&self) -> &MwKernel {
        &self.inner
    }

    /// Consume and return the raw kernel.
    pub fn into_kernel(self) -> MwKernel {
        self.inner
    }

    /// Cached decompressed excess point. Guaranteed to succeed
    /// because construction of `ValidatedMwKernel` proves it.
    pub fn excess_point(&self) -> RistrettoPoint {
        // Unwrap is safe by construction — `validate` returned
        // Some only when this decode succeeded.
        self.inner.excess_point().expect(
            "R-31: ValidatedMwKernel invariant broken — excess bytes changed after validate()",
        )
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

    /// Verify a kernel set. Two independent checks, both required:
    ///
    /// 1. **Per-kernel excess signature** — each kernel must prove
    ///    knowledge of the blinding `x` where `excess = x*G + fee*H`
    ///    (see [`verify_kernel_signature`]). This is what makes the
    ///    aggregate check below sound: without it, kernels can carry
    ///    canceling `±v*H` components that hide value creation while the
    ///    sum still lands on `fee_sum*H`.
    /// 2. **Aggregate balance** — `sum(kernel.excess) == sum(fees) * H`.
    ///    Per Grin, the pruned kernel set's cumulative excess must commit
    ///    to the total fee on the value generator `H` (the blinding
    ///    components cancel across a balanced set).
    ///
    /// Any kernel whose excess fails to decompress, or whose signature is
    /// missing/invalid, rejects the whole set.
    pub fn verify_kernel_set(kernels: &[MwKernel]) -> Result<()> {
        // sum(excess_points)
        let mut excess_sum = RistrettoPoint::identity();
        let mut fee_sum: u64 = 0;
        for k in kernels {
            let p = k
                .excess_point()
                .ok_or_else(|| Error::MwCutthroughVerifyFailed)?;
            // Per-kernel soundness: reject any kernel that cannot prove its
            // excess is fee*H plus a pure blinding it knows the key to.
            if !verify_kernel_signature(k) {
                return Err(Error::MwCutthroughVerifyFailed);
            }
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
            compression_ratio: if total == 0 {
                0.0
            } else {
                self.bytes_saved as f64 / total as f64
            },
        }
    }
}

impl Default for CutThroughEngine {
    fn default() -> Self {
        Self::new()
    }
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
pub fn compute_kernel_excess(output_blindings: &[Scalar], input_blindings: &[Scalar]) -> [u8; 32] {
    let out_sum: Scalar = output_blindings.iter().sum();
    let in_sum: Scalar = input_blindings.iter().sum();
    let excess = out_sum - in_sum;
    (G * excess).compress().to_bytes()
}

// ─── Kernel excess signature ───────────────────────────────────────────
//
// SOUNDNESS FIX (kernel excess-signature verification): a kernel's public
// excess is `excess = x*G + fee*H`, where `x` is the pure blinding-factor
// difference `sum(r_out) - sum(r_in)` and `fee` is the declared fee. The
// signature proves the signer knows `x` — i.e. that `excess - fee*H` is a
// pure `x*G` point with NO hidden value on `H`.
//
// Without this proof, `verify_kernel_set` (which only checks the aggregate
// `sum(excess) == sum(fee)*H`) admits inflation: two kernels can carry
// `+v*H` and `-v*H` components that cancel in the aggregate while each
// hides value creation. Requiring a G-based Schnorr signature over
// `excess - fee*H` makes any residual `H` component unsignable, so each
// kernel individually proves it created no value beyond its stated fee.
//
// Feature-gated (`sketch-cut-through`, off by default) and inert
// (`register_cut_through_candidate` has no production caller) — no v1.0
// activation impact. Hand-rolled Schnorr: needs external review before the
// cut-through feature is ever turned on.

const KERNEL_SIG_NONCE_TAG: &[u8] = b"coincync/mw-kernel-nonce/v1";
const KERNEL_SIG_CHALLENGE_TAG: &[u8] = b"coincync/mw-kernel-sig/v1";

fn kernel_scalar_from(tag: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    for p in parts {
        hasher.update(p);
    }
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Fiat-Shamir challenge for a kernel signature. Binds the nonce point,
/// the public key `P = excess - fee*H`, and the fee/height so a signature
/// can never be lifted onto a kernel with a different fee or height.
fn kernel_sig_challenge(r_point: &RistrettoPoint, pubkey: &RistrettoPoint, fee: u64, height: u64) -> Scalar {
    kernel_scalar_from(
        KERNEL_SIG_CHALLENGE_TAG,
        &[
            r_point.compress().as_bytes(),
            pubkey.compress().as_bytes(),
            &fee.to_le_bytes(),
            &height.to_le_bytes(),
        ],
    )
}

/// Deterministic (RFC-6979-style) nonce so signing needs no RNG and can't
/// reuse a nonce across distinct messages.
fn kernel_sig_nonce(blinding_excess: &Scalar, fee: u64, height: u64) -> Scalar {
    kernel_scalar_from(
        KERNEL_SIG_NONCE_TAG,
        &[
            blinding_excess.as_bytes(),
            &fee.to_le_bytes(),
            &height.to_le_bytes(),
        ],
    )
}

/// Sign a kernel: prove knowledge of the blinding excess `x` where the
/// kernel's public excess is `x*G + fee*H`. Returns a 64-byte `R || s`
/// Schnorr signature over base `G`.
pub fn sign_kernel(blinding_excess: &Scalar, fee: u64, height: u64) -> Vec<u8> {
    let pubkey = G * blinding_excess; // P = x*G  (= excess - fee*H)
    let k = kernel_sig_nonce(blinding_excess, fee, height);
    let r_point = G * k;
    let e = kernel_sig_challenge(&r_point, &pubkey, fee, height);
    let s = k + e * blinding_excess;
    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(r_point.compress().as_bytes());
    sig.extend_from_slice(s.as_bytes());
    sig
}

/// Verify a kernel's excess signature: recompute the public key
/// `P = excess - fee*H` and check the Schnorr equation `s*G == R + e*P`.
/// Returns `false` on any malformed field. A residual `H` component in the
/// excess makes `P` un-signable over base `G`, so this rejects value
/// inflation hidden in the excess.
pub fn verify_kernel_signature(kernel: &MwKernel) -> bool {
    let excess = match kernel.excess_point() {
        Some(p) => p,
        None => return false,
    };
    if kernel.signature.len() != 64 {
        return false;
    }
    let h = crate::crypto::curve::generator_h();
    let pubkey = excess - h * Scalar::from(kernel.fee); // should be x*G

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&kernel.signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&kernel.signature[32..]);

    let r_point = match CompressedRistretto(r_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };
    let s: Scalar = match Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) {
        Some(s) => s,
        None => return false,
    };

    let e = kernel_sig_challenge(&r_point, &pubkey, kernel.fee, kernel.height);
    G * s == r_point + pubkey * e
}

/// Build a fully-signed kernel from the transaction's output/input
/// blinding factors, fee, and height. The public excess is
/// `x*G + fee*H` with `x = sum(r_out) - sum(r_in)`, and the signature
/// proves knowledge of `x`.
pub fn build_signed_kernel(
    output_blindings: &[Scalar],
    input_blindings: &[Scalar],
    fee: u64,
    height: u64,
) -> MwKernel {
    let out_sum: Scalar = output_blindings.iter().sum();
    let in_sum: Scalar = input_blindings.iter().sum();
    let blinding_excess = out_sum - in_sum; // x
    let h = crate::crypto::curve::generator_h();
    let excess_point = G * blinding_excess + h * Scalar::from(fee); // x*G + fee*H
    let signature = sign_kernel(&blinding_excess, fee, height);
    MwKernel {
        excess: excess_point.compress().to_bytes(),
        signature,
        fee,
        height,
    }
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
        // Zero-fee, zero-blinding kernels: excess = identity, fee = 0.
        // Each carries a valid signature (x = 0). sum(identity) == 0*H.
        let kernels = vec![
            build_signed_kernel(&[], &[], 0, 1),
            build_signed_kernel(&[], &[], 0, 2),
        ];
        assert!(CutThroughEngine::verify_kernel_set(&kernels).is_ok());
    }

    #[test]
    fn verify_kernel_set_balanced_with_fee_pass() {
        // A balanced kernel: excess = fee*H (x = 0), valid signature.
        // sum(excess) == fee*H. Passes both signature + balance checks.
        let kernels = vec![build_signed_kernel(&[], &[], 42, 1)];
        assert!(CutThroughEngine::verify_kernel_set(&kernels).is_ok());
    }

    #[test]
    fn verify_kernel_set_unbalanced_fails() {
        // A correctly-SIGNED kernel whose blinding excess is non-zero
        // (x != 0). Its signature is valid, but sum(excess) = x*G != 0*H,
        // so the aggregate balance check rejects it.
        let x = random_scalar();
        let kernel = build_signed_kernel(&[x], &[], 0, 1);
        assert!(verify_kernel_signature(&kernel), "sig itself must be valid");
        assert!(CutThroughEngine::verify_kernel_set(&[kernel]).is_err());
    }

    #[test]
    fn verify_kernel_set_rejects_unsigned_kernel() {
        // A balancing kernel (excess = fee*H) with NO signature must be
        // rejected — this is exactly the case the pre-fix verifier accepted.
        use crate::crypto::curve::generator_h;
        let fee: u64 = 42;
        let kernel = MwKernel {
            excess: (generator_h() * Scalar::from(fee)).compress().to_bytes(),
            signature: vec![], // unsigned
            fee,
            height: 1,
        };
        assert!(CutThroughEngine::verify_kernel_set(&[kernel]).is_err());
    }

    #[test]
    fn verify_kernel_set_rejects_hidden_value_inflation() {
        // The inflation attack the signature closes: two kernels carrying
        // canceling +v*H / -v*H components. Their excesses still SUM to
        // fee_sum*H (so the aggregate balance check alone would pass), but
        // each hides value creation. Neither can be signed (excess - fee*H
        // has an H component with no G discrete log), so verification fails.
        use crate::crypto::curve::generator_h;
        let h = generator_h();
        let hidden = Scalar::from(5u64); // smuggled value
        let (fee_a, fee_b) = (10u64, 20u64);

        // excess_a = (fee_a + hidden)*H ; excess_b = (fee_b - hidden)*H
        let excess_a = h * (Scalar::from(fee_a) + hidden);
        let excess_b = h * (Scalar::from(fee_b) - hidden);

        // Document that the aggregate balance equation DOES hold — i.e. the
        // old check would have been fooled.
        let fee_sum = fee_a + fee_b;
        assert_eq!(
            (excess_a + excess_b).compress(),
            (h * Scalar::from(fee_sum)).compress(),
            "crafted kernels balance in aggregate (old check passes)"
        );

        let kernels = vec![
            MwKernel {
                excess: excess_a.compress().to_bytes(),
                signature: vec![], // no valid signature can exist for this excess
                fee: fee_a,
                height: 1,
            },
            MwKernel {
                excess: excess_b.compress().to_bytes(),
                signature: vec![],
                fee: fee_b,
                height: 2,
            },
        ];
        assert!(
            CutThroughEngine::verify_kernel_set(&kernels).is_err(),
            "hidden-value inflation MUST be rejected by the excess signature"
        );
    }

    #[test]
    fn sign_verify_kernel_roundtrip() {
        // A signed kernel verifies; tampering fee or signature breaks it.
        let x = random_scalar();
        let kernel = build_signed_kernel(&[x], &[], 7, 5);
        assert!(verify_kernel_signature(&kernel));

        // Wrong fee → challenge/pubkey mismatch → reject.
        let mut bad_fee = kernel.clone();
        bad_fee.fee = 8;
        assert!(!verify_kernel_signature(&bad_fee));

        // Flipped signature byte → reject.
        let mut bad_sig = kernel.clone();
        bad_sig.signature[0] ^= 0x01;
        assert!(!verify_kernel_signature(&bad_sig));

        // Truncated signature → reject.
        let mut short_sig = kernel.clone();
        short_sig.signature.truncate(63);
        assert!(!verify_kernel_signature(&short_sig));
    }
}
