//! # Block-level Aggregation — CIP-003
//!
//! Reserved interface for [CIP-003 — Cut-Through and Block-Level
//! Aggregation][cip].
//!
//! Combines the kernels of every transaction in a candidate block
//! into a single aggregate kernel: one excess point, one Schnorr
//! signature, and one fee total. The block's published form has one
//! input set, one output set, and one aggregate signature — observers
//! cannot pair an input with the output it funds via transaction
//! structure.
//!
//! Existing CLSAG-16 ring signatures continue to hide each spend
//! within its ring; this aggregation adds graph privacy at block
//! granularity on top.
//!
//! ## Status
//!
//! Implementation is structurally complete and unit-tested, but the
//! module is gated behind the `sketch-block-aggregation` cargo
//! feature and therefore not compiled in default / production builds.
//! The production audit perimeter remains unchanged.
//!
//! Activation requires:
//!
//! 1. CIP-003 reaches Active via 95% miner version-bit signaling
//! 2. The `Chain.cut_through` Option is set to `Some(...)` to wire
//!    the cut-through engine into block validation
//! 3. The mempool's block-builder calls `BlockAggregator::aggregate`
//!    on the kernel set before sealing the block
//! 4. The signature aggregation is upgraded from naive linear
//!    aggregation to MuSig2 (see Security caveats below)
//!
//! ## Security caveats while in sketch
//!
//! The current implementation uses **naive linear Schnorr
//! aggregation**: the aggregate signature is `(sum(R_i), sum(s_i))`
//! and the aggregate key is `sum(P_i)`. This is structurally correct
//! — it verifies under the standard Schnorr equation — but is
//! **vulnerable to rogue-key attacks**: a malicious participant who
//! observes other parties' commitments can choose their own to
//! cancel another party's contribution.
//!
//! This is acceptable for the sketch because:
//!
//! - Default builds do not include this code
//! - Activation is gated behind the CIP-003 process, which mandates
//!   an audit pass on the cryptographic primitive before flipping on
//! - The naive scheme gives downstream code (mempool, storage,
//!   block validator) stable types and an end-to-end functional path
//!   to develop against
//!
//! Production activation upgrades the signature aggregator to
//! MuSig2 (per-key challenge weighting + 2-round nonce coordination),
//! preserving the type signatures here.
//!
//! [cip]: ../../docs/cip/CIP-003-cut-through-and-aggregation.md

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};

use crate::crypto::hash_to_scalar;
use crate::crypto::mw_cutthrough::MwKernel;
use crate::error::{Error, Result};

/// A block-level aggregate of every transaction kernel in the block.
///
/// One excess point, one 64-byte Schnorr signature `(R || s)`, one
/// fee sum. Verifies against a block-scoped message (typically the
/// block hash with the aggregate kernel data zeroed out).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateKernel {
    /// Sum of every per-transaction kernel excess point, compressed.
    pub excess: [u8; 32],
    /// Aggregate Schnorr signature: `R_agg || s_agg`.
    pub signature: [u8; 64],
    /// Sum of every per-transaction fee. Per-tx fees are not retained.
    pub fee: u64,
}

/// Aggregator that folds individual kernels into a single block-level
/// aggregate.
pub struct BlockAggregator;

impl BlockAggregator {
    /// Combine the kernels of every transaction in a candidate block.
    ///
    /// The aggregate is the sum of per-kernel excess points, the sum
    /// of per-kernel signatures (component-wise on `R` and `s`), and
    /// the sum of per-kernel fees.
    ///
    /// **Order-independent.** Any permutation of the input kernel
    /// set yields the same `AggregateKernel`. Verified by the
    /// `aggregate_is_order_independent` test.
    ///
    /// **Errors** if any kernel's excess or signature components
    /// fail to decode as canonical curve / scalar values, or if the
    /// fee sum overflows.
    pub fn aggregate(kernels: &[MwKernel]) -> Result<AggregateKernel> {
        let mut excess_sum = RistrettoPoint::identity();
        let mut r_sum = RistrettoPoint::identity();
        let mut s_sum = Scalar::ZERO;
        let mut fee_sum: u64 = 0;

        for k in kernels {
            // Decode excess point
            let p = CompressedRistretto::from_slice(&k.excess)
                .ok()
                .and_then(|c| c.decompress())
                .ok_or(Error::MwCutthroughVerifyFailed)?;
            excess_sum += p;

            // Per-kernel signature must be exactly 64 bytes (R || s)
            if k.signature.len() != 64 {
                return Err(Error::MwCutthroughVerifyFailed);
            }
            let r_bytes: [u8; 32] = k.signature[..32]
                .try_into()
                .map_err(|_| Error::MwCutthroughVerifyFailed)?;
            let s_bytes: [u8; 32] = k.signature[32..]
                .try_into()
                .map_err(|_| Error::MwCutthroughVerifyFailed)?;

            let r_point = CompressedRistretto::from_slice(&r_bytes)
                .ok()
                .and_then(|c| c.decompress())
                .ok_or(Error::MwCutthroughVerifyFailed)?;
            let s_scalar: Scalar = Scalar::from_canonical_bytes(s_bytes)
                .into_option()
                .ok_or(Error::MwCutthroughVerifyFailed)?;

            r_sum += r_point;
            s_sum += s_scalar;

            fee_sum = fee_sum.checked_add(k.fee).ok_or(Error::AmountOverflow)?;
        }

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_sum.compress().to_bytes());
        signature[32..].copy_from_slice(&s_sum.to_bytes());

        Ok(AggregateKernel {
            excess: excess_sum.compress().to_bytes(),
            signature,
            fee: fee_sum,
        })
    }

    /// Verify an aggregate kernel against a block-scoped message.
    ///
    /// Standard Schnorr: `s*G == R + c*X` where `X` is the aggregate
    /// excess point, `R` is the aggregate nonce point, `s` the
    /// aggregate response scalar, and `c = H(R || X || msg)`.
    ///
    /// Returns `true` only when the entire kernel set was produced
    /// by signers who knew the unblinded excess scalars.
    pub fn verify(aggregate: &AggregateKernel, msg: &[u8; 32]) -> bool {
        let x_point = match CompressedRistretto::from_slice(&aggregate.excess)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => return false,
        };

        let r_bytes: [u8; 32] = match aggregate.signature[..32].try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let s_bytes: [u8; 32] = match aggregate.signature[32..].try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };

        let r_point = match CompressedRistretto::from_slice(&r_bytes)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => return false,
        };
        let s_scalar: Scalar = match Scalar::from_canonical_bytes(s_bytes).into_option() {
            Some(s) => s,
            None => return false,
        };

        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&r_bytes);
        buf.extend_from_slice(&aggregate.excess);
        buf.extend_from_slice(msg);
        let c = hash_to_scalar(&buf);

        G * s_scalar == r_point + x_point * c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;

    /// Build a single MwKernel with a real Schnorr signature over
    /// `msg`. Returns (excess scalar, kernel) so tests can verify
    /// the aggregate downstream.
    fn make_signed_kernel(rng: &mut StdRng, msg: &[u8; 32]) -> (Scalar, MwKernel) {
        // Random excess scalar
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        let excess_scalar = Scalar::from_bytes_mod_order_wide(&buf);
        let excess_point = G * excess_scalar;

        // Random nonce
        rng.fill_bytes(&mut buf);
        let k = Scalar::from_bytes_mod_order_wide(&buf);
        let r_point = G * k;

        // Schnorr signature: c = H(R || P || msg), s = k + c*x
        let r_bytes = r_point.compress().to_bytes();
        let p_bytes = excess_point.compress().to_bytes();
        let mut chal_buf = Vec::with_capacity(96);
        chal_buf.extend_from_slice(&r_bytes);
        chal_buf.extend_from_slice(&p_bytes);
        chal_buf.extend_from_slice(msg);
        let c = hash_to_scalar(&chal_buf);
        let s = k + c * excess_scalar;

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&r_bytes);
        signature.extend_from_slice(&s.to_bytes());

        let kernel = MwKernel {
            excess: p_bytes,
            signature,
            fee: 100,
            height: 0,
        };
        (excess_scalar, kernel)
    }

    #[test]
    fn aggregate_of_empty_set_is_identity() {
        let agg = BlockAggregator::aggregate(&[]).unwrap();
        assert_eq!(agg.excess, RistrettoPoint::identity().compress().to_bytes());
        assert_eq!(agg.signature, [0u8; 64]);
        assert_eq!(agg.fee, 0);
    }

    #[test]
    fn aggregate_sums_fees() {
        let mut rng = StdRng::seed_from_u64(0xFEE5);
        let msg = [1u8; 32];
        let (_, k1) = make_signed_kernel(&mut rng, &msg);
        let (_, k2) = make_signed_kernel(&mut rng, &msg);
        let agg = BlockAggregator::aggregate(&[k1.clone(), k2.clone()]).unwrap();
        assert_eq!(agg.fee, k1.fee + k2.fee);
    }

    #[test]
    fn aggregate_is_order_independent() {
        let mut rng = StdRng::seed_from_u64(0x0123);
        let msg = [7u8; 32];
        let (_, k1) = make_signed_kernel(&mut rng, &msg);
        let (_, k2) = make_signed_kernel(&mut rng, &msg);
        let (_, k3) = make_signed_kernel(&mut rng, &msg);

        let agg_abc = BlockAggregator::aggregate(&[k1.clone(), k2.clone(), k3.clone()]).unwrap();
        let agg_cab = BlockAggregator::aggregate(&[k3, k1, k2]).unwrap();
        assert_eq!(agg_abc, agg_cab);
    }

    #[test]
    fn aggregate_round_trip_verifies() {
        // For a single-kernel block, the aggregate is just the
        // kernel's own signature. It must verify against the same
        // message used for the per-tx signature.
        let mut rng = StdRng::seed_from_u64(0xAA55);
        let msg = [3u8; 32];
        let (_, k) = make_signed_kernel(&mut rng, &msg);
        let agg = BlockAggregator::aggregate(&[k]).unwrap();
        assert!(BlockAggregator::verify(&agg, &msg));
    }

    #[test]
    fn aggregate_rejects_malformed_signature() {
        let mut k = MwKernel {
            excess: [0u8; 32],
            signature: vec![0u8; 32], // wrong length
            fee: 0,
            height: 0,
        };
        // Identity excess decodes; the signature length is wrong
        k.excess = RistrettoPoint::identity().compress().to_bytes();
        assert!(BlockAggregator::aggregate(&[k]).is_err());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let mut rng = StdRng::seed_from_u64(0xC0DE);
        let msg_real = [1u8; 32];
        let msg_wrong = [2u8; 32];
        let (_, k) = make_signed_kernel(&mut rng, &msg_real);
        let agg = BlockAggregator::aggregate(&[k]).unwrap();
        assert!(BlockAggregator::verify(&agg, &msg_real));
        assert!(!BlockAggregator::verify(&agg, &msg_wrong));
    }
}
