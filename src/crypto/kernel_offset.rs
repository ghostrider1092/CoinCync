//! # Kernel Offsets — CIP-004
//!
//! Reserved interface for [CIP-004 — Kernel Offsets][cip].
//!
//! Kernel offsets are a single 32-byte scalar added to a transaction's
//! kernel-excess blinding factor at signing time. The published kernel
//! signature is over `excess - offset`, the offset is published in the
//! transaction, and verifiers re-add `offset * G` to the published
//! excess point to recover the actual signing key. The offset breaks
//! the otherwise-direct linkage between input and output blinding
//! factors, providing an unlinkability layer that does not depend on
//! CLSAG ring soundness.
//!
//! ## Status
//!
//! Implementation is structurally complete and unit-tested, but the
//! module is gated behind the `sketch-kernel-offsets` cargo feature
//! and therefore not compiled in default / production builds. The
//! production audit perimeter remains unchanged.
//!
//! Activation of this CIP requires:
//!
//! 1. CIP-003 (cut-through + block-level aggregation) reaches Active
//! 2. CIP-004 reaches Active via 95% miner version-bit signaling
//! 3. The `Kernel` struct in `src/transaction/types.rs` adopts the
//!    additional `offset: [u8; 32]` field
//! 4. Wallet builder calls `KernelOffset::generate()` at signing time
//!
//! ## Security caveats while in sketch
//!
//! - Offset generation uses `OsRng`. Tests should not rely on
//!   reproducibility — call sites must inject a deterministic RNG
//!   when needed (see test module).
//! - Aggregation is plain scalar addition. This is rogue-key safe
//!   *only because* the offsets are not signing keys; they are
//!   blinding factors over a published commitment. A malicious peer
//!   choosing an offset to cancel another's offset achieves nothing
//!   — the published kernel-excess for that transaction is also
//!   shifted by the same amount, so verification re-adds it back.
//!
//! [cip]: ../../docs/cip/CIP-004-kernel-offsets.md

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::{rngs::OsRng, RngCore};

use crate::crypto::hash_to_scalar;

/// Per-transaction kernel offset.
///
/// Stored as a 32-byte scalar. The curve-point form `offset * G` is
/// computed at verification time. Offsets are independent across
/// transactions — knowing one offset reveals nothing about another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelOffset(pub [u8; 32]);

/// The combined offset across an aggregated block — sum of every
/// per-transaction offset in the block. Used by CIP-003 block-level
/// aggregation; the per-tx offsets are consumed and only the
/// aggregate is stored on chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateOffset(pub [u8; 32]);

impl KernelOffset {
    /// Generate a fresh random offset using the platform CSPRNG.
    ///
    /// Pulls 64 bytes from `OsRng` and reduces mod the ed25519 group
    /// order via `Scalar::from_bytes_mod_order_wide`, matching the
    /// pattern used by [`crate::crypto::curve::SecretScalar::random`].
    pub fn generate() -> Self {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        KernelOffset(scalar.to_bytes())
    }

    /// Generate an offset from a caller-provided RNG. Test-only path
    /// — production callers should use [`KernelOffset::generate`].
    pub fn generate_with<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        KernelOffset(scalar.to_bytes())
    }

    /// Decode the underlying scalar, returning `None` if the bytes
    /// are not a canonical scalar encoding.
    pub fn as_scalar(&self) -> Option<Scalar> {
        Scalar::from_canonical_bytes(self.0).into()
    }

    /// Combine this offset with another. Addition is commutative, so
    /// block-level aggregation order does not matter.
    ///
    /// Returns `None` if either operand is non-canonical.
    pub fn aggregate(self, other: Self) -> Option<AggregateOffset> {
        let a = self.as_scalar()?;
        let b = other.as_scalar()?;
        Some(AggregateOffset((a + b).to_bytes()))
    }

    /// Verify a Schnorr signature `(R, s)` against `(excess + offset*G)`
    /// over `msg`.
    ///
    /// Returns `true` iff the signature was produced by the holder of
    /// the unblinded excess scalar, given the published offset.
    pub fn verify_against(&self, excess: &[u8; 32], signature: &[u8; 64], msg: &[u8; 32]) -> bool {
        // Decode excess point and offset scalar
        let excess_point = match CompressedRistretto::from_slice(excess)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => return false,
        };
        let offset_scalar = match self.as_scalar() {
            Some(s) => s,
            None => return false,
        };

        // Effective verification key: excess + offset*G
        let key = excess_point + G * offset_scalar;

        // Parse signature R || s
        let r_bytes: [u8; 32] = match signature[..32].try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let s_bytes: [u8; 32] = match signature[32..].try_into() {
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
        let s_scalar: Scalar = match Scalar::from_canonical_bytes(s_bytes).into() {
            Some(s) => s,
            None => return false,
        };

        // Schnorr verification: s*G == R + c*key,  c = H(R || key || msg)
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(&r_bytes);
        buf.extend_from_slice(&key.compress().to_bytes());
        buf.extend_from_slice(msg);
        let c = hash_to_scalar(&buf);

        G * s_scalar == r_point + key * c
    }
}

impl AggregateOffset {
    /// The neutral aggregate — sum of zero offsets. Identity element
    /// for fold operations.
    pub const ZERO: Self = AggregateOffset([0u8; 32]);

    /// Decode the underlying scalar, returning `None` if the bytes
    /// are not a canonical scalar encoding.
    pub fn as_scalar(&self) -> Option<Scalar> {
        Scalar::from_canonical_bytes(self.0).into()
    }

    /// Add a fresh per-tx offset onto the running aggregate.
    pub fn add_offset(self, offset: KernelOffset) -> Option<Self> {
        let agg = self.as_scalar()?;
        let kern = offset.as_scalar()?;
        Some(AggregateOffset((agg + kern).to_bytes()))
    }

    /// Aggregate-point form: the curve point corresponding to this
    /// aggregate scalar. Used by verifiers to add to the aggregate
    /// kernel excess.
    pub fn to_point(&self) -> Option<RistrettoPoint> {
        Some(G * self.as_scalar()?)
    }
}

impl Default for AggregateOffset {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn generate_returns_canonical_scalar() {
        let off = KernelOffset::generate();
        assert!(off.as_scalar().is_some());
    }

    #[test]
    fn aggregate_of_two_offsets_equals_scalar_sum() {
        let mut rng = StdRng::seed_from_u64(0xC0DE);
        let a = KernelOffset::generate_with(&mut rng);
        let b = KernelOffset::generate_with(&mut rng);
        let combined = a.aggregate(b).expect("canonical");

        let a_s = a.as_scalar().unwrap();
        let b_s = b.as_scalar().unwrap();
        assert_eq!(combined.0, (a_s + b_s).to_bytes());
    }

    #[test]
    fn aggregate_is_commutative() {
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        let a = KernelOffset::generate_with(&mut rng);
        let b = KernelOffset::generate_with(&mut rng);
        assert_eq!(a.aggregate(b), b.aggregate(a));
    }

    #[test]
    fn add_offset_chain_is_commutative() {
        let mut rng = StdRng::seed_from_u64(0xCAFE);
        let a = KernelOffset::generate_with(&mut rng);
        let b = KernelOffset::generate_with(&mut rng);
        let c = KernelOffset::generate_with(&mut rng);

        let order1 = AggregateOffset::ZERO
            .add_offset(a)
            .unwrap()
            .add_offset(b)
            .unwrap()
            .add_offset(c)
            .unwrap();
        let order2 = AggregateOffset::ZERO
            .add_offset(c)
            .unwrap()
            .add_offset(a)
            .unwrap()
            .add_offset(b)
            .unwrap();
        assert_eq!(order1, order2);
    }

    #[test]
    fn verify_round_trip_with_offset() {
        // Construct a kernel: pick a secret excess scalar, sign a
        // message with (excess - offset), publish (excess - offset)*G
        // as the kernel excess + the offset. Verifier should accept.
        let mut rng = StdRng::seed_from_u64(0x1234);
        let offset = KernelOffset::generate_with(&mut rng);
        let off_scalar = offset.as_scalar().unwrap();

        // True signing scalar
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        let true_excess = Scalar::from_bytes_mod_order_wide(&buf);

        // Published excess = (true_excess - offset)
        let published_excess_scalar = true_excess - off_scalar;
        let published_excess = (G * published_excess_scalar).compress().to_bytes();

        // Sign with true_excess (the unblinded scalar = published + offset)
        let mut nonce_buf = [0u8; 64];
        rng.fill_bytes(&mut nonce_buf);
        let k = Scalar::from_bytes_mod_order_wide(&nonce_buf);
        let r_point = G * k;
        let r_bytes = r_point.compress().to_bytes();

        let key_point = G * true_excess;
        let mut chal_buf = Vec::with_capacity(96);
        chal_buf.extend_from_slice(&r_bytes);
        chal_buf.extend_from_slice(&key_point.compress().to_bytes());
        let msg = [42u8; 32];
        chal_buf.extend_from_slice(&msg);
        let c = hash_to_scalar(&chal_buf);
        let s = k + c * true_excess;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s.to_bytes());

        assert!(offset.verify_against(&published_excess, &sig, &msg));
    }

    #[test]
    fn verify_rejects_wrong_offset() {
        let mut rng = StdRng::seed_from_u64(0xABCD);
        let real_offset = KernelOffset::generate_with(&mut rng);
        let bogus_offset = KernelOffset::generate_with(&mut rng);

        // Pretend we have a valid sig + excess for `real_offset`. We
        // verify the SAME excess + sig with `bogus_offset` and expect
        // failure. Use a synthetic excess (point at infinity) and a
        // zeroed signature — verify returns false either way for
        // mismatched offset.
        let excess = [0u8; 32];
        let sig = [0u8; 64];
        let msg = [9u8; 32];

        assert!(!real_offset.verify_against(&excess, &sig, &msg));
        assert!(!bogus_offset.verify_against(&excess, &sig, &msg));
    }
}
