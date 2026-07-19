//! Pedersen value commitments — the homomorphic accounting layer.
//!
//! Every shielded transaction balances **iff** the sum of input
//! value commitments equals the sum of output value commitments
//! (plus the transparent `value_balance` that bridges into the
//! transparent pool). The verifier doesn't see the individual
//! values; it sees only their commitments and the proof that the
//! homomorphic difference is zero.
//!
//! ## Construction (Zcash NU5 §5.4.8.3)
//!
//! ```text
//!   cv = [v] · V^Orchard + [rcv] · R^Orchard
//! ```
//!
//! where:
//! - `V^Orchard = hash_to_curve("z.cash:Orchard-cv")(b"v")` —
//!   the value generator on Pallas
//! - `R^Orchard = hash_to_curve("z.cash:Orchard-cv")(b"r")` —
//!   the trapdoor-randomness generator on Pallas
//! - `v` is the note value (a u64 today; the spec uses i64 so
//!   shielded balance differences can be negative — the i64
//!   support lands with the balance-equation work)
//! - `rcv` is the value-commitment trapdoor (a `pallas::Scalar`)
//!
//! ## Homomorphic add
//!
//! `cv_a + cv_b = [v_a + v_b]·V + [rcv_a + rcv_b]·R` — straight
//! point addition. The verifier composes this across all inputs
//! and outputs; if the resulting point equals `[value_balance]·V`
//! the transaction balances. The matching scalar relation is
//! proven via a separate RedPallas "binding signature" — out of
//! scope for this slice; see [`crate::action`] for the proof
//! envelope it will eventually live in.
//!
//! ## What this slice ships
//!
//! - [`ValueCommitment::commit`] — real Pedersen commit using
//!   live Pallas point arithmetic, with hiding under `rcv` and
//!   binding to the value via the V generator
//! - [`ValueCommitment::add`] / [`ValueCommitment::sub`] —
//!   homomorphic composition for the verifier's balance check
//! - [`TrapdoorRandomness`] with a validating constructor (reject
//!   non-canonical scalars at the boundary)
//!
//! ## What is still deferred
//!
//! - **`verify_balance`** — needs the RedPallas binding-signature
//!   primitive (proves the prover knows the discrete log of the
//!   summed rcv differences without revealing rcv). That belongs
//!   in a `binding_sig.rs` slice paired with the action circuit.
//! - **i64 value support.** Negative values in the balance equation
//!   require encoding `v` as `pallas::Scalar::from_repr` of a
//!   sign-aware u128 form. Skipped here for ergonomic reasons;
//!   the existing stub took u64.

use ff::{Field, PrimeField};
use pasta_curves::{arithmetic::CurveExt, pallas};
use std::sync::OnceLock;

use crate::{Error, Result};

/// A Pedersen value commitment over the Pallas group. Stored as a
/// 32-byte compressed point representation when it crosses the
/// wire / chain boundary.
#[derive(Clone, Debug)]
pub struct ValueCommitment(pub(crate) pallas::Point);

impl ValueCommitment {
    /// Construct from a raw `pallas::Point`. Crate-private —
    /// callers outside the crate should use [`commit`] or the
    /// bridge envelope. Useful for tests that need a placeholder
    /// commitment without paying the hash-to-curve cost.
    ///
    /// [`commit`]: ValueCommitment::commit
    #[allow(dead_code)] // used by sibling-module action.rs tests; the dead-code lint can't see cross-module crate-test usage
    pub(crate) fn from_point(point: pallas::Point) -> Self {
        Self(point)
    }

    /// Construct a value commitment for a (value, trapdoor) pair.
    ///
    /// `cv = [value] · V + [rcv] · R` using the Orchard value and
    /// randomness generators.
    ///
    /// # Errors
    /// Returns `DomainRule` only via [`TrapdoorRandomness`]
    /// validation (caller passes a parsed `rcv`).
    pub fn commit(value: u64, rcv: &TrapdoorRandomness) -> Result<Self> {
        let v_scalar = pallas::Scalar::from(value);
        let cv = (value_generator() * v_scalar) + (randomness_generator() * rcv.0);
        Ok(Self(cv))
    }

    /// Homomorphic sum: `c1 + c2`. Useful for verifier-side
    /// balance checks across multiple actions.
    pub fn add(&self, other: &ValueCommitment) -> Result<ValueCommitment> {
        Ok(ValueCommitment(self.0 + other.0))
    }

    /// Homomorphic difference: `c1 - c2`. Used in the balance
    /// equation `sum(inputs) - sum(outputs) == [value_balance]·V`.
    pub fn sub(&self, other: &ValueCommitment) -> Result<ValueCommitment> {
        Ok(ValueCommitment(self.0 - other.0))
    }

    /// Verify the balance equation for a shielded transaction.
    ///
    /// Computes the **binding verifying key**:
    /// ```text
    ///   bvk = sum(cv_inputs) - sum(cv_outputs) - [value_balance] · V
    /// ```
    /// then checks `sig` is a valid RedPallas signature over `msg`
    /// under `bvk`. If both halves pass, the transaction balances
    /// (the prover proved knowledge of the discrete log of the
    /// summed `rcv` differences) AND the prover authenticated the
    /// transaction (via `msg`, typically a sighash).
    ///
    /// `value_balance` is the transparent value crossing the
    /// bridge — positive for "shielded → transparent",
    /// non-negative in this slice (negative values need the i64
    /// refactor flagged in [`commit`]'s docs).
    ///
    /// # Errors
    /// `Verification` if the signature doesn't verify under the
    /// computed `bvk`.
    pub fn verify_balance(
        inputs: &[ValueCommitment],
        outputs: &[ValueCommitment],
        value_balance: u64,
        msg: &[u8; 32],
        sig: &crate::binding_sig::BindingSignature,
    ) -> Result<()> {
        let bvk = crate::binding_sig::BindingVerifyingKey::from_commitments(
            inputs,
            outputs,
            value_balance,
        )?;
        sig.verify(&bvk, msg)
    }

    /// Raw 32-byte compressed Pallas point bytes — what wire
    /// format and the bridge consume.
    pub fn to_bytes(&self) -> [u8; 32] {
        use group::GroupEncoding;
        let bytes = self.0.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes.as_ref());
        out
    }

    /// Equality based on the underlying Pallas point (handles
    /// non-unique compressed representations correctly — two
    /// commitments to the same point compare equal even if the
    /// internal `pallas::Point` reps differ via the identity
    /// element edge case).
    pub fn point_eq(&self, other: &ValueCommitment) -> bool {
        self.0 == other.0
    }

    /// Borrow the underlying Pallas point. Crate-private for use
    /// by [`crate::binding_sig`] which sums commitments when
    /// deriving the binding verifying key.
    pub(crate) fn point(&self) -> &pallas::Point {
        &self.0
    }
}

/// `rcv` — the value-commitment trapdoor randomness. One per
/// note; must be fresh per commit for the hiding property.
#[derive(Clone, Debug)]
pub struct TrapdoorRandomness(pub(crate) pallas::Scalar);

impl TrapdoorRandomness {
    /// Parse from raw bytes. Validates `bytes` is canonical as a
    /// Pallas scalar (`< ℓ_pallas`); non-canonical input would
    /// silently wrap, producing different commitments on prover
    /// and verifier sides for the same logical `rcv`.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let s: pallas::Scalar = Option::from(pallas::Scalar::from_repr(bytes))
            .ok_or(Error::DomainRule("rcv is not a canonical Pallas scalar"))?;
        if s == pallas::Scalar::ZERO {
            // Zero rcv → cv = [v]·V — the commitment leaks v
            // exactly. Refuse rather than silently producing an
            // insecure commitment.
            return Err(Error::DomainRule("rcv must be non-zero (would leak value)"));
        }
        Ok(Self(s))
    }

    /// Borrow the underlying scalar — useful for combining
    /// trapdoor randomness across inputs/outputs when computing
    /// the binding signature.
    ///
    /// Currently called only from tests; the production caller is
    /// the upcoming RedPallas binding-signature primitive (see the
    /// module header). Allow-dead-code rather than wait to remove
    /// the lint silencer until then.
    #[allow(dead_code)]
    pub(crate) fn scalar(&self) -> &pallas::Scalar {
        &self.0
    }

    /// Add two trapdoor scalars: `(r1 + r2) mod ℓ`. Used in
    /// homomorphism testing and in the binding-signature path
    /// where the prover sums input-side and output-side trapdoors
    /// to derive the binding signing key.
    pub fn add(&self, other: &TrapdoorRandomness) -> TrapdoorRandomness {
        // Scalar addition is mod ℓ by construction; the result is
        // always canonical. We do NOT rebuild via from_bytes here
        // because the result might be zero (a + (-a) = 0), and
        // from_bytes rejects zero — but a zero SUM is legitimate
        // in the binding-sig math (output - input = 0 means a
        // balanced transaction). Return directly.
        TrapdoorRandomness(self.0 + other.0)
    }
}

// ── Generators ───────────────────────────────────────────────────────
//
// V^Orchard and R^Orchard are derived from hash-to-curve calls with
// fixed domain strings. We compute them once via OnceLock so the
// 30-µs hash-to-curve cost is paid only at first use; subsequent
// commits + adds are pure point arithmetic.
//
// Why the same domain string with different messages, rather than
// two separate domain strings: matches the canonical Zcash Orchard
// derivation (`OrchardValueCommitVPallas` /
// `OrchardValueCommitRPallas` both use "z.cash:Orchard-cv"). Anyone
// re-deriving these from the spec would land on the same points.

fn value_generator() -> pallas::Point {
    static V: OnceLock<pallas::Point> = OnceLock::new();
    *V.get_or_init(|| pallas::Point::hash_to_curve("z.cash:Orchard-cv")(b"v"))
}

fn randomness_generator() -> pallas::Point {
    static R: OnceLock<pallas::Point> = OnceLock::new();
    *R.get_or_init(|| pallas::Point::hash_to_curve("z.cash:Orchard-cv")(b"r"))
}

/// The RedPallas binding-signature generator — **the same point**
/// as [`randomness_generator`]. Exposed for [`crate::binding_sig`]
/// to use. By design, the value-commitment scheme and the binding
/// signature share `R^Orchard_cv` so that the balance equation
/// `sum(cv_old) - sum(cv_new) - [v_b]·V == bsk · R` reduces to a
/// Schnorr signature under `R`.
pub(crate) fn binding_generator() -> pallas::Point {
    randomness_generator()
}

/// The value-commitment value generator `V^Orchard`. Exposed for
/// [`crate::binding_sig`] which subtracts `[value_balance] · V`
/// when computing the binding verifying key.
pub(crate) fn value_generator_pub() -> pallas::Point {
    value_generator()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pallas_canonical(b: u8) -> [u8; 32] {
        let mut out = [b; 32];
        out[31] = 0;
        out
    }

    fn test_rcv(seed: u8) -> TrapdoorRandomness {
        TrapdoorRandomness::from_bytes(pallas_canonical(seed)).unwrap()
    }

    #[test]
    fn rcv_rejects_zero() {
        assert!(TrapdoorRandomness::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn rcv_rejects_non_canonical() {
        // All-0xFF exceeds ℓ_pallas.
        assert!(TrapdoorRandomness::from_bytes([0xff; 32]).is_err());
    }

    #[test]
    fn rcv_accepts_canonical_nonzero() {
        TrapdoorRandomness::from_bytes(pallas_canonical(1)).unwrap();
    }

    #[test]
    fn commit_is_deterministic() {
        let rcv = test_rcv(7);
        let cv1 = ValueCommitment::commit(1_000_000, &rcv).unwrap();
        let cv2 = ValueCommitment::commit(1_000_000, &rcv).unwrap();
        assert!(cv1.point_eq(&cv2));
        assert_eq!(cv1.to_bytes(), cv2.to_bytes());
    }

    #[test]
    fn commit_differs_per_value() {
        let rcv = test_rcv(8);
        let cv_a = ValueCommitment::commit(1_000_000, &rcv).unwrap();
        let cv_b = ValueCommitment::commit(1_000_001, &rcv).unwrap();
        assert!(!cv_a.point_eq(&cv_b));
    }

    #[test]
    fn commit_differs_per_rcv_with_same_value() {
        // Same value, fresh rcv → different commitment. This is
        // the *hiding* property — without it, a verifier could
        // recognize repeated-value notes.
        let rcv_a = test_rcv(9);
        let rcv_b = test_rcv(10);
        let cv_a = ValueCommitment::commit(1_000_000, &rcv_a).unwrap();
        let cv_b = ValueCommitment::commit(1_000_000, &rcv_b).unwrap();
        assert!(!cv_a.point_eq(&cv_b));
    }

    #[test]
    fn homomorphic_add_matches_combined_commit() {
        // commit(a, r_a) + commit(b, r_b) == commit(a+b, r_a+r_b)
        // — the load-bearing property for verifier-side balance
        // composition.
        let rcv_a = test_rcv(11);
        let rcv_b = test_rcv(12);
        let cv_a = ValueCommitment::commit(700_000, &rcv_a).unwrap();
        let cv_b = ValueCommitment::commit(300_000, &rcv_b).unwrap();
        let cv_sum = cv_a.add(&cv_b).unwrap();

        // Reconstruct the expected commitment from the combined
        // value and combined randomness.
        let combined_scalar = *rcv_a.scalar() + *rcv_b.scalar();
        let expected_point = (value_generator() * pallas::Scalar::from(1_000_000u64))
            + (randomness_generator() * combined_scalar);
        let expected = ValueCommitment(expected_point);
        assert!(
            cv_sum.point_eq(&expected),
            "homomorphic add must equal combined-input commit"
        );
    }

    #[test]
    fn homomorphic_sub_zeros_for_identical_commits() {
        // commit(v, r) - commit(v, r) = identity — the trivial
        // case but a useful invariant: subtracting equal
        // commitments must yield the identity point regardless of
        // the underlying value or randomness.
        use group::Group;
        let rcv = test_rcv(13);
        let cv = ValueCommitment::commit(42_000, &rcv).unwrap();
        let diff = cv.sub(&cv).unwrap();
        assert_eq!(diff.0, pallas::Point::identity());
    }

    #[test]
    fn homomorphic_sub_matches_combined_commit() {
        // commit(a, r_a) - commit(b, r_b) == commit(a-b, r_a-r_b)
        // — used in the balance equation
        // `sum(inputs) - sum(outputs) == [value_balance]·V`.
        let rcv_a = test_rcv(14);
        let rcv_b = test_rcv(15);
        let cv_a = ValueCommitment::commit(1_000_000, &rcv_a).unwrap();
        let cv_b = ValueCommitment::commit(400_000, &rcv_b).unwrap();
        let cv_diff = cv_a.sub(&cv_b).unwrap();

        let combined_scalar = *rcv_a.scalar() - *rcv_b.scalar();
        let expected_point = (value_generator() * pallas::Scalar::from(600_000u64))
            + (randomness_generator() * combined_scalar);
        let expected = ValueCommitment(expected_point);
        assert!(cv_diff.point_eq(&expected));
    }

    #[test]
    fn generators_are_distinct_and_nonidentity() {
        // V and R must be different points and neither can be
        // the identity — otherwise the commitment scheme is
        // trivially broken.
        use group::Group;
        let v = value_generator();
        let r = randomness_generator();
        assert_ne!(v, r);
        assert_ne!(v, pallas::Point::identity());
        assert_ne!(r, pallas::Point::identity());
    }

    #[test]
    fn generators_are_stable_across_calls() {
        // OnceLock must produce the same bytes on every call.
        // Catches any future refactor that accidentally re-derives.
        let v1 = value_generator();
        let v2 = value_generator();
        assert_eq!(v1, v2);
    }

    // `verify_balance` is now real (no longer stubbed) — its
    // end-to-end behaviour is covered by the
    // `balance_check_passes_for_balanced_tx` /
    // `balance_check_rejects_unbalanced_tx` tests in
    // `binding_sig.rs`.

    #[test]
    fn to_bytes_is_32_bytes() {
        let rcv = test_rcv(21);
        let cv = ValueCommitment::commit(1_000, &rcv).unwrap();
        let bytes = cv.to_bytes();
        assert_eq!(bytes.len(), 32);
    }
}
