//! RedPallas binding signature — the verifier-side balance check.
//!
//! ## What this primitive does
//!
//! A shielded transaction's prover holds the trapdoor randomness
//! `rcv_i` for every input commitment and `rcv_o` for every output
//! commitment. Summing these:
//!
//! ```text
//!   bsk = sum(rcv_i) - sum(rcv_o)            (the binding signing key)
//! ```
//!
//! the value-commitment equation
//! `cv_i = [v_i]·V + [rcv_i]·R` combined across all inputs/outputs
//! plus the transparent balance `[v_b]·V` gives:
//!
//! ```text
//!   bvk = sum(cv_i) - sum(cv_o) - [v_b]·V    (the binding verifying key)
//!       = (sum(v_i) - sum(v_o) - v_b) · V
//!         + (sum(rcv_i) - sum(rcv_o))     · R
//! ```
//!
//! If the transaction **balances** (sum(v_i) == sum(v_o) + v_b),
//! the `V` term vanishes and `bvk = bsk · R`. The prover then
//! signs a RedPallas signature over the transaction sighash using
//! `bsk`; the verifier checks the signature under `bvk`. Both
//! halves passing simultaneously implies:
//! - The values balance (otherwise no `bsk` would let the prover
//!   produce a valid sig under the computed `bvk`).
//! - The prover authenticated the transaction (binds the sig to
//!   the sighash).
//!
//! ## Construction (Zcash NU5 §5.4.7 RedDSA)
//!
//! Standard Schnorr-over-Pallas with Blake2b challenge:
//!
//! ```text
//!   Sign(sk, msg):
//!     r = fresh nonce
//!     R = r · G_binding
//!     c = H(R || vk || msg) mod q_S    (Blake2b-512 reduced)
//!     s = r + c · sk      (mod q_S)
//!     sig = (R, s) — 64 bytes
//!
//!   Verify(vk, msg, sig=(R,s)):
//!     c = H(R || vk || msg) mod q_S
//!     check  s · G_binding == R + c · vk
//! ```
//!
//! `G_binding` is the same `R^Orchard_cv` generator used in
//! [`crate::value_commit`] (binding-sig and value-commit must
//! share it — that's what makes the balance equation reduce to a
//! Schnorr verification).

use blake2b_simd::Params as Blake2bParams;
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use pasta_curves::{group::ff::FromUniformBytes, pallas};

use crate::value_commit::{
    binding_generator, value_generator_pub, TrapdoorRandomness, ValueCommitment,
};
use crate::{Error, Result};

const REDPALLAS_CHALLENGE_PERSONALIZATION: &[u8; 16] = b"Zcash_RedPallasH";

// ── Signing key ──────────────────────────────────────────────────────

/// Binding signing key `bsk = sum(input rcv) - sum(output rcv)`.
/// Held by the prover; never crosses the chain boundary.
#[derive(Clone, Debug)]
pub struct BindingSigningKey(pallas::Scalar);

impl BindingSigningKey {
    /// Construct from the per-input and per-output trapdoor
    /// randomness. Computes the difference modulo the Pallas
    /// scalar field order.
    pub fn from_rcvs(
        input_rcvs: &[TrapdoorRandomness],
        output_rcvs: &[TrapdoorRandomness],
    ) -> Self {
        let mut bsk = pallas::Scalar::ZERO;
        for r in input_rcvs {
            bsk += r.scalar();
        }
        for r in output_rcvs {
            bsk -= r.scalar();
        }
        Self(bsk)
    }

    /// Public binding verifying key `bvk = bsk · G_binding`. The
    /// chain-side verifier reconstructs the same point from the
    /// public value commitments + transparent value_balance via
    /// [`BindingVerifyingKey::from_commitments`].
    pub fn verifying_key(&self) -> BindingVerifyingKey {
        BindingVerifyingKey(binding_generator() * self.0)
    }

    /// Sign `msg` (typically a transaction sighash) under this
    /// binding key.
    ///
    /// `nonce_bytes` is the fresh signing nonce in Pallas scalar
    /// repr — caller is responsible for freshness. Tests pass a
    /// deterministic value for round-trips; production callers
    /// MUST source from a CSPRNG and never reuse per
    /// `(bsk, msg)` pair.
    ///
    /// # Errors
    /// `DomainRule` if `nonce_bytes` is not a canonical Pallas
    /// scalar (≥ q_S).
    pub fn sign(&self, msg: &[u8; 32], nonce_bytes: [u8; 32]) -> Result<BindingSignature> {
        let r: pallas::Scalar = Option::from(pallas::Scalar::from_repr(nonce_bytes)).ok_or(
            Error::DomainRule("signing nonce is not a canonical Pallas scalar"),
        )?;

        // R = r · G_binding
        let r_point = binding_generator() * r;

        // vk = bsk · G_binding (recompute rather than take as
        // parameter — saves the caller a step and keeps the
        // signing API minimal).
        let vk_point = binding_generator() * self.0;

        // c = H(R || vk || msg) reduced into pallas::Scalar.
        let c = challenge_scalar(&r_point, &vk_point, msg);

        // s = r + c · bsk
        let s = r + (c * self.0);

        Ok(BindingSignature { r_point, s })
    }
}

// ── Verifying key ────────────────────────────────────────────────────

/// Binding verifying key `bvk` — the public point the verifier
/// checks the signature against.
#[derive(Clone, Debug)]
pub struct BindingVerifyingKey(pallas::Point);

impl BindingVerifyingKey {
    /// Construct from the public value commitments + transparent
    /// `value_balance`:
    ///
    /// ```text
    ///   bvk = sum(cv_inputs) - sum(cv_outputs) - [value_balance] · V
    /// ```
    ///
    /// If the transaction balances, this equals `bsk · G_binding`
    /// and a signature under `bsk` will verify under this key.
    pub fn from_commitments(
        inputs: &[ValueCommitment],
        outputs: &[ValueCommitment],
        value_balance: u64,
    ) -> Result<Self> {
        let mut acc = pallas::Point::identity();
        for cv in inputs {
            acc += cv.point();
        }
        for cv in outputs {
            acc -= cv.point();
        }
        if value_balance > 0 {
            let v_term = value_generator_pub() * pallas::Scalar::from(value_balance);
            acc -= v_term;
        }
        Ok(Self(acc))
    }

    /// Wire-format bytes — compressed Pallas point.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.to_bytes().as_ref());
        out
    }
}

// ── Signature ────────────────────────────────────────────────────────

/// 64-byte RedPallas binding signature: `R || s`.
#[derive(Clone, Debug)]
pub struct BindingSignature {
    pub(crate) r_point: pallas::Point,
    pub(crate) s: pallas::Scalar,
}

impl BindingSignature {
    /// Verify under the given binding verifying key.
    ///
    /// Returns `Ok(())` iff `s · G_binding == R + c · vk` where
    /// `c = H(R || vk || msg)`.
    pub fn verify(&self, vk: &BindingVerifyingKey, msg: &[u8; 32]) -> Result<()> {
        let c = challenge_scalar(&self.r_point, &vk.0, msg);
        let lhs = binding_generator() * self.s;
        let rhs = self.r_point + (vk.0 * c);
        if lhs == rhs {
            Ok(())
        } else {
            Err(Error::InvalidProof(
                "binding signature does not verify — balance equation broken or sig forged"
                    .to_string(),
            ))
        }
    }

    /// Serialize as 64 bytes: `R (32 bytes) || s (32 bytes)`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(self.r_point.to_bytes().as_ref());
        out[32..64].copy_from_slice(&self.s.to_repr());
        out
    }

    /// Parse from 64 bytes. Validates both halves are canonical
    /// (R decodes as a Pallas point, s is canonical as a Pallas
    /// scalar).
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self> {
        let r_bytes: <pallas::Point as GroupEncoding>::Repr = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes[0..32]);
            buf.into()
        };
        let r_point: pallas::Point = Option::from(pallas::Point::from_bytes(&r_bytes))
            .ok_or(Error::MalformedWireFormat("R is not a valid Pallas point"))?;

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let s: pallas::Scalar = Option::from(pallas::Scalar::from_repr(s_bytes)).ok_or(
            Error::MalformedWireFormat("s is not a canonical Pallas scalar"),
        )?;

        Ok(Self { r_point, s })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// RedPallas challenge hash: `Blake2b-512(personal="Zcash_RedPallasH",
/// input = R || vk || msg)` reduced into pallas::Scalar via uniform-
/// bytes reduction.
fn challenge_scalar(r: &pallas::Point, vk: &pallas::Point, msg: &[u8; 32]) -> pallas::Scalar {
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(REDPALLAS_CHALLENGE_PERSONALIZATION)
        .to_state();
    h.update(r.to_bytes().as_ref());
    h.update(vk.to_bytes().as_ref());
    h.update(msg);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(digest.as_bytes());
    pallas::Scalar::from_uniform_bytes(&wide)
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

    fn test_msg(seed: u8) -> [u8; 32] {
        pallas_canonical(seed.wrapping_add(100))
    }

    #[test]
    fn sign_then_verify_round_trips() {
        // Single-input single-output balanced transaction.
        let rcv_in = test_rcv(1);
        let rcv_out = test_rcv(2);
        let bsk = BindingSigningKey::from_rcvs(&[rcv_in.clone()], &[rcv_out.clone()]);

        let msg = test_msg(1);
        let nonce = pallas_canonical(20);
        let sig = bsk.sign(&msg, nonce).unwrap();

        let vk = bsk.verifying_key();
        sig.verify(&vk, &msg)
            .expect("freshly-signed sig must verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let rcv_in = test_rcv(3);
        let rcv_out = test_rcv(4);
        let bsk = BindingSigningKey::from_rcvs(&[rcv_in], &[rcv_out]);
        let sig = bsk.sign(&test_msg(5), pallas_canonical(21)).unwrap();
        let vk = bsk.verifying_key();
        let r = sig.verify(&vk, &test_msg(99));
        assert!(matches!(r, Err(Error::InvalidProof(_))));
    }

    #[test]
    fn verify_rejects_wrong_vk() {
        // Use distinct seed counts so the two bsks have genuinely
        // different scalar values. Naive `(test_rcv(a), test_rcv(b))`
        // pairs would alias because `test_rcv(seed) ≈ seed · K` for
        // a fixed K (the geometric pattern of `[seed; 32]`), so
        // any equal-difference seed pair produces the same bsk.
        let bsk = BindingSigningKey::from_rcvs(&[test_rcv(5)], &[test_rcv(6)]);
        let other = BindingSigningKey::from_rcvs(&[test_rcv(5), test_rcv(7)], &[test_rcv(6)]);
        // Sanity: the two bvks really are different.
        assert_ne!(
            bsk.verifying_key().to_bytes(),
            other.verifying_key().to_bytes(),
        );

        let msg = test_msg(2);
        let sig = bsk.sign(&msg, pallas_canonical(22)).unwrap();
        let r = sig.verify(&other.verifying_key(), &msg);
        assert!(matches!(r, Err(Error::InvalidProof(_))));
    }

    #[test]
    fn sig_round_trips_through_bytes() {
        let bsk = BindingSigningKey::from_rcvs(&[test_rcv(9)], &[test_rcv(10)]);
        let msg = test_msg(3);
        let sig1 = bsk.sign(&msg, pallas_canonical(23)).unwrap();
        let bytes = sig1.to_bytes();
        let sig2 = BindingSignature::from_bytes(bytes).expect("parse");
        sig2.verify(&bsk.verifying_key(), &msg)
            .expect("re-parsed sig must verify");
    }

    #[test]
    fn from_bytes_rejects_invalid_s() {
        // Reliably-non-canonical s: all 0xff in the second half
        // exceeds q_S. The R half is the Pallas-identity encoding
        // (32 zero bytes), which IS a valid GroupEncoding —
        // so the failure surfaces from the scalar parse, not the
        // point parse, which is what we want to exercise.
        let mut bad = [0u8; 64];
        for b in &mut bad[32..64] {
            *b = 0xff;
        }
        let r = BindingSignature::from_bytes(bad);
        assert!(matches!(r, Err(Error::MalformedWireFormat(_))));
    }

    #[test]
    fn balance_check_passes_for_balanced_tx() {
        // Construct a *balanced* transaction:
        //   inputs:  values 700, 300 with fresh rcv
        //   outputs: values 900, 100 with fresh rcv
        //   value_balance = 0
        // Sum(v_in) == Sum(v_out) so the V-term vanishes;
        // sum(rcv_in) - sum(rcv_out) is the bsk that signs.
        let rcv_in_a = test_rcv(11);
        let rcv_in_b = test_rcv(12);
        let rcv_out_a = test_rcv(13);
        let rcv_out_b = test_rcv(14);

        let cv_in_a = ValueCommitment::commit(700, &rcv_in_a).unwrap();
        let cv_in_b = ValueCommitment::commit(300, &rcv_in_b).unwrap();
        let cv_out_a = ValueCommitment::commit(900, &rcv_out_a).unwrap();
        let cv_out_b = ValueCommitment::commit(100, &rcv_out_b).unwrap();

        let bsk = BindingSigningKey::from_rcvs(&[rcv_in_a, rcv_in_b], &[rcv_out_a, rcv_out_b]);
        let msg = test_msg(10);
        let sig = bsk.sign(&msg, pallas_canonical(24)).unwrap();

        // Verifier path: derive bvk from public commitments, run
        // ValueCommitment::verify_balance.
        ValueCommitment::verify_balance(
            &[cv_in_a, cv_in_b],
            &[cv_out_a, cv_out_b],
            0, // value_balance = 0 (no transparent flow)
            &msg,
            &sig,
        )
        .expect("balanced tx must verify");
    }

    #[test]
    fn balance_check_passes_with_transparent_outflow() {
        // Shielded inputs: 1000 + 500 = 1500
        // Shielded outputs: 800 + 400 = 1200
        // value_balance = 300 (300 flowing OUT to transparent pool)
        let rcv_in_a = test_rcv(15);
        let rcv_in_b = test_rcv(16);
        let rcv_out_a = test_rcv(17);
        let rcv_out_b = test_rcv(18);

        let cv_in_a = ValueCommitment::commit(1000, &rcv_in_a).unwrap();
        let cv_in_b = ValueCommitment::commit(500, &rcv_in_b).unwrap();
        let cv_out_a = ValueCommitment::commit(800, &rcv_out_a).unwrap();
        let cv_out_b = ValueCommitment::commit(400, &rcv_out_b).unwrap();

        let bsk = BindingSigningKey::from_rcvs(&[rcv_in_a, rcv_in_b], &[rcv_out_a, rcv_out_b]);
        let msg = test_msg(11);
        let sig = bsk.sign(&msg, pallas_canonical(25)).unwrap();

        ValueCommitment::verify_balance(
            &[cv_in_a, cv_in_b],
            &[cv_out_a, cv_out_b],
            300,
            &msg,
            &sig,
        )
        .expect("balanced tx with v_b=300 must verify");
    }

    #[test]
    fn balance_check_rejects_unbalanced_tx() {
        // Inputs total 1000, outputs total 999, value_balance = 0
        // — off by 1, should reject.
        let rcv_in = test_rcv(19);
        let rcv_out = test_rcv(20);
        let cv_in = ValueCommitment::commit(1000, &rcv_in).unwrap();
        let cv_out = ValueCommitment::commit(999, &rcv_out).unwrap();

        let bsk = BindingSigningKey::from_rcvs(&[rcv_in], &[rcv_out]);
        let msg = test_msg(12);
        let sig = bsk.sign(&msg, pallas_canonical(26)).unwrap();

        // The prover signed with the bsk that matches the rcv
        // difference, but the bvk the verifier derives includes
        // a `[1] · V` term (the value mismatch) that the
        // signature didn't account for — must reject.
        let r = ValueCommitment::verify_balance(&[cv_in], &[cv_out], 0, &msg, &sig);
        assert!(
            matches!(r, Err(Error::InvalidProof(_))),
            "unbalanced tx must be rejected"
        );
    }

    #[test]
    fn balance_check_rejects_wrong_value_balance() {
        // Balanced inputs/outputs but the verifier supplies the
        // wrong value_balance — must reject.
        let rcv_in = test_rcv(21);
        let rcv_out = test_rcv(22);
        let cv_in = ValueCommitment::commit(1000, &rcv_in).unwrap();
        let cv_out = ValueCommitment::commit(1000, &rcv_out).unwrap();

        let bsk = BindingSigningKey::from_rcvs(&[rcv_in], &[rcv_out]);
        let msg = test_msg(13);
        let sig = bsk.sign(&msg, pallas_canonical(27)).unwrap();

        // Prover thinks value_balance = 0; verifier passes 50.
        let r = ValueCommitment::verify_balance(&[cv_in], &[cv_out], 50, &msg, &sig);
        assert!(matches!(r, Err(Error::InvalidProof(_))));
    }

    #[test]
    fn sign_rejects_non_canonical_nonce() {
        let bsk = BindingSigningKey::from_rcvs(&[test_rcv(23)], &[test_rcv(24)]);
        let r = bsk.sign(&test_msg(14), [0xff; 32]);
        assert!(matches!(r, Err(Error::DomainRule(_))));
    }

    #[test]
    fn verifying_key_matches_bvk_from_commitments_for_balanced_tx() {
        // Sanity: bsk.verifying_key() (computed by the prover)
        // must equal BindingVerifyingKey::from_commitments(...)
        // (computed by the verifier) when the transaction
        // balances. If they ever disagree for a balanced tx, the
        // honest prover would fail to authenticate.
        let rcv_in = test_rcv(25);
        let rcv_out = test_rcv(26);
        let cv_in = ValueCommitment::commit(1234, &rcv_in).unwrap();
        let cv_out = ValueCommitment::commit(1234, &rcv_out).unwrap();

        let bsk = BindingSigningKey::from_rcvs(&[rcv_in], &[rcv_out]);
        let vk_from_bsk = bsk.verifying_key();
        let vk_from_cvs = BindingVerifyingKey::from_commitments(&[cv_in], &[cv_out], 0).unwrap();

        assert_eq!(
            vk_from_bsk.to_bytes(),
            vk_from_cvs.to_bytes(),
            "prover-side and verifier-side bvk must match for balanced tx"
        );
    }
}
