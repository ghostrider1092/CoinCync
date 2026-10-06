//! crypto-cluster #5 — CLSAG commitment-image (D) binding guard.
//!
//! Item #5 of `docs/audit/2026-08-30-crypto-cluster-expert-briefing.md` calls for
//! the negative test "tamper `commitment_image` (D) → verify must reject". This
//! is that test, run against the CURRENT CLSAG on `main` via the documented
//! `crypto::testbed` audit entry point (no edit to the hash-locked `clsag.rs`).
//!
//! SCOPE — read before trusting this as "C-1 is fixed": this guards that the
//! commitment image `D` is bound into the per-ring challenge, so a *naive* swap
//! of `D` is rejected. It does NOT prove CLSAG soundness against the actual C-1
//! weakness (the aggregation coefficients μ_P/μ_C omit `D` and μ_C is derived
//! from μ_P rather than an independent transcept — clsag.rs:144). Demonstrating
//! or refuting a forgery that exploits that coefficient dependence requires a
//! cryptographer's analysis, not a byte-swap. This test is a regression guard
//! for the challenge-binding property only; the soundness question stays open
//! in the briefing (item #5) pending expert review + the hf-gated D-binding fix.

use coincync::crypto::testbed::{
    clsag_sign, clsag_verify, Commitment, SecretScalar,
};
// RingMember is re-exported from the same testbed module.
use coincync::crypto::testbed::RingMember;
use rand::rngs::OsRng;

#[test]
fn clsag_verify_rejects_tampered_commitment_image() {
    let value = 1000u64;

    // Real signer + real/pseudo commitments with different blindings.
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    let z_real = SecretScalar::random(&mut OsRng);
    let real_commitment = Commitment::commit(value, &z_real);
    let z_pseudo = SecretScalar::random(&mut OsRng);
    let pseudo_output = Commitment::commit(value, &z_pseudo);
    let blinding_diff = SecretScalar::from_scalar(z_real.as_scalar() - z_pseudo.as_scalar());

    // Two decoys.
    let decoy1 = SecretScalar::random(&mut OsRng);
    let decoy2 = SecretScalar::random(&mut OsRng);
    let ring = vec![
        RingMember::new(public, real_commitment),
        RingMember::new(
            decoy1.to_public(),
            Commitment::commit(value, &SecretScalar::random(&mut OsRng)),
        ),
        RingMember::new(
            decoy2.to_public(),
            Commitment::commit(value, &SecretScalar::random(&mut OsRng)),
        ),
    ];
    let message = b"CLSAG commitment-image binding test";

    let mut sig = clsag_sign(
        message,
        &ring,
        0,
        &secret,
        &blinding_diff,
        &pseudo_output,
        &mut OsRng,
    )
    .expect("honest CLSAG signing must succeed");

    // Sanity: the honest signature verifies.
    assert!(
        clsag_verify(message, &ring, &pseudo_output, &sig),
        "honest CLSAG must verify"
    );

    // Tamper the commitment image D: replace it with a different valid point.
    let other = SecretScalar::from_bytes([0x5a; 32]).to_public();
    assert_ne!(
        other.to_bytes(),
        sig.commitment_image.to_bytes(),
        "tamper point must differ from the real D"
    );
    sig.commitment_image = other;

    // Load-bearing assertion: a swapped commitment image must be rejected.
    assert!(
        !clsag_verify(message, &ring, &pseudo_output, &sig),
        "CLSAG accepted a tampered commitment_image (D) — the commitment image \
         is not bound into verification on this build"
    );
}
