//! # Tier 12 (shielded extension) — Cryptographic Warfare against the native
//! Groth–Kohlweiss Spark spend proofs (`SparkSpendProofV5` / `V6`).
//!
//! Companion to `tier12_crypto_warfare.rs` (which hammers the ACTIVE crypto —
//! CLSAG, bulletproofs, Pedersen). This file brings the **gated** native spend
//! proofs under the same tier-12 adversarial umbrella: forged membership over a
//! substituted anonymity set, nullifier replay (double-spend), cross-transaction
//! proof lifting (signature-of-knowledge message binding), value inflation, and
//! non-canonical point injection.
//!
//! The whole file is gated on `sketch-gk-proof` (the same feature that gates
//! `src/crypto/groth_kohlweiss.rs`), so it compiles to nothing in a normal
//! build and only runs under `--features "testnet sketch-gk-proof"`.
//!
//! A failure here means the native shielded spend proof is unsound — it must be
//! caught before the proof is ever wired into consensus / activated.
#![cfg(feature = "sketch-gk-proof")]

use coincync::crypto::groth_kohlweiss::{
    prove_spend_full, prove_spend_spark, verify_spend_full, verify_spend_spark,
};
use coincync::crypto::spark_generators::{gen_gv, gen_h, gen_k, gen_u};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Deterministic filler coin (mirrors the in-module helper): a point in the
/// coin group that is NOT a valid Spark opening the prover knows.
fn filler(seed: u64) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * Scalar::from(seed + 1) + gen_k() * Scalar::from(seed * 7 + 3)
}

/// Build a v6 (Spark-native) coin ring with a real opening at index `l`,
/// returning (coins, serial, blinding, value_blinding, value).
fn v6_ring(
    rng: &mut ChaCha20Rng,
    m: usize,
    l: usize,
    value: u64,
) -> (Vec<RistrettoPoint>, Scalar, Scalar, Scalar) {
    let n = 1usize << m;
    let serial = Scalar::random(rng);
    let blinding = Scalar::random(rng);
    let value_blinding = Scalar::random(rng);
    let mut coins: Vec<RistrettoPoint> = (0..n).map(|i| filler(i as u64 + 700)).collect();
    coins[l] = gen_gv() * Scalar::from(value) + gen_h() * serial + gen_k() * blinding;
    (coins, serial, blinding, value_blinding)
}

// =============================================================================
// ATTACK 1: ANONYMITY-SET SUBSTITUTION — verify a valid proof against a
// DIFFERENT coin set than it was proven over. The one-of-many membership binds
// to the exact set via the Fiat–Shamir challenge; swapping any member must fail.
// =============================================================================
#[test]
fn attack_gk_v6_proof_does_not_transfer_to_a_substituted_set() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1201_0001);
    let (m, l, value) = (3, 2usize, 9001u64);
    let (coins, serial, blinding, vb) = v6_ring(&mut rng, m, l, value);
    let msg = [3u8; 32];
    let proof = prove_spend_spark(&coins, l, value, &serial, &blinding, &vb, &msg, &mut rng)
        .expect("honest v6 spend proves");
    assert!(verify_spend_spark(&coins, &proof, &msg).is_ok(), "sanity: honest proof verifies");

    // Substitute one (non-l) filler. The proof was Fiat–Shamir-bound to the
    // original set; verifying against the altered set must be rejected.
    let mut substituted = coins.clone();
    substituted[0] = filler(999_999);
    assert!(
        verify_spend_spark(&substituted, &proof, &msg).is_err(),
        "a membership proof must NOT transfer to a substituted anonymity set"
    );
}

// =============================================================================
// ATTACK 2: NULLIFIER REPLAY (DOUBLE-SPEND) — spending the SAME coin twice,
// across different anonymity sets AND different messages, must yield the SAME
// nullifier, so the node's spent-tag set deterministically catches it.
// =============================================================================
#[test]
fn attack_gk_v6_double_spend_collides_in_nullifier() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1202_0002);
    let value = 4242u64;
    // Same (serial, blinding, value) spent in two unrelated contexts.
    let serial = Scalar::random(&mut rng);
    let blinding = Scalar::random(&mut rng);

    let build = |rng: &mut ChaCha20Rng, m: usize, l: usize, msg: [u8; 32]| {
        let n = 1usize << m;
        let vb = Scalar::random(rng);
        let mut coins: Vec<RistrettoPoint> = (0..n).map(|i| filler(i as u64 + 1500)).collect();
        coins[l] = gen_gv() * Scalar::from(value) + gen_h() * serial + gen_k() * blinding;
        let p = prove_spend_spark(&coins, l, value, &serial, &blinding, &vb, &msg, rng).unwrap();
        let (_, nf) = verify_spend_spark(&coins, &p, &msg).unwrap();
        nf
    };

    let nf1 = build(&mut rng, 3, 2, [1u8; 32]);
    let nf2 = build(&mut rng, 4, 5, [2u8; 32]);
    assert_eq!(nf1, nf2, "same coin serial MUST produce the same nullifier (double-spend caught)");

    // A different serial must NOT collide (no cross-coin nullifier reuse).
    let other_serial = Scalar::random(&mut rng);
    let n = 8usize;
    let vb = Scalar::random(&mut rng);
    let mut coins: Vec<RistrettoPoint> = (0..n).map(|i| filler(i as u64 + 1500)).collect();
    coins[3] = gen_gv() * Scalar::from(value) + gen_h() * other_serial + gen_k() * blinding;
    let p = prove_spend_spark(&coins, 3, value, &other_serial, &blinding, &vb, &[9u8; 32], &mut rng)
        .unwrap();
    let (_, nf3) = verify_spend_spark(&coins, &p, &[9u8; 32]).unwrap();
    assert_ne!(nf1, nf3, "distinct serials MUST give distinct nullifiers");
}

// =============================================================================
// ATTACK 3: CROSS-TRANSACTION PROOF LIFTING — a v6 proof is a signature of
// knowledge over a tx message. Lifting a valid proof onto a DIFFERENT message
// (i.e. replaying it in another transaction) must be rejected.
// =============================================================================
#[test]
fn attack_gk_v6_proof_cannot_be_lifted_to_another_tx() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1203_0003);
    let (coins, serial, blinding, vb) = v6_ring(&mut rng, 3, 1, 777);
    let msg_a = *b"transaction-A___________________";
    let proof = prove_spend_spark(&coins, 1, 777, &serial, &blinding, &vb, &msg_a, &mut rng).unwrap();
    assert!(verify_spend_spark(&coins, &proof, &msg_a).is_ok());

    let msg_b = *b"transaction-B___________________";
    assert!(
        verify_spend_spark(&coins, &proof, &msg_b).is_err(),
        "a proof bound to tx-A must not verify against tx-B (no cross-tx lifting)"
    );
}

// =============================================================================
// ATTACK 4: VALUE INFLATION — swap the published value commitment to encode a
// LARGER value while reusing the proof. Membership was proven over W_i = C_i − V
// for the original V; a different V breaks membership at the real index.
// =============================================================================
#[test]
fn attack_gk_v6_value_inflation_is_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1204_0004);
    let value = 1000u64;
    let (coins, serial, blinding, vb) = v6_ring(&mut rng, 3, 2, value);
    let msg = [5u8; 32];
    let mut proof =
        prove_spend_spark(&coins, 2, value, &serial, &blinding, &vb, &msg, &mut rng).unwrap();
    // Re-commit to value+1_000_000 with the same blinding (an inflation attempt).
    proof.value_commitment =
        (gen_gv() * Scalar::from(value + 1_000_000) + gen_k() * vb).compress().to_bytes();
    assert!(
        verify_spend_spark(&coins, &proof, &msg).is_err(),
        "a value commitment the membership was not proven over must be rejected (no inflation)"
    );
}

// =============================================================================
// ATTACK 5: NON-CANONICAL POINT INJECTION — feed garbage/non-canonical
// compressed-point bytes for the nullifier. The verifier must fail closed on
// decode, never panic or silently accept.
// =============================================================================
#[test]
fn attack_gk_v6_non_canonical_nullifier_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1205_0005);
    let (coins, serial, blinding, vb) = v6_ring(&mut rng, 3, 0, 55);
    let msg = [6u8; 32];
    let mut proof =
        prove_spend_spark(&coins, 0, 55, &serial, &blinding, &vb, &msg, &mut rng).unwrap();
    proof.nullifier = [0xFFu8; 32]; // not a canonical compressed Ristretto point
    assert!(
        verify_spend_spark(&coins, &proof, &msg).is_err(),
        "non-canonical nullifier bytes must be rejected at decode (fail closed)"
    );
}

// =============================================================================
// ATTACK 6: V5 KEY-IMAGE / TAG FORGERY — the key-image-bound variant. A forged
// nullifier tag, or verification under a different tag generator, must fail.
// =============================================================================
#[test]
fn attack_gk_v5_tag_forgery_and_wrong_generator_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1206_0006);
    let pk_gen = gen_gv();
    let ki_gen = gen_u();
    let (m, l, value) = (3usize, 4usize, 1234u64);
    let n = 1usize << m;
    let h_coef = Scalar::random(&mut rng);
    let blinding = Scalar::random(&mut rng);
    let value_blinding = Scalar::random(&mut rng);
    let x_l = Scalar::random(&mut rng);

    let mut coins: Vec<RistrettoPoint> = (0..n).map(|i| filler(i as u64 + 500)).collect();
    coins[l] = gen_gv() * Scalar::from(value) + gen_h() * h_coef + gen_k() * blinding;
    let mut pubkeys: Vec<RistrettoPoint> =
        (0..n).map(|i| RISTRETTO_BASEPOINT_POINT * Scalar::from(i as u64 * 31 + 3)).collect();
    pubkeys[l] = pk_gen * x_l;
    let msg = [7u8; 32];

    let proof = prove_spend_full(
        &coins, &pubkeys, l, value, &h_coef, &blinding, &value_blinding, &x_l, pk_gen, ki_gen,
        &msg, &mut rng,
    )
    .expect("honest v5 spend proves");
    assert!(verify_spend_full(&coins, &pubkeys, &proof, pk_gen, ki_gen, &msg).is_ok());

    // Forged tag (spend key off by one).
    let mut forged = proof.clone();
    forged.tag = (ki_gen * (x_l + Scalar::ONE)).compress().to_bytes();
    assert!(
        verify_spend_full(&coins, &pubkeys, &forged, pk_gen, ki_gen, &msg).is_err(),
        "a forged nullifier tag must be rejected"
    );

    // Verification under a different tag generator must fail.
    assert!(
        verify_spend_full(&coins, &pubkeys, &proof, pk_gen, gen_h(), &msg).is_err(),
        "verifying under the wrong tag generator must be rejected"
    );
}
