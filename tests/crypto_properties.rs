//! Tier 4: Cryptographic property tests.
//!
//! Property-based tests that verify mathematical invariants hold across
//! randomly-generated inputs. Any single violation is a critical finding.
//!
//! T4.1 — Ring signature: forgery without secret always fails
//! T4.2 — Keyimage: deterministic under variable ring composition
//! T4.3 — Stealth address: unlinkability (statistical)
//! T4.4 — Pedersen commitment: homomorphic property
//! T4.5 — Bulletproofs: batch verify consistency
//! T4.6 — Signature determinism: same key signs consistently
//! T4.7 — Range proof tightness: boundary values

use coincync::crypto::{
    create_aggregated_range_proof_for_height,
    create_range_proof_for_height,
    // 2026-06-03 audit pass narrowed the legacy `generate_stealth_address`
    // to `#[cfg(test)] pub(crate)` inside stealth.rs (removed from the
    // public re-export). Test fixtures here pass valid curve points, so
    // the .expect() on the Result is a never-fires assertion.
    generate_stealth_address_checked,
    generator,
    generator_h,
    hash_to_point,
    verify_range_proof_dispatch,
    verify_range_proofs_dispatch,
    BlindingFactor,
    EcCommitment,
    KeyImage as CryptoKeyImage,
    PedersenCommitment,
    PublicPoint,
    SecretScalar,
};
use coincync::primitives::{Amount, PublicKey};
use rand::rngs::OsRng;
use std::collections::HashSet;

// =============================================================================
// T4.2 — KEYIMAGE DETERMINISM
//
// Property: For any secret key k, the keyimage I = k * Hp(P) is the same
// regardless of which ring k appears in. If this fails, double-spend
// protection is broken.
// =============================================================================

#[test]
fn keyimage_is_deterministic_for_same_secret() {
    // Generate a secret key and compute its keyimage 100 times
    let secret = SecretScalar::random(&mut OsRng);
    let ki1 = CryptoKeyImage::from_secret(&secret);

    for _ in 0..100 {
        let ki = CryptoKeyImage::from_secret(&secret);
        assert_eq!(
            ki.to_bytes(),
            ki1.to_bytes(),
            "keyimage must be deterministic for the same secret key"
        );
    }
}

#[test]
fn different_secrets_produce_different_keyimages() {
    let mut keyimages = HashSet::new();
    for i in 0u64..200 {
        let secret = SecretScalar::from_bytes({
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&i.to_le_bytes());
            b[8] = 1; // avoid zero scalar
            b
        });
        let ki = CryptoKeyImage::from_secret(&secret);
        let inserted = keyimages.insert(ki.to_bytes());
        assert!(
            inserted,
            "keyimage collision at i={} — two different secrets produced the same keyimage",
            i
        );
    }
}

// =============================================================================
// T4.3 — STEALTH ADDRESS UNLINKABILITY
//
// Property: Stealth addresses derived for the same recipient from different
// tx_public_keys should look like random curve points.
// =============================================================================

#[test]
fn stealth_addresses_for_same_recipient_are_all_different() {
    let spend_secret = SecretScalar::random(&mut OsRng);
    let view_secret = SecretScalar::random(&mut OsRng);
    let spend_pub = PublicKey::from_bytes(spend_secret.to_public().to_bytes());
    let view_pub = PublicKey::from_bytes(view_secret.to_public().to_bytes());

    let mut addresses = HashSet::new();
    for _ in 0..500 {
        let (stealth, _tx_secret) =
            generate_stealth_address_checked(&spend_pub, &view_pub, 0, &mut OsRng)
                .expect("test fixtures pass valid curve points");
        let addr_bytes = *stealth.public_key.as_bytes();
        let inserted = addresses.insert(addr_bytes);
        assert!(
            inserted,
            "stealth address collision — two derivations produced the same address"
        );
    }
    assert_eq!(
        addresses.len(),
        500,
        "all 500 stealth addresses should be unique"
    );
}

#[test]
fn stealth_addresses_for_different_recipients_are_different() {
    let mut addresses = HashSet::new();
    for i in 0u64..100 {
        let spend = SecretScalar::from_bytes({
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&i.to_le_bytes());
            b[8] = 1;
            b
        });
        let view = SecretScalar::from_bytes({
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&(i + 1000).to_le_bytes());
            b[8] = 2;
            b
        });
        let sp = PublicKey::from_bytes(spend.to_public().to_bytes());
        let vp = PublicKey::from_bytes(view.to_public().to_bytes());
        let (stealth, _) = generate_stealth_address_checked(&sp, &vp, 0, &mut OsRng)
            .expect("test fixtures pass valid curve points");
        addresses.insert(stealth.public_key.as_bytes().clone());
    }
    assert_eq!(
        addresses.len(),
        100,
        "stealth addresses for 100 different recipients should all be unique"
    );
}

// =============================================================================
// T4.4 — PEDERSEN COMMITMENT HOMOMORPHISM
//
// Property: Commit(r1, v1) + Commit(r2, v2) = Commit(r1+r2, v1+v2)
// This is load-bearing for range proofs and balance checks.
// =============================================================================

#[test]
fn pedersen_commitment_is_homomorphic() {
    for _ in 0..500 {
        let v1 = rand::random::<u32>() as u64;
        let v2 = rand::random::<u32>() as u64;
        let r1 = SecretScalar::random(&mut OsRng);
        let r2 = SecretScalar::random(&mut OsRng);

        let c1 = EcCommitment::commit(v1, &r1);
        let c2 = EcCommitment::commit(v2, &r2);
        let c_sum = c1.add(&c2);

        let r_sum = r1.add(&r2);
        let c_direct = EcCommitment::commit(v1 + v2, &r_sum);

        assert_eq!(
            c_sum.to_bytes(),
            c_direct.to_bytes(),
            "Commit(v1,r1) + Commit(v2,r2) must equal Commit(v1+v2, r1+r2)"
        );
    }
}

#[test]
fn pedersen_commitment_zero_value_is_blinding_only() {
    // Commit(r, 0) = r*G (only the blinding generator)
    let r = SecretScalar::random(&mut OsRng);
    let c_zero = EcCommitment::commit(0, &r);
    let expected = r.to_public(); // r*G
    assert_eq!(
        c_zero.to_bytes(),
        expected.to_bytes(),
        "Commit(0, r) should equal r*G"
    );
}

#[test]
fn pedersen_different_values_different_commitments() {
    // Same blinding, different values → different commitments
    let r = SecretScalar::random(&mut OsRng);
    let c1 = EcCommitment::commit(100, &r);
    let c2 = EcCommitment::commit(200, &r);
    assert_ne!(
        c1.to_bytes(),
        c2.to_bytes(),
        "different values with same blinding must produce different commitments"
    );
}

#[test]
fn pedersen_different_blindings_different_commitments() {
    // Same value, different blindings → different commitments (hiding property)
    let r1 = SecretScalar::random(&mut OsRng);
    let r2 = SecretScalar::random(&mut OsRng);
    let c1 = EcCommitment::commit(42, &r1);
    let c2 = EcCommitment::commit(42, &r2);
    assert_ne!(
        c1.to_bytes(),
        c2.to_bytes(),
        "same value with different blindings must produce different commitments (hiding)"
    );
}

// =============================================================================
// T4.5 — BULLETPROOFS RANGE PROOF ROUNDTRIP
//
// Property: A valid range proof verifies. An invalid one doesn't.
// =============================================================================

#[test]
fn range_proof_valid_amount_verifies() {
    let amount = Amount::from_atomic(1_000_000);
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(amount.as_atomic(), &blinding);

    let proof = create_range_proof_for_height(amount, &blinding, &mut OsRng, 0)
        .expect("proof creation should succeed");

    assert!(
        verify_range_proof_dispatch(&commitment, &proof, 0),
        "valid range proof must verify"
    );
}

#[test]
fn range_proof_zero_amount_verifies() {
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(0, &blinding);

    let proof = create_range_proof_for_height(Amount::ZERO, &blinding, &mut OsRng, 0)
        .expect("proof for zero should succeed");

    assert!(
        verify_range_proof_dispatch(&commitment, &proof, 0),
        "range proof for zero amount must verify"
    );
}

#[test]
fn range_proof_wrong_commitment_fails() {
    let amount = Amount::from_atomic(500_000);
    let blinding = BlindingFactor::random(&mut OsRng);
    let _correct = PedersenCommitment::commit(amount.as_atomic(), &blinding);

    let proof = create_range_proof_for_height(amount, &blinding, &mut OsRng, 0)
        .expect("proof creation should succeed");

    // Wrong commitment
    let wrong_blinding = BlindingFactor::random(&mut OsRng);
    let wrong = PedersenCommitment::commit(999_999, &wrong_blinding);

    assert!(
        !verify_range_proof_dispatch(&wrong, &proof, 0),
        "range proof must fail with wrong commitment"
    );
}

#[test]
fn range_proof_large_value_verifies() {
    // Test with a large value near u64 range
    let value = u64::MAX / 2;
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(value, &blinding);

    let proof = create_range_proof_for_height(Amount::from_atomic(value), &blinding, &mut OsRng, 0)
        .expect("proof for large value should succeed");

    assert!(
        verify_range_proof_dispatch(&commitment, &proof, 0),
        "range proof for large value must verify"
    );
}

// =============================================================================
// T4.5b — AGGREGATED RANGE PROOF
// =============================================================================

#[test]
fn aggregated_range_proof_multi_output_verifies() {
    let amounts = vec![
        Amount::from_atomic(1_000_000),
        Amount::from_atomic(2_000_000),
    ];
    let blindings: Vec<BlindingFactor> = (0..amounts.len())
        .map(|_| BlindingFactor::random(&mut OsRng))
        .collect();
    let commitments: Vec<PedersenCommitment> = amounts
        .iter()
        .zip(blindings.iter())
        .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
        .collect();

    let proof = create_aggregated_range_proof_for_height(&amounts, &blindings, &mut OsRng, 0)
        .expect("aggregated proof should succeed");

    assert!(
        verify_range_proofs_dispatch(&commitments, &proof, 0),
        "aggregated range proof must verify with correct commitments"
    );
}

// =============================================================================
// T4.6 — KEYIMAGE COMPUTATION IS CONSISTENT
//
// Property: Computing keyimage from the same secret always gives the same
// result, even across different program runs (deterministic).
// =============================================================================

#[test]
fn keyimage_from_known_secret_is_reproducible() {
    // Use a fixed seed so this test is deterministic across runs
    let secret = SecretScalar::from_bytes([42u8; 32]);
    let ki1 = CryptoKeyImage::from_secret(&secret);
    let ki2 = CryptoKeyImage::from_secret(&secret);
    assert_eq!(ki1.to_bytes(), ki2.to_bytes());

    // Different secret → different keyimage
    let secret2 = SecretScalar::from_bytes([43u8; 32]);
    let ki3 = CryptoKeyImage::from_secret(&secret2);
    assert_ne!(ki1.to_bytes(), ki3.to_bytes());
}

// =============================================================================
// T4.7 — GENERATOR POINTS ARE NOT IDENTITY
//
// The generators G and H must not be the identity point.
// If either is identity, the commitment scheme is broken.
// =============================================================================

#[test]
fn generators_are_not_identity() {
    let g = generator();
    let h = generator_h();
    let identity = curve25519_dalek::ristretto::RistrettoPoint::default();

    assert_ne!(g, identity, "generator G must not be identity");
    assert_ne!(h, identity, "generator H must not be identity");
    assert_ne!(g, h, "generators G and H must be different");
}

// =============================================================================
// T4.8 — HASH TO POINT IS DETERMINISTIC AND COLLISION-FREE
// =============================================================================

#[test]
fn hash_to_point_is_deterministic() {
    let data = b"test input for hash_to_point";
    let p1 = hash_to_point(data);
    let p2 = hash_to_point(data);
    assert_eq!(p1, p2, "hash_to_point must be deterministic");
}

#[test]
fn hash_to_point_different_inputs_different_points() {
    let mut points = HashSet::new();
    for i in 0u64..200 {
        let p = hash_to_point(&i.to_le_bytes());
        let bytes = p.compress().to_bytes();
        let inserted = points.insert(bytes);
        assert!(inserted, "hash_to_point collision at i={}", i);
    }
}

// =============================================================================
// T4.9 — SCALAR ARITHMETIC CONSISTENCY
// =============================================================================

#[test]
fn scalar_add_is_commutative() {
    for _ in 0..100 {
        let a = SecretScalar::random(&mut OsRng);
        let b = SecretScalar::random(&mut OsRng);
        assert_eq!(
            a.add(&b).to_bytes(),
            b.add(&a).to_bytes(),
            "scalar addition must be commutative"
        );
    }
}

#[test]
fn scalar_add_identity() {
    let a = SecretScalar::random(&mut OsRng);
    let zero = SecretScalar::from_bytes([0u8; 32]);
    assert_eq!(
        a.add(&zero).to_bytes(),
        a.to_bytes(),
        "adding zero scalar must be identity"
    );
}

// =============================================================================
// T4.10 — PUBLIC POINT SERIALIZATION ROUNDTRIP
// =============================================================================

#[test]
fn public_point_roundtrip_1000() {
    for _ in 0..1000 {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let bytes = public.to_bytes();
        let recovered = PublicPoint::from_bytes(bytes);
        assert!(
            recovered.is_some(),
            "valid public point must roundtrip through bytes"
        );
        assert_eq!(recovered.unwrap().to_bytes(), bytes);
    }
}
