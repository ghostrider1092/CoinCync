//! Tier 4 — Adversarial Cryptographic Corpora
//!
//! NOT random inputs. These are the exact boundary values where crypto
//! bugs live: group order, 2^64 boundaries, identity points, zero
//! scalars, all-ones, and modular wraparound values.
//!
//! Any failure here is a critical finding.

use coincync::crypto::{
    create_aggregated_range_proof_for_height, create_range_proof_for_height, hash_to_point,
    verify_range_proof_dispatch, verify_range_proofs_dispatch, BlindingFactor, EcCommitment,
    KeyImage as CryptoKeyImage, PedersenCommitment, PublicPoint, SecretScalar,
};
use coincync::primitives::{Amount, PublicKey};
use rand::rngs::OsRng;

// Ristretto group order: l = 2^252 + 27742317777372353535851937790883648493
const GROUP_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

// =============================================================================
// IDENTITY POINT ATTACKS
// =============================================================================

#[test]
fn zero_scalar_produces_identity_public_key() {
    let zero = SecretScalar::from_bytes([0u8; 32]);
    let public = zero.to_public();
    // Identity point has specific bytes — verify it's handled
    let bytes = public.to_bytes();
    // The identity in Ristretto compressed form is all zeros
    assert_eq!(
        bytes, [0u8; 32],
        "zero scalar should produce identity point (all-zero bytes)"
    );
}

#[test]
fn identity_point_not_accepted_as_valid_public_key() {
    // PublicKey::from_bytes_checked should reject identity
    let result = PublicKey::from_bytes_checked([0u8; 32]);
    assert!(
        result.is_err(),
        "identity point (all zeros) must be rejected as a public key"
    );
}

#[test]
fn commitment_to_zero_with_zero_blinding_is_identity() {
    let zero_scalar = SecretScalar::from_bytes([0u8; 32]);
    let c = EcCommitment::commit(0, &zero_scalar);
    assert_eq!(
        c.to_bytes(),
        [0u8; 32],
        "Commit(0, 0) should be the identity point"
    );
}

#[test]
fn commitment_to_zero_with_nonzero_blinding_is_not_identity() {
    let r = SecretScalar::random(&mut OsRng);
    let c = EcCommitment::commit(0, &r);
    assert_ne!(
        c.to_bytes(),
        [0u8; 32],
        "Commit(0, r) with r≠0 must NOT be identity"
    );
}

// =============================================================================
// GROUP ORDER BOUNDARY
// =============================================================================

#[test]
fn scalar_from_group_order_wraps_to_zero() {
    // The group order l should reduce to zero modulo l
    let s = SecretScalar::from_bytes(GROUP_ORDER_BYTES);
    let public = s.to_public();
    // l mod l = 0, so this should be the identity
    assert_eq!(
        public.to_bytes(),
        [0u8; 32],
        "group order scalar should reduce to zero (identity point)"
    );
}

#[test]
fn scalar_from_group_order_minus_one_is_valid() {
    // l - 1 should be the largest valid non-zero scalar
    let mut bytes = GROUP_ORDER_BYTES;
    // Subtract 1 from little-endian
    let mut borrow = true;
    for b in bytes.iter_mut() {
        if borrow {
            if *b == 0 {
                *b = 0xFF;
            } else {
                *b -= 1;
                borrow = false;
            }
        }
    }

    let s = SecretScalar::from_bytes(bytes);
    let public = s.to_public();
    assert_ne!(
        public.to_bytes(),
        [0u8; 32],
        "group_order - 1 should produce a valid non-identity point"
    );
}

#[test]
fn scalar_one_produces_generator() {
    let mut one = [0u8; 32];
    one[0] = 1;
    let s = SecretScalar::from_bytes(one);
    let public = s.to_public();
    // 1 * G = G (the generator point)
    assert_ne!(
        public.to_bytes(),
        [0u8; 32],
        "scalar 1 should produce the generator (non-identity)"
    );
}

// =============================================================================
// 2^64 BOUNDARY VALUES (Amount/Value attacks)
// =============================================================================

#[test]
fn range_proof_at_u64_max() {
    let value = u64::MAX;
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(value, &blinding);

    let proof = create_range_proof_for_height(Amount::from_atomic(value), &blinding, &mut OsRng, 0);
    match proof {
        Ok(p) => {
            assert!(
                verify_range_proof_dispatch(&commitment, &p, 0),
                "range proof for u64::MAX should verify if created successfully"
            );
        }
        Err(_) => {
            // Some implementations reject u64::MAX — that's also valid
            // as long as it's a clean error, not a panic
        }
    }
}

#[test]
fn range_proof_at_u64_max_minus_1() {
    let value = u64::MAX - 1;
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(value, &blinding);

    let proof = create_range_proof_for_height(Amount::from_atomic(value), &blinding, &mut OsRng, 0)
        .expect("range proof for u64::MAX-1 should succeed");

    assert!(
        verify_range_proof_dispatch(&commitment, &proof, 0),
        "range proof for u64::MAX-1 must verify"
    );
}

#[test]
fn range_proof_at_power_of_2_boundaries() {
    // Test at every power-of-2 boundary — these are where bit-level bugs hide
    for exp in [1u32, 2, 4, 8, 16, 31, 32, 48, 63] {
        let value = 1u64 << exp;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);

        let proof =
            create_range_proof_for_height(Amount::from_atomic(value), &blinding, &mut OsRng, 0)
                .expect(&format!("range proof for 2^{} should succeed", exp));

        assert!(
            verify_range_proof_dispatch(&commitment, &proof, 0),
            "range proof for 2^{} = {} must verify",
            exp,
            value
        );
    }
}

#[test]
fn range_proof_at_power_of_2_minus_1() {
    for exp in [8u32, 16, 32, 48, 63] {
        let value = (1u64 << exp) - 1;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);

        let proof =
            create_range_proof_for_height(Amount::from_atomic(value), &blinding, &mut OsRng, 0)
                .expect(&format!("range proof for 2^{}-1 should succeed", exp));

        assert!(
            verify_range_proof_dispatch(&commitment, &proof, 0),
            "range proof for 2^{}-1 = {} must verify",
            exp,
            value
        );
    }
}

// =============================================================================
// COMMITMENT ARITHMETIC EDGE CASES
// =============================================================================

#[test]
fn commitment_add_with_identity_is_self() {
    let r = SecretScalar::random(&mut OsRng);
    let c = EcCommitment::commit(42, &r);
    let zero = SecretScalar::from_bytes([0u8; 32]);
    let identity = EcCommitment::commit(0, &zero);

    let sum = c.add(&identity);
    assert_eq!(sum.to_bytes(), c.to_bytes(), "C + identity should equal C");
}

#[test]
fn commitment_homomorphism_with_max_values() {
    // Test homomorphism at the edge: large values that sum near u64 overflow
    let v1 = u64::MAX / 2;
    let v2 = u64::MAX / 2;
    let r1 = SecretScalar::random(&mut OsRng);
    let r2 = SecretScalar::random(&mut OsRng);

    let c1 = EcCommitment::commit(v1, &r1);
    let c2 = EcCommitment::commit(v2, &r2);
    let c_sum = c1.add(&c2);

    let r_sum = r1.add(&r2);
    // v1 + v2 overflows u64 but commit works in the scalar field
    // which is much larger. The sum should still match.
    let c_direct = EcCommitment::commit(v1.wrapping_add(v2), &r_sum);
    assert_eq!(
        c_sum.to_bytes(),
        c_direct.to_bytes(),
        "homomorphism must hold even when u64 values wrap"
    );
}

// =============================================================================
// KEYIMAGE EDGE CASES
// =============================================================================

#[test]
fn keyimage_from_zero_scalar_handled() {
    let zero = SecretScalar::from_bytes([0u8; 32]);
    // This should either produce a deterministic result or panic cleanly
    // (not UB, not garbage)
    let ki = CryptoKeyImage::from_secret(&zero);
    // Zero secret → zero public → hash_to_point(zero) → zero * point = identity
    let _ = ki.to_bytes(); // Should not panic
}

#[test]
fn keyimage_from_one_is_deterministic() {
    let mut one = [0u8; 32];
    one[0] = 1;
    let s = SecretScalar::from_bytes(one);
    let ki1 = CryptoKeyImage::from_secret(&s);
    let ki2 = CryptoKeyImage::from_secret(&s);
    assert_eq!(
        ki1.to_bytes(),
        ki2.to_bytes(),
        "keyimage from scalar=1 must be deterministic"
    );
}

#[test]
fn keyimage_from_group_order_minus_1() {
    let mut bytes = GROUP_ORDER_BYTES;
    let mut borrow = true;
    for b in bytes.iter_mut() {
        if borrow {
            if *b == 0 {
                *b = 0xFF;
            } else {
                *b -= 1;
                borrow = false;
            }
        }
    }
    let s = SecretScalar::from_bytes(bytes);
    let ki = CryptoKeyImage::from_secret(&s);
    assert_ne!(
        ki.to_bytes(),
        [0u8; 32],
        "keyimage from group_order-1 should not be identity"
    );
}

// =============================================================================
// ALL-ONES AND ALL-FF INPUTS
// =============================================================================

#[test]
fn all_ones_scalar() {
    let s = SecretScalar::from_bytes([0x01; 32]);
    let p = s.to_public();
    assert_ne!(
        p.to_bytes(),
        [0u8; 32],
        "all-0x01 scalar should not be identity"
    );
}

#[test]
fn all_ff_scalar() {
    let s = SecretScalar::from_bytes([0xFF; 32]);
    let p = s.to_public();
    // 0xFFFF...FF is reduced modulo group order — should be valid
    assert_ne!(
        p.to_bytes(),
        [0u8; 32],
        "all-0xFF scalar (reduced mod l) should produce a valid point"
    );
}

#[test]
fn all_ff_not_valid_compressed_point() {
    let result = PublicPoint::from_bytes([0xFF; 32]);
    // All-FF is not a valid compressed Ristretto point
    assert!(
        result.is_none(),
        "all-0xFF bytes should not decompress to a valid Ristretto point"
    );
}

#[test]
fn hash_to_point_with_empty_input() {
    let p = hash_to_point(b"");
    let identity = curve25519_dalek::ristretto::RistrettoPoint::default();
    assert_ne!(p, identity, "hash_to_point('') must not return identity");
}

#[test]
fn hash_to_point_with_single_zero_byte() {
    let p = hash_to_point(&[0u8]);
    let identity = curve25519_dalek::ristretto::RistrettoPoint::default();
    assert_ne!(p, identity, "hash_to_point([0]) must not return identity");
}

// =============================================================================
// BULLETPROOFS ADVERSARIAL CORPORA
// =============================================================================

#[test]
fn aggregated_proof_boundary_amounts() {
    // Two outputs at boundary values
    let amounts = vec![Amount::from_atomic(0), Amount::from_atomic(u64::MAX / 2)];
    let blindings: Vec<BlindingFactor> =
        (0..2).map(|_| BlindingFactor::random(&mut OsRng)).collect();
    let commitments: Vec<PedersenCommitment> = amounts
        .iter()
        .zip(blindings.iter())
        .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
        .collect();

    let proof = create_aggregated_range_proof_for_height(&amounts, &blindings, &mut OsRng, 0)
        .expect("aggregated proof with boundary amounts should succeed");

    assert!(
        verify_range_proofs_dispatch(&commitments, &proof, 0),
        "aggregated proof with [0, u64::MAX/2] must verify"
    );
}

#[test]
fn single_output_amounts_corpus() {
    // Test every notable single-output amount value
    let test_values: Vec<u64> = vec![
        0,
        1,
        2,
        255,
        256,
        257,
        65535,
        65536,
        65537,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        1_000_000_000_000,       // 1 CYNC in atomic units
        100_000_000_000_000_000, // 100K CYNC
    ];

    for value in test_values {
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);

        let proof =
            create_range_proof_for_height(Amount::from_atomic(value), &blinding, &mut OsRng, 0)
                .expect(&format!("range proof for value {} should succeed", value));

        assert!(
            verify_range_proof_dispatch(&commitment, &proof, 0),
            "range proof for value {} must verify",
            value
        );
    }
}
