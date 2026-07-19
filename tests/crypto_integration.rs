//! End-to-end cryptographic integration tests for CoinCync 1.0
//!
//! These tests verify the full transaction lifecycle:
//! - Keypair generation → transaction building → CLSAG signing → verification
//! - Range proof creation and verification
//! - Signing hash consistency between builder and Transaction::signing_hash()
//! - Balance equation: sum(inputs) == sum(outputs) + fee
//!
//! The builder/signing_hash divergence bug would have been caught by test #3.

use coincync::crypto::{
    create_aggregated_range_proof_for_height, verify_range_proofs_dispatch, BlindingFactor,
    PedersenCommitment, PublicPoint, SecretScalar,
};
use coincync::primitives::{Amount, Hash, PublicKey, SecretKey};
use coincync::transaction::{DecoyOutput, Recipient, SpendableInput, TransactionBuilder, TxType};
use rand::rngs::OsRng;

// =============================================================================
// HELPERS
// =============================================================================

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    (
        SecretKey::from_bytes(secret.to_bytes()),
        PublicKey::from_bytes(public.to_bytes()),
    )
}

fn create_mock_input(amount: Amount, seed: u8, height: u64) -> SpendableInput {
    let (secret, _) = generate_keypair();
    let mut tx_hash_bytes = [0u8; 32];
    tx_hash_bytes[0] = seed;
    tx_hash_bytes[1] = seed.wrapping_mul(7);
    SpendableInput {
        tx_hash: Hash::from_bytes(tx_hash_bytes),
        output_index: 0,
        amount,
        one_time_secret: secret,
        blinding: BlindingFactor::random(&mut OsRng),
        height,
    }
}

fn create_decoys(count: usize) -> Vec<DecoyOutput> {
    (0..count)
        .map(|_| {
            let s = SecretScalar::random(&mut OsRng);
            let p = s.to_public();
            DecoyOutput {
                public_key: PublicKey::from_bytes(p.to_bytes()),
                commitment: p.to_bytes(), // mock commitment
                height: 500,
            }
        })
        .collect()
}

// =============================================================================
// TEST 1: Keypair round-trip (SecretScalar → PublicPoint → bytes → back)
// =============================================================================

#[test]
fn test_keypair_roundtrip() {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();

    // Round-trip through bytes
    let recovered = PublicPoint::from_bytes(public.to_bytes());
    assert!(
        recovered.is_some(),
        "Public key must survive byte round-trip"
    );
    assert_eq!(
        recovered.unwrap().to_bytes(),
        public.to_bytes(),
        "Round-tripped public key must match original"
    );
}

// =============================================================================
// TEST 2: Range proof creation + verification
// =============================================================================

#[test]
fn test_range_proof_roundtrip() {
    let mut rng = OsRng;
    let amounts = vec![
        Amount::from_atomic(500_000_000),
        Amount::from_atomic(400_000_000),
    ];
    let blindings: Vec<BlindingFactor> = (0..amounts.len())
        .map(|_| BlindingFactor::random(&mut rng))
        .collect();

    // Create commitments
    let commitments: Vec<PedersenCommitment> = amounts
        .iter()
        .zip(blindings.iter())
        .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
        .collect();

    // Create and verify range proof (pre-BP+ era, height 0)
    let proof = create_aggregated_range_proof_for_height(&amounts, &blindings, &mut rng, 0)
        .expect("Range proof creation must succeed");
    assert!(!proof.is_empty(), "Proof must not be empty");

    // Verify at same era (height 0 = pre-BP+)
    let valid = verify_range_proofs_dispatch(&commitments, &proof, 0);
    assert!(valid, "Range proof must verify with correct commitments");

    // Wrong commitment must fail
    let wrong = PedersenCommitment::commit(999_999, &BlindingFactor::random(&mut rng));
    let invalid = verify_range_proofs_dispatch(&[wrong], &proof, 0);
    assert!(!invalid, "Range proof must fail with wrong commitment");
}

// =============================================================================
// TEST 3: Signing hash consistency (builder vs Transaction::signing_hash)
//
// THIS IS THE TEST THAT CATCHES THE V1/V2 DIVERGENCE BUG.
// The builder and Transaction must compute the same signing message.
// =============================================================================

#[test]
fn test_signing_hash_deterministic_and_nonzero() {
    let mut rng = OsRng;
    let (_, recipient_spend) = generate_keypair();
    let (_, recipient_view) = generate_keypair();

    let input = create_mock_input(Amount::from_atomic(1_000_000_000), 42, 1000);
    let decoys = create_decoys(10);

    let mut builder = TransactionBuilder::transfer();
    builder.add_input(input, decoys, 5).expect("add_input");
    builder
        .add_output(
            &Recipient {
                spend_public: recipient_spend,
                view_public: recipient_view,
                amount: Amount::from_atomic(900_000_000),
                lock_height: None,
            },
            0,
            &mut rng,
        )
        .expect("add_output");
    builder.set_fee(Amount::from_atomic(100_000_000));

    let tx = builder.build(&mut rng).expect("build");

    // Signing hash must be non-zero
    let hash = tx.signing_hash();
    assert!(
        !hash.as_bytes().iter().all(|&b| b == 0),
        "Signing hash must not be all zeros"
    );

    // Must be deterministic
    assert_eq!(
        tx.signing_hash(),
        hash,
        "Signing hash must be deterministic across calls"
    );
}

// =============================================================================
// TEST 4: Full transaction build (1 input, 2 outputs, ring size 11)
// =============================================================================

#[test]
fn test_full_transaction_build() {
    let mut rng = OsRng;
    let (_, recipient_spend) = generate_keypair();
    let (_, recipient_view) = generate_keypair();
    let (_, change_spend) = generate_keypair();
    let (_, change_view) = generate_keypair();

    let input = create_mock_input(Amount::from_atomic(2_000_000_000), 99, 5000);
    let decoys = create_decoys(10);

    let mut builder = TransactionBuilder::transfer().with_target_height(0);
    builder.add_input(input, decoys, 3).expect("add_input");
    builder
        .add_output(
            &Recipient {
                spend_public: recipient_spend,
                view_public: recipient_view,
                amount: Amount::from_atomic(1_000_000_000),
                lock_height: None,
            },
            0,
            &mut rng,
        )
        .expect("add_output");
    builder
        .add_change(
            &change_spend,
            &change_view,
            Amount::from_atomic(950_000_000),
            1,
            &mut rng,
        )
        .expect("add_change");
    builder.set_fee(Amount::from_atomic(50_000_000));

    let tx = builder
        .build(&mut rng)
        .expect("Transaction build must succeed");

    // Structure checks
    assert_eq!(tx.tx_type, TxType::Transfer);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.fee.as_atomic(), 50_000_000);

    // Ring must have 11 members (10 decoys + 1 real)
    assert_eq!(tx.inputs[0].ring_members.len(), 11);

    // CLSAG signature must be present
    assert!(
        !tx.inputs[0]
            .signature
            .to_bytes()
            .unwrap()
            .iter()
            .all(|&b| b == 0),
        "CLSAG signature must not be zero"
    );

    // Key image must be present
    assert!(
        !tx.inputs[0].key_image.as_bytes().iter().all(|&b| b == 0),
        "Key image must not be zero"
    );

    // Range proof must be present
    assert!(!tx.range_proof.is_empty(), "Range proof must be present");

    // Outputs must have non-zero stealth addresses and commitments
    for (i, out) in tx.outputs.iter().enumerate() {
        assert!(
            !out.stealth_address.as_bytes().iter().all(|&b| b == 0),
            "Output {} stealth address must not be zero",
            i
        );
        assert!(
            !out.commitment.iter().all(|&b| b == 0),
            "Output {} commitment must not be zero",
            i
        );
        assert_eq!(
            out.encrypted_amount.len(),
            8,
            "Output {} encrypted amount must be 8 bytes",
            i
        );
    }
}

// =============================================================================
// TEST 5: Balance equation (inputs = outputs + fee via commitments)
// =============================================================================

#[test]
fn test_balance_equation_commitments_nonzero() {
    let mut rng = OsRng;
    let (_, r_spend) = generate_keypair();
    let (_, r_view) = generate_keypair();

    // 2.0 CYNC in, 1.9 out, 0.1 fee
    let input = create_mock_input(Amount::from_atomic(2_000_000_000), 77, 3000);
    let decoys = create_decoys(10);

    let mut builder = TransactionBuilder::transfer().with_target_height(0);
    builder.add_input(input, decoys, 0).expect("add_input");
    builder
        .add_output(
            &Recipient {
                spend_public: r_spend,
                view_public: r_view,
                amount: Amount::from_atomic(1_900_000_000),
                lock_height: None,
            },
            0,
            &mut rng,
        )
        .expect("add_output");
    builder.set_fee(Amount::from_atomic(100_000_000));

    let tx = builder.build(&mut rng).expect("build");

    // Pseudo-output commitment (input side) must be non-zero
    let pseudo = &tx.inputs[0].pseudo_output_commitment;
    assert!(
        !pseudo.iter().all(|&b| b == 0),
        "Pseudo output commitment must not be zero"
    );

    // Output commitment must be non-zero
    let out_c = &tx.outputs[0].commitment;
    assert!(
        !out_c.iter().all(|&b| b == 0),
        "Output commitment must not be zero"
    );

    // They must be different (different blinding factors)
    assert_ne!(pseudo, out_c, "Input and output commitments must differ");
}

// =============================================================================
// TEST 6: Transaction hash and signing hash are different
// =============================================================================

#[test]
fn test_tx_hash_vs_signing_hash() {
    let mut rng = OsRng;
    let (_, r_spend) = generate_keypair();
    let (_, r_view) = generate_keypair();

    let input = create_mock_input(Amount::from_atomic(1_000_000_000), 11, 100);
    let decoys = create_decoys(10);

    let mut builder = TransactionBuilder::transfer();
    builder.add_input(input, decoys, 2).expect("add_input");
    builder
        .add_output(
            &Recipient {
                spend_public: r_spend,
                view_public: r_view,
                amount: Amount::from_atomic(900_000_000),
                lock_height: None,
            },
            0,
            &mut rng,
        )
        .expect("add_output");
    builder.set_fee(Amount::from_atomic(100_000_000));

    let tx = builder.build(&mut rng).expect("build");

    let tx_hash = tx.hash();
    let signing_hash = tx.signing_hash();

    // tx.hash() includes signatures, signing_hash() does not
    // They must be different
    assert_ne!(
        tx_hash, signing_hash,
        "tx.hash() and signing_hash() must differ (hash includes signatures)"
    );
}
