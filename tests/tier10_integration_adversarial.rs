//! # Tier 10 — Full-Stack Integration Adversarial Tests
//!
//! Tests multi-component attack chains that span the entire system:
//! chain + mempool + crypto + wallet + validation working together.
//!
//! These tests simulate real attacker scenarios where multiple
//! subsystems must cooperate to prevent damage.
//!
//! NO MOCKS. Every component is real.

use coincync::chain::Blockchain;
use coincync::mempool::Mempool;
use coincync::primitives::{Amount, PublicKey, SecretKey, Hash};
use coincync::transaction::{
    TransactionBuilder, SpendableInput, Recipient, DecoyOutput, Transaction,
};
use coincync::crypto::{
    SecretScalar, BlindingFactor, PedersenCommitment,
    KeyImage as CryptoKeyImage, create_aggregated_range_proof_for_height,
    verify_range_proofs_dispatch,
};
use coincync::wallet::{WalletKeys};
use coincync::consensus::validate_transaction_basic;
use coincync::constants::BOOTSTRAP_MIN_RING_SIZE;
use rand::rngs::OsRng;

// =============================================================================
// HELPERS
// =============================================================================

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    (SecretKey::from_bytes(secret.to_bytes()), PublicKey::from_bytes(public.to_bytes()))
}

fn build_real_tx(input_amount: u64, output_amount: u64, fee: u64) -> Transaction {
    assert_eq!(input_amount, output_amount + fee);
    let mut rng = OsRng;
    let (_, r_spend) = generate_keypair();
    let (_, r_view) = generate_keypair();

    let secret = SecretScalar::random(&mut rng);
    let input = SpendableInput {
        tx_hash: Hash::from_bytes([rand::random::<u8>(); 32]),
        output_index: 0,
        amount: Amount::from_atomic(input_amount),
        one_time_secret: SecretKey::from_bytes(secret.to_bytes()),
        blinding: BlindingFactor::random(&mut rng),
        height: 1000,
    };

    let decoys: Vec<DecoyOutput> = (0..BOOTSTRAP_MIN_RING_SIZE - 1).map(|_| {
        let s = SecretScalar::random(&mut rng);
        let bf = BlindingFactor::random(&mut rng);
        DecoyOutput {
            public_key: PublicKey::from_bytes(s.to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            height: 500,
        }
    }).collect();

    let real_idx = rand::random::<usize>() % BOOTSTRAP_MIN_RING_SIZE;
    let mut builder = TransactionBuilder::transfer().with_target_height(0);
    builder.add_input(input, decoys, real_idx).unwrap();
    builder.add_output(&Recipient {
        spend_public: r_spend,
        view_public: r_view,
        amount: Amount::from_atomic(output_amount),
        lock_height: None,
    }, 0, &mut rng).unwrap();
    builder.set_fee(Amount::from_atomic(fee));
    builder.build(&mut rng).unwrap()
}

// =============================================================================
// TEST 1: Full attack chain — build tx, admit to mempool, verify crypto
//
// Simulates: honest wallet builds tx → mempool admits → all checks pass
// =============================================================================

#[test]
fn tier10_honest_wallet_to_mempool_full_pipeline() {
    let mut pool = Mempool::new();
    let fee = 50_000_000;
    let output = 1_950_000_000;
    let tx = build_real_tx(output + fee, output, fee);

    // Structural validation passes
    let struct_result = validate_transaction_basic(&tx);
    assert!(struct_result.is_ok(), "Structural validation failed: {:?}", struct_result.err());

    // Full mempool admission (real crypto)
    let result = pool.add(tx.clone());
    assert!(result.is_ok(), "Full pipeline admission failed: {:?}", result.err());

    // Verify it's actually in the mempool
    assert!(pool.contains(&tx.hash()), "Transaction must be in mempool after admission");
    assert_eq!(pool.len(), 1);
}

// =============================================================================
// TEST 2: Inflation attack — forge commitment, attempt mempool admission
//
// Simulates: attacker modifies output commitment to claim more coins
// =============================================================================

#[test]
fn tier10_inflation_attack_blocked_at_every_layer() {
    let mut pool = Mempool::new();
    let fee = 50_000_000;
    let output = 1_950_000_000;
    let mut tx = build_real_tx(output + fee, output, fee);

    // Attacker forges output commitment to claim 999 billion
    let fake_bf = BlindingFactor::random(&mut OsRng);
    let inflated_commitment = PedersenCommitment::commit(999_000_000_000_000, &fake_bf);
    tx.outputs[0].commitment = inflated_commitment.to_bytes();

    // Layer 1: Range proof verification should fail (proof was for original amount)
    // Layer 2: Balance equation should fail (commitments don't sum)
    // Layer 3: Mempool must reject
    let result = pool.add(tx);
    assert!(
        result.is_err(),
        "INFLATION ATTACK SUCCEEDED! Forged commitment was accepted. \
         This means an attacker can print unlimited coins."
    );
}

// =============================================================================
// TEST 3: Double-spend race — two valid txs spending same output
//
// Simulates: attacker sends same coins to two different recipients
// =============================================================================

#[test]
fn tier10_double_spend_race_condition() {
    let mut pool = Mempool::new();

    // Build two valid transactions
    let tx1 = build_real_tx(2_000_000_000, 1_950_000_000, 50_000_000);
    let tx2 = build_real_tx(2_000_000_000, 1_950_000_000, 50_000_000);

    // First goes in fine
    pool.add(tx1.clone()).expect("first tx must be admitted");

    // Force second tx to use same key image (simulating spending same output)
    let mut tx2_double = tx2;
    tx2_double.inputs[0].key_image = tx1.inputs[0].key_image;

    // Mempool must reject (either wrong signature or duplicate key image)
    let result = pool.add(tx2_double);
    assert!(
        result.is_err(),
        "DOUBLE SPEND ACCEPTED! Two transactions spending the same output \
         were both admitted to the mempool."
    );
}

// =============================================================================
// TEST 4: Privacy attack — zero stealth address through full pipeline
//
// Simulates: attacker crafts a tx that reveals the recipient's identity
// =============================================================================

#[test]
fn tier10_privacy_violation_blocked_full_pipeline() {
    let mut pool = Mempool::new();
    let fee = 50_000_000;
    let output = 1_950_000_000;
    let mut tx = build_real_tx(output + fee, output, fee);

    // Attack: set stealth address to zero (reveals recipient)
    tx.outputs[0].stealth_address = PublicKey::from_bytes([0u8; 32]);

    let result = pool.add(tx);
    assert!(
        result.is_err(),
        "PRIVACY ATTACK SUCCEEDED! Transaction with zero stealth address was accepted. \
         This means recipient identity is exposed on-chain."
    );
}

// =============================================================================
// TEST 5: Wallet key isolation — view key doesn't enable spending
//
// Simulates: attacker compromises view key, tries to spend
// =============================================================================

#[test]
fn tier10_view_key_compromise_cannot_spend() {
    let seed = [42u8; 32];
    let mut keys = WalletKeys::from_seed(seed);
    keys.derive_epoch(0);
    let epoch = keys.current().unwrap();

    let view_secret = &epoch.view_secret;
    let spend_public = &epoch.spend_public;

    // Attacker has view_secret — can they derive the spend secret?
    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
    let view_derived_public = view_scalar.to_public();

    assert_ne!(
        view_derived_public.to_bytes(),
        spend_public.as_bytes().to_owned(),
        "CRITICAL: View key derives to spend public key! \
         View key compromise = full wallet compromise."
    );

    // Attacker tries to compute key image using view secret (wrong key)
    let fake_ki = CryptoKeyImage::from_secret(&view_scalar);
    let real_spend_scalar = SecretScalar::from_bytes(*epoch.spend_secret.as_bytes());
    let real_ki = CryptoKeyImage::from_secret(&real_spend_scalar);

    assert_ne!(
        fake_ki.to_bytes(),
        real_ki.to_bytes(),
        "CRITICAL: View key produces same key image as spend key!"
    );
}

// =============================================================================
// TEST 6: Range proof portability attack — use proof from different tx
//
// Simulates: attacker copies a valid range proof from one tx to another
// =============================================================================

#[test]
fn tier10_range_proof_not_portable() {
    let mut rng = OsRng;

    // Create a valid range proof for 1 CYNC
    let amount1 = Amount::from_atomic(1_000_000_000);
    let bf1 = BlindingFactor::random(&mut rng);
    let commitment1 = PedersenCommitment::commit(amount1.as_atomic(), &bf1);
    let proof1 = create_aggregated_range_proof_for_height(
        &[amount1], &[bf1.clone()], &mut rng, 0
    ).unwrap();

    // Verify it works with original commitment
    let proof_ref = coincync::crypto::RangeProof::from_bytes(&proof1.try_to_bytes().unwrap()).unwrap();
    assert!(
        verify_range_proofs_dispatch(&[commitment1.clone()], &proof_ref, 0),
        "Original proof must verify"
    );

    // Attack: use this proof with a DIFFERENT commitment (different amount)
    let bf2 = BlindingFactor::random(&mut rng);
    let fake_commitment = PedersenCommitment::commit(999_000_000_000, &bf2);

    let portable_attack = verify_range_proofs_dispatch(&[fake_commitment], &proof_ref, 0);
    assert!(
        !portable_attack,
        "RANGE PROOF PORTABILITY ATTACK SUCCEEDED! \
         A proof valid for 1 CYNC also validates for 999 CYNC."
    );
}

// =============================================================================
// TEST 7: Different wallet seeds produce completely different transactions
// =============================================================================

#[test]
fn tier10_different_wallets_different_key_images() {
    let _rng = OsRng;

    // Two different wallets spending same amount
    let tx1 = build_real_tx(2_000_000_000, 1_950_000_000, 50_000_000);
    let tx2 = build_real_tx(2_000_000_000, 1_950_000_000, 50_000_000);

    // Key images must be different (different secrets)
    assert_ne!(
        tx1.inputs[0].key_image,
        tx2.inputs[0].key_image,
        "Different wallets must produce different key images"
    );

    // Transaction hashes must be different
    assert_ne!(tx1.hash(), tx2.hash(), "Different transactions must have different hashes");
}

// =============================================================================
// TEST 8: Transaction malleability — modifying extra field
//
// Simulates: relay node modifies extra field to change tx hash
// =============================================================================

#[test]
fn tier10_tx_malleability_changes_hash() {
    let tx = build_real_tx(2_000_000_000, 1_950_000_000, 50_000_000);
    let original_hash = tx.hash();

    // Attacker modifies the extra field
    let mut malleable_tx = tx.clone();
    malleable_tx.extra = vec![0xFF; 32];

    let new_hash = malleable_tx.hash();

    // The hash MUST change (if it doesn't, the extra field isn't covered)
    assert_ne!(
        original_hash, new_hash,
        "Modifying extra field must change tx hash (prevents malleability)"
    );

    // The signing hash should also change (CLSAG covers extra)
    let original_signing = tx.signing_hash();
    let malleable_signing = malleable_tx.signing_hash();
    assert_ne!(
        original_signing, malleable_signing,
        "Modifying extra must change signing hash (CLSAG binds all fields)"
    );
}

// =============================================================================
// TEST 9: Chain + mempool consistency — confirmed tx removed from mempool
// =============================================================================

#[test]
fn tier10_chain_mempool_consistency() {
    let chain = Blockchain::new();
    chain.init_genesis().unwrap();
    let mut pool = Mempool::new();

    // Build two valid txs
    let tx1 = build_real_tx(2_000_000_000, 1_950_000_000, 50_000_000);
    let tx2 = build_real_tx(2_000_000_000, 1_950_000_000, 50_000_000);

    pool.add(tx1.clone()).expect("tx1 admitted");
    pool.add(tx2.clone()).expect("tx2 admitted");
    assert_eq!(pool.len(), 2);

    // Simulate tx1 being confirmed in a block
    pool.remove_confirmed(&[tx1.clone()]);
    assert_eq!(pool.len(), 1, "Confirmed tx must be removed");
    assert!(!pool.contains(&tx1.hash()), "tx1 should no longer be in mempool");
    assert!(pool.contains(&tx2.hash()), "tx2 should remain in mempool");
}

// =============================================================================
// TEST 10: Multi-input transaction — all inputs verified independently
// =============================================================================

#[test]
fn tier10_multi_input_all_verified() {
    let mut rng = OsRng;
    let (_, r_spend) = generate_keypair();
    let (_, r_view) = generate_keypair();

    // Build a 2-input transaction
    let input1 = SpendableInput {
        tx_hash: Hash::from_bytes([1u8; 32]),
        output_index: 0,
        amount: Amount::from_atomic(1_000_000_000),
        one_time_secret: SecretKey::from_bytes(SecretScalar::random(&mut rng).to_bytes()),
        blinding: BlindingFactor::random(&mut rng),
        height: 1000,
    };
    let input2 = SpendableInput {
        tx_hash: Hash::from_bytes([2u8; 32]),
        output_index: 0,
        amount: Amount::from_atomic(1_000_000_000),
        one_time_secret: SecretKey::from_bytes(SecretScalar::random(&mut rng).to_bytes()),
        blinding: BlindingFactor::random(&mut rng),
        height: 1000,
    };

    let decoys1: Vec<DecoyOutput> = (0..BOOTSTRAP_MIN_RING_SIZE - 1).map(|_| {
        let s = SecretScalar::random(&mut rng);
        let bf = BlindingFactor::random(&mut rng);
        DecoyOutput {
            public_key: PublicKey::from_bytes(s.to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            height: 500,
        }
    }).collect();
    let decoys2 = decoys1.clone();

    let mut builder = TransactionBuilder::transfer().with_target_height(0);
    builder.add_input(input1, decoys1, 0).unwrap();
    builder.add_input(input2, decoys2, 3).unwrap();
    builder.add_output(&Recipient {
        spend_public: r_spend,
        view_public: r_view,
        amount: Amount::from_atomic(1_950_000_000),
        lock_height: None,
    }, 0, &mut rng).unwrap();
    builder.set_fee(Amount::from_atomic(50_000_000));

    let tx = builder.build(&mut rng).expect("multi-input build");

    // Verify both inputs have distinct key images
    assert_ne!(
        tx.inputs[0].key_image,
        tx.inputs[1].key_image,
        "Multi-input tx must have distinct key images per input"
    );

    // Full mempool admission
    let mut pool = Mempool::new();
    let result = pool.add(tx);
    assert!(
        result.is_ok(),
        "Multi-input transaction must be accepted through full crypto pipeline: {:?}",
        result.err()
    );
}

// =============================================================================
// TEST 11: Wallet seed → keys → transaction → mempool (complete lifecycle)
// =============================================================================

#[test]
fn tier10_complete_lifecycle_seed_to_mempool() {
    let mut rng = OsRng;

    // Step 1: Generate wallet from seed
    let seed = [77u8; 32];
    let mut keys = WalletKeys::from_seed(seed);
    keys.derive_epoch(0);
    let epoch = keys.current().unwrap();

    // Step 2: Generate recipient address
    let (_, recipient_spend) = generate_keypair();
    let (_, recipient_view) = generate_keypair();

    // Step 3: Create a spendable input using wallet's spend secret
    let spend_scalar = SecretScalar::from_bytes(*epoch.spend_secret.as_bytes());
    let input = SpendableInput {
        tx_hash: Hash::from_bytes([42u8; 32]),
        output_index: 0,
        amount: Amount::from_atomic(5_000_000_000),
        one_time_secret: SecretKey::from_bytes(spend_scalar.to_bytes()),
        blinding: BlindingFactor::random(&mut rng),
        height: 2000,
    };

    // Step 4: Build decoy ring
    let decoys: Vec<DecoyOutput> = (0..BOOTSTRAP_MIN_RING_SIZE - 1).map(|_| {
        let s = SecretScalar::random(&mut rng);
        let bf = BlindingFactor::random(&mut rng);
        DecoyOutput {
            public_key: PublicKey::from_bytes(s.to_public().to_bytes()),
            commitment: PedersenCommitment::commit(5_000_000_000, &bf).to_bytes(),
            height: 1500,
        }
    }).collect();

    // Step 5: Build transaction
    let mut builder = TransactionBuilder::transfer().with_target_height(0);
    builder.add_input(input, decoys, 5).unwrap();
    builder.add_output(&Recipient {
        spend_public: recipient_spend,
        view_public: recipient_view,
        amount: Amount::from_atomic(4_900_000_000),
        lock_height: None,
    }, 0, &mut rng).unwrap();
    builder.set_fee(Amount::from_atomic(100_000_000));

    let tx = builder.build(&mut rng).expect("build from wallet keys");

    // Step 6: Full crypto verification admission
    let mut pool = Mempool::new();
    let result = pool.add(tx);
    assert!(
        result.is_ok(),
        "Complete lifecycle (seed → keys → tx → mempool) FAILED: {:?}",
        result.err()
    );
}
