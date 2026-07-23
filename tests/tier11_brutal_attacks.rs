//! # Tier 11 — Brutal Attack Scenarios
//!
//! These tests simulate actual attacks that have destroyed real blockchains:
//! - Inflation bugs (Bitcoin CVE-2018-17144 equivalent)
//! - Commitment overflow (Monero infinite money bug equivalent)
//! - Key image grinding
//! - Fee bypass
//! - Coinbase theft
//! - Merkle tree collision
//!
//! If ANY of these pass when they shouldn't, the chain is compromised.

use coincync::consensus::validate_transaction_basic;
use coincync::constants::{BOOTSTRAP_MIN_RING_SIZE, COIN, MIN_FEE_PER_BYTE, TOTAL_SUPPLY_TARGET};
use coincync::crypto::{
    clsag_sign, clsag_verify, create_aggregated_range_proof_for_height,
    verify_range_proofs_dispatch, BlindingFactor, ClsagRingMember, ClsagSignature, EcCommitment,
    KeyImage as CryptoKeyImage, PedersenCommitment, PublicPoint, RangeProof, SecretScalar,
};
use coincync::mempool::Mempool;
use coincync::primitives::{merkle_root, Amount, Hash, KeyImage, PublicKey};
use coincync::transaction::{DecoyOutput, Recipient, SpendableInput, TransactionBuilder};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use rand::rngs::OsRng;

// =============================================================================
// HELPERS
// =============================================================================

fn generate_keypair() -> (coincync::primitives::SecretKey, PublicKey) {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    (
        coincync::primitives::SecretKey::from_bytes(secret.to_bytes()),
        PublicKey::from_bytes(public.to_bytes()),
    )
}

fn build_legit_tx(fee: u64) -> Transaction {
    let mut rng = OsRng;
    let output_amount = 2_000_000_000u64 - fee;
    let (_, r_spend) = generate_keypair();
    let (_, r_view) = generate_keypair();
    let secret = SecretScalar::random(&mut rng);
    let input = SpendableInput {
        tx_hash: Hash::from_bytes([rand::random::<u8>(); 32]),
        output_index: 0,
        amount: Amount::from_atomic(2_000_000_000),
        one_time_secret: coincync::primitives::SecretKey::from_bytes(secret.to_bytes()),
        blinding: BlindingFactor::random(&mut rng),
        height: 1000,
    };
    let decoys: Vec<DecoyOutput> = (0..BOOTSTRAP_MIN_RING_SIZE - 1)
        .map(|_| {
            let s = SecretScalar::random(&mut rng);
            let bf = BlindingFactor::random(&mut rng);
            DecoyOutput {
                public_key: PublicKey::from_bytes(s.to_public().to_bytes()),
                commitment: PedersenCommitment::commit(2_000_000_000, &bf).to_bytes(),
                height: 500,
            }
        })
        .collect();
    let real_idx = rand::random::<usize>() % BOOTSTRAP_MIN_RING_SIZE;
    let mut builder = TransactionBuilder::transfer().with_target_height(0);
    builder.add_input(input, decoys, real_idx).unwrap();
    builder
        .add_output(
            &Recipient {
                spend_public: r_spend,
                view_public: r_view,
                amount: Amount::from_atomic(output_amount),
                lock_height: None,
            },
            0,
            &mut rng,
        )
        .unwrap();
    builder.set_fee(Amount::from_atomic(fee));
    builder.build(&mut rng).unwrap()
}

// =============================================================================
// ATTACK 1: INFLATION — Duplicate input key images in same transaction
//
// CVE-2018-17144 equivalent. Bitcoin let you spend the same input twice
// in one transaction, doubling your money.
// =============================================================================

#[test]
fn attack_duplicate_key_image_in_same_tx() {
    let mut pool = Mempool::new();
    let mut tx = build_legit_tx(50_000_000);

    // Clone the first input (same key image, same signature)
    let dup_input = tx.inputs[0].clone();
    tx.inputs.push(dup_input);

    let result = pool.add(tx.clone());
    let basic = validate_transaction_basic(&tx);

    assert!(
        result.is_err() || basic.is_err(),
        "INFLATION BUG: Duplicate key image in same transaction was ACCEPTED! \
         Attacker can double-spend within a single tx."
    );
}

// =============================================================================
// ATTACK 2: INFLATION — Output commitment sum exceeds input
//
// Create outputs that commit to MORE than inputs. If balance check is
// broken, attacker prints unlimited money.
// =============================================================================

#[test]
fn attack_output_exceeds_input_commitment_arithmetic() {
    let mut pool = Mempool::new();
    let mut tx = build_legit_tx(50_000_000);

    // Replace output commitment with one committing to u64::MAX
    let huge_bf = BlindingFactor::random(&mut OsRng);
    let huge_commit = PedersenCommitment::commit(u64::MAX, &huge_bf);
    tx.outputs[0].commitment = huge_commit.to_bytes();

    let result = pool.add(tx);
    assert!(
        result.is_err(),
        "INFLATION BUG: Output committing to u64::MAX was ACCEPTED! \
         Balance equation is broken."
    );
}

// =============================================================================
// ATTACK 3: INFLATION — Negative amount via wraparound
//
// In Pedersen commitments: C = v*H + r*G. If v wraps around the group
// order, you could commit to a "negative" amount that looks like a huge
// positive when interpreted as u64.
// =============================================================================

#[test]
fn attack_commitment_wraparound() {
    let mut rng = OsRng;

    // Try to create a range proof for amount 0 but commitment for u64::MAX
    let amount = Amount::from_atomic(0);
    let bf = BlindingFactor::random(&mut rng);
    let _honest_commit = PedersenCommitment::commit(0, &bf);

    // Create proof for 0
    let proof =
        create_aggregated_range_proof_for_height(&[amount], &[bf.clone()], &mut rng, 0).unwrap();

    // But verify against a commitment for u64::MAX (different blinding)
    let evil_bf = BlindingFactor::random(&mut rng);
    let evil_commit = PedersenCommitment::commit(u64::MAX, &evil_bf);

    let proof_ref = RangeProof::from_bytes(&proof.try_to_bytes().unwrap()).unwrap();
    let result = verify_range_proofs_dispatch(&[evil_commit], &proof_ref, 0);
    assert!(
        !result,
        "INFLATION BUG: Range proof for 0 validates against commitment for u64::MAX!"
    );
}

// =============================================================================
// ATTACK 4: KEY IMAGE COLLISION — Two different secrets, same key image
//
// If key images collide, double-spend detection fails completely.
// This tests the mathematical impossibility.
// =============================================================================

#[test]
fn attack_key_image_collision_impossible() {
    // Generate 10,000 key images from random secrets
    let mut key_images = std::collections::HashMap::new();

    for i in 0..10_000u32 {
        let secret = SecretScalar::random(&mut OsRng);
        let ki = CryptoKeyImage::from_secret(&secret);
        let ki_bytes = ki.to_bytes();

        if let Some(prev_idx) = key_images.insert(ki_bytes, i) {
            panic!(
                "KEY IMAGE COLLISION at iteration {}! \
                 Same key image produced by secrets at index {} and {}. \
                 Double-spend detection is BROKEN.",
                i, prev_idx, i
            );
        }
    }
}

// =============================================================================
// ATTACK 5: COINBASE THEFT — Inject coinbase into mempool to steal block reward
// =============================================================================

#[test]
fn attack_coinbase_into_mempool() {
    let mut pool = Mempool::new();

    // Craft a coinbase transaction claiming the block reward
    let attacker_key = SecretScalar::random(&mut OsRng).to_public();
    let coinbase = Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(attacker_key.to_bytes()),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: PedersenCommitment::commit(
                5_000_000_000,
                &BlindingFactor::random(&mut OsRng),
            )
            .to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(0),
        range_proof: vec![],
        extra: vec![],
    };

    let result = pool.add(coinbase);
    assert!(
        result.is_err(),
        "COINBASE THEFT: Coinbase transaction entered the mempool! \
         Attacker can steal block rewards by injecting fake coinbase."
    );
}

// =============================================================================
// ATTACK 6: FEE BYPASS — Transaction size exceeds what fee covers
// =============================================================================

#[test]
fn attack_fee_bypass_bloated_extra() {
    let mut pool = Mempool::new();
    let mut tx = build_legit_tx(50_000_000);

    // Bloat the transaction with extra data — fee should now be insufficient
    tx.extra = vec![0xDE; 50_000]; // 50KB of garbage

    // Recalculate: fee should be size * MIN_FEE_PER_BYTE
    let required_fee = tx.size() as u64 * MIN_FEE_PER_BYTE;

    if tx.fee.as_atomic() < required_fee {
        let result = pool.add(tx);
        assert!(
            result.is_err(),
            "FEE BYPASS: Bloated transaction accepted with insufficient fee! \
             Attacker can spam the chain for free."
        );
    }
}

// =============================================================================
// ATTACK 7: CLSAG FORGERY — Attempt to sign without knowing the secret
//
// The attacker knows all ring members' public keys but NOT the secret.
// They try to forge a signature.
// =============================================================================

#[test]
fn attack_clsag_forgery_without_secret() {
    let ring_size = 11;
    let message = b"attacker_forged_this";

    // Build a real ring (attacker sees these on-chain)
    let ring: Vec<ClsagRingMember> = (0..ring_size)
        .map(|_| {
            let s = SecretScalar::random(&mut OsRng);
            let bf = BlindingFactor::random(&mut OsRng);
            let commit = PedersenCommitment::commit(1_000_000_000, &bf);
            ClsagRingMember::new(
                s.to_public(),
                EcCommitment::from_point(PublicPoint::from_bytes(commit.to_bytes()).unwrap()),
            )
        })
        .collect();

    let pseudo_output = EcCommitment::from_point(
        PublicPoint::from_bytes(
            PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng))
                .to_bytes(),
        )
        .unwrap(),
    );

    // Attacker's "forged" signature: random values stuffed into fields
    let fake_ki = CryptoKeyImage::from_secret(&SecretScalar::random(&mut OsRng));
    let forged_sig = ClsagSignature {
        key_image: fake_ki,
        commitment_image: SecretScalar::random(&mut OsRng).to_public(),
        c1: rand::random::<[u8; 32]>(),
        responses: (0..ring_size).map(|_| rand::random::<[u8; 32]>()).collect(),
    };

    let valid = clsag_verify(message, &ring, &pseudo_output, &forged_sig);
    assert!(
        !valid,
        "CLSAG FORGERY SUCCEEDED! Random values verified as valid signature. \
         Ring signatures provide ZERO security."
    );
}

// =============================================================================
// ATTACK 8: CLSAG FORGERY — Reuse signature from different message
//
// Attacker takes a valid signature for message A and tries to use it
// for message B (different transaction).
// =============================================================================

#[test]
fn attack_clsag_signature_not_replayable_across_messages() {
    let ring_size = 11;
    let real_secret = SecretScalar::random(&mut OsRng);
    let real_blinding = BlindingFactor::random(&mut OsRng);
    let pseudo_blinding = BlindingFactor::random(&mut OsRng);

    let mut ring: Vec<ClsagRingMember> = Vec::new();
    for i in 0..ring_size {
        let (pk, commit) = if i == 0 {
            (
                real_secret.to_public(),
                PedersenCommitment::commit(1_000_000_000, &real_blinding),
            )
        } else {
            let s = SecretScalar::random(&mut OsRng);
            let bf = BlindingFactor::random(&mut OsRng);
            (
                s.to_public(),
                PedersenCommitment::commit(1_000_000_000, &bf),
            )
        };
        ring.push(ClsagRingMember::new(
            pk,
            EcCommitment::from_point(PublicPoint::from_bytes(commit.to_bytes()).unwrap()),
        ));
    }

    let pseudo_output = EcCommitment::from_point(
        PublicPoint::from_bytes(
            PedersenCommitment::commit(1_000_000_000, &pseudo_blinding).to_bytes(),
        )
        .unwrap(),
    );
    let blinding_diff = SecretScalar::from_bytes(real_blinding.sub(&pseudo_blinding).to_bytes());

    // Sign message A
    let message_a = b"legitimate_transaction_hash_aaaa";
    let sig = clsag_sign(
        message_a,
        &ring,
        0,
        &real_secret,
        &blinding_diff,
        &pseudo_output,
        &mut OsRng,
    )
    .unwrap();

    // Verify it works for message A
    assert!(
        clsag_verify(message_a, &ring, &pseudo_output, &sig),
        "Original sig must verify"
    );

    // Try to replay for message B (different transaction)
    let message_b = b"attacker_wants_to_steal_funds_bb";
    let replay_valid = clsag_verify(message_b, &ring, &pseudo_output, &sig);
    assert!(
        !replay_valid,
        "SIGNATURE REPLAY ATTACK: Signature valid for message A also validates for message B! \
         Attacker can replay signatures across different transactions."
    );
}

// =============================================================================
// ATTACK 9: MERKLE TREE COLLISION — Two different tx sets, same root
// =============================================================================

#[test]
fn attack_merkle_collision_impossible() {
    // Create two different transaction sets
    let tx_a = build_legit_tx(50_000_000);
    let tx_b = build_legit_tx(60_000_000);

    let hash_a = tx_a.hash();
    let hash_b = tx_b.hash();

    // Transactions must have different hashes
    assert_ne!(
        hash_a, hash_b,
        "Different transactions must have different hashes"
    );

    // Merkle roots must be different for different sets
    let root_single_a = merkle_root(&[hash_a]);
    let root_single_b = merkle_root(&[hash_b]);
    assert_ne!(
        root_single_a, root_single_b,
        "Different tx sets must produce different merkle roots"
    );

    // Order matters
    let root_ab = merkle_root(&[hash_a, hash_b]);
    let root_ba = merkle_root(&[hash_b, hash_a]);
    assert_ne!(
        root_ab, root_ba,
        "Merkle root must be order-dependent (prevents reordering attacks)"
    );
}

// =============================================================================
// ATTACK 10: SUPPLY CAP — Verify total supply constant is enforced
// =============================================================================

#[test]
fn attack_supply_cap_correct() {
    // The total supply target must be exactly 100 million CYNC
    assert_eq!(
        TOTAL_SUPPLY_TARGET, 100_000_000u64,
        "SUPPLY CAP WRONG: Expected 100_000_000, got {}.",
        TOTAL_SUPPLY_TARGET
    );
    // COIN conversion must be consistent
    assert!(COIN > 0, "COIN constant must be nonzero");
}

// =============================================================================
// ATTACK 11: ZERO COMMITMENT — Hide money in identity point
//
// If commitment = identity (zero point), the balance equation breaks
// because identity is the additive identity in the group.
// =============================================================================

#[test]
fn attack_zero_commitment_rejected() {
    let mut pool = Mempool::new();
    let mut tx = build_legit_tx(50_000_000);

    // Set output commitment to all zeros (identity point attempt)
    tx.outputs[0].commitment = [0u8; 32];

    let result = pool.add(tx.clone());
    let basic = validate_transaction_basic(&tx);

    assert!(
        result.is_err() || basic.is_err(),
        "ZERO COMMITMENT ACCEPTED! Identity point in commitment means \
         balance equation is trivially satisfiable. Infinite money."
    );
}

// =============================================================================
// ATTACK 12: EMPTY INPUTS — Transfer with no inputs (money from nothing)
// =============================================================================

#[test]
fn attack_transfer_no_inputs() {
    let mut pool = Mempool::new();
    let attacker = SecretScalar::random(&mut OsRng).to_public();
    let bf = BlindingFactor::random(&mut OsRng);

    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![], // NO INPUTS — money from nothing
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(attacker.to_bytes()),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: PedersenCommitment::commit(999_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(0),
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    let result = pool.add(tx.clone());
    let basic = validate_transaction_basic(&tx);

    assert!(
        result.is_err() || basic.is_err(),
        "MONEY FROM NOTHING: Transfer with zero inputs was ACCEPTED!"
    );
}

// =============================================================================
// ATTACK 13: TYPE CONFUSION — Coinbase pretending to be Transfer
// =============================================================================

#[test]
fn attack_type_confusion_coinbase_as_transfer() {
    let mut pool = Mempool::new();
    let attacker = SecretScalar::random(&mut OsRng).to_public();
    let bf = BlindingFactor::random(&mut OsRng);

    // A transaction marked as Transfer but with no inputs (like coinbase)
    // Should be caught by validation
    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer, // claims to be transfer
        inputs: vec![],            // but has no inputs like coinbase
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(attacker.to_bytes()),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: PedersenCommitment::commit(5_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(0),
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    let result = pool.add(tx);
    assert!(
        result.is_err(),
        "TYPE CONFUSION: Coinbase disguised as Transfer was ACCEPTED! \
         Attacker can create money by submitting inputless 'transfers'."
    );
}

// =============================================================================
// ATTACK 14: RING SIZE 1 — Signer is trivially identified
// =============================================================================

#[test]
fn attack_ring_size_one_rejected() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CryptoKeyImage::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(1_000_000_000, &bf);

    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members: vec![RingMemberRef {
                // Only 1 ring member!
                public_key: PublicKey::from_bytes(secret.to_public().to_bytes()),
                commitment: commitment.to_bytes(),
            }],
            signature: ClsagSignature {
                key_image: ki,
                commitment_image: secret.to_public(),
                c1: [0; 32],
                responses: vec![[0; 32]; 1],
            },
            pseudo_output_commitment: commitment.to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: commitment.to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    let result = pool.add_skip_crypto(tx);
    assert!(
        result.is_err(),
        "PRIVACY DESTROYED: Ring size 1 accepted! Signer is trivially identifiable."
    );
}

// =============================================================================
// ATTACK 15: AMOUNT OVERFLOW — u64::MAX + 1 in fee calculation
// =============================================================================

#[test]
fn attack_amount_overflow_in_fee() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CryptoKeyImage::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(1_000_000_000, &bf);
    let ring_size = BOOTSTRAP_MIN_RING_SIZE;

    let ring_members: Vec<RingMemberRef> = (0..ring_size)
        .map(|_| RingMemberRef {
            public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: PedersenCommitment::commit(
                1_000_000_000,
                &BlindingFactor::random(&mut OsRng),
            )
            .to_bytes(),
        })
        .collect();

    // Fee set to u64::MAX — should not cause overflow in any calculation
    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members,
            signature: ClsagSignature {
                key_image: ki,
                commitment_image: secret.to_public(),
                c1: [0x42; 32],
                responses: vec![[0x13; 32]; ring_size],
            },
            pseudo_output_commitment: commitment.to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: commitment.to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(u64::MAX), // absurd fee
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    // Must not panic — either accepts or rejects gracefully
    let _ = pool.add_skip_crypto(tx);
    // If we get here without panicking, overflow handling works
}
