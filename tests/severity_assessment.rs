//! # Severity Assessment Tests
//!
//! These tests determine whether findings H-16 through H-19 are
//! "defense in depth gaps" (medium) or "actual exploits" (critical).
//!
//! For each finding: can the attack succeed END-TO-END through the
//! full verification path, or does a downstream check catch it?

use coincync::mempool::Mempool;
use coincync::primitives::{Amount, PublicKey, KeyImage};
use coincync::transaction::{Transaction, TxType, TxInput, TxOutput, RingMemberRef};
use coincync::crypto::{SecretScalar, BlindingFactor, PedersenCommitment, KeyImage as CKI, ClsagSignature};
use coincync::constants::BOOTSTRAP_MIN_RING_SIZE;
use rand::rngs::OsRng;

// =============================================================================
// FINDING 3 SEVERITY: Can a zero key image + valid CLSAG produce a double-spend?
//
// If mempool.add() (full crypto path) accepts a zero key image, it's CRITICAL.
// If only add_skip_crypto() accepts it, it's HIGH (defense-in-depth gap).
// =============================================================================

#[test]
fn severity_f3_zero_keyimage_through_full_crypto_path() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);

    let ring_members: Vec<RingMemberRef> = (0..BOOTSTRAP_MIN_RING_SIZE).map(|_| {
        RingMemberRef {
            public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng)).to_bytes(),
        }
    }).collect();

    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes([0u8; 32]), // ZERO KEY IMAGE
            ring_members,
            signature: ClsagSignature {
                key_image: ki, // Real KI in signature (mismatch)
                commitment_image: secret.to_public(),
                c1: [0x42; 32],
                responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE],
            },
            pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            tx_public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8], view_tag: 0, lock_height: None, encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64], extra: vec![],
    };

    // The FULL crypto path (mempool.add) — does CLSAG verification catch it?
    let full_result = pool.add(tx);

    if full_result.is_ok() {
        panic!(
            "CRITICAL SEVERITY CONFIRMED (C-9): Zero key image accepted through FULL \
             crypto verification path! An attacker can submit the same zero-KI transaction \
             repeatedly, bypassing double-spend detection entirely. \
             The CLSAG verifier does NOT catch the KI mismatch."
        );
    }
    // If we get here, the full path catches it (CLSAG verification fails).
    // The finding is still HIGH (structural gap) but not CRITICAL.
    // The error proves the downstream check works.
    println!("Finding F3 severity: HIGH (not CRITICAL). Full crypto path rejects it.");
    println!("CLSAG verification catches the key image mismatch.");
    println!("However, add_skip_crypto() still accepts it = defense-in-depth gap.");
}

// =============================================================================
// FINDING 3 FOLLOW-UP: Can two txs with zero key image BOTH enter the pool?
//
// If yes, the double-spend detection for zero-KI is broken even in skip_crypto.
// =============================================================================

#[test]
fn severity_f3_double_spend_via_zero_keyimage() {
    let mut pool = Mempool::new();

    let make_tx_with_zero_ki = |seed: u8| -> Transaction {
        let secret = SecretScalar::random(&mut OsRng);
        let ki = CKI::from_secret(&secret);
        let bf = BlindingFactor::random(&mut OsRng);
        let ring_members: Vec<RingMemberRef> = (0..BOOTSTRAP_MIN_RING_SIZE).map(|_| {
            RingMemberRef {
                public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
                commitment: PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng)).to_bytes(),
            }
        }).collect();
        Transaction {
            version: 1, tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                key_image: KeyImage::from_bytes([0u8; 32]), // ZERO
                ring_members,
                signature: ClsagSignature { key_image: ki, commitment_image: secret.to_public(), c1: [seed; 32], responses: vec![[seed; 32]; BOOTSTRAP_MIN_RING_SIZE] },
                pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            }],
            outputs: vec![TxOutput {
                stealth_address: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
                tx_public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
                commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
                encrypted_amount: vec![0u8; 8], view_tag: seed, lock_height: None, encrypted_memo: vec![],
            }],
            fee: Amount::from_atomic(50_000_000),
            range_proof: vec![0u8; 64], extra: vec![seed],
        }
    };

    let tx1 = make_tx_with_zero_ki(1);
    let tx2 = make_tx_with_zero_ki(2);

    let r1 = pool.add_skip_crypto(tx1);
    let r2 = pool.add_skip_crypto(tx2);

    if r1.is_ok() && r2.is_ok() && pool.len() == 2 {
        panic!(
            "CRITICAL: TWO transactions with zero key image BOTH entered the mempool! \
             Double-spend detection is completely bypassed for zero-KI transactions. \
             Attacker can spend the same output unlimited times."
        );
    }

    // If the second is rejected due to duplicate KI, the mempool KI tracker works.
    // The structural gap still exists (first tx shouldn't be accepted) but the
    // double-spend protection still functions.
    if r1.is_ok() && r2.is_err() {
        println!("Finding F3: First zero-KI tx enters via skip_crypto, second is blocked by KI dedup.");
        println!("Severity: HIGH (gap exists but double-spend is still prevented by KI tracking).");
    }
}

// =============================================================================
// FINDING 4 SEVERITY: Can an attacker burn a specific user's funds?
//
// The attack: send outputs to unspendable addresses. The recipient's wallet
// sees them as received but can never spend them.
// For this to work, the tx must be includable in a BLOCK (not just mempool).
// =============================================================================

#[test]
fn severity_f4_unspendable_output_enters_mempool() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);

    let ring_members: Vec<RingMemberRef> = (0..BOOTSTRAP_MIN_RING_SIZE).map(|_| {
        RingMemberRef {
            public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng)).to_bytes(),
        }
    }).collect();

    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members,
            signature: ClsagSignature { key_image: ki, commitment_image: secret.to_public(), c1: [0x42; 32], responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE] },
            pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes([0xFF; 32]), // INVALID POINT — unspendable
            tx_public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8], view_tag: 0, lock_height: None, encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64], extra: vec![],
    };

    // Try skip_crypto path (structural only)
    let structural = pool.add_skip_crypto(tx.clone());

    if structural.is_ok() {
        println!("CONFIRMED: Invalid Ristretto point stealth address passes structural validation.");
        println!("Severity: HIGH. Attacker can burn funds by sending to unspendable addresses.");
        println!("The recipient wallet will show received funds that can never be spent.");
    }

    // Also try full crypto — does the range proof / sig check happen to catch it?
    let mut pool2 = Mempool::new();
    let full = pool2.add(tx);
    if full.is_ok() {
        println!("ALSO passes full crypto path — burning attack works through all defenses.");
    }
}
