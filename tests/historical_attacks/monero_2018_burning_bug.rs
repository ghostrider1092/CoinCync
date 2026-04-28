//! ## Monero Burning Bug (September 2018)
//!
//! An attacker could burn another user's funds by sending to a provably
//! unspendable address. The recipient sees the funds but can never spend
//! them — the stealth address resolves to a point with no known discrete log.
//!
//! Citation: https://www.getmonero.org/2018/09/25/a-post-mortem-of-the-burning-bug.html
//! Chain: Monero
//! Impact: Fund destruction (patched before widespread exploitation)

use coincync::mempool::Mempool;
use coincync::primitives::{Amount, PublicKey, KeyImage};
use coincync::transaction::{Transaction, TxType, TxInput, TxOutput, RingMemberRef};
use coincync::consensus::validate_transaction_basic;
use coincync::crypto::{SecretScalar, BlindingFactor, PedersenCommitment, KeyImage as CKI, ClsagSignature};
use coincync::constants::BOOTSTRAP_MIN_RING_SIZE;
use rand::rngs::OsRng;

fn make_ring() -> Vec<RingMemberRef> {
    (0..BOOTSTRAP_MIN_RING_SIZE).map(|_| RingMemberRef {
        public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
        commitment: PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng)).to_bytes(),
    }).collect()
}

/// Attack: Output with zero stealth address (provably unspendable)
#[test]
fn monero_2018_zero_stealth_address_rejected() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);

    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members: make_ring(),
            signature: ClsagSignature { key_image: ki, commitment_image: secret.to_public(), c1: [0x42; 32], responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE] },
            pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes([0u8; 32]), // ZERO — unspendable
            tx_public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8], view_tag: 0, lock_height: None, encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64], extra: vec![],
    };

    let basic = validate_transaction_basic(&tx);
    let mempool = pool.add_skip_crypto(tx);
    assert!(
        basic.is_err() || mempool.is_err(),
        "BURNING BUG: Zero stealth address accepted! Attacker can burn others' funds."
    );
}

/// Attack: Output with all-0xFF address (likely not on curve)
#[test]
fn monero_2018_invalid_curve_point_address_rejected() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);

    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members: make_ring(),
            signature: ClsagSignature { key_image: ki, commitment_image: secret.to_public(), c1: [0x42; 32], responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE] },
            pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes([0xFF; 32]), // all-FF — not valid Ristretto
            tx_public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8], view_tag: 0, lock_height: None, encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64], extra: vec![],
    };

    let basic = validate_transaction_basic(&tx);
    let mempool = pool.add_skip_crypto(tx);
    assert!(
        basic.is_err() || mempool.is_err(),
        "BURNING BUG VARIANT: Invalid curve point address accepted!"
    );
}
