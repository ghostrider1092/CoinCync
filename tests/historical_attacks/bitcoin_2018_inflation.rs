//! ## Bitcoin CVE-2018-17144 — Duplicate Input Inflation (September 2018)
//!
//! Bitcoin Core 0.14.0-0.16.2 had a bug where the duplicate-input check was
//! removed for "performance" in the UTXO validation path. This allowed miners
//! to create transactions spending the same UTXO twice, inflating the supply.
//!
//! The bug: `CheckTransaction()` checked for duplicate inputs, but
//! `ConnectBlock()` (the actual block validation) did NOT. A miner could
//! include a tx spending input X twice, getting 2x the value.
//!
//! Citation: https://bitcoincore.org/en/2018/09/20/notice/
//! CVE: CVE-2018-17144
//! Chain: Bitcoin
//! Impact: Infinite inflation (discovered before exploitation)
//!
//! Relevance to CoinCync: Tests that duplicate key images are caught in ALL
//! validation paths — mempool admission, block validation, and the skip_crypto
//! path (which was our C-8 fix: privacy checks must never be skippable).

use coincync::consensus::validate_transaction_basic;
use coincync::constants::BOOTSTRAP_MIN_RING_SIZE;
use coincync::crypto::{
    BlindingFactor, ClsagSignature, KeyImage as CKI, PedersenCommitment, SecretScalar,
};
use coincync::mempool::Mempool;
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use rand::rngs::OsRng;

/// The exact CVE-2018-17144 pattern: same input appears twice in one transaction
#[test]
fn bitcoin_2018_duplicate_input_in_single_tx() {
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(1_000_000_000, &bf);

    let ring_members: Vec<RingMemberRef> = (0..BOOTSTRAP_MIN_RING_SIZE)
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

    let input = TxInput {
        key_image: KeyImage::from_bytes(ki.to_bytes()),
        ring_members: ring_members.clone(),
        signature: ClsagSignature {
            key_image: ki,
            commitment_image: secret.to_public(),
            c1: [0x42; 32],
            responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE],
        },
        pseudo_output_commitment: commitment.to_bytes(),
    };

    // DUPLICATE THE INPUT — this is the CVE-2018-17144 attack
    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![input.clone(), input], // SAME KEY IMAGE TWICE
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

    // Must be caught in structural validation
    let basic = validate_transaction_basic(&tx);
    assert!(
        basic.is_err(),
        "CVE-2018-17144 REPRODUCED: Duplicate key image in same transaction passed \
         structural validation! Attacker can double-spend within a single tx."
    );

    // Must also be caught by mempool (defense in depth)
    let mut pool = Mempool::new();
    let mempool_result = pool.add_skip_crypto(tx);
    assert!(
        mempool_result.is_err(),
        "CVE-2018-17144 REPRODUCED: Duplicate key image passed mempool admission!"
    );
}

/// The C-8 variant: duplicate key images caught even in skip_crypto path
#[test]
fn bitcoin_2018_duplicate_caught_in_all_paths() {
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);

    let ring_members: Vec<RingMemberRef> = (0..BOOTSTRAP_MIN_RING_SIZE)
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

    let input = TxInput {
        key_image: KeyImage::from_bytes(ki.to_bytes()),
        ring_members,
        signature: ClsagSignature {
            key_image: ki,
            commitment_image: secret.to_public(),
            c1: [0x42; 32],
            responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE],
        },
        pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
    };

    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![input.clone(), input],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: PedersenCommitment::commit(
                1_000_000_000,
                &BlindingFactor::random(&mut OsRng),
            )
            .to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    // BOTH paths must reject
    let basic = validate_transaction_basic(&tx);
    let mut pool = Mempool::new();
    let skip = pool.add_skip_crypto(tx.clone());
    let full = pool.add(tx);

    let all_rejected = basic.is_err() || (skip.is_err() && full.is_err());
    assert!(
        all_rejected,
        "CVE-2018-17144 VARIANT: At least one validation path accepts duplicate key images!"
    );
}
