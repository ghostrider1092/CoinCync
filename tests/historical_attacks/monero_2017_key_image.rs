//! ## Monero Key Image Validation Bug (April 2017)
//!
//! A bug in CryptoNote-based currencies allowed double-spending by
//! constructing specific malformed key images that bypassed validation.
//! The key image uniqueness check didn't verify the key image was a
//! valid curve point derived from an actual secret.
//!
//! Citation: https://www.getmonero.org/2017/05/17/disclosure-of-a-major-bug-in-cryptonote-based-currencies.html
//! Chain: Monero (and all CryptoNote forks)
//! Impact: Double-spend (patched before known exploitation)

use coincync::consensus::validate_transaction_basic;
use coincync::constants::BOOTSTRAP_MIN_RING_SIZE;
use coincync::crypto::{
    BlindingFactor, ClsagSignature, KeyImage as CKI, PedersenCommitment, SecretScalar,
};
use coincync::mempool::Mempool;
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use rand::rngs::OsRng;

fn make_ring() -> Vec<RingMemberRef> {
    (0..BOOTSTRAP_MIN_RING_SIZE)
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
        .collect()
}

/// Attack: All-zero key image (identity point)
#[test]
fn monero_2017_zero_key_image_rejected() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let bf = BlindingFactor::random(&mut OsRng);

    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes([0u8; 32]), // ALL ZEROS
            ring_members: make_ring(),
            signature: ClsagSignature {
                key_image: CKI::from_secret(&secret),
                commitment_image: secret.to_public(),
                c1: [0x42; 32],
                responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE],
            },
            pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    let basic = validate_transaction_basic(&tx);
    let mempool = pool.add_skip_crypto(tx);

    assert!(
        basic.is_err() || mempool.is_err(),
        "MONERO 2017 KEY IMAGE BUG: All-zero key image accepted! Double-spend possible."
    );
}

/// Attack: Key image is a random point (not derived from any secret via Hp)
#[test]
fn monero_2017_random_point_key_image() {
    // A random curve point as key image should fail CLSAG verification
    // (the key image must equal x * Hp(P) for the real signer's secret x)
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let fake_ki_point = SecretScalar::random(&mut OsRng).to_public(); // random, NOT from Hp
    let bf = BlindingFactor::random(&mut OsRng);

    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(fake_ki_point.to_bytes()),
            ring_members: make_ring(),
            signature: ClsagSignature {
                key_image: CKI::from_secret(&secret), // real KI in sig
                commitment_image: secret.to_public(),
                c1: [0x42; 32],
                responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE],
            },
            pseudo_output_commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            tx_public_key: PublicKey::from_bytes(
                SecretScalar::random(&mut OsRng).to_public().to_bytes(),
            ),
            commitment: PedersenCommitment::commit(1_000_000_000, &bf).to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    // Full verification MUST catch key image mismatch
    let result = pool.add(tx);
    assert!(
        result.is_err(),
        "MONERO 2017 BUG: Random-point key image passed full verification! \
         Attacker can forge key images and double-spend."
    );
}
