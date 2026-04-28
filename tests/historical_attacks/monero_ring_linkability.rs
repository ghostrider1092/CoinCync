//! ## Monero Ring Traceability — Academic Analysis (2017)
//!
//! Miller et al. showed that pre-2017 Monero transactions with ring size 1
//! (no decoys) were trivially traceable. Worse: these traceable spends could
//! be used as "known real spends" to eliminate decoys in later rings,
//! creating a cascade of deanonymization.
//!
//! Citation: Miller et al., "An Empirical Analysis of Traceability in the
//!           Monero Blockchain," PoPETs 2017
//! Chain: Monero (pre-mandatory ring size enforcement)
//! Impact: Majority of historical Monero transactions traceable

use coincync::mempool::Mempool;
use coincync::primitives::{Amount, PublicKey, KeyImage};
use coincync::transaction::{Transaction, TxType, TxInput, TxOutput, RingMemberRef};
use coincync::consensus::validate_transaction_basic;
use coincync::crypto::{SecretScalar, BlindingFactor, PedersenCommitment, KeyImage as CKI, ClsagSignature};
use coincync::constants::BOOTSTRAP_MIN_RING_SIZE;
use rand::rngs::OsRng;

/// Test: Ring size 1 (no decoys) is rejected at consensus level
#[test]
fn monero_linkability_ring_size_1_rejected() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);
    let commit = PedersenCommitment::commit(1_000_000_000, &bf);

    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members: vec![RingMemberRef { // ONLY 1 MEMBER
                public_key: PublicKey::from_bytes(secret.to_public().to_bytes()),
                commitment: commit.to_bytes(),
            }],
            signature: ClsagSignature { key_image: ki, commitment_image: secret.to_public(), c1: [0; 32], responses: vec![[0; 32]; 1] },
            pseudo_output_commitment: commit.to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            tx_public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: commit.to_bytes(), encrypted_amount: vec![0u8; 8], view_tag: 0, lock_height: None, encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(50_000_000),
        range_proof: vec![0u8; 64], extra: vec![],
    };

    let basic = validate_transaction_basic(&tx);
    let mempool = pool.add_skip_crypto(tx);
    assert!(
        basic.is_err() || mempool.is_err(),
        "MONERO LINKABILITY: Ring size 1 accepted! Transaction is trivially traceable."
    );
}

/// Test: Minimum ring size is at least 11 (sufficient for privacy)
#[test]
fn monero_linkability_minimum_ring_enforced() {
    assert!(
        BOOTSTRAP_MIN_RING_SIZE >= 11,
        "MONERO LINKABILITY: Minimum ring size is {} (must be >= 11). \
         Small rings are statistically traceable per Miller et al. 2017.",
        BOOTSTRAP_MIN_RING_SIZE
    );
}

/// Test: Ring size 10 (one below minimum) is rejected
#[test]
fn monero_linkability_below_minimum_rejected() {
    let mut pool = Mempool::new();
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);
    let below_min = BOOTSTRAP_MIN_RING_SIZE - 1;

    let ring: Vec<RingMemberRef> = (0..below_min).map(|_| RingMemberRef {
        public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
        commitment: PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng)).to_bytes(),
    }).collect();

    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members: ring,
            signature: ClsagSignature { key_image: ki, commitment_image: secret.to_public(), c1: [0; 32], responses: vec![[0; 32]; below_min] },
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

    let result = pool.add_skip_crypto(tx);
    assert!(
        result.is_err(),
        "MONERO LINKABILITY: Ring size {} (below minimum {}) was accepted!",
        below_min, BOOTSTRAP_MIN_RING_SIZE
    );
}
