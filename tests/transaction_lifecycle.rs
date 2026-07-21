//! Transaction lifecycle integration tests (rewrite — targets 1.0 API).
//!
//! Replaces the pre-1.0 file that referenced the removed `SoloMiner`
//! helper and stale tx fields. This rewrite covers the mempool-side
//! lifecycle of a transaction — admission rules, fee policy, ring-size
//! enforcement, idempotency, and borsh round-trip stability — using
//! `Mempool::add_skip_crypto` as the admission entry point so tests
//! don't need to set up full CLSAG signing.
//!
//! Coverage rationale: the original file also tested miner / block
//! weight behavior, which depended on `SoloMiner`. That surface is now
//! tested directly in the `consensus::validation` lib test module and
//! via `cargo run --bin coincync-miner` smoke tests in CI. The
//! integration tests here focus on what only integration can catch:
//! the admission pipeline from raw `Transaction` input through the
//! real `Mempool` state transitions.

use coincync::constants::{BOOTSTRAP_MIN_RING_SIZE, MIN_FEE_PER_BYTE};
use coincync::crypto::{ClsagSignature, KeyImage as CryptoKeyImage, SecretScalar};
use coincync::mempool::Mempool;
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use rand::rngs::OsRng;

// =============================================================================
// Helpers
// =============================================================================

/// Build a well-formed Transfer transaction with the given parameters.
/// Always produces a structurally-valid tx with a crypto-checkable shape;
/// the CLSAG signature is a placeholder because tests enter via
/// `add_skip_crypto`, which bypasses ring-signature verification while
/// still enforcing all structural / policy rules (fee, ring size,
/// coinbase rejection, size cap).
fn make_transfer_tx(unique: u8, fee_atomic: u64, ring_size: usize) -> Transaction {
    let secret = SecretScalar::random(&mut OsRng);
    let pub_point = secret.to_public();
    let crypto_ki = CryptoKeyImage::from_secret(&secret);
    let key_image = KeyImage::from_bytes(crypto_ki.to_bytes());

    let ring_size = ring_size.max(BOOTSTRAP_MIN_RING_SIZE);
    let mut ring_members = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let rm_secret = SecretScalar::from_bytes([unique.wrapping_add(i as u8 + 1); 32]);
        let rm_pub = rm_secret.to_public();
        ring_members.push(RingMemberRef {
            public_key: PublicKey::from_bytes(rm_pub.to_bytes()),
            commitment: rm_pub.to_bytes(),
        });
    }

    let signature = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: pub_point,
        c1: [unique; 32],
        responses: vec![[unique; 32]; ring_size],
    };

    let out_secret = SecretScalar::from_bytes([unique.wrapping_add(99); 32]);
    let out_pub = out_secret.to_public();
    let output = TxOutput {
        stealth_address: PublicKey::from_bytes(out_pub.to_bytes()),
        tx_public_key: PublicKey::from_bytes(out_pub.to_bytes()),
        commitment: out_pub.to_bytes(),
        encrypted_amount: vec![0u8; 8],
        view_tag: unique,
        lock_height: None,
        encrypted_memo: Vec::new(),
    };

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image,
            ring_members,
            signature,
            pseudo_output_commitment: pub_point.to_bytes(),
        }],
        outputs: vec![output],
        fee: Amount::from_atomic(fee_atomic),
        range_proof: vec![0u8; 64], // non-empty as required by constitution
        extra: vec![unique],
    };

    // Bump fee to meet `MIN_FEE_PER_BYTE * size` if the caller passed a
    // too-low value. Tests that specifically want sub-minimum fee must
    // skip this helper.
    let size = tx.size();
    let min_fee = size as u64 * MIN_FEE_PER_BYTE;
    if tx.fee.as_atomic() < min_fee {
        tx.fee = Amount::from_atomic(min_fee);
    }
    tx
}

/// Build a coinbase transaction — should be rejected by the mempool.
fn make_coinbase_tx() -> Transaction {
    Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: Vec::new(),
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes([1u8; 32]),
            tx_public_key: PublicKey::from_bytes([2u8; 32]),
            commitment: [3u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(0),
        range_proof: vec![0u8; 64],
        extra: Vec::new(),
    }
}

// =============================================================================
// 1. Coinbase rejected from mempool
// =============================================================================

#[test]
fn mempool_rejects_coinbase_transactions() {
    // SECURITY invariant: allowing a coinbase into the mempool would let
    // anyone create money from nothing. This is defended both at the
    // `add()` preflight check and at `add_skip_crypto()`. The rejection
    // must happen BEFORE crypto verification, so the skip-crypto path is
    // the right one to exercise.
    let mut pool = Mempool::new();
    let coinbase = make_coinbase_tx();
    let result = pool.add_skip_crypto(coinbase);
    assert!(
        result.is_err(),
        "coinbase tx must be rejected from the mempool, got {:?}",
        result
    );
    assert_eq!(pool.len(), 0);
}

// =============================================================================
// 2. Ring size below BOOTSTRAP_MIN_RING_SIZE rejected
// =============================================================================

#[test]
fn mempool_rejects_insufficient_ring_size() {
    // Constitution Article III: BOOTSTRAP_MIN_RING_SIZE >= 11. A tx with fewer
    // ring members would leak anonymity and must be rejected at
    // admission, not silently accepted.
    let mut pool = Mempool::new();

    // Manually build a transfer with a deliberately-too-small ring.
    // We can't use `make_transfer_tx` because its `.max(BOOTSTRAP_MIN_RING_SIZE)`
    // clamp would sneak the tx through.
    let secret = SecretScalar::from_bytes([5u8; 32]);
    let pub_point = secret.to_public();
    let crypto_ki = CryptoKeyImage::from_secret(&secret);
    let key_image = KeyImage::from_bytes(crypto_ki.to_bytes());
    let mut ring_members = Vec::new();
    for i in 0..(BOOTSTRAP_MIN_RING_SIZE - 1) {
        let rm = SecretScalar::from_bytes([(i as u8).wrapping_add(1); 32]).to_public();
        ring_members.push(RingMemberRef {
            public_key: PublicKey::from_bytes(rm.to_bytes()),
            commitment: rm.to_bytes(),
        });
    }
    let signature = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: pub_point,
        c1: [0u8; 32],
        responses: vec![[0u8; 32]; BOOTSTRAP_MIN_RING_SIZE - 1],
    };
    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image,
            ring_members,
            signature,
            pseudo_output_commitment: pub_point.to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes([7u8; 32]),
            tx_public_key: PublicKey::from_bytes([8u8; 32]),
            commitment: [9u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(1_000_000),
        range_proof: vec![0u8; 64],
        extra: Vec::new(),
    };
    let result = pool.add_skip_crypto(tx);
    assert!(
        result.is_err(),
        "tx with ring size < {} must be rejected, got {:?}",
        BOOTSTRAP_MIN_RING_SIZE,
        result
    );
    assert_eq!(pool.len(), 0);
}

// =============================================================================
// 3. Below-minimum fee rejected
// =============================================================================

#[test]
fn mempool_rejects_below_minimum_fee() {
    // MIN_FEE_PER_BYTE enforcement: tx fee must be >= size * min. Tests
    // that the per-byte fee policy fires at admission.
    let mut pool = Mempool::new();
    // Deliberately build a tx with fee = 1 (way below threshold).
    let mut tx = make_transfer_tx(42, 0, BOOTSTRAP_MIN_RING_SIZE);
    tx.fee = Amount::from_atomic(1);
    let result = pool.add_skip_crypto(tx);
    assert!(
        result.is_err(),
        "tx with fee well below MIN_FEE_PER_BYTE must be rejected"
    );
    assert_eq!(pool.len(), 0);
}

// =============================================================================
// 4. Valid tx accepted; duplicate is idempotent
// =============================================================================

#[test]
fn mempool_accepts_valid_tx_and_dedups_on_second_add() {
    let mut pool = Mempool::new();
    let tx = make_transfer_tx(7, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);
    let hash = tx.hash();

    // First add — must succeed and bump the count.
    let result1 = pool.add_skip_crypto(tx.clone());
    assert!(result1.is_ok(), "well-formed tx must admit: {:?}", result1);
    assert!(pool.contains(&hash));
    assert_eq!(pool.len(), 1);

    // Second add of the SAME tx — must be idempotent: no error, no
    // double-counting. A mempool that returned an error here would
    // leak information about seen/unseen txs to a peer, and a mempool
    // that double-counted would be vulnerable to fee-market spam.
    let result2 = pool.add_skip_crypto(tx);
    assert!(result2.is_ok(), "duplicate add must be idempotent");
    assert_eq!(pool.len(), 1, "duplicate must not double-count");
}

// =============================================================================
// 5. Tx hash is stable across borsh serialization round-trip
// =============================================================================

#[test]
fn tx_hash_stable_across_borsh_roundtrip() {
    // Transaction::hash() delegates to borsh::to_vec internally. If
    // borsh's serialization of a Transaction ever becomes non-canonical
    // (e.g. a HashMap field sneaks in with unstable iteration order),
    // the hash breaks — and since the hash is the txid used for
    // mempool dedup, block inclusion, and peer relay, non-canonicality
    // here is a consensus split waiting to happen.
    //
    // This test deserializes a tx from its own bytes and verifies the
    // recomputed hash matches the original.
    let tx1 = make_transfer_tx(99, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);
    let bytes = borsh::to_vec(&tx1).expect("borsh serialize");
    let tx2: Transaction = borsh::from_slice(&bytes).expect("borsh deserialize");
    assert_eq!(
        tx1.hash(),
        tx2.hash(),
        "tx hash must be stable across borsh round-trip"
    );
    // And the signing hash too, since it's used as the CLSAG message.
    assert_eq!(
        tx1.signing_hash(),
        tx2.signing_hash(),
        "signing hash must be stable across borsh round-trip"
    );
}
