//! Mempool Ordering, Eviction, and Capacity Tests
//!
//! Verifies that the mempool correctly orders by fee, evicts lowest-fee
//! transactions when full, and handles edge cases.

use coincync::constants::MIN_FEE_PER_BYTE;
use coincync::crypto::{ClsagSignature, KeyImage as CryptoKeyImage, SecretScalar};
use coincync::mempool::Mempool;
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use rand::rngs::OsRng;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a test transaction with a given key image seed and fee.
/// Same seed = same key image (for conflict testing).
fn make_tx(_key_image_seed: u8, fee_atomic: u64, output_count: usize) -> Transaction {
    let secret = SecretScalar::random(&mut OsRng);
    let pub_point = secret.to_public();

    // SECURITY FIX: Use a real curve-point key image derived from the secret.
    // Previously used arbitrary bytes which are now correctly rejected by
    // structural validation (C-9/H-18 fix).
    let ki = CryptoKeyImage::from_secret(&secret);
    let key_image = KeyImage::from_bytes(ki.to_bytes());

    let mut ring_members = Vec::new();
    for _ in 0..11 {
        let rm_secret = SecretScalar::random(&mut OsRng);
        let rm_pub = rm_secret.to_public();
        ring_members.push(RingMemberRef {
            public_key: PublicKey::from_bytes(rm_pub.to_bytes()),
            commitment: rm_pub.to_bytes(),
        });
    }

    let signature = ClsagSignature {
        key_image: ki,
        commitment_image: pub_point,
        c1: [0u8; 32],
        responses: vec![[0u8; 32]; 11],
    };

    let mut outputs = Vec::new();
    for _ in 0..output_count.max(1) {
        let out_secret = SecretScalar::random(&mut OsRng);
        let out_pub = out_secret.to_public();
        outputs.push(TxOutput {
            stealth_address: PublicKey::from_bytes(out_pub.to_bytes()),
            tx_public_key: PublicKey::from_bytes(out_pub.to_bytes()),
            commitment: out_pub.to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        });
    }

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image,
            ring_members,
            signature,
            pseudo_output_commitment: pub_point.to_bytes(),
        }],
        outputs,
        fee: Amount::from_atomic(fee_atomic),
        range_proof: vec![0u8; 64], // Non-empty for constitutional requirement
        extra: Vec::new(),
    };

    let size = tx.size();
    let min_fee = size as u64 * MIN_FEE_PER_BYTE;
    if tx.fee.as_atomic() < min_fee {
        tx.fee = Amount::from_atomic(min_fee);
    }

    tx
}

// ---------------------------------------------------------------------------
// TEST 1: Fee ordering — highest fee first
// ---------------------------------------------------------------------------

#[test]
fn test_highest_fee_mined_first() {
    let mut pool = Mempool::new();

    // Add 5 txs with increasing fees (different key images)
    let low = make_tx(1, 100_000_000, 1);
    let med = make_tx(2, 500_000_000, 1);
    let high = make_tx(3, 1_000_000_000, 1);

    let low_hash = pool.add_skip_crypto(low).unwrap();
    let _med_hash = pool.add_skip_crypto(med).unwrap();
    let high_hash = pool.add_skip_crypto(high).unwrap();

    // Get 1 transaction — should be the highest fee
    let block_txs = pool.get_block_transactions(10_000_000, 1);
    assert_eq!(block_txs.len(), 1);
    assert_eq!(
        block_txs[0].hash(),
        high_hash,
        "Highest fee tx should be selected first"
    );

    // Get all 3 — first should still be highest fee
    let all_txs = pool.get_block_transactions(10_000_000, 3);
    assert_eq!(all_txs.len(), 3);
    assert_eq!(
        all_txs[0].hash(),
        high_hash,
        "First tx should be highest fee"
    );
    assert_eq!(all_txs[2].hash(), low_hash, "Last tx should be lowest fee");
}

// ---------------------------------------------------------------------------
// TEST 2: Eviction — capacity limit drops lowest fee
// ---------------------------------------------------------------------------

#[test]
fn test_eviction_at_capacity() {
    // Create a tiny mempool (just enough for ~2 transactions)
    let tx1 = make_tx(1, 100_000_000, 1);
    let tx1_size = tx1.size();
    let small_capacity = tx1_size * 2 + 100; // Room for ~2 txs

    let mut pool = Mempool::with_max_size(small_capacity);

    // Add 2 low-fee txs
    let low1 = make_tx(10, 100_000_000, 1);
    let low2 = make_tx(11, 200_000_000, 1);
    let low1_hash = pool.add_skip_crypto(low1).unwrap();
    let _low2_hash = pool.add_skip_crypto(low2).unwrap();

    assert_eq!(pool.len(), 2);

    // Add a high-fee tx — should evict the lowest-fee one
    let high = make_tx(12, 1_000_000_000, 1);
    let high_hash = pool.add_skip_crypto(high).unwrap();

    // The high-fee tx should be in, and the lowest-fee one out
    assert!(
        pool.contains(&high_hash),
        "High-fee tx should be in mempool"
    );
    assert!(
        !pool.contains(&low1_hash),
        "Lowest-fee tx should be evicted"
    );
}

// ---------------------------------------------------------------------------
// TEST 3: Duplicate key image rejection
// ---------------------------------------------------------------------------

#[test]
fn test_key_image_conflict_rejected() {
    let mut pool = Mempool::new();

    let tx1 = make_tx(1, 100_000_000, 1);
    let ki = tx1.inputs[0].key_image;
    pool.add_skip_crypto(tx1).unwrap();

    // Second tx with SAME key image (forced) but same fee — no RBF
    let mut tx2 = make_tx(2, 100_000_000, 1);
    tx2.inputs[0].key_image = ki;
    let result = pool.add_skip_crypto(tx2);
    assert!(
        result.is_err() || pool.len() == 1,
        "Conflicting tx should not coexist"
    );
}

// ---------------------------------------------------------------------------
// TEST 4: Remove confirmed — cleans up properly
// ---------------------------------------------------------------------------

#[test]
fn test_remove_confirmed_cleans_state() {
    let mut pool = Mempool::new();

    let tx1 = make_tx(1, 200_000_000, 1);
    let tx2 = make_tx(2, 300_000_000, 1);
    let tx1_hash = pool.add_skip_crypto(tx1.clone()).unwrap();
    let tx2_hash = pool.add_skip_crypto(tx2.clone()).unwrap();

    assert_eq!(pool.len(), 2);

    // Remove tx1 as confirmed
    pool.remove_confirmed(&[tx1]);

    assert!(!pool.contains(&tx1_hash));
    assert!(pool.contains(&tx2_hash));
    assert_eq!(pool.len(), 1);
}

// ---------------------------------------------------------------------------
// TEST 5: Expiration — old txs evicted
// ---------------------------------------------------------------------------

#[test]
fn test_expire_old_transactions() {
    let mut pool = Mempool::new();

    let tx = make_tx(1, 200_000_000, 1);
    pool.add_skip_crypto(tx).unwrap();

    assert_eq!(pool.len(), 1);

    // Wait 2 seconds so the tx has a nonzero age, then expire with 1-second threshold
    std::thread::sleep(std::time::Duration::from_secs(2));
    let evicted = pool.expire_old(1);
    assert_eq!(evicted, 1);
    assert_eq!(pool.len(), 0);
}

// ---------------------------------------------------------------------------
// TEST 6: Empty mempool — get_block_transactions returns empty
// ---------------------------------------------------------------------------

#[test]
fn test_empty_mempool() {
    let pool = Mempool::new();

    let txs = pool.get_block_transactions(10_000_000, 100);
    assert!(txs.is_empty());
    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
}

// ---------------------------------------------------------------------------
// TEST 7: Size invariant holds after operations
// ---------------------------------------------------------------------------

#[test]
fn test_size_invariant() {
    let mut pool = Mempool::new();

    for i in 0..10u8 {
        let tx = make_tx(i, 100_000_000 + i as u64 * 50_000_000, 1);
        pool.add_skip_crypto(tx).unwrap();
    }

    assert!(
        pool.verify_size_invariant(),
        "Size invariant violated after adds"
    );

    // Remove some
    pool.expire_old(0);

    assert!(
        pool.verify_size_invariant(),
        "Size invariant violated after expiry"
    );
}

// ---------------------------------------------------------------------------
// TEST 8: Coinbase rejected
// ---------------------------------------------------------------------------

#[test]
fn test_coinbase_rejected() {
    let mut pool = Mempool::new();

    let mut tx = make_tx(1, 0, 1);
    tx.tx_type = TxType::Coinbase;

    let result = pool.add_skip_crypto(tx);
    assert!(result.is_err(), "Coinbase must be rejected from mempool");
}
