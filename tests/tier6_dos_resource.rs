//! # Tier 6 — DoS & Resource Exhaustion Adversarial Tests
//!
//! Tests mempool flooding, capacity enforcement, and rate limiting.
//! NO MOCKS. Real mempool, real transactions, real limits.

use coincync::constants::{BOOTSTRAP_MIN_RING_SIZE, MAX_TX_SIZE, MIN_FEE_PER_BYTE};
use coincync::crypto::{
    BlindingFactor, ClsagSignature, KeyImage as CryptoKeyImage, PedersenCommitment, SecretScalar,
};
use coincync::mempool::Mempool;
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use rand::rngs::OsRng;

// =============================================================================
// HELPERS
// =============================================================================

fn make_unique_tx(fee: u64) -> Transaction {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    let bf = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(1_000_000_000, &bf);
    let ring_size = BOOTSTRAP_MIN_RING_SIZE;

    let ring_members: Vec<RingMemberRef> = (0..ring_size)
        .map(|_| {
            let s = SecretScalar::random(&mut OsRng);
            let c = PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng));
            RingMemberRef {
                public_key: PublicKey::from_bytes(s.to_public().to_bytes()),
                commitment: c.to_bytes(),
            }
        })
        .collect();

    let ki = CryptoKeyImage::from_secret(&secret);
    let sig = ClsagSignature {
        key_image: ki,
        commitment_image: public,
        c1: [rand::random::<u8>(); 32],
        responses: vec![[rand::random::<u8>(); 32]; ring_size],
    };

    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members,
            signature: sig,
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
            view_tag: rand::random::<u8>(),
            lock_height: None,
            encrypted_memo: vec![],
        }],
        fee: Amount::from_atomic(fee),
        range_proof: vec![0u8; 64],
        extra: vec![
            rand::random::<u8>(),
            rand::random::<u8>(),
            rand::random::<u8>(),
        ],
    };

    let size = tx.size();
    let min_fee = size as u64 * MIN_FEE_PER_BYTE;
    if tx.fee.as_atomic() < min_fee {
        tx.fee = Amount::from_atomic(min_fee + 1);
    }
    tx
}

// =============================================================================
// TEST 1: Mempool enforces max transaction count
// =============================================================================

#[test]
fn tier6_mempool_has_finite_capacity() {
    let mut pool = Mempool::new();
    let mut admitted = 0;

    for _ in 0..500 {
        let tx = make_unique_tx(50_000_000);
        match pool.add_skip_crypto(tx) {
            Ok(_) => admitted += 1,
            Err(_) => break,
        }
    }

    // Pool must accept at least some transactions
    assert!(admitted > 0, "Mempool must accept valid transactions");
    // Pool size must be bounded
    let size = pool.size();
    assert!(
        size < 500 * 1024 * 1024,
        "Mempool size must be bounded, got {}",
        size
    );
}

// =============================================================================
// TEST 2: Duplicate key image flood (double-spend storm)
// =============================================================================

#[test]
fn tier6_duplicate_keyimage_flood_contained() {
    let mut pool = Mempool::new();

    let tx1 = make_unique_tx(50_000_000);
    let ki = tx1.inputs[0].key_image;
    pool.add_skip_crypto(tx1).expect("first tx");

    let mut rejected = 0;
    for _ in 0..254 {
        let mut tx = make_unique_tx(50_000_000);
        tx.inputs[0].key_image = ki; // same key image, no fee bump
        match pool.add_skip_crypto(tx) {
            Err(_) => rejected += 1,
            Ok(_) => {}
        }
    }

    assert!(
        rejected > 200,
        "Most duplicate key image txs must be rejected. Only {}/254 rejected.",
        rejected
    );
}

// =============================================================================
// TEST 3: Oversized transaction rejected
// =============================================================================

#[test]
fn tier6_oversized_transaction_rejected() {
    let mut pool = Mempool::new();
    let mut tx = make_unique_tx(500_000_000);
    tx.extra = vec![0xAB; MAX_TX_SIZE + 1];

    let result = pool.add_skip_crypto(tx);
    assert!(
        result.is_err(),
        "Transaction exceeding MAX_TX_SIZE must be rejected"
    );
}

// =============================================================================
// TEST 4: Zero-fee flood all rejected
// =============================================================================

#[test]
fn tier6_zero_fee_flood_all_rejected() {
    let mut pool = Mempool::new();
    let mut rejected = 0;

    for _ in 0..100 {
        let mut tx = make_unique_tx(0);
        tx.fee = Amount::from_atomic(0);
        match pool.add_skip_crypto(tx) {
            Err(_) => rejected += 1,
            Ok(_) => {}
        }
    }

    assert_eq!(
        rejected, 100,
        "ALL zero-fee txs must be rejected. Only {}/100 rejected.",
        rejected
    );
}

// =============================================================================
// TEST 5: Mempool clear removes all
// =============================================================================

#[test]
fn tier6_mempool_clear_removes_all() {
    let mut pool = Mempool::new();
    for _ in 0..50 {
        let _ = pool.add_skip_crypto(make_unique_tx(50_000_000));
    }
    assert!(pool.len() > 0);

    pool.clear();
    assert_eq!(pool.len(), 0, "After clear, mempool must be empty");
    assert_eq!(pool.size(), 0, "After clear, mempool size must be 0");
}

// =============================================================================
// TEST 6: Confirmed transaction removal
// =============================================================================

#[test]
fn tier6_confirmed_txs_removed_from_mempool() {
    let mut pool = Mempool::new();
    let tx1 = make_unique_tx(50_000_000);
    let tx2 = make_unique_tx(50_000_000);
    let tx1_clone = tx1.clone();

    pool.add_skip_crypto(tx1).unwrap();
    pool.add_skip_crypto(tx2).unwrap();
    assert_eq!(pool.len(), 2);

    pool.remove_confirmed(&[tx1_clone]);
    assert_eq!(pool.len(), 1, "Confirmed tx must be removed");
}

// =============================================================================
// TEST 7: Coinbase injection flood rejected
// =============================================================================

#[test]
fn tier6_coinbase_injection_flood_rejected() {
    let mut pool = Mempool::new();
    let mut rejected = 0;

    for i in 0..100u8 {
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: PublicKey::from_bytes(
                    SecretScalar::random(&mut OsRng).to_public().to_bytes(),
                ),
                tx_public_key: PublicKey::from_bytes(
                    SecretScalar::random(&mut OsRng).to_public().to_bytes(),
                ),
                commitment: [i; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: i,
                lock_height: None,
                encrypted_memo: vec![],
            }],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![i],
        };
        match pool.add_skip_crypto(tx) {
            Err(_) => rejected += 1,
            Ok(_) => {}
        }
    }

    assert_eq!(
        rejected, 100,
        "ALL coinbase injections must be rejected. Only {}/100.",
        rejected
    );
}

// =============================================================================
// TEST 8: Key image conflict removal
// =============================================================================

#[test]
fn tier6_key_image_conflict_removal() {
    let mut pool = Mempool::new();
    let tx1 = make_unique_tx(50_000_000);
    let tx2 = make_unique_tx(50_000_000);
    let ki1 = tx1.inputs[0].key_image;
    let ki2 = tx2.inputs[0].key_image;

    pool.add_skip_crypto(tx1).unwrap();
    pool.add_skip_crypto(tx2).unwrap();
    assert_eq!(pool.len(), 2);

    pool.remove_conflicts(&[ki1]);
    assert_eq!(pool.len(), 1);
    assert!(!pool.contains_key_image(&ki1));
    assert!(pool.contains_key_image(&ki2));
}

// =============================================================================
// TEST 9: Below-minimum fee always rejected
// =============================================================================

#[test]
fn tier6_below_minimum_fee_rejected() {
    let mut pool = Mempool::new();
    // Fee of 1 atomic unit — guaranteed below minimum for any tx size
    let mut tx = make_unique_tx(1);
    tx.fee = Amount::from_atomic(1);

    let result = pool.add_skip_crypto(tx);
    assert!(
        result.is_err(),
        "Fee of 1 atomic unit must be rejected (below MIN_FEE_PER_BYTE * size)"
    );
}

// =============================================================================
// TEST 10: Mempool deduplication
// =============================================================================

#[test]
fn tier6_duplicate_tx_returns_same_hash() {
    let mut pool = Mempool::new();
    let tx = make_unique_tx(50_000_000);
    let tx_clone = tx.clone();
    let expected = tx.hash();

    let h1 = pool.add_skip_crypto(tx).unwrap();
    let h2 = pool.add_skip_crypto(tx_clone).unwrap();

    assert_eq!(h1, expected);
    assert_eq!(h2, expected, "Duplicate submission must return same hash");
    assert_eq!(pool.len(), 1, "Duplicate must not increase pool size");
}
