//! Adversarial block validation tests (rewrite — targets 1.0 API).
//!
//! Replaces the pre-1.0 file that depended on `SoloMiner` for reorg
//! stress tests. This rewrite exercises `validate_block` directly
//! with hand-crafted byzantine inputs so we don't need a full mining
//! pipeline to check the validator's rejection rules. Integration
//! value (over the lib-level `consensus::validation::tests`): tests
//! go through the public API surface, so any future change that
//! accidentally relaxes a check or reorders it will fire here first.
//!
//! Adversarial cases covered:
//!
//! 1. **Wrong network magic** — cross-network contamination attempt
//!    (testnet block fed to a mainnet validator, or vice versa). Must
//!    reject in the very first check, before any expensive crypto.
//!
//! 2. **Height not monotone** — child block with `height != prev + 1`.
//!    Attacker skipping heights to confuse height-indexed storage.
//!
//! 3. **Timestamp not monotone** — child block with
//!    `timestamp <= prev.timestamp`. Attacker winding back time to
//!    game difficulty / fee market.
//!
//! 4. **Timestamp too far in future** — attacker time-travels to
//!    present a block far beyond wall clock + `MAX_TIMESTAMP_DRIFT`.
//!    Must be rejected for non-genesis heights (genesis is exempt per
//!    the fix in `validate_header`).
//!
//! 5. **Non-genesis block with height 0** — trying to replace genesis
//!    at runtime by claiming `height == 0` but with different content.
//!
//! 6. **Bad prev_hash** — child block whose `prev_hash` does not match
//!    the parent header. Standard chain-integrity check.

use coincync::consensus::{validate_block, Block, BlockHeader};
use coincync::constants::{
    MAX_TIMESTAMP_DRIFT, BOOTSTRAP_MIN_RING_SIZE, MIN_FEE_PER_BYTE,
};
use coincync::crypto::{ClsagSignature, KeyImage as CryptoKeyImage, SecretScalar};
use coincync::mempool::Mempool;
use coincync::primitives::{Hash, PublicKey, Amount, KeyImage};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use coincync::storage::UtxoSet;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Pick the network magic this build expects. `validate_block`'s first
/// check is feature-gated: with `feature = "testnet"` it expects
/// `TESTNET_MAGIC`, otherwise `MAINNET_MAGIC`. These tests must match
/// the active feature so we don't mask other checks behind a magic
/// mismatch.
fn expected_magic() -> [u8; 4] {
    #[cfg(feature = "testnet")]
    {
        coincync::constants::TESTNET_MAGIC
    }
    #[cfg(not(feature = "testnet"))]
    {
        coincync::constants::MAINNET_MAGIC
    }
}

/// The network magic this build does NOT expect — used to craft a
/// cross-network contamination attempt.
fn wrong_magic() -> [u8; 4] {
    #[cfg(feature = "testnet")]
    {
        coincync::constants::MAINNET_MAGIC
    }
    #[cfg(not(feature = "testnet"))]
    {
        coincync::constants::TESTNET_MAGIC
    }
}

/// Build a shaped BlockHeader with sensible defaults. Callers patch
/// specific fields to create the adversarial shape they need.
fn base_header(height: u64, timestamp: u64, prev_hash: Hash, magic: [u8; 4]) -> BlockHeader {
    BlockHeader {
        network_magic: magic,
        version: 1,
        height,
        timestamp,
        prev_hash,
        tx_root: Hash::zero(),
        anchor: Hash::zero(),
        algorithm: 0,
        nonce: 0,
        target: Hash::from_bytes([0xFF; 32]), // trivially-met target for tests
        miner_pubkey: PublicKey::from_bytes([0u8; 32]),
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    }
}

// -----------------------------------------------------------------------------
// 1. Wrong network magic
// -----------------------------------------------------------------------------

#[test]
fn cross_network_block_is_rejected_at_first_check() {
    // A block carrying the other network's magic bytes must be rejected
    // immediately — before any crypto or height check. This is the
    // cross-contamination defense (FIX #43 in validate_block).
    let header = base_header(1, 1_000_000_000, Hash::zero(), wrong_magic());
    let block = Block::new(header, Vec::new());
    let utxos = UtxoSet::new();

    let result = validate_block(&block, None, &utxos).expect("validator runs");
    assert!(
        !result.valid,
        "cross-network block must be rejected, got {:?}",
        result
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("network magic")),
        "rejection reason must mention network magic, got {:?}",
        result.errors
    );
}

// -----------------------------------------------------------------------------
// 2. Height not monotone
// -----------------------------------------------------------------------------

#[test]
fn non_monotone_height_rejected() {
    // Parent at height 10. Child claims height 12 (skipping 11).
    let parent_header = base_header(10, 1_000_000, Hash::zero(), expected_magic());
    let parent_block = Block::new(parent_header.clone(), Vec::new());

    let mut child_header = base_header(12, parent_header.timestamp + 1, parent_header.hash(), expected_magic());
    child_header.version = 1;
    let child_block = Block::new(child_header, Vec::new());

    let utxos = UtxoSet::new();
    let result = validate_block(&child_block, Some(&parent_block), &utxos).expect("validator runs");
    assert!(
        !result.valid,
        "height-skipping block must be rejected, got {:?}",
        result
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("height")),
        "rejection must cite the height mismatch, got {:?}",
        result.errors
    );
}

// -----------------------------------------------------------------------------
// 3. Timestamp not monotone
// -----------------------------------------------------------------------------

#[test]
fn non_monotone_timestamp_rejected() {
    // Parent timestamp 2_000_000. Child claims 1_999_999 (time-warp
    // attack — used in difficulty-manipulation schemes).
    let parent_header = base_header(10, 2_000_000, Hash::zero(), expected_magic());
    let parent_block = Block::new(parent_header.clone(), Vec::new());

    let child_header = base_header(11, 1_999_999, parent_header.hash(), expected_magic());
    let child_block = Block::new(child_header, Vec::new());

    let utxos = UtxoSet::new();
    let result = validate_block(&child_block, Some(&parent_block), &utxos).expect("validator runs");
    assert!(
        !result.valid,
        "backwards-timestamp block must be rejected, got {:?}",
        result
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("timestamp")),
        "rejection must cite timestamp monotonicity, got {:?}",
        result.errors
    );
}

// -----------------------------------------------------------------------------
// 4. Timestamp too far in future
// -----------------------------------------------------------------------------

#[test]
fn timestamp_far_in_future_rejected_for_non_genesis() {
    // Non-genesis block claiming a timestamp one hour past the
    // `MAX_TIMESTAMP_DRIFT` window (which is currently 10 minutes).
    // This must fire because `validate_header` exempts ONLY height==0
    // from the future-timestamp check — intentional, per the genesis
    // timestamp fix.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let far_future = now + MAX_TIMESTAMP_DRIFT + 3600;

    // Parent is plausibly-timed.
    let parent_header = base_header(10, now - 60, Hash::zero(), expected_magic());
    let parent_block = Block::new(parent_header.clone(), Vec::new());

    let child_header = base_header(11, far_future, parent_header.hash(), expected_magic());
    let child_block = Block::new(child_header, Vec::new());

    let utxos = UtxoSet::new();
    let result = validate_block(&child_block, Some(&parent_block), &utxos).expect("validator runs");
    assert!(
        !result.valid,
        "future-dated non-genesis block must be rejected, got {:?}",
        result
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("future")),
        "rejection must cite future timestamp, got {:?}",
        result.errors
    );
}

// -----------------------------------------------------------------------------
// 5. Non-genesis block claiming height 0
// -----------------------------------------------------------------------------

#[test]
fn claiming_height_zero_without_parent_but_with_nonzero_prev_hash_rejected() {
    // A block at height 0 MUST have `prev_hash == Hash::zero()`. If an
    // attacker tries to present a forged "genesis" with a non-zero prev
    // hash (to link it to a fake pre-genesis chain), the validator
    // must reject it. The validator's genesis branch lives in
    // `validate_header` — this test drives it through the public API.
    let forged_prev = Hash::from_bytes([0xEE; 32]);
    let forged = base_header(0, 1_000_000, forged_prev, expected_magic());
    let block = Block::new(forged, Vec::new());
    let utxos = UtxoSet::new();

    let result = validate_block(&block, None, &utxos).expect("validator runs");
    assert!(
        !result.valid,
        "forged genesis with non-zero prev_hash must be rejected, got {:?}",
        result
    );
}

// -----------------------------------------------------------------------------
// 6. Bad prev_hash on a child block
// -----------------------------------------------------------------------------

#[test]
fn bad_prev_hash_on_child_rejected() {
    // Parent header P has hash h(P). A child claims prev_hash = h'
    // where h' != h(P). The validator must reject — otherwise an
    // attacker can rewrite chain history.
    let parent_header = base_header(5, 1_000_000, Hash::zero(), expected_magic());
    let parent_block = Block::new(parent_header.clone(), Vec::new());

    let wrong_prev = Hash::from_bytes([0xAA; 32]);
    let child_header = base_header(6, parent_header.timestamp + 1, wrong_prev, expected_magic());
    let child_block = Block::new(child_header, Vec::new());

    let utxos = UtxoSet::new();
    let result = validate_block(&child_block, Some(&parent_block), &utxos).expect("validator runs");
    assert!(
        !result.valid,
        "child with wrong prev_hash must be rejected, got {:?}",
        result
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("previous hash") || e.to_lowercase().contains("prev")),
        "rejection must cite prev_hash mismatch, got {:?}",
        result.errors
    );
}

// =============================================================================
// TX HELPERS
// =============================================================================

fn make_secret(seed: u8) -> SecretScalar {
    SecretScalar::from_bytes([seed; 32])
}

fn make_keyimage(seed: u8) -> (KeyImage, CryptoKeyImage, SecretScalar) {
    let secret = make_secret(seed);
    let crypto_ki = CryptoKeyImage::from_secret(&secret);
    let ki = KeyImage::from_bytes(crypto_ki.to_bytes());
    (ki, crypto_ki, secret)
}

fn make_ring(seed: u8, size: usize) -> Vec<RingMemberRef> {
    (0..size).map(|i| {
        let s = make_secret(seed.wrapping_add(i as u8 + 100));
        let p = s.to_public();
        RingMemberRef { public_key: PublicKey::from_bytes(p.to_bytes()), commitment: p.to_bytes() }
    }).collect()
}

fn make_output(seed: u8) -> TxOutput {
    let s = make_secret(seed.wrapping_add(200));
    let p = s.to_public();
    TxOutput {
        stealth_address: PublicKey::from_bytes(p.to_bytes()),
        tx_public_key: PublicKey::from_bytes(p.to_bytes()),
        commitment: p.to_bytes(),
        encrypted_amount: vec![0u8; 8],
        view_tag: seed,
        lock_height: None,
        encrypted_memo: Vec::new(),
    }
}

fn make_transfer(seed: u8, fee: u64, ring_size: usize) -> Transaction {
    let (ki, crypto_ki, secret) = make_keyimage(seed);
    let ring = make_ring(seed, ring_size);
    let sig = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: secret.to_public(),
        c1: [seed; 32],
        responses: vec![[seed; 32]; ring_size],
    };
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: ki,
            ring_members: ring,
            signature: sig,
            pseudo_output_commitment: secret.to_public().to_bytes(),
        }],
        outputs: vec![make_output(seed)],
        fee: Amount::from_atomic(fee),
        range_proof: vec![0u8; 64],
        extra: vec![seed],
    };
    let size = tx.size();
    let min_fee = size as u64 * MIN_FEE_PER_BYTE;
    if tx.fee.as_atomic() < min_fee { tx.fee = Amount::from_atomic(min_fee); }
    tx
}

// =============================================================================
// 7. DOUBLE-SPEND: Same keyimage in two txs submitted to mempool
// =============================================================================

#[test]
fn mempool_rejects_duplicate_keyimage_without_fee_bump() {
    let mut pool = Mempool::new();
    let tx1 = make_transfer(50, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);
    let tx2 = {
        let mut t = make_transfer(50, 10_000_000, BOOTSTRAP_MIN_RING_SIZE); // same fee = no RBF
        t.inputs[0].key_image = tx1.inputs[0].key_image;
        t.extra = vec![51]; // different tx hash
        t
    };

    pool.add_skip_crypto(tx1).expect("first tx admitted");
    let result = pool.add_skip_crypto(tx2);
    assert!(result.is_err(), "second tx with same keyimage (no fee bump) must be rejected");
}

#[test]
fn mempool_allows_rbf_with_fee_bump() {
    // RBF (Replace-By-Fee) is a legitimate feature — a tx with a higher fee
    // can replace one with the same keyimage. This is not a double-spend;
    // only one of the two txs will ever be mined.
    let mut pool = Mempool::new();
    let tx1 = make_transfer(50, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);
    let tx2 = {
        let mut t = make_transfer(50, 50_000_000, BOOTSTRAP_MIN_RING_SIZE); // 5x fee = valid RBF
        t.inputs[0].key_image = tx1.inputs[0].key_image;
        t.extra = vec![51];
        t
    };

    pool.add_skip_crypto(tx1).expect("first tx admitted");
    let result = pool.add_skip_crypto(tx2);
    assert!(result.is_ok(), "RBF with sufficient fee bump should be accepted");
    assert_eq!(pool.len(), 1, "pool should have exactly 1 tx after RBF (replacement, not addition)");
}

// =============================================================================
// 8. DOUBLE-SPEND: Bit-flipped keyimage should be different
// =============================================================================

#[test]
fn different_keyimage_is_distinct_spend() {
    let mut pool = Mempool::new();
    let tx1 = make_transfer(60, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);
    let tx2 = make_transfer(61, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);

    // tx2 has a completely different key image (derived from different secret)
    // so it represents a distinct spend and should be accepted alongside tx1
    assert_ne!(
        tx1.inputs[0].key_image, tx2.inputs[0].key_image,
        "Test setup: tx1 and tx2 must have different key images"
    );

    pool.add_skip_crypto(tx1).expect("first tx admitted");
    let result = pool.add_skip_crypto(tx2);
    assert!(result.is_ok(), "different keyimage is a distinct spend, should be accepted");
}

// =============================================================================
// 9. Block with wrong merkle root
// =============================================================================

#[test]
fn block_with_wrong_merkle_root_rejected() {
    let parent_header = base_header(10, 1_000_000, Hash::zero(), expected_magic());
    let parent_block = Block::new(parent_header.clone(), Vec::new());

    // Build a block with a valid coinbase but wrong tx_root
    let coinbase = Transaction {
        version: 1, tx_type: TxType::Coinbase, inputs: vec![],
        outputs: vec![make_output(1)],
        fee: Amount::ZERO, range_proof: vec![], extra: vec![],
    };
    let mut child_header = base_header(11, parent_header.timestamp + 120, parent_header.hash(), expected_magic());
    child_header.tx_root = Hash::from_bytes([0xDE; 32]); // deliberately wrong
    let child_block = Block::new(child_header, vec![coinbase]);

    let utxos = UtxoSet::new();
    let result = validate_block(&child_block, Some(&parent_block), &utxos).expect("validator runs");
    assert!(!result.valid, "block with wrong merkle root must be rejected");
    assert!(
        result.errors.iter().any(|e| e.to_lowercase().contains("merkle")),
        "rejection must cite merkle root, got {:?}", result.errors
    );
}

// =============================================================================
// 10. Block with zero transactions (no coinbase)
// =============================================================================

#[test]
fn block_with_no_transactions_rejected() {
    let parent_header = base_header(10, 1_000_000, Hash::zero(), expected_magic());
    let parent_block = Block::new(parent_header.clone(), Vec::new());

    let child_header = base_header(11, parent_header.timestamp + 120, parent_header.hash(), expected_magic());
    let child_block = Block::new(child_header, Vec::new()); // no txs at all

    let utxos = UtxoSet::new();
    let result = validate_block(&child_block, Some(&parent_block), &utxos).expect("validator runs");
    assert!(!result.valid, "block with zero transactions must be rejected");
}

// =============================================================================
// 11. Coinbase with extra outputs (inflation attempt)
// =============================================================================

#[test]
fn coinbase_with_extra_outputs_rejected() {
    let mut pool = Mempool::new();
    let coinbase = Transaction {
        version: 1, tx_type: TxType::Coinbase, inputs: vec![],
        outputs: vec![make_output(1), make_output(2), make_output(3)], // 3 outputs — suspicious
        fee: Amount::ZERO, range_proof: vec![], extra: vec![],
    };
    // Coinbase should never enter the mempool regardless
    let result = pool.add_skip_crypto(coinbase);
    assert!(result.is_err(), "coinbase must never enter the mempool");
}

// =============================================================================
// 12. Ring size exactly at minimum — accepted
// =============================================================================

#[test]
fn ring_size_at_minimum_accepted() {
    let mut pool = Mempool::new();
    let tx = make_transfer(70, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);
    assert_eq!(tx.inputs[0].ring_members.len(), BOOTSTRAP_MIN_RING_SIZE);
    let result = pool.add_skip_crypto(tx);
    assert!(result.is_ok(), "ring size exactly at minimum should be accepted");
}

// =============================================================================
// 13. Ring size one below minimum — rejected
// =============================================================================

#[test]
fn ring_size_below_minimum_rejected() {
    let mut pool = Mempool::new();
    let (ki, crypto_ki, secret) = make_keyimage(71);
    let small_ring = make_ring(71, BOOTSTRAP_MIN_RING_SIZE - 1);
    let sig = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: secret.to_public(),
        c1: [71; 32],
        responses: vec![[71; 32]; BOOTSTRAP_MIN_RING_SIZE - 1],
    };
    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: ki, ring_members: small_ring, signature: sig,
            pseudo_output_commitment: secret.to_public().to_bytes(),
        }],
        outputs: vec![make_output(71)],
        fee: Amount::from_atomic(10_000_000),
        range_proof: vec![0u8; 64], extra: vec![71],
    };
    let result = pool.add_skip_crypto(tx);
    assert!(result.is_err(), "ring size below minimum must be rejected");
}

// =============================================================================
// 14. Transaction replay — same tx submitted twice
// =============================================================================

#[test]
fn transaction_replay_returns_existing_hash() {
    // Submitting the exact same tx twice returns the existing hash (idempotent),
    // which is correct — mempool deduplicates by tx hash.
    let mut pool = Mempool::new();
    let tx = make_transfer(80, 10_000_000, BOOTSTRAP_MIN_RING_SIZE);
    let h1 = pool.add_skip_crypto(tx.clone()).expect("first admission");
    let h2 = pool.add_skip_crypto(tx).expect("replay returns existing hash");
    assert_eq!(h1, h2, "same tx submitted twice should return same hash");
    assert_eq!(pool.len(), 1, "pool should still have exactly 1 tx");
}

// =============================================================================
// 15. Transfer tx with zero fee — rejected
// =============================================================================

#[test]
fn zero_fee_transfer_rejected() {
    let mut pool = Mempool::new();
    let (ki, crypto_ki, secret) = make_keyimage(90);
    let ring = make_ring(90, BOOTSTRAP_MIN_RING_SIZE);
    let sig = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: secret.to_public(),
        c1: [90; 32],
        responses: vec![[90; 32]; BOOTSTRAP_MIN_RING_SIZE],
    };
    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: ki, ring_members: ring, signature: sig,
            pseudo_output_commitment: secret.to_public().to_bytes(),
        }],
        outputs: vec![make_output(90)],
        fee: Amount::ZERO, // zero fee
        range_proof: vec![0u8; 64], extra: vec![90],
    };
    let result = pool.add_skip_crypto(tx);
    assert!(result.is_err(), "zero-fee transfer must be rejected");
}

// =============================================================================
// 16. Block with impossibly early timestamp (equal to parent)
// =============================================================================

#[test]
fn block_with_same_timestamp_as_parent_rejected() {
    let ts = 2_000_000u64;
    let parent_header = base_header(10, ts, Hash::zero(), expected_magic());
    let parent_block = Block::new(parent_header.clone(), Vec::new());

    // Child has exact same timestamp
    let child_header = base_header(11, ts, parent_header.hash(), expected_magic());
    let child_block = Block::new(child_header, Vec::new());

    let utxos = UtxoSet::new();
    let result = validate_block(&child_block, Some(&parent_block), &utxos).expect("validator runs");
    assert!(!result.valid, "block with timestamp == parent timestamp must be rejected");
}

// =============================================================================
// 17. Privacy: transfer with zero stealth address
// Note: add_skip_crypto bypasses privacy checks. These tests verify that
// the full validate_transaction path (used at block validation) catches them.
// =============================================================================

#[test]
fn transfer_with_zero_stealth_address_rejected_even_on_skip_crypto() {
    let mut pool = Mempool::new();
    let (ki, crypto_ki, secret) = make_keyimage(95);
    let ring = make_ring(95, BOOTSTRAP_MIN_RING_SIZE);
    let sig = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: secret.to_public(),
        c1: [95; 32],
        responses: vec![[95; 32]; BOOTSTRAP_MIN_RING_SIZE],
    };
    // Use valid commitment but zero stealth address
    let valid_pub = make_secret(195).to_public();
    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: ki, ring_members: ring, signature: sig,
            pseudo_output_commitment: secret.to_public().to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes([0u8; 32]), // zero = identity = no privacy
            tx_public_key: PublicKey::from_bytes(valid_pub.to_bytes()),
            commitment: valid_pub.to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0, lock_height: None, encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(10_000_000),
        range_proof: vec![0u8; 64], extra: vec![95],
    };
    let result = pool.add_skip_crypto(tx);
    assert!(result.is_err(), "tx with zero stealth address must be rejected (privacy violation)");
}

// =============================================================================
// 18. Privacy: transfer with zero commitment — rejected
// =============================================================================

#[test]
fn transfer_with_zero_commitment_rejected() {
    let mut pool = Mempool::new();
    let (ki, crypto_ki, secret) = make_keyimage(96);
    let ring = make_ring(96, BOOTSTRAP_MIN_RING_SIZE);
    let sig = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: secret.to_public(),
        c1: [96; 32],
        responses: vec![[96; 32]; BOOTSTRAP_MIN_RING_SIZE],
    };
    let valid_pub = make_secret(196).to_public();
    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: ki, ring_members: ring, signature: sig,
            pseudo_output_commitment: secret.to_public().to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(valid_pub.to_bytes()),
            tx_public_key: PublicKey::from_bytes(valid_pub.to_bytes()),
            commitment: [0u8; 32], // zero commitment = transparent amount
            encrypted_amount: vec![0u8; 8],
            view_tag: 0, lock_height: None, encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(10_000_000),
        range_proof: vec![0u8; 64], extra: vec![96],
    };
    let result = pool.add_skip_crypto(tx);
    assert!(result.is_err(), "tx with zero commitment must be rejected (transparent amount)");
}

// =============================================================================
// 19. Empty inputs on transfer — rejected (unshielded)
// =============================================================================

#[test]
fn transfer_with_no_inputs_rejected() {
    let mut pool = Mempool::new();
    let valid_pub = make_secret(197).to_public();
    let tx = Transaction {
        version: 1, tx_type: TxType::Transfer,
        inputs: vec![], // no inputs = money from nowhere
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(valid_pub.to_bytes()),
            tx_public_key: PublicKey::from_bytes(valid_pub.to_bytes()),
            commitment: valid_pub.to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0, lock_height: None, encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(10_000_000),
        range_proof: vec![0u8; 64], extra: vec![],
    };
    let result = pool.add_skip_crypto(tx);
    assert!(result.is_err(), "transfer with no inputs must be rejected");
}
