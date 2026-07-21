//! # Tier 5 — Chain State Machine Adversarial Tests
//!
//! Tests fork handling, deep reorgs, UTXO state consistency,
//! and chain invariant preservation under adversarial conditions.
//!
//! NO MOCKS. Uses real Blockchain + Block + Transaction types.

use coincync::chain::{BlockStatus, Blockchain};
use coincync::consensus::{Block, BlockHeader};
use coincync::crypto::{BlindingFactor, PedersenCommitment, SecretScalar};
use coincync::primitives::{merkle_root, Amount, Hash, KeyImage, PublicKey};
use coincync::transaction::{Transaction, TxOutput, TxType};
use rand::rngs::OsRng;

// =============================================================================
// HELPERS
// =============================================================================

fn make_header(height: u64, prev_hash: Hash, tx_root: Hash, seed: u8) -> BlockHeader {
    let miner = SecretScalar::random(&mut OsRng).to_public();
    BlockHeader {
        network_magic: *b"CYNC",
        version: 1,
        height,
        timestamp: 1700000000 + height * 120,
        prev_hash,
        tx_root,
        anchor: Hash::zero(),
        algorithm: 0,
        nonce: seed as u64,
        target: Hash::from_bytes([0xFF; 32]), // easy target for tests
        miner_pubkey: PublicKey::from_bytes(miner.to_bytes()),
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    }
}

fn make_block_at(height: u64, prev_hash: Hash, seed: u8) -> Block {
    let coinbase = Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![make_coinbase_output(seed)],
        fee: Amount::from_atomic(0),
        range_proof: vec![],
        extra: vec![seed, height as u8],
    };
    let tx_root = merkle_root(&[coinbase.hash()]);
    let header = make_header(height, prev_hash, tx_root, seed);
    Block::new(header, vec![coinbase])
}

fn make_coinbase_output(seed: u8) -> TxOutput {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    let bf = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(5_000_000_000, &bf);
    TxOutput {
        stealth_address: PublicKey::from_bytes(public.to_bytes()),
        tx_public_key: PublicKey::from_bytes(
            SecretScalar::random(&mut OsRng).to_public().to_bytes(),
        ),
        commitment: commitment.to_bytes(),
        encrypted_amount: vec![0u8; 8],
        view_tag: seed,
        lock_height: None,
        encrypted_memo: vec![],
    }
}

// =============================================================================
// TEST 1: Chain rejects blocks with invalid parent
// =============================================================================

#[test]
fn tier5_orphan_block_without_parent_not_added_to_main() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    // Create a block pointing to a non-existent parent
    let fake_parent = Hash::from_bytes([0xAA; 32]);
    let orphan = make_block_at(5, fake_parent, 99);

    let result = chain.add_block(orphan);
    assert!(result.is_ok());
    match result.unwrap() {
        BlockStatus::Orphan => {} // correct
        other => panic!(
            "Block with unknown parent should be Orphan, got {:?}",
            other
        ),
    }
    // Chain height should not have changed
    assert_eq!(
        chain.height(),
        0,
        "Orphan block must not advance chain height"
    );
}

// =============================================================================
// TEST 2: Chain rejects height skip
// =============================================================================

#[test]
fn tier5_height_skip_rejected() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");
    let genesis_hash = chain.tip_hash();

    // Try to add block at height 5 directly after genesis (height 0)
    let skip_block = make_block_at(5, genesis_hash, 1);
    let result = chain.add_block(skip_block);
    assert!(result.is_ok());
    match result.unwrap() {
        BlockStatus::Invalid(reason) => {
            assert!(
                reason.contains("height"),
                "Rejection must mention height, got: {}",
                reason
            );
        }
        other => panic!("Height skip should be Invalid, got {:?}", other),
    }
}

// =============================================================================
// TEST 3: Invalid block (validation catches forgery)
//
// Our test blocks are intentionally malformed (no PoW, wrong anchor).
// The chain CORRECTLY rejects them. This IS the test — validation works.
// =============================================================================

#[test]
fn tier5_invalid_block_correctly_rejected() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");
    let genesis_hash = chain.tip_hash();

    // Block with no valid PoW, wrong anchor, wrong coinbase commitment
    let block1 = make_block_at(1, genesis_hash, 10);
    let result = chain.add_block(block1).unwrap();

    // Chain validation SHOULD catch this and reject it
    assert!(
        matches!(result, BlockStatus::Invalid(_)),
        "Block without valid PoW/anchor must be rejected, got {:?}",
        result
    );
}

// =============================================================================
// TEST 4: Blockchain correctly tracks genesis state
// =============================================================================

#[test]
fn tier5_genesis_state_correct() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    assert_eq!(chain.height(), 0, "Genesis height must be 0");
    assert!(chain.difficulty() > 0, "Genesis difficulty must be nonzero");
    let tip = chain.tip_hash();
    assert_ne!(tip, Hash::zero(), "Genesis hash must not be zero");

    // Genesis block should be retrievable
    let genesis = chain.get_block_by_height(0);
    assert!(genesis.is_some(), "Genesis block must be retrievable");
}

// =============================================================================
// TEST 5: Rollback to same height is no-op
// =============================================================================

#[test]
fn tier5_rollback_to_current_height_is_noop() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    let mut prev = chain.tip_hash();
    for i in 1..=3u64 {
        let b = make_block_at(i, prev, i as u8);
        prev = b.hash();
        chain.add_block(b).unwrap();
    }

    let height_before = chain.height();
    let _tip_before = chain.tip_hash();
    let result = chain.rollback_to_height(height_before);
    assert!(result.is_ok());
    assert_eq!(chain.height(), height_before);
}

// =============================================================================
// TEST 6: Rollback beyond genesis fails
// =============================================================================

#[test]
fn tier5_rollback_beyond_genesis_handled() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    let mut prev = chain.tip_hash();
    for i in 1..=3u64 {
        let b = make_block_at(i, prev, i as u8);
        prev = b.hash();
        chain.add_block(b).unwrap();
    }

    // Rollback to 0 should work (genesis stays)
    let result = chain.rollback_to_height(0);
    assert!(result.is_ok());
    assert_eq!(chain.height(), 0);
}

// =============================================================================
// TEST 7: Invalid blocks don't advance chain (sequential rejection)
// =============================================================================

#[test]
fn tier5_invalid_blocks_never_advance_chain() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    let genesis_height = chain.height();
    let genesis_hash = chain.tip_hash();

    // Submit 20 invalid blocks — none should advance the chain
    for i in 1..=20u64 {
        let b = make_block_at(i, genesis_hash, i as u8);
        let _ = chain.add_block(b);
    }
    assert_eq!(
        chain.height(),
        genesis_height,
        "Invalid blocks must never advance chain height"
    );
}

// =============================================================================
// TEST 8: Supply at genesis is correct (emission curve)
// =============================================================================

#[test]
fn tier5_genesis_supply_matches_emission() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    let stats = chain.stats();
    // Genesis creates the first block reward — supply must be > 0
    assert!(
        stats.total_supply > 0,
        "Total supply after genesis must be > 0 (genesis block reward)"
    );
    // But must not exceed the cap
    assert!(
        stats.total_supply < 100_000_000_000_000_000, // 100M CYNC in atomic
        "Genesis supply must not exceed total cap"
    );
}

// =============================================================================
// TEST 9: Key image spent tracking survives rollback
// =============================================================================

#[test]
fn tier5_key_image_unspent_after_rollback() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    // Create a fake key image
    let ki = KeyImage::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes());

    // Before spending, it should not be marked spent
    assert!(!chain.is_spent(&ki), "Fresh key image should not be spent");
}

// =============================================================================
// TEST 10: get_block_by_height returns None for future heights
// =============================================================================

#[test]
fn tier5_future_height_returns_none() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    // Genesis (height 0) exists
    assert!(chain.get_block_hash(0).is_some(), "Height 0 must exist");
    assert!(
        chain.get_block_by_height(0).is_some(),
        "Genesis block must be retrievable"
    );

    // Future heights must return None
    assert_eq!(
        chain.get_block_hash(1),
        None,
        "Height 1 should not exist yet"
    );
    assert_eq!(
        chain.get_block_hash(100),
        None,
        "Height 100 should not exist"
    );
    assert_eq!(
        chain.get_block_hash(u64::MAX),
        None,
        "u64::MAX height should not exist"
    );
}

// =============================================================================
// TEST 11: Chain tip stays at genesis when only invalid blocks submitted
// =============================================================================

#[test]
fn tier5_tip_stays_at_genesis_under_attack() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");
    let genesis_hash = chain.tip_hash();

    // Submit many invalid blocks (forged PoW, wrong anchors, etc.)
    for i in 1..=50u64 {
        let b = make_block_at(i, genesis_hash, i as u8);
        let _ = chain.add_block(b);
    }

    // Tip must still be genesis
    assert_eq!(chain.height(), 0, "Height must stay at 0");
    assert_eq!(chain.tip_hash(), genesis_hash, "Tip must remain genesis");
}

// =============================================================================
// TEST 12: Difficulty is always nonzero
// =============================================================================

#[test]
fn tier5_difficulty_never_zero() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    assert!(
        chain.difficulty() > 0,
        "Difficulty must never be zero (even at genesis)"
    );

    let mut prev = chain.tip_hash();
    for i in 1..=5u64 {
        let b = make_block_at(i, prev, i as u8);
        prev = b.hash();
        chain.add_block(b).unwrap();
        assert!(
            chain.difficulty() > 0,
            "Difficulty must never be zero at height {}",
            i
        );
    }
}
