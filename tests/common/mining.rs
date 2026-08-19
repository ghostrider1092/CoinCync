//! Shared real-PoW mining helpers for the multi-node / determinism test layers
//! (L6 chaos-partition, L3 sim, …). Lifted from `reorg_double_spend_e2e.rs` so
//! new harnesses don't re-derive them. Coinbase-only: no CLSAG, so blocks are a
//! deterministic function of (parent, height, timestamp, target, miner keys).
//!
//! Include via `#[path = "common/mining.rs"] mod mining;`.
#![allow(dead_code)]

use coincync::consensus::block::Block;
use coincync::consensus::fork_signal::{encode_coinbase_extra, SignalBits};
use coincync::consensus::{
    compute_full_anchor, compute_pow_hash, BlockHeader, DifficultyBlock, PowAlgorithm,
};
use coincync::constants::block_version_at_height;
use coincync::crypto::{
    coinbase_stealth_address, BlindingFactor, PedersenCommitment, SecretScalar, StealthAddress,
};
use coincync::emission::calculate_block_reward;
use coincync::primitives::{hash_domain, merkle_root, Amount, Hash, PublicKey, SecretKey};
use coincync::transaction::{Transaction, TxOutput, TxType};
use rand::rngs::OsRng;

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    (
        SecretKey::from_bytes(secret.to_bytes()),
        PublicKey::from_bytes(public.to_bytes()),
    )
}

/// Build a coinbase paying `reward(height) + total_fees` to a stealth address
/// derived from (spend_pub, view_pub, height, output_index = 0).
pub fn build_coinbase(
    height: u64,
    spend_pub: &PublicKey,
    view_pub: &PublicKey,
    total_fees: u64,
) -> (Transaction, StealthAddress) {
    let reward = calculate_block_reward(height);
    let total_amount = reward.as_atomic().saturating_add(total_fees);
    let commitment = PedersenCommitment::commit(total_amount, &BlindingFactor::zero());

    let miner_secret: [u8; 32] = *blake3::hash(view_pub.as_bytes()).as_bytes();
    let (stealth, _tx_secret) =
        coinbase_stealth_address(spend_pub, view_pub, height, 0, &miner_secret)
            .expect("coinbase stealth derivation must succeed");

    let view_tag = {
        let shared = hash_domain(
            b"COINCYNC_VIEW_TAG",
            &[stealth.tx_public_key.as_bytes().as_slice(), &[0u8]].concat(),
        );
        shared.as_bytes()[0]
    };

    let output = TxOutput {
        stealth_address: stealth.public_key,
        tx_public_key: stealth.tx_public_key,
        encrypted_amount: total_amount.to_le_bytes().to_vec(),
        commitment: commitment.to_bytes(),
        view_tag,
        lock_height: None,
        encrypted_memo: vec![],
    };

    let tx = Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![output],
        fee: Amount::ZERO,
        range_proof: vec![],
        extra: encode_coinbase_extra(height, SignalBits(0)),
    };

    (tx, stealth)
}

/// Mine a real RandomX block on top of `prev` at `target`. Loops the nonce until
/// PoW meets the target — set `COINCYNC_RANDOMX_LIGHT_MODE=1` and mine at the
/// `MIN_DIFFICULTY` floor to keep this cheap.
pub fn mine_block(
    prev: &Block,
    height: u64,
    timestamp: u64,
    target: Hash,
    transactions: Vec<Transaction>,
    miner_pubkey: PublicKey,
    magic: [u8; 4],
) -> Block {
    let prev_hash = prev.hash();
    let tx_hashes: Vec<Hash> = transactions.iter().map(|t| t.hash()).collect();
    let tx_root = merkle_root(&tx_hashes);
    let anchor = compute_full_anchor(&prev_hash, height, timestamp)
        .expect("anchor computation must succeed")
        .mixed_hash;

    let mut nonce = 0u64;
    loop {
        let pow = compute_pow_hash(PowAlgorithm::RandomX, &anchor, nonce, &tx_root, height)
            .expect("RandomX hash must succeed (build with --features randomx)");
        if pow.meets_difficulty(&target) {
            break;
        }
        nonce = nonce
            .checked_add(1)
            .expect("nonce space exhausted — target unexpectedly hard");
    }

    let header = BlockHeader {
        network_magic: magic,
        version: block_version_at_height(height),
        height,
        timestamp,
        prev_hash,
        tx_root,
        anchor,
        algorithm: PowAlgorithm::RandomX as u8,
        nonce,
        target,
        miner_pubkey,
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };

    Block::new(header, transactions)
}

pub fn diff_block(b: &Block) -> DifficultyBlock {
    DifficultyBlock {
        height: b.header.height,
        timestamp: b.header.timestamp,
        target: b.header.target,
    }
}
