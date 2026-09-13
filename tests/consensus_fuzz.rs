//! Consensus fuzzer — differential accept/reject agreement.
//!
//! The fork-causing bug class is "one node accepts a block another rejects."
//! This generates a corpus of malformed blocks and asserts that EVERY node
//! classifies each one identically AND never Accepts it. The corpus here is
//! STRUCTURALLY invalid (wrong magic, bad height/link, bad version, far-future
//! timestamp, double coinbase), so each is rejected before the expensive PoW
//! check — the whole suite runs in milliseconds, no mining.
//!
//! Built on `simkit` so the same corpus can later be replayed against nodes with
//! DIFFERENT state/config (where agreement is a real, non-trivial property).

#[path = "common/mining.rs"]
mod mining;
#[path = "common/simkit.rs"]
mod simkit;

use coincync::chain::BlockStatus;
use coincync::config::NetworkType;
use coincync::consensus::block::Block;
use coincync::consensus::{BlockHeader, PowAlgorithm};
use coincync::primitives::{Hash, PublicKey};
use mining::build_coinbase;
use simkit::Sim;

fn classify(r: &coincync::error::Result<BlockStatus>) -> &'static str {
    match r {
        Ok(BlockStatus::Accepted) => "Accepted",
        Ok(BlockStatus::AcceptedFork) => "AcceptedFork",
        Ok(BlockStatus::AcceptedReorg { .. }) => "AcceptedReorg",
        Ok(BlockStatus::AlreadyKnown) => "AlreadyKnown",
        Ok(BlockStatus::Orphan) => "Orphan",
        Ok(BlockStatus::Invalid(_)) => "Invalid",
        Err(_) => "Err",
    }
}

/// Build a block on top of genesis with fully-specified (mutable) header fields.
fn block(magic: [u8; 4], version: u8, height: u64, prev: Hash, ts: u64, n_coinbase: usize) -> Block {
    let zero_pk = PublicKey::from_bytes([0u8; 32]);
    let (cb, _) = build_coinbase(height, &zero_pk, &zero_pk, 0);
    let txs = std::iter::repeat(cb).take(n_coinbase.max(1)).collect::<Vec<_>>();
    let header = BlockHeader {
        network_magic: magic,
        version,
        height,
        timestamp: ts,
        prev_hash: prev,
        tx_root: Hash::zero(),
        anchor: Hash::zero(),
        algorithm: PowAlgorithm::RandomX as u8,
        nonce: 0,
        target: Hash::from_difficulty(1),
        miner_pubkey: PublicKey::from_bytes([0u8; 32]),
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };
    Block::new(header, txs)
}

#[test]
fn malformed_blocks_are_rejected_identically_by_every_node() {
    let sim = Sim::new(3);
    let magic = NetworkType::Testnet.magic_bytes();
    let genesis = sim.nodes[0].chain.get_block_by_height(0).unwrap().hash();
    let good_ts = sim.nodes[0].chain.get_block_by_height(0).unwrap().header.timestamp + 3600;
    let far_future = good_ts + 10 * 365 * 24 * 3600;

    // Deterministic corpus — each block violates a distinct structural rule.
    let corpus = vec![
        ("wrong_magic", block([0xDE, 0xAD, 0xBE, 0xEF], 1, 1, genesis, good_ts, 1)),
        ("height_gap", block(magic, 1, 5, genesis, good_ts, 1)),
        ("bad_prev_link", block(magic, 1, 1, Hash::from_bytes([9u8; 32]), good_ts, 1)),
        ("version_zero", block(magic, 0, 1, genesis, good_ts, 1)),
        ("version_max", block(magic, 255, 1, genesis, good_ts, 1)),
        ("far_future_ts", block(magic, 1, 1, genesis, far_future, 1)),
        ("double_coinbase", block(magic, 1, 1, genesis, good_ts, 2)),
    ];

    for (name, blk) in &corpus {
        let responses: Vec<&'static str> = sim
            .nodes
            .iter()
            .map(|n| classify(&n.chain.add_block(blk.clone())))
            .collect();
        // (1) all nodes agree on the classification
        assert!(
            responses.iter().all(|r| *r == responses[0]),
            "nodes DISAGREED on `{name}`: {responses:?} — a fork surface"
        );
        // (2) a malformed block is never Accepted onto the main chain
        assert_ne!(
            responses[0], "Accepted",
            "malformed block `{name}` was ACCEPTED — consensus rule missing"
        );
    }
}
