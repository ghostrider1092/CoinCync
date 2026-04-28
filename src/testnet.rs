//! # Testnet Configuration
//!
//! Configuration, genesis block, and checkpoints for CoinCync testnet.

use crate::primitives::{Hash, PublicKey, Amount};
use crate::consensus::{Block, BlockHeader};
use crate::config::NetworkType;
use crate::transaction::{Transaction, TxType, TxOutput};
use std::net::SocketAddr;

// ── Network constants ────────────────────────────────────────────────────────

pub const TESTNET_MAGIC: [u8; 4] = [0x74, 0x43, 0x59, 0x4E]; // "tCYN"
pub const TESTNET_P2P_PORT: u16 = 28080;
pub const TESTNET_RPC_PORT: u16 = 28081;
pub const TESTNET_ADDRESS_PREFIX: &str = "tCYNC";

/// Public DNS names that must resolve to hosts listening on `TESTNET_P2P_PORT`.
/// (The `*.testnet.*` hostnames are not deployed in DNS; clearnet bootstrap uses these.)
pub const TESTNET_DNS_SEEDS: &[&str] = &[
    "seed1.coincync.network",
    "seed2.coincync.network",
    "seed3.coincync.network",
];

/// Hard-coded testnet seed peers. Roles match the deployment layout in
/// `/deploy/landing/mirrors.json` and the operations section of the
/// mdBook docs. All six nodes run RandomX under Article V; the role
/// annotation reflects what *else* the host does (explorer, API, faucet,
/// monitoring) on top of running a seed peer.
// Community bootstrap peers: prioritize hosts that are consistently reachable
// from external networks (seed/relay/mempool/miner nodes on testnet P2P 28080).
// DNS A records (seed*.coincync.network): seed1→143.110.218.99, seed2→45.55.32.13, seed3→164.92.153.24
pub const TESTNET_SEED_NODES: &[&str] = &[
    "192.34.59.42:28080",     // NYC1      — mempool1 + relay
    "46.101.138.120:28080",   // FRA       — mempool2 + relay
    "143.110.218.99:28080",   // TOR       — public RPC + DNS seed1 (seed1.coincync.network)
    "165.245.161.62:28080",   // RIC       — relay
    "165.245.140.113:28080",  // ATL       — miner + relay
    "164.92.153.24:28080",    // AMS       — relay + DNS seed3 (seed3.coincync.network)
];

pub const TESTNET_MIN_RING_SIZE: usize = 11;
pub const TESTNET_BLOCK_TIME: u64 = crate::constants::TARGET_BLOCK_TIME;
// Matched to the measured ~40 H/s RandomX JIT throughput on DO
// Premium AMD 1 vCPU droplets (light mode, no huge pages). Target
// block time = 120 s → difficulty = 40 × 120 = 4800. from_difficulty
// rounds to 12 leading zero bits (effective ~4096).
pub const TESTNET_INITIAL_DIFFICULTY: u64 = 4_800;

// Recomputed after the header/tx signing-hash domain separator landing.
// See `BlockHeader::HEADER_HASH_DOMAIN_TAG` in src/consensus/header.rs and
// `TX_SIGN_DOMAIN_TAG` in src/transaction/types.rs. If either tag changes,
// this constant must be recomputed — `test_genesis_hash_consistency` below
// fails fast so CI catches it before it ships.
// Public testnet genesis — April 21, 2026 reset
pub const TESTNET_GENESIS_HASH: [u8; 32] = [
    0x41, 0xf9, 0x70, 0xdf, 0x61, 0x52, 0x42, 0x5a,
    0x29, 0x38, 0x72, 0x54, 0x23, 0x23, 0x5c, 0x2c,
    0x40, 0xec, 0x52, 0x55, 0x6e, 0xcc, 0x0f, 0xd1,
    0x42, 0x2d, 0x58, 0x86, 0x52, 0xcc, 0x56, 0xb4,
];

// ── Checkpoints ──────────────────────────────────────────────────────────────

/// Hardcoded testnet checkpoints: (height, "64_hex_chars_block_hash").
/// Add entries as the testnet matures. Never remove existing entries.
///
/// To add a checkpoint: run `curl -s http://NODE:28081 -d '{"jsonrpc":"2.0","method":"get_block_hash","params":[HEIGHT],"id":1}'`
/// and paste the result hash here.
///
/// SECURITY: Checkpoints prevent long-range attacks where an adversary builds
/// an alternative chain from genesis. Any chain that disagrees with a checkpoint
/// at or below the checkpoint height is rejected immediately.
pub const TESTNET_CHECKPOINT_LIST: &[(u64, &str)] = &[
    // Checkpoints enable fast sync: blocks below the highest checkpoint
    // skip expensive crypto verification (range proofs, ring signatures).
    // Structural checks still run. ~10-50x faster initial sync.
    //
    // Previous checkpoints cleared — chain redeployed April 23, 2026.
    // New checkpoints will be added after 7 days of stability.
];

pub fn highest_checkpoint_height() -> u64 {
    TESTNET_CHECKPOINT_LIST.iter().map(|(h, _)| *h).max().unwrap_or(0)
}

pub fn verify_hardcoded_checkpoint(height: u64, hash: &Hash) -> Option<bool> {
    if height == 0 {
        return Some(&Hash::from_bytes(TESTNET_GENESIS_HASH) == hash);
    }
    for (cp_h, cp_hex) in TESTNET_CHECKPOINT_LIST {
        if *cp_h == height {
            let mut bytes = [0u8; 32];
            if hex::decode_to_slice(cp_hex, &mut bytes).is_ok() {
                return Some(&Hash::from_bytes(bytes) == hash);
            }
            return Some(false);
        }
    }
    None
}

// ── Emission ─────────────────────────────────────────────────────────────────

pub mod emission {
    pub const INITIAL_REWARD: u64 = 50_000_000_000;
    pub const TAIL_EMISSION: u64 = 600_000_000;
    pub const TAIL_EMISSION_HEIGHT: u64 = 2_000_000;
    pub const ANNUAL_DECAY: u64 = 8500;
}

// ── Config ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct TestnetConfig {
    pub network_magic: [u8; 4],
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub address_prefix: String,
    pub min_ring_size: usize,
    pub block_time: u64,
    pub initial_difficulty: u64,
    pub dns_seeds: Vec<String>,
    pub seed_nodes: Vec<SocketAddr>,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        let params = NetworkType::Testnet.params();
        TestnetConfig {
            network_magic: params.magic,
            p2p_port: params.p2p_port,
            rpc_port: params.rpc_port,
            address_prefix: params.address_prefix.to_string(),
            min_ring_size: TESTNET_MIN_RING_SIZE,
            block_time: TESTNET_BLOCK_TIME,
            initial_difficulty: TESTNET_INITIAL_DIFFICULTY,
            dns_seeds: TESTNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            seed_nodes: TESTNET_SEED_NODES.iter().filter_map(|s| s.parse().ok()).collect(),
        }
    }
}

// ── Genesis ──────────────────────────────────────────────────────────────────

pub fn testnet_genesis() -> Block {
    // Bumped +1 from the original 1772784000 — the old value produced
    // genesis hash 41863f9e which derives RandomX key 4759d1a3, and that
    // specific key triggers a pathological hang in randomx_rs's Argon2d
    // cache fill on DigitalOcean's KVM hypervisor (both AMD and Intel).
    // Bumping the timestamp by 1 second changes the genesis hash and
    // therefore the RandomX key, avoiding the bad key.
    // L-7: +1 workaround for randomx_rs Argon2d KVM hang. File upstream bug.
    // RESET 2026-04-21: New genesis for public testnet launch.
    // Previous timestamp 1772784001 produced chains that got contaminated
    // during infrastructure updates. Fresh start with current timestamp.
    let timestamp = 1776818628;
    let genesis_message = b"CoinCync Public Testnet - April 2026 - Trust the Math";
    let coinbase_tx = create_genesis_coinbase(genesis_message);

    let params = NetworkType::Testnet.params();
    let header = BlockHeader {
        network_magic: params.magic,
        version: 1, height: 0, timestamp,
        prev_hash: Hash::zero(),
        tx_root: crate::primitives::merkle_root(&[coinbase_tx.hash()]),
        anchor: Hash::zero(), algorithm: 0, nonce: 0,
        target: Hash::from_difficulty(TESTNET_INITIAL_DIFFICULTY),
        miner_pubkey: PublicKey::from_bytes([0u8; 32]),
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };

    Block { header, transactions: vec![coinbase_tx] }
}

fn create_genesis_coinbase(message: &[u8]) -> Transaction {
    let pk = PublicKey::from_bytes([0u8; 32]);
    let output = TxOutput {
        stealth_address: pk,
        tx_public_key: pk,
        encrypted_amount: vec![0u8; 8],
        commitment: [0u8; 32],
        view_tag: 0,
        lock_height: None,
        encrypted_memo: vec![],
    };
    Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![output],
        fee: Amount::from_atomic(0),
        range_proof: vec![],
        extra: message.to_vec(),
    }
}

pub fn verify_genesis(block: &Block) -> bool {
    block.header.height == 0 && block.header.prev_hash.is_zero()
        && !block.transactions.is_empty()
        && block.transactions[0].tx_type == TxType::Coinbase
        && block.transactions[0].inputs.is_empty()
}

pub fn expected_genesis_hash() -> Hash {
    let hardcoded = Hash::from_bytes(TESTNET_GENESIS_HASH);
    #[cfg(any(debug_assertions, test))]
    {
        let computed = testnet_genesis().hash();
        assert_eq!(hardcoded, computed,
            "CRITICAL: Genesis hash mismatch! Update TESTNET_GENESIS_HASH. Computed: {}",
            computed.to_hex()
        );
    }
    hardcoded
}

#[derive(Clone, Debug)]
pub struct Checkpoint { pub height: u64, pub hash: Hash }

pub fn testnet_checkpoints() -> Vec<Checkpoint> {
    let mut cps = vec![Checkpoint { height: 0, hash: expected_genesis_hash() }];
    for (h, hex_str) in TESTNET_CHECKPOINT_LIST {
        let mut bytes = [0u8; 32];
        if hex::decode_to_slice(hex_str, &mut bytes).is_ok() {
            cps.push(Checkpoint { height: *h, hash: Hash::from_bytes(bytes) });
        }
    }
    cps
}

pub fn verify_checkpoint(height: u64, hash: &Hash) -> Option<bool> {
    verify_hardcoded_checkpoint(height, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_creation() {
        let g = testnet_genesis();
        assert_eq!(g.header.height, 0);
        assert!(verify_genesis(&g));
    }

    #[test]
    fn test_genesis_hash_consistency() {
        assert_eq!(expected_genesis_hash(), testnet_genesis().hash());
    }

    #[test]
    fn test_genesis_hash_stability() {
        assert_eq!(testnet_genesis().hash(), expected_genesis_hash());
    }

    #[test]
    fn test_config_default() {
        let c = TestnetConfig::default();
        assert_eq!(c.p2p_port, 28080);
        assert_eq!(c.rpc_port, 28081);
    }

    #[test]
    fn test_checkpoints_ready_to_populate() {
        // Checkpoint list is empty until real testnet hashes are collected.
        // Once populated, update this test to verify highest_checkpoint_height() > 0.
        // Heights not in the list return None (no opinion).
        assert_eq!(verify_hardcoded_checkpoint(999, &Hash::zero()), None);
    }

    #[test]
    fn test_genesis_checkpoint() {
        let gh = expected_genesis_hash();
        assert_eq!(verify_hardcoded_checkpoint(0, &gh), Some(true));
        assert_eq!(verify_hardcoded_checkpoint(0, &Hash::from_bytes([1u8; 32])), Some(false));
    }
}
