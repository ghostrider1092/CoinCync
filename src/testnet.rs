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

/// Hard-coded testnet seed peers — Monero-style minimal bootstrap set.
///
/// These are PURE SEED hosts: their only job is to accept inbound P2P,
/// hand out a peer list, and serve the chain to bootstrapping nodes.
/// They do NOT run app workloads (landing page, explorer, API) — those
/// live on separate hosts (NYC3, LON, TOR) which are deliberately
/// excluded from this list so a public-app DDoS doesn't take out the
/// bootstrap layer too.
///
/// Six entries across three continents (US, Europe, Australia) mirrors
/// Monero's `MIN_WANTED_SEED_NODES = 12` posture but at half the count
/// (we run a smaller fleet during testnet). Add community-run seeds as
/// volunteers come online; never remove an entry without a paired add.
pub const TESTNET_SEED_NODES: &[&str] = &[
    "192.34.59.42:28080",     // NYC1 — mempool + relay (US-East)
    "46.101.138.120:28080",   // FRA  — mempool + relay (Europe)
    "165.245.161.62:28080",   // RIC  — relay (US-East)
    "165.245.140.113:28080",  // ATL  — relay (US-South)
    "164.92.153.24:28080",    // AMS  — relay (Europe) + DNS seed3
    "170.64.142.146:28080",   // SYD  — relay (Asia-Pacific)
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
    // skip expensive crypto verification (range proofs, ring signatures,
    // RandomX PoW). Structural checks still run. ~10-50x faster initial sync.
    //
    // Pulled from the canonical testnet (post-2026-05-02 redeploy) via
    // `get_block_by_height`. Add new entries every ~50–100 blocks as the
    // chain matures. Never remove an existing entry — that would let a
    // long-range attacker rewrite history below the deleted checkpoint.
    (  50, "9b282b2732ce2b935ecffae92e00c243ea579331d304d522cbf0f507458e04f2"),
    ( 100, "e2f6cdb8e496ae0b8a526ce8a91150d96d675625c69d64724627bcdbaa546a9b"),
    ( 150, "4060d5059f25c1be5234da1947495c6128ec9980d37915d06463576bee58ca3d"),
    ( 200, "8c8a44d79aa4b330e2f731c5323cd24bbed1d819660d3a3569a85bbf92039b29"),
    ( 250, "a00ffb1ccd0e5acf77cf114937c3ab824bfe7ffb2a90b95ab974231e1e242ce3"),
    ( 300, "7f026477d87e6a8e73ee47fd7ceb3fbb6f3e449e1ab672bdc1d8b7d59f824af4"),
    ( 350, "54f346581f666f08e6561e639f9f12b471382bc8fee0c8bf65a9d52a2f1048cc"),
    ( 400, "da1601f6b62b05f7f8be983fdfe5cf69ffb47bbd277fa1d88f481629038ce37a"),
    ( 450, "da3f78bd553f2cb36c335a37118d52e630939d88dafa9b3c1d092921233b2e4d"),
    ( 488, "17384b417ffd0a5bd0f49c26f599bd44cda88010ae2146e8fe260d7e47185e22"),
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
    fn test_checkpoints_populated() {
        // Heights not in the list return None (no opinion).
        assert_eq!(verify_hardcoded_checkpoint(999_999, &Hash::zero()), None);
        // Highest checkpoint must be at or above the last known good height
        // captured during list population. Bump this when adding new entries.
        assert!(highest_checkpoint_height() >= 488,
            "checkpoint list regressed: highest is {}", highest_checkpoint_height());
        // List must be strictly monotonic in height — accidental duplicates
        // or out-of-order entries break the long-range-attack defence.
        let heights: Vec<u64> = TESTNET_CHECKPOINT_LIST.iter().map(|(h, _)| *h).collect();
        for w in heights.windows(2) {
            assert!(w[0] < w[1], "checkpoint heights not strictly increasing: {} >= {}", w[0], w[1]);
        }
        // Each hash string must parse to 32 bytes.
        for (h, hex_str) in TESTNET_CHECKPOINT_LIST {
            assert_eq!(hex_str.len(), 64, "checkpoint at h={} has wrong hex length", h);
            for c in hex_str.chars() {
                assert!(c.is_ascii_hexdigit(), "checkpoint h={} has non-hex char {:?}", h, c);
            }
        }
    }

    #[test]
    fn test_genesis_checkpoint() {
        let gh = expected_genesis_hash();
        assert_eq!(verify_hardcoded_checkpoint(0, &gh), Some(true));
        assert_eq!(verify_hardcoded_checkpoint(0, &Hash::from_bytes([1u8; 32])), Some(false));
    }
}
