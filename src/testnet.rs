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

/// Hard-coded testnet seed peers — small, purpose-scoped bootstrap
/// set. (Prior comment characterised this as "Monero-style"; whether
/// Monero's testnet or mainnet seed sets follow a specifically
/// smaller-than-Bitcoin shape was not re-verified against Monero
/// source this session, so the qualifier is dropped.)
///
/// These are PURE SEED hosts: their only job is to accept inbound P2P,
/// hand out a peer list, and serve the chain to bootstrapping nodes.
/// They do NOT run app workloads (landing page, explorer, API) — those
/// either live on separate hosts OR (for `api.coincync.network`) live
/// as nginx-only proxies that forward to one of these seeds. So an
/// app-layer DDoS does not take out the bootstrap layer.
///
/// Five entries spanning US + EU. Asia/Oceania coverage is intentionally
/// deferred until v1.0 mainnet when budget for additional fleet boxes
/// is committed. Add community-run seeds as volunteers come online;
/// never remove an entry without a paired add.
///
/// 2026-06-03 REFRESH: the previous list referenced legacy DigitalOcean
/// hosts that were decommissioned during the 2026-05 Vultr migration.
/// Operators bootstrapping with that list could not reach a live seed
/// without supplying `--addnode` explicitly — observed multiple times
/// during 2026-06-01 → 06-03 community testing. The correct deployed
/// fleet is enumerated in `docs/src/getting-started/run-a-node.md`
/// and `scripts/deploy-node-binary.sh` (which both reference these IPs).
/// `95.179.165.225` (the former api node) is intentionally excluded —
/// see `docs/operations/api-role-architecture.md` for that node's
/// migration to nginx-only.
pub const TESTNET_SEED_NODES: &[&str] = &[
    // 2026-06-21 refresh — see `src/network/dns_seeds.rs::TESTNET_FALLBACK`
    // for the parallel list (which this MUST stay in sync with — the
    // `testnet_fallback_matches_seed_nodes` test enforces this).
    "66.135.23.193:28080",    // seed1 — Vultr
    "140.82.57.168:28080",    // seed2 — Vultr
    "45.32.251.6:28080",      // seed3 — Vultr (replaces dead 207.148.111.76)
    "207.148.6.50:28080",     // explorer — Vultr (deliberate exception per dns_seeds.rs)
    "173.199.93.21:28080",    // randomx miner — Vultr (provisioned 2026-06-20)
    //
    // History:
    // - 2026-06-05: Vultr London (192.248.151.16) decommissioned (missed
    //   the 2026-06-04 testnet wipe, drifted onto pre-wipe chain at
    //   h=12,201 while live fleet was at ~2,200, poisoned the api-box's
    //   nginx backend, destroyed).
    // - 2026-06-18: original seed3 (207.148.111.76) decommissioned after
    //   host-key rotation issue; replaced by fresh box at 45.32.251.6.
    // - 2026-06-20: randomx miner (173.199.93.21) replaces destroyed
    //   149.248.37.11; added to seed list for the same reason explorer is:
    //   gives new operators an extra fallback IP for IBD bootstrap.
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

/// Hardcoded testnet checkpoints (height → block hash) — pinned by
/// the project to short-circuit long-range attacks and to make IBD
/// reject divergent forks early instead of mining hashes against
/// an alternative chain from genesis. Any chain that disagrees with a checkpoint
/// at or below the checkpoint height is rejected immediately.
pub const TESTNET_CHECKPOINT_LIST: &[(u64, &str)] = &[
    // ── 2026-06-04 POST-WIPE: list intentionally empty ──
    // The previous 280 entries (h=50 → h=14000) anchored block
    // hashes from the pre-2026-06-04 chain. After the testnet
    // was wiped to genesis on 2026-06-04 (see
    // docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md)
    // those hashes no longer correspond to any block — they
    // were causing every fresh-chain block at h=50 to be
    // rejected with `Hardcoded checkpoint mismatch at height 50`.
    //
    // Re-populate once the new chain has soaked stably above
    // h=20k for >72h on the current binary. Until then, the
    // chain runs without hardcoded-checkpoint anchoring
    // (acceptable on testnet pre-mainnet — long-range-attack
    // protection is via cumulative work + MESS, not yet via
    // hardcoded anchors).
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
        // 2026-06-04 wipe: TESTNET_CHECKPOINT_LIST is INTENTIONALLY empty
        // following the testnet reset to genesis (see
        // docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md).
        // The previous 280 entries (h=50 → h=14000) anchored block hashes
        // from the pre-wipe chain and no longer correspond to any block.
        //
        // The assertion accepts either: (a) the current intentionally-empty
        // state (highest == 0), or (b) a re-populated list at >= 14000,
        // which is what the bar was set to during the 2026-06-03 refresh.
        // When the chain soaks above h=20k for >72h and we re-populate,
        // drop the `h == 0` branch and tighten back to `>= 14000` (or higher).
        let h = highest_checkpoint_height();
        assert!(h == 0 || h >= 14000,
            "checkpoint list regressed: highest is {} (expected 0 for intentionally-empty post-wipe, or >= 14000 once re-populated)", h);
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
