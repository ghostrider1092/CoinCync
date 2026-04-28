//! # Mainnet Configuration
//!
//! Configuration and genesis block for CoinCync mainnet.
//! This is the production network — changes here affect real funds.

use crate::primitives::{Hash, PublicKey, Amount};
use crate::consensus::{Block, BlockHeader};
use crate::config::NetworkType;
use crate::transaction::{Transaction, TxType, TxOutput};
use std::net::SocketAddr;

/// Mainnet network magic bytes ("CYNC")
pub const MAINNET_MAGIC: [u8; 4] = [0x43, 0x59, 0x4E, 0x43];

/// Mainnet default P2P port
pub const MAINNET_P2P_PORT: u16 = 19080;

/// Mainnet default RPC port
pub const MAINNET_RPC_PORT: u16 = 19081;

/// Mainnet address prefix
pub const MAINNET_ADDRESS_PREFIX: &str = "CYNC";

/// Mainnet DNS seeds
/// Register A/AAAA records before launch.
pub const MAINNET_DNS_SEEDS: &[&str] = &[
    "seed1.coincync.org",
    "seed2.coincync.org",
    "seed3.coincync.org",
];

/// Mainnet hardcoded seed nodes
/// These are the initial bootstrap nodes for mainnet peer discovery.
/// Use `--peer <addr:port>` to connect to additional nodes manually.
/// Use `--seed-node <addr:port>` to override these with your own seeds.
///
/// Mainnet seed nodes — populated from testnet fleet.
/// L-6: These will be replaced with dedicated mainnet IPs before October 2026 launch.
/// For now, they point to the existing infrastructure on mainnet ports.
pub const MAINNET_SEED_NODES: &[&str] = &[
    "138.68.172.80:19080",   // LON
    "64.227.49.44:19080",    // SFO
    "170.64.142.146:19080",  // SYD
    "45.55.32.13:19080",     // NYC3
    "143.110.218.99:19080",  // TOR
];

/// Mainnet minimum ring size (same as testnet — constitutional minimum)
pub const MAINNET_MIN_RING_SIZE: usize = 11;

/// Mainnet block time target: 60 seconds.
/// Slower than testnet (30s) for safety — proven safe by Dogecoin (60s, 10+ years).
/// 2x faster than Monero (120s). 10 confirmations = 10 minutes.
pub const MAINNET_BLOCK_TIME: u64 = 60;

/// Mainnet initial difficulty.
/// Higher than testnet to account for real mining hardware at launch.
/// Targets ~30 second blocks with modest initial hashrate.
pub const MAINNET_INITIAL_DIFFICULTY: u64 = 10_000;

/// Hardcoded mainnet genesis hash.
/// Computed from `mainnet_genesis()` — any accidental change to the genesis
/// block struct will cause a mismatch, catching silent chain forks at startup.
///
/// NOTE: This is initialized by running `cargo test --features mainnet-genesis`
/// and copying the computed hash. It MUST match `mainnet_genesis().hash()`.
// Recomputed after the header/tx signing-hash domain separator landing.
// See `BlockHeader::HEADER_HASH_DOMAIN_TAG` in src/consensus/header.rs and
// `TX_SIGN_DOMAIN_TAG` in src/transaction/types.rs. If either tag changes,
// this constant must be recomputed — `test_mainnet_genesis_hash_consistency`
// below fails fast so CI catches it before it ships.
pub const MAINNET_GENESIS_HASH: [u8; 32] = [
    0x9d, 0xbb, 0x99, 0xab, 0x3e, 0x63, 0xac, 0x14,
    0x0f, 0x4a, 0xdf, 0xb8, 0xfb, 0x76, 0xef, 0xbd,
    0x66, 0x5f, 0xb7, 0xf2, 0x3d, 0x75, 0xda, 0x9f,
    0xa7, 0xda, 0x82, 0xe4, 0xd5, 0xc0, 0x33, 0x68,
];

/// Mainnet emission parameters (mirrors constants.rs — single source of truth)
pub mod emission {
    /// Initial block reward (in atomic units)
    pub const INITIAL_REWARD: u64 = 50_000_000_000; // 50 CYNC

    /// Tail emission (perpetual, in atomic units per block)
    pub const TAIL_EMISSION: u64 = 600_000_000; // 0.6 CYNC

    /// Blocks until tail emission begins
    pub const TAIL_EMISSION_HEIGHT: u64 = 2_000_000;

    /// Reward decay factor per year (in basis points, 10000 = 100%)
    pub const ANNUAL_DECAY: u64 = 8500; // 85% (15% reduction per year)
}

/// Mainnet configuration
#[derive(Clone, Debug)]
pub struct MainnetConfig {
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

impl Default for MainnetConfig {
    fn default() -> Self {
        let params = NetworkType::Mainnet.params();
        MainnetConfig {
            network_magic: params.magic,
            p2p_port: params.p2p_port,
            rpc_port: params.rpc_port,
            address_prefix: params.address_prefix.to_string(),
            min_ring_size: MAINNET_MIN_RING_SIZE,
            block_time: MAINNET_BLOCK_TIME,
            initial_difficulty: MAINNET_INITIAL_DIFFICULTY,
            dns_seeds: MAINNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            seed_nodes: MAINNET_SEED_NODES.iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
        }
    }
}

/// Genesis block for mainnet
pub fn mainnet_genesis() -> Block {
    let timestamp = 1790812800; // October 1, 2026 00:00:00 UTC

    // Genesis message embedded in the block
    let genesis_message = b"CoinCync Mainnet Genesis - Privacy You Can Audit - October 2026";

    // Create genesis coinbase transaction
    let coinbase_tx = create_genesis_coinbase(genesis_message);

    // Genesis block header
    let params = NetworkType::Mainnet.params();
    let header = BlockHeader {
        network_magic: params.magic,
        version: 1,
        height: 0,
        timestamp,
        prev_hash: Hash::zero(),
        tx_root: crate::primitives::merkle_root(&[coinbase_tx.hash()]),
        anchor: Hash::zero(),
        algorithm: 0,
        nonce: 0,
        target: Hash::from_difficulty(MAINNET_INITIAL_DIFFICULTY),
        miner_pubkey: PublicKey::from_bytes([0u8; 32]),
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };

    Block {
        header,
        transactions: vec![coinbase_tx],
    }
}

/// Create the genesis coinbase transaction
fn create_genesis_coinbase(message: &[u8]) -> Transaction {
    // Genesis reward goes to a burn address (no one has the key)
    let genesis_pubkey = PublicKey::from_bytes([0u8; 32]);

    let output = TxOutput {
        stealth_address: genesis_pubkey,
        tx_public_key: genesis_pubkey,
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

/// Verify genesis block
pub fn verify_genesis(block: &Block) -> bool {
    if block.header.height != 0 {
        return false;
    }
    if !block.header.prev_hash.is_zero() {
        return false;
    }
    if block.transactions.is_empty() {
        return false;
    }

    let coinbase = &block.transactions[0];
    if coinbase.tx_type != TxType::Coinbase {
        return false;
    }
    if !coinbase.inputs.is_empty() {
        return false;
    }

    true
}

/// Get the expected mainnet genesis hash for verification.
///
/// Returns the hardcoded genesis hash. In debug builds, verifies it matches
/// the computed genesis block hash.
pub fn expected_genesis_hash() -> Hash {
    let hardcoded = Hash::from_bytes(MAINNET_GENESIS_HASH);

    // In debug/test builds, verify the hardcoded hash matches the computed one.
    // Skip if the hash is all zeros (placeholder before first computation).
    #[cfg(any(debug_assertions, test))]
    {
        if MAINNET_GENESIS_HASH != [0u8; 32] {
            let computed = mainnet_genesis().hash();
            assert_eq!(
                hardcoded, computed,
                "CRITICAL: Hardcoded mainnet genesis hash does not match computed genesis hash! \
                 Someone changed the genesis block struct without updating MAINNET_GENESIS_HASH. \
                 Computed: {}",
                computed.to_hex()
            );
        }
    }
    hardcoded
}

/// Mainnet checkpoint
#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: Hash,
}

/// Mainnet checkpoints for fast sync
pub fn mainnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        // Genesis
        Checkpoint {
            height: 0,
            hash: Hash::from_bytes(MAINNET_GENESIS_HASH),
        },
        // Add more checkpoints as mainnet grows
    ]
}

/// Verify a mainnet checkpoint
pub fn verify_checkpoint(height: u64, hash: &Hash) -> Option<bool> {
    mainnet_checkpoints()
        .iter()
        .find(|cp| cp.height == height)
        .map(|cp| &cp.hash == hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_genesis_creation() {
        let genesis = mainnet_genesis();
        assert_eq!(genesis.header.height, 0);
        assert!(genesis.header.prev_hash.is_zero());
        assert!(!genesis.transactions.is_empty());
        assert_eq!(genesis.header.timestamp, 1790812800);
    }

    #[test]
    fn test_mainnet_genesis_verification() {
        let genesis = mainnet_genesis();
        assert!(verify_genesis(&genesis));
    }

    #[test]
    fn test_mainnet_genesis_hash_computation() {
        // Print the computed genesis hash so it can be hardcoded
        let hash = mainnet_genesis().hash();
        eprintln!("MAINNET_GENESIS_HASH = {:?}", hash.as_bytes());
        // This test always passes — it's here to compute the hash
    }

    /// CI invariant: the hardcoded `MAINNET_GENESIS_HASH` must equal the
    /// computed hash of `mainnet_genesis()`. If this test fails, someone
    /// changed the genesis block struct, a header field, or a hash preimage
    /// (e.g. domain separator) without updating the constant. Don't "fix"
    /// this test by updating the constant — first understand *why* the hash
    /// changed, because any change to the mainnet genesis hash is a hard
    /// fork and must be a deliberate, documented decision.
    ///
    /// This mirrors `testnet::tests::test_genesis_hash_consistency`. The
    /// two must stay in lockstep so both networks are protected by CI.
    #[test]
    fn test_mainnet_genesis_hash_consistency() {
        assert_eq!(
            expected_genesis_hash(),
            mainnet_genesis().hash(),
            "MAINNET_GENESIS_HASH is stale — recompute with \
             `cargo test mainnet::tests::test_mainnet_genesis_hash_computation -- --nocapture` \
             and update src/mainnet.rs. ONLY do this if the hash change is intentional."
        );
    }

    #[test]
    fn test_mainnet_genesis_differs_from_testnet() {
        let mainnet = mainnet_genesis().hash();
        let testnet = crate::testnet::testnet_genesis().hash();
        assert_ne!(mainnet, testnet, "Mainnet and testnet genesis must be different!");
    }

    #[test]
    fn test_mainnet_config_default() {
        let config = MainnetConfig::default();
        assert_eq!(config.p2p_port, 19080);
        assert_eq!(config.rpc_port, 19081);
        assert_eq!(config.min_ring_size, 11);
        assert_eq!(config.initial_difficulty, 10_000);
    }

    #[test]
    fn test_mainnet_seed_ips() {
        // Verify seed nodes constant is defined (may be empty pre-launch)
        // When populated, each should be a valid socket address
        for seed in MAINNET_SEED_NODES {
            assert!(seed.parse::<std::net::SocketAddr>().is_ok(),
                "Seed node '{}' is not a valid socket address", seed);
        }
        // DNS seeds should be non-empty
        assert!(!MAINNET_DNS_SEEDS.is_empty(), "DNS seeds must be configured");
    }
}
