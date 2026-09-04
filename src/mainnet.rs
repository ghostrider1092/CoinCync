//! # Mainnet Configuration
//!
//! Configuration and genesis block for CoinCync mainnet.
//! This is the production network — changes here affect real funds.

use crate::config::NetworkType;
use crate::consensus::{Block, BlockHeader};
use crate::primitives::{Amount, Hash, PublicKey};
use crate::transaction::{Transaction, TxOutput, TxType};

// NOTE (2026-08-16 dead-code sweep): removed the dead `MainnetConfig` struct
// (+ `impl Default`, unit tests) and its supporting duplicate constants
// (`MAINNET_MAGIC`, `MAINNET_P2P_PORT`, `MAINNET_RPC_PORT`,
// `MAINNET_ADDRESS_PREFIX`, `MAINNET_DNS_SEEDS`, `MAINNET_SEED_NODES`,
// `MAINNET_MIN_RING_SIZE`, `MAINNET_BLOCK_TIME`). Nothing constructed
// `MainnetConfig` at runtime, and the constants shadowed the LIVE copies in
// `constants.rs` / `network::dns_seeds` — an "operator edits the wrong file"
// trap. The live sources of truth are `crate::constants::*` (magic/ports/
// prefix/block-time/ring-size) and `network::dns_seeds::{MAINNET_DNS_SEEDS,
// MAINNET_FALLBACK}` (seeds, consumed by `BootstrapConfig::for_network`).

/// Mainnet initial difficulty.
/// Higher than testnet to account for real mining hardware at launch.
/// ASERT converges toward the `TARGET_BLOCK_TIME` (120s) target regardless of
/// this seed; a modest initial hashrate simply takes a few blocks to settle.
// Calibrated 2026-09-02 to a home-CPU RandomX launch hashrate (~530 H/s per
// CPU): initial difficulty ≈ H × TARGET_BLOCK_TIME (120s) so genesis-era blocks
// land near the 120s target instead of solving far under it and driving ASERT
// into a startup overshoot/stall. 64k assumes a single-CPU founder launch and
// stays safe as more home miners join (blocks stay well above 1s, so no
// timestamp-compression spiral — a gentle bounded ramp at worst). If mainnet
// launches with substantially more aggregate hashrate, raise this to
// ≈ total_launch_hashrate × 120. See docs/design/difficulty-oscillation-analysis.md §7.
pub const MAINNET_INITIAL_DIFFICULTY: u64 = 64_000;

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
    0xc9, 0xeb, 0x73, 0xab, 0x1e, 0xd2, 0xd9, 0xe4, 0x00, 0x42, 0xa9, 0x62, 0x99, 0x0b, 0xba, 0x98,
    0x11, 0x4b, 0xc5, 0x09, 0xb3, 0x30, 0xbc, 0xda, 0x02, 0x2b, 0x9e, 0xc8, 0xfe, 0x07, 0x63, 0x5c,
];

// AUDIT (2026-07-02): removed the `pub mod emission { ... }` block that
// previously lived here. It was dead code — zero references across the
// repo (grep for `mainnet::emission::TAIL_EMISSION` / `INITIAL_REWARD`
// / `TAIL_EMISSION_HEIGHT` / `ANNUAL_DECAY` yields nothing). The live
// emission curve reads `crate::constants::TAIL_EMISSION` (see
// src/emission/curve.rs L75).
//
// The bigger problem was value drift: the removed `TAIL_EMISSION`
// declared 600_000_000 (0.0006 CYNC) while the authoritative
// `constants::TAIL_EMISSION` is 600_000_000_000 (0.6 CYNC). A 1000×
// mismatch on the same conceptual constant, sitting in a file named
// `mainnet.rs` where any future refactor might reach for the "obvious"
// module-scoped copy. The comment above the block claimed it "mirrors
// constants.rs — single source of truth", which the value directly
// contradicted.
//
// Removed rather than corrected: keeping a second declaration would
// re-invite the drift. If future work needs mainnet-scoped emission
// overrides, `constants.rs` is the place — its per-network parameters
// are already the single source of truth the docstring claimed this
// block was. Same removal was NOT made to `testnet.rs` in this pass
// because that file is `critical_files.lock`-protected; the mainnet
// removal alone eliminates the higher-risk "future code lands on the
// mainnet path and picks the wrong constant" scenario.

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
                hardcoded,
                computed,
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
        assert_ne!(
            mainnet, testnet,
            "Mainnet and testnet genesis must be different!"
        );
    }

}
