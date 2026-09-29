//! Beta-channel genesis + checkpoints (see [`crate::config::NetworkType::Beta`]).
//!
//! The beta genesis is the **testnet genesis with `BETA_MAGIC` swapped into the
//! header**. Because `network_magic` is part of the header hash, this yields a
//! DISTINCT genesis hash — so beta is its own chain — and it passes the height-0
//! network-magic check on the beta network (`header.network_magic == BETA_MAGIC`).
//! Everything else mirrors testnet; isolation from testnet/mainnet is by magic.

use crate::consensus::Block;
use crate::primitives::Hash;

/// Beta genesis block: the testnet genesis with the beta magic swapped in.
pub fn beta_genesis() -> Block {
    let mut g = crate::testnet::testnet_genesis();
    g.header.network_magic = crate::constants::BETA_MAGIC;
    g
}

/// Hardcoded beta genesis hash. Regenerate if `beta_genesis()` ever changes:
///   cargo test --features testnet beta::tests::print_beta_genesis_hash -- --nocapture
pub const BETA_GENESIS_HASH: [u8; 32] = [
    0xf1, 0xa8, 0xe0, 0x33, 0x60, 0xa8, 0xbb, 0x31, 0xc4, 0x9c, 0x12, 0x57, 0x23, 0xeb, 0x47, 0x18,
    0x85, 0x1b, 0x7d, 0xef, 0x3f, 0xa3, 0x16, 0xa4, 0x57, 0xaa, 0xca, 0x9e, 0x68, 0x1d, 0x11, 0xae,
];

/// Beta's genesis hash, with a debug/test self-check that the hardcoded value
/// still matches `beta_genesis()` (mirrors `testnet::expected_genesis_hash`).
pub fn expected_genesis_hash() -> Hash {
    let hardcoded = Hash::from_bytes(BETA_GENESIS_HASH);
    #[cfg(any(debug_assertions, test))]
    {
        let computed = beta_genesis().hash();
        assert_eq!(
            hardcoded,
            computed,
            "CRITICAL: beta genesis hash mismatch! Update BETA_GENESIS_HASH. Computed: {}",
            computed.to_hex()
        );
    }
    hardcoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_beta_genesis_hash() {
        // One-off helper: prints the value to hardcode into BETA_GENESIS_HASH.
        println!("BETA_GENESIS_HASH_HEX={}", beta_genesis().hash().to_hex());
    }

    #[test]
    fn beta_genesis_is_valid_carries_beta_magic_and_hash_matches() {
        let g = beta_genesis();
        // Distinct genesis via BETA_MAGIC (so beta is its own chain + passes the
        // height-0 magic check on the beta network).
        assert_eq!(g.header.network_magic, crate::constants::BETA_MAGIC);
        // It's a structurally valid genesis.
        assert!(crate::testnet::verify_genesis(&g));
        // The hardcoded BETA_GENESIS_HASH matches the computed genesis (this is
        // exactly the self-check expected_genesis_hash() runs in debug/test).
        assert_eq!(expected_genesis_hash(), g.hash());
        // And it is genuinely distinct from testnet's genesis.
        assert_ne!(g.hash(), crate::testnet::testnet_genesis().hash());
    }
}
