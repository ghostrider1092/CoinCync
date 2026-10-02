//! Beta-channel genesis + checkpoints (see [`crate::config::NetworkType::Beta`]).
//!
//! The beta genesis is the **testnet genesis with `BETA_MAGIC` swapped into the
//! header**. Because `network_magic` is part of the header hash, this yields a
//! DISTINCT genesis hash — so beta is its own chain — and it passes the height-0
//! network-magic check on the beta network (`header.network_magic == BETA_MAGIC`).
//! Everything else mirrors testnet; isolation from testnet/mainnet is by magic.

use crate::consensus::Block;
use crate::primitives::Hash;

/// True only when this binary can validate shielded transactions on Beta,
/// i.e. it was built with both `sketch-gk-proof` and `libspark-ffi`.
pub const fn shielded_capable_build() -> bool {
    cfg!(all(feature = "sketch-gk-proof", feature = "libspark-ffi"))
}

/// Beta genesis block: the testnet genesis with the beta magic swapped in.
pub fn beta_genesis() -> Block {
    let mut g = crate::testnet::testnet_genesis();
    g.header.network_magic = crate::constants::BETA_MAGIC;
    // Trivial initial difficulty (beta is a disposable test network) so blocks
    // mine near-instantly — shielded activation at height 5 is reachable in
    // seconds. This changes the header (target) → distinct hash from testnet.
    g.header.target = Hash::from_difficulty(crate::constants::BETA_INITIAL_DIFFICULTY);
    g
}

/// Hardcoded beta genesis hash. Regenerate if `beta_genesis()` ever changes:
///   cargo test --features testnet beta::tests::print_beta_genesis_hash -- --nocapture
pub const BETA_GENESIS_HASH: [u8; 32] = [
    0x6b, 0x63, 0x18, 0x92, 0x7a, 0xc6, 0x99, 0xa0, 0x43, 0x1b, 0x9c, 0x0c, 0xad, 0x66, 0x7f, 0xe6,
    0x29, 0x19, 0x80, 0x73, 0x0c, 0x69, 0x2f, 0x99, 0x93, 0x44, 0xc1, 0x55, 0xcb, 0xe7, 0x19, 0x76,
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

    #[cfg(all(feature = "sketch-gk-proof", feature = "libspark-ffi"))]
    #[test]
    fn shielded_capable_when_required_features_are_enabled() {
        assert!(shielded_capable_build());
    }

    // Also covers the partial builds (only one of the two features), which must
    // still be refused by the beta startup guard.
    #[cfg(not(all(feature = "sketch-gk-proof", feature = "libspark-ffi")))]
    #[test]
    fn not_shielded_capable_without_required_features() {
        assert!(!shielded_capable_build());
    }

    #[test]
    fn shielded_capable_build_agrees_with_beta_activation_height() {
        use crate::config::NetworkType;
        use crate::constants::{
            shielded_activation_height, SHIELDED_BETA_ACTIVATION_HEIGHT,
            SHIELDED_TX_ACTIVATION_HEIGHT,
        };

        let height = shielded_activation_height(NetworkType::Beta);
        // A build allowed to start on beta must actually activate shielded there.
        if shielded_capable_build() {
            assert_eq!(height, SHIELDED_BETA_ACTIVATION_HEIGHT);
        }
        // Without sketch-gk-proof, shielded never activates on beta and the
        // build is not shielded-capable.
        if !cfg!(feature = "sketch-gk-proof") {
            assert_eq!(height, SHIELDED_TX_ACTIVATION_HEIGHT);
            assert!(!shielded_capable_build());
        }
    }

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
