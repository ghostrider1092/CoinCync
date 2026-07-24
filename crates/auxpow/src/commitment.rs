//! The merge-mining commitment tag carried in a parent block's coinbase.
//!
//! A parent-chain miner embeds this tag in their coinbase to pledge one PoW
//! solution to a Merkle tree of auxiliary-chain block hashes. A single parent
//! solution can therefore commit to *several* aux chains at once, each pinned
//! to a deterministic slot so a miner cannot reuse one solution for two
//! conflicting blocks of the same aux chain.
//!
//! ## Reference wire format
//!
//! This crate implements the Namecoin/Bitcoin-style tag as the canonical
//! reference encoding:
//!
//! ```text
//! [ magic: 4 bytes = 0xFA 0xBE 'm' 'm' ] [ merkle_root: 32 bytes ]
//! [ merkle_size: u32 LE ] [ nonce: u32 LE ]
//! ```
//!
//! A Monero parent expresses the same `(merkle_root, merkle_size, nonce)`
//! payload through its own `tx_extra` merge-mining field (tag `0x03`); adapting
//! the parser to that container is a thin, parent-specific shim added at
//! consensus-integration time. The *payload* — and the slot math below — is
//! identical across parents.

use crate::error::AuxPowError;

/// Reference tag magic: `0xFA 0xBE 'm' 'm'` (the widely used AuxPoW marker).
pub const MERGE_MINING_MAGIC: [u8; 4] = [0xFA, 0xBE, b'm', b'm'];

/// Serialized length of the reference tag: magic(4) + root(32) + size(4) + nonce(4).
pub const TAG_LEN: usize = 4 + 32 + 4 + 4;

/// A 32-byte, domain-separated auxiliary-chain identifier.
///
/// Per the 2026-07-24 review: the chain id must NOT be a hand-picked short
/// constant. It is derived with domain separation from the protocol version,
/// the CoinCync genesis hash, the network magic, and the selected parent
/// network/genesis identifier — so mainnet, testnet, and regtest get distinct
/// ids, and the final mainnet value cannot exist until genesis parameters are
/// locked. The Merkle-slot math folds it down to a `u32` seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuxChainId(pub [u8; 32]);

impl AuxChainId {
    /// Derive the id from its network-binding inputs.
    pub fn derive(
        protocol_version: u32,
        genesis_hash: &[u8; 32],
        network_magic: &[u8; 4],
        parent_id: &[u8],
    ) -> Self {
        let mut h = blake3::Hasher::new_derive_key("coincync/auxpow/chain-id/v1");
        h.update(&protocol_version.to_le_bytes());
        h.update(genesis_hash);
        h.update(network_magic);
        h.update(parent_id);
        AuxChainId(*h.finalize().as_bytes())
    }

    /// The `u32` seed used in the deterministic Merkle-slot derivation.
    pub fn slot_seed(&self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }
}

/// A parsed merge-mining tag payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeMiningTag {
    /// Root of the Merkle tree of committed aux-chain block hashes.
    pub merkle_root: [u8; 32],
    /// Number of leaves in that tree (a power of two).
    pub merkle_size: u32,
    /// Miner-chosen nonce that (with the chain id) fixes each aux chain's slot.
    pub nonce: u32,
}

impl MergeMiningTag {
    /// Encode the tag in the reference wire format ([`TAG_LEN`] bytes).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TAG_LEN);
        out.extend_from_slice(&MERGE_MINING_MAGIC);
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.merkle_size.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Parse a tag from `coinbase[offset..]` in the reference wire format.
    ///
    /// Validates the magic, bounds, and that `merkle_size` is a power of two.
    pub fn parse(coinbase: &[u8], offset: usize) -> Result<Self, AuxPowError> {
        let end = offset
            .checked_add(TAG_LEN)
            .ok_or(AuxPowError::TagNotFound { offset })?;
        if end > coinbase.len() {
            return Err(AuxPowError::TagTruncated {
                offset,
                need: TAG_LEN,
                have: coinbase.len().saturating_sub(offset),
            });
        }
        let bytes = &coinbase[offset..end];
        if bytes[0..4] != MERGE_MINING_MAGIC {
            return Err(AuxPowError::TagNotFound { offset });
        }
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[4..36]);
        let merkle_size = u32::from_le_bytes(bytes[36..40].try_into().expect("4 bytes"));
        let nonce = u32::from_le_bytes(bytes[40..44].try_into().expect("4 bytes"));
        if merkle_size == 0 || !merkle_size.is_power_of_two() {
            return Err(AuxPowError::MerkleSizeNotPow2(merkle_size));
        }
        Ok(MergeMiningTag {
            merkle_root,
            merkle_size,
            nonce,
        })
    }

    /// The deterministic slot an aux chain occupies in this tag's Merkle tree.
    ///
    /// Uses the canonical AuxPoW derivation (Namecoin `getExpectedIndex`): a
    /// two-round LCG over `(nonce, chain_id)`, reduced modulo the tree size.
    /// Because the slot is a pseudo-random function of the nonce and chain id,
    /// a miner cannot freely choose where a child hash lands, so one parent
    /// solution cannot be replayed for a different block of the same aux chain.
    pub fn expected_slot(&self, chain_id: &AuxChainId) -> u32 {
        let mut rand = self.nonce;
        rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        rand = rand.wrapping_add(chain_id.slot_seed());
        rand = rand.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        // merkle_size is a checked power of two, so this is a mask.
        rand % self.merkle_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag() -> MergeMiningTag {
        MergeMiningTag {
            merkle_root: [7u8; 32],
            merkle_size: 8,
            nonce: 0xDEAD_BEEF,
        }
    }

    #[test]
    fn encode_parse_round_trip() {
        let t = tag();
        let bytes = t.encode();
        assert_eq!(bytes.len(), TAG_LEN);
        assert_eq!(MergeMiningTag::parse(&bytes, 0).unwrap(), t);
    }

    #[test]
    fn parse_finds_tag_at_offset() {
        let t = tag();
        let mut buf = vec![0u8; 11];
        buf.extend_from_slice(&t.encode());
        buf.extend_from_slice(&[0u8; 5]);
        assert_eq!(MergeMiningTag::parse(&buf, 11).unwrap(), t);
    }

    #[test]
    fn wrong_magic_is_tag_not_found() {
        let mut bytes = tag().encode();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            MergeMiningTag::parse(&bytes, 0),
            Err(AuxPowError::TagNotFound { .. })
        ));
    }

    #[test]
    fn truncated_tag_is_rejected() {
        let bytes = tag().encode();
        assert!(matches!(
            MergeMiningTag::parse(&bytes[..TAG_LEN - 1], 0),
            Err(AuxPowError::TagTruncated { .. })
        ));
    }

    #[test]
    fn non_pow2_size_rejected() {
        let mut bytes = tag().encode();
        bytes[36..40].copy_from_slice(&3u32.to_le_bytes());
        assert!(matches!(
            MergeMiningTag::parse(&bytes, 0),
            Err(AuxPowError::MerkleSizeNotPow2(3))
        ));
    }

    fn cid(byte: u8) -> AuxChainId {
        AuxChainId([byte; 32])
    }

    #[test]
    fn expected_slot_is_in_range_and_deterministic() {
        let t = tag();
        let s1 = t.expected_slot(&cid(1));
        let s2 = t.expected_slot(&cid(1));
        assert_eq!(s1, s2, "deterministic");
        assert!(s1 < t.merkle_size, "within tree");
    }

    #[test]
    fn different_chain_ids_generally_differ() {
        // Not a hard guarantee for every nonce, but the derivation should
        // separate chains across a sweep of nonces.
        let (a, b) = (cid(1), cid(2));
        let mut differ = 0;
        for nonce in 0..64u32 {
            let t = MergeMiningTag {
                merkle_root: [0u8; 32],
                merkle_size: 16,
                nonce,
            };
            if t.expected_slot(&a) != t.expected_slot(&b) {
                differ += 1;
            }
        }
        assert!(differ > 32, "chain id should shift most slots; got {differ}/64");
    }

    #[test]
    fn derive_separates_networks() {
        let genesis = [9u8; 32];
        let mainnet = AuxChainId::derive(1, &genesis, b"CYNC", b"monero-main");
        let testnet = AuxChainId::derive(1, &genesis, b"tCYN", b"monero-stage");
        assert_ne!(mainnet, testnet, "networks must get distinct ids");
        // Deterministic for identical inputs.
        assert_eq!(mainnet, AuxChainId::derive(1, &genesis, b"CYNC", b"monero-main"));
    }
}
