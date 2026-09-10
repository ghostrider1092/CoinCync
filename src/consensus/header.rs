//! # Block Header for CoinCync 1.0
//!
//! Simpler than 2.0: `anchor_stamp` and `stamps` were removed in the 1.0
//! trim. The stamping / anchor machinery is covered by IronConsensus on
//! the chain-convergence side and is no longer a header-level consensus
//! input.

use crate::primitives::{hash_concat, Hash, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    /// Network magic bytes — FIRST field, checked before any crypto validation.
    pub network_magic: [u8; 4],
    pub version: u8,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: Hash,
    pub tx_root: Hash,
    pub anchor: Hash,
    pub algorithm: u8,
    pub nonce: u64,
    pub target: Hash,
    pub miner_pubkey: PublicKey,
    /// RESERVED / NOT YET ENFORCED (audit 2026-09-07). `calculate_supply_commitment`
    /// exists but no consensus rule compares this field to it, and every producer
    /// currently sets it to `[0u8; 32]`. Do NOT rely on it as an integrity control
    /// until it is both enforced in validation AND bound by PoW (see the §1 PoW
    /// header-binding change in `docs/SECURITY-REVIEW-2026-09-07.md`).
    pub supply_commitment: [u8; 32],
    pub checkpoint_vote: Option<(u64, Hash)>,

    /// Lelantus Spark accumulator root (Phase 2).
    /// Zero until the Lelantus Spark fork activates. Included in the header
    /// hash so every block commits to the current Spark set.
    pub spark_set_root: [u8; 32],

    /// MimbleWimble kernel-set root (Phase 2).
    /// Zero until the MW cut-through fork activates. Included in the header
    /// hash so every block commits to the current kernel set.
    pub mw_kernel_root: [u8; 32],
}

/// Domain-separation tag for the block header hash preimage. Prefixed to
/// every byte sequence fed into `hash_concat` for header hashing so this
/// hash can never collide with any other preimage in the protocol
/// (tx signing, pow anchor, CLSAG Fiat-Shamir, bulletproof transcript,
/// balance proof).
pub(crate) const HEADER_HASH_DOMAIN_TAG: &[u8] = b"coincync/header/v1";

/// Domain-separation tag for the PoW header-binding digest (see
/// [`BlockHeader::pow_binding`]).
pub(crate) const POW_BINDING_DOMAIN_TAG: &[u8] = b"coincync/pow-binding/v1";

impl BlockHeader {
    /// Compute block header hash.
    ///
    /// SECURITY: All fields are included to prevent block malleability where a
    /// miner could modify omitted fields after finding a valid PoW hash. The
    /// preimage is domain-separated with [`HEADER_HASH_DOMAIN_TAG`] so it can
    /// never collide with any other hash in the protocol.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::with_capacity(HEADER_HASH_DOMAIN_TAG.len() + 256);
        // Domain separator — must be first.
        data.extend_from_slice(HEADER_HASH_DOMAIN_TAG);
        // Network magic is hashed next — binds every block to its network.
        data.extend_from_slice(&self.network_magic);
        data.push(self.version);
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(self.prev_hash.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(self.anchor.as_bytes());
        data.push(self.algorithm);
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(self.target.as_bytes());
        data.extend_from_slice(self.miner_pubkey.as_bytes());
        data.extend_from_slice(&self.supply_commitment);
        // Serialize checkpoint_vote deterministically (Some/None distinct).
        match &self.checkpoint_vote {
            Some((height, hash)) => {
                data.push(1);
                data.extend_from_slice(&height.to_le_bytes());
                data.extend_from_slice(hash.as_bytes());
            }
            None => {
                data.push(0);
            }
        }
        // Phase 2 roots (Lelantus Spark + MimbleWimble). Hashed unconditionally
        // — zero bytes pre-activation, real roots after the forks activate.
        data.extend_from_slice(&self.spark_set_root);
        data.extend_from_slice(&self.mw_kernel_root);
        hash_concat(&[&data])
    }

    /// Digest of the header fields that are otherwise **not** committed to by the
    /// proof of work, so they can be folded into the anchor seed and thereby
    /// bound to the PoW (audit §1, 2026-09-07). Without this, a single PoW
    /// solution could be reused with these fields mutated (block-hash
    /// malleability + tie-break grinding).
    ///
    /// Excluded because they are already bound elsewhere: `prev_hash`, `height`,
    /// `timestamp` (anchor seed); `nonce`, `tx_root` (`compute_pow_hash` input);
    /// `target`, `algorithm` (checked directly in `verify_pow`); `network_magic`
    /// (checked before any PoW work). `anchor` itself is excluded to avoid
    /// circularity (the anchor is derived FROM this binding).
    pub fn pow_binding(&self) -> Hash {
        let mut data = Vec::with_capacity(POW_BINDING_DOMAIN_TAG.len() + 160);
        data.extend_from_slice(POW_BINDING_DOMAIN_TAG);
        data.push(self.version);
        data.extend_from_slice(self.miner_pubkey.as_bytes());
        data.extend_from_slice(&self.supply_commitment);
        match &self.checkpoint_vote {
            Some((height, hash)) => {
                data.push(1);
                data.extend_from_slice(&height.to_le_bytes());
                data.extend_from_slice(hash.as_bytes());
            }
            None => data.push(0),
        }
        data.extend_from_slice(&self.spark_set_root);
        data.extend_from_slice(&self.mw_kernel_root);
        hash_concat(&[&data])
    }

    pub fn meets_target(&self, pow_hash: &Hash) -> bool {
        pow_hash.meets_difficulty(&self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PublicKey;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            network_magic: [1, 2, 3, 4],
            version: 1,
            height: 42,
            timestamp: 1_700_000_000,
            prev_hash: Hash::from_bytes([7u8; 32]),
            tx_root: Hash::from_bytes([8u8; 32]),
            anchor: Hash::from_bytes([9u8; 32]),
            algorithm: 0,
            nonce: 123,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: PublicKey::from_bytes([5u8; 32]),
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        }
    }

    /// audit §1: the PoW header-binding must cover EVERY field that isn't already
    /// bound by the anchor seed / `compute_pow_hash` / direct checks — otherwise
    /// that field is malleable while keeping a valid PoW. And it must NOT cover
    /// the fields bound elsewhere (double-binding / anchor circularity).
    #[test]
    fn pow_binding_covers_exactly_the_otherwise_unbound_fields() {
        let base = sample_header();
        let b0 = base.pow_binding();

        // Each currently-unbound field MUST change the binding.
        let mut h = base.clone();
        h.version ^= 1;
        assert_ne!(b0, h.pow_binding(), "version must be bound");
        let mut h = base.clone();
        h.miner_pubkey = PublicKey::from_bytes([6u8; 32]);
        assert_ne!(b0, h.pow_binding(), "miner_pubkey must be bound");
        let mut h = base.clone();
        h.supply_commitment = [1u8; 32];
        assert_ne!(b0, h.pow_binding(), "supply_commitment must be bound");
        let mut h = base.clone();
        h.checkpoint_vote = Some((1, Hash::from_bytes([2u8; 32])));
        assert_ne!(b0, h.pow_binding(), "checkpoint_vote must be bound");
        let mut h = base.clone();
        h.spark_set_root = [3u8; 32];
        assert_ne!(b0, h.pow_binding(), "spark_set_root must be bound");
        let mut h = base.clone();
        h.mw_kernel_root = [4u8; 32];
        assert_ne!(b0, h.pow_binding(), "mw_kernel_root must be bound");

        // Fields bound elsewhere MUST NOT change the binding.
        let mut h = base.clone();
        h.nonce = 999;
        assert_eq!(b0, h.pow_binding(), "nonce is bound via compute_pow_hash");
        let mut h = base.clone();
        h.tx_root = Hash::from_bytes([0xCD; 32]);
        assert_eq!(b0, h.pow_binding(), "tx_root is bound via compute_pow_hash");
        let mut h = base.clone();
        h.anchor = Hash::from_bytes([0xAB; 32]);
        assert_eq!(b0, h.pow_binding(), "anchor is DERIVED from the binding");
        let mut h = base.clone();
        h.target = Hash::from_bytes([0x01; 32]);
        assert_eq!(b0, h.pow_binding(), "target is checked directly in verify_pow");
    }
}
