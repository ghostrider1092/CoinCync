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

    pub fn meets_target(&self, pow_hash: &Hash) -> bool {
        pow_hash.meets_difficulty(&self.target)
    }
}
