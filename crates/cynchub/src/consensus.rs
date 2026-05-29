//! CyncHub chain consensus: block, header, PoW validation, difficulty.
//!
//! ## Status: SKELETON
//!
//! Public types are declared; every fn returns
//! [`Error::NotImplemented`][crate::Error::NotImplemented] until
//! implementation lands. See CIP-002 §"Mechanism — Merge-Mining" and
//! §"Mechanism — Transaction Types" for the design.
//!
//! ## Design summary (CIP-002 §"V1 Scope" + §"Mechanism — Merge-Mining")
//!
//! - **Block time:** 60 seconds (matches CYNC; simplest possible
//!   merge-mining: ≤ 1 CyncHub block per CYNC block).
//! - **PoW:** RandomX, inherited from CYNC via merge-mining. No new
//!   mining algorithm.
//! - **Difficulty retarget:** every 144 blocks (~2.4 hours).
//! - **Merge-mining commitment:** Namecoin-style 4-byte magic
//!   `0x43484342` ("CHCB") + 32-byte CyncHub block hash, embedded in
//!   CYNC coinbase. PoW satisfaction comes from the CYNC block header
//!   (which already meets CYNC's harder difficulty target).
//! - **Block body:** max 100 KB (~500 orders/block).

use serde::{Deserialize, Serialize};

use crate::Error;

/// CyncHub block header.
///
/// Layout matches CIP-002 §"Block structure":
/// - `prev_hash`: previous CyncHub block hash (32 bytes)
/// - `merkle_root`: Merkle root of the body's tx list
/// - `timestamp`: Unix seconds (validated against CYNC parent block's time)
/// - `height`: monotonic CyncHub height
/// - `cync_block_hash`: hash of the CYNC block containing the merge-mining commitment
/// - `merkle_path_to_coinbase_commitment`: proof that this CyncHub block
///   hash appears in `cync_block_hash`'s coinbase
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// 32-byte hash of the parent CyncHub block.
    pub prev_hash: [u8; 32],
    /// 32-byte Merkle root of this block's transaction list.
    pub merkle_root: [u8; 32],
    /// Unix-seconds timestamp. MUST be ≥ parent timestamp and ≤ parent
    /// CYNC block timestamp + a tolerance (TBD in implementation).
    pub timestamp: u64,
    /// Monotonic height of this CyncHub block.
    pub height: u64,
    /// 32-byte hash of the CYNC block whose coinbase commits to this
    /// CyncHub block. The PoW satisfying CYNC's target is the PoW
    /// satisfying CyncHub's (lower) target.
    pub cync_block_hash: [u8; 32],
    /// Merkle inclusion proof for the CHCB-magic commitment within
    /// `cync_block_hash`'s transaction Merkle tree. Length is
    /// `ceil(log2(cync_tx_count))` 32-byte hashes plus a u32 path index.
    pub merkle_path_to_coinbase_commitment: Vec<u8>,
}

/// CyncHub block: header + body (the list of transactions).
///
/// The body is opaque at this skeleton stage — once [`crate::tx`] is
/// implemented, this field becomes `Vec<crate::tx::Transaction>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// Transaction list (placeholder until [`crate::tx::Transaction`] lands).
    pub body: Vec<Vec<u8>>,
}

/// Validate a block against its parent and the corresponding CYNC parent
/// block. This is the load-bearing fn for consensus correctness.
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn validate_block(_block: &Block, _parent: &BlockHeader) -> Result<(), Error> {
    Err(Error::NotImplemented {
        stage: "consensus.validate_block",
    })
}

/// Recompute the PoW-target for the block at `height`, based on the
/// difficulty-retarget rule (every 144 blocks).
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn target_for_height(_height: u64) -> Result<[u8; 32], Error> {
    Err(Error::NotImplemented {
        stage: "consensus.target_for_height",
    })
}

/// Verify a block satisfies its PoW target — which, for CyncHub, means
/// the CYNC parent block's header meets CYNC's target AND the CYNC
/// coinbase commits to this CyncHub block.
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn verify_pow(_block: &Block) -> Result<(), Error> {
    Err(Error::NotImplemented {
        stage: "consensus.verify_pow",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_header_round_trips_serde() {
        let header = BlockHeader {
            prev_hash: [1u8; 32],
            merkle_root: [2u8; 32],
            timestamp: 1_700_000_000,
            height: 42,
            cync_block_hash: [3u8; 32],
            merkle_path_to_coinbase_commitment: vec![0u8; 64],
        };
        let json = serde_json::to_vec(&header).expect("serialize");
        let back: BlockHeader = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(header.height, back.height);
        assert_eq!(header.prev_hash, back.prev_hash);
    }

    #[test]
    fn validate_block_is_unimplemented_in_skeleton() {
        let header = BlockHeader {
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0,
            height: 1,
            cync_block_hash: [0u8; 32],
            merkle_path_to_coinbase_commitment: Vec::new(),
        };
        let block = Block { header: header.clone(), body: Vec::new() };
        let err = validate_block(&block, &header).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { stage: "consensus.validate_block" }));
    }
}
