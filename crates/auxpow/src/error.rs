//! Error type for the merge-mining commitment primitive.

use thiserror::Error;

/// Errors from parsing / verifying a merge-mining (AuxPoW) commitment.
///
/// Every variant is a *commitment-structure* failure. Parent proof-of-work
/// validation is out of scope for this crate (it is the consensus-integration
/// phase), so there is no "PoW too weak" variant here.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuxPowError {
    /// No merge-mining tag magic was found at the claimed offset.
    #[error("merge-mining tag magic not found at offset {offset}")]
    TagNotFound { offset: usize },

    /// The tag runs past the end of the coinbase bytes.
    #[error("merge-mining tag truncated: need {need} bytes at offset {offset}, have {have}")]
    TagTruncated {
        offset: usize,
        need: usize,
        have: usize,
    },

    /// `merkle_size` is not a power of two (aux Merkle trees are binary).
    #[error("merkle_size must be a power of two, got {0}")]
    MerkleSizeNotPow2(u32),

    /// A Merkle branch is longer than [`crate::merkle::MAX_BRANCH_LEN`].
    #[error("merkle branch too long: {len} exceeds max {max}")]
    BranchTooLong { len: usize, max: usize },

    /// The child block hash does not sit at the slot the tag's
    /// `(nonce, chain_id, merkle_size)` deterministically assigns it — a
    /// miner is trying to reuse one parent solution for a different child.
    #[error("child at merkle slot {actual}, expected {expected} (nonce={nonce}, size={size})")]
    WrongMerkleSlot {
        expected: u32,
        actual: u32,
        nonce: u32,
        size: u32,
    },

    /// The aux branch does not fold the child hash up to the tag's Merkle root.
    #[error("aux merkle branch does not connect the child hash to the tag root")]
    AuxBranchMismatch,

    /// The coinbase branch does not fold the coinbase up to the parent's tx root.
    #[error("coinbase merkle branch does not connect the coinbase to the parent tx root")]
    CoinbaseBranchMismatch,

    /// Borsh (de)serialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
}
