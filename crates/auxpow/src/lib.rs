//! # auxpow — direction-agnostic merge-mining commitment primitive
//!
//! Phase 1 of CoinCync's governed merge-mining
//! ([`docs/design/auxpow-governed-merge-mining.md`](../../../docs/design/auxpow-governed-merge-mining.md)).
//!
//! This crate provides the *commitment plumbing* shared by both directions of a
//! merge-mining stack — CoinCync-as-aux (under Monero) and CoinCync-as-parent
//! (over CyncHub, per CIP-002) — without baking in any specific chain:
//!
//! - [`merkle::MerkleBranch`] — generic binary Merkle inclusion proof, folded
//!   with a caller-supplied `combine` function.
//! - [`commitment::MergeMiningTag`] — the parent-coinbase tag `(merkle_root,
//!   merkle_size, nonce)` plus the deterministic aux-slot derivation.
//! - [`auxpow::AuxPow`] — the proof that a child block hash is committed in a
//!   parent block's transaction Merkle root, and [`auxpow::AuxPow::verify_commitment`].
//!
//! ## Scope boundary (important)
//!
//! This crate verifies the **commitment chain only**. It does *not*:
//!
//! - verify the parent's proof-of-work (`RandomX(seed, blob) ≤ target`), or
//! - parse a parent header / bind `parent_tx_merkle_root` to a real header, or
//! - touch any CoinCync consensus code or hash-locked file.
//!
//! Those belong to the consensus-integration phase (Phase 2). Keeping them out
//! here makes the primitive small, `#![forbid(unsafe_code)]`, RandomX-free, and
//! exhaustively testable on its own.

#![forbid(unsafe_code)]

pub mod auxpow;
pub mod commitment;
pub mod error;
pub mod merkle;

pub use auxpow::{AuxPow, Blake3Hasher, CommitmentHasher};
pub use commitment::{AuxChainId, MergeMiningTag, MERGE_MINING_MAGIC, TAG_LEN};
pub use error::AuxPowError;
pub use merkle::{build_branch, MerkleBranch, MAX_BRANCH_LEN};

/// Phase sentinel: this crate implements the Phase-1 commitment primitive only
/// (see the module docs' scope boundary). Consensus integration is a later
/// phase; downstream code that needs full AuxPoW block validation should not
/// assume it lives here yet.
pub const fn is_commitment_primitive_only() -> bool {
    true
}
