//! Typed errors for the CyncHub consensus + orderbook surfaces.
//!
//! Every operation in this crate currently returns
//! [`Error::NotImplemented`] with a `stage` field naming where the
//! eventual implementation belongs (see CIP-002 §"Implementation Plan").
//! This is the same "load-bearing skeleton" pattern used by
//! `coincync-swap` for CIP-001: callers can write error-handling code
//! today and have it remain valid when the real implementation lands.

use thiserror::Error;

/// Top-level error type for the CyncHub crate.
#[derive(Debug, Error)]
pub enum Error {
    /// Returned by every public function until the corresponding stage
    /// of CIP-002 is implemented. The `stage` field names which protocol
    /// component is still skeleton, so future work has a clear search
    /// target. Example values: `"consensus.block.validate"`,
    /// `"orderbook.match"`, `"mergemining.commitment.parse"`,
    /// `"spv.btc.verify_lock"`.
    #[error("not implemented: stage `{stage}` is still skeleton — see CIP-002")]
    NotImplemented {
        /// The CIP-002 stage that this call would belong to once the
        /// implementation is shipped.
        stage: &'static str,
    },

    /// Reserved: a transaction failed structural / consensus validation.
    /// Used by [`crate::consensus`] and [`crate::tx`].
    #[error("transaction validation failed: {0}")]
    InvalidTx(&'static str),

    /// Reserved: a block failed validation (bad header, bad PoW, bad
    /// merge-mining commitment, body-vs-header mismatch).
    #[error("block validation failed: {0}")]
    InvalidBlock(&'static str),

    /// Reserved: the orderbook state machine is in a state that does
    /// not permit the requested transition (e.g. matching an already-
    /// matched order, cancelling a settled order).
    #[error("invalid orderbook state for this operation: {0}")]
    InvalidOrderbookState(&'static str),

    /// Reserved: a peer-supplied SPV proof failed verification — either
    /// the chain header chain is wrong, the merkle path doesn't connect,
    /// or the referenced tx isn't deep enough for the protocol's
    /// confirmation requirement.
    #[error("SPV proof verification failed: {0}")]
    InvalidSpvProof(&'static str),

    /// Reserved: merge-mining commitment in a CYNC coinbase tx was
    /// malformed, in the wrong position, or referenced a CyncHub block
    /// that doesn't exist.
    #[error("merge-mining commitment invalid: {0}")]
    InvalidMergeMiningCommitment(&'static str),

    /// Reserved: I/O during chain sync / RPC / peer messaging failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
