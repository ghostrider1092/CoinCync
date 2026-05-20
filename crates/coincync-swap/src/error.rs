//! Typed errors for the atomic-swap state machine.
//!
//! Every operation in this crate currently returns [`Error::NotImplemented`]
//! with a `stage` field naming where the eventual implementation belongs.
//! This is a deliberate "load-bearing skeleton" pattern: callers can write
//! handle-the-error code today and have it be valid against the eventual
//! shipped surface. When real implementations land, the variants here
//! grow but `NotImplemented` never returns from a code path that's been
//! filled in.

use thiserror::Error;

/// Top-level error type for the swap crate.
#[derive(Debug, Error)]
pub enum Error {
    /// Returned by every public function until the corresponding stage
    /// of CIP-001 is implemented. The `stage` field names which protocol
    /// step is still skeleton, so future work has a clear search target.
    #[error("not implemented: stage `{stage}` is still skeleton — see CIP-001")]
    NotImplemented {
        /// The CIP-001 stage that this call would belong to once the
        /// protocol is shipped (e.g. "alice.lock", "bob.refund",
        /// "coordinator.handshake").
        stage: &'static str,
    },

    /// Reserved: the swap state machine is in a state that does not
    /// permit the requested transition.
    #[error("invalid swap state for this operation: {0}")]
    InvalidState(&'static str),

    /// Reserved: a peer message failed cryptographic verification.
    #[error("peer message verification failed: {0}")]
    Verification(&'static str),

    /// Reserved: a timeout elapsed before the counterparty acted.
    /// The state machine moves to the refund path.
    #[error("counterparty timed out at stage `{stage}`")]
    Timeout {
        /// Which stage's timeout fired.
        stage: &'static str,
    },

    /// Reserved: I/O during peer-to-peer coordination failed.
    #[error("I/O error during swap: {0}")]
    Io(#[from] std::io::Error),

    /// RPC-layer failure with a dynamic context message. Used by
    /// the BTC / CYNC chain interactors when the underlying HTTP
    /// transport or the remote node returns an error — the message
    /// is propagated verbatim for debugging.
    #[error("RPC error: {0}")]
    Rpc(String),
}

impl Error {
    /// Convenience constructor for the common case.
    pub const fn not_implemented(stage: &'static str) -> Self {
        Self::NotImplemented { stage }
    }
}
