//! Coordinator-internal error type.
//!
//! All errors are recoverable from the participants' perspective —
//! an error means "this transition was rejected; the session is
//! unchanged." Participants can retry, abort, or wait.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoordinatorError>;

/// Errors a session transition can return. Each variant names a
/// specific invariant that was violated; the variant name itself
/// is the protocol contract.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorError {
    /// A transition was attempted in a state that doesn't permit it.
    /// (e.g. submitting round-2 share before round-1 commitment.)
    #[error("invalid transition '{transition}' from state '{state}'")]
    InvalidTransition { transition: String, state: String },

    /// A participant pubkey not in the session tried to act.
    /// CRITICAL: never reveal which pubkeys ARE in the session in
    /// the error — that's a metadata leak. Always say "unauthorized."
    #[error("participant unauthorized for this session")]
    UnauthorizedParticipant,

    /// The session has reached a terminal state (Aborted, Aggregated,
    /// or Expired) and cannot accept further transitions.
    #[error("session is in terminal state '{state}'")]
    SessionTerminal { state: String },

    /// Timeout: the requested transition arrived after the session's
    /// per-state deadline. The session should be transitioned to
    /// Expired; this error tells the caller they were too late.
    #[error("session deadline elapsed for state '{state}'")]
    SessionExpired { state: String },

    /// Threshold / count violation. e.g., the creator declared
    /// total=5 but tried to invite 6 participants, OR the session
    /// has fewer than `threshold` participants attached so
    /// round-1 cannot start.
    #[error("threshold violation: {what}")]
    ThresholdViolation { what: String },

    /// Duplicate transition: e.g., the same participant submitted
    /// two round-1 commitments. The first one stands; the second
    /// is rejected to keep the protocol deterministic.
    #[error("duplicate {what} from participant")]
    DuplicateAction { what: String },

    /// Internal invariant broken — should never fire in practice.
    /// If it does, it's a bug in the state machine.
    #[error("coordinator internal: {0}")]
    Internal(String),
}
