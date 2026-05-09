//! Crate-level error type.
//!
//! All errors here describe REJECTED ATTESTATIONS or QUERY-LEVEL
//! violations. The state of the `FinalityTracker` itself is never
//! corrupted by an error — a returned `Err` means "this attestation
//! was not accepted; the tracker is unchanged." The consensus layer
//! treats accepted-vs-rejected as a binary signal; the variant is
//! informational, mostly for logs and audit.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, FinalityError>;

/// Errors a finality-tracker operation can return.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FinalityError {
    /// The attestation's signature failed cryptographic verification.
    /// The verifier (`AttestationVerifier::verify`) returned false.
    /// Phase 1 uses a stub verifier; phase 2+ uses real ed25519.
    #[error("attestation signature is not valid")]
    InvalidSignature,

    /// The miner's pubkey is not in the active miner set. Could mean:
    ///
    /// - the miner has been inactive for >WINDOW blocks
    /// - the miner has never produced a block (so was never seen)
    ///
    /// In either case, their attestation does NOT count toward the
    /// 2/3 threshold.
    #[error("miner not in active set at height {height}")]
    MinerNotActive { height: u64 },

    /// The attestation's `target_height` is too far in the past
    /// (outside the per-attestation acceptance window). Prevents
    /// late-flooding of attestations for ancient heights to disrupt
    /// pruning.
    #[error("attestation target_height {target_height} is too old (earliest accepted: {earliest_accepted})")]
    StaleTarget {
        target_height: u64,
        earliest_accepted: u64,
    },

    /// The attestation's `target_height` is in the future (ahead of
    /// the current chain tip the tracker knows about). Possibly
    /// well-formed but useless — we don't store attestations for
    /// future heights because we have no canonical hash to compare
    /// against.
    #[error("attestation target_height {target_height} is ahead of tracker tip {tracker_tip}")]
    FutureTarget {
        target_height: u64,
        tracker_tip: u64,
    },

    /// This (miner, target_height, target_hash) triple was already
    /// recorded. Idempotent: the previous record stands; the
    /// duplicate is rejected without changing state.
    ///
    /// Note: a miner CAN sign two DIFFERENT hashes at the same height
    /// (e.g., during a fork the miner sees both sides). That's NOT a
    /// duplicate; both records are kept. The 2/3 threshold operates
    /// per (height, hash), so a miner who signs both sides of a fork
    /// contributes one vote to each side, never doubles their weight.
    #[error("duplicate attestation from miner at height {target_height}")]
    DuplicateAttestation { target_height: u64 },

    /// Internal invariant broken — should not fire in practice. If it
    /// does, it's a state-machine bug.
    #[error("rolling-finality internal: {0}")]
    Internal(String),
}
