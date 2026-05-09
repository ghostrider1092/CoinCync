//! # CoinCync FROST coordinator (CIP-008)
//!
//! Phase 1 (this commit): pure state-machine library. Defines session
//! types, transitions, and invariants. Property-tested. NO networking.
//!
//! Phase 2+ (future commits): wraps this crate in a WSS server,
//! adds invitation-token auth, persists session state to SQLite,
//! exposes the coordinator as a deployable bin.
//!
//! ## What this is for
//!
//! CoinCync's wallet has FROST primitives (`coincync::wallet::multisig`)
//! that let M of N participants jointly sign a transaction. The
//! primitives are the math; they don't solve the message-relay
//! problem. Without a coordinator, participants exchange round-1
//! commitments and round-2 signature shares by manual copy-paste,
//! which is unusable in practice — most M-of-N wallets in the wild
//! get set up and never used.
//!
//! This crate is the message-relay layer. It is **untrusted**: a
//! coordinator that goes offline, misbehaves, or shows different
//! views to different participants cannot forge signatures or steal
//! funds. The worst outcome is "session fails to complete." See
//! `docs/cip/CIP-008-frost-coordinator.md` for the full trust model.
//!
//! ## What's in phase 1
//!
//! - `Session` struct + `SessionState` enum
//! - `Transition` enum and `apply()` function — pure, deterministic
//! - State invariants enforced at the type level where possible
//!   (terminal states cannot transition out)
//! - Error type for impossible / out-of-order / unauthorized
//!   transitions
//! - Property tests via `proptest` covering:
//!     - terminal-state immutability (Aborted/Aggregated/Expired
//!       reject all transitions)
//!     - threshold semantics (Round1 only advances when M
//!       commitments arrive)
//!     - participant authorization (a non-attached pubkey cannot
//!       advance state)
//!     - timeout semantics (expiry trumps any other transition)
//!
//! ## What's NOT in phase 1
//!
//! - Networking. No WSS, no HTTP, no socket code.
//! - Persistence. Sessions live in memory only.
//! - Authentication. Invitation tokens are deferred.
//! - The cryptographic verification of commitments / sig shares
//!   themselves. The coordinator just relays bytes; the wallet's
//!   FROST primitives are the truth-of-record.
//!
//! That stuff arrives in phase 2-6 per the CIP.

pub mod error;
pub mod session;

#[cfg(feature = "invitations")]
pub mod invitations;

#[cfg(feature = "persistence")]
pub mod persistence;

pub use error::{CoordinatorError, Result};
pub use session::{
    ParticipantId, ParticipantState, Session, SessionId, SessionState, Transition,
    AGGREGATED_RETENTION_SECS, INVITED_TIMEOUT_SECS, ROUND_1_TIMEOUT_SECS, ROUND_2_TIMEOUT_SECS,
};

#[cfg(feature = "invitations")]
pub use invitations::{
    mint_token, verify_token, InvitationError, InvitationToken, MAC_LEN, SESSION_SECRET_LEN,
};

#[cfg(feature = "persistence")]
pub use persistence::{PersistError, SessionStore, PERSISTENCE_VERSION};
