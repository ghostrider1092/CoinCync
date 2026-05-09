//! # CoinCync rolling soft-finality (CIP-009.D)
//!
//! Phase 1 (this commit): pure state-machine library. Defines the
//! active miner set, attestation accumulation logic, and the
//! soft-finality tip-watermark rule. Property-tested. NO networking
//! and NO real cryptography — the verification surface is a trait
//! (`AttestationVerifier`), so the consensus layer plugs in real
//! ed25519 verification at integration time.
//!
//! Phase 2+ (future commits): wires this crate into `validate_block`
//! as a layered defense on top of Path B (CONSENSUS_CHECKPOINTS).
//! Real ed25519 via `ed25519-dalek`. Coinbase wire-format codec.
//! Activation behind a CIP-007 Mode A height gate after a 6-month
//! testnet rehearsal window.
//!
//! ## What this is for
//!
//! CoinCync's reorg defense currently has Path B (project-cut
//! checkpoints, shipped at commit 45e621d) and the proposed Path D
//! (this — miner-signed rolling checkpoints, queued for post-launch).
//! Together they cover the cold horizon (B, days-old) and the live
//! tip (D, ~100 blocks behind tip once quorum is met).
//!
//! See `docs/cip/CIP-009-D-miner-signed-rolling-checkpoints.md` for
//! the full protocol specification.
//!
//! ## What's in phase 1
//!
//! - `FinalityAttestation` struct: the per-block payload a miner
//!   includes in coinbase, post-activation
//! - `ActiveMinerSet`: rolling window of miners with at least one
//!   block in the last `WINDOW` blocks
//! - `FinalityTracker`: the main state machine. Accumulates
//!   attestations, computes the soft-final tip, exposes a
//!   `would_reorg_violate_finality()` query for the validator
//! - `AttestationVerifier` trait: the cryptographic verification
//!   surface. The state machine never calls real `ed25519_verify`;
//!   it calls this trait. Phase 2 wires the real verifier in.
//! - Error type for invalid / duplicate / unauthorized attestations
//! - Property tests covering:
//!     - monotonic soft-final tip (never decreases)
//!     - threshold semantics (fires at exactly ceil(2/3 * |active|))
//!     - quorum gate (no finalization below MIN_QUORUM miners)
//!     - window expiry (miners outside the window don't vote)
//!     - dual-fork attestation (signing both sides of a fork doesn't
//!       help an attacker — each side still needs 2/3 distinct)
//!
//! ## What's NOT in phase 1
//!
//! - Networking. No P2P codec, no fetch-by-height.
//! - Persistence. The tracker lives in memory only; the consensus
//!   layer is responsible for replaying attestations from chain
//!   state on startup.
//! - Real cryptographic verification. The `AttestationVerifier`
//!   trait is the seam.
//! - Coinbase wire-format. The on-chain serialization for
//!   attestations is consensus-critical and ships in a separate
//!   commit alongside the activation height.
//! - Key rotation. The CIP specifies it; phase 1 carries the type
//!   shape but no rotation-message handler. Reason: rotation
//!   touches the `ActiveMinerSet`'s identity-mapping in subtle
//!   ways and deserves its own focused commit + test pass.
//!
//! That stuff arrives in phase 2-N per the CIP.

pub mod active_set;
pub mod error;
pub mod finality;
pub mod types;

#[cfg(feature = "ed25519")]
pub mod verifier_ed25519;

#[cfg(feature = "wire-codec")]
pub mod codec;

pub use active_set::{ActiveMinerSet, MinerRecord};
pub use error::{FinalityError, Result};
pub use finality::{
    ApplyOutcome, FinalityStats, FinalityTracker, DEFAULT_LAG, DEFAULT_MIN_QUORUM, DEFAULT_WINDOW,
};
pub use types::{
    AttestationVerifier, BlockHash, FinalityAttestation, MinerPubkey, NoopVerifier,
    RecordedAttestation,
};

#[cfg(feature = "ed25519")]
pub use verifier_ed25519::{Ed25519Verifier, Ed25519VerifyError};

#[cfg(feature = "wire-codec")]
pub use codec::{decode, encode, WireAttestation, WireError, WIRE_MAGIC, WIRE_VERSION};
