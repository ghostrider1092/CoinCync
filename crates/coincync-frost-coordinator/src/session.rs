//! Session state machine for the FROST coordinator.
//!
//! See `docs/cip/CIP-008-frost-coordinator.md` for the full
//! protocol. This file is the deterministic, in-memory state
//! machine — no I/O, no networking, no persistence.
//!
//! ## State diagram
//!
//! ```text
//!                  ┌───────────┐
//!                  │  Created  │
//!                  └─────┬─────┘
//!  creator declares total/threshold,
//!  publishes group public key
//!                        │
//!                        ▼
//!                  ┌───────────┐
//!                  │  Invited  │
//!                  └─────┬─────┘
//!  ≥ threshold participants attach
//!                        │
//!                        ▼
//!                  ┌───────────┐    each participant submits
//!                  │  Round1   │    their round-1 commitment
//!                  └─────┬─────┘
//!  threshold commitments collected
//!                        │
//!                        ▼
//!                  ┌───────────┐    each participant submits
//!                  │  Round2   │    their round-2 sig share
//!                  └─────┬─────┘
//!  threshold shares collected
//!                        │
//!                        ▼
//!                  ┌───────────┐
//!                  │ Aggregated│  TERMINAL (success)
//!                  └───────────┘
//!
//!  any non-terminal state can transition to:
//!    - Aborted   (TERMINAL, via signal_abort)
//!    - Expired   (TERMINAL, via tick after deadline)
//! ```
//!
//! ## Invariants
//!
//! 1. **Terminal states are sticky.** Once a session is
//!    `Aborted`, `Aggregated`, or `Expired`, no transition
//!    advances it. New transitions return `SessionTerminal`.
//! 2. **Threshold semantics.** Round1 advances only when
//!    EXACTLY `threshold` participants have submitted their
//!    commitment. Same for Round2 (sig shares). FROST tolerates
//!    EXTRA shares but the coordinator stops collecting after
//!    threshold to keep the protocol deterministic.
//! 3. **Participant authorization.** Only pubkeys attached
//!    during the `Invited` phase can submit round-1 / round-2
//!    actions. Unrecognized pubkeys get
//!    `UnauthorizedParticipant`.
//! 4. **No duplicate actions.** A participant can submit each
//!    action ONCE. Repeats are rejected with `DuplicateAction`
//!    rather than silently accepted (which would let a
//!    participant retract their commitment — breaking FROST's
//!    determinism guarantee).
//! 5. **Time monotonic.** Session timestamps must be
//!    non-decreasing in the per-session view. `tick()` calls
//!    must pass a `now` >= the last `now`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::error::{CoordinatorError, Result};

// ────────────────────────────────────────────────────────────────
// Timeouts
// ────────────────────────────────────────────────────────────────

/// How long a session can sit in `Invited` before timing out.
/// Generous — participants need real-world time to receive their
/// invitation token, install the wallet, and join.
pub const INVITED_TIMEOUT_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// How long Round 1 can collect commitments before timing out.
/// Tighter than `Invited` because Round 1 nonces are time-sensitive
/// — a participant cannot reuse round-1 nonces in a future session,
/// so a stale Round 1 forces participants to retry from scratch.
pub const ROUND_1_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour

/// Same logic as Round 1: tight, because Round 2 sig shares are
/// computed from Round 1 nonces and inherit their staleness window.
pub const ROUND_2_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour

/// How long a successfully-aggregated session is retained for
/// audit / replay before being archived. After this period, the
/// session can be GC'd from coordinator storage.
pub const AGGREGATED_RETENTION_SECS: u64 = 30 * 24 * 60 * 60; // 30 days

// ────────────────────────────────────────────────────────────────
// Identifiers
// ────────────────────────────────────────────────────────────────

/// 128-bit session ID. UUIDv7 in production (sortable timestamp
/// + entropy); arbitrary in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        SessionId(Uuid::now_v7())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// 32-byte ed25519 pubkey identifying a participant. This is the
/// public half of their FROST key share's verifying key.
///
/// Pubkey is the canonical identifier across the protocol — the
/// coordinator never sees signing material, only verifying material.
///
/// Serialized as a 64-char lower-hex string so JSON object keys
/// (e.g., `BTreeMap<ParticipantId, ParticipantState>` in `Session`)
/// work — JSON requires string keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantId(pub [u8; 32]);

impl Serialize for ParticipantId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex32(&self.0))
    }
}

impl<'de> Deserialize<'de> for ParticipantId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(deserializer)?;
        decode_hex32(&s)
            .map(ParticipantId)
            .map_err(D::Error::custom)
    }
}

fn encode_hex32(bytes: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    out
}

fn decode_hex32(s: &str) -> std::result::Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = decode_hex_nibble(bytes[i * 2])
            .ok_or_else(|| format!("non-hex char at offset {}", i * 2))?;
        let lo = decode_hex_nibble(bytes[i * 2 + 1])
            .ok_or_else(|| format!("non-hex char at offset {}", i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ────────────────────────────────────────────────────────────────
// Per-participant state inside a session
// ────────────────────────────────────────────────────────────────

/// What we know about a participant within a single session.
///
/// `commitment` and `sig_share` are opaque byte blobs from the
/// coordinator's perspective; the wallet validates them
/// cryptographically.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantState {
    /// Whether this participant has actually attached / connected
    /// to the session yet (post-invitation).
    pub attached: bool,
    /// Round 1 commitment bytes if submitted. None until then.
    pub commitment: Option<Vec<u8>>,
    /// Round 2 signature share bytes if submitted. None until then.
    pub sig_share: Option<Vec<u8>>,
}

impl ParticipantState {
    fn invited() -> Self {
        ParticipantState {
            attached: false,
            commitment: None,
            sig_share: None,
        }
    }
}

// ────────────────────────────────────────────────────────────────
// Session state — the core enum
// ────────────────────────────────────────────────────────────────

/// Session lifecycle. Variants are EXHAUSTIVELY matched in
/// `Session::apply` so adding a new variant later forces every
/// transition site to update — by design.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Just created. Creator has declared (threshold, total, group
    /// pubkey) but no participants are attached yet.
    Created,
    /// Creator has invited participants by emitting tokens. Some
    /// (zero or more) have attached. Cannot start Round 1 until
    /// `threshold` are attached.
    Invited,
    /// Round 1 in progress: collecting commitments. Advances to
    /// `Round2` when `threshold` commitments are in. The signing
    /// message has been declared (locks the protocol's "what is
    /// being signed").
    Round1,
    /// Round 2 in progress: collecting signature shares.
    /// Advances to `Aggregated` when `threshold` shares are in.
    Round2,
    /// Terminal — success. Aggregate signature is available for
    /// participants to read. Retained for `AGGREGATED_RETENTION_SECS`
    /// then GC-eligible.
    Aggregated,
    /// Terminal — explicit abort. Some participant signaled abort,
    /// or the creator cancelled. The session is dead; participants
    /// must start a new session if they want to try again.
    Aborted,
    /// Terminal — timeout. The session sat in a non-terminal state
    /// past its deadline. Same operational meaning as `Aborted`
    /// but distinguishable in logs.
    Expired,
}

impl SessionState {
    /// `true` if this state cannot transition to anything other
    /// than itself. Used to short-circuit `apply()` and to make
    /// the terminal-stickiness invariant testable.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionState::Aggregated | SessionState::Aborted | SessionState::Expired
        )
    }

    /// Per-state deadline relative to the time the session entered
    /// this state. Returns None for states that don't time out.
    pub fn timeout_secs(&self) -> Option<u64> {
        match self {
            SessionState::Created => Some(INVITED_TIMEOUT_SECS),
            SessionState::Invited => Some(INVITED_TIMEOUT_SECS),
            SessionState::Round1 => Some(ROUND_1_TIMEOUT_SECS),
            SessionState::Round2 => Some(ROUND_2_TIMEOUT_SECS),
            SessionState::Aggregated => None, // retention only, not "timeout"
            SessionState::Aborted | SessionState::Expired => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            SessionState::Created => "Created",
            SessionState::Invited => "Invited",
            SessionState::Round1 => "Round1",
            SessionState::Round2 => "Round2",
            SessionState::Aggregated => "Aggregated",
            SessionState::Aborted => "Aborted",
            SessionState::Expired => "Expired",
        }
    }
}

// ────────────────────────────────────────────────────────────────
// The Session struct
// ────────────────────────────────────────────────────────────────

/// Full session state. Holds everything the coordinator needs to
/// route messages between participants, plus the audit-relevant
/// metadata. Does NOT hold any cryptographic secrets; only public
/// bytes (commitments, sig shares, pubkeys) are stored here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub state: SessionState,

    // Configuration (immutable after Created):
    pub threshold: u16,
    pub total: u16,
    pub group_pubkey: [u8; 32],
    pub creator: ParticipantId,

    // The message being signed. Set when Round1 begins; once set,
    // immutable. A coordinator that lets a malicious actor change
    // the message after Round1 starts would defeat FROST's
    // signing-target-binding property.
    pub message: Option<Vec<u8>>,

    // Per-participant state. BTreeMap so iteration is deterministic
    // (important for property tests + replay).
    pub participants: BTreeMap<ParticipantId, ParticipantState>,

    // Final aggregate signature, set when state transitions to
    // Aggregated.
    pub aggregate_signature: Option<Vec<u8>>,

    // Time bookkeeping. Both unix-seconds.
    pub created_at: u64,
    pub state_entered_at: u64,
}

impl Session {
    /// Construct a fresh session in `Created` state.
    pub fn new(
        threshold: u16,
        total: u16,
        group_pubkey: [u8; 32],
        creator: ParticipantId,
        now: u64,
    ) -> Result<Self> {
        if threshold < 2 {
            return Err(CoordinatorError::ThresholdViolation {
                what: "threshold must be >= 2".into(),
            });
        }
        if total < threshold {
            return Err(CoordinatorError::ThresholdViolation {
                what: "total must be >= threshold".into(),
            });
        }
        if total > 255 {
            return Err(CoordinatorError::ThresholdViolation {
                what: "total must be <= 255 (FROST participant ID byte)".into(),
            });
        }
        Ok(Session {
            id: SessionId::new(),
            state: SessionState::Created,
            threshold,
            total,
            group_pubkey,
            creator,
            message: None,
            participants: BTreeMap::new(),
            aggregate_signature: None,
            created_at: now,
            state_entered_at: now,
        })
    }

    /// Apply a transition. Returns `Ok(())` on success and updates
    /// `self` in place. Returns `Err` (with the session UNCHANGED)
    /// on any invariant violation.
    pub fn apply(&mut self, transition: Transition, now: u64) -> Result<()> {
        // Invariant: terminal states reject everything except
        // re-checks. This is the "terminal stickiness" property.
        if self.state.is_terminal() {
            return Err(CoordinatorError::SessionTerminal {
                state: self.state.name().into(),
            });
        }

        // Invariant: deadline check before any state-advancing
        // transition. If the deadline has passed, the session
        // expires REGARDLESS of what the caller asked for.
        if let Some(timeout) = self.state.timeout_secs() {
            if now >= self.state_entered_at + timeout {
                // Capture the timing-out state's name BEFORE
                // transitioning — otherwise the error reports
                // "Expired" instead of which-state-just-expired,
                // which is what callers actually need.
                let expiring_state = self.state.name().to_string();
                self.transition_to(SessionState::Expired, now);
                return Err(CoordinatorError::SessionExpired {
                    state: expiring_state,
                });
            }
        }

        // Dispatch on the transition. We pre-clone the state name
        // for error messages; the actual mutation happens inside.
        let state_name = self.state.name();
        match transition {
            Transition::AttachParticipant { participant } => self.handle_attach(participant, now),
            Transition::DeclareMessage { message } => self.handle_declare_message(message, now),
            Transition::SubmitRound1 {
                participant,
                commitment,
            } => self.handle_round1(participant, commitment, now),
            Transition::SubmitRound2 {
                participant,
                sig_share,
            } => self.handle_round2(participant, sig_share, now),
            Transition::SubmitAggregate { signature } => self.handle_aggregate(signature, now),
            Transition::Abort { participant: _ } => {
                self.transition_to(SessionState::Aborted, now);
                Ok(())
            }
            Transition::Tick => {
                // No-op apart from the deadline check at the top
                // of `apply()`. If we got here, the session is
                // still healthy.
                let _ = state_name;
                Ok(())
            }
        }
    }

    // ────────────────────────────────────────────────────────
    // Per-transition handlers
    // ────────────────────────────────────────────────────────

    fn handle_attach(&mut self, participant: ParticipantId, now: u64) -> Result<()> {
        // Attach is allowed only in Created or Invited.
        match &self.state {
            SessionState::Created => {
                self.transition_to(SessionState::Invited, now);
            }
            SessionState::Invited => {}
            other => {
                return Err(CoordinatorError::InvalidTransition {
                    transition: "AttachParticipant".into(),
                    state: other.name().into(),
                });
            }
        }

        if self.participants.len() >= self.total as usize
            && !self.participants.contains_key(&participant)
        {
            return Err(CoordinatorError::ThresholdViolation {
                what: format!("session already has total={} participants", self.total),
            });
        }

        // Idempotent: re-attaching the same pubkey is a no-op.
        // Real-world reason: a participant whose connection drops
        // mid-round reconnects with the same pubkey; we should
        // recognize them, not reject them.
        let entry = self
            .participants
            .entry(participant)
            .or_insert_with(ParticipantState::invited);
        entry.attached = true;
        Ok(())
    }

    fn handle_declare_message(&mut self, message: Vec<u8>, now: u64) -> Result<()> {
        // Message can only be declared in Invited (transitioning
        // to Round1) and only once.
        match &self.state {
            SessionState::Invited => {}
            other => {
                return Err(CoordinatorError::InvalidTransition {
                    transition: "DeclareMessage".into(),
                    state: other.name().into(),
                });
            }
        }
        if self.message.is_some() {
            return Err(CoordinatorError::DuplicateAction {
                what: "message-declaration".into(),
            });
        }
        // Need at least `threshold` attached participants.
        let attached = self.participants.values().filter(|p| p.attached).count();
        if attached < self.threshold as usize {
            return Err(CoordinatorError::ThresholdViolation {
                what: format!(
                    "need {} attached participants to start Round1, have {}",
                    self.threshold, attached
                ),
            });
        }
        self.message = Some(message);
        self.transition_to(SessionState::Round1, now);
        Ok(())
    }

    fn handle_round1(
        &mut self,
        participant: ParticipantId,
        commitment: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        if self.state != SessionState::Round1 {
            return Err(CoordinatorError::InvalidTransition {
                transition: "SubmitRound1".into(),
                state: self.state.name().into(),
            });
        }
        let entry = self
            .participants
            .get_mut(&participant)
            .ok_or(CoordinatorError::UnauthorizedParticipant)?;
        if !entry.attached {
            return Err(CoordinatorError::UnauthorizedParticipant);
        }
        if entry.commitment.is_some() {
            return Err(CoordinatorError::DuplicateAction {
                what: "round-1 commitment".into(),
            });
        }
        entry.commitment = Some(commitment);

        // If we now have `threshold` commitments, advance to Round 2.
        let collected = self
            .participants
            .values()
            .filter(|p| p.commitment.is_some())
            .count();
        if collected >= self.threshold as usize {
            self.transition_to(SessionState::Round2, now);
        }
        Ok(())
    }

    fn handle_round2(
        &mut self,
        participant: ParticipantId,
        sig_share: Vec<u8>,
        now: u64,
    ) -> Result<()> {
        if self.state != SessionState::Round2 {
            return Err(CoordinatorError::InvalidTransition {
                transition: "SubmitRound2".into(),
                state: self.state.name().into(),
            });
        }
        let entry = self
            .participants
            .get_mut(&participant)
            .ok_or(CoordinatorError::UnauthorizedParticipant)?;
        // Round 2 share is only valid from a participant who
        // submitted Round 1.
        if entry.commitment.is_none() {
            return Err(CoordinatorError::UnauthorizedParticipant);
        }
        if entry.sig_share.is_some() {
            return Err(CoordinatorError::DuplicateAction {
                what: "round-2 share".into(),
            });
        }
        entry.sig_share = Some(sig_share);
        // The session does NOT auto-transition to Aggregated when
        // threshold shares arrive. The aggregate signature is
        // computed externally (by any participant or the coordinator
        // itself in a phase 2+ build) and submitted via
        // `Transition::SubmitAggregate`. This separation lets the
        // coordinator stay completely out of the cryptographic
        // critical path.
        let _ = now;
        Ok(())
    }

    fn handle_aggregate(&mut self, signature: Vec<u8>, now: u64) -> Result<()> {
        if self.state != SessionState::Round2 {
            return Err(CoordinatorError::InvalidTransition {
                transition: "SubmitAggregate".into(),
                state: self.state.name().into(),
            });
        }
        let collected = self
            .participants
            .values()
            .filter(|p| p.sig_share.is_some())
            .count();
        if collected < self.threshold as usize {
            return Err(CoordinatorError::ThresholdViolation {
                what: format!(
                    "need {} sig shares to aggregate, have {}",
                    self.threshold, collected
                ),
            });
        }
        self.aggregate_signature = Some(signature);
        self.transition_to(SessionState::Aggregated, now);
        Ok(())
    }

    fn transition_to(&mut self, new_state: SessionState, now: u64) {
        self.state = new_state;
        self.state_entered_at = now;
    }

    /// Number of participants who have submitted a round-1
    /// commitment. Used by the coordinator's progress reporting.
    pub fn round1_count(&self) -> usize {
        self.participants
            .values()
            .filter(|p| p.commitment.is_some())
            .count()
    }

    /// Number of participants who have submitted a round-2 share.
    pub fn round2_count(&self) -> usize {
        self.participants
            .values()
            .filter(|p| p.sig_share.is_some())
            .count()
    }
}

// ────────────────────────────────────────────────────────────────
// Transitions — the input alphabet of the state machine
// ────────────────────────────────────────────────────────────────

/// Every external action that can advance a session. The
/// coordinator's job is to receive these from participants over the
/// wire, validate signatures (phase 2+), and call `Session::apply`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transition {
    /// A participant attaches to the session (post-invitation).
    /// Idempotent: same pubkey can attach multiple times.
    AttachParticipant { participant: ParticipantId },

    /// The creator declares the message that will be signed.
    /// Locks the message and advances `Invited` -> `Round1`.
    DeclareMessage { message: Vec<u8> },

    /// A participant submits their round-1 commitment.
    SubmitRound1 {
        participant: ParticipantId,
        commitment: Vec<u8>,
    },

    /// A participant submits their round-2 signature share.
    SubmitRound2 {
        participant: ParticipantId,
        sig_share: Vec<u8>,
    },

    /// The aggregate signature is computed externally and
    /// submitted. Advances `Round2` -> `Aggregated`. NOT signed
    /// by any single participant — anyone with all the round-2
    /// shares can compute it; the signature itself is verifiable
    /// against the group_pubkey, so trust in the submitter is
    /// unnecessary.
    SubmitAggregate { signature: Vec<u8> },

    /// Any attached participant can signal an abort. Sends the
    /// session to `Aborted`.
    Abort { participant: ParticipantId },

    /// No-op except for the deadline check inside `apply`. Useful
    /// for waking up a session and forcing it to expire if its
    /// deadline has passed without any participant action.
    Tick,
}

// ────────────────────────────────────────────────────────────────
// Tests — unit + property-based
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(byte: u8) -> ParticipantId {
        ParticipantId([byte; 32])
    }

    fn fresh_session() -> Session {
        Session::new(2, 3, [1u8; 32], pid(0xAA), 1000).expect("valid session")
    }

    #[test]
    fn test_creation_validates_threshold() {
        // threshold < 2 rejected
        assert!(Session::new(1, 5, [0; 32], pid(0), 0).is_err());
        // threshold > total rejected
        assert!(Session::new(5, 3, [0; 32], pid(0), 0).is_err());
        // total > 255 rejected
        assert!(Session::new(2, 256, [0; 32], pid(0), 0).is_err());
        // valid
        assert!(Session::new(2, 3, [0; 32], pid(0), 0).is_ok());
    }

    #[test]
    fn test_happy_path_to_aggregated() {
        let mut s = fresh_session();
        let p1 = pid(0xAA);
        let p2 = pid(0xBB);

        // Attach 2 participants (threshold = 2)
        s.apply(Transition::AttachParticipant { participant: p1 }, 1001)
            .unwrap();
        s.apply(Transition::AttachParticipant { participant: p2 }, 1002)
            .unwrap();
        assert_eq!(s.state, SessionState::Invited);

        // Declare message → Round1
        s.apply(
            Transition::DeclareMessage {
                message: vec![1, 2, 3],
            },
            1003,
        )
        .unwrap();
        assert_eq!(s.state, SessionState::Round1);

        // Both submit round-1 → Round2
        s.apply(
            Transition::SubmitRound1 {
                participant: p1,
                commitment: vec![1],
            },
            1004,
        )
        .unwrap();
        s.apply(
            Transition::SubmitRound1 {
                participant: p2,
                commitment: vec![2],
            },
            1005,
        )
        .unwrap();
        assert_eq!(s.state, SessionState::Round2);

        // Both submit round-2 — state stays in Round2
        s.apply(
            Transition::SubmitRound2 {
                participant: p1,
                sig_share: vec![3],
            },
            1006,
        )
        .unwrap();
        s.apply(
            Transition::SubmitRound2 {
                participant: p2,
                sig_share: vec![4],
            },
            1007,
        )
        .unwrap();
        assert_eq!(s.state, SessionState::Round2);

        // Submit aggregate → Aggregated
        s.apply(
            Transition::SubmitAggregate {
                signature: vec![0xAA; 64],
            },
            1008,
        )
        .unwrap();
        assert_eq!(s.state, SessionState::Aggregated);
        assert_eq!(s.aggregate_signature, Some(vec![0xAA; 64]));
    }

    #[test]
    fn test_terminal_states_reject_everything() {
        let mut s = fresh_session();
        // Force into Aborted
        s.apply(
            Transition::Abort {
                participant: pid(0xAA),
            },
            1001,
        )
        .unwrap();
        assert_eq!(s.state, SessionState::Aborted);
        // Now every transition is rejected
        let result = s.apply(
            Transition::AttachParticipant {
                participant: pid(0xBB),
            },
            1002,
        );
        assert!(matches!(
            result,
            Err(CoordinatorError::SessionTerminal { .. })
        ));
        let result = s.apply(Transition::Tick, 1003);
        assert!(matches!(
            result,
            Err(CoordinatorError::SessionTerminal { .. })
        ));
    }

    #[test]
    fn test_round1_blocks_unattached_participant() {
        let mut s = fresh_session();
        let p1 = pid(0xAA);
        let p2 = pid(0xBB);
        let stranger = pid(0xCC);
        s.apply(Transition::AttachParticipant { participant: p1 }, 1001)
            .unwrap();
        s.apply(Transition::AttachParticipant { participant: p2 }, 1002)
            .unwrap();
        s.apply(Transition::DeclareMessage { message: vec![] }, 1003)
            .unwrap();
        // Stranger pubkey not in session → unauthorized
        let result = s.apply(
            Transition::SubmitRound1 {
                participant: stranger,
                commitment: vec![],
            },
            1004,
        );
        assert!(matches!(
            result,
            Err(CoordinatorError::UnauthorizedParticipant)
        ));
    }

    #[test]
    fn test_round1_blocks_double_submit() {
        let mut s = fresh_session();
        let p1 = pid(0xAA);
        let p2 = pid(0xBB);
        s.apply(Transition::AttachParticipant { participant: p1 }, 1001)
            .unwrap();
        s.apply(Transition::AttachParticipant { participant: p2 }, 1002)
            .unwrap();
        s.apply(Transition::DeclareMessage { message: vec![] }, 1003)
            .unwrap();
        s.apply(
            Transition::SubmitRound1 {
                participant: p1,
                commitment: vec![1],
            },
            1004,
        )
        .unwrap();
        // Same participant tries to resubmit
        let result = s.apply(
            Transition::SubmitRound1 {
                participant: p1,
                commitment: vec![2],
            },
            1005,
        );
        assert!(matches!(
            result,
            Err(CoordinatorError::DuplicateAction { .. })
        ));
    }

    #[test]
    fn test_declare_message_blocked_below_threshold() {
        let mut s = fresh_session();
        let p1 = pid(0xAA);
        s.apply(Transition::AttachParticipant { participant: p1 }, 1001)
            .unwrap();
        // Only 1 attached, threshold=2 → DeclareMessage fails
        let result = s.apply(Transition::DeclareMessage { message: vec![] }, 1002);
        assert!(matches!(
            result,
            Err(CoordinatorError::ThresholdViolation { .. })
        ));
    }

    #[test]
    fn test_aggregate_blocked_below_threshold_shares() {
        let mut s = fresh_session();
        let p1 = pid(0xAA);
        let p2 = pid(0xBB);
        s.apply(Transition::AttachParticipant { participant: p1 }, 1001)
            .unwrap();
        s.apply(Transition::AttachParticipant { participant: p2 }, 1002)
            .unwrap();
        s.apply(Transition::DeclareMessage { message: vec![] }, 1003)
            .unwrap();
        s.apply(
            Transition::SubmitRound1 {
                participant: p1,
                commitment: vec![1],
            },
            1004,
        )
        .unwrap();
        s.apply(
            Transition::SubmitRound1 {
                participant: p2,
                commitment: vec![2],
            },
            1005,
        )
        .unwrap();
        // Only p1 submits round 2
        s.apply(
            Transition::SubmitRound2 {
                participant: p1,
                sig_share: vec![3],
            },
            1006,
        )
        .unwrap();
        // Aggregate fails — only 1 of 2 shares
        let result = s.apply(Transition::SubmitAggregate { signature: vec![] }, 1007);
        assert!(matches!(
            result,
            Err(CoordinatorError::ThresholdViolation { .. })
        ));
    }

    #[test]
    fn test_round1_timeout() {
        let mut s = fresh_session();
        let p1 = pid(0xAA);
        let p2 = pid(0xBB);
        s.apply(Transition::AttachParticipant { participant: p1 }, 1001)
            .unwrap();
        s.apply(Transition::AttachParticipant { participant: p2 }, 1002)
            .unwrap();
        s.apply(Transition::DeclareMessage { message: vec![] }, 1003)
            .unwrap();
        // Wait past Round1 timeout (1 hour = 3600s)
        let too_late = 1003 + ROUND_1_TIMEOUT_SECS + 1;
        let result = s.apply(
            Transition::SubmitRound1 {
                participant: p1,
                commitment: vec![1],
            },
            too_late,
        );
        assert!(matches!(
            result,
            Err(CoordinatorError::SessionExpired { .. })
        ));
        assert_eq!(s.state, SessionState::Expired);
    }

    // ────────────────────────────────────────────────────────
    // Property tests — the heart of phase 1's correctness story
    // ────────────────────────────────────────────────────────

    use proptest::prelude::*;

    // PROPERTY: terminal states are sticky. Once a session reaches
    // a terminal state, no sequence of transitions can move it out.
    proptest! {
        #[test]
        fn prop_terminal_stickiness(
            participant_byte in any::<u8>(),
            commit in proptest::collection::vec(any::<u8>(), 0..32),
            msg in proptest::collection::vec(any::<u8>(), 0..32),
            sig in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut s = fresh_session();
            // Force terminal
            s.apply(Transition::Abort { participant: pid(0xAA) }, 1001).unwrap();
            let original = s.clone();
            // Try every transition; none should change the session
            let transitions = [
                Transition::AttachParticipant { participant: pid(participant_byte) },
                Transition::DeclareMessage { message: msg },
                Transition::SubmitRound1 { participant: pid(participant_byte), commitment: commit.clone() },
                Transition::SubmitRound2 { participant: pid(participant_byte), sig_share: sig.clone() },
                Transition::SubmitAggregate { signature: sig },
                Transition::Tick,
            ];
            for t in transitions {
                let _ = s.apply(t, 2000);
                // State and aggregate must be unchanged
                prop_assert_eq!(&s.state, &original.state);
                prop_assert_eq!(&s.aggregate_signature, &original.aggregate_signature);
            }
        }
    }

    // PROPERTY: round-1 count can never exceed threshold without
    // the session having transitioned to Round2. Specifically, the
    // transition fires the moment the threshold-th commitment lands,
    // not later.
    proptest! {
        #[test]
        fn prop_round1_advances_at_threshold(
            extra_commits in 0u8..5,
        ) {
            let mut s = fresh_session();
            let p1 = pid(0xAA);
            let p2 = pid(0xBB);
            let p3 = pid(0xCC);
            s.apply(Transition::AttachParticipant { participant: p1 }, 1001).unwrap();
            s.apply(Transition::AttachParticipant { participant: p2 }, 1002).unwrap();
            s.apply(Transition::AttachParticipant { participant: p3 }, 1003).unwrap();
            s.apply(Transition::DeclareMessage { message: vec![] }, 1004).unwrap();
            // p1 submits → still Round1 (threshold=2)
            s.apply(Transition::SubmitRound1 { participant: p1, commitment: vec![1] }, 1005).unwrap();
            prop_assert_eq!(s.state.clone(), SessionState::Round1);
            // p2 submits → Round2 (threshold reached)
            s.apply(Transition::SubmitRound1 { participant: p2, commitment: vec![2] }, 1006).unwrap();
            prop_assert_eq!(s.state.clone(), SessionState::Round2);
            // Even if `extra_commits` participants tried to submit
            // round-1 now, they'd fail (state is Round2).
            let _ = extra_commits;
            let result = s.apply(
                Transition::SubmitRound1 { participant: p3, commitment: vec![3] },
                1007,
            );
            let is_invalid_transition = matches!(result, Err(CoordinatorError::InvalidTransition { .. }));
            prop_assert!(is_invalid_transition);
        }
    }

    // PROPERTY: once an aggregate signature is set, it's
    // immutable. Even with further transitions (which all error
    // because Aggregated is terminal), the signature bytes don't
    // change.
    proptest! {
        #[test]
        fn prop_aggregate_signature_immutable(
            other_sig in proptest::collection::vec(any::<u8>(), 64..128),
        ) {
            let mut s = fresh_session();
            let p1 = pid(0xAA);
            let p2 = pid(0xBB);
            s.apply(Transition::AttachParticipant { participant: p1 }, 1001).unwrap();
            s.apply(Transition::AttachParticipant { participant: p2 }, 1002).unwrap();
            s.apply(Transition::DeclareMessage { message: vec![] }, 1003).unwrap();
            s.apply(Transition::SubmitRound1 { participant: p1, commitment: vec![1] }, 1004).unwrap();
            s.apply(Transition::SubmitRound1 { participant: p2, commitment: vec![2] }, 1005).unwrap();
            s.apply(Transition::SubmitRound2 { participant: p1, sig_share: vec![3] }, 1006).unwrap();
            s.apply(Transition::SubmitRound2 { participant: p2, sig_share: vec![4] }, 1007).unwrap();
            let sig = vec![0xAA; 64];
            s.apply(Transition::SubmitAggregate { signature: sig.clone() }, 1008).unwrap();
            // Try to overwrite — must fail (terminal)
            let _ = s.apply(Transition::SubmitAggregate { signature: other_sig }, 1009);
            prop_assert_eq!(s.aggregate_signature, Some(sig));
        }
    }
}
