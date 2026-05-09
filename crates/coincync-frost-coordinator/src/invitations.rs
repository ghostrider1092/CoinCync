//! Invitation-token authentication for FROST sessions (phase 2).
//!
//! Phase 1's session state machine accepts any pubkey at attach
//! time — the caller is trusted to authorize. That works for tests
//! and for the in-memory bench where there's no untrusted network,
//! but it's not the production model. In production, a session's
//! creator generates one-time invitation tokens for each invited
//! participant, communicated out-of-band (Signal, email, QR code,
//! ...). The participant presents the token at attach time; the
//! coordinator verifies the HMAC and the binding to the
//! participant's pubkey before letting them join.
//!
//! Feature-gated: this module is compiled only when the
//! `invitations` Cargo feature is enabled. Off by default so the
//! core state-machine library remains zero-crypto.
//!
//! ## Token contents
//!
//! ```text
//!   session_id:        16 bytes (UUID)
//!   participant_pubkey: 32 bytes (ed25519)
//!   expires_at:         8 bytes (unix seconds, LE)
//!   mac:                32 bytes (HMAC-SHA256 over the above,
//!                                 keyed by the session secret)
//! ```
//!
//! Total: **88 bytes**. Encodes nicely as 12 mnemonic English words
//! (88 bytes ≈ 11.7 BIP-39 words; round to 12 for human transcription)
//! or 176 hex chars / ~118 base64 chars.
//!
//! ## Threat model
//!
//! What a token CAN do:
//! - Attest "the bearer of this pubkey is allowed to join session X
//!   before time T."
//! - Be revoked by destroying / aborting the session.
//!
//! What a token CANNOT do:
//! - Authenticate the session's creator to the participant. (That's
//!   why the session secret is shared out-of-band — the participant
//!   should already know they're talking to the right creator
//!   before requesting a token.)
//! - Hide the session_id or participant_pubkey from anyone who
//!   intercepts the token. (HMAC provides integrity, not
//!   confidentiality. Pair with TLS / Noise transport for
//!   confidentiality.)
//! - Bind the participant's signing key. Tokens authenticate
//!   *who can join*; signing-key compromise is a separate
//!   problem.
//!
//! ## Constant-time verification
//!
//! HMAC comparison uses `subtle::ConstantTimeEq` to avoid leaking
//! the position of the first mismatching byte via timing. Without
//! this, an attacker could byte-by-byte forge a valid HMAC.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::session::{ParticipantId, SessionId};

type HmacSha256 = Hmac<Sha256>;

/// Length of the HMAC output (SHA-256 -> 32 bytes).
pub const MAC_LEN: usize = 32;

/// Length of the session secret used as HMAC key. 32 bytes is the
/// SHA-256 block-output size; using a shorter key is allowed by
/// HMAC but loses entropy and is rejected here for simplicity.
pub const SESSION_SECRET_LEN: usize = 32;

/// One-time invitation issued by the session creator. The bearer
/// of (the right pubkey + this token) can attach to the session.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InvitationToken {
    /// Which session this invitation is for.
    pub session_id: SessionId,
    /// Which pubkey is invited. The bearer must prove possession
    /// of the corresponding private key out-of-band before this
    /// token's HMAC accepts.
    pub participant_pubkey: ParticipantId,
    /// Unix-seconds expiry. After this, the token is rejected
    /// regardless of HMAC.
    pub expires_at: u64,
    /// HMAC-SHA256 over the canonical encoding of the above
    /// fields, keyed by the session secret.
    pub mac: [u8; MAC_LEN],
}

/// Errors emitted by `verify_token`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvitationError {
    /// Session secret has the wrong length.
    #[error("session secret must be exactly {SESSION_SECRET_LEN} bytes")]
    BadSecretLength,
    /// `now` is past the token's `expires_at`.
    #[error("invitation token expired at {expires_at}, now is {now}")]
    Expired { expires_at: u64, now: u64 },
    /// HMAC didn't match. Could mean: wrong secret, wrong session,
    /// wrong pubkey, wrong expiry, or tampered token.
    #[error("invitation token MAC did not verify")]
    BadMac,
}

/// Mint a new invitation token. The `session_secret` is a 32-byte
/// per-session key that the creator generated and never shares
/// directly — it's only used to mint and verify tokens.
pub fn mint_token(
    session_secret: &[u8],
    session_id: SessionId,
    participant_pubkey: ParticipantId,
    expires_at: u64,
) -> std::result::Result<InvitationToken, InvitationError> {
    if session_secret.len() != SESSION_SECRET_LEN {
        return Err(InvitationError::BadSecretLength);
    }
    let mac = compute_mac(session_secret, session_id, participant_pubkey, expires_at);
    Ok(InvitationToken {
        session_id,
        participant_pubkey,
        expires_at,
        mac,
    })
}

/// Verify an invitation token. Returns `Ok(())` if the token is
/// valid for the given session-secret + present time; otherwise
/// returns the specific failure mode.
pub fn verify_token(
    session_secret: &[u8],
    token: &InvitationToken,
    now: u64,
) -> std::result::Result<(), InvitationError> {
    if session_secret.len() != SESSION_SECRET_LEN {
        return Err(InvitationError::BadSecretLength);
    }
    if now > token.expires_at {
        return Err(InvitationError::Expired {
            expires_at: token.expires_at,
            now,
        });
    }
    let expected = compute_mac(
        session_secret,
        token.session_id,
        token.participant_pubkey,
        token.expires_at,
    );
    // Constant-time compare so an attacker can't byte-by-byte
    // forge a MAC by measuring response time.
    if expected.ct_eq(&token.mac).into() {
        Ok(())
    } else {
        Err(InvitationError::BadMac)
    }
}

/// Compute HMAC-SHA256 over the canonical encoding of the
/// invitation fields. Domain-separated with a constant prefix so a
/// FROST invitation MAC can never be replayed as some other HMAC
/// in the protocol.
fn compute_mac(
    session_secret: &[u8],
    session_id: SessionId,
    participant_pubkey: ParticipantId,
    expires_at: u64,
) -> [u8; MAC_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(session_secret)
        .expect("HMAC key length already validated");
    mac.update(b"CYNC.CIP-008.invite.\0");
    mac.update(uuid_bytes(&session_id.0));
    mac.update(&participant_pubkey.0);
    mac.update(&expires_at.to_le_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&bytes);
    out
}

fn uuid_bytes(uuid: &Uuid) -> &[u8; 16] {
    uuid.as_bytes()
}

// ────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{ParticipantId, SessionId};

    fn secret() -> [u8; SESSION_SECRET_LEN] {
        [0x42; SESSION_SECRET_LEN]
    }

    fn other_secret() -> [u8; SESSION_SECRET_LEN] {
        [0x99; SESSION_SECRET_LEN]
    }

    fn pid(byte: u8) -> ParticipantId {
        ParticipantId([byte; 32])
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let sid = SessionId::new();
        let p = pid(0xAA);
        let exp = 2_000_000_000;
        let token = mint_token(&secret(), sid, p, exp).unwrap();
        verify_token(&secret(), &token, 1_000_000_000).unwrap();
    }

    #[test]
    fn expired_token_rejected() {
        let sid = SessionId::new();
        let token = mint_token(&secret(), sid, pid(0xAA), 100).unwrap();
        let result = verify_token(&secret(), &token, 200);
        assert!(matches!(result, Err(InvitationError::Expired { .. })));
    }

    #[test]
    fn token_at_exact_expiry_accepted() {
        let sid = SessionId::new();
        let token = mint_token(&secret(), sid, pid(0xAA), 100).unwrap();
        // now == expires_at => still valid (the rejection rule is
        // strict greater-than)
        verify_token(&secret(), &token, 100).unwrap();
    }

    #[test]
    fn wrong_secret_rejected() {
        let sid = SessionId::new();
        let token = mint_token(&secret(), sid, pid(0xAA), 1_000_000_000).unwrap();
        let result = verify_token(&other_secret(), &token, 0);
        assert!(matches!(result, Err(InvitationError::BadMac)));
    }

    #[test]
    fn tampered_pubkey_rejected() {
        let sid = SessionId::new();
        let mut token = mint_token(&secret(), sid, pid(0xAA), 1_000_000_000).unwrap();
        token.participant_pubkey = pid(0xBB); // tamper
        let result = verify_token(&secret(), &token, 0);
        assert!(matches!(result, Err(InvitationError::BadMac)));
    }

    #[test]
    fn tampered_session_rejected() {
        let sid = SessionId::new();
        let mut token = mint_token(&secret(), sid, pid(0xAA), 1_000_000_000).unwrap();
        token.session_id = SessionId::new(); // different session
        let result = verify_token(&secret(), &token, 0);
        assert!(matches!(result, Err(InvitationError::BadMac)));
    }

    #[test]
    fn tampered_expiry_rejected() {
        let sid = SessionId::new();
        let mut token = mint_token(&secret(), sid, pid(0xAA), 1_000_000_000).unwrap();
        token.expires_at = u64::MAX; // try to extend forever
        let result = verify_token(&secret(), &token, 0);
        assert!(matches!(result, Err(InvitationError::BadMac)));
    }

    #[test]
    fn tampered_mac_rejected() {
        let sid = SessionId::new();
        let mut token = mint_token(&secret(), sid, pid(0xAA), 1_000_000_000).unwrap();
        token.mac[0] ^= 1; // flip one bit
        let result = verify_token(&secret(), &token, 0);
        assert!(matches!(result, Err(InvitationError::BadMac)));
    }

    #[test]
    fn short_secret_rejected_in_mint() {
        let result = mint_token(b"too-short", SessionId::new(), pid(0xAA), 100);
        assert!(matches!(result, Err(InvitationError::BadSecretLength)));
    }

    #[test]
    fn short_secret_rejected_in_verify() {
        let sid = SessionId::new();
        let token = mint_token(&secret(), sid, pid(0xAA), 1_000_000_000).unwrap();
        let result = verify_token(b"too-short", &token, 0);
        assert!(matches!(result, Err(InvitationError::BadSecretLength)));
    }

    #[test]
    fn distinct_secrets_produce_distinct_macs() {
        let sid = SessionId::new();
        let t1 = mint_token(&secret(), sid, pid(0xAA), 100).unwrap();
        let t2 = mint_token(&other_secret(), sid, pid(0xAA), 100).unwrap();
        assert_ne!(t1.mac, t2.mac);
    }

    #[test]
    fn distinct_pubkeys_produce_distinct_macs() {
        let sid = SessionId::new();
        let t1 = mint_token(&secret(), sid, pid(0xAA), 100).unwrap();
        let t2 = mint_token(&secret(), sid, pid(0xBB), 100).unwrap();
        assert_ne!(t1.mac, t2.mac);
    }

    #[test]
    fn distinct_expiries_produce_distinct_macs() {
        let sid = SessionId::new();
        let t1 = mint_token(&secret(), sid, pid(0xAA), 100).unwrap();
        let t2 = mint_token(&secret(), sid, pid(0xAA), 200).unwrap();
        assert_ne!(t1.mac, t2.mac);
    }

    #[test]
    fn token_is_serializable_for_qr_code_etc() {
        let sid = SessionId::new();
        let token = mint_token(&secret(), sid, pid(0xAA), 1_000_000_000).unwrap();
        let json = serde_json::to_string(&token).unwrap();
        let decoded: InvitationToken = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, token);
    }
}
