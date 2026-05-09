//! Phase 5 integration tests — full FROST coordinator flow.
//!
//! Exercises the entire stack (state machine + invitations +
//! persistence) through a realistic 2-of-3 signing-session flow,
//! plus adversarial cases. Phase 5 is in-process — no WSS server
//! is involved. Phase 6 will refactor the server bin into a
//! library function and add wire-level integration tests.
//!
//! Why in-process for phase 5: the WSS layer is a bytes-on-the-
//! wire wrapper around the same library types these tests use
//! directly. Verifying the library types compose correctly is
//! the foundation; the WSS layer can only break things on top of
//! that, so testing it next is the right order.
//!
//! ## Crypto note
//!
//! The coordinator's contract is that it RELAYS opaque bytes
//! between participants without verifying them — the cryptographic
//! verification is the wallet's responsibility. These tests use
//! placeholder bytes (e.g., `vec![0xAA; 64]`) for commitments,
//! sig shares, and aggregate signatures; they would behave
//! identically with real `frost_ed25519` byte payloads.

use coincync_frost_coordinator::{
    invitations::{mint_token, verify_token},
    session::{ParticipantId, Session, SessionState, Transition},
    SessionStore,
};
use tempfile::tempdir;

const SESSION_SECRET: [u8; 32] = [0x42; 32];

fn pid(byte: u8) -> ParticipantId {
    ParticipantId([byte; 32])
}

fn make_session(threshold: u16, total: u16, now: u64) -> Session {
    Session::new(threshold, total, [0xCC; 32], pid(0xAA), now)
        .expect("session params valid for tests")
}

// ────────────────────────────────────────────────────────────────
// Happy path: full 2-of-3 signing flow through every layer
// ────────────────────────────────────────────────────────────────

/// PROPERTY: a complete 2-of-3 signing session walks through
/// Created → Invited → Round1 → Round2 → Aggregated, with
/// invitations gating attach and persistence preserving every
/// transition.
#[test]
fn full_2_of_3_signing_flow() {
    let dir = tempdir().unwrap();
    let store = SessionStore::new(dir.path().join("sessions.json"));

    // ─── Setup: operator creates a session ──────────────────
    let now = 1000;
    let session = make_session(2, 3, now);
    let session_id = session.id;

    store.save(&[session]).unwrap();
    assert_eq!(store.load().unwrap().len(), 1);

    // ─── Setup: operator mints 3 invitation tokens ───────────
    let alice = pid(0xA1);
    let bob = pid(0xB2);
    let carol = pid(0xC3);
    let expires_at = now + 7 * 24 * 60 * 60; // 7 days

    let token_alice = mint_token(&SESSION_SECRET, session_id, alice, expires_at).unwrap();
    let token_bob = mint_token(&SESSION_SECRET, session_id, bob, expires_at).unwrap();
    let token_carol = mint_token(&SESSION_SECRET, session_id, carol, expires_at).unwrap();

    // ─── Phase 1: each participant verifies their token + attaches ───
    for (token, pubkey) in [
        (&token_alice, alice),
        (&token_bob, bob),
        (&token_carol, carol),
    ] {
        // Server-side: verify the token before applying the transition
        verify_token(&SESSION_SECRET, token, now + 10).unwrap();

        // Apply attach
        let mut sessions = store.load().unwrap();
        let s = sessions.iter_mut().find(|s| s.id == session_id).unwrap();
        s.apply(
            Transition::AttachParticipant { participant: pubkey },
            now + 20,
        )
        .unwrap();
        store.save(&sessions).unwrap();
    }

    // After all 3 attach: state is Invited (advanced from Created
    // on the first attach), and 3 participants are registered.
    let sessions = store.load().unwrap();
    let s = sessions.iter().find(|s| s.id == session_id).unwrap();
    assert_eq!(s.state, SessionState::Invited);
    assert_eq!(s.participants.len(), 3);

    // ─── Phase 2: creator declares the message → advances to Round1 ───
    let message_to_sign = b"transfer 1.5 CYNC to <stealth-addr>".to_vec();
    {
        let mut sessions = store.load().unwrap();
        let s = sessions.iter_mut().find(|s| s.id == session_id).unwrap();
        s.apply(
            Transition::DeclareMessage {
                message: message_to_sign.clone(),
            },
            now + 100,
        )
        .unwrap();
        store.save(&sessions).unwrap();
    }
    let sessions = store.load().unwrap();
    let s = sessions.iter().find(|s| s.id == session_id).unwrap();
    assert_eq!(s.state, SessionState::Round1);
    assert_eq!(s.message, Some(message_to_sign));

    // ─── Phase 3: 2 of 3 submit Round 1 commitments → advances to Round2 ───
    // Carol stays absent in this scenario (2-of-3 threshold met
    // by alice + bob).
    {
        let mut sessions = store.load().unwrap();
        let s = sessions.iter_mut().find(|s| s.id == session_id).unwrap();
        s.apply(
            Transition::SubmitRound1 {
                participant: alice,
                commitment: vec![0xA1; 32],
            },
            now + 200,
        )
        .unwrap();
        // After 1 commitment: still in Round1 (need 2 for threshold)
        assert_eq!(s.state, SessionState::Round1);
        s.apply(
            Transition::SubmitRound1 {
                participant: bob,
                commitment: vec![0xB2; 32],
            },
            now + 210,
        )
        .unwrap();
        // After 2 commitments: advanced to Round2
        assert_eq!(s.state, SessionState::Round2);
        store.save(&sessions).unwrap();
    }

    // ─── Phase 4: 2 of 3 submit Round 2 sig shares → stays Round2 ───
    // Round 2 doesn't auto-advance per CIP-008 (the aggregate is
    // computed externally and submitted separately).
    {
        let mut sessions = store.load().unwrap();
        let s = sessions.iter_mut().find(|s| s.id == session_id).unwrap();
        s.apply(
            Transition::SubmitRound2 {
                participant: alice,
                sig_share: vec![0xA1; 32],
            },
            now + 300,
        )
        .unwrap();
        s.apply(
            Transition::SubmitRound2 {
                participant: bob,
                sig_share: vec![0xB2; 32],
            },
            now + 310,
        )
        .unwrap();
        // Still in Round2 — state advances on SubmitAggregate
        assert_eq!(s.state, SessionState::Round2);
        store.save(&sessions).unwrap();
    }

    // ─── Phase 5: external aggregator submits the signature ───
    let aggregate_signature = vec![0xFF; 64];
    {
        let mut sessions = store.load().unwrap();
        let s = sessions.iter_mut().find(|s| s.id == session_id).unwrap();
        s.apply(
            Transition::SubmitAggregate {
                signature: aggregate_signature.clone(),
            },
            now + 400,
        )
        .unwrap();
        store.save(&sessions).unwrap();
    }

    // ─── Verify final state ───
    let sessions = store.load().unwrap();
    let s = sessions.iter().find(|s| s.id == session_id).unwrap();
    assert_eq!(s.state, SessionState::Aggregated);
    assert_eq!(s.aggregate_signature, Some(aggregate_signature));

    // Persistence sanity: terminal state survives reload.
    drop(sessions);
    let reloaded = store.load().unwrap();
    let s = reloaded.iter().find(|s| s.id == session_id).unwrap();
    assert_eq!(s.state, SessionState::Aggregated);
}

// ────────────────────────────────────────────────────────────────
// Adversarial cases
// ────────────────────────────────────────────────────────────────

/// PROPERTY: a token from a different session is rejected.
#[test]
fn cross_session_token_rejected() {
    let session_a = make_session(2, 3, 1000);
    let session_b = make_session(2, 3, 1000);
    assert_ne!(session_a.id, session_b.id);

    let token_for_a = mint_token(&SESSION_SECRET, session_a.id, pid(0xAA), 9999).unwrap();
    // Try to verify this token AGAINST session_b's HMAC context
    // by tampering session_id. The MAC won't match because the
    // MAC was computed over session_a.id, not session_b.id.
    let mut tampered = token_for_a.clone();
    tampered.session_id = session_b.id;
    let result = verify_token(&SESSION_SECRET, &tampered, 0);
    assert!(result.is_err());
}

/// PROPERTY: a token used past its expiry is rejected, even if
/// the MAC is otherwise valid.
#[test]
fn expired_token_rejected() {
    let session = make_session(2, 3, 1000);
    let token = mint_token(&SESSION_SECRET, session.id, pid(0xAA), 100).unwrap();

    // Now > expires_at -> rejected
    let result = verify_token(&SESSION_SECRET, &token, 200);
    assert!(result.is_err());
}

/// PROPERTY: a participant who isn't attached cannot submit
/// round-1 commitments. Closes the door once Round1 begins.
#[test]
fn unattached_participant_cannot_submit_round1() {
    let now = 1000;
    let mut session = make_session(2, 3, now);
    let alice = pid(0xA1);
    let bob = pid(0xB2);
    let carol = pid(0xC3);
    let stranger = pid(0xFF);

    // Attach 3 legitimate participants
    for p in [alice, bob, carol] {
        session
            .apply(Transition::AttachParticipant { participant: p }, now + 10)
            .unwrap();
    }
    // Move to Round1
    session
        .apply(
            Transition::DeclareMessage {
                message: vec![1, 2, 3],
            },
            now + 20,
        )
        .unwrap();
    assert_eq!(session.state, SessionState::Round1);

    // The stranger tries to submit a Round1 commitment
    let result = session.apply(
        Transition::SubmitRound1 {
            participant: stranger,
            commitment: vec![0xFF; 32],
        },
        now + 30,
    );
    assert!(result.is_err());
    // State is unchanged
    assert_eq!(session.state, SessionState::Round1);
}

/// PROPERTY: double-submit of round-1 from the same participant
/// is rejected (would otherwise allow a participant to lock out
/// other participants by flooding).
#[test]
fn double_submit_round1_rejected() {
    let now = 1000;
    let mut session = make_session(2, 3, now);
    let alice = pid(0xA1);
    let bob = pid(0xB2);

    session
        .apply(Transition::AttachParticipant { participant: alice }, now)
        .unwrap();
    session
        .apply(Transition::AttachParticipant { participant: bob }, now)
        .unwrap();
    session
        .apply(
            Transition::DeclareMessage {
                message: vec![1],
            },
            now,
        )
        .unwrap();

    session
        .apply(
            Transition::SubmitRound1 {
                participant: alice,
                commitment: vec![0xA1; 32],
            },
            now,
        )
        .unwrap();
    let result = session.apply(
        Transition::SubmitRound1 {
            participant: alice,
            commitment: vec![0xAA; 32],
        },
        now,
    );
    assert!(result.is_err());
}

/// PROPERTY: a session that has been Aborted rejects every further
/// transition. This is the terminal-stickiness invariant from
/// phase 1, validated through the persistence layer.
#[test]
fn aborted_session_rejects_further_transitions_after_reload() {
    let dir = tempdir().unwrap();
    let store = SessionStore::new(dir.path().join("sessions.json"));
    let session = make_session(2, 3, 1000);
    let session_id = session.id;

    let mut sessions = vec![session];
    sessions[0]
        .apply(
            Transition::Abort {
                participant: pid(0xAA),
            },
            1100,
        )
        .unwrap();
    store.save(&sessions).unwrap();

    // Reload from disk and try to apply ANY transition; all must reject.
    let mut loaded = store.load().unwrap();
    let s = loaded.iter_mut().find(|s| s.id == session_id).unwrap();
    assert!(s.state.is_terminal());

    let attempts = [
        Transition::AttachParticipant {
            participant: pid(0xBB),
        },
        Transition::DeclareMessage {
            message: vec![1, 2, 3],
        },
        Transition::SubmitRound1 {
            participant: pid(0xAA),
            commitment: vec![1; 32],
        },
        Transition::Abort {
            participant: pid(0xAA),
        },
        Transition::Tick,
    ];
    for t in attempts {
        let result = s.apply(t, 1200);
        assert!(result.is_err(), "terminal session must reject every transition");
    }
}

/// PROPERTY: persistence is resilient to crash mid-flow. Save
/// after every transition + reload mid-session = same end state
/// as a single-process run.
#[test]
fn crash_recovery_resumes_session_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sessions.json");
    let now = 1000;

    // Run the first half of the protocol with one store handle
    let session_id = {
        let store = SessionStore::new(&path);
        let session = make_session(2, 3, now);
        let session_id = session.id;
        let mut sessions = vec![session];
        for p in [pid(0xA1), pid(0xB2)] {
            sessions[0]
                .apply(Transition::AttachParticipant { participant: p }, now)
                .unwrap();
            store.save(&sessions).unwrap(); // save after EVERY transition
        }
        sessions[0]
            .apply(
                Transition::DeclareMessage {
                    message: b"hi".to_vec(),
                },
                now,
            )
            .unwrap();
        store.save(&sessions).unwrap();
        sessions[0]
            .apply(
                Transition::SubmitRound1 {
                    participant: pid(0xA1),
                    commitment: vec![1; 32],
                },
                now,
            )
            .unwrap();
        store.save(&sessions).unwrap();
        session_id
    };

    // Simulate a crash by dropping all in-memory state. Then a
    // fresh store handle reads from disk and continues.
    let store = SessionStore::new(&path);
    let mut loaded = store.load().unwrap();
    let s = loaded.iter_mut().find(|s| s.id == session_id).unwrap();
    assert_eq!(s.state, SessionState::Round1);
    // Resume: apply the second round-1 commitment to advance
    s.apply(
        Transition::SubmitRound1 {
            participant: pid(0xB2),
            commitment: vec![2; 32],
        },
        now,
    )
    .unwrap();
    assert_eq!(s.state, SessionState::Round2);
    store.save(&loaded).unwrap();

    // Final reload + verify
    let final_state = store.load().unwrap();
    let s = final_state.iter().find(|s| s.id == session_id).unwrap();
    assert_eq!(s.state, SessionState::Round2);
}

/// PROPERTY: invitation-token MAC binds session_id, pubkey, AND
/// expiry simultaneously. Tampering any field invalidates the
/// MAC.
#[test]
fn token_mac_binds_all_fields() {
    let session = make_session(2, 3, 1000);
    let pubkey = pid(0xAA);
    let original = mint_token(&SESSION_SECRET, session.id, pubkey, 9999).unwrap();

    // Tamper participant_pubkey
    let mut t = original.clone();
    t.participant_pubkey = pid(0xBB);
    assert!(verify_token(&SESSION_SECRET, &t, 0).is_err());

    // Tamper expires_at
    let mut t = original.clone();
    t.expires_at = 99999;
    assert!(verify_token(&SESSION_SECRET, &t, 0).is_err());

    // Tamper mac itself
    let mut t = original.clone();
    t.mac[0] ^= 1;
    assert!(verify_token(&SESSION_SECRET, &t, 0).is_err());

    // No tampering -> verifies
    assert!(verify_token(&SESSION_SECRET, &original, 0).is_ok());
}
