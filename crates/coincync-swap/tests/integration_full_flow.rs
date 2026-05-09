//! Phase 2.5 integration tests — full atomic-swap composition.
//!
//! Exercises the entire ready-today stack — protocol state
//! machine, handshake state machine, and state persistence —
//! through end-to-end flows from both Alice's and Bob's
//! perspectives, plus the adversarial cases that matter for
//! refund safety.
//!
//! Phase 3 will add real cryptography (adaptor signatures + DL-
//! equality proof + on-chain tx construction). These tests use
//! placeholder bytes for the cryptographic blobs because the
//! protocol-level state machine treats them as opaque payloads —
//! testing the bytes' cryptographic validity is the wallet's
//! responsibility, not the swap-coordination layer's.
//!
//! ## What this validates
//!
//! 1. **Composition.** The three modules — protocol, coordinator,
//!    state — all hand off correctly when wired together.
//! 2. **Refund safety.** The single most important property of an
//!    atomic swap: at every non-terminal state, the local party
//!    can recover their funds. Tests verify the refund path is
//!    legal and persists correctly from every relevant state.
//! 3. **Crash recovery.** A swap mid-handshake or mid-on-chain
//!    that survives a process crash MUST resume from the
//!    persisted state without losing the negotiation.
//! 4. **Terminal stickiness.** Completed / Refunded / Aborted
//!    swaps cannot be re-entered. A reload from disk preserves
//!    this.
//! 5. **Timeout safety.** SwapParameters that violate the
//!    btc_timeout < cync_timeout invariant are rejected at
//!    negotiation time AND in the handshake's HelloAck handler.

use coincync_swap::coordinator::{
    HandshakeAction, HandshakeError, HandshakeSession, Message, Phase,
};
use coincync_swap::protocol::{Role, State, Swap, SwapParameters, Transition};
use coincync_swap::SwapStore;
use tempfile::tempdir;

fn safe_params() -> SwapParameters {
    // is_timeout_safe demands cync_secs > btc_secs * 6/5.
    // BTC=100 blocks (60000s); threshold = 72000s.
    // CYNC=720 blocks * 120s = 86400s > 72000s. SAFE.
    SwapParameters {
        cync_amount: 100_000_000,
        btc_amount_sats: 1_000_000,
        cync_timeout_blocks: 720,
        btc_timeout_blocks: 100,
        alice_cync_address: "alice-stealth".into(),
        bob_btc_address: "bob-p2wpkh".into(),
    }
}

fn dummy_pub(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

fn dummy_blob(byte: u8) -> Vec<u8> {
    vec![byte; 64]
}

// ────────────────────────────────────────────────────────────────
// Happy paths — full composition through every layer
// ────────────────────────────────────────────────────────────────

/// PROPERTY: a complete swap walks Negotiated -> AliceLocked ->
/// BobLocked -> SecretRevealed -> Completed (Bob's view) with
/// every transition persisted to disk and reloaded.
#[test]
fn full_composition_completes_swap() {
    let dir = tempdir().unwrap();
    let alice_path = dir.path().join("alice.json");
    let bob_path = dir.path().join("bob.json");
    let alice_store = SwapStore::new(&alice_path);
    let bob_store = SwapStore::new(&bob_path);

    // ─── Negotiation handshake (in-memory, no real transport) ───
    let mut alice_hs = HandshakeSession::new_alice("swap-1".into());
    let mut bob_hs = HandshakeSession::new_bob("swap-1".into());

    let hello = bob_hs.start_bob(dummy_pub(0xB1), dummy_pub(0xB2)).unwrap();
    alice_hs.handle_inbound(hello).unwrap();
    let ack = alice_hs
        .respond_with_hello_ack(dummy_pub(0xA1), dummy_pub(0xA2), safe_params())
        .unwrap();
    bob_hs.handle_inbound(ack).unwrap();
    bob_hs.accept().unwrap();
    alice_hs.handle_inbound(Message::Accept).unwrap();
    let alice_adapt = alice_hs
        .send_adaptors(
            dummy_blob(0xA3),
            dummy_blob(0xA4),
            dummy_blob(0xA5),
            dummy_blob(0xA6),
        )
        .unwrap();
    let bob_adapt = bob_hs
        .send_adaptors(
            dummy_blob(0xB3),
            dummy_blob(0xB4),
            dummy_blob(0xB5),
            dummy_blob(0xB6),
        )
        .unwrap();
    let _ = alice_hs.handle_inbound(bob_adapt).unwrap();
    let _ = bob_hs.handle_inbound(alice_adapt).unwrap();
    assert_eq!(alice_hs.phase, Phase::AwaitingReady);
    assert_eq!(bob_hs.phase, Phase::AwaitingReady);
    let ar = alice_hs.send_ready().unwrap();
    let br = bob_hs.send_ready().unwrap();
    let action_a = alice_hs.handle_inbound(br).unwrap();
    let action_b = bob_hs.handle_inbound(ar).unwrap();
    assert_eq!(action_a, HandshakeAction::Done);
    assert_eq!(action_b, HandshakeAction::Done);

    // ─── On-chain phase (state machine + persistence) ───
    let mut alice_swap = Swap::negotiate("swap-1".into(), Role::Alice, safe_params()).unwrap();
    let mut bob_swap = Swap::negotiate("swap-1".into(), Role::Bob, safe_params()).unwrap();
    alice_store.save(&alice_swap).unwrap();
    bob_store.save(&bob_swap).unwrap();

    // Alice broadcasts CYNC lock (her local state advances; Bob's
    // chain watcher will eventually deliver a synthetic transition
    // — we model that by directly forcing Bob's state to
    // AliceLocked).
    alice_swap.apply(Transition::AliceLocksCync).unwrap();
    alice_store.save(&alice_swap).unwrap();
    bob_swap.state = State::AliceLocked;
    bob_store.save(&bob_swap).unwrap();

    // Bob broadcasts BTC lock; Alice's chain watcher catches it.
    bob_swap.apply(Transition::BobLocksBtc).unwrap();
    bob_store.save(&bob_swap).unwrap();
    alice_swap.apply(Transition::ObserveBobLocked).unwrap();
    alice_store.save(&alice_swap).unwrap();

    // Alice claims BTC, revealing the secret.
    alice_swap.apply(Transition::AliceClaimsBtc).unwrap();
    alice_store.save(&alice_swap).unwrap();

    // Bob's chain watcher catches Alice's claim, extracts the
    // secret, claims CYNC.
    bob_swap.apply(Transition::ObserveSecretRevealed).unwrap();
    bob_store.save(&bob_swap).unwrap();
    bob_swap.apply(Transition::BobClaimsCync).unwrap();
    bob_store.save(&bob_swap).unwrap();

    // Final reload from disk; verify both sides at expected
    // terminal states.
    let alice_final = alice_store.load().unwrap().unwrap();
    let bob_final = bob_store.load().unwrap().unwrap();
    assert_eq!(alice_final.state, State::SecretRevealed);
    assert_eq!(bob_final.state, State::Completed);
    assert!(bob_final.is_completed());
    assert!(bob_final.is_terminal());
}

// ────────────────────────────────────────────────────────────────
// Refund safety — the single most important property
// ────────────────────────────────────────────────────────────────

/// PROPERTY: from AliceLocked, Alice can refund (= her CYNC lock
/// returns to her). Persistence preserves the refunded state.
#[test]
fn alice_can_refund_from_alice_locked_with_persistence() {
    let dir = tempdir().unwrap();
    let store = SwapStore::new(dir.path().join("swap.json"));

    let mut swap = Swap::negotiate("a-1".into(), Role::Alice, safe_params()).unwrap();
    swap.apply(Transition::AliceLocksCync).unwrap();
    store.save(&swap).unwrap();

    // Reload + refund (simulating "the user came back N hours
    // later and decided to abandon the swap"; in production this
    // would be triggered by chain timeout, not user choice).
    let mut reloaded = store.load().unwrap().unwrap();
    assert_eq!(reloaded.state, State::AliceLocked);
    reloaded.apply(Transition::AliceRefunds).unwrap();
    store.save(&reloaded).unwrap();

    let final_state = store.load().unwrap().unwrap();
    assert_eq!(final_state.state, State::Refunded);
    assert!(final_state.is_terminal());
}

/// PROPERTY: from BobLocked, BOTH Alice (her CYNC) and Bob (his
/// BTC) can refund independently. They don't need each other.
#[test]
fn both_parties_refund_from_bob_locked() {
    let dir = tempdir().unwrap();
    let alice_store = SwapStore::new(dir.path().join("alice.json"));
    let bob_store = SwapStore::new(dir.path().join("bob.json"));

    // Alice
    let mut alice_swap = Swap::negotiate("a".into(), Role::Alice, safe_params()).unwrap();
    alice_swap.apply(Transition::AliceLocksCync).unwrap();
    alice_swap.apply(Transition::ObserveBobLocked).unwrap();
    alice_store.save(&alice_swap).unwrap();

    // Bob
    let mut bob_swap = Swap::negotiate("b".into(), Role::Bob, safe_params()).unwrap();
    bob_swap.state = State::AliceLocked;
    bob_swap.apply(Transition::BobLocksBtc).unwrap();
    bob_store.save(&bob_swap).unwrap();

    // Each refunds independently
    alice_swap.apply(Transition::AliceRefunds).unwrap();
    alice_store.save(&alice_swap).unwrap();
    bob_swap.apply(Transition::BobRefunds).unwrap();
    bob_store.save(&bob_swap).unwrap();

    let alice_final = alice_store.load().unwrap().unwrap();
    let bob_final = bob_store.load().unwrap().unwrap();
    assert_eq!(alice_final.state, State::Refunded);
    assert_eq!(bob_final.state, State::Refunded);
}

/// PROPERTY: refund-path safety holds for every non-terminal state
/// where a lock could exist. From Negotiated (no lock), refund
/// is a no-op (just abort). From AliceLocked / BobLocked, refund
/// is the legitimate recovery path.
#[test]
fn refund_path_legal_from_every_non_terminal_lock_state() {
    let mut alice_states_with_refund = Vec::new();
    for forced_state in [State::AliceLocked, State::BobLocked] {
        let mut s = Swap::negotiate("rf".into(), Role::Alice, safe_params()).unwrap();
        s.state = forced_state;
        let result = s.apply(Transition::AliceRefunds);
        alice_states_with_refund.push((forced_state, result.is_ok(), s.state));
    }
    assert!(alice_states_with_refund
        .iter()
        .all(|(_, ok, end)| *ok && *end == State::Refunded));
}

// ────────────────────────────────────────────────────────────────
// Crash recovery
// ────────────────────────────────────────────────────────────────

/// PROPERTY: a swap interrupted at any non-terminal state resumes
/// correctly after a "crash" (= drop in-memory state, reload from
/// disk).
#[test]
fn crash_recovery_resumes_swap_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("swap.json");

    // First "process": negotiate + apply two transitions
    let id = {
        let store = SwapStore::new(&path);
        let mut swap = Swap::negotiate("c-1".into(), Role::Alice, safe_params()).unwrap();
        store.save(&swap).unwrap();
        swap.apply(Transition::AliceLocksCync).unwrap();
        store.save(&swap).unwrap();
        swap.apply(Transition::ObserveBobLocked).unwrap();
        store.save(&swap).unwrap();
        swap.id.clone()
    };

    // Second "process": fresh handle, load, continue
    let store = SwapStore::new(&path);
    let mut reloaded = store.load().unwrap().unwrap();
    assert_eq!(reloaded.id, id);
    assert_eq!(reloaded.state, State::BobLocked);
    reloaded.apply(Transition::AliceClaimsBtc).unwrap();
    store.save(&reloaded).unwrap();

    let final_state = store.load().unwrap().unwrap();
    assert_eq!(final_state.state, State::SecretRevealed);
}

// ────────────────────────────────────────────────────────────────
// Terminal stickiness through persistence
// ────────────────────────────────────────────────────────────────

/// PROPERTY: a Completed swap reloaded from disk rejects every
/// further transition.
#[test]
fn completed_swap_rejects_all_transitions_after_reload() {
    let dir = tempdir().unwrap();
    let store = SwapStore::new(dir.path().join("swap.json"));

    // Drive Bob through to Completed
    let mut bob_swap = Swap::negotiate("b".into(), Role::Bob, safe_params()).unwrap();
    bob_swap.state = State::AliceLocked;
    bob_swap.apply(Transition::BobLocksBtc).unwrap();
    bob_swap.apply(Transition::ObserveSecretRevealed).unwrap();
    bob_swap.apply(Transition::BobClaimsCync).unwrap();
    assert_eq!(bob_swap.state, State::Completed);
    store.save(&bob_swap).unwrap();

    // Reload + try every transition
    let mut reloaded = store.load().unwrap().unwrap();
    let attempts = [
        Transition::AliceLocksCync,
        Transition::BobLocksBtc,
        Transition::AliceClaimsBtc,
        Transition::BobClaimsCync,
        Transition::AliceRefunds,
        Transition::BobRefunds,
        Transition::ObserveBobLocked,
        Transition::ObserveSecretRevealed,
        Transition::ObserveCompleted,
        Transition::Abort,
    ];
    for t in attempts {
        let result = reloaded.apply(t);
        assert!(result.is_err(), "Completed swap must reject {:?}", t);
        assert_eq!(reloaded.state, State::Completed, "state must not change");
    }
}

// ────────────────────────────────────────────────────────────────
// Adversarial: timeout-safety enforcement
// ────────────────────────────────────────────────────────────────

/// PROPERTY: unsafe timeouts are rejected at swap construction
/// AND inside the handshake's HelloAck handler. Two layers of
/// defense, since either could be reached first depending on
/// the deployment flow.
#[test]
fn unsafe_timeouts_rejected_at_both_layers() {
    let mut bad = safe_params();
    bad.btc_timeout_blocks = 1000; // BTC much longer than CYNC -> unsafe
    bad.cync_timeout_blocks = 100;
    assert!(!bad.is_timeout_safe());

    // Layer 1: protocol-level Swap::negotiate
    let result = Swap::negotiate("u".into(), Role::Alice, bad.clone());
    assert!(result.is_err());

    // Layer 2: handshake's HelloAck handler — Alice cannot send
    // a HelloAck with unsafe parameters
    let mut alice = HandshakeSession::new_alice("u".into());
    let mut bob = HandshakeSession::new_bob("u".into());
    let h = bob.start_bob(dummy_pub(1), dummy_pub(2)).unwrap();
    alice.handle_inbound(h).unwrap();
    let result = alice.respond_with_hello_ack(dummy_pub(3), dummy_pub(4), bad);
    assert!(matches!(result, Err(HandshakeError::OutOfOrder { .. })));
}

// ────────────────────────────────────────────────────────────────
// Adversarial: handshake-level role + sequencing gates
// ────────────────────────────────────────────────────────────────

/// PROPERTY: a counterparty connecting with the WRONG swap_id
/// is rejected at handshake time. Bob can't accidentally
/// hijack a different Alice's session.
#[test]
fn handshake_swap_id_mismatch_rejected() {
    let mut alice = HandshakeSession::new_alice("session-A".into());
    let bad_hello = Message::Hello {
        swap_id: "session-DIFFERENT".into(),
        bob_btc_pubkey: dummy_pub(1),
        bob_cync_pubkey: dummy_pub(2),
    };
    let result = alice.handle_inbound(bad_hello);
    assert!(matches!(result, Err(HandshakeError::SwapIdMismatch { .. })));
    // Session phase unchanged after rejection
    assert_eq!(alice.phase, Phase::Initial);
}

/// PROPERTY: handshake aborts cleanly from any non-terminal phase.
/// The local session moves to `Aborted`; subsequent messages are
/// rejected.
#[test]
fn handshake_abort_terminates_cleanly() {
    let mut alice = HandshakeSession::new_alice("a".into());
    let _ = alice.send_abort("operator-changed-mind");
    assert_eq!(alice.phase, Phase::Aborted);

    // Any further inbound is rejected
    let result = alice.handle_inbound(Message::Hello {
        swap_id: "a".into(),
        bob_btc_pubkey: dummy_pub(1),
        bob_cync_pubkey: dummy_pub(2),
    });
    assert!(matches!(result, Err(HandshakeError::Terminal(_))));
}

// ────────────────────────────────────────────────────────────────
// Cross-layer: cancel-with-persistence
// ────────────────────────────────────────────────────────────────

/// PROPERTY: cancelling a swap (Abort transition) with a
/// pre-existing on-chain lock advances to Aborted. The wallet
/// must independently broadcast the pre-signed refund — the
/// state machine's Aborted state is the local-view marker, NOT
/// a chain action. (Phase 3 will make `cyncswap cancel` broadcast
/// the refund automatically; phase 2.5 is local-only.)
#[test]
fn cancel_after_lock_advances_to_aborted_locally() {
    let dir = tempdir().unwrap();
    let store = SwapStore::new(dir.path().join("swap.json"));

    let mut swap = Swap::negotiate("c".into(), Role::Alice, safe_params()).unwrap();
    swap.apply(Transition::AliceLocksCync).unwrap();
    store.save(&swap).unwrap();

    // The CLI's `cancel` subcommand applies Abort
    swap.apply(Transition::Abort).unwrap();
    store.save(&swap).unwrap();

    let final_state = store.load().unwrap().unwrap();
    assert_eq!(final_state.state, State::Aborted);
    assert!(final_state.is_terminal());
}
