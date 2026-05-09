//! Peer-to-peer coordination between Alice and Bob during the swap.
//!
//! The atomic-swap protocol requires several rounds of off-chain
//! message exchange before either party commits anything to a
//! blockchain. Both parties need to agree on parameters, exchange
//! adaptor public keys, exchange cross-curve DL-equality proofs,
//! and coordinate the ordered chain operations.
//!
//! ## What's in this module (phase 2)
//!
//! - The `Message` enum: wire-format messages between Alice and Bob
//! - The `Phase` enum: handshake state-machine positions
//! - The `HandshakeSession` struct: per-role state machine that
//!   takes an inbound `Message` and either produces the next
//!   outbound `Message`, signals successful negotiation
//!   (`HandshakeAction::Done`), or aborts
//! - Domain-error type for protocol-violation cases
//! - Unit tests covering each role's happy path, role-gating,
//!   out-of-order rejection, double-message rejection,
//!   abort-from-any-state semantics
//!
//! ## What's NOT in this module
//!
//! - **Transport.** No bytes-on-the-wire. The session is a pure
//!   message-level state machine: caller wraps it in TCP+Noise /
//!   Tor / libp2p / sneakernet — the choice is deferred to
//!   CIP-001 and to the eventual production deployment.
//! - **Cryptographic verification.** When the protocol delivers
//!   adaptor material, the session emits a `VerifyAdaptorMaterial`
//!   action and the caller dispatches to `adaptor.rs` (still
//!   `NotImplemented` until phase 3). This module's job is
//!   sequencing — *what* gets exchanged when, not *how* the
//!   crypto verifies.
//! - **Asynchrony.** This is sync code that takes one inbound
//!   message at a time. The transport layer adds async on top.
//!
//! ## Why this shape
//!
//! Same pattern as the FROST coordinator session and the
//! rolling-finality tracker: a pure-state machine with the
//! cryptographic / I/O boundaries explicit. Lets us property-test
//! the message-ordering invariants today without ed25519 /
//! secp256k1 / Tor in the build graph, and lets the transport
//! layer evolve independently.

use serde::{Deserialize, Serialize};

use crate::protocol::{Role, SwapParameters};

// ──────────────────────────────────────────────────────────────────
// Wire messages
// ──────────────────────────────────────────────────────────────────

/// Messages exchanged between Alice and Bob during negotiation.
/// These are the wire-format types; transport-layer encoding
/// (borsh / JSON / msgpack) is up to the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Bob -> Alice. Initial connection. Bob announces which swap
    /// he's joining (out-of-band swap_id Alice published) and
    /// shares his BTC + CYNC pubkeys.
    Hello {
        swap_id: String,
        bob_btc_pubkey: Vec<u8>,
        bob_cync_pubkey: Vec<u8>,
    },

    /// Alice -> Bob. Alice acknowledges the connection, shares her
    /// pubkeys, and proposes the swap parameters (amounts +
    /// timeouts). Bob may accept or counter (counters are not
    /// modeled in phase 2 — abort + restart with new parameters
    /// is fine).
    HelloAck {
        alice_btc_pubkey: Vec<u8>,
        alice_cync_pubkey: Vec<u8>,
        parameters: SwapParameters,
    },

    /// Bob -> Alice. Bob accepts Alice's parameters and begins
    /// the adaptor-material phase.
    Accept,

    /// Either -> the other. The full bundle of adaptor + refund
    /// material exchanged in step 3 of CIP-001 negotiation.
    /// Both parties must send theirs and verify the
    /// counterparty's before either side commits a lock tx.
    AdaptorMaterial {
        /// Adaptor signature on the BTC side (opaque to the state
        /// machine; the cryptographic verification lives in
        /// `adaptor.rs`).
        btc_adaptor: Vec<u8>,
        /// Adaptor signature on the CYNC side.
        cync_adaptor: Vec<u8>,
        /// Cross-curve DL-equality proof.
        dl_proof: Vec<u8>,
        /// Pre-signed refund transaction (BTC for Bob, CYNC for
        /// Alice). Phase 2 doesn't decode these; phase 3+ does.
        refund_tx: Vec<u8>,
    },

    /// Either -> the other. Final acknowledgment that everything
    /// has been exchanged and verified. After both sides see this
    /// from the other, the negotiation phase ends and the on-chain
    /// phase begins (Alice broadcasts her CYNC lock).
    Ready,

    /// Either -> the other. Explicit abort. Sender will not
    /// continue. No funds at risk because no lock has happened
    /// yet.
    Abort { reason: String },
}

// ──────────────────────────────────────────────────────────────────
// Handshake phases
// ──────────────────────────────────────────────────────────────────

/// State-machine position in the handshake. Each role traverses
/// these in a specific order; out-of-order or wrong-role
/// transitions abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Alice: waiting for Bob's Hello.
    /// Bob:   waiting to send Hello (no inbound expected).
    Initial,
    /// Bob: sent Hello, waiting for Alice's HelloAck.
    /// Alice: sent HelloAck, waiting for Bob's Accept.
    AwaitingAck,
    /// Both: counterparty has accepted; exchanging adaptor
    /// material. The session has either sent its own
    /// AdaptorMaterial yet or not, AND it has either received the
    /// counterparty's yet or not. We track those two booleans
    /// inside the session, not in this enum.
    ExchangingAdaptors,
    /// Both: adaptor exchange complete + verified. Sending /
    /// awaiting Ready.
    AwaitingReady,
    /// Both: negotiation succeeded. The session is finished.
    Negotiated,
    /// Both: aborted. Terminal.
    Aborted,
}

impl Phase {
    pub fn is_terminal(self) -> bool {
        matches!(self, Phase::Negotiated | Phase::Aborted)
    }
}

// ──────────────────────────────────────────────────────────────────
// Session
// ──────────────────────────────────────────────────────────────────

/// One side of a handshake. Construct with `new_alice` /
/// `new_bob`, feed inbound messages with `handle_inbound`, send
/// the resulting `HandshakeAction::Send` outbound.
#[derive(Clone, Debug)]
pub struct HandshakeSession {
    pub role: Role,
    pub phase: Phase,
    pub swap_id: String,

    /// Once a `Hello` / `HelloAck` exchange has happened, both
    /// sides know each other's pubkeys; we cache them here for
    /// later consistency checks (e.g., the `AdaptorMaterial`
    /// refund-tx must match the established pubkey set).
    pub counterparty_btc_pubkey: Option<Vec<u8>>,
    pub counterparty_cync_pubkey: Option<Vec<u8>>,

    /// Set when Alice has sent HelloAck or Bob has received it.
    /// Defines the parameters both sides have committed to.
    pub parameters: Option<SwapParameters>,

    /// Per-role: have we sent / received our adaptor material?
    /// Used in `ExchangingAdaptors` to know when to advance.
    pub sent_adaptors: bool,
    pub received_adaptors: bool,
}

/// Output of `handle_inbound`. The caller's transport layer is
/// responsible for executing each action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeAction {
    /// Send this message to the counterparty.
    Send(Message),
    /// The handshake is complete and successful. Negotiated
    /// parameters + counterparty pubkeys are accessible via the
    /// session struct; the caller can move into the on-chain
    /// phase (Alice broadcasts CYNC lock).
    Done,
    /// Verify the adaptor material out-of-band (calls into
    /// `adaptor.rs`). Returned alongside any next-step
    /// `Send(_)` — wrapped in this enum because verification is
    /// a side effect, not a message. After the caller returns
    /// the verification result, the session continues. Phase 2
    /// lifts this to an action so phase 3 (the real adaptor
    /// crypto) can plug in without changing the message-level
    /// state machine.
    VerifyAdaptorMaterial {
        btc_adaptor: Vec<u8>,
        cync_adaptor: Vec<u8>,
        dl_proof: Vec<u8>,
        refund_tx: Vec<u8>,
    },
    /// Counterparty signaled abort. Session is now terminal.
    Aborted { reason: String },
}

/// Errors emitted when the inbound message violates the protocol.
/// Distinct from `Error::Verification`: these are sequencing
/// errors, not crypto-verification failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// Inbound message arrived in a phase that doesn't accept it.
    #[error("unexpected message {message_kind} in phase {phase:?}")]
    OutOfOrder {
        message_kind: &'static str,
        phase: Phase,
    },

    /// The incoming Hello's swap_id doesn't match this session's
    /// swap_id. Bob may have connected to the wrong Alice; we
    /// abort.
    #[error("hello swap_id mismatch: session={session_swap_id} incoming={incoming_swap_id}")]
    SwapIdMismatch {
        session_swap_id: String,
        incoming_swap_id: String,
    },

    /// Session is terminal; no further messages are accepted.
    #[error("handshake is in terminal phase {0:?}; cannot accept further messages")]
    Terminal(Phase),

    /// A duplicate of a message we've already received in this
    /// phase. E.g., Bob sent two `AdaptorMaterial`s in a row.
    /// Could be a peer-side bug or a malicious replay; either way
    /// we abort.
    #[error("duplicate {kind} from counterparty")]
    Duplicate { kind: &'static str },
}

impl HandshakeSession {
    /// Construct Alice's session. Alice listens for Bob's `Hello`.
    pub fn new_alice(swap_id: String) -> Self {
        HandshakeSession {
            role: Role::Alice,
            phase: Phase::Initial,
            swap_id,
            counterparty_btc_pubkey: None,
            counterparty_cync_pubkey: None,
            parameters: None,
            sent_adaptors: false,
            received_adaptors: false,
        }
    }

    /// Construct Bob's session. Bob's first action is to send a
    /// `Hello`; `start_bob` returns it so the caller can transmit.
    pub fn new_bob(swap_id: String) -> Self {
        HandshakeSession {
            role: Role::Bob,
            phase: Phase::Initial,
            swap_id,
            counterparty_btc_pubkey: None,
            counterparty_cync_pubkey: None,
            parameters: None,
            sent_adaptors: false,
            received_adaptors: false,
        }
    }

    /// Bob's initiating action. Returns the `Hello` Bob should
    /// send first; advances Bob's phase to `AwaitingAck`.
    /// Alice never calls this. Returns an error if called by
    /// Alice or from a non-`Initial` phase.
    pub fn start_bob(
        &mut self,
        bob_btc_pubkey: Vec<u8>,
        bob_cync_pubkey: Vec<u8>,
    ) -> std::result::Result<Message, HandshakeError> {
        if self.role != Role::Bob {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "start_bob",
                phase: self.phase,
            });
        }
        if self.phase != Phase::Initial {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "start_bob",
                phase: self.phase,
            });
        }
        let msg = Message::Hello {
            swap_id: self.swap_id.clone(),
            bob_btc_pubkey,
            bob_cync_pubkey,
        };
        self.phase = Phase::AwaitingAck;
        Ok(msg)
    }

    /// Send our own `AdaptorMaterial`. Both roles call this once
    /// they've reached `ExchangingAdaptors`. The fields are
    /// produced by the cryptographic skeleton in `adaptor.rs`
    /// (still `NotImplemented` until phase 3).
    pub fn send_adaptors(
        &mut self,
        btc_adaptor: Vec<u8>,
        cync_adaptor: Vec<u8>,
        dl_proof: Vec<u8>,
        refund_tx: Vec<u8>,
    ) -> std::result::Result<Message, HandshakeError> {
        if self.phase != Phase::ExchangingAdaptors {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "send_adaptors",
                phase: self.phase,
            });
        }
        if self.sent_adaptors {
            return Err(HandshakeError::Duplicate {
                kind: "outbound AdaptorMaterial",
            });
        }
        self.sent_adaptors = true;
        let msg = Message::AdaptorMaterial {
            btc_adaptor,
            cync_adaptor,
            dl_proof,
            refund_tx,
        };
        self.maybe_advance_to_awaiting_ready();
        Ok(msg)
    }

    /// Send a `Ready`. Both roles call this once they've finished
    /// adaptor exchange and verified the counterparty's material.
    pub fn send_ready(&mut self) -> std::result::Result<Message, HandshakeError> {
        if self.phase != Phase::AwaitingReady {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "send_ready",
                phase: self.phase,
            });
        }
        // Local state doesn't need to track that we've sent
        // Ready — the next inbound Ready completes the handshake;
        // before that, sending a second Ready is a peer-side
        // problem, not a session-state issue.
        Ok(Message::Ready)
    }

    /// Send an `Abort`. Always legal from any non-terminal phase.
    /// Drives the local session to `Aborted` immediately.
    pub fn send_abort(&mut self, reason: impl Into<String>) -> Message {
        let reason = reason.into();
        self.phase = Phase::Aborted;
        Message::Abort { reason }
    }

    /// Process an inbound message. Returns the action the caller
    /// should take (send a message, run verification, or signal
    /// completion / abort). Errors leave the session UNCHANGED.
    pub fn handle_inbound(
        &mut self,
        msg: Message,
    ) -> std::result::Result<HandshakeAction, HandshakeError> {
        // Terminal-phase guard.
        if self.phase.is_terminal() {
            return Err(HandshakeError::Terminal(self.phase));
        }

        match (msg, self.role, self.phase) {
            // ── Abort always accepted from any non-terminal phase ──
            (Message::Abort { reason }, _, _) => {
                self.phase = Phase::Aborted;
                Ok(HandshakeAction::Aborted { reason })
            }

            // ── Alice receives Hello from Bob ──
            (
                Message::Hello {
                    swap_id,
                    bob_btc_pubkey,
                    bob_cync_pubkey,
                },
                Role::Alice,
                Phase::Initial,
            ) => {
                if swap_id != self.swap_id {
                    return Err(HandshakeError::SwapIdMismatch {
                        session_swap_id: self.swap_id.clone(),
                        incoming_swap_id: swap_id,
                    });
                }
                self.counterparty_btc_pubkey = Some(bob_btc_pubkey);
                self.counterparty_cync_pubkey = Some(bob_cync_pubkey);
                self.phase = Phase::AwaitingAck;
                // Alice now needs to send HelloAck. She gets it
                // from our side via a separate `send_hello_ack`
                // call (next).
                Ok(HandshakeAction::Send(Message::Abort {
                    // We don't know Alice's pubkeys + parameters
                    // here yet — the caller plugs those in via
                    // `respond_with_hello_ack`. To keep the API
                    // simple, this branch returns a placeholder
                    // and the caller is expected to invoke
                    // `respond_with_hello_ack` immediately.
                    //
                    // Alternative design considered: have
                    // `handle_inbound` take callbacks for
                    // pubkey-providing. Rejected because callbacks
                    // make the state machine harder to test in
                    // isolation. The placeholder approach keeps
                    // pure inputs->pure outputs cleaner.
                    reason: "placeholder; caller must invoke respond_with_hello_ack".into(),
                }))
            }

            // ── Bob receives HelloAck from Alice ──
            (
                Message::HelloAck {
                    alice_btc_pubkey,
                    alice_cync_pubkey,
                    parameters,
                },
                Role::Bob,
                Phase::AwaitingAck,
            ) => {
                self.counterparty_btc_pubkey = Some(alice_btc_pubkey);
                self.counterparty_cync_pubkey = Some(alice_cync_pubkey);
                self.parameters = Some(parameters);
                // Bob needs to decide accept or abort. We don't
                // auto-accept here — the caller decides based on
                // whether the parameters are satisfactory and
                // calls `accept` or `send_abort` next.
                self.phase = Phase::AwaitingAck;
                Ok(HandshakeAction::Send(Message::Abort {
                    reason: "placeholder; caller must call accept() or send_abort()".into(),
                }))
            }

            // ── Alice receives Accept from Bob ──
            (Message::Accept, Role::Alice, Phase::AwaitingAck) => {
                // Negotiation moves into adaptor exchange. Alice
                // hasn't sent her adaptors yet; the caller drives
                // that via `send_adaptors`.
                self.phase = Phase::ExchangingAdaptors;
                // Suggest Alice send her adaptors next; the
                // caller's transport will do that via
                // `send_adaptors` and transmit the returned msg.
                // No outbound message from `handle_inbound` itself
                // here — there's nothing to immediately respond
                // with until the caller produces the adaptor
                // material.
                Ok(HandshakeAction::Send(Message::Abort {
                    reason: "placeholder; caller must call send_adaptors()".into(),
                }))
            }

            // ── AdaptorMaterial inbound (either role) ──
            (
                Message::AdaptorMaterial {
                    btc_adaptor,
                    cync_adaptor,
                    dl_proof,
                    refund_tx,
                },
                _,
                Phase::ExchangingAdaptors,
            ) => {
                if self.received_adaptors {
                    return Err(HandshakeError::Duplicate {
                        kind: "AdaptorMaterial",
                    });
                }
                self.received_adaptors = true;
                self.maybe_advance_to_awaiting_ready();
                Ok(HandshakeAction::VerifyAdaptorMaterial {
                    btc_adaptor,
                    cync_adaptor,
                    dl_proof,
                    refund_tx,
                })
            }

            // ── Ready inbound (either role) ──
            (Message::Ready, _, Phase::AwaitingReady) => {
                self.phase = Phase::Negotiated;
                Ok(HandshakeAction::Done)
            }

            // ── Anything else is out of order ──
            (msg, _, phase) => Err(HandshakeError::OutOfOrder {
                message_kind: message_kind(&msg),
                phase,
            }),
        }
    }

    /// After `handle_inbound` returned the placeholder for an
    /// inbound `Hello`, Alice's caller invokes this to produce
    /// the real `HelloAck`. Splits the (impure: needs caller-
    /// supplied keys) part out of `handle_inbound`'s pure path.
    pub fn respond_with_hello_ack(
        &mut self,
        alice_btc_pubkey: Vec<u8>,
        alice_cync_pubkey: Vec<u8>,
        parameters: SwapParameters,
    ) -> std::result::Result<Message, HandshakeError> {
        if self.role != Role::Alice {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "respond_with_hello_ack",
                phase: self.phase,
            });
        }
        if self.phase != Phase::AwaitingAck {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "respond_with_hello_ack",
                phase: self.phase,
            });
        }
        if !parameters.is_timeout_safe() {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "respond_with_hello_ack (unsafe timeouts)",
                phase: self.phase,
            });
        }
        self.parameters = Some(parameters.clone());
        Ok(Message::HelloAck {
            alice_btc_pubkey,
            alice_cync_pubkey,
            parameters,
        })
    }

    /// Bob accepts the parameters Alice proposed in HelloAck and
    /// sends the `Accept` message. Phase advances to
    /// `ExchangingAdaptors`.
    pub fn accept(&mut self) -> std::result::Result<Message, HandshakeError> {
        if self.role != Role::Bob {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "accept",
                phase: self.phase,
            });
        }
        if self.phase != Phase::AwaitingAck {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "accept",
                phase: self.phase,
            });
        }
        if self.parameters.is_none() {
            return Err(HandshakeError::OutOfOrder {
                message_kind: "accept (no parameters)",
                phase: self.phase,
            });
        }
        self.phase = Phase::ExchangingAdaptors;
        Ok(Message::Accept)
    }

    /// Once both sides have sent + received adaptors, phase
    /// advances to `AwaitingReady`.
    fn maybe_advance_to_awaiting_ready(&mut self) {
        if self.sent_adaptors && self.received_adaptors {
            self.phase = Phase::AwaitingReady;
        }
    }
}

fn message_kind(msg: &Message) -> &'static str {
    match msg {
        Message::Hello { .. } => "Hello",
        Message::HelloAck { .. } => "HelloAck",
        Message::Accept => "Accept",
        Message::AdaptorMaterial { .. } => "AdaptorMaterial",
        Message::Ready => "Ready",
        Message::Abort { .. } => "Abort",
    }
}

// Public re-export of the placeholder Coordinator from the
// pre-phase-2 skeleton, kept at the bottom so existing call sites
// (none yet, but the public API contract mentions it) still find
// it. The transport-level Coordinator is the eventual phase-3
// wrapper around HandshakeSession + a real network transport.
//
// All four of its methods still return `NotImplemented`.
use crate::{Error, Result};

/// One side of an active coordination session (transport-level).
/// Phase 2 keeps this struct as a public stub; the real wrapping
/// of `HandshakeSession` with TCP+Noise / Tor lives in phase 3.
#[derive(Debug)]
pub struct Coordinator {
    #[allow(dead_code)]
    pub(crate) endpoint: String,
}

impl Coordinator {
    /// Begin listening as Alice. Bob will connect with a swap-id.
    pub fn listen(_endpoint: &str) -> Result<Self> {
        Err(Error::not_implemented("coordinator.listen"))
    }

    /// Connect to Alice's listening endpoint as Bob.
    pub fn connect(_endpoint: &str, _swap_id: &str) -> Result<Self> {
        Err(Error::not_implemented("coordinator.connect"))
    }

    /// Run one round of the negotiation handshake. Returns when
    /// both sides have agreed on parameters or the round fails.
    pub fn handshake(&mut self) -> Result<()> {
        Err(Error::not_implemented("coordinator.handshake"))
    }
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_params() -> SwapParameters {
        SwapParameters {
            cync_amount: 100_000_000,
            btc_amount_sats: 1_000_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice_addr".into(),
            bob_btc_address: "bob_addr".into(),
        }
    }

    fn dummy_pub(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn dummy_blob(byte: u8) -> Vec<u8> {
        vec![byte; 64]
    }

    fn run_full_handshake() -> (HandshakeSession, HandshakeSession) {
        // Two sessions, exchange messages in order.
        let mut alice = HandshakeSession::new_alice("swap-test".into());
        let mut bob = HandshakeSession::new_bob("swap-test".into());

        // Bob -> Alice: Hello
        let hello = bob.start_bob(dummy_pub(0xB1), dummy_pub(0xB2)).unwrap();
        let _action = alice.handle_inbound(hello).unwrap();
        // Alice -> Bob: HelloAck
        let ack = alice
            .respond_with_hello_ack(dummy_pub(0xA1), dummy_pub(0xA2), safe_params())
            .unwrap();
        let _action = bob.handle_inbound(ack).unwrap();
        // Bob -> Alice: Accept
        let accept = bob.accept().unwrap();
        let _action = alice.handle_inbound(accept).unwrap();
        // Both: send AdaptorMaterial
        let alice_adapt = alice
            .send_adaptors(
                dummy_blob(0xA3),
                dummy_blob(0xA4),
                dummy_blob(0xA5),
                dummy_blob(0xA6),
            )
            .unwrap();
        let bob_adapt = bob
            .send_adaptors(
                dummy_blob(0xB3),
                dummy_blob(0xB4),
                dummy_blob(0xB5),
                dummy_blob(0xB6),
            )
            .unwrap();
        let _action_a = alice.handle_inbound(bob_adapt).unwrap();
        let _action_b = bob.handle_inbound(alice_adapt).unwrap();
        // Both should now be in AwaitingReady
        assert_eq!(alice.phase, Phase::AwaitingReady);
        assert_eq!(bob.phase, Phase::AwaitingReady);
        // Both: send Ready
        let ar = alice.send_ready().unwrap();
        let br = bob.send_ready().unwrap();
        let action_a = alice.handle_inbound(br).unwrap();
        let action_b = bob.handle_inbound(ar).unwrap();
        // Both should be Done
        assert_eq!(action_a, HandshakeAction::Done);
        assert_eq!(action_b, HandshakeAction::Done);
        assert_eq!(alice.phase, Phase::Negotiated);
        assert_eq!(bob.phase, Phase::Negotiated);
        (alice, bob)
    }

    #[test]
    fn full_happy_path_completes() {
        let (alice, bob) = run_full_handshake();
        // Both sides know counterparty pubkeys + parameters
        assert!(alice.counterparty_btc_pubkey.is_some());
        assert!(alice.counterparty_cync_pubkey.is_some());
        assert!(alice.parameters.is_some());
        assert!(bob.counterparty_btc_pubkey.is_some());
        assert!(bob.counterparty_cync_pubkey.is_some());
        assert!(bob.parameters.is_some());
    }

    #[test]
    fn role_gating_alice_cannot_send_hello() {
        let mut alice = HandshakeSession::new_alice("s".into());
        let result = alice.start_bob(dummy_pub(1), dummy_pub(2));
        assert!(matches!(result, Err(HandshakeError::OutOfOrder { .. })));
    }

    #[test]
    fn role_gating_bob_cannot_send_hello_ack() {
        let mut bob = HandshakeSession::new_bob("s".into());
        let result = bob.respond_with_hello_ack(dummy_pub(1), dummy_pub(2), safe_params());
        assert!(matches!(result, Err(HandshakeError::OutOfOrder { .. })));
    }

    #[test]
    fn swap_id_mismatch_rejected() {
        let mut alice = HandshakeSession::new_alice("session-A".into());
        let bad_hello = Message::Hello {
            swap_id: "session-DIFFERENT".into(),
            bob_btc_pubkey: dummy_pub(1),
            bob_cync_pubkey: dummy_pub(2),
        };
        let result = alice.handle_inbound(bad_hello);
        assert!(matches!(result, Err(HandshakeError::SwapIdMismatch { .. })));
        assert_eq!(
            alice.phase,
            Phase::Initial,
            "session unchanged after rejection"
        );
    }

    #[test]
    fn out_of_order_hello_during_exchange_rejected() {
        let (mut alice, _bob) = run_full_handshake();
        // Negotiated is terminal
        let result = alice.handle_inbound(Message::Hello {
            swap_id: "anything".into(),
            bob_btc_pubkey: dummy_pub(1),
            bob_cync_pubkey: dummy_pub(2),
        });
        assert!(matches!(result, Err(HandshakeError::Terminal(_))));
    }

    #[test]
    fn duplicate_adaptor_material_rejected() {
        let mut alice = HandshakeSession::new_alice("s".into());
        let mut bob = HandshakeSession::new_bob("s".into());
        let h = bob.start_bob(dummy_pub(1), dummy_pub(2)).unwrap();
        alice.handle_inbound(h).unwrap();
        let a = alice
            .respond_with_hello_ack(dummy_pub(3), dummy_pub(4), safe_params())
            .unwrap();
        bob.handle_inbound(a).unwrap();
        let acc = bob.accept().unwrap();
        alice.handle_inbound(acc).unwrap();
        // Bob sends his adaptors twice — second one is a peer bug
        let bob_adapt = bob
            .send_adaptors(dummy_blob(1), dummy_blob(2), dummy_blob(3), dummy_blob(4))
            .unwrap();
        let _ = alice.handle_inbound(bob_adapt.clone()).unwrap();
        let result = alice.handle_inbound(bob_adapt);
        assert!(matches!(result, Err(HandshakeError::Duplicate { .. })));
    }

    #[test]
    fn abort_from_any_phase_terminates() {
        let phases_to_test = [
            Phase::Initial,
            Phase::AwaitingAck,
            Phase::ExchangingAdaptors,
            Phase::AwaitingReady,
        ];
        for phase in phases_to_test {
            let mut s = HandshakeSession::new_alice("s".into());
            s.phase = phase;
            let action = s
                .handle_inbound(Message::Abort {
                    reason: "test".into(),
                })
                .unwrap();
            assert!(matches!(action, HandshakeAction::Aborted { .. }));
            assert_eq!(s.phase, Phase::Aborted);
        }
    }

    #[test]
    fn aborted_session_rejects_further_messages() {
        let mut s = HandshakeSession::new_alice("s".into());
        let _ = s.send_abort("operator quit");
        assert_eq!(s.phase, Phase::Aborted);
        let result = s.handle_inbound(Message::Hello {
            swap_id: "s".into(),
            bob_btc_pubkey: dummy_pub(1),
            bob_cync_pubkey: dummy_pub(2),
        });
        assert!(matches!(result, Err(HandshakeError::Terminal(_))));
    }

    #[test]
    fn unsafe_parameters_rejected_in_hello_ack() {
        let mut alice = HandshakeSession::new_alice("s".into());
        let mut bob = HandshakeSession::new_bob("s".into());
        let h = bob.start_bob(dummy_pub(1), dummy_pub(2)).unwrap();
        alice.handle_inbound(h).unwrap();
        // Construct unsafe parameters (btc much larger than cync)
        let mut bad_params = safe_params();
        bad_params.btc_timeout_blocks = 1000;
        bad_params.cync_timeout_blocks = 100;
        let result = alice.respond_with_hello_ack(dummy_pub(3), dummy_pub(4), bad_params);
        assert!(matches!(result, Err(HandshakeError::OutOfOrder { .. })));
    }

    #[test]
    fn double_send_adaptors_rejected() {
        let mut s = HandshakeSession::new_alice("s".into());
        s.phase = Phase::ExchangingAdaptors;
        let _ = s
            .send_adaptors(dummy_blob(1), dummy_blob(2), dummy_blob(3), dummy_blob(4))
            .unwrap();
        let result = s.send_adaptors(dummy_blob(5), dummy_blob(6), dummy_blob(7), dummy_blob(8));
        assert!(matches!(result, Err(HandshakeError::Duplicate { .. })));
    }

    #[test]
    fn phase_advances_correctly_through_adaptor_exchange() {
        let mut alice = HandshakeSession::new_alice("s".into());
        let mut bob = HandshakeSession::new_bob("s".into());
        // Step into ExchangingAdaptors
        let h = bob.start_bob(dummy_pub(1), dummy_pub(2)).unwrap();
        alice.handle_inbound(h).unwrap();
        let a = alice
            .respond_with_hello_ack(dummy_pub(3), dummy_pub(4), safe_params())
            .unwrap();
        bob.handle_inbound(a).unwrap();
        let acc = bob.accept().unwrap();
        alice.handle_inbound(acc).unwrap();
        assert_eq!(alice.phase, Phase::ExchangingAdaptors);
        assert_eq!(bob.phase, Phase::ExchangingAdaptors);
        // Alice sends but hasn't received -> still ExchangingAdaptors
        let _ = alice
            .send_adaptors(dummy_blob(1), dummy_blob(2), dummy_blob(3), dummy_blob(4))
            .unwrap();
        assert_eq!(alice.phase, Phase::ExchangingAdaptors);
        // Bob sends + Alice receives -> Alice advances to AwaitingReady
        let bob_adapt = bob
            .send_adaptors(dummy_blob(5), dummy_blob(6), dummy_blob(7), dummy_blob(8))
            .unwrap();
        let _ = alice.handle_inbound(bob_adapt).unwrap();
        assert_eq!(alice.phase, Phase::AwaitingReady);
    }

    #[test]
    fn coordinator_listen_still_unimplemented() {
        // Phase 2 keeps the transport stub for phase 3.
        let result = Coordinator::listen("127.0.0.1:0");
        assert!(matches!(result, Err(Error::NotImplemented { .. })));
    }
}
