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
    /// The state machine has advanced internally but cannot produce
    /// the next outbound message itself — the application layer must
    /// call a specific session method (named in `next_call`) to
    /// supply the locally-held data (pubkeys, parameters, adaptor
    /// material). Transport layers MUST NOT transmit anything in
    /// response to this action.
    ///
    /// Earlier code returned a placeholder `Send(Message::Abort{..})`
    /// here, which a naïve "loop and forward" transport would have
    /// turned into a real abort. Splitting it into a distinct variant
    /// makes the contract type-checked.
    WaitForCaller { next_call: &'static str },
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
                // Alice's HelloAck depends on locally-held data
                // (her pubkeys + the parameters she'll propose).
                // The caller drives that via respond_with_hello_ack.
                Ok(HandshakeAction::WaitForCaller {
                    next_call: "respond_with_hello_ack",
                })
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
                // Bob needs to decide accept or abort based on
                // whether the parameters are satisfactory.
                self.phase = Phase::AwaitingAck;
                Ok(HandshakeAction::WaitForCaller {
                    next_call: "accept_or_send_abort",
                })
            }

            // ── Alice receives Accept from Bob ──
            (Message::Accept, Role::Alice, Phase::AwaitingAck) => {
                // Negotiation moves into adaptor exchange. Alice's
                // adaptors are produced by her wallet; the caller
                // drives that via send_adaptors().
                self.phase = Phase::ExchangingAdaptors;
                Ok(HandshakeAction::WaitForCaller {
                    next_call: "send_adaptors",
                })
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

// ──────────────────────────────────────────────────────────────────
// Transport (TCP + length-prefixed JSON framing)
// ──────────────────────────────────────────────────────────────────
//
// Plain TCP, length-prefixed JSON-serialized messages. This is the
// **minimal** transport — sufficient for localhost-to-localhost
// testing and trusted-network deployment but does NOT provide
// confidentiality or integrity over an untrusted link. The Noise
// layer (CIP-001 §6 "Network privacy") wraps this transport without
// changing its API: the future `NoiseTransport` exposes the same
// `send`/`recv` shape. Tor goes one more layer outside, treating
// either transport as an opaque byte stream over a SOCKS proxy.
//
// Why JSON over Bincode for the wire? Three reasons:
//   1. Debuggability — handshake messages on the wire are
//      human-readable in packet captures during testnet shakeouts.
//   2. Schema flexibility — adding a field to `Message` doesn't
//      invalidate older transcripts the way Bincode's positional
//      encoding would.
//   3. Negotiation messages are infrequent + small (≤ ~100 KB even
//      with a strict-DLEQ proof attached); the JSON overhead is
//      irrelevant at this volume.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Maximum length of a single wire message in bytes. Protects the
/// receiver against a malicious sender claiming a multi-gigabyte
/// frame. 16 MiB is well above the worst-case strict-DLEQ proof
/// (~81 KB) with comfortable headroom.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Default per-operation socket timeout. Handshake messages should
/// round-trip in milliseconds on a healthy link; 30 s catches a
/// dropped peer without making the operator stare at a frozen CLI.
const DEFAULT_SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// Length-prefixed JSON message transport over a single TCP socket.
/// Use [`Coordinator::listen`] / [`Coordinator::connect`] to
/// construct — this struct is exposed for advanced callers who need
/// raw transport access (e.g., to layer Noise on top in a future
/// slice).
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Bind to `endpoint` (e.g. `"127.0.0.1:9000"` or
    /// `"0.0.0.0:9000"`), accept exactly one inbound connection,
    /// and return the transport for that peer. Alice's role.
    ///
    /// Each swap is a 1:1 pairing; if Alice wants multiple
    /// concurrent swaps she runs multiple listeners.
    pub fn bind_and_accept(endpoint: &str) -> Result<Self> {
        let addrs: Vec<_> = endpoint
            .to_socket_addrs()
            .map_err(|e| Error::Rpc(format!("TCP resolve {endpoint}: {e}")))?
            .collect();
        let listener = TcpListener::bind(addrs.as_slice())
            .map_err(|e| Error::Rpc(format!("TCP bind {endpoint}: {e}")))?;
        let (stream, _peer) = listener
            .accept()
            .map_err(|e| Error::Rpc(format!("TCP accept on {endpoint}: {e}")))?;
        Self::configure(stream)
    }

    /// Connect to `endpoint`. Bob's role.
    pub fn dial(endpoint: &str) -> Result<Self> {
        let stream = TcpStream::connect(endpoint)
            .map_err(|e| Error::Rpc(format!("TCP dial {endpoint}: {e}")))?;
        Self::configure(stream)
    }

    fn configure(stream: TcpStream) -> Result<Self> {
        stream
            .set_read_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
            .map_err(|e| Error::Rpc(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
            .map_err(|e| Error::Rpc(format!("set_write_timeout: {e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| Error::Rpc(format!("set_nodelay: {e}")))?;
        Ok(Self { stream })
    }

    /// Override the per-operation socket timeout. Useful for tests
    /// that want a tighter bound. Affects both read and write.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::Rpc(format!("set_read_timeout: {e}")))?;
        self.stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::Rpc(format!("set_write_timeout: {e}")))?;
        Ok(())
    }

    /// Serialize `msg` to JSON, prepend a 4-byte BE length prefix,
    /// and write the frame to the socket.
    pub fn send(&mut self, msg: &Message) -> Result<()> {
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| Error::Rpc(format!("JSON serialize Message: {e}")))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(Error::Rpc(format!(
                "outbound frame {} bytes exceeds MAX_FRAME_BYTES {}",
                bytes.len(),
                MAX_FRAME_BYTES
            )));
        }
        let len = (bytes.len() as u32).to_be_bytes();
        self.stream
            .write_all(&len)
            .map_err(|e| Error::Rpc(format!("TCP write length: {e}")))?;
        self.stream
            .write_all(&bytes)
            .map_err(|e| Error::Rpc(format!("TCP write body: {e}")))?;
        self.stream
            .flush()
            .map_err(|e| Error::Rpc(format!("TCP flush: {e}")))?;
        Ok(())
    }

    /// Read a 4-byte BE length prefix, then read that many bytes,
    /// then JSON-deserialize into a [`Message`]. Errors on EOF,
    /// timeout, oversized frame, or malformed JSON.
    pub fn recv(&mut self) -> Result<Message> {
        let body = recv_framed_bytes(&mut self.stream)?;
        serde_json::from_slice(&body)
            .map_err(|e| Error::Rpc(format!("JSON deserialize Message: {e}")))
    }
}

/// Low-level: read a 4-byte BE length prefix + N bytes from the
/// stream. Reused by [`NoiseTransport`] for both handshake messages
/// and post-handshake AEAD-encrypted payloads.
fn recv_framed_bytes(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| Error::Rpc(format!("TCP read length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::Rpc(format!(
            "inbound frame {len} bytes exceeds MAX_FRAME_BYTES {MAX_FRAME_BYTES}"
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| Error::Rpc(format!("TCP read body ({len} bytes): {e}")))?;
    Ok(body)
}

/// Low-level: write a 4-byte BE length prefix + N bytes to the
/// stream, then flush. Reused by [`NoiseTransport`].
fn send_framed_bytes(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::Rpc(format!(
            "outbound frame {} bytes exceeds MAX_FRAME_BYTES {}",
            bytes.len(),
            MAX_FRAME_BYTES
        )));
    }
    let len = (bytes.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|e| Error::Rpc(format!("TCP write length: {e}")))?;
    stream
        .write_all(bytes)
        .map_err(|e| Error::Rpc(format!("TCP write body: {e}")))?;
    stream
        .flush()
        .map_err(|e| Error::Rpc(format!("TCP flush: {e}")))?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// Noise transport (XX pattern over TCP)
// ──────────────────────────────────────────────────────────────────
//
// Wraps [`TcpStream`] with a Noise XX handshake establishing a
// mutually-authenticated AEAD-encrypted session. Cipher suite:
// `Noise_XX_25519_ChaChaPoly_BLAKE2s`. After handshake completes,
// every outbound [`Message`] is JSON-serialized, encrypted with the
// session key (16-byte AEAD tag appended per message), and framed
// the same way [`TcpTransport`] frames plaintext — so the wire
// format on the listener side is interchangeable: the responder
// learns whether it's a Plain or Noise client from which constructor
// the operator chose, not from any byte-level signal.
//
// Why XX?
//   - Both parties learn each other's long-term Curve25519 static key
//     during the handshake (3 messages). This is the standard "mutual-
//     auth without prior knowledge of the peer's key" pattern.
//   - Caller is expected to verify the negotiated remote-static-key
//     against an out-of-band expectation (e.g., posted alongside the
//     swap_id) via [`NoiseTransport::remote_static`]. Without that
//     check, the protocol is vulnerable to active MitM on the first
//     connection.

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise message size per the spec: 65535 bytes including the
/// 16-byte AEAD tag. Our handshake messages fit well within this; for
/// post-handshake [`Message`] payloads larger than ~65 KiB we'd need
/// to chunk + reassemble. The largest expected message is a
/// strict-DLEQ proof (~81 KB); see the chunking logic in
/// [`NoiseTransport::send`].
const NOISE_MAX_MESSAGE: usize = 65535;

/// Max plaintext per Noise message (accounting for the 16-byte AEAD
/// tag overhead).
const NOISE_MAX_PLAINTEXT: usize = NOISE_MAX_MESSAGE - 16;

/// TCP transport wrapped with a Noise XX session. Handshake completes
/// in the constructor; the resulting struct is ready for
/// [`send`](Self::send) / [`recv`](Self::recv).
pub struct NoiseTransport {
    stream: TcpStream,
    cipher: snow::TransportState,
    remote_static: [u8; 32],
}

impl std::fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseTransport")
            .field("remote_static", &hex::encode(self.remote_static))
            .finish_non_exhaustive()
    }
}

impl NoiseTransport {
    /// Initiator (client) role. Drives the XX handshake to completion
    /// over the supplied [`TcpStream`]. After this returns,
    /// `self.remote_static()` gives the responder's long-term key —
    /// the caller MUST compare it against an out-of-band expectation
    /// before proceeding.
    pub fn handshake_initiator(
        mut stream: TcpStream,
        local_static_key: &[u8; 32],
    ) -> Result<Self> {
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| Error::Rpc(format!("Noise params parse: {e}")))?;
        let mut handshake = snow::Builder::new(params)
            .local_private_key(local_static_key)
            .build_initiator()
            .map_err(|e| Error::Rpc(format!("Noise builder initiator: {e}")))?;

        let mut buf = vec![0u8; NOISE_MAX_MESSAGE];

        // Message 1: -> e
        let n = handshake
            .write_message(&[], &mut buf)
            .map_err(|e| Error::Rpc(format!("Noise XX msg1 write: {e}")))?;
        send_framed_bytes(&mut stream, &buf[..n])?;

        // Message 2: <- e, ee, s, es
        let frame = recv_framed_bytes(&mut stream)?;
        let mut payload = vec![0u8; NOISE_MAX_MESSAGE];
        handshake
            .read_message(&frame, &mut payload)
            .map_err(|e| Error::Rpc(format!("Noise XX msg2 read: {e}")))?;

        // Message 3: -> s, se
        let n = handshake
            .write_message(&[], &mut buf)
            .map_err(|e| Error::Rpc(format!("Noise XX msg3 write: {e}")))?;
        send_framed_bytes(&mut stream, &buf[..n])?;

        Self::finalize(stream, handshake)
    }

    /// Responder (server) role. Drives the XX handshake to completion.
    /// After this returns, `self.remote_static()` gives the initiator's
    /// long-term key.
    pub fn handshake_responder(
        mut stream: TcpStream,
        local_static_key: &[u8; 32],
    ) -> Result<Self> {
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| Error::Rpc(format!("Noise params parse: {e}")))?;
        let mut handshake = snow::Builder::new(params)
            .local_private_key(local_static_key)
            .build_responder()
            .map_err(|e| Error::Rpc(format!("Noise builder responder: {e}")))?;

        let mut buf = vec![0u8; NOISE_MAX_MESSAGE];

        // Message 1: <- e
        let frame = recv_framed_bytes(&mut stream)?;
        handshake
            .read_message(&frame, &mut buf)
            .map_err(|e| Error::Rpc(format!("Noise XX msg1 read: {e}")))?;

        // Message 2: -> e, ee, s, es
        let n = handshake
            .write_message(&[], &mut buf)
            .map_err(|e| Error::Rpc(format!("Noise XX msg2 write: {e}")))?;
        send_framed_bytes(&mut stream, &buf[..n])?;

        // Message 3: <- s, se
        let frame = recv_framed_bytes(&mut stream)?;
        handshake
            .read_message(&frame, &mut buf)
            .map_err(|e| Error::Rpc(format!("Noise XX msg3 read: {e}")))?;

        Self::finalize(stream, handshake)
    }

    /// Transition `handshake` into transport mode + snapshot the
    /// remote static key. Shared post-handshake setup for both roles.
    fn finalize(stream: TcpStream, handshake: snow::HandshakeState) -> Result<Self> {
        let remote_static_slice = handshake
            .get_remote_static()
            .ok_or(Error::Rpc(format!(
                "Noise XX handshake completed without remote static key"
            )))?;
        if remote_static_slice.len() != 32 {
            return Err(Error::Rpc(format!(
                "Noise XX remote static key has unexpected length {}",
                remote_static_slice.len()
            )));
        }
        let mut remote_static = [0u8; 32];
        remote_static.copy_from_slice(remote_static_slice);

        let cipher = handshake
            .into_transport_mode()
            .map_err(|e| Error::Rpc(format!("Noise into_transport_mode: {e}")))?;
        Ok(Self {
            stream,
            cipher,
            remote_static,
        })
    }

    /// The counterparty's long-term Curve25519 static public key,
    /// learned during the XX handshake. **Callers MUST verify** this
    /// against an out-of-band expectation (e.g., a fingerprint
    /// published alongside the `swap_id`) before relying on the
    /// session — without that check the protocol is vulnerable to
    /// an active MitM on the first connection.
    pub fn remote_static(&self) -> [u8; 32] {
        self.remote_static
    }

    /// Override the per-operation socket timeout.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::Rpc(format!("set_read_timeout: {e}")))?;
        self.stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::Rpc(format!("set_write_timeout: {e}")))?;
        Ok(())
    }

    /// JSON-serialize `msg`, AEAD-encrypt the result, frame each
    /// Noise chunk with a 4-byte BE length prefix on the wire.
    /// Messages larger than `NOISE_MAX_PLAINTEXT` (~65 KiB minus the
    /// AEAD tag) are split across multiple AEAD frames — the
    /// outer length-prefixed wrapper carries a 4-byte "chunk count"
    /// header so the receiver knows how many AEAD frames make up a
    /// single logical [`Message`].
    pub fn send(&mut self, msg: &Message) -> Result<()> {
        let plaintext = serde_json::to_vec(msg)
            .map_err(|e| Error::Rpc(format!("JSON serialize Message: {e}")))?;
        let chunks = plaintext.chunks(NOISE_MAX_PLAINTEXT).collect::<Vec<_>>();
        if chunks.len() > u32::MAX as usize {
            return Err(Error::Rpc(format!(
                "Message too large to chunk: {} > {} chunks max",
                chunks.len(),
                u32::MAX
            )));
        }

        // Header frame: 4-byte BE chunk count. Sent as its own length-
        // prefixed frame so the receiver knows how many AEAD frames
        // to pull off the wire next.
        send_framed_bytes(&mut self.stream, &(chunks.len() as u32).to_be_bytes())?;

        let mut ciphertext = vec![0u8; NOISE_MAX_MESSAGE];
        for chunk in chunks {
            let n = self
                .cipher
                .write_message(chunk, &mut ciphertext)
                .map_err(|e| Error::Rpc(format!("Noise AEAD encrypt: {e}")))?;
            send_framed_bytes(&mut self.stream, &ciphertext[..n])?;
        }
        Ok(())
    }

    /// Read the chunk-count header, then the AEAD-encrypted chunks,
    /// decrypt + concatenate, JSON-deserialize.
    pub fn recv(&mut self) -> Result<Message> {
        let count_frame = recv_framed_bytes(&mut self.stream)?;
        if count_frame.len() != 4 {
            return Err(Error::Rpc(format!(
                "Noise recv: expected 4-byte chunk header, got {} bytes",
                count_frame.len()
            )));
        }
        let chunk_count = u32::from_be_bytes(
            count_frame
                .as_slice()
                .try_into()
                .map_err(|_| Error::Rpc("chunk count length".to_string()))?,
        ) as usize;
        if chunk_count == 0 {
            return Err(Error::Rpc(
                "Noise recv: zero-chunk message is malformed".into(),
            ));
        }
        // Cap chunk_count to prevent a malicious sender claiming a
        // huge count and forcing us to do many reads before the AEAD
        // check fails. 1024 chunks of NOISE_MAX_PLAINTEXT bytes ≈ 64
        // MiB, well above any legitimate handshake message.
        if chunk_count > 1024 {
            return Err(Error::Rpc(format!(
                "Noise recv: chunk count {chunk_count} exceeds cap (1024)"
            )));
        }

        let mut plaintext = Vec::with_capacity(chunk_count * NOISE_MAX_PLAINTEXT);
        let mut buf = vec![0u8; NOISE_MAX_MESSAGE];
        for _ in 0..chunk_count {
            let frame = recv_framed_bytes(&mut self.stream)?;
            let n = self
                .cipher
                .read_message(&frame, &mut buf)
                .map_err(|e| Error::Rpc(format!("Noise AEAD decrypt: {e}")))?;
            plaintext.extend_from_slice(&buf[..n]);
        }

        serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Rpc(format!("JSON deserialize Message: {e}")))
    }
}

/// Derive the Curve25519 public key matching a 32-byte X25519
/// private key, following the RFC 7748 clamping that snow uses
/// internally. The result is byte-for-byte identical to what
/// `NoiseTransport::remote_static()` reports on the peer side after
/// a successful XX handshake — so this function is the canonical
/// way to compute "the fingerprint the OTHER party will see."
///
/// Use this for:
/// - Pre-generating Noise static keypairs at operator-setup time
///   (the operator publishes the derived public key as the
///   out-of-band fingerprint).
/// - Validating that a stored private key still produces the
///   expected published fingerprint (`derived == published`).
///
/// Does NOT validate the input is a "good" private key — every
/// 32-byte string is a valid X25519 private after clamping. If the
/// caller wants randomness, generate `[u8; 32]` from `OsRng`.
pub fn derive_noise_static_public(private: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::constants::X25519_BASEPOINT;
    // RFC 7748 §5 X25519 clamping: clear the bottom 3 bits of
    // byte 0, clear the top bit of byte 31, set bit 254 of the
    // little-endian scalar (which is bit 6 of byte 31). snow does
    // this internally; we replicate to get the same public key.
    let mut clamped = *private;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    X25519_BASEPOINT.mul_clamped(clamped).to_bytes()
}

// ──────────────────────────────────────────────────────────────────
// SOCKS5 CONNECT (for Tor / proxy dial)
// ──────────────────────────────────────────────────────────────────
//
// SOCKS5 CONNECT helper. Thin wrapper around the `socks` crate; we
// keep this fn (rather than inlining the crate call at every caller)
// so the validation + timeout + nodelay policy stays in one place.
// Was hand-rolled (~166 LOC) until commit replacing it with the crate
// — see audit-prep §5 priority 9 closure.
//
// The target hostname is passed through to the proxy as a domain
// string (ATYP=DOMAINNAME), NOT resolved client-side. This is the
// required behavior for Tor: the .onion address has no public DNS
// entry; only Tor's hidden-service directory can resolve it. The
// `socks` crate produces ATYP=DOMAINNAME when given a `(&str, u16)`
// tuple as the target (the `ToTargetAddr` impl for that pair).

/// SOCKS5 CONNECT through `proxy_addr` to `target_host:target_port`.
/// Returns the established TCP socket on success.
///
/// `target_host` is sent as ATYP=DOMAINNAME (forced) — required for
/// .onion addresses, harmless for regular hostnames. Length must
/// fit in one byte (≤ 255 chars); all real-world hostnames including
/// v3 .onion addresses (62 chars) fit comfortably.
///
/// # Errors
///
/// - `Error::Rpc` on TCP connect failure, SOCKS5 protocol violation,
///   or non-zero reply code from the proxy.
fn socks5_connect_domain(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    // Pre-validate before handing to the crate: an empty or
    // over-length host would be either accepted-and-silently-corrupt
    // or rejected with an unhelpful inner error. Explicit checks here
    // surface the bug at the caller's boundary.
    if target_host.is_empty() {
        return Err(Error::Rpc("SOCKS5: empty target host".into()));
    }
    if target_host.len() > 255 {
        return Err(Error::Rpc(format!(
            "SOCKS5: target host {} chars > 255 (max for ATYP=DOMAINNAME)",
            target_host.len()
        )));
    }

    // `(target_host, target_port)` -> ATYP=DOMAINNAME via the crate's
    // `ToTargetAddr` impl for `(&str, u16)`. No client-side DNS
    // resolution happens — the host string is sent verbatim to the
    // proxy. This is the critical Tor property; see the ATYP=3 path
    // in the audit-prep doc §5 priority 9.
    let s = socks::Socks5Stream::connect(proxy_addr, (target_host, target_port))
        .map_err(|e| {
            Error::Rpc(format!(
                "SOCKS5 CONNECT to {target_host}:{target_port} via {proxy_addr}: {e}"
            ))
        })?;

    let stream = s.into_inner();
    stream
        .set_read_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
        .map_err(|e| Error::Rpc(format!("SOCKS5 set_read_timeout: {e}")))?;
    stream
        .set_write_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
        .map_err(|e| Error::Rpc(format!("SOCKS5 set_write_timeout: {e}")))?;
    stream
        .set_nodelay(true)
        .map_err(|e| Error::Rpc(format!("SOCKS5 tunneled set_nodelay: {e}")))?;
    Ok(stream)
}

// ──────────────────────────────────────────────────────────────────
// Coordinator: TCP-backed handshake driver
// ──────────────────────────────────────────────────────────────────

/// The pubkey pair each party brings to the handshake. Opaque bytes
/// — wire format matches whatever the cryptographic layer produces
/// (33-byte compressed secp256k1 for BTC, 32-byte Ristretto for
/// CYNC), but the coordinator doesn't decode them.
#[derive(Clone, Debug)]
pub struct Pubkeys {
    pub btc: Vec<u8>,
    pub cync: Vec<u8>,
}

/// The adaptor material each party sends in
/// `Message::AdaptorMaterial`. Same opaque-bytes posture as
/// [`Pubkeys`] — cryptographic verification is the caller's
/// `AdaptorVerifier` callback.
#[derive(Clone, Debug)]
pub struct AdaptorBundle {
    pub btc_adaptor: Vec<u8>,
    pub cync_adaptor: Vec<u8>,
    pub dl_proof: Vec<u8>,
    pub refund_tx: Vec<u8>,
}

/// Callback signature for verifying the counterparty's adaptor
/// material. Boxed-Fn so it can capture cryptographic key state
/// from the caller's environment without bleeding generics into
/// `Coordinator`. Returns `Ok(())` on accept; any `Err` aborts the
/// handshake and propagates to the `run_*` caller.
pub type AdaptorVerifier<'a> = Box<dyn FnOnce(&AdaptorBundle) -> Result<()> + 'a>;

/// Sum type wrapping either a plain [`TcpTransport`] or a
/// [`NoiseTransport`] under the same `send`/`recv` interface, so
/// [`Coordinator::run_alice`] / [`Coordinator::run_bob`] don't have
/// to be generic in the transport. Constructed via the
/// `Coordinator::{listen, connect, listen_noise, connect_noise}`
/// pairs.
#[derive(Debug)]
pub enum CoordTransport {
    Plain(TcpTransport),
    Noise(NoiseTransport),
}

impl CoordTransport {
    fn send(&mut self, msg: &Message) -> Result<()> {
        match self {
            Self::Plain(t) => t.send(msg),
            Self::Noise(t) => t.send(msg),
        }
    }

    fn recv(&mut self) -> Result<Message> {
        match self {
            Self::Plain(t) => t.recv(),
            Self::Noise(t) => t.recv(),
        }
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        match self {
            Self::Plain(t) => t.set_timeout(timeout),
            Self::Noise(t) => t.set_timeout(timeout),
        }
    }
}

/// One side of an active coordination session — TCP (or Noise-wrapped
/// TCP) transport plus the per-role [`HandshakeSession`] state
/// machine, with a driver that runs the protocol to completion.
#[derive(Debug)]
pub struct Coordinator {
    transport: CoordTransport,
    session: HandshakeSession,
}

impl Coordinator {
    /// Construct Alice's side: bind to `endpoint`, accept one
    /// inbound connection, return a `Coordinator` ready for
    /// [`run_alice`](Self::run_alice). Caller is expected to have
    /// already published `swap_id` out-of-band so Bob knows what to
    /// connect with.
    ///
    /// Uses plain TCP — no confidentiality or integrity over the
    /// link. Pair Alice with [`connect`](Self::connect) for the
    /// plaintext transport, or use the
    /// [`listen_noise`](Self::listen_noise) / `connect_noise` pair
    /// for the Noise XX wrapper.
    pub fn listen(endpoint: &str, swap_id: String) -> Result<Self> {
        let transport = TcpTransport::bind_and_accept(endpoint)?;
        let session = HandshakeSession::new_alice(swap_id);
        Ok(Self {
            transport: CoordTransport::Plain(transport),
            session,
        })
    }

    /// Construct Bob's side over plain TCP. Mirror of
    /// [`listen`](Self::listen). For Noise-wrapped TCP use
    /// [`connect_noise`](Self::connect_noise).
    pub fn connect(endpoint: &str, swap_id: String) -> Result<Self> {
        let transport = TcpTransport::dial(endpoint)?;
        let session = HandshakeSession::new_bob(swap_id);
        Ok(Self {
            transport: CoordTransport::Plain(transport),
            session,
        })
    }

    /// Construct Alice's side wrapped in a Noise XX handshake. Bind
    /// + accept the TCP connection, then run the XX handshake as
    /// responder. After this returns, the [`HandshakeSession`] is
    /// in `Initial` (ready for the swap-level protocol), and
    /// `self.remote_static()` exposes Bob's long-term Curve25519
    /// static key for **out-of-band fingerprint verification** —
    /// without that check the protocol is vulnerable to active MitM.
    pub fn listen_noise(
        endpoint: &str,
        swap_id: String,
        local_static_key: &[u8; 32],
    ) -> Result<Self> {
        use std::net::TcpListener;
        // We can't reuse TcpTransport::bind_and_accept here because
        // it eats the raw stream into its own struct; for Noise we
        // need the raw stream to hand to NoiseTransport's handshake.
        let listener = TcpListener::bind(endpoint)
            .map_err(|e| Error::Rpc(format!("TCP bind {endpoint}: {e}")))?;
        let (stream, _peer) = listener
            .accept()
            .map_err(|e| Error::Rpc(format!("TCP accept on {endpoint}: {e}")))?;
        stream
            .set_read_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
            .map_err(|e| Error::Rpc(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
            .map_err(|e| Error::Rpc(format!("set_write_timeout: {e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| Error::Rpc(format!("set_nodelay: {e}")))?;

        let transport = NoiseTransport::handshake_responder(stream, local_static_key)?;
        let session = HandshakeSession::new_alice(swap_id);
        Ok(Self {
            transport: CoordTransport::Noise(transport),
            session,
        })
    }

    /// Construct Bob's side wrapped in a Noise XX handshake. Mirror
    /// of [`listen_noise`](Self::listen_noise); runs the XX
    /// handshake as initiator after dialing Alice. Same MitM
    /// caveat: caller MUST verify `self.remote_static()` against an
    /// out-of-band expectation.
    pub fn connect_noise(
        endpoint: &str,
        swap_id: String,
        local_static_key: &[u8; 32],
    ) -> Result<Self> {
        let stream = TcpStream::connect(endpoint)
            .map_err(|e| Error::Rpc(format!("TCP dial {endpoint}: {e}")))?;
        stream
            .set_read_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
            .map_err(|e| Error::Rpc(format!("set_read_timeout: {e}")))?;
        stream
            .set_write_timeout(Some(DEFAULT_SOCKET_TIMEOUT))
            .map_err(|e| Error::Rpc(format!("set_write_timeout: {e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| Error::Rpc(format!("set_nodelay: {e}")))?;

        let transport = NoiseTransport::handshake_initiator(stream, local_static_key)?;
        let session = HandshakeSession::new_bob(swap_id);
        Ok(Self {
            transport: CoordTransport::Noise(transport),
            session,
        })
    }

    /// **DoS-hardened** version of [`listen`](Self::listen). Binds
    /// `endpoint`, then loops on `accept` + Hello-validation: a peer
    /// that doesn't deliver a valid Hello message matching `swap_id`
    /// within `peer_timeout` is dropped and the next peer's
    /// connection is tried. Up to `max_attempts` peers are tried
    /// before giving up.
    ///
    /// Returns a Coordinator **already past the Hello-receive step**
    /// — the [`HandshakeSession`] is in `AwaitingAck` with the
    /// counterparty's pubkeys cached. Pair with
    /// [`run_alice_post_hello`](Self::run_alice_post_hello), NOT
    /// [`run_alice`](Self::run_alice). The "post Hello" naming
    /// makes the contract obvious to callers; calling `run_alice`
    /// on a filtered-listen coordinator would deadlock waiting for a
    /// Hello that's already been consumed.
    ///
    /// Why bother? `listen` accepts exactly one connection — a
    /// griefer who beats the legitimate Bob to the port will
    /// consume Alice's slot and force her to restart. With
    /// `listen_filtered`, Alice keeps listening until a peer that
    /// actually has the right `swap_id` connects.
    ///
    /// `max_attempts` upper-bounds the resource cost of a sustained
    /// connect-flood attack. 100 is a reasonable production
    /// default; integration tests usually want 2 or 3 so the
    /// "exhausted attempts" path is exercisable.
    pub fn listen_filtered(
        endpoint: &str,
        swap_id: String,
        peer_timeout: Duration,
        max_attempts: u32,
    ) -> Result<Self> {
        if max_attempts == 0 {
            return Err(Error::Rpc(
                "listen_filtered: max_attempts must be ≥ 1".into(),
            ));
        }
        use std::net::TcpListener;
        let listener = TcpListener::bind(endpoint)
            .map_err(|e| Error::Rpc(format!("TCP bind {endpoint}: {e}")))?;

        let mut last_err: Option<String> = None;
        for attempt in 1..=max_attempts {
            let (stream, peer_addr) = listener.accept().map_err(|e| {
                Error::Rpc(format!("TCP accept on {endpoint} attempt {attempt}: {e}"))
            })?;
            // Per-peer (short) timeout while we wait for their Hello.
            // Restored to DEFAULT_SOCKET_TIMEOUT below if validation
            // succeeds.
            if let Err(e) = stream.set_read_timeout(Some(peer_timeout)) {
                last_err = Some(format!("attempt {attempt}: set_read_timeout: {e}"));
                continue;
            }
            if let Err(e) = stream.set_write_timeout(Some(peer_timeout)) {
                last_err = Some(format!("attempt {attempt}: set_write_timeout: {e}"));
                continue;
            }
            let _ = stream.set_nodelay(true);

            let mut transport = TcpTransport { stream };
            match validate_hello_plain(&mut transport, &swap_id) {
                Ok(session) => {
                    // Restore production timeout for the remainder of
                    // the handshake.
                    if let Err(e) = transport.set_timeout(DEFAULT_SOCKET_TIMEOUT) {
                        return Err(Error::Rpc(format!(
                            "listen_filtered: restore timeout: {e}"
                        )));
                    }
                    return Ok(Self {
                        transport: CoordTransport::Plain(transport),
                        session,
                    });
                }
                Err(e) => {
                    last_err =
                        Some(format!("attempt {attempt} (peer {peer_addr}): {e}"));
                    // Drop transport → close stream → loop.
                    continue;
                }
            }
        }
        Err(Error::Rpc(format!(
            "listen_filtered: exhausted {max_attempts} attempts without a valid peer; last error: {}",
            last_err.unwrap_or_else(|| "(none recorded)".into())
        )))
    }

    /// DoS-hardened version of [`listen_noise`](Self::listen_noise).
    /// Same loop-on-bad-peer semantics as
    /// [`listen_filtered`](Self::listen_filtered), but each candidate
    /// peer must ALSO complete the Noise XX handshake before being
    /// allowed to send Hello — an attacker who can't do Noise (or
    /// times out during it) is filtered at that step.
    ///
    /// Returns a Coordinator with the Hello already processed and
    /// the Noise transport carrying the AEAD session. The
    /// counterparty's Curve25519 static key is accessible via
    /// [`remote_static`](Self::remote_static); **caller MUST verify
    /// it against an out-of-band expectation** before relying on
    /// the negotiated session — `listen_noise_filtered` does NOT
    /// authenticate by static key on its own.
    pub fn listen_noise_filtered(
        endpoint: &str,
        swap_id: String,
        local_static_key: &[u8; 32],
        peer_timeout: Duration,
        max_attempts: u32,
    ) -> Result<Self> {
        if max_attempts == 0 {
            return Err(Error::Rpc(
                "listen_noise_filtered: max_attempts must be ≥ 1".into(),
            ));
        }
        use std::net::TcpListener;
        let listener = TcpListener::bind(endpoint)
            .map_err(|e| Error::Rpc(format!("TCP bind {endpoint}: {e}")))?;

        let mut last_err: Option<String> = None;
        for attempt in 1..=max_attempts {
            let (stream, peer_addr) = listener.accept().map_err(|e| {
                Error::Rpc(format!("TCP accept on {endpoint} attempt {attempt}: {e}"))
            })?;
            if let Err(e) = stream.set_read_timeout(Some(peer_timeout)) {
                last_err = Some(format!("attempt {attempt}: set_read_timeout: {e}"));
                continue;
            }
            if let Err(e) = stream.set_write_timeout(Some(peer_timeout)) {
                last_err = Some(format!("attempt {attempt}: set_write_timeout: {e}"));
                continue;
            }
            let _ = stream.set_nodelay(true);

            // Noise handshake. A peer who can't complete this gets
            // filtered here — no Hello stage reached.
            let mut noise = match NoiseTransport::handshake_responder(stream, local_static_key)
            {
                Ok(t) => t,
                Err(e) => {
                    last_err =
                        Some(format!("attempt {attempt} (peer {peer_addr}) Noise: {e}"));
                    continue;
                }
            };

            match validate_hello_noise(&mut noise, &swap_id) {
                Ok(session) => {
                    if let Err(e) = noise.set_timeout(DEFAULT_SOCKET_TIMEOUT) {
                        return Err(Error::Rpc(format!(
                            "listen_noise_filtered: restore timeout: {e}"
                        )));
                    }
                    return Ok(Self {
                        transport: CoordTransport::Noise(noise),
                        session,
                    });
                }
                Err(e) => {
                    last_err =
                        Some(format!("attempt {attempt} (peer {peer_addr}): {e}"));
                    continue;
                }
            }
        }
        Err(Error::Rpc(format!(
            "listen_noise_filtered: exhausted {max_attempts} attempts without a valid peer; last error: {}",
            last_err.unwrap_or_else(|| "(none recorded)".into())
        )))
    }

    /// Drive Alice's side of the handshake to completion, starting
    /// from the **HelloAck send** step. Use this after
    /// [`listen_filtered`](Self::listen_filtered) or
    /// [`listen_noise_filtered`](Self::listen_noise_filtered),
    /// which already consumed + validated the inbound Hello.
    ///
    /// Calling this on a Coordinator built via the simple
    /// [`listen`](Self::listen) / [`listen_noise`](Self::listen_noise)
    /// constructors is a logic error — the session would still be
    /// in `Initial`, and `respond_with_hello_ack` would reject it.
    pub fn run_alice_post_hello<'a>(
        &mut self,
        alice_pubkeys: Pubkeys,
        params: SwapParameters,
        adaptors: AdaptorBundle,
        verifier: AdaptorVerifier<'a>,
    ) -> Result<()> {
        // ── Step 2: send HelloAck (step 1 was done by listen_filtered) ──
        let ack = self
            .session
            .respond_with_hello_ack(alice_pubkeys.btc, alice_pubkeys.cync, params)
            .map_err(|e| Error::Rpc(format!("Alice respond_with_hello_ack: {e}")))?;
        self.transport.send(&ack)?;

        // ── Step 3: recv Accept ──
        let accept = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(accept)
            .map_err(|e| Error::Rpc(format!("Alice recv Accept: {e}")))?;
        expect_wait_for(&action, "send_adaptors")?;

        // ── Step 4: send AdaptorMaterial ──
        let adapt = self
            .session
            .send_adaptors(
                adaptors.btc_adaptor,
                adaptors.cync_adaptor,
                adaptors.dl_proof,
                adaptors.refund_tx,
            )
            .map_err(|e| Error::Rpc(format!("Alice send_adaptors: {e}")))?;
        self.transport.send(&adapt)?;

        // ── Step 5: recv counterparty AdaptorMaterial, verify ──
        let bob_adapt = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(bob_adapt)
            .map_err(|e| Error::Rpc(format!("Alice recv AdaptorMaterial: {e}")))?;
        run_verifier(action, verifier)?;

        // ── Step 6: send Ready ──
        let ready = self
            .session
            .send_ready()
            .map_err(|e| Error::Rpc(format!("Alice send_ready: {e}")))?;
        self.transport.send(&ready)?;

        // ── Step 7: recv Ready → Negotiated ──
        let bob_ready = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(bob_ready)
            .map_err(|e| Error::Rpc(format!("Alice recv Ready: {e}")))?;
        expect_done(&action)
    }

    /// Return the counterparty's long-term Curve25519 static key if
    /// the underlying transport is Noise-wrapped. Returns `None` for
    /// the plain-TCP transport (which has no peer authentication).
    /// Callers MUST verify this against an out-of-band expectation
    /// before relying on the negotiated session.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        match &self.transport {
            CoordTransport::Plain(_) => None,
            CoordTransport::Noise(t) => Some(t.remote_static()),
        }
    }

    /// Connect to `target_host:target_port` via a SOCKS5 proxy at
    /// `proxy_addr`. The target host is sent as ATYP=DOMAINNAME so
    /// Tor's hidden-service directory can resolve `.onion` addresses
    /// without leaking a DNS query — required for the Tor use case.
    ///
    /// Bob's role. Plain TCP framing inside the tunnel — no
    /// confidentiality beyond what the proxy provides (Tor encrypts
    /// the circuit; a non-Tor SOCKS5 proxy generally does not). For
    /// strong end-to-end security pair this with
    /// [`connect_noise_via_socks5`](Self::connect_noise_via_socks5)
    /// instead.
    ///
    /// Example: connect Bob through a local Tor instance to Alice's
    /// hidden service:
    /// ```ignore
    /// let coord = Coordinator::connect_via_socks5(
    ///     "127.0.0.1:9050",                  // local Tor SOCKS5
    ///     "abcdef...onion", 9000,            // Alice's hidden service
    ///     swap_id,
    /// )?;
    /// ```
    pub fn connect_via_socks5(
        proxy_addr: &str,
        target_host: &str,
        target_port: u16,
        swap_id: String,
    ) -> Result<Self> {
        let stream = socks5_connect_domain(proxy_addr, target_host, target_port)?;
        let transport = TcpTransport::configure(stream)?;
        let session = HandshakeSession::new_bob(swap_id);
        Ok(Self {
            transport: CoordTransport::Plain(transport),
            session,
        })
    }

    /// Connect to `target_host:target_port` via SOCKS5 AND wrap the
    /// tunneled stream in a Noise XX handshake. The intended
    /// deployment: Bob's traffic to Alice's `.onion` hidden service
    /// is encrypted twice — once by Tor's circuit, once by the
    /// Noise XX session. The Noise layer additionally provides
    /// mutual authentication of long-term Curve25519 keys, which
    /// Tor alone does not.
    ///
    /// MitM caveat from [`connect_noise`](Self::connect_noise)
    /// applies: caller MUST verify `self.remote_static()` against
    /// an out-of-band expectation.
    pub fn connect_noise_via_socks5(
        proxy_addr: &str,
        target_host: &str,
        target_port: u16,
        swap_id: String,
        local_static_key: &[u8; 32],
    ) -> Result<Self> {
        let stream = socks5_connect_domain(proxy_addr, target_host, target_port)?;
        let transport = NoiseTransport::handshake_initiator(stream, local_static_key)?;
        let session = HandshakeSession::new_bob(swap_id);
        Ok(Self {
            transport: CoordTransport::Noise(transport),
            session,
        })
    }

    /// Get a reference to the underlying [`HandshakeSession`]. After
    /// a successful `run_*`, this gives access to the negotiated
    /// counterparty pubkeys + parameters via the session fields.
    pub fn session(&self) -> &HandshakeSession {
        &self.session
    }

    /// Override the per-operation socket timeout on the underlying
    /// transport. Most callers use the 30 s default; integration
    /// tests usually want something much tighter.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        self.transport.set_timeout(timeout)
    }

    /// Drive Alice's side of the handshake to completion:
    /// recv `Hello` → send `HelloAck` → recv `Accept` → send
    /// `AdaptorMaterial` → recv counterparty's `AdaptorMaterial`
    /// (call `verifier`) → send `Ready` → recv `Ready`.
    ///
    /// Returns `Ok(())` only if the session reaches
    /// `Phase::Negotiated`. Any handshake-layer error, transport
    /// I/O error, or verifier rejection aborts and propagates.
    pub fn run_alice<'a>(
        &mut self,
        alice_pubkeys: Pubkeys,
        params: SwapParameters,
        adaptors: AdaptorBundle,
        verifier: AdaptorVerifier<'a>,
    ) -> Result<()> {
        // ── 1. recv Hello ──
        let hello = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(hello)
            .map_err(|e| Error::Rpc(format!("Alice recv Hello: {e}")))?;
        expect_wait_for(&action, "respond_with_hello_ack")?;

        // ── 2. send HelloAck ──
        let ack = self
            .session
            .respond_with_hello_ack(alice_pubkeys.btc, alice_pubkeys.cync, params)
            .map_err(|e| Error::Rpc(format!("Alice respond_with_hello_ack: {e}")))?;
        self.transport.send(&ack)?;

        // ── 3. recv Accept ──
        let accept = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(accept)
            .map_err(|e| Error::Rpc(format!("Alice recv Accept: {e}")))?;
        expect_wait_for(&action, "send_adaptors")?;

        // ── 4. send AdaptorMaterial ──
        let adapt = self
            .session
            .send_adaptors(
                adaptors.btc_adaptor,
                adaptors.cync_adaptor,
                adaptors.dl_proof,
                adaptors.refund_tx,
            )
            .map_err(|e| Error::Rpc(format!("Alice send_adaptors: {e}")))?;
        self.transport.send(&adapt)?;

        // ── 5. recv counterparty AdaptorMaterial, verify ──
        let bob_adapt = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(bob_adapt)
            .map_err(|e| Error::Rpc(format!("Alice recv AdaptorMaterial: {e}")))?;
        run_verifier(action, verifier)?;

        // ── 6. send Ready ──
        let ready = self
            .session
            .send_ready()
            .map_err(|e| Error::Rpc(format!("Alice send_ready: {e}")))?;
        self.transport.send(&ready)?;

        // ── 7. recv Ready → Negotiated ──
        let bob_ready = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(bob_ready)
            .map_err(|e| Error::Rpc(format!("Alice recv Ready: {e}")))?;
        expect_done(&action)
    }

    /// Drive Bob's side of the handshake to completion:
    /// send `Hello` → recv `HelloAck` → send `Accept` → send
    /// `AdaptorMaterial` → recv counterparty's `AdaptorMaterial`
    /// (call `verifier`) → send `Ready` → recv `Ready`.
    ///
    /// Mirror of [`run_alice`](Self::run_alice).
    pub fn run_bob<'a>(
        &mut self,
        bob_pubkeys: Pubkeys,
        adaptors: AdaptorBundle,
        verifier: AdaptorVerifier<'a>,
    ) -> Result<()> {
        // ── 1. send Hello ──
        let hello = self
            .session
            .start_bob(bob_pubkeys.btc, bob_pubkeys.cync)
            .map_err(|e| Error::Rpc(format!("Bob start_bob: {e}")))?;
        self.transport.send(&hello)?;

        // ── 2. recv HelloAck ──
        let ack = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(ack)
            .map_err(|e| Error::Rpc(format!("Bob recv HelloAck: {e}")))?;
        expect_wait_for(&action, "accept_or_send_abort")?;

        // ── 3. send Accept ──
        let accept = self
            .session
            .accept()
            .map_err(|e| Error::Rpc(format!("Bob accept: {e}")))?;
        self.transport.send(&accept)?;

        // ── 4. send AdaptorMaterial ──
        let adapt = self
            .session
            .send_adaptors(
                adaptors.btc_adaptor,
                adaptors.cync_adaptor,
                adaptors.dl_proof,
                adaptors.refund_tx,
            )
            .map_err(|e| Error::Rpc(format!("Bob send_adaptors: {e}")))?;
        self.transport.send(&adapt)?;

        // ── 5. recv Alice's AdaptorMaterial, verify ──
        let alice_adapt = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(alice_adapt)
            .map_err(|e| Error::Rpc(format!("Bob recv AdaptorMaterial: {e}")))?;
        run_verifier(action, verifier)?;

        // ── 6. send Ready ──
        let ready = self
            .session
            .send_ready()
            .map_err(|e| Error::Rpc(format!("Bob send_ready: {e}")))?;
        self.transport.send(&ready)?;

        // ── 7. recv Ready → Negotiated ──
        let alice_ready = self.transport.recv()?;
        let action = self
            .session
            .handle_inbound(alice_ready)
            .map_err(|e| Error::Rpc(format!("Bob recv Ready: {e}")))?;
        expect_done(&action)
    }
}

/// Helper: assert the just-returned action is a `WaitForCaller`
/// pointing at the expected next-call name. Otherwise the driver
/// is out of sync with the state machine.
fn expect_wait_for(action: &HandshakeAction, expected: &'static str) -> Result<()> {
    match action {
        HandshakeAction::WaitForCaller { next_call } if *next_call == expected => Ok(()),
        HandshakeAction::Aborted { reason } => Err(Error::Rpc(format!(
            "counterparty aborted handshake: {reason}"
        ))),
        other => Err(Error::Rpc(format!(
            "expected WaitForCaller(\"{expected}\"), got {other:?}"
        ))),
    }
}

/// Helper: assert the just-returned action is `Done`.
fn expect_done(action: &HandshakeAction) -> Result<()> {
    match action {
        HandshakeAction::Done => Ok(()),
        HandshakeAction::Aborted { reason } => Err(Error::Rpc(format!(
            "counterparty aborted at final step: {reason}"
        ))),
        other => Err(Error::Rpc(format!(
            "expected HandshakeAction::Done, got {other:?}"
        ))),
    }
}

/// Helper: read + validate Hello over a plain TCP transport. Returns
/// the freshly-built [`HandshakeSession`] (in `AwaitingAck` with the
/// counterparty's pubkeys cached) on success, or an error string
/// describing why the peer was rejected.
///
/// Used by [`Coordinator::listen_filtered`] in its accept-loop. A
/// rejected peer just gets dropped + the loop tries the next one;
/// only the FIRST successful peer reaches the caller of
/// `listen_filtered`.
fn validate_hello_plain(
    transport: &mut TcpTransport,
    swap_id: &str,
) -> std::result::Result<HandshakeSession, String> {
    let hello = transport
        .recv()
        .map_err(|e| format!("first message recv: {e}"))?;
    let mut session = HandshakeSession::new_alice(swap_id.to_string());
    let action = session
        .handle_inbound(hello)
        .map_err(|e| format!("Hello validation: {e}"))?;
    match action {
        HandshakeAction::WaitForCaller { next_call } if next_call == "respond_with_hello_ack" => {
            Ok(session)
        }
        HandshakeAction::Aborted { reason } => {
            Err(format!("peer's first message was Abort: {reason}"))
        }
        other => Err(format!(
            "expected WaitForCaller(respond_with_hello_ack) after valid Hello, got {other:?}"
        )),
    }
}

/// Helper: same as [`validate_hello_plain`] but reads from a
/// Noise-wrapped transport.
fn validate_hello_noise(
    transport: &mut NoiseTransport,
    swap_id: &str,
) -> std::result::Result<HandshakeSession, String> {
    let hello = transport
        .recv()
        .map_err(|e| format!("first message recv: {e}"))?;
    let mut session = HandshakeSession::new_alice(swap_id.to_string());
    let action = session
        .handle_inbound(hello)
        .map_err(|e| format!("Hello validation: {e}"))?;
    match action {
        HandshakeAction::WaitForCaller { next_call } if next_call == "respond_with_hello_ack" => {
            Ok(session)
        }
        HandshakeAction::Aborted { reason } => {
            Err(format!("peer's first message was Abort: {reason}"))
        }
        other => Err(format!(
            "expected WaitForCaller(respond_with_hello_ack) after valid Hello, got {other:?}"
        )),
    }
}

/// Helper: run the supplied verifier callback on the inbound adaptor
/// material. Action must be `VerifyAdaptorMaterial` — anything else
/// is a driver/state-machine desync.
fn run_verifier(action: HandshakeAction, verifier: AdaptorVerifier<'_>) -> Result<()> {
    match action {
        HandshakeAction::VerifyAdaptorMaterial {
            btc_adaptor,
            cync_adaptor,
            dl_proof,
            refund_tx,
        } => verifier(&AdaptorBundle {
            btc_adaptor,
            cync_adaptor,
            dl_proof,
            refund_tx,
        }),
        HandshakeAction::Aborted { reason } => {
            Err(Error::Rpc(format!("counterparty aborted: {reason}")))
        }
        other => Err(Error::Rpc(format!(
            "expected VerifyAdaptorMaterial, got {other:?}"
        ))),
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
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
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
    fn handle_inbound_returns_wait_for_caller_at_pubkey_supply_points() {
        // Regression: earlier code returned Send(Message::Abort{..}) as
        // a placeholder at three points where the caller has to supply
        // locally-held data. A naive transport would have transmitted
        // the placeholder Abort and broken the handshake. These three
        // points must return WaitForCaller, never Send.

        // 1. Alice receives Hello -> needs respond_with_hello_ack
        let mut alice = HandshakeSession::new_alice("s".into());
        let hello = Message::Hello {
            swap_id: "s".into(),
            bob_btc_pubkey: dummy_pub(0xB1),
            bob_cync_pubkey: dummy_pub(0xB2),
        };
        match alice.handle_inbound(hello).unwrap() {
            HandshakeAction::WaitForCaller { next_call } => {
                assert_eq!(next_call, "respond_with_hello_ack")
            }
            other => panic!("expected WaitForCaller, got {:?}", other),
        }

        // 2. Bob receives HelloAck -> needs accept_or_send_abort
        let mut alice2 = HandshakeSession::new_alice("s".into());
        let mut bob = HandshakeSession::new_bob("s".into());
        let h = bob.start_bob(dummy_pub(0xB1), dummy_pub(0xB2)).unwrap();
        alice2.handle_inbound(h).unwrap();
        let ack = alice2
            .respond_with_hello_ack(dummy_pub(0xA1), dummy_pub(0xA2), safe_params())
            .unwrap();
        match bob.handle_inbound(ack).unwrap() {
            HandshakeAction::WaitForCaller { next_call } => {
                assert_eq!(next_call, "accept_or_send_abort")
            }
            other => panic!("expected WaitForCaller, got {:?}", other),
        }

        // 3. Alice receives Accept -> needs send_adaptors
        let accept = bob.accept().unwrap();
        match alice2.handle_inbound(accept).unwrap() {
            HandshakeAction::WaitForCaller { next_call } => assert_eq!(next_call, "send_adaptors"),
            other => panic!("expected WaitForCaller, got {:?}", other),
        }
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

    // ── Coordinator TCP transport (loopback integration) ─────────

    /// Pick a free localhost port by binding port 0 + reading back
    /// the OS-assigned port. Used to avoid hardcoded port collisions
    /// in parallel test runs.
    fn ephemeral_endpoint() -> String {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let port = listener.local_addr().unwrap().port();
        // Drop the listener so Coordinator::listen can re-bind. There
        // is a small race window where another process could grab the
        // port between drop and re-bind; in test runs it's never
        // come up. If it does, we can switch to passing the listener
        // into Coordinator instead.
        drop(listener);
        format!("127.0.0.1:{port}")
    }

    /// Full Alice↔Bob handshake driven through real TCP sockets on
    /// 127.0.0.1. Both sides reach Phase::Negotiated; counterparty
    /// pubkeys + parameters are populated on both sessions; the
    /// verifier callbacks fire with the expected adaptor bytes.
    #[test]
    fn coordinator_loopback_full_handshake() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let endpoint = ephemeral_endpoint();
        let swap_id = "test-swap-loopback".to_string();

        let alice_btc = vec![0x01; 33];
        let alice_cync = vec![0x02; 32];
        let bob_btc = vec![0x03; 33];
        let bob_cync = vec![0x04; 32];

        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let alice_adapt = AdaptorBundle {
            btc_adaptor: vec![0xAA; 65],
            cync_adaptor: vec![0xBB; 64],
            dl_proof: vec![0xCC; 100],
            refund_tx: vec![0xDD; 200],
        };
        let bob_adapt = AdaptorBundle {
            btc_adaptor: vec![0x11; 65],
            cync_adaptor: vec![0x22; 64],
            dl_proof: vec![0x33; 100],
            refund_tx: vec![0x44; 200],
        };

        // Channels for shipping the negotiated-session snapshot back
        // to the test thread for assertions.
        let (alice_tx, alice_rx) = mpsc::channel::<HandshakeSession>();
        let (bob_tx, bob_rx) = mpsc::channel::<HandshakeSession>();

        // ── Alice thread: bind + accept + drive run_alice ──
        let alice_endpoint = endpoint.clone();
        let alice_swap_id = swap_id.clone();
        let alice_btc_clone = alice_btc.clone();
        let alice_cync_clone = alice_cync.clone();
        let alice_adapt_clone = alice_adapt.clone();
        let bob_adapt_expected = bob_adapt.clone();
        let alice_params = params.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord =
                Coordinator::listen(&alice_endpoint, alice_swap_id).expect("alice listen");
            coord
                .set_timeout(Duration::from_secs(5))
                .expect("alice timeout");
            let verifier: AdaptorVerifier = Box::new(move |bundle| {
                assert_eq!(bundle.btc_adaptor, bob_adapt_expected.btc_adaptor);
                assert_eq!(bundle.cync_adaptor, bob_adapt_expected.cync_adaptor);
                assert_eq!(bundle.dl_proof, bob_adapt_expected.dl_proof);
                assert_eq!(bundle.refund_tx, bob_adapt_expected.refund_tx);
                Ok(())
            });
            coord
                .run_alice(
                    Pubkeys {
                        btc: alice_btc_clone,
                        cync: alice_cync_clone,
                    },
                    alice_params,
                    alice_adapt_clone,
                    verifier,
                )
                .expect("alice run_alice");
            alice_tx.send(coord.session().clone()).expect("alice send");
        });

        // ── Bob thread: connect + drive run_bob. Tiny sleep gives
        //    Alice's bind a chance to win the ephemeral-port race. ──
        let bob_endpoint = endpoint.clone();
        let bob_swap_id = swap_id.clone();
        let bob_btc_clone = bob_btc.clone();
        let bob_cync_clone = bob_cync.clone();
        let bob_adapt_clone = bob_adapt.clone();
        let alice_adapt_expected = alice_adapt.clone();
        let bob_handle = thread::spawn(move || {
            // Give Alice a moment to bind; 100ms is plenty for
            // loopback. If the race ever shows up in CI we can
            // poll-and-retry instead.
            thread::sleep(Duration::from_millis(100));
            let mut coord =
                Coordinator::connect(&bob_endpoint, bob_swap_id).expect("bob connect");
            coord
                .set_timeout(Duration::from_secs(5))
                .expect("bob timeout");
            let verifier: AdaptorVerifier = Box::new(move |bundle| {
                assert_eq!(bundle.btc_adaptor, alice_adapt_expected.btc_adaptor);
                assert_eq!(bundle.cync_adaptor, alice_adapt_expected.cync_adaptor);
                assert_eq!(bundle.dl_proof, alice_adapt_expected.dl_proof);
                assert_eq!(bundle.refund_tx, alice_adapt_expected.refund_tx);
                Ok(())
            });
            coord
                .run_bob(
                    Pubkeys {
                        btc: bob_btc_clone,
                        cync: bob_cync_clone,
                    },
                    bob_adapt_clone,
                    verifier,
                )
                .expect("bob run_bob");
            bob_tx.send(coord.session().clone()).expect("bob send");
        });

        alice_handle.join().expect("alice thread");
        bob_handle.join().expect("bob thread");
        let alice_session = alice_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("alice session snapshot");
        let bob_session = bob_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("bob session snapshot");

        // Both sides reached Negotiated.
        assert_eq!(alice_session.phase, Phase::Negotiated);
        assert_eq!(bob_session.phase, Phase::Negotiated);

        // Both sides cached their counterparty's pubkeys.
        assert_eq!(alice_session.counterparty_btc_pubkey, Some(bob_btc));
        assert_eq!(alice_session.counterparty_cync_pubkey, Some(bob_cync));
        assert_eq!(bob_session.counterparty_btc_pubkey, Some(alice_btc));
        assert_eq!(bob_session.counterparty_cync_pubkey, Some(alice_cync));

        // Both sides agree on the same parameters Alice proposed.
        assert_eq!(alice_session.parameters, Some(params.clone()));
        assert_eq!(bob_session.parameters, Some(params));
    }

    /// Full Alice↔Bob handshake driven through a **Noise XX**-wrapped
    /// TCP socket. Both sides reach Phase::Negotiated AND learn each
    /// other's long-term Curve25519 static key. The static-key check
    /// is what makes the transport resistant to active MitM.
    #[test]
    fn coordinator_loopback_noise_full_handshake() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let endpoint = ephemeral_endpoint();
        let swap_id = "test-swap-noise-loopback".to_string();

        // Deterministic test keypairs — in production use OsRng via
        // `snow::Builder::generate_keypair`.
        let alice_static = [0x11u8; 32];
        let bob_static = [0x22u8; 32];

        // Derive the public keys from the privates so the test can
        // verify the negotiated remote-static-key. snow's keypair
        // type bundles both, but here we just use the public-key
        // derivation directly via x25519-dalek (already in our tree
        // through curve25519-dalek).
        let alice_pub = curve25519_static_pub(&alice_static);
        let bob_pub = curve25519_static_pub(&bob_static);

        let alice_btc = vec![0xA1; 33];
        let alice_cync = vec![0xA2; 32];
        let bob_btc = vec![0xB1; 33];
        let bob_cync = vec![0xB2; 32];

        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let alice_adapt = AdaptorBundle {
            btc_adaptor: vec![0xAA; 65],
            cync_adaptor: vec![0xBB; 64],
            dl_proof: vec![0xCC; 100],
            refund_tx: vec![0xDD; 200],
        };
        let bob_adapt = AdaptorBundle {
            btc_adaptor: vec![0x11; 65],
            cync_adaptor: vec![0x22; 64],
            dl_proof: vec![0x33; 100],
            refund_tx: vec![0x44; 200],
        };

        // Snapshot channels for assertion in the main thread.
        let (alice_tx, alice_rx) =
            mpsc::channel::<(HandshakeSession, Option<[u8; 32]>)>();
        let (bob_tx, bob_rx) =
            mpsc::channel::<(HandshakeSession, Option<[u8; 32]>)>();

        // ── Alice thread (responder) ──
        let alice_endpoint = endpoint.clone();
        let alice_swap_id = swap_id.clone();
        let alice_params = params.clone();
        let alice_btc_clone = alice_btc.clone();
        let alice_cync_clone = alice_cync.clone();
        let alice_adapt_clone = alice_adapt.clone();
        let bob_adapt_expected = bob_adapt.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord =
                Coordinator::listen_noise(&alice_endpoint, alice_swap_id, &alice_static)
                    .expect("alice listen_noise");
            coord
                .set_timeout(Duration::from_secs(5))
                .expect("alice timeout");
            let verifier: AdaptorVerifier = Box::new(move |bundle| {
                assert_eq!(bundle.btc_adaptor, bob_adapt_expected.btc_adaptor);
                assert_eq!(bundle.cync_adaptor, bob_adapt_expected.cync_adaptor);
                Ok(())
            });
            coord
                .run_alice(
                    Pubkeys {
                        btc: alice_btc_clone,
                        cync: alice_cync_clone,
                    },
                    alice_params,
                    alice_adapt_clone,
                    verifier,
                )
                .expect("alice run_alice");
            let remote = coord.remote_static();
            alice_tx
                .send((coord.session().clone(), remote))
                .expect("alice send");
        });

        // ── Bob thread (initiator) ──
        let bob_endpoint = endpoint.clone();
        let bob_swap_id = swap_id.clone();
        let bob_btc_clone = bob_btc.clone();
        let bob_cync_clone = bob_cync.clone();
        let bob_adapt_clone = bob_adapt.clone();
        let alice_adapt_expected = alice_adapt.clone();
        let bob_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let mut coord =
                Coordinator::connect_noise(&bob_endpoint, bob_swap_id, &bob_static)
                    .expect("bob connect_noise");
            coord
                .set_timeout(Duration::from_secs(5))
                .expect("bob timeout");
            let verifier: AdaptorVerifier = Box::new(move |bundle| {
                assert_eq!(bundle.btc_adaptor, alice_adapt_expected.btc_adaptor);
                assert_eq!(bundle.cync_adaptor, alice_adapt_expected.cync_adaptor);
                Ok(())
            });
            coord
                .run_bob(
                    Pubkeys {
                        btc: bob_btc_clone,
                        cync: bob_cync_clone,
                    },
                    bob_adapt_clone,
                    verifier,
                )
                .expect("bob run_bob");
            let remote = coord.remote_static();
            bob_tx
                .send((coord.session().clone(), remote))
                .expect("bob send");
        });

        alice_handle.join().expect("alice thread");
        bob_handle.join().expect("bob thread");
        let (alice_session, alice_sees_bob) = alice_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("alice snapshot");
        let (bob_session, bob_sees_alice) = bob_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("bob snapshot");

        // Swap protocol completed on both sides.
        assert_eq!(alice_session.phase, Phase::Negotiated);
        assert_eq!(bob_session.phase, Phase::Negotiated);

        // Each side learned the OTHER's long-term static key. This is
        // the key (no pun intended) Noise-XX property — both ends
        // can now verify the negotiated key against an out-of-band
        // fingerprint to detect MitM.
        assert_eq!(
            alice_sees_bob,
            Some(bob_pub),
            "Alice must see Bob's static public key, not someone else's"
        );
        assert_eq!(
            bob_sees_alice,
            Some(alice_pub),
            "Bob must see Alice's static public key, not someone else's"
        );

        // Swap-level pubkeys + parameters still carried correctly
        // through the AEAD-encrypted channel.
        assert_eq!(alice_session.counterparty_btc_pubkey, Some(bob_btc));
        assert_eq!(bob_session.counterparty_btc_pubkey, Some(alice_btc));
        assert_eq!(alice_session.parameters, Some(params.clone()));
        assert_eq!(bob_session.parameters, Some(params));
    }

    /// Test alias for [`derive_noise_static_public`]. Kept under its
    /// old name so existing test references read naturally; the
    /// public helper at module-top is the production entry point.
    fn curve25519_static_pub(private: &[u8; 32]) -> [u8; 32] {
        super::derive_noise_static_public(private)
    }

    /// Bob's dial against a non-existent endpoint must surface as a
    /// transport-layer error (not a panic / hang).
    #[test]
    fn coordinator_connect_to_dead_endpoint_errors() {
        // Pick a port and don't bind it. There's a small chance some
        // other process is listening there; for the test, port 1
        // (privileged + reserved) is almost certainly closed for
        // userspace bindings on every reasonable OS.
        let result =
            Coordinator::connect("127.0.0.1:1", "test-swap-no-peer".to_string());
        assert!(
            matches!(result, Err(Error::Rpc(_))),
            "expected Error::Rpc, got {result:?}"
        );
    }

    // ── SOCKS5 / Tor-style dial tests ────────────────────────────

    /// A minimal RFC 1928 §3-4 no-auth SOCKS5 server that connects to
    /// one client, validates the protocol bytes, dials the requested
    /// target (taking it AS LITERAL `host:port` from the
    /// ATYP=DOMAINNAME field — which suits our test where the
    /// "domain" is `127.0.0.1` and the proxy can resolve it
    /// directly), and bidirectionally bridges the two sockets in
    /// background threads. Returns the proxy's bound endpoint.
    ///
    /// The byte-validation assertions live in this mock server, so
    /// any drift from the protocol in `socks5_connect_domain` shows
    /// up as a panicked test thread.
    fn spawn_mock_socks5_forwarder(
        target_host: String,
        target_port: u16,
        ready_tx: std::sync::mpsc::Sender<String>,
    ) -> std::thread::JoinHandle<()> {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        std::thread::spawn(move || {
            let listener =
                TcpListener::bind("127.0.0.1:0").expect("mock SOCKS5 bind");
            let proxy_addr = listener.local_addr().unwrap();
            ready_tx
                .send(proxy_addr.to_string())
                .expect("ready broadcast");

            let (mut client, _) = listener.accept().expect("mock SOCKS5 accept");
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            // ── Greeting ──
            let mut greeting = [0u8; 3];
            client.read_exact(&mut greeting).expect("greeting read");
            assert_eq!(
                greeting,
                [0x05, 0x01, 0x00],
                "expected SOCKS5 greeting VER=5 NMETHODS=1 METHOD=0"
            );
            client.write_all(&[0x05, 0x00]).expect("method-sel write");

            // ── CONNECT request ──
            let mut hdr = [0u8; 4];
            client.read_exact(&mut hdr).expect("CONNECT hdr read");
            assert_eq!(&hdr[..3], &[0x05, 0x01, 0x00]);
            assert_eq!(hdr[3], 0x03, "expected ATYP=DOMAINNAME");
            let mut len = [0u8; 1];
            client.read_exact(&mut len).expect("CONNECT len read");
            let mut host = vec![0u8; len[0] as usize];
            client.read_exact(&mut host).expect("CONNECT host read");
            let mut port = [0u8; 2];
            client.read_exact(&mut port).expect("CONNECT port read");
            let got_host = std::str::from_utf8(&host).expect("utf-8 host");
            let got_port = u16::from_be_bytes(port);
            assert_eq!(got_host, target_host, "CONNECT target host");
            assert_eq!(got_port, target_port, "CONNECT target port");

            // ── Dial the actual target ──
            let target =
                std::net::TcpStream::connect(format!("{target_host}:{target_port}"))
                    .expect("mock SOCKS5 dial target");
            target
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            target
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            // ── Success reply: BND.ADDR=127.0.0.1:0 ──
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .expect("CONNECT reply write");

            // ── Bidirectional pump ──
            let client_clone = client.try_clone().expect("client clone");
            let target_clone = target.try_clone().expect("target clone");
            let pump_a = std::thread::spawn(move || {
                let mut from = client_clone;
                let mut to = target_clone;
                let mut buf = [0u8; 8192];
                loop {
                    match from.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if to.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Best-effort half-close so the other pump can drain.
                let _ = to.shutdown(std::net::Shutdown::Write);
            });
            let pump_b = std::thread::spawn(move || {
                let mut from = target;
                let mut to = client;
                let mut buf = [0u8; 8192];
                loop {
                    match from.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if to.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = to.shutdown(std::net::Shutdown::Write);
            });
            let _ = pump_a.join();
            let _ = pump_b.join();
        })
    }

    /// Bob's `connect_via_socks5` dials through a mock SOCKS5 proxy
    /// that forwards to Alice's plain-TCP listener. End-to-end
    /// handshake completes the same way `coordinator_loopback_full_handshake`
    /// does — proving the SOCKS5 indirection is invisible to the
    /// handshake driver.
    #[test]
    fn coordinator_loopback_full_handshake_via_socks5() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let alice_endpoint = ephemeral_endpoint();
        let (proxy_ready_tx, proxy_ready_rx) = mpsc::channel::<String>();

        let alice_host: String = alice_endpoint
            .split(':')
            .next()
            .unwrap()
            .to_string();
        let alice_port: u16 = alice_endpoint
            .split(':')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let proxy_handle =
            spawn_mock_socks5_forwarder(alice_host.clone(), alice_port, proxy_ready_tx);
        let proxy_addr = proxy_ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("proxy ready");

        let swap_id = "test-swap-via-socks5".to_string();
        let alice_btc = vec![0x01; 33];
        let alice_cync = vec![0x02; 32];
        let bob_btc = vec![0x03; 33];
        let bob_cync = vec![0x04; 32];

        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let blob = vec![0xAA; 64];
        let bundle = AdaptorBundle {
            btc_adaptor: blob.clone(),
            cync_adaptor: blob.clone(),
            dl_proof: blob.clone(),
            refund_tx: blob.clone(),
        };

        let (alice_tx, alice_rx) = mpsc::channel::<HandshakeSession>();
        let (bob_tx, bob_rx) = mpsc::channel::<HandshakeSession>();

        // Alice: plain TCP listener (no awareness of the SOCKS5 hop).
        let alice_endpoint_clone = alice_endpoint.clone();
        let alice_swap_id = swap_id.clone();
        let alice_params = params.clone();
        let alice_bundle = bundle.clone();
        let alice_btc_clone = alice_btc.clone();
        let alice_cync_clone = alice_cync.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord =
                Coordinator::listen(&alice_endpoint_clone, alice_swap_id).expect("alice listen");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_alice(
                    Pubkeys {
                        btc: alice_btc_clone,
                        cync: alice_cync_clone,
                    },
                    alice_params,
                    alice_bundle,
                    verifier,
                )
                .expect("alice run_alice");
            alice_tx.send(coord.session().clone()).unwrap();
        });

        // Bob: dials through the SOCKS5 proxy.
        let proxy_addr_clone = proxy_addr.clone();
        let bob_swap_id = swap_id.clone();
        let bob_bundle = bundle.clone();
        let bob_btc_clone = bob_btc.clone();
        let bob_cync_clone = bob_cync.clone();
        let bob_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let mut coord = Coordinator::connect_via_socks5(
                &proxy_addr_clone,
                &alice_host,
                alice_port,
                bob_swap_id,
            )
            .expect("bob connect_via_socks5");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_bob(
                    Pubkeys {
                        btc: bob_btc_clone,
                        cync: bob_cync_clone,
                    },
                    bob_bundle,
                    verifier,
                )
                .expect("bob run_bob");
            bob_tx.send(coord.session().clone()).unwrap();
        });

        alice_handle.join().unwrap();
        bob_handle.join().unwrap();
        let alice_session = alice_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let bob_session = bob_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        assert_eq!(alice_session.phase, Phase::Negotiated);
        assert_eq!(bob_session.phase, Phase::Negotiated);
        assert_eq!(alice_session.counterparty_btc_pubkey, Some(bob_btc));
        assert_eq!(bob_session.counterparty_btc_pubkey, Some(alice_btc));

        // Let the proxy threads drain. Don't strictly need to join
        // them, but joining proves they exited cleanly.
        let _ = proxy_handle.join();
    }

    /// Same as above but with Noise XX wrapping inside the SOCKS5
    /// tunnel — Bob's connection is encrypted twice (Noise + the
    /// tunneling layer, which in production would be Tor). Proves
    /// the Noise handshake works through the indirection.
    #[test]
    fn coordinator_loopback_noise_via_socks5() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let alice_endpoint = ephemeral_endpoint();
        let (proxy_ready_tx, proxy_ready_rx) = mpsc::channel::<String>();

        let alice_host: String = alice_endpoint.split(':').next().unwrap().to_string();
        let alice_port: u16 = alice_endpoint.split(':').nth(1).unwrap().parse().unwrap();
        let proxy_handle =
            spawn_mock_socks5_forwarder(alice_host.clone(), alice_port, proxy_ready_tx);
        let proxy_addr = proxy_ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("proxy ready");

        let alice_static = [0x55u8; 32];
        let bob_static = [0x66u8; 32];

        let swap_id = "test-swap-noise-via-socks5".to_string();
        let blob = vec![0xCD; 64];
        let bundle = AdaptorBundle {
            btc_adaptor: blob.clone(),
            cync_adaptor: blob.clone(),
            dl_proof: blob.clone(),
            refund_tx: blob.clone(),
        };
        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let (alice_tx, alice_rx) = mpsc::channel::<(HandshakeSession, Option<[u8; 32]>)>();
        let (bob_tx, bob_rx) = mpsc::channel::<(HandshakeSession, Option<[u8; 32]>)>();

        let alice_endpoint_clone = alice_endpoint.clone();
        let alice_swap_id = swap_id.clone();
        let alice_params = params.clone();
        let alice_bundle = bundle.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord =
                Coordinator::listen_noise(&alice_endpoint_clone, alice_swap_id, &alice_static)
                    .expect("alice listen_noise");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_alice(
                    Pubkeys {
                        btc: vec![0xA1; 33],
                        cync: vec![0xA2; 32],
                    },
                    alice_params,
                    alice_bundle,
                    verifier,
                )
                .expect("alice run_alice");
            let remote = coord.remote_static();
            alice_tx.send((coord.session().clone(), remote)).unwrap();
        });

        let proxy_addr_clone = proxy_addr.clone();
        let bob_swap_id = swap_id.clone();
        let bob_bundle = bundle.clone();
        let bob_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let mut coord = Coordinator::connect_noise_via_socks5(
                &proxy_addr_clone,
                &alice_host,
                alice_port,
                bob_swap_id,
                &bob_static,
            )
            .expect("bob connect_noise_via_socks5");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_bob(
                    Pubkeys {
                        btc: vec![0xB1; 33],
                        cync: vec![0xB2; 32],
                    },
                    bob_bundle,
                    verifier,
                )
                .expect("bob run_bob");
            let remote = coord.remote_static();
            bob_tx.send((coord.session().clone(), remote)).unwrap();
        });

        alice_handle.join().unwrap();
        bob_handle.join().unwrap();
        let (alice_session, alice_sees_bob) =
            alice_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (bob_session, bob_sees_alice) =
            bob_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        assert_eq!(alice_session.phase, Phase::Negotiated);
        assert_eq!(bob_session.phase, Phase::Negotiated);
        // Noise XX mutual-auth survives the SOCKS5 hop.
        assert_eq!(alice_sees_bob, Some(curve25519_static_pub(&bob_static)));
        assert_eq!(bob_sees_alice, Some(curve25519_static_pub(&alice_static)));

        let _ = proxy_handle.join();
    }

    /// `socks5_connect_domain` rejects target hostnames longer than
    /// 255 bytes (the ATYP=DOMAINNAME length field is a single byte).
    /// Tor v3 onions are 62 chars; nothing legitimate exceeds 255.
    #[test]
    fn socks5_rejects_overlong_target_host() {
        let very_long = "a".repeat(256);
        // Use a definitely-closed proxy port — the validation should
        // fire before any TCP I/O.
        let r = socks5_connect_domain("127.0.0.1:1", &very_long, 9000);
        assert!(
            matches!(r, Err(Error::Rpc(msg)) if msg.contains("> 255")),
            "expected length-limit Err"
        );
    }

    /// `socks5_connect_domain` rejects the empty hostname.
    #[test]
    fn socks5_rejects_empty_target_host() {
        let r = socks5_connect_domain("127.0.0.1:1", "", 9000);
        assert!(
            matches!(r, Err(Error::Rpc(msg)) if msg.contains("empty target host")),
            "expected empty-host Err"
        );
    }

    // ── Filtered-listen (DoS hardening) tests ──────────────────

    /// `listen_filtered` skips a silent peer and accepts the next
    /// valid Bob. Simulates the classic DoS scenario: an attacker
    /// races the legitimate Bob to Alice's port but then sits
    /// silent. Alice's `peer_timeout` fires, she drops the attacker,
    /// the loop tries again, and the next connection (real Bob)
    /// succeeds.
    #[test]
    fn listen_filtered_skips_silent_peer() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let endpoint = ephemeral_endpoint();
        let swap_id = "test-swap-filtered-silent".to_string();

        let alice_btc = vec![0x01; 33];
        let alice_cync = vec![0x02; 32];
        let bob_btc = vec![0x03; 33];
        let bob_cync = vec![0x04; 32];

        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let alice_bundle = AdaptorBundle {
            btc_adaptor: vec![0xA; 32],
            cync_adaptor: vec![0xA; 32],
            dl_proof: vec![0xA; 32],
            refund_tx: vec![0xA; 32],
        };
        let bob_bundle = alice_bundle.clone();

        let (alice_tx, alice_rx) = mpsc::channel::<HandshakeSession>();
        let (bob_tx, bob_rx) = mpsc::channel::<HandshakeSession>();

        // Alice thread: listen_filtered with a tight peer_timeout
        // (300 ms — so the silent griefer is dropped fast) + 3 max
        // attempts.
        let alice_endpoint = endpoint.clone();
        let alice_swap_id = swap_id.clone();
        let alice_params = params.clone();
        let alice_btc_clone = alice_btc.clone();
        let alice_cync_clone = alice_cync.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord = Coordinator::listen_filtered(
                &alice_endpoint,
                alice_swap_id,
                Duration::from_millis(300),
                3,
            )
            .expect("alice listen_filtered");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_alice_post_hello(
                    Pubkeys {
                        btc: alice_btc_clone,
                        cync: alice_cync_clone,
                    },
                    alice_params,
                    alice_bundle,
                    verifier,
                )
                .expect("alice run_alice_post_hello");
            alice_tx.send(coord.session().clone()).unwrap();
        });

        // Silent peer thread: connects + sits silent forever. Alice's
        // 300ms timeout should drop them.
        let endpoint_silent = endpoint.clone();
        let silent_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let _silent = std::net::TcpStream::connect(&endpoint_silent)
                .expect("silent peer connect");
            // Keep it alive long enough for Alice to time out + loop.
            thread::sleep(Duration::from_millis(1500));
            // Drop silently.
        });

        // Real Bob thread: connects AFTER the silent peer is dropped,
        // drives a normal handshake.
        let endpoint_bob = endpoint.clone();
        let bob_swap_id = swap_id.clone();
        let bob_btc_clone = bob_btc.clone();
        let bob_cync_clone = bob_cync.clone();
        let bob_handle = thread::spawn(move || {
            // Wait long enough that Alice has timed out the silent
            // peer (300ms + slack) and is back in the accept loop.
            thread::sleep(Duration::from_millis(700));
            let mut coord = Coordinator::connect(&endpoint_bob, bob_swap_id)
                .expect("bob connect");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_bob(
                    Pubkeys {
                        btc: bob_btc_clone,
                        cync: bob_cync_clone,
                    },
                    bob_bundle,
                    verifier,
                )
                .expect("bob run_bob");
            bob_tx.send(coord.session().clone()).unwrap();
        });

        silent_handle.join().expect("silent");
        alice_handle.join().expect("alice");
        bob_handle.join().expect("bob");
        let alice_session = alice_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let bob_session = bob_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        // Alice survived the silent peer + handshook with real Bob.
        assert_eq!(alice_session.phase, Phase::Negotiated);
        assert_eq!(bob_session.phase, Phase::Negotiated);
        assert_eq!(alice_session.counterparty_btc_pubkey, Some(bob_btc));
        assert_eq!(bob_session.counterparty_btc_pubkey, Some(alice_btc));
    }

    /// `listen_filtered` rejects a peer whose Hello carries the
    /// wrong swap_id, then accepts the next valid Bob. Tests the
    /// state-machine-rejection path of validate_hello_plain.
    #[test]
    fn listen_filtered_skips_wrong_swap_id_peer() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let endpoint = ephemeral_endpoint();
        let swap_id = "test-swap-filtered-wrong-id".to_string();

        let alice_btc = vec![0x01; 33];
        let alice_cync = vec![0x02; 32];
        let bob_btc = vec![0x03; 33];
        let bob_cync = vec![0x04; 32];

        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let bundle = AdaptorBundle {
            btc_adaptor: vec![0xA; 32],
            cync_adaptor: vec![0xA; 32],
            dl_proof: vec![0xA; 32],
            refund_tx: vec![0xA; 32],
        };

        let (alice_tx, alice_rx) = mpsc::channel::<HandshakeSession>();
        let (bob_tx, bob_rx) = mpsc::channel::<HandshakeSession>();

        let alice_endpoint = endpoint.clone();
        let alice_swap_id = swap_id.clone();
        let alice_params = params.clone();
        let alice_bundle = bundle.clone();
        let alice_btc_clone = alice_btc.clone();
        let alice_cync_clone = alice_cync.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord = Coordinator::listen_filtered(
                &alice_endpoint,
                alice_swap_id,
                Duration::from_millis(500),
                3,
            )
            .expect("alice listen_filtered");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_alice_post_hello(
                    Pubkeys {
                        btc: alice_btc_clone,
                        cync: alice_cync_clone,
                    },
                    alice_params,
                    alice_bundle,
                    verifier,
                )
                .expect("alice run_alice_post_hello");
            alice_tx.send(coord.session().clone()).unwrap();
        });

        // Bad peer: connects, sends Hello with the WRONG swap_id.
        // Alice's state machine returns SwapIdMismatch → loop continues.
        let endpoint_bad = endpoint.clone();
        let bad_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let mut bad =
                Coordinator::connect(&endpoint_bad, "swap-WRONG".to_string()).expect("bad connect");
            bad.set_timeout(Duration::from_millis(500)).unwrap();
            // Send a malformed Hello and tear down.
            let bad_hello = Message::Hello {
                swap_id: "swap-WRONG".to_string(),
                bob_btc_pubkey: vec![0xFF; 33],
                bob_cync_pubkey: vec![0xFF; 32],
            };
            // CoordTransport::send dispatches to TcpTransport::send for Plain
            let _ = bad.transport.send(&bad_hello);
            // Sit briefly so Alice sees the read happen before connection drop.
            thread::sleep(Duration::from_millis(100));
        });

        let endpoint_bob = endpoint.clone();
        let bob_swap_id = swap_id.clone();
        let bob_btc_clone = bob_btc.clone();
        let bob_cync_clone = bob_cync.clone();
        let bob_bundle = bundle.clone();
        let bob_handle = thread::spawn(move || {
            // Wait long enough that Alice has rejected the bad peer.
            thread::sleep(Duration::from_millis(500));
            let mut coord = Coordinator::connect(&endpoint_bob, bob_swap_id)
                .expect("bob connect");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_bob(
                    Pubkeys {
                        btc: bob_btc_clone,
                        cync: bob_cync_clone,
                    },
                    bob_bundle,
                    verifier,
                )
                .expect("bob run_bob");
            bob_tx.send(coord.session().clone()).unwrap();
        });

        bad_handle.join().expect("bad");
        alice_handle.join().expect("alice");
        bob_handle.join().expect("bob");
        let alice_session = alice_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let bob_session = bob_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        assert_eq!(alice_session.phase, Phase::Negotiated);
        assert_eq!(bob_session.phase, Phase::Negotiated);
        assert_eq!(alice_session.counterparty_btc_pubkey, Some(bob_btc));
    }

    /// `listen_filtered` returns an error after max_attempts of
    /// silent-peer connections, rather than blocking indefinitely.
    /// Bounds the worst-case resource cost of a sustained
    /// connect-flood attack.
    #[test]
    fn listen_filtered_exhausts_after_max_attempts() {
        use std::thread;
        use std::time::Duration;

        let endpoint = ephemeral_endpoint();
        let swap_id = "test-swap-filtered-exhaust".to_string();

        let alice_endpoint = endpoint.clone();
        let alice_handle = thread::spawn(move || {
            Coordinator::listen_filtered(
                &alice_endpoint,
                swap_id,
                Duration::from_millis(200),
                2, // very low so we hit the cap fast
            )
        });

        // Spawn 3 silent peers — 2 will be tried (per max_attempts);
        // the 3rd connects after the listener has already errored out.
        let endpoint_silent = endpoint.clone();
        let silent_handle = thread::spawn(move || {
            for i in 0..3 {
                thread::sleep(Duration::from_millis(50 + i * 100));
                let _ = std::net::TcpStream::connect(&endpoint_silent);
            }
            thread::sleep(Duration::from_millis(800));
        });

        let result = alice_handle.join().expect("alice");
        let _ = silent_handle.join();

        match result {
            Err(Error::Rpc(msg)) => {
                assert!(
                    msg.contains("exhausted 2 attempts"),
                    "expected exhaustion message, got: {msg}"
                );
            }
            other => panic!("expected Err(Rpc(\"exhausted\")), got {other:?}"),
        }
    }

    /// `listen_noise_filtered` skips a peer that can't complete the
    /// Noise handshake (e.g., sends garbage instead of a Noise
    /// message), then accepts the next valid Bob.
    #[test]
    fn listen_noise_filtered_skips_garbage_peer() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let endpoint = ephemeral_endpoint();
        let swap_id = "test-swap-noise-filtered".to_string();

        let alice_static = [0x99u8; 32];
        let bob_static = [0xAAu8; 32];

        let alice_btc = vec![0x01; 33];
        let alice_cync = vec![0x02; 32];
        let bob_btc = vec![0x03; 33];
        let bob_cync = vec![0x04; 32];

        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let bundle = AdaptorBundle {
            btc_adaptor: vec![0xC; 32],
            cync_adaptor: vec![0xC; 32],
            dl_proof: vec![0xC; 32],
            refund_tx: vec![0xC; 32],
        };

        let (alice_tx, alice_rx) = mpsc::channel::<HandshakeSession>();
        let (bob_tx, bob_rx) = mpsc::channel::<HandshakeSession>();

        let alice_endpoint = endpoint.clone();
        let alice_swap_id = swap_id.clone();
        let alice_params = params.clone();
        let alice_bundle = bundle.clone();
        let alice_btc_clone = alice_btc.clone();
        let alice_cync_clone = alice_cync.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord = Coordinator::listen_noise_filtered(
                &alice_endpoint,
                alice_swap_id,
                &alice_static,
                Duration::from_millis(500),
                3,
            )
            .expect("alice listen_noise_filtered");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_alice_post_hello(
                    Pubkeys {
                        btc: alice_btc_clone,
                        cync: alice_cync_clone,
                    },
                    alice_params,
                    alice_bundle,
                    verifier,
                )
                .expect("alice run_alice_post_hello");
            alice_tx.send(coord.session().clone()).unwrap();
        });

        // Garbage peer: sends raw plaintext bytes instead of a Noise
        // first message. Alice's NoiseTransport::handshake_responder
        // returns Err → loop continues.
        let endpoint_garbage = endpoint.clone();
        let garbage_handle = thread::spawn(move || {
            use std::io::Write;
            thread::sleep(Duration::from_millis(50));
            let mut bad = std::net::TcpStream::connect(&endpoint_garbage)
                .expect("garbage connect");
            // 4-byte length prefix (consistent with framed messages)
            // pointing at 16 bytes of zeros — not a valid Noise XX
            // first message.
            let _ = bad.write_all(&16u32.to_be_bytes());
            let _ = bad.write_all(&[0u8; 16]);
            thread::sleep(Duration::from_millis(200));
        });

        let endpoint_bob = endpoint.clone();
        let bob_swap_id = swap_id.clone();
        let bob_btc_clone = bob_btc.clone();
        let bob_cync_clone = bob_cync.clone();
        let bob_bundle = bundle.clone();
        let bob_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(500));
            let mut coord = Coordinator::connect_noise(
                &endpoint_bob,
                bob_swap_id,
                &bob_static,
            )
            .expect("bob connect_noise");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            coord
                .run_bob(
                    Pubkeys {
                        btc: bob_btc_clone,
                        cync: bob_cync_clone,
                    },
                    bob_bundle,
                    verifier,
                )
                .expect("bob run_bob");
            bob_tx.send(coord.session().clone()).unwrap();
        });

        garbage_handle.join().expect("garbage");
        alice_handle.join().expect("alice");
        bob_handle.join().expect("bob");
        let alice_session = alice_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let bob_session = bob_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        assert_eq!(alice_session.phase, Phase::Negotiated);
        assert_eq!(bob_session.phase, Phase::Negotiated);
        assert_eq!(alice_session.counterparty_btc_pubkey, Some(bob_btc));
    }

    /// Bob's swap_id mismatch must abort Alice's handshake at the
    /// recv-Hello step (not the bind step). Drives the transport +
    /// the state-machine's SwapIdMismatch path together.
    #[test]
    fn coordinator_loopback_rejects_mismatched_swap_id() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let endpoint = ephemeral_endpoint();

        let params = SwapParameters {
            cync_amount: 1_000,
            btc_amount_sats: 1_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".to_string(),
            bob_btc_address: "bob".to_string(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        };

        let (alice_tx, alice_rx) = mpsc::channel::<std::result::Result<(), String>>();

        let alice_endpoint = endpoint.clone();
        let alice_handle = thread::spawn(move || {
            let mut coord = Coordinator::listen(&alice_endpoint, "swap-A".to_string())
                .expect("alice listen");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            let verifier: AdaptorVerifier = Box::new(|_| Ok(()));
            let r = coord.run_alice(
                Pubkeys {
                    btc: vec![0x01; 33],
                    cync: vec![0x02; 32],
                },
                params,
                AdaptorBundle {
                    btc_adaptor: vec![0; 1],
                    cync_adaptor: vec![0; 1],
                    dl_proof: vec![0; 1],
                    refund_tx: vec![0; 1],
                },
                verifier,
            );
            // run_alice maps handle_inbound's SwapIdMismatch into an
            // Error::Rpc(format!("Alice recv Hello: {e}")) — the
            // outer test asserts on the Err.
            alice_tx
                .send(r.map_err(|e| format!("{e}")))
                .expect("alice send");
        });

        let bob_endpoint = endpoint.clone();
        let bob_handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            // Bob connects with the WRONG swap_id.
            let mut coord = Coordinator::connect(&bob_endpoint, "swap-B-WRONG".to_string())
                .expect("bob connect");
            coord.set_timeout(Duration::from_secs(5)).unwrap();
            // Bob's run_bob will get an EOF or a brief readable when
            // Alice errors out and drops the socket — either way it
            // surfaces as an Err. We don't assert on Bob's error
            // (just confirming Alice rejected is sufficient for the
            // soundness property).
            let _ = coord.run_bob(
                Pubkeys {
                    btc: vec![0x03; 33],
                    cync: vec![0x04; 32],
                },
                AdaptorBundle {
                    btc_adaptor: vec![0; 1],
                    cync_adaptor: vec![0; 1],
                    dl_proof: vec![0; 1],
                    refund_tx: vec![0; 1],
                },
                Box::new(|_| Ok(())),
            );
        });

        alice_handle.join().expect("alice thread");
        bob_handle.join().expect("bob thread");

        let alice_result = alice_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("alice result");
        let err_msg = alice_result.expect_err("alice must reject mismatched swap_id");
        assert!(
            err_msg.contains("swap_id") || err_msg.contains("SwapId") || err_msg.contains("mismatch"),
            "expected swap_id mismatch error, got: {err_msg}"
        );
    }
}
