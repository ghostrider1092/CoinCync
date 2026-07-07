//! `coord` — FROST coordinator WSS server (phase 4).
//!
//! Wraps the in-process `Session` state machine in a WebSocket
//! transport, persisting every transition to a `SessionStore` and
//! verifying participant attaches against invitation-token HMACs.
//!
//! ## Status: PHASE 4 — works, but minimal
//!
//! Ships:
//! - WSS listener accepting JSON-encoded request/response messages
//! - Per-session message routing (an action by one participant
//!   becomes a notification to all attached participants)
//! - Invitation-token verification at attach time
//! - Persistence on every accepted transition
//! - Graceful shutdown on SIGINT
//!
//! Defers to phase 5/6:
//! - TLS termination (run behind nginx / Caddy reverse proxy
//!   with WSS on the public side; the coord binary speaks WS
//!   over loopback)
//! - Prometheus metrics endpoint
//! - Rate limiting (max attaches/second, max message rate per
//!   connection)
//! - Connection idle timeouts
//! - Integration tests against a real `frost_ed25519` round-trip
//!
//! ## Wire protocol (request/response)
//!
//! Both client→server and server→client messages are JSON objects.
//! Each request carries a `kind` discriminator; each response
//! carries a `type` discriminator and (if it's a reply to a
//! specific request) the same `request_id` the client supplied.
//!
//! Request kinds:
//!   - `attach` — present an invitation token; on success the
//!     connection becomes "subscribed" to the session and
//!     receives broadcasts of every transition.
//!   - `submit_round1` — submit your round-1 commitment bytes
//!   - `submit_round2` — submit your round-2 sig-share bytes
//!   - `submit_aggregate` — submit the aggregate signature
//!   - `abort` — abort the session
//!   - `tick` — admin/debug; force a deadline check
//!
//! Response types:
//!   - `accepted` { request_id, transition }
//!   - `rejected` { request_id, code, message }
//!   - `state_change` { session_id, new_state }
//!   - `aggregated` { session_id, signature }
//!   - `aborted` { session_id, reason }
//!
//! Sessions are created OUT-OF-BAND by an operator using a
//! separate CLI (phase 4.5; not in this commit). The server reads
//! the SessionStore at startup and serves whatever sessions it
//! finds; `attach` against an unknown session_id rejects.
//!
//! ## Operator setup (phase 4)
//!
//! ```bash
//! # Generate a session out of band by writing the JSON file
//! # directly. Real CLI tooling is phase 4.5.
//! mkdir -p /var/lib/coincync-coord
//! # ... write sessions.json ...
//!
//! # Run the server
//! COINCYNC_COORD_LISTEN=127.0.0.1:8443 \
//! COINCYNC_COORD_STATE=/var/lib/coincync-coord/sessions.json \
//! COINCYNC_COORD_INVITE_SECRET=<hex32> \
//! ./coord
//! ```

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use governor::clock::DefaultClock;
use governor::{Quota, RateLimiter};
use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use coincync_frost_coordinator::{
    invitations::{verify_token, InvitationError, InvitationToken, SESSION_SECRET_LEN},
    session::{ParticipantId, Session, SessionId, SessionState, Transition},
    CoordinatorError, SessionStore,
};

/// Maximum bytes accepted in a single WebSocket message. Sized
/// for FROST round-2 sig shares (~64 bytes) plus headroom for
/// debug fields. Defends against state-exhaustion DoS.
const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Maximum number of concurrent WebSocket connections. Bounds
/// memory; phase 6 makes this enforceable but not configurable —
/// future ops work can promote it to an env var.
const MAX_CONNECTIONS: usize = 1000;

/// Channel capacity for per-session broadcast. A single session
/// won't generate many events (a few transitions over its
/// lifetime); 64 is plenty.
const SESSION_BROADCAST_CAPACITY: usize = 64;

/// Per-IP attach-rate limit (per minute). Defends against an
/// attacker spamming attach attempts to exhaust state. 60/min is
/// loose enough that a legitimate user (one attach per session,
/// at most a handful of sessions per hour) has zero friction;
/// tight enough that a flood is bounded.
const ATTACH_RATE_PER_MINUTE_PER_IP: u32 = 60;

/// Idle-connection timeout. After this many seconds of NO
/// inbound traffic from a connection, we close it. Defends
/// against connection-hoarding attacks that open a socket and
/// never speak. 5 minutes is long enough to absorb human-paced
/// flows + occasional WSS keepalive gaps.
const IDLE_TIMEOUT_SECS: u64 = 300;

/// Default metrics endpoint bind address.
const DEFAULT_METRICS_LISTEN: &str = "127.0.0.1:9100";

// ──────────────────────────────────────────────────────────────────
// Wire types
// ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Request {
    Attach {
        request_id: String,
        token: InvitationToken,
    },
    /// Declare the message being signed. Only the session creator
    /// should send this; CIP-008 doesn't enforce authorship at the
    /// state-machine level, so phase 6 may add an authorship check
    /// here. Phase 4 accepts from any attached participant.
    DeclareMessage {
        request_id: String,
        session_id: SessionId,
        message: Vec<u8>,
    },
    SubmitRound1 {
        request_id: String,
        session_id: SessionId,
        participant: ParticipantId,
        commitment: Vec<u8>,
    },
    SubmitRound2 {
        request_id: String,
        session_id: SessionId,
        participant: ParticipantId,
        sig_share: Vec<u8>,
    },
    SubmitAggregate {
        request_id: String,
        session_id: SessionId,
        signature: Vec<u8>,
    },
    Abort {
        request_id: String,
        session_id: SessionId,
        participant: ParticipantId,
    },
    Tick {
        request_id: String,
        session_id: SessionId,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Response {
    /// The request was accepted; state may have advanced. Reply
    /// to a specific request, so it carries the request_id.
    Accepted {
        request_id: String,
        new_state: String,
    },
    /// The request was rejected. State is UNCHANGED.
    Rejected {
        request_id: String,
        code: &'static str,
        message: String,
    },
    /// Broadcast: a session's state changed (any reason).
    StateChange {
        session_id: SessionId,
        new_state: String,
    },
    /// Broadcast: a session reached `Aggregated`. Signature is
    /// available for participants to read.
    Aggregated {
        session_id: SessionId,
        signature: Vec<u8>,
    },
    /// Broadcast: a session reached `Aborted` or `Expired`.
    Aborted {
        session_id: SessionId,
        reason: String,
    },
}

// ──────────────────────────────────────────────────────────────────
// Server state
// ──────────────────────────────────────────────────────────────────

/// Type alias for the per-IP attach-rate limiter. governor's
/// keyed-state limiter wraps a HashMap<IpAddr, _> internally;
/// the type signature is verbose so we hide it here.
type AttachLimiter = governor::RateLimiter<
    IpAddr,
    governor::state::keyed::DashMapStateStore<IpAddr>,
    DefaultClock,
>;

/// Prometheus metrics registered on the dedicated metrics
/// endpoint. Each field is a separate counter / gauge so a
/// scraper can chart them independently.
struct Metrics {
    registry: Registry,
    /// Total connection attempts (success + reject).
    connections_attempted: IntCounter,
    /// Connection attempts rejected because MAX_CONNECTIONS hit.
    connections_rejected_limit: IntCounter,
    /// Currently-active connection count.
    connections_active: IntGauge,
    /// Attach attempts grouped by outcome (accepted / rejected).
    attach_attempts: IntCounterVec,
    /// Attestation-equivalent: state-machine transitions accepted
    /// or rejected (by transition kind label).
    transitions: IntCounterVec,
    /// Per-IP attach rate-limit hits.
    attach_rate_limit_hits: IntCounter,
    /// Connections closed because the idle-timeout fired.
    idle_timeouts: IntCounter,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        let connections_attempted =
            IntCounter::new("coord_connections_attempted_total", "Total WSS connections accepted")
                .expect("static counter init");
        let connections_rejected_limit = IntCounter::new(
            "coord_connections_rejected_max_total",
            "Connections rejected because MAX_CONNECTIONS was reached",
        )
        .expect("static counter init");
        let connections_active = IntGauge::new(
            "coord_connections_active",
            "Currently-active WSS connections",
        )
        .expect("static gauge init");
        let attach_attempts = IntCounterVec::new(
            Opts::new("coord_attach_attempts_total", "Attach requests by outcome"),
            &["outcome"],
        )
        .expect("static counter init");
        let transitions = IntCounterVec::new(
            Opts::new(
                "coord_transitions_total",
                "State-machine transitions by kind and outcome",
            ),
            &["kind", "outcome"],
        )
        .expect("static counter init");
        let attach_rate_limit_hits = IntCounter::new(
            "coord_attach_rate_limit_hits_total",
            "Attach attempts dropped by per-IP rate limiter",
        )
        .expect("static counter init");
        let idle_timeouts = IntCounter::new(
            "coord_idle_timeouts_total",
            "Connections closed because the idle-timeout fired",
        )
        .expect("static counter init");

        for c in [
            Box::new(connections_attempted.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(connections_rejected_limit.clone()),
            Box::new(connections_active.clone()),
            Box::new(attach_attempts.clone()),
            Box::new(transitions.clone()),
            Box::new(attach_rate_limit_hits.clone()),
            Box::new(idle_timeouts.clone()),
        ] {
            registry
                .register(c)
                .expect("registering static metric must not fail");
        }

        Metrics {
            registry,
            connections_attempted,
            connections_rejected_limit,
            connections_active,
            attach_attempts,
            transitions,
            attach_rate_limit_hits,
            idle_timeouts,
        }
    }
}

struct Coord {
    /// All sessions known to the coordinator. Keyed by SessionId.
    sessions: RwLock<HashMap<SessionId, Session>>,

    /// Per-session broadcast channels. Each attached connection
    /// holds a `Receiver`; transitions emit on the `Sender`.
    broadcasters: RwLock<HashMap<SessionId, broadcast::Sender<Response>>>,

    /// Per-session secret used to verify invitation tokens.
    /// Single secret across all sessions for phase 4; phase 6 will
    /// make per-session secrets.
    invite_secret: [u8; SESSION_SECRET_LEN],

    /// Persistence backing.
    store: SessionStore,

    /// Active connection count. Used to enforce MAX_CONNECTIONS.
    connections: RwLock<usize>,

    /// Per-IP attach-rate limiter (phase 6). Quota-keyed by
    /// IpAddr; uses `governor` with an in-memory dashmap.
    attach_limiter: AttachLimiter,

    /// Prometheus metrics for the dedicated metrics endpoint.
    metrics: Arc<Metrics>,
}

impl Coord {
    fn new(invite_secret: [u8; SESSION_SECRET_LEN], store: SessionStore) -> Self {
        let quota = Quota::per_minute(
            NonZeroU32::new(ATTACH_RATE_PER_MINUTE_PER_IP)
                .expect("ATTACH_RATE_PER_MINUTE_PER_IP must be > 0"),
        );
        let attach_limiter = RateLimiter::keyed(quota);
        Coord {
            sessions: RwLock::new(HashMap::new()),
            broadcasters: RwLock::new(HashMap::new()),
            invite_secret,
            store,
            connections: RwLock::new(0),
            attach_limiter,
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// Load any existing sessions from disk on startup.
    async fn load_existing_sessions(&self) -> Result<usize, String> {
        let loaded = self.store.load().map_err(|e| format!("load failed: {e}"))?;
        let count = loaded.len();
        let mut sessions = self.sessions.write().await;
        let mut broadcasters = self.broadcasters.write().await;
        for s in loaded {
            broadcasters
                .entry(s.id)
                .or_insert_with(|| broadcast::channel(SESSION_BROADCAST_CAPACITY).0);
            sessions.insert(s.id, s);
        }
        Ok(count)
    }

    /// Persist all sessions atomically. Called after every
    /// accepted transition.
    async fn persist(&self) -> Result<(), String> {
        let sessions = self.sessions.read().await;
        let snapshot: Vec<Session> = sessions.values().cloned().collect();
        self.store
            .save(&snapshot)
            .map_err(|e| format!("save failed: {e}"))?;
        Ok(())
    }

    /// Apply a transition + handle persistence + handle broadcast.
    /// Returns the new state name for the response.
    async fn apply_transition(
        &self,
        session_id: SessionId,
        transition: Transition,
    ) -> Result<String, CoordinatorError> {
        let now = unix_now();
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| CoordinatorError::Internal("unknown session".into()))?;
        // Snapshot state before applying so the broadcast can tell
        // whether to emit Aggregated / Aborted special-cases.
        let prior_state = session.state.clone();
        session.apply(transition.clone(), now)?;
        let new_state = state_name(&session.state).to_string();
        let aggregate_sig = session.aggregate_signature.clone();
        let session_id_copy = session.id;
        let new_state_for_broadcast = session.state.clone();
        // Drop the lock before persisting + broadcasting (those
        // do their own I/O).
        drop(sessions);

        if let Err(e) = self.persist().await {
            warn!(
                ?session_id, error=%e,
                "persist failed after transition; in-memory state has advanced but on-disk view is stale"
            );
        }

        // Broadcast state-change to attached connections.
        let broadcasters = self.broadcasters.read().await;
        if let Some(tx) = broadcasters.get(&session_id_copy) {
            let _ = tx.send(Response::StateChange {
                session_id: session_id_copy,
                new_state: new_state.clone(),
            });
            // If we just became Aggregated, broadcast the signature.
            if new_state_for_broadcast == SessionState::Aggregated {
                if let Some(sig) = aggregate_sig {
                    let _ = tx.send(Response::Aggregated {
                        session_id: session_id_copy,
                        signature: sig,
                    });
                }
            }
            // If we just became Aborted or Expired, broadcast.
            if matches!(
                (
                    prior_state.is_terminal(),
                    new_state_for_broadcast.is_terminal()
                ),
                (false, true)
            ) && new_state_for_broadcast != SessionState::Aggregated
            {
                let _ = tx.send(Response::Aborted {
                    session_id: session_id_copy,
                    reason: format!("session entered {new_state}"),
                });
            }
        }
        let _ = transition; // suppress unused-variable warning
        Ok(new_state)
    }
}

// ──────────────────────────────────────────────────────────────────
// Connection handler
// ──────────────────────────────────────────────────────────────────

async fn handle_connection(coord: Arc<Coord>, stream: TcpStream, peer: SocketAddr) {
    coord.metrics.connections_attempted.inc();
    {
        let mut count = coord.connections.write().await;
        if *count >= MAX_CONNECTIONS {
            coord.metrics.connections_rejected_limit.inc();
            warn!(?peer, "rejected: connection limit reached");
            return;
        }
        *count += 1;
        coord.metrics.connections_active.set(*count as i64);
    }
    debug!(?peer, "client connected");

    let result = run_connection(coord.clone(), stream, peer).await;

    {
        let mut count = coord.connections.write().await;
        *count = count.saturating_sub(1);
        coord.metrics.connections_active.set(*count as i64);
    }
    match result {
        Ok(()) => debug!(?peer, "client disconnected cleanly"),
        Err(e) => warn!(?peer, error=%e, "client disconnected with error"),
    }
}

async fn run_connection(
    coord: Arc<Coord>,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<(), String> {
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| format!("ws accept: {e}"))?;
    let (mut sink, mut stream_in) = ws.split();

    // Per-connection state: which sessions has this connection
    // attached to? We hold one broadcast::Receiver per attached
    // session.
    let mut attached: HashMap<SessionId, broadcast::Receiver<Response>> = HashMap::new();
    let idle_timeout = Duration::from_secs(IDLE_TIMEOUT_SECS);

    loop {
        // Multiplex: either an inbound WS message, a broadcast
        // event from any attached session, or the idle-timeout
        // expiring. The timeout resets on every inbound message;
        // a connection that goes silent past the timeout window
        // is closed.
        tokio::select! {
            ws_msg = tokio::time::timeout(idle_timeout, stream_in.next()) => {
                let ws_msg = match ws_msg {
                    Ok(m) => m,
                    Err(_) => {
                        // Idle-timeout expired. Close the
                        // connection so a hoarding peer can't
                        // keep state pinned indefinitely.
                        coord.metrics.idle_timeouts.inc();
                        debug!(?peer, "idle timeout; closing connection");
                        return Ok(());
                    }
                };
                let Some(msg_result) = ws_msg else {
                    return Ok(()); // stream ended
                };
                let msg = msg_result.map_err(|e| format!("ws read: {e}"))?;
                match msg {
                    Message::Text(text) => {
                        if text.len() > MAX_MESSAGE_BYTES {
                            return Err(format!("message too large: {} bytes", text.len()));
                        }
                        let response = handle_request(&coord, &text, &mut attached, peer.ip()).await;
                        let payload = serde_json::to_string(&response)
                            .map_err(|e| format!("encode response: {e}"))?;
                        sink.send(Message::Text(payload.into()))
                            .await
                            .map_err(|e| format!("ws send: {e}"))?;
                    }
                    Message::Binary(_) => {
                        // We use JSON exclusively. Binary frames
                        // are rejected as a protocol violation.
                        return Err("binary frames not accepted".into());
                    }
                    Message::Close(_) => return Ok(()),
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                        // Tungstenite handles ping/pong automatically.
                    }
                }
            }
            broadcast_event = next_broadcast(&mut attached) => {
                match broadcast_event {
                    Some(Ok(event)) => {
                        let payload = serde_json::to_string(&event)
                            .map_err(|e| format!("encode broadcast: {e}"))?;
                        sink.send(Message::Text(payload.into()))
                            .await
                            .map_err(|e| format!("ws send: {e}"))?;
                    }
                    Some(Err(_lag)) => {
                        // RecvError::Lagged means we missed events
                        // because the broadcast channel filled up.
                        // Phase 4 just logs; phase 6 may close the
                        // connection so the client knows to refetch.
                        warn!(?peer, "broadcast lagged; client may have missed events");
                    }
                    None => {
                        // No attached sessions -> the future is a
                        // pending future that resolves only when
                        // the attached map gets populated. The
                        // tokio::select biases ws_msg first so this
                        // arm only fires when there ARE attached
                        // sessions; the None case can't happen
                        // here in practice.
                    }
                }
            }
        }
    }
}

/// Future: the next broadcast event from any attached session.
/// If the attached map is empty, returns `None` immediately so
/// the caller's `tokio::select!` keeps waiting on the WS read.
async fn next_broadcast(
    attached: &mut HashMap<SessionId, broadcast::Receiver<Response>>,
) -> Option<Result<Response, broadcast::error::RecvError>> {
    if attached.is_empty() {
        return std::future::pending().await;
    }
    // Race the receivers. We use `select_all` semantics by
    // polling each in turn; a real production server would use
    // `futures::stream::select_all` over an iterator of
    // `BroadcastStream`s for O(N)-fairness. Phase 4 keeps it
    // simple.
    let mut futures = Vec::with_capacity(attached.len());
    for (_sid, rx) in attached.iter_mut() {
        futures.push(Box::pin(rx.recv()));
    }
    let (result, _idx, _rest) = futures_util::future::select_all(futures).await;
    Some(result)
}

// ──────────────────────────────────────────────────────────────────
// Request dispatch
// ──────────────────────────────────────────────────────────────────

async fn handle_request(
    coord: &Arc<Coord>,
    text: &str,
    attached: &mut HashMap<SessionId, broadcast::Receiver<Response>>,
    peer_ip: IpAddr,
) -> Response {
    let req: Request = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(e) => {
            return Response::Rejected {
                request_id: String::new(),
                code: "bad_request",
                message: format!("malformed JSON: {e}"),
            };
        }
    };

    match req {
        Request::Attach { request_id, token } => {
            handle_attach(coord, request_id, token, attached, peer_ip).await
        }
        Request::DeclareMessage {
            request_id,
            session_id,
            message,
        } => {
            apply_helper(
                coord,
                &request_id,
                session_id,
                Transition::DeclareMessage { message },
            )
            .await
        }
        Request::SubmitRound1 {
            request_id,
            session_id,
            participant,
            commitment,
        } => {
            apply_helper(
                coord,
                &request_id,
                session_id,
                Transition::SubmitRound1 {
                    participant,
                    commitment,
                },
            )
            .await
        }
        Request::SubmitRound2 {
            request_id,
            session_id,
            participant,
            sig_share,
        } => {
            apply_helper(
                coord,
                &request_id,
                session_id,
                Transition::SubmitRound2 {
                    participant,
                    sig_share,
                },
            )
            .await
        }
        Request::SubmitAggregate {
            request_id,
            session_id,
            signature,
        } => {
            apply_helper(
                coord,
                &request_id,
                session_id,
                Transition::SubmitAggregate { signature },
            )
            .await
        }
        Request::Abort {
            request_id,
            session_id,
            participant,
        } => {
            apply_helper(
                coord,
                &request_id,
                session_id,
                Transition::Abort { participant },
            )
            .await
        }
        Request::Tick {
            request_id,
            session_id,
        } => apply_helper(coord, &request_id, session_id, Transition::Tick).await,
    }
}

async fn handle_attach(
    coord: &Arc<Coord>,
    request_id: String,
    token: InvitationToken,
    attached: &mut HashMap<SessionId, broadcast::Receiver<Response>>,
    peer_ip: IpAddr,
) -> Response {
    // Phase 6: per-IP attach rate-limit. The check is non-blocking
    // (`check_key`); a denied attempt returns immediately without
    // ever touching the state machine.
    //
    // The bucket key is the CANONICALIZED IP — we collapse an
    // IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to its IPv4 form so a
    // single client can't get two buckets by toggling families.
    // For IPv6 we further bucket by /64 prefix because rotating
    // within a /64 is trivially cheap for an attacker; treating
    // the whole /64 as one entity is the standard mitigation.
    let bucket_ip = canonicalize_ip_for_rate_limit(peer_ip);
    if coord.attach_limiter.check_key(&bucket_ip).is_err() {
        coord.metrics.attach_rate_limit_hits.inc();
        coord
            .metrics
            .attach_attempts
            .with_label_values(&["rate_limited"])
            .inc();
        return Response::Rejected {
            request_id,
            code: "rate_limited",
            message: format!(
                "attach rate limit exceeded ({} attempts/min/IP)",
                ATTACH_RATE_PER_MINUTE_PER_IP
            ),
        };
    }

    let now = unix_now();
    // Borrow `invite_secret` directly rather than copying onto the
    // stack. The previous `let secret = coord.invite_secret;` made a
    // stack-resident copy that lingered until the function frame was
    // overwritten — observable to an attacker with stack-read primitive
    // (rare, but free to close). Audit-prep nicety, no behavioral change.
    if let Err(e) = verify_token(&coord.invite_secret, &token, now) {
        coord
            .metrics
            .attach_attempts
            .with_label_values(&["bad_token"])
            .inc();
        return Response::Rejected {
            request_id,
            code: invitation_error_code(&e),
            message: e.to_string(),
        };
    }

    // Verify the session exists.
    let sessions = coord.sessions.read().await;
    if !sessions.contains_key(&token.session_id) {
        coord
            .metrics
            .attach_attempts
            .with_label_values(&["unknown_session"])
            .inc();
        return Response::Rejected {
            request_id,
            code: "unknown_session",
            message: "session not found in coordinator state".into(),
        };
    }
    drop(sessions);

    // Apply the AttachParticipant transition.
    match coord
        .apply_transition(
            token.session_id,
            Transition::AttachParticipant {
                participant: token.participant_pubkey,
            },
        )
        .await
    {
        Ok(new_state) => {
            // Subscribe this connection to broadcasts for the
            // session.
            let broadcasters = coord.broadcasters.read().await;
            if let Some(tx) = broadcasters.get(&token.session_id) {
                let rx = tx.subscribe();
                attached.insert(token.session_id, rx);
            }
            coord
                .metrics
                .attach_attempts
                .with_label_values(&["accepted"])
                .inc();
            Response::Accepted {
                request_id,
                new_state,
            }
        }
        Err(e) => {
            coord
                .metrics
                .attach_attempts
                .with_label_values(&["rejected"])
                .inc();
            Response::Rejected {
                request_id,
                code: coordinator_error_code(&e),
                message: e.to_string(),
            }
        }
    }
}

async fn apply_helper(
    coord: &Arc<Coord>,
    request_id: &str,
    session_id: SessionId,
    transition: Transition,
) -> Response {
    let kind = transition_kind(&transition);
    match coord.apply_transition(session_id, transition).await {
        Ok(new_state) => {
            coord
                .metrics
                .transitions
                .with_label_values(&[kind, "accepted"])
                .inc();
            Response::Accepted {
                request_id: request_id.to_string(),
                new_state,
            }
        }
        Err(e) => {
            coord
                .metrics
                .transitions
                .with_label_values(&[kind, "rejected"])
                .inc();
            Response::Rejected {
                request_id: request_id.to_string(),
                code: coordinator_error_code(&e),
                message: e.to_string(),
            }
        }
    }
}

/// Kind label for the `coord_transitions_total{kind=...}`
/// Prometheus metric. Static-string return so the labels stay
/// bounded — no high-cardinality leakage.
fn transition_kind(t: &Transition) -> &'static str {
    match t {
        Transition::AttachParticipant { .. } => "attach",
        Transition::DeclareMessage { .. } => "declare_message",
        Transition::SubmitRound1 { .. } => "submit_round1",
        Transition::SubmitRound2 { .. } => "submit_round2",
        Transition::SubmitAggregate { .. } => "submit_aggregate",
        Transition::Abort { .. } => "abort",
        Transition::Tick => "tick",
    }
}

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

fn invitation_error_code(e: &InvitationError) -> &'static str {
    match e {
        InvitationError::BadSecretLength => "bad_secret_length",
        InvitationError::Expired { .. } => "token_expired",
        InvitationError::BadMac => "token_invalid",
    }
}

fn coordinator_error_code(e: &CoordinatorError) -> &'static str {
    match e {
        CoordinatorError::InvalidTransition { .. } => "invalid_transition",
        CoordinatorError::UnauthorizedParticipant => "unauthorized_participant",
        CoordinatorError::SessionTerminal { .. } => "session_terminal",
        CoordinatorError::SessionExpired { .. } => "session_expired",
        CoordinatorError::ThresholdViolation { .. } => "threshold_violation",
        CoordinatorError::DuplicateAction { .. } => "duplicate_action",
        CoordinatorError::Internal(_) => "internal_error",
    }
}

fn state_name(s: &SessionState) -> &'static str {
    match s {
        SessionState::Created => "Created",
        SessionState::Invited => "Invited",
        SessionState::Round1 => "Round1",
        SessionState::Round2 => "Round2",
        SessionState::Aggregated => "Aggregated",
        SessionState::Aborted => "Aborted",
        SessionState::Expired => "Expired",
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map an inbound peer IP to the bucket key the rate limiter
/// should use. Two normalizations:
///
/// 1. **IPv4-mapped IPv6 → IPv4.** `::ffff:1.2.3.4` and
///    `1.2.3.4` are the same client; a misconfigured stack
///    can flip between them on reconnects. Without this,
///    one client gets two rate-limit buckets and effectively
///    doubles its allowed rate.
///
/// 2. **IPv6 /64 collapse.** A single IPv6 client typically
///    has a /64 of their own; rotating addresses within their
///    own /64 is trivial. Treating the /64 as one bucket means
///    the rate limit applies to the client, not to each IP they
///    can rotate to.
fn canonicalize_ip_for_rate_limit(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            // Pull out an embedded IPv4 if present (::ffff:x.y.z.w
            // form). std::net::Ipv6Addr::to_ipv4_mapped() is
            // stable since 1.85; we open-code it for MSRV 1.75.
            let segments = v6.segments();
            let is_v4_mapped = segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0xffff;
            if is_v4_mapped {
                let high = segments[6];
                let low = segments[7];
                return IpAddr::V4(std::net::Ipv4Addr::new(
                    (high >> 8) as u8,
                    (high & 0xff) as u8,
                    (low >> 8) as u8,
                    (low & 0xff) as u8,
                ));
            }
            // Otherwise collapse to /64 (zero out the lower 64 bits).
            IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0, 0, 0, 0,
            ))
        }
    }
}

fn parse_invite_secret(hex_str: &str) -> Result<[u8; SESSION_SECRET_LEN], String> {
    if hex_str.len() != SESSION_SECRET_LEN * 2 {
        return Err(format!(
            "invite secret must be {} hex chars (= {} bytes)",
            SESSION_SECRET_LEN * 2,
            SESSION_SECRET_LEN
        ));
    }
    let mut out = [0u8; SESSION_SECRET_LEN];
    for (i, byte_pair) in hex_str.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(byte_pair).map_err(|_| "non-ASCII hex".to_string())?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| "non-hex character".to_string())?;
    }
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────
// Main
// ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            error!(error=%e, "coord exiting with error");
            std::process::ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), String> {
    let listen: SocketAddr = env::var("COINCYNC_COORD_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8443".to_string())
        .parse()
        .map_err(|e| format!("invalid COINCYNC_COORD_LISTEN: {e}"))?;
    let metrics_listen: SocketAddr = env::var("COINCYNC_COORD_METRICS_LISTEN")
        .unwrap_or_else(|_| DEFAULT_METRICS_LISTEN.to_string())
        .parse()
        .map_err(|e| format!("invalid COINCYNC_COORD_METRICS_LISTEN: {e}"))?;
    let state_path = env::var("COINCYNC_COORD_STATE")
        .unwrap_or_else(|_| "/var/lib/coincync-coord/sessions.json".to_string());
    let secret_hex = env::var("COINCYNC_COORD_INVITE_SECRET")
        .map_err(|_| "COINCYNC_COORD_INVITE_SECRET environment variable not set".to_string())?;
    let secret = parse_invite_secret(&secret_hex)?;

    let store = SessionStore::new(PathBuf::from(state_path.clone()));
    let coord = Arc::new(Coord::new(secret, store));

    let n = coord.load_existing_sessions().await?;
    info!(
        listen = %listen,
        metrics_listen = %metrics_listen,
        state_file = %state_path,
        existing_sessions = n,
        "coord starting"
    );

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {listen}: {e}"))?;

    // Run accept loop until SIGINT.
    let coord_for_loop = coord.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let coord = coord_for_loop.clone();
                    tokio::spawn(async move {
                        handle_connection(coord, stream, peer).await;
                    });
                }
                Err(e) => {
                    warn!(error=%e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    // Phase 6: dedicated metrics endpoint on a separate port. A
    // metrics-scrape flood on port 9100 cannot exhaust state on
    // the protocol port 8443 because they're independent
    // listeners.
    let metrics_task = tokio::spawn(serve_metrics(coord.clone(), metrics_listen));

    // Wait for SIGINT.
    let _ = signal::ctrl_c().await;
    info!("SIGINT received; shutting down");
    accept_task.abort();
    metrics_task.abort();
    // Best-effort final persist.
    if let Err(e) = coord.persist().await {
        warn!(error=%e, "final persist failed during shutdown");
    }
    Ok(())
}

/// Serve the Prometheus `/metrics` endpoint on `bind`. Returns
/// only when the spawned task is aborted.
async fn serve_metrics(coord: Arc<Coord>, bind: SocketAddr) {
    use axum::routing::get;
    use axum::Router;

    let coord_for_handler = coord.clone();
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let coord = coord_for_handler.clone();
            async move { render_metrics(coord).await }
        }),
    );

    match TcpListener::bind(bind).await {
        Ok(listener) => {
            info!(?bind, "metrics endpoint listening");
            if let Err(e) = axum::serve(listener, app).await {
                warn!(error=%e, "metrics server exited");
            }
        }
        Err(e) => {
            warn!(?bind, error=%e, "metrics endpoint failed to bind");
        }
    }
}

async fn render_metrics(coord: Arc<Coord>) -> (axum::http::StatusCode, String) {
    let metric_families = coord.metrics.registry.gather();
    let encoder = TextEncoder::new();
    match encoder.encode_to_string(&metric_families) {
        Ok(body) => (axum::http::StatusCode::OK, body),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("metrics encode failed: {e}"),
        ),
    }
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invite_secret_accepts_64_hex_chars() {
        let hex = "00".repeat(SESSION_SECRET_LEN);
        let parsed = parse_invite_secret(&hex).unwrap();
        assert_eq!(parsed, [0u8; SESSION_SECRET_LEN]);
    }

    #[test]
    fn parse_invite_secret_rejects_wrong_length() {
        assert!(parse_invite_secret("aabbcc").is_err());
        assert!(parse_invite_secret(&"00".repeat(64)).is_err()); // 128 hex chars
    }

    #[test]
    fn parse_invite_secret_rejects_non_hex() {
        let bad = "z".repeat(SESSION_SECRET_LEN * 2);
        assert!(parse_invite_secret(&bad).is_err());
    }

    #[test]
    fn invitation_error_codes_distinct() {
        // Unique stable strings — clients dispatch on these.
        let codes = [
            invitation_error_code(&InvitationError::BadSecretLength),
            invitation_error_code(&InvitationError::Expired {
                expires_at: 0,
                now: 0,
            }),
            invitation_error_code(&InvitationError::BadMac),
        ];
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn coordinator_error_codes_distinct() {
        let codes = [
            coordinator_error_code(&CoordinatorError::InvalidTransition {
                transition: "x".into(),
                state: "y".into(),
            }),
            coordinator_error_code(&CoordinatorError::UnauthorizedParticipant),
            coordinator_error_code(&CoordinatorError::SessionTerminal { state: "z".into() }),
            coordinator_error_code(&CoordinatorError::SessionExpired { state: "z".into() }),
            coordinator_error_code(&CoordinatorError::ThresholdViolation { what: "x".into() }),
            coordinator_error_code(&CoordinatorError::DuplicateAction { what: "x".into() }),
            coordinator_error_code(&CoordinatorError::Internal("x".into())),
        ];
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn request_round_trips_through_json() {
        // Sanity: client can decode what server encodes.
        let req = Request::SubmitRound1 {
            request_id: "abc".into(),
            session_id: SessionId::new(),
            participant: ParticipantId([0xAA; 32]),
            commitment: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        match decoded {
            Request::SubmitRound1 { request_id, .. } => assert_eq!(request_id, "abc"),
            _ => panic!("decoded as wrong variant"),
        }
    }

    #[test]
    fn response_serializes_with_type_discriminator() {
        let r = Response::Accepted {
            request_id: "x".into(),
            new_state: "Round1".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""type":"accepted""#));
        assert!(json.contains(r#""new_state":"Round1""#));
    }
}
