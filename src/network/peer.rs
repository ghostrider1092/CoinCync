//! # Peer Management
//!
//! P2P peer connection handling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;
use crate::primitives::Hash;
use crate::error::{Error, Result};

/// Peer identifier (32 bytes)
pub type PeerId = [u8; 32];

/// Generate random peer ID using cryptographically secure RNG
pub fn generate_peer_id() -> PeerId {
    use rand::RngCore;
    use rand::rngs::OsRng;
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    id
}

/// Peer connection state.
///
/// AUDIT (2026-07-02): removed 3 dead variants (`Handshaking`,
/// `Disconnecting`, `Disconnected`). Grep-verified across the entire
/// repo (src/ + tests/): zero writes and zero reads for any of them.
/// The observed lifecycle is a strict 3-state progression:
///
///   Connecting → VersionReceived → Connected
///
/// with `Connecting` set at `network/peer.rs:108`, `VersionReceived`
/// at `network/node.rs:3091` (handle_version), and `Connected` at
/// `network/node.rs:3132` (handle_verack). "Handshaking" and
/// "Disconnecting" appear to have been part of an early state-machine
/// sketch that was never wired up — a common code-history shape.
/// "Disconnected" reflected a not-implemented graceful-shutdown path;
/// today, peer teardown drops the peer struct directly rather than
/// transitioning through a Disconnected state.
///
/// The removal is safe: `PeerState` is not Borsh-persisted (grep
/// confirms no `BorshSerialize`/`BorshDeserialize` derive on the
/// enum), so the discriminant renumbering has no on-disk-format
/// implication. If a future feature needs a Disconnecting handshake
/// (e.g. Noise-level goodbye frame) or a Disconnected-with-reason
/// terminal state, those variants should be added back with real
/// write/read sites at the same time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Connection pending (TCP not yet up).
    Connecting,
    /// Version message received, awaiting Verack.
    VersionReceived,
    /// Connected and ready.
    Connected,
}

/// Peer information
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Peer ID
    pub id: PeerId,
    /// Remote address
    pub addr: SocketAddr,
    /// Current state
    pub state: PeerState,
    /// Reported chain height
    pub height: u64,
    /// Reported tip hash
    pub tip_hash: Hash,
    /// Protocol version
    pub version: u32,
    /// User agent string
    pub user_agent: String,
    /// Last activity time
    pub last_seen: Instant,
    /// Connection start time. Set once at PeerInfo construction and
    /// not updated thereafter. Used to time the Noise + Version/Verack
    /// handshake (Phase 1 #6: `PEER_HANDSHAKE` histogram).
    pub connected_at: Instant,
    /// Reputation score
    pub reputation: i32,
    /// Whether we initiated the connection
    pub outbound: bool,
    /// Bytes received
    pub bytes_recv: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Whether this connection is Noise-encrypted
    pub encrypted: bool,
    /// Remote node's static X25519 public key (if Noise was used)
    pub remote_static_key: Option<[u8; 32]>,
    /// Firework: Flare capability bitfield received from this peer.
    /// Zero until a Flare message is received. Unknown bits are ignored.
    /// Use `firework::has_cap(peer.capabilities, CAP_*)` to test a feature.
    pub capabilities: u64,
    /// Consecutive `try_send(Full)` count for this peer's broadcast
    /// channel. Reset on any successful send. When it crosses the
    /// stall threshold (see `node/broadcast.rs::STALL_THRESHOLD`) the peer is
    /// disconnected. Atomic so the lock-free broadcast hot path can
    /// update it without taking a write lock on the peer table.
    pub consecutive_full: Arc<AtomicU32>,
    /// Identifies the connection instance that owns this map entry so an
    /// older task cannot remove a replacement connection with the same peer ID.
    pub(crate) connection_token: Arc<()>,
    /// Eclipse-defense per-/16 outbound slot. Some(slot) for outbound
    /// peers, None for inbound. The slot's lifetime is tied to this
    /// PeerInfo entry: when the entry is removed from the peers map
    /// or overwritten by a reconnection, the Arc decrements and (if
    /// last) drops, releasing the per-/16 counter slot. This binding
    /// is what makes the eclipse defense leak-free under the
    /// skip-cleanup branch in handle_connection — without it, the
    /// slot's lifetime would be tied to the spawn task, which can
    /// end while the peers entry stays. See ConnectionTracker for
    /// the slot's RAII semantics.
    pub eclipse_slot: Option<Arc<crate::network::connection_tracker::OutboundSubnetSlot>>,
}

impl PeerInfo {
    pub fn new(id: PeerId, addr: SocketAddr, outbound: bool) -> Self {
        let now = Instant::now();
        PeerInfo {
            id,
            addr,
            state: PeerState::Connecting,
            height: 0,
            tip_hash: Hash::zero(),
            version: 0,
            user_agent: String::new(),
            last_seen: now,
            connected_at: now,
            reputation: 100,
            outbound,
            bytes_recv: 0,
            bytes_sent: 0,
            encrypted: false,
            remote_static_key: None,
            capabilities: 0,
            consecutive_full: Arc::new(AtomicU32::new(0)),
            connection_token: Arc::new(()),
            eclipse_slot: None,
        }
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if peer is stale
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    /// Adjust reputation
    pub fn adjust_reputation(&mut self, delta: i32) {
        self.reputation = (self.reputation + delta).clamp(-100, 100);
    }

    /// Check if peer should be banned
    pub fn should_ban(&self) -> bool {
        self.reputation <= -50
    }

    /// Decay reputation toward neutral over time
    ///
    /// SECURITY: Reputation decay prevents permanent penalties for transient issues
    /// and prevents permanently "trusted" peers from exploiting their status.
    ///
    /// Call this periodically (e.g., every 5 minutes) to slowly normalize reputation.
    ///
    /// # Arguments
    /// * `decay_rate` - How many points to decay toward neutral (typically 1-5)
    /// * `neutral_reputation` - The neutral reputation value to decay toward (typically 50-100)
    ///
    /// # Example
    /// ```ignore
    /// // Decay 1 point every 5 minutes toward neutral (50)
    /// peer.decay_reputation(1, 50);
    /// ```
    pub fn decay_reputation(&mut self, decay_rate: i32, neutral_reputation: i32) {
        let neutral = neutral_reputation.clamp(-100, 100);

        if self.reputation > neutral {
            // Above neutral: decay down
            self.reputation = (self.reputation - decay_rate).max(neutral);
        } else if self.reputation < neutral {
            // Below neutral: decay up
            self.reputation = (self.reputation + decay_rate).min(neutral);
        }
        // At neutral: no change
    }

    /// Decay reputation with default parameters (decay 1 point toward 50)
    pub fn decay_reputation_default(&mut self) {
        self.decay_reputation(1, 50);
    }
}

/// Peer handle for communication
pub struct Peer {
    pub info: PeerInfo,
    /// Message sender
    tx: mpsc::Sender<Vec<u8>>,
    /// Shutdown signal
    shutdown: mpsc::Sender<()>,
}

impl Peer {
    /// Create peer from TCP stream
    pub async fn from_stream(
        stream: TcpStream,
        id: PeerId,
        outbound: bool,
    ) -> Result<(Self, PeerConnection)> {
        let addr = stream.peer_addr()
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        let info = PeerInfo::new(id, addr, outbound);
        let (tx, rx) = mpsc::channel(100);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let connection = PeerConnection {
            stream,
            rx,
            shutdown: shutdown_rx,
        };

        let peer = Peer {
            info,
            tx,
            shutdown: shutdown_tx,
        };

        Ok((peer, connection))
    }

    /// Send message to peer
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.tx.send(data).await
            .map_err(|_| Error::ConnectionFailed("peer disconnected".into()))
    }

    /// Disconnect peer
    pub async fn disconnect(&self) {
        let _ = self.shutdown.send(()).await;
    }

    /// Get peer ID as hex string
    pub fn id_hex(&self) -> String {
        hex::encode(&self.info.id[..8])
    }
}

/// Maximum message size — use the protocol-level constant for consistency
use super::protocol::MAX_MESSAGE_SIZE;

/// Maximum bytes to buffer before forcing a flush
const MAX_BUFFER_SIZE: usize = 64 * 1024;

/// Peer connection handler
pub struct PeerConnection {
    stream: TcpStream,
    rx: mpsc::Receiver<Vec<u8>>,
    shutdown: mpsc::Receiver<()>,
}

impl PeerConnection {
    /// Run the connection loop
    ///
    /// SECURITY: Implements message size limits to prevent memory exhaustion attacks.
    /// Messages larger than MAX_MESSAGE_SIZE are rejected and the connection is closed.
    ///
    /// PERF / DOS NOTE: `reader.read()` returns as soon as ≥1 byte is available,
    /// so a peer sending 1-byte TCP frames forces this loop to iterate once per
    /// byte. Per-connection cost is bounded by MAX_BYTES_PER_SECOND (10 MB/s) +
    /// WINDOW_BYTE_LIMIT (100 MB / 60s), so worst-case ~10 M loop iterations/sec
    /// per attacker connection. The framing layer (framing.rs) reassembles
    /// bytes into messages downstream — this layer just forwards raw bytes. If
    /// loop-overhead-per-iteration becomes a measured bottleneck, switching
    /// to `reader.read_exact(N)` for known frame-header sizes (12 bytes) would
    /// amortize the syscall storm; deferred until profiled, because the rate
    /// limits already cap the per-connection CPU cost.
    pub async fn run(mut self, msg_tx: mpsc::Sender<(PeerId, Vec<u8>)>, peer_id: PeerId) -> Result<()> {
        let (reader, writer) = self.stream.split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);
        let mut read_buf = vec![0u8; MAX_BUFFER_SIZE];

        // H-7 FIX: Rolling window instead of lifetime cumulative cap.
        // Prevents breaking IBD (initial block download) where legitimate
        // peers transfer gigabytes of historical blocks.
        let mut bytes_in_window: usize = 0;
        let mut window_start = Instant::now();
        const WINDOW_DURATION: Duration = Duration::from_secs(60);
        const WINDOW_BYTE_LIMIT: usize = 100 * 1024 * 1024; // 100 MB per 60s window

        let mut bytes_received_this_second: usize = 0;
        let mut last_rate_check = std::time::Instant::now();

        // Rate limit: 10 MB/second maximum
        const MAX_BYTES_PER_SECOND: usize = 10 * 1024 * 1024;

        loop {
            tokio::select! {
                // Check for shutdown
                _ = self.shutdown.recv() => {
                    break;
                }

                // Read from network
                result = reader.read(&mut read_buf) => {
                    match result {
                        Ok(0) => break, // Connection closed
                        Ok(n) => {
                            // SECURITY: Rate limiting check
                            bytes_received_this_second += n;
                            if last_rate_check.elapsed() >= Duration::from_secs(1) {
                                if bytes_received_this_second > MAX_BYTES_PER_SECOND {
                                    tracing::warn!(
                                        "Peer {} exceeded rate limit ({} bytes/sec), disconnecting",
                                        hex::encode(&peer_id[..8]),
                                        bytes_received_this_second
                                    );
                                    break;
                                }
                                bytes_received_this_second = 0;
                                last_rate_check = std::time::Instant::now();
                            }

                            // H-7 FIX: Rolling-window byte cap (replaces lifetime cumulative cap).
                            // Reset the window when the 60-second period expires.
                            if window_start.elapsed() >= WINDOW_DURATION {
                                bytes_in_window = 0;
                                window_start = Instant::now();
                            }
                            bytes_in_window += n;
                            if bytes_in_window > WINDOW_BYTE_LIMIT {
                                tracing::warn!(
                                    "Peer {} exceeded {}-byte rolling window limit, disconnecting",
                                    hex::encode(&peer_id[..8]),
                                    WINDOW_BYTE_LIMIT
                                );
                                break;
                            }

                            let data = read_buf[..n].to_vec();
                            if msg_tx.send((peer_id, data)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Read error: {}", e);
                            break;
                        }
                    }
                }

                // Write to network
                Some(data) = self.rx.recv() => {
                    // SECURITY: Validate outgoing message size
                    if data.len() > MAX_MESSAGE_SIZE {
                        tracing::error!(
                            "Attempted to send message exceeding {} bytes limit",
                            MAX_MESSAGE_SIZE
                        );
                        continue; // Skip this message but don't disconnect
                    }

                    if let Err(e) = writer.write_all(&data).await {
                        tracing::warn!("Write error: {}", e);
                        break;
                    }
                    if let Err(e) = writer.flush().await {
                        tracing::warn!("Flush error: {}", e);
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Address book entry
#[derive(Clone, Debug)]
pub struct AddressEntry {
    pub addr: SocketAddr,
    pub last_seen: u64,
    pub last_attempt: u64,
    pub attempts: u32,
    pub success: bool,
    pub source: AddressSource,
}

/// Source of address
#[derive(Clone, Copy, Debug)]
pub enum AddressSource {
    /// From DNS seeds
    Dns,
    /// From peer exchange
    Peer,
    /// Manual configuration
    Manual,
    /// From incoming connection
    Incoming,
}

impl AddressEntry {
    pub fn new(addr: SocketAddr, source: AddressSource) -> Self {
        AddressEntry {
            addr,
            last_seen: 0,
            last_attempt: 0,
            attempts: 0,
            success: false,
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_info() {
        let id = generate_peer_id();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let mut info = PeerInfo::new(id, addr, true);

        assert_eq!(info.state, PeerState::Connecting);
        assert_eq!(info.reputation, 100);

        info.adjust_reputation(-20);
        assert_eq!(info.reputation, 80);

        info.adjust_reputation(-150);
        // 80 - 150 = -70, clamped to [-100, 100] = -70
        assert_eq!(info.reputation, -70);
    }
}
