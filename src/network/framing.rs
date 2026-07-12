//! # Message Framing for TCP P2P
//!
//! Handles proper message boundaries over TCP streams.
//! TCP is a stream protocol - messages can be split across reads
//! or multiple messages can arrive in a single read.
//!
//! This module implements length-prefixed message framing to
//! ensure complete messages are delivered to the processor.
//!
//! # TODO: tokio_util::codec replacement opportunity
//!
//! The hand-rolled framing here could potentially use `tokio_util::codec::Decoder`
//! / `Encoder` traits (the crate is already a dependency with the `codec` feature).
//! However, the wire format is NOT a simple length-prefix: it is a 13-byte header
//! containing 4-byte magic + 1-byte message type + 4-byte payload length + 4-byte
//! checksum. `LengthDelimitedCodec` only handles length-prefixed framing and cannot
//! express the magic-byte validation, per-message-type size limits, or checksum
//! verification that this protocol requires. A custom `Decoder`/`Encoder` impl could
//! wrap the same logic but would not reduce complexity meaningfully, and any change
//! to the wire-level framing risks breaking compatibility with already-deployed nodes.
//! If a protocol v2 is introduced, consider migrating to a codec-based design then.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use crate::error::{Error, Result};
use crate::network::connection_tracker::{ConnectionTracker, MemoryReservation};
use crate::network::protocol::{MessageHeader, MAX_MESSAGE_SIZE};

/// Default read timeout — must be longer than PING_INTERVAL (120s)
/// to prevent killing idle but valid connections between pings.
/// Bitcoin uses 90 minutes; we use 5 minutes as a balance between
/// Slowloris protection and keeping good connections alive.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Message header size in bytes
pub const HEADER_SIZE: usize = 13; // 4 (magic) + 1 (type) + 4 (length) + 4 (checksum)

pub(crate) struct BudgetedMessage {
    pub(crate) msg_type: u8,
    pub(crate) payload: Vec<u8>,
    pub(crate) reservation: MemoryReservation,
}

struct FramedMessage {
    msg_type: u8,
    payload: Vec<u8>,
    reservation: Option<MemoryReservation>,
}

/// Connection state for message framing.
///
/// All read state lives on this struct (not on local variables in
/// `read_message_*`) so that a future dropped mid-message — which happens
/// every iteration of the per-peer `tokio::select!` loop, since outbound
/// `rx.recv()` cancels the in-flight read — does not lose bytes already
/// pulled out of the underlying reader.
pub struct MessageFramer<R, W> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    magic: [u8; 4],
    /// Partial header bytes being accumulated across (possibly cancelled) reads.
    header_buf: Vec<u8>,
    /// Partial payload bytes being accumulated across (possibly cancelled) reads.
    payload_buf: Vec<u8>,
    /// Expected payload length (from header)
    expected_len: usize,
    /// Whether we're past the header and into payload bytes.
    reading_payload: bool,
    tracker: Option<Arc<ConnectionTracker>>,
    reservation: Option<MemoryReservation>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> MessageFramer<R, W> {
    /// Create a new message framer
    pub fn new(reader: R, writer: W, magic: [u8; 4]) -> Self {
        Self::with_tracker(reader, writer, magic, None)
    }

    pub(crate) fn new_budgeted(
        reader: R,
        writer: W,
        magic: [u8; 4],
        tracker: Arc<ConnectionTracker>,
    ) -> Self {
        Self::with_tracker(reader, writer, magic, Some(tracker))
    }

    fn with_tracker(
        reader: R,
        writer: W,
        magic: [u8; 4],
        tracker: Option<Arc<ConnectionTracker>>,
    ) -> Self {
        MessageFramer {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            magic,
            header_buf: Vec::with_capacity(HEADER_SIZE),
            payload_buf: Vec::new(),
            expected_len: 0,
            reading_payload: false,
            tracker,
            reservation: None,
        }
    }

    /// Read the next complete message from the stream
    /// Returns (message_type, payload) on success
    pub async fn read_message(&mut self) -> Result<(u8, Vec<u8>)> {
        if self.tracker.is_some() {
            return Err(Error::ProtocolError(
                "budgeted framer requires the budget-preserving read API".into(),
            ));
        }
        loop {
            if !self.reading_payload {
                // Reading header
                let needed = HEADER_SIZE - self.header_buf.len();
                if needed > 0 {
                    let mut buf = vec![0u8; needed];
                    let n = self.reader.read(&mut buf).await
                        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

                    if n == 0 {
                        return Err(Error::ConnectionFailed("connection closed".into()));
                    }

                    self.header_buf.extend_from_slice(&buf[..n]);
                }

                // Check if we have complete header
                if self.header_buf.len() >= HEADER_SIZE {
                    // Parse header
                    let header = self.parse_header()?;

                    // Validate magic
                    if header.magic != self.magic {
                        self.header_buf.clear();
                        return Err(Error::ProtocolError("invalid magic".into()));
                    }

                    // Validate length against global limit
                    if header.length as usize > MAX_MESSAGE_SIZE {
                        return Err(Error::MessageTooLarge);
                    }

                    // SECURITY (H15-FIX): Per-command size limit enforcement.
                    // Each message type has its own max size to prevent oversized
                    // payloads for small message types (e.g., 16MB "Ping").
                    if let Ok(msg_type) = crate::network::protocol::MessageType::try_from(header.msg_type) {
                        let type_limit = msg_type.max_size();
                        if header.length as usize > type_limit {
                            tracing::warn!(
                                "Message type {:?} exceeds per-type limit: {} > {}",
                                msg_type, header.length, type_limit
                            );
                            return Err(Error::MessageTooLarge);
                        }
                    }

                    self.expected_len = header.length as usize;
                    self.reading_payload = true;
                    // SECURITY: Don't pre-allocate full buffer to prevent memory exhaustion attacks.
                    // An attacker could send headers claiming large payloads but never send the data.
                    // Instead, start with a reasonable initial allocation and grow as data arrives.
                    //
                    // PERF TRADE-OFF: For a worst-case 16 MB payload, this incremental
                    // strategy triggers ~8 reallocs (Vec doubles: 64K → 128K → … → 16M)
                    // and a final ~8 MB memcpy when growing from 8M to 16M. Per peer-
                    // connection cost; pooled-buffer reuse across messages would amortize
                    // this if/when throughput becomes a measured bottleneck. Currently
                    // accepted because memory-exhaustion safety dominates on a fresh peer
                    // (attacker claims 16M, never sends → we only commit 64K not 16M).
                    let initial_capacity = std::cmp::min(self.expected_len, 64 * 1024); // Max 64KB initial
                    self.payload_buf = Vec::with_capacity(initial_capacity);
                }
            }

            if self.reading_payload {
                // Reading payload
                let needed = self.expected_len - self.payload_buf.len();
                if needed > 0 {
                    // Read in chunks to avoid large temporary allocations
                    let to_read = std::cmp::min(needed, 65536);
                    let mut buf = vec![0u8; to_read];
                    let n = self.reader.read(&mut buf).await
                        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

                    if n == 0 {
                        return Err(Error::ConnectionFailed("connection closed".into()));
                    }

                    // Extend buffer with received data (Vec will grow as needed)
                    self.payload_buf.extend_from_slice(&buf[..n]);
                }

                // Check if we have complete payload
                if self.payload_buf.len() >= self.expected_len {
                    // Verify checksum
                    let header = self.parse_header()?;
                    if !header.verify_checksum(&self.payload_buf[..self.expected_len]) {
                        return Err(Error::InvalidMessage("checksum mismatch".into()));
                    }

                    // Extract message
                    let msg_type = header.msg_type;
                    let payload = std::mem::take(&mut self.payload_buf);

                    // Reset state for next message
                    self.header_buf.clear();
                    self.reading_payload = false;
                    self.expected_len = 0;

                    return Ok((msg_type, payload));
                }
            }
        }
    }

    /// Read the next complete message with timeout protection
    ///
    /// SECURITY: Prevents Slowloris-style DoS attacks where a peer sends
    /// data very slowly to hold connections open indefinitely.
    pub async fn read_message_with_timeout(&mut self, timeout: Duration) -> Result<(u8, Vec<u8>)> {
        tokio::time::timeout(timeout, self.read_message())
            .await
            .map_err(|_| Error::ConnectionFailed("read timeout".into()))?
    }

    /// Read the next complete message with per-chunk inactivity timeout.
    ///
    /// Unlike `read_message_with_timeout` which wraps the entire read in one
    /// hard wall, this resets the timer on every chunk received. Large messages
    /// (multi-MB block batches) survive as long as data keeps flowing — but a
    /// stalled peer that stops sending is still caught within `inactivity`.
    ///
    /// CANCELLATION SAFETY: This function MUST be cancellation-safe because
    /// the per-peer connection loop puts it in a `tokio::select!` alongside an
    /// outbound-message channel. If the future is dropped mid-payload-read,
    /// any bytes already pulled out of the underlying reader must survive on
    /// `self` so the next call can resume — otherwise the in-flight bytes are
    /// silently lost from the duplex/Noise stream and every subsequent header
    /// parse hits "invalid magic" mid-payload. (Hit on 2026-05-03 during
    /// fresh-node IBD: the IBD timer fires `rx.recv()` every 500 ms while a
    /// 535 KB Headers message is still streaming in, cancelling the read and
    /// dropping ~half a megabyte on the floor each time.)
    ///
    /// Concretely: header bytes are accumulated into `self.header_buf` and
    /// payload bytes into `self.payload_buf`, with `self.reading_payload` and
    /// `self.expected_len` tracking phase. We only clear those fields on
    /// successful completion or unrecoverable error — never on a dropped
    /// future.
    pub async fn read_message_with_inactivity_timeout(
        &mut self, inactivity: Duration,
    ) -> Result<(u8, Vec<u8>)> {
        if self.tracker.is_some() {
            return Err(Error::ProtocolError(
                "budgeted framer requires the budget-preserving read API".into(),
            ));
        }
        let message = self
            .read_message_with_inactivity_timeout_inner(inactivity)
            .await?;
        Ok((message.msg_type, message.payload))
    }

    pub(crate) async fn read_budgeted_message_timeout(&mut self) -> Result<BudgetedMessage> {
        if self.tracker.is_none() {
            return Err(Error::ProtocolError(
                "budget-preserving read API requires a connection tracker".into(),
            ));
        }
        let message = self
            .read_message_with_inactivity_timeout_inner(DEFAULT_READ_TIMEOUT)
            .await?;
        let reservation = message.reservation.ok_or_else(|| {
            Error::ProtocolError("budgeted message completed without a reservation".into())
        })?;
        Ok(BudgetedMessage {
            msg_type: message.msg_type,
            payload: message.payload,
            reservation,
        })
    }

    async fn read_message_with_inactivity_timeout_inner(
        &mut self, inactivity: Duration,
    ) -> Result<FramedMessage> {
        // Phase 1: Read HEADER_SIZE bytes with inactivity timeout per chunk.
        // self.header_buf may already contain partial bytes from a previously
        // cancelled call — that's the whole point of holding it on `self`.
        while !self.reading_payload && self.header_buf.len() < HEADER_SIZE {
            let needed = HEADER_SIZE - self.header_buf.len();
            let mut buf = vec![0u8; needed];
            let n = tokio::time::timeout(inactivity, self.reader.read(&mut buf))
                .await
                .map_err(|_| Error::ConnectionFailed("read stalled (header)".into()))?
                .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
            if n == 0 {
                return Err(Error::ConnectionFailed("connection closed".into()));
            }
            self.header_buf.extend_from_slice(&buf[..n]);
        }

        // Parse header (always — header_buf is full whether we got here from
        // Phase 1 or resumed mid-payload from a prior cancellation).
        let header = self.parse_header()?;

        // Validate header on the FIRST entry into Phase 2 only.
        // (On a resumed call where reading_payload is already true, we've
        // already validated the header on the prior call.)
        if !self.reading_payload {
            if header.magic != self.magic {
                // SECURITY: invalid magic is the textbook scan/probe signature
                // (HTTP GET, TLS hello, kid-script port-scanners). At `warn`
                // level with a full hex-dump it floods operator logs every
                // time a port scan runs against the public P2P port. Drop to
                // `debug` so it's still capturable for investigation but
                // doesn't dominate steady-state log output. Connection close
                // alone (returned via Err below) is the operator-visible
                // signal.
                tracing::debug!(
                    "framing: invalid magic, got_header_buf={} expected_magic={}",
                    hex::encode(&self.header_buf[..]),
                    hex::encode(self.magic)
                );
                self.header_buf.clear();
                return Err(Error::ProtocolError("invalid magic".into()));
            }
            if header.length as usize > MAX_MESSAGE_SIZE {
                self.header_buf.clear();
                return Err(Error::MessageTooLarge);
            }

            // SECURITY (H15-FIX): Per-command size limit enforcement
            if let Ok(msg_type) = crate::network::protocol::MessageType::try_from(header.msg_type) {
                let type_limit = msg_type.max_size();
                if header.length as usize > type_limit {
                    tracing::warn!(
                        "Message type {:?} exceeds per-type limit: {} > {}",
                        msg_type, header.length, type_limit
                    );
                    self.header_buf.clear();
                    return Err(Error::MessageTooLarge);
                }
            }

            self.expected_len = header.length as usize;
            self.reading_payload = true;
            let initial_cap = std::cmp::min(self.expected_len, 64 * 1024);
            self.payload_buf = Vec::with_capacity(initial_cap);
            self.reservation = self.tracker.as_ref().map(|tracker| tracker.reservation());
        }

        // Phase 2: Read payload into self.payload_buf so partial progress
        // survives a cancellation of this future.
        while self.payload_buf.len() < self.expected_len {
            let remaining = self.expected_len - self.payload_buf.len();
            let chunk_size = std::cmp::min(remaining, 65536);
            let mut buf = vec![0u8; chunk_size];
            let n = tokio::time::timeout(inactivity, self.reader.read(&mut buf))
                .await
                .map_err(|_| Error::ConnectionFailed("read stalled (payload)".into()))?
                .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
            if n == 0 {
                // Connection closed mid-payload — unrecoverable. Clear state
                // so the (now-defunct) framer doesn't leak partial buffers.
                self.reset_read_state();
                return Err(Error::ConnectionFailed("connection closed".into()));
            }
            let admitted = match self.reservation.as_mut() {
                Some(reservation) => reservation.try_grow(n),
                None => true,
            };
            if !admitted {
                self.reset_read_state();
                return Err(Error::P2pMemoryBudgetExceeded { requested: n });
            }
            self.payload_buf.extend_from_slice(&buf[..n]);
        }

        // Verify checksum
        if !header.verify_checksum(&self.payload_buf) {
            self.reset_read_state();
            return Err(Error::InvalidMessage("checksum mismatch".into()));
        }

        let msg_type = header.msg_type;
        let payload = std::mem::take(&mut self.payload_buf);
        let reservation = self.reservation.take();
        self.reset_read_state();

        Ok(FramedMessage {
            msg_type,
            payload,
            reservation,
        })
    }

    /// Read the next complete message with default timeout
    pub async fn read_message_timeout(&mut self) -> Result<(u8, Vec<u8>)> {
        self.read_message_with_inactivity_timeout(DEFAULT_READ_TIMEOUT).await
    }

    fn reset_read_state(&mut self) {
        self.header_buf.clear();
        self.payload_buf.clear();
        self.reading_payload = false;
        self.expected_len = 0;
        self.reservation = None;
    }

    /// Parse header from buffer
    fn parse_header(&self) -> Result<MessageHeader> {
        if self.header_buf.len() < HEADER_SIZE {
            return Err(Error::InvalidMessage("incomplete header".into()));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&self.header_buf[0..4]);

        let msg_type = self.header_buf[4];

        let length = u32::from_le_bytes([
            self.header_buf[5],
            self.header_buf[6],
            self.header_buf[7],
            self.header_buf[8],
        ]);

        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&self.header_buf[9..13]);

        Ok(MessageHeader {
            magic,
            msg_type,
            length,
            checksum,
        })
    }

    /// Write a complete message to the stream
    pub async fn write_message(&mut self, msg_type: u8, payload: &[u8]) -> Result<()> {
        use crate::network::protocol::MessageType;

        // Create header
        let header = MessageHeader::new(
            self.magic,
            MessageType::try_from(msg_type)?,
            payload,
        );

        // Serialize header
        let header_bytes = borsh::to_vec(&header)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        // Write header and payload
        self.writer.write_all(&header_bytes).await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
        self.writer.write_all(payload).await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
        self.writer.flush().await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        Ok(())
    }

    /// Flush pending writes
    pub async fn flush(&mut self) -> Result<()> {
        self.writer.flush().await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))
    }
}

/// Token bucket rate limiter for bandwidth management
pub struct RateLimiter {
    /// Bytes allowed per second
    bytes_per_sec: u64,
    /// Tokens available
    tokens: u64,
    /// Last refill time
    last_refill: std::time::Instant,
    /// Maximum burst size (tokens can accumulate up to this)
    burst_size: u64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(bytes_per_sec: u64) -> Self {
        RateLimiter {
            bytes_per_sec,
            tokens: bytes_per_sec,
            last_refill: std::time::Instant::now(),
            burst_size: bytes_per_sec * 2,
        }
    }

    /// Create with custom burst size
    pub fn with_burst(bytes_per_sec: u64, burst_size: u64) -> Self {
        RateLimiter {
            bytes_per_sec,
            tokens: burst_size,
            last_refill: std::time::Instant::now(),
            burst_size,
        }
    }

    /// Try to consume tokens, returns true if allowed
    pub fn try_consume(&mut self, bytes: u64) -> bool {
        self.refill();

        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    /// Wait until we have enough tokens
    pub async fn wait_for(&mut self, bytes: u64) {
        while !self.try_consume(bytes) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Check how many tokens are available
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = (elapsed.as_secs_f64() * self.bytes_per_sec as f64) as u64;

        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.burst_size);
            self.last_refill = now;
        }
    }
}

// NOTE: Per-peer PeerRateLimiter was removed because it was dropping
// solicited block data during IBD (Initial Block Download). (Prior
// comment characterized this as "matching Bitcoin/Monero's pattern of
// no per-message rate limiting on the P2P layer"; that specific
// cross-project generalization was not verified this session and is
// dropped.) RPC rate limiting is handled separately in
// src/rpc/ratelimit.rs.

/// Backoff strategy for reconnection
pub struct ExponentialBackoff {
    /// Initial delay
    initial: std::time::Duration,
    /// Maximum delay
    max: std::time::Duration,
    /// Current delay
    current: std::time::Duration,
    /// Multiplier
    multiplier: f64,
    /// Jitter factor (0.0 to 1.0)
    jitter: f64,
}

impl ExponentialBackoff {
    /// Create a new backoff with default settings
    pub fn new() -> Self {
        ExponentialBackoff {
            initial: std::time::Duration::from_secs(1),
            max: std::time::Duration::from_secs(300),
            current: std::time::Duration::from_secs(1),
            multiplier: 2.0,
            jitter: 0.1,
        }
    }

    /// Get the next delay and advance state
    pub fn next_delay(&mut self) -> std::time::Duration {
        let delay = self.current;

        // Apply jitter
        let jitter_range = delay.as_secs_f64() * self.jitter;
        let jitter = rand::random::<f64>() * jitter_range * 2.0 - jitter_range;
        let jittered = std::time::Duration::from_secs_f64(
            (delay.as_secs_f64() + jitter).max(0.0)
        );

        // Advance for next time
        self.current = std::time::Duration::from_secs_f64(
            (self.current.as_secs_f64() * self.multiplier).min(self.max.as_secs_f64())
        );

        jittered
    }

    /// Reset backoff to initial state
    pub fn reset(&mut self) {
        self.current = self.initial;
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::protocol::{Message, MessageType};

    fn wire_message(magic: [u8; 4], payload: &[u8]) -> Vec<u8> {
        Message::new(magic, MessageType::Blocks, payload.to_vec())
            .to_bytes()
            .unwrap()
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(1000);

        // Should allow initial consumption (starts with 1000 tokens, burst = 2000)
        assert!(limiter.try_consume(500));
        assert!(limiter.try_consume(500));

        // Should deny when exhausted
        assert!(!limiter.try_consume(100));
    }

    #[test]
    fn test_rate_limiter_with_burst() {
        let mut limiter = RateLimiter::with_burst(100, 500);

        // Can use full burst
        assert!(limiter.try_consume(500));
        // Now depleted
        assert!(!limiter.try_consume(1));
    }

    #[test]
    fn test_exponential_backoff() {
        let mut backoff = ExponentialBackoff::new();

        let d1 = backoff.next_delay();
        let d2 = backoff.next_delay();
        let d3 = backoff.next_delay();

        // Delays should increase (accounting for jitter)
        assert!(d2.as_secs_f64() >= d1.as_secs_f64() * 0.9);
        assert!(d3.as_secs_f64() >= d2.as_secs_f64() * 0.9);

        // Reset should work
        backoff.reset();
        let d_reset = backoff.next_delay();
        assert!(d_reset.as_secs_f64() < d3.as_secs_f64());
    }

    #[test]
    fn test_fragmented_message() {
        // TODO: Requires async runtime + mock AsyncRead to test partial message
        // reassembly through MessageFramer. Skipping due to complex mocking.
        // Verify header size constant is consistent
        assert_eq!(HEADER_SIZE, 13); // 4 magic + 1 type + 4 length + 4 checksum
    }

    #[tokio::test]
    async fn budgeted_message_holds_reservation_until_drop() {
        let magic = [1, 2, 3, 4];
        let tracker = Arc::new(ConnectionTracker::new(4));
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_budgeted(reader, writer, magic, tracker.clone());
        peer.write_all(&wire_message(magic, &[1, 2, 3, 4])).await.unwrap();
        let message = framer.read_budgeted_message_timeout().await.unwrap();
        assert_eq!(message.payload, vec![1, 2, 3, 4]);
        assert_eq!(tracker.memory_usage(), 4);
        drop(message);
        assert_eq!(tracker.memory_usage(), 0);
    }

    #[tokio::test]
    async fn payload_growth_over_budget_is_rejected_without_leak() {
        let magic = [1, 2, 3, 4];
        let tracker = Arc::new(ConnectionTracker::new(3));
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_budgeted(reader, writer, magic, tracker.clone());
        peer.write_all(&wire_message(magic, &[1, 2, 3, 4])).await.unwrap();
        assert!(matches!(
            framer.read_budgeted_message_timeout().await,
            Err(Error::P2pMemoryBudgetExceeded { .. })
        ));
        assert_eq!(tracker.memory_usage(), 0);
    }

    #[tokio::test]
    async fn cancellation_preserves_partial_payload_reservation() {
        let magic = [1, 2, 3, 4];
        let tracker = Arc::new(ConnectionTracker::new(8));
        let wire = wire_message(magic, &[1, 2, 3, 4]);
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_budgeted(reader, writer, magic, tracker.clone());
        peer.write_all(&wire[..HEADER_SIZE + 2]).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                framer.read_message_with_inactivity_timeout_inner(Duration::from_secs(5)),
            )
            .await
            .is_err()
        );
        assert_eq!(tracker.memory_usage(), 2);
        peer.write_all(&wire[HEADER_SIZE + 2..]).await.unwrap();
        let message = framer.read_budgeted_message_timeout().await.unwrap();
        assert_eq!(tracker.memory_usage(), 4);
        drop(message);
        assert_eq!(tracker.memory_usage(), 0);
    }

    #[tokio::test]
    async fn checksum_failure_releases_payload_reservation() {
        let magic = [1, 2, 3, 4];
        let tracker = Arc::new(ConnectionTracker::new(8));
        let mut wire = wire_message(magic, &[1, 2, 3, 4]);
        *wire.last_mut().unwrap() ^= 0xff;
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_budgeted(reader, writer, magic, tracker.clone());
        peer.write_all(&wire).await.unwrap();
        assert!(matches!(
            framer.read_budgeted_message_timeout().await,
            Err(Error::InvalidMessage(_))
        ));
        assert_eq!(tracker.memory_usage(), 0);
    }

    #[tokio::test]
    async fn empty_payload_uses_no_budget() {
        let magic = [1, 2, 3, 4];
        let tracker = Arc::new(ConnectionTracker::new(0));
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_budgeted(reader, writer, magic, tracker.clone());
        peer.write_all(&wire_message(magic, &[])).await.unwrap();
        let message = framer.read_budgeted_message_timeout().await.unwrap();
        assert!(message.payload.is_empty());
        assert_eq!(tracker.memory_usage(), 0);
    }

    #[tokio::test]
    async fn legacy_read_api_remains_unbudgeted_and_compatible() {
        let magic = [1, 2, 3, 4];
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);
        peer.write_all(&wire_message(magic, &[7])).await.unwrap();
        let (msg_type, payload) = framer.read_message_timeout().await.unwrap();
        assert_eq!(msg_type, MessageType::Blocks as u8);
        assert_eq!(payload, vec![7]);
    }
}
