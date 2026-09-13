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
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `MessageFramer::read_message` (header/payload accumulation)** —
//!   INVARIANT: payload bytes are only ever grown incrementally (starting at
//!   a ≤64 KB initial allocation) rather than pre-allocated to the header's
//!   claimed length. THREAT: an attacker claiming a huge payload but never
//!   sending it would otherwise force large up-front memory commitment
//!   per connection. TESTS: `fragmented_header_and_payload_reassemble_across_reads`,
//!   `connection_closed_mid_header_is_connection_failed`,
//!   `connection_closed_mid_payload_is_connection_failed`.
//! - **§2 `validate_wire_header`** — INVARIANT: a frame is rejected before
//!   its payload is read if the magic bytes mismatch, the wire length
//!   exceeds `MAX_MESSAGE_SIZE` or the per-type limit, or (when
//!   normalization is enabled) the size isn't a canonical bucket.
//!   THREAT: oversized/forged frames causing unbounded allocation or
//!   protocol confusion. TESTS: `unnormalized_reader_rejects_oversized_wire_length`,
//!   `normalized_reader_enforces_semantic_type_limit`,
//!   `normalized_reader_rejects_unmarked_payload`.
//! - **§3 `decode_payload` (checksum + semantic size re-check)** — INVARIANT:
//!   the payload's checksum must verify and its *decoded* (post-denormalize)
//!   length must still respect `MAX_MESSAGE_SIZE` and the per-type cap, even
//!   though the wire length already passed `validate_wire_header`.
//!   THREAT: A6 (denormalize inflating an accepted small wire frame into an
//!   oversized logical payload) plus generic bit-flip corruption.
//!   TESTS: `checksum_failure_releases_payload_reservation`.
//! - **§4 `read_message_with_inactivity_timeout_inner` (cancellation safety)**
//!   — INVARIANT: header and payload bytes already pulled off the reader
//!   survive a dropped/cancelled future on `self.header_buf` /
//!   `self.payload_buf`, so a resumed call completes the same logical
//!   message instead of losing bytes and desyncing the stream.
//!   THREAT: `tokio::select!`-driven cancellation (e.g. outbound `rx.recv()`
//!   firing mid-read during IBD) silently dropping in-flight bytes, corrupting
//!   all subsequent frame parsing ("invalid magic" cascade). TESTS:
//!   `cancellation_preserves_partial_payload_reservation`,
//!   `cancellation_mid_header_preserves_partial_bytes`,
//!   `repeated_cancellation_mid_payload_preserves_bytes`.
//! - **§5 memory-budget reservation lifecycle (`read_budgeted_message_timeout`,
//!   `MemoryReservation`)** — INVARIANT: a payload byte is only ever counted
//!   against the connection's memory budget once, the reservation grows in
//!   step with bytes actually buffered, and it is released exactly once
//!   (on success, on budget-exceeded rejection, or on connection close) —
//!   never leaked and never double-counted across a cancellation.
//!   THREAT: per-connection memory-budget bypass / accounting drift leading
//!   to unbounded memory growth (DoS). TESTS:
//!   `budgeted_message_holds_reservation_until_drop`,
//!   `payload_growth_over_budget_is_rejected_without_leak`,
//!   `empty_payload_uses_no_budget`.
//! - **§6 `write_message`** — INVARIANT: an outbound payload is rejected
//!   before any bytes reach the wire if it exceeds `MAX_MESSAGE_SIZE`, the
//!   per-type cap, or names an undefined message-type discriminant.
//!   THREAT: a local bug emitting an oversized or malformed frame that a
//!   remote peer's own header validation would otherwise have to catch.
//!   TESTS: `write_message_rejects_payload_over_type_max_size`,
//!   `write_message_rejects_unknown_msg_type_byte`.
//! - **§7 traffic-shaping normalization round-trip (`normalize_size_with_overhead`
//!   / `TrafficShaper::denormalize`)** — INVARIANT: normalizing a payload to a
//!   fixed bucket size and later denormalizing it recovers the exact original
//!   bytes, including at every bucket-size boundary. THREAT: size-based
//!   traffic-analysis leakage if normalization is skipped, or payload
//!   corruption if the round-trip isn't exact. TESTS:
//!   `normalized_framers_round_trip_payload`,
//!   `normalized_framer_round_trips_bucket_edge_payload_sizes`.
//! - **§8 Slowloris / stalled-peer bound (`read_message_with_inactivity_timeout`)**
//!   — INVARIANT: a peer that stops sending mid-message (rather than closing
//!   the connection) is bounded by a per-chunk inactivity timer, not an
//!   unbounded wait. THREAT: Slowloris-style connection-slot exhaustion.
//!   TESTS: `header_claims_large_payload_but_none_sent_times_out`.

use crate::error::{Error, Result};
use crate::network::connection_tracker::{ConnectionTracker, MemoryReservation};
use crate::network::protocol::{MessageHeader, MessageType, MAX_MESSAGE_SIZE};
use crate::network::traffic_shaping::TrafficShaper;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};

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
    traffic_shaper: Option<Arc<TrafficShaper>>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> MessageFramer<R, W> {
    /// Create a new message framer
    pub fn new(reader: R, writer: W, magic: [u8; 4]) -> Self {
        Self::with_tracker(reader, writer, magic, None, None)
    }

    pub fn new_normalized(
        reader: R,
        writer: W,
        magic: [u8; 4],
        traffic_shaper: Arc<TrafficShaper>,
    ) -> Self {
        Self::with_tracker(reader, writer, magic, None, Some(traffic_shaper))
    }

    pub(crate) fn new_budgeted(
        reader: R,
        writer: W,
        magic: [u8; 4],
        tracker: Arc<ConnectionTracker>,
        traffic_shaper: Arc<TrafficShaper>,
    ) -> Self {
        Self::with_tracker(reader, writer, magic, Some(tracker), Some(traffic_shaper))
    }

    fn with_tracker(
        reader: R,
        writer: W,
        magic: [u8; 4],
        tracker: Option<Arc<ConnectionTracker>>,
        traffic_shaper: Option<Arc<TrafficShaper>>,
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
            traffic_shaper,
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
                    let n = self
                        .reader
                        .read(&mut buf)
                        .await
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

                    if let Err(error) = self.validate_wire_header(&header) {
                        self.reset_read_state();
                        return Err(error);
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
                    let n = self
                        .reader
                        .read(&mut buf)
                        .await
                        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

                    if n == 0 {
                        return Err(Error::ConnectionFailed("connection closed".into()));
                    }

                    // Extend buffer with received data (Vec will grow as needed)
                    self.payload_buf.extend_from_slice(&buf[..n]);
                }

                // Check if we have complete payload
                if self.payload_buf.len() >= self.expected_len {
                    let header = self.parse_header()?;
                    let msg_type = header.msg_type;
                    let wire_payload = std::mem::take(&mut self.payload_buf);
                    let payload = self.decode_payload(&header, &wire_payload);
                    self.reset_read_state();

                    return Ok((msg_type, payload?));
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
        &mut self,
        inactivity: Duration,
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
        &mut self,
        inactivity: Duration,
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
            if let Err(error) = self.validate_wire_header(&header) {
                self.reset_read_state();
                return Err(error);
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

        let msg_type = header.msg_type;
        let wire_payload = std::mem::take(&mut self.payload_buf);
        let payload = self.decode_payload(&header, &wire_payload);
        let reservation = self.reservation.take();
        self.reset_read_state();

        Ok(FramedMessage {
            msg_type,
            payload: payload?,
            reservation,
        })
    }

    /// Read the next complete message with default timeout
    pub async fn read_message_timeout(&mut self) -> Result<(u8, Vec<u8>)> {
        self.read_message_with_inactivity_timeout(DEFAULT_READ_TIMEOUT)
            .await
    }

    fn normalization_enabled(&self) -> bool {
        self.traffic_shaper
            .as_ref()
            .is_some_and(|shaper| shaper.normalization_enabled())
    }

    fn wire_payload_limit(&self, logical_limit: usize) -> usize {
        if self.normalization_enabled() {
            TrafficShaper::normalized_payload_limit(logical_limit, HEADER_SIZE)
        } else {
            logical_limit
        }
    }

    fn validate_wire_header(&self, header: &MessageHeader) -> Result<()> {
        if header.magic != self.magic {
            tracing::debug!(
                "framing: invalid magic, got_header_buf={} expected_magic={}",
                hex::encode(&self.header_buf[..]),
                hex::encode(self.magic)
            );
            return Err(Error::ProtocolError("invalid magic".into()));
        }

        let wire_len = header.length as usize;
        if wire_len > self.wire_payload_limit(MAX_MESSAGE_SIZE) {
            return Err(Error::MessageTooLarge);
        }
        if self.normalization_enabled()
            && !TrafficShaper::is_normalized_payload_size(wire_len, HEADER_SIZE)
        {
            return Err(Error::InvalidMessage(
                "non-canonical normalized frame size".into(),
            ));
        }

        if let Ok(msg_type) = MessageType::try_from(header.msg_type) {
            let type_limit = self.wire_payload_limit(msg_type.max_size());
            if wire_len > type_limit {
                tracing::warn!(
                    "Message type {:?} exceeds wire limit: {} > {}",
                    msg_type,
                    wire_len,
                    type_limit
                );
                return Err(Error::MessageTooLarge);
            }
        }
        Ok(())
    }

    fn decode_payload(&self, header: &MessageHeader, wire_payload: &[u8]) -> Result<Vec<u8>> {
        if !header.verify_checksum(wire_payload) {
            return Err(Error::InvalidMessage("checksum mismatch".into()));
        }

        let payload = if self.normalization_enabled() {
            TrafficShaper::denormalize(wire_payload)
                .ok_or_else(|| Error::InvalidMessage("invalid normalized payload".into()))?
        } else {
            wire_payload.to_vec()
        };

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }
        if let Ok(msg_type) = MessageType::try_from(header.msg_type) {
            let type_limit = msg_type.max_size();
            if payload.len() > type_limit {
                tracing::warn!(
                    "Message type {:?} exceeds semantic limit: {} > {}",
                    msg_type,
                    payload.len(),
                    type_limit
                );
                return Err(Error::MessageTooLarge);
            }
        }
        Ok(payload)
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
        let msg_type = MessageType::try_from(msg_type)?;
        if payload.len() > MAX_MESSAGE_SIZE || payload.len() > msg_type.max_size() {
            return Err(Error::MessageTooLarge);
        }
        if self.normalization_enabled() {
            if let Some(shaper) = &self.traffic_shaper {
                shaper.record_shaped_packet();
            }
        }
        let wire_payload = self.traffic_shaper.as_ref().map_or_else(
            || payload.to_vec(),
            |shaper| shaper.normalize_size_with_overhead(payload, HEADER_SIZE),
        );
        let header = MessageHeader::new(self.magic, msg_type, &wire_payload);

        // Serialize header
        let header_bytes =
            borsh::to_vec(&header).map_err(|e| Error::SerializationError(e.to_string()))?;

        // Write header and payload
        self.writer
            .write_all(&header_bytes)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
        self.writer
            .write_all(&wire_payload)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
        self.writer
            .flush()
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        Ok(())
    }

    /// Flush pending writes
    pub async fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .await
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
        let jittered = std::time::Duration::from_secs_f64((delay.as_secs_f64() + jitter).max(0.0));

        // Advance for next time
        self.current = std::time::Duration::from_secs_f64(
            (self.current.as_secs_f64() * self.multiplier).min(self.max.as_secs_f64()),
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

    fn unnormalized_shaper() -> Arc<TrafficShaper> {
        let shaper = Arc::new(TrafficShaper::default_enabled());
        shaper.set_enabled(false);
        shaper
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
        let mut framer = MessageFramer::new_budgeted(
            reader,
            writer,
            magic,
            tracker.clone(),
            unnormalized_shaper(),
        );
        peer.write_all(&wire_message(magic, &[1, 2, 3, 4]))
            .await
            .unwrap();
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
        let mut framer = MessageFramer::new_budgeted(
            reader,
            writer,
            magic,
            tracker.clone(),
            unnormalized_shaper(),
        );
        peer.write_all(&wire_message(magic, &[1, 2, 3, 4]))
            .await
            .unwrap();
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
        let mut framer = MessageFramer::new_budgeted(
            reader,
            writer,
            magic,
            tracker.clone(),
            unnormalized_shaper(),
        );
        peer.write_all(&wire[..HEADER_SIZE + 2]).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            framer.read_message_with_inactivity_timeout_inner(Duration::from_secs(5)),
        )
        .await
        .is_err());
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
        let mut framer = MessageFramer::new_budgeted(
            reader,
            writer,
            magic,
            tracker.clone(),
            unnormalized_shaper(),
        );
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
        let mut framer = MessageFramer::new_budgeted(
            reader,
            writer,
            magic,
            tracker.clone(),
            unnormalized_shaper(),
        );
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

    #[tokio::test]
    async fn normalized_framers_round_trip_payload() {
        let magic = [1, 2, 3, 4];
        let shaper = Arc::new(TrafficShaper::default_enabled());
        let (left, right) = tokio::io::duplex(4096);
        let (left_reader, left_writer) = tokio::io::split(left);
        let (right_reader, right_writer) = tokio::io::split(right);
        let mut sender =
            MessageFramer::new_normalized(left_reader, left_writer, magic, Arc::clone(&shaper));
        let mut receiver = MessageFramer::new_normalized(right_reader, right_writer, magic, shaper);
        let payload = vec![0x5a; 333];

        let (sent, received) = tokio::join!(
            sender.write_message(MessageType::Txs as u8, &payload),
            receiver.read_message_timeout(),
        );

        sent.unwrap();
        let (msg_type, recovered) = received.unwrap();
        assert_eq!(msg_type, MessageType::Txs as u8);
        assert_eq!(recovered, payload);
    }

    #[tokio::test]
    async fn normalized_reader_enforces_semantic_type_limit() {
        let magic = [1, 2, 3, 4];
        let shaper = Arc::new(TrafficShaper::default_enabled());
        let oversized_ping = vec![0x5a; MessageType::Ping.max_size() + 1];
        let wire_payload = shaper.normalize_size_with_overhead(&oversized_ping, HEADER_SIZE);
        let wire = Message::new(magic, MessageType::Ping, wire_payload)
            .to_bytes()
            .unwrap();
        let (mut peer, local) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_normalized(reader, writer, magic, shaper);

        peer.write_all(&wire).await.unwrap();
        assert!(matches!(
            framer.read_message_timeout().await,
            Err(Error::MessageTooLarge)
        ));
    }

    #[tokio::test]
    async fn normalized_reader_rejects_unmarked_payload() {
        let magic = [1, 2, 3, 4];
        let raw_payload = vec![0x5a; 256 - HEADER_SIZE];
        let wire = Message::new(magic, MessageType::Blocks, raw_payload)
            .to_bytes()
            .unwrap();
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_normalized(
            reader,
            writer,
            magic,
            Arc::new(TrafficShaper::default_enabled()),
        );

        peer.write_all(&wire).await.unwrap();
        assert!(matches!(
            framer.read_message_timeout().await,
            Err(Error::InvalidMessage(_))
        ));
    }

    // ── Audit test-plan additions ───────────────────────────────────────

    /// Build just the 13-byte header (no payload) with an arbitrary length /
    /// zero checksum, for tests that exercise the header-validation path
    /// before any payload is read.
    fn header_only_wire(magic: [u8; 4], msg_type: MessageType, length: u32) -> Vec<u8> {
        let header = MessageHeader {
            magic,
            msg_type: msg_type as u8,
            length,
            checksum: [0u8; 4],
        };
        borsh::to_vec(&header).unwrap()
    }

    /// A full message whose header and payload each arrive split across
    /// multiple reads must reassemble into the original payload. The duplex
    /// capacity (64 B) is smaller than the 213-byte frame, forcing the writer
    /// to block and the reader to perform several partial reads.
    #[tokio::test]
    async fn fragmented_header_and_payload_reassemble_across_reads() {
        let magic = [1, 2, 3, 4];
        let payload: Vec<u8> = (0u8..200).collect();
        let wire = wire_message(magic, &payload);
        let (mut peer, local) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);

        let wire_for_task = wire.clone();
        let writer_task = tokio::spawn(async move {
            // Header split across two writes.
            peer.write_all(&wire_for_task[..5]).await.unwrap();
            tokio::task::yield_now().await;
            peer.write_all(&wire_for_task[5..HEADER_SIZE]).await.unwrap();
            tokio::task::yield_now().await;
            // Payload split across two writes.
            peer.write_all(&wire_for_task[HEADER_SIZE..HEADER_SIZE + 50])
                .await
                .unwrap();
            tokio::task::yield_now().await;
            peer.write_all(&wire_for_task[HEADER_SIZE + 50..])
                .await
                .unwrap();
        });

        let (msg_type, got) = framer
            .read_message_with_inactivity_timeout(Duration::from_secs(5))
            .await
            .unwrap();
        writer_task.await.unwrap();
        assert_eq!(msg_type, MessageType::Blocks as u8);
        assert_eq!(got, payload);
    }

    /// Connection closed (read returns 0) while only part of the header has
    /// arrived → ConnectionFailed.
    #[tokio::test]
    async fn connection_closed_mid_header_is_connection_failed() {
        let magic = [1, 2, 3, 4];
        let wire = wire_message(magic, &[9u8; 40]);
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);
        peer.write_all(&wire[..5]).await.unwrap();
        drop(peer);
        assert!(matches!(
            framer.read_message().await,
            Err(Error::ConnectionFailed(_))
        ));
    }

    /// Connection closed while only part of the payload has arrived →
    /// ConnectionFailed.
    #[tokio::test]
    async fn connection_closed_mid_payload_is_connection_failed() {
        let magic = [1, 2, 3, 4];
        let wire = wire_message(magic, &[9u8; 100]);
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);
        peer.write_all(&wire[..HEADER_SIZE + 10]).await.unwrap();
        drop(peer);
        assert!(matches!(
            framer.read_message().await,
            Err(Error::ConnectionFailed(_))
        ));
    }

    /// write_message rejects a payload larger than the message type's
    /// per-command cap (Ping.max_size() == 256).
    #[tokio::test]
    async fn write_message_rejects_payload_over_type_max_size() {
        let magic = [1, 2, 3, 4];
        let (_peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);
        let too_big = vec![0u8; MessageType::Ping.max_size() + 1];
        assert!(matches!(
            framer.write_message(MessageType::Ping as u8, &too_big).await,
            Err(Error::MessageTooLarge)
        ));
    }

    /// write_message rejects an unknown message-type byte via `try_from`
    /// before any bytes reach the wire.
    #[tokio::test]
    async fn write_message_rejects_unknown_msg_type_byte() {
        let magic = [1, 2, 3, 4];
        let (_peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);
        // 200 is not a defined discriminant.
        assert!(matches!(
            framer.write_message(200u8, &[]).await,
            Err(Error::InvalidMessage(_))
        ));
    }

    /// Unnormalized reader rejects a wire length above MAX_MESSAGE_SIZE at
    /// header validation, before reading (or allocating) the payload.
    #[tokio::test]
    async fn unnormalized_reader_rejects_oversized_wire_length() {
        let magic = [1, 2, 3, 4];
        let header = header_only_wire(magic, MessageType::Blocks, (MAX_MESSAGE_SIZE + 1) as u32);
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);
        peer.write_all(&header).await.unwrap();
        assert!(matches!(
            framer.read_message().await,
            Err(Error::MessageTooLarge)
        ));
    }

    /// Normalized framer denormalize recovers the exact payload across a
    /// sweep of sizes straddling every bucket edge (256/512/1024/2048/4096),
    /// plus the empty and near-empty cases.
    #[tokio::test]
    async fn normalized_framer_round_trips_bucket_edge_payload_sizes() {
        let magic = [1, 2, 3, 4];
        let shaper = Arc::new(TrafficShaper::default_enabled());
        let (left, right) = tokio::io::duplex(1 << 16);
        let (lr, lw) = tokio::io::split(left);
        let (rr, rw) = tokio::io::split(right);
        let mut sender = MessageFramer::new_normalized(lr, lw, magic, Arc::clone(&shaper));
        let mut receiver = MessageFramer::new_normalized(rr, rw, magic, shaper);

        let mut sizes = vec![0usize, 1, 2];
        for b in [256usize, 512, 1024, 2048, 4096] {
            // A payload of `b - HEADER_SIZE - NORMALIZATION_PREFIX_SIZE(4)`
            // exactly fills bucket `b`; straddle that edge.
            let edge = b - HEADER_SIZE - 4;
            sizes.push(edge - 1);
            sizes.push(edge);
            sizes.push(edge + 1);
        }

        for size in sizes {
            let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (sent, received) = tokio::join!(
                sender.write_message(MessageType::Txs as u8, &payload),
                receiver.read_message_timeout(),
            );
            sent.unwrap();
            let (msg_type, got) = received.unwrap();
            assert_eq!(msg_type, MessageType::Txs as u8);
            assert_eq!(got, payload, "round-trip mismatch at payload size {}", size);
        }
    }

    /// Cancelling the read while only part of the HEADER has arrived must
    /// preserve those bytes on `self` so a resumed read completes the message
    /// (no "invalid magic" from lost bytes). No reservation is taken until the
    /// header is fully parsed.
    #[tokio::test]
    async fn cancellation_mid_header_preserves_partial_bytes() {
        let magic = [1, 2, 3, 4];
        let tracker = Arc::new(ConnectionTracker::new(8));
        let wire = wire_message(magic, &[1, 2, 3, 4]);
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_budgeted(
            reader,
            writer,
            magic,
            tracker.clone(),
            unnormalized_shaper(),
        );
        // Fewer than HEADER_SIZE bytes, then cancel the in-flight read.
        peer.write_all(&wire[..5]).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            framer.read_message_with_inactivity_timeout_inner(Duration::from_secs(5)),
        )
        .await
        .is_err());
        // Header phase reserves nothing.
        assert_eq!(tracker.memory_usage(), 0);
        // Deliver the rest; the 5 buffered header bytes must have survived.
        peer.write_all(&wire[5..]).await.unwrap();
        let message = framer.read_budgeted_message_timeout().await.unwrap();
        assert_eq!(message.payload, vec![1, 2, 3, 4]);
        assert_eq!(tracker.memory_usage(), 4);
        drop(message);
        assert_eq!(tracker.memory_usage(), 0);
    }

    /// Multiple cancellations mid-payload (churn) must not lose bytes or
    /// double-count the reservation; the reassembled payload is exact.
    #[tokio::test]
    async fn repeated_cancellation_mid_payload_preserves_bytes() {
        let magic = [1, 2, 3, 4];
        let tracker = Arc::new(ConnectionTracker::new(8));
        let wire = wire_message(magic, &[10, 20, 30, 40]);
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new_budgeted(
            reader,
            writer,
            magic,
            tracker.clone(),
            unnormalized_shaper(),
        );
        // Header + 1 payload byte, then cancel.
        peer.write_all(&wire[..HEADER_SIZE + 1]).await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            framer.read_message_with_inactivity_timeout_inner(Duration::from_secs(5)),
        )
        .await
        .is_err());
        assert_eq!(tracker.memory_usage(), 1);
        // One more byte, cancel again.
        peer.write_all(&wire[HEADER_SIZE + 1..HEADER_SIZE + 2])
            .await
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            framer.read_message_with_inactivity_timeout_inner(Duration::from_secs(5)),
        )
        .await
        .is_err());
        assert_eq!(tracker.memory_usage(), 2);
        // Remainder; the read now completes with the full payload.
        peer.write_all(&wire[HEADER_SIZE + 2..]).await.unwrap();
        let message = framer.read_budgeted_message_timeout().await.unwrap();
        assert_eq!(message.payload, vec![10, 20, 30, 40]);
        assert_eq!(tracker.memory_usage(), 4);
        drop(message);
        assert_eq!(tracker.memory_usage(), 0);
    }

    /// A header that claims a large payload but whose peer then sends nothing
    /// is bounded by the per-chunk inactivity timeout: the read fails with a
    /// "stalled" ConnectionFailed rather than blocking on / pre-allocating the
    /// claimed size. Uses a short (100 ms) inactivity window — the read MUST
    /// time out because no payload byte ever arrives, so this is deterministic
    /// and does not sleep on the success path.
    #[tokio::test]
    async fn header_claims_large_payload_but_none_sent_times_out() {
        let magic = [1, 2, 3, 4];
        // 1 MiB is well under Blocks' cap (MAX_MESSAGE_SIZE), so the header is
        // accepted and the framer proceeds to await the payload.
        let header = header_only_wire(magic, MessageType::Blocks, 1 << 20);
        let (mut peer, local) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(local);
        let mut framer = MessageFramer::new(reader, writer, magic);
        peer.write_all(&header).await.unwrap();
        // Keep `peer` alive (not dropped) so the read stalls rather than
        // seeing a closed connection.
        let result = framer
            .read_message_with_inactivity_timeout(Duration::from_millis(100))
            .await;
        match result {
            Err(Error::ConnectionFailed(msg)) => {
                assert!(msg.contains("stalled"), "expected stall, got: {}", msg)
            }
            other => panic!("expected stalled ConnectionFailed, got {:?}", other),
        }
        drop(peer);
    }
}
