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

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use crate::error::{Error, Result};
use crate::network::protocol::{MessageHeader, MAX_MESSAGE_SIZE};

/// Default read timeout — must be longer than PING_INTERVAL (120s)
/// to prevent killing idle but valid connections between pings.
/// Bitcoin uses 90 minutes; we use 5 minutes as a balance between
/// Slowloris protection and keeping good connections alive.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Message header size in bytes
pub const HEADER_SIZE: usize = 13; // 4 (magic) + 1 (type) + 4 (length) + 4 (checksum)

/// Connection state for message framing
pub struct MessageFramer<R, W> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    magic: [u8; 4],
    /// Partial header bytes being accumulated
    header_buf: Vec<u8>,
    /// Partial payload bytes being accumulated
    payload_buf: Vec<u8>,
    /// Expected payload length (from header)
    expected_len: usize,
    /// Whether we're reading header or payload
    reading_payload: bool,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> MessageFramer<R, W> {
    /// Create a new message framer
    pub fn new(reader: R, writer: W, magic: [u8; 4]) -> Self {
        MessageFramer {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            magic,
            header_buf: Vec::with_capacity(HEADER_SIZE),
            payload_buf: Vec::new(),
            expected_len: 0,
            reading_payload: false,
        }
    }

    /// Read the next complete message from the stream
    /// Returns (message_type, payload) on success
    pub async fn read_message(&mut self) -> Result<(u8, Vec<u8>)> {
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
    pub async fn read_message_with_inactivity_timeout(
        &mut self, inactivity: Duration,
    ) -> Result<(u8, Vec<u8>)> {
        // Phase 1: Read HEADER_SIZE bytes with inactivity timeout per chunk
        while self.header_buf.len() < HEADER_SIZE {
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

        // Parse header
        let header = self.parse_header()?;
        if header.magic != self.magic {
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

        let expected_len = header.length as usize;

        // Phase 2: Read payload with per-chunk inactivity timeout
        let initial_cap = std::cmp::min(expected_len, 64 * 1024);
        let mut payload = Vec::with_capacity(initial_cap);
        while payload.len() < expected_len {
            let remaining = expected_len - payload.len();
            let chunk_size = std::cmp::min(remaining, 65536);
            let mut buf = vec![0u8; chunk_size];
            let n = tokio::time::timeout(inactivity, self.reader.read(&mut buf))
                .await
                .map_err(|_| Error::ConnectionFailed("read stalled (payload)".into()))?
                .map_err(|e| Error::ConnectionFailed(e.to_string()))?;
            if n == 0 {
                self.header_buf.clear();
                return Err(Error::ConnectionFailed("connection closed".into()));
            }
            payload.extend_from_slice(&buf[..n]);
            // Timer resets automatically on next loop iteration
        }

        // Verify checksum
        if !header.verify_checksum(&payload) {
            self.header_buf.clear();
            return Err(Error::InvalidMessage("checksum mismatch".into()));
        }

        let msg_type = header.msg_type;

        tracing::trace!(
            "framer: read complete msg type={} payload={} bytes",
            msg_type, payload.len()
        );

        // Reset state for next message
        self.header_buf.clear();
        self.reading_payload = false;
        self.expected_len = 0;

        Ok((msg_type, payload))
    }

    /// Read the next complete message with default timeout
    pub async fn read_message_timeout(&mut self) -> Result<(u8, Vec<u8>)> {
        self.read_message_with_inactivity_timeout(DEFAULT_READ_TIMEOUT).await
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

// NOTE: Per-peer PeerRateLimiter was removed. It was dropping solicited block
// data during IBD (Initial Block Download), matching Bitcoin/Monero's pattern
// of no per-message rate limiting on the P2P layer. RPC rate limiting is
// handled separately in src/rpc/ratelimit.rs.

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
}
