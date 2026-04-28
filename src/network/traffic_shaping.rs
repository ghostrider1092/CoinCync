//! # Network Fingerprint Resistance — Traffic Shaping
//!
//! Makes CoinCync P2P traffic indistinguishable from generic TLS/HTTPS
//! traffic to ISPs and deep-packet inspectors. Three layers:
//!
//! 1. **Constant-rate padding** — dummy packets at fixed intervals so an
//!    observer sees steady bandwidth regardless of real activity.
//! 2. **Packet size normalization** — all outbound messages padded to the
//!    nearest standard TLS frame size so packet length doesn't leak
//!    message type (block announcements vs tx announcements).
//! 3. **Timing jitter** — random delay (0–200 ms) on outbound messages
//!    so an observer can't correlate "node A sent at T, node B received
//!    at T + latency".
//!
//! ## Constitutional basis
//!
//! Bill of Rights, Article IV (4th Amendment):
//! > The right of the people to be secure in their persons, houses, papers,
//! > and effects, against unreasonable searches and seizures, shall not be
//! > violated.
//!
//! Network metadata is an "effect" — traffic analysis is a search.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use rand::Rng;
use tracing::{debug, trace};

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

/// Standard TLS record sizes used for normalization. Real TLS traffic
/// clusters around these sizes, so our padded packets blend in.
const STANDARD_SIZES: [usize; 5] = [256, 512, 1024, 2048, 4096];

/// Maximum packet size — anything larger gets sent as-is (already a
/// full-sized frame and can't be hidden further).
const MAX_PADDED_SIZE: usize = 4096;

/// Default interval between padding packets (milliseconds).
const DEFAULT_PADDING_INTERVAL_MS: u64 = 500;

/// Default maximum random jitter added to outbound messages (milliseconds).
const DEFAULT_MAX_JITTER_MS: u64 = 200;

/// Magic prefix for dummy padding packets. Peers recognize and discard
/// these without processing. The tag is chosen to never collide with
/// any valid CoinCync protocol message magic.
const PADDING_MAGIC: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

// ═══════════════════════════════════════════════════════════════════════
// TrafficShaper
// ═══════════════════════════════════════════════════════════════════════

/// Configuration for the traffic shaper.
#[derive(Clone, Debug)]
pub struct TrafficShaperConfig {
    /// Interval between dummy padding packets in milliseconds.
    pub padding_interval_ms: u64,
    /// Maximum random jitter added before sending (milliseconds).
    pub max_jitter_ms: u64,
    /// Whether to enable constant-rate padding.
    pub padding_enabled: bool,
    /// Whether to enable packet size normalization.
    pub normalize_enabled: bool,
    /// Whether to enable timing jitter.
    pub jitter_enabled: bool,
}

impl Default for TrafficShaperConfig {
    fn default() -> Self {
        Self {
            padding_interval_ms: DEFAULT_PADDING_INTERVAL_MS,
            max_jitter_ms: DEFAULT_MAX_JITTER_MS,
            padding_enabled: true,
            normalize_enabled: true,
            jitter_enabled: true,
        }
    }
}

/// Network traffic shaper for fingerprint resistance.
///
/// Wraps all outbound P2P sends to normalize sizes, add timing jitter,
/// and inject constant-rate padding. An ISP or network observer sees a
/// steady stream of identically-sized encrypted frames — no way to
/// distinguish idle from active, block from tx, real from dummy.
pub struct TrafficShaper {
    config: TrafficShaperConfig,
    enabled: AtomicBool,
    /// Total real packets shaped (diagnostics).
    packets_shaped: AtomicU64,
    /// Total padding packets sent (diagnostics).
    padding_sent: AtomicU64,
}

impl TrafficShaper {
    /// Create a new traffic shaper with the given configuration.
    pub fn new(config: TrafficShaperConfig) -> Self {
        Self {
            config,
            enabled: AtomicBool::new(true),
            packets_shaped: AtomicU64::new(0),
            padding_sent: AtomicU64::new(0),
        }
    }

    /// Create with default (all protections enabled).
    pub fn default_enabled() -> Self {
        Self::new(TrafficShaperConfig::default())
    }

    /// Enable or disable the shaper at runtime.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    // ─── Packet size normalization ──────────────────────────────────

    /// Pad `data` to the nearest standard TLS frame size.
    ///
    /// The padding uses random bytes (not zeros) so compressed/encrypted
    /// views of the padding look like payload data.
    pub fn normalize_size(&self, data: &[u8]) -> Vec<u8> {
        if !self.config.normalize_enabled || !self.is_enabled() {
            return data.to_vec();
        }

        let raw_len = data.len();
        let target_size = Self::nearest_standard_size(raw_len);

        let mut padded = Vec::with_capacity(target_size);
        // 4-byte length prefix (original length, little-endian) so the
        // receiver knows where real data ends and padding begins.
        if raw_len > u32::MAX as usize {
            return data.to_vec(); // too large to encode length; pass through unshaped
        }
        padded.extend_from_slice(&(raw_len as u32).to_le_bytes());
        padded.extend_from_slice(data);

        // Fill remaining space with random bytes.
        if padded.len() < target_size {
            let pad_len = target_size - padded.len();
            let mut rng = rand::thread_rng();
            let mut pad = vec![0u8; pad_len];
            rng.fill(&mut pad[..]);
            padded.extend_from_slice(&pad);
        }

        padded
    }

    /// Strip normalization padding and recover the original payload.
    pub fn denormalize(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 4 {
            return None;
        }
        let orig_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if orig_len + 4 > data.len() {
            return None;
        }
        Some(data[4..4 + orig_len].to_vec())
    }

    /// Find the smallest standard size that fits `len` bytes plus the
    /// 4-byte length prefix.
    fn nearest_standard_size(len: usize) -> usize {
        let needed = len + 4; // +4 for length prefix
        for &size in &STANDARD_SIZES {
            if size >= needed {
                return size;
            }
        }
        // Larger than any standard size — round up to nearest 4096 multiple.
        ((needed + MAX_PADDED_SIZE - 1) / MAX_PADDED_SIZE) * MAX_PADDED_SIZE
    }

    // ─── Timing jitter ─────────────────────────────────────────────

    /// Add a random delay before sending to prevent timing correlation.
    ///
    /// The jitter is uniformly distributed in [0, max_jitter_ms] so an
    /// observer can't use timing to correlate sender and receiver.
    pub async fn apply_jitter(&self) {
        if !self.config.jitter_enabled || !self.is_enabled() {
            return;
        }
        let jitter_ms = rand::thread_rng().gen_range(0..=self.config.max_jitter_ms);
        if jitter_ms > 0 {
            trace!(jitter_ms, "applying timing jitter");
            sleep(Duration::from_millis(jitter_ms)).await;
        }
    }

    // ─── Full shaping pipeline ─────────────────────────────────────

    /// Shape an outbound packet: normalize size + apply jitter.
    ///
    /// Call this instead of writing raw bytes to the peer socket.
    pub async fn shape(&self, data: Vec<u8>) -> Vec<u8> {
        if !self.is_enabled() {
            return data;
        }
        self.packets_shaped.fetch_add(1, Ordering::Relaxed);
        self.apply_jitter().await;
        self.normalize_size(&data)
    }

    // ─── Padding (constant-rate cover traffic) ─────────────────────

    /// Generate a dummy padding packet that peers will discard.
    ///
    /// The packet is a random standard size filled with random bytes,
    /// prefixed with the `PADDING_MAGIC` tag so the receiver can
    /// identify and drop it without parsing.
    pub fn generate_padding_packet() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let size_idx = rng.gen_range(0..STANDARD_SIZES.len());
        let size = STANDARD_SIZES[size_idx];

        let mut packet = Vec::with_capacity(size);
        packet.extend_from_slice(&PADDING_MAGIC);
        let mut fill = vec![0u8; size - PADDING_MAGIC.len()];
        rng.fill(&mut fill[..]);
        packet.extend_from_slice(&fill);
        packet
    }

    /// Check if a received packet is a dummy padding packet.
    pub fn is_padding_packet(data: &[u8]) -> bool {
        data.len() >= PADDING_MAGIC.len() && data[..PADDING_MAGIC.len()] == PADDING_MAGIC
    }

    /// Run the constant-rate padding loop as a background task.
    ///
    /// Sends a dummy packet through `sender` at regular intervals
    /// regardless of real traffic. This makes idle and active nodes
    /// look identical to a network observer.
    pub async fn run_padding_loop(
        self: Arc<Self>,
        sender: mpsc::Sender<Vec<u8>>,
        shutdown: Arc<AtomicBool>,
    ) {
        let interval = Duration::from_millis(self.config.padding_interval_ms);
        debug!(
            interval_ms = self.config.padding_interval_ms,
            "traffic shaper padding loop started"
        );

        while !shutdown.load(Ordering::Relaxed) {
            sleep(interval).await;

            if !self.is_enabled() || !self.config.padding_enabled {
                continue;
            }

            let packet = Self::generate_padding_packet();
            if sender.send(packet).await.is_err() {
                debug!("padding loop: channel closed, stopping");
                break;
            }
            self.padding_sent.fetch_add(1, Ordering::Relaxed);
            trace!("sent padding packet");
        }

        debug!("traffic shaper padding loop stopped");
    }

    // ─── Diagnostics ───────────────────────────────────────────────

    /// Get traffic shaping statistics.
    pub fn stats(&self) -> TrafficShapingStats {
        TrafficShapingStats {
            enabled: self.is_enabled(),
            packets_shaped: self.packets_shaped.load(Ordering::Relaxed),
            padding_sent: self.padding_sent.load(Ordering::Relaxed),
            padding_interval_ms: self.config.padding_interval_ms,
            max_jitter_ms: self.config.max_jitter_ms,
            normalize_enabled: self.config.normalize_enabled,
            jitter_enabled: self.config.jitter_enabled,
            padding_enabled: self.config.padding_enabled,
        }
    }
}

/// Traffic shaping statistics for diagnostics / RPC.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TrafficShapingStats {
    pub enabled: bool,
    pub packets_shaped: u64,
    pub padding_sent: u64,
    pub padding_interval_ms: u64,
    pub max_jitter_ms: u64,
    pub normalize_enabled: bool,
    pub jitter_enabled: bool,
    pub padding_enabled: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_round_trips() {
        let shaper = TrafficShaper::default_enabled();
        let original = b"hello world this is a test message";
        let normalized = shaper.normalize_size(original);

        // Must be one of the standard sizes
        assert!(
            STANDARD_SIZES.contains(&normalized.len())
                || normalized.len() % MAX_PADDED_SIZE == 0,
            "normalized size {} is not standard",
            normalized.len()
        );

        // Must round-trip
        let recovered = TrafficShaper::denormalize(&normalized).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn normalize_large_payload() {
        let shaper = TrafficShaper::default_enabled();
        let original = vec![0xAB; 5000]; // Bigger than any standard size
        let normalized = shaper.normalize_size(&original);
        assert!(normalized.len() >= original.len() + 4);
        assert_eq!(normalized.len() % MAX_PADDED_SIZE, 0);

        let recovered = TrafficShaper::denormalize(&normalized).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn padding_packet_detected() {
        let packet = TrafficShaper::generate_padding_packet();
        assert!(TrafficShaper::is_padding_packet(&packet));
        assert!(STANDARD_SIZES.contains(&packet.len()));
    }

    #[test]
    fn real_packet_not_detected_as_padding() {
        let real = b"not a padding packet at all";
        assert!(!TrafficShaper::is_padding_packet(real));
    }

    #[test]
    fn nearest_size_picks_smallest_fit() {
        // 10 bytes + 4 prefix = 14 → 256
        assert_eq!(TrafficShaper::nearest_standard_size(10), 256);
        // 250 bytes + 4 = 254 → 256
        assert_eq!(TrafficShaper::nearest_standard_size(250), 256);
        // 253 bytes + 4 = 257 → 512
        assert_eq!(TrafficShaper::nearest_standard_size(253), 512);
        // 1020 bytes + 4 = 1024 → 1024
        assert_eq!(TrafficShaper::nearest_standard_size(1020), 1024);
    }

    #[test]
    fn disabled_shaper_passes_through() {
        let shaper = TrafficShaper::default_enabled();
        shaper.set_enabled(false);
        let original = b"passthrough data";
        let result = shaper.normalize_size(original);
        assert_eq!(result, original);
    }
}
