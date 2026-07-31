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

use crate::colony::stick_insect::{padded_len, SIZE_BUCKETS};
use rand::Rng;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{debug, trace};

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

pub(crate) const NORMALIZATION_PREFIX_SIZE: usize = 4;
const NORMALIZED_LENGTH_FLAG: u32 = 1 << 31;

/// Default interval between padding packets (milliseconds).
const DEFAULT_PADDING_INTERVAL_MS: u64 = 500;

/// Default maximum random jitter added to outbound messages (milliseconds).
const DEFAULT_MAX_JITTER_MS: u64 = 200;

// Padding packets are now framed as `MessageType::Padding` (discriminant 99)
// rather than using a custom magic. The pre-launch `PADDING_MAGIC = 0xDEADBEEF`
// scheme bypassed the message framer entirely and could never reach a peer
// (the per-peer write loop in `node.rs::handle_connection` validates the
// msg_type byte against `MessageType::try_from`, so untyped padding bytes
// would drop the connection). Phase 2 of the post-launch campaign replaced
// that hack with proper framing.

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
    /// CIP-020: engage substitutive constant-rate origination pacing. When
    /// true, the node's own originations (wallet sends + auto-churn) are paced
    /// into a single constant-rate slot clock (real-if-queued-else-dummy)
    /// instead of the additive padding loop + jitter — which leaves real
    /// timing recoverable (measured observer r=0.63 → r=0.00). Off by default;
    /// opt-in per node during rollout. Relay/block/inv traffic is never paced.
    pub constant_rate_enabled: bool,
}

impl Default for TrafficShaperConfig {
    fn default() -> Self {
        Self {
            padding_interval_ms: DEFAULT_PADDING_INTERVAL_MS,
            max_jitter_ms: DEFAULT_MAX_JITTER_MS,
            padding_enabled: true,
            normalize_enabled: true,
            jitter_enabled: true,
            constant_rate_enabled: false, // CIP-020: opt-in per node during rollout
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

    pub(crate) fn normalization_enabled(&self) -> bool {
        self.config.normalize_enabled && self.is_enabled()
    }

    pub(crate) fn record_shaped_packet(&self) {
        self.packets_shaped.fetch_add(1, Ordering::Relaxed);
    }

    // ─── Packet size normalization ──────────────────────────────────

    /// Pad `data` to the nearest standard TLS frame size.
    ///
    /// The padding uses random bytes (not zeros) so compressed/encrypted
    /// views of the padding look like payload data.
    pub fn normalize_size(&self, data: &[u8]) -> Vec<u8> {
        self.normalize_size_with_overhead(data, 0)
    }

    pub(crate) fn normalize_size_with_overhead(
        &self,
        data: &[u8],
        outer_overhead: usize,
    ) -> Vec<u8> {
        if !self.normalization_enabled() {
            return data.to_vec();
        }

        let raw_len = data.len();
        if raw_len > u32::MAX as usize || raw_len >= NORMALIZED_LENGTH_FLAG as usize {
            return data.to_vec();
        }
        let encoded_len = raw_len.saturating_add(NORMALIZATION_PREFIX_SIZE);
        let target_total = padded_len(outer_overhead.saturating_add(encoded_len));
        let target_size = target_total.saturating_sub(outer_overhead).max(encoded_len);

        let mut padded = Vec::with_capacity(target_size);
        let encoded_length = (raw_len as u32) | NORMALIZED_LENGTH_FLAG;
        padded.extend_from_slice(&encoded_length.to_le_bytes());
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
        if data.len() < NORMALIZATION_PREFIX_SIZE {
            return None;
        }
        let encoded_length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if encoded_length & NORMALIZED_LENGTH_FLAG == 0 {
            return None;
        }
        let orig_len = (encoded_length & !NORMALIZED_LENGTH_FLAG) as usize;
        let payload_end = NORMALIZATION_PREFIX_SIZE.checked_add(orig_len)?;
        if payload_end > data.len() {
            return None;
        }
        Some(data[NORMALIZATION_PREFIX_SIZE..payload_end].to_vec())
    }

    pub(crate) fn normalized_payload_limit(logical_limit: usize, outer_overhead: usize) -> usize {
        let needed = outer_overhead
            .saturating_add(NORMALIZATION_PREFIX_SIZE)
            .saturating_add(logical_limit);
        padded_len(needed).saturating_sub(outer_overhead)
    }

    pub(crate) fn is_normalized_payload_size(payload_len: usize, outer_overhead: usize) -> bool {
        let total = match payload_len.checked_add(outer_overhead) {
            Some(total) => total,
            None => return false,
        };
        SIZE_BUCKETS.contains(&total)
            || total
                .checked_rem(SIZE_BUCKETS[SIZE_BUCKETS.len() - 1])
                .is_some_and(|remainder| remainder == 0)
    }

    pub(crate) fn max_normalizable_input(
        max_output_payload: usize,
        outer_overhead: usize,
    ) -> Option<usize> {
        let max_total = max_output_payload.checked_add(outer_overhead)?;
        let bucket = SIZE_BUCKETS
            .iter()
            .rev()
            .copied()
            .find(|bucket| *bucket <= max_total)?;
        bucket
            .checked_sub(outer_overhead)?
            .checked_sub(NORMALIZATION_PREFIX_SIZE)
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

    /// Generate a dummy padding message that peers will discard.
    ///
    /// Returns a framed logical message with a small random payload. The
    /// per-connection framer applies the same size normalization used for
    /// every other message.
    ///
    /// Pass the live network magic the node is configured with — the
    /// receiver's framer rejects messages whose magic doesn't match.
    pub fn generate_padding_packet(magic: [u8; 4]) -> Vec<u8> {
        use super::protocol::{Message, MessageType};
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; 32];
        rng.fill(&mut payload[..]);
        Message::new(magic, MessageType::Padding, payload)
            .to_bytes()
            .unwrap_or_default()
    }

    /// Legacy is-padding pre-check. Retained for backward compatibility
    /// with tests; production no longer needs it because the framer
    /// routes `MessageType::Padding` to the dispatch arm that discards
    /// silently. New code should match on `MessageType::Padding`
    /// directly. Will be removed in a follow-up after callers migrate.
    #[deprecated(note = "match MessageType::Padding in process_message instead")]
    pub fn is_padding_packet(_data: &[u8]) -> bool {
        false
    }

    /// Run the constant-rate padding loop as a background task.
    ///
    /// Sends a dummy packet through `sender` at regular intervals
    /// regardless of real traffic. This makes idle and active nodes
    /// look identical to a network observer.
    pub async fn run_padding_loop(
        self: Arc<Self>,
        magic: [u8; 4],
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

            let packet = Self::generate_padding_packet(magic);
            if sender.send(packet).await.is_err() {
                debug!("padding loop: channel closed, stopping");
                break;
            }
            self.padding_sent.fetch_add(1, Ordering::Relaxed);
            trace!("sent padding packet");
        }

        debug!("traffic shaper padding loop stopped");
    }

    /// Run the constant-rate padding loop, broadcasting a fresh padding
    /// packet to every currently-connected peer at each interval.
    ///
    /// This is the production wire-up. The single-`Sender` variant
    /// `run_padding_loop` above is for unit tests; in a live node we
    /// have many peers and a DashMap of senders, and we want every peer
    /// to see the padding stream so an observer correlating two peers'
    /// inbound traffic still sees it constant.
    ///
    /// Per-tick behavior:
    ///   1. Sleep `padding_interval_ms`.
    ///   2. If shaper or padding feature is disabled, skip the tick.
    ///   3. Generate ONE padding packet per peer (fresh randomness so the
    ///      packet bytes differ across peers — otherwise a colluding pair
    ///      could detect that they received the SAME bytes at the SAME
    ///      time and infer a single sender).
    ///   4. `try_send` to each peer (non-blocking — a saturated peer
    ///      gets its tick skipped, the loop doesn't stall on one slow
    ///      peer).
    ///
    /// Increments `padding_sent` once per *successful* send so the stat
    /// reflects packets that actually entered the per-peer write queue.
    pub async fn run_padding_loop_broadcast<I, F>(
        self: Arc<Self>,
        magic: [u8; 4],
        peer_senders: F,
        shutdown: Arc<AtomicBool>,
    ) where
        F: Fn() -> I + Send + 'static,
        I: IntoIterator<Item = mpsc::Sender<Vec<u8>>>,
    {
        let interval = Duration::from_millis(self.config.padding_interval_ms);
        debug!(
            interval_ms = self.config.padding_interval_ms,
            "traffic shaper padding broadcast loop started"
        );

        while !shutdown.load(Ordering::Relaxed) {
            sleep(interval).await;

            if !self.is_enabled() || !self.config.padding_enabled {
                continue;
            }

            let mut sent_this_tick: u64 = 0;
            for sender in peer_senders() {
                // Fresh randomness per peer — a colluding pair must not
                // be able to detect that they received the same bytes.
                let packet = Self::generate_padding_packet(magic);
                if sender.try_send(packet).is_ok() {
                    sent_this_tick += 1;
                }
                // Drop on full / disconnected channel — don't block the
                // broadcast on a slow peer. The peer will see the next
                // tick's packet if its queue drains.
            }
            if sent_this_tick > 0 {
                self.padding_sent
                    .fetch_add(sent_this_tick, Ordering::Relaxed);
                trace!(packets = sent_this_tick, "broadcast padding packets");
            }
        }

        debug!("traffic shaper padding broadcast loop stopped");
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
// Constant-rate origination pacing (CIP-020)
// ═══════════════════════════════════════════════════════════════════════

/// Bound on the origination queue. Above this the pacer stops absorbing
/// originations and the caller must direct-send (non-blocking, privacy-degraded)
/// — only reachable when the node originates faster than one packet per slot
/// (2 tx/s at the default 500 ms slot), which is rare for a wallet. At the slot
/// rate this bound is ~16 s of backlog.
const DEFAULT_MAX_ORIGINATION_QUEUE: usize = 32;

/// Substitutive constant-rate pacer for the node's **own** originations (CIP-020).
///
/// The additive padding loop (`run_padding_loop*`) emits a dummy every slot *in
/// addition to* real traffic, so the real-traffic timing stays recoverable — a
/// passive observer subtracts the known grid and reconstructs the node's
/// activity schedule (measured Pearson r = 0.63). This pacer instead drives a
/// **single** slot clock: each slot carries a queued origination if one is
/// waiting, else a dummy. Real and cover then share one clock and are
/// timing-indistinguishable (measured r = 0.00).
///
/// **Scope:** only the node's own originations (wallet sends + auto-churn) are
/// queued here. Relay / block / inv / header traffic bypasses the pacer entirely
/// and is sent directly, so consensus propagation latency is unchanged — pacing
/// *all* outbound would add up to one slot per hop to block propagation and
/// regress CIP-019. See CIP-020 for the latency analysis.
///
/// **Off by default:** only engaged when `TrafficShaperConfig::constant_rate_enabled`
/// is set; until a node opts in, the existing additive shaper is unchanged.
pub struct ConstantRatePacer {
    slot: Duration,
    magic: [u8; 4],
    max_queue: usize,
    queue: Mutex<VecDeque<Vec<u8>>>,
    /// Slots filled with a real origination (diagnostics).
    real_slots: AtomicU64,
    /// Slots filled with a dummy (diagnostics).
    dummy_slots: AtomicU64,
    /// Originations rejected by a full queue — caller direct-sent (diagnostics).
    overflow: AtomicU64,
}

impl ConstantRatePacer {
    /// Create a pacer with the given slot period (ms) and network magic.
    pub fn new(slot_ms: u64, magic: [u8; 4]) -> Self {
        Self {
            slot: Duration::from_millis(slot_ms.max(1)),
            magic,
            max_queue: DEFAULT_MAX_ORIGINATION_QUEUE,
            queue: Mutex::new(VecDeque::new()),
            real_slots: AtomicU64::new(0),
            dummy_slots: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
        }
    }

    /// Queue one already-framed origination for the next free slot.
    ///
    /// Returns `true` if queued. Returns `false` if the bounded queue is full —
    /// the caller MUST then direct-send the packet itself (non-blocking; the
    /// only privacy-degraded path, reachable solely above the slot rate). This
    /// never blocks and never silently drops the packet.
    #[must_use]
    pub fn submit(&self, framed: Vec<u8>) -> bool {
        let mut q = self.queue.lock().expect("pacer queue poisoned");
        if q.len() >= self.max_queue {
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        q.push_back(framed);
        true
    }

    /// The substitutive core: produce this slot's wire packet — a queued
    /// origination if one waits, else a fresh dummy. The returned `bool` is
    /// `true` when the packet was a real origination. Pure and synchronous so
    /// the real-vs-dummy decision is unit-testable without the async clock.
    fn fill_slot(&self) -> (Vec<u8>, bool) {
        // Pop under the lock, then release it before generating a dummy.
        let popped = self.queue.lock().expect("pacer queue poisoned").pop_front();
        match popped {
            Some(real) => {
                self.real_slots.fetch_add(1, Ordering::Relaxed);
                (real, true)
            }
            None => {
                self.dummy_slots.fetch_add(1, Ordering::Relaxed);
                (TrafficShaper::generate_padding_packet(self.magic), false)
            }
        }
    }

    /// Current queue depth (diagnostics / tests).
    pub fn queued(&self) -> usize {
        self.queue.lock().expect("pacer queue poisoned").len()
    }

    /// Number of originations rejected by a full queue (diagnostics).
    pub fn overflow_count(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }

    /// Run the pacing loop: emit exactly one packet per slot to `sender` until
    /// `shutdown`. This is the stream a network observer sees — flat and
    /// constant-rate whether the node is transacting or idle.
    pub async fn run(self: Arc<Self>, sender: mpsc::Sender<Vec<u8>>, shutdown: Arc<AtomicBool>) {
        debug!(
            slot_ms = self.slot.as_millis() as u64,
            "constant-rate origination pacer started"
        );
        while !shutdown.load(Ordering::Relaxed) {
            sleep(self.slot).await;
            let (packet, was_real) = self.fill_slot();
            if sender.send(packet).await.is_err() {
                debug!("pacer: channel closed, stopping");
                break;
            }
            trace!(real = was_real, "pacer filled slot");
        }
        debug!("constant-rate origination pacer stopped");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only network magic. Production uses the live testnet/mainnet
    /// value from `NetworkType::magic_bytes()`; these bytes never appear
    /// on a real wire so collisions with production aren't possible.
    const TEST_MAGIC: [u8; 4] = [0x42, 0x42, 0x42, 0x42];

    // ─── CIP-020 constant-rate pacer ───────────────────────────────

    #[test]
    fn pacer_prefers_real_then_falls_back_to_dummy() {
        let p = ConstantRatePacer::new(500, TEST_MAGIC);
        assert!(p.submit(vec![9, 9, 9]));
        // A queued origination fills the slot in preference to a dummy.
        let (pkt, was_real) = p.fill_slot();
        assert!(was_real);
        assert_eq!(pkt, vec![9, 9, 9]);
        // Queue now empty → the slot is filled with a framed dummy instead.
        let (dummy, was_real2) = p.fill_slot();
        assert!(!was_real2);
        assert!(
            !dummy.is_empty(),
            "dummy must be a real framed padding packet"
        );
    }

    #[test]
    fn pacer_emits_exactly_one_packet_per_slot() {
        // The substitutive invariant: over K slots with M<K originations queued,
        // exactly K packets leave the wire — M real, then K−M dummies. This is
        // what makes the stream flat (idle and active look identical).
        let p = ConstantRatePacer::new(500, TEST_MAGIC);
        for i in 0..3u8 {
            assert!(p.submit(vec![i]));
        }
        let (mut reals, mut total) = (0, 0);
        for _ in 0..10 {
            let (_pkt, was_real) = p.fill_slot();
            total += 1;
            if was_real {
                reals += 1;
            }
        }
        assert_eq!(total, 10, "one packet per slot, always");
        assert_eq!(reals, 3, "exactly the queued originations were real");
        assert_eq!(p.queued(), 0);
    }

    #[test]
    fn pacer_bounded_queue_signals_caller_to_direct_send() {
        let p = ConstantRatePacer::new(500, TEST_MAGIC);
        // Fill to the bound — every submit accepted.
        for _ in 0..DEFAULT_MAX_ORIGINATION_QUEUE {
            assert!(p.submit(vec![0]));
        }
        // The next submit is rejected so the caller direct-sends (privacy-
        // degraded but non-blocking) rather than the pacer growing unbounded.
        assert!(!p.submit(vec![0]));
        assert_eq!(p.overflow_count(), 1);
        assert_eq!(p.queued(), DEFAULT_MAX_ORIGINATION_QUEUE);
    }

    #[test]
    fn normalize_round_trips() {
        let shaper = TrafficShaper::default_enabled();
        let original = b"hello world this is a test message";
        let normalized = shaper.normalize_size(original);

        assert!(TrafficShaper::is_normalized_payload_size(
            normalized.len(),
            0
        ));

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
        assert!(TrafficShaper::is_normalized_payload_size(
            normalized.len(),
            0
        ));

        let recovered = TrafficShaper::denormalize(&normalized).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn normalization_accounts_for_outer_overhead() {
        let shaper = TrafficShaper::default_enabled();
        let original = vec![0x42; 250];
        let normalized =
            shaper.normalize_size_with_overhead(&original, super::super::framing::HEADER_SIZE);
        assert!(TrafficShaper::is_normalized_payload_size(
            normalized.len(),
            super::super::framing::HEADER_SIZE,
        ));
        assert_eq!(TrafficShaper::denormalize(&normalized).unwrap(), original);
    }

    #[test]
    fn denormalize_rejects_unmarked_payload() {
        assert!(TrafficShaper::denormalize(&[0, 0, 0, 0]).is_none());
    }

    #[test]
    fn noise_record_input_fits_largest_bucket() {
        assert_eq!(
            TrafficShaper::max_normalizable_input(65_519, 18),
            Some(65_514)
        );
    }

    #[test]
    fn padding_packet_is_properly_framed() {
        // Phase 2: padding now goes through the framer as MessageType::Padding.
        // Verify the bytes have the right magic in the prefix and the
        // msg_type byte (at offset 4) is the Padding discriminant (99).
        let packet = TrafficShaper::generate_padding_packet(TEST_MAGIC);
        assert!(packet.len() >= super::super::framing::HEADER_SIZE);
        assert_eq!(
            &packet[..4],
            &TEST_MAGIC,
            "packet must start with the supplied network magic",
        );
        assert_eq!(
            packet[4],
            super::super::protocol::MessageType::Padding as u8,
            "msg_type byte must be MessageType::Padding ({})",
            super::super::protocol::MessageType::Padding as u8,
        );
        assert_eq!(packet.len(), super::super::framing::HEADER_SIZE + 32);
    }

    #[test]
    fn padding_packet_random_per_call() {
        // Fresh randomness per packet — two consecutive packets must
        // differ in their payload bytes (the header is deterministic).
        let p1 = TrafficShaper::generate_padding_packet(TEST_MAGIC);
        let p2 = TrafficShaper::generate_padding_packet(TEST_MAGIC);
        // Skip header bytes when comparing — the payload after HEADER_SIZE
        // is random per call.
        let body1 = &p1[super::super::framing::HEADER_SIZE..];
        let body2 = &p2[super::super::framing::HEADER_SIZE..];
        // The size index is also random, so packets might differ in length.
        // If they're the same length, the bodies must differ.
        if body1.len() == body2.len() && body1.len() > 0 {
            assert_ne!(
                body1, body2,
                "padding packet bodies must be random per call"
            );
        }
    }

    #[test]
    fn normalized_limit_picks_smallest_fit() {
        // 10 bytes + 4 prefix = 14 → 256
        assert_eq!(TrafficShaper::normalized_payload_limit(10, 0), 256);
        // 250 bytes + 4 = 254 → 256
        assert_eq!(TrafficShaper::normalized_payload_limit(250, 0), 256);
        // 253 bytes + 4 = 257 → 512
        assert_eq!(TrafficShaper::normalized_payload_limit(253, 0), 512);
        // 1020 bytes + 4 = 1024 → 1024
        assert_eq!(TrafficShaper::normalized_payload_limit(1020, 0), 1024);
    }

    #[test]
    fn disabled_shaper_passes_through() {
        let shaper = TrafficShaper::default_enabled();
        shaper.set_enabled(false);
        let original = b"passthrough data";
        let result = shaper.normalize_size(original);
        assert_eq!(result, original);
    }

    // ─── Broadcast-loop production wire-up tests ─────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_loop_emits_packets_per_peer_per_tick() {
        // Three mock peers (each with its own mpsc Receiver). Tight
        // padding_interval (50ms) so the test finishes fast. Verify
        // every receiver sees at least one padding packet within ~3
        // ticks AND padding_sent counts match the total deliveries.
        let cfg = TrafficShaperConfig {
            padding_interval_ms: 50,
            ..TrafficShaperConfig::default()
        };
        let shaper = Arc::new(TrafficShaper::new(cfg));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (tx0, mut rx0) = mpsc::channel::<Vec<u8>>(8);
        let (tx1, mut rx1) = mpsc::channel::<Vec<u8>>(8);
        let (tx2, mut rx2) = mpsc::channel::<Vec<u8>>(8);
        let txs = vec![tx0, tx1, tx2];

        let s_clone = shaper.clone();
        let sd_clone = shutdown.clone();
        let txs_clone = txs.clone();
        let handle = tokio::spawn(async move {
            s_clone
                .run_padding_loop_broadcast(
                    TEST_MAGIC,
                    move || txs_clone.clone().into_iter(),
                    sd_clone,
                )
                .await;
        });

        // Wait long enough for ~3 ticks to fire.
        tokio::time::sleep(Duration::from_millis(180)).await;
        shutdown.store(true, Ordering::Relaxed);
        // Drop the loop's senders so the loop's try_send errors out
        // and the recvs we hold below stop blocking.
        drop(txs);
        let _ = handle.await;

        // Each peer should have received at least 2 packets in 180ms
        // at 50ms cadence.
        let r0 = collect_until_empty(&mut rx0).await;
        let r1 = collect_until_empty(&mut rx1).await;
        let r2 = collect_until_empty(&mut rx2).await;
        assert!(
            r0.len() >= 2,
            "peer 0 saw {} packets, expected >= 2",
            r0.len()
        );
        assert!(
            r1.len() >= 2,
            "peer 1 saw {} packets, expected >= 2",
            r1.len()
        );
        assert!(
            r2.len() >= 2,
            "peer 2 saw {} packets, expected >= 2",
            r2.len()
        );

        // padding_sent should equal sum of all peer deliveries
        // (the loop counts each successful try_send).
        let stats = shaper.stats();
        let total_received = (r0.len() + r1.len() + r2.len()) as u64;
        assert_eq!(
            stats.padding_sent, total_received,
            "padding_sent counter ({}) must match peers' received total ({})",
            stats.padding_sent, total_received
        );

        // Every received packet must be properly framed: TEST_MAGIC
        // in the first 4 bytes, MessageType::Padding (99) at offset 4.
        for p in r0.iter().chain(r1.iter()).chain(r2.iter()) {
            assert!(
                p.len() >= super::super::framing::HEADER_SIZE,
                "packet too short"
            );
            assert_eq!(&p[..4], &TEST_MAGIC, "wrong magic prefix");
            assert_eq!(
                p[4],
                super::super::protocol::MessageType::Padding as u8,
                "msg_type byte must be Padding",
            );
        }

        // Per-peer packets must differ — otherwise colluding observers
        // could detect the shared payload.
        if !r0.is_empty() && !r1.is_empty() {
            assert_ne!(
                r0[0], r1[0],
                "peers 0 and 1 received identical padding bytes"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_loop_skips_ticks_when_disabled() {
        // Disable the shaper after spawning. Padding counter must
        // freeze. Verifies the per-tick is_enabled / padding_enabled
        // gate works at runtime.
        let cfg = TrafficShaperConfig {
            padding_interval_ms: 50,
            ..TrafficShaperConfig::default()
        };
        let shaper = Arc::new(TrafficShaper::new(cfg));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
        let txs = vec![tx];
        let s_clone = shaper.clone();
        let sd_clone = shutdown.clone();
        let txs_clone = txs.clone();
        let handle = tokio::spawn(async move {
            s_clone
                .run_padding_loop_broadcast(
                    TEST_MAGIC,
                    move || txs_clone.clone().into_iter(),
                    sd_clone,
                )
                .await;
        });

        // Run ~2 ticks while ENABLED so the loop ramps up.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            shaper.stats().padding_sent >= 1,
            "shaper should have sent at least 1 packet before disable"
        );

        // Disable, then sleep at least 2× the interval so any tick
        // that was already past the is_enabled gate when we flipped
        // the flag has time to complete. Read the WARM baseline
        // AFTER that drain — anything between this read and the
        // cold read below is the test signal.
        shaper.set_enabled(false);
        tokio::time::sleep(Duration::from_millis(120)).await;
        let warm = shaper.stats().padding_sent;

        // Run another 200ms — counter must NOT increase past warm.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let cold = shaper.stats().padding_sent;
        assert_eq!(
            warm, cold,
            "disabled shaper still emitted packets ({} -> {})",
            warm, cold
        );

        shutdown.store(true, Ordering::Relaxed);
        drop(txs);
        let _ = handle.await;
        let _ = collect_until_empty(&mut rx).await; // drain
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_loop_does_not_block_on_full_peer() {
        // One peer with a 1-slot channel that we never drain. The
        // broadcast loop must NOT stall — it should `try_send`, see
        // Full, drop the packet, and continue ticking. Verifies
        // backpressure-safety.
        let cfg = TrafficShaperConfig {
            padding_interval_ms: 30,
            ..TrafficShaperConfig::default()
        };
        let shaper = Arc::new(TrafficShaper::new(cfg));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (slow_tx, _slow_rx) = mpsc::channel::<Vec<u8>>(1);
        let (fast_tx, mut fast_rx) = mpsc::channel::<Vec<u8>>(64);
        let txs = vec![slow_tx, fast_tx];
        let s_clone = shaper.clone();
        let sd_clone = shutdown.clone();
        let txs_clone = txs.clone();
        let handle = tokio::spawn(async move {
            s_clone
                .run_padding_loop_broadcast(
                    TEST_MAGIC,
                    move || txs_clone.clone().into_iter(),
                    sd_clone,
                )
                .await;
        });

        // 10 ticks at 30ms = 300ms.
        tokio::time::sleep(Duration::from_millis(330)).await;
        shutdown.store(true, Ordering::Relaxed);
        drop(txs);
        let _ = handle.await;

        // Fast peer should have received many packets — proves the
        // loop wasn't blocked by the slow peer.
        let fast_received = collect_until_empty(&mut fast_rx).await;
        assert!(
            fast_received.len() >= 5,
            "fast peer saw only {} packets, expected >= 5 (slow peer stalled the loop?)",
            fast_received.len()
        );
    }

    async fn collect_until_empty(rx: &mut mpsc::Receiver<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(20), rx.recv()).await {
                Ok(Some(v)) => out.push(v),
                _ => return out,
            }
        }
    }
}
