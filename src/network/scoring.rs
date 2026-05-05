//! Enhanced peer scoring and reputation system
//!
//! Provides detailed behavioral tracking for peer selection and prioritization.
//! Peers are scored based on multiple factors including latency, reliability,
//! and protocol compliance.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// SECURITY (H17-FIX): Per-behavior misbehavior types with specific penalties.
/// Based on Bitcoin Core's `Misbehaving()` pattern in `net_processing.cpp`.
/// Each offense type carries a calibrated penalty that accumulates toward
/// the ban threshold (-50 reputation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MisbehaviorType {
    /// Sent block with invalid PoW (instant ban)
    InvalidBlockPoW,
    /// Sent block with invalid signatures or proofs
    InvalidBlockProofs,
    /// Sent invalid transaction (bad ring sig, range proof, etc.)
    InvalidTransaction,
    /// Sent oversized message exceeding per-type limit
    OversizedMessage,
    /// Sent too many orphan blocks (flooding)
    OrphanFlood,
    /// Protocol version mismatch or invalid handshake
    ProtocolViolation,
    /// Repeated requests for data we already sent (bandwidth waste)
    DuplicateRequests,
    /// Sent unrequested data (unsolicited blocks/txs)
    UnrequestedData,
    /// Stalling: requested blocks but never completed download
    DownloadStall,
    /// Invalid address in addr message
    InvalidAddress,
    /// Block or message from wrong network (instant ban)
    WrongNetwork,
    /// Block missing or invalid ChainAnchorStamp
    InvalidAnchorStamp,
    /// Per-message-type flood (e.g. 100 GetBlocks/sec)
    MessageFlood,
    /// Peer's outbound channel was chronically full — they couldn't keep
    /// up with broadcasts and were disconnected by `broadcast_raw` after
    /// `STALL_THRESHOLD` consecutive `Full` errors. Penalty scored so the
    /// same peer can't immediately reconnect and resume the same pattern.
    ChronicSendQueueFull,
}

impl MisbehaviorType {
    /// Penalty in reputation points for each offense type.
    /// Calibrated so that serious offenses (invalid PoW) ban immediately,
    /// while minor offenses (duplicate requests) accumulate gradually.
    pub fn penalty(&self) -> i32 {
        match self {
            // Instant ban (penalty >= 50, threshold is -50)
            MisbehaviorType::InvalidBlockPoW => 100,
            MisbehaviorType::InvalidBlockProofs => 50,

            // Severe (2-3 offenses → ban)
            MisbehaviorType::InvalidTransaction => 25,
            MisbehaviorType::OrphanFlood => 20,
            MisbehaviorType::ProtocolViolation => 20,

            // Moderate (5-10 offenses → ban)
            MisbehaviorType::OversizedMessage => 10,
            MisbehaviorType::UnrequestedData => 10,

            // Minor (10-25 offenses → ban)
            MisbehaviorType::DuplicateRequests => 5,
            MisbehaviorType::DownloadStall => 5,
            MisbehaviorType::InvalidAddress => 2,

            // Wrong network — instant ban (cross-network pollution)
            MisbehaviorType::WrongNetwork => 100,
            // Invalid anchor stamp — severe (faked sync proof)
            MisbehaviorType::InvalidAnchorStamp => 50,
            // Message flood — moderate (10 offenses → ban)
            MisbehaviorType::MessageFlood => 5,
            // Chronic send-queue full — severe. We've already disconnected
            // them; this penalty (2 strikes -> ban) ensures they don't
            // immediately reconnect and re-occupy a peer slot.
            MisbehaviorType::ChronicSendQueueFull => 25,
        }
    }
}

/// Detailed peer score with multiple factors
#[derive(Clone, Debug)]
pub struct PeerScore {
    /// Base reputation (-100 to 100)
    pub reputation: i32,
    /// Average response latency in milliseconds
    pub latency_ms: u32,
    /// Block delivery speed (blocks per second)
    pub block_speed: f64,
    /// Percentage of valid messages (0.0 to 1.0)
    pub validity_rate: f64,
    /// Number of successful block deliveries
    pub blocks_delivered: u64,
    /// Number of failed/invalid deliveries
    pub blocks_failed: u64,
    /// Number of transactions relayed
    pub txs_relayed: u64,
    /// Number of invalid transactions sent
    pub invalid_txs: u64,
    /// Time of last successful interaction
    pub last_success: Option<Instant>,
    /// Time of last failure
    pub last_failure: Option<Instant>,
    /// Whether peer supports compact blocks
    pub supports_compact_blocks: bool,
    /// Whether peer has been validated (completed handshake)
    pub validated: bool,
    /// Connection uptime in seconds
    pub uptime_secs: u64,
    /// Number of reconnection attempts
    pub reconnects: u32,
    /// Number of consecutive `Blocks` responses where the peer returned 0
    /// blocks. Reset to 0 on any successful (non-empty) `Blocks` reply.
    /// Drives the temporary GetBlocks ban below.
    ///
    /// This catches the "stall pathology" failure mode observed twice on the
    /// public testnet (peer 15.1.193.74 on 2026-05-04, peer 75.82.181.240 on
    /// 2026-05-05): the peer accepts `GetBlocks`, replies with an empty
    /// `Blocks` message, and the IBD orphan-loop fix re-queues the request
    /// against the same peer forever. Tracking consecutive empties lets us
    /// demote unhelpful peers without banning peers that are simply on a
    /// different fork (a single empty reply is normal).
    pub consecutive_empty_blocks: u32,
    /// If `Some`, this peer is banned from `GetBlocks` selection until the
    /// instant in the variant. Auto-expires (cleared by `is_get_blocks_banned`)
    /// so peers that recover from their own resync get another shot.
    pub get_blocks_banned_until: Option<Instant>,
}

impl Default for PeerScore {
    fn default() -> Self {
        PeerScore {
            reputation: 50, // Start neutral
            latency_ms: 1000, // Assume 1s until measured
            block_speed: 0.0,
            validity_rate: 1.0, // Assume valid until proven otherwise
            blocks_delivered: 0,
            blocks_failed: 0,
            txs_relayed: 0,
            invalid_txs: 0,
            last_success: None,
            last_failure: None,
            supports_compact_blocks: false,
            validated: false,
            uptime_secs: 0,
            reconnects: 0,
            consecutive_empty_blocks: 0,
            get_blocks_banned_until: None,
        }
    }
}

/// After this many consecutive empty `Blocks` responses, ban the peer from
/// GetBlocks selection. 5 is enough to distinguish "peer is on a different
/// fork" (typically 1-2 empties) from "peer is unhelpful" (the wedge pattern,
/// which produces dozens to thousands of consecutive empties).
pub const EMPTY_BLOCKS_BAN_THRESHOLD: u32 = 5;

/// How long a peer stays banned from GetBlocks after triggering the threshold.
/// 1 hour is long enough to give the peer time to fix its own state (often
/// they're in the middle of their own resync) without permanently locking
/// them out. Auto-expires; no manual unban needed.
pub const EMPTY_BLOCKS_BAN_DURATION_SECS: u64 = 3600;

/// Per-peer, per-message-type rate tracker.
///
/// Tracks how many messages of each type a peer sends per window.
/// When a peer exceeds the limit for any message type, report
/// `MisbehaviorType::MessageFlood` to the scorer.
///
/// Limits are calibrated so normal IBD (requesting many blocks) is fine,
/// but 100 GetBlocks/sec from a single peer triggers a penalty.
// AUDIT (Phase D): Wired into P2P dispatch loop in `node.rs::handle_connection`.
#[allow(dead_code)]
pub struct PeerMessageRateTracker {
    /// (message_type_id, count) for the current window
    counts: HashMap<u8, u32>,
    /// Start of current measurement window
    window_start: Instant,
    /// Window duration (default 10 seconds)
    window_secs: u64,
}

/// Per-message-type limits (messages per 10-second window).
/// Heavy request types have lower limits. Data responses are unlimited
/// (we asked for them).
#[allow(dead_code)]
const MSG_RATE_LIMITS: &[(u8, u32)] = &[
    (0x01, 50),   // Version — 5/sec
    (0x03, 100),  // GetHeaders — 10/sec
    (0x05, 100),  // GetBlocks — 10/sec
    (0x07, 200),  // GetData — 20/sec
    (0x09, 500),  // InvTx — 50/sec (relaying txs to many peers is normal)
    (0x0A, 100),  // InvBlock — 10/sec
    (0x0B, 50),   // GetAddr — 5/sec
    (0x10, 30),   // Ping — 3/sec
];

#[allow(dead_code)]
impl PeerMessageRateTracker {
    pub fn new() -> Self {
        PeerMessageRateTracker {
            counts: HashMap::new(),
            window_start: Instant::now(),
            window_secs: 10,
        }
    }

    /// Record a message and return true if the rate limit is exceeded.
    pub fn record(&mut self, msg_type_id: u8) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= self.window_secs {
            self.counts.clear();
            self.window_start = now;
        }

        let count = self.counts.entry(msg_type_id).or_insert(0);
        *count += 1;

        // Check against per-type limit
        for &(type_id, limit) in MSG_RATE_LIMITS {
            if msg_type_id == type_id && *count > limit {
                return true; // Rate exceeded
            }
        }
        false
    }
}

impl Default for PeerMessageRateTracker {
    fn default() -> Self { Self::new() }
}

impl PeerScore {
    /// Calculate composite score for peer ranking (higher = better)
    ///
    /// The composite score weighs multiple factors:
    /// - Reputation (40%): Base trust level
    /// - Latency (25%): Lower is better
    /// - Validity (20%): Higher is better
    /// - Block speed (15%): Higher is better
    pub fn composite_score(&self) -> f64 {
        // Normalize reputation to 0-1
        let rep_normalized = (self.reputation + 100) as f64 / 200.0;

        // Normalize latency (lower is better, cap at 5000ms)
        let latency_capped = self.latency_ms.min(5000) as f64;
        let latency_normalized = 1.0 - (latency_capped / 5000.0);

        // Validity rate already 0-1
        let validity = self.validity_rate;

        // Normalize block speed (assume 100 blocks/sec is excellent)
        let speed_normalized = (self.block_speed / 100.0).min(1.0);

        // Weighted combination
        0.40 * rep_normalized
            + 0.25 * latency_normalized
            + 0.20 * validity
            + 0.15 * speed_normalized
    }

    /// Record a successful block delivery
    ///
    /// SECURITY (H-15 FIX): Also marks peer as validated. A peer that delivers
    /// a valid block has proven itself more conclusively than one that merely
    /// completed handshake. Without this, is_good() never returns true for
    /// peers that skip the handshake-validation path (e.g., inbound connections
    /// that start sending blocks before the scorer sees the handshake event).
    pub fn record_block_success(&mut self, latency: Duration) {
        self.blocks_delivered += 1;
        self.last_success = Some(Instant::now());
        self.validated = true; // H-15 FIX: delivering valid block = validated
        self.consecutive_empty_blocks = 0; // a real delivery clears the wedge counter
        self.update_latency(latency);
        self.update_validity_rate();
        self.adjust_reputation(2);
    }

    /// Record a failed/invalid block
    pub fn record_block_failure(&mut self) {
        self.blocks_failed += 1;
        self.last_failure = Some(Instant::now());
        self.update_validity_rate();
        self.adjust_reputation(-10);
    }

    /// Record that the peer responded to a `GetBlocks` request with an empty
    /// `Blocks` message. Different from [`record_block_failure`] because no
    /// invalid data was sent — the peer simply isn't delivering. After
    /// [`EMPTY_BLOCKS_BAN_THRESHOLD`] consecutive empties the peer is banned
    /// from `GetBlocks` selection for [`EMPTY_BLOCKS_BAN_DURATION_SECS`].
    /// Auto-expires; the peer gets another chance once its own state is
    /// presumed fixed.
    ///
    /// This closes the "stall pathology" recurrence pattern documented in
    /// `project_explorer_peer_wedge.md` (memory): on 2026-05-04 + 2026-05-05
    /// the explorer node wedged on misbehaving peers responding with empty
    /// `Blocks` messages indefinitely, requiring manual `systemctl restart`.
    pub fn record_empty_blocks_response(&mut self) {
        self.consecutive_empty_blocks = self.consecutive_empty_blocks.saturating_add(1);
        self.last_failure = Some(Instant::now());
        // Modest reputation hit per empty reply; the harder consequence is
        // the GetBlocks-selection ban below. -15 each so a normal "different
        // fork" empty (1-2 of them) doesn't permanently demote a peer.
        self.adjust_reputation(-15);
        if self.consecutive_empty_blocks >= EMPTY_BLOCKS_BAN_THRESHOLD {
            self.get_blocks_banned_until = Some(
                Instant::now() + Duration::from_secs(EMPTY_BLOCKS_BAN_DURATION_SECS),
            );
        }
    }

    /// Check whether this peer is currently banned from `GetBlocks` selection.
    /// Auto-expires the ban if the duration has elapsed; on expiry the
    /// `consecutive_empty_blocks` counter is also reset so the peer starts
    /// from a clean slate. Returns `true` only if the ban is still active.
    pub fn is_get_blocks_banned(&mut self) -> bool {
        match self.get_blocks_banned_until {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                // Ban expired — give the peer another chance.
                self.get_blocks_banned_until = None;
                self.consecutive_empty_blocks = 0;
                false
            }
            None => false,
        }
    }

    /// Record a successful transaction relay
    pub fn record_tx_success(&mut self) {
        self.txs_relayed += 1;
        self.last_success = Some(Instant::now());
        self.validated = true; // H-15 FIX: relaying valid tx = validated
        self.adjust_reputation(1);
    }

    /// Record an invalid transaction
    pub fn record_invalid_tx(&mut self) {
        self.invalid_txs += 1;
        self.last_failure = Some(Instant::now());
        self.update_validity_rate();
        self.adjust_reputation(-5);
    }

    /// Record protocol violation (spam, malformed messages, etc.)
    pub fn record_protocol_violation(&mut self) {
        self.adjust_reputation(-20);
        self.last_failure = Some(Instant::now());
    }

    /// SECURITY (H17-FIX): Per-behavior misbehavior scoring (Bitcoin Misbehaving() pattern).
    /// Each offense type has a specific penalty. Accumulates toward the ban threshold.
    /// Like Bitcoin's `net_processing.cpp:Misbehaving()`, this enables nuanced responses
    /// to different types of bad behavior rather than a single flat penalty.
    pub fn record_misbehavior(&mut self, offense: MisbehaviorType) {
        let penalty = offense.penalty();
        self.adjust_reputation(-penalty);
        self.last_failure = Some(Instant::now());
        tracing::debug!(
            "Peer misbehavior: {:?} (penalty: -{}, reputation now: {})",
            offense, penalty, self.reputation
        );
    }

    /// Update average latency with exponential moving average
    fn update_latency(&mut self, latency: Duration) {
        let new_latency = latency.as_millis().min(u32::MAX as u128) as u32;
        // EMA with alpha = 0.3 (more weight on recent)
        self.latency_ms = ((self.latency_ms as f64 * 0.7) + (new_latency as f64 * 0.3)) as u32;
    }

    /// Update validity rate
    fn update_validity_rate(&mut self) {
        let total_blocks = self.blocks_delivered + self.blocks_failed;
        let total_txs = self.txs_relayed + self.invalid_txs;
        let total = total_blocks + total_txs;

        if total > 0 {
            let valid = self.blocks_delivered + self.txs_relayed;
            self.validity_rate = valid as f64 / total as f64;
        }
    }

    /// Adjust reputation with clamping
    fn adjust_reputation(&mut self, delta: i32) {
        self.reputation = (self.reputation + delta).clamp(-100, 100);
    }

    /// Check if peer should be banned
    pub fn should_ban(&self) -> bool {
        self.reputation <= -50
    }

    /// Check if peer is good quality
    pub fn is_good(&self) -> bool {
        self.composite_score() >= 0.6 && self.validated
    }

    /// Decay reputation toward neutral (call periodically)
    pub fn decay(&mut self, neutral: i32) {
        if self.reputation > neutral {
            self.reputation -= 1;
        } else if self.reputation < neutral {
            self.reputation += 1;
        }
    }
}

/// Peer scoring manager for the entire network
pub struct PeerScorer {
    /// Scores by peer address
    scores: HashMap<SocketAddr, PeerScore>,
    /// Banned peers with ban expiry
    banned: HashMap<SocketAddr, Instant>,
    /// Ban duration
    ban_duration: Duration,
    /// Minimum score to be considered for block download
    min_download_score: f64,
}

impl PeerScorer {
    /// Create a new peer scorer
    pub fn new() -> Self {
        PeerScorer {
            scores: HashMap::new(),
            banned: HashMap::new(),
            ban_duration: Duration::from_secs(3600), // 1 hour default ban
            min_download_score: 0.3,
        }
    }

    /// Get or create score for a peer
    pub fn get_or_create(&mut self, addr: SocketAddr) -> &mut PeerScore {
        self.scores.entry(addr).or_insert_with(PeerScore::default)
    }

    /// Get score for a peer (read-only)
    pub fn get(&self, addr: &SocketAddr) -> Option<&PeerScore> {
        self.scores.get(addr)
    }

    /// Remove a peer's score
    pub fn remove(&mut self, addr: &SocketAddr) {
        self.scores.remove(addr);
    }

    /// Check if peer is banned
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(expiry) = self.banned.get(addr) {
            if Instant::now() < *expiry {
                return true;
            }
        }
        false
    }

    /// Ban a peer
    pub fn ban(&mut self, addr: SocketAddr) {
        let expiry = Instant::now() + self.ban_duration;
        self.banned.insert(addr, expiry);
        self.scores.remove(&addr);
    }

    /// Unban a peer
    pub fn unban(&mut self, addr: &SocketAddr) {
        self.banned.remove(addr);
    }

    /// Get top N peers for block download
    pub fn top_peers_for_download(&self, n: usize) -> Vec<SocketAddr> {
        let mut peers: Vec<_> = self.scores.iter()
            .filter(|(_, score)| score.composite_score() >= self.min_download_score)
            .filter(|(_, score)| score.validated)
            .collect();

        peers.sort_by(|a, b| {
            b.1.composite_score().partial_cmp(&a.1.composite_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        peers.into_iter()
            .take(n)
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Get peers sorted by latency (for time-sensitive operations)
    pub fn peers_by_latency(&self) -> Vec<SocketAddr> {
        let mut peers: Vec<_> = self.scores.iter()
            .filter(|(_, score)| score.validated)
            .collect();

        peers.sort_by_key(|(_, score)| score.latency_ms);

        peers.into_iter()
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Get statistics about peer quality
    pub fn stats(&self) -> ScorerStats {
        let total = self.scores.len();
        let good = self.scores.values().filter(|s| s.is_good()).count();
        let banned = self.banned.len();

        let avg_score = if total > 0 {
            self.scores.values().map(|s| s.composite_score()).sum::<f64>() / total as f64
        } else {
            0.0
        };

        let avg_latency = if total > 0 {
            self.scores.values().map(|s| s.latency_ms as u64).sum::<u64>() / total as u64
        } else {
            0
        };

        ScorerStats {
            total_peers: total,
            good_peers: good,
            banned_peers: banned,
            average_score: avg_score,
            average_latency_ms: avg_latency,
        }
    }

    /// Clean up expired bans
    pub fn cleanup_bans(&mut self) {
        let now = Instant::now();
        self.banned.retain(|_, expiry| *expiry > now);
    }

    /// Decay all peer reputations (call periodically)
    pub fn decay_all(&mut self, neutral: i32) {
        for score in self.scores.values_mut() {
            score.decay(neutral);
        }
    }

    /// Check and ban peers with low scores
    pub fn auto_ban_bad_peers(&mut self) {
        let to_ban: Vec<_> = self.scores.iter()
            .filter(|(_, score)| score.should_ban())
            .map(|(addr, _)| *addr)
            .collect();

        for addr in to_ban {
            self.ban(addr);
        }
    }
}

impl Default for PeerScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable ban entry for disk persistence
#[derive(serde::Serialize, serde::Deserialize)]
struct BanEntry {
    addr: String,
    /// Seconds remaining in ban at time of save
    remaining_secs: u64,
}

impl PeerScorer {
    /// Save ban list to disk for persistence across restarts
    pub fn save_bans_to_file(&self, path: &std::path::Path) -> std::result::Result<(), String> {
        let now = Instant::now();
        let entries: Vec<BanEntry> = self.banned.iter()
            .filter(|(_, expiry)| **expiry > now)
            .map(|(addr, expiry)| BanEntry {
                addr: addr.to_string(),
                remaining_secs: expiry.duration_since(now).as_secs(),
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| format!("serialize bans: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("write ban list: {}", e))?;
        Ok(())
    }

    /// Load ban list from disk
    pub fn load_bans_from_file(&mut self, path: &std::path::Path) -> std::result::Result<usize, String> {
        if !path.exists() {
            return Ok(0);
        }
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("read ban list: {}", e))?;
        let entries: Vec<BanEntry> = serde_json::from_str(&data)
            .map_err(|e| format!("parse ban list: {}", e))?;

        let mut loaded = 0;
        for entry in entries {
            if let Ok(addr) = entry.addr.parse::<std::net::SocketAddr>() {
                if entry.remaining_secs > 0 {
                    let expiry = Instant::now() + Duration::from_secs(entry.remaining_secs);
                    self.banned.insert(addr, expiry);
                    loaded += 1;
                }
            }
        }
        Ok(loaded)
    }
}

/// Scorer statistics
#[derive(Debug, Clone)]
pub struct ScorerStats {
    pub total_peers: usize,
    pub good_peers: usize,
    pub banned_peers: usize,
    pub average_score: f64,
    pub average_latency_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_composite_score() {
        let mut score = PeerScore::default();
        score.reputation = 100;
        score.latency_ms = 100;
        score.validity_rate = 1.0;
        score.block_speed = 50.0;

        let composite = score.composite_score();
        assert!(composite > 0.8, "Good peer should have high score: {}", composite);
    }

    #[test]
    fn test_peer_scorer() {
        let mut scorer = PeerScorer::new();
        let addr = test_addr(8080);

        // Get or create
        {
            let score = scorer.get_or_create(addr);
            score.validated = true;
            score.reputation = 80;
            score.record_block_success(Duration::from_millis(50));
        }

        // Check it's in top peers
        let top = scorer.top_peers_for_download(5);
        assert!(top.contains(&addr));
    }

    #[test]
    fn test_ban_system() {
        let mut scorer = PeerScorer::new();
        let addr = test_addr(8080);

        assert!(!scorer.is_banned(&addr));
        scorer.ban(addr);
        assert!(scorer.is_banned(&addr));
        scorer.unban(&addr);
        assert!(!scorer.is_banned(&addr));
    }

    #[test]
    fn empty_blocks_ban_triggers_at_threshold() {
        // Closes the wedge-pattern recurrence: peer keeps replying to
        // GetBlocks with empty Blocks messages → after THRESHOLD consecutive
        // empties, peer is banned from GetBlocks selection.
        let mut score = PeerScore::default();
        assert!(!score.is_get_blocks_banned(), "fresh peer not banned");
        assert_eq!(score.consecutive_empty_blocks, 0);

        // One empty reply: no ban yet (could just be different fork).
        score.record_empty_blocks_response();
        assert_eq!(score.consecutive_empty_blocks, 1);
        assert!(!score.is_get_blocks_banned());

        // Drive up to (but not past) the threshold.
        for _ in 1..EMPTY_BLOCKS_BAN_THRESHOLD {
            score.record_empty_blocks_response();
        }
        assert_eq!(score.consecutive_empty_blocks, EMPTY_BLOCKS_BAN_THRESHOLD);
        assert!(score.is_get_blocks_banned(), "ban triggered at threshold");
    }

    #[test]
    fn empty_blocks_ban_resets_on_real_block_delivery() {
        // A peer that recovers (sends an actual block) should clear the
        // consecutive-empty counter so a fresh streak can build up. This
        // prevents permanent demotion of peers that had one bad window.
        let mut score = PeerScore::default();
        for _ in 0..(EMPTY_BLOCKS_BAN_THRESHOLD - 1) {
            score.record_empty_blocks_response();
        }
        assert!(!score.is_get_blocks_banned(), "below threshold = not banned");
        assert_eq!(score.consecutive_empty_blocks, EMPTY_BLOCKS_BAN_THRESHOLD - 1);

        // Successful delivery resets the counter.
        score.record_block_success(Duration::from_millis(100));
        assert_eq!(score.consecutive_empty_blocks, 0, "real delivery clears the wedge counter");
        assert!(!score.is_get_blocks_banned());
    }

    #[test]
    fn empty_blocks_ban_auto_expires() {
        // Manually set get_blocks_banned_until in the past — the next
        // is_get_blocks_banned() call should observe expiry, clear the ban,
        // and reset the counter so the peer gets a fresh start.
        let mut score = PeerScore::default();
        for _ in 0..EMPTY_BLOCKS_BAN_THRESHOLD {
            score.record_empty_blocks_response();
        }
        assert!(score.is_get_blocks_banned());

        // Force expiry by overwriting with a past instant.
        score.get_blocks_banned_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!score.is_get_blocks_banned(), "expired ban auto-clears");
        assert_eq!(score.consecutive_empty_blocks, 0, "counter reset on expiry");
        assert!(score.get_blocks_banned_until.is_none(), "ban field cleared on expiry");
    }

    #[test]
    fn test_decay_convergence() {
        let mut score = PeerScore::default();
        score.reputation = 80;
        let neutral = 50;
        // Decay toward neutral over many iterations
        for _ in 0..100 {
            score.decay(neutral);
        }
        assert_eq!(score.reputation, neutral);
    }

    #[test]
    fn test_message_rate_tracker_flags_flood() {
        let mut tracker = PeerMessageRateTracker::new();
        let mut exceeded = false;
        for _ in 0..101 {
            exceeded = tracker.record(0x05); // GetBlocks, limit 100/10s
        }
        assert!(exceeded, "expected message flood threshold to trigger");
    }

    #[test]
    fn test_misbehavior_wrong_network_is_immediate_ban_threshold() {
        let mut score = PeerScore::default();
        score.record_misbehavior(MisbehaviorType::WrongNetwork);
        assert!(score.should_ban(), "wrong-network offense should trigger ban");
    }

    #[test]
    fn test_auto_ban_bad_peers_after_severe_offense() {
        let mut scorer = PeerScorer::new();
        let addr = test_addr(9090);
        {
            let s = scorer.get_or_create(addr);
            s.record_misbehavior(MisbehaviorType::InvalidBlockPoW);
            assert!(s.should_ban());
        }
        scorer.auto_ban_bad_peers();
        assert!(scorer.is_banned(&addr));
        assert!(scorer.get(&addr).is_none(), "banned peer score should be removed");
    }
}
