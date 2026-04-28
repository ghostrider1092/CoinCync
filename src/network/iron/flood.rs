//! # Flood and Sybil Protection
//!
//! 1. **IP rate limiting** — max N connection attempts per IP per minute
//! 2. **Subnet limiting** — max M peers from the same /24 subnet
//! 3. **Header flood** — max pending headers per peer
//! 4. **Block request flood** — max inflight block requests per peer
//! 5. **Disconnect spam** — ban peers that connect-disconnect repeatedly

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::network::peer::PeerId;

const IP_RATE_LIMIT:        u32      = 10;
const IP_RATE_WINDOW:       Duration = Duration::from_secs(60);
const MAX_PEERS_PER_SUBNET: usize    = 3;
const MAX_HEADERS_PER_PEER: usize    = 2000;
const MAX_BLOCKS_PER_PEER:  usize    = 64;
const DISCO_SPAM_LIMIT:     u32      = 5;
const DISCO_SPAM_WINDOW:    Duration = Duration::from_secs(60);

struct IpRecord {
    attempts: Vec<Instant>,
    banned_until: Option<Instant>,
}

impl IpRecord {
    fn new() -> Self { IpRecord { attempts: Vec::new(), banned_until: None } }

    fn is_banned(&self) -> bool {
        self.banned_until.map(|t| Instant::now() < t).unwrap_or(false)
    }

    // FIX #22: accept ban duration as a parameter so the ban length is
    // driven by `IronConfig.ban_base` instead of a hardcoded 300s. Previously
    // an operator who tuned `ban_base` in their config would find that
    // FloodGuard bans remained at 5 minutes regardless — silently ignoring
    // their configuration.
    fn allow_attempt(&mut self, limit: u32, window: Duration, ban_duration: Duration) -> bool {
        if self.is_banned() { return false; }
        let now = Instant::now();
        self.attempts.retain(|t| now.duration_since(*t) < window);
        if self.attempts.len().min(u32::MAX as usize) as u32 >= limit {
            self.banned_until = Some(now + ban_duration);
            warn!(
                ban_secs = ban_duration.as_secs(),
                "FloodGuard: IP rate limit exceeded"
            );
            return false;
        }
        self.attempts.push(now);
        true
    }
}

struct DiscoRecord {
    cycles: Vec<Instant>,
}

impl DiscoRecord {
    fn new() -> Self { DiscoRecord { cycles: Vec::new() } }

    fn on_disconnect(&mut self) -> bool {
        let now = Instant::now();
        self.cycles.retain(|t| now.duration_since(*t) < DISCO_SPAM_WINDOW);
        self.cycles.push(now);
        self.cycles.len().min(u32::MAX as usize) as u32 >= DISCO_SPAM_LIMIT
    }
}

#[derive(Default)]
struct PeerCounters {
    pending_headers: usize,
    inflight_blocks: usize,
}

/// Default ban duration applied when a peer trips the rate limiter.
/// Previously hardcoded inline as `Duration::from_secs(300)`; now exposed
/// so tests and callers can override via `FloodGuard::with_ban_base`.
pub const DEFAULT_BAN_BASE: Duration = Duration::from_secs(300);

/// All flood and Sybil protections in one struct.
pub struct FloodGuard {
    ip_records:    HashMap<IpAddr, IpRecord>,
    disco_records: HashMap<IpAddr, DiscoRecord>,
    peer_counters: HashMap<PeerId, PeerCounters>,
    ip_rate_limit:        u32,
    ip_rate_window:       Duration,
    max_per_subnet:       usize,
    max_headers_per_peer: usize,
    max_blocks_per_peer:  usize,
    /// FIX #22: ban duration applied to rate-limited IPs, sourced from
    /// `IronConfig.ban_base` instead of hardcoded inline.
    ban_base:             Duration,
}

impl FloodGuard {
    pub fn new() -> Self {
        FloodGuard {
            ip_records:           HashMap::new(),
            disco_records:        HashMap::new(),
            peer_counters:        HashMap::new(),
            ip_rate_limit:        IP_RATE_LIMIT,
            ip_rate_window:       IP_RATE_WINDOW,
            max_per_subnet:       MAX_PEERS_PER_SUBNET,
            max_headers_per_peer: MAX_HEADERS_PER_PEER,
            max_blocks_per_peer:  MAX_BLOCKS_PER_PEER,
            ban_base:             DEFAULT_BAN_BASE,
        }
    }

    /// FIX #22: configure the ban duration used by the rate limiter.
    /// Typically called from engine startup with `IronConfig.ban_base`.
    pub fn with_ban_base(mut self, ban_base: Duration) -> Self {
        self.ban_base = ban_base;
        self
    }

    pub fn with_limits(
        mut self,
        ip_rate_limit:        u32,
        max_per_subnet:       usize,
        max_headers_per_peer: usize,
        max_blocks_per_peer:  usize,
    ) -> Self {
        self.ip_rate_limit        = ip_rate_limit;
        self.max_per_subnet       = max_per_subnet;
        self.max_headers_per_peer = max_headers_per_peer;
        self.max_blocks_per_peer  = max_blocks_per_peer;
        self
    }

    /// Returns true if the inbound connection attempt should be accepted.
    pub fn allow_connection(&mut self, addr: SocketAddr) -> bool {
        let ip = addr.ip();
        let ban_base = self.ban_base;
        let rec = self.ip_records.entry(ip).or_insert_with(IpRecord::new);
        if !rec.allow_attempt(self.ip_rate_limit, self.ip_rate_window, ban_base) {
            warn!(%addr, "FloodGuard: connection rejected — IP rate limit");
            return false;
        }
        true
    }

    /// Returns true if we should accept this peer given current subnet counts.
    pub fn allow_subnet(&self, addr: SocketAddr, connected: &[SocketAddr]) -> bool {
        let subnet = subnet24(addr.ip());
        let count = connected.iter()
            .filter(|a| subnet24(a.ip()) == subnet)
            .count();
        if count >= self.max_per_subnet {
            warn!(
                %addr, count,
                "FloodGuard: subnet limit reached ({}/{})",
                count, self.max_per_subnet
            );
            return false;
        }
        true
    }

    /// Record N headers queued from a peer. Returns false if flooding.
    pub fn record_headers(&mut self, peer: PeerId, count: usize) -> bool {
        let c = self.peer_counters.entry(peer).or_default();
        c.pending_headers += count;
        if c.pending_headers > self.max_headers_per_peer {
            warn!(
                pending = c.pending_headers,
                limit = self.max_headers_per_peer,
                "FloodGuard: header flood from peer"
            );
            return false;
        }
        true
    }

    pub fn consume_headers(&mut self, peer: &PeerId, count: usize) {
        if let Some(c) = self.peer_counters.get_mut(peer) {
            c.pending_headers = c.pending_headers.saturating_sub(count);
        }
    }

    /// Record a new block request. Returns false if at limit.
    pub fn record_block_request(&mut self, peer: PeerId) -> bool {
        let c = self.peer_counters.entry(peer).or_default();
        if c.inflight_blocks >= self.max_blocks_per_peer {
            debug!(
                inflight = c.inflight_blocks,
                "FloodGuard: block request limit for peer"
            );
            return false;
        }
        c.inflight_blocks += 1;
        true
    }

    pub fn complete_block_request(&mut self, peer: &PeerId) {
        if let Some(c) = self.peer_counters.get_mut(peer) {
            c.inflight_blocks = c.inflight_blocks.saturating_sub(1);
        }
    }

    /// Record a disconnect event. Returns true if this peer should be banned.
    pub fn record_disconnect(&mut self, addr: SocketAddr) -> bool {
        let rec = self.disco_records.entry(addr.ip()).or_insert_with(DiscoRecord::new);
        let is_spamming = rec.on_disconnect();
        if is_spamming {
            warn!(%addr, "FloodGuard: disconnect spam detected — ban recommended");
        }
        is_spamming
    }

    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.peer_counters.remove(peer);
    }

    /// Evict stale IP records (call periodically).
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        self.ip_records.retain(|_, r| {
            !r.attempts.iter().all(|t| now.duration_since(*t) >= self.ip_rate_window)
                || r.is_banned()
        });
        self.disco_records.retain(|_, r| {
            r.cycles.iter().any(|t| now.duration_since(*t) < DISCO_SPAM_WINDOW)
        });
    }
}

impl Default for FloodGuard { fn default() -> Self { Self::new() } }

fn subnet24(ip: IpAddr) -> [u8; 3] {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [o[0], o[1], o[2]]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [o[0], o[1], o[2]]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr { s.parse().unwrap() }

    #[test]
    fn ip_rate_limit_blocks_after_limit() {
        let mut g = FloodGuard::new();
        let a = addr("1.2.3.4:1000");
        for _ in 0..IP_RATE_LIMIT {
            assert!(g.allow_connection(a));
        }
        assert!(!g.allow_connection(a));
    }

    #[test]
    fn subnet_limit_blocks_too_many() {
        let g = FloodGuard::new();
        let connected = vec![
            addr("1.2.3.10:1000"),
            addr("1.2.3.20:1000"),
            addr("1.2.3.30:1000"),
        ];
        assert!(!g.allow_subnet(addr("1.2.3.40:1000"), &connected));
    }

    #[test]
    fn different_subnet_allowed() {
        let g = FloodGuard::new();
        let connected = vec![
            addr("1.2.3.10:1000"),
            addr("1.2.3.20:1000"),
            addr("1.2.3.30:1000"),
        ];
        assert!(g.allow_subnet(addr("1.2.4.10:1000"), &connected));
    }

    #[test]
    fn header_flood_blocks_excess() {
        let mut g = FloodGuard::new();
        let peer = [1u8; 32];
        assert!(!g.record_headers(peer, MAX_HEADERS_PER_PEER + 1));
    }

    #[test]
    fn block_request_limit_enforced() {
        let mut g = FloodGuard::new();
        let peer = [2u8; 32];
        for _ in 0..MAX_BLOCKS_PER_PEER {
            assert!(g.record_block_request(peer));
        }
        assert!(!g.record_block_request(peer));
    }

    #[test]
    fn disconnect_spam_detected() {
        let mut g = FloodGuard::new();
        let a = addr("5.5.5.5:9999");
        for i in 0..DISCO_SPAM_LIMIT {
            let is_spam = g.record_disconnect(a);
            if i < DISCO_SPAM_LIMIT - 1 {
                assert!(!is_spam);
            } else {
                assert!(is_spam);
            }
        }
    }
}
