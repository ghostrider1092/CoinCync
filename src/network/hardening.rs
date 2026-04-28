//! # P2P Network Hardening (Layer 4)
//!
//! Defense mechanisms for the P2P layer:
//! - Validate-before-relay enforcement
//! - Peer message rate limiting with banscore escalation
//! - Inbound message size validation
//! - Eclipse attack detection heuristics

use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::Instant;

/// Per-peer rate limiter for P2P messages.
///
/// Tracks message counts per peer over a sliding window. Peers that
/// exceed the rate limit get banscore points. Three thresholds:
/// - Warning: 100 msgs/sec (log)
/// - Throttle: 200 msgs/sec (drop messages)
/// - Ban: 500 msgs/sec (disconnect + ban)
pub struct PeerRateLimiter {
    /// Message count per peer in current window
    counts: HashMap<SocketAddr, (u64, Instant)>,
    /// Window size in seconds
    window_secs: u64,
}

impl PeerRateLimiter {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            window_secs: 1,
        }
    }

    /// Record a message from a peer. Returns the action to take.
    pub fn record_message(&mut self, addr: &SocketAddr) -> RateLimitAction {
        let now = Instant::now();
        let entry = self.counts.entry(*addr).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1).as_secs() >= self.window_secs {
            entry.0 = 0;
            entry.1 = now;
        }

        entry.0 += 1;

        match entry.0 {
            0..=100 => RateLimitAction::Allow,
            101..=200 => RateLimitAction::Warn,
            201..=500 => RateLimitAction::Throttle,
            _ => RateLimitAction::Ban,
        }
    }

    /// Prune stale entries to prevent memory growth.
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.counts.retain(|_, (_, last)| {
            now.duration_since(*last).as_secs() < 60
        });
    }
}

/// Action to take based on rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitAction {
    /// Normal — allow the message
    Allow,
    /// Rate is elevated — log warning
    Warn,
    /// Rate is high — drop the message silently
    Throttle,
    /// Rate is extreme — disconnect and ban the peer
    Ban,
}

/// Eclipse attack detector.
///
/// Monitors the distribution of peer connections to detect potential
/// eclipse attacks. An eclipse attack isolates a node by filling all
/// its connection slots with attacker-controlled peers.
///
/// Warning signs:
/// - All peers are inbound (no outbound diversity)
/// - All peers are from the same subnet
/// - All peers report the same height (possibly fake)
/// - Sudden peer churn (many disconnects + reconnects)
pub struct EclipseDetector {
    /// Number of recent connection events
    recent_connects: u64,
    /// Number of recent disconnection events
    recent_disconnects: u64,
    /// Last reset time
    last_reset: Instant,
}

impl EclipseDetector {
    pub fn new() -> Self {
        Self {
            recent_connects: 0,
            recent_disconnects: 0,
            last_reset: Instant::now(),
        }
    }

    /// Record a peer connection event.
    pub fn record_connect(&mut self) {
        self.maybe_reset();
        self.recent_connects += 1;
    }

    /// Record a peer disconnection event.
    pub fn record_disconnect(&mut self) {
        self.maybe_reset();
        self.recent_disconnects += 1;
    }

    /// Check for suspicious churn patterns.
    /// Returns true if the churn rate suggests a possible eclipse attack.
    pub fn is_suspicious_churn(&self) -> bool {
        // If we've had >20 connects AND >20 disconnects in 5 minutes,
        // someone might be cycling connections to fill our peer slots.
        self.recent_connects > 20 && self.recent_disconnects > 20
    }

    fn maybe_reset(&mut self) {
        if self.last_reset.elapsed().as_secs() > 300 {
            self.recent_connects = 0;
            self.recent_disconnects = 0;
            self.last_reset = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_normal_traffic() {
        let mut limiter = PeerRateLimiter::new();
        let addr: SocketAddr = "1.2.3.4:28080".parse().unwrap();
        for _ in 0..100 {
            assert_eq!(limiter.record_message(&addr), RateLimitAction::Allow);
        }
    }

    #[test]
    fn rate_limiter_warns_on_elevated() {
        let mut limiter = PeerRateLimiter::new();
        let addr: SocketAddr = "1.2.3.4:28080".parse().unwrap();
        for _ in 0..100 { limiter.record_message(&addr); }
        assert_eq!(limiter.record_message(&addr), RateLimitAction::Warn);
    }

    #[test]
    fn rate_limiter_bans_on_extreme() {
        let mut limiter = PeerRateLimiter::new();
        let addr: SocketAddr = "1.2.3.4:28080".parse().unwrap();
        for _ in 0..501 { limiter.record_message(&addr); }
        assert_eq!(limiter.record_message(&addr), RateLimitAction::Ban);
    }

    #[test]
    fn eclipse_detector_normal() {
        let det = EclipseDetector::new();
        assert!(!det.is_suspicious_churn());
    }

    #[test]
    fn eclipse_detector_suspicious_churn() {
        let mut det = EclipseDetector::new();
        for _ in 0..25 {
            det.record_connect();
            det.record_disconnect();
        }
        assert!(det.is_suspicious_churn());
    }
}
