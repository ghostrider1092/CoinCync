//! # P2P Network Hardening (Layer 4)
//!
//! Defense mechanisms layered on top of the framed/Noise transport:
//! - **Eclipse-attack churn detector** (this module)
//! - **Validate-before-relay enforcement** — caller-side, see [`crate::network::node`]
//! - **Bandwidth caps** — per-peer 10 MB/s + 100 MB / 60 s, see [`crate::network::peer`]
//! - **Misbehavior scoring** — banscore-driven disconnects, see [`crate::network::scoring`]
//!
//! ## Why no per-message rate limiter here
//!
//! An earlier revision wired a `PeerRateLimiter` (sliding 1 s window with
//! Allow / Warn / Throttle / Ban actions) into [`crate::network::framing`].
//! It was removed because under Initial Block Download a peer legitimately
//! bursts hundreds of solicited blocks per second, and the limiter was
//! dropping that traffic and stalling sync. (Prior comment claimed
//! "Bitcoin Core and Monero use the same posture: no count-based
//! per-message limit on the P2P layer; rely on bandwidth caps +
//! protocol-violation banscore instead". That cross-project
//! generalization was not verified this session and is dropped.) The
//! design here relies on bandwidth caps + protocol-violation banscore
//! rather than per-message counting, on its own reasoning above. The
//! breadcrumb in
//! [`crate::network::framing`] (search for "PeerRateLimiter was removed")
//! preserves the rationale.
//!
//! Flood-class misbehavior is reported through
//! [`MisbehaviorType::MessageFlood`](crate::network::scoring::MisbehaviorType)
//! at the call sites that actually detect a flood (e.g. duplicate inv waves,
//! header spam). Those sites apply the banscore penalty directly via
//! [`PeerScorer::record_misbehavior`](crate::network::scoring::PeerScorer);
//! a peer that crosses the ban threshold is disconnected and added to the
//! local banlist.

use std::time::Instant;

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
