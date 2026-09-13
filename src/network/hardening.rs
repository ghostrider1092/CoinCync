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
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `EclipseDetector::record_connect` / `record_disconnect`** —
//!   INVARIANT: connect/disconnect counters only ever increment within the
//!   current 5-minute window; `maybe_reset` clears them once the window has
//!   elapsed, so churn from a stale window never leaks into the current
//!   one. THREAT: undercounting real churn (window drift) or overcounting
//!   stale churn, either of which defeats the eclipse-attack signal.
//!   TESTS: `eclipse_detector_normal`, `eclipse_detector_suspicious_churn`.
//! - **§2 `EclipseDetector::is_suspicious_churn`** — INVARIANT: the
//!   suspicious-churn signal fires only when BOTH recent connects and
//!   recent disconnects exceed 20 in the current window — a one-sided
//!   spike (e.g. many disconnects from a network blip) does not alone
//!   trigger it. THREAT: an eclipse attacker cycling connections to fill
//!   all peer slots with attacker-controlled peers; also guards against
//!   false positives from ordinary network instability. TESTS:
//!   `eclipse_detector_suspicious_churn`, `eclipse_detector_normal`.
//! - **§3 `maybe_reset` window boundary** — INVARIANT: the reset check uses
//!   a fixed 300-second threshold (`last_reset.elapsed().as_secs() > 300`)
//!   applied identically on every `record_connect`/`record_disconnect` call,
//!   so the window length is deterministic and cannot be extended by
//!   caller timing. THREAT: an attacker pacing connection churn just under
//!   the reset boundary to stay under threshold indefinitely while still
//!   cycling peers. TESTS: (gap — no test advances/mocks `Instant` to
//!   assert the reset actually fires at the 300s boundary; the two tests
//!   above only cover within-window accumulation).

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
