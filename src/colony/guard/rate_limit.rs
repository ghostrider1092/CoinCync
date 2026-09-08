//! Per-action token-bucket rate limiter for colony Acts.
//!
//! Each [`ColonyActionKind`] has its own bucket, so a caste can never spam an
//! action even after the kill switch is armed. Budgets mirror the posture of
//! the tick sidecar's `RescueConfig` (deliberately stingy: reconnections and
//! tarpits are rare, housekeeping is frequent). Deterministic, monotonic-clock
//! based; no external state.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::ColonyActionKind;

/// A classic token bucket: `tokens` refill at `refill_per_sec` up to
/// `capacity`; one Act costs one token.
#[derive(Debug, Clone)]
struct Bucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl Bucket {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity, // start full — the first action is always allowed
            refill_per_sec,
            last: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// One bucket per action kind.
#[derive(Debug, Clone)]
pub struct ActionRateLimiter {
    buckets: HashMap<ColonyActionKind, Bucket>,
}

impl ActionRateLimiter {
    /// Per-action budgets. Rare/expensive actions get tiny budgets; cheap
    /// local ones get generous ones. `capacity` = burst; `refill_per_sec` sets
    /// the steady rate.
    pub fn with_default_budgets() -> Self {
        use ColonyActionKind::*;
        let hz = |per_min: f64| per_min / 60.0;
        let mut buckets = HashMap::new();
        // Rare, high-impact — must not flap the topology.
        buckets.insert(BridgeReconnect, Bucket::new(2.0, hz(2.0) / 60.0)); // ~2/hour
        buckets.insert(Tarpit, Bucket::new(8.0, hz(4.0))); // burst 8, ~4/min
        buckets.insert(PreferPeers, Bucket::new(2.0, hz(1.0))); // ~1/min
        buckets.insert(RelayLegs, Bucket::new(4.0, hz(30.0))); // per-block-ish
        buckets.insert(SwarmMode, Bucket::new(2.0, hz(2.0))); // hysteresis-bounded already
        buckets.insert(CoverPulse, Bucket::new(6.0, hz(12.0)));
        // Frequent, cheap, local.
        buckets.insert(Housekeep, Bucket::new(20.0, hz(60.0)));
        buckets.insert(WireProfile, Bucket::new(20.0, hz(120.0)));
        Self { buckets }
    }

    /// Test helper: a single bucket for `kind` with capacity 1 and effectively
    /// no refill, so the first action passes and the second is denied.
    #[cfg(test)]
    pub fn for_test_single_shot(kind: ColonyActionKind) -> Self {
        let mut buckets = HashMap::new();
        buckets.insert(kind, Bucket::new(1.0, 0.000_001));
        Self { buckets }
    }

    /// Attempt to spend one token for `kind`. An unknown kind (no configured
    /// bucket) is denied — fail-closed.
    pub fn try_consume(&mut self, kind: ColonyActionKind) -> bool {
        match self.buckets.get_mut(&kind) {
            Some(b) => b.try_consume(),
            None => false,
        }
    }
}

impl Default for ActionRateLimiter {
    fn default() -> Self {
        Self::with_default_budgets()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_action_allowed_second_denied_single_shot() {
        let mut r = ActionRateLimiter::for_test_single_shot(ColonyActionKind::Tarpit);
        assert!(r.try_consume(ColonyActionKind::Tarpit));
        assert!(!r.try_consume(ColonyActionKind::Tarpit));
    }

    #[test]
    fn unknown_kind_is_fail_closed() {
        // A limiter that only knows Tarpit denies a PreferPeers request.
        let mut r = ActionRateLimiter::for_test_single_shot(ColonyActionKind::Tarpit);
        assert!(!r.try_consume(ColonyActionKind::PreferPeers));
    }

    #[test]
    fn default_budgets_allow_initial_burst() {
        let mut r = ActionRateLimiter::with_default_budgets();
        // BridgeReconnect capacity is 2 — two allowed, third denied.
        assert!(r.try_consume(ColonyActionKind::BridgeReconnect));
        assert!(r.try_consume(ColonyActionKind::BridgeReconnect));
        assert!(!r.try_consume(ColonyActionKind::BridgeReconnect));
    }

    #[test]
    fn buckets_refill_over_time() {
        let mut b = Bucket::new(1.0, 1000.0); // refills fast
        assert!(b.try_consume());
        assert!(!b.try_consume());
        std::thread::sleep(Duration::from_millis(5));
        assert!(b.try_consume(), "bucket should refill after elapsed time");
    }
}
