//! Circuit breakers (correctness-program feature **F4**): a uniform
//! trip → fail-closed → observe primitive for the node's scattered protective
//! controls, so they share one shape (a threshold, a `CYNC-*` diagnostics code,
//! an open/closed state, a snapshot) instead of each reinventing an ad-hoc
//! counter + boolean.
//!
//! A breaker counts consecutive failures; at its threshold it **opens** and
//! stays open — `guard()` then returns `Err(code)` so the caller fails CLOSED
//! (rejects the action) rather than limping on degraded. A tripped breaker does
//! NOT auto-close on the next success: recovery is a deliberate [`reset`], so a
//! fault that keeps a breaker open keeps the node safe until an operator or a
//! recovery routine clears it. This matches the fail-closed discipline the rest
//! of the guard module already follows.
//!
//! SCOPE: this increment is the primitive + a registry snapshot for telemetry.
//! Converting the existing scattered controls onto it (solo-mine gate,
//! connections-per-IP, mempool admission caps, stratum invalid-streak, bootstrap
//! tried-cap / seed allowlist, treasury velocity) is the follow-up — each becomes
//! one `CircuitBreaker` with its own code, wired at its check site.
//!
//! [`reset`]: CircuitBreaker::reset

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A single protective control: closed = normal, open = tripped (fail-closed).
pub struct CircuitBreaker {
    name: &'static str,
    /// The `CYNC-*` diagnostics code this breaker emits when it trips / denies.
    code: &'static str,
    /// Consecutive failures that trip the breaker. `0` means it only ever opens
    /// via an explicit [`trip`](CircuitBreaker::trip).
    threshold: u64,
    failures: AtomicU64,
    open: AtomicBool,
}

impl CircuitBreaker {
    /// A closed breaker that trips after `threshold` consecutive failures (or
    /// only on an explicit `trip()` when `threshold == 0`). `const` so breakers
    /// can be `static` at their check sites.
    pub const fn new(name: &'static str, code: &'static str, threshold: u64) -> Self {
        Self {
            name,
            code,
            threshold,
            failures: AtomicU64::new(0),
            open: AtomicBool::new(false),
        }
    }

    /// A breaker pre-loaded with `failures` consecutive failures (opening it if
    /// that already meets a non-zero `threshold`) — for restoring a known state
    /// or constructing a near-threshold breaker in a test.
    pub fn preloaded(
        name: &'static str,
        code: &'static str,
        threshold: u64,
        failures: u64,
    ) -> Self {
        let b = Self::new(name, code, threshold);
        b.failures.store(failures, Ordering::Relaxed);
        if threshold != 0 && failures >= threshold {
            b.open.store(true, Ordering::Relaxed);
        }
        b
    }

    /// Record one failure. Opens the breaker when the consecutive-failure count
    /// reaches a non-zero `threshold`. Returns whether the breaker is now open.
    pub fn record_failure(&self) -> bool {
        let n = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if self.threshold != 0 && n >= self.threshold && !self.open.swap(true, Ordering::Relaxed) {
            // F5: record only the closed→open transition (not every later failure).
            crate::flight_recorder::record(
                self.code,
                format!("breaker '{}' opened after {} failures", self.name, n),
            );
        }
        self.is_open()
    }

    /// Record a success: clears the consecutive-failure streak. It does NOT
    /// close an already-open breaker — a tripped breaker stays open until an
    /// explicit [`reset`](CircuitBreaker::reset) (fail-closed recovery).
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }

    /// Open the breaker immediately, regardless of the failure count (e.g. a
    /// single catastrophic event).
    pub fn trip(&self) {
        if !self.open.swap(true, Ordering::Relaxed) {
            crate::flight_recorder::record(self.code, format!("breaker '{}' tripped", self.name));
        }
    }

    /// Close the breaker and clear its failure streak — deliberate recovery.
    pub fn reset(&self) {
        self.open.store(false, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
    }

    /// Whether the breaker is open (tripped).
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Relaxed)
    }

    /// The gate check at a protected call site: `Err(code)` when open (caller
    /// MUST fail closed — reject the action), `Ok(())` when closed.
    pub fn guard(&self) -> Result<(), &'static str> {
        if self.is_open() {
            Err(self.code)
        } else {
            Ok(())
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// A point-in-time view for telemetry / the `/colony` status surface.
    pub fn snapshot(&self) -> BreakerSnapshot {
        BreakerSnapshot {
            name: self.name,
            code: self.code,
            open: self.is_open(),
            failures: self.failures(),
            threshold: self.threshold,
        }
    }
}

/// An immutable view of a breaker's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakerSnapshot {
    pub name: &'static str,
    pub code: &'static str,
    pub open: bool,
    pub failures: u64,
    pub threshold: u64,
}

/// Snapshot a set of registered breakers (e.g. the node's full control set) for
/// one status report. Takes the breakers by reference so callers keep ownership
/// of their `static`s.
pub fn snapshot_all(breakers: &[&CircuitBreaker]) -> Vec<BreakerSnapshot> {
    breakers.iter().map(|b| b.snapshot()).collect()
}

/// Whether any breaker in the set is open — a cheap "is the node degraded?" check.
pub fn any_open(breakers: &[&CircuitBreaker]) -> bool {
    breakers.iter().any(|b| b.is_open())
}

/// The node's canonical protective controls, as process-global breakers.
///
/// Each wraps a control that already exists ad-hoc elsewhere; wiring a control
/// onto its breaker means calling `record_failure()` on its reject path and
/// `guard()?` (fail closed) at its admission point. Thresholds here are the
/// DEFAULTS — the wiring step aligns each to the control's existing constant
/// (noted per breaker) so there is one number, not two. Codes are the breaker's
/// own `CYNC-GUARD-*` labels until promoted into the diagnostics CATALOG (F5).
pub mod node {
    use super::CircuitBreaker;

    /// Solo-mining gate: mining with too few peers (eclipse risk). Trips to
    /// refuse solo mining. Aligns to `mining::solo_mine_gate` peer-floor logic.
    pub static SOLO_MINE: CircuitBreaker =
        CircuitBreaker::new("solo_mine_gate", "CYNC-GUARD-SOLOMINE", 0); // event-driven trip

    /// Per-IP connection cap. Aligns to `connection_tracker::MAX_CONNECTIONS_PER_IP`.
    pub static CONN_PER_IP: CircuitBreaker =
        CircuitBreaker::new("connections_per_ip", "CYNC-GUARD-CONNIP", 0);

    /// Mempool admission guard. Aligns to the mempool `MAX_*` admission caps.
    pub static MEMPOOL_ADMIT: CircuitBreaker =
        CircuitBreaker::new("mempool_admission", "CYNC-GUARD-MEMADMIT", 0);

    /// Stratum invalid-share streak. Aligns to `stratum::MAX_INVALID_STREAK`.
    pub static STRATUM_STREAK: CircuitBreaker =
        CircuitBreaker::new("stratum_invalid_streak", "CYNC-GUARD-STRATUM", 20);

    /// Bootstrap tried-address cap. Aligns to `bootstrap::MAX_TRIED`.
    pub static BOOTSTRAP_TRIED: CircuitBreaker =
        CircuitBreaker::new("bootstrap_tried", "CYNC-GUARD-BOOTSTRAP", 0);

    /// Treasury spend-velocity guard. Aligns to the treasury velocity limit.
    pub static TREASURY_VELOCITY: CircuitBreaker =
        CircuitBreaker::new("treasury_velocity", "CYNC-GUARD-TREASURY", 0);

    /// All node breakers, for a single status snapshot (`/colony` surface).
    pub fn all() -> [&'static CircuitBreaker; 6] {
        [
            &SOLO_MINE,
            &CONN_PER_IP,
            &MEMPOOL_ADMIT,
            &STRATUM_STREAK,
            &BOOTSTRAP_TRIED,
            &TREASURY_VELOCITY,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_at_threshold_and_fails_closed() {
        let b = CircuitBreaker::new("test", "CYNC-TEST-001", 3);
        assert!(b.guard().is_ok());
        assert!(!b.record_failure()); // 1
        assert!(!b.record_failure()); // 2
        assert!(b.record_failure()); // 3 → open
        assert!(b.is_open());
        assert_eq!(b.guard(), Err("CYNC-TEST-001"));
    }

    #[test]
    fn success_clears_streak_but_not_an_open_breaker() {
        let b = CircuitBreaker::new("t", "CYNC-TEST-002", 2);
        b.record_failure(); // 1
        b.record_success(); // streak back to 0
        assert!(!b.record_failure()); // 1 again, not tripped
        assert!(!b.is_open());
        // Now trip it, then a success must NOT re-close it.
        b.record_failure(); // 2 → open
        assert!(b.is_open());
        b.record_success();
        assert!(b.is_open(), "a tripped breaker only closes on explicit reset");
    }

    #[test]
    fn explicit_trip_and_reset() {
        let b = CircuitBreaker::new("t", "CYNC-TEST-003", 0); // only trips manually
        assert!(!b.is_open());
        b.record_failure(); // threshold 0 → never auto-trips
        assert!(!b.is_open());
        b.trip();
        assert!(b.is_open());
        b.reset();
        assert!(!b.is_open());
        assert_eq!(b.failures(), 0);
    }

    #[test]
    fn registry_snapshot_and_any_open() {
        static A: CircuitBreaker = CircuitBreaker::new("a", "CYNC-A", 1);
        static B: CircuitBreaker = CircuitBreaker::new("b", "CYNC-B", 1);
        let set = [&A, &B];
        assert!(!any_open(&set));
        A.trip();
        assert!(any_open(&set));
        let snaps = snapshot_all(&set);
        assert_eq!(snaps.len(), 2);
        assert!(snaps[0].open && snaps[0].name == "a");
        assert!(!snaps[1].open);
        A.reset(); // keep the process-global statics clean for other tests
    }

    #[test]
    fn node_registry_lists_all_six_with_distinct_codes() {
        let set = node::all();
        assert_eq!(set.len(), 6);
        // Start clean (other tests may have run); none open at rest.
        for b in set {
            b.reset();
        }
        assert!(!any_open(&set));
        // Codes are distinct (no copy-paste collision).
        let mut codes: Vec<&str> = set.iter().map(|b| b.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 6, "every node breaker needs a unique code");
    }

    #[test]
    fn opening_a_breaker_is_recorded_in_the_flight_recorder() {
        // F5 wiring: a breaker's closed→open transition records to the flight
        // recorder. Unique code so the assertion is robust to the process-global
        // recorder being shared with other tests.
        let b = CircuitBreaker::new("f5_tap_test", "CYNC-TEST-F5TAP", 1);
        b.record_failure(); // crosses threshold → opens → records
        let snap = crate::flight_recorder::snapshot();
        assert!(
            snap.iter().any(|e| e.code == "CYNC-TEST-F5TAP"),
            "a breaker opening should appear in the flight recorder"
        );
    }
}
