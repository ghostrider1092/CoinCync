//! Canonical wall-clock source — the single place the node reads unix time.
//!
//! Production reads the real system clock. A test or the deterministic-simulation
//! harness installs an **override**, and from then on every `clock::unix_now()`
//! across the whole process returns virtual time — the enabler for running the
//! real node under a deterministic schedule (correctness-program enabler **E1**;
//! see docs/design/correctness-program.md).
//!
//! It is also a single-source-of-truth consolidation: the codebase previously had
//! ~8 independent `unix_now()` / `now_secs()` helpers, each wrapping
//! `SystemTime::now()` separately (the #173 bug class applied to time). Those
//! delegate here, so there is one clock to override and one to reason about.
//!
//! Scope: wall-clock **unix seconds** (what consensus timestamps and most time
//! logic use) via [`unix_now`], AND a virtual monotonic clock ([`mono_now`] /
//! [`MonoInstant`]) for **timeouts and backoffs** — the two time axes a node
//! depends on. Both honor the same override, so the deterministic-simulation
//! harness can drive wall time and elapsed-time forward together and reproduce
//! timeout-driven behavior (partition stalls, retry backoff, eviction) exactly.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `-1` = no override, use the real clock. Any value `>= 0` is virtual unix
/// seconds that every reader returns. `Relaxed` is sufficient: readers only need
/// the latest published value, not ordering against other memory.
static SIM_UNIX_SECS: AtomicI64 = AtomicI64::new(-1);

/// Unix time in seconds — the canonical wall-clock read for the whole node.
/// Returns virtual time while an override is installed, else the real clock.
pub fn unix_now() -> u64 {
    let v = SIM_UNIX_SECS.load(Ordering::Relaxed);
    if v >= 0 {
        return v as u64;
    }
    real_unix_now()
}

/// The real system clock, bypassing any override. Reserve for the rare site that
/// genuinely needs wall time even under simulation (e.g. a log timestamp); normal
/// code calls [`unix_now`].
pub fn real_unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Monotonic-nondecreasing unix seconds: `max(unix_now(), last_returned)`.
///
/// Use this where a backwards clock step (NTP correction) must not make a fresh
/// record look ancient — e.g. mempool entry ages / TTL. Never steps backwards
/// within a process. Costs one relaxed atomic per call. Honors a virtual-clock
/// override (tracks it) but still never decreases.
pub fn unix_now_monotonic() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = unix_now();
    let last = LAST.load(Ordering::Relaxed);
    let out = now.max(last);
    if out > last {
        LAST.store(out, Ordering::Relaxed);
    }
    out
}

/// Whether a virtual-clock override is currently installed.
pub fn is_overridden() -> bool {
    SIM_UNIX_SECS.load(Ordering::Relaxed) >= 0
}

// ─── Monotonic clock (for timeouts / backoff) ────────────────────────────────
//
// `unix_now` is wall time (can jump on NTP correction) — wrong for measuring a
// *duration* like "has this peer been silent for 30s?". That needs a monotonic
// source: `std::time::Instant`. But `Instant` can't be constructed from a value,
// so it can't be driven by the simulation harness. `MonoInstant` is the
// overridable equivalent: real mode reads `Instant`, simulation reads a virtual
// elapsed-nanos atomic the harness advances.

/// `-1` = real monotonic clock. `>= 0` is virtual elapsed **nanoseconds** since
/// the (virtual) process epoch that every [`mono_now`] returns.
static SIM_MONO_NANOS: AtomicI64 = AtomicI64::new(-1);

/// Lazily-captured real process-start instant. `mono_now` reports elapsed since
/// here in real mode, so a `MonoInstant` is a small `Duration`, not a raw clock
/// value — comparable and override-able.
fn process_start() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

/// A monotonic-nondecreasing point in time, for measuring elapsed durations
/// (timeouts, backoff, rate windows). Wire-irrelevant — never serialized — so it
/// is purely an in-memory clock abstraction. Compare two with
/// [`MonoInstant::saturating_duration_since`] or read age with
/// [`MonoInstant::elapsed`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct MonoInstant(Duration);

impl MonoInstant {
    /// Elapsed since an *earlier* instant, saturating to zero (never panics on a
    /// backwards pair, unlike `Instant::duration_since`).
    #[inline]
    pub fn saturating_duration_since(self, earlier: MonoInstant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// Time elapsed from `self` to now (saturating). The drop-in for
    /// `Instant::elapsed()`.
    #[inline]
    pub fn elapsed(self) -> Duration {
        mono_now().saturating_duration_since(self)
    }

    /// `self` minus a duration, or `None` if it would go before the epoch.
    /// Mirrors `std::time::Instant::checked_sub`.
    #[inline]
    pub fn checked_sub(self, d: Duration) -> Option<MonoInstant> {
        self.0.checked_sub(d).map(MonoInstant)
    }
}

impl std::ops::Add<Duration> for MonoInstant {
    type Output = MonoInstant;
    #[inline]
    fn add(self, d: Duration) -> MonoInstant {
        MonoInstant(self.0.saturating_add(d))
    }
}
impl std::ops::Sub<Duration> for MonoInstant {
    type Output = MonoInstant;
    #[inline]
    fn sub(self, d: Duration) -> MonoInstant {
        MonoInstant(self.0.saturating_sub(d))
    }
}

/// Current monotonic instant — the drop-in for `Instant::now()` on any timeout or
/// backoff path. Returns virtual elapsed time while a monotonic override is
/// installed, else the real monotonic clock. Never steps backwards.
pub fn mono_now() -> MonoInstant {
    let v = SIM_MONO_NANOS.load(Ordering::Relaxed);
    if v >= 0 {
        return MonoInstant(Duration::from_nanos(v as u64));
    }
    MonoInstant(process_start().elapsed())
}

/// Whether a virtual monotonic override is installed.
pub fn is_mono_overridden() -> bool {
    SIM_MONO_NANOS.load(Ordering::Relaxed) >= 0
}

/// Pin the virtual monotonic clock to `elapsed` since the virtual epoch. For the
/// simulation harness and tests only.
pub fn set_sim_mono(elapsed: Duration) {
    let nanos = elapsed.as_nanos().min(i64::MAX as u128) as i64;
    SIM_MONO_NANOS.store(nanos, Ordering::Relaxed);
}

/// Advance the virtual monotonic clock by `by` and return the new instant. If no
/// override is installed yet, it starts from zero (installing one). This is the
/// harness's "tick elapsed-time forward" primitive — the thing that fires a
/// pending timeout deterministically.
pub fn advance_sim_mono(by: Duration) -> MonoInstant {
    let add = by.as_nanos().min(i64::MAX as u128) as i64;
    loop {
        let cur = SIM_MONO_NANOS.load(Ordering::Relaxed);
        let base = cur.max(0); // real mode (-1) advances from 0
        let next = base.saturating_add(add);
        if SIM_MONO_NANOS
            .compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return MonoInstant(Duration::from_nanos(next as u64));
        }
    }
}

/// Clear the monotonic override, restoring the real monotonic clock.
pub fn clear_sim_mono() {
    SIM_MONO_NANOS.store(-1, Ordering::Relaxed);
}

/// Install (or update) a virtual clock: every [`unix_now`] returns `secs` until
/// cleared. For tests and the simulation harness only — production never calls
/// this, so production always reads the real clock.
pub fn set_sim_unix(secs: u64) {
    SIM_UNIX_SECS.store(secs as i64, Ordering::Relaxed);
}

/// Clear the override, restoring the real clock.
pub fn clear_sim() {
    SIM_UNIX_SECS.store(-1, Ordering::Relaxed);
}

/// Install a virtual clock and return a guard that restores the real clock when
/// dropped — the RAII form for scoped test use. Pins wall time to `secs` AND
/// resets the virtual monotonic clock to zero, so both time axes are
/// deterministic within the scope; advance either with [`set_sim_unix`] /
/// [`advance_sim_mono`].
#[must_use = "dropping the guard immediately restores the real clock"]
pub fn override_scope(secs: u64) -> ClockGuard {
    set_sim_unix(secs);
    set_sim_mono(Duration::ZERO);
    ClockGuard { _priv: () }
}

/// Restores the real clock (both axes) on drop. See [`override_scope`].
pub struct ClockGuard {
    _priv: (),
}

impl Drop for ClockGuard {
    fn drop(&mut self) {
        clear_sim();
        clear_sim_mono();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate the process-global override, so they serialize on a
    // guard and always restore the real clock afterwards.
    static TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn real_clock_is_plausible_and_default() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_sim();
        assert!(!is_overridden());
        // Real unix time is well past 2020-01-01 and before 2100.
        let now = unix_now();
        assert!(now > 1_577_836_800, "unix_now looks too small: {now}");
        assert!(now < 4_102_444_800, "unix_now looks too large: {now}");
    }

    #[test]
    fn override_is_read_by_unix_now_and_guard_restores() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_sim();
        {
            let _clock = override_scope(1_234_567);
            assert!(is_overridden());
            assert_eq!(unix_now(), 1_234_567);
            set_sim_unix(1_234_600);
            assert_eq!(unix_now(), 1_234_600);
        }
        // Guard dropped → real clock restored.
        assert!(!is_overridden());
        assert!(unix_now() > 1_577_836_800);
    }

    #[test]
    fn real_unix_now_bypasses_the_override() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let _clock = override_scope(42);
        assert_eq!(unix_now(), 42);
        // real_unix_now ignores the override.
        assert!(real_unix_now() > 1_577_836_800);
    }

    #[test]
    fn mono_real_mode_advances_and_measures_elapsed() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_sim_mono();
        assert!(!is_mono_overridden());
        let t0 = mono_now();
        // Real monotonic clock: a tiny bit of work elapses a non-negative amount
        // and never goes backwards.
        let t1 = mono_now();
        assert!(t1 >= t0, "real monotonic clock stepped backwards");
        assert_eq!(t0.saturating_duration_since(t1), Duration::ZERO);
    }

    #[test]
    fn mono_override_is_deterministic_and_fires_timeouts() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let _clock = override_scope(1_000_000); // also resets mono to 0
        assert!(is_mono_overridden());
        let start = mono_now();
        assert_eq!(start, MonoInstant(Duration::ZERO));

        // A 30s timeout has NOT fired yet.
        assert!(start.elapsed() < Duration::from_secs(30));

        // Advance virtual elapsed-time past the timeout — deterministically fires.
        let now = advance_sim_mono(Duration::from_secs(31));
        assert_eq!(now.saturating_duration_since(start), Duration::from_secs(31));
        assert!(start.elapsed() >= Duration::from_secs(30), "timeout must now fire");

        // Arithmetic: a deadline is start + timeout.
        let deadline = start + Duration::from_secs(30);
        assert!(mono_now() > deadline);
    }

    #[test]
    fn mono_guard_restores_real_clock() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        {
            let _clock = override_scope(42);
            assert!(is_mono_overridden());
            advance_sim_mono(Duration::from_secs(5));
        }
        // Guard dropped → real monotonic clock restored.
        assert!(!is_mono_overridden());
    }

    #[test]
    fn monotonic_never_decreases() {
        // The monotonic LAST is process-global, so assert the INVARIANT, not
        // exact values (other calls in the process advance it).
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_sim();
        let base = unix_now_monotonic();
        let future = base + 10_000;
        let _clock = override_scope(future);
        assert!(unix_now_monotonic() >= future);
        // Stepping the override backwards must never decrease the output.
        set_sim_unix(base.saturating_sub(5_000));
        assert!(
            unix_now_monotonic() >= future,
            "monotonic must not step backwards"
        );
    }
}
