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
//! Scope: this first increment covers **unix seconds** (what consensus timestamps
//! and most time logic use). A virtual monotonic `Instant` (for timeouts) is a
//! later E1 increment.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
/// dropped — the RAII form for scoped test use.
#[must_use = "dropping the guard immediately restores the real clock"]
pub fn override_scope(secs: u64) -> ClockGuard {
    set_sim_unix(secs);
    ClockGuard { _priv: () }
}

/// Restores the real clock on drop. See [`override_scope`].
pub struct ClockGuard {
    _priv: (),
}

impl Drop for ClockGuard {
    fn drop(&mut self) {
        clear_sim();
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
