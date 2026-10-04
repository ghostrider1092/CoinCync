//! Flight recorder (correctness-program feature **F5**): a bounded in-memory
//! ring of the most recent diagnostic events, so when a fault trips (a failed
//! invariant, a fail-closed guard, a rejected block) the node can dump the
//! *lead-up* — the last N coded events with their timing — instead of only the
//! single error at the crash site. This is the post-mortem companion to the
//! diagnostics CATALOG (which defines the `CYNC-*` codes) and the executable
//! invariants (which emit them).
//!
//! SCOPE: this increment adds the recorder type + a process-global default and
//! the free-function API. Wiring the emit sites (invariants, validation, the
//! guard registry) to also `flight_recorder::record(code, detail)` is a
//! follow-up, so this lands isolated with zero behavior change on the live path.
//!
//! Cost: one `Mutex` lock + a `VecDeque` push per recorded event, bounded at
//! `cap`. It is in-memory only and never serialized, so it is wire- and
//! consensus-irrelevant. NOTE: timestamps come from the real system clock here;
//! once the clock seam (E1) is present on this branch, [`now_secs`] should
//! delegate to `crate::clock::unix_now` so a replayed simulation records
//! deterministic times.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// One recorded event. `seq` is a process-monotonic counter (survives ring
/// eviction, so a gap in `seq` across a snapshot means events were evicted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub seq: u64,
    pub unix_secs: u64,
    /// A `CYNC-*` diagnostics code, or an ad-hoc static tag.
    pub code: &'static str,
    pub detail: String,
}

/// A bounded ring of recent [`Event`]s. Thread-safe; cheap to `record` into.
pub struct FlightRecorder {
    buf: Mutex<VecDeque<Event>>,
    cap: usize,
    seq: AtomicU64,
}

impl FlightRecorder {
    /// A recorder holding at most `cap` events (clamped to `>= 1`).
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            buf: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            cap,
            seq: AtomicU64::new(0),
        }
    }

    /// Append an event, evicting the oldest if at capacity.
    pub fn record(&self, code: &'static str, detail: impl Into<String>) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let ev = Event {
            seq,
            unix_secs: now_secs(),
            code,
            detail: detail.into(),
        };
        let mut b = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        if b.len() == self.cap {
            b.pop_front();
        }
        b.push_back(ev);
    }

    /// The buffered events, oldest → newest. A clone, so the lock is held only
    /// briefly (safe to call on a fault path).
    pub fn snapshot(&self) -> Vec<Event> {
        self.buf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Number of events currently buffered (`<= cap`).
    pub fn len(&self) -> usize {
        self.buf.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total events ever recorded (monotonic; includes evicted ones).
    pub fn recorded_total(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// Drop all buffered events (does not reset the `seq` counter).
    pub fn clear(&self) {
        self.buf.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Default capacity of the process-global recorder.
pub const DEFAULT_CAPACITY: usize = 256;

/// The process-global recorder — the one most emit sites will use.
pub fn global() -> &'static FlightRecorder {
    static G: OnceLock<FlightRecorder> = OnceLock::new();
    G.get_or_init(|| FlightRecorder::new(DEFAULT_CAPACITY))
}

/// Record an event into the process-global recorder.
pub fn record(code: &'static str, detail: impl Into<String>) {
    global().record(code, detail);
}

/// Snapshot the process-global recorder (oldest → newest).
pub fn snapshot() -> Vec<Event> {
    global().snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_snapshots_oldest_to_newest() {
        let r = FlightRecorder::new(8);
        r.record("CYNC-CONS-001", "pow invalid");
        r.record("CYNC-CONS-002", "double spend");
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].code, "CYNC-CONS-001");
        assert_eq!(snap[1].code, "CYNC-CONS-002");
        assert!(snap[0].seq < snap[1].seq, "seq must be monotonic");
    }

    #[test]
    fn ring_evicts_oldest_past_capacity() {
        let r = FlightRecorder::new(3);
        for i in 0..10u32 {
            r.record("CYNC-TEST", format!("event {i}"));
        }
        let snap = r.snapshot();
        assert_eq!(snap.len(), 3, "must never exceed cap");
        // Only the last 3 survive; the recorder saw 10 total.
        assert_eq!(snap[0].detail, "event 7");
        assert_eq!(snap[2].detail, "event 9");
        assert_eq!(r.recorded_total(), 10);
        // Evicted events leave a seq gap: first surviving seq is 7, not 0.
        assert_eq!(snap[0].seq, 7);
    }

    #[test]
    fn cap_is_clamped_to_at_least_one() {
        let r = FlightRecorder::new(0);
        r.record("CYNC-TEST", "x");
        r.record("CYNC-TEST", "y");
        assert_eq!(r.len(), 1);
        assert_eq!(r.snapshot()[0].detail, "y");
    }

    #[test]
    fn clear_empties_buffer_but_keeps_seq() {
        let r = FlightRecorder::new(4);
        r.record("CYNC-TEST", "a");
        r.record("CYNC-TEST", "b");
        r.clear();
        assert!(r.is_empty());
        assert_eq!(r.recorded_total(), 2, "clear must not reset seq");
        r.record("CYNC-TEST", "c");
        assert_eq!(r.snapshot()[0].seq, 2, "seq continues after clear");
    }

    #[test]
    fn global_is_shared_and_usable() {
        let before = global().recorded_total();
        record("CYNC-TEST", "via free fn");
        assert!(global().recorded_total() > before);
        assert!(snapshot().iter().any(|e| e.detail == "via free fn"));
    }
}
