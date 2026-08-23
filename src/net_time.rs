//! Network-adjusted time (audit M-4).
//!
//! A bounded median of peer clock offsets, mirroring Bitcoin's `GetAdjustedTime`.
//! Block validation's future-timestamp check (`consensus::validation`) uses
//! `local_now + time_offset_secs()` instead of the raw local clock, so a single
//! node whose wall clock drifts by more than the drift tolerance cannot desync
//! its future-block acceptance from the rest of the network (self-isolation /
//! partition hazard).
//!
//! Safety properties:
//! - **Median, not mean** — robust to a minority of lying/skewed peers.
//! - **Warmup gate** — the offset stays 0 until at least [`MIN_SAMPLES`] peers
//!   have reported, so one early peer can't move our clock.
//! - **Hard cap** — the applied offset is clamped to ±[`MAX_TIME_OFFSET_SECS`],
//!   so even a colluding majority can only shift acceptance by a bounded amount
//!   (Bitcoin uses the same 70-minute cap).
//! - **Node-local** — this only affects when THIS node accepts a
//!   not-yet-in-chain block near the future boundary; it never changes the
//!   validity of already-mined blocks and is not part of consensus state.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

/// Maximum absolute offset ever applied, in seconds (Bitcoin: 70 minutes).
pub const MAX_TIME_OFFSET_SECS: i64 = 70 * 60;

/// Minimum peer samples before any nonzero offset is applied.
const MIN_SAMPLES: usize = 5;

/// Cap on retained samples (bounded memory; oldest dropped first).
const MAX_SAMPLES: usize = 200;

static OFFSET: AtomicI64 = AtomicI64::new(0);
static SAMPLES: Mutex<Vec<i64>> = Mutex::new(Vec::new());

/// Record a peer's clock offset (`peer_time - our_time`, seconds) and recompute
/// the median-derived, clamped network offset. Call once per accepted handshake.
pub fn record_peer_offset(offset_secs: i64) {
    let mut samples = match SAMPLES.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // a poisoned lock still holds valid samples
    };
    if samples.len() >= MAX_SAMPLES {
        samples.remove(0);
    }
    samples.push(offset_secs);

    if samples.len() < MIN_SAMPLES {
        OFFSET.store(0, Ordering::Relaxed);
        return;
    }
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    OFFSET.store(
        median.clamp(-MAX_TIME_OFFSET_SECS, MAX_TIME_OFFSET_SECS),
        Ordering::Relaxed,
    );
}

/// The current network time offset in seconds: a clamped median of peer offsets,
/// or `0` until [`MIN_SAMPLES`] peers have reported. Add it to the local unix
/// time to get network-adjusted time.
pub fn time_offset_secs() -> i64 {
    OFFSET.load(Ordering::Relaxed)
}

/// Test-only reset of the accumulated samples/offset.
#[cfg(test)]
pub fn reset_for_test() {
    if let Ok(mut s) = SAMPLES.lock() {
        s.clear();
    }
    OFFSET.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Single test fn — the module has global state, so all cases run
    // sequentially here rather than as separate (parallel) test fns.
    #[test]
    fn network_time_offset_behaviour() {
        // Stays 0 until MIN_SAMPLES peers have reported.
        reset_for_test();
        for _ in 0..(MIN_SAMPLES - 1) {
            record_peer_offset(1000);
        }
        assert_eq!(time_offset_secs(), 0, "must stay 0 until MIN_SAMPLES peers");

        // Becomes the median once warmed up.
        reset_for_test();
        for o in [10, 20, 30, 40, 50] {
            record_peer_offset(o);
        }
        assert_eq!(time_offset_secs(), 30, "median of 5 samples");

        // A single wild outlier can't move the median.
        reset_for_test();
        for o in [-2, -1, 0, 1, 86_400] {
            record_peer_offset(o);
        }
        assert_eq!(time_offset_secs(), 0, "median rejects a single wild outlier");

        // A colluding majority still can't exceed the hard cap.
        reset_for_test();
        for _ in 0..MIN_SAMPLES {
            record_peer_offset(10 * 86_400);
        }
        assert_eq!(time_offset_secs(), MAX_TIME_OFFSET_SECS, "clamped to the cap");

        reset_for_test();
    }
}
