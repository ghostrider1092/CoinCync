//! Network-adjusted time (audit M-4).
//!
//! A bounded median of peer clock offsets, mirroring Bitcoin's `GetAdjustedTime`.
//! Block validation's future-timestamp check (`consensus::validation`) uses
//! `local_now + time_offset_secs()` instead of the raw local clock, so a single
//! node whose wall clock drifts by more than the drift tolerance cannot desync
//! its future-block acceptance from the rest of the network (self-isolation /
//! partition hazard).
//!
//! Safety properties (hardened per jun's M-4 review):
//! - **Median, not mean** — robust to a minority of lying/skewed peers.
//! - **One sample per peer** — offsets are keyed by peer IP, so repeated Version
//!   messages (or many connections) from a single peer collapse to one sample.
//!   A single peer therefore cannot satisfy the warmup or dominate the median.
//! - **Outbound-only** — only peers WE dialed are sampled (see the caller in
//!   `dispatch::control`); an attacker cannot make us dial them, so inbound
//!   floods cannot poison the median.
//! - **Warmup gate** — the offset stays 0 until at least [`MIN_PEERS`] DISTINCT
//!   peers have reported.
//! - **Implausible medians rejected** — a median beyond ±[`MAX_TIME_OFFSET_SECS`]
//!   is treated as garbage/attack and applies NO adjustment (rather than being
//!   clamped to the maximum, which would let a bad majority buy the full cap).
//! - **Node-local** — this only affects when THIS node accepts a
//!   not-yet-in-chain block near the future boundary; it never changes the
//!   validity of already-mined blocks and is not part of consensus state.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

/// Maximum absolute offset ever applied, in seconds (Bitcoin: 70 minutes).
pub const MAX_TIME_OFFSET_SECS: i64 = 70 * 60;

/// Minimum number of DISTINCT peers before any nonzero offset is applied.
/// Distinct — not raw samples — so one peer flooding Version messages cannot
/// reach the warmup on its own.
const MIN_PEERS: usize = 5;

/// Cap on retained distinct-peer samples (bounded memory; an arbitrary old
/// entry is dropped when a NEW peer arrives at capacity).
const MAX_PEERS: usize = 200;

static OFFSET: AtomicI64 = AtomicI64::new(0);

/// One offset per peer IP. Inserting the same IP overwrites in place, which is
/// what guarantees at most one sample per peer no matter how many Version
/// messages or reconnections it sends.
static SAMPLES: Mutex<BTreeMap<IpAddr, i64>> = Mutex::new(BTreeMap::new());

/// Record an **outbound** peer's clock offset (`peer_time - our_time`, seconds),
/// keyed by its IP, and recompute the median-derived network offset.
///
/// The caller must only pass OUTBOUND peers, and must call this only AFTER the
/// self-connection check and `version.validate()` have passed — so a Version
/// message that is later rejected can never move the global network-time state.
pub fn record_peer_offset(peer_ip: IpAddr, offset_secs: i64) {
    let mut samples = match SAMPLES.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // a poisoned lock still holds valid samples
    };

    // Bound memory: only evict when a genuinely NEW peer arrives at capacity.
    // Re-recording a peer we already know just overwrites its entry.
    if samples.len() >= MAX_PEERS && !samples.contains_key(&peer_ip) {
        if let Some(oldest) = samples.keys().next().copied() {
            samples.remove(&oldest);
        }
    }
    samples.insert(peer_ip, offset_secs);

    if samples.len() < MIN_PEERS {
        OFFSET.store(0, Ordering::Relaxed);
        return;
    }
    let mut sorted: Vec<i64> = samples.values().copied().collect();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];

    // Reject an implausible median rather than clamping it to the cap. A real
    // network-wide skew is smaller than the cap; a median beyond it is garbage
    // or an attack, so apply NO adjustment instead of the strongest allowed one
    // (which -1 day and -1 year would otherwise both collapse to).
    let applied = if median.abs() > MAX_TIME_OFFSET_SECS {
        0
    } else {
        median
    };
    OFFSET.store(applied, Ordering::Relaxed);
}

/// The current network time offset in seconds: a clamped median of distinct-peer
/// offsets, or `0` until [`MIN_PEERS`] peers have reported. Add it to the local
/// unix time to get network-adjusted time.
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
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    // Single test fn — the module has global state, so all cases run
    // sequentially here rather than as separate (parallel) test fns.
    #[test]
    fn network_time_offset_behaviour() {
        // Stays 0 until MIN_PEERS DISTINCT peers have reported.
        reset_for_test();
        for i in 0..(MIN_PEERS as u8 - 1) {
            record_peer_offset(ip(i), 1000);
        }
        assert_eq!(time_offset_secs(), 0, "0 until MIN_PEERS distinct peers");

        // jun M-4: one peer flooding many Version messages cannot satisfy the
        // warmup — same IP collapses to a single sample.
        reset_for_test();
        for _ in 0..20 {
            record_peer_offset(ip(7), -86_400);
        }
        assert_eq!(
            time_offset_secs(),
            0,
            "a single peer's repeated samples collapse to one — warmup unmet"
        );

        // Becomes the median once warmed up across distinct peers.
        reset_for_test();
        for (i, o) in [10, 20, 30, 40, 50].into_iter().enumerate() {
            record_peer_offset(ip(i as u8), o);
        }
        assert_eq!(time_offset_secs(), 30, "median of 5 distinct peers");

        // A single wild outlier still can't move the median.
        reset_for_test();
        for (i, o) in [-2, -1, 0, 1, 86_400].into_iter().enumerate() {
            record_peer_offset(ip(i as u8), o);
        }
        assert_eq!(time_offset_secs(), 0, "median rejects a single wild outlier");

        // jun M-4: an implausible median is REJECTED (applies 0), not clamped to
        // the cap — a colluding majority can no longer buy the full 70 minutes.
        reset_for_test();
        for i in 0..(MIN_PEERS as u8) {
            record_peer_offset(ip(i), 10 * 86_400);
        }
        assert_eq!(
            time_offset_secs(),
            0,
            "implausible median applies no adjustment, not the max"
        );

        // A plausible, in-cap skew agreed by distinct peers is applied as-is.
        reset_for_test();
        for i in 0..(MIN_PEERS as u8) {
            record_peer_offset(ip(i), 600);
        }
        assert_eq!(time_offset_secs(), 600, "in-cap median applied");

        reset_for_test();
    }
}
