//! Network-adjusted time (audit item **M-4**), with clock-poisoning defenses.
//!
//! The consensus future-block timestamp cap
//! (`consensus::validation::check_header_future_timestamp`) must tolerate a
//! skewed **local** clock without trusting any single peer. Like Bitcoin Core's
//! `GetAdjustedTime`, we track the median offset between peers' claimed VERSION
//! time and our own clock and add it to the local time used for that cap.
//!
//! A naive version of this (reviewed on PR #59 by `junbyjun1238`) is a **remote
//! clock-poisoning** vector. This implementation closes all three holes that
//! review identified:
//!
//! 1. **One sample per peer *netgroup* (/16 v4, /32 v6), not per message.** A
//!    single connection sending five VERSIONs — or a flood from one /16 — counts
//!    **once**, so it cannot alone satisfy the [`MIN_TIME_PEERS`] warmup. The
//!    "≥N peers" property is enforced over *distinct netgroups*, not samples.
//! 2. **Sampled only after acceptance.** [`record_offset`] is called from
//!    `handle_version` **after** the self-connection-nonce and `version.validate()`
//!    checks pass — a later-rejected VERSION never mutates the time state.
//! 3. **Out-of-range median ⇒ offset 0, never clamp-to-max.** A median outside
//!    ±[`MAX_TIME_OFFSET_SECS`] is treated as untrusted and discarded (offset 0),
//!    rather than being converted into the *strongest* allowed adjustment (which
//!    is what made arbitrary peer timestamps dangerous in the reviewed version).
//!
//! Additionally, only **outbound** peers (ones we dialed from our own address
//! book) are sampled — inbound connections are attacker-chosen, so their clocks
//! are not trusted for consensus-relevant time.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

/// Minimum number of **distinct netgroups** sampled before any adjustment is
/// applied. Below this the offset is 0 (use the local clock as-is).
pub const MIN_TIME_PEERS: usize = 5;

/// Maximum magnitude (seconds) of the applied offset — ~70 minutes, matching
/// the historical bound. A median beyond this is **discarded** (offset 0), not
/// clamped to it.
pub const MAX_TIME_OFFSET_SECS: i64 = 70 * 60;

/// Upper bound on tracked netgroups (bounded memory; first-come once full).
const MAX_TRACKED: usize = 200;

/// A sample older than this (seconds) is discarded: it reflects a peer we may no
/// longer be connected to, and a stale offset must not survive a local clock
/// correction (per the PR #59/#170 review). Samples are also refreshed every
/// time the netgroup reconnects, so a live peer's offset never ages out.
const SAMPLE_TTL_SECS: u64 = 3 * 3600;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct State {
    /// netgroup key → (offset sample, unix time it was recorded). One per group;
    /// a reconnect refreshes the timestamp so live peers don't expire, while a
    /// peer that goes away ages out after `SAMPLE_TTL_SECS`.
    samples: HashMap<u64, (i64, u64)>,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State { samples: HashMap::new() }))
}

/// Anti-eclipse netgroup key: /16 for IPv4, /32 for IPv6, in disjoint v4/v6
/// namespaces. Mirrors `bootstrap::AddressManager::addr_netgroup` so a single
/// /16 (or /32) is one identity for time sampling just as it is for the book.
pub fn netgroup_key(addr: &SocketAddr) -> u64 {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            ((o[0] as u64) << 8) | (o[1] as u64)
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            0x1_0000_0000 | ((s[0] as u64) << 16) | (s[1] as u64)
        }
    }
}

/// Record a peer's clock offset `offset_secs = peer_claimed_time − our_local_time`,
/// keyed by the peer's netgroup.
///
/// MUST be called only **after** the VERSION has passed the self-connection and
/// `validate()` checks, and only for **outbound** peers (see module docs). A new
/// sample from a netgroup already present **replaces** the old one, so each
/// netgroup contributes at most one vote regardless of how many messages or
/// connections it opens.
pub fn record_offset(addr: &SocketAddr, offset_secs: i64) {
    record_offset_at(addr, offset_secs, now_unix())
}

/// As [`record_offset`] but with an explicit record time (seam for tests).
fn record_offset_at(addr: &SocketAddr, offset_secs: i64, at_unix: u64) {
    let key = netgroup_key(addr);
    let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
    if !st.samples.contains_key(&key) && st.samples.len() >= MAX_TRACKED {
        return; // bounded; ignore new groups once full
    }
    st.samples.insert(key, (offset_secs, at_unix));
}

/// The network-adjusted offset (seconds) to **add** to the local clock for the
/// future-block timestamp cap.
///
/// - `0` until [`MIN_TIME_PEERS`] distinct netgroups have been sampled (warmup).
/// - `0` if the median is outside ±[`MAX_TIME_OFFSET_SECS`] (untrusted — **not**
///   clamped to the bound).
/// - otherwise the median of the per-netgroup samples.
pub fn offset_secs() -> i64 {
    let now = now_unix();
    let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
    prune_stale(&mut st, now);
    if st.samples.len() < MIN_TIME_PEERS {
        return 0;
    }
    let mut v: Vec<i64> = st.samples.values().map(|(off, _)| *off).collect();
    v.sort_unstable();
    let median = v[v.len() / 2];
    if median < -MAX_TIME_OFFSET_SECS || median > MAX_TIME_OFFSET_SECS {
        0
    } else {
        median
    }
}

/// Drop samples older than `SAMPLE_TTL_SECS` so the median reflects the current
/// peer set and a stale offset can't survive a local clock correction.
fn prune_stale(st: &mut State, now: u64) {
    st.samples
        .retain(|_, (_, at)| now.saturating_sub(*at) <= SAMPLE_TTL_SECS);
}

/// Number of distinct **fresh** netgroups currently sampled (diagnostics/tests).
pub fn sample_count() -> usize {
    let now = now_unix();
    let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
    prune_stale(&mut st, now);
    st.samples.len()
}

/// Test-only: clear all samples so tests don't leak global state into each other.
#[cfg(test)]
pub fn reset_for_test() {
    state().lock().unwrap_or_else(|e| e.into_inner()).samples.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate the process-global sample map, so they must not run
    // concurrently with each other. Each acquires this guard for its duration
    // (held via the `_guard` binding) and resets the state under it.
    static TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn addr(a: u8, b: u8) -> SocketAddr {
        format!("{a}.{b}.0.1:28080").parse().unwrap()
    }

    #[test]
    fn warmup_returns_zero_until_min_distinct_netgroups() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        // 4 distinct /16s with a big offset — still below the warmup floor → 0.
        for i in 0..(MIN_TIME_PEERS as u8 - 1) {
            record_offset(&addr(10, i), 3600);
        }
        assert_eq!(sample_count(), MIN_TIME_PEERS - 1);
        assert_eq!(offset_secs(), 0, "below warmup must not adjust");
        // The 5th distinct netgroup crosses the floor.
        record_offset(&addr(10, 99), 3600);
        assert_eq!(offset_secs(), 3600);
    }

    #[test]
    fn single_netgroup_flood_cannot_satisfy_warmup() {
        // junbyjun1238's attack: one peer (one /16) sends many samples. With
        // per-netgroup dedup this is ONE vote, never enough to warm up alone.
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        for k in 0..50i64 {
            record_offset(&addr(203, 0), -86400 + k); // all 203.0.0.0/16
        }
        assert_eq!(sample_count(), 1, "one /16 is one sample, not many");
        assert_eq!(offset_secs(), 0, "a single netgroup cannot poison the clock");
    }

    #[test]
    fn out_of_range_median_resets_to_zero_not_clamp() {
        // 5 distinct netgroups all claiming -1 day. Median is out of range →
        // untrusted → 0 (NOT clamped to -MAX_TIME_OFFSET_SECS).
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        for i in 0..MIN_TIME_PEERS as u8 {
            record_offset(&addr(10, i), -86400);
        }
        assert_eq!(sample_count(), MIN_TIME_PEERS);
        assert_eq!(
            offset_secs(),
            0,
            "out-of-range median must be discarded, not clamped to the max adjustment"
        );
    }

    #[test]
    fn in_range_median_is_applied() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        for (i, off) in [100, 200, 300, 400, 500].into_iter().enumerate() {
            record_offset(&addr(10, i as u8), off);
        }
        assert_eq!(offset_secs(), 300, "median of the 5 in-range offsets");
    }

    #[test]
    fn resampling_same_netgroup_replaces_not_appends() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        record_offset(&addr(10, 1), 100);
        record_offset(&addr(10, 1), 999); // same /16 updates in place
        assert_eq!(sample_count(), 1);
    }

    #[test]
    fn stale_samples_expire_and_do_not_influence_the_cap() {
        // #170 review (junbyjun1238): a sample must not outlive its peer or
        // survive a local clock correction. Samples older than the TTL are
        // pruned, so even a full set of stale offsets yields 0.
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        let old = now_unix().saturating_sub(SAMPLE_TTL_SECS + 60);
        for i in 0..MIN_TIME_PEERS as u8 {
            record_offset_at(&addr(10, i), 600, old);
        }
        assert_eq!(sample_count(), 0, "stale samples must be pruned");
        assert_eq!(offset_secs(), 0, "an expired offset must not shift the future-block cap");
    }
}
