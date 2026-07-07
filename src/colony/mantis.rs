//! mantis — adversarial tarpit (escalating slow-hold for misbehaving peers).
//!
//! A praying mantis stays motionless and simply *holds* what wanders into
//! reach. This caste applies that to abusive peers: rather than instantly
//! dropping a peer that sends malformed frames / fails handshakes / probes,
//! which merely signals "rotate to a fresh IP and try again", the node
//! **tarpits** it — keeps the near-idle socket on an *escalating* hold
//! timer. The asymmetry is the point (rule D.2): holding a quiet socket on
//! a timer is nearly free for us, but ties up the attacker's connection
//! slot and defeats fast retry loops.
//!
//! ## What this module is — and is not
//!
//! This is the **pure decision core**: peer → offense count → hold seconds.
//! It performs no I/O, holds no sockets, and never inspects message
//! *content* (so it cannot leak or key on transaction data — it only ever
//! sees "this peer misbehaved", a boolean the caller supplies). Actually
//! holding the connection is the sidecar/node's job; this core just says
//! *how long*.
//!
//! ## Honest-glitch vs. malice (rule D.5)
//!
//! A single offense yields only a **[`TARPIT_BASE_SECS`]-second** hold —
//! trivial, so a peer that hiccups once (a truncated frame on a flaky
//! link) is barely affected. The hold **doubles per offense**, so cost
//! grows only for *repeat* offenders — the signature of deliberate abuse.
//! [`forgive_round`](MantisTarpit::forgive_round) decays offense counts
//! over time, so a reformed peer is fully forgiven and never carries a
//! permanent mark from a transient fault.
//!
//! ## The tarpit map is itself DoS surface (rule D.2)
//!
//! An attacker cycling many source addresses could try to bloat the map.
//! It is therefore capped at [`MAX_TRACKED_PEERS`]; when full, the
//! **least-offending** entry is evicted to admit a new offender, so the
//! worst actors stay tarpitted and memory stays bounded. Eviction is
//! deterministic (lowest offense count, ties broken by key).
//!
//! Integer and deterministic throughout — same rationale as
//! [`super::pheromone`].

use std::collections::BTreeMap;

/// Hold applied on the first offense (seconds). Deliberately tiny so an
/// honest one-off fault costs a peer almost nothing.
pub const TARPIT_BASE_SECS: u64 = 2;

/// Cap on any single hold (seconds). Beyond this the tarpit stops paying
/// off — it would tie up *our* socket/timer for little added attacker
/// cost. 5 minutes is long enough to shred a fast-retry loop.
pub const TARPIT_MAX_SECS: u64 = 300;

/// Cap on offense count stored per peer. Holds saturate at
/// [`TARPIT_MAX_SECS`] well before this, so this only bounds the integer;
/// it prevents unbounded growth under a sustained-abuse peer.
pub const MAX_OFFENSES: u32 = 32;

/// Maximum peers tracked at once. Bounds memory against address-rotation
/// flooding; when full, the least-offending peer is evicted.
pub const MAX_TRACKED_PEERS: usize = 4096;

/// Stable identity for a tarpitted peer (typically its IP or peer id as a
/// string). Ordered so eviction tie-breaks and iteration are deterministic.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TarpitKey(pub String);

/// Pure hold computation: `offenses` → seconds to hold.
///
/// Boundaries (stated per integer discipline):
/// - `offenses == 0` → `0` (unknown/clean peer is never held).
/// - doubles per offense: 1→2, 2→4, 3→8 … saturating at
///   [`TARPIT_MAX_SECS`].
/// - large `offenses`: the shift is clamped to 63 and uses `checked_shl`,
///   so it can never overflow or hit shift-UB — it just pins at the cap.
pub fn hold_secs(offenses: u32) -> u64 {
    if offenses == 0 {
        return 0;
    }
    // hold = TARPIT_BASE_SECS * 2^(offenses-1), overflow-safe.
    // NB: `TARPIT_BASE_SECS.checked_shl(n)` is WRONG here — checked_shl only
    // guards the shift *amount* (n < 64), not value loss, so `2u64 << 63`
    // silently returns Some(0). Build 2^(offenses-1) via `1u64 << shift`
    // (never loses its bit for shift < 64) then a checked multiply, which
    // DOES catch value overflow and pins the hold at the cap.
    let shift = (offenses - 1).min(63);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX); // 2^(offenses-1)
    let held = factor.checked_mul(TARPIT_BASE_SECS).unwrap_or(u64::MAX);
    held.min(TARPIT_MAX_SECS)
}

/// Per-peer tarpit state: peer → offense count.
#[derive(Clone, Debug, Default)]
pub struct MantisTarpit {
    offenses: BTreeMap<TarpitKey, u32>,
}

impl MantisTarpit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one offense against `peer` and return the hold (seconds) the
    /// caller should now apply. Offense count saturates at
    /// [`MAX_OFFENSES`]. If the map is full and `peer` is new, the
    /// least-offending tracked peer is evicted first so the worst actors
    /// stay held and memory stays bounded.
    pub fn record_offense(&mut self, peer: TarpitKey) -> u64 {
        if !self.offenses.contains_key(&peer) && self.offenses.len() >= MAX_TRACKED_PEERS {
            self.evict_least_offending();
        }
        let e = self.offenses.entry(peer).or_insert(0);
        *e = (*e + 1).min(MAX_OFFENSES);
        hold_secs(*e)
    }

    /// Current hold (seconds) for `peer` without recording a new offense.
    /// `0` if the peer is unknown/clean.
    pub fn hold_for(&self, peer: &TarpitKey) -> u64 {
        hold_secs(self.offenses.get(peer).copied().unwrap_or(0))
    }

    /// Offense count for `peer` (`0` if unknown).
    pub fn offenses(&self, peer: &TarpitKey) -> u32 {
        self.offenses.get(peer).copied().unwrap_or(0)
    }

    /// Decay every offense count by one and drop peers that reach zero.
    /// Call periodically so a peer that stops misbehaving is progressively
    /// forgiven and eventually falls out of the map entirely.
    pub fn forgive_round(&mut self) {
        for v in self.offenses.values_mut() {
            *v = v.saturating_sub(1);
        }
        self.offenses.retain(|_, v| *v > 0);
    }

    /// Drop the entry with the lowest offense count (ties broken by key
    /// order, so it is deterministic). No-op on an empty map.
    fn evict_least_offending(&mut self) {
        if let Some(victim) = self
            .offenses
            .iter()
            .min_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)))
            .map(|(k, _)| k.clone())
        {
            self.offenses.remove(&victim);
        }
    }

    pub fn len(&self) -> usize {
        self.offenses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.offenses.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> TarpitKey {
        TarpitKey(s.to_string())
    }

    #[test]
    fn clean_peer_is_never_held() {
        assert_eq!(hold_secs(0), 0);
        let t = MantisTarpit::new();
        assert_eq!(t.hold_for(&k("stranger")), 0);
    }

    #[test]
    fn hold_doubles_per_offense_then_caps() {
        assert_eq!(hold_secs(1), 2);
        assert_eq!(hold_secs(2), 4);
        assert_eq!(hold_secs(3), 8);
        assert_eq!(hold_secs(4), 16);
        // Doubling passes the cap between offense 8 (256) and 9 (would be
        // 512) — must clamp to TARPIT_MAX_SECS.
        assert_eq!(hold_secs(8), 256);
        assert_eq!(hold_secs(9), TARPIT_MAX_SECS);
        assert_eq!(hold_secs(20), TARPIT_MAX_SECS);
    }

    #[test]
    fn large_offense_count_never_overflows_or_ub() {
        // Shift clamp + checked_shl: even absurd counts just pin at the cap.
        assert_eq!(hold_secs(u32::MAX), TARPIT_MAX_SECS);
        assert_eq!(hold_secs(1000), TARPIT_MAX_SECS);
    }

    #[test]
    fn record_escalates_and_returns_hold() {
        let mut t = MantisTarpit::new();
        assert_eq!(t.record_offense(k("bad")), 2); // 1st
        assert_eq!(t.record_offense(k("bad")), 4); // 2nd
        assert_eq!(t.record_offense(k("bad")), 8); // 3rd
        assert_eq!(t.offenses(&k("bad")), 3);
        assert_eq!(t.hold_for(&k("bad")), 8);
    }

    #[test]
    fn offense_count_saturates_at_max() {
        let mut t = MantisTarpit::new();
        for _ in 0..(MAX_OFFENSES + 50) {
            t.record_offense(k("relentless"));
        }
        assert_eq!(t.offenses(&k("relentless")), MAX_OFFENSES);
        assert_eq!(t.hold_for(&k("relentless")), TARPIT_MAX_SECS);
    }

    #[test]
    fn forgive_decays_and_eventually_drops() {
        let mut t = MantisTarpit::new();
        t.record_offense(k("glitchy")); // offenses = 1
        t.record_offense(k("glitchy")); // offenses = 2
        t.forgive_round(); // -> 1
        assert_eq!(t.offenses(&k("glitchy")), 1);
        t.forgive_round(); // -> 0, dropped
        assert!(!t.offenses.contains_key(&k("glitchy")));
        assert_eq!(t.hold_for(&k("glitchy")), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn map_is_capacity_bounded_and_keeps_worst_offenders() {
        let mut t = MantisTarpit::new();
        // Fill to capacity, each with a distinct offense profile.
        for i in 0..MAX_TRACKED_PEERS {
            let key = k(&format!("peer{i:05}"));
            // Give the first peer many offenses (a heavy offender), the
            // rest exactly one.
            let times = if i == 0 { 5 } else { 1 };
            for _ in 0..times {
                t.record_offense(key.clone());
            }
        }
        assert_eq!(t.len(), MAX_TRACKED_PEERS);
        let heavy = k("peer00000");
        let heavy_offenses = t.offenses(&heavy);
        assert_eq!(heavy_offenses, 5);

        // One more distinct peer must evict a *least-offending* (1-offense)
        // entry, never the heavy offender, and stay within the cap.
        t.record_offense(k("newcomer"));
        assert_eq!(t.len(), MAX_TRACKED_PEERS, "must stay capacity-bounded");
        assert_eq!(
            t.offenses(&heavy),
            5,
            "the worst offender must survive eviction"
        );
        assert_eq!(t.offenses(&k("newcomer")), 1);
    }

    #[test]
    fn hold_for_does_not_mutate() {
        let mut t = MantisTarpit::new();
        t.record_offense(k("p"));
        let before = t.offenses(&k("p"));
        let _ = t.hold_for(&k("p"));
        assert_eq!(t.offenses(&k("p")), before, "hold_for must be read-only");
    }
}
