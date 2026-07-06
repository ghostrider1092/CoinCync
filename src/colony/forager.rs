//! Colony forager — **Phase 1 (observe mode)**.
//!
//! Foragers score the node's peers by how well they relay **blocks** and
//! how current their chain tip is, and — in observe mode — report the
//! ranking. Observe mode **sends nothing, changes no node behavior, and
//! observes no transaction.** It is pure measurement, safe to run on the
//! live fleet.
//!
//! ## Prime Invariant (enforced in code)
//!
//! The only input to a pheromone deposit is [`ChainTipState`], which
//! carries **public block/tip signals only** — height, tip age, sync flag,
//! peer count, difficulty. It contains **no transaction data**, so this
//! module is *structurally incapable* of scoring on transaction activity.
//! Wiring a transaction in would require changing [`deposit_for_probe`]'s
//! signature — a visible, reviewable change that trips the tests below.
//! See `docs/architecture/colony.md` → "Forking hazards".

use tick::{ChainAdapter, ChainTipState};

use crate::colony::pheromone::{PeerKey, PheromoneMap};

// Deposit weights (fixed-point; one round's max = 700, well under SCORE_MAX).
const W_REACHABLE: u32 = 100; // the peer answered our probe at all
const W_AT_OR_AHEAD: u32 = 250; // its tip height is >= our local height
const W_FRESH_TIP: u32 = 250; // its tip is recent (not stalled)
const W_SYNCED: u32 = 100; // it reports itself in sync

/// A peer tip fresher than this (seconds) earns the freshness bonus.
const FRESH_TIP_SECS: u64 = 180;

/// Pheromone to deposit for one **successful** peer probe, from public
/// block/tip signals only.
///
/// Inputs: our `local_height` and the peer's [`ChainTipState`]. No
/// transaction-derived value is — or can be — an input here (see module
/// docs). Called only on a reachable peer, so the reachability base is
/// always included.
pub fn deposit_for_probe<Id>(local_height: u64, tip: &ChainTipState<Id>) -> u32 {
    let mut d = W_REACHABLE;
    if tip.height >= local_height {
        d += W_AT_OR_AHEAD;
    }
    if tip.tip_age_secs <= FRESH_TIP_SECS {
        d += W_FRESH_TIP;
    }
    if tip.is_synced {
        d += W_SYNCED;
    }
    d
}

/// Run one observe round: probe every fleet peer, deposit pheromone from
/// the public tip signals, evaporate, and return the ranked recommendation
/// (highest-scored peers first).
///
/// **Observe mode contract:** this function only *reads* (tip_state +
/// probe_peer) and mutates the local pheromone `map`. It sends nothing to
/// the node and never touches a transaction. The caller logs the result.
pub fn observe_round<A: ChainAdapter>(
    adapter: &A,
    map: &mut PheromoneMap,
) -> Vec<(PeerKey, u32)> {
    // Our own tip height — the reference the peers are scored against. If
    // the local RPC is down, fall back to 0 (every reachable peer then
    // counts as at-or-ahead, which is the safe/expected reading when we
    // can't see our own tip).
    let local_height = adapter.tip_state().map(|t| t.height).unwrap_or(0);

    for peer in adapter.fleet_peers() {
        let key = PeerKey(peer.name.clone());
        match adapter.probe_peer(&peer) {
            Ok(tip) => map.deposit(key, deposit_for_probe(local_height, &tip)),
            // Unreachable this round: no deposit. Evaporation decays the
            // peer's existing score, so persistent unreachability drops it.
            Err(_) => {}
        }
    }

    map.evaporate();
    map.ranked()
}

// ─── Advise mode (Phase 2, decision only) ─────────────────────────────────

/// A bounded peer-preference recommendation. In advise mode the colony would
/// ask the node to **prefer** these peers for block relay / connection
/// retention. Advisory only: the node validates, caps, keeps its anchors,
/// and may ignore it. The colony has no direct authority over the peer set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAdvice {
    /// Peers to prefer, highest-scored first (already capped).
    pub prefer: Vec<PeerKey>,
}

/// Minimum pheromone a peer must have before the colony will recommend it.
/// A peer has to have relayed well over several rounds (deposits accumulate,
/// evaporation decays) — one lucky-fast block is not enough. First defense
/// against pheromone-poisoning: a transient spike can't reach the threshold.
pub const ADVISE_MIN_SCORE: u32 = 600;

/// Turn the current pheromone ranking into a bounded [`PeerAdvice`]: the top
/// `max_prefer` peers whose score clears [`ADVISE_MIN_SCORE`].
///
/// Pure and non-mutating — computes a recommendation from the map; it does
/// **not** send anything or touch the node. Wiring this to the node's peer
/// manager (an eclipse-safe retention hint) is the reviewed next step.
pub fn advise(map: &PheromoneMap, max_prefer: usize) -> PeerAdvice {
    let prefer = map
        .ranked()
        .into_iter()
        .filter(|(_, score)| *score >= ADVISE_MIN_SCORE)
        .take(max_prefer)
        .map(|(key, _)| key)
        .collect();
    PeerAdvice { prefer }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tick_adapter::BlockIdBytes;
    use crate::primitives::Hash;

    fn tip(height: u64, tip_age_secs: u64, is_synced: bool) -> ChainTipState<BlockIdBytes> {
        ChainTipState {
            height,
            difficulty: 1,
            tip_id: BlockIdBytes(Hash::from_bytes([0u8; 32])),
            is_synced,
            peer_count: 3,
            tip_age_secs,
        }
    }

    #[test]
    fn reachable_peer_earns_the_base() {
        // A reachable peer that is behind, stale, and not synced still earns
        // the reachability base and nothing else.
        let d = deposit_for_probe(1000, &tip(500, 9999, false));
        assert_eq!(d, W_REACHABLE);
    }

    #[test]
    fn at_or_ahead_fresh_synced_earns_full() {
        let d = deposit_for_probe(1000, &tip(1000, 10, true));
        assert_eq!(d, W_REACHABLE + W_AT_OR_AHEAD + W_FRESH_TIP + W_SYNCED);
    }

    #[test]
    fn ahead_counts_as_at_or_ahead() {
        let d = deposit_for_probe(1000, &tip(1001, 10, true));
        assert_eq!(d, W_REACHABLE + W_AT_OR_AHEAD + W_FRESH_TIP + W_SYNCED);
    }

    #[test]
    fn stale_tip_loses_freshness_bonus() {
        let d = deposit_for_probe(1000, &tip(1000, FRESH_TIP_SECS + 1, true));
        assert_eq!(d, W_REACHABLE + W_AT_OR_AHEAD + W_SYNCED);
    }

    #[test]
    fn boundary_fresh_tip_age_is_inclusive() {
        // Exactly FRESH_TIP_SECS still counts as fresh.
        let d = deposit_for_probe(1000, &tip(1000, FRESH_TIP_SECS, false));
        assert_eq!(d, W_REACHABLE + W_AT_OR_AHEAD + W_FRESH_TIP);
    }

    #[test]
    fn deposit_input_is_block_tip_signals_only() {
        // Invariant guard (documentation-as-test): the deposit is a pure
        // function of local_height + ChainTipState's public block/tip
        // fields. ChainTipState carries no transaction data, so there is no
        // way to score on tx activity without changing this signature.
        // Same inputs -> same deposit, every time.
        let a = deposit_for_probe(1000, &tip(1200, 30, true));
        let b = deposit_for_probe(1000, &tip(1200, 30, true));
        assert_eq!(a, b);
    }

    // ── advise ──────────────────────────────────────────────────────────

    fn key(s: &str) -> PeerKey {
        PeerKey(s.to_string())
    }

    #[test]
    fn advise_recommends_top_peers_above_threshold_highest_first() {
        let mut m = PheromoneMap::new();
        m.deposit(key("best"), 900);
        m.deposit(key("good"), 700);
        let advice = advise(&m, 5);
        assert_eq!(advice.prefer, vec![key("best"), key("good")]);
    }

    #[test]
    fn advise_excludes_peers_below_min_score() {
        let mut m = PheromoneMap::new();
        m.deposit(key("proven"), ADVISE_MIN_SCORE);
        m.deposit(key("unproven"), ADVISE_MIN_SCORE - 1);
        let advice = advise(&m, 5);
        // Only the peer clearing the threshold is recommended — a transient
        // spike below it can't get advised (poison resistance).
        assert_eq!(advice.prefer, vec![key("proven")]);
    }

    #[test]
    fn advise_caps_at_max_prefer() {
        let mut m = PheromoneMap::new();
        for name in ["a", "b", "c", "d"] {
            m.deposit(key(name), 800);
        }
        assert_eq!(advise(&m, 2).prefer.len(), 2);
    }

    #[test]
    fn advise_is_empty_when_nothing_qualifies() {
        let mut m = PheromoneMap::new();
        m.deposit(key("weak"), 100);
        assert!(advise(&m, 5).prefer.is_empty());
    }
}
