// src/mining/mod.rs
pub mod bans;
pub mod block_builder;
pub mod entropy;
pub mod miner;
pub mod pool;
pub mod stratum;
pub mod template;

/// Whether the built-in solo miner may produce a block right now.
///
/// #147: the "synced" path REQUIRES a live peer. When an isolated node's last
/// peer drops, `best_known_height` recomputes to `local_height`, so `is_synced`
/// flips true — which previously (via an unguarded `|| is_synced()` in the
/// miner loop) bypassed the 0-peer `--allow-solo-mine` opt-in and let the node
/// keep mining a private fork it could not reorg off (#126). A genuine solo
/// operator (e.g. a bootstrap seed) still mines by passing `--allow-solo-mine`.
///
/// - regtest → always (local dev),
/// - `has_peers && is_synced && !diverged` -> normal healthy mining,
/// - `!has_peers && allow_solo_mine` -> explicit solo opt-in,
/// - `has_peers && is_synced && diverged && allow_solo_mine` -> a bootstrap seed
///   whose followers lag keeps producing (that is what the flag is for).
///
/// `diverged` is `fork_diverged()`: our tip runs far ahead of every peer. A
/// peer that is BEHIND us does not make `is_synced` false (it is
/// `height >= peer_target_height`), so a node whose only peer is stale, e.g. a
/// frozen seed, passed the old gate and mined alone. Seen on testnet
/// 2026-10-07: 279 blocks on a private fork, which the reorg depth rule then
/// made permanent. The rig has had this check since the 2026-07-08 runaway
/// fork; the built-in miner did not.
pub fn solo_mine_gate_allowed(
    is_regtest: bool,
    has_peers: bool,
    is_synced: bool,
    allow_solo_mine: bool,
    diverged: bool,
) -> bool {
    is_regtest
        || (has_peers && is_synced && (!diverged || allow_solo_mine))
        || (!has_peers && allow_solo_mine)
}

/// How many blocks our tip may run ahead of the best peer-advertised height
/// before the miner treats its chain as a private fork and stops. Peers that
/// accept our blocks re-advertise their height on every tip change, so an
/// honest miner's lead stays at a block or two.
pub const FORK_DIVERGENCE_MARGIN: u64 = 25;

/// Pure predicate for the fork-divergence gate (shared by the built-in miner
/// and coincync-rig).
///
/// Returns `true` when the local tip has run so far ahead of every peer that
/// our blocks are provably not being adopted, i.e. we are mining a private
/// fork and must stop. `peer_target == 0` means "no peer height reported
/// yet", which is NOT divergence (the peer-count gate covers the empty-mesh
/// case); we return `false` so a fresh node is not wedged.
pub fn fork_diverged(local_height: u64, peer_target: u64, margin: u64) -> bool {
    peer_target > 0 && local_height > peer_target.saturating_add(margin)
}

/// Built-in miner's view of `fork_diverged`: `best_peer_height` is the raw
/// maximum over connected peers (`P2PNode::max_peer_height`), and a peer that
/// has not reported any height (0) does not vouch for our tip either. Only
/// meaningful when at least one peer is connected; the caller checks that.
pub fn no_peer_near_tip(local_height: u64, best_peer_height: u64, margin: u64) -> bool {
    best_peer_height == 0 || fork_diverged(local_height, best_peer_height, margin)
}

// ── Built-in solo-miner observability (backs the `get_mining_live` RPC) ──────
//
// Monotonic counters since process start. The in-process miner (the `--mine`
// path in the node binary) feeds these: `MINER_HASHES_TOTAL` is bumped by the
// nonce search, `MINER_BLOCKS_FOUND` by the miner loop on an accepted mined
// block. Before this, `get_mining_live` was hardcoded to `is_mining:false` /
// zeros because mining lived only in the external rig; now a plain `--mine`
// node reports its real state. A poller (the rig/TUI) derives hashrate from
// successive `hashes_total` samples; `sample_hashrate` also offers a
// best-effort instantaneous rate for single-poller convenience.
pub static MINER_HASHES_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static MINER_BLOCKS_FOUND: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Best-effort hashes/sec: the delta in `MINER_HASHES_TOTAL` since the previous
/// call divided by elapsed wall-time. Intended for a single periodic poller
/// (the TUI). Returns 0.0 on the first call or when no time has elapsed. This
/// is an observability convenience, not a precise meter — concurrent callers
/// just see noisier numbers, never UB.
pub fn sample_hashrate() -> f64 {
    use std::sync::atomic::Ordering;
    use std::time::Instant;
    static LAST: std::sync::Mutex<Option<(u64, Instant)>> = std::sync::Mutex::new(None);
    let now_total = MINER_HASHES_TOTAL.load(Ordering::Relaxed);
    let now = Instant::now();
    let mut guard = LAST.lock().unwrap_or_else(|p| p.into_inner());
    let rate = match *guard {
        Some((prev_total, prev_at)) => {
            let dt = now.duration_since(prev_at).as_secs_f64();
            if dt > 0.0 {
                now_total.saturating_sub(prev_total) as f64 / dt
            } else {
                0.0
            }
        }
        None => 0.0,
    };
    *guard = Some((now_total, now));
    rate
}

#[cfg(test)]
mod gate_tests {
    use super::{fork_diverged, no_peer_near_tip, solo_mine_gate_allowed, FORK_DIVERGENCE_MARGIN};

    #[test]
    fn solo_mine_gate_147() {
        // regtest: always mines.
        assert!(solo_mine_gate_allowed(true, false, false, false, false));
        // synced WITH at least one peer: normal mining.
        assert!(solo_mine_gate_allowed(false, true, true, false, false));
        // THE #147 FIX: synced but ZERO peers and no opt-in → BLOCKED.
        // Pre-fix the unguarded is_synced() let this mine a private fork.
        assert!(!solo_mine_gate_allowed(false, false, true, false, false));
        // zero peers + explicit --allow-solo-mine: mines (bootstrap seed).
        assert!(solo_mine_gate_allowed(false, false, false, true, false));
        // zero peers + opt-in, regardless of the stale synced flag: mines.
        assert!(solo_mine_gate_allowed(false, false, true, true, false));
        // has peers but NOT synced: don't mine (still catching up).
        assert!(!solo_mine_gate_allowed(false, true, false, false, false));
    }

    /// 2026-10-07 testnet: only peer frozen at 107, we are at 827 -> "synced",
    /// 279 blocks mined alone. Divergence must close the gate; the explicit
    /// bootstrap opt-in may keep it open; regtest is unaffected.
    #[test]
    fn solo_mine_gate_blocks_private_fork() {
        assert!(!solo_mine_gate_allowed(false, true, true, false, true));
        assert!(solo_mine_gate_allowed(false, true, true, true, true));
        assert!(solo_mine_gate_allowed(true, true, true, false, true));
        // not synced stays blocked whatever the flags say
        assert!(!solo_mine_gate_allowed(false, true, false, true, true));
    }

    #[test]
    fn fork_diverged_margin() {
        // no peer height yet: not divergence
        assert!(!fork_diverged(10_544, 0, FORK_DIVERGENCE_MARGIN));
        assert!(!fork_diverged(0, 0, FORK_DIVERGENCE_MARGIN));
        // at, below or within the margin of the best peer: fine
        assert!(!fork_diverged(10_000, 10_042, FORK_DIVERGENCE_MARGIN));
        assert!(!fork_diverged(10_042, 10_042, FORK_DIVERGENCE_MARGIN));
        assert!(!fork_diverged(10_042 + FORK_DIVERGENCE_MARGIN, 10_042, FORK_DIVERGENCE_MARGIN));
        // one past the margin, and the real incident (827 vs 107)
        assert!(fork_diverged(10_042 + FORK_DIVERGENCE_MARGIN + 1, 10_042, FORK_DIVERGENCE_MARGIN));
        assert!(fork_diverged(827, 107, FORK_DIVERGENCE_MARGIN));
    }

    #[test]
    fn no_peer_near_tip_counts_unknown_height() {
        // the incident, and a peer that never said where it is
        assert!(no_peer_near_tip(827, 107, FORK_DIVERGENCE_MARGIN));
        assert!(no_peer_near_tip(2399, 0, FORK_DIVERGENCE_MARGIN));
        // a peer at, just behind or ahead of us vouches for the tip
        assert!(!no_peer_near_tip(2403, 2403, FORK_DIVERGENCE_MARGIN));
        assert!(!no_peer_near_tip(2403, 2403 - FORK_DIVERGENCE_MARGIN, FORK_DIVERGENCE_MARGIN));
        assert!(!no_peer_near_tip(2401, 2402, FORK_DIVERGENCE_MARGIN));
    }
}

#[cfg(test)]
mod miner_obs_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn miner_counters_monotonic_and_sampler_is_finite() {
        // Process-global counters: assert on deltas (another test may also be
        // incrementing), never absolutes. The hashrate sampler must always
        // return a finite, non-negative number.
        let before = MINER_HASHES_TOTAL.load(Ordering::Relaxed);
        MINER_HASHES_TOTAL.fetch_add(1000, Ordering::Relaxed);
        assert!(MINER_HASHES_TOTAL.load(Ordering::Relaxed) >= before + 1000);

        let blocks_before = MINER_BLOCKS_FOUND.load(Ordering::Relaxed);
        MINER_BLOCKS_FOUND.fetch_add(1, Ordering::Relaxed);
        assert!(MINER_BLOCKS_FOUND.load(Ordering::Relaxed) >= blocks_before + 1);

        let r = sample_hashrate();
        assert!(r.is_finite() && r >= 0.0, "hashrate must be finite/non-negative, got {r}");
    }
}
