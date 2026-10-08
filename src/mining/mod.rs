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
/// - `has_peers && is_synced` → normal healthy mining,
/// - `!has_peers && allow_solo_mine` → explicit solo opt-in.
pub fn solo_mine_gate_allowed(
    is_regtest: bool,
    has_peers: bool,
    is_synced: bool,
    allow_solo_mine: bool,
) -> bool {
    is_regtest || (has_peers && is_synced) || (!has_peers && allow_solo_mine)
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
    use super::solo_mine_gate_allowed;

    #[test]
    fn solo_mine_gate_147() {
        // regtest: always mines.
        assert!(solo_mine_gate_allowed(true, false, false, false));
        // synced WITH at least one peer: normal mining.
        assert!(solo_mine_gate_allowed(false, true, true, false));
        // THE #147 FIX: synced but ZERO peers and no opt-in → BLOCKED.
        // Pre-fix the unguarded is_synced() let this mine a private fork.
        assert!(!solo_mine_gate_allowed(false, false, true, false));
        // zero peers + explicit --allow-solo-mine: mines (bootstrap seed).
        assert!(solo_mine_gate_allowed(false, false, false, true));
        // zero peers + opt-in, regardless of the stale synced flag: mines.
        assert!(solo_mine_gate_allowed(false, false, true, true));
        // has peers but NOT synced: don't mine (still catching up).
        assert!(!solo_mine_gate_allowed(false, true, false, false));
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
