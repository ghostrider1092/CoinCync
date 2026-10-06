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
