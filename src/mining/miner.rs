//! # Mining Implementation (stub)
//!
//! The mining loop ported from CoinCync 2.0 referenced many features
//! that were removed in 1.0. The module is stubbed to keep the project
//! compiling. Real mining is driven by the `cyncd` binary using
//! `template::build_template` and the `consensus::pow` helpers.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (This is the 1.0 stub — real
//! mining runs in `cyncd`, so several areas are intentionally inert.)
//!
//! - **§1 `Miner::stats`** — INVARIANT: the stub reports default (all-zero,
//!   not-mining) stats, never fabricated hashrate. THREAT: a TUI shows phantom
//!   mining activity from a node that is not mining. TESTS:
//!   `stats_returns_default_mining_stats`.
//! - **§2 `Miner::start`** — INVARIANT: the stubbed loop returns `Ok(())`
//!   immediately and spawns no work. THREAT: a caller believes it started a real
//!   miner and burns CPU or blocks. TESTS: `start_stub_returns_ok`.
//! - **§3 `Miner::new`** — INVARIANT: constructor stores the shared chain and
//!   config without side effects. THREAT: construction mutates chain state.
//!   TESTS: `stats_returns_default_mining_stats`, `start_stub_returns_ok`.
//! - **§4 `Miner::stop`** — INVARIANT: stop is a safe no-op on the stub. THREAT:
//!   stopping a non-running miner panics. TESTS: (gap — trivial no-op, exercised
//!   indirectly by the stub lifecycle).
//! - **§5 `MiningStats` / `MiningLiveData` / `SampleHash`** — INVARIANT: TUI live
//!   data types default to inert values. THREAT: uninitialized display fields
//!   render stale mining state. TESTS: `stats_returns_default_mining_stats`.

use std::sync::Arc;

use crate::chain::SharedBlockchain;
use crate::error::Result;

/// Mining statistics.
#[derive(Clone, Debug, Default)]
pub struct MiningStats {
    pub hashrate: f64,
    pub hashes_total: u64,
    pub blocks_found: u64,
    pub last_block_time: u64,
    pub is_mining: bool,
}

/// Mining live data for TUI displays.
#[derive(Clone, Debug, Default)]
pub struct MiningLiveData {
    pub current_nonce: u64,
    pub algorithm: u8,
    pub mining_height: u64,
    pub target_hex: String,
    pub best_hash_hex: String,
    pub best_leading_zeros: u32,
    pub target_leading_zeros: u32,
    pub sample_hashes: Vec<SampleHash>,
    pub hashrate: f64,
    pub hashes_total: u64,
    pub blocks_found: u64,
    pub is_mining: bool,
    pub block_just_found: bool,
    pub winning_nonce: u64,
    pub winning_hash_hex: String,
}

/// A sampled hash attempt for display.
#[derive(Clone, Debug)]
pub struct SampleHash {
    pub nonce: u64,
    pub hash_hex: String,
    pub leading_zeros: u32,
}

/// Minimal mining configuration.
#[derive(Clone, Debug, Default)]
pub struct MinerConfig {
    pub threads: usize,
    pub mine_to: Option<String>,
}

/// The miner driver struct.
pub struct Miner {
    pub chain: SharedBlockchain,
    pub config: MinerConfig,
}

impl Miner {
    pub fn new(chain: SharedBlockchain, config: MinerConfig) -> Self {
        Self { chain, config }
    }

    /// Returns current stats.
    pub fn stats(&self) -> MiningStats {
        MiningStats::default()
    }

    /// Start mining loop — stubbed; returns immediately.
    pub fn start(self: Arc<Self>) -> Result<()> {
        tracing::warn!("mining::miner::start is a stub in CoinCync 1.0");
        Ok(())
    }

    pub fn stop(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 1.0 stub reports default (all-zero, not-mining) stats.
    #[test]
    fn stats_returns_default_mining_stats() {
        let chain: SharedBlockchain = Arc::new(crate::chain::Blockchain::new());
        let miner = Miner::new(chain, MinerConfig::default());
        let stats = miner.stats();
        assert_eq!(stats.hashrate, 0.0);
        assert_eq!(stats.hashes_total, 0);
        assert_eq!(stats.blocks_found, 0);
        assert_eq!(stats.last_block_time, 0);
        assert!(!stats.is_mining);
    }

    /// The stubbed mining loop returns Ok without spawning any work.
    #[test]
    fn start_stub_returns_ok() {
        let chain: SharedBlockchain = Arc::new(crate::chain::Blockchain::new());
        let miner = Arc::new(Miner::new(chain, MinerConfig::default()));
        assert!(miner.start().is_ok());
    }
}
