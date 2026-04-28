//! # Mining Implementation (stub)
//!
//! The mining loop ported from CoinCync 2.0 referenced many features
//! that were removed in 1.0. The module is stubbed to keep the project
//! compiling. Real mining is driven by the `cyncd` binary using
//! `template::build_template` and the `consensus::pow` helpers.

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
