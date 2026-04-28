// src/mining/mod.rs
pub mod template;
pub mod bans;
pub mod entropy;
pub mod progress;
pub mod pool;
pub mod stratum;
pub mod miner;

// Re-exports consumed by src/bin/miner.rs (the standalone miner binary).
pub use progress::{
    MinerDisplay, MinerDisplayConfig, MiningMode,
    NetworkState, LiveMetrics, MinerWarning,
    format_hashrate, format_duration, format_difficulty, format_large_number,
};
