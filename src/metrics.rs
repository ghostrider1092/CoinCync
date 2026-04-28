// src/metrics.rs
//
// Prometheus metrics for the full node.
//
// The CoinCync 2.0 metrics module depended on the `metrics` and
// `metrics-exporter-prometheus` crates which are not part of the 1.0 trim.
// This module is stubbed with noop implementations so that the rest of the
// crate compiles. Real metrics wiring returns in a later pass.

use crate::error::Result;

/// Initialize the Prometheus metrics exporter (noop stub).
pub fn init(_bind_addr: &str) -> Result<()> { Ok(()) }

// ── Chain metrics ────────────────────────────────────────────
pub fn block_height(_h: u64)      {}
pub fn block_time_secs(_t: f64)   {}
pub fn block_size_bytes(_s: usize) {}
pub fn orphan_block()             {}
pub fn reorg(_depth: u64)         {}
pub fn difficulty(_d: f64)        {}
pub fn circulating_supply(_s: u64) {}

// ── Mempool metrics ───────────────────────────────────────────
pub fn mempool_size(_n: usize)    {}
pub fn mempool_bytes(_b: usize)   {}
pub fn tx_accepted()              {}
pub fn tx_rejected()              {}

// ── Validation timing ─────────────────────────────────────────
pub fn validation_ms(_ms: f64)    {}
pub fn clsag_verify_ms(_ms: f64)  {}
pub fn bp_verify_ms(_ms: f64)     {}
pub fn halo2_verify_ms(_ms: f64)  {}

// ── Network metrics ───────────────────────────────────────────
pub fn peer_count(_n: usize)      {}
pub fn inbound_peers(_n: usize)   {}
pub fn outbound_peers(_n: usize)  {}
pub fn bytes_sent(_b: u64)        {}
pub fn bytes_recv(_b: u64)        {}
pub fn msg_sent()                 {}
pub fn msg_recv()                 {}

// ── Mining metrics ────────────────────────────────────────────
pub fn hashrate(_hr: f64)         {}
pub fn mined_block()              {}

// ── Privacy metrics ───────────────────────────────────────────
pub fn shielded_tx_count()        {}
pub fn shielded_pool_size(_n: u64) {}
pub fn shielded_tx_ratio(_r: f64) {}

/// Stub sub-module for dandelion++ metrics.
pub mod dandelion {
    /// Noop counter placeholder.
    pub struct NoopCounter;
    impl NoopCounter {
        pub fn inc(&self) {}
        pub fn set<T>(&self, _v: T) {}
    }

    pub static EPOCH_ROTATIONS_TOTAL: NoopCounter = NoopCounter;
    pub static CURRENT_EPOCH_MODE:    NoopCounter = NoopCounter;
    pub static EMBARGO_FLUFFS_TOTAL:  NoopCounter = NoopCounter;
    pub static STEM_RELAYS_TOTAL:     NoopCounter = NoopCounter;
    pub static FLUFF_BROADCASTS_TOTAL: NoopCounter = NoopCounter;
    pub static STEMPOOL_SIZE:         NoopCounter = NoopCounter;
}
