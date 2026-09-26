//! # Storage Module for CoinCync 1.0
//! Persistent storage. The primary key/value path is `src/db/` (RocksDB
//! via `db::shim`); this module hosts the in-memory UTXO set, bloom
//! filters, LRU caches, pruning metadata, and the Phase 2 shielded/Spark
//! stores.

mod bloom;
mod lru_cache;
mod pruning;
mod utxos;

// ── Phase 2 stores (in-memory stubs for now) ────────────────────
pub mod kernels;
/// The unified reorg seam for the three Phase-2 accumulator stores.
pub mod phase2;
pub mod shielded;
pub mod spark;
/// The libspark-FFI-aligned canonical Spark pool store (coins by outpoint +
/// deterministic serial context + the VRF-tag spent-set). Gated + inert; see
/// `docs/design/cip-triptych-ki-binding.md`.
#[cfg(feature = "sketch-gk-proof")]
pub mod spark_pool;

pub use utxos::{OutputRef, UtxoBatch, UtxoSet};

pub use bloom::{BloomFilter, CountingBloomFilter, KeyImageFilter};

pub use lru_cache::{CacheStats, LruCache, SizedLruCache};

pub use pruning::{
    ChainPruner, PrunedBlockData, PruningMode, PruningPlan, PruningRules, PruningStats,
};

pub use kernels::KernelStore;
pub use phase2::{Phase2Store, RewindOutcome};
pub use shielded::{NoteCommitmentEntry, ShieldedStore};
pub use spark::{SparkCoinEntry, SparkStore};
