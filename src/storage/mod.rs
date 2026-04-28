//! # Storage Module for CoinCync 1.0
//! Persistent storage. The primary key/value path is `src/db/` (RocksDB
//! via `db::shim`); this module hosts the in-memory UTXO set, bloom
//! filters, LRU caches, pruning metadata, and the Phase 2 shielded/Spark
//! stores.

mod utxos;
mod bloom;
mod lru_cache;
mod pruning;

// ── Phase 2 stores (in-memory stubs for now) ────────────────────
pub mod shielded;
pub mod spark;
pub mod kernels;

pub use utxos::{UtxoSet, UtxoBatch, OutputRef};

pub use bloom::{
    BloomFilter, CountingBloomFilter, KeyImageFilter,
};

pub use lru_cache::{
    LruCache, SizedLruCache, CacheStats,
};

pub use pruning::{
    PruningMode, PruningRules, PruningStats,
    ChainPruner, PrunedBlockData, PruningPlan,
};

pub use shielded::{ShieldedStore, NoteCommitmentEntry};
pub use spark::{SparkStore, SparkCoinEntry};
pub use kernels::KernelStore;
