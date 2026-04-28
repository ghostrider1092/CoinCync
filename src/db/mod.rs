//! # Database Module
//!
//! Persistent storage using sled embedded database.
//!
//! ## Key Encoding Convention (H26)
//!
//! CONVENTION: All sled tree keys use big-endian (BE) encoding for correct
//! lexicographic ordering. PoW hash inputs use little-endian (LE) as part of
//! the hash preimage. These are different contexts and intentionally use
//! different encodings.
//!
//! ## Performance Tuning
//!
//! Sled is configured for optimal blockchain performance:
//! - Large cache for hot data (blocks, UTXOs)
//! - Async flushing to reduce write latency
//! - Optimized segment size for blockchain workloads
//! - Optional compression for storage efficiency

pub mod shim;
mod blocks;
mod utxos;
mod state;
mod keys;
mod mempool;
mod wallet;
mod output_index;
pub mod filters;
pub mod pruning;

pub use blocks::BlockDb;
pub use utxos::{UtxoDb, OutputEntry};
pub use state::{StateDb, ChainStateData};
pub use keys::{KeyDb, EncryptedKey, KeyEntry, KeyMetadata};
pub use mempool::{MempoolDb, MempoolEntry};
pub use wallet::{WalletDb, OwnedOutput, ScanState};
pub use output_index::{OutputIndexDb, OutputIndexEntry};
pub use filters::FilterDb;
pub use pruning::{PruneResult, prune_blocks, is_pruned};

use std::path::Path;
use crate::error::{Error, Result};

/// Database performance mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbMode {
    /// Fast mode: prioritize speed over durability
    /// Good for initial sync, uses async I/O aggressively
    Fast,
    /// Safe mode: prioritize durability over speed
    /// Good for normal operation, ensures writes are persisted
    Safe,
    /// Balanced mode: reasonable trade-off (default)
    Balanced,
}

impl Default for DbMode {
    fn default() -> Self {
        DbMode::Balanced
    }
}

/// Database configuration with performance tuning options
#[derive(Clone, Debug)]
pub struct DbConfig {
    /// Cache size in MB (default: 512 MB for good read performance)
    pub cache_size_mb: usize,
    /// Flush interval in ms (None = manual flush only)
    pub flush_interval_ms: Option<u64>,
    /// Performance mode
    pub mode: DbMode,
    /// Use compression (saves ~30% space, slight CPU cost)
    pub use_compression: bool,
    /// Segment size in bytes (larger = better sequential reads)
    /// Default: 16 MB (sled maximum)
    pub segment_size: usize,
    /// Maximum concurrent readers
    pub max_readers: usize,
    /// Print size limit for debugging (0 = disabled)
    pub print_profile_on_drop: bool,
}

impl Default for DbConfig {
    fn default() -> Self {
        DbConfig {
            cache_size_mb: 512,                    // 512 MB cache
            flush_interval_ms: Some(1000),         // Flush every second
            mode: DbMode::Balanced,
            use_compression: true,                 // Enable zstd compression
            segment_size: 16 * 1024 * 1024,       // 16 MB segments (sled max)
            max_readers: 128,
            print_profile_on_drop: false,
        }
    }
}

impl DbConfig {
    /// Configuration optimized for initial blockchain sync
    pub fn fast_sync() -> Self {
        DbConfig {
            cache_size_mb: 1024,                   // 1 GB cache for sync
            flush_interval_ms: Some(5000),         // Flush every 5 seconds
            mode: DbMode::Fast,
            use_compression: false,                // Skip compression during sync
            segment_size: 16 * 1024 * 1024,        // 16 MB (sled max)
            max_readers: 64,
            print_profile_on_drop: false,
        }
    }

    /// Configuration optimized for low-memory systems
    pub fn low_memory() -> Self {
        DbConfig {
            cache_size_mb: 128,                    // 128 MB cache
            flush_interval_ms: Some(500),          // Flush more often
            mode: DbMode::Safe,
            use_compression: true,                 // Save disk space
            segment_size: 8 * 1024 * 1024,        // 8 MB segments
            max_readers: 32,
            print_profile_on_drop: false,
        }
    }

    /// Configuration for maximum safety (exchanges, validators)
    pub fn maximum_safety() -> Self {
        DbConfig {
            cache_size_mb: 256,
            flush_interval_ms: Some(100),          // Flush very often
            mode: DbMode::Safe,
            use_compression: true,
            segment_size: 16 * 1024 * 1024,       // 16 MB (sled max)
            max_readers: 64,
            print_profile_on_drop: false,
        }
    }

    /// Auto-detect optimal config based on system resources
    pub fn auto() -> Self {
        let available_memory_mb = get_available_memory_mb();

        if available_memory_mb > 8192 {
            // 8+ GB RAM: use aggressive caching
            DbConfig {
                cache_size_mb: 1024,
                ..Default::default()
            }
        } else if available_memory_mb > 4096 {
            // 4-8 GB RAM: standard config
            DbConfig::default()
        } else if available_memory_mb > 2048 {
            // 2-4 GB RAM: conservative
            DbConfig {
                cache_size_mb: 256,
                ..Default::default()
            }
        } else {
            // <2 GB RAM: minimal
            DbConfig::low_memory()
        }
    }
}

/// Get available system memory in MB
fn get_available_memory_mb() -> usize {
    // Try to detect system memory
    // Falls back to conservative estimate if detection fails
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<usize>() {
                            return kb / 1024;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Use sysinfo or default
        // For simplicity, return a reasonable default
    }

    // Default: assume 4 GB
    4096
}

/// Main database handle
pub struct Database {
    /// Underlying key/value store (RocksDB-backed shim)
    db: shim::Db,
    /// Block storage
    pub blocks: BlockDb,
    /// UTXO storage
    pub utxos: UtxoDb,
    /// Chain state
    pub state: StateDb,
    /// Key storage
    pub keys: KeyDb,
    /// Mempool storage
    pub mempool: MempoolDb,
    /// Permanent output index (for ring member validation of spent outputs)
    pub output_index: OutputIndexDb,
    /// Block filter storage for personal node protocol (Tier 2 serving)
    pub filters: FilterDb,
    /// Transaction hash → (block_height, tx_index) for O(1) tx lookups
    pub tx_index: shim::Tree,
}

impl Database {
    /// Open or create database at path with auto-detected optimal config
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_config(path, DbConfig::auto())
    }

    /// Open with default config
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_config(path, DbConfig::default())
    }

    /// Open with custom config
    pub fn open_with_config<P: AsRef<Path>>(path: P, config: DbConfig) -> Result<Self> {
        tracing::info!(
            "Opening database with config: cache={}MB, mode={:?}, compression={}",
            config.cache_size_mb,
            config.mode,
            config.use_compression
        );

        // RocksDB-backed shim. DbConfig fields are preserved for API
        // parity but most are now no-ops (rocksdb tunes itself).
        let db = shim::Config::new()
            .path(path)
            .cache_capacity((config.cache_size_mb * 1024 * 1024) as u64)
            .flush_every_ms(config.flush_interval_ms)
            .open()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let blocks = BlockDb::new(&db)?;
        let utxos = UtxoDb::new(&db)?;
        let state = StateDb::new(&db)?;
        let keys = KeyDb::new(&db)?;
        let mempool = MempoolDb::new(&db)?;
        let output_index = OutputIndexDb::new(&db)?;
        let filters = FilterDb::new(&db)?;
        let tx_index = db.open_tree("tx_index")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        tracing::info!("Database opened successfully");

        Ok(Database {
            db,
            blocks,
            utxos,
            state,
            keys,
            mempool,
            output_index,
            filters,
            tx_index,
        })
    }

    /// Open a temporary database (for testing)
    #[cfg(test)]
    pub fn open_temp() -> Result<Self> {
        let dir = tempfile::tempdir()
            .map_err(|e: std::io::Error| Error::DatabaseError(e.to_string()))?;
        Self::open(dir.keep())
    }

    /// Index a transaction hash to its block height and position.
    pub fn index_tx(&self, tx_hash: &[u8], height: u64, tx_idx: u32) -> Result<()> {
        let mut value = [0u8; 12];
        value[..8].copy_from_slice(&height.to_le_bytes());
        value[8..].copy_from_slice(&tx_idx.to_le_bytes());
        self.tx_index.insert(tx_hash, &value)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Look up a transaction's block height and index within that block.
    pub fn get_tx_location(&self, tx_hash: &[u8]) -> Option<(u64, u32)> {
        match self.tx_index.get(tx_hash) {
            Ok(Some(data)) if data.len() >= 12 => {
                let height = u64::from_le_bytes(data[..8].try_into().unwrap());
                let tx_idx = u32::from_le_bytes(data[8..12].try_into().unwrap());
                Some((height, tx_idx))
            }
            _ => None,
        }
    }

    /// Remove a transaction from the index (used during reorgs).
    pub fn remove_tx_index(&self, tx_hash: &[u8]) {
        let _ = self.tx_index.remove(tx_hash);
    }

    /// Check if the tx_index tree is empty (for migration).
    pub fn tx_index_is_empty(&self) -> bool {
        self.tx_index.is_empty()
    }

    // ── Atomic reorg state transition ──────────────────────────────────────
    //
    // SECURITY: During a chain reorg, the output_index, height_index, state,
    // and tx_index trees must all transition atomically. A crash between
    // individual writes leaves the DB in a state where height mappings exist
    // but output_index entries don't (or vice versa), causing ring member
    // validation failures and wallet scan errors after restart.
    //
    // Sled's `Transactional` trait supports atomic multi-tree transactions.
    // We collect all mutations into a single `trees.transaction(|..| { })` call.

    /// Atomically apply a reorg's persistent state transition.
    ///
    /// All output_index removals, output_index additions, height→hash updates,
    /// height removals, state update, and tx_index changes land together or
    /// not at all. Called from `chain.rs` after in-memory UTXO set is already
    /// updated and all fork blocks are validated.
    pub fn apply_reorg_atomic(
        &self,
        // Output index entries to remove (disconnected blocks' output stealth keys)
        output_removals: &[[u8; 32]],
        // Output index entries to add (fork blocks' outputs): (stealth, serialized_entry)
        output_additions: &[([u8; 32], Vec<u8>)],
        // Height→hash mappings to set (fork blocks + new tip)
        height_sets: &[(u64, [u8; 32])],
        // Heights to remove (stale main-chain heights above new tip)
        height_removals: &[u64],
        // New chain state (serialized)
        new_state: &[u8],
        // Tx index additions: (tx_hash, height, tx_idx)
        tx_index_adds: &[([u8; 32], u64, u32)],
        // Tx index removals: tx_hash bytes
        tx_index_removes: &[[u8; 32]],
    ) -> Result<()> {
        use shim::transaction::Transactional;

        // Pre-compute oldest-wins additions: the transaction closure must
        // be purely writes (shim TxTree reads pass through to committed
        // state, not the pending batch), so do the "already present" check
        // up-front against the committed DB.
        let mut oi_to_insert: Vec<(&[u8; 32], &Vec<u8>)> = Vec::new();
        for (stealth, entry_bytes) in output_additions {
            if self.output_index.tree.get(stealth.as_slice())
                .map_err(|e| Error::DatabaseError(e.to_string()))?
                .is_none()
            {
                oi_to_insert.push((stealth, entry_bytes));
            }
        }

        let trees: &[&shim::Tree] = &[
            &self.output_index.tree,
            &self.blocks.height_index,
            &self.state.state,
            &self.tx_index,
        ];

        trees.transaction(|tx_trees| {
            let oi_tree = &tx_trees[0];
            let hi_tree = &tx_trees[1];
            let st_tree = &tx_trees[2];
            let ti_tree = &tx_trees[3];

            // 1. Remove disconnected outputs from output_index
            for stealth in output_removals {
                oi_tree.remove(stealth.as_slice())?;
            }

            // 2. Add fork-block outputs (filtered for oldest-wins above)
            for (stealth, entry_bytes) in &oi_to_insert {
                oi_tree.insert(stealth.as_slice(), entry_bytes.as_slice())?;
            }

            // 3. Set height→hash for fork blocks + new tip
            for (height, hash) in height_sets {
                hi_tree.insert(&height.to_be_bytes(), hash.as_slice())?;
            }

            // 4. Remove stale heights above new tip
            for height in height_removals {
                hi_tree.remove(&height.to_be_bytes())?;
            }

            // 5. Update chain state
            st_tree.insert(b"chain_state", new_state)?;

            // 6. Update tx index
            for hash in tx_index_removes {
                ti_tree.remove(hash.as_slice())?;
            }
            for (hash, height, tx_idx) in tx_index_adds {
                let mut value = [0u8; 12];
                value[..8].copy_from_slice(&height.to_le_bytes());
                value[8..].copy_from_slice(&tx_idx.to_le_bytes());
                ti_tree.insert(hash.as_slice(), &value)?;
            }

            Ok(())
        }).map_err(|e: shim::transaction::TransactionError| {
            Error::DatabaseError(format!("Atomic reorg transaction failed: {:?}", e))
        })?;

        // Sync to disk after atomic transaction completes
        self.flush()?;

        Ok(())
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Best-effort flush — calls sync flush and logs any error.
    /// For critical writes, use `flush()` which returns a Result.
    pub fn flush_best_effort(&self) {
        if let Err(e) = self.db.flush() {
            tracing::error!("Database flush failed: {}. Data may be lost on crash.", e);
        }
    }

    /// Get database size in bytes
    pub fn size_on_disk(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }

    /// Open (or lazily create) a column family by name. Used by
    /// standalone stores — e.g. the Phase 2 Spark/shielded/MW-kernel
    /// stores — that want their own trees without living inside the
    /// main `Database` struct.
    pub fn open_tree(&self, name: &str) -> Result<shim::Tree> {
        self.db
            .open_tree(name)
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Get human-readable database size
    pub fn size_on_disk_formatted(&self) -> String {
        let bytes = self.size_on_disk();
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /// Get database statistics for monitoring.
    /// Returns (total_entries_across_trees, disk_size_bytes).
    pub fn cache_stats(&self) -> (u64, u64) {
        let entries = self.db.tree_names().iter().filter_map(|name| {
            let name_str = std::str::from_utf8(name).ok()?;
            self.db.open_tree(name_str).ok().map(|t| t.len() as u64)
        }).sum::<u64>();
        (entries, self.size_on_disk())
    }

    /// Generate a monotonically increasing ID
    pub fn generate_id(&self) -> Result<u64> {
        self.db.generate_id()
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Check if database was recovered from crash
    pub fn was_recovered(&self) -> bool {
        self.db.was_recovered()
    }

    /// Export database statistics
    pub fn stats(&self) -> DbStats {
        DbStats {
            size_bytes: self.size_on_disk(),
            was_recovered: self.was_recovered(),
            tree_count: 8, // blocks, utxos, state, keys, wallet, mempool, assets, output_index
        }
    }
}

/// Database statistics
#[derive(Clone, Debug)]
pub struct DbStats {
    pub size_bytes: u64,
    pub was_recovered: bool,
    pub tree_count: usize,
}

/// Helper to serialize data for storage
pub fn serialize<T: borsh::BorshSerialize>(value: &T) -> Result<Vec<u8>> {
    borsh::to_vec(value)
        .map_err(|e| Error::SerializationError(e.to_string()))
}

/// Helper to deserialize data from storage
pub fn deserialize<T: borsh::BorshDeserialize>(bytes: &[u8]) -> Result<T> {
    borsh::from_slice(bytes)
        .map_err(|e| Error::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_open() {
        let dir = tempdir().unwrap();
        let db = Database::open(dir.path()).unwrap();
        // Database opened successfully - size might be 0 on fresh empty DB
        // Just verify it doesn't error
        let _ = db.size_on_disk();
        assert!(db.flush().is_ok());
    }

    #[test]
    fn test_database_config() {
        let dir = tempdir().unwrap();
        let db1 = Database::open(dir.path()).unwrap();
        db1.flush().unwrap();
        drop(db1);
        // Re-open same path should work (not corrupt)
        let db2 = Database::open(dir.path()).unwrap();
        assert!(db2.flush().is_ok());
    }
}
