//! # Block Filter Database
//!
//! Persistent storage for compact block filters (BIP158-style GCS).
//! Network (Tier 2) and Archive (Tier 3) nodes build and store filters
//! for every block, then serve them to Personal (Tier 1) nodes on request.

use crate::db::shim::{Db, Tree};
use crate::primitives::Hash;
use crate::consensus::Block;
use crate::network::block_filter::{BlockFilter, FilterCheckpoint};
use crate::error::{Error, Result};
use super::{serialize, deserialize};

/// Persistent block filter storage.
///
/// Stores GCS filters indexed by block height (big-endian for correct ordering).
/// Typical size: ~150 bytes per filter × 1M blocks = ~150 MB on disk.
pub struct FilterDb {
    /// Filters by height (BE u64 key → serialized BlockFilter)
    filters: Tree,
    /// Filter checkpoints (every 1000 blocks)
    checkpoints: Tree,
    /// Highest filter height stored
    tip_height: u64,
}

impl FilterDb {
    /// Open a standalone filter database at a specific path.
    /// Used by FilterService for dedicated filter storage.
    pub fn open_at(path: &std::path::Path) -> Result<Self> {
        let db = crate::db::shim::open(path)
            .map_err(|e| Error::DatabaseError(format!("Failed to open filter DB: {}", e)))?;
        Self::new(&db)
    }

    /// Open or create the filter database from an existing sled Db handle.
    pub fn new(db: &Db) -> Result<Self> {
        let filters = db.open_tree("block_filters")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let checkpoints = db.open_tree("filter_checkpoints")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        // Recover tip height from last entry. A malformed (non-8-byte)
        // filter index key is treated as DB corruption and propagated
        // — silently coercing to 0 would mask the corruption as "no
        // filters yet" and cause the node to re-download from genesis.
        let tip_height = match filters.last() {
            Ok(Some((key, _))) => {
                let key_bytes = key.as_ref();
                let arr: [u8; 8] = key_bytes.try_into().map_err(|_| {
                    Error::DatabaseError(format!(
                        "filter index tip key has unexpected length {} (expected 8); \
                         filter database may be corrupted",
                        key_bytes.len()
                    ))
                })?;
                u64::from_be_bytes(arr)
            }
            _ => 0,
        };

        Ok(FilterDb {
            filters,
            checkpoints,
            tip_height,
        })
    }

    /// Build and store a filter for a block.
    /// Returns the filter for immediate use.
    ///
    /// AUDIT (R-47 fix, 2026-07-03): pre-fix code did two separate
    /// writes — filter insert, then (every 1000 blocks) checkpoint
    /// insert. A crash between them left the filter tree ahead of
    /// checkpoints, so a personal-node consumer that fetched the
    /// filter and cross-checked against the checkpoint tree got a
    /// "checkpoint missing" for a height where the filter did land
    /// — legitimate-looking but wrong. Bundle both writes in a
    /// single Transactional batch. `tip_height` update is in-memory
    /// only, so it doesn't need to be part of the atomic set.
    pub fn build_and_store(&mut self, block: &Block, prev_filter_hash: Hash) -> Result<BlockFilter> {
        let filter = BlockFilter::from_block(block, prev_filter_hash);
        let height = filter.height;

        let data = serialize(&filter)?;
        let height_key = height.to_be_bytes();
        let checkpoint_pair = if height % 1000 == 0 {
            let checkpoint = FilterCheckpoint {
                height,
                block_hash: filter.block_hash,
                filter_hash: filter.filter_hash(),
            };
            Some(serialize(&checkpoint)?)
        } else {
            None
        };

        use crate::db::shim::transaction::Transactional;
        let trees: &[&Tree] = &[&self.filters, &self.checkpoints];
        trees.transaction(|tx| {
            tx[0].insert(&height_key[..], data.as_slice())?;
            if let Some(ref cp_data) = checkpoint_pair {
                tx[1].insert(&height_key[..], cp_data.as_slice())?;
            }
            Ok(())
        }).map_err(|e| Error::DatabaseError(format!(
            "R-47: atomic filter+checkpoint commit failed at height {}: {:?}",
            height, e
        )))?;

        if height > self.tip_height {
            self.tip_height = height;
        }

        Ok(filter)
    }

    /// Get filter for a specific height.
    pub fn get(&self, height: u64) -> Result<Option<BlockFilter>> {
        match self.filters.get(&height.to_be_bytes()) {
            Ok(Some(data)) => {
                let filter: BlockFilter = deserialize(&data)?;
                Ok(Some(filter))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Get filters for a height range (for serving to personal nodes).
    /// Bounded to MAX_FILTER_BATCH to prevent DoS.
    pub fn get_range(&self, start: u64, end: u64) -> Result<Vec<BlockFilter>> {
        const MAX_FILTER_BATCH: u64 = 1000;
        let end = end.min(start.saturating_add(MAX_FILTER_BATCH));

        let mut filters = Vec::new();
        for height in start..=end {
            if let Some(filter) = self.get(height)? {
                filters.push(filter);
            }
        }
        Ok(filters)
    }

    // AUDIT (2026-07-01): removed the `prev_filter_hash(height) -> Hash`
    // helper. Two problems:
    //
    //   1. Zero external callers. The one code path that chains filters —
    //      `network/node.rs` line ~3936 — carries its own `prev_filter_hash`
    //      variable through the build loop and never calls this method.
    //      Delete it and the chain-continuity API surface stays honest.
    //
    //   2. Silent error-swallowing footgun. The old body was
    //      `self.get(height - 1).ok().flatten().map(...).unwrap_or_default()`
    //      which coerces any RocksDB error (I/O failure, WAL corruption,
    //      partial-page read) into `Hash::default()` — a valid-looking
    //      "no filter yet" answer. Any future caller wiring this into
    //      chain-continuity validation would silently accept a zeroed
    //      link across the corruption point. Removing the method is
    //      safer than "fix" via `?`-propagation, because there is no
    //      caller to accept the new `Result<Hash>` signature and the
    //      silent-error variant would be one refactor away from
    //      returning.
    //
    // If a caller ever needs prev-filter-hash lookup, wire it directly
    // via `self.get(height - 1)?` — that call is already `Result`-returning
    // and will surface a rocksdb::Error properly. Reference: Bitcoin
    // Core's `GetFilterHeader` returns `Status`, not a coerced default.

    /// Get filter checkpoints for verification.
    ///
    /// AUDIT (R-48 fix, 2026-07-03): the pre-fix code hit an
    /// iterator error and did `tracing::warn!(...); break;` —
    /// silently returning the partial list of checkpoints
    /// collected so far. A downstream consumer (checkpoint-cross-
    /// check for personal nodes) would then verify against a
    /// TRUNCATED checkpoint list and think the missing tail is
    /// legitimate. If the tail contained the checkpoint the
    /// consumer needed, that's a silent verification bypass.
    ///
    /// Fix: on iterator error, return `Err(...)` immediately.
    /// Consumers get an explicit signal that the checkpoint set
    /// is unreadable and can decide whether to retry, block, or
    /// fall through to a slower verification path. NEVER silently
    /// truncate a consensus-relevant list.
    pub fn get_checkpoints(&self) -> Result<Vec<FilterCheckpoint>> {
        let mut checkpoints = Vec::new();
        for item in self.checkpoints.iter() {
            match item {
                Ok((_, data)) => {
                    let cp: FilterCheckpoint = deserialize(&data)?;
                    checkpoints.push(cp);
                }
                Err(e) => {
                    return Err(Error::DatabaseError(format!(
                        "R-48: filter-checkpoint iteration failed after {} entries — \
                         refusing to return a truncated checkpoint set. Underlying: {}",
                        checkpoints.len(), e
                    )));
                }
            }
        }
        Ok(checkpoints)
    }

    /// Get the highest stored filter height.
    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// Count stored filters.
    pub fn count(&self) -> usize {
        self.filters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::chain::create_genesis_block;

    #[test]
    fn test_filter_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let mut filter_db = FilterDb::new(&db).unwrap();

        let genesis = create_genesis_block();
        let prev_hash = Hash::default();

        let filter = filter_db.build_and_store(&genesis, prev_hash).unwrap();
        assert_eq!(filter.height, 0);

        let loaded = filter_db.get(0).unwrap().unwrap();
        assert_eq!(loaded.block_hash, filter.block_hash);
        assert_eq!(loaded.height, 0);
    }

    #[test]
    fn test_filter_range() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let filter_db = FilterDb::new(&db).unwrap();

        // Empty range returns empty
        let filters = filter_db.get_range(0, 10).unwrap();
        assert!(filters.is_empty());
    }
}
