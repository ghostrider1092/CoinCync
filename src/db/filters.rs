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

        // Recover tip height from last entry
        let tip_height = match filters.last() {
            Ok(Some((key, _))) => {
                u64::from_be_bytes(key.as_ref().try_into().unwrap_or([0u8; 8]))
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
    pub fn build_and_store(&mut self, block: &Block, prev_filter_hash: Hash) -> Result<BlockFilter> {
        let filter = BlockFilter::from_block(block, prev_filter_hash);
        let height = filter.height;

        let data = serialize(&filter)?;
        self.filters.insert(&height.to_be_bytes(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        if height > self.tip_height {
            self.tip_height = height;
        }

        // Store checkpoint every 1000 blocks
        if height % 1000 == 0 {
            let checkpoint = FilterCheckpoint {
                height,
                block_hash: filter.block_hash,
                filter_hash: filter.filter_hash(),
            };
            let cp_data = serialize(&checkpoint)?;
            self.checkpoints.insert(&height.to_be_bytes(), cp_data)
                .map_err(|e| Error::DatabaseError(e.to_string()))?;
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

    /// Get the previous filter hash for chaining.
    pub fn prev_filter_hash(&self, height: u64) -> Hash {
        if height == 0 {
            return Hash::default();
        }
        self.get(height - 1)
            .ok()
            .flatten()
            .map(|f| f.filter_hash())
            .unwrap_or_default()
    }

    /// Get filter checkpoints for verification.
    pub fn get_checkpoints(&self) -> Result<Vec<FilterCheckpoint>> {
        let mut checkpoints = Vec::new();
        for item in self.checkpoints.iter() {
            match item {
                Ok((_, data)) => {
                    let cp: FilterCheckpoint = deserialize(&data)?;
                    checkpoints.push(cp);
                }
                Err(e) => {
                    tracing::warn!("Error reading filter checkpoint: {}", e);
                    break;
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
