//! # Block Database
//!
//! Persistent storage for blocks.

use crate::db::shim::{Db, Tree, transaction::Transactional};
use crate::primitives::Hash;
use crate::consensus::Block;
use crate::error::{Error, Result};
use super::{serialize, deserialize};

/// Block storage
#[allow(dead_code)]
pub struct BlockDb {
    /// Blocks by hash
    blocks: Tree,
    /// Block hash by height index
    pub(crate) height_index: Tree,
    /// Block metadata
    meta: Tree,
    /// Pruned block headers (height -> compact header bytes)
    pruned_headers: Tree,
}

impl BlockDb {
    /// Create new block database
    pub fn new(db: &Db) -> Result<Self> {
        let blocks = db.open_tree("blocks")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let height_index = db.open_tree("block_heights")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let meta = db.open_tree("block_meta")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let pruned_headers = db.open_tree("pruned_blocks")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(BlockDb {
            blocks,
            height_index,
            meta,
            pruned_headers,
        })
    }

    /// True if no blocks have been stored yet.
    ///
    /// Used by `Database::open_with_config` to distinguish "fresh DB
    /// from genesis" (legitimate first-stamp of schema_version) from
    /// "existing DB with no schema_version stamp" (legacy v0 DB, must
    /// not silently auto-migrate). See `verify_or_stamp_schema_version`
    /// in `db/mod.rs`.
    ///
    /// Checks the `blocks` tree specifically because that's the
    /// authoritative "real chain data exists" signal — the other
    /// trees (height_index, meta, pruned) are derived from / indexed
    /// against it.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Store a block (block data only, by hash)
    ///
    /// SECURITY (M-1): Split from old insert() which unconditionally overwrote
    /// the height index. Now the height index is only updated via set_height_hash()
    /// for main chain blocks, preventing fork blocks from corrupting it.
    pub fn insert(&self, block: &Block) -> Result<()> {
        let hash = block.hash();

        // Serialize block
        let block_data = serialize(block)?;

        // Store block by hash only
        self.blocks.insert(hash.as_bytes(), block_data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Update height -> hash index (main chain blocks only)
    ///
    /// Uses big-endian encoding so sled's lexicographic ordering matches
    /// numeric height ordering (required for `last()` to return the true tip).
    pub fn set_height_hash(&self, height: u64, hash: &Hash) -> Result<()> {
        self.height_index.insert(&height.to_be_bytes(), hash.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove height -> hash index entry (for reorg cleanup)
    ///
    /// Removes stale height entries above the new tip after a reorg,
    /// preventing `height()` from returning an incorrect tip height.
    pub fn remove_height_hash(&self, height: u64) -> Result<()> {
        self.height_index.remove(&height.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove all height→hash mappings above a given height.
    /// Used after reorgs to clean up stale entries from the old chain.
    /// Keys are 8-byte big-endian u64, so we scan from max_valid_height+1.
    pub fn remove_heights_above(&self, max_valid_height: u64) -> Result<u64> {
        let mut removed = 0u64;
        // Scan from max_valid_height+1 using sled's range scan on BE keys
        let start = (max_valid_height + 1).to_be_bytes();
        for item in self.height_index.range(start..) {
            match item {
                Ok((key, _)) => {
                    self.height_index.remove(&key)
                        .map_err(|e| Error::DatabaseError(e.to_string()))?;
                    removed += 1;
                }
                Err(e) => {
                    tracing::warn!("Error scanning height index: {}", e);
                    break;
                }
            }
        }
        if removed > 0 {
            tracing::info!("Cleaned {} stale height mappings above height {}", removed, max_valid_height);
        }
        Ok(removed)
    }

    /// Get block by hash
    pub fn get(&self, hash: &Hash) -> Result<Option<Block>> {
        match self.blocks.get(hash.as_bytes()) {
            Ok(Some(data)) => {
                let block: Block = deserialize(&data)?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Get block by height
    pub fn get_by_height(&self, height: u64) -> Result<Option<Block>> {
        match self.height_index.get(&height.to_be_bytes()) {
            Ok(Some(hash_bytes)) => {
                if let Some(hash) = Hash::from_slice(&hash_bytes) {
                    self.get(&hash)
                } else {
                    Ok(None)
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Get block hash by height
    pub fn get_hash_by_height(&self, height: u64) -> Result<Option<Hash>> {
        match self.height_index.get(&height.to_be_bytes()) {
            Ok(Some(hash_bytes)) => Ok(Hash::from_slice(&hash_bytes)),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Check if block exists
    pub fn contains(&self, hash: &Hash) -> Result<bool> {
        self.blocks.contains_key(hash.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Get highest block height
    ///
    /// Uses `last()` on the height index, which works correctly because
    /// heights are stored as big-endian bytes (lexicographic == numeric order).
    ///
    /// A malformed (non-8-byte) key is treated as database corruption and
    /// surfaces as a `DatabaseError` — silently defaulting to 0 was the
    /// prior behaviour and would have masked corruption as a legitimate
    /// "genesis tip" reading, which is consensus-relevant.
    pub fn height(&self) -> Result<u64> {
        match self.height_index.last() {
            Ok(Some((key, _))) => {
                let key_bytes = key.as_ref();
                let arr: [u8; 8] = key_bytes.try_into().map_err(|_| {
                    Error::DatabaseError(format!(
                        "height_index key has unexpected length {} (expected 8); \
                         block database may be corrupted",
                        key_bytes.len()
                    ))
                })?;
                Ok(u64::from_be_bytes(arr))
            }
            Ok(None) => Ok(0),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Get the tip block
    pub fn tip(&self) -> Result<Option<Block>> {
        let height = self.height()?;
        self.get_by_height(height)
    }

    /// Delete a block (for reorg)
    ///
    /// SECURITY (C12-FIX): Uses sled multi-tree transaction to atomically remove
    /// the block data and its height index entry. Previously these were separate
    /// operations — a crash between them could leave orphaned entries.
    /// Only removes the height index entry if it points to THIS block's hash.
    pub fn delete(&self, hash: &Hash) -> Result<Option<Block>> {
        // Get block first to return it (read-only, before the atomic write)
        let block = self.get(hash)?;

        if let Some(ref b) = block {
            let height_key = b.height().to_be_bytes();
            let hash_bytes = hash.as_bytes().to_vec();

            // Check if height index points to this block
            let should_remove_height = self.height_index.get(&height_key)
                .map_err(|e| Error::DatabaseError(e.to_string()))?
                .map(|stored| stored.as_ref() == hash.as_bytes())
                .unwrap_or(false);

            // SECURITY (C12-FIX): Atomic transaction: remove block + height index together
            let trees: &[&Tree] = &[&self.blocks, &self.height_index];
            trees.transaction(|tx_trees| {
                tx_trees[0].remove(hash_bytes.as_slice())?;
                if should_remove_height {
                    tx_trees[1].remove(height_key.as_slice())?;
                }
                Ok(())
            }).map_err(|e: crate::db::shim::transaction::TransactionError| {
                Error::DatabaseError(format!("Atomic block delete failed: {:?}", e))
            })?;
        } else {
            // Block not found by get(), still try to remove raw data
            self.blocks.remove(hash.as_bytes())
                .map_err(|e| Error::DatabaseError(e.to_string()))?;
        }

        Ok(block)
    }

    /// Get blocks in height range
    pub fn get_range(&self, start_height: u64, end_height: u64) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();

        for height in start_height..=end_height {
            if let Some(block) = self.get_by_height(height)? {
                blocks.push(block);
            }
        }

        Ok(blocks)
    }

    /// Count total blocks
    pub fn count(&self) -> usize {
        self.blocks.len()
    }

    /// Iterate all blocks
    pub fn iter(&self) -> impl Iterator<Item = Result<Block>> + '_ {
        self.blocks.iter().map(|result| {
            match result {
                Ok((_, data)) => deserialize(&data),
                Err(e) => Err(Error::DatabaseError(e.to_string())),
            }
        })
    }

    /// Store a pruned block header (compact data replacing the full block)
    pub fn store_pruned_header(&self, height: u64, data: &[u8]) -> Result<()> {
        self.pruned_headers.insert(&height.to_be_bytes(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove full block data by height (used during pruning)
    ///
    /// Looks up the block hash via the height index, then removes the full
    /// block from the blocks tree. The height index entry is preserved so
    /// that `has_pruned_header` can still locate the pruned header.
    pub fn remove_by_height(&self, height: u64) -> Result<()> {
        if let Some(hash_bytes) = self.height_index.get(&height.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?
        {
            self.blocks.remove(&hash_bytes)
                .map_err(|e| Error::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }

    /// Check if a pruned header exists for the given height
    pub fn has_pruned_header(&self, height: u64) -> bool {
        self.pruned_headers.contains_key(&height.to_be_bytes()).unwrap_or(false)
    }

    /// Get a pruned header by height (raw bytes)
    pub fn get_pruned_header(&self, height: u64) -> Result<Option<Vec<u8>>> {
        match self.pruned_headers.get(&height.to_be_bytes()) {
            Ok(Some(data)) => Ok(Some(data.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::chain::create_genesis_block;

    #[test]
    fn test_block_storage() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let block_db = BlockDb::new(&db).unwrap();

        let genesis = create_genesis_block();
        let hash = genesis.hash();

        block_db.insert(&genesis).unwrap();

        assert!(block_db.contains(&hash).unwrap());
        assert_eq!(block_db.height().unwrap(), 0);

        let loaded = block_db.get(&hash).unwrap().unwrap();
        assert_eq!(loaded.hash(), hash);
    }
}
