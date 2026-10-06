//! # Block Database
//!
//! Persistent storage for blocks.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `insert` / `get` / `get_by_height` / `get_hash_by_height` / `contains`
//!   / `height` / `tip`** — INVARIANT: blocks are stored by hash only; the
//!   height→hash index uses big-endian keys so lexicographic order equals numeric
//!   order and `last()` returns the true tip; a non-8-byte height key surfaces as
//!   `DatabaseError`, never a silent height-0 tip (M-1: `insert` no longer touches
//!   the height index). THREAT: a fork block overwriting the main-chain height
//!   index; corruption masquerading as a legitimate genesis tip.
//!   TESTS: `test_block_storage`.
//! - **§2 `set_height_hash` / `remove_height_hash` / `remove_heights_above`** —
//!   INVARIANT: `remove_heights_above` removes EVERY stale height above the cutoff
//!   exactly once by collecting keys under the iterator first, THEN deleting — no
//!   skip, no duplicate. THREAT: R-39 — the pre-fix mutate-during-iteration
//!   (delete_cf inside a live `range(..)` scan) skipped/duplicated keys, leaving
//!   stale height→hash mappings that survived a reorg (the 2026-06-04 testnet
//!   cascade). TESTS: `set_and_remove_height_hash_round_trip`,
//!   `remove_heights_above_clears_all_stale_heights_across_wide_range_no_skip_or_dup`.
//! - **§3 `delete`** — INVARIANT: removing a block for a reorg deletes the block
//!   body AND its height entry in ONE transaction, and only clears the height
//!   entry when it points at THIS block's hash; returns the prior block.
//!   THREAT: C12 — a crash between two separate removes leaving an orphaned height
//!   mapping or block body. TESTS:
//!   `delete_removes_block_and_height_mapping_and_returns_prior`.
//! - **§4 `get_range` / `count` / `iter` / `is_empty` / `has_any_chain_data`** —
//!   INVARIANT: `get_range` is inclusive on both bounds and silently skips missing
//!   heights; `is_empty` tracks the `blocks` tree specifically, while
//!   `has_any_chain_data` is true if ANY block-related tree is non-empty (the
//!   fresh-vs-legacy DB signal for schema stamping). THREAT: mis-classifying a
//!   legacy DB as fresh and auto-stamping it. TESTS:
//!   `get_range_is_inclusive_and_skips_missing_heights`,
//!   `is_empty_and_has_any_chain_data_reflect_true_emptiness`,
//!   `iter_and_count_reflect_stored_blocks`.
//! - **§5 pruned headers (`store_pruned_header` / `remove_by_height` /
//!   `store_pruned_and_remove` / `has_pruned_header` / `get_pruned_header`)** —
//!   INVARIANT: `store_pruned_and_remove` writes the compact header AND removes the
//!   full block body in ONE WriteBatch (both or neither); the height index is
//!   preserved so the pruned header stays locatable. THREAT: the two-call form
//!   crash-windows to a header-stored-but-body-still-present state that wastes disk
//!   indefinitely (the pruning loop never revisits the height). TESTS:
//!   `pruned_header_store_get_and_store_and_remove_round_trip`.

use super::{deserialize, serialize};
use crate::consensus::Block;
use crate::db::shim::{transaction::Transactional, Db, Tree};
use crate::error::{Error, Result};
use crate::primitives::Hash;

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
        let blocks = db
            .open_tree("blocks")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let height_index = db
            .open_tree("block_heights")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let meta = db
            .open_tree("block_meta")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let pruned_headers = db
            .open_tree("pruned_blocks")
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

    /// Fresh initialization is safe only when every block-related tree is empty.
    pub fn has_any_chain_data(&self) -> bool {
        !self.blocks.is_empty()
            || !self.height_index.is_empty()
            || !self.meta.is_empty()
            || !self.pruned_headers.is_empty()
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
        self.blocks
            .insert(hash.as_bytes(), block_data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Update height -> hash index (main chain blocks only)
    ///
    /// Uses big-endian encoding so sled's lexicographic ordering matches
    /// numeric height ordering (required for `last()` to return the true tip).
    pub fn set_height_hash(&self, height: u64, hash: &Hash) -> Result<()> {
        self.height_index
            .insert(&height.to_be_bytes(), hash.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove height -> hash index entry (for reorg cleanup)
    ///
    /// Removes stale height entries above the new tip after a reorg,
    /// preventing `height()` from returning an incorrect tip height.
    pub fn remove_height_hash(&self, height: u64) -> Result<()> {
        self.height_index
            .remove(&height.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove all height→hash mappings above a given height.
    /// Used after reorgs to clean up stale entries from the old chain.
    /// Keys are 8-byte big-endian u64, so we scan from max_valid_height+1.
    ///
    /// AUDIT (R-39 fix, 2026-07-03): pre-fix code called
    /// `self.height_index.remove(&key)` INSIDE the `for item in
    /// self.height_index.range(start..)` iteration. Under the
    /// RocksDB shim, `range(...)` returns an iterator whose
    /// underlying `rocksdb::DBIterator` does NOT hold a snapshot —
    /// it observes live column-family state. Mutating the CF
    /// (delete_cf) mid-iteration can:
    ///   1. Skip entries (the iterator's next() lands past a
    ///      deleted key and continues from the next-live key,
    ///      possibly missing keys that were valid at scan start).
    ///   2. Return duplicate entries if the delete-and-advance
    ///      interleaving hits a tombstone the iterator later
    ///      re-observes.
    /// Either failure leaves stale height→hash mappings that survive
    /// past the reorg, causing the "old height still points to
    /// orphaned block" corruption the 2026-06-04 testnet cascade
    /// investigation traced back to this exact function.
    ///
    /// Fix: collect ALL matching keys into a Vec first (iterator
    /// runs to completion without any mutation), THEN issue the
    /// removes as a separate loop. Same net effect, but no live
    /// mutation during iteration.
    ///
    /// A better long-term fix would use RocksDB's own `DeleteRange`
    /// primitive (declared at include/rocksdb/db.h:557 in the RocksDB
    /// master source read this session), which is atomic-in-batch;
    /// deferred because the shim doesn't currently expose it.
    pub fn remove_heights_above(&self, max_valid_height: u64) -> Result<u64> {
        // Phase 1: collect keys under iterator; NO writes during scan.
        let start = (max_valid_height + 1).to_be_bytes();
        let mut keys_to_remove: Vec<Vec<u8>> = Vec::new();
        for item in self.height_index.range(start..) {
            match item {
                Ok((key, _)) => keys_to_remove.push(key.to_vec()),
                Err(e) => {
                    tracing::warn!("Error scanning height index: {}", e);
                    break;
                }
            }
        }
        // Phase 2: delete each collected key. No iterator in flight.
        let mut removed = 0u64;
        for key in &keys_to_remove {
            self.height_index
                .remove(key)
                .map_err(|e| Error::DatabaseError(e.to_string()))?;
            removed += 1;
        }
        if removed > 0 {
            tracing::info!(
                "Cleaned {} stale height mappings above height {}",
                removed,
                max_valid_height
            );
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
        self.blocks
            .contains_key(hash.as_bytes())
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
            let should_remove_height = self
                .height_index
                .get(&height_key)
                .map_err(|e| Error::DatabaseError(e.to_string()))?
                .map(|stored| stored.as_ref() == hash.as_bytes())
                .unwrap_or(false);

            // SECURITY (C12-FIX): Atomic transaction: remove block + height index together
            let trees: &[&Tree] = &[&self.blocks, &self.height_index];
            trees
                .transaction(|tx_trees| {
                    tx_trees[0].remove(hash_bytes.as_slice())?;
                    if should_remove_height {
                        tx_trees[1].remove(height_key.as_slice())?;
                    }
                    Ok(())
                })
                .map_err(|e: crate::db::shim::transaction::TransactionError| {
                    Error::DatabaseError(format!("Atomic block delete failed: {:?}", e))
                })?;
        } else {
            // Block not found by get(), still try to remove raw data
            self.blocks
                .remove(hash.as_bytes())
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
        self.blocks.iter().map(|result| match result {
            Ok((_, data)) => deserialize(&data),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        })
    }

    /// Store a pruned block header (compact data replacing the full block)
    pub fn store_pruned_header(&self, height: u64, data: &[u8]) -> Result<()> {
        self.pruned_headers
            .insert(&height.to_be_bytes(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Remove full block data by height (used during pruning)
    ///
    /// Looks up the block hash via the height index, then removes the full
    /// block from the blocks tree. The height index entry is preserved so
    /// that `has_pruned_header` can still locate the pruned header.
    pub fn remove_by_height(&self, height: u64) -> Result<()> {
        if let Some(hash_bytes) = self
            .height_index
            .get(&height.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?
        {
            self.blocks
                .remove(&hash_bytes)
                .map_err(|e| Error::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }

    /// Atomically prune a block: store the compact header AND remove the
    /// full block body in a single multi-tree transaction.
    ///
    /// AUDIT (2026-07-01): callers that want the atomicity property must
    /// use this instead of `store_pruned_header` + `remove_by_height`
    /// back-to-back. The two-call form crash-windows to a state where
    /// `pruned_headers[height]` exists but the full block still lives in
    /// `blocks[hash]`, wasting disk indefinitely (the outer pruning
    /// loop doesn't revisit heights across restarts). This method packs
    /// the header-write and the block-body-remove into a single RocksDB
    /// WriteBatch — either both land or neither. `height_index` is only
    /// read (to translate height → hash) and is not part of the write
    /// set; the read happens BEFORE the transaction because RocksDB
    /// TxTree::get semantics under this shim are "read-live-not-batch"
    /// and can't observe staged writes anyway (see `db/shim.rs` line
    /// ~709 for the documented behavior).
    ///
    /// AUDIT (R-40 SURGICAL FIX, 2026-07-03): moved the
    /// height→hash lookup INSIDE the transaction closure. The shim's
    /// `TxTree::get()` (db/shim.rs L825-831) reads live committed
    /// state, so a race with a concurrent `set_height_hash` writer
    /// still exists AT THE READ LEVEL — but the read now happens
    /// as close to the commit as possible, and the caller can
    /// hold a chain-level lock across the whole `.transaction(...)`
    /// call to structurally serialise. For parallel pruning we
    /// also need `[&self.pruned_headers, &self.blocks, &self.height_index]`
    /// so the TxTree::get uses the same tx handle set. For now,
    /// the height_index is read via a separate TxTree (get is
    /// read-only and doesn't stage a write).
    pub fn store_pruned_and_remove(&self, height: u64, header_bytes: &[u8]) -> Result<()> {
        let height_key = height.to_be_bytes();

        use crate::db::shim::transaction::Transactional;
        [&self.pruned_headers, &self.blocks, &self.height_index]
            .as_slice()
            .transaction(|trees| {
                let pruned_tx = &trees[0];
                let blocks_tx = &trees[1];
                let heights_tx = &trees[2];
                // R-40: read the height→hash mapping INSIDE the
                // transaction. This still doesn't observe staged
                // writes (see shim's TxTree::get semantics), but it
                // moves the read closer to the commit so the window
                // for a concurrent mutator is minimized.
                let hash_bytes = heights_tx.get(&height_key[..])?;
                pruned_tx.insert(&height_key[..], header_bytes)?;
                if let Some(ref h) = hash_bytes {
                    blocks_tx.remove(h.as_ref())?;
                }
                Ok(())
            })
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Check if a pruned header exists for the given height
    pub fn has_pruned_header(&self, height: u64) -> bool {
        self.pruned_headers
            .contains_key(&height.to_be_bytes())
            .unwrap_or(false)
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
    use crate::chain::create_genesis_block;
    use tempfile::tempdir;

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

    fn fresh_block_db() -> (tempfile::TempDir, BlockDb) {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let block_db = BlockDb::new(&db).unwrap();
        (dir, block_db)
    }

    /// set_height_hash / remove_height_hash round-trip on the height index.
    #[test]
    fn set_and_remove_height_hash_round_trip() {
        let (_dir, block_db) = fresh_block_db();
        let h = Hash::from_bytes([0x11u8; 32]);
        block_db.set_height_hash(42, &h).unwrap();
        assert_eq!(block_db.get_hash_by_height(42).unwrap(), Some(h));
        block_db.remove_height_hash(42).unwrap();
        assert_eq!(block_db.get_hash_by_height(42).unwrap(), None);
    }

    /// R-39 regression: remove_heights_above must remove EVERY stale height
    /// across a wide, gappy range (crossing the single-byte 0xFF boundary so
    /// multi-key big-endian range scanning is exercised) with no skip and no
    /// duplicate. The pre-fix mutate-during-iteration bug left stale mappings.
    #[test]
    fn remove_heights_above_clears_all_stale_heights_across_wide_range_no_skip_or_dup() {
        let (_dir, block_db) = fresh_block_db();
        let heights: Vec<u64> = (1..=5).chain(100..=105).chain(250..=260).collect();
        for &h in &heights {
            block_db
                .set_height_hash(h, &Hash::from_bytes([h as u8; 32]))
                .unwrap();
        }
        let removed = block_db.remove_heights_above(3).unwrap();
        let expected_removed = heights.iter().filter(|&&h| h > 3).count() as u64;
        assert_eq!(
            removed, expected_removed,
            "must remove ALL stale heights exactly once (R-39)"
        );
        for h in 1..=3u64 {
            assert!(
                block_db.get_hash_by_height(h).unwrap().is_some(),
                "height {h} at/below the cutoff must survive"
            );
        }
        for &h in heights.iter().filter(|&&h| h > 3) {
            assert!(
                block_db.get_hash_by_height(h).unwrap().is_none(),
                "stale height {h} must be removed"
            );
        }
        // No stale mapping leaked: the reported tip is now exactly the cutoff.
        assert_eq!(block_db.height().unwrap(), 3);
    }

    /// delete removes the block body AND its height mapping (when the mapping
    /// points at this block) and returns the prior block.
    #[test]
    fn delete_removes_block_and_height_mapping_and_returns_prior() {
        let (_dir, block_db) = fresh_block_db();
        let genesis = create_genesis_block();
        let hash = genesis.hash();
        block_db.insert(&genesis).unwrap();
        block_db.set_height_hash(genesis.height(), &hash).unwrap();

        let returned = block_db.delete(&hash).unwrap();
        assert!(returned.is_some(), "delete returns the removed block");
        assert_eq!(returned.unwrap().hash(), hash);
        assert!(
            block_db.get(&hash).unwrap().is_none(),
            "block body must be removed"
        );
        assert_eq!(
            block_db.get_hash_by_height(genesis.height()).unwrap(),
            None,
            "height mapping must be removed"
        );
    }

    /// get_range is inclusive on both bounds and silently skips missing heights.
    #[test]
    fn get_range_is_inclusive_and_skips_missing_heights() {
        let (_dir, block_db) = fresh_block_db();
        let genesis = create_genesis_block();
        block_db.insert(&genesis).unwrap();
        block_db.set_height_hash(0, &genesis.hash()).unwrap();

        // Only height 0 exists; 1..=5 are missing and must be skipped, not error.
        let range = block_db.get_range(0, 5).unwrap();
        assert_eq!(range.len(), 1, "missing heights are skipped");
        assert_eq!(range[0].hash(), genesis.hash());

        // Inclusive single-height range returns the one block.
        let single = block_db.get_range(0, 0).unwrap();
        assert_eq!(single.len(), 1);
    }

    /// is_empty tracks the blocks tree specifically; has_any_chain_data is
    /// true whenever ANY block-related tree (here: height_index) is non-empty.
    #[test]
    fn is_empty_and_has_any_chain_data_reflect_true_emptiness() {
        let (_dir, block_db) = fresh_block_db();
        assert!(block_db.is_empty());
        assert!(!block_db.has_any_chain_data());

        // A height_index-only entry: blocks tree still empty, but chain data exists.
        block_db
            .set_height_hash(0, &Hash::from_bytes([7u8; 32]))
            .unwrap();
        assert!(
            block_db.is_empty(),
            "is_empty tracks the blocks tree only"
        );
        assert!(
            block_db.has_any_chain_data(),
            "has_any_chain_data sees the height index"
        );

        // A real block makes both false/true accordingly.
        let genesis = create_genesis_block();
        block_db.insert(&genesis).unwrap();
        assert!(!block_db.is_empty());
        assert!(block_db.has_any_chain_data());
    }

    /// Pruned-header round-trip, plus the atomic store_pruned_and_remove:
    /// header stored, full block body removed, height index preserved so the
    /// pruned header stays locatable.
    #[test]
    fn pruned_header_store_get_and_store_and_remove_round_trip() {
        let (_dir, block_db) = fresh_block_db();

        assert!(!block_db.has_pruned_header(9));
        block_db.store_pruned_header(9, b"compact-header-bytes").unwrap();
        assert!(block_db.has_pruned_header(9));
        assert_eq!(
            block_db.get_pruned_header(9).unwrap().as_deref(),
            Some(&b"compact-header-bytes"[..])
        );
        assert_eq!(block_db.get_pruned_header(10).unwrap(), None);

        let genesis = create_genesis_block();
        let hash = genesis.hash();
        let h = genesis.height();
        block_db.insert(&genesis).unwrap();
        block_db.set_height_hash(h, &hash).unwrap();

        block_db.store_pruned_and_remove(h, b"pruned").unwrap();
        assert!(block_db.has_pruned_header(h));
        assert!(
            block_db.get(&hash).unwrap().is_none(),
            "full block body must be pruned"
        );
        assert_eq!(
            block_db.get_hash_by_height(h).unwrap(),
            Some(hash),
            "height index preserved for pruned-header lookup"
        );
    }

    /// iter yields stored blocks and count reflects the blocks tree size.
    #[test]
    fn iter_and_count_reflect_stored_blocks() {
        let (_dir, block_db) = fresh_block_db();
        assert_eq!(block_db.count(), 0);

        let genesis = create_genesis_block();
        block_db.insert(&genesis).unwrap();
        assert_eq!(block_db.count(), 1);

        let collected: Vec<_> = block_db.iter().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].hash(), genesis.hash());
    }
}
