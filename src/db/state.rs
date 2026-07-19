//! # Chain State Database
//!
//! Persistent storage for chain state and metadata.
//!
//! SECURITY (A6-STATE-ORDER): All height-indexed sled keys use big-endian
//! encoding. Sled sorts keys lexicographically, so little-endian u64 keys
//! produce wrong ordering for heights > 255. Big-endian preserves numeric
//! ordering under byte comparison.

use super::{deserialize, serialize};
use crate::db::shim::{Db, Tree};
use crate::error::{Error, Result};
use crate::primitives::Hash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Chain state snapshot
#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ChainStateData {
    /// Current tip hash
    pub tip_hash: Hash,
    /// Current height
    pub height: u64,
    /// Total difficulty
    pub total_difficulty: u128,
    /// Total supply
    pub total_supply: u64,
    /// Total burned
    pub total_burned: u64,
    /// Last checkpoint height
    pub last_checkpoint: u64,
}

/// State database
pub struct StateDb {
    /// Main state tree
    pub(crate) state: Tree,
    /// Checkpoints: height -> hash
    checkpoints: Tree,
    /// Chain state undo data for reorgs
    undo: Tree,
}

impl StateDb {
    /// State key constants
    const KEY_CHAIN_STATE: &'static [u8] = b"chain_state";
    const KEY_GENESIS_HASH: &'static [u8] = b"genesis_hash";

    /// Create new state database
    pub fn new(db: &Db) -> Result<Self> {
        let state = db
            .open_tree("chain_state")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let checkpoints = db
            .open_tree("checkpoints")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let undo = db
            .open_tree("undo_data")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(StateDb {
            state,
            checkpoints,
            undo,
        })
    }

    /// Get chain state
    pub fn get_state(&self) -> Result<Option<ChainStateData>> {
        match self.state.get(Self::KEY_CHAIN_STATE) {
            Ok(Some(data)) => {
                let state: ChainStateData = deserialize(&data)?;
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Save chain state
    pub fn save_state(&self, state: &ChainStateData) -> Result<()> {
        let data = serialize(state)?;
        self.state
            .insert(Self::KEY_CHAIN_STATE, data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get genesis hash
    pub fn get_genesis_hash(&self) -> Result<Option<Hash>> {
        match self.state.get(Self::KEY_GENESIS_HASH) {
            Ok(Some(data)) => Ok(Hash::from_slice(&data)),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Set genesis hash
    pub fn set_genesis_hash(&self, hash: &Hash) -> Result<()> {
        self.state
            .insert(Self::KEY_GENESIS_HASH, hash.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Add checkpoint
    pub fn add_checkpoint(&self, height: u64, hash: &Hash) -> Result<()> {
        self.checkpoints
            .insert(&height.to_be_bytes(), hash.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get checkpoint at height
    pub fn get_checkpoint(&self, height: u64) -> Result<Option<Hash>> {
        match self.checkpoints.get(&height.to_be_bytes()) {
            Ok(Some(data)) => Ok(Hash::from_slice(&data)),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Get all checkpoints.
    ///
    /// A malformed (non-8-byte) checkpoint key is treated as DB
    /// corruption and surfaces as DatabaseError — silently coercing
    /// to height 0 would attribute a corrupted checkpoint to genesis,
    /// which downstream reorg-validation code would then trust.
    pub fn get_checkpoints(&self) -> Result<Vec<(u64, Hash)>> {
        let mut result = Vec::new();

        for entry in self.checkpoints.iter() {
            let (key, value) = entry.map_err(|e| Error::DatabaseError(e.to_string()))?;
            let arr: [u8; 8] = key.as_ref().try_into().map_err(|_| {
                Error::DatabaseError(format!(
                    "checkpoint entry has unexpected key length {} (expected 8); \
                     state database may be corrupted",
                    key.as_ref().len()
                ))
            })?;
            let height = u64::from_be_bytes(arr);
            if let Some(hash) = Hash::from_slice(&value) {
                result.push((height, hash));
            }
        }

        Ok(result)
    }

    /// Store undo data for a block
    pub fn store_undo(&self, height: u64, data: &[u8]) -> Result<()> {
        self.undo
            .insert(&height.to_be_bytes(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get undo data for a block
    pub fn get_undo(&self, height: u64) -> Result<Option<Vec<u8>>> {
        match self.undo.get(&height.to_be_bytes()) {
            Ok(Some(data)) => Ok(Some(data.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Remove undo data
    pub fn remove_undo(&self, height: u64) -> Result<()> {
        self.undo
            .remove(&height.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Prune old undo data
    pub fn prune_undo(&self, keep_from_height: u64) -> Result<usize> {
        let mut removed = 0;

        // SECURITY (A6-DB-CORRUPT): Propagate DB read errors instead of silently
        // dropping them. Corrupted undo entries that are silently skipped will never
        // be cleaned up and could cause incomplete reorgs.
        //
        // A malformed (non-8-byte) undo key is treated as DB corruption and
        // surfaces as DatabaseError — silently coercing to height 0 would
        // mark every legitimate height-0 entry as "below keep_from_height"
        // and queue them all for deletion, exactly the wrong behaviour.
        let mut keys_to_remove = Vec::new();
        for result in self.undo.iter() {
            let (k, _) = result.map_err(|e| Error::DatabaseError(format!("undo iter: {}", e)))?;
            let arr: [u8; 8] = k.as_ref().try_into().map_err(|_| {
                Error::DatabaseError(format!(
                    "undo entry has unexpected key length {} (expected 8); \
                     undo log may be corrupted",
                    k.as_ref().len()
                ))
            })?;
            let height = u64::from_be_bytes(arr);
            if height < keep_from_height {
                keys_to_remove.push(k);
            }
        }

        for key in keys_to_remove {
            self.undo
                .remove(&key)
                .map_err(|e| Error::DatabaseError(e.to_string()))?;
            removed += 1;
        }

        Ok(removed)
    }

    /// Store arbitrary key-value.
    ///
    /// AUDIT (R-41 fix, 2026-07-03): the pre-fix put/get/delete
    /// operated on the same tree that stores the canonical
    /// `KEY_CHAIN_STATE` (b"chain_state") and `KEY_GENESIS_HASH`
    /// (b"genesis_hash") records. A caller writing raw bytes to
    /// either of those keys would silently CORRUPT the persisted
    /// ChainStateData / genesis, making the DB unloadable on next
    /// open. Reject those two reserved keys structurally so no
    /// mis-typed caller can wedge the DB.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        if key == Self::KEY_CHAIN_STATE || key == Self::KEY_GENESIS_HASH {
            return Err(Error::DatabaseError(format!(
                "R-41: put() refused for reserved chain-state key {:?} — \
                 use the typed setter (set_chain_state/set_genesis_hash) \
                 instead so the encoded structure is preserved.",
                std::str::from_utf8(key).unwrap_or("<non-utf8>")
            )));
        }
        self.state
            .insert(key, value)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get arbitrary key-value.
    ///
    /// R-41: reads pass through unchanged — a caller inspecting the
    /// reserved keys' raw bytes for debugging is a legitimate use
    /// case. The corruption risk is only on writes.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.state.get(key) {
            Ok(Some(data)) => Ok(Some(data.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Delete key.
    ///
    /// R-41: delete also protected — removing the canonical state
    /// keys would wedge the DB on next open (StateDb::get_state
    /// would return None and the chain-loader treats that as
    /// "fresh install", potentially wiping the chain).
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        if key == Self::KEY_CHAIN_STATE || key == Self::KEY_GENESIS_HASH {
            return Err(Error::DatabaseError(format!(
                "R-41: delete() refused for reserved chain-state key {:?}",
                std::str::from_utf8(key).unwrap_or("<non-utf8>")
            )));
        }
        self.state
            .remove(key)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_state_storage() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        let state = ChainStateData {
            tip_hash: Hash::from_bytes([1u8; 32]),
            height: 100,
            total_difficulty: 1000,
            total_supply: 1_000_000_000,
            total_burned: 50_000_000,
            last_checkpoint: 50,
        };

        state_db.save_state(&state).unwrap();

        let loaded = state_db.get_state().unwrap().unwrap();
        assert_eq!(loaded.height, 100);
        assert_eq!(loaded.total_supply, 1_000_000_000);
    }

    #[test]
    fn test_checkpoints() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        let hash1 = Hash::from_bytes([1u8; 32]);
        let hash2 = Hash::from_bytes([2u8; 32]);

        state_db.add_checkpoint(100, &hash1).unwrap();
        state_db.add_checkpoint(200, &hash2).unwrap();

        assert_eq!(state_db.get_checkpoint(100).unwrap(), Some(hash1));
        assert_eq!(state_db.get_checkpoint(200).unwrap(), Some(hash2));
        assert_eq!(state_db.get_checkpoint(300).unwrap(), None);
    }

    #[test]
    fn test_checkpoint_ordering_above_255() {
        // Regression test: LE encoding caused height 256 to sort before height 1
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        for &h in &[1u64, 256, 2, 1000, 0] {
            let hash = Hash::from_bytes([h as u8; 32]);
            state_db.add_checkpoint(h, &hash).unwrap();
        }

        let all = state_db.get_checkpoints().unwrap();
        let heights: Vec<u64> = all.iter().map(|(h, _)| *h).collect();
        // With BE encoding, sled iteration yields sorted order
        assert_eq!(heights, vec![0, 1, 2, 256, 1000]);
    }

    #[test]
    fn test_undo_data_ordering() {
        // Verify undo data uses BE and prune_undo works correctly for heights > 255
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        for &h in &[1u64, 256, 512, 1000] {
            state_db.store_undo(h, &[h as u8]).unwrap();
        }

        // Prune everything below 300
        let removed = state_db.prune_undo(300).unwrap();
        assert_eq!(removed, 2); // heights 1 and 256

        // Only 512 and 1000 should remain
        assert!(state_db.get_undo(1).unwrap().is_none());
        assert!(state_db.get_undo(256).unwrap().is_none());
        assert!(state_db.get_undo(512).unwrap().is_some());
        assert!(state_db.get_undo(1000).unwrap().is_some());
    }
}
