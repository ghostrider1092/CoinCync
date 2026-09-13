//! # Chain State Database
//!
//! Persistent storage for chain state and metadata.
//!
//! SECURITY (A6-STATE-ORDER): All height-indexed sled keys use big-endian
//! encoding. Sled sorts keys lexicographically, so little-endian u64 keys
//! produce wrong ordering for heights > 255. Big-endian preserves numeric
//! ordering under byte comparison.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `get_state` / `save_state` / `read_schema_v1_state_for_migration`
//!   (`ChainStateData`, `ChainStateDataLegacyV1`)** — INVARIANT: `total_supply` is
//!   `u128` (MAX_SUPPLY 10^20 exceeds `u64::MAX`); `get_state` decodes ONLY the
//!   current layout — the schema stamp, not trial decoding, selects the format, so
//!   a legacy (u64-supply) record is REJECTED by `get_state` and read only by the
//!   registered v1→v2 migration path. THREAT: the old u64 aggregate overflowed and
//!   panicked `checked_add` at ~18.4M CYNC (height ~408k); a mis-stamped DB
//!   selecting the wrong record layout by luck. TESTS: `test_state_storage`,
//!   `get_state_rejects_schema_v1_layout_without_open_time_migration`,
//!   `get_state_returns_none_on_empty_db`.
//! - **§2 `get_genesis_hash` / `set_genesis_hash`** — INVARIANT: genesis hash
//!   starts unset and round-trips through set/get; overwrite is honored.
//!   THREAT: a missing/wrong genesis identifier defeating the network-match gate.
//!   TESTS: `genesis_hash_get_set_round_trip`.
//! - **§3 `add_checkpoint` / `get_checkpoint` / `get_checkpoints`** — INVARIANT:
//!   checkpoints are BE-keyed so iteration yields numeric-sorted heights (correct
//!   above 255); a malformed (non-8-byte) checkpoint key surfaces as
//!   `DatabaseError`, never a silent coercion to height 0. THREAT: A6 — a corrupted
//!   checkpoint attributed to genesis and then trusted by reorg validation.
//!   TESTS: `test_checkpoints`, `test_checkpoint_ordering_above_255`.
//! - **§4 `store_undo` / `get_undo` / `remove_undo` / `prune_undo`** — INVARIANT:
//!   undo data is BE-keyed; `prune_undo` removes every entry strictly below
//!   `keep_from_height` and returns the count; DB read errors and malformed keys
//!   propagate rather than being silently dropped. THREAT: A6-DB-CORRUPT — a
//!   silently-coerced height-0 key queuing every genesis-height entry for deletion,
//!   or corrupt entries never cleaned → incomplete reorgs. TESTS:
//!   `test_undo_data_ordering`, `store_get_remove_undo_round_trip`,
//!   `prune_undo_removes_below_keep_from_height`.
//! - **§5 generic `put` / `get` / `delete`** — INVARIANT: put/delete structurally
//!   REFUSE the reserved keys `chain_state` and `genesis_hash` (typed setters only);
//!   reads pass through for debugging. THREAT: R-41 — a raw write/delete to a
//!   reserved key corrupting the persisted `ChainStateData`/genesis, wedging the DB
//!   on next open (or making the loader treat it as a fresh install and wipe the
//!   chain). TESTS: `put_get_delete_generic_kv_and_reserved_key_guard`.

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
    /// Total (cumulative) emitted supply, in atomic units.
    ///
    /// `u128`, not `u64`: MAX_SUPPLY = 100M CYNC × 10^12 atomic/CYNC = 10^20,
    /// which exceeds `u64::MAX` (~1.84×10^19 ≈ 18.4M CYNC). The prior `u64`
    /// aggregate overflowed and panicked the `checked_add` on block connect at
    /// ~18.4M CYNC of cumulative emission (height ~408k). Individual `Amount`s
    /// stay `u64` — only this running total widened. See `ChainStateDataLegacyV1`
    /// for the on-disk migration.
    pub total_supply: u128,
    /// Total burned
    pub total_burned: u64,
    /// Last checkpoint height
    pub last_checkpoint: u64,
}

/// Pre-widening on-disk layout of [`ChainStateData`] (`total_supply` was `u64`).
///
/// Kept only for the explicit schema-v1 to schema-v2 migration. Normal state
/// reads never try this layout: the schema stamp, not deserialization success,
/// determines which record format is valid.
///
/// Field order MUST match the original `ChainStateData` exactly because borsh
/// is positional.
#[derive(BorshDeserialize)]
struct ChainStateDataLegacyV1 {
    tip_hash: Hash,
    height: u64,
    total_difficulty: u128,
    total_supply: u64,
    total_burned: u64,
    last_checkpoint: u64,
}

impl From<ChainStateDataLegacyV1> for ChainStateData {
    fn from(v: ChainStateDataLegacyV1) -> Self {
        ChainStateData {
            tip_hash: v.tip_hash,
            height: v.height,
            total_difficulty: v.total_difficulty,
            total_supply: v.total_supply as u128,
            total_burned: v.total_burned,
            last_checkpoint: v.last_checkpoint,
        }
    }
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
    pub(super) const KEY_CHAIN_STATE: &'static [u8] = b"chain_state";
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
            Ok(Some(data)) => Ok(Some(deserialize(&data)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Decode the schema-v1 chain-state record for the registered v1→v2
    /// migration. Keeping this separate from `get_state` prevents a malformed
    /// or mis-stamped database from selecting its layout by trial decoding.
    pub(super) fn read_schema_v1_state_for_migration(&self) -> Result<Option<ChainStateData>> {
        match self.state.get(Self::KEY_CHAIN_STATE) {
            Ok(Some(data)) => {
                let legacy: ChainStateDataLegacyV1 = deserialize(&data).map_err(|e| {
                    Error::DatabaseError(format!(
                        "schema-v1 chain_state does not match the registered layout: {}",
                        e
                    ))
                })?;
                Ok(Some(legacy.into()))
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
    fn get_state_rejects_schema_v1_layout_without_open_time_migration() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        // Mirror of the ORIGINAL on-disk field order, so borsh reproduces the
        // exact legacy byte layout (total_supply as u64).
        #[derive(BorshSerialize)]
        struct LegacyWrite {
            tip_hash: Hash,
            height: u64,
            total_difficulty: u128,
            total_supply: u64,
            total_burned: u64,
            last_checkpoint: u64,
        }
        // A supply near the old u64 ceiling — exactly the regime that panicked.
        let legacy = LegacyWrite {
            tip_hash: Hash::from_bytes([7u8; 32]),
            height: 407_838,
            total_difficulty: 999,
            total_supply: 18_446_744_073_000_000_000, // ~1.8446e19, just under u64::MAX
            total_burned: 42,
            last_checkpoint: 400_000,
        };
        let bytes = borsh::to_vec(&legacy).unwrap();
        state_db
            .state
            .insert(StateDb::KEY_CHAIN_STATE, bytes)
            .unwrap();

        assert!(
            state_db.get_state().is_err(),
            "legacy records must only be decoded by the schema-v1 migration"
        );
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

    /// store_undo → get_undo returns the exact bytes; remove_undo deletes it.
    #[test]
    fn store_get_remove_undo_round_trip() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        // Nothing stored yet.
        assert!(state_db.get_undo(42).unwrap().is_none());

        let payload = vec![9u8, 8, 7, 6, 5];
        state_db.store_undo(42, &payload).unwrap();
        assert_eq!(state_db.get_undo(42).unwrap(), Some(payload.clone()));

        // Overwrite at the same height replaces the value.
        let payload2 = vec![1u8, 2, 3];
        state_db.store_undo(42, &payload2).unwrap();
        assert_eq!(state_db.get_undo(42).unwrap(), Some(payload2));

        // Remove leaves nothing behind.
        state_db.remove_undo(42).unwrap();
        assert!(state_db.get_undo(42).unwrap().is_none());
        // Removing a missing height is a no-op, not an error.
        state_db.remove_undo(42).unwrap();
    }

    /// prune_undo removes every entry strictly below keep_from_height and
    /// returns the number removed; entries at or above the floor survive.
    #[test]
    fn prune_undo_removes_below_keep_from_height() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        for &h in &[0u64, 5, 9, 10, 11, 100] {
            state_db.store_undo(h, &[h as u8]).unwrap();
        }

        // keep_from_height = 10 → heights 0, 5, 9 are removed (3 entries).
        let removed = state_db.prune_undo(10).unwrap();
        assert_eq!(removed, 3);

        assert!(state_db.get_undo(0).unwrap().is_none());
        assert!(state_db.get_undo(5).unwrap().is_none());
        assert!(state_db.get_undo(9).unwrap().is_none());
        // The floor height itself is kept (strictly-below semantics).
        assert!(state_db.get_undo(10).unwrap().is_some());
        assert!(state_db.get_undo(11).unwrap().is_some());
        assert!(state_db.get_undo(100).unwrap().is_some());

        // Pruning again with the same floor removes nothing.
        assert_eq!(state_db.prune_undo(10).unwrap(), 0);
    }

    /// Genesis hash starts unset and round-trips through set/get.
    #[test]
    fn genesis_hash_get_set_round_trip() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        assert!(state_db.get_genesis_hash().unwrap().is_none());

        let genesis = Hash::from_bytes([0xABu8; 32]);
        state_db.set_genesis_hash(&genesis).unwrap();
        assert_eq!(state_db.get_genesis_hash().unwrap(), Some(genesis));

        // Overwrite is honored.
        let genesis2 = Hash::from_bytes([0xCDu8; 32]);
        state_db.set_genesis_hash(&genesis2).unwrap();
        assert_eq!(state_db.get_genesis_hash().unwrap(), Some(genesis2));
    }

    /// A brand-new database has no chain state — get_state returns None
    /// rather than a defaulted record.
    #[test]
    fn get_state_returns_none_on_empty_db() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        assert!(state_db.get_state().unwrap().is_none());
    }

    /// Generic put/get/delete round-trips for non-reserved keys, and refuses
    /// to touch the reserved chain-state / genesis keys (R-41).
    #[test]
    fn put_get_delete_generic_kv_and_reserved_key_guard() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let state_db = StateDb::new(&db).unwrap();

        // Non-reserved key round-trips.
        assert!(state_db.get(b"custom_key").unwrap().is_none());
        state_db.put(b"custom_key", b"custom_value").unwrap();
        assert_eq!(
            state_db.get(b"custom_key").unwrap(),
            Some(b"custom_value".to_vec())
        );
        state_db.delete(b"custom_key").unwrap();
        assert!(state_db.get(b"custom_key").unwrap().is_none());

        // Reserved keys are structurally rejected on put/delete so a
        // mis-typed caller cannot corrupt the persisted chain state.
        assert!(state_db.put(StateDb::KEY_CHAIN_STATE, b"junk").is_err());
        assert!(state_db.put(StateDb::KEY_GENESIS_HASH, b"junk").is_err());
        assert!(state_db.delete(StateDb::KEY_CHAIN_STATE).is_err());
        assert!(state_db.delete(StateDb::KEY_GENESIS_HASH).is_err());

        // A real state written via the typed setter survives the rejected
        // raw writes intact.
        let state = ChainStateData {
            tip_hash: Hash::from_bytes([3u8; 32]),
            height: 7,
            total_difficulty: 11,
            total_supply: 123,
            total_burned: 4,
            last_checkpoint: 0,
        };
        state_db.save_state(&state).unwrap();
        let _ = state_db.put(StateDb::KEY_CHAIN_STATE, b"junk");
        assert_eq!(state_db.get_state().unwrap().unwrap().height, 7);
    }
}
