//! # Output Index Database
//!
//! Permanent index of all outputs ever created on-chain.
//! Unlike the UTXO set, entries are NEVER removed when spent —
//! only during reorg (block disconnection). This enables full
//! validation of ring member commitments even for spent outputs.

use crate::db::shim::{Db, Tree};
use crate::error::{Error, Result};
use super::{serialize, deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

/// Minimal metadata for validating a ring member that may have been spent.
///
/// Stored permanently in sled keyed by stealth address bytes.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct OutputIndexEntry {
    /// Pedersen commitment (needed to verify ring member commitments)
    pub commitment: [u8; 32],
    /// Block height where the output was created
    pub height: u64,
    /// Whether this output came from a coinbase transaction
    pub is_coinbase: bool,
    /// Optional time-lock height
    pub lock_height: Option<u64>,
}

/// Persistent output index database
pub struct OutputIndexDb {
    /// stealth_address_bytes -> OutputIndexEntry
    pub(crate) tree: Tree,
}

impl OutputIndexDb {
    /// Create new output index database
    pub fn new(db: &Db) -> Result<Self> {
        let tree = db.open_tree("output_index")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(OutputIndexDb { tree })
    }

    /// Insert an output entry (oldest-wins semantics to match stealth_index).
    ///
    /// If the stealth address already exists, the entry is NOT overwritten.
    /// This matches the in-memory stealth_index behavior where old coinbase
    /// outputs sharing the same stealth address keep the oldest entry.
    pub fn insert(&self, stealth: &[u8; 32], entry: &OutputIndexEntry) -> Result<()> {
        // Only insert if not already present (oldest wins)
        if self.tree.contains_key(stealth)
            .map_err(|e| Error::DatabaseError(e.to_string()))? {
            return Ok(());
        }

        let data = serialize(entry)?;
        self.tree.insert(stealth, data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get an output entry by stealth address
    pub fn get(&self, stealth: &[u8; 32]) -> Result<Option<OutputIndexEntry>> {
        match self.tree.get(stealth) {
            Ok(Some(data)) => {
                let entry: OutputIndexEntry = deserialize(&data)?;
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Remove an output entry (only during reorg/block disconnection)
    pub fn remove(&self, stealth: &[u8; 32]) -> Result<()> {
        self.tree.remove(stealth)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Count total entries
    pub fn count(&self) -> usize {
        self.tree.len()
    }

    /// Check if the index is empty (used for migration detection)
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_index_insert_and_lookup() {
        let db = crate::db::shim::Config::new().temporary(true).open().unwrap();
        let idx = OutputIndexDb::new(&db).unwrap();

        let stealth = [42u8; 32];
        let entry = OutputIndexEntry {
            commitment: [1u8; 32],
            height: 100,
            is_coinbase: false,
            lock_height: None,
        };

        idx.insert(&stealth, &entry).unwrap();
        let retrieved = idx.get(&stealth).unwrap().unwrap();
        assert_eq!(retrieved.height, 100);
        assert!(!retrieved.is_coinbase);
        assert_eq!(idx.count(), 1);
    }

    #[test]
    fn test_output_index_oldest_wins() {
        let db = crate::db::shim::Config::new().temporary(true).open().unwrap();
        let idx = OutputIndexDb::new(&db).unwrap();

        let stealth = [99u8; 32];
        let entry1 = OutputIndexEntry {
            commitment: [1u8; 32],
            height: 50,
            is_coinbase: true,
            lock_height: None,
        };
        let entry2 = OutputIndexEntry {
            commitment: [2u8; 32],
            height: 200,
            is_coinbase: false,
            lock_height: None,
        };

        idx.insert(&stealth, &entry1).unwrap();
        idx.insert(&stealth, &entry2).unwrap(); // should NOT overwrite
        let retrieved = idx.get(&stealth).unwrap().unwrap();
        assert_eq!(retrieved.height, 50, "oldest entry should win");
        assert!(retrieved.is_coinbase);
    }

    #[test]
    fn test_output_index_remove() {
        let db = crate::db::shim::Config::new().temporary(true).open().unwrap();
        let idx = OutputIndexDb::new(&db).unwrap();

        let stealth = [7u8; 32];
        let entry = OutputIndexEntry {
            commitment: [0u8; 32],
            height: 10,
            is_coinbase: false,
            lock_height: Some(500),
        };

        idx.insert(&stealth, &entry).unwrap();
        assert!(!idx.is_empty());
        idx.remove(&stealth).unwrap();
        assert!(idx.get(&stealth).unwrap().is_none());
    }
}
