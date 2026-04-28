//! # Key Database
//!
//! Secure storage for wallet keys.
//!
//! SECURITY (A6-KEY-ORDER): All epoch-indexed sled keys use big-endian encoding.
//! Sled sorts keys lexicographically (byte-by-byte), so little-endian u64 keys
//! produce wrong ordering for values > 255. For example, epoch 256 in LE is
//! [0,1,0,0,0,0,0,0] which sorts BEFORE epoch 1 [1,0,0,0,0,0,0,0].
//! Big-endian preserves numeric ordering under lexicographic comparison.

use crate::db::shim::{Db, Tree};
use crate::error::{Error, Result};
use super::{serialize, deserialize};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

/// Encrypted key data
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct EncryptedKey {
    /// Encryption nonce
    pub nonce: [u8; 24],
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Salt for key derivation
    pub salt: [u8; 32],
}

/// Key metadata
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct KeyMetadata {
    /// Key epoch
    pub epoch: u64,
    /// Creation height
    pub created_at_height: u64,
    /// Creation timestamp
    pub created_at_time: u64,
    /// Whether this is a view key
    pub is_view_key: bool,
    /// Label
    pub label: Option<String>,
}

/// Key entry (view key with metadata)
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct KeyEntry {
    pub public: [u8; 32],
    pub metadata: KeyMetadata,
}

/// Key database for wallet
pub struct KeyDb {
    /// Encrypted spend keys (epoch -> encrypted key)
    spend_keys: Tree,
    /// View keys (epoch -> public key)
    view_keys: Tree,
    /// Key metadata
    metadata: Tree,
    /// Current epoch
    current_epoch: Tree,
}

impl KeyDb {
    const KEY_CURRENT_EPOCH: &'static [u8] = b"current_epoch";
    const KEY_MASTER_KEY_HASH: &'static [u8] = b"master_key_hash";

    /// Create new key database
    pub fn new(db: &Db) -> Result<Self> {
        let spend_keys = db.open_tree("spend_keys")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let view_keys = db.open_tree("view_keys")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let metadata = db.open_tree("key_metadata")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let current_epoch = db.open_tree("key_epoch")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(KeyDb {
            spend_keys,
            view_keys,
            metadata,
            current_epoch,
        })
    }

    /// Store encrypted spend key for epoch
    pub fn store_spend_key(&self, epoch: u64, encrypted: &EncryptedKey) -> Result<()> {
        let data = serialize(encrypted)?;
        self.spend_keys.insert(&epoch.to_be_bytes(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get encrypted spend key for epoch
    pub fn get_spend_key(&self, epoch: u64) -> Result<Option<EncryptedKey>> {
        match self.spend_keys.get(&epoch.to_be_bytes()) {
            Ok(Some(data)) => {
                let key: EncryptedKey = deserialize(&data)?;
                Ok(Some(key))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Store view key for epoch
    pub fn store_view_key(&self, epoch: u64, entry: &KeyEntry) -> Result<()> {
        let data = serialize(entry)?;
        self.view_keys.insert(&epoch.to_be_bytes(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get view key for epoch
    pub fn get_view_key(&self, epoch: u64) -> Result<Option<KeyEntry>> {
        match self.view_keys.get(&epoch.to_be_bytes()) {
            Ok(Some(data)) => {
                let entry: KeyEntry = deserialize(&data)?;
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Get all view keys
    pub fn get_all_view_keys(&self) -> Result<Vec<(u64, KeyEntry)>> {
        let mut result = Vec::new();

        for entry in self.view_keys.iter() {
            let (key, value) = entry.map_err(|e| Error::DatabaseError(e.to_string()))?;
            let epoch = u64::from_be_bytes(key.as_ref().try_into().unwrap_or([0u8; 8]));
            let key_entry: KeyEntry = deserialize(&value)?;
            result.push((epoch, key_entry));
        }

        Ok(result)
    }

    /// Get current epoch
    pub fn get_current_epoch(&self) -> Result<u64> {
        match self.current_epoch.get(Self::KEY_CURRENT_EPOCH) {
            Ok(Some(data)) => {
                let bytes: [u8; 8] = data.as_ref().try_into().unwrap_or([0u8; 8]);
                Ok(u64::from_be_bytes(bytes))
            }
            Ok(None) => Ok(0),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Set current epoch
    pub fn set_current_epoch(&self, epoch: u64) -> Result<()> {
        self.current_epoch.insert(Self::KEY_CURRENT_EPOCH, &epoch.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Store master key hash (for password verification)
    pub fn store_master_key_hash(&self, hash: &[u8; 32]) -> Result<()> {
        self.metadata.insert(Self::KEY_MASTER_KEY_HASH, hash.as_slice())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get master key hash
    pub fn get_master_key_hash(&self) -> Result<Option<[u8; 32]>> {
        match self.metadata.get(Self::KEY_MASTER_KEY_HASH) {
            Ok(Some(data)) => {
                let bytes: [u8; 32] = data.as_ref().try_into()
                    .map_err(|_| Error::DatabaseError("invalid master key hash".into()))?;
                Ok(Some(bytes))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Delete keys for epoch (for key rotation/deletion)
    pub fn delete_epoch_keys(&self, epoch: u64) -> Result<()> {
        self.spend_keys.remove(&epoch.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.view_keys.remove(&epoch.to_be_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Count key epochs
    pub fn epoch_count(&self) -> usize {
        self.spend_keys.len()
    }

    /// Clear all keys (dangerous!)
    pub fn clear(&self) -> Result<()> {
        self.spend_keys.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.view_keys.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.metadata.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.current_epoch.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_key_storage() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let key_db = KeyDb::new(&db).unwrap();

        let encrypted = EncryptedKey {
            nonce: [1u8; 24],
            ciphertext: vec![2, 3, 4, 5],
            salt: [6u8; 32],
        };

        key_db.store_spend_key(0, &encrypted).unwrap();
        key_db.set_current_epoch(1).unwrap();

        assert_eq!(key_db.get_current_epoch().unwrap(), 1);
        assert!(key_db.get_spend_key(0).unwrap().is_some());
    }

    #[test]
    fn test_epoch_ordering_above_255() {
        // Regression test: LE encoding caused epoch 256 to sort before epoch 1
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let key_db = KeyDb::new(&db).unwrap();

        let mk_entry = |epoch: u64| KeyEntry {
            public: [epoch as u8; 32],
            metadata: KeyMetadata {
                epoch,
                created_at_height: 0,
                created_at_time: 0,
                is_view_key: true,
                label: None,
            },
        };

        // Insert epochs out of order, including values > 255
        for &e in &[1u64, 256, 2, 1000, 0] {
            key_db.store_view_key(e, &mk_entry(e)).unwrap();
        }

        let all = key_db.get_all_view_keys().unwrap();
        let epochs: Vec<u64> = all.iter().map(|(e, _)| *e).collect();
        // With BE encoding, sled iteration should yield sorted order
        assert_eq!(epochs, vec![0, 1, 2, 256, 1000]);
    }
}
