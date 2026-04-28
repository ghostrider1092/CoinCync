//! # Mempool Database
//!
//! Persistent storage for unconfirmed transactions (mempool).

use crate::db::shim::{Db, Tree, transaction::Transactional};
use crate::primitives::{Hash, KeyImage};
#[cfg(test)]
use crate::primitives::Amount;
use crate::transaction::Transaction;
use crate::error::{Error, Result};
use super::{serialize, deserialize};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

/// Mempool transaction entry
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct MempoolEntry {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Full transaction
    pub tx: Transaction,
    /// Fee in atomic units
    pub fee: u64,
    /// Fee per byte
    pub fee_per_byte: u64,
    /// Transaction size in bytes
    pub size: usize,
    /// Time added to mempool
    pub added_time: u64,
    /// Last seen time
    pub last_seen: u64,
    /// Number of times relayed
    pub relay_count: u32,
    /// Key images used by this transaction
    pub key_images: Vec<KeyImage>,
}

impl MempoolEntry {
    /// Create entry from transaction
    ///
    /// # Fee Calculation
    /// Uses scaled fee calculation (micro-syncs per byte) to prevent precision loss
    /// for small fees. This matches the in-memory mempool calculation.
    pub fn from_tx(tx: Transaction, added_time: u64) -> Self {
        let tx_hash = tx.hash();
        let fee = tx.fee.as_atomic();
        let size = borsh::to_vec(&tx).map(|v| v.len()).unwrap_or(0);

        // SECURITY: Use scaled fee calculation to prevent precision loss
        // Multiply fee by 1_000_000 before division to maintain precision for small fees
        // This gives us micro-sync per byte precision instead of sync per byte
        //
        // Example: 50 syncs / 100 bytes = 0 (lost precision)
        // With scaling: (50 * 1_000_000) / 100 = 500_000 micro-syncs per byte
        let fee_per_byte = if size > 0 {
            // Use u128 intermediate to prevent overflow for large fees
            let scaled_fee = fee as u128 * 1_000_000;
            (scaled_fee / size as u128) as u64
        } else {
            0
        };

        // Extract key images from inputs
        let key_images: Vec<KeyImage> = tx.inputs.iter()
            .map(|i| i.key_image)
            .collect();

        MempoolEntry {
            tx_hash,
            tx,
            fee,
            fee_per_byte,
            size,
            added_time,
            last_seen: added_time,
            relay_count: 0,
            key_images,
        }
    }

    /// Check if transaction has expired
    pub fn is_expired(&self, current_time: u64, max_age: u64) -> bool {
        current_time > self.added_time + max_age
    }
}

/// Mempool database
pub struct MempoolDb {
    /// Transactions: tx_hash -> MempoolEntry
    transactions: Tree,
    /// Key images in mempool: key_image -> tx_hash
    key_images: Tree,
    /// Fee index for efficient selection
    fee_index: Tree,
}

impl MempoolDb {
    /// Create new mempool database
    pub fn new(db: &Db) -> Result<Self> {
        let transactions = db.open_tree("mempool_txs")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let key_images = db.open_tree("mempool_key_images")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let fee_index = db.open_tree("mempool_fee_index")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(MempoolDb {
            transactions,
            key_images,
            fee_index,
        })
    }

    /// Add transaction to mempool
    ///
    /// SECURITY (C13-FIX): Uses sled multi-tree transaction to atomically write
    /// the transaction, key image index, and fee index entries. Previously these
    /// were separate operations — a crash between them could leave the mempool
    /// in an inconsistent state (e.g., transaction present but key images missing,
    /// breaking double-spend detection).
    pub fn add(&self, entry: &MempoolEntry) -> Result<bool> {
        // Check for double-spend (key image already in mempool)
        for ki in &entry.key_images {
            if self.key_images.contains_key(ki.as_bytes())
                .map_err(|e| Error::DatabaseError(e.to_string()))? {
                return Ok(false); // Double-spend detected
            }
        }

        // Pre-compute all data before the atomic transaction
        let data = serialize(entry)?;
        let tx_hash_bytes = entry.tx_hash.as_bytes().to_vec();
        let fee_key = self.make_fee_key(entry.fee_per_byte, &entry.tx_hash);
        let ki_pairs: Vec<(Vec<u8>, Vec<u8>)> = entry.key_images.iter()
            .map(|ki| (ki.as_bytes().to_vec(), tx_hash_bytes.clone()))
            .collect();

        // SECURITY (C13-FIX): Atomic transaction across all three trees
        let trees: &[&Tree] = &[&self.transactions, &self.key_images, &self.fee_index];
        trees.transaction(|tx_trees| {
            tx_trees[0].insert(tx_hash_bytes.as_slice(), data.as_slice())?;
            for (ki_key, ki_val) in &ki_pairs {
                tx_trees[1].insert(ki_key.as_slice(), ki_val.as_slice())?;
            }
            tx_trees[2].insert(fee_key.as_slice(), tx_hash_bytes.as_slice())?;
            Ok(())
        })
        .map_err(|e: crate::db::shim::transaction::TransactionError| {
            Error::DatabaseError(format!("Atomic mempool add failed: {:?}", e))
        })?;

        Ok(true)
    }

    /// Make fee index key (higher fees first)
    fn make_fee_key(&self, fee_per_byte: u64, tx_hash: &Hash) -> Vec<u8> {
        let mut key = Vec::with_capacity(40);
        // Use inverted fee for descending order
        key.extend_from_slice(&(u64::MAX - fee_per_byte).to_be_bytes());
        key.extend_from_slice(tx_hash.as_bytes());
        key
    }

    /// Get transaction by hash
    pub fn get(&self, tx_hash: &Hash) -> Result<Option<MempoolEntry>> {
        match self.transactions.get(tx_hash.as_bytes()) {
            Ok(Some(data)) => {
                let entry: MempoolEntry = deserialize(&data)?;
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Check if transaction is in mempool
    pub fn contains(&self, tx_hash: &Hash) -> Result<bool> {
        self.transactions.contains_key(tx_hash.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Check if key image is in mempool (double-spend check)
    pub fn has_key_image(&self, key_image: &KeyImage) -> Result<bool> {
        self.key_images.contains_key(key_image.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Get transaction using a key image
    pub fn get_by_key_image(&self, key_image: &KeyImage) -> Result<Option<Hash>> {
        match self.key_images.get(key_image.as_bytes()) {
            Ok(Some(data)) => Ok(Hash::from_slice(&data)),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Remove transaction from mempool
    ///
    /// SECURITY (C13-FIX): Uses sled multi-tree transaction to atomically remove
    /// the transaction, key images, and fee index entries. Previously a crash
    /// between removals could leave stale key images blocking future transactions.
    pub fn remove(&self, tx_hash: &Hash) -> Result<Option<MempoolEntry>> {
        // Get entry first (read-only, before the atomic write)
        let entry = self.get(tx_hash)?;

        if let Some(ref e) = entry {
            // Pre-compute keys before the atomic transaction
            let tx_hash_bytes = tx_hash.as_bytes().to_vec();
            let fee_key = self.make_fee_key(e.fee_per_byte, tx_hash);
            let ki_keys: Vec<Vec<u8>> = e.key_images.iter()
                .map(|ki| ki.as_bytes().to_vec())
                .collect();

            // SECURITY (C13-FIX): Atomic transaction across all three trees
            let trees: &[&Tree] = &[&self.transactions, &self.key_images, &self.fee_index];
            trees.transaction(|tx_trees| {
                tx_trees[0].remove(tx_hash_bytes.as_slice())?;
                for ki_key in &ki_keys {
                    tx_trees[1].remove(ki_key.as_slice())?;
                }
                tx_trees[2].remove(fee_key.as_slice())?;
                Ok(())
            })
            .map_err(|e: crate::db::shim::transaction::TransactionError| {
                Error::DatabaseError(format!("Atomic mempool remove failed: {:?}", e))
            })?;
        }

        Ok(entry)
    }

    /// Get transactions sorted by fee (for block building)
    pub fn get_by_fee(&self, limit: usize) -> Result<Vec<MempoolEntry>> {
        let mut entries = Vec::new();

        for result in self.fee_index.iter() {
            if entries.len() >= limit {
                break;
            }

            let (_, tx_hash_bytes) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;

            if let Some(entry) = self.get(&Hash::from_slice(&tx_hash_bytes).unwrap_or_default())? {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Get all transactions
    pub fn get_all(&self) -> Result<Vec<MempoolEntry>> {
        let mut entries = Vec::new();

        for result in self.transactions.iter() {
            let (_, data) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;
            let entry: MempoolEntry = deserialize(&data)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Remove expired transactions
    pub fn remove_expired(&self, current_time: u64, max_age: u64) -> Result<usize> {
        let expired: Vec<Hash> = self.get_all()?
            .into_iter()
            .filter(|e| e.is_expired(current_time, max_age))
            .map(|e| e.tx_hash)
            .collect();

        let count = expired.len();
        for hash in expired {
            self.remove(&hash)?;
        }

        Ok(count)
    }

    /// Remove transactions that conflict with block
    pub fn remove_confirmed(&self, key_images: &[KeyImage]) -> Result<usize> {
        let mut removed = 0;

        for ki in key_images {
            if let Some(tx_hash) = self.get_by_key_image(ki)? {
                self.remove(&tx_hash)?;
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// Update last seen time
    pub fn touch(&self, tx_hash: &Hash, current_time: u64) -> Result<bool> {
        if let Some(mut entry) = self.get(tx_hash)? {
            entry.last_seen = current_time;
            entry.relay_count += 1;

            let data = serialize(&entry)?;
            self.transactions.insert(tx_hash.as_bytes(), data)
                .map_err(|e| Error::DatabaseError(e.to_string()))?;

            return Ok(true);
        }

        Ok(false)
    }

    /// Get mempool size
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Get total fees in mempool
    pub fn total_fees(&self) -> Result<u64> {
        let entries = self.get_all()?;
        Ok(entries.iter().map(|e| e.fee).sum())
    }

    /// Get total size in bytes
    pub fn total_bytes(&self) -> Result<usize> {
        let entries = self.get_all()?;
        Ok(entries.iter().map(|e| e.size).sum())
    }

    /// Clear all transactions (for testing/reset)
    pub fn clear(&self) -> Result<()> {
        self.transactions.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.key_images.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.fee_index.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::transaction::{TxType, TxInput, TxOutput, RingMemberRef};
    use crate::primitives::PublicKey;
    use crate::crypto::{ClsagSignature, SecretScalar};

    fn make_test_tx(nonce: u8) -> Transaction {
        // Generate valid curve points for mock CLSAG signature
        let mock_secret = SecretScalar::from_bytes([nonce; 32]);
        let mock_pub = mock_secret.to_public();
        let mock_ki = crate::crypto::KeyImage::from_secret(&mock_secret);
        let key_image = KeyImage::from_bytes(mock_ki.to_bytes());

        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                ring_members: vec![RingMemberRef {
                    public_key: PublicKey::from_bytes(mock_pub.to_bytes()),
                    commitment: mock_pub.to_bytes(), // valid curve point bytes
                }],
                key_image,
                signature: ClsagSignature {
                    key_image: mock_ki,
                    commitment_image: mock_pub,
                    c1: [0u8; 32],
                    responses: vec![[0u8; 32]],
                },
                pseudo_output_commitment: mock_pub.to_bytes(),
            }],
            outputs: vec![TxOutput {
                stealth_address: PublicKey::from_bytes([1u8; 32]),
                tx_public_key: PublicKey::from_bytes([2u8; 32]),
                commitment: [3u8; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: 0,
                lock_height: None,
                encrypted_memo: vec![],
            }],
            fee: Amount::from_atomic(10000),
            range_proof: vec![],
            extra: vec![nonce],
        }
    }

    #[test]
    fn test_mempool_add_remove() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let mempool = MempoolDb::new(&db).unwrap();

        let tx = make_test_tx(1);
        let entry = MempoolEntry::from_tx(tx.clone(), 1000);

        assert!(mempool.add(&entry).unwrap());
        assert_eq!(mempool.size(), 1);
        assert!(mempool.contains(&tx.hash()).unwrap());

        mempool.remove(&tx.hash()).unwrap();
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_double_spend_detection() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let mempool = MempoolDb::new(&db).unwrap();

        let tx1 = make_test_tx(1);
        let tx2 = make_test_tx(1); // Same key image

        let entry1 = MempoolEntry::from_tx(tx1, 1000);
        let entry2 = MempoolEntry::from_tx(tx2, 1001);

        assert!(mempool.add(&entry1).unwrap());
        assert!(!mempool.add(&entry2).unwrap()); // Should fail - double spend
    }

    #[test]
    fn test_fee_ordering() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let mempool = MempoolDb::new(&db).unwrap();

        for i in 1..=5 {
            let mut tx = make_test_tx(i);
            tx.fee = Amount::from_atomic(i as u64 * 10000);
            let entry = MempoolEntry::from_tx(tx, 1000);
            mempool.add(&entry).unwrap();
        }

        let by_fee = mempool.get_by_fee(10).unwrap();
        assert_eq!(by_fee.len(), 5);

        // Higher fees should come first
        assert!(by_fee[0].fee >= by_fee[1].fee);
    }

    #[test]
    fn test_concurrent_mempool_write() {
        // Sled is thread-safe; verify two separate MempoolDb handles work
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let mempool1 = MempoolDb::new(&db).unwrap();
        let mempool2 = MempoolDb::new(&db).unwrap();

        let tx1 = make_test_tx(10);
        let tx2 = make_test_tx(20);
        mempool1.add(&MempoolEntry::from_tx(tx1, 1000)).unwrap();
        mempool2.add(&MempoolEntry::from_tx(tx2, 1001)).unwrap();

        assert_eq!(mempool1.size(), 2);
        assert_eq!(mempool2.size(), 2);
    }
}
