//! # UTXO Database
//!
//! Persistent storage for unspent transaction outputs.

use super::{deserialize, serialize};
use crate::db::shim::{transaction::Transactional, Db, Tree};
use crate::error::{Error, Result};
use crate::primitives::{Hash, KeyImage};
use crate::transaction::TxOutput;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Output reference with metadata
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OutputEntry {
    pub tx_hash: Hash,
    pub index: u8,
    pub output: TxOutput,
    pub height: u64,
    pub coinbase: bool,
}

/// UTXO set database
pub struct UtxoDb {
    /// Unspent outputs: (tx_hash, index) -> OutputEntry
    outputs: Tree,
    /// Spent key images
    key_images: Tree,
    /// Output count by height (for ring member selection)
    height_counts: Tree,
    /// H21: Secondary index — BE height bytes -> output keys for prefix scan
    utxo_by_height: Tree,
}

impl UtxoDb {
    /// Create new UTXO database
    pub fn new(db: &Db) -> Result<Self> {
        let outputs = db
            .open_tree("utxos")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let key_images = db
            .open_tree("key_images")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let height_counts = db
            .open_tree("utxo_height_counts")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let utxo_by_height = db
            .open_tree("utxo_by_height")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(UtxoDb {
            outputs,
            key_images,
            height_counts,
            utxo_by_height,
        })
    }

    /// Make key for output lookup
    fn make_output_key(tx_hash: &Hash, index: u8) -> Vec<u8> {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(tx_hash.as_bytes());
        key.push(index);
        key
    }

    /// Add an unspent output.
    ///
    /// AUDIT (R-43 fix, 2026-07-03): pre-fix code did three
    /// sequential writes — outputs.insert, utxo_by_height.insert,
    /// increment_height_count (a fetch_and_update). A crash between
    /// writes left the DB in mismatched states:
    ///   - outputs written, height index missing → ring selection
    ///     picks up the output but can't find it via the height
    ///     scan; wallet scan misses it.
    ///   - Both written but height count missing → the output
    ///     count for the block understates by one; downstream
    ///     ring-decoy sampling gets a wrong distribution.
    ///
    /// Now the two straight inserts (outputs, utxo_by_height) go
    /// through a single Transactional batch — one atomic
    /// RocksBatch. `increment_height_count` uses `fetch_and_update`
    /// (a CAS-like read-modify-write) which cannot participate in
    /// the same batch because the shim's TxTree can't observe
    /// staged writes; we run it AFTER the transactional commit,
    /// so at worst a crash between the atomic batch and the count
    /// bump leaves the count under-by-one — a stats drift, not a
    /// UTXO-visibility bug. A defensive tracing::warn fires if the
    /// commit succeeds but the count bump then fails, so ops see
    /// the drift.
    pub fn add_output(
        &self,
        tx_hash: Hash,
        index: u8,
        output: TxOutput,
        height: u64,
        coinbase: bool,
    ) -> Result<()> {
        let entry = OutputEntry {
            tx_hash,
            index,
            output,
            height,
            coinbase,
        };

        let key = Self::make_output_key(&tx_hash, index);
        let data = serialize(&entry)?;
        let mut height_key = Vec::with_capacity(8 + key.len());
        height_key.extend_from_slice(&height.to_be_bytes());
        height_key.extend_from_slice(&key);

        // R-43: atomic 2-tree commit for the UTXO-visible writes.
        use crate::db::shim::transaction::Transactional;
        let trees: &[&Tree] = &[&self.outputs, &self.utxo_by_height];
        trees
            .transaction(|tx| {
                tx[0].insert(key.as_slice(), data.as_slice())?;
                tx[1].insert(height_key.as_slice(), &[1u8][..])?;
                Ok(())
            })
            .map_err(|e| {
                Error::DatabaseError(format!(
                    "R-43: atomic add_output commit failed for tx_hash {} index {}: {:?}",
                    hex::encode(tx_hash.as_bytes()),
                    index,
                    e
                ))
            })?;

        // Height count bump runs post-commit. On failure we log
        // loudly but do not propagate an error — the UTXO is
        // durably visible; a stat drift is recoverable via reindex.
        if let Err(e) = self.increment_height_count(height) {
            tracing::error!(
                target: "db::utxos",
                "R-43: post-commit height_count bump failed at height {} \
                 (tx {} idx {}) — stat drift, does NOT affect UTXO validity. \
                 Reindex height_counts to correct: {}",
                height, hex::encode(tx_hash.as_bytes()), index, e
            );
        }

        Ok(())
    }

    /// Spend an output (mark key image as used)
    ///
    /// SECURITY: Uses compare_and_swap for atomic double-spend prevention.
    /// This eliminates the TOCTOU race condition between checking if spent
    /// and marking as spent.
    pub fn spend_output(&self, tx_hash: &Hash, index: u8, key_image: KeyImage) -> Result<bool> {
        let output_key = Self::make_output_key(tx_hash, index);
        let ki_bytes = key_image.as_bytes();

        // SECURITY: Use compare_and_swap for atomic check-and-set
        // This prevents the race condition where two threads both see "not spent"
        // and then both try to spend the same output.
        //
        // compare_and_swap(key, expected, new):
        // - If current value == expected, atomically set to new and return Ok(Ok(()))
        // - If current value != expected, return Ok(Err(current_value))
        // - If error, return Err(...)
        let cas_result = self
            .key_images
            .compare_and_swap(
                ki_bytes,
                None::<&[u8]>, // Expected: not present (not spent)
                Some(&[1u8]),  // New: mark as spent
            )
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        // Check if we won the race
        match cas_result {
            Ok(()) => {
                // SECURITY (cleanup atomicity): the key image is now marked spent
                // (CAS above is atomic at the single-key level), but the UTXO
                // cleanup touches THREE separate trees (outputs, utxo_by_height,
                // height_counts). Previously these were independent writes — a
                // crash or io error between them left the DB in a partially-
                // consistent state where the same logical output had:
                //   - key_image marked spent
                //   - entry still present in outputs and/or utxo_by_height
                //   - height_count overcounted
                // Consumers of `utxo_by_height` re-validate against `outputs` and
                // skip orphans, so the leak isn't a correctness break, but it
                // wastes I/O on every ring decoy selection and ages the DB.
                //
                // Wrap the cleanup in a multi-tree transaction so either all
                // three trees are updated or none are. Prior art: Monero's
                // `BlockchainLMDB::remove_output` is declared at
                // src/blockchain_db/lmdb/db_lmdb.cpp:1167 (VERIFIED via
                // direct fetch this session) and is invoked from within
                // the LMDB transaction that wraps the caller's block-apply
                // path — the transaction wrapping itself is caller-side and
                // I did not read those call sites this session.
                //
                // Audit-fix cross-ref: R-43 storage #1+#7 atomicity work on
                // refactor/sync-state-model; this merge takes main's
                // 3-tree implementation as the superset (includes
                // utxo_by_height cleanup that R-43's 2-tree version omitted).
                //
                // If the cleanup transaction fails (DB error), the CAS is
                // already committed, so the chain state remains CONSISTENT
                // FROM A CONSENSUS PERSPECTIVE: the key image is marked
                // spent, so no double-spend can succeed. The worst case is
                // a stale outputs / utxo_by_height entry.
                let height_to_decrement = match self
                    .outputs
                    .get(&output_key)
                    .map_err(|e| Error::DatabaseError(e.to_string()))?
                {
                    Some(data) => {
                        let entry: OutputEntry = deserialize(&data)?;
                        Some(entry.height)
                    }
                    _ => None,
                };

                let trees: &[&Tree] = &[&self.outputs, &self.utxo_by_height, &self.height_counts];
                trees
                    .transaction(|tx_trees| {
                        // 1. Remove from primary UTXO set
                        tx_trees[0].remove(output_key.as_slice())?;

                        // 2. Remove from height secondary index so spent outputs
                        //    don't leak into ring decoy scans.
                        if let Some(height) = height_to_decrement {
                            let mut height_key = Vec::with_capacity(8 + output_key.len());
                            height_key.extend_from_slice(&height.to_be_bytes());
                            height_key.extend_from_slice(&output_key);
                            tx_trees[1].remove(height_key.as_slice())?;

                            // 3. Decrement the per-height counter inline. We do
                            //    the decode/update/encode by hand because
                            //    fetch_and_update is a single-tree primitive that
                            //    can't participate in this multi-tree tx.
                            let counter_key = height.to_be_bytes();
                            let current = match tx_trees[2].get(counter_key.as_slice())? {
                                Some(b) if b.len() == 8 => {
                                    let mut arr = [0u8; 8];
                                    arr.copy_from_slice(&b);
                                    u64::from_le_bytes(arr)
                                }
                                // Wrong-length entries are treated as zero by the
                                // single-tree path (with an error log); preserve
                                // that behavior here so a corrupt counter doesn't
                                // abort the spend. A trace would require io inside
                                // the tx closure — keep it silent here, the
                                // single-tree path will surface it on the next
                                // increment_height_count call.
                                _ => 0,
                            };
                            let new_count = current.saturating_sub(1);
                            if new_count == 0 {
                                tx_trees[2].remove(counter_key.as_slice())?;
                            } else {
                                tx_trees[2].insert(
                                    counter_key.as_slice(),
                                    new_count.to_le_bytes().as_slice(),
                                )?;
                            }
                        }

                        Ok(())
                    })
                    .map_err(|e: crate::db::shim::transaction::TransactionError| {
                        // R-43 audit-context log: CAS already committed above;
                        // chain state remains consensus-consistent (key_image is
                        // spent so double-spend is blocked). Log CRITICAL so
                        // the operator can spot recurring failures + reindex.
                        tracing::error!(
                            target: "db::utxos",
                            "CRITICAL: spend_output cleanup transaction failed after CAS \
                             succeeded for tx={} index={} ({:?}). Key image IS spent (chain \
                             safe); UTXO map may have a stale entry. Run reindex if \
                             this recurs.",
                            hex::encode(tx_hash.as_bytes()), index, e
                        );
                        Error::DatabaseError(format!("spend_output cleanup tx failed: {:?}", e))
                    })?;

                // Single global flush — Tree::flush() routes through
                // db.flush() which syncs all column families atomically.
                self.outputs
                    .flush()
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                self.utxo_by_height
                    .flush()
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                self.height_counts
                    .flush()
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                self.key_images
                    .flush()
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;

                Ok(true)
            }
            Err(_current_value) => {
                // Key image already exists - already spent (we lost the race or it was pre-spent)
                Ok(false)
            }
        }
    }

    /// Check if key image is spent
    pub fn is_spent(&self, key_image: &KeyImage) -> Result<bool> {
        self.key_images
            .contains_key(key_image.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Mark a key image as spent (C15: for checkpoint persistence).
    /// Unlike spend_output, this only records the key image without removing a UTXO.
    pub fn mark_key_image(&self, key_image: &KeyImage) -> Result<()> {
        self.key_images
            .insert(key_image.as_bytes(), &[1u8])
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get an output
    pub fn get_output(&self, tx_hash: &Hash, index: u8) -> Result<Option<OutputEntry>> {
        let key = Self::make_output_key(tx_hash, index);

        match self.outputs.get(&key) {
            Ok(Some(data)) => {
                let entry: OutputEntry = deserialize(&data)?;
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Check if output exists
    pub fn has_output(&self, tx_hash: &Hash, index: u8) -> Result<bool> {
        let key = Self::make_output_key(tx_hash, index);
        self.outputs
            .contains_key(&key)
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Count total UTXOs
    pub fn count(&self) -> usize {
        self.outputs.len()
    }

    /// Count spent key images
    pub fn spent_count(&self) -> usize {
        self.key_images.len()
    }

    /// Get outputs at a specific height (for ring member selection).
    ///
    /// H21: Uses the `utxo_by_height` secondary index tree with a prefix scan
    /// instead of a full table scan, giving O(k) where k = outputs at that height.
    pub fn get_outputs_at_height(&self, height: u64) -> Result<Vec<OutputEntry>> {
        let prefix = height.to_be_bytes();
        let mut outputs = Vec::new();

        for result in self.utxo_by_height.scan_prefix(&prefix) {
            let (height_key, _) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;
            // The output key is everything after the 8-byte height prefix
            let output_key = &height_key[8..];
            if let Some(data) = self
                .outputs
                .get(output_key)
                .map_err(|e| Error::DatabaseError(e.to_string()))?
            {
                let entry: OutputEntry = deserialize(&data)?;
                outputs.push(entry);
            }
        }

        Ok(outputs)
    }

    /// Increment output count at height (atomic)
    ///
    /// SECURITY (BUG-20): Uses to_be_bytes for lexicographic ordering consistency
    /// with BlockDb (which also uses BE). Enables correct ordered iteration.
    fn increment_height_count(&self, height: u64) -> Result<()> {
        let key = height.to_be_bytes();
        // On a malformed entry (length != 8 — only possible if sled itself
        // is corrupted) we previously fell back to current=0 silently and
        // wrote 1, permanently destroying the true count. Emit a tracing
        // warn instead so the corruption is visible; we still continue
        // (treating the entry as 0) because returning an error from inside
        // fetch_and_update isn't supported, but the operator has a signal.
        self.height_counts.fetch_and_update(&key, |old| {
            let current = match old {
                Some(b) if b.len() == 8 => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(b);
                    u64::from_le_bytes(arr)
                }
                Some(b) => {
                    tracing::error!(
                        "DB CORRUPTION: height_counts[height={}] has {} bytes, expected 8 — treating as 0",
                        height, b.len()
                    );
                    0
                }
                None => 0,
            };
            Some((current + 1).to_le_bytes().to_vec())
        }).map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    // AUDIT (2026-07-01): removed the standalone `decrement_height_count`
    // helper. It was replaced during the "storage #1 + #7" atomicity fix
    // by the INLINE, transactional decrement inside `spend_output` (see
    // the multi-tree transaction block above). The inline version is the
    // correct pattern because it uses the tx-scoped tree handles, so the
    // decrement and the `outputs.remove` land in the same RocksDB
    // WriteBatch — the whole point of the fix. The standalone method used
    // `self.height_counts.fetch_and_update(...)` on the live tree, which
    // is the exact non-atomic pattern the audit removed.
    //
    // Leaving it in the file was a live footgun: any future caller that
    // reached for the "obvious" helper name would silently reintroduce
    // the non-atomic decrement, and the outputs↔height_counts skew that
    // the atomicity fix closed would return. Deleting keeps the file
    // honest — the *only* way to decrement height_counts is now inside
    // the shared multi-tree transaction.
    //
    // If a reindex/repair path is ever added, it should extend the
    // existing multi-tree transaction pattern, not resurrect this helper.

    /// Get output count at height
    #[cfg(test)]
    fn get_height_count(&self, height: u64) -> Result<u64> {
        let key = height.to_be_bytes();

        match self.height_counts.get(&key) {
            Ok(Some(data)) => {
                if data.len() != 8 {
                    return Err(Error::DatabaseError(format!(
                        "Corrupted height_counts entry for height {} ({} bytes, expected 8)",
                        height,
                        data.len()
                    )));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(data.as_ref());
                Ok(u64::from_le_bytes(bytes))
            }
            Ok(None) => Ok(0),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Clear all data (for testing/reset)
    pub fn clear(&self) -> Result<()> {
        self.outputs
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.key_images
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.height_counts
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PublicKey;
    use tempfile::tempdir;

    #[test]
    fn test_utxo_storage() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let utxo_db = UtxoDb::new(&db).unwrap();

        let tx_hash = Hash::from_bytes([1u8; 32]);
        let output = TxOutput {
            stealth_address: PublicKey::from_bytes([2u8; 32]),
            tx_public_key: PublicKey::from_bytes([3u8; 32]),
            commitment: [4u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        };

        utxo_db
            .add_output(tx_hash, 0, output.clone(), 100, false)
            .unwrap();

        assert!(utxo_db.has_output(&tx_hash, 0).unwrap());
        assert_eq!(utxo_db.count(), 1);

        let key_image = KeyImage::from_bytes([5u8; 32]);
        assert!(utxo_db.spend_output(&tx_hash, 0, key_image).unwrap());
        assert!(utxo_db.is_spent(&key_image).unwrap());
        assert!(!utxo_db.has_output(&tx_hash, 0).unwrap());
    }

    #[test]
    fn test_utxo_store_retrieve() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let utxo_db = UtxoDb::new(&db).unwrap();

        let tx_hash = Hash::from_bytes([10u8; 32]);
        let output = TxOutput {
            stealth_address: PublicKey::from_bytes([11u8; 32]),
            tx_public_key: PublicKey::from_bytes([12u8; 32]),
            commitment: [13u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 42,
            lock_height: None,
            encrypted_memo: vec![],
        };

        utxo_db
            .add_output(tx_hash, 0, output.clone(), 50, false)
            .unwrap();
        utxo_db.add_output(tx_hash, 1, output, 50, false).unwrap();
        assert_eq!(utxo_db.count(), 2);
        assert!(utxo_db.has_output(&tx_hash, 0).unwrap());
        assert!(utxo_db.has_output(&tx_hash, 1).unwrap());
        assert!(!utxo_db.has_output(&tx_hash, 2).unwrap());
    }

    /// After a successful spend, the height secondary index must be cleared
    /// for that output. Otherwise spent outputs leak into ring decoy scans.
    #[test]
    fn spend_output_clears_height_index() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let utxo_db = UtxoDb::new(&db).unwrap();

        let tx_hash = Hash::from_bytes([20u8; 32]);
        let output = TxOutput {
            stealth_address: PublicKey::from_bytes([21u8; 32]),
            tx_public_key: PublicKey::from_bytes([22u8; 32]),
            commitment: [23u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        };

        utxo_db.add_output(tx_hash, 0, output, 777, false).unwrap();
        assert_eq!(utxo_db.get_outputs_at_height(777).unwrap().len(), 1);

        let key_image = KeyImage::from_bytes([99u8; 32]);
        assert!(utxo_db.spend_output(&tx_hash, 0, key_image).unwrap());

        // Height index must be empty after spend, not just the primary tree.
        assert_eq!(
            utxo_db.get_outputs_at_height(777).unwrap().len(),
            0,
            "spent output leaked into utxo_by_height — ring decoy selection would surface it"
        );
    }

    /// height_counts must be decremented in lockstep with the primary tree.
    /// When the last output at a height is spent, the counter key must be
    /// removed (no zero-value zombies).
    #[test]
    fn spend_output_decrements_and_removes_zero_height_count() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let utxo_db = UtxoDb::new(&db).unwrap();

        let tx_hash = Hash::from_bytes([30u8; 32]);
        let output = TxOutput {
            stealth_address: PublicKey::from_bytes([31u8; 32]),
            tx_public_key: PublicKey::from_bytes([32u8; 32]),
            commitment: [33u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        };

        utxo_db
            .add_output(tx_hash, 0, output.clone(), 1000, false)
            .unwrap();
        utxo_db.add_output(tx_hash, 1, output, 1000, false).unwrap();
        assert_eq!(utxo_db.get_height_count(1000).unwrap(), 2);

        let ki0 = KeyImage::from_bytes([41u8; 32]);
        assert!(utxo_db.spend_output(&tx_hash, 0, ki0).unwrap());
        assert_eq!(utxo_db.get_height_count(1000).unwrap(), 1);

        let ki1 = KeyImage::from_bytes([42u8; 32]);
        assert!(utxo_db.spend_output(&tx_hash, 1, ki1).unwrap());
        assert_eq!(
            utxo_db.get_height_count(1000).unwrap(),
            0,
            "height_counts must read as zero (entry removed) when all outputs at the height are spent"
        );
    }

    /// CAS still rejects a second spend with the same key image — the
    /// transactional cleanup must not change the double-spend guarantee.
    #[test]
    fn spend_output_second_attempt_returns_false() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let utxo_db = UtxoDb::new(&db).unwrap();

        let tx_hash = Hash::from_bytes([50u8; 32]);
        let output = TxOutput {
            stealth_address: PublicKey::from_bytes([51u8; 32]),
            tx_public_key: PublicKey::from_bytes([52u8; 32]),
            commitment: [53u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        };

        utxo_db.add_output(tx_hash, 0, output, 200, false).unwrap();
        let key_image = KeyImage::from_bytes([77u8; 32]);
        assert!(utxo_db.spend_output(&tx_hash, 0, key_image).unwrap());

        // Second attempt with the same key_image MUST return false (key image
        // already present — CAS loses the race).
        assert!(!utxo_db.spend_output(&tx_hash, 0, key_image).unwrap());
        // And second attempt must not corrupt state — key image still spent,
        // output still gone, height count still consistent.
        assert!(utxo_db.is_spent(&key_image).unwrap());
        assert!(!utxo_db.has_output(&tx_hash, 0).unwrap());
        assert_eq!(utxo_db.get_height_count(200).unwrap(), 0);
    }
}
