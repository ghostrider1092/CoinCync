//! # UTXO Database
//!
//! Persistent storage for unspent transaction outputs.

use crate::db::shim::{Db, Tree, transaction::Transactional};
use crate::primitives::{Hash, KeyImage};
use crate::transaction::TxOutput;
use crate::error::{Error, Result};
use super::{serialize, deserialize};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

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
        let outputs = db.open_tree("utxos")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let key_images = db.open_tree("key_images")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let height_counts = db.open_tree("utxo_height_counts")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let utxo_by_height = db.open_tree("utxo_by_height")
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

    /// Add an unspent output
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

        self.outputs.insert(key.clone(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        // H21: Insert into height index (BE height prefix + output key)
        let mut height_key = Vec::with_capacity(8 + key.len());
        height_key.extend_from_slice(&height.to_be_bytes());
        height_key.extend_from_slice(&key);
        self.utxo_by_height.insert(height_key, &[1u8])
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        // Update height count
        self.increment_height_count(height)?;

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
        let cas_result = self.key_images
            .compare_and_swap(
                ki_bytes,
                None::<&[u8]>,  // Expected: not present (not spent)
                Some(&[1u8]),   // New: mark as spent
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
                // BlockchainLMDB `remove_output` runs inside the parent
                // mdb_txn that wraps the whole block apply, giving the same
                // all-or-nothing guarantee.
                let height_to_decrement = match self.outputs.get(&output_key)
                    .map_err(|e| Error::DatabaseError(e.to_string()))? { Some(data) => {
                    let entry: OutputEntry = deserialize(&data)?;
                    Some(entry.height)
                } _ => {
                    None
                }};

                let trees: &[&Tree] = &[&self.outputs, &self.utxo_by_height, &self.height_counts];
                trees.transaction(|tx_trees| {
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
                            tx_trees[2].insert(counter_key.as_slice(), new_count.to_le_bytes().as_slice())?;
                        }
                    }

                    Ok(())
                }).map_err(|e: crate::db::shim::transaction::TransactionError| {
                    Error::DatabaseError(format!("spend_output cleanup tx failed: {:?}", e))
                })?;

                // Flush to ensure durability
                self.outputs.flush()
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                self.utxo_by_height.flush()
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                self.height_counts.flush()
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                self.key_images.flush()
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
        self.key_images.contains_key(key_image.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Mark a key image as spent (C15: for checkpoint persistence).
    /// Unlike spend_output, this only records the key image without removing a UTXO.
    pub fn mark_key_image(&self, key_image: &KeyImage) -> Result<()> {
        self.key_images.insert(key_image.as_bytes(), &[1u8])
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
        self.outputs.contains_key(&key)
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
            if let Some(data) = self.outputs.get(output_key)
                .map_err(|e| Error::DatabaseError(e.to_string()))? {
                let entry: OutputEntry = deserialize(&data)?;
                outputs.push(entry);
            }
        }

        Ok(outputs)
    }

    /// Get random outputs for ring members using gamma-distributed selection.
    ///
    /// SECURITY (M-3): Uses a gamma distribution biased toward recent outputs,
    /// matching real-world spending patterns. Uniform selection would make the
    /// true spend obvious (real users spend recent outputs far more often).
    /// The `exclude` parameter filters out key images that must not appear as decoys
    /// (e.g., the real input's key image).
    pub fn get_random_outputs(
        &self,
        min_height: u64,
        max_height: u64,
        count: usize,
        exclude: &[KeyImage],
    ) -> Result<Vec<OutputEntry>> {
        use rand::Rng;
        use rand_distr::{Distribution, Gamma};
        use std::collections::HashSet;

        if max_height <= min_height || count == 0 {
            return Ok(Vec::new());
        }

        // Build set of excluded key images for O(1) lookup
        let excluded_set: HashSet<[u8; 32]> = exclude.iter()
            .map(|ki| *ki.as_bytes())
            .collect();

        // Collect heights that have outputs using the height_counts index
        let height_range = max_height - min_height + 1;

        // Gamma distribution: shape=19.28, rate=1.61 (Monero-derived parameters)
        // This biases heavily toward recent outputs (high heights)
        let gamma = Gamma::new(19.28, 1.0 / 1.61)
            .unwrap_or_else(|_| Gamma::new(19.0, 0.6).unwrap());

        // SECURITY: ring decoy selection is a privacy boundary — use OsRng
        // (direct kernel entropy) rather than thread_rng, so a downstream
        // change to the rand crate's ThreadRng algorithm can never silently
        // degrade ring-signature unlinkability.
        let mut rng = rand::rngs::OsRng;
        let mut selected = Vec::with_capacity(count);
        let mut attempts = 0;
        let max_attempts = count * 50; // Prevent infinite loop

        while selected.len() < count && attempts < max_attempts {
            attempts += 1;

            // Sample from gamma, normalize to height range, bias toward tip
            let sample: f64 = gamma.sample(&mut rng);
            // Normalize: gamma mean ≈ 19.28/1.61 ≈ 12.0, scale to [0, height_range)
            // Map so that higher gamma values → more recent heights (closer to max_height)
            let normalized = sample / 50.0; // Rough normalization to [0, ~1)
            let clamped = normalized.clamp(0.0, 0.9999);
            // Invert so recent heights are more likely
            let height_offset = ((1.0 - clamped) * height_range as f64) as u64;
            let target_height = max_height.saturating_sub(height_offset).max(min_height);

            // Check if this height has outputs
            let output_count = self.get_height_count(target_height)?;
            if output_count == 0 {
                continue;
            }

            // Get outputs at this height
            let outputs_at_height = self.get_outputs_at_height(target_height)?;
            if outputs_at_height.is_empty() {
                continue;
            }

            // Pick a random output from this height
            let idx = rng.gen_range(0..outputs_at_height.len());
            let candidate = &outputs_at_height[idx];

            // Skip if in the exclude set
            let candidate_ki = candidate.output.stealth_address.as_bytes();
            if excluded_set.contains(candidate_ki) {
                continue;
            }

            // Skip duplicates
            let already_selected = selected.iter().any(|s: &OutputEntry| {
                s.tx_hash == candidate.tx_hash && s.index == candidate.index
            });
            if already_selected {
                continue;
            }

            selected.push(candidate.clone());
        }

        // H22: Fallback uses utxo_by_height range scan instead of full table scan.
        // Scans from min_height to max_height using BE prefix ordering.
        if selected.len() < count {
            let start_prefix: &[u8] = &min_height.to_be_bytes();
            let end_prefix: &[u8] = &(max_height + 1).to_be_bytes();
            for result in self.utxo_by_height.range(start_prefix..end_prefix) {
                if selected.len() >= count {
                    break;
                }
                if let Ok((height_key, _)) = result {
                    let output_key = &height_key[8..];
                    if let Ok(Some(data)) = self.outputs.get(output_key) {
                        if let Ok(entry) = deserialize::<OutputEntry>(&data) {
                            let ki = entry.output.stealth_address.as_bytes();
                            if excluded_set.contains(ki) {
                                continue;
                            }
                            let already = selected.iter().any(|s: &OutputEntry| {
                                s.tx_hash == entry.tx_hash && s.index == entry.index
                            });
                            if !already {
                                selected.push(entry);
                            }
                        }
                    }
                }
            }
        }

        Ok(selected)
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

    /// Get output count at height
    fn get_height_count(&self, height: u64) -> Result<u64> {
        let key = height.to_be_bytes();

        match self.height_counts.get(&key) {
            Ok(Some(data)) => {
                if data.len() != 8 {
                    return Err(Error::DatabaseError(format!(
                        "Corrupted height_counts entry for height {} ({} bytes, expected 8)",
                        height, data.len()
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
        self.outputs.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.key_images.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.height_counts.clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::primitives::PublicKey;

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

        utxo_db.add_output(tx_hash, 0, output.clone(), 100, false).unwrap();

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

        utxo_db.add_output(tx_hash, 0, output.clone(), 50, false).unwrap();
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

        utxo_db.add_output(tx_hash, 0, output.clone(), 1000, false).unwrap();
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
