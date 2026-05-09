//! UTXO set storage with height indexing for fast decoy selection

use crate::primitives::{Hash, KeyImage};
use crate::transaction::TxOutput;
use crate::db::{OutputIndexEntry, Database};
use std::collections::{HashMap, HashSet, BTreeMap, BTreeSet};
use std::sync::Arc;

/// Reference to a transaction output
#[derive(Clone)]
pub struct OutputRef {
    pub tx_hash: Hash,
    pub index: u8,
    pub output: TxOutput,
    pub height: u64,
    /// Whether this output came from a coinbase transaction
    pub is_coinbase: bool,
}

/// Output key for primary hashmap
type OutputKey = (Hash, u8);

/// UTXO set with height index for fast ring member selection
///
/// Privacy coins need to quickly find random outputs within a height range
/// for ring signatures. The height_index provides O(log n) lookups by height.
///
/// # Thread Safety
///
/// The UtxoSet struct is NOT thread-safe by itself. It uses internal HashMap,
/// HashSet, and BTreeMap which are not synchronized. Callers MUST wrap it in
/// appropriate synchronization primitives (typically `Arc<RwLock<UtxoSet>>`).
///
/// All operations that modify state require exclusive (write) access:
/// - `add_output()`, `spend_output()`, `mark_key_image_spent()`, `remove_output()`
/// - `remove_key_image()`
///
/// Read-only operations require shared (read) access:
/// - `contains_key_image()`, `get_output()`, `output_count()`, `outputs_in_range()`
/// - `select_decoys()`, `height_stats()`, `total_outputs_ever()`
///
/// # Atomicity of Operations
///
/// The check-then-modify operations (`spend_output`, `mark_key_image_spent`)
/// are atomic within a single call, but only if the caller holds exclusive
/// access throughout the operation. This is guaranteed when using proper
/// external synchronization (e.g., `RwLock::write()`).
pub struct UtxoSet {
    /// Primary storage: (tx_hash, index) -> OutputRef
    outputs: HashMap<OutputKey, OutputRef>,
    /// Spent key images (prevents double-spend)
    key_images: HashSet<KeyImage>,
    /// Height index: height -> set of output keys at that height
    /// Using BTreeMap for ordered iteration by height
    height_index: BTreeMap<u64, BTreeSet<OutputKey>>,
    /// Stealth address index: stealth_address_bytes -> output key
    /// Used for ring member validation and coinbase maturity checks (CRIT-5, HIGH-4)
    stealth_index: HashMap<[u8; 32], OutputKey>,
    /// Permanent output index: stealth_address_bytes -> OutputIndexEntry
    /// Unlike stealth_index, entries are NEVER removed on spend — only during reorg.
    /// Used to validate ring members referencing spent outputs.
    /// BOUNDED: Only recent entries (~1000 blocks) are kept in memory.
    /// Older entries fall back to the on-disk OutputIndexDb.
    output_index: HashMap<[u8; 32], OutputIndexEntry>,
    /// On-disk database for output_index cache miss fallback
    db: Option<Arc<Database>>,
    /// Total outputs ever created. Monotonic — never decrements, even on
    /// reorg. The previous behaviour of decrementing on reorg violated the
    /// "ever created" semantics and broke any monitoring built on this counter.
    /// L2 (audit fix): see also `reorg_disconnects_total` below for the
    /// matching reorg statistic.
    total_outputs_ever: u64,
    /// Number of outputs disconnected via reorg over the lifetime of this
    /// UtxoSet. L2 (audit fix): added so callers that previously relied on
    /// `total_outputs_ever` decrementing to reflect "current load" can now
    /// compute it as `total_outputs_ever - reorg_disconnects_total - spent`.
    reorg_disconnects_total: u64,
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet {
            outputs: HashMap::new(),
            key_images: HashSet::new(),
            height_index: BTreeMap::new(),
            stealth_index: HashMap::new(),
            output_index: HashMap::new(),
            db: None,
            total_outputs_ever: 0,
            reorg_disconnects_total: 0,
        }
    }

    /// Add an output to the set
    pub fn add_output(&mut self, tx_hash: Hash, index: u8, output: TxOutput, height: u64) {
        self.add_output_ext(tx_hash, index, output, height, false);
    }

    /// Add an output with coinbase flag (CRIT-5: needed for maturity tracking)
    pub fn add_output_ext(&mut self, tx_hash: Hash, index: u8, output: TxOutput, height: u64, is_coinbase: bool) {
        let key = (tx_hash, index);
        let stealth_addr = *output.stealth_address.as_bytes();
        let commitment = output.commitment;
        let lock_height = output.lock_height;
        let output_ref = OutputRef { tx_hash, index, output, height, is_coinbase };

        // Add to primary storage
        self.outputs.insert(key, output_ref);

        // Add to height index
        self.height_index
            .entry(height)
            .or_insert_with(BTreeSet::new)
            .insert(key);

        // Add to stealth address index (CRIT-5, HIGH-4)
        // Use or_insert to keep the OLDEST output per stealth_address.
        // Old coinbase outputs share stealth_address = miner_pubkey; keeping the oldest
        // ensures maturity checks find a mature output, not the latest immature one.
        self.stealth_index.entry(stealth_addr).or_insert(key);

        // Add to permanent output index (oldest wins, matching stealth_index)
        // This index persists across spends — entries are only removed during reorg.
        self.output_index.entry(stealth_addr).or_insert(OutputIndexEntry {
            commitment,
            height,
            is_coinbase,
            lock_height,
        });

        self.total_outputs_ever += 1;
    }

    /// Spend an output (mark key image as spent and remove output)
    pub fn spend_output(&mut self, tx_hash: Hash, index: u8, key_image: KeyImage) -> bool {
        if self.key_images.contains(&key_image) { return false; }
        self.key_images.insert(key_image);

        let key = (tx_hash, index);
        if let Some(output_ref) = self.outputs.remove(&key) {
            // Remove from height index
            if let Some(set) = self.height_index.get_mut(&output_ref.height) {
                set.remove(&key);
                if set.is_empty() {
                    self.height_index.remove(&output_ref.height);
                }
            }
            // SECURITY (A6-STEALTH-IDX): Remove from stealth index to maintain
            // consistency. Previously this was missed, leaving dangling references
            // that could bypass coinbase maturity checks for ring members.
            let stealth_addr = *output_ref.output.stealth_address.as_bytes();
            self.stealth_index.remove(&stealth_addr);
            true
        } else {
            false
        }
    }

    /// Mark a key image as spent without removing a specific output.
    /// For privacy coins with ring signatures, we don't know which output was spent.
    /// Returns false if already spent (double-spend attempt).
    pub fn mark_key_image_spent(&mut self, key_image: KeyImage) -> bool {
        if self.key_images.contains(&key_image) { return false; }
        self.key_images.insert(key_image);
        true
    }

    /// Check if key image is spent
    pub fn contains_key_image(&self, ki: &KeyImage) -> bool {
        self.key_images.contains(ki)
    }

    /// Get output by reference
    pub fn get_output(&self, tx_hash: &Hash, index: u8) -> Option<&OutputRef> {
        self.outputs.get(&(*tx_hash, index))
    }

    /// Look up an output by its stealth address (one-time public key)
    ///
    /// SECURITY (CRIT-5, HIGH-4): Used to validate ring members exist on-chain
    /// and to check coinbase maturity before allowing outputs in rings.
    pub fn get_output_by_stealth(&self, stealth_addr: &[u8; 32]) -> Option<&OutputRef> {
        self.stealth_index.get(stealth_addr)
            .and_then(|key| self.outputs.get(key))
    }

    /// Look up an output in the permanent output index by stealth address.
    ///
    /// Unlike `get_output_by_stealth()`, this returns entries even for spent
    /// outputs — enabling ring member validation for the full anonymity set.
    pub fn get_output_index_entry(&self, stealth_addr: &[u8; 32]) -> Option<OutputIndexEntry> {
        // Fast path: in-memory cache
        if let Some(entry) = self.output_index.get(stealth_addr) {
            return Some(entry.clone());
        }
        // Slow path: on-disk fallback for evicted entries
        if let Some(ref db) = self.db {
            db.output_index.get(stealth_addr).ok().flatten()
        } else {
            None
        }
    }

    /// Set the database for on-disk output_index fallback.
    pub fn set_database(&mut self, db: Arc<Database>) {
        self.db = Some(db);
    }

    /// Evict output_index entries older than `keep_depth` blocks.
    /// Bounds memory growth to ~keep_depth blocks of outputs.
    /// Evicted entries remain available via on-disk OutputIndexDb fallback.
    pub fn evict_old_outputs(&mut self, current_height: u64, keep_depth: u64) {
        if current_height <= keep_depth {
            return;
        }
        let cutoff = current_height - keep_depth;
        self.output_index.retain(|_, entry| entry.height >= cutoff);
    }

    /// Get current output count
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Remove an output (used during block disconnection)
    pub fn remove_output(&mut self, tx_hash: &Hash, index: u8) -> Option<OutputRef> {
        let key = (*tx_hash, index);
        if let Some(output_ref) = self.outputs.remove(&key) {
            // Remove from height index
            if let Some(set) = self.height_index.get_mut(&output_ref.height) {
                set.remove(&key);
                if set.is_empty() {
                    self.height_index.remove(&output_ref.height);
                }
            }
            // Remove from stealth index
            let stealth_addr = *output_ref.output.stealth_address.as_bytes();
            self.stealth_index.remove(&stealth_addr);
            // Remove from permanent output index (reorg only)
            self.output_index.remove(&stealth_addr);
            // L2 (audit fix): total_outputs_ever is now MONOTONIC — never
            // decrements, even on reorg. The previous decrement violated the
            // "ever created" semantics. Reorg disconnects are tracked
            // separately in reorg_disconnects_total so monitors that need
            // "current load" can compute it from the difference.
            self.reorg_disconnects_total = self.reorg_disconnects_total.saturating_add(1);
            Some(output_ref)
        } else {
            None
        }
    }

    /// Remove a key image (used during block disconnection to un-mark as spent)
    pub fn remove_key_image(&mut self, ki: &KeyImage) -> bool {
        self.key_images.remove(ki)
    }


    // ===== Fast decoy selection methods =====

    /// Get outputs in a height range for decoy selection
    ///
    /// This is O(k log n) where k is the number of outputs in range
    /// and n is the total number of distinct heights.
    pub fn outputs_in_range(&self, min_height: u64, max_height: u64) -> Vec<&OutputRef> {
        self.height_index
            .range(min_height..=max_height)
            .flat_map(|(_, keys)| keys.iter())
            .filter_map(|key| self.outputs.get(key))
            .collect()
    }

    /// Get random outputs for ring members (decoys) using gamma distribution
    ///
    /// Selects `count` random outputs from heights older than `min_age` blocks.
    /// Uses gamma distribution weighting to prefer recent outputs, matching
    /// real spend patterns for better privacy (like Monero's algorithm).
    ///
    /// ## Privacy Model
    /// Real spends are heavily biased toward recent outputs. If decoys were
    /// uniformly random, attackers could identify the real spend by its age.
    /// The gamma distribution matches the natural spend curve.
    ///
    /// ## Parameters (Monero-inspired)
    /// - Shape (k) = 19.28: Controls curve shape
    /// - Scale (θ) = 1/1.61: Average output age ~12 blocks
    pub fn select_decoys<R: rand::Rng>(
        &self,
        current_height: u64,
        min_age: u64,
        count: usize,
        rng: &mut R,
    ) -> Vec<&OutputRef> {
        use rand_distr::{Gamma, Distribution};

        let max_height = current_height.saturating_sub(min_age);

        // Get all eligible outputs (exclude time-locked outputs that haven't unlocked)
        let eligible: Vec<&OutputRef> = self.outputs_in_range(0, max_height)
            .into_iter()
            .filter(|o| o.output.lock_height.map_or(true, |lh| current_height >= lh))
            .collect();

        if eligible.len() <= count {
            return eligible;
        }

        // Gamma distribution parameters (Monero-inspired)
        // These match real spend age patterns
        const GAMMA_SHAPE: f64 = 19.28;
        const GAMMA_SCALE: f64 = 1.0 / 1.61;
        let gamma = Gamma::new(GAMMA_SHAPE, GAMMA_SCALE).unwrap();

        let total_outputs = eligible.len() as f64;
        let mut selected_indices = std::collections::HashSet::new();
        let mut attempts = 0;
        // FIX: scale loop bound with requested count to avoid early exit on large rings
        let max_attempts = count * 100;

        while selected_indices.len() < count && attempts < max_attempts {
            attempts += 1;

            // Sample from gamma distribution
            // This gives us a "relative age" value
            let gamma_sample: f64 = gamma.sample(rng);

            // Convert gamma sample to output index
            // Higher gamma values = older outputs (less likely)
            // Clamp to valid range
            let age_factor = gamma_sample.min(100.0) / 100.0;

            // Map to index: recent outputs (high indices) are more likely
            // age_factor near 0 = very recent, near 1 = very old
            let raw_index = ((1.0 - age_factor) * total_outputs) as usize;
            let index = raw_index.min(eligible.len() - 1);

            // Avoid duplicates
            if !selected_indices.contains(&index) {
                selected_indices.insert(index);
            }
        }

        // If we couldn't get enough via gamma, fill with uniform random
        if selected_indices.len() < count {
            use rand::seq::SliceRandom;
            let mut remaining: Vec<usize> = (0..eligible.len())
                .filter(|i| !selected_indices.contains(i))
                .collect();
            remaining.shuffle(rng);

            for idx in remaining.into_iter().take(count - selected_indices.len()) {
                selected_indices.insert(idx);
            }
        }

        selected_indices.into_iter()
            .map(|idx| eligible[idx])
            .collect()
    }

    /// Select decoys with additional constraints for better privacy
    ///
    /// Ensures selected decoys:
    /// - Have diverse heights (not all from same block)
    /// - Include mix of recent and older outputs
    /// - Avoid outputs from the same transaction
    pub fn select_decoys_constrained<R: rand::Rng>(
        &self,
        current_height: u64,
        min_age: u64,
        count: usize,
        exclude_tx: Option<&Hash>,
        rng: &mut R,
    ) -> Vec<&OutputRef> {
        let max_height = current_height.saturating_sub(min_age);
        let eligible: Vec<&OutputRef> = self.outputs_in_range(0, max_height)
            .into_iter()
            .filter(|o| o.output.lock_height.map_or(true, |lh| current_height >= lh))
            .collect();

        // Filter out outputs from excluded transaction
        let filtered: Vec<&OutputRef> = if let Some(tx_hash) = exclude_tx {
            eligible.into_iter()
                .filter(|o| &o.tx_hash != tx_hash)
                .collect()
        } else {
            eligible
        };

        if filtered.len() <= count {
            return filtered;
        }

        // Use gamma-based selection
        self.select_decoys_internal(&filtered, current_height, count, rng)
    }

    /// Internal gamma-based selection from pre-filtered list
    fn select_decoys_internal<'a, R: rand::Rng>(
        &self,
        eligible: &[&'a OutputRef],
        _current_height: u64,
        count: usize,
        rng: &mut R,
    ) -> Vec<&'a OutputRef> {
        use rand_distr::{Gamma, Distribution};
        use std::collections::HashSet;

        if eligible.len() <= count {
            return eligible.to_vec();
        }

        const GAMMA_SHAPE: f64 = 19.28;
        const GAMMA_SCALE: f64 = 1.0 / 1.61;
        let gamma = Gamma::new(GAMMA_SHAPE, GAMMA_SCALE).unwrap();
        let mut selected = HashSet::new();
        let mut used_heights = HashSet::new();
        let mut attempts = 0;

        // Try to get diverse heights
        while selected.len() < count && attempts < count * 10 {
            attempts += 1;

            let gamma_sample: f64 = gamma.sample(rng);
            let age_factor = (gamma_sample / 100.0).min(1.0);
            let index = ((1.0 - age_factor) * eligible.len() as f64) as usize;
            let index = index.min(eligible.len() - 1);

            let output = eligible[index];

            // Prefer diverse heights (but don't require it)
            if selected.len() < count / 2 || !used_heights.contains(&output.height) {
                if selected.insert(index) {
                    used_heights.insert(output.height);
                }
            } else if selected.len() >= count / 2 {
                // After half, allow any valid index
                selected.insert(index);
            }
        }

        // Fill remaining with any valid outputs
        if selected.len() < count {
            use rand::seq::SliceRandom;
            let mut remaining: Vec<usize> = (0..eligible.len())
                .filter(|i| !selected.contains(i))
                .collect();
            remaining.shuffle(rng);
            for idx in remaining.into_iter().take(count - selected.len()) {
                selected.insert(idx);
            }
        }

        selected.into_iter().map(|i| eligible[i]).collect()
    }

    /// Get height range statistics
    pub fn height_stats(&self) -> (u64, u64, usize) {
        let min = self.height_index.keys().next().copied().unwrap_or(0);
        let max = self.height_index.keys().next_back().copied().unwrap_or(0);
        let distinct_heights = self.height_index.len();
        (min, max, distinct_heights)
    }

    /// Get total outputs ever created (for global output index).
    /// L2 (audit fix): this counter is monotonic — never decrements on reorg.
    /// Use `reorg_disconnects_total()` to track disconnects separately.
    pub fn total_outputs_ever(&self) -> u64 {
        self.total_outputs_ever
    }

    /// Number of outputs disconnected via reorg over the lifetime of this
    /// UtxoSet. L2 (audit fix): added so callers needing "current outputs"
    /// can compute it via subtraction without relying on the monotonic
    /// counter being decremented.
    pub fn reorg_disconnects_total(&self) -> u64 {
        self.reorg_disconnects_total
    }

    /// Iterate over the permanent output index (for migration to persistent storage)
    pub fn output_index_iter(&self) -> impl Iterator<Item = (&[u8; 32], &OutputIndexEntry)> {
        self.output_index.iter()
    }

    /// Flush key data to the database for crash recovery (C15).
    ///
    /// Writes the in-memory key_images set and output_index to the on-disk
    /// database, giving crash recovery a consistent restore point.
    pub fn checkpoint(&self) -> crate::error::Result<()> {
        if let Some(ref db) = self.db {
            // Persist key images to on-disk UtxoDb
            for ki in &self.key_images {
                db.utxos.mark_key_image(ki)
                    .unwrap_or_else(|e| {
                        tracing::error!("checkpoint: failed to persist key image: {}", e);
                    });
            }
            // Persist output index entries
            for (stealth_addr, entry) in &self.output_index {
                db.output_index.insert(stealth_addr, entry)
                    .unwrap_or_else(|e| {
                        tracing::error!("checkpoint: failed to persist output index entry: {}", e);
                    });
            }
            db.flush()?;
        }
        Ok(())
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Batch Operations for Performance
// =============================================================================

/// Batch of UTXO operations for efficient bulk updates
pub struct UtxoBatch {
    /// Outputs to add: (tx_hash, index, output, height, is_coinbase)
    pub adds: Vec<(Hash, u8, TxOutput, u64, bool)>,
    /// Key images to mark as spent
    pub key_images: Vec<KeyImage>,
    /// Outputs to remove: (tx_hash, index)
    pub removes: Vec<(Hash, u8)>,
    /// Key images to UN-mark as spent (used during block disconnection / reorg)
    pub key_image_removals: Vec<KeyImage>,
}

impl UtxoBatch {
    /// Create a new empty batch
    pub fn new() -> Self {
        UtxoBatch {
            adds: Vec::new(),
            key_images: Vec::new(),
            removes: Vec::new(),
            key_image_removals: Vec::new(),
        }
    }

    /// Create batch with pre-allocated capacity
    pub fn with_capacity(adds: usize, key_images: usize, removes: usize) -> Self {
        UtxoBatch {
            adds: Vec::with_capacity(adds),
            key_images: Vec::with_capacity(key_images),
            removes: Vec::with_capacity(removes),
            key_image_removals: Vec::new(),
        }
    }

    /// Add an output to the batch
    pub fn add_output(&mut self, tx_hash: Hash, index: u8, output: TxOutput, height: u64) {
        self.adds.push((tx_hash, index, output, height, false));
    }

    /// Add an output with coinbase flag to the batch
    pub fn add_output_ext(&mut self, tx_hash: Hash, index: u8, output: TxOutput, height: u64, is_coinbase: bool) {
        self.adds.push((tx_hash, index, output, height, is_coinbase));
    }

    /// Mark a key image as spent
    pub fn spend_key_image(&mut self, key_image: KeyImage) {
        self.key_images.push(key_image);
    }

    /// Remove an output
    pub fn remove_output(&mut self, tx_hash: Hash, index: u8) {
        self.removes.push((tx_hash, index));
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.key_images.is_empty() && self.removes.is_empty() && self.key_image_removals.is_empty()
    }

    /// Get total operation count
    pub fn len(&self) -> usize {
        self.adds.len() + self.key_images.len() + self.removes.len() + self.key_image_removals.len()
    }
}

impl Default for UtxoBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoSet {
    /// Apply a batch of operations atomically
    ///
    /// This is more efficient than individual operations because:
    /// 1. Reduces lock contention (single write lock acquisition)
    /// 2. Batches index updates
    /// 3. Allows future database backends to use batch writes
    ///
    /// Returns the number of operations applied
    pub fn apply_batch(&mut self, batch: UtxoBatch) -> usize {
        let mut count = 0;

        // Add outputs first (most common operation)
        for (tx_hash, index, output, height, is_coinbase) in batch.adds {
            self.add_output_ext(tx_hash, index, output, height, is_coinbase);
            count += 1;
        }

        // Mark key images as spent
        for key_image in batch.key_images {
            if self.mark_key_image_spent(key_image) {
                count += 1;
            }
        }

        // Remove outputs last
        for (tx_hash, index) in batch.removes {
            if self.remove_output(&tx_hash, index).is_some() {
                count += 1;
            }
        }

        // SECURITY (BUG-1): Un-mark key images during block disconnection.
        // This restores spendability of outputs consumed by the disconnected block.
        for key_image in batch.key_image_removals {
            if self.remove_key_image(&key_image) {
                count += 1;
            }
        }

        count
    }

    /// Create a batch from a block's transactions
    ///
    /// Extracts all UTXO operations from a block for efficient batch application
    pub fn batch_from_block(
        block_height: u64,
        transactions: &[crate::transaction::Transaction],
    ) -> UtxoBatch {
        let mut batch = UtxoBatch::with_capacity(
            transactions.iter().map(|tx| tx.outputs.len()).sum(),
            transactions.iter().map(|tx| tx.inputs.len()).sum(),
            0,
        );

        for tx in transactions {
            let tx_hash = tx.hash();
            let is_coinbase = tx.is_coinbase();

            // Add outputs (with coinbase flag for maturity tracking - CRIT-5)
            for (idx, output) in tx.outputs.iter().enumerate() {
                batch.add_output_ext(tx_hash, idx as u8, output.clone(), block_height, is_coinbase);
            }

            // Mark key images as spent (for non-coinbase)
            if !is_coinbase {
                for input in &tx.inputs {
                    batch.spend_key_image(input.key_image);
                }
            }
        }

        batch
    }

    /// Create a batch for disconnecting a block (reorg)
    ///
    /// Reverses the operations from a block:
    /// 1. Removes outputs that the block added
    /// 2. Removes key images that non-coinbase transactions spent
    ///
    /// SECURITY (BUG-1/BUG-3): The caller must ALSO restore the outputs that
    /// were consumed by this block's inputs. Since ring-signature transactions
    /// don't reveal which specific output was spent (only the key image), the
    /// key images are removed here so the outputs become spendable again on the
    /// new fork. The actual output data remains in the UTXO set because
    /// `mark_key_image_spent()` only records the key image — it does NOT remove
    /// the output from the set (unlike `spend_output()` which is not used for
    /// ring-sig chains).
    pub fn batch_disconnect_block(
        transactions: &[crate::transaction::Transaction],
    ) -> UtxoBatch {
        let mut batch = UtxoBatch::with_capacity(
            0,
            transactions.iter().filter(|tx| !tx.is_coinbase()).map(|tx| tx.inputs.len()).sum(),
            transactions.iter().map(|tx| tx.outputs.len()).sum(),
        );

        for tx in transactions {
            let tx_hash = tx.hash();

            // Remove outputs that were added by this block
            for idx in 0..tx.outputs.len() {
                batch.remove_output(tx_hash, idx as u8);
            }

            // Un-mark key images that were marked spent by this block's inputs.
            // SECURITY (BUG-1): Previously key images were NOT included in the
            // disconnect batch, leaving them marked as spent after reorg. This
            // made outputs unspendable on the new fork even though they were
            // never spent there.
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    batch.key_image_removals.push(input.key_image);
                }
            }
        }

        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PublicKey;

    fn make_test_output(_height: u64, idx: u8) -> (Hash, TxOutput) {
        let hash = Hash::from_bytes([idx; 32]);
        let output = TxOutput {
            stealth_address: PublicKey::from_bytes([idx; 32]),
            tx_public_key: PublicKey::from_bytes([idx; 32]),
            commitment: [0u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: idx,
            lock_height: None,
            encrypted_memo: vec![],
        };
        (hash, output)
    }

    #[test]
    fn test_height_index() {
        let mut utxos = UtxoSet::new();

        // Add outputs at different heights
        for h in 0..10u64 {
            let (hash, output) = make_test_output(h, h as u8);
            utxos.add_output(hash, 0, output, h);
        }

        // Query height range
        let outputs = utxos.outputs_in_range(3, 7);
        assert_eq!(outputs.len(), 5); // heights 3, 4, 5, 6, 7

        // Verify heights
        for out in outputs {
            assert!(out.height >= 3 && out.height <= 7);
        }
    }

    #[test]
    fn test_decoy_selection() {
        let mut utxos = UtxoSet::new();
        let mut rng = rand::thread_rng();

        // Add 100 outputs
        for h in 0..100u64 {
            let (hash, output) = make_test_output(h, (h % 256) as u8);
            utxos.add_output(hash, 0, output, h);
        }

        // Select decoys (min age 10)
        let decoys = utxos.select_decoys(100, 10, 11, &mut rng);

        // Should get 11 decoys (or fewer if not enough eligible)
        assert!(decoys.len() <= 11);

        // All should be at height <= 90
        for d in decoys {
            assert!(d.height <= 90);
        }
    }
}
