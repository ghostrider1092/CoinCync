//! UTXO set storage with height indexing for fast decoy selection

use crate::db::{Database, OutputIndexEntry};
use crate::decoy::{HeightOutputCount, OutputLocator, ResolvedDecoyOutput};
use crate::error::{Error, Result};
use crate::primitives::{Hash, KeyImage, PublicKey};
use crate::transaction::TxOutput;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

struct LocatorOutput {
    public_key: PublicKey,
    commitment: [u8; 32],
    height: u64,
    is_coinbase: bool,
    lock_height: Option<u64>,
}

/// UTXO set with height index for fast ring member selection
///
/// The height index provides ordered lookup by height. Decoy selection may scan
/// additional heights and outputs when the canonical set is sparse or locked.
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
    /// Canonical all-output catalog. Entries survive spends so `(height,
    /// ordinal)` remains stable and are removed only when their block disconnects.
    locator_index: BTreeMap<u64, BTreeSet<OutputKey>>,
    locator_outputs: HashMap<OutputKey, LocatorOutput>,
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
            locator_index: BTreeMap::new(),
            locator_outputs: HashMap::new(),
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
    pub fn add_output_ext(
        &mut self,
        tx_hash: Hash,
        index: u8,
        output: TxOutput,
        height: u64,
        is_coinbase: bool,
    ) {
        let key = (tx_hash, index);
        let stealth_addr = *output.stealth_address.as_bytes();
        let public_key = output.stealth_address;
        let commitment = output.commitment;
        let lock_height = output.lock_height;
        let output_ref = OutputRef {
            tx_hash,
            index,
            output,
            height,
            is_coinbase,
        };

        // Add to primary storage
        self.outputs.insert(key, output_ref);

        // Add to height index
        self.height_index
            .entry(height)
            .or_insert_with(BTreeSet::new)
            .insert(key);

        self.locator_index
            .entry(height)
            .or_insert_with(BTreeSet::new)
            .insert(key);
        self.locator_outputs.insert(
            key,
            LocatorOutput {
                public_key,
                commitment,
                height,
                is_coinbase,
                lock_height,
            },
        );

        // Add to stealth address index (CRIT-5, HIGH-4)
        // Use or_insert to keep the OLDEST output per stealth_address.
        // Old coinbase outputs share stealth_address = miner_pubkey; keeping the oldest
        // ensures maturity checks find a mature output, not the latest immature one.
        self.stealth_index.entry(stealth_addr).or_insert(key);

        // Add to permanent output index (oldest wins, matching stealth_index)
        // This index persists across spends — entries are only removed during reorg.
        self.output_index
            .entry(stealth_addr)
            .or_insert(OutputIndexEntry {
                commitment,
                height,
                is_coinbase,
                lock_height,
            });

        self.total_outputs_ever += 1;
    }

    /// Spend an output (mark key image as spent and remove output)
    pub fn spend_output(&mut self, tx_hash: Hash, index: u8, key_image: KeyImage) -> bool {
        if self.key_images.contains(&key_image) {
            return false;
        }
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
        if self.key_images.contains(&key_image) {
            return false;
        }
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
        self.stealth_index
            .get(stealth_addr)
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

    /// Remove an output (used during block disconnection).
    ///
    /// AUDIT (R-68 fix, 2026-07-03): the pre-fix code removed the
    /// stealth entry from the in-memory `self.output_index` HashMap
    /// (L64 field, ~1000-block cache), but did NOT propagate the
    /// removal to `self.db.output_index` (the persistent RocksDB
    /// index at L66 field). During a reorg that disconnects the
    /// creating block for a UTXO, the on-disk output_index still
    /// carried the entry. Ring-member validation for a subsequent
    /// transaction using that stealth address as a decoy would then
    /// look up the on-disk row, find it, and ACCEPT the ring member
    /// — the disconnected UTXO acts as a valid ring member for a
    /// chain in which it no longer exists. That's a real
    /// consensus-visibility bug: transactions signed under the
    /// pre-fix code with such rings would be accepted by nodes that
    /// hadn't rolled back their on-disk output_index yet, and
    /// rejected by nodes that had. A partitioned mempool follows.
    ///
    /// Fix: propagate the removal to the on-disk DB. Failure to
    /// remove is a corruption event — we log it loudly and continue
    /// (the in-memory state IS rolled back, and a next-startup
    /// reindex will re-derive the on-disk state from the chain).
    pub fn remove_output(&mut self, tx_hash: &Hash, index: u8) -> Option<OutputRef> {
        let key = (*tx_hash, index);
        let locator_output = self.locator_outputs.remove(&key);
        if let Some(output) = locator_output.as_ref() {
            if let Some(set) = self.locator_index.get_mut(&output.height) {
                set.remove(&key);
                if set.is_empty() {
                    self.locator_index.remove(&output.height);
                }
            }
        }
        let output_ref = self.outputs.remove(&key);
        if let Some(output_ref) = output_ref.as_ref() {
            // Remove from height index
            if let Some(set) = self.height_index.get_mut(&output_ref.height) {
                set.remove(&key);
                if set.is_empty() {
                    self.height_index.remove(&output_ref.height);
                }
            }
        }
        let stealth_addr = output_ref
            .as_ref()
            .map(|output| *output.output.stealth_address.as_bytes())
            .or_else(|| {
                locator_output
                    .as_ref()
                    .map(|output| *output.public_key.as_bytes())
            });
        if let Some(stealth_addr) = stealth_addr {
            self.stealth_index.remove(&stealth_addr);
            // Remove from permanent output index (reorg only)
            self.output_index.remove(&stealth_addr);
            // R-68: propagate to on-disk output_index so ring-member
            // validation on other nodes / after restart doesn't
            // accept the disconnected UTXO as a valid decoy.
            if let Some(ref db) = self.db {
                if let Err(e) = db.output_index.remove(&stealth_addr) {
                    tracing::error!(
                        target: "storage::utxos::R68",
                        stealth = hex::encode(stealth_addr),
                        tx_hash = hex::encode(tx_hash.as_bytes()),
                        error = %e,
                        "R-68: reorg removal failed to propagate to on-disk \
                         output_index. Ring-member validation MAY accept this \
                         disconnected UTXO as a valid decoy on next startup. \
                         Reindex output_index from block store to recover."
                    );
                }
            }
            // L2 (audit fix): total_outputs_ever is now MONOTONIC — never
            // decrements, even on reorg. The previous decrement violated the
            // "ever created" semantics. Reorg disconnects are tracked
            // separately in reorg_disconnects_total so monitors that need
            // "current load" can compute it from the difference.
            self.reorg_disconnects_total = self.reorg_disconnects_total.saturating_add(1);
        }
        output_ref
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

    pub fn output_distribution(&self, up_to_height: u64) -> Vec<HeightOutputCount> {
        self.locator_index
            .range(..=up_to_height)
            .map(|(height, keys)| HeightOutputCount {
                height: *height,
                count: keys.len() as u32,
            })
            .collect()
    }

    pub fn resolve_output_locators(
        &self,
        locators: &[OutputLocator],
    ) -> Result<Vec<ResolvedDecoyOutput>> {
        let mut seen = HashSet::with_capacity(locators.len());
        let mut resolved = Vec::with_capacity(locators.len());

        for locator in locators {
            if !seen.insert(*locator) {
                return Err(Error::InvalidState(format!(
                    "duplicate output locator at height {} ordinal {}",
                    locator.height, locator.ordinal
                )));
            }

            let keys = self.locator_index.get(&locator.height).ok_or_else(|| {
                Error::InvalidState(format!(
                    "output locator references unknown height {}",
                    locator.height
                ))
            })?;
            let key = keys.iter().nth(locator.ordinal as usize).ok_or_else(|| {
                Error::InvalidState(format!(
                    "output locator ordinal {} is outside height {} bucket of {} outputs",
                    locator.ordinal,
                    locator.height,
                    keys.len()
                ))
            })?;
            let output_ref = self.locator_outputs.get(key).ok_or_else(|| {
                Error::InvalidState(format!(
                    "output locator at height {} ordinal {} has no canonical output",
                    locator.height, locator.ordinal
                ))
            })?;

            resolved.push(ResolvedDecoyOutput {
                locator: *locator,
                public_key: output_ref.public_key,
                commitment: output_ref.commitment,
                height: output_ref.height,
                is_coinbase: output_ref.is_coinbase,
                lock_height: output_ref.lock_height,
            });
        }

        Ok(resolved)
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
    ///
    /// AUDIT (R-70 fix, 2026-07-03): the pre-fix code used
    /// `.unwrap_or_else(|e| tracing::error!(...))` for each per-item
    /// persistence failure and then `Ok(())` at the end. If the disk
    /// failed for even one key_image or output_index entry, checkpoint
    /// returned Ok — the caller thought the checkpoint was durable, but
    /// on restart the missing entries would let a double-spend through
    /// (missing key_image) or admit a stale ring member (missing
    /// output_index). This is a silent partial-checkpoint bug —
    /// the exact class the checkpoint API is supposed to prevent.
    ///
    /// Fix: track per-item failures. If ANY persistence op failed, return
    /// Err with a count so the caller can decide to retry or halt.
    /// `db.flush()?` at the end still propagates a flush-level failure
    /// as before.
    pub fn checkpoint(&self) -> crate::error::Result<()> {
        if let Some(ref db) = self.db {
            let mut ki_failures = 0usize;
            let mut oi_failures = 0usize;

            // Persist key images to on-disk UtxoDb
            for ki in &self.key_images {
                if let Err(e) = db.utxos.mark_key_image(ki) {
                    ki_failures += 1;
                    tracing::error!(
                        target: "storage::utxos::R70",
                        key_image = hex::encode(ki.as_bytes()),
                        error = %e,
                        "R-70: checkpoint failed to persist key_image"
                    );
                }
            }
            // Persist output index entries
            for (stealth_addr, entry) in &self.output_index {
                if let Err(e) = db.output_index.insert(stealth_addr, entry) {
                    oi_failures += 1;
                    tracing::error!(
                        target: "storage::utxos::R70",
                        stealth = hex::encode(stealth_addr),
                        error = %e,
                        "R-70: checkpoint failed to persist output_index entry"
                    );
                }
            }

            db.flush()?;

            if ki_failures > 0 || oi_failures > 0 {
                return Err(crate::error::Error::DatabaseError(format!(
                    "R-70: checkpoint reported {} key_image + {} output_index \
                     persistence failures. Checkpoint is NOT a valid restore \
                     point; caller must retry or halt.",
                    ki_failures, oi_failures
                )));
            }
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
    pub fn add_output_ext(
        &mut self,
        tx_hash: Hash,
        index: u8,
        output: TxOutput,
        height: u64,
        is_coinbase: bool,
    ) {
        self.adds
            .push((tx_hash, index, output, height, is_coinbase));
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
        self.adds.is_empty()
            && self.key_images.is_empty()
            && self.removes.is_empty()
            && self.key_image_removals.is_empty()
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
    /// Apply a batch of operations.
    ///
    /// AUDIT (R-71 fix, 2026-07-03): the pre-fix docstring said
    /// "Apply a batch of operations ATOMICALLY". That was WRONG.
    /// The implementation is a sequential loop that calls
    /// `add_output`, `spend_key_image`, and `remove_output` one at
    /// a time (see the loop bodies below). There is NO transaction
    /// boundary — a panic mid-batch (OOM, cross-thread poison)
    /// leaves the UtxoSet with PARTIAL mutations applied. Callers
    /// who read the old docstring and assumed atomicity built
    /// invariant checks that could silently be violated after a
    /// panic-recovery.
    ///
    /// The current implementation IS "more efficient than individual
    /// operations" (bullets 1-3 below stand), but "atomically" was a
    /// lie. Truth-corrected docstring below.
    ///
    /// This is more efficient than individual operations because:
    /// 1. Reduces lock contention (single write lock acquisition
    ///    across the whole batch, assuming the caller wraps this in
    ///    the chain's write lock).
    /// 2. Batches index updates.
    /// 3. Allows future database backends to use batch writes.
    ///
    /// A future refactor should wrap the whole batch in a single
    /// on-disk RocksBatch (via the shim Transactional trait) so the
    /// atomicity claim CAN be truthfully made. Deferred because the
    /// current in-memory state model doesn't map cleanly to a
    /// batch-commit primitive without a large rework of index
    /// updates.
    ///
    /// Returns the number of operations applied.
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
                batch.add_output_ext(
                    tx_hash,
                    idx as u8,
                    output.clone(),
                    block_height,
                    is_coinbase,
                );
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
    pub fn batch_disconnect_block(transactions: &[crate::transaction::Transaction]) -> UtxoBatch {
        let mut batch = UtxoBatch::with_capacity(
            0,
            transactions
                .iter()
                .filter(|tx| !tx.is_coinbase())
                .map(|tx| tx.inputs.len())
                .sum(),
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
    use crate::decoy::OutputLocator;
    use crate::primitives::PublicKey;

    fn make_test_output(id: u64, lock_height: Option<u64>) -> (Hash, TxOutput) {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&id.to_le_bytes());
        bytes[8] = 1;
        let hash = Hash::from_bytes(bytes);
        let output = TxOutput {
            stealth_address: PublicKey::from_bytes(bytes),
            tx_public_key: PublicKey::from_bytes(bytes),
            commitment: [0u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: id as u8,
            lock_height,
            encrypted_memo: vec![],
        };
        (hash, output)
    }

    fn add_test_output(
        utxos: &mut UtxoSet,
        id: u64,
        height: u64,
        lock_height: Option<u64>,
    ) -> Hash {
        let (hash, output) = make_test_output(id, lock_height);
        utxos.add_output(hash, 0, output, height);
        hash
    }

    // Regression for the ring-size determinism launch-blocker (2026-08-16):
    // the consensus "available outputs" metric that feeds effective_ring_size
    // MUST be independent of a node's reorg history, or two nodes on the same
    // canonical tip can require different ring sizes and fork the chain.
    #[test]
    fn ring_size_availability_is_reorg_history_invariant() {
        // Node A: synced 5 canonical outputs directly.
        let mut a = UtxoSet::new();
        for i in 0..5u64 {
            add_test_output(&mut a, i, 1, None);
        }

        // Node B: same 5 canonical outputs, but it also saw 3 orphan outputs on
        // a fork block that was later reorged away (added, then disconnected).
        let mut b = UtxoSet::new();
        for i in 0..5u64 {
            add_test_output(&mut b, i, 1, None);
        }
        let orphans: Vec<Hash> = (100..103u64)
            .map(|i| add_test_output(&mut b, i, 2, None))
            .collect();
        for h in &orphans {
            b.remove_output(h, 0); // reorg disconnect
        }

        // The raw monotonic counter DIVERGES — this is the bug surface.
        assert_ne!(a.total_outputs_ever(), b.total_outputs_ever());
        // The fixed availability metric (ever - reorg_disconnects) is invariant.
        let avail_a = a.total_outputs_ever().saturating_sub(a.reorg_disconnects_total());
        let avail_b = b.total_outputs_ever().saturating_sub(b.reorg_disconnects_total());
        assert_eq!(avail_a, 5, "node A canonical availability");
        assert_eq!(avail_b, 5, "reorg history must not change availability");
        // ...so both nodes require the SAME ring size for a block at this tip.
        assert_eq!(
            crate::constants::effective_ring_size(3, avail_a as usize),
            crate::constants::effective_ring_size(3, avail_b as usize),
            "two nodes on the same tip must require the same ring size",
        );
    }

    #[test]
    fn test_height_index() {
        let mut utxos = UtxoSet::new();

        for h in 0..10u64 {
            add_test_output(&mut utxos, h, h, None);
        }

        let outputs = utxos.outputs_in_range(3, 7);
        assert_eq!(outputs.len(), 5);

        for out in outputs {
            assert!(out.height >= 3 && out.height <= 7);
        }
    }

    #[test]
    fn reorg_batches_replace_orphaned_outputs_in_decoy_catalog() {
        let mut utxos = UtxoSet::new();
        let (old_hash, old_output) = make_test_output(1, None);
        let old_public_key = old_output.stealth_address;
        let mut connect_old = UtxoBatch::new();
        connect_old.add_output(old_hash, 0, old_output.clone(), 100);
        utxos.apply_batch(connect_old);

        let locator = OutputLocator {
            height: 100,
            ordinal: 0,
        };
        assert_eq!(
            utxos.resolve_output_locators(&[locator]).unwrap()[0].public_key,
            old_public_key
        );

        let mut disconnect_old = UtxoBatch::new();
        disconnect_old.remove_output(old_hash, 0);
        utxos.apply_batch(disconnect_old);
        assert!(utxos.resolve_output_locators(&[locator]).is_err());

        let (new_hash, new_output) = make_test_output(2, None);
        let new_public_key = new_output.stealth_address;
        let mut connect_new = UtxoBatch::new();
        connect_new.add_output(new_hash, 0, new_output, 100);
        utxos.apply_batch(connect_new);

        let resolved = utxos.resolve_output_locators(&[locator]).unwrap();
        assert_eq!(resolved[0].public_key, new_public_key);
        assert_ne!(resolved[0].public_key, old_public_key);
    }

    #[test]
    fn canonical_locators_ignore_insertion_order() {
        let mut left = UtxoSet::new();
        let mut right = UtxoSet::new();
        let outputs = [
            make_test_output(3, None),
            make_test_output(1, None),
            make_test_output(2, None),
        ];

        for (hash, output) in outputs.iter().cloned() {
            left.add_output(hash, 0, output, 40);
        }
        for (hash, output) in outputs.iter().cloned().rev() {
            right.add_output(hash, 0, output, 40);
        }

        let locators = [
            OutputLocator {
                height: 40,
                ordinal: 0,
            },
            OutputLocator {
                height: 40,
                ordinal: 2,
            },
        ];
        let left_keys: Vec<_> = left
            .resolve_output_locators(&locators)
            .unwrap()
            .into_iter()
            .map(|output| output.public_key)
            .collect();
        let right_keys: Vec<_> = right
            .resolve_output_locators(&locators)
            .unwrap()
            .into_iter()
            .map(|output| output.public_key)
            .collect();

        assert_eq!(left_keys, right_keys);
    }

    #[test]
    fn canonical_locators_survive_output_spends() {
        let mut utxos = UtxoSet::new();
        let first = add_test_output(&mut utxos, 1, 40, None);
        add_test_output(&mut utxos, 2, 40, None);
        let locators = [
            OutputLocator {
                height: 40,
                ordinal: 0,
            },
            OutputLocator {
                height: 40,
                ordinal: 1,
            },
        ];
        let before = utxos.resolve_output_locators(&locators).unwrap();

        assert!(utxos.spend_output(first, 0, KeyImage::from_bytes([9; 32])));

        let after = utxos.resolve_output_locators(&locators).unwrap();
        assert_eq!(after, before);
        assert_eq!(utxos.output_distribution(40)[0].count, 2);
    }

    #[test]
    fn locator_resolution_rejects_out_of_range_ordinal() {
        let mut utxos = UtxoSet::new();
        add_test_output(&mut utxos, 1, 40, None);

        let result = utxos.resolve_output_locators(&[OutputLocator {
            height: 40,
            ordinal: 1,
        }]);

        assert!(result.is_err());
    }

    #[test]
    fn output_distribution_is_height_sorted_and_bounded() {
        let mut utxos = UtxoSet::new();
        add_test_output(&mut utxos, 1, 20, None);
        add_test_output(&mut utxos, 2, 10, None);
        add_test_output(&mut utxos, 3, 20, None);
        add_test_output(&mut utxos, 4, 30, None);

        let distribution = utxos.output_distribution(20);

        assert_eq!(distribution.len(), 2);
        assert_eq!(distribution[0].height, 10);
        assert_eq!(distribution[0].count, 1);
        assert_eq!(distribution[1].height, 20);
        assert_eq!(distribution[1].count, 2);
    }
}
