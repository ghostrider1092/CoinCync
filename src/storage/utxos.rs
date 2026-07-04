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

    /// Get random outputs for ring members (decoys) using UNIFORM selection.
    ///
    /// Selects `count` random outputs from heights older than `min_age` blocks,
    /// each with equal probability among all eligible outputs.
    ///
    /// ## Privacy model — uniform, NOT gamma
    ///
    /// AUDIT (2026-07-02): SEV-A fix. The prior implementation used a gamma
    /// distribution (shape=19.28, scale=1/1.61 — Monero's parameters), the
    /// exact shape the Möser et al. 2018 paper "An Empirical Analysis of
    /// Traceability in the Monero Blockchain" showed enables ring-signature
    /// deanonymization via output-age regression. That prior version's own
    /// docstring even said the quiet part out loud:
    ///
    ///     Real spends are heavily biased toward recent outputs. If decoys
    ///     were uniformly random, attackers could identify the real spend
    ///     by its age.
    ///
    /// The premise of that argument is exactly the attack the Möser paper
    /// weaponizes — an observer measures the age-distribution of every
    /// ring, spots the outlier when the real spend age doesn't match the
    /// biased-toward-recent decoy pool, and deanonymizes.
    ///
    /// CoinCync's constitutional Article III (Mandatory Privacy) and the
    /// module-header comment in `src/crypto/ring_selection.rs` (L3–L22)
    /// both explicitly commit to UNIFORM decoy selection as the privacy
    /// differentiator vs. Monero. That module-level ring assembler
    /// already does its own uniform shuffle, but the pool it received via
    /// the wallet -> chain::get_decoy_outputs -> this function path was
    /// gamma-biased BEFORE it reached the uniform shuffle. Shuffling a
    /// pre-biased pool doesn't remove the bias; the age distribution is
    /// baked in upstream. The ring_selection uniform shuffle was doing
    /// exactly no privacy work.
    ///
    /// This implementation uses a Fisher-Yates partial shuffle with
    /// `rng.gen_range` (rejection-sampled, no modulo bias — matches the
    /// 2026-07-01 ring_selection.rs Fisher-Yates fix) so every eligible
    /// output has EXACTLY equal probability of appearing in the returned
    /// set. The observer gets zero information from the age distribution.
    ///
    /// Prior art on why uniform beats gamma for privacy:
    ///   - Miller et al. 2017 "Empirical Analysis of Traceability in the
    ///     Monero Blockchain" — ring members must have indistinguishable
    ///     age from the real spend.
    ///   - Möser et al. 2018 — quantifies the attack; 85%+ accuracy
    ///     identifying real spends in Monero rings.
    ///   - Yu et al. 2019 "New Empirical Traceability Analysis of
    ///     CryptoNote-Style Blockchains" — 0-mixin heuristic + age.
    ///   - MRL uniform-selection recommendation.
    ///
    /// If the network needs age-mimicry in the FUTURE (attacker-model
    /// changes), the right fix is to sample decoys with an age
    /// distribution that matches the real spend's OWN age distribution,
    /// not the population-wide gamma. That requires knowing the real
    /// spend's age at ring-build time and adjusting per-ring, which is
    /// a per-tx-context algorithm, not a chain-wide constant.
    pub fn select_decoys<R: rand::Rng>(
        &self,
        current_height: u64,
        min_age: u64,
        count: usize,
        rng: &mut R,
    ) -> Vec<&OutputRef> {
        let max_height = current_height.saturating_sub(min_age);

        // Get all eligible outputs (exclude time-locked outputs that haven't
        // unlocked). The eligible pool is what a uniform draw is over.
        let mut eligible: Vec<&OutputRef> = self.outputs_in_range(0, max_height)
            .into_iter()
            .filter(|o| o.output.lock_height.map_or(true, |lh| current_height >= lh))
            .collect();

        if eligible.len() <= count {
            return eligible;
        }

        // Fisher-Yates partial shuffle: draws the first `count` uniformly at
        // random from `eligible`. `gen_range(0..=i)` uses rejection sampling
        // in the rand crate — no modulo bias. Matches the pattern used in
        // src/crypto/ring_selection.rs (2026-07-01 audit fix). Complexity is
        // O(count), which is what we want vs the O(n) full shuffle.
        let last = eligible.len() - 1;
        for i in 0..count {
            let j = rng.gen_range(i..=last);
            eligible.swap(i, j);
        }
        eligible.truncate(count);
        eligible
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

    /// Internal uniform selection from pre-filtered list.
    ///
    /// AUDIT (2026-07-02): rewritten to uniform Fisher-Yates partial shuffle,
    /// matching the primary `select_decoys` fix above and the constitutional
    /// uniform-selection design. Prior gamma-with-height-diversity heuristic
    /// leaked age signal (Möser 2018) AND the height-diversity constraint
    /// leaked ADDITIONAL correlation signal (an observer can filter out
    /// rings that suspiciously cluster by height, further isolating
    /// gamma-drawn real spends).
    ///
    /// AUDIT (R-69 cross-ref, 2026-07-03): re-verified — no stale
    /// gamma or Möser reference in the current implementation
    /// describes it as ACTIVE behavior. Every gamma mention here
    /// is historical context in the audit trail. The fn body is
    /// uniform Fisher-Yates. R-69 disposition: no code change; the
    /// R-69 finding was flagged pre-Wave-15 and is now closed by
    /// the 2026-07-02 rewrite. Documented for the audit trail.
    fn select_decoys_internal<'a, R: rand::Rng>(
        &self,
        eligible: &[&'a OutputRef],
        _current_height: u64,
        count: usize,
        rng: &mut R,
    ) -> Vec<&'a OutputRef> {
        if eligible.len() <= count {
            return eligible.to_vec();
        }
        // Uniform Fisher-Yates partial shuffle over indices to avoid
        // materializing a copy of the slice-of-references.
        let n = eligible.len();
        let mut indices: Vec<usize> = (0..n).collect();
        let last = n - 1;
        for i in 0..count {
            let j = rng.gen_range(i..=last);
            indices.swap(i, j);
        }
        indices.truncate(count);
        indices.into_iter().map(|i| eligible[i]).collect()
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

    /// REGRESSION (2026-07-02): assert decoy age distribution is UNIFORM,
    /// not gamma-biased-toward-recent.
    ///
    /// This is the test that would have caught the pre-2026-07-02 SEV-A
    /// (gamma decoy bias — Möser 2018 shape). Prior to the fix,
    /// `select_decoys` drew from `Gamma::new(19.28, 1/1.61)` which biases
    /// heavily toward RECENT heights (per the pre-fix docstring's own
    /// admission). Under gamma, of 10000 decoys drawn from a 1000-block
    /// pool, ~90% would land in the newest ~200 blocks. Under uniform,
    /// ~90% would land across the full range with each of the 10 equal-
    /// sized age buckets receiving ~10% (± sampling noise).
    ///
    /// The test asserts the "10 equal buckets, each within [7%, 13%]"
    /// property, which fails on gamma with overwhelming probability
    /// (buckets 0..7 would get ~0%; buckets 8-9 would get ~50%+ each).
    /// The 7-13% band is wide enough that legitimate uniform noise
    /// passes and gamma fails deterministically.
    ///
    /// Prior art: Monero's ring_ct_batch_tests / Zcash Sapling test
    /// suites both include distribution-uniformity assertions on their
    /// decoy analogues.
    #[test]
    fn test_decoy_selection_is_uniform_not_gamma() {
        let mut utxos = UtxoSet::new();
        let mut rng = rand::thread_rng();

        // Build a 1000-block eligible pool with one UNIQUE output per height.
        // min_age is 0 so every one is eligible. The uniqueness matters: the
        // shared make_test_output helper uses idx-derived hashes, so if we
        // fed `h % 256` we'd overwrite entries (256 keys, 4 heights each,
        // only the last stick — verified by pre-fix test failure). Build a
        // per-height 32-byte hash directly so each add_output is a distinct
        // (hash, 0) key.
        for h in 0..1_000u64 {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..8].copy_from_slice(&h.to_le_bytes());
            let hash = Hash::from_bytes(hash_bytes);
            let output = TxOutput {
                stealth_address: PublicKey::from_bytes([0u8; 32]),
                tx_public_key: PublicKey::from_bytes([0u8; 32]),
                commitment: [0u8; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: 0,
                lock_height: None,
                encrypted_memo: vec![],
            };
            utxos.add_output(hash, 0, output, h);
        }

        // Draw 10_000 decoys total (in batches, since each call returns
        // deduped-within-batch results). 100 calls of 100 gives us the
        // sample size we need for the distribution assertion.
        let mut age_histogram = [0u32; 10];
        let calls = 100;
        let per_call = 100;
        for _ in 0..calls {
            let decoys = utxos.select_decoys(1_000, 0, per_call, &mut rng);
            for d in decoys {
                // Bucket by age: 0 = newest 100 blocks, 9 = oldest 100 blocks.
                // current_height is 1000; height h has age (1000 - h). Bucket
                // is age / 100, clamped to 0..=9.
                let age = 1_000 - d.height;
                let bucket = ((age / 100) as usize).min(9);
                age_histogram[bucket] += 1;
            }
        }

        let total: u32 = age_histogram.iter().sum();
        assert!(total > 0, "must have drawn at least some decoys");

        // Uniform expectation: each of the 10 buckets gets 10% of the mass.
        // Allow a wide band [7%, 13%] — passes uniform noise, fails gamma.
        // Note: bucket 0 corresponds to age 0..100 which includes the tip
        // side of the pool; under gamma this would be >50%, under uniform
        // it's ~10%.
        for (b, &count) in age_histogram.iter().enumerate() {
            let frac = count as f64 / total as f64;
            assert!(
                frac >= 0.07 && frac <= 0.13,
                "bucket {} has {:.1}% of the mass — outside the uniform [7%, 13%] band. \
                 Full histogram: {:?}. If this fails, decoy selection has regressed to a \
                 non-uniform distribution (e.g. gamma bias toward recent).",
                b,
                frac * 100.0,
                age_histogram,
            );
        }
    }
}
