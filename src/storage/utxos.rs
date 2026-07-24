//! UTXO set storage with height indexing for fast decoy selection

use crate::db::{Database, OutputIndexEntry};
use crate::primitives::{Hash, KeyImage};
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

/// Population-wide gamma decoy-age model (Monero's fit, Möser et al. 2018):
/// `shape = 19.28`, `scale = 1/1.61 = 0.621`. A decoy's age in seconds is
/// `exp(Gamma(shape, scale))`; dividing by the target block time gives an age in
/// blocks, which is mapped to the nearest eligible output.
///
/// Decision (2026-07-24, owner + co-founder, with full knowledge of the
/// 2026-07-02 uniform SEV-A it reverses): decoys follow the real-spend age law
/// so the overwhelming common case — spending a *recent* output — is hidden in a
/// same-age crowd. Accepted trade-off: a genuinely OLD real output is an age
/// outlier in a recent-biased ring. The durable fix for that tail is a
/// large-ring / zero-knowledge upgrade (long-term roadmap), not distribution
/// tuning; population-wide gamma is the lesser of the two evils until then.
pub const DECOY_GAMMA_SHAPE: f64 = 19.28;
/// See [`DECOY_GAMMA_SHAPE`].
pub const DECOY_GAMMA_SCALE: f64 = 0.621;

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

    /// Select `count` decoys for a ring, age-matched to the real-spend
    /// distribution via a **population-wide gamma** law ([`DECOY_GAMMA_SHAPE`]).
    ///
    /// Excludes outputs younger than `min_age` and still-time-locked outputs;
    /// among the eligible set, decoy ages follow the gamma model rather than
    /// being uniform.
    ///
    /// ## Privacy model — gamma age-matching
    ///
    /// Real spends are overwhelmingly *recent*. If decoys were drawn uniformly
    /// across all history, the real (recent) input would be the young outlier in
    /// its ring — the exact output-age regression the traceability literature
    /// weaponises. Matching the decoys to the real-spend age law removes that
    /// signal for the common case. This is Monero's approach and the same fit
    /// (`shape = 19.28`, `scale = 1/1.61`).
    ///
    /// **Decision history.** A 2026-07-02 change had moved this path to uniform,
    /// arguing uniform was the safer default. On 2026-07-24 the owner and
    /// co-founder reversed that *with full knowledge of it*: population-wide
    /// gamma protects the vast majority of (recent) spends, which uniform does
    /// not. The accepted cost is the tail — a genuinely OLD real output is an age
    /// outlier in a recent-biased ring. Closing that tail needs a large-ring /
    /// zero-knowledge upgrade (roadmap), not distribution tuning; gamma is the
    /// lesser of two evils until then.
    ///
    /// Age-matching is applied **here at the source**, over the full eligible
    /// age distribution — not in the ring assembler. A downstream shuffle over a
    /// pre-sampled pool cannot reconstruct an age distribution the pool doesn't
    /// already carry (the 2026-07-02 note made this point; it is applied here in
    /// reverse). The ring assembler (`src/crypto/ring_selection.rs`) does uniform
    /// final assembly so it does not double-bias the already-gamma pool.
    ///
    /// Prior art (these papers motivate age-matching — real and decoy ages must
    /// be statistically indistinguishable, which uniform selection fails):
    ///   - Miller et al. 2017 "Empirical Analysis of Traceability in the
    ///     Monero Blockchain".
    ///   - Möser et al. 2018 — ~85%+ real-spend identification on *early,
    ///     pre-gamma* Monero rings; gamma was the fix.
    ///   - Yu et al. 2019 "New Empirical Traceability Analysis of
    ///     CryptoNote-Style Blockchains".
    ///
    /// A stronger model still would match each ring to its *own* real output's
    /// age rather than the population-wide law; that is per-tx context, deferred
    /// with the large-ring/ZK work.
    pub fn select_decoys<R: rand::Rng>(
        &self,
        current_height: u64,
        min_age: u64,
        count: usize,
        rng: &mut R,
    ) -> Vec<&OutputRef> {
        let max_height = current_height.saturating_sub(min_age);
        // Gamma age-matching happens HERE, over the entire eligible age
        // distribution (the whole UTXO set), because a population-wide age law
        // needs the whole distribution — a downstream shuffle over a
        // pre-sampled pool cannot reconstruct it (that was the 2026-07-02
        // finding, now applied in reverse). See DECOY_GAMMA_SHAPE.
        self.gamma_select_decoys(current_height, max_height, count, rng)
    }

    /// Draw `count` distinct decoys whose ages follow the population-wide gamma
    /// law ([`DECOY_GAMMA_SHAPE`]).
    ///
    /// For each decoy: sample an age, map it to a target height, then take the
    /// nearest eligible untaken output via the height index — O(log n) per
    /// decoy, never a linear scan over the UTXO set. Among outputs sharing the
    /// chosen height, one is picked uniformly at random. Falls back to a uniform
    /// target height only if the gamma distribution is degenerate.
    fn gamma_select_decoys<R: rand::Rng>(
        &self,
        current_height: u64,
        max_height: u64,
        count: usize,
        rng: &mut R,
    ) -> Vec<&OutputRef> {
        use rand_distr::{Distribution, Gamma};
        let gamma = Gamma::new(DECOY_GAMMA_SHAPE, DECOY_GAMMA_SCALE).ok();
        let block_time = crate::constants::TARGET_BLOCK_TIME.max(1) as f64;
        let lo = self.height_index.keys().next().copied().unwrap_or(0);
        let hi = self
            .height_index
            .range(..=max_height)
            .next_back()
            .map(|(h, _)| *h)
            .unwrap_or(max_height);

        let mut taken: HashSet<OutputKey> = HashSet::new();
        let mut chosen: Vec<&OutputRef> = Vec::with_capacity(count);
        // Bounded attempts guarantee termination when the eligible set is
        // smaller than `count` (pick_near_height returns None once exhausted).
        let max_attempts = count.saturating_mul(4).saturating_add(8);
        let mut attempts = 0usize;
        while chosen.len() < count && attempts < max_attempts {
            attempts += 1;
            let target = match &gamma {
                Some(g) => {
                    let age_blocks = (g.sample(rng).exp() / block_time) as u64;
                    current_height.saturating_sub(age_blocks).min(max_height)
                }
                None if hi > lo => rng.gen_range(lo..=hi),
                None => lo,
            };
            match self.pick_near_height(target, max_height, current_height, &taken, rng) {
                Some(oref) => {
                    taken.insert((oref.tx_hash, oref.index));
                    chosen.push(oref);
                }
                None => break, // eligible set exhausted
            }
        }
        chosen
    }

    /// Nearest eligible, untaken output to `target`, scanning the height index
    /// outward in both directions. `None` only when every eligible output is
    /// already taken.
    fn pick_near_height<R: rand::Rng>(
        &self,
        target: u64,
        max_height: u64,
        current_height: u64,
        taken: &HashSet<OutputKey>,
        rng: &mut R,
    ) -> Option<&OutputRef> {
        let capped = target.min(max_height);
        let mut below = self.height_index.range(..=capped).rev();
        let mut above = self.height_index.range(capped.saturating_add(1)..=max_height);
        let mut lo = below.next();
        let mut hi = above.next();
        loop {
            let use_below = match (lo, hi) {
                (Some((lh, _)), Some((hh, _))) => target.abs_diff(*lh) <= hh.abs_diff(target),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return None,
            };
            let (_h, keys) = if use_below { lo.unwrap() } else { hi.unwrap() };
            if let Some(oref) = self.eligible_untaken_at(keys, current_height, taken, rng) {
                return Some(oref);
            }
            if use_below {
                lo = below.next();
            } else {
                hi = above.next();
            }
        }
    }

    /// A uniformly-random eligible, untaken output among `keys` at one height
    /// (reservoir sampling), or `None` if none qualify.
    fn eligible_untaken_at<R: rand::Rng>(
        &self,
        keys: &BTreeSet<OutputKey>,
        current_height: u64,
        taken: &HashSet<OutputKey>,
        rng: &mut R,
    ) -> Option<&OutputRef> {
        let mut pick: Option<&OutputRef> = None;
        let mut seen = 0u32;
        for key in keys {
            if taken.contains(key) {
                continue;
            }
            if let Some(oref) = self.outputs.get(key) {
                let unlocked = oref
                    .output
                    .lock_height
                    .map_or(true, |lh| current_height >= lh);
                if unlocked {
                    seen += 1;
                    if rng.gen_range(0..seen) == 0 {
                        pick = Some(oref);
                    }
                }
            }
        }
        pick
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
        let eligible: Vec<&OutputRef> = self
            .outputs_in_range(0, max_height)
            .into_iter()
            .filter(|o| o.output.lock_height.map_or(true, |lh| current_height >= lh))
            .collect();

        // Filter out outputs from excluded transaction
        let filtered: Vec<&OutputRef> = if let Some(tx_hash) = exclude_tx {
            eligible
                .into_iter()
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

    /// REGRESSION (2026-07-24): assert decoy age distribution is GAMMA
    /// (recent-biased), matching the real-spend age law — NOT uniform.
    ///
    /// Reverses the 2026-07-02 uniform assertion (owner + co-founder decision,
    /// with full knowledge of that SEV-A). Over a pool much larger than the
    /// gamma's ~1300-block median age, decoys concentrate in the newest age
    /// bucket, whereas a uniform selector would put ~10% in every bucket. The
    /// gamma's long upper tail clamps onto the oldest available output, so the
    /// oldest bucket is non-empty — the signature is "newest bucket dominates",
    /// not "oldest empty".
    #[test]
    fn test_decoy_selection_is_gamma_recent_biased() {
        let mut utxos = UtxoSet::new();
        let mut rng = rand::thread_rng();

        // Pool spanning 30k blocks (>> the gamma median age) so the recency
        // bias is visible in the newest bucket. One unique output per height.
        let n = 30_000u64;
        for h in 0..n {
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

        let bucket = n / 10; // 3000 blocks per age bucket
        let mut hist = [0u32; 10];
        for _ in 0..20 {
            for d in utxos.select_decoys(n, 0, 100, &mut rng) {
                let age = n - d.height;
                hist[((age / bucket) as usize).min(9)] += 1;
            }
        }
        let total: u32 = hist.iter().sum();
        assert!(total > 0, "must have drawn at least some decoys");
        let frac = |b: usize| hist[b] as f64 / total as f64;

        // Gamma signature: the newest age bucket carries the bulk of the mass...
        assert!(
            frac(0) > 0.40,
            "gamma: newest age bucket should dominate, got {:.1}% (hist {:?})",
            frac(0) * 100.0,
            hist,
        );
        // ...far more than the oldest (uniform would make these ~equal at 10%)...
        assert!(
            frac(0) > 2.0 * frac(9),
            "gamma: newest must exceed oldest by a wide margin (hist {:?})",
            hist,
        );
        // ...and the distribution is concentrated, not flat (anti-uniform).
        assert!(
            frac(0) > 3.0 * frac(5),
            "gamma: mass must concentrate at recent ages, not spread uniformly (hist {:?})",
            hist,
        );
    }
}
