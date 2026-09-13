//! Fork-choice and difficulty-window calculation helpers, extracted from
//! `chain.rs` (issue #108).
//!
//! Every method here is a read-only `&self` helper: it reads the DB and/or an
//! `inner.read()`, never takes `apply_lock`, never mutates state, and never
//! writes. `add_block` and `rollback`/`load` keep calling them at the exact same
//! sites (including the deliberately lock-released `collect_fork_chain` call in
//! the reorg path), so `apply_lock` scope and writer interleaving are unchanged.
//! They are `pub(super)` — visible to the parent `chain` module (the callers in
//! `add_block`/`load_from_database`) and its test submodule, nothing wider.
//!
//! ## Audit map
//! - **§3 fork cumulative work** — INVARIANT: `calculate_fork_cumulative_work`
//!   uses the genesis base `1` (NOT `dft(genesis)`), matching the extend path and
//!   `recompute_total_difficulty`, so an equal-work fork is not seen as heavier.
//!   Bounded walk (height+100 cap) breaks `prev_hash` cycles. THREAT: fleet-wide
//!   `total_difficulty` divergence → spurious reorg + `work_behind` false-veto.
//!   TESTS: `calculate_fork_cumulative_work_parent_not_found_returns_partial`,
//!   `calculate_fork_cumulative_work_cycle_breaks_at_max_steps`,
//!   `total_difficulty_recompute_and_fork_walk_agree_on_genesis_base`.
//! - **§4 fork walk helpers** — INVARIANT: `find_fork_point` returns `None` on
//!   DB corruption (cycle / missing parent), distinct from the legitimate
//!   genesis fork point `Some(0)`; `collect_fork_chain` returns the fork
//!   ascending and stops at the fork point; the difficulty window is DB-sourced
//!   so every node computes an identical ASERT window. THREAT: corruption masked
//!   as a deep reorg; cold-cache/hot-cache window divergence (a consensus split).
//!   TESTS: `find_fork_point_returns_common_ancestor_and_genesis`,
//!   `find_fork_point_detects_cycle_returns_none`,
//!   `find_fork_point_missing_parent_returns_none`,
//!   `collect_fork_chain_returns_ascending_and_stops_at_fork_point`,
//!   `recompute_total_difficulty_missing_mid_range_returns_none`.

use super::*;

impl Blockchain {
    /// Main-chain difficulty sample at `height`, DB-sourced so every node builds
    /// an identical ASERT window (the in-memory cache fallback is reached only in
    /// no-DB test mode, where callers hold no `inner` lock).
    pub(super) fn main_chain_diff_block(&self, height: u64) -> Option<DifficultyBlock> {
        if let Some(ref db) = self.db {
            match db.blocks.get_by_height(height) {
                Ok(Some(b)) => Some(DifficultyBlock {
                    height,
                    timestamp: b.header.timestamp,
                    target: b.header.target,
                }),
                _ => None,
            }
        } else {
            let inner = self.inner.read();
            let hash = inner.height_to_hash.get(&height)?;
            let b = inner.blocks.get(hash)?;
            Some(DifficultyBlock {
                height,
                timestamp: b.header.timestamp,
                target: b.header.target,
            })
        }
    }

    /// Fork-aware ASERT window for a block whose parent is `parent_hash`, sourced
    /// from the DB so every node computes the same window (fix for chain.rs:2056).
    /// Walks the fork's prev_hash chain to the fork point, then assembles
    /// main-chain-below-fork + fork-above-fork, ascending. DB-sourced in
    /// production; the in-memory cache is used only in no-DB test mode, and its
    /// read guard is dropped before the assembly loop so `main_chain_diff_block`
    /// (which re-reads) can never recursive-read-lock.
    pub(super) fn fork_difficulty_window(
        &self,
        parent_hash: Hash,
        block_height: u64,
    ) -> Vec<DifficultyBlock> {
        let window = 144u64; // DIFFICULTY_LONG_WINDOW
        let start = block_height.saturating_sub(window);

        // (height, timestamp, target) of the above-fork fork blocks, ascending.
        let mut fork: Vec<(u64, u64, Hash)> = Vec::new();
        let mut fork_point = 0u64;
        let mut cursor = parent_hash;
        let mut visited = std::collections::HashSet::new();

        if let Some(ref db) = self.db {
            loop {
                if !visited.insert(cursor) {
                    break; // prev_hash cycle (corruption) — exact-target check rejects a wrong window
                }
                let blk = match db.blocks.get(&cursor) {
                    Ok(Some(b)) => b,
                    _ => break, // parent not in DB — can't extend the walk
                };
                let h = blk.header.height;
                if let Ok(Some(main_hash)) = db.blocks.get_hash_by_height(h) {
                    if main_hash == cursor {
                        fork_point = h;
                        break;
                    }
                }
                fork.push((h, blk.header.timestamp, blk.header.target));
                if h == 0 {
                    break;
                }
                cursor = blk.header.prev_hash;
            }
        } else {
            // No-DB in-memory test mode: walk the cache. Scoped so the read
            // guard drops before the assembly loop below.
            let inner = self.inner.read();
            loop {
                if !visited.insert(cursor) {
                    break;
                }
                let blk = match inner.blocks.get(&cursor) {
                    Some(b) => b,
                    None => break,
                };
                let h = blk.header.height;
                if let Some(main_hash) = inner.height_to_hash.get(&h) {
                    if *main_hash == cursor {
                        fork_point = h;
                        break;
                    }
                }
                fork.push((h, blk.header.timestamp, blk.header.target));
                if h == 0 {
                    break;
                }
                cursor = blk.header.prev_hash;
            }
        }
        fork.reverse(); // ascending

        let mut out = Vec::new();
        for h in start..block_height {
            if h <= fork_point {
                if let Some(d) = self.main_chain_diff_block(h) {
                    out.push(d);
                }
            } else {
                let off = (h - fork_point - 1) as usize;
                if let Some(&(fh, ts, tgt)) = fork.get(off) {
                    out.push(DifficultyBlock {
                        height: fh,
                        timestamp: ts,
                        target: tgt,
                    });
                }
            }
        }
        out
    }

    /// Calculate cumulative work for a fork chain ending at the given block.
    ///
    /// Walks backwards from the block through its parents, summing difficulty
    /// until reaching the genesis block or a block not in our storage.
    ///
    /// SECURITY: bounded by `block.header.height + 1` (max walk = genesis →
    /// block, plus the starting block itself). A corrupt DB with a cycle
    /// in `prev_hash` would otherwise loop forever consuming CPU. Matching
    /// the visited-set pattern in `find_fork_point` (lines 2533+) would
    /// also catch cycles but costs an allocation; the height-derived cap
    /// is allocation-free and serves the same purpose because the walk
    /// can only legitimately visit at most `block.height` distinct heights.
    pub(super) fn calculate_fork_cumulative_work(&self, block: &Block) -> u128 {
        let mut total_work = calculate_difficulty_from_target(&block.header.target);
        let mut current_hash = block.header.prev_hash;
        // +1 covers the starting block; +100 absorbs height-key off-by-one
        // edge cases and is still vanishingly cheap if exercised.
        let max_steps = block.header.height.saturating_add(100);
        let mut steps: u64 = 0;

        loop {
            steps = steps.saturating_add(1);
            if steps > max_steps {
                tracing::error!(
                    "calculate_fork_cumulative_work walked {} steps from block height {} \
                     without reaching genesis — possible prev_hash cycle in DB. Returning \
                     partial work; caller's IronConsensus classifier will reject the fork.",
                    steps,
                    block.header.height
                );
                break;
            }
            if let Some(parent) = self.get_block(&current_hash) {
                // Genesis contributes the fixed base `1`, NOT its
                // `dft(genesis_target)`. This matches the extend path, which
                // starts from `total_difficulty = 1` at construction
                // (chain.rs genesis init) and does `+= dft(block)` for each
                // block height ≥ 1. Adding `dft(genesis)` here instead made
                // this from-scratch fork walk exceed the incrementally
                // accumulated `current total_difficulty` by
                // `dft(genesis) - 1`, so an EQUAL-work fork looked heavier and
                // triggered a spurious reorg — and every reorg then latched
                // the higher base into the stored value, producing the
                // fleet-wide `total_difficulty` divergence (nodes on the
                // identical tip disagreeing on cumulative work) that
                // false-positived the `work_behind` veto and locked follower
                // miners out. See recompute_total_difficulty for the canonical
                // definition this must agree with.
                if parent.header.height == 0 {
                    total_work = total_work.saturating_add(1);
                    break; // Reached genesis
                }
                let prev_work = total_work;
                total_work = total_work
                    .saturating_add(calculate_difficulty_from_target(&parent.header.target));
                // SECURITY (H-7): Detect u128 saturation during deep reorgs.
                // saturating_add silently caps at u128::MAX, which could cause
                // incorrect chain selection if both forks saturate.
                if total_work == u128::MAX && prev_work != u128::MAX {
                    tracing::warn!(
                        "Cumulative work saturated at u128::MAX during fork calculation at height {}",
                        parent.header.height
                    );
                }
                current_hash = parent.header.prev_hash;
            } else {
                break; // Parent not found
            }
        }

        total_work
    }

    /// Deterministically recompute cumulative chain work for the active chain
    /// `[0, height]` as `1 + Σ dft(block_h.target)` for `h in 1..=height`.
    ///
    /// This is the SINGLE canonical definition of `total_difficulty`, and it
    /// agrees by construction with:
    ///   - the extend path (`total_difficulty += dft(block)` from a genesis
    ///     base of `1`), and
    ///   - the reorg path (`calculate_fork_cumulative_work`, which now also
    ///     uses the genesis base `1`).
    ///
    /// Called once on load (`load_from_database`) so that a node whose stored
    /// value drifted — via the pre-fix reorg path that used a `dft(genesis)`
    /// base, or a partial fork walk — SELF-HEALS to the deterministic value on
    /// restart. Because `total_difficulty` is advertised to peers in
    /// `ChainWorkMessage` (feeding the `work_behind` heavier-chain veto),
    /// converging every node's value is what stops the veto from
    /// false-positiving followers whose only "sin" was computing the same
    /// tip's work correctly.
    ///
    /// Returns `None` if any block in `[1, height]` is missing from storage
    /// (caller keeps the existing value rather than storing a wrong partial).
    ///
    /// Cost: O(height) DB reads, once per process start. Fine at testnet
    /// scale (~12k blocks, sub-second). A mainnet-scale chain would want a
    /// periodically-checkpointed cumulative value instead of a full walk.
    pub(super) fn recompute_total_difficulty(&self, height: u64) -> Option<u128> {
        let mut total: u128 = 1; // genesis base (matches genesis init + fork walk)
        for h in 1..=height {
            let block = self.get_block_by_height(h)?;
            total = total.saturating_add(calculate_difficulty_from_target(&block.header.target));
        }
        Some(total)
    }

    /// Find the common ancestor (fork point) between the current main chain
    /// and a fork block.
    ///
    /// Returns `Some(height)` for a real common ancestor (including the
    /// legitimate "fork point is genesis" case → `Some(0)`).
    ///
    /// Returns `None` when DB corruption is detected:
    /// - Cycle in `prev_hash` chain (the walk would loop forever
    ///   without the visited-set guard).
    /// - A `prev_hash` references a block that isn't in storage.
    ///
    /// The caller (chain reorganization in [`Self::add_block`]) MUST
    /// treat `None` as a corruption-class rejection — not as "fork
    /// point is genesis". Previously this function returned `0` for
    /// both genesis and corruption, which masked corruption as a
    /// legitimate deep-reorg attempt: `evaluate_reorg_acceptability`
    /// then rejected it as "ReorgTooDeep" with a misleading
    /// diagnostic. Audit-prep fix 2026-05-23.
    pub(super) fn find_fork_point(&self, fork_block: &Block) -> Option<u64> {
        let mut current_hash = fork_block.header.prev_hash;
        let mut visited = std::collections::HashSet::new();

        loop {
            if !visited.insert(current_hash) {
                tracing::error!(
                    "DB corruption: cycle detected during fork-point search; \
                     starting from fork_block height={} hash={}",
                    fork_block.header.height,
                    fork_block.hash().to_hex(),
                );
                return None;
            }
            if let Some(parent) = self.get_block(&current_hash) {
                let height = parent.header.height;
                if let Some(main_hash) = self.get_block_hash(height) {
                    if main_hash == current_hash {
                        return Some(height);
                    }
                }
                if height == 0 {
                    return Some(0);
                }
                current_hash = parent.header.prev_hash;
            } else {
                tracing::error!(
                    "DB corruption: prev_hash {} not in storage during fork-point search; \
                     fork_block height={}",
                    current_hash.to_hex(),
                    fork_block.header.height,
                );
                return None;
            }
        }
    }

    /// Collect the fork chain from fork_point+1 to the given block (exclusive).
    /// Returns blocks in ascending height order.
    pub(super) fn collect_fork_chain(&self, fork_tip: &Block, fork_point: u64) -> Vec<Block> {
        let mut chain = Vec::new();
        let mut current_hash = fork_tip.header.prev_hash;
        let mut visited = std::collections::HashSet::new();

        // Walk back from fork tip to fork point, collecting blocks.
        // SECURITY: Track visited hashes to detect cycles and prevent infinite loops.
        loop {
            if !visited.insert(current_hash) {
                tracing::error!(
                    "Cycle detected in fork chain at hash {}",
                    current_hash.to_hex()
                );
                break;
            }
            if let Some(block) = self.get_block(&current_hash) {
                if block.header.height <= fork_point {
                    break;
                }
                current_hash = block.header.prev_hash;
                chain.push(block.clone());
            } else {
                break;
            }
        }

        chain.reverse(); // Return in ascending order
        chain
    }
}
