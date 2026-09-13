//! Read-only chain query getters, extracted from `chain.rs` (issue #108).
//!
//! Every method here is a pure `&self` getter: it takes at most an
//! `inner.read()` or reads `self.db` — none acquire `apply_lock`, none mutate
//! state, none write the DB. Relocating them changes no lock scope and adds no
//! interleaving point, so consensus/observable behavior is byte-for-behavior
//! identical to the previous in-`chain.rs` definitions. As a child module of
//! `chain`, this file can read `Blockchain`'s private fields directly.

use super::*;

impl Blockchain {
    /// Get current height
    pub fn height(&self) -> u64 {
        self.inner.read().tip.height
    }

    /// Get current tip
    pub fn tip(&self) -> ChainTip {
        self.inner.read().tip.clone()
    }

    /// Number of unspent outputs currently tracked. Observability only
    /// (metrics/RPC) — not a consensus value.
    pub fn utxo_count(&self) -> usize {
        self.inner.read().utxos.output_count()
    }

    /// Look up a transaction's block height and index via the tx_index.
    pub fn get_tx_location(&self, tx_hash: &[u8]) -> Option<(u64, u32)> {
        self.db.as_ref().and_then(|db| db.get_tx_location(tx_hash))
    }

    /// Get tip hash
    pub fn tip_hash(&self) -> Hash {
        self.inner.read().tip.hash
    }

    /// Get the number of available (unspent) outputs in the UTXO set
    pub fn available_output_count(&self) -> usize {
        self.inner.read().utxos.output_count()
    }
}

// ── additional read-only getters (issue #108, queries expansion) ──
impl Blockchain {
    /// Validate a transaction against the current UTXO set
    /// Used by the miner to pre-validate mempool txs before including in blocks.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        let inner = self.inner.read();
        crate::consensus::validate_transaction_for_network(
            tx,
            &inner.utxos,
            inner.tip.height + 1,
            self.network,
        )
    }

    /// Get current difficulty
    pub fn difficulty(&self) -> u128 {
        self.inner.read().tip.difficulty
    }

    /// Get next difficulty (placeholder)
    pub fn next_difficulty(&self) -> u128 {
        self.inner.read().tip.difficulty
    }

    /// Consensus difficulty target for a block at `height`, given its difficulty
    /// window `blocks` (whose last element is the parent). All networks use
    /// dual-anchor ASERT (`calculate_difficulty`) EXCEPT regtest, which pins
    /// difficulty at the parent's target and never retargets — Bitcoin-regtest
    /// style. That keeps a single CPU producing blocks at a stable, low,
    /// overshoot-free rate for local functional testing (ASERT's fast-block
    /// ramp would otherwise spike difficulty on an isolated miner). Regtest is
    /// an isolated, local-only network (never dials peers, never mainnet/testnet
    /// genesis), so this branch has ZERO effect on testnet/mainnet consensus.
    /// A pinned target also trivially satisfies the ±4x/step sanity layer in
    /// `validate_difficulty_target` (ratio is always 1.0).
    ///
    /// SINGLE SOURCE OF THE DIFFICULTY RULE: every expected-target computation
    /// must go through this — the miner (`next_target`), block validation, fork
    /// validation, AND header validation (`network::node::dispatch::headers`).
    /// (Regtest DOES peer via `--addnode`; header validation previously called
    /// `calculate_difficulty` directly and diverged from this regtest branch,
    /// rejecting every peer header so regtest nodes could not sync. Hence `pub`.)
    pub fn expected_next_target(&self, blocks: &[DifficultyBlock], height: u64) -> Hash {
        if self.network == crate::config::NetworkType::Regtest {
            // Ease difficulty DOWN toward the MIN_DIFFICULTY floor at <=3x per
            // block (safely inside the ±4x/step sanity layer), then pin there
            // and never retarget. Applies from the very first block (parent =
            // genesis), so a fresh regtest chain drops from the genesis
            // difficulty to the floor in a few blocks and then produces blocks
            // at a stable, low, overshoot-free rate — the fast local harness
            // Bitcoin's regtest provides. (The ease starts at genesis rather
            // than jumping straight to the floor because the locked ±4x/step
            // sanity layer would reject a single large drop.)
            let parent = blocks.last().map(|b| b.target).unwrap_or_else(max_target);
            let parent_diff = crate::consensus::difficulty::target_to_difficulty(&parent);
            let floor = crate::consensus::difficulty::MIN_DIFFICULTY;
            if parent_diff <= floor {
                return parent;
            }
            // next_diff <= parent_diff <= genesis difficulty, so it always fits u64.
            let next_diff = (parent_diff / 3).max(floor).min(u64::MAX as u128) as u64;
            return Hash::from_difficulty(next_diff);
        }
        if blocks.len() >= 2 {
            calculate_difficulty(blocks, height)
        } else {
            // Only genesis (or nothing): maintain genesis difficulty until ASERT
            // has a full window. Non-regtest networks rely on a calibrated
            // genesis difficulty here (see {testnet,mainnet}.rs INITIAL_DIFFICULTY).
            blocks.last().map(|b| b.target).unwrap_or_else(max_target)
        }
    }

    /// Compute the exact target hash for the next block using ASERT difficulty adjustment.
    /// This is the authoritative target that the validator will enforce.
    pub fn next_target(&self) -> Hash {
        let height = self.height() + 1;
        let diff_blocks = self.get_difficulty_blocks(height);
        self.expected_next_target(&diff_blocks, height)
    }

    /// Check if chain is synced (updated by P2P layer via set_sync_info).
    ///
    /// Three conditions, any one of which is sufficient:
    ///   1. The P2P layer flagged us synced explicitly.
    ///   2. We're at or above the highest peer-advertised height.
    ///   3. We're within 2 blocks of that target AND the tip itself is
    ///      recent (younger than 3× the target block time = 6 min).
    ///
    /// Condition 3 covers the steady-state case where a peer announces
    /// a new block (bumping `peer_target_height` by 1) a beat before
    /// we've ingested it. Without this, a chain producing blocks at the
    /// target rate is reported as "syncing" forever — which is what
    /// users of the explorer kept reporting as "the chain stalled".
    /// A fresh tip + tiny overshoot is the textbook "essentially synced"
    /// state; reporting it as such matches user reality.
    pub fn is_synced(&self) -> bool {
        // Firework Phase 2 (I6): a peer advertising a verifiably-heavier
        // chain vetoes "synced" regardless of block height — this is what
        // stops a node on a higher-block/lower-work fork from reporting
        // synced (and its miner from mining). Inert for height-only peers
        // (no CAP_CHAINWORK), and cleared by the sync layer's anti-wedge
        // machinery (expire/ban/prune) once an unsubstantiated claim is
        // dropped, so it can never wedge us permanently.
        if self.work_behind.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        let flag = self.synced.load(std::sync::atomic::Ordering::Relaxed);
        if flag {
            return true;
        }
        let h = self.height();
        if h == 0 {
            return false;
        }
        let target = self
            .peer_target_height
            .load(std::sync::atomic::Ordering::Relaxed);
        if h >= target {
            return true;
        }
        // Tolerance for in-flight peer advertisements: ≤2 blocks behind
        // the peer-advertised target, AND tip is fresh enough that the
        // chain is clearly producing blocks (not actually stalled).
        if target.saturating_sub(h) <= 2 {
            let tip_timestamp = self.inner.read().tip.timestamp;
            if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                let now_secs = d.as_secs();
                let age = now_secs.saturating_sub(tip_timestamp);
                // 3× testnet target block time. Same threshold is fine
                // for mainnet (also 120s target).
                const FRESH_TIP_SECS: u64 = 3 * crate::constants::TARGET_BLOCK_TIME;
                if age <= FRESH_TIP_SECS {
                    return true;
                }
            }
        }
        false
    }

    /// Get chain statistics
    pub fn stats(&self) -> ChainStats {
        self.inner.read().stats.clone()
    }

    /// Get block by hash
    /// Median-Time-Past of the 11 blocks preceding `prev_hash` ON ITS OWN
    /// CHAIN — walking the actual parent lineage via `prev_hash`, not the
    /// active chain by height. Returns `None` if fewer than 11 ancestors are
    /// reachable (caller then skips the MTP rule, matching the historical
    /// genesis-window behaviour).
    ///
    /// REORG-CORRECTNESS (R-1): validating a competing-fork block against the
    /// active chain's timestamps at those heights wrongly rejected valid
    /// heavier forks whose near-fork blocks predated the active chain's MTP —
    /// and banned the honest peer serving them (InvalidBlockPoW). For a
    /// main-chain block the parent lineage IS the by-height ancestry, so this
    /// is behaviour-identical on the common path. `get_block` resolves both
    /// in-memory side-chain blocks and DB-backed ancestors.
    pub(super) fn median_time_past_of_lineage(&self, prev_hash: Hash) -> Option<u64> {
        let mut timestamps: Vec<u64> = Vec::with_capacity(crate::constants::MTP_WINDOW);
        let mut cursor = prev_hash;
        for _ in 0..crate::constants::MTP_WINDOW {
            match self.get_block(&cursor) {
                Some(ancestor) => {
                    timestamps.push(ancestor.header.timestamp);
                    cursor = ancestor.header.prev_hash;
                }
                None => break,
            }
        }
        if timestamps.len() >= crate::constants::MTP_WINDOW {
            timestamps.sort_unstable();
            Some(timestamps[timestamps.len() / 2])
        } else {
            None
        }
    }

    pub fn get_block(&self, hash: &Hash) -> Option<Block> {
        // Try in-memory first
        {
            let inner = self.inner.read();
            if let Some(block) = inner.blocks.get(hash) {
                return Some(block.clone());
            }
        }
        // Try database
        if let Some(ref db) = self.db {
            if let Ok(Some(block)) = db.blocks.get(hash) {
                return Some(block);
            }
        }
        None
    }

    /// Get block hash by height
    pub fn get_block_hash(&self, height: u64) -> Option<Hash> {
        // Try in-memory first
        {
            let inner = self.inner.read();
            if let Some(hash) = inner.height_to_hash.get(&height) {
                return Some(*hash);
            }
        }
        // Try database
        if let Some(ref db) = self.db {
            if let Ok(Some(hash)) = db.blocks.get_hash_by_height(height) {
                return Some(hash);
            }
        }
        None
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> Option<Block> {
        if let Some(hash) = self.get_block_hash(height) {
            return self.get_block(&hash);
        }
        None
    }

    /// Count blocks in `[window_start, window_end)` whose coinbase signals
    /// the given BIP-9 deployment bit.
    ///
    /// Provides the `signal_count_fn` callback that `ForkSignaler::state()`
    /// (see `src/consensus/fork_signal.rs`) consumes. Walks the main-chain
    /// blocks in the half-open range, inspects each block's coinbase
    /// transaction's `extra` field, decodes the trailing 4 bytes as
    /// `SignalBits` (via `fork_signal::decode_signal_bits`), and counts the
    /// blocks where the queried bit is set.
    ///
    /// ## Backward compatibility
    ///
    /// Blocks mined by a pre-CIP-012 rig binary have an 8-byte coinbase
    /// `extra` (height only, no trailing signal bytes). `decode_signal_bits`
    /// returns `SignalBits(0)` for those, so they contribute 0 to the count
    /// — same as a v1.0.12-aware rig that didn't pass `--signal-v1012`.
    /// New miners that DO opt in produce 12-byte extras with the bit set,
    /// and contribute 1 to the count.
    ///
    /// ## Performance
    ///
    /// `get_block_by_height` is amortized O(1): two `HashMap` lookups in
    /// the in-memory cache (`blocks` + `height_to_hash`) for blocks within
    /// the cache window, with a sled-disk fallback for older blocks. The
    /// signal-window scan is 2016 blocks, which fits well within the
    /// in-memory cache for any block within `2 × MAX_BLOCK_CACHE` of the
    /// tip — i.e., the entire BIP-9 window is almost certainly hot. If
    /// every block in the window were uncached (worst case during a deep
    /// reorg-replay), each lookup adds ~one sled `get()` of <1 ms, capping
    /// the full scan at ~2 seconds — still acceptable for a once-per-block
    /// invocation, but worth noting that the "O(1) per lookup" claim
    /// assumes hot cache.
    ///
    /// No memoization yet; if profiling shows this on a hot path, the
    /// per-window count is trivially memoizable since it only changes by
    /// ±1 when a new block lands (or a reorg unwinds + replays). A
    /// single read-lock-held-across-the-whole-scan variant would also
    /// shave ~300 µs vs the current per-block acquire pattern. Both
    /// optimizations are YAGNI right now — BIP-9 query is one-per-block
    /// at most, dwarfed by the RandomX + Bulletproof costs of validation.
    ///
    /// ## Missing-block handling
    ///
    /// A height that maps to no block (gap in the chain, e.g. during
    /// reorg-rollback) is skipped without error — counts as 0 contribution.
    /// A block whose coinbase is missing (impossible by construction, but
    /// defensive) is similarly skipped. The point of the BIP-9 state
    /// machine is to be robust against partial state; an aggressive panic
    /// here would convert a transient DB-gap into a node halt.
    ///
    /// ## Prior art
    ///
    /// - **Bitcoin Core `AbstractThresholdConditionChecker::GetStateStatisticsFor`**
    ///   at versionbits.cpp:119 in the master read this session does the
    ///   equivalent count by walking `CBlockIndex` pointers. The prior
    ///   comment misattributed the method to `ThresholdConditionCache`
    ///   (which is a `std::map` typedef at versionbits.h:33, not the
    ///   owner of the method).
    /// - Other BIP-9-derived chains (Bitcoin Cash / Litecoin / Dogecoin)
    ///   inherit the walk-block-index-counting shape; specific per-fork
    ///   identifiers UNVERIFIED this session.
    pub fn count_signaling_blocks_in_window(
        &self,
        window_start: u64,
        window_end: u64,
        bit: u32,
    ) -> u64 {
        use crate::consensus::fork_signal::decode_signal_bits;

        // Early-out on degenerate/inverted ranges. saturating_sub guards
        // against the (window_end < window_start) case — a caller bug
        // that shouldn't happen but won't underflow a u64 if it does.
        // Inlined into the check (no variable) per review feedback —
        // the value isn't used elsewhere.
        if window_end.saturating_sub(window_start) == 0 {
            return 0;
        }

        let mut count: u64 = 0;
        for h in window_start..window_end {
            let Some(block) = self.get_block_by_height(h) else {
                continue; // gap; contributes 0
            };
            let Some(coinbase) = block.coinbase() else {
                continue; // structurally impossible; defensive
            };
            if decode_signal_bits(&coinbase.extra).signals(bit) {
                count = count.saturating_add(1);
            }
        }
        count
    }
}
