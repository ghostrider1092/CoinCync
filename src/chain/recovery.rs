//! Database load, genesis init & recovery, extracted from `chain.rs` (issue #108).
//!
//! These run at construction / reopen only — never on the live `add_block`
//! apply path. Each takes its own `inner.write()` / `begin_state_update()` guard
//! (moved verbatim, so those acquisitions keep the exact same scope) and NONE
//! takes `apply_lock`. The apply-path index helpers `persist_output_index` /
//! `remove_output_index` stay in `chain.rs`; this module reaches them (and
//! `begin_state_update`, `create_genesis_block_for`) as a descendant of `chain`.
//!
//! ## Audit map
//! - **§11 `load_from_database` / `rebuild_utxo_set`** — INVARIANT: a load either
//!   fully restores the expected chain (blocks, tip, UTXO set, counters,
//!   total_difficulty self-healed via `recompute_total_difficulty`) or fails
//!   without leaving partial state; rejects a fresh/mismatched/wrong-network DB.
//!   THREAT: silent state corruption surviving a restart. TESTS:
//!   `load_from_database_distinguishes_fresh_and_loaded_state`,
//!   `load_from_database_rejects_wrong_network_genesis`,
//!   `load_from_database_rejects_state_height_mismatch_with_tip_block`.
//! - **§12 `init_genesis` / `verify_tip_integrity`** — INVARIANT: genesis matches
//!   the network's expected hash; a tip/DB disagreement reloads from the DB.
//!   THREAT: booting on the wrong genesis or a stale tip.

use super::*;

impl Blockchain {
    /// Initialize genesis block
    pub fn init_genesis(&self) -> Result<Hash> {
        let _state_update = self.begin_state_update();
        let genesis = create_genesis_block_for(self.network);
        let hash = genesis.hash();

        // SECURITY: Verify genesis hash matches the hardcoded constant.
        // This catches accidental genesis block changes that would cause chain forks.
        let expected = self.expected_genesis_hash();
        if hash != expected {
            return Err(Error::InvalidState(format!(
                "Genesis hash mismatch! Computed {} but expected {}. \
                 The genesis block definition may have been altered.",
                hash.to_hex(),
                expected.to_hex()
            )));
        }

        {
            let mut inner = self.inner.write();
            inner.blocks.insert(hash, genesis.clone());
            inner.height_to_hash.insert(0, hash);
            inner.genesis_hash = Some(hash);

            inner.tip = ChainTip {
                hash,
                height: 0,
                difficulty: 1,
                timestamp: genesis.header.timestamp,
            };

            inner.stats.height = 0;
            inner.stats.total_blocks = 1;
            inner.stats.total_transactions = genesis.transactions.len() as u64;
            inner.stats.tip_hash = hash;
            inner.stats.total_supply = calculate_block_reward(0).as_atomic() as u128;
            // Genesis carries no fees (height 0 is below FEE_DISTRIBUTION_HEIGHT
            // and has no non-coinbase txs), so the burn accumulator starts at 0.
            inner.stats.total_burned = 0;

            // SECURITY (CC-001): Apply genesis block transactions to UTXO set
            let batch = UtxoSet::batch_from_block(0, &genesis.transactions);
            inner.utxos.apply_batch(batch);
        }

        // Persist output index for genesis block
        self.persist_output_index(&genesis.transactions, 0);

        // Save to database if available
        if let Some(ref db) = self.db {
            db.blocks.insert(&genesis)?;
            db.blocks.set_height_hash(0, &hash)?;
            db.state.set_genesis_hash(&hash)?;
            let state = ChainStateData {
                tip_hash: hash,
                height: 0,
                total_difficulty: 1,
                total_supply: calculate_block_reward(0).as_atomic() as u128,
                total_burned: 0,
                last_checkpoint: 0,
            };
            db.state.save_state(&state)?;

            // Record genesis as the first checkpoint
            let _ = db.state.add_checkpoint(0, &hash);
        }

        tracing::info!("Genesis block initialized: {}", hash.to_hex());
        Ok(hash)
    }

    fn expected_genesis_hash(&self) -> Hash {
        match self.network {
            NetworkType::Testnet | NetworkType::Regtest => crate::testnet::expected_genesis_hash(),
            NetworkType::Mainnet => crate::mainnet::expected_genesis_hash(),
        }
    }

    /// Verify chain tip integrity after recovering from a poisoned lock.
    /// Compares in-memory tip hash against the database to detect corruption.
    /// Can also be called periodically from the maintenance loop as a health check.
    pub fn verify_tip_integrity(&self) -> Result<()> {
        if let Some(ref db) = self.db {
            if let Some(state) = db.state.get_state()? {
                let inner = self.inner.read();
                if inner.tip.hash != state.tip_hash && inner.tip.height > 0 {
                    tracing::error!(
                        "TIP INTEGRITY MISMATCH: in-memory tip {} (height {}) != DB tip {} (height {}). \
                         Reloading from database.",
                        inner.tip.hash.to_hex()[..16].to_string(),
                        inner.tip.height,
                        state.tip_hash.to_hex()[..16].to_string(),
                        state.height,
                    );
                    drop(inner);
                    return self.load_from_database();
                }
            }
        }
        Ok(())
    }

    /// Load chain state from database
    pub fn load_from_database(&self) -> Result<()> {
        self.load_from_database_with_outcome().map(|_| ())
    }

    /// Genesis initialization requires an explicit fresh-database result.
    pub fn load_from_database_with_outcome(&self) -> Result<ChainLoadOutcome> {
        let _state_update = self.begin_state_update();
        if let Some(ref db) = self.db {
            let state = match db.state.get_state()? {
                Some(state) => state,
                None if !db.blocks.has_any_chain_data() => return Ok(ChainLoadOutcome::Fresh),
                None => {
                    return Err(Error::DatabaseError(
                        "persisted block data exists without chain state; refusing to initialize genesis"
                            .into(),
                    ));
                }
            };

            let actual_genesis = db.blocks.get_hash_by_height(0)?.ok_or_else(|| {
                Error::DatabaseError(
                    "chain state exists but the block height index has no genesis entry".into(),
                )
            })?;
            let expected_genesis = self.expected_genesis_hash();
            if actual_genesis != expected_genesis {
                return Err(Error::DatabaseError(format!(
                    "database genesis {} does not match the expected {} genesis {}",
                    actual_genesis, self.network, expected_genesis,
                )));
            }

            return match db.blocks.get(&state.tip_hash)? {
                Some(tip_block) => {
                    if tip_block.header.height != state.height {
                        return Err(Error::DatabaseError(format!(
                            "chain state height {} does not match tip block height {}",
                            state.height, tip_block.header.height,
                        )));
                    }
                    let difficulty = calculate_difficulty_from_target(&tip_block.header.target);
                    {
                        let mut inner = self.inner.write();
                        inner.tip = ChainTip {
                            hash: state.tip_hash,
                            height: state.height,
                            difficulty,
                            timestamp: tip_block.header.timestamp,
                        };
                        inner.stats.height = state.height;
                        inner.stats.total_supply = state.total_supply;
                        // Load the persisted burn accumulator alongside supply.
                        // ChainStateData.total_burned is `u64` on disk; the
                        // in-memory accumulator is `u128` for parity with
                        // total_supply — widen on load.
                        inner.stats.total_burned = state.total_burned as u128;
                        inner.stats.tip_hash = state.tip_hash;
                        inner.stats.total_difficulty = state.total_difficulty;
                        // Sync stats.difficulty with the loaded tip. Without this,
                        // stats.difficulty stays at ChainStats::default() (= 0) until
                        // a new block lands via the main-chain add path (chain.rs:1490).
                        // The RPC `get_info` "difficulty" field reads from
                        // stats.difficulty (src/rpc/server.rs:511), so the bug surfaces
                        // as `"difficulty":"0"` in get_info after every node restart
                        // until the first non-fork block arrives. Observed on the
                        // testnet api box 2026-06-01 after the fleet upgrade.
                        inner.stats.difficulty = difficulty;
                    }
                    tracing::info!(
                        "Loaded chain state: height={}, tip={}",
                        state.height,
                        state.tip_hash.to_hex()
                    );

                    // Self-heal total_difficulty from the active chain.
                    //
                    // The stored value can drift from the deterministic
                    // `1 + Σ dft(1..=height)` when the node has taken the
                    // (pre-fix) reorg path, which accumulated against a
                    // `dft(genesis)` base or stored a partial fork walk. A
                    // drifted value makes this node advertise a `ChainWorkMessage`
                    // that disagrees with peers on the SAME tip's work, which
                    // false-positives their `work_behind` veto and locks their
                    // (follower) miners out. Recompute the canonical value and
                    // overwrite in memory; the corrected value persists on the
                    // next block commit. If any block is missing we keep the
                    // stored value rather than store a wrong partial.
                    if let Some(recomputed) = self.recompute_total_difficulty(state.height) {
                        let mut inner = self.inner.write();
                        if inner.stats.total_difficulty != recomputed {
                            tracing::warn!(
                                "total_difficulty self-heal on load: stored={} recomputed={} delta={} \
                                 — converging to the deterministic 1 + Σ dft(1..=height)",
                                inner.stats.total_difficulty,
                                recomputed,
                                (recomputed as i128) - (inner.stats.total_difficulty as i128),
                            );
                            inner.stats.total_difficulty = recomputed;
                        }
                    }

                    // Rebuild UTXO set from stored blocks so that key image
                    // checks and decoy selection work immediately after restart.
                    self.rebuild_utxo_set(state.height)?;

                    // Rebuild tx index if empty (migration for existing chains)
                    if let Some(ref db) = self.db {
                        if db.tx_index_is_empty() && state.height > 0 {
                            tracing::info!("Building tx index for {} blocks...", state.height + 1);
                            let start = std::time::Instant::now();
                            let mut indexed = 0u64;
                            let mut failed = 0u64;
                            for h in 0..=state.height {
                                if let Some(block) = self.get_block_by_height(h) {
                                    for (idx, tx) in block.transactions.iter().enumerate() {
                                        if let Err(e) =
                                            db.index_tx(tx.hash().as_bytes(), h, idx as u32)
                                        {
                                            failed += 1;
                                            // Log per-failure at DEBUG to avoid log
                                            // spam during a corrupt-DB rebuild, but
                                            // a non-zero `failed` count at the end
                                            // surfaces the issue at WARN.
                                            tracing::debug!(
                                                target: "chain::tx_index_rebuild",
                                                "index_tx failed at h={} idx={}: {}",
                                                h, idx, e
                                            );
                                        } else {
                                            indexed += 1;
                                        }
                                    }
                                }
                            }
                            if failed > 0 {
                                tracing::warn!(
                                    "Tx index rebuild: {} indexed, {} FAILED in {:.2}s. \
                                     Failed lookups will return None until next rebuild.",
                                    indexed,
                                    failed,
                                    start.elapsed().as_secs_f64()
                                );
                            } else {
                                tracing::info!(
                                    "Tx index built: {} txs in {:.2}s",
                                    indexed,
                                    start.elapsed().as_secs_f64()
                                );
                            }
                        }
                    }

                    // Verify tip integrity after loading (catches poisoned lock corruption)
                    self.verify_tip_integrity()?;

                    Ok(ChainLoadOutcome::Loaded)
                }
                None => Err(Error::DatabaseError(format!(
                    "chain state references missing tip block {} at height {}",
                    state.tip_hash, state.height,
                ))),
            };
        }
        Ok(ChainLoadOutcome::Fresh)
    }

    /// Rebuild in-memory UTXO set by replaying all blocks from the database.
    ///
    /// Called on startup after loading chain state to ensure the UTXO set
    /// (key images, outputs, height index) is fully populated. Without this,
    /// `validate_transaction()` would miss pre-restart key images, allowing
    /// double-spends during the window before re-sync completes.
    fn rebuild_utxo_set(&self, tip_height: u64) -> Result<()> {
        let db = match self.db.as_ref() {
            Some(db) => db,
            None => return Ok(()),
        };

        tracing::info!("Rebuilding UTXO set from {} blocks...", tip_height + 1);
        let start = std::time::Instant::now();

        let mut inner = self.inner.write();
        inner.utxos = UtxoSet::new();
        // Wire up on-disk fallback for output_index cache misses
        if let Some(ref db) = self.db {
            inner.utxos.set_database(Arc::clone(db));
        }

        // Also rebuild in-memory block caches for recent blocks (needed by
        // get_difficulty_blocks, find_fork_point, etc.)
        let cache_depth = 200u64;
        let cache_start = tip_height.saturating_sub(cache_depth);

        let mut prev_hash = Hash::zero(); // genesis prev_hash
        // Reconstruct the block/tx counters from the actual persisted chain.
        // ChainStateData does NOT persist total_blocks/total_transactions, so
        // without this they reload as 0 and undercount forever after a restart
        // (same "stats field not reconstructed on load" class as the difficulty=0
        // fix above; surfaced by the L8 db-reopen determinism test 2026-08-18).
        let mut blocks_applied: u64 = 0;
        let mut txs_applied: u64 = 0;
        for height in 0..=tip_height {
            match db.blocks.get_by_height(height) {
                Ok(Some(block)) => {
                    // Verify chain link integrity
                    if height > 0 && block.header.prev_hash != prev_hash {
                        tracing::error!(
                            "CHAIN CORRUPTION at height {}: prev_hash {} != expected {}. \
                             Truncating chain to height {}.",
                            height,
                            block.header.prev_hash.to_hex()[..16].to_string(),
                            prev_hash.to_hex()[..16].to_string(),
                            height - 1
                        );
                        // Fix: truncate the tip to the last good height.
                        //
                        // 2026-06-03 bug fix: previously the tip-restore branch
                        // only ran if `height_to_hash.get(&good_height)`
                        // returned Some — but that in-memory map is populated
                        // only for blocks in the cache window (last ~200
                        // heights, see line ~803-806). For corruption detected
                        // at any height BELOW the cache window, the lookup
                        // returned None and `inner.tip` was never reset. The
                        // node would restart looking healthy (stats.height
                        // dropped to good_height, but tip.height stayed at the
                        // state-claimed pre-corruption value), then reject
                        // every subsequent new block with "invalid height:
                        // expected <state_tip+1>, got <good_height+1>", and
                        // the chain would be stuck until manual intervention.
                        //
                        // `prev_hash` already holds the hash of the previous
                        // good block (set at line ~796-797 each iteration), so
                        // use it directly — no cache dependency. stats.height,
                        // tip.height, and tip.hash now ALWAYS move together.
                        let good_height = height - 1;
                        let good_hash = prev_hash;
                        inner.stats.height = good_height;
                        inner.tip.height = good_height;
                        inner.tip.hash = good_hash;
                        inner.stats.tip_hash = good_hash;
                        // Remove broken height entries from DB
                        for h in height..=tip_height {
                            let _ = db.blocks.remove_height_hash(h);
                        }
                        // Save corrected state
                        let last_checkpoint = db
                            .state
                            .get_state()
                            .ok()
                            .flatten()
                            .map(|s| s.last_checkpoint)
                            .unwrap_or(0);
                        let state = crate::db::ChainStateData {
                            tip_hash: inner.stats.tip_hash,
                            height: good_height,
                            total_difficulty: inner.stats.total_difficulty,
                            total_supply: inner.stats.total_supply,
                            total_burned: inner.stats.total_burned as u64,
                            last_checkpoint,
                        };
                        if let Err(e) = db.state.save_state(&state) {
                            // Surfacing this previously-silent error closes the
                            // audit finding "let _ = save_state drops critical
                            // persistence error." If save_state fails after a
                            // truncation, the on-disk tip will be ahead of the
                            // in-memory truncated state — on restart the chain
                            // re-loads the stale tip, masking the truncation.
                            // We can't abort here (we're mid-truncation, the
                            // in-memory state is correct), but at least the
                            // operator gets a CRITICAL log line. Reference:
                            // Bitcoin Core reports comparable post-flush
                            // failures through `FatalError()` (validation.h:104
                            // in the master read this session; the previous
                            // `AbortNode()` identifier was renamed).
                            tracing::error!(
                                target: "chain::persistence",
                                "CRITICAL: save_state failed after truncation to height {} ({}). \
                                 Restart will reload stale on-disk tip. Manual operator \
                                 intervention required.",
                                good_height, e
                            );
                        }
                        tracing::warn!(
                            "Chain truncated to height {}. Node will re-sync missing blocks.",
                            good_height
                        );
                        break;
                    }

                    let hash = block.hash();
                    prev_hash = hash;

                    let batch = UtxoSet::batch_from_block(height, &block.transactions);
                    inner.utxos.apply_batch(batch);

                    // Count this successfully-applied block toward the
                    // reconstructed counters (the truncation path `break`s above,
                    // so post-corruption blocks are correctly excluded).
                    blocks_applied += 1;
                    txs_applied += block.transactions.len() as u64;

                    // Cache recent blocks in memory for fast access
                    if height >= cache_start {
                        inner.height_to_hash.insert(height, hash);
                        inner.blocks.insert(hash, block);
                    }

                    if height > 0 && height % 10000 == 0 {
                        tracing::info!(
                            "  UTXO rebuild: {}/{} blocks processed",
                            height,
                            tip_height
                        );
                    }
                }
                Ok(None) => {
                    tracing::warn!("Block at height {} missing during UTXO rebuild", height);
                }
                Err(e) => {
                    tracing::error!("Failed to read block at height {}: {}", height, e);
                    return Err(e);
                }
            }
        }

        // Reconstruct the counters ChainStateData does not persist, so RPC
        // get_info / explorer totals are correct immediately after a restart
        // instead of resetting to 0 (L8 db-reopen finding, 2026-08-18).
        inner.stats.total_blocks = blocks_applied;
        inner.stats.total_transactions = txs_applied;

        // Migration: if the persistent output_index sled tree is empty but we
        // have blocks, bulk-insert from the in-memory output_index that was
        // populated during the replay above.
        if let Some(ref db) = self.db {
            if db.output_index.is_empty() && tip_height > 0 {
                tracing::info!("Migrating output index to persistent storage...");
                let mut migrated = 0u64;
                for (stealth, entry) in inner.utxos.output_index_iter() {
                    if let Err(e) = db.output_index.insert(stealth, entry) {
                        tracing::error!("Failed to migrate output index entry: {}", e);
                    } else {
                        migrated += 1;
                    }
                }
                tracing::info!("Migrated {} output index entries to sled", migrated);
            }
        }

        // Evict old output_index entries to bound memory (~1000 blocks in RAM).
        // Older entries fall back to the on-disk OutputIndexDb.
        inner.utxos.evict_old_outputs(tip_height, 1000);

        let elapsed = start.elapsed();
        tracing::info!(
            "UTXO set rebuilt: {} outputs, {} spent key images, {} blocks in {:.2}s",
            inner.utxos.output_count(),
            inner.utxos.total_outputs_ever(),
            tip_height + 1,
            elapsed.as_secs_f64()
        );

        Ok(())
    }
}
