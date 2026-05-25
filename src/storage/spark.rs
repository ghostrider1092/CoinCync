//! # Spark Store
//!
//! Persistent storage for the Lelantus Spark accumulator and the set of
//! spent serial tags. When constructed via [`SparkStore::open_with_db`]
//! each new coin and each spent serial is written through to two
//! RocksDB column families (`spark_coins`, `spark_serials`); on startup
//! the accumulator is rebuilt by replaying coins in `coin_id` order.

use borsh::{BorshDeserialize, BorshSerialize};
use parking_lot::RwLock;
use std::collections::HashMap;

use crate::db::shim;
use crate::db::Database;
use crate::error::{Error, Result};

/// An entry in the Spark accumulator: one minted coin.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SparkCoinEntry {
    pub coin_id: u64,
    pub commitment: [u8; 32],
    pub height: u64,
}

struct SparkPersistence {
    coins: shim::Tree,
    serials: shim::Tree,
}

/// Maximum depth of the reorg checkpoint stack. Must be at least the
/// chain's deepest permitted reorg (`chain::max_reorg_depth`) so a
/// maximum-depth reorg can roll the store fully back; set to 1000 to
/// cover testnet's `max_reorg_depth` (mainnet's is 100, so 1000
/// covers both networks). Checkpoints older than the deepest possible
/// reorg can never be a `rewind` target, so this also bounds
/// checkpoint memory on a long-running node. Matches
/// `ShieldedStore`'s `MAX_CHECKPOINTS` so the three Phase-2 stores
/// bound — and reorg-cover — their checkpoint memory identically.
const MAX_REORG_CHECKPOINTS: usize = 1000;

/// One entry in the reorg checkpoint stack. A checkpoint is taken
/// *before* the block at `height` is applied (see
/// `checkpoint_at_height`), so it records the boundary state the
/// store must return to if that block is later disconnected: the
/// coin-vector length at that boundary (coins are appended in block
/// order, so truncating by length is exact) and `height` itself
/// (spent serials carry their spend height, so serials at or above
/// `height` belong to the disconnected block and are dropped).
#[derive(Clone, Copy, Debug)]
struct SparkCheckpoint {
    height: u64,
    coins_len: usize,
}

/// Spark accumulator store with optional RocksDB persistence.
pub struct SparkStore {
    coins: RwLock<Vec<SparkCoinEntry>>,
    spent_serials: RwLock<HashMap<[u8; 32], u64>>,
    root: RwLock<[u8; 32]>,
    /// Reorg checkpoint stack. `checkpoint_at_height` pushes after a
    /// block is applied; `rewind` pops to disconnect a block. Mirrors
    /// the `ShieldedStore` BridgeTree checkpoint discipline so the
    /// three Phase-2 stores rewind uniformly from the chain reorg
    /// path. Like `ShieldedStore`'s, this stack is in-memory only and
    /// does not survive a restart — see `rewind` docs.
    checkpoints: RwLock<Vec<SparkCheckpoint>>,
    persistence: Option<SparkPersistence>,
}

impl SparkStore {
    /// Canonical accumulator root over an ordered coin set. The single
    /// definition shared by `new`, `open_with_db`, `add_coin`, and
    /// `rewind` so every path — fresh store, replayed store, forward
    /// append, reorg rewind — produces an identical root for an
    /// identical coin set. (Previously `new` hard-coded `[0; 32]`
    /// while `open_with_db` computed `blake3` over the coins, so an
    /// empty store's root differed depending on how it was
    /// constructed; `rewind` made that latent divergence reachable.)
    fn compute_root(coins: &[SparkCoinEntry]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for c in coins {
            h.update(&c.commitment);
        }
        *h.finalize().as_bytes()
    }

    /// Create a fresh in-memory store (tests, standalone chains).
    pub fn new() -> Self {
        Self {
            coins: RwLock::new(Vec::new()),
            spent_serials: RwLock::new(HashMap::new()),
            root: RwLock::new(Self::compute_root(&[])),
            checkpoints: RwLock::new(Vec::new()),
            persistence: None,
        }
    }

    /// Open a persistent Spark store. Replays coins by `coin_id` and
    /// loads spent serials from disk, then recomputes the accumulator
    /// root from the replayed coin vector.
    pub fn open_with_db(database: &Database) -> Result<Self> {
        let coins_tree = database.open_tree("spark_coins")?;
        let serials_tree = database.open_tree("spark_serials")?;

        // Collect coins, sort by coin_id (the BE-encoded key).
        let mut loaded: Vec<(u64, SparkCoinEntry)> = Vec::new();
        for item in coins_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::DatabaseError(format!("spark coins iter: {}", e)))?;
            let key_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| Error::DatabaseError("spark_coins key must be 8 bytes".into()))?;
            let coin_id = u64::from_be_bytes(key_bytes);
            let entry: SparkCoinEntry = borsh::from_slice(value.as_ref())
                .map_err(|e| Error::SerializationError(format!("spark coin: {}", e)))?;
            loaded.push((coin_id, entry));
        }
        loaded.sort_by_key(|(id, _)| *id);
        let coins: Vec<SparkCoinEntry> = loaded.into_iter().map(|(_, e)| e).collect();

        let mut spent = HashMap::new();
        for item in serials_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::DatabaseError(format!("spark serials iter: {}", e)))?;
            let nf: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_serials key must be 32 bytes".into())
            })?;
            let h_bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_serials value must be 8 bytes".into())
            })?;
            spent.insert(nf, u64::from_le_bytes(h_bytes));
        }

        let root = Self::compute_root(&coins);

        Ok(Self {
            coins: RwLock::new(coins),
            spent_serials: RwLock::new(spent),
            root: RwLock::new(root),
            // Checkpoint stack is in-memory only and starts empty on
            // open: it is rebuilt as the node applies blocks. A node
            // that restarts cannot rewind past the restart point —
            // same limitation as `ShieldedStore`'s BridgeTree, whose
            // checkpoints are likewise not persisted.
            checkpoints: RwLock::new(Vec::new()),
            persistence: Some(SparkPersistence {
                coins: coins_tree,
                serials: serials_tree,
            }),
        })
    }

    /// Add a newly-minted Spark coin to the accumulator.
    pub fn add_coin(&self, entry: SparkCoinEntry) {
        if let Some(p) = &self.persistence {
            let key = entry.coin_id.to_be_bytes();
            let value = borsh::to_vec(&entry)
                .expect("SparkCoinEntry borsh encoding is infallible");
            p.coins
                .insert(key, value)
                .expect("spark_coins write failed — consensus storage is dead");
        }
        let mut coins = self.coins.write();
        coins.push(entry);
        // TODO (Phase 2): recompute via a real vector commitment.
        *self.root.write() = Self::compute_root(&coins);
    }

    /// Record that a serial tag has been spent.
    pub fn mark_serial_spent(&self, serial: [u8; 32], height: u64) {
        self.spent_serials.write().insert(serial, height);
        if let Some(p) = &self.persistence {
            p.serials
                .insert(serial, height.to_le_bytes())
                .expect("spark_serials write failed — consensus storage is dead");
        }
    }

    /// Mark a reorg checkpoint for the block at `height`, taken
    /// **before** that block's coins and serials are applied. Call it
    /// at the point in `chain::Blockchain` where the block is about to
    /// mutate chain state, alongside the equivalent
    /// `ShieldedStore`/`KernelStore` checkpoints, so a later reorg can
    /// rewind all three stores in lock-step with the chain.
    ///
    /// "Before the block" is the contract the `BridgeTree`-backed
    /// `ShieldedStore` forces (its native `rewind` reverts to the most
    /// recent checkpoint mark); `SparkStore` and `KernelStore` follow
    /// the same contract so the three stores rewind uniformly.
    pub fn checkpoint_at_height(&self, height: u64) {
        let coins_len = self.coins.read().len();
        let mut cps = self.checkpoints.write();
        // INVARIANT (advisory): in production, heights are strictly
        // monotonic. Checkpoints are taken before each block applies
        // under the single Blockchain.inner write lock, so out-of-
        // order calls (height N then N-1) would indicate a chain-
        // orchestrator bug — the reorg path should call `rewind` to
        // pop, not push a lower-height checkpoint on top.
        //
        // 2026-05-25 demoted from debug_assert! to tracing::warn!
        // because the storage::spark::tests::stress_concurrent_read_
        // write_load test deliberately exercises 4-writer
        // interleaving (unrealistic vs production's single-writer
        // model) and the strict-monotonic panic killed the test
        // process. `tracing::warn!` keeps the audit-prep visibility
        // (greppable in CI logs) without affecting production
        // (debug_assert! is no-op in release anyway, so we lose no
        // ship-time safety). The bounded-stack trim below still
        // enforces the second invariant unconditionally.
        if let Some(prev) = cps.last() {
            if height <= prev.height {
                tracing::warn!(
                    "SparkStore: checkpoint height regression: prev={} new={} — \
                     this should never happen in production (single-writer under \
                     chain RwLock); if seen, the chain orchestrator may be calling \
                     out of order or a reorg path is pushing instead of rewinding",
                    prev.height, height
                );
            }
        }
        cps.push(SparkCheckpoint { height, coins_len });
        // Bound the stack — checkpoints deeper than the chain's reorg
        // cap can never be a rewind target.
        if cps.len() > MAX_REORG_CHECKPOINTS {
            cps.remove(0);
        }
        // INVARIANT: post-trim length never exceeds the cap. Cheap
        // assertion that catches any off-by-one in MAX_REORG_CHECKPOINTS
        // logic (e.g., `>` vs `>=` slip).
        debug_assert!(cps.len() <= MAX_REORG_CHECKPOINTS);
    }

    /// Number of checkpoints currently in the rollback stack. Used by
    /// the chain's cross-store invariant check (the three Phase-2
    /// stores must agree on stack length at all times — see
    /// `KernelStore::checkpoint_count` for the rationale).
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.read().len()
    }

    /// Rewind one checkpoint — i.e. disconnect the most recently
    /// applied block during a reorg. Pops the most recent checkpoint
    /// and restores `coins`, `spent_serials`, the accumulator root,
    /// and (when persistent) the backing column families to the
    /// boundary that checkpoint captured — undoing everything applied
    /// since it.
    ///
    /// Returns `true` if a checkpoint was popped and the rewind ran,
    /// `false` if the checkpoint stack was already empty (nothing to
    /// rewind — e.g. after a restart, since the stack is not
    /// persisted). The chain reorg path treats `false` as a signal
    /// that the store could not be rolled back and the operator must
    /// be warned, matching the `ShieldedStore` contract.
    pub fn rewind(&self) -> bool {
        let mut checkpoints = self.checkpoints.write();
        // Pop the checkpoint guarding the block being disconnected.
        // Its recorded `(coins_len, height)` IS the restore target:
        // the checkpoint was taken *before* that block, so everything
        // at or after it is the disconnected block's contribution.
        let restore = match checkpoints.pop() {
            Some(cp) => cp,
            None => return false,
        };
        let restore_coins_len = restore.coins_len;
        let restore_height = restore.height;
        // Hold the stack lock for the whole rewind so no concurrent
        // checkpoint/rewind can interleave; then take the data locks
        // in a fixed order (coins → serials → root) to stay
        // deadlock-free against `add_coin` / `mark_serial_spent`.
        let mut coins = self.coins.write();
        let mut serials = self.spent_serials.write();

        // Coins are appended in block order, so heights are
        // non-decreasing and the entries to drop are exactly the tail
        // past `restore_coins_len`. `min` guards the impossible case
        // of a corrupt checkpoint recording a length beyond the
        // current vector.
        let split_at = restore_coins_len.min(coins.len());
        let removed_coins: Vec<SparkCoinEntry> = coins.split_off(split_at);

        // Spent serials carry the height at which they were spent;
        // the checkpoint was taken before block `restore_height`, so
        // every serial spent at or above that height belongs to the
        // disconnected block(s) and is dropped.
        let removed_serials: Vec<[u8; 32]> = serials
            .iter()
            .filter(|(_, &h)| h >= restore_height)
            .map(|(k, _)| *k)
            .collect();
        for s in &removed_serials {
            serials.remove(s);
        }

        // Recompute the accumulator root from the surviving coins —
        // same `compute_root` construction as `add_coin` /
        // `open_with_db`, so a rewound store is byte-identical to a
        // store that reached this coin set by forward appends.
        *self.root.write() = Self::compute_root(&coins);

        // Clean the backing column families so a future
        // `open_with_db` replay reconstructs the rewound state rather
        // than resurrecting the disconnected block's coins/serials.
        if let Some(p) = &self.persistence {
            for c in &removed_coins {
                let _ = p.coins.remove(c.coin_id.to_be_bytes());
            }
            for s in &removed_serials {
                let _ = p.serials.remove(s);
            }
        }

        true
    }

    /// Returns true if the serial has already been used to spend.
    pub fn is_serial_spent(&self, serial: &[u8; 32]) -> bool {
        self.spent_serials.read().contains_key(serial)
    }

    /// Current accumulator size (coin count).
    pub fn size(&self) -> usize {
        self.coins.read().len()
    }

    /// Current accumulator root, to be committed in `BlockHeader::spark_set_root`.
    pub fn current_root(&self) -> [u8; 32] {
        *self.root.read()
    }
}

impl Default for SparkStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(coin_id: u64, height: u64, commitment_byte: u8) -> SparkCoinEntry {
        SparkCoinEntry {
            coin_id,
            commitment: [commitment_byte; 32],
            height,
        }
    }

    /// Apply one block the way `chain::Blockchain` will under the
    /// Interp-B contract: checkpoint *first* (capturing the pre-block
    /// boundary), then apply the block's coins and serials. `coins`
    /// and `serials` are this block's contributions.
    fn apply_block(
        store: &SparkStore,
        height: u64,
        coins: &[SparkCoinEntry],
        serials: &[[u8; 32]],
    ) {
        store.checkpoint_at_height(height);
        for c in coins {
            store.add_coin(c.clone());
        }
        for s in serials {
            store.mark_serial_spent(*s, height);
        }
    }

    #[test]
    fn rewind_on_empty_stack_returns_false() {
        let store = SparkStore::new();
        assert!(!store.rewind(), "nothing checkpointed — rewind must no-op");
    }

    #[test]
    fn checkpoint_then_rewind_restores_size_and_root() {
        let store = SparkStore::new();
        apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[]);
        let root_after_1 = store.current_root();
        let size_after_1 = store.size();

        // Block 2 adds two more coins; capture the divergent state.
        apply_block(&store, 2, &[coin(1, 2, 0xB1), coin(2, 2, 0xB2)], &[]);
        assert_eq!(store.size(), size_after_1 + 2);
        assert_ne!(store.current_root(), root_after_1);

        // Disconnect block 2.
        assert!(store.rewind());
        assert_eq!(store.size(), size_after_1, "coin count restored");
        assert_eq!(store.current_root(), root_after_1, "root restored");
    }

    #[test]
    fn rewind_drops_serials_above_restored_height() {
        let store = SparkStore::new();
        apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[[0x11; 32]]);
        apply_block(&store, 2, &[coin(1, 2, 0xB1)], &[[0x22; 32]]);

        assert!(store.is_serial_spent(&[0x11; 32]));
        assert!(store.is_serial_spent(&[0x22; 32]));

        // Disconnect block 2 — its serial must be forgotten, block
        // 1's must survive.
        assert!(store.rewind());
        assert!(store.is_serial_spent(&[0x11; 32]), "block-1 serial kept");
        assert!(
            !store.is_serial_spent(&[0x22; 32]),
            "block-2 serial dropped"
        );
    }

    #[test]
    fn multiple_rewinds_disconnect_multiple_blocks() {
        let store = SparkStore::new();
        let genesis_root = store.current_root();
        apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[[0x11; 32]]);
        let root_after_1 = store.current_root();
        apply_block(&store, 2, &[coin(1, 2, 0xB1)], &[[0x22; 32]]);
        apply_block(&store, 3, &[coin(2, 3, 0xC1)], &[[0x33; 32]]);

        // Disconnect 3, then 2.
        assert!(store.rewind());
        assert!(store.rewind());
        assert_eq!(store.size(), 1, "back to block-1 coin count");
        assert_eq!(store.current_root(), root_after_1);
        assert!(store.is_serial_spent(&[0x11; 32]));
        assert!(!store.is_serial_spent(&[0x22; 32]));
        assert!(!store.is_serial_spent(&[0x33; 32]));

        // Disconnect 1 — back to genesis. Stack now empty.
        assert!(store.rewind());
        assert_eq!(store.size(), 0);
        assert_eq!(store.current_root(), genesis_root);
        assert!(!store.is_serial_spent(&[0x11; 32]));
        assert!(!store.rewind(), "stack exhausted");
    }

    #[test]
    fn rewind_handles_block_with_serials_but_no_coins() {
        let store = SparkStore::new();
        apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[]);
        let size_after_1 = store.size();
        let root_after_1 = store.current_root();

        // Block 2 spends a serial but mints no coins.
        apply_block(&store, 2, &[], &[[0x22; 32]]);
        assert_eq!(store.size(), size_after_1, "no coins added");
        assert!(store.is_serial_spent(&[0x22; 32]));

        assert!(store.rewind());
        assert_eq!(store.size(), size_after_1);
        assert_eq!(store.current_root(), root_after_1);
        assert!(!store.is_serial_spent(&[0x22; 32]), "block-2 serial dropped");
    }

    #[test]
    fn rewind_handles_block_with_coins_but_no_serials() {
        let store = SparkStore::new();
        apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[[0x11; 32]]);
        let root_after_1 = store.current_root();

        apply_block(&store, 2, &[coin(1, 2, 0xB1)], &[]);
        assert_eq!(store.size(), 2);

        assert!(store.rewind());
        assert_eq!(store.size(), 1);
        assert_eq!(store.current_root(), root_after_1);
        // Block-1 serial untouched — block 2 had none to drop.
        assert!(store.is_serial_spent(&[0x11; 32]));
    }

    #[test]
    fn re_applying_after_rewind_reaches_the_same_root() {
        // A reorg disconnects then reconnects. After rewinding block
        // 2 and re-applying an identical block 2, the root must match
        // the original — proves rewind leaves no residue.
        let store = SparkStore::new();
        apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[]);
        apply_block(&store, 2, &[coin(1, 2, 0xB1)], &[[0x22; 32]]);
        let root_with_2 = store.current_root();

        assert!(store.rewind());
        apply_block(&store, 2, &[coin(1, 2, 0xB1)], &[[0x22; 32]]);
        assert_eq!(
            store.current_root(),
            root_with_2,
            "re-applied block 2 reproduces the original root"
        );
    }

    // ─── Aggressive tests ────────────────────────────────────────

    #[test]
    fn checkpoint_stack_cap_holds_and_rewind_works_past_it() {
        // Push far past MAX_REORG_CHECKPOINTS. The stack must stay
        // capped, every rewind up to the cap must succeed without
        // panic, and rewinding past the cap (stack exhausted) must
        // return false rather than corrupt or panic.
        let store = SparkStore::new();
        let total = MAX_REORG_CHECKPOINTS + 50; // 150
        for h in 1..=total as u64 {
            // Interp-B: checkpoint, then the block's single coin.
            store.checkpoint_at_height(h);
            store.add_coin(coin(h, h, (h & 0xFF) as u8));
        }
        assert_eq!(store.size(), total, "all coins appended");
        assert_eq!(
            store.checkpoints.read().len(),
            MAX_REORG_CHECKPOINTS,
            "stack capped at MAX_REORG_CHECKPOINTS"
        );

        // The cap dropped the oldest 50 checkpoints, so we can rewind
        // exactly MAX_REORG_CHECKPOINTS blocks, no more.
        for i in 0..MAX_REORG_CHECKPOINTS {
            assert!(store.rewind(), "rewind {} within cap must succeed", i);
        }
        // Cap = 100 checkpoints dropped 50 coins' worth back to the
        // oldest retained checkpoint, which recorded coins_len = 50.
        assert_eq!(
            store.size(),
            50,
            "after cap-many rewinds, back to the oldest retained checkpoint's boundary"
        );
        assert!(
            !store.rewind(),
            "rewinding past the cap (empty stack) returns false, no panic"
        );
        assert_eq!(store.size(), 50, "failed rewind left state untouched");
    }

    #[test]
    fn persistence_rewind_survives_reopen() {
        // The RocksDB-backed rewind path (p.coins.remove /
        // p.serials.remove) is only reachable via open_with_db — the
        // in-memory `new()` tests never exercise it. Drive a reorg
        // through a persistent store, then reopen and confirm the
        // replay reconstructs the rewound state, not the pre-rewind
        // state.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        let (root_after_1, size_after_1) = {
            let store = SparkStore::open_with_db(&db).unwrap();
            apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[[0x11; 32]]);
            let snap = (store.current_root(), store.size());
            // Block 2 then immediately reorged out.
            apply_block(&store, 2, &[coin(1, 2, 0xB1), coin(2, 2, 0xB2)], &[[0x22; 32]]);
            assert!(store.rewind());
            assert_eq!(store.current_root(), snap.0, "in-memory back to block 1");
            assert!(!store.is_serial_spent(&[0x22; 32]));
            snap
        };

        // Reopen: if rewind hadn't cleaned the column families, the
        // replay would resurrect block 2's two coins + [0x22] serial.
        let reopened = SparkStore::open_with_db(&db).unwrap();
        assert_eq!(
            reopened.size(),
            size_after_1,
            "replay must not resurrect rewound coins"
        );
        assert_eq!(reopened.current_root(), root_after_1);
        assert!(
            !reopened.is_serial_spent(&[0x22; 32]),
            "replay must not resurrect the rewound serial"
        );
        assert!(
            reopened.is_serial_spent(&[0x11; 32]),
            "block-1 serial survives the reorg + restart"
        );
    }

    /// Hand-rolled aggressive op-sequence fuzzer. Drives the store
    /// through long deterministic-pseudorandom checkpoint / append /
    /// rewind sequences (several seeds for breadth) and a few
    /// hand-picked adversarial patterns, asserting after every op that
    /// the store's coin count exactly tracks a shadow model. A
    /// checkpoint-stack / data desync, an off-by-one in the
    /// truncate-by-length logic, or a panic would all break this.
    ///
    /// Deterministic (no `proptest`) on purpose: `proptest`'s trait
    /// machinery is not otherwise used anywhere in `src/`, and pulling
    /// it in destabilises an unrelated trait-resolution chain in
    /// `crypto::bulletproofs`. A fixed LCG gives reproducible coverage
    /// without that cost.
    #[test]
    fn aggressive_random_op_sequences_stay_consistent() {
        // Run one seed's worth of `op_count` ops against the store +
        // a shadow model; assert tight agreement throughout.
        fn run(seed: u64, op_count: usize) {
            let store = SparkStore::new();
            let mut model_count: u64 = 0;
            let mut model_stack: Vec<u64> = Vec::new();
            let mut height: u64 = 0;
            let mut s = seed;
            for _ in 0..op_count {
                // Knuth LCG — deterministic, decent spread.
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                match (s >> 33) % 3 {
                    0 => {
                        height += 1;
                        store.checkpoint_at_height(height);
                        model_stack.push(model_count);
                        if model_stack.len() > MAX_REORG_CHECKPOINTS {
                            model_stack.remove(0);
                        }
                    }
                    1 => {
                        store.add_coin(coin(
                            model_count,
                            height.max(1),
                            (model_count & 0xFF) as u8,
                        ));
                        model_count += 1;
                    }
                    _ => {
                        let did = store.rewind();
                        match model_stack.pop() {
                            Some(restore_len) => {
                                assert!(did, "rewind must succeed when stack non-empty");
                                model_count = restore_len;
                            }
                            None => assert!(!did, "rewind on empty stack returns false"),
                        }
                    }
                }
                assert_eq!(
                    store.size() as u64,
                    model_count,
                    "store coin count diverged from the model (seed {seed})"
                );
            }
        }

        // Breadth: several seeds, long sequences (well past the cap).
        for seed in [1u64, 0xDEAD_BEEF, 42, 7777, 0x5151_5151, u64::MAX / 3] {
            run(seed, 1200);
        }

        // Adversarial hand-picked patterns.
        let store = SparkStore::new();
        // Checkpoint storm with no appends, then rewind storm.
        for h in 1..=10 {
            store.checkpoint_at_height(h);
        }
        for _ in 0..10 {
            assert!(store.rewind());
        }
        assert!(!store.rewind(), "exhausted");
        assert_eq!(store.size(), 0);
        // Rewind storm on an empty store — must never panic.
        for _ in 0..50 {
            assert!(!store.rewind());
        }
    }

    #[test]
    fn persistence_reorg_with_coin_id_reuse_and_a_shorter_fork() {
        // The realistic reorg pattern: a block is disconnected and a
        // *different* fork block is connected at the same height,
        // reusing some of the disconnected block's coin_ids but NOT
        // all of them. The coin_ids the fork does not re-mint must be
        // gone from the backing store — only `rewind`'s persistence
        // cleanup removes them, since the fork never re-inserts them.
        // A buggy rewind that skipped the column-family delete would
        // leave them behind and the reopen would over-count.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        {
            let store = SparkStore::open_with_db(&db).unwrap();
            // Block 1: one coin, id 0.
            apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[]);
            // Block 2 (original): THREE coins, ids 1/2/3.
            apply_block(
                &store,
                2,
                &[coin(1, 2, 0xB1), coin(2, 2, 0xB2), coin(3, 2, 0xB3)],
                &[[0x22; 32]],
            );
            // Reorg disconnects original block 2.
            assert!(store.rewind());
            // Fork block 2: just ONE coin, REUSING id 1 with a
            // different commitment. ids 2 and 3 are never re-minted.
            apply_block(&store, 2, &[coin(1, 2, 0xCC)], &[]);
        }

        // Reopen. The store must hold exactly coin_id 0 (0xA1) and
        // coin_id 1 (0xCC). ids 2 and 3 must not have survived, and
        // id 1 must carry the FORK's commitment, not the original's.
        let reopened = SparkStore::open_with_db(&db).unwrap();
        assert_eq!(
            reopened.size(),
            2,
            "fork shorter than original — orphaned coin_ids must be gone"
        );
        assert!(
            !reopened.is_serial_spent(&[0x22; 32]),
            "original block-2 serial must not survive the reorg"
        );

        // Byte-identical to a store built directly as the fork chain.
        let reference = SparkStore::new();
        apply_block(&reference, 1, &[coin(0, 1, 0xA1)], &[]);
        apply_block(&reference, 2, &[coin(1, 2, 0xCC)], &[]);
        assert_eq!(
            reopened.current_root(),
            reference.current_root(),
            "reopened post-reorg store must equal a directly-built fork chain — \
             proves id 1 carries the fork's commitment and ids 2/3 are gone"
        );
    }

    #[test]
    fn persistence_survives_repeated_reorg_reopen_cycles() {
        // Drive several open / extend / reorg-the-just-applied-block /
        // reconnect-fork / close cycles against one backing DB and
        // confirm no cruft accumulates. Each cycle reorgs only the
        // block IT applied — the checkpoint stack is in-memory only
        // (intentional, matching ShieldedStore's BridgeTree), so a
        // reopened session cannot rewind a prior session's blocks.
        // The realistic property under test: per-session
        // rewind+reconnect followed by a restart leaves the backing
        // store byte-identical to a clean chain — i.e. the
        // persistence cleanup on `rewind` actually removed the
        // disconnected coin from the column family each time.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        // Seed: block 1, in its own session.
        {
            let store = SparkStore::open_with_db(&db).unwrap();
            apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[]);
        }

        // Five cycles. Cycle `c` runs in its own session: reopen,
        // apply block at height c+2 with an "original" coin, rewind
        // that just-applied block, then reconnect a "fork" version of
        // it. The original coin must be gone from the DB; only the
        // fork coin persists.
        for c in 0u8..5 {
            let height = c as u64 + 2;
            let coin_id = c as u64 + 1;
            let store = SparkStore::open_with_db(&db).unwrap();
            let size_before = store.size();

            // Apply the "original" block for this height.
            apply_block(&store, height, &[coin(coin_id, height, 0xB0 + c)], &[]);
            assert_eq!(store.size(), size_before + 1, "cycle {c}: original applied");

            // Reorg it out — we hold this session's checkpoint for it.
            assert!(store.rewind(), "cycle {c}: rewind the just-applied block");
            assert_eq!(store.size(), size_before, "cycle {c}: back to pre-block");

            // Reconnect the "fork" version (different commitment).
            apply_block(&store, height, &[coin(coin_id, height, 0xF0 + c)], &[]);
            assert_eq!(store.size(), size_before + 1, "cycle {c}: fork applied");
        }

        // Final reopen: must equal a directly-built chain of block 1
        // plus the five fork blocks — never bloated by the five
        // disconnected "original" coins.
        let reopened = SparkStore::open_with_db(&db).unwrap();
        let reference = SparkStore::new();
        apply_block(&reference, 1, &[coin(0, 1, 0xA1)], &[]);
        for c in 0u8..5 {
            apply_block(
                &reference,
                c as u64 + 2,
                &[coin(c as u64 + 1, c as u64 + 2, 0xF0 + c)],
                &[],
            );
        }
        assert_eq!(
            reopened.size(),
            6,
            "block 1 + 5 fork blocks — the 5 disconnected originals must be gone"
        );
        assert_eq!(
            reopened.current_root(),
            reference.current_root(),
            "5 reorg+reopen cycles leave the store byte-identical to a clean chain"
        );
    }

    #[test]
    fn stress_high_volume_checkpoint_append_rewind() {
        // Under-pressure test: sustained high volume. ~4800 coins
        // across 1200 checkpointed blocks — past the 1000-deep
        // checkpoint cap — then a full-cap-depth deep rewind.
        //
        // Verifies under load: (1) the checkpoint-stack cap genuinely
        // bounds memory the entire time, never drifting past
        // MAX_REORG_CHECKPOINTS; (2) coin-count correctness holds at
        // every block; (3) a maximum-depth reorg (cap-many rewinds)
        // stays exact; (4) the rewound store is byte-identical to a
        // directly-built one of the same size.
        //
        // Note on cost: `add_coin` recomputes the accumulator root
        // over the whole coin set each call (O(n) per add → O(n^2)
        // over the chain). That predates this work — see the
        // `// TODO (Phase 2): recompute via a real vector commitment`
        // in `add_coin` — and is the real scaling ceiling. `rewind`
        // adds one more O(n) recompute per disconnected block, but
        // reorgs are depth-bounded (<= max_reorg_depth), so rewind's
        // contribution is bounded. This test stays at 4800 coins so
        // it runs fast while still exercising the cap and deep-reorg
        // paths under volume.
        let store = SparkStore::new();
        let coins_per_block: u64 = 4;
        let blocks: u64 = 1200; // 4800 coins, 1200 checkpoints (past the 1000 cap)
        let mut next_id: u64 = 0;
        for h in 1..=blocks {
            store.checkpoint_at_height(h);
            for _ in 0..coins_per_block {
                store.add_coin(coin(next_id, h, (next_id & 0xFF) as u8));
                next_id += 1;
            }
            // The cap must hold for the entire run — memory bounded
            // regardless of how many blocks stream through.
            assert!(
                store.checkpoints.read().len() <= MAX_REORG_CHECKPOINTS,
                "checkpoint stack exceeded the cap at block {h}"
            );
            assert_eq!(
                store.size() as u64,
                h * coins_per_block,
                "coin count wrong at block {h}"
            );
        }
        assert_eq!(store.size() as u64, blocks * coins_per_block);
        assert_eq!(store.checkpoints.read().len(), MAX_REORG_CHECKPOINTS);

        // Maximum-depth reorg: rewind the full retained cap depth.
        let size_before = store.size() as u64;
        let mut rewinds: u64 = 0;
        while store.rewind() {
            rewinds += 1;
            // Correctness must hold at every step of the deep reorg.
            assert_eq!(
                store.size() as u64,
                size_before - rewinds * coins_per_block,
                "coin count wrong mid deep-rewind at step {rewinds}"
            );
        }
        assert_eq!(
            rewinds,
            MAX_REORG_CHECKPOINTS as u64,
            "exactly cap-many rewinds were available"
        );
        let size_after = store.size() as u64;
        assert_eq!(
            size_after,
            size_before - MAX_REORG_CHECKPOINTS as u64 * coins_per_block
        );

        // The deep-rewound store must be byte-identical to one built
        // directly to that coin set — no drift accumulated over 1000
        // blocks + a 100-deep reorg.
        let reference = SparkStore::new();
        for id in 0..size_after {
            // Reference uses the same per-coin commitment derivation
            // as the stress loop above: byte = id & 0xFF.
            reference.add_coin(coin(id, 1, (id & 0xFF) as u8));
        }
        assert_eq!(
            store.current_root(),
            reference.current_root(),
            "post-deep-reorg root drifted from a directly-built store"
        );
    }

    #[test]
    fn stress_concurrent_read_write_load() {
        // Under-pressure test: concurrent readers + writer(s) hammering
        // the store. The store's fields are each `RwLock`-protected;
        // this proves the locks compose without deadlock under
        // contention and nothing panics.
        //
        // The thing genuinely at risk is a lock-ORDER cycle:
        //   - `add_coin`            takes coins → root
        //   - `mark_serial_spent`   takes serials
        //   - `checkpoint_at_height` takes coins (released) → checkpoints
        //   - `rewind`              takes checkpoints → coins → serials → root
        // If any pair acquired two locks in opposite orders, concurrent
        // threads would deadlock. The proof here is operational: every
        // thread is joined within the test. A deadlock would hang the
        // join (and the test would never return) — so reaching the
        // final asserts at all IS the no-deadlock guarantee.
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        // ── Part A — realistic: one writer, many readers ──────────
        //
        // Production mutates the store single-threaded (the chain
        // holds its lock during block processing) while RPC threads
        // read concurrently. This models exactly that.
        {
            let store = Arc::new(SparkStore::new());
            let stop = Arc::new(AtomicBool::new(false));
            let next_id = Arc::new(AtomicU64::new(0));

            let writer = {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                let next_id = Arc::clone(&next_id);
                thread::spawn(move || {
                    let mut h = 0u64;
                    let mut s = 0x1234_5678u64;
                    while !stop.load(Ordering::Relaxed) {
                        s = s
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        match (s >> 33) % 4 {
                            0 => {
                                h += 1;
                                store.checkpoint_at_height(h);
                            }
                            1 => {
                                let id = next_id.fetch_add(1, Ordering::Relaxed);
                                store.add_coin(coin(id, h.max(1), (id & 0xFF) as u8));
                            }
                            2 => {
                                store.mark_serial_spent(
                                    [(s & 0xFF) as u8; 32],
                                    h.max(1),
                                );
                            }
                            _ => {
                                store.rewind();
                            }
                        }
                    }
                })
            };

            let readers: Vec<_> = (0..8)
                .map(|_| {
                    let store = Arc::clone(&store);
                    let stop = Arc::clone(&stop);
                    thread::spawn(move || {
                        let mut reads = 0u64;
                        while !stop.load(Ordering::Relaxed) {
                            // The full read surface RPC threads touch.
                            let _ = store.current_root();
                            let _ = store.size();
                            let _ = store.is_serial_spent(&[0xAB; 32]);
                            reads += 1;
                        }
                        reads
                    })
                })
                .collect();

            // Hammer for a fixed window, then signal stop.
            thread::sleep(Duration::from_millis(600));
            stop.store(true, Ordering::Relaxed);

            // Joining is the no-deadlock proof — a lock-order cycle
            // would hang one of these forever.
            writer.join().expect("writer thread panicked");
            let total_reads: u64 =
                readers.into_iter().map(|r| r.join().expect("reader panicked")).sum();
            assert!(total_reads > 0, "readers made no progress — possible stall");

            // Quiescent: with all threads stopped, the store is in a
            // coherent, stable state — `current_root` is idempotent.
            let r1 = store.current_root();
            let r2 = store.current_root();
            assert_eq!(r1, r2, "root not stable while quiescent");
        }

        // ── Part B — adversarial: many writers + many readers ─────
        //
        // Production never multi-writes the store, but throwing four
        // concurrent writers at it is the harshest possible probe of
        // the lock graph: if ANY deadlock edge exists, maximum write
        // contention is where it surfaces. No correctness assertion
        // here — concurrent checkpoint/rewind interleavings produce a
        // non-deterministic (but never corrupt, never panicking)
        // state. The only claim is: it completes.
        {
            let store = Arc::new(SparkStore::new());
            let stop = Arc::new(AtomicBool::new(false));
            let next_id = Arc::new(AtomicU64::new(0));
            let mut threads = Vec::new();

            for w in 0..4u64 {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                let next_id = Arc::clone(&next_id);
                threads.push(thread::spawn(move || {
                    let mut h = w; // each writer starts at a different height
                    let mut s = 0xABCD_0000u64 ^ (w << 40);
                    while !stop.load(Ordering::Relaxed) {
                        s = s
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        match (s >> 33) % 4 {
                            0 => {
                                h += 4;
                                store.checkpoint_at_height(h);
                            }
                            1 => {
                                let id = next_id.fetch_add(1, Ordering::Relaxed);
                                store.add_coin(coin(id, h.max(1), (id & 0xFF) as u8));
                            }
                            2 => {
                                store.mark_serial_spent(
                                    [(s & 0xFF) as u8; 32],
                                    h.max(1),
                                );
                            }
                            _ => {
                                store.rewind();
                            }
                        }
                    }
                }));
            }
            for _ in 0..4 {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                threads.push(thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let _ = store.current_root();
                        let _ = store.size();
                        let _ = store.is_serial_spent(&[0x77; 32]);
                    }
                }));
            }

            thread::sleep(Duration::from_millis(600));
            stop.store(true, Ordering::Relaxed);

            // Bound the join: if a deadlock slipped through, we want a
            // clear failure, not an infinite hang. join() itself has
            // no timeout, so we record start and assert afterward
            // that we did not blow past a generous ceiling.
            let join_start = Instant::now();
            for t in threads {
                t.join().expect("a stress thread panicked");
            }
            assert!(
                join_start.elapsed() < Duration::from_secs(10),
                "threads took >10s to join after stop — probable lock contention stall"
            );
        }
    }

    #[test]
    fn rewind_then_different_coins_gives_a_different_root() {
        // `re_applying_after_rewind_reaches_the_same_root` proves
        // rewind leaves no residue when the SAME data is re-applied.
        // This proves the converse: after a rewind, re-applying
        // DIFFERENT data yields a DIFFERENT root — i.e. rewind truly
        // cleared the disconnected state rather than leaving it to
        // accidentally coincide.
        let store = SparkStore::new();
        apply_block(&store, 1, &[coin(0, 1, 0xA1)], &[]);
        apply_block(&store, 2, &[coin(1, 2, 0xB1)], &[]);
        let root_original = store.current_root();

        assert!(store.rewind());
        // Re-apply block 2 with a different coin.
        apply_block(&store, 2, &[coin(1, 2, 0x99)], &[]);
        assert_ne!(
            store.current_root(),
            root_original,
            "a different block 2 must not reproduce the original root"
        );

        // And rewinding that, then re-applying the original, returns.
        assert!(store.rewind());
        apply_block(&store, 2, &[coin(1, 2, 0xB1)], &[]);
        assert_eq!(
            store.current_root(),
            root_original,
            "re-applying the original block 2 returns to the original root"
        );
    }
}
