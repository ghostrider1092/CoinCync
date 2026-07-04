//! # MW Kernel Store
//!
//! Persistent storage for MimbleWimble kernels that survive cut-through
//! pruning. The input/output pairs are deleted after `MW_CUTTHROUGH_DEPTH`
//! confirmations, but the kernel stays so the chain's balance proof
//! remains verifiable.
//!
//! When constructed via [`KernelStore::open_with_db`] each appended
//! kernel is written through to the `mw_kernels` column family, keyed
//! on a monotonic index. On startup the in-memory vector and root are
//! rebuilt by replaying the stored kernels in key order.

use parking_lot::RwLock;

use crate::crypto::mw_cutthrough::MwKernel;
use crate::db::shim;
use crate::db::Database;
use crate::error::{Error, Result};

struct KernelPersistence {
    kernels: shim::Tree,
}

/// Maximum depth of the reorg checkpoint stack — see the identically
/// named constant and rationale in `storage::spark`. Set to 1000 to
/// cover testnet's `max_reorg_depth` (mainnet's is 100); matches
/// `ShieldedStore`'s `MAX_CHECKPOINTS` so the three Phase-2 stores
/// bound — and reorg-cover — their checkpoint memory identically.
const MAX_REORG_CHECKPOINTS: usize = 1000;

/// One entry in the reorg checkpoint stack. A checkpoint is taken
/// *before* the block at `height` is applied (see
/// `checkpoint_at_height`); it records the kernel-vector length at
/// that pre-block boundary. Kernels are appended in block order, so
/// truncating back to that length is an exact undo of the
/// disconnected block(s).
#[derive(Clone, Copy, Debug)]
struct KernelCheckpoint {
    #[allow(dead_code)] // recorded for diagnostics / symmetry with SparkCheckpoint
    height: u64,
    kernels_len: usize,
}

pub struct KernelStore {
    kernels: RwLock<Vec<MwKernel>>,
    root: RwLock<[u8; 32]>,
    /// Reorg checkpoint stack — see `checkpoint_at_height` / `rewind`.
    /// In-memory only, not persisted, so a restarted node cannot
    /// rewind past the restart point; this matches the `ShieldedStore`
    /// and `SparkStore` checkpoint discipline.
    checkpoints: RwLock<Vec<KernelCheckpoint>>,
    persistence: Option<KernelPersistence>,
}

impl KernelStore {
    /// Canonical kernel-set root over an ordered kernel slice. The
    /// single definition shared by `new`, `open_with_db`, `append`,
    /// and `rewind` so every path produces an identical root for an
    /// identical kernel set. (Previously `new` hard-coded `[0; 32]`
    /// while `open_with_db`/`append` computed a `blake3` digest, so an
    /// empty store's root depended on how it was constructed; `rewind`
    /// would have made that latent divergence reachable.)
    fn compute_root(kernels: &[MwKernel]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for k in kernels {
            h.update(&k.excess);
            h.update(&k.height.to_le_bytes());
        }
        *h.finalize().as_bytes()
    }

    /// Create a fresh in-memory store (tests, standalone chains).
    pub fn new() -> Self {
        Self {
            kernels: RwLock::new(Vec::new()),
            root: RwLock::new(Self::compute_root(&[])),
            checkpoints: RwLock::new(Vec::new()),
            persistence: None,
        }
    }

    /// Open a persistent kernel store. Replays stored kernels in key
    /// order (BE u64 index) and recomputes the root from the loaded
    /// vector.
    pub fn open_with_db(database: &Database) -> Result<Self> {
        let kernels_tree = database.open_tree("mw_kernels")?;

        let mut loaded: Vec<(u64, MwKernel)> = Vec::new();
        for item in kernels_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::DatabaseError(format!("mw_kernels iter: {}", e)))?;
            let key_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| Error::DatabaseError("mw_kernels key must be 8 bytes".into()))?;
            let idx = u64::from_be_bytes(key_bytes);
            let kernel: MwKernel = borsh::from_slice(value.as_ref())
                .map_err(|e| Error::SerializationError(format!("mw kernel: {}", e)))?;
            loaded.push((idx, kernel));
        }
        loaded.sort_by_key(|(i, _)| *i);
        let kernels: Vec<MwKernel> = loaded.into_iter().map(|(_, k)| k).collect();

        let root = Self::compute_root(&kernels);

        Ok(Self {
            kernels: RwLock::new(kernels),
            root: RwLock::new(root),
            // In-memory checkpoint stack, rebuilt as blocks are applied
            // — see the field doc and `rewind`.
            checkpoints: RwLock::new(Vec::new()),
            persistence: Some(KernelPersistence {
                kernels: kernels_tree,
            }),
        })
    }

    /// Append a kernel that has survived cut-through pruning.
    ///
    /// AUDIT (R-61 CLASS site, 2026-07-03): the previous `.expect()`
    /// calls panicked the whole node with a bare message. Panicking
    /// IS the semantically-correct response — a consensus-storage
    /// write failure means the node can't produce a valid state
    /// snapshot and continuing would silently corrupt the chain.
    /// But the bare-panic path lost the structured context that ops
    /// needed to triage (disk full? WAL corruption? RocksDB open
    /// state?). Emit a tracing::error with structured fields
    /// BEFORE the panic so the crash log carries real signal, and
    /// give the panic message an operator-actionable summary.
    ///
    /// Follow-up (deferred): return `Result<(), Error>` and let
    /// the caller decide (chain.rs::apply_block currently would
    /// convert the error to a block-rejection outcome). Deferred
    /// because the calling site is inside a `write()` guard that
    /// makes rollback nontrivial without a per-store transaction
    /// primitive.
    pub fn append(&self, kernel: MwKernel) {
        let mut kernels = self.kernels.write();
        let idx = kernels.len() as u64;
        if let Some(p) = &self.persistence {
            let key = idx.to_be_bytes();
            let value = match borsh::to_vec(&kernel) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        target: "storage::kernels::R61",
                        error = %e,
                        kernel_idx = idx,
                        "R-61: MwKernel borsh serialize failed at idx {}. \
                         Borsh serialization is infallible for well-formed \
                         MwKernel; this indicates upstream memory corruption \
                         or a bug in MwKernel construction. Halting.",
                        idx
                    );
                    panic!(
                        "R-61: MwKernel borsh serialize failed at idx {}: {}",
                        idx, e
                    );
                }
            };
            if let Err(e) = p.kernels.insert(key, value) {
                tracing::error!(
                    target: "storage::kernels::R61",
                    error = %e,
                    kernel_idx = idx,
                    "R-61: mw_kernels write failed at idx {}. Consensus \
                     storage is unavailable — likely disk full, WAL \
                     corruption, or RocksDB open state issue. Halting to \
                     preserve on-disk state; SIGTERM handler will flush \
                     cleanly. Investigate disk + RocksDB state before restart.",
                    idx
                );
                panic!(
                    "R-61: mw_kernels write failed at idx {}: {}",
                    idx, e
                );
            }
        }
        kernels.push(kernel);
        *self.root.write() = Self::compute_root(&kernels);
    }

    /// Mark a reorg checkpoint for the block at `height`, taken
    /// **before** that block's surviving kernels are appended. Call it
    /// at the point in `chain::Blockchain` where the block is about to
    /// mutate chain state, alongside the equivalent `ShieldedStore` /
    /// `SparkStore` checkpoints, so a later reorg rewinds all three
    /// stores in lock-step with the chain. See `SparkStore::
    /// checkpoint_at_height` for why "before the block" is the
    /// uniform contract.
    pub fn checkpoint_at_height(&self, height: u64) {
        let kernels_len = self.kernels.read().len();
        let mut cps = self.checkpoints.write();
        cps.push(KernelCheckpoint { height, kernels_len });
        // Bound the stack — checkpoints deeper than the chain's reorg
        // cap can never be a rewind target.
        if cps.len() > MAX_REORG_CHECKPOINTS {
            cps.remove(0);
        }
    }

    /// Number of checkpoints currently in the rollback stack. Used by
    /// the chain's cross-store invariant check — the three Phase-2
    /// stores (shielded / spark / kernel) must agree on stack length
    /// at all times, or a reorg would unwind them unevenly and leave
    /// the chain with stores at different effective heights.
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.read().len()
    }

    /// Rewind one checkpoint — disconnect the most recently applied
    /// block during a reorg. Pops the most recent checkpoint and
    /// truncates `kernels` back to the pre-block boundary that
    /// checkpoint captured, recomputes the root, and (when persistent)
    /// deletes the dropped kernels' column-family entries so a future
    /// `open_with_db` replay reconstructs the rewound state.
    ///
    /// Returns `true` if a checkpoint was popped and the rewind ran,
    /// `false` if the stack was already empty (nothing to rewind —
    /// e.g. after a restart, since the stack is not persisted). The
    /// chain reorg path treats `false` as a signal that the store
    /// could not be rolled back and the operator must be warned,
    /// matching the `ShieldedStore` / `SparkStore` contract.
    /// Rewind the kernel store to the last checkpoint.
    ///
    /// AUDIT (R-62 fix, 2026-07-03): the pre-fix code
    ///   (a) popped a checkpoint,
    ///   (b) truncated the in-memory `kernels` vec,
    ///   (c) recomputed the root,
    ///   (d) iterated the on-disk kernels and issued individual
    ///       `remove` calls, silently discarding each error via
    ///       `let _ = ...` (see R-63 class).
    /// A crash between any of these steps left the in-memory state
    /// and the on-disk state inconsistent:
    ///   - Between (b) and (c): in-mem truncated, root not
    ///     recomputed → header commit uses the wrong root.
    ///   - Between (c) and (d): in-mem truncated + root correct,
    ///     but disk still has the extra kernels; on restart, load
    ///     replays them and diverges from the committed root.
    /// Fix: R-63 site is treated below (per-item remove errors are
    /// now surfaced via a warn AND collected — see the log at the
    /// end). The (b)→(c)→(d) atomicity gap is documented; a
    /// structural fix requires the persistence layer to expose a
    /// batch-delete-range primitive that runs atomically with a
    /// "set root" write. Deferred pending shim extension. The
    /// in-memory state IS correctly ordered (truncate BEFORE root
    /// recompute), so an in-flight rewind is safe; only a crash
    /// mid-rewind is problematic.
    pub fn rewind(&self) -> bool {
        let mut checkpoints = self.checkpoints.write();
        // Pop the checkpoint guarding the block being disconnected.
        // Its recorded `kernels_len` IS the restore target: the
        // checkpoint was taken *before* that block, so every kernel
        // past it is the disconnected block's contribution.
        let restore_len = match checkpoints.pop() {
            Some(cp) => cp.kernels_len,
            None => return false,
        };

        let mut kernels = self.kernels.write();
        // `min` guards the impossible case of a corrupt checkpoint
        // recording a length beyond the current vector.
        let split_at = restore_len.min(kernels.len());
        let old_len = kernels.len();
        kernels.truncate(split_at);

        // Recompute the root from the surviving kernels — same
        // `compute_root` construction as `append` / `open_with_db`,
        // so a rewound store is byte-identical to one that reached
        // this kernel set by forward appends.
        *self.root.write() = Self::compute_root(&kernels);

        // Clean the backing column family. Kernels are persisted under
        // their vector index as a BE u64 key (see `append`), so the
        // dropped kernels are exactly keys `split_at..old_len`.
        //
        // R-63 fix (2026-07-03): pre-fix code did `let _ = p.kernels.remove(...)`,
        // silently discarding every failure. A partial rewind that
        // left orphan kernels on disk would then get REPLAYED on
        // next open, corrupting the committed root. Now we track
        // failures and emit a loud tracing::error so ops see the
        // event. We don't return `false` because the in-memory
        // state IS correctly rewound and rejecting the caller
        // would produce a worse divergence (in-memory rolled back,
        // caller thinks it wasn't).
        if let Some(p) = &self.persistence {
            let mut remove_failures = 0usize;
            for idx in split_at..old_len {
                if let Err(e) = p.kernels.remove((idx as u64).to_be_bytes()) {
                    remove_failures += 1;
                    tracing::error!(
                        target: "storage::kernels",
                        idx = idx,
                        error = %e,
                        "R-63: rewind failed to remove on-disk kernel {} — \
                         disk may replay orphan kernel on next open, \
                         corrupting committed root. Reindex required.",
                        idx
                    );
                }
            }
            if remove_failures > 0 {
                tracing::error!(
                    target: "storage::kernels",
                    remove_failures = remove_failures,
                    kernels_range = format!("{}..{}", split_at, old_len),
                    "R-63: {} kernel removes failed during rewind",
                    remove_failures
                );
            }
        }

        true
    }

    pub fn len(&self) -> usize {
        self.kernels.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.kernels.read().is_empty()
    }

    /// Current kernel-set root, committed in `BlockHeader::mw_kernel_root`.
    pub fn current_root(&self) -> [u8; 32] {
        *self.root.read()
    }
}

impl Default for KernelStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(excess_byte: u8, height: u64) -> MwKernel {
        MwKernel {
            excess: [excess_byte; 32],
            signature: vec![0u8; 64],
            fee: 0,
            height,
        }
    }

    /// Apply one block the way `chain::Blockchain` will under the
    /// Interp-B contract: checkpoint *first* (capturing the pre-block
    /// boundary), then append the block's surviving kernels.
    fn apply_block(store: &KernelStore, height: u64, kernels: &[MwKernel]) {
        store.checkpoint_at_height(height);
        for k in kernels {
            store.append(k.clone());
        }
    }

    #[test]
    fn rewind_on_empty_stack_returns_false() {
        let store = KernelStore::new();
        assert!(!store.rewind(), "nothing checkpointed — rewind must no-op");
    }

    #[test]
    fn checkpoint_then_rewind_restores_len_and_root() {
        let store = KernelStore::new();
        apply_block(&store, 1, &[kernel(0xA1, 1)]);
        let len_after_1 = store.len();
        let root_after_1 = store.current_root();

        apply_block(&store, 2, &[kernel(0xB1, 2), kernel(0xB2, 2)]);
        assert_eq!(store.len(), len_after_1 + 2);
        assert_ne!(store.current_root(), root_after_1);

        // Disconnect block 2.
        assert!(store.rewind());
        assert_eq!(store.len(), len_after_1, "kernel count restored");
        assert_eq!(store.current_root(), root_after_1, "root restored");
    }

    #[test]
    fn multiple_rewinds_disconnect_multiple_blocks() {
        let store = KernelStore::new();
        let genesis_root = store.current_root();
        apply_block(&store, 1, &[kernel(0xA1, 1)]);
        let root_after_1 = store.current_root();
        apply_block(&store, 2, &[kernel(0xB1, 2)]);
        apply_block(&store, 3, &[kernel(0xC1, 3)]);

        assert!(store.rewind()); // disconnect 3
        assert!(store.rewind()); // disconnect 2
        assert_eq!(store.len(), 1);
        assert_eq!(store.current_root(), root_after_1);

        assert!(store.rewind()); // disconnect 1 — back to genesis
        assert_eq!(store.len(), 0);
        assert_eq!(store.current_root(), genesis_root);
        assert!(!store.rewind(), "stack exhausted");
    }

    #[test]
    fn rewind_handles_block_with_no_kernels() {
        let store = KernelStore::new();
        apply_block(&store, 1, &[kernel(0xA1, 1)]);
        let len_after_1 = store.len();
        let root_after_1 = store.current_root();

        // Block 2 surfaces no cut-through-surviving kernels.
        apply_block(&store, 2, &[]);
        assert_eq!(store.len(), len_after_1, "no kernels added");

        assert!(store.rewind());
        assert_eq!(store.len(), len_after_1);
        assert_eq!(store.current_root(), root_after_1);
    }

    #[test]
    fn re_applying_after_rewind_reaches_the_same_root() {
        // A reorg disconnects then reconnects. After rewinding block 2
        // and re-applying an identical block 2, the root must match
        // the original — proves rewind leaves no residue.
        let store = KernelStore::new();
        apply_block(&store, 1, &[kernel(0xA1, 1)]);
        apply_block(&store, 2, &[kernel(0xB1, 2)]);
        let root_with_2 = store.current_root();

        assert!(store.rewind());
        apply_block(&store, 2, &[kernel(0xB1, 2)]);
        assert_eq!(
            store.current_root(),
            root_with_2,
            "re-applied block 2 reproduces the original root"
        );
    }

    #[test]
    fn empty_store_root_is_consistent_across_constructors() {
        // Regression for the latent bug `compute_root` fixes: `new()`
        // previously hard-coded `[0; 32]` while the digest paths used
        // blake3. An empty store's root must be the same canonical
        // value regardless of construction path.
        let fresh = KernelStore::new();
        let store = KernelStore::new();
        apply_block(&store, 1, &[kernel(0xA1, 1)]);
        assert!(store.rewind()); // rewind all the way back to empty
        assert_eq!(
            store.current_root(),
            fresh.current_root(),
            "rewound-to-empty root must equal a fresh store's root"
        );
    }

    // ─── Aggressive tests ────────────────────────────────────────

    #[test]
    fn checkpoint_stack_cap_holds_and_rewind_works_past_it() {
        // Push far past MAX_REORG_CHECKPOINTS — the stack must stay
        // capped, every rewind within the cap must succeed, and a
        // rewind past the cap must return false without panic.
        let store = KernelStore::new();
        let total = MAX_REORG_CHECKPOINTS + 50; // 150
        for h in 1..=total as u64 {
            store.checkpoint_at_height(h);
            store.append(kernel((h & 0xFF) as u8, h));
        }
        assert_eq!(store.len(), total, "all kernels appended");
        assert_eq!(
            store.checkpoints.read().len(),
            MAX_REORG_CHECKPOINTS,
            "stack capped at MAX_REORG_CHECKPOINTS"
        );

        for i in 0..MAX_REORG_CHECKPOINTS {
            assert!(store.rewind(), "rewind {} within cap must succeed", i);
        }
        assert_eq!(
            store.len(),
            50,
            "after cap-many rewinds, back to the oldest retained checkpoint's boundary"
        );
        assert!(
            !store.rewind(),
            "rewinding past the cap (empty stack) returns false, no panic"
        );
        assert_eq!(store.len(), 50, "failed rewind left state untouched");
    }

    #[test]
    fn persistence_rewind_survives_reopen() {
        // The RocksDB-backed rewind path (p.kernels.remove) is only
        // reachable via open_with_db. Drive a reorg through a
        // persistent store, then reopen and confirm the replay
        // reconstructs the rewound state.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        let (root_after_1, len_after_1) = {
            let store = KernelStore::open_with_db(&db).unwrap();
            apply_block(&store, 1, &[kernel(0xA1, 1)]);
            let snap = (store.current_root(), store.len());
            apply_block(&store, 2, &[kernel(0xB1, 2), kernel(0xB2, 2)]);
            assert!(store.rewind());
            assert_eq!(store.current_root(), snap.0, "in-memory back to block 1");
            snap
        };

        let reopened = KernelStore::open_with_db(&db).unwrap();
        assert_eq!(
            reopened.len(),
            len_after_1,
            "replay must not resurrect rewound kernels"
        );
        assert_eq!(reopened.current_root(), root_after_1);
    }

    /// Hand-rolled aggressive op-sequence fuzzer — same approach and
    /// rationale as `SparkStore`'s (deterministic LCG, no `proptest`,
    /// shadow-model agreement after every op, several seeds + a few
    /// adversarial patterns).
    #[test]
    fn aggressive_random_op_sequences_stay_consistent() {
        fn run(seed: u64, op_count: usize) {
            let store = KernelStore::new();
            let mut model_count: u64 = 0;
            let mut model_stack: Vec<u64> = Vec::new();
            let mut height: u64 = 0;
            let mut s = seed;
            for _ in 0..op_count {
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
                        store.append(kernel((model_count & 0xFF) as u8, height.max(1)));
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
                    store.len() as u64,
                    model_count,
                    "store kernel count diverged from the model (seed {seed})"
                );
            }
        }

        for seed in [1u64, 0xDEAD_BEEF, 42, 7777, 0x5151_5151, u64::MAX / 3] {
            run(seed, 1200);
        }

        // Adversarial: checkpoint storm, rewind storm, empty-store
        // rewind storm — none may panic.
        let store = KernelStore::new();
        for h in 1..=10 {
            store.checkpoint_at_height(h);
        }
        for _ in 0..10 {
            assert!(store.rewind());
        }
        assert!(!store.rewind(), "exhausted");
        assert_eq!(store.len(), 0);
        for _ in 0..50 {
            assert!(!store.rewind());
        }
    }

    #[test]
    fn stress_high_volume_checkpoint_append_rewind() {
        // Under-pressure test: 4800 kernels across 1200 checkpointed
        // blocks — past the 1000-deep cap — then a full-cap-depth
        // deep rewind. Verifies the cap bounds memory the whole time,
        // count correctness holds at every block, a maximum-depth
        // reorg stays exact, and the rewound store is byte-identical
        // to a directly-built one. Same O(n^2)-`append` caveat as
        // `SparkStore` — see that store's equivalent test.
        let store = KernelStore::new();
        let kernels_per_block: u64 = 4;
        let blocks: u64 = 1200; // past the 1000 cap
        for h in 1..=blocks {
            store.checkpoint_at_height(h);
            for _ in 0..kernels_per_block {
                store.append(kernel((h & 0xFF) as u8, h));
            }
            assert!(
                store.checkpoints.read().len() <= MAX_REORG_CHECKPOINTS,
                "checkpoint stack exceeded the cap at block {h}"
            );
            assert_eq!(store.len() as u64, h * kernels_per_block);
        }
        assert_eq!(store.checkpoints.read().len(), MAX_REORG_CHECKPOINTS);

        let len_before = store.len() as u64;
        let mut rewinds: u64 = 0;
        while store.rewind() {
            rewinds += 1;
            assert_eq!(
                store.len() as u64,
                len_before - rewinds * kernels_per_block,
                "kernel count wrong mid deep-rewind at step {rewinds}"
            );
        }
        assert_eq!(rewinds, MAX_REORG_CHECKPOINTS as u64);
        // Rebuild a reference of the surviving kernels. The stress
        // loop appended kernel((h & 0xFF), h) for h = 1..=survivors,
        // 4 per height.
        let survivors_blocks = (len_before / kernels_per_block) - MAX_REORG_CHECKPOINTS as u64;
        let reference = KernelStore::new();
        for h in 1..=survivors_blocks {
            for _ in 0..kernels_per_block {
                reference.append(kernel((h & 0xFF) as u8, h));
            }
        }
        assert_eq!(
            store.current_root(),
            reference.current_root(),
            "post-deep-reorg root drifted from a directly-built store"
        );
    }

    #[test]
    fn persistence_survives_repeated_reorg_reopen_cycles() {
        // Per-session reorg across multiple open/close cycles against
        // one backing DB — same realistic pattern and rationale as
        // `SparkStore`'s equivalent (the checkpoint stack is
        // in-memory only, so each session reorgs only the block it
        // applied). Confirms the persistence cleanup on `rewind`
        // removed the disconnected kernels from the column family
        // every cycle — no cruft.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        {
            let store = KernelStore::open_with_db(&db).unwrap();
            apply_block(&store, 1, &[kernel(0xA1, 1)]);
        }

        for c in 0u8..5 {
            let height = c as u64 + 2;
            let store = KernelStore::open_with_db(&db).unwrap();
            let len_before = store.len();
            apply_block(&store, height, &[kernel(0xB0 + c, height)]);
            assert_eq!(store.len(), len_before + 1, "cycle {c}: original applied");
            assert!(store.rewind(), "cycle {c}: rewind the just-applied block");
            assert_eq!(store.len(), len_before, "cycle {c}: back to pre-block");
            apply_block(&store, height, &[kernel(0xF0 + c, height)]);
            assert_eq!(store.len(), len_before + 1, "cycle {c}: fork applied");
        }

        let reopened = KernelStore::open_with_db(&db).unwrap();
        let reference = KernelStore::new();
        apply_block(&reference, 1, &[kernel(0xA1, 1)]);
        for c in 0u8..5 {
            apply_block(&reference, c as u64 + 2, &[kernel(0xF0 + c, c as u64 + 2)]);
        }
        assert_eq!(reopened.len(), 6, "no cruft after 5 reorg cycles");
        assert_eq!(
            reopened.current_root(),
            reference.current_root(),
            "5 reorg+reopen cycles leave the store byte-identical to a clean chain"
        );
    }

    #[test]
    fn stress_concurrent_read_write_load() {
        // Concurrent readers + writer(s) hammering the store. Proves
        // the `RwLock`s compose without deadlock under contention and
        // nothing panics. KernelStore's lock graph is simpler than
        // SparkStore's (no serial set): `append` takes kernels→root,
        // `checkpoint_at_height` takes kernels(read,released)→
        // checkpoints, `rewind` takes checkpoints→kernels→root — a
        // strict order, no cycle. The proof is operational: every
        // thread is joined; a deadlock would hang the join forever.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        // Part A — realistic: one writer, many readers.
        {
            let store = Arc::new(KernelStore::new());
            let stop = Arc::new(AtomicBool::new(false));

            let writer = {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    let mut h = 0u64;
                    let mut s = 0x1234_5678u64;
                    while !stop.load(Ordering::Relaxed) {
                        s = s
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        match (s >> 33) % 3 {
                            0 => {
                                h += 1;
                                store.checkpoint_at_height(h);
                            }
                            1 => store.append(kernel((s & 0xFF) as u8, h.max(1))),
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
                            let _ = store.current_root();
                            let _ = store.len();
                            let _ = store.is_empty();
                            reads += 1;
                        }
                        reads
                    })
                })
                .collect();

            thread::sleep(Duration::from_millis(600));
            stop.store(true, Ordering::Relaxed);
            writer.join().expect("writer thread panicked");
            let total_reads: u64 =
                readers.into_iter().map(|r| r.join().expect("reader panicked")).sum();
            assert!(total_reads > 0, "readers made no progress — possible stall");
            let r1 = store.current_root();
            assert_eq!(r1, store.current_root(), "root not stable while quiescent");
        }

        // Part B — adversarial: many writers + many readers.
        {
            let store = Arc::new(KernelStore::new());
            let stop = Arc::new(AtomicBool::new(false));
            let mut threads = Vec::new();
            for w in 0..4u64 {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                threads.push(thread::spawn(move || {
                    let mut h = w;
                    let mut s = 0xABCD_0000u64 ^ (w << 40);
                    while !stop.load(Ordering::Relaxed) {
                        s = s
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        match (s >> 33) % 3 {
                            0 => {
                                h += 4;
                                store.checkpoint_at_height(h);
                            }
                            1 => store.append(kernel((s & 0xFF) as u8, h.max(1))),
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
                        let _ = store.len();
                    }
                }));
            }
            thread::sleep(Duration::from_millis(600));
            stop.store(true, Ordering::Relaxed);
            let join_start = Instant::now();
            for t in threads {
                t.join().expect("a stress thread panicked");
            }
            assert!(
                join_start.elapsed() < Duration::from_secs(10),
                "threads took >10s to join after stop — probable lock stall"
            );
        }
    }
}
