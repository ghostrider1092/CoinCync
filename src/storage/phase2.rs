//! `Phase2Store` — the unified reorg seam for the three Phase-2 accumulator
//! stores ([`SparkStore`], [`ShieldedStore`], [`KernelStore`]).
//!
//! All three carry the *same* reorg contract: a checkpoint is taken **before**
//! each block is applied, and one `rewind` disconnects one block. They must move
//! in lock-step — after every checkpoint their stack depths must agree, or a
//! reorg would unwind them to different heights and diverge chain state (see the
//! cross-store invariant in `chain::Blockchain`). Historically that contract was
//! enforced by three hand-copied arms in `chain.rs` plus a `debug_assert!`; this
//! trait turns it into one seam with one shared driver, so a fourth store (or a
//! changed contract) is a single edit and the lock-step check is unit-testable
//! against a mock rather than only reachable via a live reorg.
//!
//! Behaviour-preserving: each impl forwards to the store's existing inherent
//! methods (inherent methods win method resolution, so `self.rewind()` below
//! calls the store's own `rewind`, never this trait method — the
//! `mock_store_*`/`real_stores_*` tests would stack-overflow if that regressed).

use crate::storage::{KernelStore, ShieldedStore, SparkStore};

/// The common reorg + accumulator surface every Phase-2 store exposes.
pub trait Phase2Store: Send + Sync {
    /// Short name for diagnostics (`"shielded"`, `"spark"`, `"kernel"`).
    fn store_label(&self) -> &'static str;
    /// Take a reorg checkpoint for the block about to be applied at `height`.
    fn checkpoint_at_height(&self, height: u64);
    /// Depth of the reorg checkpoint stack (the lock-step quantity).
    fn checkpoint_count(&self) -> usize;
    /// Disconnect one block; `false` iff the checkpoint stack was empty.
    fn rewind(&self) -> bool;
    /// Number of live elements (leaves/coins/kernels) — used only to tell an
    /// empty store (benign `rewind`==false) from a non-empty one (a real
    /// inconsistency) in diagnostics.
    fn element_count(&self) -> usize;
    /// Current accumulator root.
    fn current_root(&self) -> [u8; 32];
}

impl Phase2Store for ShieldedStore {
    fn store_label(&self) -> &'static str {
        "shielded"
    }
    fn checkpoint_at_height(&self, height: u64) {
        self.checkpoint_at_height(height)
    }
    fn checkpoint_count(&self) -> usize {
        self.checkpoint_count()
    }
    fn rewind(&self) -> bool {
        self.rewind()
    }
    fn element_count(&self) -> usize {
        self.tree_size()
    }
    fn current_root(&self) -> [u8; 32] {
        self.current_root()
    }
}

impl Phase2Store for SparkStore {
    fn store_label(&self) -> &'static str {
        "spark"
    }
    fn checkpoint_at_height(&self, height: u64) {
        self.checkpoint_at_height(height)
    }
    fn checkpoint_count(&self) -> usize {
        self.checkpoint_count()
    }
    fn rewind(&self) -> bool {
        self.rewind()
    }
    fn element_count(&self) -> usize {
        self.size()
    }
    fn current_root(&self) -> [u8; 32] {
        self.current_root()
    }
}

impl Phase2Store for KernelStore {
    fn store_label(&self) -> &'static str {
        "kernel"
    }
    fn checkpoint_at_height(&self, height: u64) {
        self.checkpoint_at_height(height)
    }
    fn checkpoint_count(&self) -> usize {
        self.checkpoint_count()
    }
    fn rewind(&self) -> bool {
        self.rewind()
    }
    fn element_count(&self) -> usize {
        self.len()
    }
    fn current_root(&self) -> [u8; 32] {
        self.current_root()
    }
}

/// Checkpoint every store in `stores` for the block at `height`, in the given
/// order, then verify they stayed in lock-step.
///
/// Returns `Ok(depth)` (the common checkpoint depth) when all stores agree, or
/// `Err(diagnostic)` naming the divergence. The caller decides how loud to be
/// (chain.rs keeps the historical `debug_assert!` on this result). Passing fewer
/// than two stores trivially agrees — the lock-step property is vacuous.
pub fn checkpoint_all(stores: &[&dyn Phase2Store], height: u64) -> Result<usize, String> {
    for s in stores {
        s.checkpoint_at_height(height);
    }
    check_lockstep(stores, height)
}

/// Verify all `stores` report the same `checkpoint_count`. Pure (no mutation).
pub fn check_lockstep(stores: &[&dyn Phase2Store], height: u64) -> Result<usize, String> {
    let Some((first, rest)) = stores.split_first() else {
        return Ok(0);
    };
    let depth = first.checkpoint_count();
    for s in rest {
        let d = s.checkpoint_count();
        if d != depth {
            let detail: Vec<String> = stores
                .iter()
                .map(|s| format!("{}={}", s.store_label(), s.checkpoint_count()))
                .collect();
            return Err(format!(
                "Phase-2 stores diverged at height {height}: [{}] — the stores were \
                 checkpointed in lock-step but their stack depths disagree, meaning one \
                 silently skipped (e.g. a BridgeTree-declined checkpoint, or a code path \
                 that bypassed the shared checkpoint driver). A reorg from this state \
                 would unwind the stores unevenly.",
                detail.join(" ")
            ));
        }
    }
    Ok(depth)
}

/// The outcome of rewinding one store during a reorg — surfaced so the caller
/// can log at the right severity.
pub enum RewindOutcome {
    /// The store rolled back one checkpoint.
    RolledBack,
    /// `rewind` returned false and the store is empty — a benign no-op (the
    /// store holds no Phase-2 data yet).
    EmptyNoop,
    /// `rewind` returned false but the store still holds `remaining` elements —
    /// a disconnected block's state is stranded above the new tip. A genuine
    /// inconsistency (e.g. a reorg reaching past a restart, before rewind
    /// checkpoints are restart-durable).
    Stranded { remaining: usize },
}

/// Rewind every store by one checkpoint (disconnect one block), classifying each
/// result. Pure over the slice + the stores' own state; the caller does the
/// logging so this stays testable.
pub fn rewind_all(stores: &[&dyn Phase2Store]) -> Vec<(&'static str, RewindOutcome)> {
    stores
        .iter()
        .map(|s| {
            let outcome = if s.rewind() {
                RewindOutcome::RolledBack
            } else if s.element_count() == 0 {
                RewindOutcome::EmptyNoop
            } else {
                RewindOutcome::Stranded {
                    remaining: s.element_count(),
                }
            };
            (s.store_label(), outcome)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A minimal Phase2Store for exercising the lock-step driver in isolation —
    /// a checkpoint stack of one usize (the element count at checkpoint time),
    /// with an optional forced skip to simulate a store that silently declines a
    /// checkpoint (the exact divergence the invariant guards).
    struct MockStore {
        label: &'static str,
        elements: AtomicUsize,
        stack: parking_lot::Mutex<Vec<usize>>,
        skip_next_checkpoint: parking_lot::Mutex<bool>,
    }
    impl MockStore {
        fn new(label: &'static str) -> Self {
            Self {
                label,
                elements: AtomicUsize::new(0),
                stack: parking_lot::Mutex::new(Vec::new()),
                skip_next_checkpoint: parking_lot::Mutex::new(false),
            }
        }
        fn add_element(&self) {
            self.elements.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl Phase2Store for MockStore {
        fn store_label(&self) -> &'static str {
            self.label
        }
        fn checkpoint_at_height(&self, _height: u64) {
            let mut skip = self.skip_next_checkpoint.lock();
            if *skip {
                *skip = false;
                return; // simulate a declined checkpoint → desync
            }
            self.stack.lock().push(self.elements.load(Ordering::Relaxed));
        }
        fn checkpoint_count(&self) -> usize {
            self.stack.lock().len()
        }
        fn rewind(&self) -> bool {
            match self.stack.lock().pop() {
                Some(n) => {
                    self.elements.store(n, Ordering::Relaxed);
                    true
                }
                None => false,
            }
        }
        fn element_count(&self) -> usize {
            self.elements.load(Ordering::Relaxed)
        }
        fn current_root(&self) -> [u8; 32] {
            (self.element_count() as u64).to_le_bytes().repeat(4)[..32]
                .try_into()
                .unwrap()
        }
    }

    #[test]
    fn checkpoint_all_keeps_stores_in_lockstep() {
        let a = MockStore::new("a");
        let b = MockStore::new("b");
        let c = MockStore::new("c");
        let stores: [&dyn Phase2Store; 3] = [&a, &b, &c];
        for h in 1..=10u64 {
            a.add_element();
            let depth = checkpoint_all(&stores, h).expect("stores agree");
            assert_eq!(depth, h as usize);
        }
        assert_eq!((a.checkpoint_count(), b.checkpoint_count(), c.checkpoint_count()), (10, 10, 10));
    }

    #[test]
    fn check_lockstep_detects_a_skipped_checkpoint() {
        let a = MockStore::new("a");
        let b = MockStore::new("b");
        *b.skip_next_checkpoint.lock() = true; // b will silently decline once
        let stores: [&dyn Phase2Store; 2] = [&a, &b];
        let err = checkpoint_all(&stores, 1).unwrap_err();
        assert!(err.contains("diverged"), "got: {err}");
        assert!(err.contains("a=1") && err.contains("b=0"), "names both depths: {err}");
    }

    #[test]
    fn zero_or_one_store_trivially_agrees() {
        assert_eq!(check_lockstep(&[], 1).unwrap(), 0);
        let a = MockStore::new("a");
        let one: [&dyn Phase2Store; 1] = [&a];
        assert_eq!(checkpoint_all(&one, 1).unwrap(), 1);
    }

    #[test]
    fn rewind_all_classifies_each_store() {
        let empty = MockStore::new("empty"); // never checkpointed, 0 elements
        let full = MockStore::new("full");
        full.add_element();
        full.checkpoint_at_height(1);
        full.add_element(); // 2 elements, 1 checkpoint guarding the boundary at 1

        let stores: [&dyn Phase2Store; 2] = [&empty, &full];
        let outcomes = rewind_all(&stores);
        assert!(matches!(outcomes[0], ("empty", RewindOutcome::EmptyNoop)));
        assert!(matches!(outcomes[1], ("full", RewindOutcome::RolledBack)));
        assert_eq!(full.element_count(), 1, "full rewound to the checkpoint boundary");
    }

    #[test]
    fn rewind_all_flags_a_stranded_store() {
        // A non-empty store whose checkpoint stack is gone (simulating a rewind
        // past a restart) reports Stranded, not a benign no-op.
        let s = MockStore::new("s");
        s.add_element();
        s.add_element(); // 2 elements, but no checkpoint taken
        let stores: [&dyn Phase2Store; 1] = [&s];
        let outcomes = rewind_all(&stores);
        assert!(matches!(outcomes[0].1, RewindOutcome::Stranded { remaining: 2 }));
    }

    #[test]
    fn real_stores_satisfy_the_trait_and_rewind_in_lockstep() {
        // The three real stores, driven ONLY through the Phase2Store seam +
        // shared drivers, must checkpoint/rewind together exactly like the mock.
        // (A recursion regression in any impl would stack-overflow here.)
        let shielded = ShieldedStore::new();
        let spark = SparkStore::new();
        let kernel = KernelStore::new();
        let stores: [&dyn Phase2Store; 3] = [&shielded, &spark, &kernel];

        for h in 1..=5u64 {
            assert_eq!(checkpoint_all(&stores, h).unwrap(), h as usize);
        }
        for _ in 0..5 {
            for (label, outcome) in rewind_all(&stores) {
                assert!(
                    matches!(outcome, RewindOutcome::RolledBack | RewindOutcome::EmptyNoop),
                    "{label} failed to roll back cleanly"
                );
            }
        }
        assert_eq!(
            (shielded.checkpoint_count(), spark.checkpoint_count(), kernel.checkpoint_count()),
            (0, 0, 0),
            "all three drained in lock-step"
        );
    }
}
