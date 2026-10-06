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
    /// Current accumulator root (the incrementally-maintained cached value).
    fn current_root(&self) -> [u8; 32];
    /// Independently recompute the accumulator root **from the store's retained
    /// contents**, bypassing the incrementally-maintained cached root. Returns
    /// `None` when the store cannot cheaply recompute — e.g. a `BridgeTree`
    /// whose live state IS the tree (an independent recompute would mean
    /// replaying every leaf into a fresh tree). Used by
    /// [`check_root_integrity`] to catch a cached root that drifted from the
    /// contents it is supposed to summarize (a maintenance bug, a partial
    /// rewind, or memory corruption) — the "wrong accumulator contents while
    /// stack depths stay aligned" gap that [`check_lockstep`] cannot see.
    ///
    /// O(n) in the retained contents, so callers run it OFF the block-apply hot
    /// path (operator/audit only), never as a per-block consensus guard.
    fn recompute_root(&self) -> Option<[u8; 32]> {
        None
    }
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
    fn recompute_root(&self) -> Option<[u8; 32]> {
        // SparkStore retains the full coin vector, so the root can be
        // recomputed from scratch and compared to the maintained one.
        Some(self.recomputed_root())
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
    fn recompute_root(&self) -> Option<[u8; 32]> {
        // KernelStore retains the full kernel vector, so the root can be
        // recomputed from scratch and compared to the maintained one.
        Some(self.recomputed_root())
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

/// Verify every store's incrementally-maintained root matches an independent
/// recompute from its retained contents. Pure (no mutation). Stores that cannot
/// cheaply recompute (`recompute_root() == None`, e.g. the `BridgeTree`-backed
/// `ShieldedStore`) are skipped — this checks only what it can independently
/// derive. Returns `Err(diagnostic)` naming each store whose cached root drifted
/// from its contents; `Ok(())` when every checkable store agrees.
///
/// This closes the `phase2-lockstep` "wrong accumulator *contents* while stack
/// depths stay aligned" gap: [`check_lockstep`] only compares checkpoint-stack
/// depths, so a store whose root drifted from its own contents (without a depth
/// change) is invisible to it. O(Σ contents) — run off the block-apply hot path.
pub fn check_root_integrity(stores: &[&dyn Phase2Store]) -> Result<(), String> {
    fn short(root: &[u8; 32]) -> String {
        // First 4 bytes are enough to disambiguate in an alert message.
        format!("{:02x}{:02x}{:02x}{:02x}", root[0], root[1], root[2], root[3])
    }
    let mut mismatches: Vec<String> = Vec::new();
    for s in stores {
        if let Some(recomputed) = s.recompute_root() {
            let maintained = s.current_root();
            if recomputed != maintained {
                mismatches.push(format!(
                    "{}: maintained={} recomputed={}",
                    s.store_label(),
                    short(&maintained),
                    short(&recomputed),
                ));
            }
        }
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Phase-2 accumulator root drift: [{}] — a store's maintained root \
             disagrees with a fresh recompute from its retained contents, meaning \
             the cached root and the contents it summarizes have diverged \
             (maintenance bug, partial rewind, or corruption). The committed \
             header root would then not match the store's true contents.",
            mismatches.join("; ")
        ))
    }
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

/// A [`SecurityDetail`](crate::security::SecurityDetail) over the Phase-2
/// accumulator stores: it flags them drifting out of checkpoint lock-step. If
/// the three stores' checkpoint stacks disagree, a reorg unwinds them to
/// different heights and diverges chain state — a consensus-critical corruption
/// surface. The check is `check_lockstep` (O(number of stores), so O(1)),
/// deterministic, and read-only, so it is safe as a consensus guard.
pub struct Phase2LockstepDetail<'a> {
    stores: &'a [&'a dyn Phase2Store],
    height: u64,
}

impl<'a> Phase2LockstepDetail<'a> {
    /// `height` is the current chain height (context for the alert message).
    pub fn new(stores: &'a [&'a dyn Phase2Store], height: u64) -> Self {
        Self { stores, height }
    }
}

impl crate::security::SecurityDetail for Phase2LockstepDetail<'_> {
    fn label(&self) -> &'static str {
        "phase2-lockstep"
    }

    fn sweep(&self) -> crate::security::SecurityReport {
        use crate::security::{SecurityReport, Severity};
        let mut r = SecurityReport::clean();
        if let Err(msg) = check_lockstep(self.stores, self.height) {
            // Deterministic + O(1) → consensus-critical (safe to halt on).
            r.raise_consensus("phase2-lockstep", Severity::Critical, "store-desync", msg);
        }
        r
    }
}

/// A [`SecurityDetail`](crate::security::SecurityDetail) over the Phase-2
/// accumulator stores' **root integrity**: it flags a store whose maintained
/// root drifted from an independent recompute of its retained contents (see
/// [`check_root_integrity`]). This is the content-corruption counterpart to
/// [`Phase2LockstepDetail`] (which only checks checkpoint-stack depth).
///
/// Classified **operational** (Critical severity — pages, never halts): the
/// recompute is O(Σ contents), so it runs off the block-apply hot path
/// (operator/audit RPC), and — like the supply-schedule reconciliation — it is
/// defense-in-depth over per-block validation, surfaced loudly rather than
/// wedging the chain. Promoting it to a consensus halt would require an O(1)
/// check (e.g. reconciling against the committed header root each block).
pub struct Phase2RootIntegrityDetail<'a> {
    stores: &'a [&'a dyn Phase2Store],
}

impl<'a> Phase2RootIntegrityDetail<'a> {
    pub fn new(stores: &'a [&'a dyn Phase2Store]) -> Self {
        Self { stores }
    }
}

impl crate::security::SecurityDetail for Phase2RootIntegrityDetail<'_> {
    fn label(&self) -> &'static str {
        "phase2-root-integrity"
    }

    fn sweep(&self) -> crate::security::SecurityReport {
        use crate::security::{SecurityReport, Severity};
        let mut r = SecurityReport::clean();
        if let Err(msg) = check_root_integrity(self.stores) {
            // Operational (Critical): loud page, never a halt — the recompute is
            // O(n) and off the consensus path.
            r.raise_operational(
                "phase2-root-integrity",
                Severity::Critical,
                "root-drift",
                msg,
            );
        }
        r
    }
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
        /// When `Some`, `current_root` returns this instead of the
        /// contents-derived root — simulates a cached root that drifted from
        /// the store's contents (the exact corruption the root-integrity guard
        /// catches). `recompute_root` always returns the contents-derived root.
        maintained_override: parking_lot::Mutex<Option<[u8; 32]>>,
    }
    impl MockStore {
        fn new(label: &'static str) -> Self {
            Self {
                label,
                elements: AtomicUsize::new(0),
                stack: parking_lot::Mutex::new(Vec::new()),
                skip_next_checkpoint: parking_lot::Mutex::new(false),
                maintained_override: parking_lot::Mutex::new(None),
            }
        }
        fn add_element(&self) {
            self.elements.fetch_add(1, Ordering::Relaxed);
        }
        /// The honest root derived from the store's live contents.
        fn contents_root(&self) -> [u8; 32] {
            (self.element_count() as u64).to_le_bytes().repeat(4)[..32]
                .try_into()
                .unwrap()
        }
        /// Corrupt the maintained (cached) root so it drifts from the contents.
        fn corrupt_maintained_root(&self, root: [u8; 32]) {
            *self.maintained_override.lock() = Some(root);
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
            let override_root = *self.maintained_override.lock();
            match override_root {
                Some(r) => r,
                None => self.contents_root(),
            }
        }
        fn recompute_root(&self) -> Option<[u8; 32]> {
            Some(self.contents_root())
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
    fn redteam_lockstep_detail_on_empty_and_single_store() {
        use crate::security::SecurityDetail;
        // No stores: lock-step is vacuously true → clean, no panic.
        let none: [&dyn Phase2Store; 0] = [];
        let d0 = Phase2LockstepDetail::new(&none, 0);
        assert!(d0.sweep().is_clean());
        // One store: trivially in lock-step with itself.
        let a = MockStore::new("a");
        let one: [&dyn Phase2Store; 1] = [&a];
        let d1 = Phase2LockstepDetail::new(&one, 5);
        assert!(d1.sweep().is_clean());
    }

    #[test]
    fn lockstep_detail_flags_desync_as_consensus_critical() {
        use crate::security::{SecurityCommand, SecurityDetail};

        let a = MockStore::new("a");
        let b = MockStore::new("b");
        let c = MockStore::new("c");
        let stores: [&dyn Phase2Store; 3] = [&a, &b, &c];

        // In lock-step → the detail is clean, no consensus halt.
        for h in 1..=3u64 {
            checkpoint_all(&stores, h).unwrap();
        }
        let detail = Phase2LockstepDetail::new(&stores, 3);
        let details: [&dyn SecurityDetail; 1] = [&detail];
        assert!(SecurityCommand::assert_consensus_safe(&details).is_ok());

        // Force a desync: `b` silently declines its next checkpoint.
        *b.skip_next_checkpoint.lock() = true;
        // Drive one more checkpoint directly (bypass the lock-step driver, as a
        // silent-skip bug would), so the stacks diverge.
        for s in stores.iter() {
            s.checkpoint_at_height(4);
        }
        let detail2 = Phase2LockstepDetail::new(&stores, 4);
        let details2: [&dyn SecurityDetail; 1] = [&detail2];
        let report = SecurityCommand::assert_consensus_safe(&details2).unwrap_err();
        assert!(report.has_consensus_halt());
        assert!(report.criticals().any(|al| al.code == "store-desync"));
    }

    #[test]
    fn root_integrity_clean_when_maintained_matches_contents() {
        let a = MockStore::new("a");
        let b = MockStore::new("b");
        a.add_element();
        b.add_element();
        b.add_element();
        let stores: [&dyn Phase2Store; 2] = [&a, &b];
        // No override → maintained root == contents root for both.
        assert!(check_root_integrity(&stores).is_ok(), "honest stores must agree");
    }

    #[test]
    fn root_integrity_flags_a_drifted_cached_root() {
        let a = MockStore::new("a");
        let b = MockStore::new("b");
        a.add_element();
        b.add_element();
        // Corrupt b's maintained root so it drifts from its contents.
        b.corrupt_maintained_root([0xAB; 32]);
        let stores: [&dyn Phase2Store; 2] = [&a, &b];
        let err = check_root_integrity(&stores).unwrap_err();
        assert!(err.contains("root drift"), "got: {err}");
        assert!(err.contains("b:"), "must name the drifted store: {err}");
        assert!(!err.contains("a:"), "must not implicate the honest store: {err}");
    }

    #[test]
    fn root_integrity_skips_stores_that_cannot_recompute() {
        // A store whose recompute_root() is None (the trait default, e.g. the
        // BridgeTree-backed ShieldedStore) is skipped, not falsely flagged.
        struct NoRecompute;
        impl Phase2Store for NoRecompute {
            fn store_label(&self) -> &'static str { "no-recompute" }
            fn checkpoint_at_height(&self, _h: u64) {}
            fn checkpoint_count(&self) -> usize { 0 }
            fn rewind(&self) -> bool { false }
            fn element_count(&self) -> usize { 0 }
            fn current_root(&self) -> [u8; 32] { [0x11; 32] }
            // recompute_root() uses the trait default → None.
        }
        let n = NoRecompute;
        let stores: [&dyn Phase2Store; 1] = [&n];
        assert!(check_root_integrity(&stores).is_ok(), "None recompute must be skipped");
    }

    #[test]
    fn root_integrity_detail_is_operational_never_a_halt() {
        use crate::security::{Disposition, SecurityDetail};
        let a = MockStore::new("a");
        a.add_element();
        a.corrupt_maintained_root([0xEE; 32]);
        let stores: [&dyn Phase2Store; 1] = [&a];
        let detail = Phase2RootIntegrityDetail::new(&stores);
        let report = detail.sweep();
        assert!(
            report.alerts.iter().any(|al| al.code == "root-drift"),
            "must raise the root-drift alert"
        );
        assert!(!report.has_consensus_halt(), "root-integrity is operational, never a halt");
        assert_ne!(report.disposition(), Disposition::Halt);
    }

    #[test]
    fn real_kernel_and_spark_stores_recompute_their_own_root() {
        // The real KernelStore and SparkStore must expose a working
        // recompute_root() that agrees with current_root() on an honest store.
        let kernel = KernelStore::new();
        let spark = SparkStore::new();
        let stores: [&dyn Phase2Store; 2] = [&kernel, &spark];
        // Empty stores: recompute == current.
        assert!(check_root_integrity(&stores).is_ok(), "empty real stores agree");
        assert_eq!(kernel.recompute_root(), Some(kernel.current_root()));
        assert_eq!(spark.recompute_root(), Some(spark.current_root()));
        // ShieldedStore cannot recompute → None (skipped by the guard).
        let shielded = ShieldedStore::new();
        assert_eq!(
            Phase2Store::recompute_root(&shielded),
            None,
            "BridgeTree-backed ShieldedStore has no cheap independent recompute"
        );
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
