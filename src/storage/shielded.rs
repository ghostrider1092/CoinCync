//! # Shielded Note Store
//!
//! Persistent storage for the Halo2 shielded-pool note commitment tree
//! and the nullifier set. Uses a real `bridgetree::BridgeTree` under
//! the hood — no more in-memory stub.
//!
//! ## What this module owns
//!
//! 1. **Note commitment tree.** An append-only Merkle tree of 32-byte
//!    commitments. Notes are added in mint order, and every note's
//!    Merkle authentication path can be requested later for spend
//!    proofs. Uses depth-32 BridgeTree (same as Zcash Sapling /
//!    Orchard).
//!
//! 2. **Nullifier set.** A hash-set of spent nullifiers. Nullifiers
//!    are 32-byte values derived from a note's secret `nk` and its
//!    position. Inserting a nullifier that already exists is rejected
//!    as a double-spend.
//!
//! 3. **Current anchor.** The Merkle root of the commitment tree,
//!    which is what shielded spend proofs anchor against. The anchor
//!    gets committed into every block header's `supply_commitment`
//!    (or a future dedicated `shielded_anchor` field).
//!
//! ## What this module does NOT do
//!
//! - **Zero-knowledge spend proofs.** A Halo2 action circuit proving
//!   in ZK "I know a note in the tree whose nullifier is `nf`" is not
//!   implemented. The shielded pool can mint and track commitments,
//!   but private spends are out of scope for v1.0.x. When the circuit
//!   lands it will live in a dedicated crate; the previous structural
//!   stub was removed pre-launch to keep audit scope tight.
//!
//! ## Persistence
//!
//! When constructed via [`ShieldedStore::open_with_db`], the store
//! writes every appended commitment and every marked nullifier
//! through to two RocksDB column families (`shielded_entries`,
//! `shielded_nullifiers`). On startup the tree is rebuilt by replay:
//! iterate `shielded_entries` in position order and re-append each
//! leaf. BridgeTree 0.4 dropped serde support, so replay is the
//! cheapest route to durability without a custom tree encoding.
//!
//! Rewinds during reorgs are currently NOT mirrored to disk — matching
//! the pre-persistence behavior — because `rewind()` isn't yet called
//! from chain.rs. Wiring that up is a follow-up.
//!
//! ## Anchor stability
//!
//! The BridgeTree supports checkpoints. Every block accept creates a
//! new checkpoint keyed on the block height; block disconnects (reorgs)
//! rewind to the pre-block checkpoint.

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use bridgetree::BridgeTree;
use incrementalmerkletree::{Hashable, Level, Position};
use parking_lot::RwLock;

use crate::db::shim;
use crate::db::Database;
use crate::error::{Error, Result};

/// Tree depth matching Zcash Orchard / Sapling.
pub const SHIELDED_TREE_DEPTH: u8 = 32;

/// Maximum checkpoint history — one per recent block up to this many
/// blocks deep. Must be at least the chain's deepest permitted reorg
/// so a maximum-depth reorg can roll the store fully back; set to
/// 1000 to cover testnet's `max_reorg_depth` (mainnet's is 100, so
/// 1000 covers both networks). Previously 100, which silently only
/// covered mainnet — a legal 101–1000-block testnet reorg would have
/// left the store unable to rewind past block 100, diverging it from
/// the UTXO set. Bounds both the `BridgeTree`'s internal checkpoint
/// retention and the parallel side-table checkpoint stack.
const MAX_CHECKPOINTS: usize = 1000;

/// 32-byte hash wrapper used as both leaf and node in the shielded
/// commitment tree. `combine` uses BLAKE3 with a level domain tag so
/// that inner nodes at different tree levels hash into disjoint
/// spaces. `empty_leaf` is the all-zero hash.
///
/// `BridgeTree<H, C, _>` requires `H: Hashable + Ord + PartialOrd +
/// Clone + Hash` for its internal checkpoint / marked-index maps, so
/// we derive `Ord`/`PartialOrd` on the raw byte array.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShieldedHash(pub [u8; 32]);

impl ShieldedHash {
    pub const fn zero() -> Self { ShieldedHash([0u8; 32]) }

    pub fn from_bytes(b: [u8; 32]) -> Self { ShieldedHash(b) }

    pub fn to_bytes(&self) -> [u8; 32] { self.0 }
}

impl Hashable for ShieldedHash {
    fn empty_leaf() -> Self { Self::zero() }

    fn combine(level: Level, a: &Self, b: &Self) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"COINCYNC_SHIELDED_NODE_v1");
        hasher.update(&(u8::from(level) as u64).to_le_bytes());
        hasher.update(&a.0);
        hasher.update(&b.0);
        let digest = hasher.finalize();
        ShieldedHash(*digest.as_bytes())
    }
}

/// One entry in the Halo2 note commitment tree — the on-chain
/// metadata the store remembers for each minted commitment.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct NoteCommitmentEntry {
    pub commitment: [u8; 32],
    pub height: u64,
    pub tx_index: u32,
    pub position: u64,
}

/// Optional RocksDB-backed persistence for the shielded store.
struct ShieldedPersistence {
    entries: shim::Tree,
    nullifiers: shim::Tree,
}

/// One entry in the side-table reorg checkpoint stack. The
/// `BridgeTree` has its own internal checkpoint stack; this parallel
/// stack is what lets `rewind` roll back the `entries` map, the
/// `nullifiers` set, and the RocksDB column families *in lock-step*
/// with the tree. (Before this existed, `rewind` rewound only the
/// `BridgeTree`, leaving the side tables and persistence ahead of the
/// tree on every reorg — the bug this struct fixes.)
///
/// A checkpoint is taken *before* the block at `height` is applied,
/// so it records the boundary the store returns to if that block is
/// disconnected: `entries_len` is the leaf count at that boundary
/// (positions are assigned `0..entries_len`, so positions `>=
/// entries_len` belong to the disconnected block) and `height` is the
/// block being guarded (nullifiers spent at or above it are dropped).
#[derive(Clone, Copy, Debug)]
struct ShieldedCheckpoint {
    height: u64,
    entries_len: usize,
}

/// Persistent store for the shielded pool.
pub struct ShieldedStore {
    /// The real Merkle tree. Protected by RwLock because `append`
    /// mutates while concurrent readers can still query the current
    /// root.
    tree: RwLock<BridgeTree<ShieldedHash, u64, SHIELDED_TREE_DEPTH>>,
    /// Side-table of leaf metadata indexed by position.
    entries: RwLock<HashMap<u64, NoteCommitmentEntry>>,
    /// Spent nullifier set.
    nullifiers: RwLock<HashMap<[u8; 32], u64>>,
    /// Reorg checkpoint stack for the side tables, kept in lock-step
    /// with the `BridgeTree`'s internal checkpoint stack (one push per
    /// `checkpoint_at_height`, one pop per `rewind`, both capped at
    /// `MAX_CHECKPOINTS`). In-memory only — not persisted — so a
    /// restarted node cannot rewind past the restart point, matching
    /// the `BridgeTree` and the `SparkStore` / `KernelStore` stacks.
    checkpoints: RwLock<Vec<ShieldedCheckpoint>>,
    /// RocksDB-backed persistence. `None` for in-memory tests.
    persistence: Option<ShieldedPersistence>,
}

impl ShieldedStore {
    /// Create a fresh in-memory store. Used by tests and by chains
    /// constructed without a backing database.
    pub fn new() -> Self {
        Self {
            tree: RwLock::new(BridgeTree::new(MAX_CHECKPOINTS)),
            entries: RwLock::new(HashMap::new()),
            nullifiers: RwLock::new(HashMap::new()),
            checkpoints: RwLock::new(Vec::new()),
            persistence: None,
        }
    }

    /// Open a persistent store backed by the given database. Rebuilds
    /// the BridgeTree by replaying stored commitments in position order
    /// and populates the nullifier set from the `shielded_nullifiers`
    /// column family.
    pub fn open_with_db(database: &Database) -> Result<Self> {
        let entries_tree = database.open_tree("shielded_entries")?;
        let nullifiers_tree = database.open_tree("shielded_nullifiers")?;

        // Collect stored entries, sort by position, replay into a
        // fresh BridgeTree.
        let mut loaded: Vec<(u64, NoteCommitmentEntry)> = Vec::new();
        for item in entries_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::DatabaseError(format!("shielded entries iter: {}", e)))?;
            let key_bytes: [u8; 8] = key.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("shielded_entries key must be 8 bytes".into())
            })?;
            let position = u64::from_be_bytes(key_bytes);
            let entry: NoteCommitmentEntry = borsh::from_slice(value.as_ref())
                .map_err(|e| Error::SerializationError(format!("shielded entry: {}", e)))?;
            loaded.push((position, entry));
        }
        loaded.sort_by_key(|(p, _)| *p);

        let mut tree: BridgeTree<ShieldedHash, u64, SHIELDED_TREE_DEPTH> =
            BridgeTree::new(MAX_CHECKPOINTS);
        let mut entries_map = HashMap::with_capacity(loaded.len());
        for (position, entry) in loaded {
            tree.append(ShieldedHash::from_bytes(entry.commitment));
            entries_map.insert(position, entry);
        }

        let mut nullifiers_map = HashMap::new();
        for item in nullifiers_tree.iter() {
            let (key, value) = item.map_err(|e| {
                Error::DatabaseError(format!("shielded nullifiers iter: {}", e))
            })?;
            let nf: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("shielded_nullifiers key must be 32 bytes".into())
            })?;
            let height_bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("shielded_nullifiers value must be 8 bytes".into())
            })?;
            nullifiers_map.insert(nf, u64::from_le_bytes(height_bytes));
        }

        Ok(Self {
            tree: RwLock::new(tree),
            entries: RwLock::new(entries_map),
            nullifiers: RwLock::new(nullifiers_map),
            // The checkpoint stack is in-memory only and starts empty
            // on open: it is rebuilt as the node applies blocks. The
            // replayed `BridgeTree` likewise starts with no
            // checkpoints, so the two remain in lock-step.
            checkpoints: RwLock::new(Vec::new()),
            persistence: Some(ShieldedPersistence {
                entries: entries_tree,
                nullifiers: nullifiers_tree,
            }),
        })
    }

    /// Append a note commitment to the tree. Returns the leaf position
    /// it was assigned. Panics only if the tree is full (1 << 32 leaves),
    /// which we treat as a consensus-level abort.
    pub fn append_commitment(&self, mut entry: NoteCommitmentEntry) -> u64 {
        let leaf = ShieldedHash::from_bytes(entry.commitment);
        let position = {
            let mut tree = self.tree.write();
            tree.append(leaf);
            // The new leaf is at the current frontier position.
            let pos = tree
                .frontier()
                .map(|f| u64::from(f.position()))
                .unwrap_or(0);
            pos
        };
        entry.position = position;
        if let Some(p) = &self.persistence {
            let key = position.to_be_bytes();
            let value = borsh::to_vec(&entry)
                .expect("NoteCommitmentEntry borsh encoding is infallible");
            p.entries
                .insert(key, value)
                .expect("shielded_entries write failed — consensus storage is dead");
        }
        self.entries.write().insert(position, entry);
        position
    }

    /// Mark a reorg checkpoint for the block at `height`, taken
    /// **before** that block's note commitments and nullifiers are
    /// applied. Call it at the point in `chain::Blockchain` where the
    /// block is about to mutate chain state, alongside the equivalent
    /// `SparkStore` / `KernelStore` checkpoints.
    ///
    /// Checkpoints both the `BridgeTree` (its native checkpoint, which
    /// the tree's own `rewind` reverts to) and the side-table parallel
    /// stack, in that order, so the two stay in lock-step. Both are
    /// capped at `MAX_CHECKPOINTS`: the `BridgeTree` drops its oldest
    /// checkpoint past the cap, so the parallel stack drops its oldest
    /// too, keeping the depths aligned.
    pub fn checkpoint_at_height(&self, height: u64) {
        let entries_len = self.entries.read().len();

        // Checkpoint the BridgeTree FIRST and only push the parallel
        // side-table checkpoint if the tree actually created one.
        // `BridgeTree::checkpoint` returns `false` when it declines —
        // notably for a non-monotonic checkpoint id. Pushing the
        // parallel checkpoint unconditionally (the earlier behaviour)
        // would silently desync the two stacks the moment that
        // happened, and `rewind` would then roll the side tables to a
        // boundary the tree never reverts to. Gating the push on the
        // tree's own decision keeps the two stacks in lock-step by
        // construction.
        let tree_checkpointed = self.tree.write().checkpoint(height);
        if !tree_checkpointed {
            tracing::warn!(
                "ShieldedStore: BridgeTree declined checkpoint at height {} \
                 (non-monotonic id?) — side-table checkpoint skipped to keep \
                 the two checkpoint stacks in sync",
                height
            );
            return;
        }

        let mut cps = self.checkpoints.write();
        cps.push(ShieldedCheckpoint { height, entries_len });
        // Mirror the BridgeTree's bounded checkpoint retention so the
        // two stacks never desync at the old end either.
        if cps.len() > MAX_CHECKPOINTS {
            cps.remove(0);
        }
    }

    /// Rewind one checkpoint — disconnect the most recently applied
    /// block during a reorg. Rewinds the `BridgeTree` **and**, in
    /// lock-step, the `entries` side-table, the `nullifiers` set, and
    /// (when persistent) the backing column families, back to the
    /// pre-block boundary the popped checkpoint captured.
    ///
    /// Before this method tracked the side tables, it rewound only the
    /// `BridgeTree`: after a reorg, `tree_size` over-counted,
    /// `entry_at` returned disconnected entries, `is_nullifier_spent`
    /// reported disconnected nullifiers as spent, and a restart's
    /// `open_with_db` replay resurrected everything. That divergence
    /// is the bug this method now fixes.
    ///
    /// Returns `true` if a checkpoint was popped and the rewind ran,
    /// `false` if the checkpoint stack was already empty (nothing to
    /// rewind — e.g. after a restart, since the stack is not
    /// persisted). The chain reorg path treats `false` as a signal
    /// that the store could not be rolled back and the operator must
    /// be warned.
    pub fn rewind(&self) -> bool {
        // Pop the side-table checkpoint guarding the block being
        // disconnected. Empty stack → nothing to rewind.
        let restore = match self.checkpoints.write().pop() {
            Some(cp) => cp,
            None => return false,
        };

        // Rewind the BridgeTree to its matching checkpoint. The
        // parallel stack and the tree's internal checkpoint stack are
        // pushed and popped in lock-step (and capped identically), so
        // this should always succeed; a false here means they
        // desynced — log it, but still align the side tables to the
        // checkpoint boundary, since leaving them ahead of the tree is
        // strictly worse.
        let tree_rewound = self.tree.write().rewind();
        if !tree_rewound {
            tracing::warn!(
                "ShieldedStore: BridgeTree rewind failed while a side-table \
                 checkpoint existed — tree/side-table state desynced"
            );
        }

        // Drop entries whose leaf position is at or past the boundary:
        // those leaves belong to the disconnected block(s).
        let removed_positions: Vec<u64> = {
            let mut entries = self.entries.write();
            let removed: Vec<u64> = entries
                .keys()
                .copied()
                .filter(|&pos| pos >= restore.entries_len as u64)
                .collect();
            for pos in &removed {
                entries.remove(pos);
            }
            removed
        };

        // Drop nullifiers spent at or after the disconnected block's
        // height — the checkpoint was taken before that block, so any
        // nullifier marked at `restore.height` or later was spent by a
        // block being disconnected.
        let removed_nullifiers: Vec<[u8; 32]> = {
            let mut nullifiers = self.nullifiers.write();
            let removed: Vec<[u8; 32]> = nullifiers
                .iter()
                .filter(|(_, &h)| h >= restore.height)
                .map(|(nf, _)| *nf)
                .collect();
            for nf in &removed {
                nullifiers.remove(nf);
            }
            removed
        };

        // Clean persistence so a future `open_with_db` replay
        // reconstructs the rewound state instead of resurrecting the
        // disconnected block's commitments and nullifiers.
        if let Some(p) = &self.persistence {
            for pos in &removed_positions {
                let _ = p.entries.remove(pos.to_be_bytes());
            }
            for nf in &removed_nullifiers {
                let _ = p.nullifiers.remove(nf);
            }
        }

        tree_rewound
    }

    /// Mark a nullifier as spent. Returns `false` if the nullifier
    /// was already in the set (double-spend).
    pub fn mark_nullifier_spent(&self, nullifier: [u8; 32], height: u64) -> bool {
        let mut nfs = self.nullifiers.write();
        if nfs.contains_key(&nullifier) {
            return false;
        }
        nfs.insert(nullifier, height);
        if let Some(p) = &self.persistence {
            p.nullifiers
                .insert(nullifier, height.to_le_bytes())
                .expect("shielded_nullifiers write failed — consensus storage is dead");
        }
        true
    }

    /// True if this nullifier has been spent before.
    pub fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.read().contains_key(nullifier)
    }

    /// Number of notes in the tree.
    pub fn tree_size(&self) -> usize {
        self.entries.read().len()
    }

    /// Current Merkle root — what shielded spend proofs anchor against.
    /// Returns the empty-tree root (zero) if no notes have been minted.
    pub fn current_root(&self) -> [u8; 32] {
        let tree = self.tree.read();
        // BridgeTree::root(0) returns the current (latest) root.
        tree.root(0)
            .map(|h| h.0)
            .unwrap_or_else(|| {
                // Empty tree root at depth SHIELDED_TREE_DEPTH
                ShieldedHash::empty_root(Level::from(SHIELDED_TREE_DEPTH)).0
            })
    }

    /// Returns the commitment entry at a given leaf position, if known.
    pub fn entry_at(&self, position: u64) -> Option<NoteCommitmentEntry> {
        self.entries.read().get(&position).cloned()
    }

    /// Mark the current leaf for later witness generation. Wallets
    /// call this when they mint a note they want to spend later; the
    /// tree retains the information needed to produce a Merkle
    /// authentication path even after many more notes are appended.
    pub fn mark_current(&self) -> Option<u64> {
        let mut tree = self.tree.write();
        tree.mark().map(|p| u64::from(p))
    }

    /// Produce a Merkle authentication path for a previously-marked
    /// leaf. The path can be used by a spender (together with the
    /// zero-knowledge spend proof) to prove membership without
    /// revealing which leaf is being spent.
    pub fn witness_path(&self, position: u64, checkpoint_depth: usize) -> Option<Vec<[u8; 32]>> {
        let tree = self.tree.read();
        tree.witness(Position::from(position), checkpoint_depth)
            .ok()
            .map(|path: Vec<ShieldedHash>| path.into_iter().map(|h| h.0).collect())
    }
}

impl Default for ShieldedStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(commitment: [u8; 32], height: u64) -> NoteCommitmentEntry {
        NoteCommitmentEntry {
            commitment,
            height,
            tx_index: 0,
            position: 0,
        }
    }

    #[test]
    fn empty_tree_has_deterministic_root() {
        let s1 = ShieldedStore::new();
        let s2 = ShieldedStore::new();
        assert_eq!(s1.current_root(), s2.current_root());
    }

    #[test]
    fn appending_commitments_changes_root() {
        let store = ShieldedStore::new();
        let empty_root = store.current_root();

        let pos0 = store.append_commitment(entry([1u8; 32], 1));
        assert_eq!(pos0, 0);

        let pos1 = store.append_commitment(entry([2u8; 32], 1));
        assert_eq!(pos1, 1);

        let new_root = store.current_root();
        assert_ne!(empty_root, new_root, "root should change after appends");
        assert_eq!(store.tree_size(), 2);
    }

    #[test]
    fn nullifier_double_spend_rejected() {
        let store = ShieldedStore::new();
        let nf = [42u8; 32];
        assert!(store.mark_nullifier_spent(nf, 5));
        // Second attempt returns false
        assert!(!store.mark_nullifier_spent(nf, 6));
        assert!(store.is_nullifier_spent(&nf));
    }

    #[test]
    fn nullifier_isolation() {
        let store = ShieldedStore::new();
        store.mark_nullifier_spent([1u8; 32], 1);
        assert!(store.is_nullifier_spent(&[1u8; 32]));
        assert!(!store.is_nullifier_spent(&[2u8; 32]));
    }

    #[test]
    fn checkpoint_then_rewind_restores_root() {
        let store = ShieldedStore::new();
        store.append_commitment(entry([1u8; 32], 1));
        store.checkpoint_at_height(1);
        let root_after_block_1 = store.current_root();

        store.append_commitment(entry([2u8; 32], 2));
        store.append_commitment(entry([3u8; 32], 2));
        let root_after_block_2 = store.current_root();
        assert_ne!(root_after_block_1, root_after_block_2);

        // Rewind: the tree should return to the state at block 1's checkpoint.
        assert!(store.rewind());
        assert_eq!(store.current_root(), root_after_block_1);
    }

    /// Apply one block the way `chain::Blockchain` will under the
    /// Interp-B contract: checkpoint *first* (capturing the pre-block
    /// boundary), then append the block's note commitments and mark
    /// its nullifiers.
    fn apply_block(
        store: &ShieldedStore,
        height: u64,
        commitments: &[[u8; 32]],
        nullifiers: &[[u8; 32]],
    ) {
        store.checkpoint_at_height(height);
        for c in commitments {
            store.append_commitment(entry(*c, height));
        }
        for nf in nullifiers {
            store.mark_nullifier_spent(*nf, height);
        }
    }

    #[test]
    fn rewind_on_empty_stack_returns_false() {
        let store = ShieldedStore::new();
        assert!(!store.rewind(), "nothing checkpointed — rewind must no-op");
    }

    #[test]
    fn rewind_drops_entries_and_nullifiers_not_just_the_tree() {
        // This is the regression test for the core bug: `rewind`
        // previously rewound only the BridgeTree, leaving the
        // `entries` map and `nullifiers` set ahead of it. After a
        // rewind, `tree_size`, `entry_at`, and `is_nullifier_spent`
        // must all reflect the rolled-back state.
        let store = ShieldedStore::new();
        apply_block(&store, 1, &[[0xA1; 32]], &[[0x11; 32]]);
        let size_after_1 = store.tree_size();
        let root_after_1 = store.current_root();

        apply_block(&store, 2, &[[0xB1; 32], [0xB2; 32]], &[[0x22; 32]]);
        assert_eq!(store.tree_size(), size_after_1 + 2);
        assert!(store.is_nullifier_spent(&[0x22; 32]));
        assert!(store.entry_at(size_after_1 as u64).is_some());

        // Disconnect block 2.
        assert!(store.rewind());
        assert_eq!(
            store.tree_size(),
            size_after_1,
            "entries map rewound, not just the tree"
        );
        assert_eq!(store.current_root(), root_after_1, "tree root rewound");
        assert!(
            !store.is_nullifier_spent(&[0x22; 32]),
            "block-2 nullifier dropped"
        );
        assert!(
            store.is_nullifier_spent(&[0x11; 32]),
            "block-1 nullifier kept"
        );
        assert!(
            store.entry_at(size_after_1 as u64).is_none(),
            "block-2 leaf entry dropped"
        );
    }

    #[test]
    fn multiple_rewinds_disconnect_multiple_blocks() {
        let store = ShieldedStore::new();
        let genesis_root = store.current_root();
        apply_block(&store, 1, &[[0xA1; 32]], &[[0x11; 32]]);
        let root_after_1 = store.current_root();
        apply_block(&store, 2, &[[0xB1; 32]], &[[0x22; 32]]);
        apply_block(&store, 3, &[[0xC1; 32]], &[[0x33; 32]]);
        assert_eq!(store.tree_size(), 3);

        // Disconnect 3, then 2.
        assert!(store.rewind());
        assert!(store.rewind());
        assert_eq!(store.tree_size(), 1);
        assert_eq!(store.current_root(), root_after_1);
        assert!(store.is_nullifier_spent(&[0x11; 32]));
        assert!(!store.is_nullifier_spent(&[0x22; 32]));
        assert!(!store.is_nullifier_spent(&[0x33; 32]));

        // Disconnect 1 — back to genesis, stack now empty.
        assert!(store.rewind());
        assert_eq!(store.tree_size(), 0);
        assert_eq!(store.current_root(), genesis_root);
        assert!(!store.is_nullifier_spent(&[0x11; 32]));
        assert!(!store.rewind(), "stack exhausted");
    }

    #[test]
    fn rewind_cleans_persistence_so_replay_matches() {
        // The persistence half of the bug: a rewound store must, after
        // a restart, replay to the rewound state — not resurrect the
        // disconnected block's commitments and nullifiers.
        use crate::db::Database;

        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        let (root_after_1, size_after_1) = {
            let store = ShieldedStore::open_with_db(&db).unwrap();
            apply_block(&store, 1, &[[0xA1; 32]], &[[0x11; 32]]);
            let snapshot = (store.current_root(), store.tree_size());

            // Block 2 then immediately reorged out.
            apply_block(&store, 2, &[[0xB1; 32], [0xB2; 32]], &[[0x22; 32]]);
            assert!(store.rewind());
            // In-memory state is back to block 1.
            assert_eq!(store.current_root(), snapshot.0);
            assert_eq!(store.tree_size(), snapshot.1);
            assert!(!store.is_nullifier_spent(&[0x22; 32]));
            snapshot
        };

        // Reopen against the same DB. If `rewind` had not cleaned the
        // column families, the replay would resurrect block 2's three
        // commitments and the [0x22] nullifier.
        let reopened = ShieldedStore::open_with_db(&db).unwrap();
        assert_eq!(
            reopened.tree_size(),
            size_after_1,
            "replay must not resurrect rewound commitments"
        );
        assert_eq!(reopened.current_root(), root_after_1);
        assert!(
            !reopened.is_nullifier_spent(&[0x22; 32]),
            "replay must not resurrect the rewound nullifier"
        );
        assert!(
            reopened.is_nullifier_spent(&[0x11; 32]),
            "block-1 nullifier survives the reorg + restart"
        );
    }

    // ─── Aggressive tests ────────────────────────────────────────

    #[test]
    fn checkpoint_stack_cap_keeps_tree_and_side_tables_synced() {
        // The single highest-risk property: the parallel side-table
        // checkpoint stack and the BridgeTree's *internal* checkpoint
        // stack are both capped at MAX_CHECKPOINTS. If they cap out
        // of sync, `rewind` rolls the tree and the side tables to
        // different boundaries and the store silently corrupts.
        //
        // Drive the store far past the cap, rewind back to the
        // oldest retained checkpoint, and prove the result is
        // byte-identical to a store built directly to that size —
        // root (tree) AND tree_size (entries map) both.
        let driven = ShieldedStore::new();
        let total = MAX_CHECKPOINTS + 50; // 150 blocks
        for h in 1..=total as u64 {
            apply_block(&driven, h, &[[(h & 0xFF) as u8; 32]], &[]);
        }
        assert_eq!(driven.tree_size(), total);
        assert_eq!(
            driven.checkpoints.read().len(),
            MAX_CHECKPOINTS,
            "parallel stack capped"
        );

        // Rewind the full cap depth. Every rewind must succeed and
        // never desync — assert tree/side-table agreement each step.
        for i in 0..MAX_CHECKPOINTS {
            assert!(driven.rewind(), "rewind {i} within cap must succeed");
            // entry positions are dense 0..tree_size; if the tree and
            // the entries map ever disagreed, an entry would be
            // missing or orphaned at the frontier.
            let sz = driven.tree_size();
            assert!(
                driven.entry_at(sz.saturating_sub(1) as u64).is_some() || sz == 0,
                "entries map dense up to tree_size at rewind step {i}"
            );
            assert!(
                driven.entry_at(sz as u64).is_none(),
                "no orphaned entry past tree_size at rewind step {i}"
            );
        }
        assert!(!driven.rewind(), "rewinding past the cap returns false");

        // The cap dropped the oldest 50 checkpoints, so the store is
        // now at the 50-block boundary. It must be byte-identical to
        // a store built directly to 50 blocks.
        let reference = ShieldedStore::new();
        for h in 1..=50u64 {
            apply_block(&reference, h, &[[(h & 0xFF) as u8; 32]], &[]);
        }
        assert_eq!(driven.tree_size(), reference.tree_size(), "size matches");
        assert_eq!(
            driven.current_root(),
            reference.current_root(),
            "rewound-past-cap store is byte-identical to a directly-built one"
        );
    }

    #[test]
    fn non_monotonic_checkpoint_id_does_not_desync() {
        // `BridgeTree::checkpoint` declines a non-monotonic id. The
        // parallel stack push is gated on the tree accepting the
        // checkpoint, so a declined checkpoint must leave the two
        // stacks in sync — and a subsequent rewind must still land
        // tree and side tables on the same boundary.
        let store = ShieldedStore::new();
        apply_block(&store, 5, &[[0xA1; 32]], &[]); // tree id now 5
        let root_after_5 = store.current_root();
        let size_after_5 = store.tree_size();

        // A non-monotonic checkpoint (id 3 <= 5) — the tree declines
        // it; the parallel push must be skipped, not desynced.
        let cps_before = store.checkpoints.read().len();
        store.checkpoint_at_height(3);
        assert_eq!(
            store.checkpoints.read().len(),
            cps_before,
            "declined tree checkpoint must not push to the parallel stack"
        );

        // Apply a real next block, then rewind it: tree and side
        // tables must land together on the post-block-5 boundary.
        apply_block(&store, 6, &[[0xB1; 32]], &[[0x66; 32]]);
        assert!(store.rewind());
        assert_eq!(store.current_root(), root_after_5, "tree rewound to block 5");
        assert_eq!(store.tree_size(), size_after_5, "entries rewound to block 5");
        assert!(
            !store.is_nullifier_spent(&[0x66; 32]),
            "block-6 nullifier dropped — side tables tracked the tree"
        );
    }

    /// Hand-rolled aggressive op-sequence fuzzer for the
    /// tree/side-table sync invariant. Drives long deterministic
    /// checkpoint / append / rewind sequences (several seeds) and
    /// asserts after every op that the entries map is exactly dense
    /// over `0..tree_size` — no gap, no orphan past the frontier. A
    /// BridgeTree / parallel-stack desync is precisely what breaks
    /// this invariant.
    ///
    /// Deterministic (no `proptest`) — see `SparkStore`'s equivalent
    /// for why.
    #[test]
    fn aggressive_random_op_sequences_keep_tree_and_entries_consistent() {
        fn run(seed: u64, op_count: usize) {
            let store = ShieldedStore::new();
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
                    }
                    1 => {
                        store.append_commitment(entry(
                            [(height & 0xFF) as u8; 32],
                            height.max(1),
                        ));
                    }
                    _ => {
                        let _ = store.rewind();
                    }
                }
                // Invariant: entries map dense over 0..tree_size —
                // never a gap, never an orphan past the frontier.
                let sz = store.tree_size() as u64;
                assert!(
                    store.entry_at(sz).is_none(),
                    "orphaned entry past tree_size {sz} (seed {seed})"
                );
                if sz > 0 {
                    assert!(
                        store.entry_at(sz - 1).is_some(),
                        "missing entry below tree_size {sz} (seed {seed})"
                    );
                }
            }
        }

        for seed in [1u64, 0xDEAD_BEEF, 42, 7777, 0x5151_5151, u64::MAX / 3] {
            run(seed, 900);
        }

        // Adversarial: checkpoint storm then rewind storm, then an
        // empty-store rewind storm — none may panic or desync.
        let store = ShieldedStore::new();
        for h in 1..=10 {
            store.checkpoint_at_height(h);
        }
        for _ in 0..10 {
            store.rewind();
        }
        for _ in 0..50 {
            assert!(!store.rewind(), "empty-stack rewind returns false");
        }
        assert_eq!(store.tree_size(), 0);
    }

    #[test]
    fn stress_high_volume_checkpoint_append_rewind() {
        // Under-pressure test: 2000 blocks each with one commitment —
        // 2x past the 1000-deep cap — then a full-cap-depth deep
        // rewind. Verifies the parallel checkpoint stack stays capped
        // and in lock-step with the BridgeTree the whole time, the
        // entries map stays dense, the deep reorg stays exact, and
        // the rewound store is byte-identical to a directly-built
        // one. Unlike Spark/Kernel, the BridgeTree is incremental
        // (O(log n) per append) — no O(n^2) ceiling here.
        let store = ShieldedStore::new();
        let blocks: u64 = 2000;
        for h in 1..=blocks {
            apply_block(&store, h, &[[(h & 0xFF) as u8; 32]], &[]);
            assert!(
                store.checkpoints.read().len() <= MAX_CHECKPOINTS,
                "parallel checkpoint stack exceeded the cap at block {h}"
            );
            assert_eq!(store.tree_size() as u64, h, "tree size wrong at block {h}");
        }
        assert_eq!(store.checkpoints.read().len(), MAX_CHECKPOINTS);

        let size_before = store.tree_size() as u64;
        let mut rewinds: u64 = 0;
        while store.rewind() {
            rewinds += 1;
            let sz = store.tree_size() as u64;
            assert_eq!(sz, size_before - rewinds, "tree size wrong mid deep-rewind");
            // Entries map stays dense — no orphan past the frontier.
            assert!(store.entry_at(sz).is_none(), "orphan past frontier mid-rewind");
        }
        assert_eq!(rewinds, MAX_CHECKPOINTS as u64);
        let size_after = store.tree_size() as u64;

        let reference = ShieldedStore::new();
        for h in 1..=size_after {
            apply_block(&reference, h, &[[(h & 0xFF) as u8; 32]], &[]);
        }
        assert_eq!(
            store.current_root(),
            reference.current_root(),
            "post-deep-reorg root drifted from a directly-built store"
        );
        assert_eq!(store.tree_size(), reference.tree_size());
    }

    #[test]
    fn stress_concurrent_read_write_load() {
        // Concurrent readers + writer(s). ShieldedStore has the most
        // complex lock graph of the three Phase-2 stores: `tree`,
        // `entries`, `nullifiers`, `checkpoints`, plus persistence.
        // The only method holding two locks at once is `rewind`
        // (entries → nullifiers); `append_commitment` releases the
        // tree lock before taking entries; `checkpoint_at_height`
        // holds none together. Global order tree → entries →
        // nullifiers, no cycle. The proof is operational — every
        // thread joined; a deadlock would hang the join forever.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        // Part A — realistic: one writer, many readers.
        {
            let store = Arc::new(ShieldedStore::new());
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
                        match (s >> 33) % 4 {
                            0 => {
                                h += 1;
                                store.checkpoint_at_height(h);
                            }
                            1 => {
                                store.append_commitment(entry(
                                    [(s & 0xFF) as u8; 32],
                                    h.max(1),
                                ));
                            }
                            2 => {
                                store.mark_nullifier_spent(
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
                            let _ = store.current_root();
                            let _ = store.tree_size();
                            let _ = store.is_nullifier_spent(&[0xAB; 32]);
                            let _ = store.entry_at(0);
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
            let store = Arc::new(ShieldedStore::new());
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
                        match (s >> 33) % 4 {
                            0 => {
                                h += 4;
                                store.checkpoint_at_height(h);
                            }
                            1 => {
                                store.append_commitment(entry(
                                    [(s & 0xFF) as u8; 32],
                                    h.max(1),
                                ));
                            }
                            2 => {
                                store.mark_nullifier_spent(
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
                        let _ = store.tree_size();
                        let _ = store.is_nullifier_spent(&[0x77; 32]);
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

    #[test]
    fn persist_and_replay_roundtrips() {
        use crate::db::Database;

        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        // First session: write three commitments and one nullifier.
        let (root_before, nf) = {
            let store = ShieldedStore::open_with_db(&db).unwrap();
            store.append_commitment(entry([1u8; 32], 1));
            store.append_commitment(entry([2u8; 32], 1));
            store.append_commitment(entry([3u8; 32], 2));
            let nf = [7u8; 32];
            assert!(store.mark_nullifier_spent(nf, 3));
            (store.current_root(), nf)
        };

        // Second session against the same DB: the store should replay
        // all three commitments (same root), see the nullifier as spent,
        // and report tree_size == 3.
        let store2 = ShieldedStore::open_with_db(&db).unwrap();
        assert_eq!(store2.current_root(), root_before);
        assert_eq!(store2.tree_size(), 3);
        assert!(store2.is_nullifier_spent(&nf));
        assert!(!store2.is_nullifier_spent(&[0u8; 32]));

        // And a fresh commit in the second session must not double-insert
        // an existing position.
        let pos = store2.append_commitment(entry([4u8; 32], 4));
        assert_eq!(pos, 3);
    }
}
