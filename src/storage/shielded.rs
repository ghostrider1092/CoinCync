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
/// blocks deep. Matches the chain's max reorg depth.
const MAX_CHECKPOINTS: usize = 100;

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

    /// Record a block's worth of note appends and checkpoint the tree.
    /// Call at the end of `chain::Blockchain::accept_block` so a
    /// reorg can rewind cleanly.
    pub fn checkpoint_at_height(&self, height: u64) {
        let mut tree = self.tree.write();
        tree.checkpoint(height);
    }

    /// Rewind the tree to a prior checkpoint (block disconnect during reorg).
    /// Returns true iff the rewind succeeded.
    pub fn rewind(&self) -> bool {
        let mut tree = self.tree.write();
        tree.rewind()
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
