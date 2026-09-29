//! # Orphan Block Pool
//!
//! Stores blocks whose parent is not yet known. Prevents unnecessary
//! rollbacks during IBD when blocks arrive out of order.
//!
//! Eviction and lookup are O(log n) via a BTreeMap secondary index
//! keyed by insertion sequence number. (Prior comment referenced
//! Bitcoin Core's `mapOrphanTransactionsByPrev` as prior art for the
//! ordered-index shape; that specific identifier was not re-located
//! in current upstream this session, so the concrete symbol
//! attribution is dropped. The BTreeMap design here stands on its own
//! reasoning.) The reverse `parent_by_hash` map turns "find and remove
//! an arbitrary orphan" into an O(log n) operation instead of the
//! previous O(n) scan across every parent bucket.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `add`** — INVARIANT: the pool never holds more than
//!   `MAX_ORPHAN_SIZE` entries; once at capacity, `evict_oldest` runs before
//!   the new block is inserted.
//!   THREAT: an unbounded orphan pool lets an attacker flood a node with
//!   parentless blocks to exhaust memory.
//!   TESTS: `add_never_exceeds_max_orphan_size_under_flood`.
//! - **§2 `evict_oldest`** — INVARIANT: eviction always removes the entry
//!   with the smallest insertion sequence number (strict oldest-first LRU),
//!   via the `oldest_first` BTreeMap index rather than a linear scan.
//!   THREAT: evicting anything other than the true oldest entry would let a
//!   flood of new orphans push out arbitrary (possibly still-relevant)
//!   entries, or regress to the prior O(n²) scan under load.
//!   TESTS: `evict_oldest_removes_the_first_inserted_at_capacity`.
//! - **§3 `take_children`** — INVARIANT: reconnecting a parent's children
//!   removes each returned block from all three indices
//!   (`by_parent`, `parent_by_hash`, `seq_by_hash`/`oldest_first`) together,
//!   leaving no dangling entries.
//!   THREAT: a partial removal would leak index entries, letting a stale
//!   `parent_by_hash`/`seq_by_hash` pair reference a block no longer in
//!   `by_parent`, corrupting later `contains`/eviction decisions.
//!   TESTS: `take_children_clears_all_indices_for_reconnected_blocks`.
//! - **§4 `expire`** — INVARIANT: only entries received strictly before
//!   `current_height - ORPHAN_TTL_BLOCKS` are dropped, and only after
//!   `current_height >= ORPHAN_TTL_BLOCKS` (no underflow on a young chain).
//!   THREAT: an unguarded subtraction would underflow `current_height` on a
//!   short chain (panic/wraparound); no TTL at all would let stale orphans
//!   accumulate forever.
//!   TESTS: `expire_respects_ttl_and_does_not_underflow_on_young_chain`.

use crate::consensus::Block;
use crate::primitives::Hash;
use std::collections::{BTreeMap, HashMap};

const MAX_ORPHAN_SIZE: usize = 200;
const ORPHAN_TTL_BLOCKS: u64 = 100;

struct OrphanEntry {
    block: Block,
    received_at_height: u64,
}

pub struct OrphanPool {
    by_parent: HashMap<Hash, Vec<OrphanEntry>>,
    /// hash -> parent hash (reverse index for O(1) parent lookup on eviction)
    parent_by_hash: HashMap<Hash, Hash>,
    /// hash -> insertion sequence number
    seq_by_hash: HashMap<Hash, u64>,
    /// sequence -> hash (ordered index for O(log n) oldest-first eviction)
    oldest_first: BTreeMap<u64, Hash>,
    next_seq: u64,
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanPool {
    pub fn new() -> Self {
        Self {
            by_parent: HashMap::new(),
            parent_by_hash: HashMap::new(),
            seq_by_hash: HashMap::new(),
            oldest_first: BTreeMap::new(),
            next_seq: 0,
        }
    }

    pub fn add(&mut self, block: Block, current_height: u64) -> bool {
        let hash = block.hash();
        let prev = block.header.prev_hash;
        if self.parent_by_hash.contains_key(&hash) {
            return false;
        }
        if self.parent_by_hash.len() >= MAX_ORPHAN_SIZE {
            self.evict_oldest();
        }
        tracing::info!(
            "[ORPHAN] Stored h={} hash={} prev={}",
            block.header.height,
            &hash.to_hex()[..12],
            &prev.to_hex()[..12]
        );
        let seq = self.next_seq;
        self.next_seq += 1;
        self.parent_by_hash.insert(hash, prev);
        self.seq_by_hash.insert(hash, seq);
        self.oldest_first.insert(seq, hash);
        self.by_parent.entry(prev).or_default().push(OrphanEntry {
            block,
            received_at_height: current_height,
        });
        true
    }

    pub fn take_children(&mut self, parent_hash: &Hash) -> Vec<Block> {
        let entries = match self.by_parent.remove(parent_hash) {
            Some(e) => e,
            None => return vec![],
        };
        let blocks: Vec<Block> = entries
            .into_iter()
            .map(|e| {
                let h = e.block.hash();
                self.parent_by_hash.remove(&h);
                if let Some(seq) = self.seq_by_hash.remove(&h) {
                    self.oldest_first.remove(&seq);
                }
                e.block
            })
            .collect();
        if !blocks.is_empty() {
            tracing::info!(
                "[ORPHAN] {} orphan(s) reconnected (parent {})",
                blocks.len(),
                &parent_hash.to_hex()[..12]
            );
        }
        blocks
    }

    pub fn expire(&mut self, current_height: u64) {
        if current_height < ORPHAN_TTL_BLOCKS {
            return;
        }
        let cutoff = current_height - ORPHAN_TTL_BLOCKS;
        let mut expired = 0;
        let parent_by_hash = &mut self.parent_by_hash;
        let seq_by_hash = &mut self.seq_by_hash;
        let oldest_first = &mut self.oldest_first;
        self.by_parent.retain(|_, entries| {
            entries.retain(|e| {
                if e.received_at_height < cutoff {
                    let h = e.block.hash();
                    parent_by_hash.remove(&h);
                    if let Some(seq) = seq_by_hash.remove(&h) {
                        oldest_first.remove(&seq);
                    }
                    expired += 1;
                    false
                } else {
                    true
                }
            });
            !entries.is_empty()
        });
        if expired > 0 {
            tracing::debug!("[ORPHAN] Expired {} orphan(s)", expired);
        }
    }

    pub fn len(&self) -> usize {
        self.parent_by_hash.len()
    }
    pub fn is_empty(&self) -> bool {
        self.parent_by_hash.is_empty()
    }
    pub fn contains(&self, hash: &Hash) -> bool {
        self.parent_by_hash.contains_key(hash)
    }
    pub fn pending_parents(&self) -> usize {
        self.by_parent.len()
    }

    pub fn diagnostics(&self) -> String {
        format!(
            "orphan_pool: {} blocks on {} parents (cap {})",
            self.parent_by_hash.len(),
            self.by_parent.len(),
            MAX_ORPHAN_SIZE
        )
    }

    /// O(log n) eviction of the oldest orphan via the BTreeMap secondary index.
    /// Previously O(n²): VecDeque pop + linear scan across every parent bucket.
    fn evict_oldest(&mut self) {
        let (_, oldest_hash) = match self.oldest_first.pop_first() {
            Some(p) => p,
            None => return,
        };
        self.seq_by_hash.remove(&oldest_hash);
        let parent = match self.parent_by_hash.remove(&oldest_hash) {
            Some(p) => p,
            None => return,
        };
        if let Some(entries) = self.by_parent.get_mut(&parent) {
            entries.retain(|e| e.block.hash() != oldest_hash);
            if entries.is_empty() {
                self.by_parent.remove(&parent);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::BlockHeader;
    use crate::primitives::PublicKey;

    /// Minimal orphan block: parent = `prev`, unique hash via `nonce`. Only the
    /// fields OrphanPool reads (prev_hash, height) plus a hash-distinguishing
    /// nonce matter here.
    fn orphan_block(prev: Hash, height: u64, nonce: u64) -> Block {
        let header = BlockHeader {
            network_magic: [0, 0, 0, 0],
            version: 1,
            height,
            timestamp: 0,
            prev_hash: prev,
            tx_root: Hash::zero(),
            anchor: Hash::zero(),
            algorithm: 0,
            nonce,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: PublicKey::from_bytes([0u8; 32]),
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        };
        Block::new(header, vec![])
    }

    // §1: the pool never holds more than MAX_ORPHAN_SIZE entries, even under a
    // parentless-block flood — eviction runs before each over-cap insert.
    #[test]
    fn add_never_exceeds_max_orphan_size_under_flood() {
        let mut pool = OrphanPool::new();
        let parent = Hash::from_bytes([1u8; 32]);
        for i in 0..(MAX_ORPHAN_SIZE as u64 + 50) {
            pool.add(orphan_block(parent, 1, i), 0);
            assert!(pool.len() <= MAX_ORPHAN_SIZE, "pool exceeded cap at insert {}", i);
        }
        assert_eq!(pool.len(), MAX_ORPHAN_SIZE, "pool settles exactly at the cap");
    }

    // §2: eviction removes the strict oldest (smallest insertion sequence),
    // leaving newer entries intact.
    #[test]
    fn evict_oldest_removes_the_first_inserted_at_capacity() {
        let mut pool = OrphanPool::new();
        let parent = Hash::from_bytes([2u8; 32]);
        let first = orphan_block(parent, 1, 0);
        let first_hash = first.hash();
        pool.add(first, 0);
        for i in 1..MAX_ORPHAN_SIZE as u64 {
            pool.add(orphan_block(parent, 1, i), 0);
        }
        assert_eq!(pool.len(), MAX_ORPHAN_SIZE);
        assert!(pool.contains(&first_hash), "oldest still present at exactly cap");

        let newest = orphan_block(parent, 1, 9_999);
        let newest_hash = newest.hash();
        pool.add(newest, 0); // over cap → evict oldest, then insert
        assert_eq!(pool.len(), MAX_ORPHAN_SIZE);
        assert!(!pool.contains(&first_hash), "the oldest entry was evicted");
        assert!(pool.contains(&newest_hash), "the newest entry is present");
    }

    // §3: take_children removes each reconnected block from ALL indices, leaving
    // no dangling entries, and does not touch other parents' children.
    #[test]
    fn take_children_clears_all_indices_for_reconnected_blocks() {
        let mut pool = OrphanPool::new();
        let parent = Hash::from_bytes([7u8; 32]);
        let c1 = orphan_block(parent, 5, 1);
        let c2 = orphan_block(parent, 5, 2);
        let other = orphan_block(Hash::from_bytes([8u8; 32]), 5, 3);
        let (h1, h2, ho) = (c1.hash(), c2.hash(), other.hash());
        pool.add(c1, 0);
        pool.add(c2, 0);
        pool.add(other, 0);
        assert_eq!(pool.len(), 3);

        let taken: Vec<Hash> = pool.take_children(&parent).iter().map(|b| b.hash()).collect();
        assert_eq!(taken.len(), 2);
        assert!(taken.contains(&h1) && taken.contains(&h2));

        assert!(!pool.contains(&h1) && !pool.contains(&h2), "taken children gone from pool");
        assert!(pool.contains(&ho), "other parent's child untouched");
        assert_eq!(pool.len(), 1);
        // No dangling secondary-index entries (in-module test can read privates).
        for h in [h1, h2] {
            assert!(!pool.parent_by_hash.contains_key(&h));
            assert!(!pool.seq_by_hash.contains_key(&h));
            assert!(!pool.oldest_first.values().any(|v| *v == h));
        }
    }

    // §4: expire drops only entries older than the TTL window, and never
    // underflows on a chain shorter than ORPHAN_TTL_BLOCKS.
    #[test]
    fn expire_respects_ttl_and_does_not_underflow_on_young_chain() {
        // Young chain: current_height < TTL → early return, no panic, nothing dropped.
        let mut pool = OrphanPool::new();
        pool.add(orphan_block(Hash::from_bytes([3u8; 32]), 1, 1), 0);
        pool.expire(ORPHAN_TTL_BLOCKS - 1);
        assert_eq!(pool.len(), 1, "no expiry (and no underflow) below the TTL floor");

        // Mature chain: an old orphan expires, a recent one survives.
        let mut pool = OrphanPool::new();
        let parent = Hash::from_bytes([4u8; 32]);
        let old = orphan_block(parent, 1, 10);
        let recent = orphan_block(parent, 1, 11);
        let (old_h, recent_h) = (old.hash(), recent.hash());
        pool.add(old, 0); // received_at_height 0
        pool.add(recent, ORPHAN_TTL_BLOCKS + 5); // received_at_height 105
        pool.expire(ORPHAN_TTL_BLOCKS + 10); // cutoff = 10
        assert!(!pool.contains(&old_h), "orphan older than the TTL window is dropped");
        assert!(pool.contains(&recent_h), "recent orphan survives");
        assert_eq!(pool.len(), 1);
    }
}
