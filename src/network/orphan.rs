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

use std::collections::{BTreeMap, HashMap};
use crate::consensus::Block;
use crate::primitives::Hash;

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
    fn default() -> Self { Self::new() }
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
        if self.parent_by_hash.contains_key(&hash) { return false; }
        if self.parent_by_hash.len() >= MAX_ORPHAN_SIZE { self.evict_oldest(); }
        tracing::info!("[ORPHAN] Stored h={} hash={} prev={}", block.header.height, &hash.to_hex()[..12], &prev.to_hex()[..12]);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.parent_by_hash.insert(hash, prev);
        self.seq_by_hash.insert(hash, seq);
        self.oldest_first.insert(seq, hash);
        self.by_parent.entry(prev).or_default().push(OrphanEntry { block, received_at_height: current_height });
        true
    }

    pub fn take_children(&mut self, parent_hash: &Hash) -> Vec<Block> {
        let entries = match self.by_parent.remove(parent_hash) { Some(e) => e, None => return vec![] };
        let blocks: Vec<Block> = entries.into_iter().map(|e| {
            let h = e.block.hash();
            self.parent_by_hash.remove(&h);
            if let Some(seq) = self.seq_by_hash.remove(&h) {
                self.oldest_first.remove(&seq);
            }
            e.block
        }).collect();
        if !blocks.is_empty() { tracing::info!("[ORPHAN] {} orphan(s) reconnected (parent {})", blocks.len(), &parent_hash.to_hex()[..12]); }
        blocks
    }

    pub fn expire(&mut self, current_height: u64) {
        if current_height < ORPHAN_TTL_BLOCKS { return; }
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
                } else { true }
            });
            !entries.is_empty()
        });
        if expired > 0 { tracing::debug!("[ORPHAN] Expired {} orphan(s)", expired); }
    }

    pub fn len(&self) -> usize { self.parent_by_hash.len() }
    pub fn is_empty(&self) -> bool { self.parent_by_hash.is_empty() }
    pub fn contains(&self, hash: &Hash) -> bool { self.parent_by_hash.contains_key(hash) }
    pub fn pending_parents(&self) -> usize { self.by_parent.len() }

    pub fn diagnostics(&self) -> String {
        format!("orphan_pool: {} blocks on {} parents (cap {})", self.parent_by_hash.len(), self.by_parent.len(), MAX_ORPHAN_SIZE)
    }

    /// O(log n) eviction of the oldest orphan via the BTreeMap secondary index.
    /// Previously O(n²): VecDeque pop + linear scan across every parent bucket.
    fn evict_oldest(&mut self) {
        let (_, oldest_hash) = match self.oldest_first.pop_first() { Some(p) => p, None => return };
        self.seq_by_hash.remove(&oldest_hash);
        let parent = match self.parent_by_hash.remove(&oldest_hash) { Some(p) => p, None => return };
        if let Some(entries) = self.by_parent.get_mut(&parent) {
            entries.retain(|e| e.block.hash() != oldest_hash);
            if entries.is_empty() { self.by_parent.remove(&parent); }
        }
    }
}
