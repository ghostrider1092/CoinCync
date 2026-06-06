//! # Chain Synchronization
//!
//! Block synchronization with peers.
//! Bug 3 fix: stuck download detection and mark_block_failed recovery.

use std::collections::{HashMap, HashSet, VecDeque};
use crate::primitives::Hash;
use crate::consensus::Block;
use crate::network::peer::PeerId;
use crate::error::Result;

/// Sync state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    Headers,
    Blocks,
    ConfirmingSynced,
    Synced,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct BlockRequest {
    hash: Hash,
    requested_from: PeerId,
    requested_at: u64,
}

const MAX_ORPHAN_BLOCKS: usize = 1000;
const MAX_PENDING_REQUESTS: usize = 10_000;
const ORPHAN_TTL_SECONDS: u64 = 30 * 60;
const ORPHAN_CLEANUP_INTERVAL: u64 = 60;
const MAX_ORPHANS_PER_PEER: usize = 50;

/// How long a block can sit in `downloading` with no `pending_requests`
/// entry before it is re-queued. Fix for Bug 3 (NYC stuck at height 12).
const STUCK_DOWNLOAD_TIMEOUT_SECS: u64 = 8;

const BLOCKS_STUCK_TIMEOUT: u64 = 10;

/// Per-peer block-download timeout scaling. Reduced from Bitcoin defaults
/// (10s base, 5s/peer) for faster stall recovery on testnet.
const BLOCK_DOWNLOAD_TIMEOUT_BASE: u64 = 5;
const BLOCK_DOWNLOAD_TIMEOUT_PER_PEER: u64 = 2;

#[derive(Clone, Debug)]
struct OrphanBlock {
    block: Block,
    received_at: u64,
}

struct DownloadEntry {
    entered_at: u64,
}

pub struct ChainSync {
    local_height: u64,
    local_tip: Hash,
    best_known_height: u64,
    state: SyncState,
    pending_requests: HashMap<Hash, BlockRequest>,
    orphan_blocks: HashMap<Hash, OrphanBlock>,
    orphan_by_parent: HashMap<Hash, Vec<Hash>>,
    pending_headers: VecDeque<Hash>,
    downloading: HashSet<Hash>,
    download_timestamps: HashMap<Hash, DownloadEntry>,
    max_concurrent: usize,
    request_timeout: u64,
    last_orphan_cleanup: u64,
    peer_failures: HashMap<PeerId, u32>,
    sync_banned_peers: HashMap<PeerId, u64>,
    last_sync_peer: Option<PeerId>,
    headers_request_time: Option<u64>,
    headers_received_this_cycle: bool,
    peer_heights: HashMap<PeerId, u64>,
    pending_header_nonces: HashSet<u64>,
    next_header_nonce: u64,
    orphans_per_peer: HashMap<PeerId, usize>,
    blocks_entered_at: Option<u64>,
}

impl ChainSync {
    pub fn new(local_height: u64, local_tip: Hash) -> Self {
        ChainSync {
            local_height, local_tip,
            best_known_height: local_height,
            state: SyncState::Idle,
            pending_requests: HashMap::new(),
            orphan_blocks: HashMap::new(),
            orphan_by_parent: HashMap::new(),
            pending_headers: VecDeque::new(),
            downloading: HashSet::new(),
            download_timestamps: HashMap::new(),
            max_concurrent: 100,
            request_timeout: 30,
            last_orphan_cleanup: 0,
            peer_failures: HashMap::new(),
            sync_banned_peers: HashMap::new(),
            last_sync_peer: None,
            headers_request_time: None,
            headers_received_this_cycle: false,
            peer_heights: HashMap::new(),
            pending_header_nonces: HashSet::new(),
            next_header_nonce: 1,
            orphans_per_peer: HashMap::new(),
            blocks_entered_at: None,
        }
    }

    pub fn cleanup_expired_orphans(&mut self, current_time: u64) -> usize {
        if current_time < self.last_orphan_cleanup { self.last_orphan_cleanup = current_time; }
        if current_time < self.last_orphan_cleanup + ORPHAN_CLEANUP_INTERVAL { return 0; }
        self.last_orphan_cleanup = current_time;

        let cutoff = current_time.saturating_sub(ORPHAN_TTL_SECONDS);
        let expired: Vec<(Hash, Hash)> = self.orphan_blocks.iter()
            .filter(|(_, o)| o.received_at <= cutoff)
            .map(|(k, o)| (*k, o.block.header.prev_hash))
            .collect();

        for (bh, ph) in &expired {
            self.orphan_blocks.remove(bh);
            if let Some(children) = self.orphan_by_parent.get_mut(ph) {
                children.retain(|h| h != bh);
                if children.is_empty() { self.orphan_by_parent.remove(ph); }
            }
        }
        if !expired.is_empty() { tracing::debug!("Cleaned {} expired orphans", expired.len()); }
        expired.len()
    }

    pub fn set_local_tip(&mut self, height: u64, tip: Hash) {
        self.local_height = height;
        self.local_tip = tip;
        if self.local_height >= self.best_known_height
            && self.pending_headers.is_empty() && self.downloading.is_empty() {
            self.state = SyncState::Synced;
        }
    }

    pub fn update_peer_height_for(&mut self, peer_id: PeerId, height: u64) {
        // 2026-06-06 hotfix: peers advertising heights more than 10_000
        // above our local view are rejected outright. The previous
        // implementation CLAMPED such claims to `local_height + 10_000`
        // and stored them as the peer's "known" height — which then
        // propagated through `refresh_best_known()` into
        // `best_known_height` (the field surfaced as `target_height` in
        // the RPC `get_info` response). When even one bogus peer
        // connected briefly, every fleet box on the receive path stored
        // the same clamped value, then re-advertised it to each other
        // on the next handshake, perpetuating a phantom
        // `target = local + 10_000` across the fleet indefinitely until
        // a manual coordinated wipe broke the cycle. The
        // `Sync EMERGENCY-TIER-3` recovery path further down in this
        // file was the code's own admission that this state could not
        // be recovered from within a running node — its operator-facing
        // message reads "operator may need to wipe + reimport snapshot."
        // Now we reject the bogus claim before it can poison
        // `best_known_height`. Post-mortem at
        // `docs/operations/incidents/2026-06-06-sync-clamp-phantom.md`.
        let max = self.local_height.saturating_add(10_000);
        if height > max {
            return;
        }
        self.peer_heights.insert(peer_id, height);
        self.refresh_best_known();
        if height > self.local_height && matches!(self.state, SyncState::Synced | SyncState::Idle | SyncState::ConfirmingSynced) {
            self.state = SyncState::Headers;
            self.headers_request_time = None;
            self.headers_received_this_cycle = false;
        }
    }

    pub fn update_peer_height(&mut self, height: u64) {
        // 2026-06-06 hotfix: same reject-don't-clamp policy as
        // `update_peer_height_for` above. See that function for the
        // full rationale and incident post-mortem reference.
        let max = self.local_height.saturating_add(10_000);
        if height > max {
            return;
        }
        if height > self.best_known_height { self.best_known_height = height; }
    }

    fn refresh_best_known(&mut self) {
        let pm = self.peer_heights.values().copied().max().unwrap_or(0);
        if pm > self.best_known_height { self.best_known_height = pm; }
    }

    pub fn true_best_height(&self) -> u64 {
        self.best_known_height.max(self.peer_heights.values().copied().max().unwrap_or(0))
    }

    pub fn remove_peer_height(&mut self, peer_id: &PeerId) { self.peer_heights.remove(peer_id); }

    pub fn peers_above_height(&self, min: u64) -> Vec<PeerId> {
        self.peer_heights.iter().filter(|(_, &h)| h >= min).map(|(&id, _)| id).collect()
    }

    pub fn is_synced(&self) -> bool { self.local_height >= self.true_best_height() }
    pub fn blocks_behind(&self) -> u64 { self.best_known_height.saturating_sub(self.local_height) }
    pub fn set_local_height(&mut self, h: u64) { self.local_height = h; }
    pub fn state(&self) -> SyncState { self.state }

    pub fn set_state(&mut self, state: SyncState) {
        if state != SyncState::Blocks { self.blocks_entered_at = None; }
        self.state = state;
    }

    pub fn progress(&self) -> f64 {
        if self.best_known_height == 0 { 1.0 } else { self.local_height as f64 / self.best_known_height as f64 }
    }

    pub fn queue_headers(&mut self, headers: Vec<Hash>) {
        const MAX_PH: usize = 50_000;
        if headers.is_empty() {
            if self.state == SyncState::ConfirmingSynced && self.local_height > 0 {
                self.state = SyncState::Synced;
            }
            if matches!(self.state, SyncState::Headers | SyncState::ConfirmingSynced) {
                if self.true_best_height() > self.local_height + 2 {
                    self.state = SyncState::Headers;
                    self.headers_request_time = None; // Reset timeout to allow re-request
                }
            }
            return;
        }
        self.headers_received_this_cycle = true;
        for hash in headers {
            if self.pending_headers.len() >= MAX_PH { break; }
            if !self.downloading.contains(&hash) && !self.orphan_blocks.contains_key(&hash) {
                self.pending_headers.push_back(hash);
            }
        }
        if !self.pending_headers.is_empty() {
            self.state = SyncState::Blocks;
            if self.blocks_entered_at.is_none() { self.blocks_entered_at = Some(unix_now()); }
        }
    }

    pub fn get_blocks_to_request(&mut self, max: usize) -> Vec<Hash> {
        let mut out = Vec::new();
        let slots = self.max_concurrent.saturating_sub(self.downloading.len());
        let now = unix_now();
        while out.len() < max.min(slots) && !self.pending_headers.is_empty() {
            if let Some(h) = self.pending_headers.pop_front() {
                if !self.downloading.contains(&h) {
                    out.push(h);
                    self.downloading.insert(h);
                    self.download_timestamps.insert(h, DownloadEntry { entered_at: now });
                }
            } else { break; }
        }
        out
    }

    pub fn record_request(&mut self, hash: Hash, peer: PeerId, ts: u64) {
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            if let Some(k) = self.pending_requests.iter().min_by_key(|(_, r)| r.requested_at).map(|(h, _)| *h) {
                self.pending_requests.remove(&k);
            }
        }
        self.pending_requests.insert(hash, BlockRequest { hash, requested_from: peer, requested_at: ts });
    }

    pub fn peer_orphan_limit_reached(&self, pid: &PeerId) -> bool {
        self.orphans_per_peer.get(pid).copied().unwrap_or(0) >= MAX_ORPHANS_PER_PEER
    }

    pub fn on_block_received(&mut self, block: Block) -> Result<Vec<Block>> { self.on_block_received_from(block, None) }

    pub fn on_block_received_from(&mut self, block: Block, from: Option<PeerId>) -> Result<Vec<Block>> {
        let hash = block.hash();
        let height = block.height();
        if height > self.local_height.saturating_add(10_000) {
            if let Some(p) = from { *self.peer_failures.entry(p).or_insert(0) += 1; }
            return Ok(vec![]);
        }
        let tb = block.header.target.as_bytes();
        if tb.iter().all(|&b| b == 0xFF) || tb.iter().all(|&b| b == 0) {
            if let Some(p) = from { *self.peer_failures.entry(p).or_insert(0) += 1; }
            return Ok(vec![]);
        }
        if !hash.meets_difficulty(&block.header.target) {
            if let Some(p) = from { *self.peer_failures.entry(p).or_insert(0) += 1; }
            return Ok(vec![]);
        }

        let now = unix_now();
        self.cleanup_expired_orphans(now);
        let was_req = self.downloading.remove(&hash);
        self.download_timestamps.remove(&hash);
        self.pending_requests.remove(&hash);

        let connects = block.header.prev_hash == self.local_tip || height == 0;
        if connects || was_req {
            let mut out = vec![block];
            if connects {
                let mut q = VecDeque::new();
                q.push_back(hash);
                while let Some(ph) = q.pop_front() {
                    if let Some(chs) = self.orphan_by_parent.remove(&ph) {
                        for ch in chs {
                            if let Some(o) = self.orphan_blocks.remove(&ch) {
                                let rh = o.block.hash();
                                out.push(o.block);
                                q.push_back(rh);
                                // FIX: Decrement orphans_per_peer when orphans are resolved.
                                // Previously the counter was only incremented, never decremented
                                // on resolution — peers were penalized indefinitely.
                                if let Some(pid) = from {
                                    if let Some(c) = self.orphans_per_peer.get_mut(&pid) {
                                        *c = c.saturating_sub(1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return Ok(out);
        }

        while self.orphan_blocks.len() >= MAX_ORPHAN_BLOCKS {
            if let Some(k) = self.orphan_blocks.iter().min_by_key(|(_, e)| e.received_at).map(|(k, _)| *k) {
                if let Some(o) = self.orphan_blocks.remove(&k) {
                    let p = o.block.header.prev_hash;
                    if let Some(c) = self.orphan_by_parent.get_mut(&p) { c.retain(|h| h != &k); if c.is_empty() { self.orphan_by_parent.remove(&p); } }
                }
            } else { break; }
        }
        if let Some(pid) = from {
            let c = self.orphans_per_peer.entry(pid).or_insert(0);
            if *c >= MAX_ORPHANS_PER_PEER { return Ok(vec![]); }
            *c += 1;
        }
        let bh = block.hash();
        let ph = block.header.prev_hash;
        self.orphan_by_parent.entry(ph).or_default().push(bh);
        self.orphan_blocks.insert(bh, OrphanBlock { block, received_at: now });
        Ok(vec![])
    }

    pub fn mark_block_received(&mut self, hash: &Hash) {
        if let Some(req) = self.pending_requests.remove(hash) { self.on_block_success(&req.requested_from); }
        self.downloading.remove(hash);
        self.download_timestamps.remove(hash);
    }

    /// Bug 3 fix: mark block as failed, re-queue for retry from different peer.
    pub fn mark_block_failed(&mut self, hash: &Hash) {
        self.pending_requests.remove(hash);
        self.downloading.remove(hash);
        self.download_timestamps.remove(hash);
        self.pending_headers.push_front(*hash);
        tracing::debug!("Block {} failed — re-queued for retry", &hash.to_hex()[..16]);
    }

    /// IBD orphan-recovery (fixes the "wedge at one height" bug 2026-05-02):
    ///
    /// When a block comes back from chain validation as `Orphan` it means
    /// we don't have its parent. Re-requesting the orphan itself causes
    /// the same peer to keep handing it back — chain never advances.
    /// Instead, drop the orphan from active tracking and queue its PARENT
    /// hash for fetch. When the parent arrives and processes successfully,
    /// gossip will re-deliver the original orphan and the second pass will
    /// connect it to the chain.
    ///
    /// This is the minimal fix; we don't store the orphan body here
    /// because the gossip relay path doesn't pass us the block. A more
    /// thorough fix would also keep the orphan in `orphan_blocks` for
    /// instant replay when the parent lands. Acceptable trade-off for
    /// testnet — see the IBD orphan-loop bug memo for full context.
    pub fn mark_block_orphan(&mut self, orphan_hash: &Hash, parent_hash: &Hash) {
        // Stop tracking the orphan itself; we're not going to retry it.
        self.pending_requests.remove(orphan_hash);
        self.downloading.remove(orphan_hash);
        self.download_timestamps.remove(orphan_hash);

        // Don't queue the parent if we already have it or are about to.
        if *parent_hash == self.local_tip {
            return;
        }
        if self.downloading.contains(parent_hash) {
            return;
        }
        if self.pending_headers.contains(parent_hash) {
            return;
        }

        // Front-queue with high priority — the orphan is gated on this parent.
        const MAX_PH: usize = 50_000;
        if self.pending_headers.len() < MAX_PH {
            self.pending_headers.push_front(*parent_hash);
            if matches!(self.state, SyncState::Synced | SyncState::ConfirmingSynced | SyncState::Idle) {
                self.state = SyncState::Blocks;
            }
        }
        tracing::debug!(
            "Orphan {} → fetching parent {}",
            &orphan_hash.to_hex()[..16],
            &parent_hash.to_hex()[..16]
        );
    }

    pub fn on_block_processed(&mut self, hash: Hash, height: u64) {
        self.local_height = height;
        self.local_tip = hash;
        if self.pending_headers.is_empty() && self.downloading.is_empty() {
            self.blocks_entered_at = None;
            let tb = self.true_best_height();
            if height < tb.saturating_sub(1) {
                self.state = SyncState::Headers;
                self.headers_received_this_cycle = false;
                return;
            }
            if height == 0 && !self.peer_heights.is_empty() && !self.peer_heights.values().any(|&h| h > 0) {
                self.state = SyncState::Headers;
                self.headers_received_this_cycle = false;
                return;
            }
            self.state = SyncState::ConfirmingSynced;
            self.headers_received_this_cycle = false;
        }
    }

    pub fn get_timed_out(&self, now: u64) -> Vec<(Hash, PeerId)> {
        self.pending_requests.iter()
            .filter(|(_, r)| now > r.requested_at + self.request_timeout)
            .map(|(h, r)| (*h, r.requested_from)).collect()
    }

    pub fn on_timeout(&mut self, hash: &Hash) {
        if let Some(req) = self.pending_requests.remove(hash) {
            let c = self.peer_failures.entry(req.requested_from).or_insert(0);
            *c += 1;
            if *c >= 3 {
                self.sync_banned_peers.insert(req.requested_from, req.requested_at + 300);
                self.peer_failures.remove(&req.requested_from);
            }
        }
        self.downloading.remove(hash);
        self.download_timestamps.remove(hash);
        self.pending_headers.push_front(*hash);
    }

    pub fn on_block_success(&mut self, pid: &PeerId) {
        self.peer_failures.remove(pid);
        self.request_timeout = (self.request_timeout * 85 / 100).max(15);
    }

    pub fn increase_timeout(&mut self) {
        self.request_timeout = (self.request_timeout * 2).min(64);
    }

    pub fn is_sync_banned(&self, pid: &PeerId, now: u64) -> bool {
        self.sync_banned_peers.get(pid).map(|&t| now < t).unwrap_or(false)
    }

    pub fn cleanup_sync_bans(&mut self, now: u64) {
        self.sync_banned_peers.retain(|_, t| now >= *t);
    }

    pub fn set_last_sync_peer(&mut self, pid: PeerId) { self.last_sync_peer = Some(pid); }
    pub fn last_sync_peer(&self) -> Option<PeerId> { self.last_sync_peer }

    pub fn allocate_header_nonce(&mut self) -> u64 {
        let n = self.next_header_nonce;
        self.next_header_nonce += 1;
        self.pending_header_nonces.insert(n);
        n
    }

    pub fn validate_header_nonce(&mut self, n: u64) -> bool {
        // Phase D (audit fix): nonce 0 is never allocated (next_header_nonce
        // starts at 1), so the old `if n == 0 { return true }` accepted
        // unsolicited Headers, enabling eclipse attacks. Removing the exception
        // enforces that every Headers response matches an outstanding request.
        self.pending_header_nonces.remove(&n)
    }

    pub fn mark_headers_requested(&mut self, now: u64) {
        if self.headers_request_time.is_none() { self.headers_request_time = Some(now); }
    }

    pub fn headers_timed_out(&self, now: u64) -> bool {
        self.headers_request_time.map(|t| now > t + 60).unwrap_or(false)
    }

    pub fn reset_headers_timeout(&mut self) { self.headers_request_time = None; }
    pub fn request_timeout(&self) -> u64 { self.request_timeout }

    /// Bitcoin-style scaled request timeout: `max(adaptive, base + per_peer * (peers-1))`.
    /// Call this from the sync tick with the current live peer count.
    pub fn request_timeout_scaled(&self, peer_count: usize) -> u64 {
        let per_peer_bonus = BLOCK_DOWNLOAD_TIMEOUT_PER_PEER
            * (peer_count as u64).saturating_sub(1);
        let bitcoin_style = BLOCK_DOWNLOAD_TIMEOUT_BASE.saturating_add(per_peer_bonus);
        self.request_timeout.max(bitcoin_style)
    }

    pub fn best_known_height(&self) -> u64 { self.best_known_height }

    pub fn stats(&self) -> SyncStats {
        SyncStats {
            local_height: self.local_height, best_known_height: self.best_known_height,
            pending_headers: self.pending_headers.len(), downloading: self.downloading.len(),
            orphans: self.orphan_blocks.len(), state: self.state,
        }
    }

    pub fn requeue_failed(&mut self, hashes: Vec<Hash>) {
        for h in hashes.into_iter().rev() {
            self.downloading.remove(&h);
            self.download_timestamps.remove(&h);
            self.pending_headers.push_front(h);
        }
    }

    pub fn track_direct_request(&mut self, hash: Hash, peer: PeerId, ts: u64) {
        self.downloading.insert(hash);
        self.download_timestamps.insert(hash, DownloadEntry { entered_at: ts });
        self.record_request(hash, peer, ts);
    }

    pub fn clear(&mut self) {
        self.pending_requests.clear();
        self.orphan_blocks.clear();
        self.orphan_by_parent.clear();
        self.orphans_per_peer.clear();
        self.pending_headers.clear();
        self.downloading.clear();
        self.download_timestamps.clear();
        self.state = SyncState::Idle;
        self.blocks_entered_at = None;
    }

    /// Check if sync is stalled. Also detects stuck downloads (Bug 3 fix).
    pub fn is_stalled(&self, now: u64, timeout: u64) -> bool {
        if matches!(self.state, SyncState::Synced | SyncState::Idle | SyncState::ConfirmingSynced) { return false; }
        let all_to = !self.pending_requests.is_empty()
            && self.pending_requests.values().all(|r| now > r.requested_at + timeout);
        let stuck = self.download_timestamps.iter().any(|(h, e)| {
            !self.pending_requests.contains_key(h) && now > e.entered_at + STUCK_DOWNLOAD_TIMEOUT_SECS
        });
        all_to || stuck
    }

    /// Get blocks to retry. Also recovers stuck downloads (Bug 3 fix).
    pub fn get_blocks_to_retry(&mut self, now: u64) -> Vec<Hash> {
        let to: Vec<Hash> = self.pending_requests.iter()
            .filter(|(_, r)| now > r.requested_at + self.request_timeout)
            .map(|(h, _)| *h).collect();
        for h in &to {
            self.pending_requests.remove(h);
            self.downloading.remove(h);
            self.download_timestamps.remove(h);
            self.pending_headers.push_front(*h);
        }

        let stuck: Vec<Hash> = self.download_timestamps.iter()
            .filter(|(h, e)| !self.pending_requests.contains_key(*h) && now > e.entered_at + STUCK_DOWNLOAD_TIMEOUT_SECS)
            .map(|(h, _)| *h).collect();
        let sc = stuck.len();
        for h in &stuck {
            self.downloading.remove(h);
            self.download_timestamps.remove(h);
            self.pending_headers.push_front(*h);
        }
        if sc > 0 {
            tracing::warn!("[SYNC] Recovered {} stuck downloads", sc);
            if sc >= 5 && self.state == SyncState::Blocks {
                self.state = SyncState::Headers;
                self.headers_received_this_cycle = false;
                self.headers_request_time = None;
                self.blocks_entered_at = None;
                self.pending_headers.clear();
            }
        }
        let mut all = to; all.extend(stuck); all
    }

    pub fn pending_count(&self) -> usize { self.pending_headers.len() + self.downloading.len() }

    pub fn recover_stuck_downloads(&mut self) -> usize {
        let s: Vec<Hash> = self.downloading.iter()
            .filter(|h| !self.pending_requests.contains_key(h)).copied().collect();
        let c = s.len();
        for h in s { self.downloading.remove(&h); self.download_timestamps.remove(&h); self.pending_headers.push_front(h); }
        c
    }

    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        self.peer_heights.remove(peer);
        self.orphans_per_peer.remove(peer);
        let rq: Vec<Hash> = self.pending_requests.iter()
            .filter(|(_, r)| &r.requested_from == peer).map(|(h, _)| *h).collect();
        for h in &rq {
            self.pending_requests.remove(h);
            self.downloading.remove(h);
            self.download_timestamps.remove(h);
            self.pending_headers.push_front(*h);
        }
        if !rq.is_empty() { tracing::info!("Peer {:?} disconnected, re-queued {} requests", peer, rq.len()); }
    }

    pub fn trigger_resync(&mut self) -> bool {
        if matches!(self.state, SyncState::Synced | SyncState::Idle) {
            self.state = SyncState::Headers;
            self.headers_received_this_cycle = false;
            self.headers_request_time = None;
            return true;
        }
        false
    }

    pub fn blocks_state_stuck(&self, now: u64) -> bool {
        if self.state != SyncState::Blocks { return false; }
        let e = match self.blocks_entered_at { Some(t) => t, None => return false };
        let empty = self.pending_headers.is_empty() && self.downloading.is_empty() && self.pending_requests.is_empty();
        empty && self.local_height < self.true_best_height() && now > e + BLOCKS_STUCK_TIMEOUT
    }

    pub fn needs_more_peers(&self) -> bool {
        !self.is_synced() && self.downloading.is_empty() && self.pending_headers.is_empty()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone, Debug)]
pub struct SyncStats {
    pub local_height: u64,
    pub best_known_height: u64,
    pub pending_headers: usize,
    pub downloading: usize,
    pub orphans: usize,
    pub state: SyncState,
}

pub fn build_locator(tip: u64, get_hash: impl Fn(u64) -> Option<Hash>) -> Vec<Hash> {
    let mut loc = Vec::new();
    let mut step = 1u64;
    let mut h = tip;
    while h > 0 {
        if let Some(hash) = get_hash(h) { loc.push(hash); }
        if loc.len() >= 10 { step *= 2; }
        if h < step { break; }
        h -= step;
    }
    if let Some(g) = get_hash(0) { if loc.last() != Some(&g) { loc.push(g); } }
    loc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state() {
        let mut sync = ChainSync::new(0, Hash::zero());
        assert_eq!(sync.state(), SyncState::Idle);
        assert!(sync.is_synced());
        sync.update_peer_height(100);
        assert!(!sync.is_synced());
    }

    #[test]
    fn test_build_locator() {
        let hashes: Vec<Hash> = (0..100).map(|i| Hash::from_bytes([i as u8; 32])).collect();
        let loc = build_locator(99, |h| hashes.get(h as usize).copied());
        assert!(!loc.is_empty());
        assert_eq!(loc.last(), Some(&hashes[0]));
    }

    #[test]
    fn test_stall_detection() {
        let mut sync = ChainSync::new(0, Hash::zero());
        let peer = super::super::peer::generate_peer_id();
        sync.update_peer_height_for(peer, 100);
        let hash = Hash::from_bytes([1u8; 32]);
        sync.record_request(hash, peer, 1000);
        assert!(!sync.is_stalled(1010, 60));
        assert!(sync.is_stalled(1100, 60));
    }

    #[test]
    fn test_stuck_download_detection() {
        let mut sync = ChainSync::new(0, Hash::zero());
        let peer = super::super::peer::generate_peer_id();
        sync.update_peer_height_for(peer, 100);
        let hash = Hash::from_bytes([5u8; 32]);
        sync.downloading.insert(hash);
        sync.download_timestamps.insert(hash, DownloadEntry { entered_at: 1000 });
        assert!(!sync.is_stalled(1005, 60));
        assert!(sync.is_stalled(1000 + STUCK_DOWNLOAD_TIMEOUT_SECS + 1, 60));
    }

    #[test]
    fn test_mark_block_failed_requeues() {
        let mut sync = ChainSync::new(0, Hash::zero());
        let peer = super::super::peer::generate_peer_id();
        sync.update_peer_height_for(peer, 100);
        let hash = Hash::from_bytes([7u8; 32]);
        sync.downloading.insert(hash);
        sync.record_request(hash, peer, 1000);
        sync.mark_block_failed(&hash);
        assert!(!sync.downloading.contains(&hash));
        assert_eq!(sync.pending_headers.len(), 1);
    }

    /// Regression test for the 2026-06-06 "phantom +10_000" fleet-wedge.
    ///
    /// A peer that advertises a height more than 10,000 above our local
    /// tip MUST be rejected outright. The pre-hotfix implementation
    /// clamped such claims to `local_height + 10_000` and stored that
    /// clamped value as the peer's "known" height, then propagated it
    /// into `best_known_height` (surfaced as `target_height` in the RPC
    /// `get_info` response). The clamped value then re-advertised to
    /// other peers on subsequent handshakes, perpetuating a phantom
    /// `target = local + 10_000` across the fleet — observable as a
    /// consistent +10_000 offset between actual height and reported
    /// target_height, surviving node restarts because peers
    /// re-poisoned each other on reconnect.
    ///
    /// This test exercises the exact behaviour change: the peer height
    /// table must NOT contain a clamped substitute for an oversized
    /// claim, AND `best_known_height` must not be bumped to the clamped
    /// value.
    #[test]
    fn regression_2026_06_06_phantom_plus_10k() {
        let mut sync = ChainSync::new(2_776, Hash::zero());
        let peer = super::super::peer::generate_peer_id();

        // Bogus claim — 100× our local height. Pre-hotfix would have
        // stored peer's height as 2_776 + 10_000 = 12_776 and bumped
        // best_known_height to 12_776. Post-hotfix: reject.
        sync.update_peer_height_for(peer, 277_600);

        // Peer height table must not contain a clamped substitute.
        assert!(
            !sync.peer_heights.contains_key(&peer),
            "rejected peer height must not appear in peer_heights at all \
             (pre-hotfix bug stored a clamped 12_776 here)"
        );

        // best_known_height must NOT have absorbed the clamped value.
        assert!(
            sync.best_known_height < 12_776,
            "rejected peer height must not bump best_known_height to the \
             clamped value (pre-hotfix bug bumped this to local + 10_000 \
             which then propagated through gossip and surfaced as the \
             phantom target_height in RPC get_info)"
        );

        // Legitimate-but-aggressive claim (right at the edge of the
        // cap) should still be accepted — this is the case the cap
        // was originally designed to allow (fresh-IBD peers slightly
        // ahead of us).
        let legit_peer = super::super::peer::generate_peer_id();
        sync.update_peer_height_for(legit_peer, 2_776 + 10_000);
        assert_eq!(
            sync.peer_heights.get(&legit_peer).copied(),
            Some(12_776),
            "claim at exactly local + 10_000 is still legitimate and \
             must be stored verbatim"
        );

        // And the `update_peer_height` variant (no peer_id) must
        // exhibit the same reject behaviour.
        let mut sync2 = ChainSync::new(2_776, Hash::zero());
        sync2.update_peer_height(277_600);
        assert!(
            sync2.best_known_height < 12_776,
            "update_peer_height must reject oversized claims same as \
             update_peer_height_for"
        );
    }
}
