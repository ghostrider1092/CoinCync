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
/// Per-peer orphan-block cap.
///
/// SECURITY (2026-07-05 audit F24 — SEV-A, same class as F1 OrphanFlood
/// and F0 MissingParent): Pre-audit this was `50`. During a legitimate
/// deep reorg (like the 2026-07-04 partition where randomx-2 mined a
/// 628-block heavier canonical chain) the peer serving the fork tip
/// sends every intermediate block as an "orphan" from our current-tip
/// vantage point. First 50 orphans stored, remaining 578 SILENTLY
/// DROPPED at the check in `on_block_received_from` (returned `Ok(vec![])`
/// with no log). The reorg could never complete because we never
/// accepted enough of the fork to backfill parents.
///
/// This is the third self-defeating-gate bug found in the peer-punishment
/// / sync surface this audit round (F0 MissingParent → PR #154, F1
/// OrphanFlood → PR #155, F24 = this).
///
/// **Reference-implementation shape (specific identifiers UNVERIFIED
/// this session):** reference orphan-pool designs typically use total-
/// pool caps + eviction (LRU/FIFO/random) rather than per-peer caps.
/// The specific per-project method / class names I cited pre-fix
/// (`AddOrphanTx`, `LimitOrphans`, `m_orphaned_by_prev_id`) were not
/// re-confirmed against current upstream sources this session, so the
/// specific identifier citations have been removed rather than
/// perpetuated without receipts.
///
/// **Why the pre-audit value was 50**: appears to be a DoS heuristic
/// intended to prevent one peer from filling the entire pool. BUT the
/// TOTAL pool cap (`MAX_ORPHAN_BLOCKS = 1000` + LRU-oldest eviction at
/// `on_block_received_from` line ~547) already provides that
/// protection. The per-peer cap was defense-in-depth that BOTH:
///   * failed to prevent DoS (LRU already does that better)
///   * created a new attack surface (silent-drop → chain-stall)
///
/// **Post-fix value**: `usize::MAX` — effectively unbounded per-peer.
/// The check `orphans_per_peer[p] >= MAX_ORPHANS_PER_PEER` becomes
/// impossible to trigger, so orphans are accepted up to the total-pool
/// cap and evicted by LRU as designed.
///
/// The `orphans_per_peer` counter itself is retained (unchanged in
/// this fix — see `on_block_received_from` and the resolution-decrement
/// path) so any future PR that adds cause-based DoS mitigation (e.g.,
/// "peer sent orphans AND refused to deliver requested parents") has
/// the tracking already wired.
///
/// See `project_hard_finality_partition_2026_07_04.md` in the memory
/// index for the incident this closes.
const MAX_ORPHANS_PER_PEER: usize = usize::MAX;

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
    /// The peer that originally sent us this orphan.
    ///
    /// AUDIT (2026-07-01): added so the resolution path can decrement the
    /// correct peer's `orphans_per_peer` counter. Prior to this field, the
    /// decrement in `on_block_received_from` at ~L466 read the CURRENT
    /// caller's `from` argument — i.e. the peer that supplied the PARENT
    /// block that resolved the orphan — which is not necessarily the peer
    /// that originally sent the orphan. Concrete misbehavior: peer A
    /// sends 100 orphans and hits `MAX_ORPHANS_PER_PEER`; peer B later
    /// sends the parent chain that resolves them; the decrements land on
    /// B's counter (which was ~zero) and A's counter stays pinned at 100
    /// for the whole connection, blocking A from sending any further
    /// orphans even though every orphan it sent has been reconciled.
    /// Storing the origin peer here lets the resolver credit the right
    /// counter.
    from: Option<PeerId>,
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
    /// v1.0.13 #4 — per-peer attribution for queued headers.
    ///
    /// Tracks which peer queued each pending-header hash so we can
    /// (a) decrement the per-peer counter on pop, and (b) cap each
    /// peer's share of the 50K-slot pool. Without this, ONE attacker
    /// peer that wins the GetHeaders nonce race can fill the entire
    /// pool with bogus header hashes, blocking legitimate peers'
    /// headers until the pool drains via downloading timeouts.
    ///
    /// Self-attributed re-queue paths (orphan recovery,
    /// recover_timed_out, block-received re-queue) do NOT insert
    /// into this map — they re-queue hashes ALREADY counted, or
    /// queue internally-generated hashes that aren't a peer-flood
    /// vector.
    pending_header_peer: HashMap<Hash, PeerId>,
    /// v1.0.13 #4 — per-peer pending-header count, capped at
    /// MAX_HEADERS_PER_PEER. Kept in sync with `pending_header_peer`
    /// — invariant: count == pending_header_peer values matching this peer.
    headers_per_peer: HashMap<PeerId, usize>,
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
    // Phase 2a (V3 partial): per-peer total cumulative difficulty.
    // Populated by `update_peer_difficulty_for`, called when we observe
    // a block (announce or response) from `peer` with a known total work.
    // Currently advisory — peer selection still uses height. Phase 2b
    // (v1.0.12 protocol bump) will introduce a wire-format handshake
    // field carrying this value at connection time, at which point peer
    // trust switches from height to cumulative difficulty.
    //
    // Why difficulty, not height? Bitcoin Core, zebrad (Zcash), and
    // bitcoin-rs all select the canonical chain by cumulative work, not
    // longest-by-count. A peer on a shorter but higher-difficulty fork
    // is on the better chain. Height-based selection is correct only in
    // honest-majority chains with stable difficulty; under fork stress
    // it's a known failure mode (V3 in the state-machine doc).
    peer_difficulties: HashMap<PeerId, u128>,
    best_known_difficulty: u128,
    /// Our own tip's cumulative work, fed by `set_local_total_difficulty`
    /// on every tip advance. This is the baseline peer work-claims are
    /// compared against: a peer with MORE work than this is a sync target
    /// even when it is shorter in height (Firework Phase 2 / V3 closure).
    local_total_difficulty: u128,
    /// Firework Phase 2 anti-wedge: last time (unix secs) we received a
    /// ChainWork claim from each peer. A claim not refreshed within
    /// `WORK_CLAIM_TTL_SECS` is dropped by `expire_stale_work_claims`, so a
    /// peer that sent one bogus over-claim and went quiet cannot pin
    /// `is_synced=false` forever (the substantiation timeout that makes the
    /// work-aware `synced` flag wedge-safe).
    peer_difficulty_seen_at: HashMap<PeerId, u64>,
}

/// Firework Phase 2: a peer work-claim not refreshed within this many
/// seconds is dropped (`expire_stale_work_claims`). Must comfortably exceed
/// the block interval so an honest heavier peer's periodic ChainWork
/// re-advertisements keep its claim fresh — 5× the 120 s target block time.
pub const WORK_CLAIM_TTL_SECS: u64 = 600;

/// v1.0.13 #4 — per-peer cap on pending-headers entries. 10% of the
/// 50K-slot pool means a flood from any one peer can't displace more
/// than 5000 legitimate headers from other peers. Picked to be:
/// - low enough that one peer can't dominate the pool
/// - high enough that a legitimate IBD GetHeaders response
///   (MAX_HEADERS_RESPONSE = 2000) fits with headroom for in-flight
///   pending entries from that same peer
pub const MAX_HEADERS_PER_PEER: usize = 5_000;

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
            pending_header_peer: HashMap::new(),
            headers_per_peer: HashMap::new(),
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
            peer_difficulties: HashMap::new(),
            best_known_difficulty: 0,
            local_total_difficulty: 0,
            peer_difficulty_seen_at: HashMap::new(),
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
        // V1/V2 closure (Phase 2/3 refactor, see docs/architecture/sync-state-machine.md):
        // When local advances, any peer whose claimed height is now <= local
        // is announcing a stale view. Prune those entries so they cannot
        // pin best_known above local indefinitely (the chronic stall bug).
        // Make the pruning explicit by removing the entry, not merely
        // ignoring it.
        self.prune_stale_peer_heights();
        // I2/I3 enforcement: best_known_height must equal
        // max(local_height, max(peer_heights.values())). Re-derive from
        // scratch rather than only-grow, so the field can SHRINK when peers
        // disconnect or local overtakes them. Bitcoin Core takes a similar
        // approach with `m_best_header` (validation.h:1078 in the master
        // read this session) — the value is refreshed via
        // `RecalculateBestHeader()` (validation.h:1366) rather than
        // treated as a monotonic latch.
        self.refresh_best_known();
        if self.local_height >= self.best_known_height
            && self.pending_headers.is_empty() && self.downloading.is_empty() {
            self.state = SyncState::Synced;
        }
    }

    /// Drop peer entries whose claimed height is at-or-below our local
    /// height. Such claims are stale — either the peer was lagging and we
    /// caught up, or it sent us a header chain we've now fully ingested.
    /// In both cases the entry contributes no useful work and risks
    /// pinning `best_known_height` (and downstream RPC `target_height`)
    /// above us indefinitely. Closes V2.
    fn prune_stale_peer_heights(&mut self) {
        let local = self.local_height;
        self.peer_heights.retain(|_, h| *h > local);
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
        // Drop stale-on-arrival claims: a peer announcing height <= local
        // is reporting work we've already absorbed. Inserting it would
        // immediately be pruned by `prune_stale_peer_heights` anyway; skip.
        if height <= self.local_height {
            // Still remove any prior (now-stale) entry for this peer.
            self.peer_heights.remove(&peer_id);
            self.refresh_best_known();
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
        // I2 enforcement: best_known must not drop below local. Use
        // recompute path so the field can be reduced if this anonymous
        // update was the only thing holding it above the peer-set max.
        if height > self.best_known_height { self.best_known_height = height; }
        if self.best_known_height < self.local_height {
            self.best_known_height = self.local_height;
        }
    }

    /// Phase 2a (V3 partial): record observed cumulative difficulty for a
    /// peer. Currently advisory. Drops claims at-or-below local total work
    /// (mirrors `prune_stale_peer_heights` semantics for the difficulty
    /// signal). Once Phase 2b wire-format lands, this is the canonical
    /// signal for peer selection.
    pub fn update_peer_difficulty_for(&mut self, peer_id: PeerId, total_difficulty: u128) {
        // Reject obviously-bogus claims: a peer cannot have more than 2x
        // the highest difficulty we've observed elsewhere, OR a fixed
        // floor for the bootstrap case. This is the difficulty analogue
        // of the height +10_000 reject in `update_peer_height_for`.
        const BOGUS_FACTOR: u128 = 2;
        let observed_max = self.peer_difficulties.values().copied().max()
            .unwrap_or(self.best_known_difficulty);
        let cap = observed_max.saturating_mul(BOGUS_FACTOR).max(1u128 << 60);
        if total_difficulty > cap {
            return;
        }
        // Drop stale-on-arrival claims at-or-below our own work: such a peer
        // is not a sync target and would be pruned by the next
        // set_local_total_difficulty anyway. Still remove any prior (now
        // stale) entry for this peer and recompute so best_known can shrink.
        if total_difficulty <= self.local_total_difficulty {
            self.peer_difficulties.remove(&peer_id);
            self.peer_difficulty_seen_at.remove(&peer_id);
            self.recompute_best_difficulty();
            return;
        }
        self.peer_difficulties.insert(peer_id, total_difficulty);
        self.peer_difficulty_seen_at.insert(peer_id, unix_now());
        self.recompute_best_difficulty();
        // Firework Phase 2 / V3 closure: a peer with MORE cumulative work
        // than us is on the better chain even when it is SHORTER in height,
        // which height-based selection can never discover. Flip into Headers
        // so the maintenance loop sends a locator-based GetHeaders to a
        // scored peer; fork choice then reorgs if the branch really is
        // heavier. Mirror of the height-triggered transition in
        // update_peer_height_for. Only interrupt a settled state — an
        // in-flight Headers/Blocks cycle already covers this.
        if matches!(
            self.state,
            SyncState::Synced | SyncState::Idle | SyncState::ConfirmingSynced
        ) {
            self.state = SyncState::Headers;
            self.headers_request_time = None;
            self.headers_received_this_cycle = false;
        }
    }

    /// Record our local cumulative difficulty. Called when the local tip
    /// advances (via `set_chain_state`).
    pub fn set_local_total_difficulty(&mut self, total_difficulty: u128) {
        self.local_total_difficulty = total_difficulty;
        // Prune stale peer claims at-or-below our own work (mirrors
        // prune_stale_peer_heights on the height side).
        self.peer_difficulties.retain(|_, d| *d > total_difficulty);
        // Keep the seen-at map in lock-step so it can't leak or resurrect a
        // pruned claim. Collect live keys first to avoid a self borrow clash.
        let live: HashSet<PeerId> = self.peer_difficulties.keys().copied().collect();
        self.peer_difficulty_seen_at.retain(|p, _| live.contains(p));
        // True recompute so best_known_difficulty can SHRINK as we advance
        // or as claims are pruned. A ratchet here would let a stale high
        // claim pin us as "behind on work" forever — the difficulty
        // analogue of the phantom-target height wedge (see refresh_best_known).
        self.recompute_best_difficulty();
    }

    /// Best peer by cumulative work — call this once Phase 2b is live;
    /// today's IBD loop still uses height-based selection.
    pub fn best_peer_by_difficulty(&self) -> Option<(PeerId, u128)> {
        self.peer_difficulties.iter().max_by_key(|(_, d)| *d).map(|(p, d)| (*p, *d))
    }

    pub fn best_known_difficulty(&self) -> u128 { self.best_known_difficulty }

    /// Re-derive `best_known_difficulty` as
    /// `max(local_total_difficulty, max(peer_difficulties))`.
    ///
    /// A TRUE recompute (can shrink), NOT a ratchet — the prior
    /// `peer_max.max(self.best_known_difficulty)` form could only grow, so a
    /// single stale/bogus high claim latched `best_known_difficulty` above
    /// local forever. That is the exact wedge the height side hit with
    /// `refresh_best_known` (see its post-mortem doc-comment).
    fn recompute_best_difficulty(&mut self) {
        let peer_max = self.peer_difficulties.values().copied().max().unwrap_or(0);
        self.best_known_difficulty = self.local_total_difficulty.max(peer_max);
    }

    /// Re-derive `best_known_height` from current state as
    /// `max(local_height, max(peer_heights))`.
    ///
    /// ## Why this is a true recompute, not a ratchet
    ///
    /// 2026-06-27 fix for the production "phantom target_height pins
    /// the chain forever" bug. Previously this was implemented as:
    ///
    ///     if pm > self.best_known_height { self.best_known_height = pm; }
    ///
    /// which is a one-way RATCHET: best_known could only grow, never
    /// shrink. The documented v1.0.11.6 refactor invariant V1
    /// ("best_known_height re-derived from max(local, max(peers)) on
    /// every state mutation") was not actually enforced — every caller
    /// of refresh_best_known got the ratchet behavior, NOT the recompute
    /// the invariant promised.
    ///
    /// Production failure mode: a peer sends an InvBlock for a block
    /// hash we don't have. node.rs:3312 speculatively bumps that peer's
    /// tracked height to `our_h + 1` via update_peer_height_for, which
    /// calls refresh_best_known. best_known_height jumps from local to
    /// local+1. We request the block via GetBlocks. The request times
    /// out (peer doesn't actually have the block, or it's an orphan-fork
    /// remnant). We never receive the block. local stays at N. With the
    /// ratchet behavior:
    ///   - peer_heights[bad_peer] = N+1
    ///   - best_known_height = N+1 (was N before the InvBlock, latched)
    ///   - is_synced() = (local >= true_best) = (N >= N+1) = false
    ///   - rig sees is_synced=false → refuses to mine
    ///   - chain wedged
    /// Even AFTER the bad peer disconnected, on_peer_disconnected called
    /// peer_heights.remove() but DID NOT call refresh_best_known —
    /// because the ratchet would have been a no-op anyway. So
    /// best_known stayed at N+1 forever, even with peer_heights empty.
    ///
    /// True recompute fixes all of these:
    ///   - Adding a higher peer_heights entry: best_known goes up
    ///   - Removing the high-water-mark peer: best_known recomputes
    ///   - All peers disconnect: best_known falls back to local
    ///   - local advances past stale peer entries: best_known follows
    ///
    /// Bitcoin Core does exactly this in CNodeState::nLastBlockAnnounced
    /// + PeerLogicValidation::FindNextBlocksToDownload: peer-height
    /// state is re-evaluated from current members on every relevant
    /// event, no latches.
    fn refresh_best_known(&mut self) {
        let pm = self.peer_heights.values().copied().max().unwrap_or(0);
        self.best_known_height = self.local_height.max(pm);
    }

    pub fn true_best_height(&self) -> u64 {
        self.best_known_height.max(self.peer_heights.values().copied().max().unwrap_or(0))
    }

    pub fn remove_peer_height(&mut self, peer_id: &PeerId) {
        self.peer_heights.remove(peer_id);
        self.peer_difficulties.remove(peer_id);
        self.peer_difficulty_seen_at.remove(peer_id);
        // Departing peer was potentially the sole holder of the highest
        // claimed height/difficulty; recompute both so best_known_*
        // shrinks when appropriate (I3 closure).
        self.refresh_best_known();
        self.recompute_best_difficulty();
    }

    /// Reconcile peer height/work state against the live connected-peer set.
    ///
    /// `peer_heights`/`peer_difficulties` are populated on handshake + block
    /// announcements, but were only pruned on LOCAL ADVANCE
    /// (`prune_stale_peer_heights`) or an explicit `remove_peer_height` at
    /// disconnect. If a peer advertised a high tip and then vanished WITHOUT
    /// a cleanly-detected disconnect while our own tip was frozen, its stale
    /// entry pinned `best_known_height` above local indefinitely →
    /// `is_synced()` false → the miner refused to mine → the tip stayed
    /// frozen: a self-reinforcing deadlock that only a node restart could
    /// break. Observed 2026-07-08 on `randomx` (target pinned at a departed
    /// peer's 10551 while local sat at 10042). Pruning to the connected set
    /// every maintenance tick lets a frozen node shed a departed peer's stale
    /// target and self-heal. Closes the V2/V3 connection-lifecycle gap in
    /// docs/architecture/sync-state-machine.md. Returns the number pruned.
    pub fn retain_connected_peers(&mut self, connected: &HashSet<PeerId>) -> usize {
        let before = self.peer_heights.len();
        self.peer_heights.retain(|p, _| connected.contains(p));
        self.peer_difficulties.retain(|p, _| connected.contains(p));
        self.peer_difficulty_seen_at.retain(|p, _| connected.contains(p));
        let pruned = before.saturating_sub(self.peer_heights.len());
        if pruned > 0 || !self.peer_difficulties.is_empty() {
            self.refresh_best_known();
            self.recompute_best_difficulty();
        }
        pruned
    }

    /// Firework Phase 2 anti-wedge: drop peer work-claims not refreshed
    /// within `ttl` seconds. An honest heavier peer re-advertises ChainWork
    /// on every tip advance, so its claim stays fresh; a peer that sent one
    /// bogus over-claim and went quiet has its claim expire here, letting
    /// `best_known_difficulty` recompute down so `is_synced` can recover.
    /// Together with the sync-ban claim-drop (persistent non-deliverer) and
    /// the overtake/disconnect prunes, this bounds the work-behind wedge.
    /// Call from the sync maintenance tick. Returns the number dropped.
    pub fn expire_stale_work_claims(&mut self, now: u64, ttl: u64) -> usize {
        let cutoff = now.saturating_sub(ttl);
        let stale: Vec<PeerId> = self
            .peer_difficulty_seen_at
            .iter()
            .filter(|(_, &seen)| seen < cutoff)
            .map(|(p, _)| *p)
            .collect();
        for p in &stale {
            self.peer_difficulties.remove(p);
            self.peer_difficulty_seen_at.remove(p);
        }
        if !stale.is_empty() {
            self.recompute_best_difficulty();
        }
        stale.len()
    }

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

    /// Legacy entry point for self-attributed header queueing (no
    /// peer flood vector — used by internal recovery paths). External
    /// peer responses go through `queue_headers_from_peer` for v1.0.13
    /// per-peer accounting.
    pub fn queue_headers(&mut self, headers: Vec<Hash>) {
        self.queue_headers_inner(headers, None);
    }

    /// v1.0.13 #4 — attributed header queueing.
    ///
    /// Use this for headers received via a peer's Headers response.
    /// Enforces a per-peer cap (MAX_HEADERS_PER_PEER) so a single
    /// peer can't fill the 50K-slot pool and starve other peers.
    pub fn queue_headers_from_peer(&mut self, peer: PeerId, headers: Vec<Hash>) {
        self.queue_headers_inner(headers, Some(peer));
    }

    fn queue_headers_inner(&mut self, headers: Vec<Hash>, peer: Option<PeerId>) {
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
        // v1.0.13 #4 — per-peer cap. Self-attributed (peer == None)
        // bypasses the cap because those paths re-queue hashes
        // already counted or queue internally-generated hashes.
        let peer_cap_room: Option<usize> = peer.map(|p| {
            let used = self.headers_per_peer.get(&p).copied().unwrap_or(0);
            MAX_HEADERS_PER_PEER.saturating_sub(used)
        });
        let mut added_for_peer = 0usize;
        for hash in headers {
            if self.pending_headers.len() >= MAX_PH { break; }
            if let Some(cap) = peer_cap_room {
                if added_for_peer >= cap { break; }
            }
            if !self.downloading.contains(&hash)
                && !self.orphan_blocks.contains_key(&hash)
                && !self.pending_header_peer.contains_key(&hash)
            {
                self.pending_headers.push_back(hash);
                if let Some(p) = peer {
                    self.pending_header_peer.insert(hash, p);
                    added_for_peer += 1;
                }
            }
        }
        if let Some(p) = peer {
            if added_for_peer > 0 {
                *self.headers_per_peer.entry(p).or_insert(0) += added_for_peer;
            }
        }
        if !self.pending_headers.is_empty() {
            self.state = SyncState::Blocks;
            if self.blocks_entered_at.is_none() { self.blocks_entered_at = Some(unix_now()); }
        }
    }

    /// v1.0.13 #4 — internal helper. Called when a pending-header
    /// hash is consumed (popped by get_blocks_to_request or removed
    /// by reset/clear). Decrements the attributed peer's counter.
    fn untrack_pending_header(&mut self, hash: &Hash) {
        if let Some(peer) = self.pending_header_peer.remove(hash) {
            match self.headers_per_peer.get_mut(&peer) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => { self.headers_per_peer.remove(&peer); }
                None => {} // shouldn't happen given the insert invariant
            }
        }
    }

    pub fn get_blocks_to_request(&mut self, max: usize) -> Vec<Hash> {
        let mut out = Vec::new();
        let slots = self.max_concurrent.saturating_sub(self.downloading.len());
        let now = unix_now();
        while out.len() < max.min(slots) && !self.pending_headers.is_empty() {
            if let Some(h) = self.pending_headers.pop_front() {
                // v1.0.13 #4 — decrement per-peer counter on pop.
                // Re-queue paths (push_front) leave attribution
                // intact so the counter stays accurate across them.
                self.untrack_pending_header(&h);
                if !self.downloading.contains(&h) {
                    out.push(h);
                    self.downloading.insert(h);
                    self.download_timestamps.insert(h, DownloadEntry { entered_at: now });
                }
            } else { break; }
        }
        out
    }

    /// Mark a block as in-flight from a specific peer.
    ///
    /// Closes V4 (downloading drift): this is the canonical mark-in-flight
    /// entry point and enforces that `downloading`, `download_timestamps`,
    /// and `pending_requests` all contain `hash` after the call. Bitcoin
    /// Core's `mapBlocksInFlight` (net_processing.cpp:960 in the master
    /// read this session) is a comparable unified map. The prior comment
    /// also cited `Monero block_queue::insert_span`, but this session's
    /// read of Monero `block_queue` shows methods `add_blocks`,
    /// `remove_span`, `remove_spans` — no `insert_span` — so that
    /// reference has been dropped rather than perpetuated.
    ///
    /// Idempotent: safe to call repeatedly; updates the peer/timestamp on
    /// re-call (the most recent request wins for timeout accounting).
    pub fn record_request(&mut self, hash: Hash, peer: PeerId, ts: u64) {
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS
            && !self.pending_requests.contains_key(&hash)
        {
            if let Some(k) = self.pending_requests.iter().min_by_key(|(_, r)| r.requested_at).map(|(h, _)| *h) {
                self.pending_requests.remove(&k);
                // Evicted from pending_requests but the in-flight set must
                // shed it too — else `downloading`/`download_timestamps`
                // leak entries forever.
                self.downloading.remove(&k);
                self.download_timestamps.remove(&k);
            }
        }
        // I8 enforcement: ensure all three collections contain `hash`.
        self.downloading.insert(hash);
        self.download_timestamps.entry(hash).or_insert(DownloadEntry { entered_at: ts });
        self.pending_requests.insert(hash, BlockRequest { hash, requested_from: peer, requested_at: ts });
        // Intentional carve-out from I10's strict reading:
        //
        //   We do NOT drop Synced→Blocks here.
        //
        // `record_request` is called both for IBD (Blocks state, fine) and
        // for InvBlock tip-catch-up (Synced state, peer announced 1-2 new
        // blocks above our tip — see node.rs:3171). The InvBlock case must
        // keep state=Synced because broadcasting is gated on Synced; if we
        // drop to Blocks for a single tip catch-up, broadcasts stall, which
        // is precisely the chronic stall bug. Bitcoin Core makes the same
        // distinction: `IsInitialBlockDownload()` returns false during tip
        // catch-up even with one block in flight.
        //
        // I10 is therefore refined: Synced tolerates a SMALL number of
        // in-flight blocks (≤ INV_CATCHUP_DOWNLOAD_TOLERANCE), but
        // pending_headers must still be empty (that's IBD, not catch-up).
        // Checked in the proptest harness via `check_i10_refined`.
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
                                let origin = o.from;
                                out.push(o.block);
                                q.push_back(rh);
                                // FIX: Decrement orphans_per_peer when orphans are resolved.
                                // Previously the counter was only incremented, never decremented
                                // on resolution — peers were penalized indefinitely.
                                //
                                // AUDIT (2026-07-01): use the ORIGIN peer (stored on
                                // OrphanBlock.from), not the current caller's `from`
                                // argument. The caller's `from` is the peer that just
                                // supplied the PARENT block, which is typically not
                                // the peer that sent this orphan. Crediting the wrong
                                // peer left honest orphan-senders permanently pinned
                                // at MAX_ORPHANS_PER_PEER even after every orphan they
                                // sent had been reconciled through the network.
                                if let Some(pid) = origin {
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
        self.orphan_blocks.insert(bh, OrphanBlock { block, received_at: now, from });
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

    /// IBD orphan-recovery (fixes the "wedge at one height" bug 2026-05-02
    /// + the "200-block-deep gossip-orphan loop" bug 2026-06-17):
    ///
    /// When a block comes back from chain validation as `Orphan` it means
    /// we don't have its parent. Re-requesting the orphan itself causes
    /// the same peer to keep handing it back — chain never advances.
    /// Instead, drop the orphan from active tracking and queue its PARENT
    /// hash for fetch. When the parent arrives and processes successfully,
    /// the orphan pool is drained forward via `on_block_received_from`'s
    /// queue walk (lines ~386-407), replaying the orphan immediately.
    ///
    /// **Body required, not just hashes.** The 2026-05-02 minimal-fix
    /// version of this function took only hashes and trusted gossip to
    /// re-deliver the orphan body after the parent connected. That was
    /// wrong for the 200-block-deep case observed 2026-06-17:
    ///
    /// 1. Miner extends chain from height H by ~200 blocks alone (peer
    ///    gossip in-flight but never queueing into the orphan pool with
    ///    bodies — the hashes-only fix path is taken)
    /// 2. Fleet node receives N+1 via gossip → Orphan (we lack N)
    /// 3. Fleet node drops the body, queues N for fetch
    /// 4. Fleet node receives N via gossip → Orphan (we lack N-1)
    /// 5. Goto 3 with N-1
    /// 6. Eventually we fetch all the way down to H — but by then we
    ///    no longer have any of the bodies for H+1..N. Gossip doesn't
    ///    re-deliver them (peer thinks we have them; we requested them
    ///    once and ack'd receipt). Chain stuck at H forever.
    ///
    /// The fix: store the orphan body in `orphan_blocks` at receive time,
    /// keyed by hash + indexed by parent. When the parent walks the
    /// chain forward via on_block_received_from's drain loop, each
    /// pooled orphan is replayed in order. No second gossip required.
    ///
    /// Eviction is LRU by `received_at`, capped at `MAX_ORPHAN_BLOCKS` —
    /// same policy as the IBD-path orphan storage. Per-peer caps via
    /// `MAX_ORPHANS_PER_PEER` prevent a single misbehaving peer from
    /// filling the pool with garbage.
    pub fn mark_block_orphan(&mut self, block: Block, from: Option<PeerId>, parent_hash: &Hash) {
        let orphan_hash = block.hash();

        // Stop tracking the orphan itself; we're not going to retry it.
        self.pending_requests.remove(&orphan_hash);
        self.downloading.remove(&orphan_hash);
        self.download_timestamps.remove(&orphan_hash);

        // Store the orphan body so the on_block_received_from drain
        // loop can replay it once the parent connects. Same storage
        // policy as the IBD-path orphan code (eviction by oldest
        // received_at, per-peer cap, parent index).
        let now = unix_now();
        if !self.orphan_blocks.contains_key(&orphan_hash) {
            // Evict oldest if pool is full.
            while self.orphan_blocks.len() >= MAX_ORPHAN_BLOCKS {
                if let Some(k) = self
                    .orphan_blocks
                    .iter()
                    .min_by_key(|(_, e)| e.received_at)
                    .map(|(k, _)| *k)
                {
                    if let Some(o) = self.orphan_blocks.remove(&k) {
                        let p = o.block.header.prev_hash;
                        if let Some(c) = self.orphan_by_parent.get_mut(&p) {
                            c.retain(|h| h != &k);
                            if c.is_empty() {
                                self.orphan_by_parent.remove(&p);
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            // Per-peer cap to bound flood damage.
            let admit = if let Some(pid) = from {
                let c = self.orphans_per_peer.entry(pid).or_insert(0);
                if *c >= MAX_ORPHANS_PER_PEER {
                    false
                } else {
                    *c += 1;
                    true
                }
            } else {
                true
            };
            if admit {
                let ph = block.header.prev_hash;
                self.orphan_by_parent.entry(ph).or_default().push(orphan_hash);
                self.orphan_blocks
                    .insert(orphan_hash, OrphanBlock { block, received_at: now, from });
            }
        }

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
            "Orphan {} → fetching parent {} (pool: {} blocks)",
            &orphan_hash.to_hex()[..16],
            &parent_hash.to_hex()[..16],
            self.orphan_blocks.len(),
        );
    }

    pub fn on_block_processed(&mut self, hash: Hash, height: u64) {
        self.local_height = height;
        self.local_tip = hash;
        // 2026-06-27 fix: re-derive best_known_height after local advance.
        // refresh_best_known computes max(local, max(peers)) so advancing
        // local naturally floors best_known up. Without this, an empty
        // peer_heights map would let best_known stay at a stale low
        // value from before; with the call, best_known tracks local
        // monotonically when no peer is ahead. Symmetric with the
        // peer-disconnect path.
        self.refresh_best_known();
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
        // P5-S3 SURGICAL FIX (2026-07-03): ban expiry uses `now`
        // (unix_now()) not `req.requested_at`. Prior code inserted
        // `req.requested_at + 300`, meaning if we processed a
        // long-stale request (e.g. pending_requests wasn't checked
        // for hours), the ban expired IMMEDIATELY upon insertion.
        // Bans should always be 5 minutes FROM NOW.
        if let Some(req) = self.pending_requests.remove(hash) {
            let c = self.peer_failures.entry(req.requested_from).or_insert(0);
            *c += 1;
            if *c >= 3 {
                let now = unix_now();
                self.sync_banned_peers.insert(req.requested_from, now + 300);
                self.peer_failures.remove(&req.requested_from);
                // Firework Phase 2 anti-wedge: a peer that fails to deliver
                // blocks has not substantiated any work claim it made. Drop
                // its claim so best_known_difficulty recomputes down and a
                // bogus over-claim cannot pin is_synced=false past the point
                // the peer is proven unreliable.
                self.peer_difficulties.remove(&req.requested_from);
                self.peer_difficulty_seen_at.remove(&req.requested_from);
                self.recompute_best_difficulty();
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

    /// Whether a headers request is currently outstanding.
    ///
    /// Callers should NOT issue a new `GetHeaders` while this returns true —
    /// the in-flight one is either still serving (gets responded to within
    /// the timeout window) or will be reset by `headers_timed_out` →
    /// `reset_headers_timeout` on the next tick.
    ///
    /// Added 2026-06-10 to fix the request-flood pathology that was
    /// emitting ~4 GetHeaders/sec against a single peer for 8 hours while
    /// stuck on a fork. The IBD tick loop checked `headers_timed_out` but
    /// not whether a request was *currently pending*, so it sent a fresh
    /// one every tick regardless of in-flight state. See
    /// `docs/crucible/cycle-01/finding-03-headers-request-flood.md`.
    pub fn headers_request_pending(&self) -> bool {
        self.headers_request_time.is_some()
    }

    pub fn reset_headers_timeout(&mut self) {
        // P5-S2 SURGICAL FIX (2026-07-03): also clear pending_header_nonces.
        // Pre-fix code left un-responded nonces in the set forever
        // (validate_header_nonce removes on RESPONSE, but a timed-out
        // request never got a response). Nonces are single-use per
        // headers-request cycle, so on cycle reset we can safely drop
        // every pending nonce — the next allocate_header_nonce() gets
        // a fresh strict-monotonic value.
        self.headers_request_time = None;
        self.pending_header_nonces.clear();
    }
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
            local_total_difficulty: self.local_total_difficulty,
            best_known_difficulty: self.best_known_difficulty,
        }
    }

    pub fn requeue_failed(&mut self, hashes: Vec<Hash>) {
        let any = !hashes.is_empty();
        for h in hashes.into_iter().rev() {
            // I8 enforcement: clear from ALL three in-flight collections,
            // not just two. Even if record_request was already called for
            // this hash (e.g. partial-send race), the requeue path must
            // fully reset its in-flight state.
            self.downloading.remove(&h);
            self.download_timestamps.remove(&h);
            self.pending_requests.remove(&h);
            self.pending_headers.push_front(h);
        }
        // I10 enforcement: state == Synced ⇒ pending_headers.is_empty().
        // If we just pushed work back into pending_headers, we're no
        // longer synced — drop to Blocks.
        if any && self.state == SyncState::Synced {
            self.state = SyncState::Blocks;
            if self.blocks_entered_at.is_none() { self.blocks_entered_at = Some(unix_now()); }
        }
    }

    /// Mark a direct (non-IBD) block request as in-flight. Retained for
    /// caller readability; semantically identical to `record_request` now
    /// that the latter enforces all-3-in-sync (V4 closure).
    pub fn track_direct_request(&mut self, hash: Hash, peer: PeerId, ts: u64) {
        self.record_request(hash, peer, ts);
    }

    pub fn clear(&mut self) {
        self.pending_requests.clear();
        self.orphan_blocks.clear();
        self.orphan_by_parent.clear();
        self.orphans_per_peer.clear();
        self.pending_headers.clear();
        // v1.0.13 #4 — keep peer attribution maps in sync.
        self.pending_header_peer.clear();
        self.headers_per_peer.clear();
        self.downloading.clear();
        self.download_timestamps.clear();
        // Phase 2a: also clear difficulty model on hard reset.
        // peer_heights/peer_difficulties are NOT cleared here — those
        // belong to the connection layer's view of peers and are reset
        // via on_peer_disconnected when connections actually drop.
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
        // I10 enforcement: pending_headers got new entries from either
        // timeout or stuck branch — if state was Synced (e.g. an InvBlock
        // catch-up request that timed out), drop to Blocks so the IBD
        // loop will re-issue them.
        if (!to.is_empty() || !stuck.is_empty()) && self.state == SyncState::Synced {
            self.state = SyncState::Blocks;
            if self.blocks_entered_at.is_none() { self.blocks_entered_at = Some(unix_now()); }
        }
        if sc > 0 {
            tracing::warn!("[SYNC] Recovered {} stuck downloads", sc);
            if sc >= 5 && self.state == SyncState::Blocks {
                self.state = SyncState::Headers;
                self.headers_received_this_cycle = false;
                self.headers_request_time = None;
                self.blocks_entered_at = None;
                self.pending_headers.clear();
                // v1.0.13 #4 — keep peer attribution maps in sync
                self.pending_header_peer.clear();
                self.headers_per_peer.clear();
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
        // I10 enforcement: pending_headers grew; if Synced, drop to Blocks.
        if c > 0 && self.state == SyncState::Synced {
            self.state = SyncState::Blocks;
            if self.blocks_entered_at.is_none() { self.blocks_entered_at = Some(unix_now()); }
        }
        c
    }

    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        // P5-S1 SURGICAL FIX (2026-07-03): drop peer_failures entry
        // for the departing peer. Pre-fix code left the counter
        // hanging, growing unbounded across long-running node
        // lifetimes with peer churn.
        self.peer_failures.remove(peer);
        self.peer_heights.remove(peer);
        self.peer_difficulties.remove(peer);
        self.orphans_per_peer.remove(peer);
        // Re-derive best_known after peer leaves (I3 closure — fixes the
        // case where the departing peer was the sole holder of the highest
        // claim and best_known would otherwise be pinned above local).
        self.refresh_best_known();
        self.recompute_best_difficulty();
        let rq: Vec<Hash> = self.pending_requests.iter()
            .filter(|(_, r)| &r.requested_from == peer).map(|(h, _)| *h).collect();
        for h in &rq {
            self.pending_requests.remove(h);
            self.downloading.remove(h);
            self.download_timestamps.remove(h);
            self.pending_headers.push_front(*h);
        }
        // I10 enforcement: pending_headers grew; if Synced, drop to Blocks.
        if !rq.is_empty() && self.state == SyncState::Synced {
            self.state = SyncState::Blocks;
            if self.blocks_entered_at.is_none() { self.blocks_entered_at = Some(unix_now()); }
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

    /// Re-arm a header pull for a NEAR-TIP node that is stuck mid-cycle.
    ///
    /// `trigger_resync` only fires from `Synced`/`Idle`, so a node that is a
    /// few blocks behind and sitting in `Headers`/`Blocks` with **nothing in
    /// flight** (its last cycle finished at a now-stale target) never re-pulls
    /// — it stays permanently behind, `is_synced()` stays false, and on a miner
    /// node that keeps the rig's sync gate latched shut ("refusing to mine"),
    /// dropping hashrate and stalling the chain (CIP-019, observed live
    /// 2026-07-11 on randomx-2). This re-arms to `Headers` **only when we are
    /// behind AND idle**, so a freshly-arrived `InvBlock` promptly closes the
    /// small gap. The idle guard (no pending headers, no downloads, no pending
    /// requests) means it can never disrupt an actively-progressing download,
    /// and because a re-arm immediately makes us non-idle, repeated InvBlocks
    /// can't churn the cycle. Non-consensus; affects only *when* we fetch.
    pub fn arm_near_tip_catchup(&mut self) -> bool {
        let idle = self.pending_headers.is_empty()
            && self.downloading.is_empty()
            && self.pending_requests.is_empty();
        if idle && !self.is_synced() {
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
    /// Firework Phase 2: our tip's cumulative work.
    pub local_total_difficulty: u128,
    /// Firework Phase 2: `max(local, best peer work-claim)`. Enforces I6 —
    /// `synced` should require `local_total_difficulty >= best_known_difficulty`.
    pub best_known_difficulty: u128,
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

    /// Regression test for the 2026-07-04 partition (F24 SEV-A).
    ///
    /// The pre-audit `MAX_ORPHANS_PER_PEER = 50` silently DROPPED any orphan
    /// past the 50th from a single peer. During a legitimate 628-block
    /// heavier-chain reorg (like the one randomx-2 delivered on 2026-07-04),
    /// the peer serving the fork tip would deliver every intermediate block
    /// as an orphan from our current-tip vantage point. First 50 stored,
    /// remaining 578 silently dropped, reorg never completed.
    ///
    /// Post-fix `MAX_ORPHANS_PER_PEER = usize::MAX` — no per-peer cap.
    /// Total-pool cap (`MAX_ORPHAN_BLOCKS = 1000`) + LRU eviction + TTL
    /// still provide DoS protection.
    ///
    /// This test simulates a peer submitting far more than 50 orphans and
    /// asserts they're all accepted (i.e., counted, not silently dropped),
    /// AND that `peer_orphan_limit_reached` never returns true for that
    /// peer no matter how many they submit.
    ///
    /// Same class as [[project_hard_finality_partition_2026_07_04.md]]
    /// (memory index) and PR #155 (F1 OrphanFlood).
    #[test]
    fn regression_2026_07_04_deep_reorg_orphan_cap() {
        let peer = super::super::peer::generate_peer_id();

        // Cap check: at any count the peer submits, limit-reached MUST be
        // false. Pre-audit at count=50 it would have flipped true and
        // subsequent orphans dropped.
        let counts_to_check: [usize; 5] = [0, 50, 100, 628, 1000];
        for count in counts_to_check {
            let mut sync = ChainSync::new(0, Hash::zero());
            // Directly poke the counter to simulate `count` prior orphans
            // from this peer without needing 1000 real Block objects.
            sync.orphans_per_peer.insert(peer, count);
            assert!(
                !sync.peer_orphan_limit_reached(&peer),
                "F24 regression: peer_orphan_limit_reached must NEVER return \
                 true no matter how many orphans a peer sent. Got true at \
                 orphans_per_peer={}. Pre-audit this returned true at 50, \
                 which caused the 2026-07-04 20hr fleet stall by silently \
                 dropping every orphan past the 50th during a 628-block \
                 reorg. If this test fails, MAX_ORPHANS_PER_PEER was reduced \
                 below usize::MAX — see the const doc-comment for the incident \
                 context.",
                count,
            );
        }

        // Also assert the constant itself hasn't been silently reduced.
        // A future refactor might tune it to something like 500 or 1000
        // "as a safety net" — that would re-introduce the F24 partition
        // risk for any reorg deeper than that value.
        assert_eq!(
            MAX_ORPHANS_PER_PEER,
            usize::MAX,
            "F24 regression: MAX_ORPHANS_PER_PEER must stay at usize::MAX. \
             Any lower value re-introduces the 2026-07-04 partition risk \
             for legitimate reorgs deeper than that cap. If a future DoS \
             concern arises, use cause-based mitigation (peer refused to \
             deliver parents) not per-peer count cap. See const doc-comment.",
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // PHASE 1: state-machine property tests
    //
    // Per `docs/architecture/sync-state-machine.md`, ChainSync has 13
    // numbered invariants (I1–I13) and 8 known violations (V1–V8). This
    // proptest harness generates random sequences of triggers (§3 of the
    // doc) and asserts invariants after each event.
    //
    // Tests that FAIL here document the known violations. Phase 2 + 3
    // code changes are scored against this harness: each fix should
    // close one or more failing properties.
    //
    // Test layout:
    //   - SyncEvent enum: one variant per externally-observable trigger
    //   - arb_event: proptest strategy mixing all event variants
    //   - apply_event: dispatches Event → ChainSync method call
    //   - invariant_*: one assert helper per invariant from §6
    //   - prop_*: one property test per invariant
    // ─────────────────────────────────────────────────────────────────────

    use proptest::prelude::*;

    /// Small peer pool: we use a fixed set of 5 PeerIds and index into them
    /// so the test generates collisions and re-asserts on the same peer
    /// (which is how the V2 bug manifests in production).
    fn peer_pool() -> Vec<PeerId> {
        (0..5u8).map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            bytes
        }).collect()
    }

    // ── Firework Phase 2 (V3 closure): work-triggered sync ──────────────

    /// A peer advertising MORE cumulative work than us must flip the sync
    /// state into Headers so we request its (possibly shorter) heavier
    /// branch. Core of the 2026-07-08 runaway-fork fix: a node on a
    /// higher-block/lower-work fork could never discover the honest heavier
    /// chain under height-only selection.
    #[test]
    fn heavier_peer_triggers_headers_even_when_settled() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.set_local_total_difficulty(1_000);
        sync.set_state(SyncState::Synced);
        sync.update_peer_difficulty_for(peers[0], 5_000); // heavier than us
        assert_eq!(sync.state(), SyncState::Headers,
            "a heavier-work peer must trigger a header sync");
        assert_eq!(sync.best_known_difficulty(), 5_000);
    }

    /// A peer at-or-below our own work is not a sync target: it must NOT
    /// flip us out of Synced, and its claim must be dropped.
    #[test]
    fn lighter_peer_does_not_trigger_and_is_dropped() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.set_local_total_difficulty(5_000);
        sync.set_state(SyncState::Synced);
        sync.update_peer_difficulty_for(peers[0], 4_000); // lighter than us
        assert_eq!(sync.state(), SyncState::Synced,
            "a lighter-work peer must not trigger a sync");
        assert_eq!(sync.best_peer_by_difficulty(), None,
            "a lighter-work claim must be dropped, not tracked");
    }

    /// Anti-wedge: `best_known_difficulty` is a TRUE recompute. A heavy
    /// claim raises it, but once the claiming peer leaves it must shrink
    /// back to our local work — otherwise a stale/bogus claim pins us
    /// "behind on work" forever (the difficulty analogue of the
    /// phantom-target height wedge).
    #[test]
    fn best_known_difficulty_shrinks_when_heavy_peer_leaves() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.set_local_total_difficulty(1_000);
        sync.update_peer_difficulty_for(peers[0], 9_000);
        assert_eq!(sync.best_known_difficulty(), 9_000);
        sync.remove_peer_height(&peers[0]); // peer disconnects
        assert_eq!(sync.best_known_difficulty(), 1_000,
            "best_known_difficulty must shrink to local work when the sole \
             heavy-claim peer disconnects (no ratchet)");
    }

    /// CIP-019 prompt near-tip catch-up. `arm_near_tip_catchup` re-arms a header
    /// pull for a node stuck a few blocks behind mid-cycle — the case where
    /// `trigger_resync` (which only fires from Synced/Idle) is a no-op and the
    /// node stays permanently behind, latching a miner's is_synced gate shut
    /// (the randomx-2 stall, 2026-07-11). Guarded so it never churns: no-op when
    /// synced, and no-op when a fetch is in flight.
    #[test]
    fn arm_near_tip_catchup_rearms_stuck_but_not_synced_or_active() {
        let peers = peer_pool();

        // (1) Behind + idle + mid-cycle (Blocks) → re-arms to Headers.
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.update_peer_height_for(peers[0], 103); // tip 3 ahead → is_synced=false
        sync.set_state(SyncState::Blocks);          // mid-cycle
        assert!(!sync.is_synced(), "node 3 behind must not be synced");
        assert!(!sync.trigger_resync(), "trigger_resync must be a no-op mid-cycle");
        assert!(sync.arm_near_tip_catchup(), "must re-arm a stuck near-tip node");
        assert_eq!(sync.state(), SyncState::Headers, "re-arm must return to Headers");

        // (2) Synced → no-op (never churn a caught-up node).
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.set_state(SyncState::Synced);
        assert!(sync.is_synced());
        assert!(!sync.arm_near_tip_catchup(), "synced node must not re-arm");

        // (3) Behind but a fetch IS in flight → no-op (no churn from repeated
        //     InvBlocks disrupting an actively-progressing download).
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.update_peer_height_for(peers[0], 103);
        sync.set_state(SyncState::Blocks);
        sync.queue_headers(vec![Hash::from_bytes([7u8; 32])]); // non-idle: pending_headers set
        assert!(!sync.is_synced());
        assert!(!sync.arm_near_tip_catchup(), "must not re-arm while a fetch is in flight");
    }

    /// Advancing our own work past a peer's claim prunes that claim.
    #[test]
    fn advancing_local_work_prunes_now_stale_peer_claims() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.set_local_total_difficulty(1_000);
        sync.update_peer_difficulty_for(peers[0], 3_000);
        assert!(sync.best_peer_by_difficulty().is_some());
        sync.set_local_total_difficulty(4_000); // we overtake the peer
        assert_eq!(sync.best_peer_by_difficulty(), None,
            "peer claims at-or-below our new work must be pruned");
        assert_eq!(sync.best_known_difficulty(), 4_000,
            "best_known_difficulty tracks our own work when no peer is heavier");
    }

    /// Anti-wedge (substantiation timeout): a work-claim not refreshed
    /// within the TTL is dropped, so a send-once bogus over-claim cannot pin
    /// best_known_difficulty above local — and thus is_synced=false — forever.
    #[test]
    fn stale_work_claim_expires_after_ttl() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.set_local_total_difficulty(1_000);
        let t0 = unix_now();
        sync.update_peer_difficulty_for(peers[0], 9_000);
        assert_eq!(sync.best_known_difficulty(), 9_000);
        // Long past the TTL with no refresh → claim expires.
        let dropped =
            sync.expire_stale_work_claims(t0 + WORK_CLAIM_TTL_SECS + 100, WORK_CLAIM_TTL_SECS);
        assert_eq!(dropped, 1);
        assert_eq!(sync.best_peer_by_difficulty(), None);
        assert_eq!(sync.best_known_difficulty(), 1_000,
            "best_known must recompute to local once the stale claim expires");
    }

    /// A freshly-received claim must survive an expiry pass — an honest
    /// heavier peer re-advertising ChainWork must not be dropped.
    #[test]
    fn fresh_work_claim_survives_expiry() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(100, Hash::zero());
        sync.set_local_total_difficulty(1_000);
        let t0 = unix_now();
        sync.update_peer_difficulty_for(peers[0], 9_000);
        let dropped = sync.expire_stale_work_claims(t0, WORK_CLAIM_TTL_SECS);
        assert_eq!(dropped, 0);
        assert_eq!(sync.best_known_difficulty(), 9_000);
    }

    /// Connection-lifecycle prune (2026-07-08 phantom-target deadlock): a
    /// departed peer's stale high height must be dropped when it is no longer
    /// in the connected set, so a FROZEN node's best_known recomputes down
    /// and it stops reporting "behind" a peer that is gone — self-healing the
    /// deadlock that previously needed a node restart.
    #[test]
    fn retain_connected_peers_drops_departed_peer_stale_target() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(10_042, Hash::zero());
        sync.update_peer_height_for(peers[0], 10_551); // high tip from a soon-departed peer
        assert_eq!(sync.true_best_height(), 10_551, "stale high target pins best-known");
        assert!(!sync.is_synced(), "node reports behind the peer");
        // Maintenance tick: peer[0] is no longer connected.
        let connected: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
        let pruned = sync.retain_connected_peers(&connected);
        assert_eq!(pruned, 1);
        assert_eq!(sync.true_best_height(), 10_042,
            "best-known recomputes to local once the departed peer is pruned");
        assert!(sync.is_synced(), "frozen node self-heals to synced");
    }

    /// A still-connected peer's advertised height must survive the prune.
    #[test]
    fn retain_connected_peers_keeps_connected_peer() {
        let peers = peer_pool();
        let mut sync = ChainSync::new(10_042, Hash::zero());
        sync.update_peer_height_for(peers[0], 10_600);
        let connected: std::collections::HashSet<PeerId> =
            [peers[0]].into_iter().collect();
        let pruned = sync.retain_connected_peers(&connected);
        assert_eq!(pruned, 0);
        assert_eq!(sync.true_best_height(), 10_600, "connected peer's height is retained");
    }

    /// Externally-observable triggers from §3 of the doc. Each variant
    /// maps to one of the public methods on ChainSync.
    #[derive(Debug, Clone)]
    enum SyncEvent {
        /// trigger: update_peer_height_for(peer_idx, height)
        PeerHeightUpdate { peer_idx: usize, height: u64 },
        /// trigger: update_peer_height(height) — the no-peer-id variant
        AnonHeightUpdate { height: u64 },
        /// trigger: set_local_tip(height, tip)
        LocalTipAdvance { delta: i32 },
        /// trigger: queue_headers(headers) — `count` random hashes
        QueueHeaders { count: u8 },
        /// trigger: remove_peer_height(peer_idx) on peer disconnect
        PeerDisconnect { peer_idx: usize },
        /// trigger: clear() — hard reset (rare)
        HardClear,
        /// trigger: get_blocks_to_request(max) — pop hashes into in-flight set
        GetBlocksToRequest { max: u8 },
        /// trigger: record_request(hash_idx, peer_idx, ts) — mark which peer owns hash
        RecordRequest { hash_seed: u8, peer_idx: usize },
        /// trigger: requeue_failed(hash_idx) — un-mark in-flight after send error
        RequeueFailed { hash_seed: u8 },
        /// trigger: track_direct_request — atomic mark-in-flight
        TrackDirectRequest { hash_seed: u8, peer_idx: usize },
        /// trigger: get_blocks_to_retry — timeout-driven re-issue
        GetBlocksToRetry { time_advance: u64 },
        /// trigger: recover_stuck_downloads — orphaned-entry sweep
        RecoverStuckDownloads,
    }

    /// proptest strategy mixing all event variants.
    fn arb_event() -> impl Strategy<Value = SyncEvent> {
        prop_oneof![
            // peer height updates dominate — that's where V1/V2 lived
            6 => (0usize..5, 0u64..2_000).prop_map(|(peer_idx, height)|
                SyncEvent::PeerHeightUpdate { peer_idx, height }),
            2 => (0u64..2_000).prop_map(|height|
                SyncEvent::AnonHeightUpdate { height }),
            // local tip advancement: occasionally retreat (reorg)
            3 => (-5i32..20).prop_map(|delta|
                SyncEvent::LocalTipAdvance { delta }),
            // block lifecycle — drives V4 surface
            3 => (1u8..15).prop_map(|count|
                SyncEvent::QueueHeaders { count }),
            3 => (1u8..10).prop_map(|max|
                SyncEvent::GetBlocksToRequest { max }),
            3 => (0u8..30, 0usize..5).prop_map(|(hash_seed, peer_idx)|
                SyncEvent::RecordRequest { hash_seed, peer_idx }),
            2 => (0u8..30).prop_map(|hash_seed|
                SyncEvent::RequeueFailed { hash_seed }),
            2 => (0u8..30, 0usize..5).prop_map(|(hash_seed, peer_idx)|
                SyncEvent::TrackDirectRequest { hash_seed, peer_idx }),
            1 => (1u64..120).prop_map(|time_advance|
                SyncEvent::GetBlocksToRetry { time_advance }),
            1 => Just(SyncEvent::RecoverStuckDownloads),
            1 => (0usize..5).prop_map(|peer_idx|
                SyncEvent::PeerDisconnect { peer_idx }),
            1 => Just(SyncEvent::HardClear),
        ]
    }

    /// Deterministic hash from a seed byte — lets two RecordRequest events
    /// reference the same hash if they share the same seed.
    fn hash_from_seed(seed: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = seed;
        b[31] = 0xAA;
        Hash::from_bytes(b)
    }

    /// Apply one event to the ChainSync.
    fn apply_event(sync: &mut ChainSync, event: &SyncEvent, peers: &[PeerId]) {
        match event {
            SyncEvent::PeerHeightUpdate { peer_idx, height } => {
                sync.update_peer_height_for(peers[*peer_idx], *height);
            }
            SyncEvent::AnonHeightUpdate { height } => {
                sync.update_peer_height(*height);
            }
            SyncEvent::LocalTipAdvance { delta } => {
                let new_height = (sync.local_height as i64 + *delta as i64).max(0) as u64;
                let mut tip_bytes = [0u8; 32];
                tip_bytes[..8].copy_from_slice(&new_height.to_le_bytes());
                sync.set_local_tip(new_height, Hash::from_bytes(tip_bytes));
            }
            SyncEvent::QueueHeaders { count } => {
                let local_byte = (sync.local_height & 0xFF) as u8;
                let headers: Vec<Hash> = (0..*count).map(|i| {
                    let mut b = [0u8; 32];
                    b[0] = i;
                    b[1] = local_byte;
                    Hash::from_bytes(b)
                }).collect();
                let _ = sync.queue_headers(headers);
            }
            SyncEvent::PeerDisconnect { peer_idx } => {
                sync.remove_peer_height(&peers[*peer_idx]);
            }
            SyncEvent::HardClear => {
                sync.clear();
            }
            SyncEvent::GetBlocksToRequest { max } => {
                let _ = sync.get_blocks_to_request(*max as usize);
            }
            SyncEvent::RecordRequest { hash_seed, peer_idx } => {
                sync.record_request(hash_from_seed(*hash_seed), peers[*peer_idx], 1000);
            }
            SyncEvent::RequeueFailed { hash_seed } => {
                sync.requeue_failed(vec![hash_from_seed(*hash_seed)]);
            }
            SyncEvent::TrackDirectRequest { hash_seed, peer_idx } => {
                sync.track_direct_request(hash_from_seed(*hash_seed), peers[*peer_idx], 1000);
            }
            SyncEvent::GetBlocksToRetry { time_advance } => {
                let _ = sync.get_blocks_to_retry(1000 + *time_advance);
            }
            SyncEvent::RecoverStuckDownloads => {
                let _ = sync.recover_stuck_downloads();
            }
        }
    }

    // ─── Invariant assertions ────────────────────────────────────
    // Each returns Ok(()) if invariant holds, Err(msg) otherwise.

    /// I2: best_known_height >= local_height at all times.
    fn check_i2(sync: &ChainSync) -> std::result::Result<(), String> {
        if sync.best_known_height < sync.local_height {
            Err(format!(
                "I2 VIOLATED: best_known_height={} < local_height={}",
                sync.best_known_height, sync.local_height,
            ))
        } else { Ok(()) }
    }

    /// I3: best_known_height == max(peer_heights.values()).max(local_height).
    /// NOTE: I3 is "should hold AT ALL TIMES." Pre-`e80a2df9`, only enforced
    /// after `set_local_tip` or `refresh_best_known`. Between those, drift
    /// is possible. This check is loose: it allows best_known_height to
    /// EXCEED the computed value (e.g., if it was set higher earlier and
    /// never decreased), but flags the inverse — being LOWER than computed.
    fn check_i3(sync: &ChainSync) -> std::result::Result<(), String> {
        let computed = sync.peer_heights.values().copied().max()
            .unwrap_or(0)
            .max(sync.local_height);
        if sync.best_known_height < computed {
            Err(format!(
                "I3 VIOLATED: best_known_height={} < computed max={} (peer heights={:?}, local={})",
                sync.best_known_height, computed,
                sync.peer_heights.values().copied().collect::<Vec<_>>(),
                sync.local_height,
            ))
        } else { Ok(()) }
    }

    /// I8 (corrected from initial doc draft):
    ///   I8a: `downloading.keys() == download_timestamps.keys()` (exact mirror)
    ///   I8b: `pending_requests.keys() ⊆ downloading.keys()` (subset; pending
    ///        may briefly be empty while downloading has the entry, since
    ///        get_blocks_to_request inserts into downloading but record_request
    ///        is called later per-peer in node.rs's IBD loop)
    ///
    /// References:
    ///   - Bitcoin Core uses a unified `mapBlocksInFlight: BlockHash → (peer,
    ///     time)` — no drift opportunity (src/net_processing.cpp).
    ///   - Monero `block_queue::insert_span` is similarly unified.
    /// We retain the 3-collection structure here but document and enforce
    /// the precise relationship so any new code path is audited against it.
    fn check_i8(sync: &ChainSync) -> std::result::Result<(), String> {
        let dl: std::collections::HashSet<_> = sync.downloading.iter().copied().collect();
        let ts: std::collections::HashSet<_> = sync.download_timestamps.keys().copied().collect();
        let pr: std::collections::HashSet<_> = sync.pending_requests.keys().copied().collect();
        if dl != ts {
            return Err(format!(
                "I8a VIOLATED: downloading.keys() ≠ download_timestamps.keys() \
                 (downloading={}, timestamps={}, sym_diff={})",
                dl.len(), ts.len(), dl.symmetric_difference(&ts).count(),
            ));
        }
        if !pr.is_subset(&dl) {
            let leak: Vec<_> = pr.difference(&dl).collect();
            return Err(format!(
                "I8b VIOLATED: pending_requests has {} hashes not in downloading: {:?}",
                leak.len(), leak.iter().take(3).collect::<Vec<_>>(),
            ));
        }
        Ok(())
    }

    /// I10 (refined): state == Synced ⇒ pending_headers.is_empty() AND
    /// downloading.len() ≤ INV_CATCHUP_DOWNLOAD_TOLERANCE.
    ///
    /// Original strict reading "downloading.is_empty() too" was incorrect
    /// because production InvBlock tip catch-up (node.rs:3171,
    /// track_direct_request) issues 1-2 GetBlocks from Synced state to
    /// fetch newly-announced tip blocks. Broadcasting is gated on Synced,
    /// so dropping to Blocks would stall broadcasts — that's the chronic
    /// stall pathology. Bitcoin Core makes the same distinction:
    /// `IsInitialBlockDownload()` stays false during small tip-fetches.
    ///
    /// pending_headers ≠ empty in Synced state remains a hard violation —
    /// pending_headers is only populated by `queue_headers`, which is the
    /// IBD-style multi-block discovery path, not tip catch-up.
    const INV_CATCHUP_DOWNLOAD_TOLERANCE: usize = 16;
    fn check_i10(sync: &ChainSync) -> std::result::Result<(), String> {
        if sync.state != SyncState::Synced { return Ok(()); }
        if !sync.pending_headers.is_empty() {
            return Err(format!(
                "I10 VIOLATED: state=Synced but pending_headers={}",
                sync.pending_headers.len(),
            ));
        }
        if sync.downloading.len() > INV_CATCHUP_DOWNLOAD_TOLERANCE {
            return Err(format!(
                "I10 VIOLATED: state=Synced but downloading={} > tolerance={}",
                sync.downloading.len(), INV_CATCHUP_DOWNLOAD_TOLERANCE,
            ));
        }
        Ok(())
    }

    /// Bonus: bounded growth of `peer_heights`.
    /// Should never exceed peer pool size (5) — only one entry per peer.
    fn check_peer_heights_bounded(sync: &ChainSync, max_peers: usize) -> std::result::Result<(), String> {
        if sync.peer_heights.len() > max_peers {
            Err(format!(
                "peer_heights.len()={} > max_peers={} (unbounded growth!)",
                sync.peer_heights.len(), max_peers,
            ))
        } else { Ok(()) }
    }

    /// Run all invariants. Returns Vec of (invariant_id, error) for any failures.
    fn check_all_invariants(sync: &ChainSync) -> Vec<(&'static str, String)> {
        let mut failures = Vec::new();
        if let Err(e) = check_i2(sync) { failures.push(("I2", e)); }
        if let Err(e) = check_i3(sync) { failures.push(("I3", e)); }
        if let Err(e) = check_i8(sync) { failures.push(("I8", e)); }
        if let Err(e) = check_i10(sync) { failures.push(("I10", e)); }
        if let Err(e) = check_peer_heights_bounded(sync, 5) { failures.push(("peer-pool-bound", e)); }
        failures
    }

    // ─── Properties ──────────────────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// Property: invariants hold after every event in a random sequence.
        ///
        /// This is the SINGLE-TEST harness. Any failing invariant produces
        /// a minimized counterexample sequence — invaluable for diagnosing
        /// which event order triggers which violation.
        ///
        /// Expected failures at Phase 1 (these document V1–V8 known bugs):
        ///   - I3: may show transient drift between events (V1)
        ///   - peer-pool-bound: may show growth past 5 if remove_peer_height
        ///     races with update_peer_height_for (V1)
        ///
        /// NOT EXPECTED to fail:
        ///   - I2 (post-`e80a2df9` should hold; if it fails, e80a2df9 was
        ///     insufficient — needs Phase 3 fix)
        ///   - I8 (downloading drift): no direct events in this harness
        ///     trigger it; needs a richer block-lifecycle event mix in a
        ///     follow-up proptest (Phase 1.5 — V4 closure)
        ///   - I10: should hold by construction in current code
        #[test]
        fn prop_invariants_hold_under_random_sequence(
            events in prop::collection::vec(arb_event(), 1..50)
        ) {
            let peers = peer_pool();
            let mut sync = ChainSync::new(0, Hash::zero());

            for (i, event) in events.iter().enumerate() {
                apply_event(&mut sync, event, &peers);
                let failures = check_all_invariants(&sync);
                if !failures.is_empty() {
                    let detail = failures.iter()
                        .map(|(id, msg)| format!("  {}: {}", id, msg))
                        .collect::<Vec<_>>()
                        .join("\n");
                    prop_assert!(
                        false,
                        "After event {}/{} ({:?}), invariants violated:\n{}\n\
                         Full sequence: {:?}",
                        i + 1, events.len(), event, detail, events,
                    );
                }
            }
        }

        /// Specific property for V2 (the recurring stall):
        /// After local advances past a peer's claimed height, that peer's
        /// entry should be pruned and best_known should drop.
        ///
        /// This is the e80a2df9 fix coded as a property. Will pass on
        /// fix/s1-asert-backport branch (where e80a2df9 is applied) but
        /// FAILS on origin/main (which is what this refactor branches from).
        /// Phase 3 reconciles the patch + model.
        #[test]
        fn prop_v2_peer_claim_pruned_when_local_overtakes(
            peer_idx in 0usize..5,
            peer_claim in 10u64..500,
            local_advance_to in 500u64..1_000,
        ) {
            let peers = peer_pool();
            let mut sync = ChainSync::new(0, Hash::zero());

            // Peer P advertises height N.
            sync.update_peer_height_for(peers[peer_idx], peer_claim);
            prop_assert_eq!(sync.best_known_height, peer_claim);

            // Local advances past N.
            let mut tip_bytes = [0u8; 32];
            tip_bytes[..8].copy_from_slice(&local_advance_to.to_le_bytes());
            sync.set_local_tip(local_advance_to, Hash::from_bytes(tip_bytes));

            // V2 closure expected: peer's claim should be pruned (it's now stale).
            prop_assert!(
                !sync.peer_heights.contains_key(&peers[peer_idx]),
                "peer's stale height claim must be pruned once local advances past it \
                 (V2 closure / e80a2df9). peer_claim={}, local_advance_to={}, \
                 still-in-peer_heights={:?}",
                peer_claim, local_advance_to,
                sync.peer_heights.get(&peers[peer_idx]).copied(),
            );
            prop_assert_eq!(
                sync.best_known_height, local_advance_to,
                "best_known_height must drop to local once stale claim is pruned"
            );
        }

        /// Phase 2a (V3 partial): peer difficulty model invariants.
        ///   - best_known_difficulty ≥ max(peer_difficulties.values())
        ///   - best_peer_by_difficulty returns the peer with max difficulty
        ///   - a peer claim ≤ local total work is pruned by
        ///     `set_local_total_difficulty` (mirrors V2 height pruning)
        #[test]
        fn prop_v3_difficulty_model_consistent(
            claims in prop::collection::vec((0usize..5, 1u128..1_000_000_000_000), 1..15),
            local_td in 0u128..500_000,
        ) {
            let peers = peer_pool();
            let mut sync = ChainSync::new(0, Hash::zero());

            // Apply peer claims; latest wins per peer.
            let mut expected: std::collections::HashMap<PeerId, u128> = Default::default();
            for (peer_idx, td) in &claims {
                sync.update_peer_difficulty_for(peers[*peer_idx], *td);
                expected.insert(peers[*peer_idx], *td);
            }

            // After all claims, best_known_difficulty ≥ max(expected.values())
            let expected_max = expected.values().copied().max().unwrap_or(0);
            prop_assert!(
                sync.best_known_difficulty() >= expected_max,
                "best_known_difficulty={} < max(peer_difficulties)={}",
                sync.best_known_difficulty(), expected_max,
            );

            // Best peer by difficulty matches.
            if let Some((p, d)) = sync.best_peer_by_difficulty() {
                prop_assert_eq!(d, expected[&p],
                    "best_peer_by_difficulty returned ({:?}, {}) but expected[p]={}",
                    p, d, expected[&p]);
            }

            // Now advance local total difficulty — peers with claims ≤ local
            // must be pruned.
            sync.set_local_total_difficulty(local_td);
            let still_present: Vec<u128> = sync.peer_difficulties.values().copied().collect();
            for d in &still_present {
                prop_assert!(*d > local_td,
                    "Peer with difficulty {} ≤ local_td {} not pruned", d, local_td);
            }
        }

        /// Specific property for V5 (the queue-stuck Synced transition):
        /// If we advance local to match best_known AND queues are drained,
        /// state should be Synced.
        #[test]
        fn prop_v5_synced_when_caught_up_and_drained(
            target_height in 100u64..500,
        ) {
            let mut sync = ChainSync::new(0, Hash::zero());
            // Advance to target. With no peer claims, best_known should equal target.
            let mut tip_bytes = [0u8; 32];
            tip_bytes[..8].copy_from_slice(&target_height.to_le_bytes());
            sync.set_local_tip(target_height, Hash::from_bytes(tip_bytes));

            prop_assert!(
                sync.pending_headers.is_empty(),
                "no events queue pending_headers in this property; should be empty"
            );
            prop_assert!(
                sync.downloading.is_empty(),
                "no events populate downloading in this property; should be empty"
            );
            prop_assert_eq!(
                sync.state, SyncState::Synced,
                "state must be Synced when local==best_known and queues empty. \
                 Actual: state={:?}, local={}, best_known={}",
                sync.state, sync.local_height, sync.best_known_height,
            );
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Regression tests for the 2026-06-27 "phantom target pins chain"
    // bug. See refresh_best_known docs for the production failure
    // mode. The bug was that refresh_best_known was a one-way ratchet
    // instead of a true recompute, so once best_known got bumped via
    // a speculative update_peer_height_for (e.g., from an InvBlock
    // for a hash that's never delivered), it stayed bumped forever
    // even when the peer disconnected.
    // ─────────────────────────────────────────────────────────────

    /// best_known_height MUST drop when the high-water-mark peer
    /// disconnects, so the chain doesn't stay pinned at a phantom
    /// target after the bogus peer is gone.
    #[test]
    fn best_known_drops_when_high_peer_disconnects() {
        let mut sync = ChainSync::new(7_291, Hash::zero());
        let p_real = super::super::peer::generate_peer_id();
        let p_bogus = super::super::peer::generate_peer_id();

        // Real peer at our height — best_known stays at 7291.
        sync.update_peer_height_for(p_real, 7_291);
        assert_eq!(sync.best_known_height, 7_291);

        // Bogus peer "announces" h=7292 (the InvBlock-for-phantom-hash
        // scenario from node.rs:3312). best_known bumps.
        sync.update_peer_height_for(p_bogus, 7_292);
        assert_eq!(sync.best_known_height, 7_292,
            "speculative bump must take effect when bumped");

        // Bogus peer disconnects (TCP drop / timeout / whatever).
        // best_known MUST recompute back down to the actual max.
        sync.on_peer_disconnected(&p_bogus);
        assert_eq!(sync.best_known_height, 7_291,
            "after the bogus peer disconnects, best_known_height MUST \
             drop back to the actual max(local, max(remaining peers)). \
             The pre-fix ratchet behavior was the production bug \
             that wedged the chain 2026-06-27 — even with the bad \
             peer gone, best_known stayed at 7_292 forever, is_synced \
             stayed false, and rigs refused to mine.");
        assert!(sync.is_synced(),
            "with local=7291 and no peer ahead, is_synced must be true");
    }

    /// best_known_height MUST drop when ALL peers disconnect, falling
    /// back to local_height. Boundary case of the above test.
    #[test]
    fn best_known_falls_to_local_when_all_peers_gone() {
        let mut sync = ChainSync::new(7_291, Hash::zero());
        let p1 = super::super::peer::generate_peer_id();
        let p2 = super::super::peer::generate_peer_id();
        sync.update_peer_height_for(p1, 7_295);
        sync.update_peer_height_for(p2, 7_300);
        assert_eq!(sync.best_known_height, 7_300);

        sync.on_peer_disconnected(&p1);
        assert_eq!(sync.best_known_height, 7_300,
            "removing the non-highest peer doesn't drop best_known");
        sync.on_peer_disconnected(&p2);
        assert_eq!(sync.best_known_height, 7_291,
            "with no peers left, best_known floors at local_height");
        assert!(sync.is_synced());
    }

    /// best_known_height MUST advance when local_height advances,
    /// even if no peer is ahead (it should track local as a floor).
    /// Symmetric with the on_peer_disconnected recompute.
    #[test]
    fn best_known_tracks_local_advance() {
        let mut sync = ChainSync::new(7_291, Hash::zero());
        let p = super::super::peer::generate_peer_id();
        sync.update_peer_height_for(p, 7_295);
        assert_eq!(sync.best_known_height, 7_295);

        // Local advances past the peer's tracked height.
        sync.on_block_processed(Hash::zero(), 7_300);
        assert_eq!(sync.best_known_height, 7_300,
            "advancing local past stale peer entries must raise best_known. \
             Without on_block_processed → refresh_best_known, best_known \
             would lag at 7_295 even though we've passed it locally.");
        assert!(sync.is_synced());
    }

    /// v1.0.13 #4 — one peer cannot fill more than MAX_HEADERS_PER_PEER
    /// slots in the pending_headers pool. Without this cap, the attacker
    /// who wins the GetHeaders nonce race in IBD can stuff 50K bogus
    /// hashes into the queue, blocking legitimate peers' headers until
    /// the pool drains via download timeouts.
    #[test]
    fn per_peer_pending_headers_cap_enforced() {
        let mut sync = ChainSync::new(0, Hash::zero());
        let attacker = super::super::peer::generate_peer_id();

        // Try to queue 2x the per-peer cap from a single peer.
        let big: Vec<Hash> = (0..(MAX_HEADERS_PER_PEER as u64 * 2))
            .map(|i: u64| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_be_bytes());
                Hash::from_bytes(h)
            })
            .collect();
        sync.queue_headers_from_peer(attacker, big);

        // Only MAX_HEADERS_PER_PEER got in.
        assert_eq!(
            sync.pending_headers.len(),
            MAX_HEADERS_PER_PEER,
            "attacker capped at MAX_HEADERS_PER_PEER ({})",
            MAX_HEADERS_PER_PEER,
        );
        assert_eq!(
            sync.headers_per_peer.get(&attacker).copied().unwrap_or(0),
            MAX_HEADERS_PER_PEER,
        );
        assert_eq!(sync.pending_header_peer.len(), MAX_HEADERS_PER_PEER);

        // Legitimate peer can still queue its own MAX_HEADERS_PER_PEER
        // (different hashes — distinct because per-peer cap is per-peer,
        // not a shared budget).
        let honest = super::super::peer::generate_peer_id();
        let honest_hdrs: Vec<Hash> = ((MAX_HEADERS_PER_PEER as u64 * 10)
            ..(MAX_HEADERS_PER_PEER as u64 * 10 + 100))
            .map(|i: u64| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_be_bytes());
                Hash::from_bytes(h)
            })
            .collect();
        sync.queue_headers_from_peer(honest, honest_hdrs);
        assert_eq!(
            sync.headers_per_peer.get(&honest).copied().unwrap_or(0),
            100,
            "honest peer got its 100 hashes in despite attacker's cap-hit",
        );
    }

    /// v1.0.13 #4 — popping pending_headers (via get_blocks_to_request)
    /// decrements the per-peer counter, freeing room for that peer to
    /// queue more legitimately.
    #[test]
    fn per_peer_counter_decrements_on_pop() {
        let mut sync = ChainSync::new(0, Hash::zero());
        let peer = super::super::peer::generate_peer_id();
        let hashes: Vec<Hash> = (0..50)
            .map(|i: u64| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_be_bytes());
                Hash::from_bytes(h)
            })
            .collect();
        sync.queue_headers_from_peer(peer, hashes);
        assert_eq!(sync.headers_per_peer.get(&peer).copied().unwrap(), 50);

        // Pop 20 via get_blocks_to_request.
        sync.max_concurrent = 100; // allow popping 20 at once
        let popped = sync.get_blocks_to_request(20);
        assert_eq!(popped.len(), 20);

        // Counter went from 50 → 30 (50 queued - 20 popped).
        assert_eq!(sync.headers_per_peer.get(&peer).copied().unwrap(), 30);
        assert_eq!(sync.pending_header_peer.len(), 30);
    }
}
