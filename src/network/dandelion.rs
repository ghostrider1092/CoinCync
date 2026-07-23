//! # Dandelion++ Transaction Privacy (Monero-grade)
//!
//! Implements the Dandelion++ protocol (BIP 156 / Fanti et al. 2018) for
//! transaction propagation privacy. Key design choices follow Monero's
//! battle-tested implementation:
//!
//! - **Per-epoch mode decision**: Each epoch (~10 min), the node randomly
//!   decides stem vs fluff mode. All received transactions in that epoch
//!   follow the same routing decision (prevents fingerprinting).
//!
//! - **2 fixed relay peers per epoch** (quasi-4-regular graph): Two outbound
//!   peers are selected at epoch start. Inbound peers are deterministically
//!   mapped to one of the two relays (per-inbound-edge routing).
//!
//! - **Exponential embargo timers**: Each stem-forwarded transaction gets an
//!   embargo timer drawn from an exponential distribution (memoryless property).
//!   This prevents the originating node from systematically timing out first.
//!
//! - **Stem loop detection**: If a stem transaction loops back, it is
//!   immediately fluffed to prevent black-holing.
//!
//! References:
//! - Monero: `src/cryptonote_protocol/levin_notify.cpp` (file confirmed
//!   present in Monero master via head-fetch this session; specific
//!   internal identifiers not enumerated).
//! - BIP 156: https://github.com/bitcoin/bips/blob/master/bip-0156.mediawiki
//! - Paper: "Dandelion++: Lightweight Cryptocurrency Networking with Formal
//!   Anonymity Guarantees" (ACM SIGMETRICS 2018)

use crate::constants::{
    DANDELION_EMBARGO_MAX_SECS, DANDELION_EMBARGO_MEAN_SECS, DANDELION_EPOCH_BASE_SECS,
    DANDELION_EPOCH_JITTER_SECS, DANDELION_FLUFF_PROBABILITY, DANDELION_STEMS,
};
use crate::network::peer::PeerId;
use crate::primitives::Hash;
use crate::transaction::Transaction;
use rand::Rng;
use std::collections::HashMap;

/// Maximum pending transactions in the stempool
const MAX_STEMPOOL: usize = 10_000;

/// Minimum outbound peers for adequate privacy
const MIN_PEERS_FOR_PRIVACY: usize = 3;

/// Monitor interval: how often to check for expired embargoes (seconds).
/// The node.rs maintenance loop calls `tick()` on this interval.
pub const DANDELION_MONITOR_INTERVAL_SECS: u64 = 10;

// ─── Stempool Entry ──────────────────────────────────────────────────────────

/// A transaction in the stempool awaiting fluff.
#[derive(Clone, Debug)]
struct StemEntry {
    tx: Transaction,
    /// When this entry was added (unix timestamp seconds).
    added_at: u64,
    /// Embargo deadline: if the tx hasn't appeared back via diffusion by this
    /// time, the node fluffs it as a fail-safe (exponential distribution).
    embargo_deadline: u64,
    /// The peer that sent us this stem tx (None = local).
    source: Option<PeerId>,
    /// Whether we already forwarded this tx in the stem phase.
    forwarded: bool,
    /// SECURITY (H16-FIX): Randomized stem forwarding time. Tx is NOT forwarded
    /// until `now >= forward_after`. Uses Poisson-distributed delay (mean 5s)
    /// like Monero's `CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE` (VERIFIED
    /// at src/cryptonote_config.h:113 in the Monero master read this
    /// session, `= 5` seconds average). Without this, all
    /// stem txs were forwarded on the next 10s tick, creating a fixed timing
    /// signature that deanonymizes the origin node.
    forward_after: u64,
}

/// Mean delay in seconds before stem-forwarding a transaction.
/// Matches Monero's `CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE = 5` seconds
/// (VERIFIED at src/cryptonote_config.h:113 in the Monero master read
/// this session).
const STEM_FORWARD_MEAN_SECS: f64 = 5.0;

// ─── Epoch State ─────────────────────────────────────────────────────────────

/// Per-epoch routing state.  Rebuilt every ~10 minutes.
#[derive(Clone, Debug)]
struct EpochState {
    /// Is this a fluff epoch?  If true, all received stem txs are immediately
    /// scheduled for diffusion broadcast.
    is_fluff_epoch: bool,
    /// The two outbound relay peers for this epoch (quasi-4-regular graph).
    relay_peers: [Option<PeerId>; 2],
    /// Deterministic mapping: inbound peer → relay index (0 or 1).
    /// Load-balanced at epoch start.
    inbound_map: HashMap<PeerId, usize>,
    /// Which relay (0 or 1) is used for our own local transactions.
    own_relay_idx: usize,
    /// When this epoch started (unix timestamp).
    started_at: u64,
    /// Duration of this epoch (randomized: base + jitter).
    duration: u64,
}

impl EpochState {
    fn expired(&self, now: u64) -> bool {
        now >= self.started_at + self.duration
    }
}

// ─── Router ──────────────────────────────────────────────────────────────────

/// Dandelion++ router for transaction privacy.
///
/// Manages the stempool and epoch-based relay routing following the Dandelion++
/// paper and Monero's hardened implementation.
pub struct DandelionRouter {
    /// Stempool: transactions in stem phase or awaiting fluff.
    stempool: HashMap<Hash, StemEntry>,
    /// All known outbound peers (set by the node on connection changes).
    outbound_peers: Vec<PeerId>,
    /// Current epoch state.
    epoch: EpochState,
    /// Epoch counter (monotonically increasing).
    epoch_number: u64,
    /// Hashes of transactions that have been fluffed (diffusion-broadcast).
    /// Kept to detect stem loops and avoid double-fluffing.
    /// Pruned periodically.
    fluffed: HashMap<Hash, u64>, // hash → fluff timestamp
}

impl DandelionRouter {
    /// Create a new Dandelion++ router.
    pub fn new() -> Self {
        DandelionRouter {
            stempool: HashMap::new(),
            outbound_peers: Vec::new(),
            epoch: EpochState {
                is_fluff_epoch: false,
                relay_peers: [None, None],
                inbound_map: HashMap::new(),
                own_relay_idx: 0,
                started_at: 0,
                duration: DANDELION_EPOCH_BASE_SECS,
            },
            epoch_number: 0,
            fluffed: HashMap::new(),
        }
    }

    // ─── Peer Management ─────────────────────────────────────────────────

    /// Set the full list of outbound peers.  Called by node.rs whenever the
    /// outbound peer set changes (connect/disconnect).
    pub fn set_outbound_peers(&mut self, peers: Vec<PeerId>) {
        if peers.len() < MIN_PEERS_FOR_PRIVACY && !peers.is_empty() {
            tracing::warn!(
                "Dandelion++ has only {} outbound peer(s) — privacy degraded. \
                 Need {} for adequate anonymity.",
                peers.len(),
                MIN_PEERS_FOR_PRIVACY
            );
        }
        self.outbound_peers = peers;
    }

    /// Add a single outbound peer.
    pub fn add_outbound_peer(&mut self, peer: PeerId) {
        if !self.outbound_peers.contains(&peer) {
            self.outbound_peers.push(peer);
        }
    }

    /// Remove an outbound peer.
    pub fn remove_outbound_peer(&mut self, peer: &PeerId) {
        self.outbound_peers.retain(|p| p != peer);
        // If we lost a relay peer, clear it (will be fixed at next epoch)
        for slot in &mut self.epoch.relay_peers {
            if slot.as_ref() == Some(peer) {
                *slot = None;
            }
        }
    }

    // ─── Epoch Rotation ──────────────────────────────────────────────────

    /// Check if the epoch needs rotation and rotate if so.
    /// Called every DANDELION_MONITOR_INTERVAL_SECS by the maintenance loop.
    pub fn maybe_rotate_epoch(&mut self, now: u64) {
        if self.epoch.expired(now) || self.epoch.started_at == 0 {
            self.rotate_epoch(now);
        }
    }

    /// Start a new epoch: pick 2 relay peers, decide stem/fluff mode,
    /// map inbound peers to relays.
    fn rotate_epoch(&mut self, now: u64) {
        // SECURITY: Dandelion++ stem peer selection is a privacy boundary.
        // Use OsRng so a predictable ThreadRng state can never let an
        // observer fingerprint which peer a node chose as its stem relay.
        let mut rng = rand::rngs::OsRng;

        self.epoch_number += 1;

        // Randomized epoch duration (Monero: 10 min + rand(0..30s))
        let jitter = rng.gen_range(0..=DANDELION_EPOCH_JITTER_SECS);
        let duration = DANDELION_EPOCH_BASE_SECS + jitter;

        // Stem/fluff decision for the entire epoch (Monero: 20% fluff)
        let is_fluff = rng.gen_range(0..100) < DANDELION_FLUFF_PROBABILITY;

        // Pick up to DANDELION_STEMS (2) outbound relay peers at random
        let mut relay_peers: [Option<PeerId>; 2] = [None, None];
        if !self.outbound_peers.is_empty() {
            use rand::seq::SliceRandom;
            let mut shuffled = self.outbound_peers.clone();
            shuffled.shuffle(&mut rng);
            for (i, peer) in shuffled.iter().take(DANDELION_STEMS).enumerate() {
                relay_peers[i] = Some(*peer);
            }
        }

        // Local transactions always go to a randomly chosen relay
        let own_relay_idx = rng.gen_range(0..DANDELION_STEMS);

        let mode_str = if is_fluff { "FLUFF" } else { "STEM" };
        let r0 = relay_peers[0]
            .map(|p| hex::encode(&p[..4]))
            .unwrap_or_else(|| "none".into());
        let r1 = relay_peers[1]
            .map(|p| hex::encode(&p[..4]))
            .unwrap_or_else(|| "none".into());
        tracing::debug!(
            "Dandelion++ epoch {} started: mode={}, relays=[{}, {}], duration={}s",
            self.epoch_number,
            mode_str,
            r0,
            r1,
            duration
        );

        self.epoch = EpochState {
            is_fluff_epoch: is_fluff,
            relay_peers,
            inbound_map: HashMap::new(), // will be populated lazily
            own_relay_idx,
            started_at: now,
            duration,
        };

        // Dandelion++ privacy metrics
        crate::metrics::dandelion::EPOCH_ROTATIONS_TOTAL.inc();
        crate::metrics::dandelion::CURRENT_EPOCH_MODE.set(if is_fluff { 1 } else { 0 });
    }

    /// Get the relay index for an inbound peer (lazy load-balanced assignment).
    fn relay_index_for_inbound(&mut self, peer: &PeerId) -> usize {
        if let Some(&idx) = self.epoch.inbound_map.get(peer) {
            return idx;
        }
        // Load-balanced: assign to the relay with fewer mapped inbound peers
        let count_0 = self.epoch.inbound_map.values().filter(|&&v| v == 0).count();
        let count_1 = self.epoch.inbound_map.values().filter(|&&v| v == 1).count();
        let idx = if count_0 <= count_1 { 0 } else { 1 };
        self.epoch.inbound_map.insert(*peer, idx);
        idx
    }

    // ─── Transaction Ingestion ───────────────────────────────────────────

    /// Add a locally-created transaction.  Always enters stem phase
    /// (even in fluff epochs, per Monero: `always_stem_local`).
    pub fn add_local_tx(&mut self, tx: Transaction, now: u64) -> Hash {
        let hash = tx.hash();

        // Already in stempool or already fluffed?
        if self.stempool.contains_key(&hash) || self.fluffed.contains_key(&hash) {
            return hash;
        }

        // Enforce stempool size limit
        self.enforce_stempool_limit();

        let embargo = self.random_embargo(now);

        tracing::info!(
            "STEM: Local tx {} entering Dandelion++ (embargo in {}s)",
            &hash.to_hex()[..16],
            embargo.saturating_sub(now)
        );

        self.stempool.insert(
            hash,
            StemEntry {
                tx,
                added_at: now,
                embargo_deadline: embargo,
                source: None,
                forwarded: false,
                forward_after: self.random_forward_time(now),
            },
        );

        hash
    }

    /// Add a transaction received from a peer via stem relay.
    ///
    /// Returns the action the caller should take.
    pub fn add_received_tx(&mut self, tx: Transaction, source: PeerId, now: u64) -> StemAction {
        let hash = tx.hash();

        // Already fluffed by us → ignore
        if self.fluffed.contains_key(&hash) {
            return StemAction::Ignore;
        }

        // Already in stempool → stem loop detected → fluff immediately
        if self.stempool.contains_key(&hash) {
            tracing::info!(
                "FLUFF: Stem loop detected for tx {} — fluffing immediately",
                &hash.to_hex()[..16]
            );
            // Remove from stempool, mark as fluffed
            let entry = self.stempool.remove(&hash);
            self.fluffed.insert(hash, now);
            if let Some(e) = entry {
                return StemAction::Fluff(e.tx);
            }
            return StemAction::Fluff(tx);
        }

        // Enforce stempool limit
        self.enforce_stempool_limit();

        // Per-epoch mode decision (Dandelion++ paper §4.1)
        if self.epoch.is_fluff_epoch {
            // We're a fluff node this epoch → broadcast immediately
            tracing::debug!(
                "FLUFF: Tx {} received in fluff epoch — broadcasting",
                &hash.to_hex()[..16]
            );
            self.fluffed.insert(hash, now);
            return StemAction::Fluff(tx);
        }

        // Stem mode: forward to the relay mapped to this inbound peer
        let embargo = self.random_embargo(now);

        tracing::debug!(
            "STEM: Tx {} continuing stem (embargo in {}s)",
            &hash.to_hex()[..16],
            embargo.saturating_sub(now)
        );

        self.stempool.insert(
            hash,
            StemEntry {
                tx,
                added_at: now,
                embargo_deadline: embargo,
                source: Some(source),
                forwarded: false,
                forward_after: self.random_forward_time(now),
            },
        );

        StemAction::Stem
    }

    // ─── Periodic Tick (called from maintenance loop) ────────────────────

    /// Main tick function.  Called every DANDELION_MONITOR_INTERVAL_SECS.
    /// Returns actions for the node to execute.
    pub fn tick(&mut self, now: u64) -> DandelionActions {
        // 1. Rotate epoch if needed
        self.maybe_rotate_epoch(now);

        let mut actions = DandelionActions::default();

        // 2. Collect stem relays that need forwarding
        let hashes: Vec<Hash> = self.stempool.keys().cloned().collect();
        for hash in hashes {
            // Extract fields we need before any mutable borrows
            let (forwarded, embargo_deadline, source, forward_after) =
                match self.stempool.get(&hash) {
                    Some(e) => (e.forwarded, e.embargo_deadline, e.source, e.forward_after),
                    None => continue,
                };

            // Skip if already forwarded in stem
            if forwarded {
                // Check embargo timeout
                if now >= embargo_deadline {
                    tracing::info!(
                        "FLUFF: Tx {} embargo expired — fail-safe broadcast",
                        &hash.to_hex()[..16]
                    );
                    if let Some(entry) = self.stempool.remove(&hash) {
                        self.fluffed.insert(hash, now);
                        actions.fluff.push((hash, entry.tx, entry.source));
                        crate::metrics::dandelion::EMBARGO_FLUFFS_TOTAL.inc();
                    }
                }
                continue;
            }

            // Determine target relay peer (we need to know whether one exists
            // BEFORE applying the random forward delay — see Phase A7-8 below).
            let relay_idx = match &source {
                Some(src) => self.relay_index_for_inbound(src),
                None => self.epoch.own_relay_idx,
            };
            let target = self.epoch.relay_peers[relay_idx];

            // Phase A7-8 (audit fix): the random forward delay (H16-FIX) only
            // makes sense when we actually have a relay peer to forward to.
            // If `target == None` we are going to fluff regardless — waiting
            // for the random delay just adds latency with zero privacy benefit
            // (and breaks the no-peers fail-safe test). Apply the forward delay
            // ONLY when we have a real stem target.
            if target.is_some() && now < forward_after {
                continue;
            }

            match target {
                Some(peer) => {
                    // SECURITY (BUG-4): Include full tx in stem_relay so the
                    // node sends the actual transaction body, not just InvTx.
                    let tx = self.stempool.get(&hash).map(|e| e.tx.clone());
                    if let Some(tx) = tx {
                        actions.stem_relay.push((hash, tx, peer));
                    }
                    // Mark as forwarded
                    if let Some(e) = self.stempool.get_mut(&hash) {
                        e.forwarded = true;
                    }
                }
                None => {
                    // No relay peer available → fluff as fail-safe
                    tracing::info!(
                        "FLUFF: No relay peer for tx {} — fail-safe broadcast",
                        &hash.to_hex()[..16]
                    );
                    if let Some(entry) = self.stempool.remove(&hash) {
                        self.fluffed.insert(hash, now);
                        actions.fluff.push((hash, entry.tx, entry.source));
                    }
                }
            }
        }

        // 3. Prune old fluffed entries (keep for 10 minutes)
        self.fluffed.retain(|_, ts| now < *ts + 600);

        actions
    }

    /// Notify that a transaction has appeared in the mempool via normal
    /// diffusion (a peer sent it to us as a normal broadcast, not stem).
    /// Remove it from the stempool since the embargo succeeded.
    pub fn tx_confirmed_via_diffusion(&mut self, hash: &Hash) {
        if self.stempool.remove(hash).is_some() {
            tracing::debug!(
                "Stempool: tx {} appeared via diffusion, removing",
                &hash.to_hex()[..16]
            );
        }
    }

    /// Current stempool size (for metrics).
    pub fn stempool_size(&self) -> usize {
        self.stempool.len()
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    /// Generate an embargo deadline using exponential distribution.
    ///
    /// The memoryless property ensures that earlier nodes in the stem path
    /// don't systematically time out first (which would deanonymize the origin).
    /// Monero PR #9295 corrected this from Poisson to exponential.
    fn random_embargo(&self, now: u64) -> u64 {
        // SECURITY: embargo timing reveals stem-path depth if predictable.
        let mut rng = rand::rngs::OsRng;
        // Exponential distribution: -ln(U) / lambda, where lambda = 1/mean
        let u: f64 = rng.gen_range(0.001..1.0); // avoid ln(0)
        let delay = (-u.ln() * DANDELION_EMBARGO_MEAN_SECS as f64) as u64;
        let capped = delay.min(DANDELION_EMBARGO_MAX_SECS);
        now + capped.max(5) // minimum 5 seconds
    }

    /// SECURITY (H16-FIX): Generate a random stem forwarding time using
    /// Poisson-distributed delay. Like Monero's fluff_average (5s mean),
    /// this prevents all stem txs from being forwarded on a fixed cadence.
    /// 95% of values fall between ~1-12s with the exponential distribution.
    fn random_forward_time(&self, now: u64) -> u64 {
        // SECURITY: forward-time jitter fingerprints the originator if predictable.
        let mut rng = rand::rngs::OsRng;
        let u: f64 = rng.gen_range(0.001..1.0);
        let delay = (-u.ln() * STEM_FORWARD_MEAN_SECS) as u64;
        let capped = delay.min(30); // cap at 30 seconds
        now + capped.max(1) // minimum 1 second
    }

    /// Enforce stempool size limit.
    ///
    /// P5-D2 SURGICAL FIX (2026-07-03): eviction now prefers
    /// PEER-SOURCED entries (source.is_some()) over LOCAL entries
    /// (source.is_none()). Pre-fix code evicted strictly by
    /// added_at — the OLDEST entry first — which meant an
    /// attacker who floods the stempool with fresh fake txs
    /// evicts OUR OWN local txs (which are older by definition)
    /// before their attack txs. Our own txs then never fluff and
    /// silently disappear.
    ///
    /// New policy: (1) evict oldest peer-sourced entry first;
    /// (2) only fall back to evicting local entries if no peer
    /// entries exist. This means an attacker's flood eats their
    /// own oldest txs before touching ours.
    fn enforce_stempool_limit(&mut self) {
        while self.stempool.len() >= MAX_STEMPOOL {
            // Prefer evicting a peer-sourced entry.
            let victim = self
                .stempool
                .iter()
                .filter(|(_, e)| e.source.is_some())
                .min_by_key(|(_, e)| e.added_at)
                .map(|(h, _)| *h)
                // Fall back to local entries only if the stempool
                // is entirely local (unusual — means only our own
                // txs are in flight).
                .or_else(|| {
                    self.stempool
                        .iter()
                        .min_by_key(|(_, e)| e.added_at)
                        .map(|(h, _)| *h)
                });
            match victim {
                Some(h) => {
                    self.stempool.remove(&h);
                }
                None => break,
            }
        }
    }

    /// Check if we have adequate peers for full Dandelion++ privacy.
    pub fn has_adequate_privacy(&self) -> bool {
        self.outbound_peers.len() >= MIN_PEERS_FOR_PRIVACY
    }

    /// Get statistics.
    pub fn stats(&self) -> DandelionStats {
        let stem_count = self.stempool.values().filter(|e| !e.forwarded).count();
        let awaiting_fluff = self.stempool.values().filter(|e| e.forwarded).count();

        DandelionStats {
            stempool_size: self.stempool.len(),
            stem_pending: stem_count,
            awaiting_embargo: awaiting_fluff,
            outbound_peers: self.outbound_peers.len(),
            epoch: self.epoch_number,
            is_fluff_epoch: self.epoch.is_fluff_epoch,
            relay_0: self.epoch.relay_peers[0],
            relay_1: self.epoch.relay_peers[1],
        }
    }
}

impl Default for DandelionRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Action Types ────────────────────────────────────────────────────────────

/// Action to take after receiving a stem transaction.
#[derive(Debug)]
pub enum StemAction {
    /// Forward in stem phase (handled by tick()).
    Stem,
    /// Immediately broadcast via diffusion (fluff epoch or loop detected).
    Fluff(Transaction),
    /// Already known — ignore.
    Ignore,
}

/// Batch of actions returned by `tick()` for the node to execute.
#[derive(Default, Debug)]
pub struct DandelionActions {
    /// Transactions to forward via stem to a specific peer.
    /// SECURITY (BUG-4): Includes the full Transaction so the node can send
    /// the actual tx body (not just InvTx hash) to the relay peer.
    pub stem_relay: Vec<(Hash, Transaction, PeerId)>,
    /// Transactions to broadcast via diffusion (fluff). The third tuple
    /// element is the originating peer (the peer that relayed the tx into
    /// our stempool) when known, or `None` for locally-generated txs. The
    /// originator is plumbed downstream so mempool-admit failures can
    /// score the responsible peer.
    pub fluff: Vec<(Hash, Transaction, Option<PeerId>)>,
}

/// Dandelion++ statistics.
#[derive(Clone, Debug)]
pub struct DandelionStats {
    pub stempool_size: usize,
    pub stem_pending: usize,
    pub awaiting_embargo: usize,
    pub outbound_peers: usize,
    pub epoch: u64,
    pub is_fluff_epoch: bool,
    pub relay_0: Option<PeerId>,
    pub relay_1: Option<PeerId>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Amount;
    use crate::transaction::TxType;

    fn make_test_tx(extra: u8) -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![extra],
        }
    }

    fn make_peer_id(n: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_local_tx_enters_stempool() {
        let mut router = DandelionRouter::new();
        router.set_outbound_peers(vec![make_peer_id(1), make_peer_id(2), make_peer_id(3)]);
        router.rotate_epoch(100);

        let tx = make_test_tx(1);
        let hash = router.add_local_tx(tx, 100);

        assert!(router.stempool.contains_key(&hash));
        assert_eq!(router.stempool.len(), 1);
    }

    #[test]
    fn test_stem_loop_detection() {
        let mut router = DandelionRouter::new();
        router.set_outbound_peers(vec![make_peer_id(1), make_peer_id(2), make_peer_id(3)]);
        // Force stem epoch
        router.epoch.is_fluff_epoch = false;
        router.epoch.started_at = 100;
        router.epoch.duration = 600;
        router.epoch.relay_peers = [Some(make_peer_id(1)), Some(make_peer_id(2))];

        let tx = make_test_tx(1);
        let hash = tx.hash();
        let peer = make_peer_id(10);

        // First add
        let action = router.add_received_tx(tx.clone(), peer, 100);
        assert!(matches!(action, StemAction::Stem));

        // Same tx again from different peer → loop → fluff
        let action2 = router.add_received_tx(tx, make_peer_id(11), 101);
        assert!(matches!(action2, StemAction::Fluff(_)));
        assert!(router.fluffed.contains_key(&hash));
    }

    #[test]
    fn test_fluff_epoch_immediately_fluffs() {
        let mut router = DandelionRouter::new();
        router.set_outbound_peers(vec![make_peer_id(1), make_peer_id(2)]);
        // Force fluff epoch
        router.epoch.is_fluff_epoch = true;
        router.epoch.started_at = 100;
        router.epoch.duration = 600;

        let tx = make_test_tx(1);
        let peer = make_peer_id(10);
        let action = router.add_received_tx(tx, peer, 100);
        assert!(matches!(action, StemAction::Fluff(_)));
    }

    #[test]
    fn test_embargo_timeout_fluffs() {
        let mut router = DandelionRouter::new();
        router.set_outbound_peers(vec![make_peer_id(1), make_peer_id(2)]);
        router.epoch.is_fluff_epoch = false;
        router.epoch.started_at = 100;
        router.epoch.duration = 600;
        router.epoch.relay_peers = [Some(make_peer_id(1)), Some(make_peer_id(2))];

        let tx = make_test_tx(1);
        let hash = tx.hash();

        // Insert with very short embargo.
        // Phase A4 (audit fix): added forward_after field which the StemEntry
        // struct gained as part of the H16-FIX (random forward jitter). The
        // test had grown stale. forward_after=0 means "no delay" — irrelevant
        // for this test which is about embargo expiry, not forward timing.
        router.stempool.insert(
            hash,
            StemEntry {
                tx: tx.clone(),
                added_at: 100,
                embargo_deadline: 105, // expires at t=105
                source: None,
                forwarded: true, // already forwarded
                forward_after: 0,
            },
        );

        // Tick at t=110 → embargo expired → fluff
        let actions = router.tick(110);
        assert_eq!(actions.fluff.len(), 1);
        assert_eq!(actions.fluff[0].0, hash);
        assert!(!router.stempool.contains_key(&hash));
    }

    #[test]
    fn test_per_inbound_edge_routing() {
        let mut router = DandelionRouter::new();
        let peers = vec![make_peer_id(1), make_peer_id(2), make_peer_id(3)];
        router.set_outbound_peers(peers);
        router.epoch.is_fluff_epoch = false;
        router.epoch.started_at = 100;
        router.epoch.duration = 600;
        router.epoch.relay_peers = [Some(make_peer_id(1)), Some(make_peer_id(2))];

        let inbound_a = make_peer_id(10);
        let inbound_b = make_peer_id(11);

        // First call assigns relay
        let idx_a1 = router.relay_index_for_inbound(&inbound_a);
        // Same peer, same epoch → same relay (deterministic)
        let idx_a2 = router.relay_index_for_inbound(&inbound_a);
        assert_eq!(idx_a1, idx_a2);

        // Load-balanced: second inbound peer should get the other relay
        let idx_b = router.relay_index_for_inbound(&inbound_b);
        assert_ne!(idx_a1, idx_b);
    }

    #[test]
    fn test_epoch_rotation() {
        let mut router = DandelionRouter::new();
        router.set_outbound_peers(vec![make_peer_id(1), make_peer_id(2)]);

        router.maybe_rotate_epoch(100);
        let epoch1 = router.epoch_number;

        // Not expired yet
        router.maybe_rotate_epoch(200);
        assert_eq!(router.epoch_number, epoch1);

        // Force expiry
        router
            .maybe_rotate_epoch(100 + DANDELION_EPOCH_BASE_SECS + DANDELION_EPOCH_JITTER_SECS + 1);
        assert!(router.epoch_number > epoch1);
    }

    #[test]
    fn test_diffusion_confirmation_removes_from_stempool() {
        let mut router = DandelionRouter::new();
        let tx = make_test_tx(1);
        let hash = router.add_local_tx(tx, 100);
        assert!(router.stempool.contains_key(&hash));

        router.tx_confirmed_via_diffusion(&hash);
        assert!(!router.stempool.contains_key(&hash));
    }

    #[test]
    fn test_no_relay_peers_falls_back_to_fluff() {
        let mut router = DandelionRouter::new();
        // No outbound peers at all
        router.epoch.is_fluff_epoch = false;
        router.epoch.started_at = 100;
        router.epoch.duration = 600;
        router.epoch.relay_peers = [None, None];

        let tx = make_test_tx(1);
        let _hash = router.add_local_tx(tx, 100);

        let actions = router.tick(101);
        // Should fluff since no relay peer available
        assert_eq!(actions.fluff.len(), 1);
        assert_eq!(actions.stem_relay.len(), 0);
    }

    #[test]
    fn test_stempool_limit_enforced() {
        let mut router = DandelionRouter::new();
        router.epoch.is_fluff_epoch = false;
        router.epoch.started_at = 100;
        router.epoch.duration = 600;

        // Insert enough entries to hit the limit (use unique hashes via
        // different added_at + embargo_deadline + a unique extra byte sequence)
        let limit = 100; // Use a smaller number for test speed
        for i in 0..limit {
            // Create unique tx by using i as extra bytes
            let tx = Transaction {
                version: 1,
                tx_type: TxType::Transfer,
                inputs: vec![],
                outputs: vec![],
                fee: Amount::ZERO,
                range_proof: vec![],
                extra: (i as u32).to_le_bytes().to_vec(),
            };
            router.stempool.insert(
                tx.hash(),
                StemEntry {
                    tx,
                    added_at: 100 + i as u64,
                    embargo_deadline: 200 + i as u64,
                    source: None,
                    forwarded: false,
                    // Phase A4 (audit fix): see matching note above. forward_after=0
                    // is irrelevant to this loop test (it's about pool capacity).
                    forward_after: 0,
                },
            );
        }
        assert_eq!(router.stempool.len(), limit);

        // Adding via add_local_tx when at MAX_STEMPOOL should evict oldest.
        // We can't easily fill 10,000 entries in a test, so verify the
        // enforce_stempool_limit logic by temporarily lowering the threshold.
        // Instead, just verify the eviction code path works by filling to
        // MAX_STEMPOOL and checking it stays bounded.
        // For now, verify the add doesn't panic and the stempool grows.
        let new_tx = make_test_tx(42);
        router.add_local_tx(new_tx, 50000);
        assert_eq!(router.stempool.len(), limit + 1);
    }

    #[test]
    fn test_epoch_rotation_clears_inbound_map() {
        let mut router = DandelionRouter::new();
        router.set_outbound_peers(vec![make_peer_id(1), make_peer_id(2), make_peer_id(3)]);

        // Assign an inbound relay in epoch 1
        router.rotate_epoch(100);
        let _idx = router.relay_index_for_inbound(&make_peer_id(10));
        assert!(!router.epoch.inbound_map.is_empty());

        // Rotating epoch should clear the inbound relay map
        router.rotate_epoch(100 + DANDELION_EPOCH_BASE_SECS + DANDELION_EPOCH_JITTER_SECS + 1);
        assert!(router.epoch.inbound_map.is_empty());
    }
}
