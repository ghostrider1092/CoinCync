//! # P2P Node Manager for CoinCync 1.0
//!
//! Central coordinator for all P2P networking:
//! - Connection management (inbound/outbound)
//! - Message routing between peers
//! - Dandelion++ transaction propagation
//! - Chain synchronization coordination
//!
//! ## Module boundary
//!
//! `P2PNode` remains the public facade and composition root. Transport,
//! dispatch, peer lifecycle, sync scheduling and maintenance tasks live in
//! focused child modules; explicit public re-exports and facade tests remain
//! here until the final cleanup phase.
//!
//! - [`super::connection_tracker`] — per-IP limits + buffer budget ✅ (extracted)
//! - `super::node::connection` — Noise transport + framed connection loop
//!   (extracted)
//! - `super::node::dispatch` — inbound routing and per-type handlers
//!   (extracted)
//! - `super::node::broadcast` — bounded peer sends and gossip propagation
//!   (extracted)
//! - `super::node::{types, constants, chain_state}` — public contracts,
//!   node policy constants and coherent chain-tip state (extracted)
//! - `super::node::peer_manager` — outbound connection orchestration,
//!   bootstrapping, eclipse-protection heuristics (extracted)
//! - `super::node::runtime` — one-shot setup and inbound processing (extracted)
//! - `super::node::sync_driver` — sync scheduling and recovery (extracted)
//! - `super::node::maintenance` — the periodic background tasks
//!   (reputation decay, mempool expiry, stale-entry cleanup; extracted)

use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::net::TcpListener;
use tokio::sync::{broadcast as event_broadcast, mpsc, RwLock};
#[allow(unused_imports)]
use tokio::time::timeout;
use tracing::{info, warn};

use crate::chain::SharedBlockchain;
use crate::consensus::Block;
use crate::error::{Error, Result};
use crate::mempool::SharedMempool;
use crate::primitives::Hash;
use crate::transaction::Transaction;

use super::bootstrap::{AddressManager, Bootstrapper, PeerAddress};
use super::connection_tracker::{ConnectionTracker, MemoryReservation};
use super::dandelion::{DandelionRouter, DandelionStats};
use super::peer::{PeerId, PeerInfo};
use super::relay_score::RelayScoreMap;
use super::scoring::{PeerScorer, ScorerStats};
use super::sync::{ChainSync, SyncStats};
use super::traffic_shaping::TrafficShaper;

mod address_policy;
mod broadcast;
mod chain_state;
mod connection;
mod constants;
mod dispatch;
mod maintenance;
mod peer_manager;
mod runtime;
mod sync_driver;
mod tx_absence;
mod types;

pub use super::connection_tracker::MAX_CONNECTIONS_PER_IP;
use chain_state::ChainState;
pub use constants::{
    CONNECT_TIMEOUT, GLOBAL_QUEUE_SIZE, MAX_INBOUND, MAX_OUTBOUND, MAX_PEERS, MEMORY_BUDGET_BYTES,
    NEAR_TIP_INV_WINDOW, PEER_QUEUE_SIZE, PEER_TIMEOUT, PING_INTERVAL,
    TIP_REBROADCAST_INTERVAL_SECS,
};
pub use tx_absence::TxAbsenceCache;
pub use types::{ChainUpdateToken, ConnectionStats, NetworkStats, NodeConfig, NodeEvent};

/// Message from peer connection
struct PeerMessage {
    peer_id: PeerId,
    msg_type: u8,
    payload: Vec<u8>,
    _reservation: MemoryReservation,
}

/// Command to connection manager
#[allow(dead_code)]
enum ConnectionCommand {
    Connect(SocketAddr),
    Disconnect(PeerId),
    Broadcast(Vec<u8>),
    SendTo(PeerId, Vec<u8>),
    Shutdown,
}

const START_ONE_SHOT_ERROR: &str =
    "P2PNode is one-shot: start cannot be called again after a successful start";

// ConnectionTracker lives in `super::connection_tracker` — extracted
// out of this monolithic file as the first step of splitting node.rs
// by responsibility. See `super::connection_tracker::ConnectionTracker`
// for the full implementation and its dedicated test module.

/// P2P Node - main networking coordinator
pub struct P2PNode {
    /// Our peer ID (derived from Noise static key if encryption enabled)
    our_id: PeerId,
    /// Configuration
    config: NodeConfig,
    /// Noise Protocol identity (persistent X25519 keypair)
    identity: Arc<super::noise::NodeIdentity>,
    /// Blockchain reference for serving blocks/headers to peers
    chain: SharedBlockchain,
    /// Mempool reference for transaction relay
    mempool: SharedMempool,
    /// Connected peers
    peers: Arc<DashMap<PeerId, PeerInfo>>,
    /// Peer message senders
    peer_senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    /// Coherent chain-tip snapshot and accept-order sequence guard.
    chain_state: ChainState,
    /// Serializes publication across the chain shadow, sync manager and chain flags.
    chain_publication: tokio::sync::Mutex<()>,
    /// Dandelion router
    dandelion: Arc<RwLock<DandelionRouter>>,
    /// Chain sync manager
    sync: Arc<RwLock<ChainSync>>,
    /// Address manager
    addresses: Arc<RwLock<AddressManager>>,
    /// Event sender
    event_tx: event_broadcast::Sender<NodeEvent>,
    /// Command sender (for future use)
    #[allow(dead_code)]
    cmd_tx: mpsc::Sender<ConnectionCommand>,
    /// Is running
    running: Arc<RwLock<bool>>,
    /// Owns cancellation and join handles for every task created by `start()`.
    runtime: tokio::sync::Mutex<Option<runtime::NodeRuntime>>,
    /// Connection tracker for per-IP limits and memory management
    conn_tracker: Arc<ConnectionTracker>,
    /// Peer scoring and reputation management
    peer_scorer: Arc<RwLock<PeerScorer>>,
    /// Node-internal inbound block-relay scores (ACO, un-poisonable).
    /// Phase 1: measured + exposed; not yet used by eviction.
    /// See docs/architecture/inbound-relay-eviction.md.
    relay_scores: Arc<RwLock<RelayScoreMap>>,
    /// Per-peer orphan-block rate tracker for flood detection.
    /// Wired into `notify_block_orphan`; flooders are scored with
    /// `MisbehaviorType::OrphanFlood`.
    orphan_flood: Arc<RwLock<super::scoring::OrphanFloodTracker>>,
    /// v1.0.13 #2 — tx-absence cache. Consulted by the InvTx-receive
    /// path to skip GetTxs for hashes recently reported NotFound.
    /// Populated by the NotFound-receive handler.
    tx_absence_cache: Arc<parking_lot::RwLock<TxAbsenceCache>>,
    /// SECURITY (NET-001): Version nonce for self-connection detection
    version_nonce: u64,
    /// Channel for sync-safe transaction broadcast queueing (used by RPC handlers)
    /// SECURITY: Bounded to prevent OOM from malicious RPC flood
    tx_broadcast_tx: tokio::sync::mpsc::Sender<Transaction>,
    /// Receiver held until start() moves it into the maintenance task
    tx_broadcast_rx: parking_lot::Mutex<Option<tokio::sync::mpsc::Receiver<Transaction>>>,
    /// DHT state for key-image stripe routing (Tier 2+ nodes).
    /// Personal (Tier 1) nodes use this to route queries to the correct stripe peer.
    pub dht: Option<Arc<parking_lot::Mutex<super::dht::DhtState>>>,
    /// Traffic shaper for network fingerprint resistance (4th Amendment).
    /// Normalizes packet sizes, adds timing jitter, and injects constant-rate
    /// padding so P2P traffic is indistinguishable from generic HTTPS.
    pub traffic_shaper: Arc<TrafficShaper>,
}

impl P2PNode {
    /// Create a new P2P node with blockchain and mempool references
    pub fn new(config: NodeConfig, chain: SharedBlockchain, mempool: SharedMempool) -> Self {
        // Load or generate Noise identity (persistent X25519 keypair).
        //
        // P5-N1 SURGICAL FIX (2026-07-03): the pre-fix code fell back
        // to an ephemeral identity on ANY error. If the identity file
        // exists but is temporarily unreadable (permission blip, backup
        // daemon holding a lock, disk transient), the node came up
        // with a FRESH peer_id — losing accumulated peer reputation
        // and appearing as a Sybil twin to any peer that remembers our
        // prior key. Now:
        //   - Check the file's presence explicitly first.
        //   - If it doesn't exist: legit fresh install, generate + save.
        //   - If it exists but load failed: LOUD error log flagging
        //     the identity oscillation risk, still fall back (don't
        //     halt — a running node with degraded rep is better than
        //     no node), but ops sees the alert.
        // File name matches network::noise::NodeIdentity::load_or_generate_fresh L176.
        let identity_path = config.data_dir.join("node_key");
        let identity = if identity_path.exists() {
            match super::noise::NodeIdentity::load_or_generate_fresh(&config.data_dir) {
                Ok(id) => {
                    tracing::info!("Noise identity loaded: {}", hex::encode(&id.peer_id()[..8]));
                    Arc::new(id)
                }
                Err(e) => {
                    tracing::error!(
                        target: "network::identity::P5N1",
                        error = %e,
                        path = %identity_path.display(),
                        "P5-N1: identity file EXISTS but load FAILED — \
                         falling back to ephemeral identity. This means \
                         our peer_id has CHANGED for this session; peers \
                         will see us as a fresh Sybil twin, and \
                         accumulated reputation is lost. Investigate file \
                         permissions / backup contention / disk health \
                         and restart when resolved."
                    );
                    let id = super::noise::NodeIdentity::generate();
                    Arc::new(id)
                }
            }
        } else {
            // Fresh install: legit case, just create + save.
            match super::noise::NodeIdentity::load_or_generate_fresh(&config.data_dir) {
                Ok(id) => {
                    tracing::info!(
                        "Noise identity generated (fresh install): {}",
                        hex::encode(&id.peer_id()[..8])
                    );
                    Arc::new(id)
                }
                Err(e) => {
                    tracing::warn!(
                        "First-run identity generation failed: {}, using ephemeral",
                        e
                    );
                    let id = super::noise::NodeIdentity::generate();
                    Arc::new(id)
                }
            }
        };

        // Use Noise static pubkey as our peer ID for cryptographic identity
        let our_id = identity.peer_id();

        let (event_tx, _) = event_broadcast::channel(GLOBAL_QUEUE_SIZE);
        let (cmd_tx, _cmd_rx) = mpsc::channel(PEER_QUEUE_SIZE);
        // SECURITY: Bounded channel prevents OOM if RPC floods transactions
        let (tx_broadcast_tx, tx_broadcast_rx) = tokio::sync::mpsc::channel(1024);

        // Capture chain state before moving into struct
        let init_height = chain.height();
        let init_tip = chain.tip_hash();

        // Seed the address manager with our own external address (if the
        // operator passed --external-ip) so peer gossip that echoes our
        // own IP back to us can never make us dial ourselves. Read before
        // `config` is moved into the struct below (SocketAddr is Copy).
        let mut address_mgr = AddressManager::new(1000);
        if let Some(ext) = config.external_addr {
            address_mgr.mark_self_address(ext);
            info!("Registered external address {ext} as self — peer gossip echoing our own IP will not cause self-dials");
        }

        P2PNode {
            our_id,
            config,
            identity,
            chain,
            mempool,
            peers: Arc::new(DashMap::new()),
            peer_senders: Arc::new(DashMap::new()),
            chain_state: ChainState::new(init_height, init_tip),
            chain_publication: tokio::sync::Mutex::new(()),
            dandelion: Arc::new(RwLock::new(DandelionRouter::new())),
            sync: Arc::new(RwLock::new(ChainSync::new(init_height, init_tip))),
            addresses: Arc::new(RwLock::new(address_mgr)),
            event_tx,
            cmd_tx,
            running: Arc::new(RwLock::new(false)),
            runtime: tokio::sync::Mutex::new(None),
            conn_tracker: Arc::new(ConnectionTracker::new(MEMORY_BUDGET_BYTES)),
            peer_scorer: Arc::new(RwLock::new(PeerScorer::new())),
            relay_scores: Arc::new(RwLock::new(RelayScoreMap::new())),
            orphan_flood: Arc::new(RwLock::new(super::scoring::OrphanFloodTracker::new())),
            tx_absence_cache: Arc::new(parking_lot::RwLock::new(TxAbsenceCache::new())),
            version_nonce: rand::random::<u64>(),
            tx_broadcast_tx,
            tx_broadcast_rx: parking_lot::Mutex::new(Some(tx_broadcast_rx)),
            dht: None,
            traffic_shaper: Arc::new(TrafficShaper::default_enabled()),
        }
    }

    /// Attach a DHT state for key-image stripe routing.
    /// Call this after construction for Tier 2+ nodes.
    pub fn set_dht(&mut self, dht: Arc<parking_lot::Mutex<super::dht::DhtState>>) {
        self.dht = Some(dht);
    }

    /// Query key image spend status via DHT stripe routing.
    ///
    /// Routes the query to a peer responsible for the key image's stripe.
    /// Returns `None` if no DHT state or no peer available for the stripe.
    pub async fn query_key_images_via_dht(
        &self,
        key_images: &[crate::primitives::KeyImage],
    ) -> Option<()> {
        let dht = self.dht.as_ref()?;

        if key_images.is_empty() {
            return Some(());
        }

        // P5-N2 SURGICAL FIX (2026-07-03): snapshot the per-stripe
        // peer selection UNDER the sync `parking_lot::Mutex`, then
        // drop the guard BEFORE any `.await`. Prior code held the
        // guard across `sender.send(data).await` at every send in
        // the loop — a classic sync-lock-across-await bug that
        // could deadlock any other async task needing DHT state
        // and blocked the tokio worker for the send's duration.
        let sends: Vec<(u32, [u8; 32], Vec<[u8; 32]>)> = {
            let dht_guard = dht.lock();

            // Group key images by stripe using the guarded stripe_count
            let mut by_stripe: std::collections::HashMap<u32, Vec<[u8; 32]>> =
                std::collections::HashMap::new();
            for ki in key_images {
                let stripe = super::dht::key_image_stripe(ki, dht_guard.stripe_count);
                by_stripe.entry(stripe).or_default().push(*ki.as_bytes());
            }

            let mut sends = Vec::new();
            for (stripe, ki_bytes) in by_stripe.into_iter() {
                let stripe_idx = stripe as usize;
                if stripe_idx >= dht_guard.peers_by_stripe.len() {
                    continue;
                }
                let stripe_peers = &dht_guard.peers_by_stripe[stripe_idx];
                if stripe_peers.is_empty() {
                    tracing::debug!(
                        "DHT: no peers for stripe {}, skipping {} key images",
                        stripe,
                        ki_bytes.len()
                    );
                    continue;
                }
                // Snapshot target + payload for later async send.
                sends.push((stripe, stripe_peers[0], ki_bytes));
            }
            sends
            // dht_guard drops here — before any await below.
        };

        // Now safe to await — no sync lock held.
        for (stripe, target, ki_bytes) in sends {
            // DEADLOCK FIX: clone the mpsc::Sender out of DashMap before awaiting.
            // The prior `if let Some(sender) = self.peer_senders.get(&target)` form held
            // the DashMap shard Ref across `sender.send(data).await`; if the peer's
            // outbound channel was at capacity that await parked the worker while still
            // holding the shard lock, blocking every other task touching the same
            // shard. Same fix applied uniformly at all `mpsc::Sender::send(...).await`
            // sites over a DashMap in this file (see PR body for the systematic
            // sweep + regression test).
            let sender = self.peer_senders.get(&target).map(|s| s.value().clone());
            if let Some(sender) = sender {
                if let Ok(encoded) = borsh::to_vec(&ki_bytes) {
                    let msg = super::protocol::Message::new(
                        self.config.magic,
                        super::protocol::MessageType::GetKeyImageStatus,
                        encoded,
                    );
                    if let Ok(data) = msg.to_bytes() {
                        let _ = sender.send(data).await;
                        tracing::debug!(
                            "DHT: sent {} key image queries to stripe {} peer {:?}",
                            ki_bytes.len(),
                            stripe,
                            &target[..4]
                        );
                    }
                }
            }
        }

        Some(())
    }

    /// Get a clone of the sync manager Arc for the healing stack.
    pub fn get_sync(&self) -> Arc<RwLock<ChainSync>> {
        self.sync.clone()
    }

    /// Get the blockchain Arc.
    pub fn get_chain(&self) -> SharedBlockchain {
        self.chain.clone()
    }

    /// Add a seed/manual peer address
    pub async fn add_seed_address(&self, addr: std::net::SocketAddr) {
        self.addresses.write().await.add(PeerAddress::new(addr));
    }

    /// Get connection tracker statistics
    pub fn connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            memory_used: self.conn_tracker.memory_usage(),
            memory_budget: MEMORY_BUDGET_BYTES,
        }
    }

    /// Get our peer ID
    pub fn our_id(&self) -> PeerId {
        self.our_id
    }

    /// Subscribe to node events
    pub fn subscribe(&self) -> event_broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    /// Queue a transaction for broadcast through Dandelion++ (sync-safe).
    ///
    /// This method is safe to call from synchronous contexts (e.g., RPC handlers)
    /// because it uses try_send on a bounded channel instead of requiring async locks.
    /// The maintenance task picks up queued transactions and routes them through
    /// the Dandelion++ stem phase for origin obfuscation.
    pub fn queue_transaction_for_broadcast(&self, tx: Transaction) -> Result<()> {
        self.tx_broadcast_tx.try_send(tx).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                tracing::warn!("Transaction broadcast queue full — dropping transaction");
                Error::InvalidState("broadcast queue full, try again later".into())
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                Error::InvalidState("broadcast queue closed".into())
            }
        })
    }

    /// Issue a single-use token for the next chain-state publication (issue #249).
    /// Callers capture this in order — before spawning a detached update —
    /// so [`set_chain_state`](Self::set_chain_state) can drop stale writes
    /// that complete out of order.
    pub fn next_chain_update(&self) -> ChainUpdateToken {
        ChainUpdateToken::new(self.chain_state.next_sequence())
    }

    /// Publish the authoritative chain snapshot to every P2P-side consumer.
    ///
    /// `update` is the publication-order token from
    /// [`next_chain_update`](Self::next_chain_update). The snapshot is read
    /// coherently from `Blockchain` after publication is serialized, so
    /// detached callers cannot supply a torn or stale `(height, tip, work)`.
    pub async fn set_chain_state(&self, update: ChainUpdateToken) {
        self.publish_chain_state(update, false).await;
    }

    async fn publish_chain_state(&self, update: ChainUpdateToken, block_processed: bool) {
        let seq = update.into_sequence();
        let _publication = self.chain_publication.lock().await;
        let mut sync = self.sync.write().await;
        let chain_stats = self.chain.stats();
        if !self
            .chain_state
            .update(seq, chain_stats.height, chain_stats.tip_hash)
            .await
        {
            return;
        }

        // There are deliberately no await points after the shadow commit:
        // cancellation cannot leave ChainState newer than ChainSync.
        if block_processed {
            sync.on_block_processed(chain_stats.tip_hash, chain_stats.height);
        }
        sync.set_local_tip(chain_stats.height, chain_stats.tip_hash);
        // Firework Phase 2: keep the sync manager's notion of our own
        // cumulative work current so peer-work claims are compared against
        // the right baseline (and stale lower-work peer claims get pruned).
        sync.set_local_total_difficulty(chain_stats.total_difficulty);
        let stats = sync.stats();
        drop(sync);
        self.chain.set_sync_info(
            stats.local_height >= stats.best_known_height,
            stats.best_known_height,
        );
        // Firework Phase 2 (I6): veto "synced" while a peer advertises more
        // cumulative work than us — a heavier chain — even when we are taller
        // in block height. Anti-wedge (expire/ban/prune) clears the claim if
        // it can't be substantiated, so this can't pin us permanently.
        self.chain
            .set_work_behind(stats.best_known_difficulty > stats.local_total_difficulty);
        // Firework Phase 2: tell CAP_CHAINWORK peers our new cumulative work
        // so a peer on a lighter (possibly higher) chain can discover ours.
        broadcast::announce_chain_work(
            &self.chain,
            self.config.magic,
            &self.peers,
            &self.peer_senders,
        );
    }

    /// Notify the sync manager that a block has been received and processed.
    /// This frees the download slot so more blocks can be requested during IBD.
    pub async fn notify_block_received(&self, hash: &Hash) {
        self.sync.write().await.mark_block_received(hash);
    }

    /// Publish a successfully processed block through the ordered chain-state path.
    pub async fn notify_block_processed(&self, update: ChainUpdateToken) {
        self.publish_chain_state(update, true).await;
    }

    /// Bug 3 fix: notify sync that add_block() failed, re-queue for retry.
    pub async fn notify_block_failed(&self, hash: &Hash) {
        self.sync.write().await.mark_block_failed(hash);
    }

    /// Record peer misbehavior for an invalid block and, if the resulting
    /// reputation crosses the ban threshold, disconnect the peer.
    ///
    /// Without this wiring, a peer can spam invalid blocks indefinitely — the
    /// validator correctly rejects them but the peer keeps reconnecting and
    /// resending, burning CPU on PoW re-verification and generating log noise.
    /// Observed in production 2026-05-11: 6 peers on a pre-MIN_DIFFICULTY-floor
    /// fork produced 164,966 `Difficulty target mismatch` warnings in 24h.
    ///
    /// The reason string (from `BlockStatus::Invalid(reason)`) is classified
    /// by [`super::scoring::classify_invalid_block_reason`] into an appropriate
    /// `MisbehaviorType`. Wrong-chain / wrong-PoW failures map to instant ban
    /// (100 penalty); body-cryptographic failures accumulate (50 penalty,
    /// 2-strike).
    pub async fn notify_block_invalid(&self, peer_id: &PeerId, reason: &str) {
        let offense = super::scoring::classify_invalid_block_reason(reason);

        // MissingParent is not misbehavior — it's an out-of-order sync race
        // during a deep reorg (peer's fork tip arrived before we backfilled
        // parents). Do NOT score, do NOT ban. The header/block sync path
        // should already be requesting the missing parents on its own; if
        // it isn't, that's a bug in sync, not the peer's fault.
        //
        // Before this short-circuit existed, this exact case banned our own
        // randomx-2 miner during a legitimate 628-block reorg on 2026-07-04
        // and locked the fleet out of the canonical chain for ~20 hours.
        // See `project_hard_finality_partition_2026_07_04.md`.
        if offense == super::scoring::MisbehaviorType::MissingParent {
            tracing::debug!(
                peer = ?&peer_id[..4],
                reason = %reason,
                "notify_block_invalid: MissingParent — not scoring peer, upstream sync should request parents"
            );
            return;
        }

        let addr = match self.peers.get(peer_id).map(|p| p.addr) {
            Some(a) => a,
            None => {
                // Peer already gone (disconnect race). Nothing to score.
                return;
            }
        };
        let banned = {
            let mut scorer = self.peer_scorer.write().await;
            let score = scorer.get_or_create(addr);
            score.record_misbehavior(offense);
            score.should_ban()
        };
        if banned {
            tracing::warn!(
                "Banning peer {:?} ({}): {:?} (reason: {})",
                &peer_id[..4],
                addr,
                offense,
                reason
            );
            self.ban_peer(peer_id).await;
        }
    }

    /// Score a peer that relayed a transaction which then failed full
    /// mempool validation (ring sig, range proof, key image, double-spend,
    /// or any other admit-time check). Counterpart to `notify_block_invalid`.
    ///
    /// The structural pre-relay validation at `process_message::Transactions`
    /// catches a small subset of bad txs (version, empty in/out, size, fee).
    /// The expensive crypto runs only in mempool admit and historically had
    /// no peer_id available, so the warning fired but no scoring happened.
    /// Plumbing `source` through `NodeEvent::TransactionReceived` closed
    /// that gap; this method scores the responsible peer.
    pub async fn notify_tx_invalid_full(&self, peer_id: &PeerId, reason: &str) {
        let offense = super::scoring::classify_invalid_tx_reason(reason);
        let addr = match self.peers.get(peer_id).map(|p| p.addr) {
            Some(a) => a,
            None => return,
        };
        let banned = {
            let mut scorer = self.peer_scorer.write().await;
            let score = scorer.get_or_create(addr);
            score.record_misbehavior(offense);
            score.invalid_txs += 1;
            score.should_ban()
        };
        if banned {
            tracing::warn!(
                "Banning peer {:?} ({}): {:?} (reason: {})",
                &peer_id[..4],
                addr,
                offense,
                reason,
            );
            self.ban_peer(peer_id).await;
        }
    }

    /// IBD orphan recovery: when a block came back as Orphan, ask the
    /// sync manager to fetch the parent so the gap fills, AND store the
    /// orphan body so the drain in `on_block_received_from` can replay
    /// it once the parent connects. See `sync::mark_block_orphan` for
    /// the full rationale + the 2026-06-17 root-cause notes on why the
    /// hashes-only version of this function stuck the chain.
    ///
    /// SECURITY (2026-07-05 audit — same class as PR #154 MissingParent):
    /// Orphan-flood scoring has been **removed** from this path. It was the
    /// direct cause of the 2026-06-22 partition (18hr stall — our own miner
    /// got banned as an "orphan flooder" while sending legitimate blocks
    /// from a heavier chain). The pattern is the same as the 2026-07-04
    /// stall: peer sending blocks we haven't backfilled parents for looks
    /// like an attacker from our current-tip vantage point, but is actually
    /// exactly what a legitimate heavier-chain takeover looks like.
    ///
    /// **Rate-tracking is kept** (see `self.orphan_flood.write().await.record`
    /// below) purely as an observability signal — the return value is
    /// logged but never fed to the scorer. If a future PR wires proper
    /// GETDATA-response tracking, THAT is where "peer refused to deliver
    /// its parents" DoS-detection belongs, not here.
    ///
    /// Prior art (specific per-project identifiers UNVERIFIED this
    /// session): the widely-followed pattern in reference impls is to
    /// hold the orphan, request the missing parent(s), and only
    /// score/ban if the peer then refuses to deliver those parents.
    /// The prior comment cited specific per-project identifiers
    /// (`MSG_BLOCK_UNKNOWN_PARENT`, Zebra orphan-pool internals,
    /// "Monero same shape") that were not re-confirmed against
    /// upstream this session, so the identifier-level citations have
    /// been removed. Consistent with the parallel scoring.rs / sync.rs
    /// scrubs in this PR.
    ///
    /// v1.0.13 orphan-body-in-pool fix (2026-06-17): takes the full
    /// `Block` (not just its hash) so `sync::mark_block_orphan` can
    /// stash the body in the orphan pool for instant replay when the
    /// parent chain connects. Pre-fix, hashes-only propagation forced
    /// gossip to re-deliver every intermediate block body 200-deep,
    /// which peers don't do unprompted — the chain stuck.
    pub async fn notify_block_orphan(&self, peer_id: &PeerId, block: Block, parent_hash: &Hash) {
        // Capture the orphan's hash BEFORE moving `block` into
        // `mark_block_orphan`. Used only in the debug-log below for
        // observability; the orphan pool stores the block itself.
        let orphan_hash = block.hash();
        self.sync
            .write()
            .await
            .mark_block_orphan(block, Some(*peer_id), parent_hash);

        // Track rate for observability only. Do NOT feed into the peer scorer.
        // See method doc-comment for the 2026-06-22 partition context.
        let flooded = self.orphan_flood.write().await.record(*peer_id);
        if flooded {
            tracing::debug!(
                peer = ?&peer_id[..4],
                threshold = super::scoring::ORPHAN_FLOOD_THRESHOLD,
                window_secs = super::scoring::ORPHAN_FLOOD_WINDOW_SECS,
                orphan = ?orphan_hash,
                parent = ?parent_hash,
                "notify_block_orphan: rate above threshold — logging as observability only, \
                 NOT scoring peer (see method doc-comment for the 2026-06-22 partition rationale)"
            );
        }
    }

    /// Force a full resync by clearing sync state and requesting headers again.
    /// Used when a deep chain divergence exceeds the reorg depth limit in chain.rs.
    pub async fn force_resync(&self) {
        tracing::warn!("[SYNC] Forcing full resync due to deep chain divergence");
        let mut sync = self.sync.write().await;
        sync.clear();
        // Reset local height to 0 so the sync engine re-downloads everything
        sync.set_local_height(0);
    }

    /// Get the best known height from peers (sync target).
    pub async fn sync_target_height(&self) -> u64 {
        self.sync.read().await.true_best_height()
    }

    /// Start the P2P node.
    ///
    /// All fallible resource acquisition completes before `running` becomes
    /// visible or any long-lived subsystem task is spawned. A failed resource
    /// acquisition may be retried, but a successfully started instance is
    /// one-shot and cannot be started again after [`stop`](Self::stop).
    pub async fn start(&self) -> Result<()> {
        let mut runtime_slot = self.runtime.lock().await;
        if runtime_slot.is_some() || *self.running.read().await {
            return Err(Error::InvalidState("node already running".into()));
        }
        if self.tx_broadcast_rx.lock().is_none() {
            return Err(Error::InvalidState(START_ONE_SHOT_ERROR.into()));
        }

        info!("Starting P2P node on {}", self.config.listen_addr);

        let addr_book_path = self.config.data_dir.join("address_book.json");
        let ban_list_path = self.config.data_dir.join("ban_list.json");

        {
            let mut addresses = self.addresses.write().await;
            match addresses.load_from_file(&addr_book_path) {
                Ok(n) if n > 0 => info!("Loaded {} addresses from disk", n),
                Ok(_) => {}
                Err(e) => warn!("Failed to load address book: {}", e),
            }
        }

        let anchors = peer_manager::load_anchors_from_disk(&self.config.data_dir);
        if !anchors.is_empty() {
            info!(
                "Loaded {} anchor peers — dialing them first on startup",
                anchors.len()
            );
            self.addresses.write().await.set_anchors(anchors);
        }

        {
            let mut scorer = self.peer_scorer.write().await;
            match scorer.load_bans_from_file(&ban_list_path) {
                Ok(n) if n > 0 => info!("Loaded {} bans from disk", n),
                Ok(_) => {}
                Err(e) => warn!("Failed to load ban list: {}", e),
            }
        }

        let onion_only = self
            .config
            .proxy
            .as_ref()
            .map(|proxy| proxy.onion_only)
            .unwrap_or(false);
        let proxy_active = self.config.proxy.is_some();

        if self.addresses.read().await.is_empty() {
            let bootstrapper = Bootstrapper::new(self.config.bootstrap.clone());
            let initial_peers = bootstrapper.get_peers(onion_only, proxy_active).await;
            let mut addresses = self.addresses.write().await;
            for addr in initial_peers {
                addresses.add(PeerAddress::new(addr));
            }
        } else {
            info!(
                "Skipping bootstrap — using {} pre-configured seed addresses",
                self.addresses.read().await.len()
            );
        }

        let socket = socket2::Socket::new(
            if self.config.listen_addr.is_ipv6() {
                socket2::Domain::IPV6
            } else {
                socket2::Domain::IPV4
            },
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|e| Error::ConnectionFailed(format!("socket create: {e}")))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| Error::ConnectionFailed(format!("SO_REUSEADDR: {e}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::ConnectionFailed(format!("set_nonblocking: {e}")))?;
        socket.bind(&self.config.listen_addr.into()).map_err(|e| {
            Error::ConnectionFailed(format!("bind {}: {e}", self.config.listen_addr))
        })?;
        socket
            .listen(128)
            .map_err(|e| Error::ConnectionFailed(format!("listen: {e}")))?;
        let listener = TcpListener::from_std(socket.into())
            .map_err(|e| Error::ConnectionFailed(format!("TcpListener::from_std: {e}")))?;

        let broadcast_rx = self
            .tx_broadcast_rx
            .lock()
            .take()
            .ok_or_else(|| Error::InvalidState(START_ONE_SHOT_ERROR.into()))?;
        let (msg_tx, msg_rx) = mpsc::channel::<PeerMessage>(GLOBAL_QUEUE_SIZE);

        *self.running.write().await = true;
        info!("P2P node listening on {}", self.config.listen_addr);

        let mut node_runtime = runtime::NodeRuntime::new();
        if self.config.upnp {
            node_runtime.track(
                "upnp-setup",
                runtime::spawn_upnp_setup(
                    self.config.listen_addr.port(),
                    node_runtime.shutdown_receiver(),
                ),
            );
        }
        node_runtime.track(
            "padding-broadcast",
            runtime::spawn_padding_broadcast(
                self.traffic_shaper.clone(),
                self.peer_senders.clone(),
                self.config.magic,
                node_runtime.shutdown_receiver(),
            ),
        );

        node_runtime.track(
            "listener-acceptor",
            peer_manager::spawn_listener_acceptor(
                listener,
                peer_manager::AcceptorContext {
                    peers: self.peers.clone(),
                    event_tx: self.event_tx.clone(),
                    msg_tx: msg_tx.clone(),
                    senders: self.peer_senders.clone(),
                    chain_state: self.chain_state.reader(),
                    tracker: self.conn_tracker.clone(),
                    scorer: self.peer_scorer.clone(),
                    identity: self.identity.clone(),
                    relay_scores: self.relay_scores.clone(),
                    encryption: self.config.encryption.clone(),
                    onion_only,
                    magic: self.config.magic,
                    our_nonce: self.version_nonce,
                },
                node_runtime.shutdown_receiver(),
            ),
        );
        node_runtime.track(
            "outbound-connector",
            peer_manager::spawn_outbound_connector(
                peer_manager::OutboundContext {
                    peers: self.peers.clone(),
                    addresses: self.addresses.clone(),
                    event_tx: self.event_tx.clone(),
                    msg_tx: msg_tx.clone(),
                    senders: self.peer_senders.clone(),
                    chain_state: self.chain_state.reader(),
                    proxy: self.config.proxy.clone(),
                    scorer: self.peer_scorer.clone(),
                    identity: self.identity.clone(),
                    encryption: self.config.encryption.clone(),
                    listen_port: self.config.listen_addr.port(),
                    tracker: self.conn_tracker.clone(),
                    data_dir: self.config.data_dir.clone(),
                    max_outbound: self.config.max_outbound,
                    magic: self.config.magic,
                    our_nonce: self.version_nonce,
                },
                node_runtime.shutdown_receiver(),
            ),
        );
        node_runtime.track(
            "message-processor",
            runtime::spawn_message_processor(
                msg_rx,
                runtime::MessageProcessorContext {
                    peers: self.peers.clone(),
                    dandelion: self.dandelion.clone(),
                    sync: self.sync.clone(),
                    event_tx: self.event_tx.clone(),
                    senders: self.peer_senders.clone(),
                    nonce: self.version_nonce,
                    chain: self.chain.clone(),
                    mempool: self.mempool.clone(),
                    addresses: self.addresses.clone(),
                    scorer: self.peer_scorer.clone(),
                    tx_absence_cache: self.tx_absence_cache.clone(),
                    relay_scores: self.relay_scores.clone(),
                    magic: self.config.magic,
                },
                node_runtime.shutdown_receiver(),
            ),
        );
        node_runtime.track(
            "sync-driver",
            sync_driver::spawn_sync_driver(
                sync_driver::SyncDriverContext {
                    peers: self.peers.clone(),
                    senders: self.peer_senders.clone(),
                    chain: self.chain.clone(),
                    sync: self.sync.clone(),
                    scorer: self.peer_scorer.clone(),
                    addresses: self.addresses.clone(),
                    magic: self.config.magic,
                },
                node_runtime.shutdown_receiver(),
            ),
        );
        node_runtime.track(
            "maintenance",
            maintenance::spawn_maintenance(
                maintenance::MaintenanceContext {
                    peers: self.peers.clone(),
                    dandelion: self.dandelion.clone(),
                    sync: self.sync.clone(),
                    senders: self.peer_senders.clone(),
                    event_tx: self.event_tx.clone(),
                    mempool: self.mempool.clone(),
                    tracker: self.conn_tracker.clone(),
                    tx_absence_cache: self.tx_absence_cache.clone(),
                    scorer: self.peer_scorer.clone(),
                    orphan_flood: self.orphan_flood.clone(),
                    relay_scores: self.relay_scores.clone(),
                    ban_list_path,
                    chain_state: self.chain_state.reader(),
                    broadcast_rx,
                    magic: self.config.magic,
                },
                node_runtime.shutdown_receiver(),
            ),
        );

        *runtime_slot = Some(node_runtime);

        info!("P2P node started successfully");
        Ok(())
    }

    /// Stop the P2P node
    pub async fn stop(&self) {
        info!("Stopping P2P node...");
        *self.running.write().await = false;

        let runtime = { self.runtime.lock().await.take() };
        if let Some(runtime) = runtime {
            runtime.shutdown().await;
        }

        // Persist state only after runtime tasks can no longer mutate it.
        let addr_book_path = self.config.data_dir.join("address_book.json");
        let ban_list_path = self.config.data_dir.join("ban_list.json");

        {
            let addresses = self.addresses.read().await;
            if let Err(e) = addresses.save_to_file(&addr_book_path) {
                warn!("Failed to save address book: {}", e);
            } else {
                info!("Saved {} addresses to disk", addresses.len());
            }
        }

        {
            let scorer = self.peer_scorer.read().await;
            if let Err(e) = scorer.save_bans_to_file(&ban_list_path) {
                warn!("Failed to save ban list: {}", e);
            }
        }

        // ANCHORS: persist known-good outbound peers for fast reconnect next start.
        peer_manager::save_anchors_to_disk(&self.peers, &self.config.data_dir);
        peer_manager::disconnect_all(&self.peers, &self.peer_senders, &self.event_tx);

        info!("P2P node stopped");
    }

    /// Broadcast transaction (using Dandelion++).
    ///
    /// The transaction enters the stempool and will be relayed during the next
    /// Dandelion++ tick.  For immediate broadcast (e.g., from RPC), use
    /// `queue_transaction_for_broadcast()` which feeds into the maintenance loop.
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<Hash> {
        Ok(broadcast::queue_transaction(&self.dandelion, tx).await)
    }

    fn broadcast_context(&self) -> broadcast::BroadcastContext<'_> {
        broadcast::BroadcastContext {
            traffic_shaper: &self.traffic_shaper,
            peers: &self.peers,
            senders: &self.peer_senders,
            tracker: &self.conn_tracker,
            scorer: &self.peer_scorer,
            dandelion: &self.dandelion,
            sync: &self.sync,
            orphan_flood: &self.orphan_flood,
            event_tx: &self.event_tx,
        }
    }

    /// Broadcast block announcement
    pub async fn broadcast_block(&self, block: &Block) -> Result<()> {
        broadcast::broadcast_block(self.config.magic, block, &self.broadcast_context()).await
    }

    /// Send message to specific peer
    pub async fn send_to(&self, peer_id: &PeerId, data: Vec<u8>) -> Result<()> {
        broadcast::send_to(&self.peer_senders, peer_id, data).await
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get current chain height (for sync guard).
    pub async fn chain_height(&self) -> u64 {
        self.chain_state.height().await
    }

    /// Get list of connected peers
    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|p| p.clone()).collect()
    }

    /// Test/support hook: inject a synthetic peer entry.
    ///
    /// This is used by integration tests that validate RPC redaction behavior
    /// against non-empty peer sets without requiring real network sockets.
    pub fn add_peer_for_testing(&self, peer: PeerInfo) {
        self.peers.insert(peer.id, peer);
    }

    /// Get sync statistics
    pub async fn sync_stats(&self) -> SyncStats {
        self.sync.read().await.stats()
    }

    /// Get dandelion statistics
    pub async fn dandelion_stats(&self) -> DandelionStats {
        self.dandelion.read().await.stats()
    }

    /// Get peer scoring statistics
    pub async fn scorer_stats(&self) -> ScorerStats {
        self.peer_scorer.read().await.stats()
    }

    /// Snapshot of currently-connected peers, with the heights they
    /// each reported in their version handshake. Operators use this
    /// via the `get_peer_info` RPC to spot fleet divergence — if some
    /// nodes report height N and others report height M >> N, one
    /// side has a fork or a stall. Cheap enough to call frequently
    /// (iterates the live DashMap, clones each entry).
    pub fn peer_snapshot(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|kv| kv.value().clone()).collect()
    }

    /// Get network statistics
    pub fn network_stats(&self) -> NetworkStats {
        let mut total_recv = 0u64;
        let mut total_sent = 0u64;
        let mut outbound = 0;
        let mut inbound = 0;

        for peer in self.peers.iter() {
            total_recv += peer.bytes_recv;
            total_sent += peer.bytes_sent;
            if peer.outbound {
                outbound += 1;
            } else {
                inbound += 1;
            }
        }

        NetworkStats {
            peer_count: self.peers.len(),
            outbound,
            inbound,
            bytes_recv: total_recv,
            bytes_sent: total_sent,
        }
    }

    /// Ban a peer
    ///
    /// SECURITY (NET-003): Untrack the connection to prevent per-IP counter leak,
    /// and store the ban to prevent immediate reconnection.
    pub async fn ban_peer(&self, peer_id: &PeerId) {
        peer_manager::ban_peer(
            peer_id,
            peer_manager::BanPeerContext {
                peers: &self.peers,
                senders: &self.peer_senders,
                tracker: &self.conn_tracker,
                scorer: &self.peer_scorer,
                dandelion: &self.dandelion,
                orphan_flood: &self.orphan_flood,
                event_tx: &self.event_tx,
            },
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert_eq!(config.max_peers, MAX_PEERS);
        assert_eq!(config.max_outbound, MAX_OUTBOUND);
    }

    #[tokio::test]
    async fn test_node_creation() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.data_dir = data_dir.path().to_path_buf();
        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let mempool = crate::mempool::SharedMempool::new();
        let node = P2PNode::new(config, chain, mempool);

        assert_eq!(node.peer_count(), 0);
        assert!(!node.our_id().iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn start_resource_failure_does_not_publish_running_state() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.listen_addr = "127.0.0.1:0".parse().unwrap();
        config.data_dir = data_dir.path().to_path_buf();
        config.upnp = false;

        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let mempool = crate::mempool::SharedMempool::new();
        let node = P2PNode::new(config, chain, mempool);
        node.add_seed_address("127.0.0.1:1".parse().unwrap()).await;

        let _held_receiver = node.tx_broadcast_rx.lock().take().unwrap();
        let error = node.start().await.unwrap_err();

        assert!(matches!(error, Error::InvalidState(_)));
        assert!(!*node.running.read().await);
        assert!(node.peers.is_empty());
    }

    #[tokio::test]
    async fn bind_failure_keeps_first_start_retryable() {
        let data_dir = tempfile::tempdir().unwrap();
        let port_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = port_reservation.local_addr().unwrap();

        let mut config = NodeConfig::default();
        config.listen_addr = listen_addr;
        config.data_dir = data_dir.path().to_path_buf();
        config.upnp = false;

        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let node = P2PNode::new(config, chain, SharedMempool::new());
        node.add_seed_address("127.0.0.1:1".parse().unwrap()).await;

        let error = node.start().await.unwrap_err();
        assert!(matches!(error, Error::ConnectionFailed(_)));
        assert!(!*node.running.read().await);

        drop(port_reservation);
        node.start().await.unwrap();
        node.stop().await;
    }

    #[tokio::test]
    async fn start_then_stop_updates_lifecycle_state() {
        let data_dir = tempfile::tempdir().unwrap();
        let port_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = port_reservation.local_addr().unwrap();
        drop(port_reservation);

        let mut config = NodeConfig::default();
        config.listen_addr = listen_addr;
        config.data_dir = data_dir.path().to_path_buf();
        config.upnp = false;

        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let mempool = crate::mempool::SharedMempool::new();
        let node = P2PNode::new(config, chain, mempool);
        node.add_seed_address("127.0.0.1:1".parse().unwrap()).await;

        node.start().await.unwrap();
        assert!(*node.running.read().await);
        let connection = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        drop(connection);

        node.stop().await;
        assert!(!*node.running.read().await);
        assert!(node.runtime.lock().await.is_none());
        assert!(tokio::net::TcpStream::connect(listen_addr).await.is_err());
        assert!(data_dir.path().join("address_book.json").exists());

        let error = node.start().await.unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidState(message) if message.contains("one-shot")
        ));
    }

    #[tokio::test]
    async fn set_chain_state_preserves_sequence_contract_at_facade() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.data_dir = data_dir.path().to_path_buf();
        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let node = P2PNode::new(config, chain.clone(), SharedMempool::new());
        let older_tip = Hash::from_bytes([0xAA; 32]);
        let newer_tip = Hash::from_bytes([0xBB; 32]);
        let older = node.next_chain_update();
        let newer = node.next_chain_update();

        chain.restore_state(100, newer_tip, 1_000).unwrap();
        node.set_chain_state(newer).await;
        node.set_chain_state(older).await;
        assert_eq!(node.chain_height().await, 100);
        assert_eq!(node.sync_stats().await.local_height, 100);
        assert_eq!(node.sync_stats().await.local_total_difficulty, 1_000);

        chain.restore_state(80, older_tip, 2_000).unwrap();
        node.set_chain_state(node.next_chain_update()).await;
        assert_eq!(node.chain_height().await, 80);
        assert_eq!(node.sync_stats().await.local_height, 80);
        assert_eq!(node.sync_stats().await.local_total_difficulty, 2_000);
    }

    #[tokio::test]
    async fn stale_processed_block_task_cannot_regress_sync_state() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.data_dir = data_dir.path().to_path_buf();
        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let node = Arc::new(P2PNode::new(config, chain.clone(), SharedMempool::new()));
        let newer_tip = Hash::from_bytes([0xBB; 32]);
        chain.restore_state(100, newer_tip, 1_000).unwrap();
        let stale_update = node.next_chain_update();
        let current_update = node.next_chain_update();

        let release_stale = Arc::new(tokio::sync::Barrier::new(2));
        let stale_node = Arc::clone(&node);
        let stale_release = Arc::clone(&release_stale);
        let stale = tokio::spawn(async move {
            stale_release.wait().await;
            stale_node.notify_block_processed(stale_update).await;
        });

        node.set_chain_state(current_update).await;
        node.sync
            .write()
            .await
            .set_state(crate::network::sync::SyncState::Headers);
        release_stale.wait().await;
        stale.await.unwrap();

        assert_eq!(node.chain_height().await, 100);
        let sync = node.sync_stats().await;
        assert_eq!(sync.local_height, 100);
        assert_eq!(sync.local_total_difficulty, 1_000);
        assert_eq!(sync.state, crate::network::sync::SyncState::Headers);
    }

    /// Verify that the ConnectionTracker enforces the per-IP connection limit
    /// and correctly tracks/untracks connections.
    #[test]
    fn test_connection_tracker_per_ip_limit() {
        let tracker = ConnectionTracker::new(MEMORY_BUDGET_BYTES);
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let ip = addr.ip();

        // No connections initially
        assert_eq!(tracker.connections_from(&ip), 0);
        assert!(tracker.can_accept(&addr));

        // Accept up to MAX_CONNECTIONS_PER_IP
        for i in 0..MAX_CONNECTIONS_PER_IP {
            let a: SocketAddr = format!("192.168.1.1:{}", 10000 + i).parse().unwrap();
            assert!(
                tracker.try_track_connection(&a),
                "should accept connection {} from same IP",
                i + 1
            );
        }

        // At limit: should reject next connection from same IP
        let extra: SocketAddr = "192.168.1.1:20000".parse().unwrap();
        assert!(!tracker.can_accept(&extra));
        assert!(!tracker.try_track_connection(&extra));
        assert_eq!(tracker.connections_from(&ip), MAX_CONNECTIONS_PER_IP);

        // A different IP should still be accepted
        let other: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        assert!(tracker.try_track_connection(&other));

        // Untrack one connection from the first IP
        tracker.untrack_connection(&addr);
        assert_eq!(tracker.connections_from(&ip), MAX_CONNECTIONS_PER_IP - 1);

        // Now we can accept again from that IP
        assert!(tracker.try_track_connection(&extra));
    }

    /// Verify that peer_count reflects the number of entries in the peers map
    /// and that connected_peers returns an empty list for a fresh node.
    #[tokio::test]
    async fn test_peer_count_and_connected_peers() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.data_dir = data_dir.path().to_path_buf();
        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let mempool = crate::mempool::SharedMempool::new();
        let node = P2PNode::new(config, chain, mempool);

        // Fresh node has zero peers
        assert_eq!(node.peer_count(), 0);
        assert!(node.connected_peers().is_empty());

        // Network stats should be zero across the board
        let stats = node.network_stats();
        assert_eq!(stats.peer_count, 0);
        assert_eq!(stats.outbound, 0);
        assert_eq!(stats.inbound, 0);
        assert_eq!(stats.bytes_recv, 0);
        assert_eq!(stats.bytes_sent, 0);

        // Connection stats should show zero memory used
        let conn_stats = node.connection_stats();
        assert_eq!(conn_stats.memory_used, 0);
        assert_eq!(conn_stats.memory_budget, MEMORY_BUDGET_BYTES);
    }

    /// Regression test for the snapshot-then-loop pattern
    /// used at broadcast sites (ping, fluff). Iterates the DashMap into
    /// a Vec<Sender>, drops the iterator, THEN awaits per-peer sends.
    /// Concurrent DashMap modification must not block on the iteration.
    ///
    /// This test only asserts the SHARD-LOCK invariant. It does NOT
    /// assert that fast peers receive their messages ahead of slow —
    /// the production broadcast loops are deliberately sequential
    /// (`for sender in snapshot { sender.send(...).await; }`) so a slow
    /// peer DOES delay the tail of the broadcast. That's a correct
    /// backpressure design, not a bug. The fix guarantees only that
    /// concurrent DashMap access remains unblocked — which is what
    /// prevents the runtime-wide futex-park cascade.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn broadcast_snapshot_pattern_releases_shard_locks_before_await() {
        use std::time::Duration;
        let senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>> = Arc::new(DashMap::new());

        // Two peers: one with a full channel (will park the send), one
        // with room. The broadcast task will park on the slow one but
        // must NOT block modification of the map.
        let (slow_tx, mut slow_rx) = mpsc::channel::<Vec<u8>>(1);
        let (fast_tx, _fast_rx) = mpsc::channel::<Vec<u8>>(4);
        let slow: PeerId = [1u8; 32];
        let fast: PeerId = [2u8; 32];
        senders.insert(slow, slow_tx.clone());
        senders.insert(fast, fast_tx);
        // Pre-fill slow's channel to force the broadcast send to park.
        slow_tx.send(vec![0]).await.expect("pre-fill");

        // Spawn a task that broadcasts using the snapshot pattern.
        let senders_bcast = senders.clone();
        let broadcast_task = tokio::spawn(async move {
            let snapshot: Vec<mpsc::Sender<Vec<u8>>> =
                senders_bcast.iter().map(|s| s.value().clone()).collect();
            // After .collect(), the DashMap iterator is dropped — no
            // shard locks held. Sequential send.await per peer is fine
            // (that's correct backpressure); the invariant we're
            // proving is that concurrent DashMap access remains free.
            for sender in snapshot {
                let _ = sender.send(vec![0xFA, 0xB]).await;
            }
        });

        // Give the broadcast a moment to enter the loop and (likely)
        // park on slow's full channel.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Concurrent DashMap modification must succeed WITHOUT waiting
        // for the parked broadcast. The pre-fix antipattern held a
        // shard lock via `.iter()` for the full duration of every peer's
        // send.await — this insert would block until the broadcast
        // finished. Post-fix, `.collect()` drops the iterator and every
        // shard is free.
        let extra: PeerId = [42u8; 32];
        let (extra_tx, _extra_rx) = mpsc::channel::<Vec<u8>>(1);
        let insert_start = std::time::Instant::now();
        senders.insert(extra, extra_tx);
        let insert_dur = insert_start.elapsed();
        assert!(
            insert_dur < Duration::from_millis(500),
            "DashMap insert took {}ms during snapshot broadcast — shard \
             lock still held across await. REGRESSION.",
            insert_dur.as_millis()
        );

        // Drain slow so the broadcast task can finish.
        let _ = slow_rx.recv().await; // drain pre-fill
        let _ = slow_rx.recv().await; // drain broadcast payload
        let _ = tokio::time::timeout(Duration::from_secs(2), broadcast_task)
            .await
            .expect("broadcast_task must complete after slow channel drained");
    }
}
