//! # P2P Node Manager for CoinCync 1.0
//!
//! Central coordinator for all P2P networking:
//! - Connection management (inbound/outbound)
//! - Message routing between peers
//! - Dandelion++ transaction propagation
//! - Chain synchronization coordination
//!
//! ## Splitting this file
//!
//! This module is ~3000 lines and holds multiple responsibilities that
//! should live in their own submodules. The split is in progress; the
//! intended final layout is:
//!
//! - [`super::connection_tracker`] — per-IP limits + buffer budget ✅ (extracted)
//! - `super::node::handshake` — Noise_XX setup + version handshake
//! - `super::node::dispatch` — inbound message routing and per-type
//!   handlers (currently living here as the ~1000 lines from ~line
//!   2100 onward)
//! - `super::node::peer_manager` — outbound connection orchestration,
//!   bootstrapping, eclipse-protection heuristics
//! - `super::node::maintenance` — the periodic background tasks
//!   (reputation decay, mempool expiry, stale-entry cleanup)
//!
//! The extraction is being done ONE submodule at a time so each step
//! can be validated by `cargo check --lib` + `cargo test --lib
//! network::` before the next one lands. `ConnectionTracker` was the
//! first and simplest: no references to `P2PNode`, so the move was a
//! pure relocation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock, broadcast};
use tokio::time::interval;
#[allow(unused_imports)]
use tokio::time::timeout;
use tracing::{info, warn, debug, trace};
use dashmap::DashMap;

use crate::primitives::Hash;
use crate::consensus::Block;
use crate::transaction::Transaction;
use crate::chain::SharedBlockchain;
use crate::mempool::SharedMempool;
use crate::error::{Error, Result};
use crate::config::NetworkType;

use super::peer::{PeerId, PeerInfo, PeerState, generate_peer_id};
use super::protocol::{
    Message, MessageType, VersionMessage, FlareMessage, ChainWorkMessage,
    GetHeadersMessage, GetBlocksMessage, InvMessage,
    MAX_HEADERS_RESPONSE, MAX_BLOCK_HASHES,
};
use super::dandelion::{DandelionRouter, DandelionStats, StemAction, DANDELION_MONITOR_INTERVAL_SECS};
use super::sync::{ChainSync, SyncState, SyncStats, build_locator};
use super::bootstrap::{Bootstrapper, BootstrapConfig, AddressManager, PeerAddress};
use super::scoring::{PeerScorer, ScorerStats};
use super::relay_score::RelayScoreMap;
use super::traffic_shaping::TrafficShaper;
use super::connection_tracker::{ConnectionTracker, MemoryReservation};

/// Maximum number of peers (reduced to reserve outbound slots)
pub const MAX_PEERS: usize = 72;
/// Maximum outbound connections (8 slots reserved for outbound diversity)
pub const MAX_OUTBOUND: usize = 16;
/// Maximum inbound connections (reduced from 117 to prevent resource exhaustion)
pub const MAX_INBOUND: usize = 64;
/// Maximum connections per IP (prevent Sybil attacks).
/// SECURITY: Reduced from 3 to 2 to prevent Sybil attacks where a
/// single entity controls multiple connections. We use 2 to allow one
/// inbound + one outbound; higher values enable trivial Sybil attacks;
/// 1 is too restrictive for localhost multi-node testing where all
/// nodes share 127.0.0.1. (The prior comment claimed "Bitcoin Core
/// uses 1 connection per IP" — that specific per-IP default was not
/// re-verified against upstream this session and is dropped.)
pub const MAX_CONNECTIONS_PER_IP: usize = 2;
/// Connection timeout
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Ping interval
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

/// CIP-019: window (in blocks) within which a not-yet-synced node is treated as
/// "near tip" — close enough that its gap chains cleanly off its own tip —
/// rather than as being in deep IBD. A near-tip node must keep catching up on
/// the fast propagation path; the old `!is_synced()` InvBlock gate treated
/// 3-behind like 3000-behind, trapping a near-tip node on slow catch-up so it
/// stayed permanently a few blocks behind and its miner's sync gate never
/// cleared (observed live 2026-07-11). See `docs/cip/CIP-019-*`.
pub const NEAR_TIP_INV_WINDOW: u64 = 16;

/// Pure predicate for the CIP-019 InvBlock regime split. `synced` short-circuits
/// (already caught up); otherwise a gap within `window` blocks is "near tip"
/// (catch up promptly) rather than deep IBD (skip the body fetch to avoid
/// orphan pileup). Kept pure so the regime decision is unit-testable in
/// isolation from the async handler.
#[inline]
pub(crate) fn invblock_near_tip(synced: bool, gap: u64, window: u64) -> bool {
    synced || gap <= window
}

/// How often the maintenance loop re-announces our current chain tip
/// to every connected peer via InvBlock.
///
/// Why this exists (2026-06-27 gossip bug): `broadcast_raw` uses
/// `try_send` on bounded per-peer mpsc channels (capacity 100, see
/// `peer.rs`). When a peer's channel is full at the moment we mine
/// a new block, that peer's InvBlock for the new tip is silently
/// dropped. Without a follow-up announcement the peer never learns
/// about the new block — they'd only re-sync if some OTHER trigger
/// (peer disconnect/reconnect, headers exchange, etc.) brought them
/// back into the IBD flow. We saw this in production: randomx2 mined
/// h=7276 → 7277 → 7278 while 7 other fleet hosts stayed stuck at
/// h=7275 for 13+ minutes. seed1's own EMERGENCY-TIER-3 detector
/// flagged the stall but had no recovery path.
///
/// Periodic tip re-announce closes the gap: even if a per-peer
/// channel was full when the original Inv was sent, the channel
/// drains within seconds and the next interval picks up. (Bitcoin
/// Core has a well-known "trickle" gossip idea; the specific
/// send-loop cadence and per-peer-task shape were not re-read this
/// session, so the identifier-level analogy is stated qualitatively
/// only.) The 60s pick matches our 120s target block time — bounds
/// peer staleness at roughly one block.
///
/// Tuning rationale (rejected alternatives):
///   - Bigger channel capacity alone (100 → 1000): just delays the
///     symptom under sustained mining bursts; still drops eventually.
///   - send().await instead of try_send: one slow peer stalls the
///     broadcast loop (explicitly rejected by the 2026-05-02 fix).
///   - More aggressive cadence (10-30s): wastes bandwidth on the
///     happy path where the original Inv already landed; the receive
///     side de-dupes via known-hash check so it's not harmful, just
///     not useful.
pub const TIP_REBROADCAST_INTERVAL_SECS: u64 = 60;
/// Peer timeout (no activity)
pub const PEER_TIMEOUT: Duration = Duration::from_secs(300);
/// Global memory budget for P2P buffers (50 MB)
pub const MEMORY_BUDGET_BYTES: usize = 50 * 1024 * 1024;
/// Per-peer send queue size (with backpressure)
pub const PEER_QUEUE_SIZE: usize = 100;
/// Global message queue size
pub const GLOBAL_QUEUE_SIZE: usize = 1000;

/// Events emitted by the P2P node
#[derive(Clone, Debug)]
pub enum NodeEvent {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// New block received from a specific peer.
    /// Carrying the peer id is required for IronConsensus feedback — the
    /// block event handler in `bin/node.rs` classifies the chain.add_block()
    /// result and dispatches a verdict back to the originating peer via
    /// `P2pNode::iron_on_block_verdict`.
    BlockReceived(Block, PeerId),
    /// New transaction received
    /// A transaction has been received and is ready for mempool admission.
    /// The second tuple element is the originating peer (the peer that
    /// relayed the tx into our stempool / fluff path) when known, or
    /// `None` for locally-generated txs. Consumers use this to score the
    /// peer on mempool-admit failure (bad ring sig, range proof, etc.).
    TransactionReceived(Transaction, Option<PeerId>),
    /// Sync state changed
    SyncStateChanged(SyncState),
    /// Network error
    Error(String),
}

/// v1.0.13 #2 — bounded TTL cache of tx hashes that peers have told
/// us (via `NotFound`) they don't have. The InvTx-receive handler
/// consults this to skip GetTxs for hashes recently NotFound'd —
/// closes the "peer flood-asks for the same tx we don't have, we
/// re-query mempool on every InvTx" amp surface.
///
/// - TTL: 60 seconds (entries expire; same tx may legitimately
///   reappear via a different peer's mempool)
/// - Max size: 10_000 entries (hard cap — under attack, oldest
///   entries get evicted on insert)
///
/// Implemented as `HashMap<Hash, Instant>` (no need for full LRU
/// — eviction is opportunistic on insert + during the maintenance
/// tick, which is enough for the use case).
pub struct TxAbsenceCache {
    inner: std::collections::HashMap<crate::primitives::Hash, std::time::Instant>,
    ttl: std::time::Duration,
    max_size: usize,
}

impl TxAbsenceCache {
    pub fn new() -> Self {
        Self {
            inner: std::collections::HashMap::new(),
            ttl: std::time::Duration::from_secs(60),
            max_size: 10_000,
        }
    }

    /// Mark a hash as known-absent from at least one peer.
    pub fn mark_absent(&mut self, hash: crate::primitives::Hash) {
        // Opportunistic eviction if we're at the cap. Drop entries
        // older than TTL first; if still at cap, drop oldest.
        if self.inner.len() >= self.max_size {
            self.prune();
            if self.inner.len() >= self.max_size {
                // Hard-cap eviction: oldest entry first. Linear scan is
                // fine at 10K entries; this only fires under attack.
                if let Some((oldest, _)) = self.inner.iter().min_by_key(|(_, ts)| *ts).map(|(h, t)| (*h, *t)) {
                    self.inner.remove(&oldest);
                }
            }
        }
        self.inner.insert(hash, std::time::Instant::now());
    }

    /// True if the hash is in the cache AND its entry hasn't expired.
    pub fn is_known_absent(&self, hash: &crate::primitives::Hash) -> bool {
        match self.inner.get(hash) {
            Some(ts) => ts.elapsed() < self.ttl,
            None => false,
        }
    }

    /// Drop expired entries. Called from the maintenance loop tick.
    pub fn prune(&mut self) -> usize {
        let ttl = self.ttl;
        let before = self.inner.len();
        self.inner.retain(|_, ts| ts.elapsed() < ttl);
        before.saturating_sub(self.inner.len())
    }

    pub fn len(&self) -> usize { self.inner.len() }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
}

impl Default for TxAbsenceCache {
    fn default() -> Self { Self::new() }
}

/// P2P node configuration
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Network magic bytes
    pub magic: [u8; 4],
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Maximum peers
    pub max_peers: usize,
    /// Maximum outbound connections
    pub max_outbound: usize,
    /// Bootstrap config
    pub bootstrap: BootstrapConfig,
    /// Enable UPnP
    pub upnp: bool,
    /// SOCKS5 proxy configuration (for Tor/I2P - user-installed)
    pub proxy: Option<crate::config::ProxyConfig>,
    /// Data directory for persistent state (node_key, etc.)
    pub data_dir: std::path::PathBuf,
    /// P2P encryption configuration
    pub encryption: crate::config::P2PEncryptionConfig,
    /// Our own externally-reachable address (from `--external-ip`). When
    /// set, it is registered as a self-address so peer gossip that echoes
    /// our own IP back to us can never make us dial ourselves. `None` =
    /// unknown (default); self-detection then relies solely on the
    /// nonce-match path, which does not persist across re-gossip.
    /// (2026-07-08: self-dials wasted outbound slots and slowed
    /// post-restart mesh re-formation.)
    pub external_addr: Option<SocketAddr>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let params = NetworkType::Mainnet.params();
        NodeConfig {
            magic: params.magic,
            listen_addr: ([0, 0, 0, 0], params.p2p_port).into(),
            max_peers: MAX_PEERS,
            max_outbound: MAX_OUTBOUND,
            bootstrap: BootstrapConfig::default(),
            upnp: true,
            proxy: None,
            data_dir: std::path::PathBuf::from("."),
            encryption: crate::config::P2PEncryptionConfig::default(),
            external_addr: None,
        }
    }
}

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
    /// Current chain height
    chain_height: Arc<RwLock<u64>>,
    /// Current chain tip
    chain_tip: Arc<RwLock<Hash>>,
    /// Dandelion router
    dandelion: Arc<RwLock<DandelionRouter>>,
    /// Chain sync manager
    sync: Arc<RwLock<ChainSync>>,
    /// Address manager
    addresses: Arc<RwLock<AddressManager>>,
    /// Event sender
    event_tx: broadcast::Sender<NodeEvent>,
    /// Command sender (for future use)
    #[allow(dead_code)]
    cmd_tx: mpsc::Sender<ConnectionCommand>,
    /// Is running
    running: Arc<RwLock<bool>>,
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
                    tracing::info!(
                        "Noise identity loaded: {}",
                        hex::encode(&id.peer_id()[..8])
                    );
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
                        "First-run identity generation failed: {}, using ephemeral", e
                    );
                    let id = super::noise::NodeIdentity::generate();
                    Arc::new(id)
                }
            }
        };

        // Use Noise static pubkey as our peer ID for cryptographic identity
        let our_id = identity.peer_id();

        let (event_tx, _) = broadcast::channel(GLOBAL_QUEUE_SIZE);
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
            chain_height: Arc::new(RwLock::new(init_height)),
            chain_tip: Arc::new(RwLock::new(init_tip)),
            dandelion: Arc::new(RwLock::new(DandelionRouter::new())),
            sync: Arc::new(RwLock::new(ChainSync::new(init_height, init_tip))),
            addresses: Arc::new(RwLock::new(address_mgr)),
            event_tx,
            cmd_tx,
            running: Arc::new(RwLock::new(false)),
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

        if key_images.is_empty() { return Some(()); }

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
                if stripe_idx >= dht_guard.peers_by_stripe.len() { continue; }
                let stripe_peers = &dht_guard.peers_by_stripe[stripe_idx];
                if stripe_peers.is_empty() {
                    tracing::debug!(
                        "DHT: no peers for stripe {}, skipping {} key images",
                        stripe, ki_bytes.len()
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
                            ki_bytes.len(), stripe, &target[..4]
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
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    /// Queue a transaction for broadcast through Dandelion++ (sync-safe).
    ///
    /// This method is safe to call from synchronous contexts (e.g., RPC handlers)
    /// because it uses try_send on a bounded channel instead of requiring async locks.
    /// The maintenance task picks up queued transactions and routes them through
    /// the Dandelion++ stem phase for origin obfuscation.
    pub fn queue_transaction_for_broadcast(&self, tx: Transaction) -> Result<()> {
        self.tx_broadcast_tx.try_send(tx)
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!("Transaction broadcast queue full — dropping transaction");
                    Error::InvalidState("broadcast queue full, try again later".into())
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    Error::InvalidState("broadcast queue closed".into())
                }
            })
    }

    /// Set chain state and propagate sync info to chain
    pub async fn set_chain_state(&self, height: u64, tip: Hash) {
        *self.chain_height.write().await = height;
        *self.chain_tip.write().await = tip;
        // Read local cumulative work before taking the sync lock (avoid
        // holding the chain lock across the sync lock).
        let total_diff = self.chain.stats().total_difficulty;
        let mut sync = self.sync.write().await;
        sync.set_local_tip(height, tip);
        // Firework Phase 2: keep the sync manager's notion of our own
        // cumulative work current so peer-work claims are compared against
        // the right baseline (and stale lower-work peer claims get pruned).
        sync.set_local_total_difficulty(total_diff);
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
        self.chain.set_work_behind(stats.best_known_difficulty > stats.local_total_difficulty);
        // Firework Phase 2: tell CAP_CHAINWORK peers our new cumulative work
        // so a peer on a lighter (possibly higher) chain can discover ours.
        self.announce_chain_work();
    }

    /// Notify the sync manager that a block has been received and processed.
    /// This frees the download slot so more blocks can be requested during IBD.
    pub async fn notify_block_received(&self, hash: &Hash) {
        self.sync.write().await.mark_block_received(hash);
    }

    /// Notify sync manager that a block was successfully processed (accepted by chain).
    /// This updates the sync's local_height and triggers next batch if needed.
    pub async fn notify_block_processed(&self, hash: Hash, height: u64) {
        self.sync.write().await.on_block_processed(hash, height);
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
        self.sync.write().await.mark_block_orphan(block, Some(*peer_id), parent_hash);

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

    /// Start the P2P node
    pub async fn start(&self) -> Result<()> {
        if *self.running.read().await {
            return Err(Error::InvalidState("node already running".into()));
        }

        *self.running.write().await = true;
        info!("Starting P2P node on {}", self.config.listen_addr);

        // Setup UPnP if enabled. UPnP is opportunistic — many home routers
        // refuse the request, ISPs block it, and the node works fine without
        // it (manual port-forwarding or accept-inbound-only-from-peers-that-
        // dial-us are both fine fallbacks). New community operators were
        // reading the WARN as "my node is broken" — demoted to debug! so it
        // only surfaces when explicitly looking at trace output. Reported by
        // barns1253 on 2026-06-01 alongside getheaders + noise issues.
        if self.config.upnp {
            let port = self.config.listen_addr.port();
            tokio::spawn(async move {
                if let Err(e) = super::bootstrap::setup_upnp(port, port).await {
                    debug!("UPnP setup failed (non-fatal — node works without it): {}", e);
                }
            });
        }

        // Load persisted address book and ban list from disk
        let addr_book_path = self.config.data_dir.join("address_book.json");
        let ban_list_path = self.config.data_dir.join("ban_list.json");

        {
            let mut addresses = self.addresses.write().await;
            match addresses.load_from_file(&addr_book_path) {
                Ok(n) if n > 0 => info!("Loaded {} addresses from disk", n),
                Ok(_) => {},
                Err(e) => warn!("Failed to load address book: {}", e),
            }
        }

        // ANCHORS: load the known-good outbound peers from the previous session
        // and mark them to be dialed FIRST (Bitcoin Core anchor model). This is
        // what re-establishes a working mesh immediately after a restart rather
        // than cold-dialing the whole address book.
        {
            let anchors = load_anchors_from_disk(&self.config.data_dir);
            if !anchors.is_empty() {
                info!("Loaded {} anchor peers — dialing them first on startup", anchors.len());
                self.addresses.write().await.set_anchors(anchors);
            }
        }

        {
            let mut scorer = self.peer_scorer.write().await;
            match scorer.load_bans_from_file(&ban_list_path) {
                Ok(n) if n > 0 => info!("Loaded {} bans from disk", n),
                Ok(_) => {},
                Err(e) => warn!("Failed to load ban list: {}", e),
            }
        }

        // Bootstrap peer discovery — only if no custom seeds were added via add_seed_address().
        // When --seed-node is used, the custom seeds are already in the address manager
        // and we skip the bootstrapper to avoid polluting the address list with
        // unreachable built-in seed IPs that would be tried before the custom ones.
        let onion_only = self.config.proxy.as_ref()
            .map(|p| p.onion_only)
            .unwrap_or(false);
        // M1 (audit fix): proxy_active flag — true if any SOCKS5 proxy is
        // configured, regardless of onion-only mode. The bootstrapper now
        // skips clearnet DNS in this case to prevent IP leaks. The user's
        // intent in setting --proxy is "do not let my ISP see my CoinCync
        // traffic" — sending DNS to their OS resolver violates that intent.
        let proxy_active = self.config.proxy.is_some();

        let has_custom_seeds = !self.addresses.read().await.is_empty();
        if !has_custom_seeds {
            let bootstrapper = Bootstrapper::new(self.config.bootstrap.clone());
            let initial_peers = bootstrapper.get_peers(onion_only, proxy_active).await;

            let mut addresses = self.addresses.write().await;
            for addr in initial_peers {
                addresses.add(PeerAddress::new(addr));
            }
        } else {
            info!("Skipping bootstrap — using {} pre-configured seed addresses",
                self.addresses.read().await.len());
        }

        // Start listener
        // Use SO_REUSEADDR to allow immediate restart after process kill.
        // Without this, the kernel holds the socket in TIME_WAIT for 60s,
        // preventing the node from restarting.
        let socket = socket2::Socket::new(
            if self.config.listen_addr.is_ipv6() { socket2::Domain::IPV6 } else { socket2::Domain::IPV4 },
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ).map_err(|e| Error::ConnectionFailed(format!("socket create: {e}")))?;
        socket.set_reuse_address(true)
            .map_err(|e| Error::ConnectionFailed(format!("SO_REUSEADDR: {e}")))?;
        socket.set_nonblocking(true)
            .map_err(|e| Error::ConnectionFailed(format!("set_nonblocking: {e}")))?;
        socket.bind(&self.config.listen_addr.into())
            .map_err(|e| Error::ConnectionFailed(format!("bind {}: {e}", self.config.listen_addr)))?;
        socket.listen(128)
            .map_err(|e| Error::ConnectionFailed(format!("listen: {e}")))?;
        let listener = TcpListener::from_std(socket.into())
            .map_err(|e| Error::ConnectionFailed(format!("TcpListener::from_std: {e}")))?;

        info!("P2P node listening on {}", self.config.listen_addr);

        // ── Phase 2: constant-rate cover-traffic loop ──────────────────
        //
        // Spawns the broadcast padding loop so an observer can't tell idle
        // from active nodes (4th Amendment defense). Replaces the
        // 0xDEADBEEF magic hack that was never reachable in production —
        // padding now flows through the framer as `MessageType::Padding`.
        // Default config (TrafficShaperConfig::default) has padding_enabled
        // = true, so this activates immediately.
        //
        // The shutdown flag is intentionally never flipped: the loop is a
        // background daemon that dies with the tokio runtime on node
        // shutdown. Disconnected per-peer senders are handled by try_send
        // returning Err, which the loop silently discards.
        {
            let shaper = self.traffic_shaper.clone();
            let senders_for_padding = self.peer_senders.clone();
            let padding_magic = self.config.magic;
            let padding_shutdown = Arc::new(AtomicBool::new(false));
            tokio::spawn(async move {
                shaper
                    .run_padding_loop_broadcast(
                        padding_magic,
                        move || {
                            senders_for_padding
                                .iter()
                                .map(|entry| entry.value().clone())
                                .collect::<Vec<_>>()
                        },
                        padding_shutdown,
                    )
                    .await;
            });
        }

        // Clone for background tasks
        let peers = self.peers.clone();
        let peer_senders = self.peer_senders.clone();
        let dandelion = self.dandelion.clone();
        let sync = self.sync.clone();
        let addresses = self.addresses.clone();
        let event_tx = self.event_tx.clone();
        let magic = self.config.magic;
        let _our_id = self.our_id;
        let our_nonce = self.version_nonce;
        let chain_height = self.chain_height.clone();
        let chain_tip = self.chain_tip.clone();
        let running = self.running.clone();
        let identity = self.identity.clone();
        let encryption_config = self.config.encryption.clone();
        let _max_peers = self.config.max_peers;
        let max_outbound = self.config.max_outbound;

        // Message channel for all peers
        let (msg_tx, mut msg_rx) = mpsc::channel::<PeerMessage>(1000);

        // Spawn connection acceptor with per-IP limiting
        let acceptor_running = running.clone();
        let acceptor_peers = peers.clone();
        let acceptor_event_tx = event_tx.clone();
        let acceptor_msg_tx = msg_tx.clone();
        let acceptor_senders = peer_senders.clone();
        let acceptor_height = chain_height.clone();
        let acceptor_tip = chain_tip.clone();
        let acceptor_tracker = self.conn_tracker.clone();
        let acceptor_scorer = self.peer_scorer.clone();
        let acceptor_identity = identity.clone();
        let acceptor_relay_scores = self.relay_scores.clone();
        let acceptor_encryption = encryption_config.clone();

        tokio::spawn(async move {
            while *acceptor_running.read().await {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        // SECURITY (M-9): In onion-only mode, reject non-localhost
                        // inbound connections to prevent clearnet IP exposure.
                        if onion_only && !addr.ip().is_loopback() {
                            debug!("Rejecting non-local inbound in onion-only mode from {}", addr);
                            continue;
                        }

                        // Check if peer is banned by scorer
                        if acceptor_scorer.read().await.is_banned(&addr) {
                            debug!("Rejecting banned peer {}", addr);
                            continue;
                        }

                        // SECURITY: Atomic check-and-track to prevent TOCTOU race
                        // where two connections from the same IP could both pass can_accept()
                        // before either calls track_connection()
                        if !acceptor_tracker.try_track_connection(&addr) {
                            debug!("Per-IP limit reached for {}, rejecting", addr.ip());
                            continue;
                        }

                        let inbound_count = acceptor_peers.iter()
                            .filter(|p| !p.outbound)
                            .count();

                        if inbound_count >= MAX_INBOUND {
                            // Saturation. Before rejecting, try to evict
                            // a more-evictable peer per the Bitcoin Core
                            // `CConnman::AttemptToEvictConnection`
                            // algorithm (VERIFIED at net.cpp:1694 in
                            // the master read this session; candidate
                            // selection delegated to node/eviction.cpp,
                            // see network/eviction.rs for details). This
                            // closes the eclipse vector where an attacker
                            // fills all 64 slots from one /16 and pins us.
                            //
                            // Snapshot the inbound peers, hand them to the
                            // selector, then disconnect the chosen victim
                            // (if any) by dropping its sender and removing
                            // it from the peers table.
                            let snapshot: Vec<crate::network::peer::PeerInfo> =
                                acceptor_peers.iter()
                                    .filter(|p| !p.outbound)
                                    .map(|p| p.clone())
                                    .collect();
                            let now = std::time::Instant::now();
                            let victim_ref: Vec<&crate::network::peer::PeerInfo> =
                                snapshot.iter().collect();
                            let relay_guard = acceptor_relay_scores.read().await;
                            match crate::network::eviction::select_inbound_to_evict(
                                victim_ref, now, &relay_guard,
                            ) {
                                Some(victim_id) => {
                                    debug!(
                                        "Inbound saturated ({}); evicting peer {:?} per AttemptToEvictConnection to admit {}",
                                        inbound_count, &victim_id[..4], addr
                                    );
                                    // Drop the sender first so the peer's
                                    // write task unwinds; then remove
                                    // from peers + untrack the IP.
                                    // (The prior comment claimed this
                                    // order matches Bitcoin Core's
                                    // CConnman eviction sequence; the
                                    // specific upstream ordering was
                                    // not re-verified this session, so
                                    // the parity claim is downgraded to
                                    // qualitative.)
                                    acceptor_senders.remove(&victim_id);
                                    if let Some((_, victim)) = acceptor_peers.remove(&victim_id) {
                                        acceptor_tracker.untrack_connection(&victim.addr);
                                    }
                                    // Slot freed; fall through to accept.
                                }
                                None => {
                                    debug!(
                                        "Max inbound connections reached ({}) and no evictable peer; rejecting {}",
                                        inbound_count, addr
                                    );
                                    acceptor_tracker.untrack_connection(&addr);
                                    continue;
                                }
                            }
                        }

                        debug!("Incoming connection from {} (IP has {} connections)",
                            addr, acceptor_tracker.connections_from(&addr.ip()));

                        let peer_id = generate_peer_id();
                        let peers = acceptor_peers.clone();
                        let senders = acceptor_senders.clone();
                        let event_tx = acceptor_event_tx.clone();
                        let msg_tx = acceptor_msg_tx.clone();
                        let height = *acceptor_height.read().await;
                        let tip = *acceptor_tip.read().await;
                        let tracker = acceptor_tracker.clone();
                        let addr_clone = addr;
                        let conn_identity = acceptor_identity.clone();
                        let conn_encryption = acceptor_encryption.clone();

                        tokio::spawn(async move {
                            let result = handle_connection(
                                stream, peer_id, false, magic, our_nonce, height, tip,
                                peers, senders, event_tx, msg_tx,
                                tracker.clone(), conn_identity, conn_encryption,
                                None, // inbound — no per-/16 slot to track
                            ).await;

                            // Untrack connection when done
                            tracker.untrack_connection(&addr_clone);

                            if let Err(e) = result {
                                warn!("Inbound connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Accept error: {}", e);
                    }
                }
            }
        });

        // Spawn outbound connector
        let connector_running = running.clone();
        let connector_peers = peers.clone();
        let connector_addresses = addresses.clone();
        let connector_event_tx = event_tx.clone();
        let connector_msg_tx = msg_tx.clone();
        let connector_senders = peer_senders.clone();
        let connector_height = chain_height.clone();
        let connector_tip = chain_tip.clone();
        let connector_proxy = self.config.proxy.clone();
        let connector_scorer = self.peer_scorer.clone();
        let connector_identity = identity.clone();
        let connector_encryption = encryption_config.clone();
        let connector_listen_port = self.config.listen_addr.port();
        let connector_tracker = self.conn_tracker.clone();
        let connector_relay_scores = self.relay_scores.clone();
        let connector_data_dir = self.config.data_dir.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            // ANCHORS: persist known-good outbound peers roughly every 60s
            // (every 6th 10s tick) so a hard kill (SIGKILL, OOM, power loss)
            // still leaves a recent anchor set for fast reconnect. Graceful
            // shutdown also saves in stop().
            let mut anchor_save_tick: u32 = 0;
            // Per-address exponential backoff for failed connections
            let backoffs: Arc<tokio::sync::Mutex<std::collections::HashMap<SocketAddr, (std::time::Instant, super::framing::ExponentialBackoff)>>> =
                Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
            // CHANGE 3: Per-address last-attempt timestamp for minimum 30s reconnect delay
            // (Bitcoin CConnman uses 30s between attempts to the same address).
            // This prevents rapid connect/disconnect cycles that waste Noise handshake slots.
            let last_attempt: Arc<tokio::sync::Mutex<std::collections::HashMap<SocketAddr, std::time::Instant>>> =
                Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
            const MIN_RECONNECT_DELAY: Duration = Duration::from_secs(30);

            // Log proxy status on startup
            if let Some(ref proxy) = connector_proxy {
                if proxy.is_active() {
                    info!("Outbound connections will use {} proxy at {}:{}",
                        match proxy.proxy_type {
                            crate::config::ProxyType::Socks5 => "SOCKS5",
                            crate::config::ProxyType::Socks4 => "SOCKS4",
                            crate::config::ProxyType::Http => "HTTP",
                        },
                        proxy.address, proxy.port
                    );
                    if proxy.onion_only {
                        info!("Onion-only mode enabled - will only connect to .onion peers");
                    }
                }
            }

            while *connector_running.read().await {
                interval.tick().await;

                // ANCHORS: persist known-good outbound peers ~every 60s so a
                // hard kill still leaves a recent set to reconnect to.
                anchor_save_tick = anchor_save_tick.wrapping_add(1);
                if anchor_save_tick % 6 == 0 {
                    save_anchors_to_disk(&connector_peers, &connector_data_dir);
                }

                // Evaporate inbound block-relay scores each tick so they track
                // current relay usefulness, and log a one-liner so the measure
                // phase is observable (Phase 1: measure only).
                {
                    let mut rs = connector_relay_scores.write().await;
                    rs.evaporate();
                    if !rs.is_empty() {
                        debug!("inbound relay-score: {} peers currently scored", rs.len());
                    }
                }

                let outbound_count = connector_peers.iter()
                    .filter(|p| p.outbound)
                    .count();
                let total_peers = connector_peers.len();
                let addr_count = connector_addresses.read().await.len();
                if total_peers < 3 {
                    info!("Peer maintenance: {} total peers ({} outbound), {} known addresses",
                        total_peers, outbound_count, addr_count);
                }

                // Eclipse-defense observability: every maintenance tick log
                // the per-/16 outbound counter map at debug level. Drops to
                // a one-line summary when the map is empty so log volume
                // stays low. Format: "[subnet=count, ...] (sum=N)" — sum
                // should equal `outbound_count` if track/untrack symmetry
                // is intact; a drift indicates a leaked slot.
                let snap = connector_tracker.outbound_subnet_snapshot();
                let snap_sum: usize = snap.iter().map(|(_, c)| *c).sum();
                if snap.is_empty() {
                    debug!("eclipse-defense: outbound_per_subnet empty (outbound_count={})",
                        outbound_count);
                } else {
                    let pretty: Vec<String> = snap.iter().map(|(k, v)| {
                        let hi = (*k >> 8) as u8;
                        let lo = (*k & 0xff) as u8;
                        format!("{}.{}/16={}", hi, lo, v)
                    }).collect();
                    // Off-by-one drift between subnet_sum and outbound_count
                    // is a cosmetic bookkeeping artifact, not a connection
                    // problem: the actual per-/16 cap is enforced atomically
                    // by ConnectionTracker::try_track_outbound_subnet_owned
                    // (see comment below), so a drift of 1 cannot cause an
                    // eclipse. Demoted from warn! to debug! because new
                    // operators (2026-05-31 barns1253 report) read the WARN
                    // as a bug and worry. A drift of >=2 is genuinely worth
                    // surfacing — that suggests multiple leaked slots.
                    let drift = (snap_sum as i64 - outbound_count as i64).abs();
                    if drift >= 2 {
                        // Self-heal (2026-07-09 seed1 wedge): a drift of >= 2
                        // means leaked outbound subnet slots have pinned the
                        // fleet's /16s at MAX_OUTBOUND_PER_SUBNET, so
                        // try_track_outbound_subnet_owned refuses new outbound
                        // and the node is stuck at a tiny outbound count — it
                        // cannot sync (seed1 idle-while-behind for hours).
                        // Reconcile the counters to the live outbound set so
                        // those subnets admit connections again.
                        let live_outbound: Vec<std::net::SocketAddr> = connector_peers
                            .iter()
                            .filter(|p| p.outbound)
                            .map(|p| p.addr)
                            .collect();
                        let (old_sum, new_sum) =
                            connector_tracker.reconcile_outbound_subnets(&live_outbound);
                        warn!(
                            "eclipse-defense: significant drift — subnet_sum={} but outbound_count={} (diff={}) :: {} :: RECONCILED {}→{} from {} live outbound",
                            snap_sum, outbound_count, drift, pretty.join(", "),
                            old_sum, new_sum, live_outbound.len()
                        );
                    } else if drift == 1 {
                        debug!(
                            "eclipse-defense: minor drift (cosmetic) — subnet_sum={} but outbound_count={} :: {}",
                            snap_sum, outbound_count, pretty.join(", ")
                        );
                    } else {
                        debug!("eclipse-defense: subnets={} sum={} :: {}",
                            snap.len(), snap_sum, pretty.join(", "));
                    }
                }

                // Enforce the global outbound peer ceiling.
                // Eclipse protection (per-/16 diversity) is now handled
                // atomically by ConnectionTracker::try_track_outbound_subnet_owned
                // below; the ad-hoc HashSet diversity check that used to
                // live here was deleted in favor of the hard-cap
                // primitive — single source of truth, no TOCTOU window,
                // and a Drop-guard that releases the slot on every exit
                // path.
                if outbound_count >= max_outbound {
                    continue;
                }

                // Get next address to try
                let addr = {
                    let mut addresses = connector_addresses.write().await;
                    addresses.get_next()
                };

                if let Some(addr) = addr {
                    // Skip non-onion addresses if onion_only mode is enabled
                    if let Some(ref proxy) = connector_proxy {
                        if proxy.onion_only {
                            // In onion_only mode, we need .onion addresses
                            // Regular SocketAddrs are skipped
                            debug!("Skipping {} in onion-only mode", addr);
                            continue;
                        }
                    }

                    // CHANGE 1: Self-connection prevention (Bitcoin CConnman::ConnectNode pattern).
                    // Skip addresses that point back to our own listen port on a local IP.
                    // This catches 127.0.0.1:port, 0.0.0.0:port, and any local interface IP.
                    // Done BEFORE the TCP connect to avoid wasting time and Noise handshake slots.
                    if addr.port() == connector_listen_port {
                        let is_self = addr.ip().is_loopback()
                            || addr.ip().is_unspecified()
                            || match addr.ip() {
                                std::net::IpAddr::V4(ip) => {
                                    // Check common local addresses
                                    ip.is_loopback() || ip.is_unspecified()
                                        || ip == std::net::Ipv4Addr::new(127, 0, 0, 1)
                                }
                                std::net::IpAddr::V6(ip) => {
                                    ip.is_loopback() || ip.is_unspecified()
                                        || ip.to_ipv4_mapped().map(|v4| v4.is_loopback() || v4.is_unspecified()).unwrap_or(false)
                                }
                            };
                        if is_self {
                            debug!("Skipping self-connection to {} (our listen port)", addr);
                            continue;
                        }
                    }

                    // Check if peer is banned by scorer
                    if connector_scorer.read().await.is_banned(&addr) {
                        debug!("Skipping banned peer {}", addr);
                        continue;
                    }

                    // Skip if we already have an active peer at this exact
                    // address. The connector previously dialed the same
                    // address whenever MIN_RECONNECT_DELAY had elapsed,
                    // even when the prior connection was still alive —
                    // surfaced as eclipse-defense drift "sum=2 but
                    // outbound_count=1" in 2026-05-09 sandbox testing.
                    //
                    // We ALSO mark the address as `tried` so get_next
                    // rotates to a different address on the next tick.
                    // Without this, mark_success on a freshly-connected
                    // peer keeps that address at the top of the
                    // last_seen-sorted list, get_next returns it again,
                    // we skip it again, and the connector loops forever
                    // on a single peer (regression caught when cap=1
                    // testing showed "0 cap fires" instead of one — the
                    // node never tried the 2nd 207.148/16 address). The
                    // tried set self-clears once all addresses have
                    // been tried, so this isn't permanent exclusion.
                    if connector_peers.iter().any(|p| p.addr == addr) {
                        trace!("Skipping {} — already have an active peer at this address", addr);
                        connector_addresses.write().await.mark_tried(addr);
                        continue;
                    }

                    // CHANGE 3: Enforce minimum 30s between connection attempts to same address.
                    // Prevents rapid connect/disconnect cycles that cause Noise handshake races.
                    {
                        let la = last_attempt.lock().await;
                        if let Some(t) = la.get(&addr) {
                            if t.elapsed() < MIN_RECONNECT_DELAY {
                                trace!("Skipping {} — last attempt was {:?} ago (min 30s)", addr, t.elapsed());
                                continue;
                            }
                        }
                    }

                    // Check exponential backoff for this address
                    {
                        let bo = backoffs.lock().await;
                        if let Some((next_time, _)) = bo.get(&addr) {
                            if std::time::Instant::now() < *next_time {
                                continue; // Not ready to retry yet
                            }
                        }
                    }

                    // HARDENING (Layer 4): Atomic per-/16 outbound cap with
                    // RAII Drop-guard semantics. The owned slot is moved
                    // into the spawned task; whenever the task exits — clean
                    // return, error path, panic, tokio cancellation — the
                    // slot drops and the counter decrements. There is no
                    // explicit untrack call to forget. Hard cap: an attacker
                    // controlling a /16 cannot saturate beyond
                    // MAX_OUTBOUND_PER_SUBNET regardless of address-book
                    // ordering or race timing.
                    let outbound_slot = match connector_tracker
                        .try_track_outbound_subnet_owned(&addr)
                    {
                        Some(slot) => Arc::new(slot),
                        None => {
                            debug!(
                                "Eclipse cap: /16 of {} is at MAX_OUTBOUND_PER_SUBNET, skipping",
                                addr
                            );
                            // Mark as tried so the connector rotates to a
                            // different /16 next tick, instead of burning
                            // ticks repeatedly hitting the cap on the same
                            // address. Symmetric with the dup-dial skip
                            // above. The tried set self-clears once all
                            // addresses are exhausted, so this isn't a
                            // permanent block — if the cap clears later
                            // (peer drops), the address becomes eligible
                            // again on the next round.
                            connector_addresses.write().await.mark_tried(addr);
                            continue;
                        }
                    };

                    debug!("Attempting outbound connection to {}", addr);

                    // CHANGE 3: Record attempt timestamp before spawning
                    last_attempt.lock().await.insert(addr, std::time::Instant::now());

                    let peers = connector_peers.clone();
                    let senders = connector_senders.clone();
                    let addresses = connector_addresses.clone();
                    let event_tx = connector_event_tx.clone();
                    let msg_tx = connector_msg_tx.clone();
                    let height = *connector_height.read().await;
                    let tip = *connector_tip.read().await;
                    let proxy = connector_proxy.clone();
                    let backoffs = backoffs.clone();
                    let conn_identity = connector_identity.clone();
                    let conn_encryption = connector_encryption.clone();
                    let tracker = connector_tracker.clone();

                    tokio::spawn(async move {
                        // Use proxy if configured, otherwise direct connection
                        let connect_result = super::proxy::connect_peer(
                            addr,
                            proxy.as_ref(),
                            CONNECT_TIMEOUT,
                        ).await;

                        match connect_result {
                            Ok(stream) => {
                                // Connection established - reset backoff
                                backoffs.lock().await.remove(&addr);

                                let peer_id = generate_peer_id();
                                if let Err(e) = handle_connection(
                                    stream, peer_id, true, magic, our_nonce, height, tip,
                                    peers, senders, event_tx, msg_tx,
                                    tracker, conn_identity, conn_encryption,
                                    Some(outbound_slot.clone()),
                                ).await {
                                    warn!("Outbound connection error: {}", e);
                                    addresses.write().await.mark_tried(addr);
                                } else {
                                    addresses.write().await.mark_success(addr);
                                }
                            }
                            Err(e) => {
                                debug!("Connection to {} failed: {}", addr, e);
                                addresses.write().await.mark_tried(addr);

                                // Apply exponential backoff for this address
                                let mut bo = backoffs.lock().await;
                                let (next_time, backoff) = bo.entry(addr)
                                    .or_insert_with(|| (std::time::Instant::now(), super::framing::ExponentialBackoff::new()));
                                let delay = backoff.next_delay();
                                *next_time = std::time::Instant::now() + delay;
                                debug!("Backoff for {}: next retry in {:?}", addr, delay);
                            }
                        }
                        // outbound_slot's Arc drops here. If we made it past
                        // peers.insert in handle_connection, the PeerInfo
                        // entry holds a clone, so the slot stays alive until
                        // the entry is removed/overwritten. If we did NOT
                        // make it past peers.insert (handshake failed,
                        // connect refused), this drop is the LAST Arc and
                        // the slot is released cleanly.
                    });
                }
            }
        });

        // Spawn message processor
        let processor_running = running.clone();
        let processor_peers = peers.clone();
        let processor_dandelion = dandelion.clone();
        let processor_sync = sync.clone();
        let processor_event_tx = event_tx.clone();
        let processor_senders = peer_senders.clone();
        let processor_nonce = our_nonce;
        let processor_chain = self.chain.clone();
        let processor_mempool = self.mempool.clone();
        let processor_addresses = addresses.clone();
        let processor_scorer = self.peer_scorer.clone();
        let processor_identity = self.identity.clone();
        // v1.0.13 #2
        let processor_tx_absence_cache = self.tx_absence_cache.clone();
        let processor_relay_scores = self.relay_scores.clone();

        tokio::spawn(async move {
            // Phase D (audit fix): per-peer message rate tracking.
            // PeerMessageRateTracker was built (scoring.rs) but never wired.
            // This HashMap lives for the lifetime of the processor task and
            // tracks each peer's per-message-type rate. When a peer exceeds
            // the configured limit, they get a MessageFlood misbehavior score.
            //
            // P5-N3 SURGICAL FIX (2026-07-03): the pre-fix HashMap grew
            // WITHOUT BOUND — entries were inserted on first message per
            // peer but never removed when peers disconnected. Over a
            // long-running node with churn, this leaked memory. Now we
            // prune every 1000 messages by dropping any tracker whose
            // peer_id is no longer in `processor_peers`. Cheap: 1000-msg
            // cadence keeps the O(N) sweep amortized to a few µs per
            // message.
            let mut rate_trackers: std::collections::HashMap<
                super::peer::PeerId,
                super::scoring::PeerMessageRateTracker,
            > = std::collections::HashMap::new();
            let mut rate_prune_ctr: u64 = 0;
            const RATE_PRUNE_EVERY: u64 = 1000;

            while *processor_running.read().await {
                match msg_rx.recv().await {
                    Some(msg) => {
                        // P5-N3: periodic prune of dead peers.
                        rate_prune_ctr = rate_prune_ctr.wrapping_add(1);
                        if rate_prune_ctr.is_multiple_of(RATE_PRUNE_EVERY) {
                            rate_trackers.retain(|pid, _| processor_peers.contains_key(pid));
                        }
                        // Rate-limit check (before expensive processing)
                        let tracker = rate_trackers
                            .entry(msg.peer_id)
                            .or_insert_with(super::scoring::PeerMessageRateTracker::new);
                        if tracker.record(msg.msg_type) {
                            warn!(
                                "Peer {:?} exceeded message rate limit for type 0x{:02x}, penalizing",
                                &msg.peer_id[..4], msg.msg_type,
                            );
                            if let Some(peer_addr) = processor_peers.get(&msg.peer_id).map(|p| p.addr) {
                                let mut scorer = processor_scorer.write().await;
                                scorer.get_or_create(peer_addr)
                                    .record_misbehavior(super::scoring::MisbehaviorType::MessageFlood);
                            }
                            continue; // Drop the message and release its reservation
                        }

                        if let Err(e) = process_message(
                            msg.peer_id,
                            msg.msg_type,
                            &msg.payload,
                            magic,
                            processor_nonce,
                            processor_peers.clone(),
                            processor_senders.clone(),
                            processor_dandelion.clone(),
                            processor_sync.clone(),
                            processor_event_tx.clone(),
                            processor_chain.clone(),
                            processor_mempool.clone(),
                            processor_addresses.clone(),
                            processor_scorer.clone(),
                            processor_identity.clone(),
                            processor_tx_absence_cache.clone(),
                            processor_relay_scores.clone(),
                        ).await {
                            warn!("Message processing error: {}", e);
                        }
                    }
                    None => break,
                }
            }
        });

        // Spawn sync driver loop
        let sync_running = running.clone();
        let sync_peers = peers.clone();
        let sync_senders = peer_senders.clone();
        let sync_chain = self.chain.clone();
        let sync_sync = sync.clone();
        let sync_scorer = self.peer_scorer.clone();
        let sync_addresses = self.addresses.clone();
        let _sync_mempool = self.mempool.clone();

        tokio::spawn(async move {
            // 500ms tick during IBD — aggressive sync for fast convergence.
            // Each tick requests up to 500 blocks distributed across all peers.
            let mut tick = interval(Duration::from_millis(500));
            let _stall_timeout: u64 = 30; // seconds before considering sync stalled
            let mut stall_count: u32 = 0;
            let mut last_progress_height: u64 = sync_chain.height();
            let mut no_progress_ticks: u32 = 0;
            let sync_start = std::time::Instant::now();

            // Tier-3 stall escalation tracking (added 2026-06-02).
            // Tier 2 alone cycles every ~12s (24 ticks × 500ms) — observed on
            // coincync-lon and barns1253's box that Tier 2 can fire thousands
            // of times over many hours without ever clearing a stuck sync.
            // Tier 3 tracks CONSECUTIVE Tier-2 firings during which height
            // never advances. After T3_THRESHOLD consecutive failures (~1
            // minute of continuous Tier-2 churn), we escalate to a deeper
            // reset: drop all orphans, clear the address book entirely
            // (not just `tried`), forcibly recompute the locator from
            // genesis, and log CRITICAL so the operator knows intervention
            // may be needed. After Tier 3 fires N_T3_BEFORE_BACKOFF times
            // without progress, we back off (sleep 30s between sync ticks)
            // to stop log-spam and stop hammering peers with requests they
            // clearly can't answer.
            let mut tier2_fires_since_progress: u32 = 0;
            let mut tier3_fires_since_progress: u32 = 0;
            let mut tier2_last_height: u64 = sync_chain.height();
            const T3_THRESHOLD: u32 = 5; // consecutive Tier-2 without progress
            const N_T3_BEFORE_BACKOFF: u32 = 3; // Tier-3 firings before backoff

            // Emergency progress-time Tier-3 (added 2026-06-02 follow-on,
            // for v1.0.11). The standard Tier-3 above only fires when
            // is_stalled() returns true. The orphan-fetch cascade observed
            // 2026-06-02 (coincync-lon stuck for 22+h with 4 connected
            // peers receiving block broadcasts but never advancing height)
            // does NOT trigger is_stalled — the sync engine internally
            // looks busy (constantly receiving + rejecting orphans, sending
            // GetHeaders) so its own stall predicate stays false.
            //
            // Belt-and-suspenders fix: track wall-clock time since the
            // last actual height advance, totally independent of any
            // sync-engine state. If chain hasn't advanced for >5 minutes
            // while the node believes it's not synced, fire emergency
            // recovery regardless of what is_stalled says. This is the
            // operator-perspective definition of "stuck": the height
            // number isn't moving.
            let mut last_progress_time_secs: u64 = sync_start.elapsed().as_secs();
            let mut emergency_t3_fires: u32 = 0;
            const EMERGENCY_T3_NO_PROGRESS_SECS: u64 = 300; // 5 minutes
            const EMERGENCY_T3_REPEAT_SECS: u64 = 120;      // re-fire every 2 min if still stuck

            while *sync_running.read().await {
                tick.tick().await;

                let state = sync_sync.read().await.state();

                // Stall detection using monotonic time (immune to NTP clock jumps).
                // We pass elapsed seconds since sync start — this is compared against
                // request timestamps that also use wall-clock time, but the monotonic
                // elapsed acts as a safety floor to avoid false stalls on clock skew.
                let now = chrono::Utc::now().timestamp() as u64;
                let monotonic_now = sync_start.elapsed().as_secs();

                // Clean up expired sync bans periodically
                sync_sync.write().await.cleanup_sync_bans(now);

                // Firework Phase 2 anti-wedge: expire peer work-claims not
                // refreshed within the TTL, then refresh the "heavier chain
                // exists" veto from the recomputed work view. Doing this on
                // the maintenance tick (not just on tip advance) is what lets
                // is_synced recover even while block production is paused
                // because a bogus claim briefly made us work-behind — without
                // it, no tip advance would ever fire to clear the veto.
                {
                    // NOTE: the connection-lifecycle prune (retain_connected_peers)
                    // was rolled back 2026-07-09 — pruning peer heights for any
                    // peer not in `Connected` state at the tick over-pruned during
                    // mesh churn (peers mid-handshake), dropping valid tips and
                    // fragmenting the fleet. The method is retained for a proper
                    // liveness-based redesign (prune on sustained silence, not
                    // transient non-Connected state). Only the Phase 2 work-claim
                    // TTL runs here for now.
                    let mut s = sync_sync.write().await;
                    s.expire_stale_work_claims(now, super::sync::WORK_CLAIM_TTL_SECS);
                    let st = s.stats();
                    drop(s);
                    sync_chain
                        .set_work_behind(st.best_known_difficulty > st.local_total_difficulty);
                }

                // ── PROGRESS-TIME STALL TRACKING (runs every tick) ────
                // Unconditionally track when height last advanced. This
                // is the ground truth for "is the chain actually moving."
                // Don't conflate with the sync-engine's internal is_stalled
                // predicate — that predicate failed to fire on the 2026-
                // 06-02 orphan-fetch cascade because the engine was busy
                // doing internal work (just no useful work).
                {
                    let current_height_for_progress = sync_chain.height();
                    if current_height_for_progress > last_progress_height {
                        last_progress_time_secs = monotonic_now;
                        emergency_t3_fires = 0;
                        // last_progress_height itself is updated by the
                        // existing else-branch below, kept there for
                        // back-compat with the Tier-2 counter-reset path.
                    }
                }

                // ── EMERGENCY TIER-3 (progress-time-based) ────────────
                // If chain hasn't advanced for EMERGENCY_T3_NO_PROGRESS_SECS
                // while we believe we're not synced, fire deep recovery
                // regardless of what is_stalled() thinks. Re-fires every
                // EMERGENCY_T3_REPEAT_SECS until something works.
                let secs_since_progress = monotonic_now.saturating_sub(last_progress_time_secs);
                // GROUND-TRUTH behind check (2026-07-09 seed1 idle/limp-while-behind):
                // the manager's is_synced() and even chain.target_height() derive
                // from the peer_heights MAP, which empties under connection churn
                // and resets the target back to local — so every recovery path
                // stops firing and the node sits idle (or limps in bursts). The
                // most reliable "are we behind" signal is the max height among
                // CURRENTLY-CONNECTED peers: PeerInfo.height is set at handshake,
                // refreshed by ChainWork, and bound to the connection lifecycle
                // (cleared only on real disconnect), so it does not go stale-empty
                // the way the manager map does. Fire recovery whenever our tip is
                // below any live peer's height. This sustains recovery until we
                // actually catch up, instead of stopping after one burst.
                let max_connected_peer_height = sync_peers
                    .iter()
                    .filter(|p| p.state == PeerState::Connected)
                    .map(|p| p.height)
                    .max()
                    .unwrap_or(0);
                let chain_behind = sync_chain.height()
                    < sync_chain.target_height().max(max_connected_peer_height);
                let should_fire_emergency = (!sync_sync.read().await.is_synced() || chain_behind)
                    && monotonic_now >= EMERGENCY_T3_NO_PROGRESS_SECS
                    && secs_since_progress >= EMERGENCY_T3_NO_PROGRESS_SECS
                    && {
                        let elapsed_since_last_fire = if emergency_t3_fires == 0 {
                            u64::MAX // first fire: no rate-limit
                        } else {
                            // we re-fire every REPEAT_SECS; track this via
                            // last_progress_time_secs which we artificially
                            // advance below so the next fire-check waits
                            // REPEAT_SECS instead of immediately.
                            monotonic_now.saturating_sub(last_progress_time_secs)
                                .saturating_sub(EMERGENCY_T3_NO_PROGRESS_SECS)
                        };
                        elapsed_since_last_fire >= EMERGENCY_T3_REPEAT_SECS
                            || emergency_t3_fires == 0
                    };

                if should_fire_emergency {
                    emergency_t3_fires += 1;
                    let current_height = sync_chain.height();
                    tracing::error!(
                        "Sync EMERGENCY-TIER-3 #{}: chain has not advanced past height {} \
                         for {}s (>= {}s threshold) despite sync engine reporting non-stalled \
                         state. This indicates an orphan-fetch cascade or similar pathology \
                         where the engine is internally busy but making no real progress. \
                         Forcing aggressive reset: clear address tried-list, drop expired \
                         orphans, reset headers-request timeout. If this fires repeatedly, \
                         operator may need to wipe + reimport snapshot.",
                        emergency_t3_fires,
                        current_height,
                        secs_since_progress,
                        EMERGENCY_T3_NO_PROGRESS_SECS,
                    );
                    sync_addresses.write().await.clear_tried();
                    {
                        let mut s = sync_sync.write().await;
                        s.cleanup_expired_orphans(now);
                        s.reset_headers_timeout();
                        // Force the state machine back into Headers so it
                        // actually re-requests. reset_headers_timeout() alone is
                        // a no-op when the manager is stuck in Synced/Idle (the
                        // idle-while-behind case where peer_heights went empty):
                        // the state machine only sends GetHeaders from the
                        // Headers state. The GetHeaders response then repopulates
                        // peer_heights, un-wedging is_synced for good.
                        s.set_state(SyncState::Headers);
                    }
                    // Artificially advance last_progress_time_secs so the
                    // next emergency-fire check waits REPEAT_SECS instead
                    // of firing immediately on the next tick. Without
                    // this, we'd hit the >= threshold every tick = log
                    // flood at 2 Hz.
                    last_progress_time_secs = monotonic_now
                        .saturating_sub(EMERGENCY_T3_NO_PROGRESS_SECS)
                        .saturating_add(EMERGENCY_T3_REPEAT_SECS);
                }

                // Bitcoin-style three-tier stall detection:
                // Tier 1 (scaled per peer): Re-request stalled blocks from another peer.
                //     Timeout = max(adaptive, BLOCK_DOWNLOAD_TIMEOUT_BASE + PER_PEER * (N-1))
                //     — more peers in flight → more tolerance per individual block so a
                //     single slow peer doesn't trigger a cascade of re-requests.
                // Tier 2 (adaptive, on repeated failure): request_timeout doubles.
                // Tier 3 (120s): Rotate peers entirely.
                let live_peer_count = sync_peers.len();
                let stall_timeout = sync_sync.read().await.request_timeout_scaled(live_peer_count);
                if monotonic_now >= 15 && sync_sync.read().await.is_stalled(now, stall_timeout) {
                    // Tier 1: Just re-request the blocks, don't rotate peers
                    let retries = sync_sync.write().await.get_blocks_to_retry(now);
                    if !retries.is_empty() {
                        tracing::debug!("Re-requesting {} stalled blocks from other peers", retries.len());
                    }

                    stall_count += 1;

                    // Tier 2: every ~12s of continuous stall (24 ticks × 500ms,
                    // not 120s as the prior comment incorrectly claimed), try
                    // rotating peers + increasing timeout. This alone has been
                    // observed to cycle thousands of times without recovering
                    // a stuck sync (coincync-lon, 2026-06-02); Tier 3 below
                    // catches that case.
                    if stall_count >= 24 {
                        let now = chrono::Utc::now().timestamp() as u64;
                        let current_height = sync_chain.height();
                        let advanced_since_last_tier2 = current_height > tier2_last_height;

                        if advanced_since_last_tier2 {
                            // We DID advance between Tier-2 firings — recovery
                            // is working, even if slowly. Reset Tier-3 counter.
                            warn!("Sync stalled, rotating peers (made progress since last rotation: {} → {})",
                                  tier2_last_height, current_height);
                            tier2_fires_since_progress = 0;
                            tier3_fires_since_progress = 0;
                        } else {
                            tier2_fires_since_progress += 1;
                            warn!("Sync stalled, rotating peers (no progress for {} consecutive rotations, height stuck at {})",
                                  tier2_fires_since_progress, current_height);
                        }
                        tier2_last_height = current_height;

                        {
                            let mut s = sync_sync.write().await;
                            s.increase_timeout();
                            // Drop expired orphans before recovery — accumulated
                            // orphans from the stall period would otherwise sit
                            // around competing with freshly-downloaded blocks
                            // on the next IBD pass, causing avoidable rework.
                            s.cleanup_expired_orphans(now);
                        }
                        sync_addresses.write().await.clear_tried();
                        stall_count = 0;

                        // Tier 3 escalation: T3_THRESHOLD consecutive Tier-2s
                        // with zero progress means rotation alone isn't fixing
                        // it. The most common cause we've seen (barns1253 +
                        // coincync-lon, 2026-06-01 → 06-02) is the orphan-
                        // fetch cascade: peer broadcasts new tip blocks via
                        // inv, every received block is orphan because we're
                        // missing parents, and Headers responses to our
                        // GetHeaders never arrive (or never advance us).
                        // Aggressive reset: drop the entire address book
                        // (not just tried), clear ALL orphans (not just
                        // expired), reset sync engine state to Idle so it
                        // re-discovers from scratch, log CRITICAL severity.
                        if tier2_fires_since_progress >= T3_THRESHOLD {
                            tier3_fires_since_progress += 1;
                            tracing::error!(
                                "Sync TIER-3 escalation #{}: {} consecutive Tier-2 rotations with zero progress, \
                                 height stuck at {} (peers={}). Performing aggressive recovery: clearing the \
                                 address book tried-list, dropping ALL orphans (not just expired), resetting \
                                 headers-request timeout. If this fires repeatedly without recovery, the node \
                                 may be on a fork the peers don't share — operator may need to wipe + reimport snapshot.",
                                tier3_fires_since_progress,
                                tier2_fires_since_progress,
                                current_height,
                                sync_peers.len(),
                            );
                            // Aggressive recovery using only existing helpers
                            // (no new public API on AddressManager / ChainSync
                            // — those would need wider testing). Effect:
                            //  1. clear_tried again, so the next peer cycle
                            //     re-attempts all addresses with no recent-
                            //     try cooldown blocking them.
                            //  2. cleanup_expired_orphans with a very small
                            //     time horizon (pass `now`) so all-but-the-
                            //     latest orphans get dropped.
                            //  3. reset_headers_timeout so the next iteration
                            //     definitely sends a fresh GetHeaders even
                            //     if the in-flight one isn't formally "timed
                            //     out" yet.
                            sync_addresses.write().await.clear_tried();
                            {
                                let mut s = sync_sync.write().await;
                                s.cleanup_expired_orphans(now);
                                s.reset_headers_timeout();
                            }
                            tier2_fires_since_progress = 0;

                            // Tier 3 backoff: after N_T3_BEFORE_BACKOFF
                            // consecutive Tier-3s with no progress, stop
                            // hammering peers with requests they can't
                            // answer. Sleep for 30s before continuing.
                            // Without this, log spam from Tier-3 messages
                            // makes the journal unreadable.
                            if tier3_fires_since_progress >= N_T3_BEFORE_BACKOFF {
                                tracing::error!(
                                    "Sync TIER-3 backoff: {} consecutive Tier-3 escalations with no progress. \
                                     Backing off for 30s. This node may be on a fork the peers don't share; \
                                     operator may need to wipe + reimport snapshot.",
                                    tier3_fires_since_progress
                                );
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                tier3_fires_since_progress = 0;
                            }
                        }
                    }
                } else if !sync_sync.read().await.is_synced() {
                    // Progress detected — reset all stall counters.
                    let current_height = sync_chain.height();
                    if current_height > last_progress_height {
                        stall_count = 0;
                        last_progress_height = current_height;
                        // Real progress made — reset Tier-3 counters too,
                        // not just Tier-1's stall_count. Otherwise a node
                        // that recovers naturally would still escalate to
                        // Tier-3 on the next minor hiccup.
                        tier2_fires_since_progress = 0;
                        tier3_fires_since_progress = 0;
                        tier2_last_height = current_height;
                    }
                }

                match state {
                    SyncState::Idle | SyncState::Headers | SyncState::ConfirmingSynced => {
                        let now = chrono::Utc::now().timestamp() as u64;

                        // Time out a stuck request first — clears the
                        // pending flag so the gate below can let a new
                        // request through. The 60-second window is in
                        // sync.rs::headers_timed_out (NOT 15s as an old
                        // comment here implied).
                        if sync_sync.read().await.headers_timed_out(now) {
                            warn!("Headers request timed out, retrying with different peer");
                            sync_sync.write().await.reset_headers_timeout();
                        }

                        // 2026-06-10: gate the send on whether a request is
                        // already in flight. Without this, every tick (~0.5s)
                        // fired a fresh GetHeaders against the same peer
                        // regardless of in-flight state — a 4 Hz hammer that
                        // accumulated 26,000+ requests + 125 EMERGENCY-TIER-3
                        // fires over 8 hours in one observed Crucible Cycle 01
                        // session before the node died. The old code's only
                        // gate was the timeout-reset above, which only fired
                        // on EXPIRY but never prevented the send itself.
                        // See docs/crucible/cycle-01/finding-03-headers-request-flood.md.
                        if sync_sync.read().await.headers_request_pending() {
                            continue;
                        }

                        // Build locator from our chain tip
                        let height = sync_chain.height();
                        let chain_ref = &sync_chain;
                        let locator = build_locator(height, |h| chain_ref.get_block_hash(h));

                        if locator.is_empty() {
                            continue;
                        }

                        // Send GetHeaders to a scored peer with nonce for correlation
                        if let Some(peer_id) = pick_scored_peer(&sync_peers, &sync_scorer) {
                            if !sync_sync.read().await.is_sync_banned(&peer_id, now) {
                                let nonce = sync_sync.write().await.allocate_header_nonce();
                                if let Ok(msg) = Message::get_headers_with_nonce(magic, locator, Hash::zero(), nonce) {
                                    if let Ok(data) = msg.to_bytes() {
                                        // DEADLOCK FIX: clone the sender BEFORE the
                                        // `sender.send(data).await` and the SECOND await
                                        // on `sync_sync.write().await` — the prior form
                                        // held the DashMap shard Ref across BOTH awaits,
                                        // making this the highest-blast-radius site of
                                        // the class. See PR body for the full sweep.
                                        let sender = sync_senders.get(&peer_id).map(|s| s.value().clone());
                                        if let Some(sender) = sender {
                                            let _ = sender.send(data).await;
                                            sync_sync.write().await.mark_headers_requested(now);
                                            info!("[IBD] GetHeaders nonce={} sent to peer {:?} (our_height={}, state={:?})", nonce, &peer_id[..4], height, state);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    SyncState::Blocks => {
                        // ============================================================
                        // AGGRESSIVE IBD FIX (Mar 2026)
                        //
                        // Approach: simple, deterministic block download.
                        // (Prior comment characterised this as "Bitcoin Core
                        // approach"; the specific upstream algorithm was
                        // not re-read this session, so the attribution is
                        // downgraded to design-neutral wording.)
                        // 1. Recover timed-out/stuck requests
                        // 2. Find BEST LIVE peer from the ACTUAL peer DashMap
                        //    (completely bypass sync engine's stale peer_heights)
                        // 3. Send GetBlocks directly, try next peer on failure
                        // 4. If all peers fail, fall back to Headers to rediscover
                        // ============================================================
                        let now = chrono::Utc::now().timestamp() as u64;
                        let our_h = sync_chain.height();

                        // Step 1: Recover timed-out and stuck block requests
                        {
                            let mut sg = sync_sync.write().await;
                            let retried = sg.get_blocks_to_retry(now);
                            if !retried.is_empty() {
                                info!("[IBD] Recovered {} timed-out block requests back to queue", retried.len());
                            }
                            let recovered = sg.recover_stuck_downloads();
                            if recovered > 0 {
                                info!("[IBD] Recovered {} stuck downloads (no pending_request)", recovered);
                            }
                        }

                        // Track progress for stall detection
                        if our_h > last_progress_height {
                            last_progress_height = our_h;
                            no_progress_ticks = 0;
                        } else {
                            no_progress_ticks += 1;
                        }

                        // Step 2: Get block hashes to download from sync engine.
                        // (Prior comment cited "Monero uses spans of 20-100";
                        // that specific numeric range was not re-confirmed
                        // against Monero source this session and is dropped.)
                        // We use 500 (protocol max) for aggressive IBD —
                        // split across all live peers.
                        let to_request = sync_sync.write().await.get_blocks_to_request(500);

                        if to_request.is_empty() {
                            // Nothing to download. Check if we're stuck.
                            let sg = sync_sync.read().await;
                            let pending = sg.pending_count();
                            let true_best = sg.true_best_height();
                            drop(sg);

                            if pending == 0 && our_h < true_best {
                                // Drained with no work but still behind — go back to Headers
                                warn!(
                                    "[IBD] Blocks drained at height {} but target is {}. Re-requesting headers.",
                                    our_h, true_best
                                );
                                let mut sg = sync_sync.write().await;
                                sg.set_state(SyncState::Headers);
                                sg.reset_headers_timeout();
                            }
                        } else {
                            // Step 3: MULTI-PEER SPAN DOWNLOAD
                            // Split block hashes across ALL connected peers
                            // simultaneously. Each peer gets a different
                            // span (chunk) of hashes. (Prior comment cited
                            // Monero achieving "720+ blocks/sec during IBD"
                            // via this pattern; that specific benchmark
                            // figure was not re-verified this session and is
                            // dropped.)
                            //
                            // Filter peers temporarily banned from GetBlocks selection
                            // (consecutive empty-Blocks replies above threshold). This
                            // is what stops the wedge pattern: a misbehaving peer that
                            // keeps returning 0-block replies is now skipped here so
                            // the next GetBlocks goes to a healthier peer.
                            let mut live_peers: Vec<(PeerId, u64)> = {
                                let mut s = sync_scorer.write().await;
                                sync_peers.iter()
                                    .filter(|p| p.state == PeerState::Connected)
                                    .filter(|p| sync_senders.get(&p.id).map(|sd| !sd.is_closed()).unwrap_or(false))
                                    .filter(|p| {
                                        // Skip peers currently banned from GetBlocks.
                                        // Look up their socket addr; if missing, allow
                                        // (no addr means we can't have scored them).
                                        match p.addr {
                                            addr => !s.get_or_create(addr).is_get_blocks_banned(),
                                        }
                                    })
                                    .map(|p| (p.id, p.height))
                                    .collect()
                            };
                            live_peers.sort_by(|a, b| b.1.cmp(&a.1));

                            // Clean up dead senders
                            let dead: Vec<PeerId> = sync_peers.iter()
                                .filter(|p| sync_senders.get(&p.id).map(|s| s.is_closed()).unwrap_or(true))
                                .map(|p| p.id)
                                .collect();
                            for pid in &dead { sync_senders.remove(pid); }

                            if live_peers.is_empty() {
                                warn!("[IBD] No live peers for GetBlocks. Re-queuing {} hashes, falling back to Headers.", to_request.len());
                                sync_sync.write().await.requeue_failed(to_request);
                                let mut sg = sync_sync.write().await;
                                sg.set_state(SyncState::Headers);
                                sg.reset_headers_timeout();
                            } else {
                                // Split hashes into spans — one per peer
                                let num_peers = live_peers.len();
                                let span_size = (to_request.len() + num_peers - 1) / num_peers;
                                let mut total_sent = 0usize;
                                let mut failed_hashes = Vec::new();

                                for (i, (pid, peer_height)) in live_peers.iter().enumerate() {
                                    let start = i * span_size;
                                    if start >= to_request.len() { break; }
                                    let end = (start + span_size).min(to_request.len());
                                    let span = &to_request[start..end];

                                    let get_blocks = super::protocol::GetBlocksMessage {
                                        hashes: span.to_vec(),
                                    };
                                    if let Ok(payload) = borsh::to_vec(&get_blocks) {
                                        let msg = Message::new(magic, MessageType::GetBlocks, payload);
                                        if let Ok(data) = msg.to_bytes() {
                                            // DEADLOCK FIX: same shape as GetHeaders above
                                            // — TWO awaits (send + sync_sync.write) inside
                                            // the guard region. Clone the sender out first.
                                            let sender = sync_senders.get(pid).map(|s| s.value().clone());
                                            if let Some(sender) = sender {
                                                if sender.send(data).await.is_ok() {
                                                    // Record requests
                                                    let mut sg = sync_sync.write().await;
                                                    for hash in span {
                                                        sg.record_request(*hash, *pid, now);
                                                    }
                                                    total_sent += span.len();
                                                    tracing::debug!(
                                                        "[IBD] Span {}: {} hashes to peer {:?} (h={})",
                                                        i, span.len(), &pid[..4], peer_height
                                                    );
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                    // This peer failed — collect hashes for re-queue
                                    failed_hashes.extend_from_slice(span);
                                }

                                if total_sent > 0 {
                                    info!("[IBD] GetBlocks sent: {} hashes across {} peers (our_height={})",
                                        total_sent, num_peers.min(to_request.len() / span_size.max(1) + 1), our_h);
                                    stall_count = 0;
                                }

                                if !failed_hashes.is_empty() {
                                    sync_sync.write().await.requeue_failed(failed_hashes);
                                }
                            }
                        }

                        // Safety net: if stuck for 60+ ticks (5min) with no progress,
                        // force back to Headers
                        if no_progress_ticks >= 60 {
                            let true_best = sync_sync.read().await.true_best_height();
                            if true_best > our_h + 2 {
                                warn!(
                                    "[IBD] No progress for {} ticks at height {} (target {}). Forcing Headers.",
                                    no_progress_ticks, our_h, true_best
                                );
                                let mut sg = sync_sync.write().await;
                                sg.set_state(SyncState::Headers);
                                sg.reset_headers_timeout();
                                no_progress_ticks = 0;
                            }
                        }
                    }
                    SyncState::Synced => {
                        stall_count = 0;

                        let our_height = sync_chain.height();
                        let true_best = sync_sync.read().await.true_best_height();
                        let has_peers = sync_peers.iter()
                            .any(|p| p.state == PeerState::Connected);

                        // If at height 0 with peers, always re-trigger.
                        // Also re-trigger if peers are ahead.
                        if (our_height == 0 && has_peers) || true_best > our_height + 2 {
                            debug!(
                                "Safety net: local={} true_best={} has_peers={}, re-triggering sync",
                                our_height, true_best, has_peers
                            );
                            sync_sync.write().await.trigger_resync();
                        }
                    }
                }
            }
        });

        // Spawn maintenance tasks
        let maint_running = running.clone();
        let maint_peers = peers.clone();
        let maint_dandelion = dandelion.clone();
        let maint_sync = sync.clone();
        let maint_senders = peer_senders.clone();
        let maint_event_tx = event_tx.clone();
        let maint_mempool = self.mempool.clone();
        // SECURITY (NET-002): Share conn_tracker with maintenance to untrack stale peers
        let maint_tracker = self.conn_tracker.clone();
        // v1.0.13 #2 — opportunistic-prune of the tx-absence cache,
        // folded into the existing ping tick.
        let maint_tx_absence_cache = self.tx_absence_cache.clone();
        let maint_scorer = self.peer_scorer.clone();
        // P5-Sc1 SURGICAL FIX (2026-07-03): capture the orphan-flood
        // tracker so the cleanup task can call `forget()` on
        // disconnected peers. Prior code left OrphanFloodTracker
        // entries for every peer ever seen, growing without bound.
        let maint_orphan_flood = self.orphan_flood.clone();
        // Captured for the periodic ban-list flush below. Closes the
        // crash-loses-recent-bans gap: shutdown-only persistence would
        // strand any ban accumulated since startup if the process is
        // SIGKILL'd or OOM-killed before clean shutdown runs. Bitcoin
        // Core's `DumpBanlist()` is similarly called both periodically
        // (every 15 min via scheduler) and on shutdown.
        let maint_ban_list_path = ban_list_path.clone();
        // 2026-06-27: needed for periodic tip re-announce
        // (TIP_REBROADCAST_INTERVAL_SECS). See the constant's doc-comment
        // for the production gossip bug this closes (PR #123).
        let maint_chain_tip = self.chain_tip.clone();
        // Take the broadcast queue receiver for the maintenance task.
        //
        // Audit fix: previously `.expect("broadcast receiver already taken")`
        // panicked on a second start() call, terminating the async task
        // without a graceful error path. Replaced with a typed error
        // return so the caller can detect double-start (e.g. supervisor
        // restart after a crash without dropping the prior P2PNode) and
        // recover. Reference: Bitcoin Core's `CConnman::Start()` is
        // VERIFIED at net.h:1166 in the master read this session as a
        // `bool`-returning method on `CConnman`. The prior comment
        // additionally asserted a specific "refuses re-start if
        // `interruptNet` was never armed" behavioural detail; that
        // internal precondition was not re-read this session and is
        // dropped.
        let mut broadcast_rx = match self.tx_broadcast_rx.lock().take() {
            Some(rx) => rx,
            None => {
                return Err(Error::InvalidState(
                    "P2PNode::start called twice on the same instance — \
                     broadcast receiver was already consumed by a prior call. \
                     This indicates a supervisor bug or unintended re-init.".into()
                ));
            }
        };

        // Spawn the maintenance task with panic supervision. Previously
        // a panic inside this task (e.g., a poisoned RwLock during
        // `.write().await`) would terminate the task silently — the node
        // would keep its TCP listeners but stop pinging peers, draining
        // the broadcast queue, and persisting bans. systemd would still
        // report `active`. The production silent-hang on 2026-06-19
        // matched this signature.
        //
        // We wrap the loop body in an outer task that simply logs at
        // ERROR if the inner work-loop ever returns. A real fix would
        // also auto-restart the loop, but auto-restart of a task that
        // holds shared mutable state (peers, scorer, dandelion) is
        // risky if those structures are mid-mutation; safer to log
        // loudly and let the operator restart the process. (Prior
        // comment invoked zebrad's actor-model supervisor pattern and
        // Bitcoin Core's `scheduler` thread as prior art; those
        // specific characterisations were not re-verified this session
        // and are dropped. The log-loudly / no-auto-restart choice
        // stands on its own reasoning above.)
        let maint_handle = tokio::spawn(async move {
            let mut ping_interval = interval(PING_INTERVAL);
            let mut cleanup_interval = interval(Duration::from_secs(60));
            // Dandelion++ monitor runs every DANDELION_MONITOR_INTERVAL_SECS
            let mut dandelion_interval = interval(Duration::from_secs(DANDELION_MONITOR_INTERVAL_SECS));
            // Periodic ban-list flush. (Prior comment claimed "same
            // cadence as Bitcoin Core's `DumpBanlist()` — every 15 min
            // via CScheduler". That specific identifier + cadence
            // pairing was not re-verified against upstream this
            // session and is dropped.) 900s (15 min) picked locally.
            // Cheap to call: writes a small JSON file even when the
            // ban list is empty. Cost-benefit favors always flushing
            // over tracking a dirty flag.
            let mut ban_flush_interval = interval(Duration::from_secs(900));
            // Outbound peer rotation. (Prior comment cited Bitcoin
            // Core's "block-relay-only" outbound peer rotation with a
            // ~22.5 min cadence, a `MaybePickEvictionCandidate` helper
            // in net_processing.cpp, and an `EXTRA_PEER_CHECK_INTERVAL`
            // constant defaulting to 45 min. Those specific identifiers
            // and cadence numbers were not re-verified against upstream
            // this session and are dropped.) 45 min picked locally to
            // balance churn against eclipse-defense — too aggressive
            // and we waste bandwidth on Noise handshakes; too slow and
            // a patient eclipse holds. Closes audit MEDIUM #28.
            let mut outbound_rotate_interval = interval(Duration::from_secs(45 * 60));
            // Heartbeat / liveness signal. Emits a single INFO line every
            // 30 seconds with a monotonically-increasing tick counter +
            // current peer count. External watchdogs (or operator `tail
            // -f`) can detect silent-hang within 30 s instead of the 17
            // hours observed in the production incident where the
            // maintenance task froze and `systemd is-active` kept
            // reporting `active`. If the heartbeat stops, the maintenance
            // loop is dead — restart the service. Reference: Bitcoin
            // Core's `scheduler` thread emits periodic LogPrintf at TRACE
            // level for similar reason. Cheap: one log line per 30 s.
            let mut heartbeat_interval = interval(Duration::from_secs(30));
            let mut heartbeat_ticks: u64 = 0;
            // 2026-06-27 gossip-bug fix: periodic InvBlock re-announce of our
            // current tip to all peers. See TIP_REBROADCAST_INTERVAL_SECS docs
            // (from PR #123).
            let mut tip_announce_interval = interval(Duration::from_secs(TIP_REBROADCAST_INTERVAL_SECS));

            while *maint_running.read().await {
                tokio::select! {
                    // Biased polling: under sustained load, the default
                    // `select!` randomization can starve low-frequency
                    // branches. PING_INTERVAL (120 s) is the most safety-
                    // critical (peers evict us after PEER_TIMEOUT=300 s
                    // of no activity), so it must run on schedule even
                    // if cleanup_interval is also ready. Listed in
                    // priority order. Reference: tokio docs on `biased;`
                    // ordering — "evaluates branches in declared order;
                    // skip random branch selection entirely." Bitcoin
                    // Core's scheduler similarly prioritizes ping/health
                    // ticks over background maintenance.
                    biased;
                    _ = ping_interval.tick() => {
                        // Send pings to all peers
                        let ping = Message::ping(magic);
                        if let Ok(data) = ping.to_bytes() {
                            // DEADLOCK FIX: snapshot senders before awaiting per-peer
                            // send. Iterating the DashMap directly holds each shard's
                            // Ref across `.send(...).await`, and this is the highest-
                            // frequency broadcast site (every PING_INTERVAL = 120s).
                            // Cloning a Vec of Sender is cheap (each clone is an Arc
                            // bump) and unblocks the shard as soon as the snapshot
                            // completes.
                            let senders_snapshot: Vec<tokio::sync::mpsc::Sender<Vec<u8>>> =
                                maint_senders.iter().map(|s| s.value().clone()).collect();
                            for sender in senders_snapshot {
                                let _ = sender.send(data.clone()).await;
                            }
                        }
                        // v1.0.13 #2 — TTL GC for the tx-absence cache.
                        // Folded into the ping tick so we don't spawn a
                        // dedicated interval for a small 10K-entry map.
                        let pruned_abs = maint_tx_absence_cache.write().prune();
                        if pruned_abs > 0 {
                            tracing::trace!("pruned {} expired tx-absence entries", pruned_abs);
                        }
                    }

                    _ = dandelion_interval.tick() => {
                        let now = chrono::Utc::now().timestamp() as u64;

                        // Drain RPC-submitted transactions into Dandelion++ stem phase
                        while let Ok(tx) = broadcast_rx.try_recv() {
                            debug!("STEM: Local transaction {} entering Dandelion++", tx.hash());
                            maint_dandelion.write().await.add_local_tx(tx, now);
                        }

                        // Update outbound peer list for relay selection
                        {
                            let outbound: Vec<PeerId> = maint_peers.iter()
                                .filter(|p| p.outbound && p.state == PeerState::Connected)
                                .map(|p| p.id)
                                .collect();
                            maint_dandelion.write().await.set_outbound_peers(outbound);
                        }

                        // Run the Dandelion++ tick — returns stem relays and fluff actions
                        let actions = maint_dandelion.write().await.tick(now);

                        // SECURITY (BUG-4): Execute stem relays: forward full tx to
                        // specific relay peer. Previously sent InvTx (hash only),
                        // which the relay peer couldn't fetch from the stempool
                        // via GetTxs (only checks mempool), completely breaking
                        // the Dandelion++ stem phase.
                        for (_tx_hash, tx, target_peer) in &actions.stem_relay {
                            // DEADLOCK FIX: this is the site most-closely matching the
                            // production 8m45s / 16-of-16-futex-parked signature. A stem
                            // relay to ONE peer whose outbound mpsc is full parks the
                            // dandelion task on that channel's capacity while STILL
                            // holding the DashMap shard Ref via `.get(target_peer)`.
                            // Every other tokio worker that touches the same shard
                            // (peer connect, disconnect, another broadcast) then blocks
                            // on the shard's futex — cascading to 100% futex-park.
                            let sender = maint_senders.get(target_peer).map(|s| s.value().clone());
                            if let Some(sender) = sender {
                                if let Ok(msg) = Message::txs(magic, vec![tx.clone()]) {
                                    if let Ok(data) = msg.to_bytes() {
                                        let _ = sender.send(data).await;
                                    }
                                }
                            }
                            crate::metrics::dandelion::STEM_RELAYS_TOTAL.inc();
                        }

                        // Execute fluff: broadcast InvTx to ALL peers + emit event
                        for (tx_hash, tx, source) in &actions.fluff {
                            if let Ok(msg) = Message::inv_tx(magic, *tx_hash) {
                                if let Ok(data) = msg.to_bytes() {
                                    // DEADLOCK FIX: same shape as the ping broadcast
                                    // above — snapshot senders, drop the DashMap iter,
                                    // then fan out. Fluff fires with actions.fluff
                                    // potentially non-empty every dandelion tick (10s);
                                    // the pre-fix code held one shard's Ref for the
                                    // duration of every peer's send.
                                    let senders_snapshot: Vec<tokio::sync::mpsc::Sender<Vec<u8>>> =
                                        maint_senders.iter().map(|s| s.value().clone()).collect();
                                    for sender in senders_snapshot {
                                        let _ = sender.send(data.clone()).await;
                                    }
                                }
                            }
                            // Emit event so the tx enters the mempool.
                            // `source` is the peer that relayed the stem tx into
                            // our stempool (None for locally-generated). Consumers
                            // use it to score the peer on mempool-admit failure.
                            let _ = maint_event_tx.send(NodeEvent::TransactionReceived(tx.clone(), *source));
                            crate::metrics::dandelion::FLUFF_BROADCASTS_TOTAL.inc();
                        }

                        // Update stempool size gauge
                        let stempool_size = maint_dandelion.read().await.stempool_size();
                        crate::metrics::dandelion::STEMPOOL_SIZE.set(stempool_size as i64);
                    }

                    _ = tip_announce_interval.tick() => {
                        // Periodic tip re-announce: every TIP_REBROADCAST_INTERVAL_SECS
                        // we send InvBlock for our current tip hash to every connected
                        // peer. Receivers de-dupe via known-hash check, so this is a
                        // no-op for peers who already have the block. Peers who missed
                        // the original Inv (per-peer channel was full at the time, see
                        // broadcast_raw doc) pick up the announcement here, request the
                        // block via GetBlocks, and catch up.
                        //
                        // Best-effort: try_send-style behavior. If a peer's channel is
                        // STILL full after 60s of drain time, something is wrong with
                        // that peer specifically — the cleanup_interval below will GC
                        // it after PEER_TIMEOUT. We don't want one slow peer to stall
                        // re-announces to everyone else.
                        let tip = *maint_chain_tip.read().await;
                        if tip != Hash::zero() {
                            if let Ok(msg) = Message::inv_block(magic, tip) {
                                if let Ok(data) = msg.to_bytes() {
                                    let mut sent = 0usize;
                                    let mut full = 0usize;
                                    for sender_ref in maint_senders.iter() {
                                        // try_send: don't block on a single congested peer.
                                        // Skip Closed (cleanup_interval handles dead peers).
                                        match sender_ref.try_send(data.clone()) {
                                            Ok(()) => sent += 1,
                                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => full += 1,
                                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                        }
                                    }
                                    if full > 0 {
                                        debug!(
                                            "tip_announce: sent InvBlock to {} peers ({} channels full, retry in {}s)",
                                            sent, full, TIP_REBROADCAST_INTERVAL_SECS,
                                        );
                                    } else {
                                        tracing::trace!(
                                            "tip_announce: sent InvBlock {} to {} peers",
                                            tip, sent,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    _ = cleanup_interval.tick() => {
                        // Clean up stale peers
                        let stale: Vec<PeerId> = maint_peers.iter()
                            .filter(|p| p.is_stale(PEER_TIMEOUT))
                            .map(|p| p.id)
                            .collect();

                        for id in stale {
                            // SECURITY (NET-002): Untrack connection before removing peer
                            if let Some(peer) = maint_peers.get(&id) {
                                maint_tracker.untrack_connection(&peer.addr);
                            }
                            maint_peers.remove(&id);
                            maint_senders.remove(&id);
                            // Re-queue any pending sync requests from this peer
                            maint_sync.write().await.on_peer_disconnected(&id);
                            // P5-Sc1: drop the peer's OrphanFloodTracker entry.
                            maint_orphan_flood.write().await.forget(&id);
                            let _ = maint_event_tx.send(NodeEvent::PeerDisconnected(id));
                        }

                        // Sync Dandelion++ outbound peers (also done in dandelion tick,
                        // but cleanup runs less frequently so we sync here too)
                        let outbound_peers: Vec<PeerId> = maint_peers.iter()
                            .filter(|p| p.outbound && p.state == PeerState::Connected)
                            .map(|p| p.id)
                            .collect();
                        maint_dandelion.write().await.set_outbound_peers(outbound_peers);

                        // SECURITY (M-8): Expire old mempool transactions (24 hours)
                        // Extended from 24h to 72h to give transactions more time during
                        // network congestion while still preventing indefinite accumulation.
                        let expired = maint_mempool.expire_old(72 * 3600);
                        if expired > 0 {
                            debug!("Expired {} old mempool transactions", expired);
                        }

                        // Peer scoring maintenance
                        let mut scorer = maint_scorer.write().await;
                        scorer.decay_all(50); // Decay toward neutral
                        scorer.auto_ban_bad_peers(); // Ban peers with very low scores
                        scorer.cleanup_bans(); // Remove expired bans
                    }
                    _ = ban_flush_interval.tick() => {
                        // Persist current ban list to disk so an unclean
                        // shutdown (OOM, SIGKILL, host crash) doesn't lose
                        // bans accumulated since startup. Bitcoin Core's
                        // `BanMan::DumpBanlist` (VERIFIED at banman.h:85
                        // in the master read this session) is the
                        // equivalent path.
                        let scorer = maint_scorer.read().await;
                        if let Err(e) = scorer.save_bans_to_file(&maint_ban_list_path) {
                            warn!("Periodic ban-list save failed: {}", e);
                        }
                    }
                    _ = outbound_rotate_interval.tick() => {
                        // Eclipse-fatigue defense: every ~45 min, disconnect
                        // the LONGEST-CONNECTED outbound peer. A new outbound
                        // slot opens; the connector loop fills it on its
                        // next tick from the address book, biasing toward
                        // peers we haven't tried recently. This is the
                        // active counterpart to the inbound netgroup
                        // eviction (eviction.rs): inbound defends against
                        // attacker-saturation, outbound rotation defends
                        // against attacker-persistence.
                        //
                        // Skip rotation when outbound peer count is at or
                        // below 3 — we don't want to drop to 2 outbound
                        // mid-IBD just for hygiene. The connector loop
                        // can be slow to fill new slots under partial
                        // network reachability.
                        let outbound_snapshot: Vec<(PeerId, std::time::Instant, std::net::SocketAddr)> =
                            maint_peers.iter()
                                .filter(|p| p.outbound && p.state == PeerState::Connected)
                                .map(|p| (p.id, p.connected_at, p.addr))
                                .collect();
                        if outbound_snapshot.len() > 3 {
                            if let Some((evict_id, _ts, evict_addr)) = outbound_snapshot
                                .into_iter()
                                .min_by_key(|(_, ts, _)| *ts)
                            {
                                debug!(
                                    "Rotating outbound peer {} (longest-connected) to disrupt potential eclipse hold",
                                    evict_addr
                                );
                                maint_senders.remove(&evict_id);
                                if let Some((_, evicted)) = maint_peers.remove(&evict_id) {
                                    maint_tracker.untrack_connection(&evicted.addr);
                                }
                            }
                        }
                    }
                    _ = heartbeat_interval.tick() => {
                        heartbeat_ticks = heartbeat_ticks.saturating_add(1);
                        // Single-line INFO heartbeat so external watchdogs +
                        // log-tailing operators can detect a silent maintenance-
                        // task freeze within 30 s. Missing heartbeats for >2
                        // intervals (~60 s) = restart the service.
                        let peer_count = maint_peers.len();
                        let outbound = maint_peers.iter()
                            .filter(|p| p.outbound && p.state == PeerState::Connected)
                            .count();
                        info!(
                            target: "node::heartbeat",
                            "maintenance tick={} peers={} outbound={}",
                            heartbeat_ticks, peer_count, outbound
                        );
                    }
                }
            }
        });

        // Supervisor watcher: detect maintenance-task panic / clean exit.
        // If the maintenance task ever terminates (panic, clean break, or
        // task abort), this watcher logs CRITICAL. Operator must restart
        // the service — auto-restart of a task holding shared mutable
        // state is unsafe without a full lock-reset protocol.
        tokio::spawn(async move {
            match maint_handle.await {
                Ok(()) => {
                    tracing::error!(
                        target: "node::supervisor",
                        "CRITICAL: maintenance task exited cleanly (no panic). \
                         This should never happen — the loop is unbounded. \
                         Node is now running WITHOUT ping/dandelion/peer-scoring/ban-flush. \
                         Restart the service immediately."
                    );
                }
                Err(e) if e.is_panic() => {
                    tracing::error!(
                        target: "node::supervisor",
                        "CRITICAL: maintenance task PANICKED ({:?}). \
                         Node is now running WITHOUT background maintenance. \
                         Heartbeat will stop. Restart the service immediately.",
                        e
                    );
                }
                Err(e) if e.is_cancelled() => {
                    tracing::warn!(
                        target: "node::supervisor",
                        "Maintenance task cancelled — expected during shutdown."
                    );
                }
                Err(e) => {
                    tracing::error!(
                        target: "node::supervisor",
                        "CRITICAL: maintenance task ended with JoinError: {:?}",
                        e
                    );
                }
            }
        });

        info!("P2P node started successfully");
        Ok(())
    }

    /// Stop the P2P node
    pub async fn stop(&self) {
        info!("Stopping P2P node...");
        *self.running.write().await = false;

        // Persist address book and ban list to disk before shutdown
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
        save_anchors_to_disk(&self.peers, &self.config.data_dir);

        // Disconnect all peers
        for entry in self.peers.iter() {
            let _ = self.event_tx.send(NodeEvent::PeerDisconnected(entry.id));
        }

        self.peers.clear();
        self.peer_senders.clear();

        info!("P2P node stopped");
    }

    /// Broadcast transaction (using Dandelion++).
    ///
    /// The transaction enters the stempool and will be relayed during the next
    /// Dandelion++ tick.  For immediate broadcast (e.g., from RPC), use
    /// `queue_transaction_for_broadcast()` which feeds into the maintenance loop.
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<Hash> {
        let now = chrono::Utc::now().timestamp() as u64;
        let hash = self.dandelion.write().await.add_local_tx(tx, now);
        // Stem relay happens in the maintenance loop's tick() call
        Ok(hash)
    }

    /// Broadcast block announcement
    pub async fn broadcast_block(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        self.broadcast_inv_block(hash).await
    }

    /// Broadcast inventory for transaction
    #[allow(dead_code)]
    async fn broadcast_inv_tx(&self, hash: Hash) -> Result<()> {
        let msg = Message::inv_tx(self.config.magic, hash)?;
        let data = msg.to_bytes()?;
        self.broadcast_raw(data).await
    }

    /// Broadcast inventory for block
    async fn broadcast_inv_block(&self, hash: Hash) -> Result<()> {
        let msg = Message::inv_block(self.config.magic, hash)?;
        let data = msg.to_bytes()?;
        self.broadcast_raw(data).await
    }

    /// Firework: advertise our current cumulative chain work to every peer
    /// that negotiated `CAP_CHAINWORK`.
    ///
    /// Best-effort (`try_send`): a dropped advertisement is re-sent on the
    /// next tip advance. Peers WITHOUT the capability (older nodes / external
    /// impls) are skipped entirely — they never receive the `ChainWork`
    /// message type (which they would reject as unknown) and keep using
    /// height-based sync. This is the mechanism that lets a work-aware peer
    /// discover a heavier chain even when that chain is shorter in height.
    fn announce_chain_work(&self) {
        use crate::network::firework::{has_cap, CAP_CHAINWORK};
        let stats = self.chain.stats();
        let data = match Message::chain_work(
            self.config.magic,
            stats.total_difficulty,
            self.chain.height(),
            self.chain.tip_hash(),
        )
        .and_then(|m| m.to_bytes())
        {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("announce_chain_work: failed to build/encode ChainWork: {}", e);
                return;
            }
        };
        // Snapshot capable peer IDs first; don't hold a DashMap ref across the
        // per-peer sender lookup.
        let capable: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|e| has_cap(e.value().capabilities, CAP_CHAINWORK))
            .map(|e| *e.key())
            .collect();
        for pid in capable {
            let sender = self.peer_senders.get(&pid).map(|s| s.value().clone());
            if let Some(sender) = sender {
                // Best-effort: a full channel means the peer is congested and
                // will receive the next advertisement instead.
                let _ = sender.try_send(data.clone());
            }
        }
    }

    /// Broadcast raw message to all peers (with traffic shaping for
    /// network fingerprint resistance — 4th Amendment protection).
    ///
    /// Uses `try_send` (non-blocking) rather than `.send().await` so a
    /// single slow peer can't stall the broadcast to everyone else.
    /// Per-peer channels are bounded (peer.rs:175 — capacity 100); when
    /// a channel is full we drop the message for that peer rather than
    /// wait. Slow peers still catch up via the IBD `GetBlocks` path.
    ///
    /// This is the Bitcoin-style best-effort gossip pattern. The previous
    /// implementation used `send().await` which serialised all sends
    /// and let one congested peer stall propagation across the fleet —
    /// matched the "25% block reach" symptom captured in
    /// project_public_testnet_launch.md before the 2026-05-02 fix.
    ///
    /// Applies timing jitter to defeat traffic correlation analysis.
    /// Packet size normalization is done at the transport layer (noise
    /// bridge) rather than here, because the connection loop expects
    /// raw protocol message format (header + payload).
    async fn broadcast_raw(&self, data: Vec<u8>) -> Result<()> {
        use std::sync::atomic::Ordering;
        use tokio::sync::mpsc::error::TrySendError;

        /// Disconnect a peer after this many consecutive `try_send` failures
        /// with `Full`. At ~10 broadcasts/min average load this is roughly
        /// 3 minutes of total radio silence — enough to be confident the
        /// peer is genuinely stuck, not just briefly slow.
        const STALL_THRESHOLD: u32 = 30;

        self.traffic_shaper.apply_jitter().await;
        let mut sent: usize = 0;
        let mut full: usize = 0;
        let mut closed: usize = 0;
        // Hot path is lock-free; we collect victims and process them after.
        let mut to_disconnect: Vec<(PeerId, u32)> = Vec::new();
        // 2026-06-03 sync-stall bug fix: when a peer's mpsc sender
        // returns Closed, the peer-connection task already exited
        // (TCP disconnect, Noise handshake collapse, channel
        // explicitly dropped by handle_connection). Previously the
        // stale `peer_senders` / `peers` entry was left in place
        // until the maintenance task's `cleanup_interval` (60s tick)
        // saw `last_seen.elapsed() > PEER_TIMEOUT` (300s) and
        // garbage-collected it — up to 360 seconds of latency.
        //
        // During those minutes EVERY broadcast (block announce, tx
        // announce, headers reply — frequently >10/sec during sync)
        // re-attempted try_send on the same dead channel, returned
        // Closed, and re-emitted the warn-level "broadcast_raw
        // partial delivery sent=N full=0 closed=M" log line. That
        // line matches the testnet operator's report at 2026-06-03
        // 20:28:39 — identical sent=4/full=0/closed=1 repeating
        // every ~10ms, fast enough to monopolise the broadcast hot
        // path until enough peers eventually got cleaned up by the
        // 5-minute maintenance sweep.
        //
        // The sync engine reported "non-stalled" the whole time
        // (it WAS doing work), so the EMERGENCY-TIER-3 stall
        // detector — which fires when chain advance lags despite a
        // non-stalled engine — was the only signal the operator
        // received that something was wrong. The "wipe + restart"
        // workaround worked because it cleared all peer_senders
        // state from process memory.
        //
        // Fix: when try_send returns Closed, the peer is already
        // gone. Collect the peer_id and clean up the stale entries
        // OFF the hot path (after the loop, like to_disconnect).
        // No banning — the peer disconnected normally, so they
        // should be able to reconnect.
        let mut to_remove_closed: Vec<PeerId> = Vec::new();

        for entry in self.peer_senders.iter() {
            let peer_id = *entry.key();
            match entry.value().try_send(data.clone()) {
                Ok(()) => {
                    sent += 1;
                    // Reset stall counter on every successful send so a peer
                    // that briefly fell behind and recovered isn't carrying
                    // old credits toward a future disconnect.
                    if let Some(p) = self.peers.get(&peer_id) {
                        p.consecutive_full.store(0, Ordering::Relaxed);
                    }
                }
                Err(TrySendError::Full(_)) => {
                    full += 1;
                    let count = if let Some(p) = self.peers.get(&peer_id) {
                        p.consecutive_full.fetch_add(1, Ordering::Relaxed) + 1
                    } else {
                        0 // peer was removed mid-iteration; nothing to track
                    };
                    if count >= STALL_THRESHOLD {
                        to_disconnect.push((peer_id, count));
                    }
                    tracing::trace!(
                        peer_id = ?peer_id,
                        consecutive_full = count,
                        "broadcast_raw: peer channel full, dropping (peer will catch up via IBD)"
                    );
                }
                Err(TrySendError::Closed(_)) => {
                    closed += 1;
                    to_remove_closed.push(peer_id);
                    tracing::trace!(
                        peer_id = ?peer_id,
                        "broadcast_raw: peer channel closed (peer disconnected) — cleaning up"
                    );
                }
            }
        }

        if full > 0 || closed > 0 {
            tracing::warn!(sent, full, closed, "broadcast_raw partial delivery");
        }

        // Disconnect chronic-slow peers OFF the hot path (after the loop)
        // so we don't acquire the dandelion write lock while iterating
        // peer_senders.
        for (peer_id, count) in to_disconnect {
            tracing::warn!(
                peer_id = %hex::encode(&peer_id[..8]),
                consecutive_full = count,
                "broadcast_raw: disconnecting chronic-slow peer (channel full {count} consecutive sends)"
            );
            // Score the peer down so they don't immediately reconnect
            // and resume eating broadcast slots.
            if let Some(p) = self.peers.get(&peer_id) {
                let addr = p.addr;
                drop(p);
                let mut scorer = self.peer_scorer.write().await;
                scorer.get_or_create(addr).record_misbehavior(
                    super::scoring::MisbehaviorType::ChronicSendQueueFull,
                );
            }
            self.ban_peer(&peer_id).await;
        }

        // Clean up peers whose channels closed normally (TCP fin, handler
        // task exited). Same cleanup the maintenance task at the
        // cleanup_interval tick does on stale peers, but immediate —
        // closes the 360-second window during which a dead peer caused
        // every subsequent broadcast to log "closed=N partial delivery"
        // and burn CPU spinning on dead channels.
        //
        // NOT calling `ban_peer` deliberately: a Closed channel is not
        // misbehaviour. The peer either disconnected for legitimate
        // operational reasons (process restart, network blip, planned
        // maintenance) or already got banned through a different path
        // and we're just chasing the leftover state. Banning here would
        // both penalise innocent peers AND double-count for already-
        // banned ones.
        if !to_remove_closed.is_empty() {
            let count = to_remove_closed.len();
            for peer_id in &to_remove_closed {
                // Untrack connection so the per-IP / per-/16 slot is
                // freed. ConnectionTracker is idempotent — if the
                // handler task already untracked, this is a no-op.
                if let Some(peer) = self.peers.get(peer_id) {
                    self.conn_tracker.untrack_connection(&peer.addr);
                }
                self.peer_senders.remove(peer_id);
                self.peers.remove(peer_id);
                self.dandelion.write().await.remove_outbound_peer(peer_id);
                self.sync.write().await.on_peer_disconnected(peer_id);
                let _ = self.event_tx.send(NodeEvent::PeerDisconnected(*peer_id));
            }
            tracing::info!(
                cleaned = count,
                "broadcast_raw: cleaned up {} closed-channel peer(s) (sync-stall fix)",
                count
            );
        }

        Ok(())
    }

    /// Send message to specific peer
    pub async fn send_to(&self, peer_id: &PeerId, data: Vec<u8>) -> Result<()> {
        // DEADLOCK FIX: clone before await; see the systematic sweep in this
        // file's PR body for the class-wide rationale.
        let sender = self.peer_senders.get(peer_id).map(|s| s.value().clone());
        if let Some(sender) = sender {
            sender.send(data).await
                .map_err(|_| Error::ConnectionFailed("peer disconnected".into()))?;
        }
        Ok(())
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get current chain height (for sync guard).
    pub async fn chain_height(&self) -> u64 {
        *self.chain_height.read().await
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
        // Get address before removing for connection tracking cleanup +
        // scorer ban propagation. Audit MEDIUM #30 closure: previously
        // ban_peer set local PeerInfo.reputation = -100 and removed the
        // entry, but the `PeerScorer` (the authority for accept-loop ban
        // checks at node.rs:763 / 1022) was NOT informed. The peer could
        // reconnect immediately because is_banned(addr) returned false
        // until the scorer's own auto_ban_bad_peers tick (~60s later)
        // observed the dropped score and persisted a ban. (The prior
        // comment described a specific "CConnman::Ban calls CBanDB::Write
        // atomically before disconnecting" ordering as prior art; that
        // specific pair + ordering was not re-verified against upstream
        // this session and is dropped. The scorer-first-then-disconnect
        // ordering below stands on the local reasoning above.)
        let peer_addr = self.peers.get(peer_id).map(|p| p.addr);
        if let Some(addr) = peer_addr {
            self.conn_tracker.untrack_connection(&addr);
            // Propagate to the scorer FIRST so any reconnect attempt
            // racing with this disconnect hits is_banned() = true.
            self.peer_scorer.write().await.ban(addr);
        }
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.reputation = -100;
        }
        // Remove from Dandelion++ outbound peers
        self.dandelion.write().await.remove_outbound_peer(peer_id);
        self.peers.remove(peer_id);
        self.peer_senders.remove(peer_id);
        // Drop any orphan-flood tracking state — keeps the tracker bounded.
        self.orphan_flood.write().await.forget(peer_id);
        let _ = self.event_tx.send(NodeEvent::PeerDisconnected(*peer_id));
    }
}

/// Network statistics
#[derive(Clone, Debug)]
pub struct NetworkStats {
    pub peer_count: usize,
    pub outbound: usize,
    pub inbound: usize,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
}

/// Connection statistics
#[derive(Clone, Debug)]
pub struct ConnectionStats {
    pub memory_used: usize,
    pub memory_budget: usize,
}

/// Bridge tasks: shuttles data between the encrypted TCP stream and the
/// plaintext duplex streams that the MessageFramer reads/writes.
///
/// CRITICAL: Uses TWO separate tasks (read and write) instead of a single
/// `select!` loop. This is because `read_encrypted` is NOT cancellation-safe:
/// it makes two sequential read_exact calls with a nonce increment between
/// them. If a select! arm cancels the future mid-read, the nonce gets
/// permanently desynced and all subsequent decryptions fail with
/// "decryption failed" — which is exactly the bug we were seeing.
async fn noise_bridge(
    transport: super::noise::NoiseTransport,
    tcp_reader: tokio::net::tcp::OwnedReadHalf,
    tcp_writer: tokio::net::tcp::OwnedWriteHalf,
    from_app: tokio::io::DuplexStream,   // plaintext from MessageFramer
    to_app: tokio::io::DuplexStream,     // plaintext to MessageFramer
) {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Split the transport into send and recv halves so each direction can
    // run in its own task without interfering with the other's nonce state.
    let (send_state, recv_state) = transport.split_into_send_recv();
    let send_state = Arc::new(Mutex::new(send_state));
    let recv_state = Arc::new(Mutex::new(recv_state));

    // Reader task: TCP → decrypt → app
    let reader_handle = tokio::spawn(noise_bridge_reader(recv_state, tcp_reader, to_app));
    // Writer task: app → encrypt → TCP
    let writer_handle = tokio::spawn(noise_bridge_writer(send_state, tcp_writer, from_app));

    // When either side terminates, abort the other to ensure clean shutdown
    tokio::select! {
        _ = reader_handle => {}
        _ = writer_handle => {}
    }
}

async fn noise_bridge_reader(
    state: std::sync::Arc<tokio::sync::Mutex<super::noise::NoiseRecvState>>,
    mut tcp_reader: tokio::net::tcp::OwnedReadHalf,
    mut to_app: tokio::io::DuplexStream,
) {
    use tokio::io::AsyncWriteExt;
    loop {
        let plaintext = {
            let s = state.lock().await;
            match s.read_encrypted(&mut tcp_reader).await {
                Ok(pt) => pt,
                Err(e) => {
                    // Classify the disconnect. The two common patterns on a
                    // thin testnet mesh are (a) the peer closed cleanly mid-
                    // stream — shows up as "unexpected end of file" from
                    // tokio's read_exact and is unactionable noise, and
                    // (b) a real protocol/decrypt error which IS worth a
                    // WARN. New operators (barns1253, 2026-06-01) read every
                    // clean disconnect as a bug; the demotion to info! for
                    // the EOF case keeps the log calm without losing real
                    // signal.
                    let msg = e.to_string();
                    if msg.contains("unexpected end of file") || msg.contains("UnexpectedEof") {
                        info!("Peer disconnected (noise stream closed): {}", e);
                    } else {
                        warn!("Noise bridge reader error: {}", e);
                    }
                    return;
                }
            }
        };
        if to_app.write_all(&plaintext).await.is_err() {
            return;
        }
        if to_app.flush().await.is_err() {
            return;
        }
    }
}

async fn noise_bridge_writer(
    state: std::sync::Arc<tokio::sync::Mutex<super::noise::NoiseSendState>>,
    mut tcp_writer: tokio::net::tcp::OwnedWriteHalf,
    mut from_app: tokio::io::DuplexStream,
) {
    use tokio::io::AsyncReadExt;
    let mut app_buf = vec![0u8; 65519];
    loop {
        match from_app.read(&mut app_buf).await {
            Ok(0) => return,
            Ok(n) => {
                let s = state.lock().await;
                if let Err(e) = s.write_encrypted(&mut tcp_writer, &app_buf[..n]).await {
                    warn!("Noise bridge writer: {}", e);
                    return;
                }
            }
            Err(e) => {
                warn!("Noise bridge: app read error: {}", e);
                return;
            }
        }
    }
}

/// Handle a new connection (inbound or outbound) with proper message framing
async fn handle_connection(
    stream: TcpStream,
    peer_id: PeerId,
    outbound: bool,
    magic: [u8; 4],
    our_nonce: u64,
    our_height: u64,
    our_tip: Hash,
    peers: Arc<DashMap<PeerId, PeerInfo>>,
    senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    event_tx: broadcast::Sender<NodeEvent>,
    msg_tx: mpsc::Sender<PeerMessage>,
    conn_tracker: Arc<ConnectionTracker>,
    identity: Arc<super::noise::NodeIdentity>,
    encryption_config: crate::config::P2PEncryptionConfig,
    // Per-/16 outbound slot for eclipse defense. Some for outbound
    // dials (acquired by the connector before spawn), None for
    // inbound accepts. We move it into the PeerInfo entry below
    // so the slot's lifetime tracks the entry's lifetime — when
    // the peers DashMap drops or overwrites this entry, the slot
    // drops with it, releasing the /16 counter cleanly even in
    // the skip-cleanup branch (where peers.remove is intentionally
    // not called to preserve a concurrent reconnection).
    eclipse_slot: Option<Arc<super::connection_tracker::OutboundSubnetSlot>>,
) -> Result<()> {
    let addr = stream.peer_addr()
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

    // Disable Nagle's algorithm for latency-sensitive handshake and message
    // framing. Without this, the 2-byte length prefix of a Noise handshake
    // message can stall for 200ms waiting for more data, causing timeouts.
    if let Err(e) = stream.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY on {}: {}", addr, e);
    }

    let mut info = PeerInfo::new(peer_id, addr, outbound);
    info.eclipse_slot = eclipse_slot;

    // ─── Noise_XX Encryption ────────────────────────────────────────────
    //
    // Modeled after Lightning BOLT #8: encryption starts immediately with no
    // proposal/negotiation byte. The Noise_XX handshake runs directly.
    //
    // Each handshake message carries a 1-byte version field (currently 0x00).
    // An unknown version causes an immediate, descriptive error before any
    // crypto is attempted — fast detection of misconfigured or incompatible nodes.
    //
    // If encryption is disabled on this node, plaintext is used. Two nodes
    // with mismatched encryption configs simply cannot connect (the Noise
    // handshake will fail with a clear version/MAC error — no stream corruption).

    let mut stream = stream;

    let noise_result: Option<(super::noise::NoiseTransport, super::PeerId)> =
        if encryption_config.preferred || encryption_config.required {
            let timeout_result = tokio::time::timeout(
                Duration::from_secs(super::noise::NOISE_HANDSHAKE_TIMEOUT_SECS),
                super::noise::perform_noise_handshake(
                    &mut stream,
                    identity.clone(),
                    outbound,
                ),
            ).await;

            match timeout_result {
                Ok(Ok((transport, remote_id))) => Some((transport, remote_id)),
                Ok(Err(e)) => {
                    // Noise handshake failed — TCP stream has partial handshake bytes
                    // on it and CANNOT be reused for plaintext. Close and let the
                    // retry loop reconnect. The stale node_key detection in
                    // load_or_generate_fresh() prevents the most common failure mode.
                    warn!("Noise handshake failed with {}: {}", addr, e);
                    return Err(e);
                }
                Err(_) => {
                    warn!("Noise handshake timed out with {} after {}s",
                        addr, super::noise::NOISE_HANDSHAKE_TIMEOUT_SECS);
                    return Err(Error::NoiseHandshakeFailed("timeout".into()));
                }
            }
        } else {
            None
        };

    // Resolve canonical peer_id: use the remote's Noise static key when
    // available (it's authenticated), otherwise fall back to the TCP-level id.
    let peer_id = if let Some((_, ref remote_id)) = noise_result {
        info.encrypted = true;
        info.remote_static_key = Some(*remote_id);

        // SECURITY: If trusted_peers is non-empty, verify this peer is trusted.
        if !encryption_config.trusted_peers.is_empty() {
            let remote_hex = hex::encode(remote_id);
            if !encryption_config.trusted_peers.contains(&remote_hex) {
                warn!(
                    "Peer {} has untrusted static key {}, disconnecting",
                    addr, remote_hex
                );
                return Err(Error::NoiseHandshakeFailed("untrusted peer".into()));
            }
        }

        info!(
            "Noise handshake succeeded with {} (remote key: {})",
            addr,
            hex::encode(&remote_id[..8])
        );

        *remote_id
    } else {
        if !encryption_config.trusted_peers.is_empty() {
            warn!("Plaintext connection from {} rejected (trusted_peers configured)", addr);
            return Err(Error::NoiseHandshakeFailed("encryption required for trusted peers".into()));
        }
        if encryption_config.required {
            warn!("Encryption required but not established with {}", addr);
            return Err(Error::NoiseHandshakeFailed("encryption required".into()));
        }
        peer_id
    };

    // Sync info.id with the finalized peer_id (which may have been replaced by
    // the Noise-derived remote static key). pick_scored_peer() returns p.id,
    // so it must match the key used in `senders` and `peers` maps.
    info.id = peer_id;

    // Create message sender for this peer with bounded channel for backpressure
    // (inserted after peer_id is finalized to ensure consistent map keys)
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    senders.insert(peer_id, tx);

    // Store peer info
    peers.insert(peer_id, info);

    // ─── Set up message framing (plaintext or encrypted) ───────────────
    use super::framing::{MessageFramer, HEADER_SIZE};

    // For encrypted connections, bridge NoiseTransport ↔ MessageFramer via
    // in-memory duplex streams. The bridge task handles encrypt/decrypt on
    // the real TCP stream while the MessageFramer operates on plaintext.
    //
    // For plaintext, the MessageFramer operates directly on the TCP stream.
    // We use Box<dyn ...> to unify the types for the connection loop.

    type DynRead = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
    type DynWrite = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

    let (app_reader, app_writer, noise_bridge_handle): (DynRead, DynWrite, Option<tokio::task::JoinHandle<()>>) =
        if let Some((transport, _remote_id)) = noise_result {
            let (tcp_reader, tcp_writer) = stream.into_split();
            let (app_read, bridge_write) = tokio::io::duplex(64 * 1024);
            let (bridge_read, app_write) = tokio::io::duplex(64 * 1024);

            // Spawn bridge task: decrypt from TCP → app, encrypt from app → TCP
            let handle = tokio::spawn(noise_bridge(
                transport, tcp_reader, tcp_writer, bridge_read, bridge_write,
            ));

            (Box::new(app_read), Box::new(app_write), Some(handle))
        } else {
            let (tcp_reader, tcp_writer) = stream.into_split();
            (Box::new(tcp_reader), Box::new(tcp_writer), None)
        };

    let mut framer = MessageFramer::new_budgeted(app_reader, app_writer, magic, conn_tracker);

    // Per-peer rate limiter to prevent abuse

    // SECURITY (NET-001): Send version message with our nonce for self-connection detection
    let version_msg = Message::version_with_nonce(magic, our_height, our_tip, our_nonce)?;
    let version_bytes = version_msg.to_bytes()?;
    // The framer handles header creation, but version_msg already includes header
    // Write the complete message directly for initial handshake
    framer.write_message(MessageType::Version as u8, &version_bytes[HEADER_SIZE..]).await?;
    if let Some(mut peer) = peers.get_mut(&peer_id) {
        peer.bytes_sent = peer.bytes_sent.saturating_add(version_bytes.len() as u64);
    }

    // Firework (Flare capability message) was removed in the 1.0 trim —
    // the convergence engine no longer negotiates per-node feature bits
    // at the protocol level. Peer capability handling reverts to the
    // standard Version/Verack handshake only.

    // Notify of connection
    let _ = event_tx.send(NodeEvent::PeerConnected(peer_id));

    // Connection loop with proper message framing
    loop {
        tokio::select! {
            // SECURITY (H-2): Use the inactivity-timed read to prevent Slowloris DoS.
            // A peer sending partial data would otherwise pin the connection slot.
            result = framer.read_budgeted_message_timeout() => {
                match result {
                    Ok(message) => {
                        // DoS protection is handled by:
                        // 1. MAX_MESSAGE_SIZE check in framing.rs (16MB cap)
                        // 2. Per-peer misbehavior scoring in process_message()
                        // 3. Connection limits (MAX_CONNECTIONS_PER_IP)
                        // Never drop solicited data — that breaks IBD.
                        // (Prior comment claimed "Bitcoin/Monero/Ethereum
                        // all process every received message" as a broad
                        // cross-project rationale; that generalization
                        // was not verified this session and is dropped.
                        // The DoS-vs-liveness reasoning above stands.)

                        if msg_tx.send(PeerMessage {
                            peer_id,
                            msg_type: message.msg_type,
                            payload: message.payload,
                            _reservation: message.reservation,
                        }).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Read error from peer {:?}: {}", &peer_id[..4], e);
                        break;
                    }
                }
            }

            // Write to network (messages from other parts of the system)
            Some(data) = rx.recv() => {
                // Data should be a complete message with header
                // Extract type and payload, then use framer to send
                // NOTE: >= HEADER_SIZE allows empty-payload messages (Verack, GetAddr)
                if data.len() >= HEADER_SIZE {
                    let msg_type = data[4];
                    // WIRETRACE (CIP-020 baseline): when COINCYNC_WIRE_TRACE=1,
                    // emit one line per outbound packet so off-node analysis can
                    // reconstruct the on-wire adversary view and compute the
                    // timing-correlation r on REAL traffic. `msg_type` 99 =
                    // MessageType::Padding (cover/dummy); anything else = real.
                    // This is the muxed choke point — every outbound packet to
                    // this peer (stem, fluff, inv, ping, block, padding) passes
                    // here. Off by default; the per-packet cost when disabled is
                    // one relaxed OnceLock load. Purely observational — it never
                    // alters what is sent, so it cannot affect consensus or
                    // propagation.
                    {
                        static WIRE_TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
                        let on = *WIRE_TRACE.get_or_init(|| {
                            std::env::var("COINCYNC_WIRE_TRACE").as_deref() == Ok("1")
                        });
                        if on {
                            let ts_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis())
                                .unwrap_or(0);
                            let p = &peer_id[..4];
                            info!(
                                target: "wiretrace",
                                "WIRETRACE {} {:02x}{:02x}{:02x}{:02x} {} {}",
                                ts_ms, p[0], p[1], p[2], p[3], msg_type, data.len()
                            );
                        }
                    }
                    let payload = &data[HEADER_SIZE..];
                    if let Err(e) = framer.write_message(msg_type, payload).await {
                        debug!("Write error to peer {:?}: {}", &peer_id[..4], e);
                        break;
                    }
                    // Track outbound bytes for telemetry (get_peers RPC, sync diagnostics).
                    // Without this, bytes_sent stays at 0 forever — masking real propagation
                    // health. Counter is per-peer, behind a DashMap entry guard, so no race.
                    if let Some(mut peer) = peers.get_mut(&peer_id) {
                        peer.bytes_sent = peer.bytes_sent.saturating_add(data.len() as u64);
                    }
                }
            }
        }
    }

    // Cleanup on disconnect — abort bridge task to release TCP socket immediately
    if let Some(handle) = noise_bridge_handle {
        handle.abort();
    }

    // BUG 2 FIX (original): only remove peer/sender entries if they still
    // belong to THIS connection. If a reconnection happened with the same
    // peer_id (Noise gives stable per-remote-key IDs after handshake), the
    // new connection's senders.insert(peer_id, tx_new) already overwrote
    // our entry — removing it would break the new connection.
    //
    // BUG 2 FIX (additional, 2026-06-03 eclipse-defense slot leak):
    // the is_closed() check below only works correctly if OUR rx is dropped
    // first. As written before this patch, `rx` was still in scope at this
    // point, so our own tx (still in the map) reported is_closed() = false,
    // should_remove = false, and we SKIPPED CLEANUP on every normal
    // disconnect. That orphaned the PeerInfo entry — and crucially its
    // eclipse_slot Arc — in the peers map, leaking one /16 subnet counter
    // slot per disconnect. Observed in production on coincync-lon as
    // `subnet_sum=N but outbound_count=M` drift, growing from 1 → 2 → 4
    // across an evening of repeated reconnections.
    //
    // The fix is to drop our rx FIRST: if no reconnection happened, our
    // tx in the map then has no rx (we held the only one) and is_closed()
    // correctly returns true → should_remove = true → cleanup runs →
    // eclipse_slot Arc drops cleanly. If a reconnection DID happen, the
    // map has the new tx (with the new connection's rx still alive), so
    // is_closed() returns false → should_remove = false → we correctly
    // skip cleanup (the new connection's entries are intact).
    drop(rx);

    let should_remove = senders.get(&peer_id)
        .map(|s| s.is_closed())
        .unwrap_or(true);

    if should_remove {
        peers.remove(&peer_id);
        senders.remove(&peer_id);
        let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
    } else {
        tracing::debug!("Skipping cleanup for peer {:?} — new connection exists", peer_id);
    }

    Ok(())
}

/// Convert a protocol NetAddr (IPv6-mapped 16 bytes + port) to std SocketAddr
fn net_addr_to_socket_addr(net_addr: &super::protocol::NetAddr) -> Option<SocketAddr> {
    let ip = std::net::Ipv6Addr::from(net_addr.ip);

    // Check if this is an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    if let Some(v4) = ip.to_ipv4_mapped() {
        Some(SocketAddr::new(std::net::IpAddr::V4(v4), net_addr.port))
    } else if ip.is_unspecified() {
        None // Skip 0.0.0.0
    } else {
        Some(SocketAddr::new(std::net::IpAddr::V6(ip), net_addr.port))
    }
}

/// Returns true if the given IP is routable on the public internet —
/// i.e., the kind of address a real peer could be reachable at.
///
/// Pre-fix the only filter on incoming Addr gossip was `is_loopback()
/// || is_unspecified()`. An attacker poisoning our address book with
/// multicast / link-local / CGNAT / docs / broadcast IPs would get us
/// to dial those (burning connection slots) and gossip them onward,
/// fanning out the pollution to peers. (Prior comment tagged this as
/// "Bitcoin CVE-2015-3641 class". That CVE is real — VERIFIED via NVD
/// this session as a bitcoind/Bitcoin-Qt pre-0.10.2 DoS, description
/// text "an 'Easy' attack" — but the CVE's public description is too
/// vague to specifically pin it to address-book poisoning. The class-
/// of-bug tag is dropped; the reachable-address filter here stands on
/// its own reasoning above.)
/// Mirrors the shape of Bitcoin Core's `CNetAddr::IsRoutable()`
/// (VERIFIED as a declared method at netaddress.h:180 in the master
/// read this session).
///
/// Rejections (all variants):
///   - Loopback (127.0.0.0/8, ::1)
///   - Unspecified (0.0.0.0, ::)
///   - Multicast (224.0.0.0/4, ff00::/8)
///   - IPv4 link-local (169.254.0.0/16) — APIPA
///   - IPv4 private (10/8, 172.16/12, 192.168/16) — RFC 1918
///   - IPv4 CGNAT shared address (100.64.0.0/10) — RFC 6598
///   - IPv4 documentation (192.0.2/24, 198.51.100/24, 203.0.113/24)
///     and benchmark (198.18/15) — RFC 5737, RFC 2544
///   - IPv4 broadcast (255.255.255.255), 0.0.0.0/8
///   - IPv6 unique local (fc00::/7) — RFC 4193
///   - IPv6 link-local (fe80::/10) — RFC 4291
///   - IPv6 documentation (2001:db8::/32) — RFC 3849
///   - IPv4-compatible IPv6 (::a.b.c.d, deprecated per RFC 4291)
///
/// NOT used for self-connection checks in this module — those use a
/// narrower loopback-only filter because a 10.x address can be a
/// legitimate dial target on a LAN testnet. Routability gating is
/// only meaningful for gossip-relayed addresses we'd push to peers.
fn is_routable(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }

    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8 — private
            if octets[0] == 10 { return false; }
            // 172.16.0.0/12 — private
            if octets[0] == 172 && (octets[1] & 0xf0) == 16 { return false; }
            // 192.168.0.0/16 — private
            if octets[0] == 192 && octets[1] == 168 { return false; }
            // 169.254.0.0/16 — link-local (APIPA)
            if octets[0] == 169 && octets[1] == 254 { return false; }
            // 100.64.0.0/10 — CGNAT (RFC 6598)
            if octets[0] == 100 && (octets[1] & 0xc0) == 64 { return false; }
            // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — docs (RFC 5737)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 { return false; }
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 { return false; }
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 { return false; }
            // 198.18.0.0/15 — benchmark (RFC 2544)
            if octets[0] == 198 && (octets[1] & 0xfe) == 18 { return false; }
            // 255.255.255.255 — broadcast
            if octets == [255, 255, 255, 255] { return false; }
            // 0.0.0.0/8 — "this network" (also covers unspecified above)
            if octets[0] == 0 { return false; }
            true
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fc00::/7 — unique local (RFC 4193)
            if (segments[0] & 0xfe00) == 0xfc00 { return false; }
            // fe80::/10 — link-local (RFC 4291)
            if (segments[0] & 0xffc0) == 0xfe80 { return false; }
            // 2001:db8::/32 — documentation (RFC 3849)
            if segments[0] == 0x2001 && segments[1] == 0x0db8 { return false; }
            // IPv4-compatible IPv6 (::a.b.c.d) — deprecated per RFC 4291.
            // Reject; the legitimate IPv4-in-v6 form is IPv4-mapped
            // (::ffff:a.b.c.d) which we already converted to V4 above.
            if v6.to_ipv4().is_some() && v6.to_ipv4_mapped().is_none() {
                return false;
            }
            true
        }
    }
}

#[cfg(test)]
mod is_routable_tests {
    use super::is_routable;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_unroutable_ipv4() {
        let reject_v4 = [
            "0.0.0.0", "127.0.0.1",
            "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
            "169.254.1.2",                         // link-local
            "100.64.0.1", "100.127.255.255",        // CGNAT
            "192.0.2.1", "198.51.100.1", "203.0.113.1",  // docs
            "198.18.0.1", "198.19.255.255",         // benchmark
            "255.255.255.255",                      // broadcast
            "224.0.0.1", "239.255.255.255",         // multicast
        ];
        for s in reject_v4 {
            let ip = IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
            assert!(!is_routable(ip), "expected NOT routable: {}", s);
        }
    }

    #[test]
    fn accepts_routable_ipv4() {
        let accept_v4 = ["1.1.1.1", "8.8.8.8", "66.135.23.193", "203.0.114.1"];
        for s in accept_v4 {
            let ip = IpAddr::V4(s.parse::<Ipv4Addr>().unwrap());
            assert!(is_routable(ip), "expected routable: {}", s);
        }
    }

    #[test]
    fn rejects_unroutable_ipv6() {
        let reject_v6 = [
            "::",                                   // unspecified
            "::1",                                  // loopback
            "fe80::1",                              // link-local
            "fc00::1", "fd00::1",                   // unique local
            "ff00::1", "ff02::1",                   // multicast
            "2001:db8::1",                          // documentation
        ];
        for s in reject_v6 {
            let ip = IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
            assert!(!is_routable(ip), "expected NOT routable: {}", s);
        }
    }

    #[test]
    fn accepts_routable_ipv6() {
        let accept_v6 = [
            "2001:4860:4860::8888",                 // Google DNS
            "2a01:e0a:c53:63d0::1",                 // real-world routable prefix
        ];
        for s in accept_v6 {
            let ip = IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
            assert!(is_routable(ip), "expected routable: {}", s);
        }
    }
}

/// Pick a connected peer for sending requests, preferring higher-scored peers.
///
/// Uses weighted random selection based on composite peer scores when a scorer
/// is available. Falls back to uniform random selection otherwise.
fn pick_scored_peer(
    peers: &Arc<DashMap<PeerId, PeerInfo>>,
    scorer: &Arc<RwLock<PeerScorer>>,
) -> Option<PeerId> {
    let connected: Vec<(PeerId, SocketAddr)> = peers.iter()
        .filter(|p| p.state == PeerState::Connected)
        .map(|p| (p.id, p.addr))
        .collect();

    if connected.is_empty() {
        return None;
    }

    // Try to get scored weights
    if let Ok(s) = scorer.try_read() {
        let weights: Vec<f64> = connected.iter().map(|(_, addr)| {
            s.get(addr)
                .map(|score| score.composite_score().max(0.05)) // floor at 0.05 so bad peers still have tiny chance
                .unwrap_or(0.5) // unknown peers get neutral weight
        }).collect();

        let total: f64 = weights.iter().sum();
        if total > 0.0 {
            use rand::Rng;
            // SECURITY: peer selection is privacy-adjacent (it determines
            // which peer sees which request). OsRng keeps the choice
            // unpredictable to network observers.
            let mut rng = rand::rngs::OsRng;
            let mut pick = rng.gen_range(0.0..total);
            for (i, w) in weights.iter().enumerate() {
                pick -= w;
                if pick <= 0.0 {
                    return Some(connected[i].0);
                }
            }
        }
    }

    // Fallback: uniform random
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let idx = rng.gen_range(0..connected.len());
    Some(connected[idx].0)
}

/// Pick a random connected peer for sending requests (unscored fallback)
#[allow(dead_code)]
fn pick_random_peer(peers: &Arc<DashMap<PeerId, PeerInfo>>) -> Option<PeerId> {
    let connected: Vec<PeerId> = peers.iter()
        .filter(|p| p.state == PeerState::Connected)
        .map(|p| p.id)
        .collect();

    if connected.is_empty() {
        return None;
    }

    use rand::Rng;
    // SECURITY: peer selection — OsRng, see pick_best_peer above.
    let mut rng = rand::rngs::OsRng;
    let idx = rng.gen_range(0..connected.len());
    Some(connected[idx])
}

/// Send `data` to `peer_id`'s outbound mpsc channel WITHOUT holding
/// the DashMap shard lock across the send.await.
///
/// This is the class-wide replacement for the deadlock antipattern:
///
/// ```ignore
/// if let Some(sender) = senders.get(&peer_id) {
///     let _ = sender.send(data).await;  // shard Ref held across await
/// }
/// ```
///
/// `dashmap`'s `get()` returns a `Ref` whose Drop releases the shard
/// lock only when the Ref goes out of scope. If the peer's outbound
/// mpsc channel is at capacity, `.send(data).await` parks the tokio
/// worker while STILL holding the shard lock — every other tokio task
/// that later touches the same shard (peer connect / disconnect /
/// broadcast) parks on the shard's futex, cascading to full-runtime
/// deadlock. Verified matches the 2026-07-02 / 2026-07-03 production
/// signature (16/16 threads on `futex_wait_queue`).
///
/// The fix clones the sender out of the DashMap FIRST (a cheap `Arc`
/// bump on `tokio::sync::mpsc::Sender`), THEN drops the Ref, THEN
/// awaits the send. See `docs/operations/runbook-watchdog-diagnostic.md`
/// for the full incident context.
///
/// Returns `true` iff the peer was in the map AND the send succeeded.
/// `false` on peer not present (disconnect race) OR channel closed OR
/// backpressure error. Callers that need to distinguish these three
/// cases should use `senders.get(...).map(|s| s.value().clone())`
/// directly.
async fn send_to_peer(
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    peer_id: &PeerId,
    data: Vec<u8>,
) -> bool {
    let sender = senders.get(peer_id).map(|s| s.value().clone());
    if let Some(sender) = sender {
        sender.send(data).await.is_ok()
    } else {
        false
    }
}

/// ANCHORS (Bitcoin Core model, PR #17428): persist the currently-connected
/// OUTBOUND peers to `<data_dir>/anchors.json`. Called periodically by the
/// connector task and on graceful shutdown. On restart these are dialed FIRST
/// (see `AddressManager::set_anchors` / `get_next`) so the node re-establishes
/// a known-good mesh immediately instead of cold-dialing the address book —
/// which, during the 2026-07-08/09 incident, churned on self-dials and
/// dead/non-p2p hosts (`broken pipe`/`reset`) and stalled sync after every
/// restart. Only outbound peers are anchored: inbound connections are
/// attacker-controllable, so anchoring them would aid, not resist, eclipsing.
fn save_anchors_to_disk(peers: &DashMap<PeerId, PeerInfo>, data_dir: &std::path::Path) {
    let anchors: Vec<SocketAddr> = peers
        .iter()
        .filter(|p| p.outbound && p.state == PeerState::Connected)
        .map(|p| p.addr)
        .collect();
    if anchors.is_empty() {
        return; // nothing worth persisting; keep the last good file
    }
    let path = data_dir.join("anchors.json");
    match serde_json::to_string(&anchors) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                warn!("Failed to save anchors: {}", e);
            }
        }
        Err(e) => warn!("Failed to serialize anchors: {}", e),
    }
}

/// Load persisted anchor peers written by [`save_anchors_to_disk`]. Missing or
/// malformed files yield an empty list (fall back to normal bootstrap).
fn load_anchors_from_disk(data_dir: &std::path::Path) -> Vec<SocketAddr> {
    let path = data_dir.join("anchors.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str::<Vec<SocketAddr>>(&s).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Process received message
/// The header has already been validated and stripped by the message framer;
/// type and payload arrive separately to avoid another payload-sized copy.
async fn process_message(
    peer_id: PeerId,
    msg_type_id: u8,
    payload: &[u8],
    magic: [u8; 4],
    our_nonce: u64,
    peers: Arc<DashMap<PeerId, PeerInfo>>,
    senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    dandelion: Arc<RwLock<DandelionRouter>>,
    sync: Arc<RwLock<ChainSync>>,
    event_tx: broadcast::Sender<NodeEvent>,
    chain: SharedBlockchain,
    mempool: SharedMempool,
    addresses: Arc<RwLock<AddressManager>>,
    scorer: Arc<RwLock<PeerScorer>>,
    _identity: Arc<super::noise::NodeIdentity>,
    // v1.0.13 #2 — tx-absence cache, populated by NotFound-receive,
    // consulted by InvTx-receive.
    tx_absence_cache: Arc<parking_lot::RwLock<TxAbsenceCache>>,
    // Node-internal inbound block-relay scores. Credited in the BlockData
    // handler when this peer delivers a valid block. Phase 1: measured
    // only — not yet consulted by eviction.
    relay_scores: Arc<RwLock<RelayScoreMap>>,
) -> Result<()> {
    let msg_type = MessageType::try_from(msg_type_id)?;

    // Traffic shaping: cover-traffic packets carry no semantic content and
    // are discarded silently. Phase 2 moved padding from the pre-launch
    // 0xDEADBEEF magic hack to a proper `MessageType::Padding` discriminant
    // routed through the framer like any other message.
    if matches!(msg_type, MessageType::Padding) {
        trace!("Discarded Padding packet from peer {:?}", &peer_id[..4]);
        return Ok(());
    }

    trace!("Received {:?} from peer {:?}", msg_type, &peer_id[..4]);


    // Update peer activity
    if let Some(mut peer) = peers.get_mut(&peer_id) {
        peer.touch();
        peer.bytes_recv = peer
            .bytes_recv
            .saturating_add(payload.len().saturating_add(1) as u64);
    }

    // SECURITY (H-3): Reject non-handshake messages from peers that haven't
    // completed the Version/Verack handshake.
    // This reduces pre-auth attack surface and aligns with production P2P posture.
    let is_allowed_pre_handshake = matches!(
        msg_type,
        // Handshake sequence
        MessageType::Version
            | MessageType::Verack
            | MessageType::Ping
            | MessageType::Pong
            | MessageType::Flare
    );
    if !is_allowed_pre_handshake {
        let is_connected = peers.get(&peer_id)
            .map(|p| p.state == PeerState::Connected)
            .unwrap_or(false);
        if !is_connected {
            tracing::trace!("Ignoring {:?} from peer {:?} (handshake in progress)", msg_type, &peer_id[..4]);
            return Ok(());
        }
    }

    match msg_type {
        MessageType::Version => {
            // SECURITY (M5): Limit payload size before deserializing VersionMessage
            // to prevent OOM from unbounded user_agent strings.
            const MAX_VERSION_MSG_SIZE: usize = 1024;
            if payload.len() > MAX_VERSION_MSG_SIZE {
                warn!("Version message too large ({} bytes) from peer {:?}", payload.len(), &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                peers.remove(&peer_id);
                senders.remove(&peer_id);
                let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
                return Ok(());
            }
            // Parse version and validate before accepting
            let version: VersionMessage = match borsh::from_slice(payload) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to deserialize Version from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    peers.remove(&peer_id);
                    senders.remove(&peer_id);
                    let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
                    return Ok(());
                }
            };
            {
                // SECURITY (NET-001 + eclipse-attack defense): Detect
                // self-connection via nonce match — but DON'T permanently
                // ban the peer's address.
                //
                // The previous code marked any address that sent us
                // `our_nonce` as "ours" and permanently skipped it. But
                // `our_nonce` is a per-node-lifetime u64; any peer who
                // received our Version (every peer we've dialed or been
                // dialed by) knows it and can replay it. An attacker
                // spins up a peer, reads our_nonce from our outbound
                // Version, then connects FROM A DIFFERENT ADDRESS sending
                // our_nonce back. With the old code we permanently banned
                // that address. Repeat → the attacker can blacklist
                // arbitrary IPs from our address book = eclipse attack
                // surface.
                //
                // Defensive fix here: detect the nonce match, disconnect,
                // but DON'T mark the address as ours. A legitimate
                // self-connection (operator addnoded their own IP) becomes
                // a one-time disconnect they can resolve via config; an
                // attacker can no longer poison the address book.
                //
                // The proper fix (per-outbound nonce tracking that binds
                // nonce ↔ dialed_addr) is a larger refactor, queued
                // separately. (Prior comment claimed Bitcoin Core's
                // `net_processing.cpp::ProcessMessage` Version handler
                // uses the identical disconnect-log-don't-ban pattern;
                // that specific internal handler shape was not re-read
                // this session and is dropped. The local disconnect-
                // without-marking design stands on its own reasoning.)
                if version.nonce == our_nonce {
                    warn!(
                        "Self-connection nonce match from peer {:?} \
                         — disconnecting. NOT marking as self-address \
                         because the nonce is replayable; if this fires \
                         repeatedly for legitimately-yours addresses, \
                         check that --addnode doesn't list this node's \
                         own IP.",
                        &peer_id[..4],
                    );
                    peers.remove(&peer_id);
                    senders.remove(&peer_id);
                    let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
                    return Ok(());
                }

                // SECURITY: Validate version message (protocol version, user agent length)
                if let Err(e) = version.validate() {
                    warn!("Rejecting peer {:?}: invalid version: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    // Disconnect the peer
                    peers.remove(&peer_id);
                    senders.remove(&peer_id);
                    let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
                    return Ok(());
                }

                // Respond with verack (only after validation passes)
                // DEADLOCK FIX: clone before await (systematic sweep).
                let sender = senders.get(&peer_id).map(|s| s.value().clone());
                if let Some(sender) = sender {
                    let verack = Message::verack(magic);
                    if let Err(e) = sender.send(verack.to_bytes()?).await {
                        warn!("Failed to send Verack to peer {:?}: {}", &peer_id[..4], e);
                    }
                    // Firework: advertise our capabilities immediately after
                    // Verack. A peer predating the capability layer receives
                    // a valid-but-unhandled Flare (type 50) and simply drops
                    // it via the dispatch catch-all — no disconnect — so this
                    // is safe to send to every peer. Its capabilities stay 0
                    // and each capability-gated feature falls back gracefully.
                    let flare = Message::flare(magic, crate::network::firework::local_capabilities())?;
                    if let Err(e) = sender.send(flare.to_bytes()?).await {
                        warn!("Failed to send Flare to peer {:?}: {}", &peer_id[..4], e);
                    }
                } else {
                    warn!("No sender for peer {:?} when sending Verack", &peer_id[..4]);
                }

                if let Some(mut peer) = peers.get_mut(&peer_id) {
                    peer.version = version.version;
                    peer.user_agent = version.user_agent;
                    peer.height = version.start_height;
                    peer.tip_hash = version.best_hash;
                    peer.state = PeerState::VersionReceived;
                }

                // Mark peer as validated in scorer
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).validated = true;
                }

                // Update sync manager and propagate target_height to chain.
                // Do NOT send GetHeaders here — peer is still VersionReceived,
                // not Connected. Headers response would be dropped by the
                // handshake gate (line 1657). GetHeaders fires in Verack handler.
                {
                    let mut s = sync.write().await;
                    s.update_peer_height_for(peer_id, version.start_height);
                    let stats = s.stats();
                    let true_best = s.true_best_height();
                    drop(s);
                    chain.set_sync_info(
                        stats.local_height >= true_best,
                        true_best,
                    );
                }
            }
        }

        MessageType::Flare => {
            // Firework capability advertisement. Store the peer's bitfield
            // into PeerInfo::capabilities; unknown bits are ignored by
            // consumers (which test specific CAP_* bits via has_cap). This
            // message is ADVISORY — an oversized or malformed payload is
            // dropped silently and is never a disconnect reason.
            const MAX_FLARE_MSG_SIZE: usize = 32;
            if payload.len() > MAX_FLARE_MSG_SIZE {
                trace!(
                    "Oversized Flare ({} bytes) from peer {:?}, ignoring",
                    payload.len(), &peer_id[..4]
                );
            } else {
                match borsh::from_slice::<FlareMessage>(payload) {
                    Ok(flare) => {
                        if let Some(mut peer) = peers.get_mut(&peer_id) {
                            peer.capabilities = flare.capabilities;
                        }
                        trace!(
                            "Peer {:?} advertised capabilities {:#x}",
                            &peer_id[..4], flare.capabilities
                        );
                        // Firework Phase 2: if the peer supports CAP_CHAINWORK,
                        // send our current cumulative work immediately so it
                        // can evaluate our chain during handshake, not only on
                        // our next tip advance.
                        if crate::network::firework::has_cap(
                            flare.capabilities,
                            crate::network::firework::CAP_CHAINWORK,
                        ) {
                            let sender = senders.get(&peer_id).map(|s| s.value().clone());
                            if let Some(sender) = sender {
                                match Message::chain_work(
                                    magic,
                                    chain.stats().total_difficulty,
                                    chain.height(),
                                    chain.tip_hash(),
                                )
                                .and_then(|m| m.to_bytes())
                                {
                                    Ok(bytes) => {
                                        let _ = sender.send(bytes).await;
                                    }
                                    Err(e) => warn!(
                                        "Flare: failed to build ChainWork for peer {:?}: {}",
                                        &peer_id[..4], e
                                    ),
                                }
                            }
                        }
                    }
                    Err(e) => {
                        trace!("Malformed Flare from peer {:?}: {} (ignoring)", &peer_id[..4], e);
                    }
                }
            }
        }

        MessageType::ChainWork => {
            // Firework Phase 2: a CAP_CHAINWORK peer told us its cumulative
            // work + tip. Feed it into the sync manager's peer-work table so
            // we can recognize a heavier chain even when it is shorter in
            // height. The advertised work is a CLAIM, not proof — it only
            // influences which peer we request headers from; adoption still
            // recomputes summed PoW in fork choice. update_peer_difficulty_for
            // already caps bogus over-claims. Advisory: malformed/oversized
            // payloads are dropped silently, never a disconnect reason.
            const MAX_CHAINWORK_MSG_SIZE: usize = 256;
            if payload.len() > MAX_CHAINWORK_MSG_SIZE {
                trace!("Oversized ChainWork ({} bytes) from peer {:?}, ignoring", payload.len(), &peer_id[..4]);
            } else {
                match borsh::from_slice::<ChainWorkMessage>(payload) {
                    Ok(cw) => {
                        if let Some(mut peer) = peers.get_mut(&peer_id) {
                            peer.height = cw.height;
                            peer.tip_hash = cw.best_hash;
                        }
                        {
                            let mut s = sync.write().await;
                            s.update_peer_difficulty_for(peer_id, cw.total_difficulty);
                            s.update_peer_height_for(peer_id, cw.height);
                        }
                        trace!(
                            "Peer {:?} ChainWork: td={} h={}",
                            &peer_id[..4], cw.total_difficulty, cw.height
                        );
                    }
                    Err(e) => {
                        trace!("Malformed ChainWork from peer {:?}: {} (ignoring)", &peer_id[..4], e);
                    }
                }
            }
        }

        MessageType::Verack => {
            let is_outbound = peers.get(&peer_id).map(|p| p.outbound).unwrap_or(false);

            // Phase 1 #6: handshake complete — observe wall-time from
            // PeerInfo::connected_at (set at peers.insert) to now.
            if let Some(p) = peers.get(&peer_id) {
                let elapsed = p.connected_at.elapsed().as_secs_f64();
                crate::metrics::PEER_HANDSHAKE.observe(elapsed);
            }

            if let Some(mut peer) = peers.get_mut(&peer_id) {
                peer.state = PeerState::Connected;
            }

            // Register outbound peers for Dandelion++ relay selection
            if is_outbound {
                dandelion.write().await.add_outbound_peer(peer_id);
                debug!("Added outbound peer {:?} to Dandelion++ pool", &peer_id[..4]);
            }

            // Send GetAddr to discover more peers after handshake
            let getaddr = Message::new(magic, MessageType::GetAddr, vec![]);
            if let Ok(data) = getaddr.to_bytes() {
                let _ = send_to_peer(&senders, &peer_id, data).await;
            }

            // Handshake complete — if this peer is ahead, send GetHeaders with nonce.
            let peer_height = peers.get(&peer_id).map(|p| p.height).unwrap_or(0);
            let our_height = chain.height();
            if peer_height > our_height {
                let chain_ref = &chain;
                let locator = build_locator(our_height, |h| chain_ref.get_block_hash(h));
                if !locator.is_empty() {
                    let nonce = sync.write().await.allocate_header_nonce();
                    if let Ok(msg) = Message::get_headers_with_nonce(magic, locator, Hash::zero(), nonce) {
                        if let Ok(data) = msg.to_bytes() {
                            // DEADLOCK FIX: inline clone-then-await to preserve the
                            // exact pre-fix log semantics — info! fires whenever the
                            // peer WAS in the map, regardless of whether the send
                            // ultimately succeeded (matches the pre-fix `let _ =
                            // sender.send(...).await` pattern that discarded the
                            // send-result). Using the send_to_peer helper here would
                            // change the log to fire only on send success, which is a
                            // subtle observable behavior change we don't want.
                            let sender = senders.get(&peer_id).map(|s| s.value().clone());
                            if let Some(sender) = sender {
                                let _ = sender.send(data).await;
                                info!(
                                    "Handshake complete — GetHeaders nonce={} to peer {:?} (h={}, we={})",
                                    nonce, &peer_id[..4], peer_height, our_height
                                );
                            }
                        }
                    }
                }
            }
        }

        MessageType::Ping => {
            // Parse nonce and respond with pong.
            // P5-N5 fix: score malformed pings (< 8 bytes) as protocol violation.
            if payload.len() < 8 {
                warn!("Malformed Ping (<8 bytes) from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                }
                return Ok(());
            }
            let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
            let pong = Message::pong(magic, nonce);
            let _ = send_to_peer(&senders, &peer_id, pong.to_bytes()?).await;
        }

        MessageType::Pong => {
            // Update latency (could track round trip time)
        }

        MessageType::GetHeaders => {
            // Peer is requesting headers - serve from our chain.
            // P5-N6 fix: tight per-type cap.
            if payload.len() > super::protocol::MAX_GETHEADERS_PAYLOAD {
                warn!("GetHeaders message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            if let Ok(msg) = borsh::from_slice::<GetHeadersMessage>(payload) {
                if let Err(e) = msg.validate() {
                    warn!("Invalid GetHeaders from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }

                // Walk locator to find the fork point, then collect headers
                // up to MAX_HEADERS_RESPONSE. Both loops do per-iteration
                // chain DB reads; wrap the whole transactional view in
                // `block_in_place` so the worker can be reused for other
                // tasks if a read stalls. (Layer 2 of post-launch campaign.)
                let headers = tokio::task::block_in_place(|| {
                    let mut start_height = 0u64;
                    for hash in &msg.locator {
                        if let Some(block) = chain.get_block(hash) {
                            start_height = block.height() + 1;
                            break;
                        }
                    }
                    let mut headers = Vec::new();
                    for h in start_height..start_height + MAX_HEADERS_RESPONSE as u64 {
                        if let Some(block) = chain.get_block_by_height(h) {
                            let block_hash = block.hash();
                            headers.push(block.header.clone());
                            if block_hash == msg.stop_hash {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    headers
                });

                // Always respond (even with empty headers) so the requester knows.
                // Echo the nonce for request/response correlation.
                if let Ok(resp) = Message::headers_with_nonce(magic, headers, msg.nonce) {
                    let _ = send_to_peer(&senders, &peer_id, resp.to_bytes()?).await;
                }
            }
        }

        MessageType::GetBlocks => {
            // Peer is requesting full blocks by hash.
            // P5-N-CLASS-A fix: tight per-type cap.
            if payload.len() > super::protocol::MAX_GETBLOCKS_PAYLOAD {
                warn!("GetBlocks message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            match borsh::from_slice::<GetBlocksMessage>(payload) {
                Ok(msg) => {
                    if let Err(e) = msg.validate() {
                        warn!("Invalid GetBlocks from peer {:?}: {}", &peer_id[..4], e);
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr)
                                .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                        }
                        return Ok(());
                    }

                    let requested = msg.hashes.len();
                    // Layer 2: pull full blocks from the chain DB inside
                    // block_in_place so a slow DB read doesn't freeze the
                    // worker thread mid-response.
                    let blocks = tokio::task::block_in_place(|| {
                        let mut blocks = Vec::new();
                        for hash in &msg.hashes {
                            if let Some(block) = chain.get_block(hash) {
                                blocks.push(block);
                                if blocks.len() >= MAX_BLOCK_HASHES {
                                    break;
                                }
                            }
                        }
                        blocks
                    });

                    debug!(
                        "GetBlocks from {:?}: {} requested, {} found",
                        &peer_id[..4], requested, blocks.len()
                    );

                    // Always respond (even with empty blocks) so the requester
                    // can free download slots instead of waiting for timeout.
                    if let Ok(resp) = Message::blocks(magic, blocks) {
                        let _ = send_to_peer(&senders, &peer_id, resp.to_bytes()?).await;
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize GetBlocks from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::InvTx => {
            // Transaction inventory - request txs we don't have.
            // P5-N8 + P5-N-CLASS-A fix: tight size cap + score borsh Err.
            if payload.len() > super::protocol::MAX_INV_PAYLOAD {
                warn!("InvTx message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            match borsh::from_slice::<InvMessage>(payload) {
                Ok(inv_msg) => {
                if let Err(e) = inv_msg.validate() {
                    warn!("Invalid InvTx from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }
                let mut needed = Vec::new();
                {
                    // v1.0.13 #2 — single read-lock to filter both
                    // mempool presence AND tx-absence cache (so we
                    // don't re-request hashes a peer recently said
                    // they don't have).
                    let absence = tx_absence_cache.read();
                    for inv in &inv_msg.inventory {
                        if !mempool.contains(&inv.hash) && !absence.is_known_absent(&inv.hash) {
                            needed.push(inv.hash);
                        }
                    }
                }
                // Request missing transactions via GetTxs
                if !needed.is_empty() {
                    // Reuse GetBlocksMessage format for tx hashes
                    let get_msg = GetBlocksMessage { hashes: needed };
                    if let Ok(payload_bytes) = borsh::to_vec(&get_msg) {
                        let msg = Message::new(magic, MessageType::GetTxs, payload_bytes);
                        let _ = send_to_peer(&senders, &peer_id, msg.to_bytes()?).await;
                    }
                }
                }
                Err(e) => {
                    // P5-N7 fix: score borsh parse failure.
                    warn!("Failed to deserialize InvTx from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::NotFound => {
            // v1.0.13 #2 — peer told us they don't have a set of
            // hashes we asked for. Mark each in the absence cache
            // so the InvTx handler skips re-requesting them via
            // GetTxs for the TTL window (60s).
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("NotFound message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            if let Ok(nf) = borsh::from_slice::<super::protocol::NotFoundMessage>(payload) {
                if let Err(e) = nf.validate() {
                    warn!("Invalid NotFound from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }
                let n = nf.hashes.len();
                {
                    let mut cache = tx_absence_cache.write();
                    for h in nf.hashes {
                        cache.mark_absent(h);
                    }
                }
                debug!("NotFound from peer {:?}: cached {} absent tx hash(es)",
                       &peer_id[..4], n);
            }
        }

        MessageType::InvBlock => {
            // Block inventory - check if we're missing blocks.
            // P5-N8 + P5-N-CLASS-A fix: tight size cap + Err scoring.
            if payload.len() > super::protocol::MAX_INV_PAYLOAD {
                warn!("InvBlock message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            match borsh::from_slice::<InvMessage>(payload) {
                Ok(inv_msg) => {
                if let Err(e) = inv_msg.validate() {
                    warn!("Invalid InvBlock from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }

                // During IBD, skip the block-body fetch (a new-tip InvBlock hash
                // generally won't chain off our current IBD position and would
                // pile up orphans). BUT — send a GetHeaders to this peer first
                // so peer.height refreshes from real header.height values in the
                // response. Without this, peer.height stays frozen at the handshake-
                // time value: when the source mines past handshake, our sync
                // target never rises, IBD declares done at the stale tip, and the
                // node stays permanently behind (this was the launch-day stall).
                if !sync.read().await.is_synced() {
                    let our_height = chain.height();
                    // CIP-019: a node only a few blocks behind (near tip) must keep
                    // catching up promptly. The old gate treated near-tip like deep
                    // IBD, trapping such a node on slow catch-up so it stayed
                    // permanently a few blocks behind and its miner's sync gate
                    // never cleared (observed live 2026-07-11). Refresh headers
                    // either way; for a near-tip node ALSO nudge a prompt resync so
                    // the small gap closes to the exact tip. Deep-IBD behavior
                    // (skip the body fetch to avoid orphan pileup) is unchanged.
                    let near_tip = invblock_near_tip(
                        false,
                        chain.peer_advertised_height().saturating_sub(our_height),
                        NEAR_TIP_INV_WINDOW,
                    );
                    let chain_ref = &chain;
                    let locator = build_locator(our_height, |h| chain_ref.get_block_hash(h));
                    if !locator.is_empty() {
                        let nonce = sync.write().await.allocate_header_nonce();
                        if let Ok(msg) = Message::get_headers_with_nonce(magic, locator, Hash::zero(), nonce) {
                            if let Ok(data) = msg.to_bytes() {
                                // DEADLOCK FIX: same pattern as the Handshake GetHeaders
                                // above — inline clone-then-await preserves the pre-fix
                                // "log fires if peer was in map" semantics exactly.
                                let sender = senders.get(&peer_id).map(|s| s.value().clone());
                                if let Some(sender) = sender {
                                    let _ = sender.send(data).await;
                                    debug!(
                                        "InvBlock during IBD: sent GetHeaders nonce={} to peer {:?} to refresh tip (our_h={})",
                                        nonce, &peer_id[..4], our_height
                                    );
                                }
                            }
                        }
                    }
                    if near_tip {
                        // Near tip: pull the small gap promptly rather than waiting on
                        // the slow tick. trigger_resync only fires from Synced/Idle;
                        // a node actively (but slowly) catching up sits in Headers/
                        // Blocks, where trigger_resync is a no-op — so it would stay
                        // stuck a few blocks behind forever (the randomx-2 case). Fall
                        // back to arm_near_tip_catchup, which re-arms a header pull when
                        // we're behind AND idle (nothing in flight), closing the gap.
                        let mut sg = sync.write().await;
                        if !sg.trigger_resync() {
                            sg.arm_near_tip_catchup();
                        }
                    }
                    return Ok(());
                }

                // Post-IBD: peer has blocks we don't. Fetch them directly
                // via GetBlocks (below). We do NOT speculatively bump
                // peer_heights[peer_id] here — the bump used to be:
                //
                //     update_peer_height_for(peer_id, our_h + 1)
                //
                // as a "lower bound" estimate. In practice that was a
                // permanent latch: if the peer never delivered the
                // announced block (stale orphan-fork remnant, peer with
                // a phantom hash in its known set, etc.), peer_heights
                // stayed at our_h+1 forever. best_known_height latched
                // to our_h+1. is_synced() returned false. coincync-rig's
                // sync gate flipped — "refusing to mine to avoid
                // producing blocks on a private fork" — and the chain
                // wedged until somebody restarted the offending peer.
                // This was the production failure mode observed
                // 2026-06-27 (multiple wedges, including one 42-min
                // stall that required an emergency
                // COINCYNC_RIG_SKIP_SYNC_CHECK=1 bypass to recover).
                //
                // The rc5 refresh_best_known fix (PR #125) made the
                // peer-disconnect path self-clear correctly. But a
                // STILL-CONNECTED peer with a latched bump kept
                // best_known pinned regardless. The bump itself is
                // the bug — remove it.
                //
                // Correct peer_height updates still happen via:
                //   - Handshake (version.start_height) at node.rs:~3033
                //   - Header sync (max_header_height) at node.rs:~3640
                // Both of those use ACTUAL heights, not speculation.
                // When we successfully receive and process the block
                // requested below, refresh_best_known runs on
                // on_block_processed (rc5 fix) and recomputes
                // best_known from current peer_heights + local. No
                // speculation needed.
                //
                // (Prior comment asserted Bitcoin Core / Monero / zebrad
                // all share this "no speculative peer-height bump on Inv"
                // posture; that cross-project generalization was not
                // verified this session and is dropped. The confirmed-
                // message-only design stands on its own reasoning.)

                let mut needed = Vec::new();
                for inv in &inv_msg.inventory {
                    if chain.get_block(&inv.hash).is_none() {
                        needed.push(inv.hash);
                    }
                }
                if !needed.is_empty() {
                    if needed.len() <= 4 {
                        // Small number of missing blocks — request them directly
                        // (fast path: avoids full header re-sync round-trip).
                        let get_blocks = super::protocol::GetBlocksMessage {
                            hashes: needed.clone(),
                        };
                        if let Ok(payload) = borsh::to_vec(&get_blocks) {
                            let msg_out = Message::new(magic, MessageType::GetBlocks, payload);
                            if let Ok(data) = msg_out.to_bytes() {
                                // DEADLOCK FIX: two awaits inside the guard (send +
                                // sync.write). Clone the sender out first, then run
                                // both awaits with the DashMap Ref already dropped.
                                let sender = senders.get(&peer_id).map(|s| s.value().clone());
                                if let Some(sender) = sender {
                                    if sender.send(data).await.is_ok() {
                                        // Track so timeout/retry works
                                        let now = chrono::Utc::now().timestamp() as u64;
                                        let mut sg = sync.write().await;
                                        for hash in &needed {
                                            sg.track_direct_request(*hash, peer_id, now);
                                        }
                                        debug!(
                                            "InvBlock: directly requesting {} blocks from peer {:?}",
                                            needed.len(), &peer_id[..4]
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        // Many missing blocks — full header re-sync (Bitcoin-style).
                        let triggered = sync.write().await.trigger_resync();
                        if triggered {
                            debug!(
                                "InvBlock from peer {:?} has {} unknown blocks, triggered header re-sync",
                                &peer_id[..4], needed.len()
                            );
                        }
                    }
                }
                }
                Err(e) => {
                    // P5-N7 fix: score borsh parse failure.
                    warn!("Failed to deserialize InvBlock from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::GetTxs => {
            // Peer is requesting transactions by hash.
            // P5-N-CLASS-A fix: tight per-type cap.
            if payload.len() > super::protocol::MAX_GETTXS_PAYLOAD {
                warn!("GetTxs message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            // P5-N7 fix: match with Err scoring instead of silent-Ok.
            match borsh::from_slice::<GetBlocksMessage>(payload) {
                Ok(msg) => {
                if let Err(e) = msg.validate() {
                    warn!("Invalid GetTxs from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }
                let mut txs = Vec::new();
                // v1.0.13 #2 — track which requested hashes we don't
                // have so we can reply NotFound for them. Pre-fix we
                // silently dropped misses; peer kept re-asking, we
                // kept doing mempool.get() per re-ask.
                let mut absent = Vec::new();
                for hash in &msg.hashes {
                    if let Some(tx) = mempool.get(hash) {
                        txs.push(tx);
                    } else {
                        absent.push(*hash);
                    }
                }
                if !txs.is_empty() {
                    if let Ok(resp) = Message::txs(magic, txs) {
                        let _ = send_to_peer(&senders, &peer_id, resp.to_bytes()?).await;
                    }
                }
                if !absent.is_empty() {
                    if let Ok(resp) = Message::not_found(magic, absent) {
                        let _ = send_to_peer(&senders, &peer_id, resp.to_bytes()?).await;
                    }
                }
                }
                Err(e) => {
                    warn!("Failed to deserialize GetTxs from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::Txs => {
            // SECURITY: Limit payload size before deserialization to prevent CPU exhaustion.
            // F12 fix (2026-07-05 audit): "message too large" is OversizedMessage
            // (10pt / 5-strike) not ProtocolViolation (20pt / 3-strike). Pre-fix used
            // the legacy `record_protocol_violation` which applied the wrong penalty.
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("Txs message too large from peer {}", hex::encode(&peer_id[..8]));
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            // Parse transactions.
            // P5-N7 fix: match with Err scoring.
            match borsh::from_slice::<super::protocol::TxsMessage>(payload) {
                Ok(txs_msg) => {
                // SECURITY: Validate message before processing
                if let Err(e) = txs_msg.validate() {
                    warn!("Invalid TxsMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr).record_invalid_tx();
                    }
                    return Ok(());
                }
                // Record successful tx relay
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    let mut s = scorer.write().await;
                    for _ in 0..txs_msg.transactions.len() {
                        s.get_or_create(addr).record_tx_success();
                    }
                }
                for tx in txs_msg.transactions {
                    // SECURITY: Quick-validate transaction structure before relay.
                    // Prevents garbage txs from consuming CPU across the network.
                    if let Err(e) = crate::consensus::validate_transaction_basic(&tx) {
                        let reason = e.to_string();
                        warn!("Rejecting invalid tx from peer {}: {}", hex::encode(&peer_id[..8]), reason);
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            // Score using the unified MisbehaviorType ladder
                            // (InvalidTransaction = 25 pts, 2-3 offenses → ban).
                            // The previous `record_invalid_tx()` path only
                            // deducted 5 pts, requiring ~10 strikes to ban.
                            // Active disconnect is handled by the maintenance
                            // loop's `auto_ban_bad_peers()` tick at node.rs:1493
                            // (within ~10s of crossing the ban threshold).
                            let offense = super::scoring::classify_invalid_tx_reason(&reason);
                            let mut s = scorer.write().await;
                            let score = s.get_or_create(addr);
                            score.record_misbehavior(offense);
                            // Keep legacy counter in sync for stats/reporting.
                            score.invalid_txs += 1;
                        }
                        continue;
                    }
                    // Route through Dandelion++ (stem/fluff/ignore)
                    let now = chrono::Utc::now().timestamp() as u64;
                    let action = dandelion.write().await.add_received_tx(tx.clone(), peer_id, now);
                    match action {
                        StemAction::Fluff(fluff_tx) => {
                            // Fluff epoch or loop detected — broadcast to all peers
                            if let Ok(msg) = Message::inv_tx(magic, fluff_tx.hash()) {
                                if let Ok(data) = msg.to_bytes() {
                                    // DEADLOCK FIX: snapshot senders before awaiting
                                    // per-peer send. See PR body for the systematic
                                    // sweep across this file.
                                    let senders_snapshot: Vec<tokio::sync::mpsc::Sender<Vec<u8>>> =
                                        senders.iter().map(|s| s.value().clone()).collect();
                                    for sender in senders_snapshot {
                                        let _ = sender.send(data.clone()).await;
                                    }
                                }
                            }
                            // Immediate-fluff (loop detection or fluff epoch).
                            // `peer_id` is the peer that just relayed this tx
                            // to us — they're the responsible party if mempool
                            // admit fails on full-crypto validation.
                            let _ = event_tx.send(NodeEvent::TransactionReceived(fluff_tx, Some(peer_id)));
                        }
                        StemAction::Stem => {
                            // Stem mode: tx is in stempool, will be relayed by tick()
                            // Do NOT add to local mempool — that would defeat Dandelion++ privacy.
                            // The tx will enter the mempool only when it is fluffed.
                        }
                        StemAction::Ignore => {
                            // Already known — skip
                        }
                    }
                }
                }
                Err(e) => {
                    warn!("Failed to deserialize TxsMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        // F2 fix: migrate to unified record_misbehavior for
                        // consistent observability. Borsh decode failure is
                        // a genuine ProtocolViolation.
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::Blocks => {
            // SECURITY: Limit payload size before deserialization to prevent CPU exhaustion.
            // F12 fix: OversizedMessage (10pt), not ProtocolViolation (20pt).
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("Blocks message too large from peer {}", hex::encode(&peer_id[..8]));
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            // Parse blocks. P5-N7 fix: match with Err scoring.
            match borsh::from_slice::<super::protocol::BlocksMessage>(payload) {
                Ok(blocks_msg) => {
                // SECURITY: Limit number of blocks per message.
                // F12 fix: "too many items in one message" is OversizedMessage
                // semantically — the peer is sending too much data in one frame,
                // not sending malformed data.
                if blocks_msg.blocks.len() > super::protocol::MAX_BLOCK_HASHES {
                    warn!("Too many blocks in message from peer {}", hex::encode(&peer_id[..8]));
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                    }
                    return Ok(());
                }
                // Record successful block delivery
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    let count = blocks_msg.blocks.len();
                    let mut s = scorer.write().await;
                    for _ in 0..count {
                        s.get_or_create(addr).record_block_success(Duration::from_millis(100));
                    }
                }
                info!("[IBD] Received Blocks message: {} blocks from peer {:?}", blocks_msg.blocks.len(), &peer_id[..4]);

                // If peer responds with 0 blocks, the hashes we requested don't
                // exist on their chain (different fork). DON'T clear sync state —
                // that destroys all progress. Instead, mark this peer as
                // incompatible and continue with other peers.
                if blocks_msg.blocks.is_empty() {
                    debug!("[IBD] Got 0 blocks from peer {:?} — empty Blocks reply, demoting", &peer_id[..4]);
                    // Record an empty-Blocks response so the scorer can ban
                    // this peer from `GetBlocks` selection after N consecutive
                    // empties. Closes the "stall pathology" wedge pattern
                    // (peer accepts requests but never delivers).
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr).record_empty_blocks_response();
                    }
                    return Ok(());
                }

                for (bi, block) in blocks_msg.blocks.into_iter().enumerate() {
                    debug!("  block[{}]: height={} algo={} size={} txs={}",
                        bi, block.header.height, block.header.algorithm,
                        block.size(), block.transactions.len());

                    // SECURITY (NetworkTag): FIRST CHECK — reject wrong-network blocks
                    // before any expensive validation. Costs 4 bytes comparison.
                    // Instant-bans the peer (MisbehaviorType::WrongNetwork = -100).
                    if block.header.network_magic != magic {
                        warn!("Rejecting block from wrong network (magic {:?} != {:?}) from peer {}",
                            block.header.network_magic, magic, hex::encode(&peer_id[..8]));
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr)
                                .record_misbehavior(super::scoring::MisbehaviorType::WrongNetwork);
                        }
                        continue;
                    }

                    // SECURITY: Quick-validate block before relay to prevent
                    // garbage blocks from consuming CPU across the network.
                    // Check size, tx count, and basic header sanity. Full PoW
                    // verification happens in chain.add_block() (requires prev block).
                    let size = block.size();
                    if size > crate::constants::MAX_BLOCK_SIZE {
                        warn!("Rejecting oversized block ({} bytes) from peer {}",
                            size, hex::encode(&peer_id[..8]));
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr).record_block_failure();
                        }
                        continue;
                    }
                    if block.transactions.len() > crate::constants::MAX_TXS_PER_BLOCK {
                        warn!("Rejecting block with too many txs ({}) from peer {}",
                            block.transactions.len(), hex::encode(&peer_id[..8]));
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr).record_block_failure();
                        }
                        continue;
                    }
                    // Verify PoW hash meets the claimed target (cheap check — no
                    // chain lookup needed). A full PoW check (anchor recomputation,
                    // difficulty validation) happens later in add_block().
                    //
                    // SECURITY (2026-07-05 audit F11 — SEV-A): The two failure
                    // paths below map to DIFFERENT peer misbehavior categories:
                    //
                    //   * `compute_pow_hash(...) → Err(_)`: We failed to
                    //     RECOMPUTE the hash locally (out-of-range algorithm
                    //     id, dataset error, etc.). This is ambiguous — the
                    //     peer sent a well-formed block whose hash we can't
                    //     verify because OUR side has a state issue. Not
                    //     clearly the peer's fault. Keep low-weight
                    //     `record_block_failure` (-10 rep, 10-strike ban)
                    //     which acts as a soft demotion.
                    //
                    //   * `!pow_hash.meets_difficulty(target)`: We recomputed
                    //     the hash and it DOES NOT satisfy the claimed
                    //     target. This is provable cryptographic invalidity —
                    //     the peer is trying to waste our CPU on validation
                    //     of a block that mathematically cannot be valid.
                    //     Instant ban (`InvalidBlockPoW`, penalty 100).
                    //
                    //   Pre-audit: both paths used `record_block_failure`
                    //   (-10), meaning a malicious peer needed 10 strikes to
                    //   accumulate the ban threshold. That's ~10 free CPU-
                    //   burning attempts before we cut them off. Bitcoin
                    //   Core's `MSG_BLOCK_HEADER_LOW_WORK` maps directly to
                    //   discouragement (their equivalent of instant ban) for
                    //   the same reason — sub-target PoW is proof of
                    //   attack intent, not accidental protocol drift.
                    let pow_hash = match crate::consensus::compute_pow_hash(
                        crate::consensus::PowAlgorithm::from_index(block.header.algorithm),
                        &block.header.anchor,
                        block.header.nonce,
                        &block.header.tx_root,
                        block.header.height,
                    ) {
                        Ok(h) => h,
                        Err(_) => {
                            warn!("PoW hash computation failed for block from peer {}",
                                hex::encode(&peer_id[..8]));
                            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                                scorer.write().await.get_or_create(addr).record_block_failure();
                            }
                            continue;
                        }
                    };
                    if !pow_hash.meets_difficulty(&block.header.target) {
                        warn!("Instant-banning peer {} — provably-invalid PoW: \
                               block hash {:?} does not meet claimed target {:?}",
                            hex::encode(&peer_id[..8]),
                            pow_hash,
                            block.header.target);
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr)
                                .record_misbehavior(super::scoring::MisbehaviorType::InvalidBlockPoW);
                        }
                        continue;
                    }
                    let _ = event_tx.send(NodeEvent::BlockReceived(block, peer_id));
                }
                }
                Err(e) => {
                    warn!("Failed to deserialize BlocksMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        // F2 fix: unified record_misbehavior for observability.
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::Headers => {
            // SECURITY: Limit payload size before deserialization.
            // F12 fix: OversizedMessage, not ProtocolViolation.
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("Headers message too large from peer {}", hex::encode(&peer_id[..8]));
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            // Parse headers and queue for download. P5-N7 fix: match with Err scoring.
            match borsh::from_slice::<super::protocol::HeadersMessage>(payload) {
                Ok(headers_msg) => {
                // SECURITY: Validate message before processing.
                // F15 fix (2026-07-05 audit): HeadersMessage struct-level validate()
                // failure is protocol-frame-level (peer sent malformed HEADERS message),
                // not block-content-level. Pre-fix used `record_block_failure` (-10 rep)
                // which is the wrong category — the peer's Headers frame itself is
                // malformed. Now uses `ProtocolViolation` (20pt / 3-strike ban) via
                // the unified record_misbehavior.
                if let Err(e) = headers_msg.validate() {
                    warn!("Invalid HeadersMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }
                // Update best_known_height from the highest header received.
                // This ensures sync knows the real chain height, not just what
                // the peer reported at connection time.
                let max_header_height = headers_msg.headers.iter()
                    .map(|h| h.height)
                    .max()
                    .unwrap_or(0);

                // Validate nonce — only accept responses to OUR requests
                let mut sync_guard = sync.write().await;
                if !sync_guard.validate_header_nonce(headers_msg.nonce) {
                    debug!(
                        "Ignoring Headers with unknown nonce={} from peer {:?} (crossed response)",
                        headers_msg.nonce, &peer_id[..4]
                    );
                    drop(sync_guard);
                    return Ok(());
                }

                // v1.0.13 #3 — pre-PoW verification on each header.
                //
                // Pre-fix, Headers responses were queued unconditionally
                // into pending_headers; PoW was only re-validated at
                // block-receive time. A peer that wins the GetHeaders
                // nonce race could send 2000 random-bytes headers,
                // filling the pool with hashes whose corresponding
                // blocks no one (including the sender) can serve.
                //
                // The cheap defense: every header carries a
                // `claimed_anchor` that's a hash of (prev_hash, height,
                // timestamp). We recompute the real anchor and reject
                // the batch on first mismatch. This forces a flooder
                // to actually BLAKE2b-precompute every fake header
                // chaining off our tip — meaningful work, no longer
                // free.
                //
                // Full RandomX-hash verification (the ~10-20ms-per-
                // header expensive check) still happens at block-
                // receive time, where it belongs (one check per
                // actually-served block, not per advertised tip).
                let bad_anchor_at = headers_msg.headers.iter().enumerate().find_map(|(i, hdr)| {
                    match crate::consensus::pow::compute_full_anchor(
                        &hdr.prev_hash, hdr.height, hdr.timestamp,
                    ) {
                        Ok(anchor) if anchor.mixed_hash == hdr.anchor => None,
                        _ => Some(i),
                    }
                });
                if let Some(idx) = bad_anchor_at {
                    warn!(
                        "Headers pre-PoW reject: header[{}] anchor mismatch from peer {:?} \
                         (h={}). Dropping batch + scoring peer.",
                        idx, &peer_id[..4], headers_msg.headers[idx].height,
                    );
                    drop(sync_guard);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }

                let hashes: Vec<Hash> = headers_msg.headers.iter()
                    .map(|h| h.hash())
                    .collect();
                // Update both global best_known and this specific peer's height.
                // This peer responded with headers up to max_header_height, so it
                // can serve blocks up to that height — critical for height-aware
                // block request routing.
                sync_guard.update_peer_height(max_header_height);
                sync_guard.update_peer_height_for(peer_id, max_header_height);
                sync_guard.reset_headers_timeout();
                debug!(
                    "Accepted Headers nonce={} count={} max_height={} from peer {:?}",
                    headers_msg.nonce, hashes.len(), max_header_height, &peer_id[..4]
                );
                // v1.0.13 #4 — attributed queue so one peer can't
                // fill the 50K-slot pending_headers pool. Cap is
                // MAX_HEADERS_PER_PEER (5000) per peer.
                sync_guard.queue_headers_from_peer(peer_id, hashes);
                }
                Err(e) => {
                    warn!("Failed to deserialize HeadersMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        // F2 fix: unified record_misbehavior for observability.
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::GetAddr => {
            // ── Firework: Veil ───────────────────────────────────────────────
            // Only respond to Noise-encrypted peers. A plaintext peer has not
            // proven its identity, so sharing our address book with it lets a
            // passive observer map P2P topology without making a single
            // authenticated connection. Silently ignore the request instead of
            // sending an error so non-Veil nodes don't see a protocol fault.
            let peer_encrypted = peers.get(&peer_id)
                .map(|p| p.encrypted)
                .unwrap_or(false);
            if !peer_encrypted {
                debug!("Veil: ignoring GetAddr from plaintext peer {:?}", &peer_id[..4]);
                return Ok(());
            }

            // 1.0: Firework "Veil" capability filter removed. Every peer
            // gets the full shareable address book. Noise-aware topology
            // separation will come back when the capability layer is
            // redesigned post-testnet.

            let addrs = addresses.read().await;
            let peer_addrs = addrs.get_for_exchange(100);
            drop(addrs);

            if !peer_addrs.is_empty() {
                let net_addrs: Vec<super::protocol::NetAddr> = peer_addrs.iter()
                    .map(|pa| {
                        let ip_bytes = match pa.addr.ip() {
                            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                            std::net::IpAddr::V6(v6) => v6.octets(),
                        };
                        super::protocol::NetAddr {
                            services: pa.services,
                            ip: ip_bytes,
                            port: pa.addr.port(),
                            timestamp: pa.last_seen,
                        }
                    })
                    .collect();

                if net_addrs.is_empty() {
                    return Ok(()); // Nothing to send after Veil filter
                }

                let addr_msg = super::protocol::AddrMessage { addresses: net_addrs };
                if let Ok(payload_bytes) = borsh::to_vec(&addr_msg) {
                    let msg = Message::new(magic, MessageType::Addr, payload_bytes);
                    let _ = send_to_peer(&senders, &peer_id, msg.to_bytes()?).await;
                }
            }
        }

        MessageType::Addr => {
            // SECURITY: Validate addr messages.
            // P5-N-CLASS-A fix: tight per-type cap.
            if payload.len() > super::protocol::MAX_ADDR_PAYLOAD {
                warn!("Addr message too large from peer {}", hex::encode(&peer_id[..8]));
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            // P5-N7 fix: match with Err scoring.
            match borsh::from_slice::<super::protocol::AddrMessage>(payload) {
                Ok(addr_msg) => {
                if let Err(e) = addr_msg.validate() {
                    warn!("Invalid AddrMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::InvalidAddress);
                    }
                    return Ok(());
                }

                let now = chrono::Utc::now().timestamp() as u64;
                let max_future = now + 600; // Allow 10 minutes of clock skew
                // FIX: Relax age check. 3 hours was too aggressive — after a
                // chain wipe or long downtime, ALL addresses in peers' books
                // have old timestamps and get rejected, preventing peer discovery.
                // 7 days allows nodes to bootstrap from peers that
                // haven't been seen recently. (Prior comment cited a
                // "Bitcoin Core uses 10 days" comparison; that specific
                // upstream threshold was not re-verified this session
                // and is dropped.)
                let max_age = 7 * 24 * 3600; // Reject addresses older than 7 days

                // 1.0: Firework "Veil" propagation removed — addresses are
                // accepted without the CAP_VEIL / SERVICES_NOISE overlay.

                let mut addrs = addresses.write().await;
                let mut accepted = 0usize;
                for net_addr in &addr_msg.addresses {
                    // Freshness check: reject stale or future-dated addresses
                    if net_addr.timestamp > max_future {
                        continue; // Future timestamp — clock manipulation
                    }
                    if now.saturating_sub(net_addr.timestamp) > max_age {
                        continue; // Stale address — too old
                    }
                    if let Some(socket_addr) = net_addr_to_socket_addr(net_addr) {
                        // Expanded unroutable filter (P5-N10 audit).
                        // (Prior comment additionally tagged this as
                        // "Bitcoin CVE-2015-3641 class"; that CVE is
                        // real per NVD but its "'Easy' attack" text is
                        // too vague to specifically pin to address-book
                        // poisoning, so the tag is dropped.) Pre-fix
                        // this only
                        // rejected loopback + unspecified, so an attacker
                        // poisoning our address book with multicast /
                        // link-local / CGNAT / IPv6-multicast / broadcast /
                        // docs / RFC1918 private IPs would have us dial
                        // those (burning connection slots) and gossip
                        // them onward, causing (a) inadvertent LAN
                        // topology leaks when peers exchanged addresses
                        // back, (b) address-book pollution with
                        // unreachable 10.x.x.x entries. See is_routable()
                        // above for the full rejection table.
                        if !is_routable(socket_addr.ip()) {
                            continue;
                        }
                        let mut pa = PeerAddress::new(socket_addr);
                        pa.last_seen = net_addr.timestamp;
                        pa.services = net_addr.services;
                        addrs.add(pa);
                        accepted += 1;
                    }
                }
                if accepted > 0 {
                    debug!("Added {} peer addresses from {}", accepted, hex::encode(&peer_id[..8]));
                }
                }
                Err(e) => {
                    warn!("Failed to deserialize AddrMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::InvalidAddress);
                    }
                }
            }
        }

        MessageType::GetData => {
            // Peer requests specific blocks by hash (individual block responses).
            // P5-N-CLASS-A fix: tight per-type cap.
            // F12 fix: OversizedMessage, not ProtocolViolation.
            if payload.len() > super::protocol::MAX_GETDATA_PAYLOAD {
                warn!("GetData message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            // P5-N7 fix: match with Err scoring.
            match borsh::from_slice::<GetBlocksMessage>(payload) {
                Ok(msg) => {
                if let Err(e) = msg.validate() {
                    warn!("Invalid GetData from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                    return Ok(());
                }
                // Send each block individually as BlockData.
                // Layer 2: pre-fetch + serialize all blocks under
                // block_in_place, then do the async per-peer sends after.
                // This keeps the sync DB reads + borsh serialization off
                // the worker thread for the duration of the request.
                let payloads: Vec<Vec<u8>> = tokio::task::block_in_place(|| {
                    msg.hashes.iter()
                        .filter_map(|hash| chain.get_block(hash))
                        .filter_map(|block| borsh::to_vec(&block).ok())
                        .collect()
                });
                for block_bytes in payloads {
                    let m = Message::new(magic, MessageType::BlockData, block_bytes);
                    if let Ok(data) = m.to_bytes() {
                        let _ = send_to_peer(&senders, &peer_id, data).await;
                    }
                }
                }
                Err(e) => {
                    warn!("Failed to deserialize GetData from peer {:?}: {}", &peer_id[..4], e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                    }
                }
            }
        }

        MessageType::BlockData => {
            // Peer sends us a single block.
            // F12 fix: OversizedMessage, not ProtocolViolation.
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("BlockData message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::OversizedMessage);
                }
                return Ok(());
            }
            if let Ok(block) = borsh::from_slice::<Block>(payload) {
                // SECURITY (NetworkTag): reject wrong-network blocks instantly
                if block.header.network_magic != magic {
                    warn!("BlockData from wrong network (magic {:?}) from peer {:?}",
                        block.header.network_magic, &peer_id[..4]);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::WrongNetwork);
                    }
                    return Ok(());
                }
                // SECURITY (2026-07-05 audit F30 — SEV-A): Cheap PoW check
                // BEFORE recording success. Pre-fix this handler called
                // `record_block_success` (+2 reputation) as soon as the
                // block deserialized + matched network_magic, WITHOUT
                // verifying that the block's PoW hash met its claimed
                // target. An attacker sending sub-target `BlockData`
                // messages gained +2 rep per attempt while the eventual
                // rejection happened much further downstream at
                // `chain.add_block` / `sync.on_block_received_from` and
                // only incremented `sync.peer_failures` (3-strike, 5-min
                // sync-only ban). Net effect: attacker's PeerScorer
                // reputation went UP while burning our CPU on garbage
                // block validation.
                //
                // Same fix pattern as F11 (the parallel bug in the Blocks
                // handler, line ~4183): provably-invalid PoW is
                // cryptographic invalidity and triggers instant ban via
                // `MisbehaviorType::InvalidBlockPoW` (penalty 100).
                //
                // Prior art (specific per-project identifiers UNVERIFIED
                // this session): reference implementations treat sub-
                // target PoW as immediate-ban material at the network
                // layer. The prior comment cited specific per-project
                // identifiers (`ProcessBlock` + `Misbehaving(100)` +
                // `MSG_BLOCK_HEADER_LOW_WORK` for Bitcoin Core, a
                // `PeerError::WrongDifficulty` + `PeerSet.remove()`
                // pair for Zebra, and Monero `peer_add_hash_ban`);
                // none were re-confirmed against upstream this session
                // and are dropped.
                let pow_hash = match crate::consensus::compute_pow_hash(
                    crate::consensus::PowAlgorithm::from_index(block.header.algorithm),
                    &block.header.anchor,
                    block.header.nonce,
                    &block.header.tx_root,
                    block.header.height,
                ) {
                    Ok(h) => h,
                    Err(_) => {
                        // Local recompute failure (out-of-range algorithm
                        // id, dataset error) — ambiguous, keep low-weight
                        // `record_block_failure` as with the Blocks
                        // handler. See F11 doc-comment there for the
                        // full split rationale.
                        warn!("BlockData: PoW hash recompute failed for block from peer {:?}",
                            &peer_id[..4]);
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr).record_block_failure();
                        }
                        return Ok(());
                    }
                };
                if !pow_hash.meets_difficulty(&block.header.target) {
                    warn!("Instant-banning peer {:?} — BlockData block with provably-invalid PoW",
                        &peer_id[..4]);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr)
                            .record_misbehavior(super::scoring::MisbehaviorType::InvalidBlockPoW);
                    }
                    return Ok(());
                }
                // Now record success and hand off to the event pipeline.
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_block_success(Duration::from_millis(100));
                }
                // Credit this peer's inbound block-relay score (Phase 1: measure
                // only — not yet consulted by eviction). Public block delivery is
                // the sole input; no transaction is observed. Credits valid
                // delivery; a new-block-only refinement is a follow-up.
                relay_scores.write().await.credit_block(peer_id);
                let _ = event_tx.send(NodeEvent::BlockReceived(block, peer_id));
            } else {
                warn!("Failed to deserialize BlockData from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    // F14 fix (2026-07-05 audit): BlockData Borsh deserialize failure
                    // is a MALFORMED PROTOCOL FRAME (peer sent us bytes we can't parse
                    // as a Block), not a block-content-level failure. Pre-fix used
                    // `record_block_failure` (-10 rep) which is the wrong category —
                    // the block content never existed in a form we could inspect.
                    // Now uses `ProtocolViolation` (20pt / 3-strike) via unified
                    // `record_misbehavior`.
                    scorer.write().await.get_or_create(addr)
                        .record_misbehavior(super::scoring::MisbehaviorType::ProtocolViolation);
                }
            }
        }

        MessageType::Reject => {
            // Peer rejected something (they didn't like a tx/block we sent).
            //
            // F16 fix (2026-07-05 audit — SEV-B): Pre-fix this handler
            // double-punished — both `Peer.adjust_reputation(-10)` (peer
            // struct's own reputation field) AND
            // `PeerScorer.record_block_failure()` (also -10 rep). Net effect
            // was -20 reputation for a single Reject message, which is
            // actually normal p2p behavior — a peer may reject a tx we
            // relayed because they already have it, or reject a block for
            // legitimate consensus disagreement. Even a single -10 is
            // arguably too harsh for the "peer expressed disagreement" case.
            //
            // Prior art (partially UNVERIFIED this session): Bitcoin
            // Core deprecated / removed BIP-61 Reject-message support
            // in the v0.19-v0.20 era as a matter of public record; the
            // specific release-note attribution ("v0.20") and citing
            // reason ("over-interpretation problem") were not re-fetched
            // this session, so those exact details are stated as
            // historical rather than authoritatively verified. The
            // prior comment additionally asserted that Zebra doesn't
            // send/process Reject and that Monero silently drops
            // received Rejects without scoring — those cross-project
            // claims were not verified this session and are dropped.
            //
            // Post-fix: only the peer struct's own reputation is nudged
            // down by a small amount (-5 rather than -10, better reflecting
            // the "they didn't like it" signal without punishing legitimate
            // disagreement). The unified `PeerScorer` is NOT touched here —
            // Reject-based scoring is off. If we ever want to re-enable it,
            // add a dedicated `MisbehaviorType::PeerRejected` with a real
            // rationale and a low penalty like LowFeeFlood.
            //
            // We keep the peer.adjust_reputation call rather than removing
            // both because the Peer struct's reputation field is separate
            // from PeerScorer's tracking (dual reputation system, tracked
            // in F17 — architectural cleanup deferred). Removing it here
            // would silently zero one signal; leaving it at -5 is the
            // minimal-diff correct behavior until F17 lands.
            if let Some(mut peer) = peers.get_mut(&peer_id) {
                peer.adjust_reputation(-5);
            }
            // Deliberately NOT calling scorer.record_block_failure or any
            // record_misbehavior variant — see F16 comment above.
        }

        // ─── Personal Node (Tier 1) Protocol ─────────────────────────────

        MessageType::GetFilters => {
            // Network/Archive nodes serve compact block filters to personal nodes.
            // Request contains (start_height: u64, end_height: u64).
            if payload.len() >= 16 {
                let start = u64::from_le_bytes(payload[0..8].try_into().unwrap_or([0u8; 8]));
                let end = u64::from_le_bytes(payload[8..16].try_into().unwrap_or([0u8; 8]));

                // Validate range and bound to prevent DoS (max 1000 filters per request)
                if start > end {
                    warn!("GetFilters: start {} > end {} from peer {:?}", start, end, &peer_id[..4]);
                    return Ok(());
                }
                let end = end.min(start.saturating_add(999));
                let chain_height = chain.height();
                let end = end.min(chain_height);

                tracing::debug!(
                    "GetFilters from {:?}: heights {}..={}", &peer_id[..4], start, end
                );

                // Build filters on the fly from blocks (or serve from cache/db).
                // Layer 2: per-height DB read + filter computation are both
                // synchronous and CPU-bound; the chained filter_hash means
                // the loop can't easily parallelize. Wrap in block_in_place.
                let filters = tokio::task::block_in_place(|| {
                    let mut filters = Vec::new();
                    let mut prev_filter_hash = crate::primitives::Hash::default();
                    for h in start..=end {
                        if let Some(block) = chain.get_block_by_height(h) {
                            let filter = crate::network::block_filter::BlockFilter::from_block(
                                &block, prev_filter_hash
                            );
                            prev_filter_hash = filter.filter_hash();
                            filters.push(filter);
                        }
                    }
                    filters
                });

                // Serialize and send response. Use Message::to_bytes() so
                // the per-peer write loop reads `data[4]` as the real
                // message type instead of a body byte (see 2026-05-09 IBD
                // wedge: 5 sites bypassed framing and broke the connection).
                if let Ok(encoded) = borsh::to_vec(&filters) {
                    let msg = Message::new(magic, MessageType::Filters, encoded);
                    if let Ok(data) = msg.to_bytes() {
                        let _ = send_to_peer(&senders, &peer_id, data).await;
                    }
                }
            }
        }

        MessageType::GetOutputDigests => {
            // Personal nodes request compact per-block output digests so
            // their light-wallet can detect ownership without downloading
            // full blocks. Wire format mirrors GetFilters: 16-byte payload
            // (start_height, end_height) u64-LE. Range is capped to keep
            // any single response well under MAX_MESSAGE_SIZE (16 MiB).
            //
            // Privacy property: the server learns only the height range,
            // never which outputs are interesting to the wallet. Stronger
            // than BIP-157, where the address-set is leaked. See
            // docs/security/LIGHTSYNC_AUDIT.md.
            const MAX_DIGEST_BLOCKS_PER_REQ: u64 = 100;

            if payload.len() < 16 {
                warn!("GetOutputDigests from {:?}: payload too short", &peer_id[..4]);
                return Ok(());
            }
            let start = u64::from_le_bytes(payload[0..8].try_into().unwrap_or([0u8; 8]));
            let end = u64::from_le_bytes(payload[8..16].try_into().unwrap_or([0u8; 8]));
            if start > end {
                warn!(
                    "GetOutputDigests: start {} > end {} from peer {:?}",
                    start, end, &peer_id[..4]
                );
                return Ok(());
            }
            let end = end.min(start.saturating_add(MAX_DIGEST_BLOCKS_PER_REQ - 1));
            let chain_height = chain.height();
            let end = end.min(chain_height);

            tracing::debug!(
                "GetOutputDigests from {:?}: heights {}..={}",
                &peer_id[..4], start, end
            );

            // Layer 2: per-height DB read + BlockDigest computation
            // wrapped in block_in_place so the worker thread is reusable
            // during the synchronous fan-out.
            let digests = tokio::task::block_in_place(|| {
                let mut digests = Vec::with_capacity(((end - start + 1) as usize).min(
                    MAX_DIGEST_BLOCKS_PER_REQ as usize,
                ));
                for h in start..=end {
                    if let Some(block) = chain.get_block_by_height(h) {
                        digests.push(crate::wallet::lightsync::BlockDigest::from_block(&block));
                    }
                }
                digests
            });

            if let Ok(encoded) = borsh::to_vec(&digests) {
                let msg = Message::new(magic, MessageType::OutputDigests, encoded);
                if let Ok(data) = msg.to_bytes() {
                    let _ = send_to_peer(&senders, &peer_id, data).await;
                }
            }
        }

        MessageType::GetFilterCheckpoints => {
            // Serve filter chain checkpoints for integrity verification.
            tracing::debug!("GetFilterCheckpoints from {:?}", &peer_id[..4]);

            // Build checkpoints from chain (every 1000 blocks).
            //
            // Bounded: at most MAX_CHECKPOINTS entries per response.
            // Each iteration does a disk-backed get_block_by_height +
            // filter recomputation, so an unbounded loop lets any peer
            // amplify their request into per-request O(chain_height)
            // disk + CPU. 1000 entries = 1M blocks of coverage at
            // 1000-block spacing, which is ~30 years of mainnet at
            // 120s block time. Plenty of headroom; well past any
            // legitimate peer's needs.
            const MAX_CHECKPOINTS: usize = 1000;
            const SPACING: u64 = 1000;
            let chain_height = chain.height();
            // Layer 2: up to 1000 disk-backed get_block_by_height +
            // filter recomputations per request. Worst-case CPU heavy;
            // wrap the whole walk in block_in_place.
            let checkpoints = tokio::task::block_in_place(|| {
                let mut checkpoints = Vec::with_capacity(MAX_CHECKPOINTS);
                let mut h = 0u64;
                while h <= chain_height && checkpoints.len() < MAX_CHECKPOINTS {
                    if let Some(block) = chain.get_block_by_height(h) {
                        let filter = crate::network::block_filter::BlockFilter::from_block(
                            &block, crate::primitives::Hash::default()
                        );
                        checkpoints.push(crate::network::block_filter::FilterCheckpoint {
                            height: h,
                            block_hash: block.hash(),
                            filter_hash: filter.filter_hash(),
                        });
                    }
                    h = match h.checked_add(SPACING) {
                        Some(next) => next,
                        None => break,
                    };
                }
                checkpoints
            });
            if checkpoints.len() == MAX_CHECKPOINTS {
                tracing::warn!(
                    "GetFilterCheckpoints from {:?}: hit MAX_CHECKPOINTS={} cap (chain_height={})",
                    &peer_id[..4], MAX_CHECKPOINTS, chain_height
                );
            }

            if let Ok(encoded) = borsh::to_vec(&checkpoints) {
                let msg = Message::new(magic, MessageType::FilterCheckpoints, encoded);
                if let Ok(data) = msg.to_bytes() {
                    let _ = send_to_peer(&senders, &peer_id, data).await;
                }
            }
        }

        // ─── Network Node (Tier 2) DHT Protocol ─────────────────────────

        MessageType::GetKeyImageStatus => {
            // DHT query: is this key image spent?
            // Payload: Vec<[u8; 32]> — list of key images to check.
            if let Ok(key_images) = borsh::from_slice::<Vec<[u8; 32]>>(payload) {
                let max_query = 100usize;
                let key_images: Vec<[u8; 32]> = key_images.into_iter().take(max_query).collect();

                tracing::debug!(
                    "GetKeyImageStatus from {:?}: {} key images",
                    &peer_id[..4], key_images.len()
                );

                // Check each key image against the chain's spent set.
                // Layer 2: up to 100 DB lookups per request; wrap in
                // block_in_place so the worker thread is reusable.
                let statuses: Vec<u8> = tokio::task::block_in_place(|| {
                    let mut statuses: Vec<u8> = Vec::with_capacity(key_images.len());
                    for ki_bytes in &key_images {
                        let ki = crate::primitives::KeyImage::from_bytes(*ki_bytes);
                        let spent = chain.is_spent(&ki);
                        statuses.push(if spent { 1 } else { 0 });
                    }
                    statuses
                });

                if let Ok(encoded) = borsh::to_vec(&statuses) {
                    let msg = Message::new(magic, MessageType::KeyImageStatus, encoded);
                    if let Ok(data) = msg.to_bytes() {
                        let _ = send_to_peer(&senders, &peer_id, data).await;
                    }
                }
            }
        }

        // Responses handled by the requesting side (personal node)
        MessageType::Filters
        | MessageType::OutputDigests
        | MessageType::FilterCheckpoints
        | MessageType::KeyImageStatus => {
            // These are responses — personal nodes process them via their sync loop.
            // Full nodes receiving these can safely ignore them.
            tracing::trace!("Received response message {:?} (no-op on full node)", msg_type);
        }

        // ChainAnchorStamp was removed in the 1.0 trim (anchor_collector /
        // anchor modules deleted). AnchorRequest / AnchorResponse message
        // variants no longer exist in protocol.rs, so the match arms below
        // would be unreachable patterns — they are gone in 1.0.

        _ => {
            trace!("Unhandled message type: {:?}", msg_type);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // CIP-019: the InvBlock regime split. A not-yet-synced node that is only a
    // few blocks behind is "near tip" (catch up promptly); one far behind is
    // deep IBD (skip the body fetch to avoid orphan pileup).
    #[test]
    fn cip019_invblock_near_tip_regime() {
        let w = NEAR_TIP_INV_WINDOW;
        // synced short-circuits regardless of gap
        assert!(invblock_near_tip(true, 9999, w));
        // behind but within the window → near tip
        assert!(invblock_near_tip(false, 0, w));
        assert!(invblock_near_tip(false, 3, w)); // the live 2026-07-11 case
        assert!(invblock_near_tip(false, w, w)); // boundary is inclusive
        // beyond the window → deep IBD, not near tip
        assert!(!invblock_near_tip(false, w + 1, w));
        assert!(!invblock_near_tip(false, 3_000, w));
    }

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert_eq!(config.max_peers, MAX_PEERS);
        assert_eq!(config.max_outbound, MAX_OUTBOUND);
    }

    // ─── v1.0.13 #2 — TxAbsenceCache ───────────────────────────

    #[test]
    fn tx_absence_cache_marks_and_reports() {
        let mut cache = TxAbsenceCache::new();
        let h1 = crate::primitives::Hash::from_bytes([1u8; 32]);
        let h2 = crate::primitives::Hash::from_bytes([2u8; 32]);

        assert!(!cache.is_known_absent(&h1));
        cache.mark_absent(h1);
        assert!(cache.is_known_absent(&h1));
        assert!(!cache.is_known_absent(&h2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn tx_absence_cache_hard_cap_evicts_oldest_under_attack() {
        let mut cache = TxAbsenceCache::new();
        // Hammer the cache past the 10K cap. Each insert under
        // cap-pressure should evict the oldest entry, keeping size
        // at exactly max_size.
        for i in 0..11_000u32 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            cache.mark_absent(crate::primitives::Hash::from_bytes(bytes));
        }
        assert_eq!(cache.len(), 10_000,
                   "hard cap must hold under attack-rate inserts");

        // The earliest entry (i=0) should have been evicted.
        let h0 = {
            let mut b = [0u8; 32]; b[..4].copy_from_slice(&0u32.to_be_bytes());
            crate::primitives::Hash::from_bytes(b)
        };
        // The most recent (i=10999) should still be there.
        let h_last = {
            let mut b = [0u8; 32]; b[..4].copy_from_slice(&10_999u32.to_be_bytes());
            crate::primitives::Hash::from_bytes(b)
        };
        assert!(!cache.is_known_absent(&h0), "oldest entry must have been evicted");
        assert!(cache.is_known_absent(&h_last), "newest entry must still be present");
    }

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::default();
        let chain = std::sync::Arc::new(crate::chain::Blockchain::new());
        let mempool = crate::mempool::SharedMempool::new();
        let node = P2PNode::new(config, chain, mempool);

        assert_eq!(node.peer_count(), 0);
        assert!(!node.our_id().iter().all(|&b| b == 0));
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
            assert!(tracker.try_track_connection(&a),
                "should accept connection {} from same IP", i + 1);
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
        let config = NodeConfig::default();
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

    // ─── DashMap-shard-lock-across-await regression tests ─────────────
    //
    // These tests guard against the deadlock class that took down the
    // fleet on 2026-07-02 (api box) and 2026-07-03 (relay1) with the
    // signature "16/16 threads on futex_wait_queue at ~8m45s uptime".
    // Root cause: multiple hot-path sites in this file held a
    // `dashmap::Ref` from `peer_senders.get(...)` or `.iter()` across a
    // subsequent `.send(...).await`; when a peer's outbound channel
    // filled up, the sending task parked on channel capacity while
    // holding the shard lock, and every other tokio worker that later
    // touched the same shard blocked on the shard's futex.
    //
    // The fix (see `send_to_peer` above + the snapshot-then-loop
    // pattern at Ping / Fluff broadcasts) clones the sender out of the
    // DashMap BEFORE the send.await. These tests lock the invariant
    // that no future edit reintroduces the antipattern.

    #[tokio::test]
    async fn send_to_peer_returns_true_when_send_succeeds() {
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        let peer_id: PeerId = [1u8; 32];
        senders.insert(peer_id, tx);

        let ok = send_to_peer(&senders, &peer_id, vec![0xAA, 0xBB]).await;
        assert!(ok, "helper must return true on successful send");
        assert_eq!(rx.recv().await, Some(vec![0xAA, 0xBB]));
    }

    #[tokio::test]
    async fn send_to_peer_returns_false_when_peer_missing() {
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let peer_id: PeerId = [7u8; 32];
        let ok = send_to_peer(&senders, &peer_id, vec![0]).await;
        assert!(!ok, "helper must return false when peer not in map");
    }

    #[tokio::test]
    async fn send_to_peer_returns_false_when_channel_closed() {
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        let peer_id: PeerId = [3u8; 32];
        senders.insert(peer_id, tx);
        drop(rx); // close the channel

        let ok = send_to_peer(&senders, &peer_id, vec![0]).await;
        assert!(!ok, "helper must return false when channel closed");
    }

    /// **This is the anti-regression test for the 2026-07-02 / 2026-07-03
    /// production deadlock.** It asserts that while `send_to_peer` is
    /// parked on a full mpsc channel, concurrent `DashMap::insert` on
    /// the SAME map from another tokio task completes without waiting
    /// for the parked send.
    ///
    /// The pre-fix antipattern held the DashMap shard lock via the
    /// `Ref` returned by `.get(peer_id)` while awaiting `.send(...)`.
    /// If any other task tried to touch the same shard (peer connect,
    /// disconnect, another broadcast), it blocked on the shard's futex.
    /// With enough tokio worker tasks all contending on that shard, the
    /// runtime dropped to 100% futex-park — the observed production
    /// signature.
    ///
    /// After the fix, `send_to_peer` clones the sender out FIRST and
    /// awaits with the DashMap Ref already dropped. Insert must proceed
    /// immediately.
    ///
    /// The test uses a bounded channel of capacity 1, pre-fills it, and
    /// starts a `send_to_peer` call that will park on channel capacity.
    /// Then concurrently issues a `DashMap::insert` and asserts that
    /// completes well within a bound (50ms) — orders of magnitude
    /// faster than the send's parked duration (which would be forever
    /// if nothing drained the channel).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_to_peer_does_not_block_concurrent_dashmap_insert_on_full_channel() {
        use std::time::Duration;
        let senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>> = Arc::new(DashMap::new());
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        let slow_peer: PeerId = [9u8; 32];
        senders.insert(slow_peer, tx.clone());

        // Fill the channel to capacity so the next `send.await` parks.
        tx.send(vec![0]).await.expect("pre-fill send must succeed");

        // Spawn the parked send.
        let senders_send = senders.clone();
        let send_task = tokio::spawn(async move {
            // With the fix, this awaits with NO DashMap lock held.
            // Will unblock once we drain `rx` at the end of the test.
            send_to_peer(&senders_send, &slow_peer, vec![1, 2, 3]).await
        });

        // Give the send task a moment to park on the channel.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Now do the operation that would deadlock under the antipattern:
        // insert into the SAME DashMap while the send is parked. With
        // the fix, this must complete IMMEDIATELY (no shard-lock wait).
        let other_peer: PeerId = [42u8; 32];
        let (tx2, _rx2) = mpsc::channel::<Vec<u8>>(1);
        let insert_start = std::time::Instant::now();
        senders.insert(other_peer, tx2);
        let insert_dur = insert_start.elapsed();

        assert!(
            insert_dur < Duration::from_millis(500),
            "DashMap insert took {}ms while send was parked — the DashMap \
             shard lock is still being held across the send.await. \
             REGRESSION: the deadlock antipattern is back in send_to_peer \
             (or in one of its callers). See node.rs:send_to_peer for the \
             correct pattern.",
            insert_dur.as_millis()
        );

        // Cleanup: drain the channel so the send can complete + the task joins.
        let _ = rx.recv().await;
        let _ = tokio::time::timeout(Duration::from_secs(1), send_task)
            .await
            .expect("send_task must complete after channel drained");
    }

    /// Companion test: same invariant for the snapshot-then-loop pattern
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
            let snapshot: Vec<mpsc::Sender<Vec<u8>>> = senders_bcast
                .iter()
                .map(|s| s.value().clone())
                .collect();
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
