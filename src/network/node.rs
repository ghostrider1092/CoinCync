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
    Message, MessageType, VersionMessage,
    GetHeadersMessage, GetBlocksMessage, InvMessage,
    MAX_HEADERS_RESPONSE, MAX_BLOCK_HASHES,
};
use super::dandelion::{DandelionRouter, DandelionStats, StemAction, DANDELION_MONITOR_INTERVAL_SECS};
use super::sync::{ChainSync, SyncState, SyncStats, build_locator};
use super::bootstrap::{Bootstrapper, BootstrapConfig, AddressManager, PeerAddress};
use super::scoring::{PeerScorer, ScorerStats};
use super::traffic_shaping::TrafficShaper;
use super::connection_tracker::ConnectionTracker;

/// Maximum number of peers (reduced to reserve outbound slots)
pub const MAX_PEERS: usize = 72;
/// Maximum outbound connections (8 slots reserved for outbound diversity)
pub const MAX_OUTBOUND: usize = 16;
/// Maximum inbound connections (reduced from 117 to prevent resource exhaustion)
pub const MAX_INBOUND: usize = 64;
/// Maximum connections per IP (prevent Sybil attacks)
/// SECURITY: Reduced from 3 to 1 to prevent Sybil attacks where a single
/// entity controls multiple connections. Bitcoin Core uses 1 connection per IP.
/// Maximum connections per IP. Set to 8 to allow multi-node local testing.
/// In production with real IPs, 2-3 is sufficient; 1 is too restrictive for
/// localhost deployments where all nodes share 127.0.0.1.
/// Maximum connections from a single IP address.
/// Bitcoin Core uses 1. We use 2 to allow one inbound + one outbound.
/// Higher values enable trivial Sybil attacks.
pub const MAX_CONNECTIONS_PER_IP: usize = 2;
/// Connection timeout
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Ping interval
pub const PING_INTERVAL: Duration = Duration::from_secs(120);
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
    TransactionReceived(Transaction),
    /// Sync state changed
    SyncStateChanged(SyncState),
    /// Network error
    Error(String),
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
        }
    }
}

/// Message from peer connection
struct PeerMessage {
    peer_id: PeerId,
    data: Vec<u8>,
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
        // Load or generate Noise identity (persistent X25519 keypair)
        let identity = match super::noise::NodeIdentity::load_or_generate_fresh(&config.data_dir) {
            Ok(id) => {
                tracing::info!(
                    "Noise identity loaded: {}",
                    hex::encode(&id.peer_id()[..8])
                );
                Arc::new(id)
            }
            Err(e) => {
                tracing::warn!("Failed to load Noise identity: {}, using ephemeral", e);
                // Generate ephemeral identity in-memory
                let id = super::noise::NodeIdentity::generate();
                Arc::new(id)
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
            addresses: Arc::new(RwLock::new(AddressManager::new(1000))),
            event_tx,
            cmd_tx,
            running: Arc::new(RwLock::new(false)),
            conn_tracker: Arc::new(ConnectionTracker::new(MEMORY_BUDGET_BYTES)),
            peer_scorer: Arc::new(RwLock::new(PeerScorer::new())),
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
        let dht_guard = dht.lock();

        if key_images.is_empty() { return Some(()); }

        // Group key images by stripe
        let mut by_stripe: std::collections::HashMap<u32, Vec<[u8; 32]>> =
            std::collections::HashMap::new();
        for ki in key_images {
            let stripe = super::dht::key_image_stripe(ki, dht_guard.stripe_count);
            by_stripe.entry(stripe).or_default().push(*ki.as_bytes());
        }

        // Send GetKeyImageStatus to one peer per stripe
        for (stripe, ki_bytes) in &by_stripe {
            let stripe_idx = *stripe as usize;
            if stripe_idx >= dht_guard.peers_by_stripe.len() { continue; }
            let stripe_peers = &dht_guard.peers_by_stripe[stripe_idx];
            if stripe_peers.is_empty() {
                tracing::debug!("DHT: no peers for stripe {}, skipping {} key images", stripe, ki_bytes.len());
                continue;
            }

            // Pick first available peer in this stripe
            let target = stripe_peers[0];
            if let Some(sender) = self.peer_senders.get(&target) {
                if let Ok(encoded) = borsh::to_vec(ki_bytes) {
                    // Frame as a real Message — the per-peer write loop in
                    // peer_handler reads `data[4]` as the message type and
                    // expects the full magic+type+length+checksum header. A
                    // raw `vec![type, ...payload]` makes data[4] a body byte,
                    // which the framer then rejects with "unknown type: N",
                    // breaking the connection mid-IBD. (See: 2026-05-09 IBD
                    // wedge investigation.)
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

        drop(dht_guard);
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
        let mut sync = self.sync.write().await;
        sync.set_local_tip(height, tip);
        let stats = sync.stats();
        drop(sync);
        self.chain.set_sync_info(
            stats.local_height >= stats.best_known_height,
            stats.best_known_height,
        );
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

    /// IBD orphan recovery: when a block came back as Orphan, ask the
    /// sync manager to fetch the parent so the gap fills, instead of
    /// re-requesting the orphan itself in a loop. See sync::mark_block_orphan
    /// for the full rationale.
    pub async fn notify_block_orphan(&self, orphan_hash: &Hash, parent_hash: &Hash) {
        self.sync.write().await.mark_block_orphan(orphan_hash, parent_hash);
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

        // Setup UPnP if enabled
        if self.config.upnp {
            let port = self.config.listen_addr.port();
            tokio::spawn(async move {
                if let Err(e) = super::bootstrap::setup_upnp(port, port).await {
                    warn!("UPnP setup failed: {}", e);
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
                            debug!("Max inbound connections reached, rejecting {}", addr);
                            acceptor_tracker.untrack_connection(&addr);
                            continue;
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
                                conn_identity, conn_encryption,
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

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
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
                    if snap_sum != outbound_count {
                        warn!(
                            "eclipse-defense: drift detected — subnet_sum={} but outbound_count={} :: {}",
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
                                    conn_identity, conn_encryption,
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

        tokio::spawn(async move {
            // Phase D (audit fix): per-peer message rate tracking.
            // PeerMessageRateTracker was built (scoring.rs) but never wired.
            // This HashMap lives for the lifetime of the processor task and
            // tracks each peer's per-message-type rate. When a peer exceeds
            // the configured limit, they get a MessageFlood misbehavior score.
            let mut rate_trackers: std::collections::HashMap<
                super::peer::PeerId,
                super::scoring::PeerMessageRateTracker,
            > = std::collections::HashMap::new();

            while *processor_running.read().await {
                match msg_rx.recv().await {
                    Some(msg) => {
                        // Rate-limit check (before expensive processing)
                        if !msg.data.is_empty() {
                            let msg_type_id = msg.data[0];
                            let tracker = rate_trackers
                                .entry(msg.peer_id)
                                .or_insert_with(super::scoring::PeerMessageRateTracker::new);
                            if tracker.record(msg_type_id) {
                                warn!(
                                    "Peer {:?} exceeded message rate limit for type 0x{:02x}, penalizing",
                                    &msg.peer_id[..4], msg_type_id,
                                );
                                if let Some(peer_addr) = processor_peers.get(&msg.peer_id).map(|p| p.addr) {
                                    let mut scorer = processor_scorer.write().await;
                                    scorer.get_or_create(peer_addr)
                                        .record_misbehavior(super::scoring::MisbehaviorType::MessageFlood);
                                }
                                continue; // Drop the message
                            }
                        }

                        if let Err(e) = process_message(
                            msg.peer_id,
                            &msg.data,
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

                    // Tier 2: Only after 120s of no progress, try rotating
                    if stall_count >= 24 { // 24 * 5s tick = 120s
                        warn!("Sync stalled for 2+ minutes, rotating peers");
                        let now = chrono::Utc::now().timestamp() as u64;
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
                    }
                } else if !sync_sync.read().await.is_synced() {
                    // Progress detected — reset stall counter
                    let current_height = sync_chain.height();
                    if current_height > last_progress_height {
                        stall_count = 0;
                        last_progress_height = current_height;
                    }
                }

                match state {
                    SyncState::Idle | SyncState::Headers | SyncState::ConfirmingSynced => {
                        let now = chrono::Utc::now().timestamp() as u64;

                        // Check if headers request timed out (no response in 15s)
                        if sync_sync.read().await.headers_timed_out(now) {
                            warn!("Headers request timed out, retrying with different peer");
                            sync_sync.write().await.reset_headers_timeout();
                            // Don't continue — fall through to send new request
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
                                        if let Some(sender) = sync_senders.get(&peer_id) {
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
                        // Bitcoin Core approach: simple, deterministic block download.
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

                        // Step 2: Get block hashes to download from sync engine
                        // Monero uses spans of 20-100. We use 500 (protocol max)
                        // for aggressive IBD — split across all live peers.
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
                            // Step 3: MONERO-STYLE MULTI-PEER SPAN DOWNLOAD
                            // Split block hashes across ALL connected peers simultaneously.
                            // Each peer gets a different span (chunk) of hashes.
                            // This is how Monero achieves 720+ blocks/sec during IBD.
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
                                            if let Some(sender) = sync_senders.get(pid) {
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
        let maint_scorer = self.peer_scorer.clone();
        // Take the broadcast queue receiver for the maintenance task
        let mut broadcast_rx = self.tx_broadcast_rx.lock()
            .take()
            .expect("broadcast receiver already taken");

        tokio::spawn(async move {
            let mut ping_interval = interval(PING_INTERVAL);
            let mut cleanup_interval = interval(Duration::from_secs(60));
            // Dandelion++ monitor runs every DANDELION_MONITOR_INTERVAL_SECS
            let mut dandelion_interval = interval(Duration::from_secs(DANDELION_MONITOR_INTERVAL_SECS));

            while *maint_running.read().await {
                tokio::select! {
                    _ = ping_interval.tick() => {
                        // Send pings to all peers
                        let ping = Message::ping(magic);
                        if let Ok(data) = ping.to_bytes() {
                            for sender in maint_senders.iter() {
                                let _ = sender.send(data.clone()).await;
                            }
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
                            if let Some(sender) = maint_senders.get(target_peer) {
                                if let Ok(msg) = Message::txs(magic, vec![tx.clone()]) {
                                    if let Ok(data) = msg.to_bytes() {
                                        let _ = sender.send(data).await;
                                    }
                                }
                            }
                            crate::metrics::dandelion::STEM_RELAYS_TOTAL.inc();
                        }

                        // Execute fluff: broadcast InvTx to ALL peers + emit event
                        for (tx_hash, tx) in &actions.fluff {
                            if let Ok(msg) = Message::inv_tx(magic, *tx_hash) {
                                if let Ok(data) = msg.to_bytes() {
                                    for sender in maint_senders.iter() {
                                        let _ = sender.send(data.clone()).await;
                                    }
                                }
                            }
                            // Emit event so the tx enters the mempool
                            let _ = maint_event_tx.send(NodeEvent::TransactionReceived(tx.clone()));
                            crate::metrics::dandelion::FLUFF_BROADCASTS_TOTAL.inc();
                        }

                        // Update stempool size gauge
                        let stempool_size = maint_dandelion.read().await.stempool_size();
                        crate::metrics::dandelion::STEMPOOL_SIZE.set(stempool_size as i64);
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
                    tracing::trace!(
                        peer_id = ?peer_id,
                        "broadcast_raw: peer channel closed (peer disconnected)"
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

        Ok(())
    }

    /// Send message to specific peer
    pub async fn send_to(&self, peer_id: &PeerId, data: Vec<u8>) -> Result<()> {
        if let Some(sender) = self.peer_senders.get(peer_id) {
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
        // Get address before removing for connection tracking cleanup
        if let Some(peer) = self.peers.get(peer_id) {
            self.conn_tracker.untrack_connection(&peer.addr);
        }
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.reputation = -100;
        }
        // Remove from Dandelion++ outbound peers
        self.dandelion.write().await.remove_outbound_peer(peer_id);
        self.peers.remove(peer_id);
        self.peer_senders.remove(peer_id);
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
                    warn!("Noise bridge reader: {}", e);
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

    let mut framer = MessageFramer::new(app_reader, app_writer, magic);

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
            // SECURITY (H-2): Use read_message_timeout() to prevent Slowloris DoS.
            // A peer sending partial data would block the untimed read_message() forever,
            // pinning the connection slot. The 30-second timeout ensures cleanup.
            result = framer.read_message_timeout() => {
                match result {
                    Ok((msg_type, payload)) => {
                        // DoS protection is handled by:
                        // 1. MAX_MESSAGE_SIZE check in framing.rs (16MB cap)
                        // 2. Per-peer misbehavior scoring in process_message()
                        // 3. Connection limits (MAX_CONNECTIONS_PER_IP)
                        // Never drop solicited data — that breaks IBD.
                        // (Bitcoin/Monero/Ethereum all process every received message.)

                        let mut data = Vec::with_capacity(1 + payload.len());
                        data.push(msg_type);
                        data.extend_from_slice(&payload);

                        if msg_tx.send(PeerMessage { peer_id, data }).await.is_err() {
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

    // BUG 2 FIX: Only remove peer/sender entries if they still belong to THIS
    // connection. If a reconnection happened, the new connection already
    // overwrote our entries — removing them would break the new connection.
    // We check if the sender channel is closed (our tx was dropped when
    // the new connection overwrote it in the senders map).
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

/// Process received message
/// Data format: [msg_type (1 byte), payload...]
/// The header has already been validated and stripped by the message framer.
async fn process_message(
    peer_id: PeerId,
    data: &[u8],
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
) -> Result<()> {
    // Traffic shaping: discard dummy padding packets (4th Amendment defense).
    // Padding packets are injected by the constant-rate padding loop and
    // should never reach message processing.
    if TrafficShaper::is_padding_packet(data) {
        trace!("Discarded padding packet from peer {:?}", &peer_id[..4]);
        return Ok(());
    }

    // Data format is now [msg_type, ...payload] after framer processing
    if data.is_empty() {
        return Err(Error::InvalidMessage("empty message".into()));
    }

    let msg_type = MessageType::try_from(data[0])?;
    let payload = if data.len() > 1 { &data[1..] } else { &[] };

    trace!("Received {:?} from peer {:?}", msg_type, &peer_id[..4]);


    // Update peer activity
    if let Some(mut peer) = peers.get_mut(&peer_id) {
        peer.touch();
        peer.bytes_recv += data.len() as u64;
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
                    peers.remove(&peer_id);
                    senders.remove(&peer_id);
                    let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
                    return Ok(());
                }
            };
            {
                // SECURITY (NET-001): Detect self-connection via nonce
                if version.nonce == our_nonce {
                    warn!("Self-connection detected (nonce match), disconnecting peer {:?}", &peer_id[..4]);
                    // Permanently ban this address in the address manager so the
                    // outbound connector never retries it. Without this, the
                    // exponential backoff delays connections to ALL seeds.
                    if let Some(peer_info) = peers.get(&peer_id) {
                        let self_addr = peer_info.addr;
                        drop(peer_info);
                        addresses.write().await.mark_self_address(self_addr);
                        tracing::info!("Permanently skipping self-address {}", self_addr);
                    }
                    peers.remove(&peer_id);
                    senders.remove(&peer_id);
                    let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
                    return Ok(());
                }

                // SECURITY: Validate version message (protocol version, user agent length)
                if let Err(e) = version.validate() {
                    warn!("Rejecting peer {:?}: invalid version: {}", &peer_id[..4], e);
                    // Disconnect the peer
                    peers.remove(&peer_id);
                    senders.remove(&peer_id);
                    let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
                    return Ok(());
                }

                // Respond with verack (only after validation passes)
                if let Some(sender) = senders.get(&peer_id) {
                    let verack = Message::verack(magic);
                    if let Err(e) = sender.send(verack.to_bytes()?).await {
                        warn!("Failed to send Verack to peer {:?}: {}", &peer_id[..4], e);
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

        // Firework Flare capability message was removed in the 1.0 trim.
        // The Flare variant no longer exists in protocol.rs and wouldn't
        // be matched here.

        MessageType::Verack => {
            let is_outbound = peers.get(&peer_id).map(|p| p.outbound).unwrap_or(false);

            if let Some(mut peer) = peers.get_mut(&peer_id) {
                peer.state = PeerState::Connected;
            }

            // Register outbound peers for Dandelion++ relay selection
            if is_outbound {
                dandelion.write().await.add_outbound_peer(peer_id);
                debug!("Added outbound peer {:?} to Dandelion++ pool", &peer_id[..4]);
            }

            // Send GetAddr to discover more peers after handshake
            if let Some(sender) = senders.get(&peer_id) {
                let getaddr = Message::new(magic, MessageType::GetAddr, vec![]);
                if let Ok(data) = getaddr.to_bytes() {
                    let _ = sender.send(data).await;
                }
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
                            if let Some(sender) = senders.get(&peer_id) {
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
            // Parse nonce and respond with pong
            if payload.len() >= 8 {
                let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                if let Some(sender) = senders.get(&peer_id) {
                    let pong = Message::pong(magic, nonce);
                    let _ = sender.send(pong.to_bytes()?).await;
                }
            }
        }

        MessageType::Pong => {
            // Update latency (could track round trip time)
        }

        MessageType::GetHeaders => {
            // Peer is requesting headers - serve from our chain
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("GetHeaders message too large from peer {:?}", &peer_id[..4]);
                return Ok(());
            }
            if let Ok(msg) = borsh::from_slice::<GetHeadersMessage>(payload) {
                if let Err(e) = msg.validate() {
                    warn!("Invalid GetHeaders from peer {:?}: {}", &peer_id[..4], e);
                    return Ok(());
                }

                // Walk locator to find the fork point
                let mut start_height = 0u64;
                for hash in &msg.locator {
                    if let Some(block) = chain.get_block(hash) {
                        start_height = block.height() + 1;
                        break;
                    }
                }

                // Collect headers from start_height up to MAX_HEADERS_RESPONSE
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

                // Always respond (even with empty headers) so the requester knows.
                // Echo the nonce for request/response correlation.
                {
                    if let Some(sender) = senders.get(&peer_id) {
                        if let Ok(resp) = Message::headers_with_nonce(magic, headers, msg.nonce) {
                            let _ = sender.send(resp.to_bytes()?).await;
                        }
                    }
                }
            }
        }

        MessageType::GetBlocks => {
            // Peer is requesting full blocks by hash
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("GetBlocks message too large from peer {:?}", &peer_id[..4]);
                return Ok(());
            }
            match borsh::from_slice::<GetBlocksMessage>(payload) {
                Ok(msg) => {
                    if let Err(e) = msg.validate() {
                        warn!("Invalid GetBlocks from peer {:?}: {}", &peer_id[..4], e);
                        return Ok(());
                    }

                    let requested = msg.hashes.len();
                    let mut blocks = Vec::new();
                    for hash in &msg.hashes {
                        if let Some(block) = chain.get_block(hash) {
                            blocks.push(block);
                            if blocks.len() >= MAX_BLOCK_HASHES {
                                break;
                            }
                        }
                    }

                    debug!(
                        "GetBlocks from {:?}: {} requested, {} found",
                        &peer_id[..4], requested, blocks.len()
                    );

                    // Always respond (even with empty blocks) so the requester
                    // can free download slots instead of waiting for timeout.
                    if let Some(sender) = senders.get(&peer_id) {
                        if let Ok(resp) = Message::blocks(magic, blocks) {
                            let _ = sender.send(resp.to_bytes()?).await;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize GetBlocks from peer {:?}: {}", &peer_id[..4], e);
                }
            }
        }

        MessageType::InvTx => {
            // Transaction inventory - request txs we don't have
            if let Ok(inv_msg) = borsh::from_slice::<InvMessage>(payload) {
                if let Err(e) = inv_msg.validate() {
                    warn!("Invalid InvTx from peer {:?}: {}", &peer_id[..4], e);
                    return Ok(());
                }
                let mut needed = Vec::new();
                for inv in &inv_msg.inventory {
                    if !mempool.contains(&inv.hash) {
                        needed.push(inv.hash);
                    }
                }
                // Request missing transactions via GetTxs
                if !needed.is_empty() {
                    if let Some(sender) = senders.get(&peer_id) {
                        // Reuse GetBlocksMessage format for tx hashes
                        let get_msg = GetBlocksMessage { hashes: needed };
                        if let Ok(payload_bytes) = borsh::to_vec(&get_msg) {
                            let msg = Message::new(magic, MessageType::GetTxs, payload_bytes);
                            let _ = sender.send(msg.to_bytes()?).await;
                        }
                    }
                }
            }
        }

        MessageType::InvBlock => {
            // Block inventory - check if we're missing blocks
            if let Ok(inv_msg) = borsh::from_slice::<InvMessage>(payload) {
                if let Err(e) = inv_msg.validate() {
                    warn!("Invalid InvBlock from peer {:?}: {}", &peer_id[..4], e);
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
                    let chain_ref = &chain;
                    let locator = build_locator(our_height, |h| chain_ref.get_block_hash(h));
                    if !locator.is_empty() {
                        let nonce = sync.write().await.allocate_header_nonce();
                        if let Ok(msg) = Message::get_headers_with_nonce(magic, locator, Hash::zero(), nonce) {
                            if let Ok(data) = msg.to_bytes() {
                                if let Some(sender) = senders.get(&peer_id) {
                                    let _ = sender.send(data).await;
                                    debug!(
                                        "InvBlock during IBD: sent GetHeaders nonce={} to peer {:?} to refresh tip (our_h={})",
                                        nonce, &peer_id[..4], our_height
                                    );
                                }
                            }
                        }
                    }
                    return Ok(());
                }

                // Post-IBD: peer has blocks we don't. Update their height
                // estimate to our_h+1 (lower bound — they're at least one
                // block ahead). Body fetch follows below.
                let our_h = chain.height();
                let estimated_peer_height = our_h + 1;
                sync.write().await.update_peer_height_for(peer_id, estimated_peer_height);

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
                                if let Some(sender) = senders.get(&peer_id) {
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
        }

        MessageType::GetTxs => {
            // Peer is requesting transactions by hash
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("GetTxs message too large from peer {:?}", &peer_id[..4]);
                return Ok(());
            }
            if let Ok(msg) = borsh::from_slice::<GetBlocksMessage>(payload) {
                if let Err(e) = msg.validate() {
                    warn!("Invalid GetTxs from peer {:?}: {}", &peer_id[..4], e);
                    return Ok(());
                }
                let mut txs = Vec::new();
                for hash in &msg.hashes {
                    if let Some(tx) = mempool.get(hash) {
                        txs.push(tx);
                    }
                }
                if !txs.is_empty() {
                    if let Some(sender) = senders.get(&peer_id) {
                        if let Ok(resp) = Message::txs(magic, txs) {
                            let _ = sender.send(resp.to_bytes()?).await;
                        }
                    }
                }
            }
        }

        MessageType::Txs => {
            // SECURITY: Limit payload size before deserialization to prevent CPU exhaustion
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("Txs message too large from peer {}", hex::encode(&peer_id[..8]));
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_protocol_violation();
                }
                return Ok(());
            }
            // Parse transactions
            if let Ok(txs_msg) = borsh::from_slice::<super::protocol::TxsMessage>(payload) {
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
                        warn!("Rejecting invalid tx from peer {}: {}", hex::encode(&peer_id[..8]), e);
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr).record_invalid_tx();
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
                                    for sender in senders.iter() {
                                        let _ = sender.send(data.clone()).await;
                                    }
                                }
                            }
                            let _ = event_tx.send(NodeEvent::TransactionReceived(fluff_tx));
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
        }

        MessageType::Blocks => {
            // SECURITY: Limit payload size before deserialization to prevent CPU exhaustion
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("Blocks message too large from peer {}", hex::encode(&peer_id[..8]));
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_protocol_violation();
                }
                return Ok(());
            }
            // Parse blocks
            if let Ok(blocks_msg) = borsh::from_slice::<super::protocol::BlocksMessage>(payload) {
                // SECURITY: Limit number of blocks per message
                if blocks_msg.blocks.len() > super::protocol::MAX_BLOCK_HASHES {
                    warn!("Too many blocks in message from peer {}", hex::encode(&peer_id[..8]));
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr).record_protocol_violation();
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
                        warn!("Rejecting block with invalid PoW from peer {}",
                            hex::encode(&peer_id[..8]));
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer.write().await.get_or_create(addr).record_block_failure();
                        }
                        continue;
                    }
                    let _ = event_tx.send(NodeEvent::BlockReceived(block, peer_id));
                }
            }
        }

        MessageType::Headers => {
            // SECURITY: Limit payload size before deserialization
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("Headers message too large from peer {}", hex::encode(&peer_id[..8]));
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_protocol_violation();
                }
                return Ok(());
            }
            // Parse headers and queue for download
            if let Ok(headers_msg) = borsh::from_slice::<super::protocol::HeadersMessage>(payload) {
                // SECURITY: Validate message before processing
                if let Err(e) = headers_msg.validate() {
                    warn!("Invalid HeadersMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr).record_block_failure();
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
                sync_guard.queue_headers(hashes);
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
                    if let Some(sender) = senders.get(&peer_id) {
                        let _ = sender.send(msg.to_bytes()?).await;
                    }
                }
            }
        }

        MessageType::Addr => {
            // SECURITY: Validate addr messages
            if let Ok(addr_msg) = borsh::from_slice::<super::protocol::AddrMessage>(payload) {
                if let Err(e) = addr_msg.validate() {
                    warn!("Invalid AddrMessage from peer {}: {}", hex::encode(&peer_id[..8]), e);
                    return Ok(());
                }

                let now = chrono::Utc::now().timestamp() as u64;
                let max_future = now + 600; // Allow 10 minutes of clock skew
                // FIX: Relax age check. 3 hours was too aggressive — after a
                // chain wipe or long downtime, ALL addresses in peers' books
                // have old timestamps and get rejected, preventing peer discovery.
                // 7 days allows nodes to bootstrap from peers that haven't been
                // seen recently. Bitcoin Core uses 10 days.
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
                        // Skip unroutable addresses
                        let ip = socket_addr.ip();
                        if ip.is_loopback() || ip.is_unspecified() {
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
        }

        MessageType::GetData => {
            // Peer requests specific blocks by hash (individual block responses)
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("GetData message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_protocol_violation();
                }
                return Ok(());
            }
            if let Ok(msg) = borsh::from_slice::<GetBlocksMessage>(payload) {
                if let Err(e) = msg.validate() {
                    warn!("Invalid GetData from peer {:?}: {}", &peer_id[..4], e);
                    return Ok(());
                }
                // Send each block individually as BlockData
                for hash in &msg.hashes {
                    if let Some(block) = chain.get_block(hash) {
                        if let Ok(block_bytes) = borsh::to_vec(&block) {
                            let msg = Message::new(magic, MessageType::BlockData, block_bytes);
                            if let Some(sender) = senders.get(&peer_id) {
                                if let Ok(data) = msg.to_bytes() {
                                    let _ = sender.send(data).await;
                                }
                            }
                        }
                    }
                }
            }
        }

        MessageType::BlockData => {
            // Peer sends us a single block
            if payload.len() > super::protocol::MAX_MESSAGE_SIZE {
                warn!("BlockData message too large from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_protocol_violation();
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
                // Record successful block delivery
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_block_success(Duration::from_millis(100));
                }
                let _ = event_tx.send(NodeEvent::BlockReceived(block, peer_id));
            } else {
                warn!("Failed to deserialize BlockData from peer {:?}", &peer_id[..4]);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_block_failure();
                }
            }
        }

        MessageType::Reject => {
            // Peer rejected something - adjust reputation
            if let Some(mut peer) = peers.get_mut(&peer_id) {
                peer.adjust_reputation(-10);
            }
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_block_failure();
            }
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

                // Build filters on the fly from blocks (or serve from cache/db)
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

                // Serialize and send response. Use Message::to_bytes() so
                // the per-peer write loop reads `data[4]` as the real
                // message type instead of a body byte (see 2026-05-09 IBD
                // wedge: 5 sites bypassed framing and broke the connection).
                if let Some(sender) = senders.get(&peer_id) {
                    if let Ok(encoded) = borsh::to_vec(&filters) {
                        let msg = Message::new(magic, MessageType::Filters, encoded);
                        if let Ok(data) = msg.to_bytes() {
                            let _ = sender.send(data).await;
                        }
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

            let mut digests = Vec::with_capacity(((end - start + 1) as usize).min(
                MAX_DIGEST_BLOCKS_PER_REQ as usize,
            ));
            for h in start..=end {
                if let Some(block) = chain.get_block_by_height(h) {
                    digests.push(crate::wallet::lightsync::BlockDigest::from_block(&block));
                }
            }

            if let Some(sender) = senders.get(&peer_id) {
                if let Ok(encoded) = borsh::to_vec(&digests) {
                    let msg = Message::new(magic, MessageType::OutputDigests, encoded);
                    if let Ok(data) = msg.to_bytes() {
                        let _ = sender.send(data).await;
                    }
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
            if checkpoints.len() == MAX_CHECKPOINTS {
                tracing::warn!(
                    "GetFilterCheckpoints from {:?}: hit MAX_CHECKPOINTS={} cap (chain_height={})",
                    &peer_id[..4], MAX_CHECKPOINTS, chain_height
                );
            }

            if let Some(sender) = senders.get(&peer_id) {
                if let Ok(encoded) = borsh::to_vec(&checkpoints) {
                    let msg = Message::new(magic, MessageType::FilterCheckpoints, encoded);
                    if let Ok(data) = msg.to_bytes() {
                        let _ = sender.send(data).await;
                    }
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

                // Check each key image against the chain's spent set
                let mut statuses: Vec<u8> = Vec::with_capacity(key_images.len());
                for ki_bytes in &key_images {
                    let ki = crate::primitives::KeyImage::from_bytes(*ki_bytes);
                    let spent = chain.is_spent(&ki);
                    statuses.push(if spent { 1 } else { 0 });
                }

                if let Some(sender) = senders.get(&peer_id) {
                    if let Ok(encoded) = borsh::to_vec(&statuses) {
                        let msg = Message::new(magic, MessageType::KeyImageStatus, encoded);
                        if let Ok(data) = msg.to_bytes() {
                            let _ = sender.send(data).await;
                        }
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

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert_eq!(config.max_peers, MAX_PEERS);
        assert_eq!(config.max_outbound, MAX_OUTBOUND);
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
}
