use std::net::SocketAddr;

use crate::config::NetworkType;
use crate::consensus::Block;
use crate::transaction::Transaction;

use super::super::bootstrap::BootstrapConfig;
use super::super::peer::PeerId;
use super::super::sync::SyncState;
use super::constants::{MAX_OUTBOUND, MAX_PEERS};

/// Opaque, single-use authorization for one ordered chain-state publication.
#[derive(Debug)]
#[must_use = "chain updates must be published or explicitly discarded"]
pub struct ChainUpdateToken(u64);

impl ChainUpdateToken {
    pub(super) fn new(sequence: u64) -> Self {
        Self(sequence)
    }

    pub(super) fn into_sequence(self) -> u64 {
        self.0
    }
}

/// Events emitted by the P2P node.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    /// New peer connected.
    PeerConnected(PeerId),
    /// Peer disconnected.
    PeerDisconnected(PeerId),
    /// A block ready for validation, paired with the relay peer so consensus
    /// feedback can score the correct connection.
    BlockReceived(Block, PeerId),
    /// A transaction ready for mempool admission and its relay source, when
    /// known, so full-validation failures can be attributed correctly.
    TransactionReceived(Transaction, Option<PeerId>),
    /// Sync state changed.
    SyncStateChanged(SyncState),
    /// Network error.
    Error(String),
}

/// P2P node configuration.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Network magic bytes.
    pub magic: [u8; 4],
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Maximum peers.
    pub max_peers: usize,
    /// Maximum outbound connections.
    pub max_outbound: usize,
    /// Bootstrap configuration.
    pub bootstrap: BootstrapConfig,
    /// Enable UPnP.
    pub upnp: bool,
    /// SOCKS5 proxy configuration for user-installed Tor/I2P.
    pub proxy: Option<crate::config::ProxyConfig>,
    /// Data directory for persistent node state.
    pub data_dir: std::path::PathBuf,
    /// P2P encryption configuration.
    pub encryption: crate::config::P2PEncryptionConfig,
    /// Externally reachable address registered as self to prevent gossip-driven
    /// self-dials when nonce detection is unavailable across restarts.
    pub external_addr: Option<SocketAddr>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let params = NetworkType::Mainnet.params();
        Self {
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

/// Aggregate network counters exposed by the facade.
#[derive(Clone, Debug)]
pub struct NetworkStats {
    pub peer_count: usize,
    pub outbound: usize,
    pub inbound: usize,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
}

/// Connection memory accounting exposed by the facade.
#[derive(Clone, Debug)]
pub struct ConnectionStats {
    pub memory_used: usize,
    pub memory_budget: usize,
}
