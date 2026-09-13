//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `ChainUpdateToken`** — INVARIANT: a token is single-use and
//!   `#[must_use]`, so a caller cannot silently drop a captured publication
//!   order without it being flagged at compile time.
//!   THREAT: a discarded or reused token would let a chain-state publication
//!   commit out of the order it was captured in, reopening the issue #249
//!   stale-write race that `ChainState::update` guards against.
//!   TESTS: (gap — no dedicated test in this file; ordering is proven at the
//!   facade by `set_chain_state_preserves_sequence_contract_at_facade` and
//!   `stale_processed_block_task_cannot_regress_sync_state` in
//!   `src/network/node.rs`).
//! - **§2 `NodeEvent`** — INVARIANT: `BlockReceived`/`TransactionReceived`
//!   always carry their relay/source `PeerId` (or `None`) alongside the
//!   payload, so downstream consensus feedback can attribute
//!   misbehavior/invalidity to the correct peer.
//!   THREAT: dropping the peer attribution would make invalid-block/invalid-tx
//!   scoring blind, letting a misbehaving peer resend indefinitely without
//!   penalty.
//!   TESTS: (gap — no dedicated test in this file; the attribution is
//!   consumed by `notify_block_invalid`/`notify_tx_invalid_full` in
//!   `src/network/node.rs`, which are themselves untested — see that file's
//!   audit map §4).
//! - **§3 `NodeConfig::default`** — INVARIANT: defaults derive from
//!   `NetworkType::Mainnet.params()` and the shared `MAX_PEERS`/`MAX_OUTBOUND`
//!   constants, so the facade and its config never drift apart.
//!   THREAT: a hand-duplicated default that skews from the real constants
//!   could silently under- or over-provision peer slots.
//!   TESTS: `test_node_config_default` (in `src/network/node.rs`).
//! - **§4 `NetworkStats` / `ConnectionStats`** — INVARIANT: these are plain
//!   aggregate snapshots with no derived/cached fields that could go stale
//!   relative to the live counters they summarize.
//!   THREAT: a stale cached counter could misreport peer/memory pressure to
//!   operators relying on these stats for capacity decisions.
//!   TESTS: `test_peer_count_and_connected_peers` (in `src/network/node.rs`).

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
