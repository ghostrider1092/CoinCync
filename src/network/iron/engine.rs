//! # IronConsensus Engine (stub)
//!
//! The CoinCync 2.0 `iron` engine depended on modules (admin, alerts) that
//! were removed in the 1.0 trim. This stub keeps the public types used by
//! `network::node` compiling so that the node can run without the full
//! zero-tolerance convergence engine. Real fork-recovery is deferred to a
//! future 1.0 release.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::network::peer::PeerId;
use crate::primitives::Hash;

/// Feed these from the peer layer into IronConsensus.
#[derive(Debug)]
pub enum IronInput {
    PeerHandshake { peer: PeerId, height: u64, tip: Hash, total_diff: u128 },
    PeerHeightUpdate { peer: PeerId, height: u64 },
    PeerBadBlock(PeerId),
    PeerForkBlock(PeerId),
    PeerTimeout(PeerId),
    PeerOrphan(PeerId),
    PeerGone(PeerId),
    AdminForceHeight { target: u64, expected_hash: Option<Hash> },
    AdminBanPeer { peer: PeerId, duration: Duration },
    AdminForcePull,
    Shutdown,
}

/// Events emitted for logging / monitoring.
#[derive(Debug, Clone)]
pub enum IronEvent {
    Synced { height: u64 },
    Pulling { local: u64, best: u64 },
    Rolled { from: u64, to: u64 },
    PeerBanned { peer: PeerId, secs: u64 },
    Partitioned,
    PartitionHealed,
    ForkDetected { local: u64, peer: u64 },
    SyncStall { stuck_secs: u64, height: u64 },
    IntegrityFailure { description: String },
    AdminLocked,
}

/// Stub engine handle — owns the input/output channels.
pub struct IronEngine {
    pub input_tx: mpsc::Sender<IronInput>,
    pub event_rx: Option<mpsc::Receiver<IronEvent>>,
}

impl IronEngine {
    pub fn new() -> Self {
        let (input_tx, _input_rx) = mpsc::channel(128);
        let (_event_tx, event_rx) = mpsc::channel(128);
        Self { input_tx, event_rx: Some(event_rx) }
    }

    pub fn spawn(self: Arc<Self>) {}
}

pub use IronInput as Input;
pub use IronEvent as Event;
