// src/network/iron/mod.rs
//
// C-7 FIX: IronConsensus engine is currently a stub — spawn() is empty
// and all input receivers are dropped. The surrounding 1,200+ lines of
// policy infrastructure (classifier, flood guard, peer verifier, state
// machine) are NOT connected to anything.
//
// SECURITY: This module gives the FALSE APPEARANCE of robust fork recovery
// and peer reputation management. It is not wired up. Prometheus metrics
// from this module always show health_score=1.0 because no engine writes them.
//
// STATUS: Research/WIP — do not rely on this module for security.
// Feature-gated behind `iron-consensus` to prevent false-positive security credit.
// The fork recovery path currently runs through chain.rs (cumulative-work reorgs).
//
// TO ENABLE: cargo build --features iron-consensus
// Only enable after wiring up IronEngine::spawn() with a real event loop.

#[cfg(feature = "iron-consensus")]
pub mod config;
#[cfg(feature = "iron-consensus")]
pub mod engine;
#[cfg(feature = "iron-consensus")]
pub mod flood;
#[cfg(feature = "iron-consensus")]
pub mod guards;
#[cfg(feature = "iron-consensus")]
pub mod metrics;
#[cfg(feature = "iron-consensus")]
pub mod peer_verify;
#[cfg(feature = "iron-consensus")]
pub mod node_iron;
#[cfg(feature = "iron-consensus")]
pub mod address_book;
#[cfg(feature = "iron-consensus")]
pub mod state;
#[cfg(feature = "iron-consensus")]
pub mod status;

#[cfg(feature = "iron-consensus")]
pub use engine::{IronInput, IronEvent, IronEngine};

// Stub types when iron-consensus is disabled — must match the variants
// used by node.rs so the code compiles. All sends are no-ops.
#[cfg(not(feature = "iron-consensus"))]
pub struct IronEngine {
    _tx: tokio::sync::mpsc::Sender<IronInput>,
}
#[cfg(not(feature = "iron-consensus"))]
impl IronEngine {
    pub fn new() -> std::sync::Arc<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<IronInput>(128);
        // Drain receiver in background so sends never block
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        std::sync::Arc::new(Self { _tx: tx })
    }
    pub fn spawn(self: std::sync::Arc<Self>) {}
    pub fn input_sender(&self) -> tokio::sync::mpsc::Sender<IronInput> {
        self._tx.clone()
    }
}

#[cfg(not(feature = "iron-consensus"))]
#[derive(Debug, Clone)]
pub enum IronInput {
    PeerBadBlock(super::peer::PeerId),
    PeerGone(super::peer::PeerId),
    PeerHandshake { peer: super::peer::PeerId, height: u64, tip: crate::primitives::Hash, total_diff: u128 },
    BlockAccepted { height: u64, hash: crate::primitives::Hash },
    BlockRejected { height: u64, reason: String },
    Tick,
}

#[cfg(not(feature = "iron-consensus"))]
#[derive(Debug, Clone)]
pub enum IronEvent {
    PeerBanned(super::peer::PeerId),
    StateChanged(String),
}
