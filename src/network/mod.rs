// src/network/mod.rs
pub mod bootstrap;
pub mod dns_seeds;
pub mod keepalive;
pub mod socks_dns;

// Ported from CoinCync (copy as-is):
pub mod dandelion;
pub mod framing;
pub mod compact_blocks;
pub mod orphan;
pub mod proxy;
pub mod peer;
pub mod block_filter;
pub mod scoring;
pub mod sync;
pub mod dht;
pub mod noise;
pub mod protocol;
pub mod node;
// First concrete step in splitting the monolithic `node.rs` — this
// holds only the per-IP / memory-budget tracking logic. Additional
// extractions (handshake, framer, dispatch, peer manager) will land
// in follow-up passes.
pub mod connection_tracker;

pub mod traffic_shaping;

pub mod hardening;

// ── Sketch / future-CIP stubs (gated, off by default) ───────────
#[cfg(feature = "sketch-block-aggregation")]
pub mod block_aggregation;

pub use bootstrap::initial_peers;
pub use dns_seeds::{resolve_seeds, resolve_seeds_with_proxy};
pub use node::P2PNode;
pub use peer::{PeerId, PeerInfo, generate_peer_id};
pub use dandelion::DandelionRouter;
pub use scoring::PeerMessageRateTracker;
pub use protocol::{MessageHeader, MessageType, MAX_MESSAGE_SIZE};
pub use traffic_shaping::{TrafficShaper, TrafficShaperConfig, TrafficShapingStats};
