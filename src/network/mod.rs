// src/network/mod.rs
pub mod bootstrap;
pub mod dns_seeds;
pub mod socks_dns;
pub mod peer_snapshot;
// Generic maintainer-signed registry — infrastructure for Fort-Knox
// items 2 (faucet decentralization), 3 (FROST-coord decentralization),
// and future decentralized-service consumers. Follows the same trust
// model as `peer_snapshot` (signature-over-namespaced-payload) but is
// generic over the payload type so multiple services share one path.
pub mod signed_registry;
// Fort-Knox item 2 consumer wiring — payload types + wallet-facing
// entry point that reuses `signed_registry` above.
pub mod faucet_registry;

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
pub mod eviction;
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
