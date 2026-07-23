// src/network/mod.rs
pub mod bootstrap;
pub mod dns_seeds;
pub mod peer_snapshot;
pub mod socks_dns;
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
pub mod block_filter;
pub mod compact_blocks;
pub mod dandelion;
pub mod eviction;
pub mod firework;
pub mod framing;
pub mod orphan;
pub mod peer;
pub mod proxy;
pub mod relay_score;
pub mod scoring;
pub mod sync;

/// Shared serialization lock for tests that mutate the process-global
/// `MAINTAINER_PUBKEY_ENV` (`COINCYNC_PEER_SNAPSHOT_PUBKEY`). Both
/// `peer_snapshot` and `faucet_registry` have tests that set/remove this
/// SAME var; without one shared lock they race across modules — a test
/// removes/overwrites the var while another has just set it, causing an
/// intermittent `is_some()`/`is_none()` failure. All such tests take this
/// lock. Poison is ignored so a panic in one env test doesn't cascade.
#[cfg(test)]
pub(crate) static MAINTAINER_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub mod dht;
pub mod node;
pub mod noise;
pub mod protocol;
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
pub use dandelion::DandelionRouter;
pub use dns_seeds::{resolve_seeds, resolve_seeds_with_proxy};
pub use node::P2PNode;
pub use peer::{generate_peer_id, PeerId, PeerInfo};
pub use protocol::{MessageHeader, MessageType, MAX_MESSAGE_SIZE};
pub use scoring::PeerMessageRateTracker;
pub use traffic_shaping::{TrafficShaper, TrafficShaperConfig, TrafficShapingStats};
