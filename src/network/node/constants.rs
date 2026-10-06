use std::time::Duration;

/// Maximum number of peers (reduced to reserve outbound slots).
pub const MAX_PEERS: usize = 72;
/// Maximum outbound connections (8 slots reserved for outbound diversity).
pub const MAX_OUTBOUND: usize = 16;
/// Maximum inbound connections (reduced from 117 to prevent resource exhaustion).
pub const MAX_INBOUND: usize = 64;
/// SEC (2026-09-07): extra concurrent-inbound-connection permits beyond
/// `MAX_INBOUND`, covering connections still in the Noise handshake (which are
/// invisible to the post-handshake `MAX_INBOUND` count). A semaphore of
/// `MAX_INBOUND + INBOUND_HANDSHAKE_SLACK` acquired at accept time bounds the
/// total in-flight inbound tasks (and their ~64 KiB handshake buffers), closing
/// the half-open-connection flood that otherwise bypasses both `MAX_INBOUND` and
/// the connection memory budget.
pub const INBOUND_HANDSHAKE_SLACK: usize = 32;
/// Connection timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Ping interval.
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

/// CIP-019 gap within which an unsynced node stays on the near-tip path.
pub const NEAR_TIP_INV_WINDOW: u64 = 16;

/// Runtime mesh-floor: minimum connected peers below which a node is considered
/// under-meshed. Standardized to 3 to match the deploy-time gate
/// (`scripts/deploy-node-binary.sh`) and the REST readiness probe
/// (`MIN_PEERS_FOR_READY`). See docs/design/runtime-mesh-floor.md.
pub const MESH_FLOOR_PEERS: usize = 3;
/// Consecutive 30s heartbeat ticks below `MESH_FLOOR_PEERS` before the node
/// flips into the sustained `mesh_degraded` state (hysteresis against transient
/// peer-count blips). 3 ticks ≈ 90s. Recovery is immediate on the first tick at
/// or above the floor.
pub const MESH_FLOOR_SUSTAIN_TICKS: u32 = 3;

/// Re-bootstrap-on-isolation (#147): minimum interval before the outbound
/// connector re-resolves the DNS seeds after finding its address book
/// exhausted while under-meshed. The startup bootstrap only runs when the book
/// starts empty; once a long-running node's book drains to zero (every known
/// peer purged after repeated failures) while isolated, nothing else re-queries
/// DNS. This is the first retry delay; it doubles up to
/// `REBOOTSTRAP_BACKOFF_MAX` while re-resolution keeps yielding no new
/// addresses, and resets to this floor as soon as a re-bootstrap adds any.
pub const REBOOTSTRAP_BACKOFF_MIN: Duration = Duration::from_secs(60);
/// Ceiling for the exponential re-bootstrap backoff, so a persistent DNS
/// outage settles at one retry every 30 minutes rather than hammering the
/// resolver.
pub const REBOOTSTRAP_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);

/// Maximum anchor peers persisted across restarts (Bitcoin Core persists 2).
/// Bounding + longevity-ranking the set keeps anchors to the most stable
/// long-lived outbound peers rather than every momentarily-connected one.
pub const ANCHOR_MAX: usize = 2;

/// Re-announcement bounds staleness when a bounded peer queue dropped the
/// original tip inventory without making one congested peer block the others.
pub const TIP_REBROADCAST_INTERVAL_SECS: u64 = 60;
/// Peer timeout (no activity).
pub const PEER_TIMEOUT: Duration = Duration::from_secs(300);
/// Max time a single outbound write may take before the peer is dropped (C2).
/// A write stalling this long means the peer stopped reading (its TCP receive
/// window is full); without the bound the per-peer write task blocks forever, its
/// PEER_QUEUE_SIZE send queue fills, and `send_to_peer` -- called by the SHARED
/// message processor -- then blocks, freezing ALL P2P message handling.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Global memory budget for P2P buffers (50 MB).
pub const MEMORY_BUDGET_BYTES: usize = 50 * 1024 * 1024;
/// Per-peer send queue size (with backpressure).
pub const PEER_QUEUE_SIZE: usize = 100;
/// Global message queue size.
pub const GLOBAL_QUEUE_SIZE: usize = 1000;
