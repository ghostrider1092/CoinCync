use std::time::Duration;

/// Maximum number of peers (reduced to reserve outbound slots).
pub const MAX_PEERS: usize = 72;
/// Maximum outbound connections (8 slots reserved for outbound diversity).
pub const MAX_OUTBOUND: usize = 16;
/// Maximum inbound connections (reduced from 117 to prevent resource exhaustion).
pub const MAX_INBOUND: usize = 64;
/// Connection timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Ping interval.
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

/// CIP-019 gap within which an unsynced node stays on the near-tip path.
pub const NEAR_TIP_INV_WINDOW: u64 = 16;

/// Re-announcement bounds staleness when a bounded peer queue dropped the
/// original tip inventory without making one congested peer block the others.
pub const TIP_REBROADCAST_INTERVAL_SECS: u64 = 60;
/// Peer timeout (no activity).
pub const PEER_TIMEOUT: Duration = Duration::from_secs(300);
/// Global memory budget for P2P buffers (50 MB).
pub const MEMORY_BUDGET_BYTES: usize = 50 * 1024 * 1024;
/// Per-peer send queue size (with backpressure).
pub const PEER_QUEUE_SIZE: usize = 100;
/// Global message queue size.
pub const GLOBAL_QUEUE_SIZE: usize = 1000;
