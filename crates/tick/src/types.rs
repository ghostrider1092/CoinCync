//! Shared types used by the trait definitions and every tick mode.
//!
//! Every type in this module has been designed with the privacy
//! contract in mind. `AggregateFleetHealth` doesn't carry per-host
//! detail; `TickNotice` text is intended to be aggregate; and
//! `DeploymentMode` decides whether HealthTick broadcasts or stays
//! local. Read `docs/architecture/tick.md` for the reasoning.

use std::fmt;

// ─── Errors ────────────────────────────────────────────────────────────────

/// Result alias used across the crate.
pub type TickResult<T> = Result<T, TickError>;

/// Errors returned by adapter and tick-behavior methods.
///
/// The variants are deliberately coarse. Ticks aren't in the business of
/// deep error taxonomy — they detect anomalies, apply best-effort
/// recovery, and log. Fine-grained errors would tempt callers to
/// per-error-branch, which grows the blast radius.
#[derive(Debug)]
pub enum TickError {
    /// Adapter couldn't reach the local or a fleet peer.
    Unreachable(String),
    /// Adapter returned inconsistent state (e.g., height went backward).
    InconsistentState(String),
    /// Adapter refused an operation on privacy grounds.
    ///
    /// Example: `is_stem_phase` returned `true` and PropagationTick tried
    /// to re-broadcast anyway. This is caught by the trait's contract.
    PrivacyViolation(String),
    /// Snapshot / restore failure at the filesystem or archive layer.
    Snapshot(String),
    /// Signature verification failed on an incoming tick notice.
    BadSignature,
    /// Generic — adapter surfaced something not covered by the above.
    Other(String),
}

impl fmt::Display for TickError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TickError::Unreachable(s) => write!(f, "unreachable: {}", s),
            TickError::InconsistentState(s) => write!(f, "inconsistent state: {}", s),
            TickError::PrivacyViolation(s) => write!(f, "privacy violation: {}", s),
            TickError::Snapshot(s) => write!(f, "snapshot error: {}", s),
            TickError::BadSignature => write!(f, "bad signature on tick notice"),
            TickError::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for TickError {}

// ─── Chain state ──────────────────────────────────────────────────────────

/// Snapshot of a node's chain tip. Consumed by all three tick modes.
///
/// Field ordering matches the `get_info` RPC response that every
/// coincync fleet host exposes; adapters for other chains map their
/// own fields onto these positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTipState<Id> {
    /// Current tip height. Monotonically nondecreasing per chain.
    pub height: u64,
    /// Cumulative work at the tip. Used to compare which of two chains
    /// is heavier (`difficulty > other.difficulty` == heavier).
    pub difficulty: u128,
    /// Opaque tip identifier. 32 bytes on coincync/bitcoin/monero.
    pub tip_id: Id,
    /// Adapter's own view of "am I synced" — usually the node's
    /// internal flag, exposed via RPC.
    pub is_synced: bool,
    /// Currently-connected peer count.
    pub peer_count: u32,
    /// Seconds since the tip's timestamp. Used by HealthTick's stall
    /// detection.
    pub tip_age_secs: u64,
}

// ─── Fleet peer ────────────────────────────────────────────────────────────

/// One host in the fleet as understood by the adapter.
///
/// PRIVACY: fleet peers are only exposed to ticks that need them by
/// role (RescueTick and HealthTick). PropagationTick doesn't get fleet
/// peers — it works on p2p peer objects instead, which are ephemeral
/// per quest cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetPeer {
    /// Human-readable name for logs. Never included in tick notices
    /// (those aggregate; see `AggregateFleetHealth`).
    pub name: String,
    /// RPC URL for this host. Used internally by RescueTick; never
    /// broadcast.
    pub rpc_url: String,
    /// Role — `"seed"`, `"miner"`, `"relay"`, `"api"`, or similar.
    /// Used for aggregation ("N miners have low hashrate") without
    /// naming individual hosts.
    pub role: String,
}

// ─── Snapshot (RescueTick payload) ────────────────────────────────────────

/// A chaindata snapshot handle. RescueTick produces one on the canonical
/// host and passes it to each stalled host.
///
/// The struct itself doesn't hold the tarball bytes — those live on
/// disk. `tarball_path` points to the file; SHA is precomputed for
/// end-to-end verification across the Noise-encrypted transfer.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Where the tarball lives on the SOURCE host's filesystem.
    pub tarball_path: std::path::PathBuf,
    /// SHA-256 of the tarball bytes, computed at snapshot time.
    /// Verified again on the receiving host before atomic-swap.
    pub sha256: [u8; 32],
    /// Opaque tip identifier at the moment the snapshot was taken.
    /// Used by the receiver to confirm they're getting the right
    /// chain (e.g., not a stale snapshot from an older tip).
    pub source_tip: Vec<u8>,
    /// Compressed byte size for logging.
    pub compressed_bytes: u64,
}

// ─── Per-node health (aggregated later) ───────────────────────────────────

/// Per-node health metrics. NEVER exposed outside the local tick — only
/// aggregated into `AggregateFleetHealth` before any external report.
///
/// A tick that leaks a `HealthSnapshot` for a specific host violates
/// the privacy contract. This type is deliberately not `Serialize` /
/// `Deserialize` — it can't accidentally be sent over the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// Percent RAM used (0-100).
    pub ram_used_pct: u8,
    /// Percent disk used on the chaindata partition (0-100).
    pub disk_used_pct: u8,
    /// Percent swap used (0-100).
    pub swap_used_pct: u8,
    /// Miner hashrate in H/s, if this host is mining.
    pub hashrate_hs: Option<u64>,
    /// Number of transactions currently in the local mempool.
    pub mempool_txs: usize,
    /// CPU utilization (0-100).
    pub cpu_used_pct: u8,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

// ─── Aggregate fleet health (broadcastable) ───────────────────────────────

/// Aggregate-only fleet health snapshot. HealthTick broadcasts THIS,
/// not per-host details.
///
/// Every field is a count or a median — never a per-host value. This
/// is enforced structurally: the type has no `Vec<HealthSnapshot>` or
/// `HashMap<HostName, ...>` field. An adapter that wanted to leak
/// per-host detail would have to change the type signature, which is
/// a review-visible change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateFleetHealth {
    /// Total hosts polled. Not their identities.
    pub total_hosts: u16,
    /// Count of hosts with `tip_age > threshold_secs`.
    pub stalled_count: u16,
    /// Count of hosts with `peer_count < threshold_secs`.
    pub low_peer_count: u16,
    /// Count of hosts with divergent difficulty (≥5% delta from median).
    pub divergent_count: u16,
    /// Median difficulty across polled hosts. Aggregate signal only.
    pub median_difficulty: u128,
    /// Count of hosts with RAM > 90%.
    pub high_ram_count: u16,
    /// Count of hosts with disk > 90% on their chaindata partition.
    pub high_disk_count: u16,
}

// ─── Deployment mode ──────────────────────────────────────────────────────

/// Where the tick is running. Determines HealthTick broadcast behavior.
///
/// The default is `Personal` — the safer default, because a personal
/// home node broadcasting anomalies leaks its own existence. Adapters
/// should return `Fleet` ONLY when the runtime configuration explicitly
/// opts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Public fleet operator. Broadcasting notices via gossip is safe
    /// because the fleet is publicly known. Applies to `--network
    /// testnet-fleet` and `--network mainnet-fleet` deployments.
    Fleet,
    /// End-user personal node. Notices are local-only; never broadcast
    /// to gossip. Applies to `--network mainnet-personal` (the wallet-
    /// adjacent home-node deployment).
    Personal,
}

impl Default for DeploymentMode {
    /// The safer default. See type-level docs.
    fn default() -> Self {
        DeploymentMode::Personal
    }
}

// ─── Tick notice (the "tick is on the hunt" broadcast) ────────────────────

/// Severity levels for tick notices.
///
/// `Info` clears any prior banner. `Warn` = yellow. `Critical` = red.
/// The mapping is up to the wallet UI; ticks just report severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Informational; recovery complete, all-clear.
    Info,
    /// Something's off but not urgent.
    Warn,
    /// Immediate attention needed (RescueTick engaged, hard-finality
    /// pattern detected, etc.).
    Critical,
}

/// What kind of event triggered the notice.
///
/// Wallet UIs may filter or style differently per kind; `Hunt` typically
/// means "recovery is starting," `Recovered` means "you can go back to
/// normal."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickNoticeKind {
    /// Tick has sensed anomaly; entering quest phase.
    Hunt,
    /// Tick has latched onto target; feeding.
    Engaged,
    /// Tick has completed feed; detaching.
    Recovered,
    /// HealthTick generic anomaly report.
    Alert,
}

/// A signed, TTL-bounded notice broadcast by a tick.
///
/// PRIVACY: `text` MUST be aggregate — no host identifiers, no per-peer
/// IPs, no per-tx hashes. See the design doc's Privacy section.
///
/// The signature covers all other fields (canonical serialization).
/// Wallets verify against a bundled tick-pubkey registry; unrecognized
/// signers get their notices dropped silently, no ACK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickNotice {
    /// Event kind (Hunt / Engaged / Recovered / Alert).
    pub kind: TickNoticeKind,
    /// Human-readable text ≤ 256 bytes. MUST be aggregate.
    pub text: String,
    /// Severity for UI mapping.
    pub severity: Severity,
    /// Which tick emitted this (identifier from `tick.toml`). Not a
    /// per-host identifier — this is the tick's own name (e.g.,
    /// `"fleet-tick-1"`).
    pub tick_id: String,
    /// Which mode fired (`0` = rescue, `1` = health, `2` = propagation).
    /// Enum-shaped rather than an enum type here because the notice
    /// is serialized to wire bytes; a stable u8 is safer across
    /// mixed-version networks.
    pub mode: u8,
    /// Wall-clock at emission (Unix seconds).
    pub emitted_at: u64,
    /// Alert expires after this Unix timestamp. Wallets that see the
    /// notice after this timestamp discard it silently.
    pub expires_at: u64,
    /// Ed25519 signature over the canonical serialization of the
    /// preceding fields, by the tick's key.
    pub signature: [u8; 64],
}

impl TickNotice {
    /// Maximum text length allowed. Notices with longer text fail
    /// serialization / validation.
    pub const MAX_TEXT_LEN: usize = 256;

    /// True if this notice has expired at the given wall-clock time.
    /// Wallets and node-side alert relayers use this to drop stale
    /// notices without further verification cost.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at
    }
}
