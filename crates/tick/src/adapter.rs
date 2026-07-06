//! The `ChainAdapter` trait — a blockchain's contract with the tick
//! runtime. Every host chain implements this once; ticks depend only on
//! the trait, so the tick crate stays portable.
//!
//! # Privacy contract
//!
//! Read `docs/architecture/tick.md`'s Privacy section before writing an
//! implementation. Method-level docs below reiterate the key rules, but
//! the design doc is the load-bearing spec.
//!
//! Summary:
//!
//! - `is_stem_phase` MUST return `true` for any tx currently in
//!   Dandelion++ stem phase. When in doubt, return `true` — refusing to
//!   act is always safer than accidentally leaking a stem tx.
//! - `stem_relay_peers` MUST accurately list the current stem relays.
//!   PropagationTick trusts this list to blacklist those peers from
//!   re-broadcast.
//! - `aggregate_fleet_health` MUST NOT expose per-host detail. The
//!   return type enforces this structurally, but adapters shouldn't
//!   log per-host data to external sinks either.
//! - `deployment_mode` MUST return `Personal` unless the runtime
//!   configuration explicitly opts into `Fleet`.

use crate::types::*;

/// The contract a host blockchain implements to become tick-runnable.
///
/// The trait is parameterized by associated types for the chain's own
/// block/tx/peer identifier shapes, so the tick core stays generic. All
/// three types are opaque to the tick — it moves them around but never
/// inspects them.
pub trait ChainAdapter: Send + Sync + 'static {
    /// Canonical wire-format identifier for a block. 32 bytes on
    /// coincync/bitcoin/monero; opaque to the tick.
    type BlockId: AsRef<[u8]> + Clone + Send + Sync + std::fmt::Debug + 'static;

    /// Opaque identifier for a transaction. Same shape considerations
    /// as `BlockId`.
    type TxId: AsRef<[u8]> + Clone + Send + Sync + std::fmt::Debug + 'static;

    /// Opaque handle to a peer. Ephemeral — no persistent identity
    /// across quest cycles (PropagationTick generates a per-quest UUID
    /// for internal use).
    type PeerId: Clone + Send + Sync + std::fmt::Debug + 'static;

    // ─── Chain state ────────────────────────────────────────────────

    /// Report the local node's view of its chain tip.
    ///
    /// Used by all three tick modes for the quest phase.
    fn tip_state(&self) -> TickResult<ChainTipState<Self::BlockId>>;

    /// List the fleet's peers as known to this node's configuration.
    ///
    /// RescueTick and HealthTick consume this to poll every fleet host.
    /// PropagationTick does NOT — it works on p2p peers, not fleet
    /// hosts.
    ///
    /// Returns an empty `Vec` for `DeploymentMode::Personal` — a home
    /// node has no fleet to speak of.
    fn fleet_peers(&self) -> Vec<FleetPeer>;

    /// RPC-probe a specific fleet peer for its tip.
    ///
    /// Used by RescueTick to detect divergence and by HealthTick to
    /// aggregate stall counts.
    ///
    /// Adapters MUST authenticate the RPC call (bearer token or
    /// equivalent); a tick that could be tricked into believing a
    /// spoofed peer would auto-recover to a wrong chain.
    fn probe_peer(&self, peer: &FleetPeer) -> TickResult<ChainTipState<Self::BlockId>>;

    // ─── Chaindata snapshot / restore (RescueTick) ─────────────────

    /// Snapshot the local chaindata to a tarball at `dest`.
    ///
    /// Blocking; async callers wrap in `spawn_blocking` themselves. The
    /// tick crate stays sync-agnostic so it can be used from either
    /// tokio or an executor-less binary.
    ///
    /// The snapshot must be taken with the node running (live-tar).
    /// Callers wait for `tip_age > 60s` before invoking to reduce WAL
    /// inconsistency (see `feedback_snapshot_procedure` memo in the
    /// coincync repo).
    fn snapshot_chaindata(
        &self,
        dest: &std::path::Path,
    ) -> TickResult<Snapshot>;

    /// Apply a chaindata snapshot atomically, replacing the current
    /// state.
    ///
    /// The receiving node MUST re-run its own validator on the applied
    /// state. RescueTick is not a consensus authority; if the applied
    /// chaindata fails validation, the receiver keeps its pre-swap
    /// state (renamed to `testnet.stalled-<timestamp>/` per the
    /// runbook).
    fn apply_chaindata(
        &self,
        source: &std::path::Path,
    ) -> TickResult<()>;

    // ─── Propagation (PropagationTick) ─────────────────────────────

    /// Re-broadcast a block to a specific peer.
    ///
    /// PropagationTick uses this after detecting a peer that said
    /// `NotFound` for a block it should have. Never re-broadcasts
    /// blocks the local node hasn't fully validated.
    fn rebroadcast_block(
        &self,
        block_id: &Self::BlockId,
        to: &Self::PeerId,
    ) -> TickResult<()>;

    // ─── Health metrics ────────────────────────────────────────────

    /// Query local node + system health for the aggregation input.
    ///
    /// Per-host detail returned here MUST NOT be exposed via
    /// `aggregate_fleet_health`. The intermediate `HealthSnapshot` is
    /// only for local decision-making; the tick aggregates before any
    /// external emission.
    fn health_snapshot(&self) -> TickResult<HealthSnapshot>;

    /// Aggregate fleet-wide health. HealthTick broadcasts this;
    /// per-host detail is deliberately absent from the return type.
    fn aggregate_fleet_health(&self) -> TickResult<AggregateFleetHealth>;

    // ─── Privacy contract (Dandelion++ preservation) ───────────────

    /// True if the given tx is in Dandelion++ stem phase locally.
    ///
    /// PropagationTick MUST call this before re-broadcasting a tx and
    /// MUST NOT re-broadcast if it returns `true`.
    ///
    /// Adapters for chains without Dandelion++ (or an equivalent
    /// stem/fluff mechanism) MAY return `false` unconditionally. That
    /// weakens PropagationTick's privacy behavior for that chain but
    /// is honest — a chain without a stem phase has different privacy
    /// guarantees.
    ///
    /// When in doubt, return `true`. Refusing to re-broadcast is
    /// always safer than accidentally leaking a stem tx.
    fn is_stem_phase(&self, tx_id: &Self::TxId) -> bool;

    /// Peers currently acting as Dandelion++ stem relays for the local
    /// node.
    ///
    /// PropagationTick MUST exclude these from any re-broadcast
    /// targeting; sending a fluffed tx to a stem-relay peer for a
    /// still-stem tx could leak the tx's origin.
    ///
    /// Adapters for chains without stem/fluff MAY return an empty
    /// `Vec` — consistent with `is_stem_phase` returning `false`.
    fn stem_relay_peers(&self) -> Vec<Self::PeerId>;

    // ─── Deployment posture ────────────────────────────────────────

    /// Report the deployment mode. HealthTick uses this to decide
    /// whether to broadcast notices via gossip or stay local.
    ///
    /// Adapters MUST return `Personal` unless the runtime config
    /// explicitly opts into `Fleet`. A misconfigured adapter that
    /// defaults to `Fleet` would cause every home node to broadcast
    /// anomaly notices to gossip — a network-level existence leak.
    fn deployment_mode(&self) -> DeploymentMode;

    // ─── Notice broadcast (Option B, on-wire) ─────────────────────

    /// Broadcast a signed tick notice over the node's gossip layer
    /// (coincync: `MessageType::Alert = 41`; other chains: their
    /// equivalent primitive).
    ///
    /// Adapters MUST verify the signature against a bundled tick-pubkey
    /// registry before propagating. Unsigned or bad-signature notices
    /// are dropped silently — no error to the caller, no ACK to the
    /// network.
    ///
    /// Adapters MUST honor `deployment_mode` — a `Personal` adapter
    /// silently no-ops this method, delivering the notice only to
    /// local log sinks.
    fn broadcast_notice(&self, notice: &TickNotice) -> TickResult<()>;
}
