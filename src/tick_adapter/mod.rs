//! CoincyncAdapter — the `tick::ChainAdapter` implementation for
//! coincync.
//!
//! This is **Phase 1c** — the adapter *shell*. Real methods are
//! implemented where they don't need the RPC surface (in particular
//! `deployment_mode`, `is_stem_phase` conservative default,
//! `stem_relay_peers` empty default, `broadcast_notice` local no-op).
//! Methods that need to talk to peers over HTTP RPC
//! (`probe_peer`, `verify_peer_header_pow`, `snapshot_chaindata`,
//! `apply_chaindata`, `rebroadcast_block`, `aggregate_fleet_health`,
//! `tip_state`, `fleet_peers`, `health_snapshot`) return
//! `TickError::Other("phase 1e: not yet implemented")`.
//!
//! Phase 1d wires the real RPC client. Phase 1e ships the `bin/tick.rs`
//! binary.
//!
//! ## Why is CoincyncAdapter RPC-based rather than direct-Arc?
//!
//! Tick runs as a SIDECAR binary — a separate process from
//! `coincync-node` on the same host. Sidecar isolation was the
//! locked decision in the design PR (#178). A separate process
//! cannot hold `Arc<Blockchain>` refs into the node's address
//! space, so every chain interaction is an RPC call over
//! loopback. The RPC surface is the same one wallets and explorers
//! use (`get_info`, `get_block`, `submit_block`, etc.), so there's
//! no extra RPC-schema work — Phase 1d just wires an HTTP client
//! to the existing endpoints.
//!
//! ## Privacy contract enforcement
//!
//! Both real-impl methods enforce the tick crate's privacy contract:
//!
//! - `is_stem_phase` returns `true` unconditionally as the safe
//!   default. Phase 1d will consult the local node's Dandelion++
//!   state (which will need a public accessor added — deferred until
//!   Phase 3 PropagationTick actually needs it).
//! - `stem_relay_peers` returns an empty `Vec` for the same reason.
//! - `deployment_mode` is driven by config; the config default is
//!   `Personal` (the safer default from Phase 1a's `DeploymentMode::default`).
//! - `broadcast_notice` local no-op keeps the "personal-node emits
//!   nothing" invariant even during the not-yet-wired phase.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use tick::{
    AggregateFleetHealth, ChainAdapter, ChainTipState, DeploymentMode, FleetPeer, HealthSnapshot,
    Snapshot, TickError, TickNotice, TickResult,
};

use crate::primitives::Hash;

pub mod fleet_config;
pub mod health;
pub mod rpc_client;
use fleet_config::FleetConfig;
use rpc_client::{get_block_by_height, get_info, submit_block, RpcClient};

/// Opaque block/tx/peer identifier types the adapter uses to
/// parameterize `ChainAdapter`. `BlockIdBytes` and `TxIdBytes` both
/// wrap `Hash` so the tick crate's `AsRef<[u8]>` bound is satisfied.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockIdBytes(pub Hash);

impl AsRef<[u8]> for BlockIdBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Same shape as `BlockIdBytes` — tx-scoped for clarity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxIdBytes(pub Hash);

impl AsRef<[u8]> for TxIdBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

// (The Phase 1c `PeerHandle([u8; 32])` type was removed in Phase 1g
// once `rebroadcast_block` needed an actionable handle to reach the
// peer. `PeerId` is now `tick::FleetPeer` — it carries the RPC URL
// directly so the adapter doesn't need a peer-handle-to-URL lookup
// table. `FleetPeer` already satisfies `Clone + Send + Sync + Debug`.)

// ─── Config ────────────────────────────────────────────────────────────────

/// Configuration for the CoincyncAdapter. Loaded from TOML at binary
/// startup (Phase 1e); tests instantiate directly.
///
/// Field defaults are Personal-safe: an operator who doesn't
/// explicitly opt into fleet mode gets the home-node posture with
/// notice broadcasting disabled.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoincyncAdapterConfig {
    /// Deployment mode. `Personal` (default) means the tick never
    /// broadcasts notices to the gossip layer; `Fleet` means it does.
    ///
    /// Deserialized from the string `"personal"` or `"fleet"` in TOML.
    #[serde(default = "default_deployment_mode")]
    pub deployment_mode: DeploymentModeStr,

    /// Where `fleet-config.json` lives. Default:
    /// `/etc/coincync-tick/fleet-config.json`. Personal deployments
    /// leave this at the default and the adapter serves an empty
    /// fleet.
    #[serde(default = "default_fleet_config_path")]
    pub fleet_config_path: PathBuf,

    /// Coincync RPC URL for the local node. The adapter talks to this
    /// URL for `tip_state`, `probe_peer`, and other chain queries.
    /// Default: `http://127.0.0.1:28081`.
    #[serde(default = "default_local_rpc_url")]
    pub local_rpc_url: String,

    /// Path to the RPC bearer token used to auth against
    /// `local_rpc_url`. Read at binary startup; not stored in the
    /// adapter (Phase 1d holds it in an Arc<String> loaded on init).
    /// Default: `/etc/coincync/rpc-token`.
    #[serde(default = "default_rpc_token_path")]
    pub local_rpc_token_path: PathBuf,
}

impl Default for CoincyncAdapterConfig {
    fn default() -> Self {
        CoincyncAdapterConfig {
            deployment_mode: DeploymentModeStr::Personal,
            fleet_config_path: default_fleet_config_path(),
            local_rpc_url: default_local_rpc_url(),
            local_rpc_token_path: default_rpc_token_path(),
        }
    }
}

fn default_deployment_mode() -> DeploymentModeStr {
    DeploymentModeStr::Personal
}
fn default_fleet_config_path() -> PathBuf {
    PathBuf::from("/etc/coincync-tick/fleet-config.json")
}
fn default_local_rpc_url() -> String {
    "http://127.0.0.1:28081".to_string()
}
fn default_rpc_token_path() -> PathBuf {
    PathBuf::from("/etc/coincync/rpc-token")
}

/// String-shaped deployment mode for TOML deserialization. Kept
/// separate from `tick::DeploymentMode` because the tick crate's enum
/// doesn't derive Serde (adding Serde to the tick crate would grow
/// its dep tree — the tick crate is intentionally dep-light).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentModeStr {
    /// Home node; no broadcast (safer default).
    Personal,
    /// Public fleet operator; broadcast allowed.
    Fleet,
}

impl From<DeploymentModeStr> for DeploymentMode {
    fn from(s: DeploymentModeStr) -> DeploymentMode {
        match s {
            DeploymentModeStr::Personal => DeploymentMode::Personal,
            DeploymentModeStr::Fleet => DeploymentMode::Fleet,
        }
    }
}

// ─── Adapter ──────────────────────────────────────────────────────────────

/// Wraps a secret so it can never leak through `Debug` output.
///
/// The adapter derives `Debug`, and rule A.6 (key hygiene) forbids
/// secret material — including RPC bearer tokens — from appearing in
/// debug output, logs, or error messages. This newtype renders as
/// `<redacted>` regardless of `T`, so `{:?}` on the adapter is safe.
#[derive(Clone)]
struct Redacted<T>(T);

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The CoincyncAdapter.
///
/// Phase 1d wires the RPC client for `tip_state` and `probe_peer`.
/// Snapshot/apply/rebroadcast/verify_pow/aggregate_fleet_health stay
/// stubbed until Phase 1e (which brings tar/scp/systemd surface).
#[derive(Clone, Debug)]
pub struct CoincyncAdapter {
    config: CoincyncAdapterConfig,
    /// RPC client for the local node. Built at construction time from
    /// `config.local_rpc_url` + the bearer token loaded from
    /// `config.local_rpc_token_path`. `None` in tests that only
    /// exercise privacy-contract methods.
    local_rpc: Option<RpcClient>,
    /// The tick-RPC bearer token, retained so cross-fleet calls
    /// (`probe_peer`, `verify_peer_header_pow`, `rebroadcast_block`)
    /// can authenticate against peer hosts. Fleet hosts share a single
    /// tick-RPC bearer (see `feedback_credential_hygiene`), so the same
    /// token that authenticates the local node also authenticates the
    /// peers. Wrapped in `Redacted` so it never leaks via `Debug`.
    peer_bearer: Redacted<Option<String>>,
}

impl CoincyncAdapter {
    /// Build a new CoincyncAdapter from a config, connecting the local
    /// RPC client using the given bearer token.
    ///
    /// Pass `bearer = None` to disable auth (test-only).
    pub fn new(config: CoincyncAdapterConfig, bearer: Option<String>) -> Result<Self, TickError> {
        // Retain the bearer for cross-fleet peer calls before it's
        // moved into the local RpcClient (reqwest doesn't expose it
        // post-construction).
        let peer_bearer = Redacted(bearer.clone());
        let local_rpc = Some(RpcClient::new(config.local_rpc_url.clone(), bearer)?);
        Ok(CoincyncAdapter {
            config,
            local_rpc,
            peer_bearer,
        })
    }

    /// Build a new adapter with defaults + no RPC client.
    ///
    /// Convenient for unit tests that only exercise the privacy-
    /// contract methods (`deployment_mode`, `is_stem_phase`,
    /// `stem_relay_peers`, `broadcast_notice`) — those don't need
    /// RPC. RPC-dependent methods (`tip_state`, `probe_peer`) return
    /// `TickError::Other("no local RPC client configured")` in this
    /// mode.
    pub fn with_defaults() -> Self {
        CoincyncAdapter {
            config: CoincyncAdapterConfig::default(),
            local_rpc: None,
            peer_bearer: Redacted(None),
        }
    }

    /// Reference to the underlying config.
    pub fn config(&self) -> &CoincyncAdapterConfig {
        &self.config
    }
}

// ─── Aggregation helper (pure function, testable without HTTP) ────────────

/// Thresholds used by `aggregate_from_tips`. Matches the defaults
/// documented in the design doc / RescueConfig; centralized so the
/// aggregate math and the RescueTick divergence-detection use the
/// same numbers.
mod agg_thresholds {
    /// tip_age > 300s counts as "stalled" in the aggregate.
    pub const STALL_SECS: u64 = 300;
    /// peer_count < 3 counts as "low_peer_count".
    pub const LOW_PEER_COUNT_MIN: u32 = 3;
    /// Difficulty delta ≥ 5% of median counts as "divergent".
    pub const DIVERGENT_PCT: u8 = 5;
}

/// Aggregate a set of per-host tips into an `AggregateFleetHealth`.
///
/// `unreachable_count` is the number of hosts we couldn't probe. They
/// also contribute to `low_peer_count` (an unreachable host effectively
/// has peer_count = 0).
///
/// PURE — no I/O. Extracted so tests can exercise the math without
/// standing up mock HTTP servers.
fn aggregate_from_tips<Id>(
    tips: &[ChainTipState<Id>],
    unreachable_count: u16,
    total_hosts: u16,
) -> AggregateFleetHealth {
    let stalled_count = tips
        .iter()
        .filter(|t| t.tip_age_secs > agg_thresholds::STALL_SECS)
        .count() as u16;
    let low_peer_count = tips
        .iter()
        .filter(|t| t.peer_count < agg_thresholds::LOW_PEER_COUNT_MIN)
        .count() as u16
        + unreachable_count; // unreachable hosts are effectively low-peer

    // Median difficulty: sorted middle element. Empty tips → 0.
    let median_difficulty: u128 = if tips.is_empty() {
        0
    } else {
        let mut diffs: Vec<u128> = tips.iter().map(|t| t.difficulty).collect();
        diffs.sort_unstable();
        diffs[diffs.len() / 2]
    };

    // Divergent: hosts whose difficulty is ≥DIVERGENT_PCT% away from
    // the median (in EITHER direction). Zero median → nobody divergent.
    let divergent_count = if median_difficulty == 0 {
        0
    } else {
        tips.iter()
            .filter(|t| {
                let diff = if t.difficulty > median_difficulty {
                    t.difficulty - median_difficulty
                } else {
                    median_difficulty - t.difficulty
                };
                let pct_u128 = (diff.saturating_mul(100)) / median_difficulty;
                pct_u128 >= agg_thresholds::DIVERGENT_PCT as u128
            })
            .count() as u16
    };

    AggregateFleetHealth {
        total_hosts,
        stalled_count,
        low_peer_count,
        divergent_count,
        median_difficulty,
        // Phase 1f: RAM/disk stats need `health_snapshot` from each host
        // (per-host stats aggregated). Deferred to the phase that lands
        // `health_snapshot` — high_ram_count / high_disk_count stay at 0
        // until then.
        high_ram_count: 0,
        high_disk_count: 0,
    }
}

// ─── ChainAdapter impl ─────────────────────────────────────────────────────

impl ChainAdapter for CoincyncAdapter {
    type BlockId = BlockIdBytes;
    type TxId = TxIdBytes;
    type PeerId = FleetPeer;

    // ── Chain state ─────────────────────────────────────────────────

    fn tip_state(&self) -> TickResult<ChainTipState<Self::BlockId>> {
        let rpc = self
            .local_rpc
            .as_ref()
            .ok_or_else(|| TickError::Other("no local RPC client configured".into()))?;
        let info = get_info(rpc)?;
        Ok(ChainTipState {
            height: info.height,
            difficulty: info.difficulty_u128(),
            tip_id: BlockIdBytes(Hash::from_bytes(info.tip_bytes())),
            is_synced: info.is_synced,
            peer_count: info.peer_count,
            // `tip_age_secs = None` on the wire (clock unavailable)
            // maps to `u64::MAX` here so downstream stall-detection
            // doesn't mistake "unknown age" for "brand new tip"
            // (which would silently mask a real stall).
            tip_age_secs: info.tip_age_secs.unwrap_or(u64::MAX),
        })
    }

    fn fleet_peers(&self) -> Vec<FleetPeer> {
        // Read + parse fleet-config.json. Personal deployments
        // legitimately have no fleet, so a missing / unreadable
        // config file → empty Vec (NOT an error).
        //
        // A parseable but empty `nodes` object also → empty Vec.
        //
        // Only genuine parse errors (malformed JSON, wrong shape)
        // would produce a warning — logged at UPSTREAM caller level
        // since `fleet_peers` returns Vec, not TickResult.
        FleetConfig::from_path(&self.config.fleet_config_path)
            .map(|c| c.to_fleet_peers())
            .unwrap_or_default()
    }

    fn probe_peer(&self, peer: &FleetPeer) -> TickResult<ChainTipState<Self::BlockId>> {
        // Build a transient per-peer RPC client using the same bearer
        // token as the local RPC (fleet hosts share a single tick-
        // RPC bearer under `feedback_credential_hygiene`).
        //
        // NOTE: this call blocks the caller's thread for up to 5s
        // (DEFAULT_TIMEOUT in rpc_client.rs). RescueTick's quest loop
        // iterates through fleet peers sequentially — an unreachable
        // peer costs 5s. Fleet size × 5s at worst per quest cycle;
        // acceptable at the current ~9-host fleet, revisit if fleet
        // grows past ~30.
        let client = RpcClient::new(peer.rpc_url.clone(), self.peer_bearer.0.clone())?;
        let info = get_info(&client)?;
        Ok(ChainTipState {
            height: info.height,
            difficulty: info.difficulty_u128(),
            tip_id: BlockIdBytes(Hash::from_bytes(info.tip_bytes())),
            is_synced: info.is_synced,
            peer_count: info.peer_count,
            tip_age_secs: info.tip_age_secs.unwrap_or(u64::MAX),
        })
    }

    fn verify_peer_header_pow(&self, peer: &FleetPeer, height: u64) -> TickResult<bool> {
        // Fetch the block at `height` from `peer` via get_block_by_height.
        // Uses the shared fleet bearer (see `peer_bearer`) so an
        // auth-required peer host doesn't 401.
        let client = RpcClient::new(peer.rpc_url.clone(), self.peer_bearer.0.clone())?;
        let resp = get_block_by_height(&client, height)?;

        // Decode the hex `bytes` field into a Block via borsh. We
        // deserialize LOCALLY — never trust the RPC's derived fields
        // like `difficulty` or `hash`. A peer that lies about those
        // can't fool the check below because we recompute everything
        // from the raw block bytes.
        let bytes = hex::decode(&resp.bytes).map_err(|e| {
            TickError::Other(format!(
                "{} get_block_by_height({}) returned bad hex: {}",
                client.url(),
                height,
                e
            ))
        })?;
        let block: crate::consensus::Block = borsh::from_slice(&bytes).map_err(|e| {
            TickError::Other(format!(
                "{} get_block_by_height({}) borsh decode failed: {}",
                client.url(),
                height,
                e
            ))
        })?;

        let header = &block.header;

        // Genesis (height 0) is exempt from PoW verification — matches
        // consensus behavior at `src/consensus/validation.rs:197`.
        // Genesis has no real PoW; it's a protocol constant hardcoded
        // in the binary. In practice RescueTick's
        // `divergence_block_threshold >= 100` means the canonical
        // is always at height > 100, so this branch is unreachable
        // in production — but we handle it correctly for
        // completeness and to match consensus exactly.
        if header.height == 0 {
            return Ok(true);
        }

        // Non-genesis: rerun the full PoW check locally. `verify_pow`
        // handles anchor + algorithm + RandomX-hash + difficulty in
        // one call.
        // - Ok(()) → Ok(true): PoW is valid, peer's chain is genuine
        // - Err(PowValidation) → Ok(false): peer is lying about their
        //   canonical chain (safety-critical case RescueTick uses to
        //   refuse feeding)
        // - Err(other error) → propagate as TickError::Other
        match crate::consensus::pow::verify_pow(
            &header.prev_hash,
            header.height,
            header.timestamp,
            header.nonce,
            &header.tx_root,
            &header.target,
            &header.anchor,
            header.algorithm,
        ) {
            Ok(()) => Ok(true),
            Err(crate::error::Error::PowValidation(_)) => Ok(false),
            Err(other) => Err(TickError::Other(format!(
                "{} verify_pow returned unexpected error: {}",
                client.url(),
                other
            ))),
        }
    }

    // ── Chaindata snapshot / restore — stubbed ──────────────────────

    fn snapshot_chaindata(
        &self,
        _source: Option<&FleetPeer>,
        _dest: &std::path::Path,
    ) -> TickResult<Snapshot> {
        Err(TickError::Other(
            "phase 1e: snapshot_chaindata requires tar+scp implementation (Phase 1e)".into(),
        ))
    }

    fn apply_chaindata(&self, _source: &std::path::Path) -> TickResult<()> {
        Err(TickError::Other(
            "phase 1e: apply_chaindata requires systemd stop+restart integration (Phase 1e)".into(),
        ))
    }

    // ── Propagation ─────────────────────────────────────────────────

    fn rebroadcast_block(&self, block_id: &Self::BlockId, to: &Self::PeerId) -> TickResult<()> {
        // Step 1: fetch the block from the LOCAL node by its hash. If
        // the local node doesn't have it, we have nothing to
        // re-broadcast — return a clear error rather than trying to
        // proceed with empty bytes.
        let local = self
            .local_rpc
            .as_ref()
            .ok_or_else(|| TickError::Other("no local RPC client configured".into()))?;
        let hash_hex = hex::encode(block_id.0.as_bytes());
        let local_block = rpc_client::get_block_by_hash(local, &hash_hex)?;

        // Step 2: submit the same bytes to the target peer's
        // `submit_block` RPC, authenticated with the shared fleet
        // bearer (see `peer_bearer`) — the same token used by
        // `probe_peer` and `verify_peer_header_pow`.
        let target = RpcClient::new(to.rpc_url.clone(), self.peer_bearer.0.clone())?;
        let resp = submit_block(&target, local_block.bytes)?;
        if !resp.accepted {
            return Err(TickError::Other(format!(
                "target {} did not accept rebroadcast (hash={}, status={:?})",
                to.name, hash_hex, resp.status
            )));
        }
        Ok(())
    }

    // ── Health metrics ──────────────────────────────────────────────

    fn health_snapshot(&self) -> TickResult<HealthSnapshot> {
        // mempool_txs comes from the local node's get_info RPC. If the
        // RPC is unreachable, we can still report the local system
        // stats — a stalled node with a slow disk is exactly the
        // scenario HealthTick wants to catch, so refusing to return
        // anything would defeat the purpose. On RPC failure we report
        // mempool_txs=0, which is indistinguishable from a genuinely
        // empty mempool: HealthSnapshot has no field to signal
        // "local RPC down", so the caller cannot tell the two apart.
        // Acceptable for now — a dead local RPC surfaces through the
        // other tip/probe paths, not this one.
        let mempool_txs = match self.local_rpc.as_ref() {
            Some(rpc) => match get_info(rpc) {
                Ok(info) => info.mempool_size.unwrap_or(0),
                Err(_) => 0,
            },
            None => 0,
        };

        Ok(HealthSnapshot {
            ram_used_pct: health::ram_used_pct(),
            swap_used_pct: health::swap_used_pct(),
            uptime_secs: health::uptime_secs(),
            mempool_txs,
            // Phase 1h TODOs — all reported as 0 with rationale in
            // health.rs module docs:
            // - disk_used_pct: needs statvfs (Phase 1i)
            // - cpu_used_pct: needs delta sample (Phase 1j)
            // - hashrate_hs: needs rig integration (Phase 1j)
            disk_used_pct: 0,
            cpu_used_pct: 0,
            hashrate_hs: None,
        })
    }

    fn aggregate_fleet_health(&self) -> TickResult<AggregateFleetHealth> {
        // Probe every fleet peer sequentially. Unreachable hosts are
        // logged into `unreachable_count` and contribute to
        // `low_peer_count` (they can't report their peer_count).
        // Successful probes contribute to the aggregate math.
        //
        // Sequential (not concurrent) because ChainAdapter is sync
        // and I don't want to spin up a runtime just for this call.
        // At ~9 hosts × 5s max timeout the worst case is 45s — fine
        // for a maintenance-loop call, revisit if fleet grows.
        let peers = <Self as ChainAdapter>::fleet_peers(self);
        let mut tips = Vec::with_capacity(peers.len());
        let mut unreachable = 0u16;
        for peer in &peers {
            match <Self as ChainAdapter>::probe_peer(self, peer) {
                Ok(tip) => tips.push(tip),
                Err(_) => unreachable += 1,
            }
        }
        Ok(aggregate_from_tips(&tips, unreachable, peers.len() as u16))
    }

    // ── Privacy contract — real impls (conservative defaults) ──────

    fn is_stem_phase(&self, _tx_id: &Self::TxId) -> bool {
        // Phase 1c CONSERVATIVE DEFAULT: assume every tx is in stem
        // phase. PropagationTick (Phase 3) treats this as "refuse to
        // re-broadcast." Under the trait's docstring: "When in doubt,
        // return true." Refusing to act is always safer than
        // accidentally leaking a stem tx.
        //
        // Phase 3 wires a real check against the node's
        // DandelionRouter state. Until then, PropagationTick simply
        // won't fire — the safer failure mode.
        true
    }

    fn stem_relay_peers(&self) -> Vec<Self::PeerId> {
        // Phase 1c: empty. PropagationTick (Phase 3) will consult
        // this to blacklist stem-relay peers from re-broadcast; an
        // empty list is a safe overapproximation (nothing to
        // blacklist against, but we also can't cause harm since
        // `is_stem_phase` returns true unconditionally).
        Vec::new()
    }

    fn deployment_mode(&self) -> DeploymentMode {
        self.config.deployment_mode.into()
    }

    fn broadcast_notice(&self, _notice: &TickNotice) -> TickResult<()> {
        // Phase 1c: local no-op. This enforces the Personal-mode
        // "silent broadcast" contract by construction — regardless of
        // the configured deployment mode, no notices go anywhere yet.
        // Fleet-mode notices start actually broadcasting in Phase 1d
        // when the AlertMessage protocol type + RPC broadcast hook
        // land.
        //
        // Returning Ok(()) rather than an error keeps the state
        // machine flowing during Phase 1c integration tests — notice
        // emission is best-effort per RescueTick's `emit_notice`
        // helper.
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_personal_mode() {
        let cfg = CoincyncAdapterConfig::default();
        assert_eq!(cfg.deployment_mode, DeploymentModeStr::Personal);
    }

    #[test]
    fn adapter_reports_personal_mode_by_default() {
        let adapter = CoincyncAdapter::with_defaults();
        assert_eq!(adapter.deployment_mode(), DeploymentMode::Personal);
    }

    #[test]
    fn adapter_reports_fleet_mode_when_configured() {
        let cfg = CoincyncAdapterConfig {
            deployment_mode: DeploymentModeStr::Fleet,
            ..CoincyncAdapterConfig::default()
        };
        let adapter = CoincyncAdapter::new(cfg, None).expect("new");
        assert_eq!(adapter.deployment_mode(), DeploymentMode::Fleet);
    }

    #[test]
    fn is_stem_phase_returns_true_conservatively() {
        // Under the trait contract, `true` = "in stem phase" = refuse
        // to re-broadcast. Conservative default until Phase 3 wires a
        // real DandelionRouter check.
        let adapter = CoincyncAdapter::with_defaults();
        let dummy_tx = TxIdBytes(Hash::from_bytes([1u8; 32]));
        assert!(adapter.is_stem_phase(&dummy_tx));
    }

    #[test]
    fn stem_relay_peers_is_empty() {
        let adapter = CoincyncAdapter::with_defaults();
        assert!(adapter.stem_relay_peers().is_empty());
    }

    #[test]
    fn fleet_peers_is_empty_when_config_missing() {
        // Personal deployments legitimately have no fleet-config.json.
        // The adapter returns an empty Vec (NOT an error), which is
        // correct for the Personal posture.
        let adapter = CoincyncAdapter::with_defaults();
        assert!(adapter.fleet_peers().is_empty());
    }

    #[test]
    fn fleet_peers_reads_config_file() {
        use std::io::Write;
        // Write a minimal fleet-config.json to a temp file.
        let dir = std::env::temp_dir().join(format!("tick-fleet-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("fleet-config.json");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(
                br#"{
                    "rpc_port": 28081,
                    "nodes": {
                        "seed1": {"ip":"1.2.3.4","rpc_bind":"0.0.0.0","role":"seed"},
                        "api":   {"ip":"5.6.7.8","rpc_bind":"0.0.0.0","role":"api"}
                    }
                }"#,
            )
            .expect("write");
        }
        let cfg = CoincyncAdapterConfig {
            fleet_config_path: path.clone(),
            ..CoincyncAdapterConfig::default()
        };
        let adapter = CoincyncAdapter::new(cfg, None).expect("adapter build");
        let peers = adapter.fleet_peers();
        // api excluded per fleet_config::to_fleet_peers.
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "seed1");
        assert_eq!(peers[0].rpc_url, "http://1.2.3.4:28081");
        // Cleanup.
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tip_state_returns_error_when_no_rpc_client_configured() {
        // `with_defaults()` builds an adapter WITHOUT an RPC client
        // for tests that only exercise privacy-contract methods.
        // `tip_state` returns a graceful error rather than panicking.
        let adapter = CoincyncAdapter::with_defaults();
        let err = adapter.tip_state().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("no local RPC client"),
            "expected 'no RPC client' error, got: {}",
            msg
        );
    }

    #[test]
    fn broadcast_notice_is_noop_in_phase_1c() {
        let adapter = CoincyncAdapter::with_defaults();
        let notice = TickNotice {
            kind: tick::TickNoticeKind::Alert,
            text: "test".into(),
            severity: tick::Severity::Info,
            tick_id: "t".into(),
            mode: 1,
            emitted_at: 100,
            expires_at: 200,
            signature: [0u8; 64],
        };
        // Should return Ok(()) — RescueTick's emit_notice depends on
        // notice broadcast being best-effort, not error-returning.
        adapter.broadcast_notice(&notice).unwrap();
    }

    #[test]
    fn config_toml_deserializes_personal() {
        let raw = r#"
deployment_mode = "personal"
local_rpc_url = "http://127.0.0.1:28081"
"#;
        let cfg: CoincyncAdapterConfig = toml::from_str(raw).expect("should parse");
        assert_eq!(cfg.deployment_mode, DeploymentModeStr::Personal);
        assert_eq!(cfg.local_rpc_url, "http://127.0.0.1:28081");
    }

    #[test]
    fn config_toml_deserializes_fleet() {
        let raw = r#"
deployment_mode = "fleet"
fleet_config_path = "/etc/coincync/fleet.json"
"#;
        let cfg: CoincyncAdapterConfig = toml::from_str(raw).expect("should parse");
        assert_eq!(cfg.deployment_mode, DeploymentModeStr::Fleet);
        assert_eq!(
            cfg.fleet_config_path,
            PathBuf::from("/etc/coincync/fleet.json")
        );
    }

    #[test]
    fn config_toml_missing_fields_use_defaults() {
        let raw = r#""#;
        let cfg: CoincyncAdapterConfig = toml::from_str(raw).expect("empty toml should parse");
        assert_eq!(cfg.deployment_mode, DeploymentModeStr::Personal);
        assert_eq!(cfg.local_rpc_url, "http://127.0.0.1:28081");
    }

    // ─── Integration test: tip_state end-to-end via mock RPC ────────

    /// Spawn a one-shot HTTP server that returns `body` (already
    /// wrapped as a JSON-RPC response with `result`) and closes.
    /// Returns the URL. Reused by multiple tests below.
    fn spawn_one_shot_json_rpc_result(result_json: String) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.read(&mut buf);
                let response_body =
                    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#, result_json);
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    response_body.len(),
                    response_body,
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    #[test]
    fn tip_state_round_trips_via_mock_rpc_server() {
        let url = spawn_one_shot_json_rpc_result(
            r#"{
            "height": 9569,
            "total_difficulty": "720000000",
            "top_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "is_synced": true,
            "peer_count": 8,
            "tip_age_secs": 12
        }"#
            .to_string(),
        );

        let cfg = CoincyncAdapterConfig {
            local_rpc_url: url,
            ..CoincyncAdapterConfig::default()
        };
        let adapter = CoincyncAdapter::new(cfg, None).expect("adapter build");
        let tip = adapter.tip_state().expect("tip_state should succeed");
        assert_eq!(tip.height, 9569);
        assert_eq!(tip.difficulty, 720_000_000);
        assert!(tip.is_synced);
        assert_eq!(tip.peer_count, 8);
        assert_eq!(tip.tip_age_secs, 12);
    }

    // ─── verify_peer_header_pow ────────────────────────────────────

    /// Build a mock get_block_by_height response from a real Block.
    /// The `bytes` field is the hex-encoded borsh serialization.
    fn mock_get_block_response(block: &crate::consensus::Block) -> String {
        let block_bytes = borsh::to_vec(block).expect("borsh serialize");
        format!(r#"{{"bytes":"{}"}}"#, hex::encode(&block_bytes))
    }

    #[test]
    fn verify_peer_header_pow_accepts_genesis_via_height_0_exemption() {
        // Genesis (height 0) is exempt from PoW verification — matches
        // consensus behavior at src/consensus/validation.rs:197.
        // Adapter should return Ok(true) via the fast path without
        // attempting verify_pow (which would reject genesis since
        // genesis has no real PoW).
        let genesis = crate::testnet::testnet_genesis();
        assert_eq!(genesis.header.height, 0, "test fixture assumption");
        let url = spawn_one_shot_json_rpc_result(mock_get_block_response(&genesis));

        let adapter = CoincyncAdapter::new(
            CoincyncAdapterConfig {
                local_rpc_url: "http://127.0.0.1:1".into(),
                ..CoincyncAdapterConfig::default()
            },
            None,
        )
        .expect("adapter build");
        let peer = FleetPeer {
            name: "canonical".into(),
            rpc_url: url,
            role: "miner".into(),
        };
        let verdict = adapter
            .verify_peer_header_pow(&peer, 0)
            .expect("should return Ok");
        assert!(
            verdict,
            "verify_peer_header_pow(genesis) must return Ok(true) via height-0 exemption"
        );
    }

    #[test]
    fn verify_peer_header_pow_rejects_spoofed_non_genesis_block() {
        // Take genesis, bump height to 1 (leaves height-0 exemption
        // branch), keep the rest of the header. verify_pow will
        // reject this because it'll try to check the anchor + RandomX
        // hash against a block that WAS genesis's PoW-less shape.
        // Adapter must return Ok(false) — NOT Err — because the peer
        // is ACTIVELY lying about their chain (distinction matters
        // for RescueTick's alert severity).
        let mut spoofed = crate::testnet::testnet_genesis();
        spoofed.header.height = 1; // move out of the height-0 exemption
        let url = spawn_one_shot_json_rpc_result(mock_get_block_response(&spoofed));

        let adapter = CoincyncAdapter::new(
            CoincyncAdapterConfig {
                local_rpc_url: "http://127.0.0.1:1".into(),
                ..CoincyncAdapterConfig::default()
            },
            None,
        )
        .expect("adapter build");
        let peer = FleetPeer {
            name: "spoofer".into(),
            rpc_url: url,
            role: "miner".into(),
        };
        let verdict = adapter
            .verify_peer_header_pow(&peer, 0)
            .expect("should return Ok, not Err (peer is actively lying, not unreachable)");
        assert!(
            !verdict,
            "verify_peer_header_pow(spoofed) must return Ok(false)"
        );
    }

    #[test]
    fn verify_peer_header_pow_returns_err_on_unreachable_peer() {
        let adapter =
            CoincyncAdapter::new(CoincyncAdapterConfig::default(), None).expect("adapter build");
        // Point at a port with nothing listening → connection refused.
        let peer = FleetPeer {
            name: "unreachable".into(),
            rpc_url: "http://127.0.0.1:1".into(),
            role: "miner".into(),
        };
        let err = adapter
            .verify_peer_header_pow(&peer, 0)
            .expect_err("should return Err on unreachable");
        assert!(
            matches!(err, tick::TickError::Unreachable(_)),
            "expected Unreachable, got: {:?}",
            err
        );
    }

    #[test]
    fn verify_peer_header_pow_returns_err_on_bad_borsh_bytes() {
        // Peer returns valid JSON with a `bytes` field, but the hex
        // decodes to nonsense that borsh can't deserialize into a Block.
        let url = spawn_one_shot_json_rpc_result(r#"{"bytes":"deadbeef"}"#.to_string());

        let adapter =
            CoincyncAdapter::new(CoincyncAdapterConfig::default(), None).expect("adapter build");
        let peer = FleetPeer {
            name: "confused".into(),
            rpc_url: url,
            role: "miner".into(),
        };
        let err = adapter
            .verify_peer_header_pow(&peer, 0)
            .expect_err("should return Err on bad borsh");
        // Bad response is `Other`, not `Unreachable` — the network
        // path worked, the peer just returned unusable data.
        assert!(
            matches!(err, tick::TickError::Other(_)),
            "expected Other, got: {:?}",
            err
        );
    }

    // ─── aggregate_from_tips (pure function) ───────────────────────

    fn mk_tip(
        difficulty: u128,
        peer_count: u32,
        tip_age_secs: u64,
    ) -> tick::ChainTipState<BlockIdBytes> {
        tick::ChainTipState {
            height: 0,
            difficulty,
            tip_id: BlockIdBytes(Hash::from_bytes([0u8; 32])),
            is_synced: true,
            peer_count,
            tip_age_secs,
        }
    }

    #[test]
    fn aggregate_empty_fleet_returns_zeros() {
        let agg = aggregate_from_tips(&Vec::<tick::ChainTipState<BlockIdBytes>>::new(), 0, 0);
        assert_eq!(agg.total_hosts, 0);
        assert_eq!(agg.stalled_count, 0);
        assert_eq!(agg.low_peer_count, 0);
        assert_eq!(agg.divergent_count, 0);
        assert_eq!(agg.median_difficulty, 0);
    }

    #[test]
    fn aggregate_counts_stalled_hosts() {
        // 4 hosts: 2 with tip_age > 300s → stalled; 2 fresh.
        let tips = vec![
            mk_tip(100, 5, 1200), // stalled
            mk_tip(100, 5, 30),   // fresh
            mk_tip(100, 5, 500),  // stalled
            mk_tip(100, 5, 10),   // fresh
        ];
        let agg = aggregate_from_tips(&tips, 0, 4);
        assert_eq!(agg.stalled_count, 2);
        assert_eq!(agg.total_hosts, 4);
    }

    #[test]
    fn aggregate_counts_low_peer_count_hosts_plus_unreachable() {
        // 3 probed hosts: 1 with peer_count < 3, 2 fine. Plus 2
        // unreachable — those also count as low_peer_count.
        let tips = vec![
            mk_tip(100, 1, 12), // low
            mk_tip(100, 5, 12), // fine
            mk_tip(100, 4, 12), // fine
        ];
        let agg = aggregate_from_tips(&tips, 2, 5);
        assert_eq!(agg.low_peer_count, 3); // 1 low + 2 unreachable
    }

    #[test]
    fn aggregate_flags_divergent_hosts_at_5pct_delta() {
        // 4 hosts. Median = 100. One host at 106 (6% above median) →
        // divergent. One at 94 (6% below) → also divergent. Two at
        // 100 (0%) → not divergent.
        //
        // The median-100 host itself counts as "0% delta" → NOT
        // divergent.
        let tips = vec![
            mk_tip(100, 5, 12),
            mk_tip(100, 5, 12),
            mk_tip(106, 5, 12), // 6% above → divergent
            mk_tip(94, 5, 12),  // 6% below → divergent
        ];
        let agg = aggregate_from_tips(&tips, 0, 4);
        assert_eq!(agg.divergent_count, 2);
        assert_eq!(agg.median_difficulty, 100);
    }

    #[test]
    fn aggregate_does_not_flag_hosts_within_delta_threshold() {
        // All hosts within 3% of median → 0 divergent.
        let tips = vec![
            mk_tip(100, 5, 12),
            mk_tip(102, 5, 12),
            mk_tip(103, 5, 12),
            mk_tip(99, 5, 12),
        ];
        let agg = aggregate_from_tips(&tips, 0, 4);
        assert_eq!(agg.divergent_count, 0);
    }

    #[test]
    fn aggregate_reports_correct_median_for_odd_count() {
        // 5 hosts sorted: 50, 100, 200, 300, 400. Median = 200.
        let tips = vec![
            mk_tip(50, 5, 12),
            mk_tip(400, 5, 12),
            mk_tip(200, 5, 12),
            mk_tip(300, 5, 12),
            mk_tip(100, 5, 12),
        ];
        let agg = aggregate_from_tips(&tips, 0, 5);
        assert_eq!(agg.median_difficulty, 200);
    }

    #[test]
    fn aggregate_fleet_health_uses_agg_math_when_probes_fail() {
        // Adapter with no fleet config → fleet_peers() empty → no
        // probes attempted → aggregate reports all-zeros.
        let adapter = CoincyncAdapter::with_defaults();
        let agg = adapter.aggregate_fleet_health().expect("Ok");
        assert_eq!(agg.total_hosts, 0);
        assert_eq!(agg.low_peer_count, 0);
    }

    // ─── rebroadcast_block (Phase 1g) ──────────────────────────────

    /// Build a JSON-RPC success-response body wrapping `result_json`.
    fn wrap_rpc_result(result_json: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#, result_json)
    }

    /// Spawn a one-shot HTTP server that serves the given HTTP body
    /// verbatim (caller pre-builds the full JSON-RPC envelope). Returns
    /// the URL.
    fn spawn_one_shot_verbatim(body: String) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    /// Spawn a one-shot server that captures the request's
    /// `Authorization` header and serves a valid `get_info` result.
    /// Returns `(url, receiver)`; the receiver yields the captured
    /// header value (or `None` if the request carried no auth header).
    fn spawn_one_shot_capture_auth(
        result_json: String,
    ) -> (String, std::sync::mpsc::Receiver<Option<String>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                // Case-insensitive scan for the Authorization header.
                let auth = req.lines().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("authorization") {
                        Some(v.trim().to_string())
                    } else {
                        None
                    }
                });
                let _ = tx.send(auth);
                let response_body =
                    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#, result_json);
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    response_body.len(),
                    response_body,
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{}", addr), rx)
    }

    #[test]
    fn probe_peer_sends_shared_fleet_bearer_to_peer() {
        // Regression guard for the fleet-auth wiring: an adapter built
        // with a bearer token must forward it as
        // `Authorization: Bearer <token>` on cross-fleet calls, so an
        // auth-required peer host doesn't 401. If a call site is ever
        // reverted to `None`, this fails.
        let info =
            r#"{"height":1,"total_difficulty":"1","top_hash":"","is_synced":true,"peer_count":3}"#;
        let (url, rx) = spawn_one_shot_capture_auth(info.to_string());

        let adapter = CoincyncAdapter::new(
            CoincyncAdapterConfig {
                local_rpc_url: "http://127.0.0.1:1".into(),
                ..CoincyncAdapterConfig::default()
            },
            Some("s3cr3t-tick-token".into()),
        )
        .expect("adapter");
        let peer = FleetPeer {
            name: "seed1".into(),
            rpc_url: url,
            role: "seed".into(),
        };
        adapter.probe_peer(&peer).expect("probe should succeed");

        let captured = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("server should have received the request");
        assert_eq!(
            captured.as_deref(),
            Some("Bearer s3cr3t-tick-token"),
            "probe_peer must forward the shared fleet bearer to the peer"
        );
    }

    #[test]
    fn adapter_debug_redacts_bearer_token() {
        // Key hygiene (rule A.6): the bearer must never appear in Debug
        // output. `{:?}` on the adapter must not leak the token.
        let adapter = CoincyncAdapter::new(
            CoincyncAdapterConfig::default(),
            Some("s3cr3t-tick-token".into()),
        )
        .expect("adapter");
        let dbg = format!("{:?}", adapter);
        assert!(
            !dbg.contains("s3cr3t-tick-token"),
            "adapter Debug leaked the bearer token: {}",
            dbg
        );
        assert!(
            dbg.contains("<redacted>"),
            "adapter Debug should mark the bearer as <redacted>: {}",
            dbg
        );
    }

    #[test]
    fn rebroadcast_block_fetches_local_and_submits_to_target() {
        // Local RPC returns genesis's bytes via get_block. Target
        // RPC accepts via submit_block. Adapter should succeed.
        let genesis = crate::testnet::testnet_genesis();
        let genesis_hash_hex = hex::encode(genesis.hash().as_bytes());
        let genesis_bytes_hex = hex::encode(borsh::to_vec(&genesis).unwrap());

        // Local server: responds to get_block with the genesis bytes.
        let local_url = spawn_one_shot_verbatim(wrap_rpc_result(&format!(
            r#"{{"bytes":"{}"}}"#,
            genesis_bytes_hex
        )));

        // Target server: responds to submit_block with accepted=true.
        let target_url = spawn_one_shot_verbatim(wrap_rpc_result(&format!(
            r#"{{"accepted":true,"hash":"{}"}}"#,
            genesis_hash_hex
        )));

        let cfg = CoincyncAdapterConfig {
            local_rpc_url: local_url,
            ..CoincyncAdapterConfig::default()
        };
        let adapter = CoincyncAdapter::new(cfg, None).expect("adapter");
        let target_peer = FleetPeer {
            name: "target".into(),
            rpc_url: target_url,
            role: "seed".into(),
        };
        adapter
            .rebroadcast_block(&BlockIdBytes(genesis.hash()), &target_peer)
            .expect("should succeed on happy path");
    }

    #[test]
    fn rebroadcast_block_returns_err_when_local_has_no_block() {
        // Local RPC returns a JSON-RPC error saying "block not found".
        // Adapter must return TickError::Other; MUST NOT proceed to
        // submit anything to the target.
        let local_url = spawn_one_shot_verbatim(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"block with hash 1234 not found"}}"#
                .to_string(),
        );
        let cfg = CoincyncAdapterConfig {
            local_rpc_url: local_url,
            ..CoincyncAdapterConfig::default()
        };
        let adapter = CoincyncAdapter::new(cfg, None).expect("adapter");
        let target_peer = FleetPeer {
            name: "target".into(),
            rpc_url: "http://127.0.0.1:1".into(), // never contacted
            role: "seed".into(),
        };
        let err = adapter
            .rebroadcast_block(&BlockIdBytes(Hash::from_bytes([0xAB; 32])), &target_peer)
            .unwrap_err();
        // Not-found is a JSON-RPC error (code -32000) → Other.
        assert!(matches!(err, tick::TickError::Other(_)));
    }

    #[test]
    fn rebroadcast_block_returns_err_on_unreachable_target() {
        // Local RPC has the block. Target port has nothing listening.
        // Adapter must return TickError::Unreachable (the local
        // fetch succeeded; only the target push failed at transport).
        let genesis = crate::testnet::testnet_genesis();
        let genesis_bytes_hex = hex::encode(borsh::to_vec(&genesis).unwrap());
        let local_url = spawn_one_shot_verbatim(wrap_rpc_result(&format!(
            r#"{{"bytes":"{}"}}"#,
            genesis_bytes_hex
        )));

        let cfg = CoincyncAdapterConfig {
            local_rpc_url: local_url,
            ..CoincyncAdapterConfig::default()
        };
        let adapter = CoincyncAdapter::new(cfg, None).expect("adapter");
        let target_peer = FleetPeer {
            name: "unreachable".into(),
            rpc_url: "http://127.0.0.1:1".into(),
            role: "seed".into(),
        };
        let err = adapter
            .rebroadcast_block(&BlockIdBytes(genesis.hash()), &target_peer)
            .unwrap_err();
        assert!(
            matches!(err, tick::TickError::Unreachable(_)),
            "got: {:?}",
            err
        );
    }

    #[test]
    fn rebroadcast_block_returns_err_when_target_rejects() {
        // Local RPC returns bytes. Target RPC returns accepted=false.
        // (Coincync's real submit_block uses a JSON-RPC error on
        // rejection — but a hypothetical peer returning accepted=false
        // is also possible under partial-compatibility scenarios.
        // Adapter should surface that clearly.)
        let genesis = crate::testnet::testnet_genesis();
        let genesis_bytes_hex = hex::encode(borsh::to_vec(&genesis).unwrap());
        let local_url = spawn_one_shot_verbatim(wrap_rpc_result(&format!(
            r#"{{"bytes":"{}"}}"#,
            genesis_bytes_hex
        )));
        let target_url = spawn_one_shot_verbatim(wrap_rpc_result(
            r#"{"accepted":false,"hash":"","status":"rejected"}"#,
        ));

        let cfg = CoincyncAdapterConfig {
            local_rpc_url: local_url,
            ..CoincyncAdapterConfig::default()
        };
        let adapter = CoincyncAdapter::new(cfg, None).expect("adapter");
        let target_peer = FleetPeer {
            name: "picky".into(),
            rpc_url: target_url,
            role: "seed".into(),
        };
        let err = adapter
            .rebroadcast_block(&BlockIdBytes(genesis.hash()), &target_peer)
            .unwrap_err();
        assert!(matches!(err, tick::TickError::Other(_)));
        let msg = format!("{}", err);
        assert!(
            msg.contains("did not accept"),
            "expected 'did not accept' in msg; got: {}",
            msg
        );
    }
}
