//! `MockAdapter` — a `ChainAdapter` implementation for testing that
//! doesn't touch a real chain.
//!
//! Gated behind the `mock` feature so it can't accidentally end up in
//! production binaries. Downstream crates depend on it only via
//! `[dev-dependencies]`.
//!
//! The mock is deliberately minimal: it stores its state in
//! `Arc<Mutex<...>>` so tests can mutate it externally to drive the
//! adapter into interesting scenarios (e.g., "make host X divergent
//! by 100 blocks and confirm RescueTick triggers").

use std::sync::{Arc, Mutex};

use crate::adapter::ChainAdapter;
use crate::types::*;

/// A block ID for testing. Wraps `[u8; 32]` so it satisfies the trait
/// bounds without pulling in a real chain's block-hash type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MockBlockId(pub [u8; 32]);

impl AsRef<[u8]> for MockBlockId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl MockBlockId {
    /// Build a block ID by tagging the first 8 bytes with a `u64` and
    /// zero-filling the rest. Convenient for tests that want distinct
    /// but predictable IDs.
    pub fn from_tag(tag: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&tag.to_be_bytes());
        MockBlockId(bytes)
    }
}

/// A tx ID for testing. Same shape as `MockBlockId`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MockTxId(pub [u8; 32]);

impl AsRef<[u8]> for MockTxId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl MockTxId {
    /// Build a tx ID by tagging the first 8 bytes with a `u64`.
    pub fn from_tag(tag: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&tag.to_be_bytes());
        MockTxId(bytes)
    }
}

/// A peer ID for testing. Just a `u32` under the hood.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MockPeerId(pub u32);

/// Inner state shared across `MockAdapter` clones (so tests can mutate
/// state via one handle while the tick runs on another).
#[derive(Debug)]
struct MockState {
    tip: ChainTipState<MockBlockId>,
    fleet: Vec<FleetPeer>,
    peer_tips: std::collections::HashMap<String, ChainTipState<MockBlockId>>,
    /// Per-peer PoW-verify verdict. Missing entry ⇒ Err (adapter can't
    /// verify — treated as "refuse to feed"). Present entry ⇒ that
    /// bool is returned by `verify_peer_header_pow`.
    peer_pow_verdicts: std::collections::HashMap<String, bool>,
    stem_txs: std::collections::HashSet<MockTxId>,
    stem_relays: Vec<MockPeerId>,
    health: HealthSnapshot,
    aggregate_health: AggregateFleetHealth,
    deployment: DeploymentMode,
    // Log of things the mock was asked to do; tests inspect this to
    // verify behavior.
    pub broadcast_log: Vec<TickNotice>,
    pub rebroadcast_log: Vec<(MockBlockId, MockPeerId)>,
    pub snapshot_calls: usize,
    pub apply_calls: usize,
}

impl Default for MockState {
    fn default() -> Self {
        MockState {
            tip: ChainTipState {
                height: 0,
                difficulty: 0,
                tip_id: MockBlockId([0u8; 32]),
                is_synced: true,
                peer_count: 0,
                tip_age_secs: 0,
            },
            fleet: Vec::new(),
            peer_tips: std::collections::HashMap::new(),
            peer_pow_verdicts: std::collections::HashMap::new(),
            stem_txs: std::collections::HashSet::new(),
            stem_relays: Vec::new(),
            health: HealthSnapshot {
                ram_used_pct: 0,
                disk_used_pct: 0,
                swap_used_pct: 0,
                hashrate_hs: None,
                mempool_txs: 0,
                cpu_used_pct: 0,
                uptime_secs: 0,
            },
            aggregate_health: AggregateFleetHealth {
                total_hosts: 0,
                stalled_count: 0,
                low_peer_count: 0,
                divergent_count: 0,
                median_difficulty: 0,
                high_ram_count: 0,
                high_disk_count: 0,
            },
            deployment: DeploymentMode::Personal,
            broadcast_log: Vec::new(),
            rebroadcast_log: Vec::new(),
            snapshot_calls: 0,
            apply_calls: 0,
        }
    }
}

/// The `ChainAdapter` used by tests. Cheap to `.clone()`; multiple
/// clones share the same underlying `Mutex`-protected state.
#[derive(Clone, Debug)]
pub struct MockAdapter {
    inner: Arc<Mutex<MockState>>,
}

impl Default for MockAdapter {
    fn default() -> Self {
        MockAdapter::new()
    }
}

impl MockAdapter {
    /// Build a mock in the default steady state (no fleet, no
    /// anomalies, `DeploymentMode::Personal`).
    pub fn new() -> Self {
        MockAdapter {
            inner: Arc::new(Mutex::new(MockState::default())),
        }
    }

    /// Overwrite the local tip state. Used by tests to drive the
    /// adapter into "stalled" or "advancing" scenarios.
    pub fn set_tip(&self, tip: ChainTipState<MockBlockId>) {
        self.inner.lock().unwrap().tip = tip;
    }

    /// Register a fleet peer and the state `probe_peer` will report
    /// for it.
    pub fn add_fleet_peer(&self, peer: FleetPeer, state: ChainTipState<MockBlockId>) {
        let mut inner = self.inner.lock().unwrap();
        inner.peer_tips.insert(peer.name.clone(), state);
        inner.fleet.push(peer);
    }

    /// Set the verdict `verify_peer_header_pow` will return for the
    /// named peer. `Some(true)` → peer's headers verify; `Some(false)`
    /// → peer is lying; `None` → `verify_peer_header_pow` returns
    /// `Err` (adapter can't verify, RescueTick treats as
    /// "refuse to feed").
    pub fn set_peer_pow_verdict(&self, peer_name: &str, verdict: Option<bool>) {
        let mut inner = self.inner.lock().unwrap();
        match verdict {
            Some(v) => { inner.peer_pow_verdicts.insert(peer_name.into(), v); }
            None => { inner.peer_pow_verdicts.remove(peer_name); }
        }
    }

    /// Mark a tx as being in stem phase. `is_stem_phase` will return
    /// `true` for this ID until removed.
    pub fn mark_stem_tx(&self, tx_id: MockTxId) {
        self.inner.lock().unwrap().stem_txs.insert(tx_id);
    }

    /// Register a stem-relay peer. `stem_relay_peers` returns these.
    pub fn add_stem_relay(&self, peer: MockPeerId) {
        self.inner.lock().unwrap().stem_relays.push(peer);
    }

    /// Override the health snapshot returned by `health_snapshot`.
    pub fn set_health(&self, health: HealthSnapshot) {
        self.inner.lock().unwrap().health = health;
    }

    /// Override the aggregate fleet health returned by
    /// `aggregate_fleet_health`.
    pub fn set_aggregate_health(&self, agg: AggregateFleetHealth) {
        self.inner.lock().unwrap().aggregate_health = agg;
    }

    /// Change the deployment mode reported by the adapter.
    pub fn set_deployment_mode(&self, mode: DeploymentMode) {
        self.inner.lock().unwrap().deployment = mode;
    }

    /// Return the notices this mock has been asked to broadcast, in
    /// order. Tests inspect this to verify tick emission.
    pub fn broadcast_log(&self) -> Vec<TickNotice> {
        self.inner.lock().unwrap().broadcast_log.clone()
    }

    /// Return the (block, peer) pairs `rebroadcast_block` was called
    /// with, in order.
    pub fn rebroadcast_log(&self) -> Vec<(MockBlockId, MockPeerId)> {
        self.inner.lock().unwrap().rebroadcast_log.clone()
    }

    /// Return the number of times `snapshot_chaindata` was called.
    pub fn snapshot_calls(&self) -> usize {
        self.inner.lock().unwrap().snapshot_calls
    }

    /// Return the number of times `apply_chaindata` was called.
    pub fn apply_calls(&self) -> usize {
        self.inner.lock().unwrap().apply_calls
    }
}

impl ChainAdapter for MockAdapter {
    type BlockId = MockBlockId;
    type TxId = MockTxId;
    type PeerId = MockPeerId;

    fn tip_state(&self) -> TickResult<ChainTipState<Self::BlockId>> {
        Ok(self.inner.lock().unwrap().tip.clone())
    }

    fn fleet_peers(&self) -> Vec<FleetPeer> {
        self.inner.lock().unwrap().fleet.clone()
    }

    fn probe_peer(&self, peer: &FleetPeer) -> TickResult<ChainTipState<Self::BlockId>> {
        self.inner
            .lock()
            .unwrap()
            .peer_tips
            .get(&peer.name)
            .cloned()
            .ok_or_else(|| TickError::Unreachable(format!("no mock tip for peer {}", peer.name)))
    }

    fn verify_peer_header_pow(
        &self,
        peer: &FleetPeer,
        _height: u64,
    ) -> TickResult<bool> {
        let inner = self.inner.lock().unwrap();
        match inner.peer_pow_verdicts.get(&peer.name) {
            Some(v) => Ok(*v),
            None => Err(TickError::Unreachable(format!(
                "no PoW verdict registered for peer {}", peer.name
            ))),
        }
    }

    fn snapshot_chaindata(
        &self,
        source: Option<&FleetPeer>,
        dest: &std::path::Path,
    ) -> TickResult<Snapshot> {
        let mut inner = self.inner.lock().unwrap();
        inner.snapshot_calls += 1;
        let tip = match source {
            Some(peer) => inner
                .peer_tips
                .get(&peer.name)
                .map(|t| t.tip_id.0.to_vec())
                .unwrap_or_else(|| inner.tip.tip_id.0.to_vec()),
            None => inner.tip.tip_id.0.to_vec(),
        };
        Ok(Snapshot {
            tarball_path: dest.to_path_buf(),
            sha256: [0u8; 32],
            source_tip: tip,
            compressed_bytes: 0,
        })
    }

    fn apply_chaindata(&self, _source: &std::path::Path) -> TickResult<()> {
        self.inner.lock().unwrap().apply_calls += 1;
        Ok(())
    }

    fn rebroadcast_block(
        &self,
        block_id: &Self::BlockId,
        to: &Self::PeerId,
    ) -> TickResult<()> {
        self.inner
            .lock()
            .unwrap()
            .rebroadcast_log
            .push((block_id.clone(), to.clone()));
        Ok(())
    }

    fn health_snapshot(&self) -> TickResult<HealthSnapshot> {
        Ok(self.inner.lock().unwrap().health.clone())
    }

    fn aggregate_fleet_health(&self) -> TickResult<AggregateFleetHealth> {
        Ok(self.inner.lock().unwrap().aggregate_health.clone())
    }

    fn is_stem_phase(&self, tx_id: &Self::TxId) -> bool {
        self.inner.lock().unwrap().stem_txs.contains(tx_id)
    }

    fn stem_relay_peers(&self) -> Vec<Self::PeerId> {
        self.inner.lock().unwrap().stem_relays.clone()
    }

    fn deployment_mode(&self) -> DeploymentMode {
        self.inner.lock().unwrap().deployment
    }

    fn broadcast_notice(&self, notice: &TickNotice) -> TickResult<()> {
        let mut inner = self.inner.lock().unwrap();
        // Enforce the deployment_mode contract even in tests — a mock
        // that ignored `Personal` would let tests pass with production
        // code that leaks. If `Personal`, silently no-op (log locally
        // only, per the contract).
        if inner.deployment == DeploymentMode::Personal {
            return Ok(());
        }
        inner.broadcast_log.push(notice.clone());
        Ok(())
    }
}
