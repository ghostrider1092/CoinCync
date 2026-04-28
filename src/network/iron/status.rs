//! # Engine Status and Runtime Controls
//!
//! `EngineStatus` — full snapshot of engine state at a point in time.
//! `PeerInspection` — per-peer score and ban info.
//! `ConfigPatch` — update tuning parameters at runtime without restart.

use std::time::Duration;
use serde::{Deserialize, Serialize};

use super::config::IronConfig;
use super::state::EngineState;

#[derive(Debug, Clone, Serialize)]
pub struct PeerInspection {
    pub peer_id_hex:       String,
    pub height:            u64,
    pub tip_hex:           String,
    pub total_diff:        u128,
    pub bad_blocks:        u32,
    pub orphans:           u32,
    pub timeouts:          u32,
    pub ban_count:         u32,
    pub is_banned:         bool,
    pub banned_until_secs: Option<u64>,
    pub proven_height:     u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineStatus {
    pub local_height:      u64,
    pub best_peer_height:  u64,
    pub lag_blocks:        u64,
    pub total_difficulty:  u128,
    pub tip_hex:           String,
    pub is_synced:         bool,
    pub state:             EngineState,
    pub secs_in_state:     u64,
    pub outbound_peers:    usize,
    pub inbound_peers:     usize,
    pub active_bans:       usize,
    pub known_addresses:   usize,
    pub tip_stalled_secs:  u64,
    pub partitioned:       bool,
    pub admin_locked:      bool,
    pub health_score:      f32,
    // L5 (audit fix): u64 — matches the engine struct counters. u32 wraps
    // are theoretical on multi-decade-uptime nodes, but the cost of u64 is
    // zero so we just promote and stop worrying about it.
    pub forks_detected:    u64,
    pub rollbacks:         u64,
    pub syncs_started:     u64,
    pub snapshot_unix_secs: u64,
}

/// FIX #21: canonical health score. Both `EngineStatus::compute_health`
/// AND `IronMetrics::update_health` previously computed their own scores
/// with different thresholds, so the Prometheus gauge and the status
/// snapshot returned different values for the same node state.
/// Consolidated here; both call sites use this function.
pub fn compute_health_score(
    lag:              u64,
    partitioned:      bool,
    forked:           bool,
    admin_locked:     bool,
    tip_stalled_secs: u64,
) -> f32 {
    if partitioned || admin_locked { return 0.0; }
    if forked                      { return 0.1; }
    if tip_stalled_secs >= 60      { return 0.5; }
    if lag > 50                    { return 0.3; }
    if lag > 10                    { return 0.5; }
    if lag > 2                     { return 0.7; }
    1.0
}

impl EngineStatus {
    pub fn compute_health(&self) -> f32 {
        compute_health_score(
            self.lag_blocks,
            self.partitioned,
            self.state == EngineState::Forked,
            self.admin_locked,
            self.tip_stalled_secs,
        )
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigPatch {
    pub lag_trigger_blocks:        Option<u64>,
    pub tip_stall_secs:            Option<u64>,
    pub sync_stall_secs:           Option<u64>,
    pub bad_block_limit:           Option<u32>,
    pub timeout_limit:             Option<u32>,
    pub orphan_limit:              Option<u32>,
    pub ban_base_secs:             Option<u64>,
    pub ban_max_secs:              Option<u64>,
    pub min_outbound_peers:        Option<usize>,
    pub target_outbound_peers:     Option<usize>,
    pub max_auto_reorg:            Option<u64>,
    pub enforce_chain_weight:      Option<bool>,
    pub alert_webhook_url:         Option<String>,
}

impl ConfigPatch {
    pub fn apply(&self, base: &IronConfig) -> Result<IronConfig, String> {
        let mut cfg = base.clone();

        if let Some(v) = self.lag_trigger_blocks    { cfg.lag_trigger_blocks    = v; }
        if let Some(v) = self.tip_stall_secs        { cfg.tip_stall_secs        = v; }
        if let Some(v) = self.sync_stall_secs       { cfg.sync_stall_secs       = v; }
        if let Some(v) = self.bad_block_limit       { cfg.bad_block_limit       = v; }
        if let Some(v) = self.timeout_limit         { cfg.timeout_limit         = v; }
        if let Some(v) = self.orphan_limit          { cfg.orphan_limit          = v; }
        if let Some(v) = self.ban_base_secs         { cfg.ban_base              = Duration::from_secs(v); }
        if let Some(v) = self.ban_max_secs          { cfg.ban_max               = Duration::from_secs(v); }
        if let Some(v) = self.min_outbound_peers    { cfg.min_outbound_peers    = v; }
        if let Some(v) = self.target_outbound_peers { cfg.target_outbound_peers = v; }
        if let Some(v) = self.max_auto_reorg        { cfg.max_auto_reorg        = v; }
        if let Some(v) = self.enforce_chain_weight  { cfg.enforce_chain_weight  = v; }
        if let Some(ref v) = self.alert_webhook_url { cfg.alert_webhook_url     = Some(v.clone()); }

        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_score_nominal() {
        let s = EngineStatus {
            local_height: 1000, best_peer_height: 1000,
            lag_blocks: 0, total_difficulty: 9999,
            tip_hex: "aabb".into(), is_synced: true,
            state: EngineState::Nominal, secs_in_state: 10,
            outbound_peers: 6, inbound_peers: 2, active_bans: 0,
            known_addresses: 50, tip_stalled_secs: 5,
            partitioned: false, admin_locked: false, health_score: 0.0,
            forks_detected: 0, rollbacks: 0, syncs_started: 1,
            snapshot_unix_secs: 0,
        };
        assert_eq!(s.compute_health(), 1.0);
    }

    #[test]
    fn health_score_partitioned_is_zero() {
        let s = EngineStatus {
            local_height: 1000, best_peer_height: 1000,
            lag_blocks: 0, total_difficulty: 9999,
            tip_hex: "aabb".into(), is_synced: true,
            state: EngineState::Nominal, secs_in_state: 10,
            outbound_peers: 0, inbound_peers: 0, active_bans: 0,
            known_addresses: 5, tip_stalled_secs: 5,
            partitioned: true, admin_locked: false, health_score: 0.0,
            forks_detected: 0, rollbacks: 0, syncs_started: 0,
            snapshot_unix_secs: 0,
        };
        assert_eq!(s.compute_health(), 0.0);
    }

    #[test]
    fn config_patch_validates() {
        let base = IronConfig::standard();
        let patch = ConfigPatch {
            lag_trigger_blocks: Some(5),
            bad_block_limit: Some(2),
            ..Default::default()
        };
        let updated = patch.apply(&base).unwrap();
        assert_eq!(updated.lag_trigger_blocks, 5);
        assert_eq!(updated.bad_block_limit, 2);
    }

    #[test]
    fn config_patch_rejects_invalid() {
        let base = IronConfig::standard();
        let patch = ConfigPatch {
            min_outbound_peers: Some(20),
            target_outbound_peers: Some(5),
            ..Default::default()
        };
        assert!(patch.apply(&base).is_err());
    }
}
