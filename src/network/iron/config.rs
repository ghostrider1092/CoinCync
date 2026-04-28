//! # IronConsensus Configuration
//!
//! Every tunable parameter in one struct, with presets for common chain types.

use std::time::Duration;

/// Full configuration for IronConsensus.
#[derive(Debug, Clone)]
pub struct IronConfig {
    // -- Tick rate --
    pub tick_interval: Duration,

    // -- Lag detection --
    pub lag_trigger_blocks: u64,

    // -- Tip stall --
    pub tip_stall_secs: u64,

    // -- Sync stall --
    pub sync_stall_secs: u64,

    // -- Fork resolution --
    pub max_auto_reorg: u64,
    pub enforce_chain_weight: bool,

    // -- Peer scoring --
    pub bad_block_limit: u32,
    pub timeout_limit: u32,
    pub orphan_limit: u32,
    pub ban_base: Duration,
    pub ban_max: Duration,
    pub bans_persist: bool,

    // -- Connection management --
    pub min_outbound_peers: usize,
    pub target_outbound_peers: usize,
    pub partition_declare_secs: u64,
    pub partition_emergency_dial: bool,

    // -- Security --
    pub max_height_lead: u64,
    pub future_block_tolerance_secs: u64,
    pub quick_pow_check: bool,
    pub enforce_difficulty_floor: bool,

    // -- Admin controls --
    pub force_height_rate_limit: u32,
    pub force_height_requires_hash: bool,

    // -- Rollback --
    pub rollback_cooldown_secs: u64,

    // -- Audit log --
    pub audit_log_path: Option<std::path::PathBuf>,
    pub audit_log_max_bytes: u64,
    pub audit_log_keep_files: u32,

    // -- Metrics --
    pub metrics_enabled: bool,

    // -- Alerting --
    pub alert_webhook_url: Option<String>,
    pub alert_webhook_timeout: Duration,
}

impl IronConfig {
    /// Zero-tolerance mode — CoinCync's defaults.
    /// Tuned for a small seed network: strict enough to punish real misbehavior,
    /// lenient enough to survive bootstrap when all nodes start on different forks.
    pub fn zero_tolerance() -> Self {
        IronConfig {
            tick_interval:                Duration::from_secs(2),
            lag_trigger_blocks:           0,
            tip_stall_secs:               30,
            sync_stall_secs:              20,
            max_auto_reorg:               u64::MAX,
            enforce_chain_weight:         true,
            bad_block_limit:              3,   // 3 strikes (was 1 — too aggressive during bootstrap)
            timeout_limit:                5,   // 5 timeouts (was 1 — network latency is normal)
            orphan_limit:                 10,  // 10 orphans (was 2 — orphans are common during sync)
            ban_base:                     Duration::from_secs(300),     // 5min (was 30min)
            ban_max:                      Duration::from_secs(86_400),  // 24hr (was 7 days)
            bans_persist:                 true,
            min_outbound_peers:           1,
            target_outbound_peers:        8,
            partition_declare_secs:       30,
            partition_emergency_dial:     true,
            max_height_lead:              500,
            future_block_tolerance_secs:  7_200,
            quick_pow_check:              true,
            enforce_difficulty_floor:     true,
            force_height_rate_limit:      2,
            force_height_requires_hash:   true,
            rollback_cooldown_secs:       0,
            audit_log_path:               None,
            audit_log_max_bytes:          100_000_000,
            audit_log_keep_files:         10,
            metrics_enabled:              true,
            alert_webhook_url:            None,
            alert_webhook_timeout:        Duration::from_secs(5),
        }
    }

    /// Standard mode — reasonable defaults for most public chains.
    pub fn standard() -> Self {
        IronConfig {
            tick_interval:                Duration::from_secs(4),
            lag_trigger_blocks:           2,
            tip_stall_secs:               90,
            sync_stall_secs:              60,
            max_auto_reorg:               50,
            rollback_cooldown_secs:       60,
            bad_block_limit:              3,
            timeout_limit:                3,
            orphan_limit:                 5,
            ban_base:                     Duration::from_secs(300),
            ban_max:                      Duration::from_secs(86_400),
            partition_declare_secs:       60,
            ..Self::zero_tolerance()
        }
    }

    /// Validate the config.
    pub fn validate(&self) -> Result<(), String> {
        if self.tick_interval.is_zero() {
            return Err("tick_interval must be > 0".into());
        }
        if self.min_outbound_peers > self.target_outbound_peers {
            return Err("min_outbound_peers must be <= target_outbound_peers".into());
        }
        if self.ban_base > self.ban_max {
            return Err("ban_base must be <= ban_max".into());
        }
        if self.bad_block_limit == 0 {
            return Err("bad_block_limit must be >= 1".into());
        }
        Ok(())
    }
}

impl Default for IronConfig {
    fn default() -> Self { Self::zero_tolerance() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_presets_are_valid() {
        IronConfig::zero_tolerance().validate().unwrap();
        IronConfig::standard().validate().unwrap();
    }

    #[test]
    fn invalid_config_rejected() {
        let mut cfg = IronConfig::standard();
        cfg.min_outbound_peers = 10;
        cfg.target_outbound_peers = 5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_tolerance_has_zero_lag_trigger() {
        assert_eq!(IronConfig::zero_tolerance().lag_trigger_blocks, 0);
    }
}
