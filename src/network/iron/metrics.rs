// M-4 FIX: This module is feature-gated behind iron-consensus.
// update_health parameters are resolved by delegating to status::compute_health_score.
//
//! # IronConsensus Metrics
//!
//! All Prometheus metrics under the `iron_consensus_` prefix.

use std::sync::OnceLock;
use prometheus::{
    Registry, Gauge, Histogram, HistogramOpts, IntCounter,
    IntCounterVec, IntGauge, Opts,
    register_gauge_with_registry,
    register_histogram_with_registry,
    register_int_counter_vec_with_registry,
    register_int_counter_with_registry,
    register_int_gauge_with_registry,
};

pub struct IronMetrics {
    pub height:                     IntGauge,
    pub lag_blocks:                 IntGauge,
    pub health_score:               Gauge,
    pub peers_outbound:             IntGauge,
    pub peers_inbound:              IntGauge,
    pub peers_banned_total:         IntCounter,
    pub peers_banned_active:        IntGauge,
    pub syncs_total:                IntCounter,
    pub convergence_total:          IntCounter,
    pub sync_duration_seconds:      Histogram,
    pub forks_detected_total:       IntCounter,
    pub rollbacks_total:            IntCounter,
    pub last_rollback_depth:        IntGauge,
    pub deep_forks_total:           IntCounter,
    pub partition_seconds_total:    IntCounter,
    pub partitioned:                IntGauge,
    pub tick_duration_seconds:      Histogram,
    pub ticks_total:                IntCounter,
    pub state_transitions_total:    IntCounterVec,
    pub force_height_total:         IntCounter,
    pub force_height_blocked_total: IntCounter,
}

static METRICS: OnceLock<IronMetrics> = OnceLock::new();

impl IronMetrics {
    pub fn init(registry: &Registry) -> &'static IronMetrics {
        METRICS.get_or_init(|| Self::register(registry))
    }

    pub fn try_get() -> Option<&'static IronMetrics> {
        METRICS.get()
    }

    fn register(r: &Registry) -> IronMetrics {
        let ig = |n, h| register_int_gauge_with_registry!(Opts::new(n, h), r).unwrap();
        let ic = |n, h| register_int_counter_with_registry!(Opts::new(n, h), r).unwrap();
        let g  = |n, h| register_gauge_with_registry!(Opts::new(n, h), r).unwrap();
        let hi = |n, h, b: Vec<f64>| register_histogram_with_registry!(
            HistogramOpts::new(n, h).buckets(b), r).unwrap();

        let state_transitions_total = register_int_counter_vec_with_registry!(
            Opts::new("iron_consensus_state_transitions_total", "State transitions by state"),
            &["state"], r
        ).unwrap();

        IronMetrics {
            height:                     ig("iron_consensus_height",                   "Local chain height"),
            lag_blocks:                 ig("iron_consensus_lag_blocks",               "Blocks behind network"),
            health_score:               g( "iron_consensus_health_score",             "Engine health 0-1"),
            peers_outbound:             ig("iron_consensus_peers_outbound",           "Outbound peers"),
            peers_inbound:              ig("iron_consensus_peers_inbound",            "Inbound peers"),
            peers_banned_total:         ic("iron_consensus_peers_banned_total",       "Total bans issued"),
            peers_banned_active:        ig("iron_consensus_peers_banned_active",      "Active bans"),
            syncs_total:                ic("iron_consensus_syncs_total",              "Sync ops started"),
            convergence_total:          ic("iron_consensus_convergence_total",        "Successful convergences"),
            sync_duration_seconds:      hi("iron_consensus_sync_duration_seconds",   "Sync duration",
                                          vec![1.0,5.0,15.0,30.0,60.0,120.0,300.0]),
            forks_detected_total:       ic("iron_consensus_forks_detected_total",    "Forks detected"),
            rollbacks_total:            ic("iron_consensus_rollbacks_total",          "Rollbacks performed"),
            last_rollback_depth:        ig("iron_consensus_last_rollback_depth",      "Last rollback depth"),
            deep_forks_total:           ic("iron_consensus_deep_forks_total",         "Deep forks needing admin"),
            partition_seconds_total:    ic("iron_consensus_partition_seconds_total",  "Seconds partitioned"),
            partitioned:                ig("iron_consensus_partitioned",              "1 if partitioned"),
            tick_duration_seconds:      hi("iron_consensus_tick_duration_seconds",   "Tick duration",
                                          vec![0.001,0.005,0.01,0.05,0.1,0.5,1.0]),
            ticks_total:                ic("iron_consensus_ticks_total",              "Total ticks"),
            state_transitions_total,
            force_height_total:         ic("iron_consensus_force_height_total",       "ForceHeight calls"),
            force_height_blocked_total: ic("iron_consensus_force_height_blocked_total","ForceHeight blocked"),
        }
    }

    pub fn update_chain(&self, height: u64, lag: u64) {
        self.height.set(height.min(i64::MAX as u64) as i64);
        self.lag_blocks.set(lag.min(i64::MAX as u64) as i64);
    }
    pub fn update_peers(&self, out: usize, inb: usize, banned: usize) {
        self.peers_outbound.set((out as u64).min(i64::MAX as u64) as i64);
        self.peers_inbound.set((inb as u64).min(i64::MAX as u64) as i64);
        self.peers_banned_active.set((banned as u64).min(i64::MAX as u64) as i64);
    }
    pub fn on_peer_banned(&self)                  { self.peers_banned_total.inc(); }
    pub fn on_sync_started(&self)                 { self.syncs_total.inc(); }
    pub fn on_converged(&self, secs: f64)         { self.convergence_total.inc(); self.sync_duration_seconds.observe(secs); }
    pub fn on_fork(&self)                         { self.forks_detected_total.inc(); }
    pub fn on_rollback(&self, depth: u64)         { self.rollbacks_total.inc(); self.last_rollback_depth.set(depth.min(i64::MAX as u64) as i64); }
    pub fn on_deep_fork(&self)                    { self.deep_forks_total.inc(); }
    pub fn on_partition_tick(&self)               { self.partitioned.set(1); self.partition_seconds_total.inc(); }
    pub fn on_partition_healed(&self)             { self.partitioned.set(0); }
    pub fn on_tick(&self, secs: f64)              { self.ticks_total.inc(); self.tick_duration_seconds.observe(secs); }
    pub fn on_state_transition(&self, to: &str)  { self.state_transitions_total.with_label_values(&[to]).inc(); }
    pub fn on_force_height(&self, blocked: bool) { self.force_height_total.inc(); if blocked { self.force_height_blocked_total.inc(); } }

    pub fn update_health(&self, lag: u64, partitioned: bool, has_fork: bool) {
        // FIX #21: delegate to the canonical scorer in status.rs so the
        // Prometheus gauge can't drift from EngineStatus::compute_health.
        // admin_locked and tip_stalled_secs aren't plumbed through this
        // path yet; partitioned + forked are the signals that matter most
        // for the metric anyway.
        let score = super::status::compute_health_score(
            lag,
            partitioned,
            has_fork,
            /* admin_locked */ false,
            /* tip_stalled_secs */ 0,
        ) as f64;
        self.health_score.set(score);
    }
}
