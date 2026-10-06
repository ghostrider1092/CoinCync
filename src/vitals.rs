//! Chain vitals — a small, stable, versioned health schema.
//!
//! This is a deliberately tiny "boring standard": the minimum set of health
//! signals a monitoring tool, load balancer, or partition detector needs, with
//! an explicit `schema_version` so consumers can depend on it across releases.
//! `get_info` remains the kitchen-sink diagnostic endpoint; `get_vitals` is the
//! stable contract.
//!
//! The health-band classification here is the single source of truth for the
//! node's self-assessed status — `get_info` and `get_vitals` both call it, and
//! it mirrors the band rendering used by the TUI status bar. See
//! `docs/design/chain-vitals-schema.md`.
//!
//! Portability (help other chains): `HealthStatus::from_signals` +
//! `ChainVitals` depend on nothing CoinCync-specific — any chain can adopt the
//! same schema so cross-chain tooling (dashboards, `check-fleet-partition`-style
//! detectors, LB health checks) speaks one language.

use serde::{Deserialize, Serialize};

/// Bump when the [`ChainVitals`] wire schema changes in a breaking way. Additive
/// optional fields do not require a bump; removals/renames/retypes do.
pub const VITALS_SCHEMA_VERSION: u32 = 1;

/// A tip older than this (seconds) while otherwise synced-with-peers is treated
/// as stalled. Mirrors the original inline threshold in `get_info`.
pub const STALL_TIP_AGE_SECS: u64 = 300;

/// Minimum peers to be considered fully "healthy" (below this but > 0 is
/// "low-peers"). Mirrors the original inline threshold in `get_info`.
pub const MIN_HEALTHY_PEERS: u64 = 2;

/// The node's self-assessed health band. Ordered worst → best is not implied;
/// use [`HealthStatus::score`] for a numeric comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Not yet synced to the network tip.
    Syncing,
    /// Synced (or believed so) but with zero peers — effectively isolated.
    NoPeers,
    /// Synced with peers, but the tip has not advanced within
    /// [`STALL_TIP_AGE_SECS`].
    Stalled,
    /// Healthy except for a thin peer set (`0 < peers < MIN_HEALTHY_PEERS`).
    LowPeers,
    /// Everything nominal.
    Healthy,
}

impl HealthStatus {
    /// Stable lowercase label used on the wire (unchanged from the strings
    /// `get_info` has always emitted, so existing consumers keep working).
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthStatus::Syncing => "syncing",
            HealthStatus::NoPeers => "no-peers",
            HealthStatus::Stalled => "stalled",
            HealthStatus::LowPeers => "low-peers",
            HealthStatus::Healthy => "healthy",
        }
    }

    /// Numeric score in `[0.0, 1.0]`; 1.0 = nominal, 0.0 = worst. Values match
    /// the original `get_info` bands exactly.
    pub fn score(&self) -> f64 {
        match self {
            HealthStatus::Syncing => 0.5,
            HealthStatus::NoPeers => 0.2,
            HealthStatus::Stalled => 0.3,
            HealthStatus::LowPeers => 0.7,
            HealthStatus::Healthy => 1.0,
        }
    }

    /// Single source of truth for the health band. `tip_age_secs = None` means
    /// the wall clock was unreadable — treated as maximally stale (stalled),
    /// preserving `get_info`'s original `unwrap_or(u64::MAX)` behavior.
    pub fn from_signals(synced: bool, peer_count: u64, tip_age_secs: Option<u64>) -> Self {
        if !synced {
            return HealthStatus::Syncing;
        }
        if peer_count == 0 {
            return HealthStatus::NoPeers;
        }
        let age = tip_age_secs.unwrap_or(u64::MAX);
        if age > STALL_TIP_AGE_SECS {
            HealthStatus::Stalled
        } else if peer_count < MIN_HEALTHY_PEERS {
            HealthStatus::LowPeers
        } else {
            HealthStatus::Healthy
        }
    }
}

/// The stable, versioned chain-vitals record returned by `get_vitals`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVitals {
    /// Schema version of this record ([`VITALS_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Network name (`"mainnet"` / `"testnet"` / `"regtest"`).
    pub network: String,
    /// Active-tip height.
    pub height: u64,
    /// Active-tip hash, hex-encoded.
    pub tip_hash: String,
    /// Seconds since the tip's timestamp; `None` if the wall clock is unreadable.
    pub tip_age_secs: Option<u64>,
    /// Whether the node believes it is synced to the network tip.
    pub is_synced: bool,
    /// Connected peer count.
    pub peer_count: u64,
    /// Current difficulty, decimal string (may exceed u64).
    pub difficulty: String,
    /// Mempool transaction count.
    pub mempool_size: u64,
    /// Sustained mesh-floor state: connected peers have been below the mesh
    /// floor for a sustained period (see `network::node::MESH_FLOOR_PEERS`).
    /// Observational — a node can be `mesh_degraded` and still healthy-by-tip.
    pub mesh_degraded: bool,
    /// Health band label ([`HealthStatus::as_str`]).
    pub status: String,
    /// Health score in `[0.0, 1.0]` ([`HealthStatus::score`]).
    pub health_score: f64,
}

impl ChainVitals {
    /// Assemble vitals from raw node signals, deriving `status`/`health_score`
    /// from the single-source-of-truth [`HealthStatus::from_signals`].
    #[allow(clippy::too_many_arguments)]
    pub fn from_signals(
        network: impl Into<String>,
        height: u64,
        tip_hash: impl Into<String>,
        tip_age_secs: Option<u64>,
        is_synced: bool,
        peer_count: u64,
        difficulty: impl Into<String>,
        mempool_size: u64,
        mesh_degraded: bool,
    ) -> Self {
        let band = HealthStatus::from_signals(is_synced, peer_count, tip_age_secs);
        ChainVitals {
            schema_version: VITALS_SCHEMA_VERSION,
            network: network.into(),
            height,
            tip_hash: tip_hash.into(),
            tip_age_secs,
            is_synced,
            peer_count,
            difficulty: difficulty.into(),
            mempool_size,
            mesh_degraded,
            status: band.as_str().to_string(),
            health_score: band.score(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_bands_match_original_get_info_logic() {
        assert_eq!(
            HealthStatus::from_signals(false, 5, Some(1)),
            HealthStatus::Syncing
        );
        assert_eq!(
            HealthStatus::from_signals(true, 0, Some(1)),
            HealthStatus::NoPeers
        );
        assert_eq!(
            HealthStatus::from_signals(true, 5, Some(301)),
            HealthStatus::Stalled
        );
        assert_eq!(
            HealthStatus::from_signals(true, 1, Some(10)),
            HealthStatus::LowPeers
        );
        assert_eq!(
            HealthStatus::from_signals(true, 3, Some(10)),
            HealthStatus::Healthy
        );
    }

    #[test]
    fn unreadable_clock_is_treated_as_stalled() {
        assert_eq!(
            HealthStatus::from_signals(true, 5, None),
            HealthStatus::Stalled
        );
    }

    #[test]
    fn boundary_at_stall_threshold_is_inclusive_of_healthy() {
        // age == threshold is NOT stalled (matches `age > STALL_TIP_AGE_SECS`).
        assert_eq!(
            HealthStatus::from_signals(true, 3, Some(STALL_TIP_AGE_SECS)),
            HealthStatus::Healthy
        );
        assert_eq!(
            HealthStatus::from_signals(true, 3, Some(STALL_TIP_AGE_SECS + 1)),
            HealthStatus::Stalled
        );
    }

    #[test]
    fn scores_and_labels_are_stable() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::NoPeers.as_str(), "no-peers");
        assert_eq!(HealthStatus::LowPeers.as_str(), "low-peers");
        assert_eq!(HealthStatus::Healthy.score(), 1.0);
        assert_eq!(HealthStatus::NoPeers.score(), 0.2);
    }

    #[test]
    fn vitals_round_trip_and_carry_schema_version() {
        let v = ChainVitals::from_signals(
            "testnet", 1441, "abcd", Some(30), true, 3, "62735", 0, false,
        );
        assert_eq!(v.schema_version, VITALS_SCHEMA_VERSION);
        assert_eq!(v.status, "healthy");
        assert_eq!(v.health_score, 1.0);
        assert!(!v.mesh_degraded);
        let json = serde_json::to_string(&v).unwrap();
        let back: ChainVitals = serde_json::from_str(&json).unwrap();
        assert_eq!(back.height, 1441);
        assert_eq!(back.network, "testnet");
        assert_eq!(back.status, "healthy");
    }
}
