//! Parser for `fleet-config.json` — the single source of truth for
//! fleet topology (shared with `scripts/fleet-config.json` in the
//! coincync repo, deployed to `/etc/coincync-tick/fleet-config.json`
//! on each fleet host).
//!
//! The tick uses this to answer `ChainAdapter::fleet_peers`. Every
//! `nodes` entry becomes one `FleetPeer` returned by the adapter,
//! EXCEPT hosts with `role == "api"` (nginx-only, doesn't run
//! coincync-node).
//!
//! ## Schema
//!
//! ```json
//! {
//!   "network": "testnet",
//!   "p2p_port": 28080,
//!   "rpc_port": 28081,
//!   "nodes": {
//!     "seed1": { "ip": "1.2.3.4", "rpc_bind": "0.0.0.0", "role": "seed" },
//!     ...
//!   },
//!   "deactivated": { ... }
//! }
//! ```
//!
//! Fields starting with `_` (like `_description`, `_last_changed`,
//! `_rpc_bind_policy`) are metadata and silently ignored by the
//! deserializer.
//!
//! ## RPC URL construction
//!
//! Every node entry's RPC URL is derived as `http://{ip}:{rpc_port}`.
//! Fleet hosts with `rpc_bind == "127.0.0.1"` (loopback-only) are
//! UNREACHABLE from other hosts — `probe_peer` will return
//! `TickError::Unreachable` for those. That's expected behavior:
//! `HealthTick` classifies unreachable hosts as a data-collection
//! gap, not a false anomaly.
//!
//! A future extension could add a `rpc_url` override per entry so
//! nodes behind nginx/stunnel/tunnels can be reached even when their
//! raw port is loopback-bound.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use tick::{FleetPeer, TickError, TickResult};

/// Default RPC port when the file omits `rpc_port`.
const DEFAULT_RPC_PORT: u16 = 28081;

/// Raw fleet-config.json shape. All fields are permissive:
///
/// - `nodes` defaults to empty map (an operator running an empty
///   config gets zero fleet peers, matching Personal-mode behavior)
/// - `deactivated` is deserialized but ignored — kept for
///   forward-compat with the coincync repo's existing tooling that
///   MAY reference the section
/// - `rpc_port` defaults to `DEFAULT_RPC_PORT`
#[derive(Debug, Clone, Deserialize)]
pub struct FleetConfig {
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default = "default_rpc_port")]
    pub rpc_port: u16,
    #[serde(default)]
    pub nodes: BTreeMap<String, FleetNodeEntry>,
    #[serde(default)]
    #[allow(dead_code)]
    pub deactivated: Option<serde_json::Value>,
}

fn default_rpc_port() -> u16 {
    DEFAULT_RPC_PORT
}

/// One entry in the `nodes` map.
#[derive(Debug, Clone, Deserialize)]
pub struct FleetNodeEntry {
    pub ip: String,
    #[serde(default)]
    pub role: String,
    /// Kept for forward-compat with the coincync repo's schema, not
    /// consumed by tick.
    #[serde(default)]
    #[allow(dead_code)]
    pub rpc_bind: Option<String>,
}

impl FleetConfig {
    /// Parse from JSON bytes.
    ///
    /// Returns `TickError::Other` on parse failure so the caller can
    /// distinguish "file exists but is broken" from "file missing"
    /// (which surfaces as `TickError::Other("read fleet config: ...
    /// No such file or directory")`).
    pub fn from_json(bytes: &[u8]) -> TickResult<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| TickError::Other(format!("fleet-config.json parse error: {}", e)))
    }

    /// Read + parse from a filesystem path.
    ///
    /// Common failure mode: the file doesn't exist yet (Personal
    /// deployments). Caller should default to an empty fleet in that
    /// case rather than propagate the error — a Personal home node
    /// legitimately has no fleet.
    pub fn from_path(path: &Path) -> TickResult<Self> {
        let bytes = std::fs::read(path).map_err(|e| {
            TickError::Other(format!("read fleet config {}: {}", path.display(), e))
        })?;
        Self::from_json(&bytes)
    }

    /// Convert active fleet nodes into `FleetPeer` entries. Hosts
    /// with `role == "api"` are EXCLUDED — they're nginx-only,
    /// don't run coincync-node, and dialing them wastes probe budget.
    ///
    /// Order is deterministic (alphabetical by node name) — same
    /// order the coincync scripts use for addnode-list rendering.
    /// `BTreeMap<String, _>` gives us that by construction.
    pub fn to_fleet_peers(&self) -> Vec<FleetPeer> {
        self.nodes
            .iter()
            .filter(|(_, entry)| entry.role != "api")
            .map(|(name, entry)| FleetPeer {
                name: name.clone(),
                rpc_url: format!("http://{}:{}", entry.ip, self.rpc_port),
                role: entry.role.clone(),
            })
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The real production fleet-config.json shape (abbreviated to
    /// the 3 fields we care about + metadata fields that must be
    /// silently ignored).
    const REAL_CONFIG_JSON: &str = r#"{
        "_description": "Single source of truth for the CoinCync testnet fleet topology.",
        "_last_changed": "2026-06-27",
        "network": "testnet",
        "p2p_port": 28080,
        "rpc_port": 28081,
        "_rpc_bind_policy": "Per-host RPC bind address.",
        "nodes": {
            "seed1": {
                "ip": "216.128.156.239",
                "rpc_bind": "0.0.0.0",
                "role": "seed",
                "notes": "..."
            },
            "seed2": {
                "ip": "140.82.57.168",
                "rpc_bind": "0.0.0.0",
                "role": "seed",
                "notes": "..."
            },
            "api": {
                "ip": "95.179.165.225",
                "rpc_bind": "0.0.0.0",
                "role": "api",
                "notes": "nginx-only"
            },
            "randomx": {
                "ip": "173.199.93.21",
                "rpc_bind": "127.0.0.1",
                "role": "miner",
                "notes": "..."
            }
        },
        "deactivated": {
            "london": {
                "ip": "TBD",
                "role": "seed"
            }
        }
    }"#;

    #[test]
    fn parses_real_config_shape() {
        let cfg = FleetConfig::from_json(REAL_CONFIG_JSON.as_bytes()).expect("parse");
        assert_eq!(cfg.network.as_deref(), Some("testnet"));
        assert_eq!(cfg.rpc_port, 28081);
        assert_eq!(cfg.nodes.len(), 4);
    }

    #[test]
    fn silently_ignores_metadata_underscore_fields() {
        // The real config has `_description`, `_last_changed`,
        // `_rpc_bind_policy`, and per-node `notes`. None of them are
        // in the FleetConfig struct — deserialization must succeed
        // regardless (serde default ignores unknown fields).
        FleetConfig::from_json(REAL_CONFIG_JSON.as_bytes()).expect("must ignore metadata");
    }

    #[test]
    fn to_fleet_peers_excludes_role_api() {
        let cfg = FleetConfig::from_json(REAL_CONFIG_JSON.as_bytes()).expect("parse");
        let peers = cfg.to_fleet_peers();
        // 3 of the 4 nodes are non-api: seed1, seed2, randomx
        assert_eq!(peers.len(), 3);
        assert!(peers.iter().all(|p| p.role != "api"));
        // The api host's IP should NOT appear in any peer's rpc_url
        assert!(peers.iter().all(|p| !p.rpc_url.contains("95.179.165.225")));
    }

    #[test]
    fn to_fleet_peers_constructs_expected_rpc_urls() {
        let cfg = FleetConfig::from_json(REAL_CONFIG_JSON.as_bytes()).expect("parse");
        let peers = cfg.to_fleet_peers();
        let by_name: std::collections::HashMap<_, _> =
            peers.into_iter().map(|p| (p.name.clone(), p)).collect();
        assert_eq!(
            by_name.get("seed1").unwrap().rpc_url,
            "http://216.128.156.239:28081"
        );
        assert_eq!(
            by_name.get("randomx").unwrap().rpc_url,
            "http://173.199.93.21:28081"
        );
    }

    #[test]
    fn to_fleet_peers_is_deterministic_order() {
        // BTreeMap gives alphabetical iteration → deterministic order.
        // A HealthTick that reports "5 hosts stalled" should hash the
        // notice text deterministically; non-deterministic ordering
        // would produce false-different notices on re-tick.
        let cfg = FleetConfig::from_json(REAL_CONFIG_JSON.as_bytes()).expect("parse");
        let names1: Vec<_> = cfg.to_fleet_peers().into_iter().map(|p| p.name).collect();
        let names2: Vec<_> = cfg.to_fleet_peers().into_iter().map(|p| p.name).collect();
        assert_eq!(names1, names2, "ordering must be deterministic");
    }

    #[test]
    fn empty_config_yields_no_peers() {
        let cfg = FleetConfig::from_json(b"{}").expect("empty object should parse");
        assert!(cfg.to_fleet_peers().is_empty());
        assert_eq!(cfg.rpc_port, DEFAULT_RPC_PORT);
    }

    #[test]
    fn missing_rpc_port_uses_default() {
        let cfg = FleetConfig::from_json(b"{\"nodes\":{}}").expect("parse");
        assert_eq!(cfg.rpc_port, 28081);
    }

    #[test]
    fn bad_json_returns_other_error() {
        let err = FleetConfig::from_json(b"this is not json").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("parse error"), "got: {}", msg);
    }

    #[test]
    fn from_path_returns_error_for_nonexistent_file() {
        let err =
            FleetConfig::from_path(std::path::Path::new("/nonexistent/path/xyz.json")).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("read fleet config"), "got: {}", msg);
    }
}
