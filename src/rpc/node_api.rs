//! # Node RPC API
//!
//! RPC methods for node operations.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use serde_json::{json, Value};

use crate::chain::SharedBlockchain;
use crate::mempool::SharedMempool;
use crate::emission::calculate_block_reward;
use crate::error::Result;
use super::types::*;

/// Count cyncd processes by scanning /proc/*/comm.
///
/// Returns `(count, available)` where `available == false` indicates the
/// caller cannot rely on the count (non-Linux platform, container with
/// /proc masked, seccomp sandbox, or any other reason `/proc` is unreadable).
///
/// M5 (audit fix): the previous version returned just `usize`, which made
/// "we observed exactly 1 process" indistinguishable from "we couldn't tell
/// — defaulting to 1." Prometheus scrapes need to differentiate so that
/// "process count == 1" doesn't silently mask a deployment problem on
/// non-Linux runners or container hosts.
fn count_cyncd_processes() -> (usize, bool) {
    #[cfg(target_os = "linux")]
    {
        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return (1, false), // /proc not accessible (chroot, sandbox)
        };
        let mut count = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // /proc/<pid>/comm exists only for numeric PID dirs
            if name_str.chars().all(|c| c.is_ascii_digit()) {
                let comm_path = format!("/proc/{}/comm", name_str);
                if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                    if comm.trim() == "cyncd" {
                        count += 1;
                    }
                }
            }
        }
        (count, true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (1, false) // Self-only sentinel; caller must check `available`
    }
}

/// Node RPC handler
pub struct NodeRpc {
    chain: SharedBlockchain,
    mempool: SharedMempool,
    peer_count: Arc<AtomicUsize>,
    network_name: String,
}

impl NodeRpc {
    pub fn new(chain: SharedBlockchain, mempool: SharedMempool) -> Self {
        NodeRpc {
            chain,
            mempool,
            peer_count: Arc::new(AtomicUsize::new(0)),
            network_name: "testnet".to_string(),
        }
    }

    /// Create with a shared peer count reference
    pub fn with_peer_count(
        chain: SharedBlockchain,
        mempool: SharedMempool,
        peer_count: Arc<AtomicUsize>,
    ) -> Self {
        NodeRpc { chain, mempool, peer_count, network_name: "testnet".to_string() }
    }

    /// Set network name for RPC responses
    pub fn set_network_name(&mut self, name: String) {
        self.network_name = name;
    }

    /// Get current peer count
    fn peers(&self) -> usize {
        self.peer_count.load(Ordering::Relaxed)
    }

    /// Get node info — enhanced for explorer health/decay/zombie detection.
    ///
    /// Monitoring contract: every "could be unavailable" datum gets an
    /// explicit availability flag so a Prometheus scraper can distinguish
    /// "this stat is currently unobservable" from "the value is genuinely
    /// zero". Returning a plausible-looking `0` for an unobservable metric
    /// is exactly the silent-stub pattern that masks eclipse attacks and
    /// stuck-clock incidents.
    pub fn get_info(&self) -> Result<Value> {
        let (process_count, process_count_available) = count_cyncd_processes();
        let tip = self.chain.tip();

        // Wall-clock read can fail (clock set before UNIX_EPOCH). On failure
        // we report `tip_age_secs = null` and `clock_available = false`
        // rather than reporting `tip_age_secs = 0`, which a monitoring
        // dashboard would (correctly) interpret as "tip is brand new" — the
        // exact opposite of "we have no idea how stale the tip is".
        let (tip_age_secs, clock_available): (Value, bool) =
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => {
                    let now_secs = d.as_secs();
                    (json!(now_secs.saturating_sub(tip.timestamp)), true)
                }
                Err(_) => (Value::Null, false),
            };

        let anonymity_set = self.chain.available_output_count();
        Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "build_commit": crate::build_info::git_commit(),
            "build_dirty": crate::build_info::git_dirty(),
            "build_profile": crate::build_info::build_profile(),
            "network": self.network_name,
            "height": tip.height,
            "top_hash": tip.hash.to_string(),
            "tip_timestamp": tip.timestamp,
            "tip_age_secs": tip_age_secs,
            "clock_available": clock_available,
            "difficulty": self.chain.difficulty().to_string(),
            "synced": self.chain.is_synced(),
            "peer_count": self.peers(),
            "tx_pool_size": self.mempool.len(),
            "process_count": process_count,
            // M5 (audit fix): explicit availability flag — Prometheus / monitoring
            // can distinguish "we observed 1 process" from "we couldn't tell".
            // `has_zombies` is only meaningful when `process_count_available == true`.
            "process_count_available": process_count_available,
            "has_zombies": process_count_available && process_count > 1,
            "anonymity_set": anonymity_set,
        }))
    }

    /// Get the total anonymity set size (unspent output count).
    /// This is the most important metric for a privacy coin — every output
    /// in the UTXO set is a potential decoy, growing the privacy of every
    /// future transaction.
    pub fn get_anonymity_set(&self) -> Result<Value> {
        let count = self.chain.available_output_count();
        let height = self.chain.height();
        Ok(json!({
            "anonymity_set": count,
            "height": height,
            "outputs_per_block": if height > 0 { count / (height as usize) } else { 0 },
        }))
    }

    /// Get recent chain events: reorgs, rollbacks, fork detections.
    /// Used by the convergence timeline in the explorer.
    pub fn get_chain_events(&self, limit: Option<usize>) -> Result<Value> {
        let limit = limit.unwrap_or(100).min(500);
        let events = self.chain.get_events(limit);
        let height = self.chain.height();
        let tip = self.chain.tip();
        Ok(json!({
            "events": events,
            "current_height": height,
            "current_tip": tip.hash.to_string(),
            "count": events.len(),
        }))
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<BlockInfo>> {
        if let Some(hash) = self.chain.get_block_hash(height) {
            if let Some(block) = self.chain.get_block(&hash) {
                return Ok(Some(BlockInfo {
                    hash: block.hash().to_string(),
                    height: block.height(),
                    timestamp: block.header.timestamp,
                    prev_hash: block.header.prev_hash.to_string(),
                    merkle_root: block.header.tx_root.to_string(),
                    difficulty: block.header.target.to_difficulty().to_string(),
                    nonce: block.header.nonce,
                    tx_count: block.transactions.len(),
                    size: block.size(),
                    reward: calculate_block_reward(block.height()).to_string(),
                }));
            }
        }
        Ok(None)
    }

    /// Get sync status
    pub fn get_sync_status(&self) -> Result<SyncStatus> {
        let target = self.chain.target_height();
        Ok(SyncStatus {
            synced: self.chain.is_synced(),
            height: self.chain.height(),
            target_height: target,
            progress: if target > 0 {
                self.chain.height() as f64 / target as f64
            } else {
                1.0
            },
            peers: self.peers() as u32,
        })
    }

    /// Get transaction pool stats
    pub fn get_tx_pool_stats(&self) -> Result<TxPoolStats> {
        Ok(TxPoolStats {
            count: self.mempool.len(),
            size: self.mempool.size(),
            fees: self.mempool.total_fees().to_string(),
            oldest_timestamp: self.mempool.oldest_timestamp(),
        })
    }

    /// Get network info.
    ///
    /// The total `connections` count is known here (we hold the peer-count
    /// atomic). The per-direction and per-bucket breakdowns require visibility
    /// into the P2P layer that this struct does not yet have; they are
    /// reported as `None` rather than guessed-as-zero. A monitoring consumer
    /// that sees `incoming = null` knows the stat is unavailable, whereas
    /// `incoming = 0` would mean "no inbound peers right now" — exactly the
    /// signal an operator needs during an eclipse attack. Returning `null`
    /// here prevents that ambiguity.
    pub fn get_network_info(&self) -> Result<NetworkInfo> {
        let total_peers = self.peers() as u32;
        Ok(NetworkInfo {
            network: self.network_name.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: crate::constants::PROTOCOL_VERSION,
            connections: total_peers,
            incoming: None,
            outgoing: None,
            white_peers: None,
            grey_peers: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Blockchain;
    use crate::mempool::SharedMempool;

    #[test]
    fn test_node_rpc_get_info() {
        let chain = Arc::new(Blockchain::new());
        let mempool = SharedMempool::new();
        let rpc = NodeRpc::new(chain, mempool);
        let info = rpc.get_info().unwrap();
        // Should return a JSON value with expected fields
        assert!(info.get("version").is_some());
        assert!(info.get("network").is_some());
        assert!(info.get("height").is_some());
    }

    #[test]
    fn test_node_rpc_get_network_info() {
        let chain = Arc::new(Blockchain::new());
        let mempool = SharedMempool::new();
        let rpc = NodeRpc::new(chain, mempool);
        let info = rpc.get_network_info().unwrap();
        assert_eq!(info.network, "testnet");
        assert_eq!(info.protocol_version, crate::constants::PROTOCOL_VERSION);
    }
}
