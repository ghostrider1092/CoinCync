//! Node status, peer metadata, and operational health RPCs.

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde_json::{json, Value};

use crate::error::{Error, Result};

use super::{supply_atomic_decimal, RpcState};

fn serialize_peer_info(peer: &crate::network::peer::PeerInfo, minimize_metadata: bool) -> Value {
    if minimize_metadata {
        // P7-R1 SURGICAL FIX (2026-07-03): also redact peer_id in
        // minimized mode. Pre-fix code exposed `peer.id[..8]`, a
        // STABLE per-session correlator that lets an RPC client
        // fingerprint peers across polls even with addr/user_agent
        // redacted.
        json!({
            "id":         "[redacted]",
            "addr":       "[redacted]",
            "height":     peer.height,
            "version":    peer.version,
            "user_agent": "[redacted]",
            "outbound":   peer.outbound,
            "encrypted":  peer.encrypted,
            "bytes_recv": 0u64,
            "bytes_sent": 0u64,
            "reputation": peer.reputation,
            "metadata_minimized": true,
        })
    } else {
        json!({
            "id":         hex::encode(&peer.id[..8]),
            "addr":       peer.addr.to_string(),
            "height":     peer.height,
            "version":    peer.version,
            "user_agent": peer.user_agent,
            "outbound":   peer.outbound,
            "encrypted":  peer.encrypted,
            "bytes_recv": peer.bytes_recv,
            "bytes_sent": peer.bytes_sent,
            "reputation": peer.reputation,
            "metadata_minimized": false,
        })
    }
}

pub(super) fn register(module: &mut RpcModule<RpcState>) -> Result<()> {
    // ── get_info ───────────────────────────────────────────────
    //
    // Rich node status payload. This is the method coincync-rig and
    // the block explorer HTML hit on every poll, so it's the
    // single most important "how is
    // my node doing" surface. Every field gets a defined
    // meaning and every "could be unavailable" datum gets an
    // explicit availability flag (see `clock_available`,
    // `process_count_available`). Consumers must distinguish
    // "we couldn't measure" from "the value is zero" — silent
    // zeros mask stuck-clock and eclipse incidents.
    // register_blocking_method (not register_method) — the closure
    // takes parking_lot read-locks on chain state which BLOCK the
    // calling thread. Running this on a tokio worker means a single
    // sync-side write-lock contention can starve the entire runtime
    // (4-8 workers all stuck on inner.read()). Blocking method runs
    // on the much larger blocking pool (default 512 threads) so
    // worker availability for genuinely-async work is preserved.
    // See src/bin/node.rs:120 BUMP 4 → 8 comment for full context.
    // 2026-06-03 fix for the silent RPC-hang pathology observed
    // three times on coincync-lon under sustained IBD activity.
    module
        .register_blocking_method("get_info", |_params, state, _ext| {
            let tip = state.chain.tip();
            let stats = state.chain.stats();
            let height = tip.height;
            let synced = state.chain.is_synced();
            let target_height = state.chain.target_height();
            let peer_count = state
                .p2p
                .as_ref()
                .map(|p| p.network_stats().peer_count)
                .unwrap_or(0);
            // anonymity_set + effective_ring_size are emitted in get_info.
            // The 2026-05-07 review proposed removing them as a chain-analyst
            // correlator (every public scrape recording "anonymity_set was M
            // at time T" gives an attacker an intersection on rings built
            // around T). The UX cost — the explorer's "anonymity set" tile
            // showing 00, every user seeing a broken stat — proved larger
            // than the marginal correlator gain (an attacker who wants this
            // data can poll get_decoys directly anyway). Field is back.
            let anonymity_set = state.chain.available_output_count();
            let effective_ring_size = crate::constants::effective_ring_size(height, anonymity_set);

            // Wall-clock read can fail if the system clock is set before
            // UNIX_EPOCH. On failure we report `tip_age_secs = null` + a
            // `clock_available = false` flag so a monitoring dashboard
            // can distinguish "tip is brand new" from "we have no idea
            // how stale the tip is".
            let (tip_age_secs, clock_available): (Value, bool) =
                match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                    Ok(d) => {
                        let now = d.as_secs();
                        (json!(now.saturating_sub(tip.timestamp)), true)
                    }
                    Err(_) => (Value::Null, false),
                };

            // Derive a simple health score and status label from the
            // observable signals. The score is a float in [0.0, 1.0];
            // 1.0 = everything nominal, 0.0 = disconnected / stalled.
            // This mirrors the health-band rendering in the TUI status
            // bar so the node, not the TUI, is the source of truth.
            let (status, health_score) = if !synced {
                ("syncing".to_string(), 0.5_f64)
            } else if peer_count == 0 {
                ("no-peers".to_string(), 0.2_f64)
            } else {
                let age = tip_age_secs.as_u64().unwrap_or(u64::MAX);
                if age > 300 {
                    ("stalled".to_string(), 0.3_f64)
                } else if peer_count < 2 {
                    ("low-peers".to_string(), 0.7_f64)
                } else {
                    ("healthy".to_string(), 1.0_f64)
                }
            };

            Ok::<_, ErrorObjectOwned>(json!({
                // Identity
                "version":                 env!("CARGO_PKG_VERSION"),
                "build_commit":            crate::build_info::git_commit(),
                "build_dirty":             crate::build_info::git_dirty(),
                "build_profile":           crate::build_info::build_profile(),
                "network":                 state.network_name,
                // Chain tip
                "height":                  height,
                "target_height":           target_height,
                "top_hash":                hex::encode(tip.hash.as_bytes()),
                // Back-compat alias: some older clients look for `tip_hash`.
                "tip_hash":                hex::encode(tip.hash.as_bytes()),
                "tip_timestamp":           tip.timestamp,
                "tip_age_secs":            tip_age_secs,
                "clock_available":         clock_available,
                "difficulty":              stats.difficulty.to_string(),
                "total_difficulty":        stats.total_difficulty.to_string(),
                // Sync + P2P
                "synced":                  synced,
                "is_synced":               synced, // back-compat alias
                "peer_count":              peer_count,
                // Mempool
                "tx_pool_size":            state.mempool.len(),
                "mempool_size":            state.mempool.len(), // back-compat alias
                // Privacy metrics. Reflect the chain-wide decoy pool size +
                // the ring size every wallet uses. Public on-chain data —
                // any caller that wants this can poll get_decoys to recover
                // the same number, so withholding it from get_info gives
                // negligible privacy gain at the cost of breaking every UI
                // that surfaces the anonymity-set stat.
                "anonymity_set":           anonymity_set,
                "available_outputs":       anonymity_set, // back-compat alias
                "effective_ring_size":     effective_ring_size,
                // Health / monitoring
                "status":                  status,
                "health_score":            health_score,
                // Per-process zombie detection (see rpc::node_api::count_cyncd_processes
                // for the availability flag rationale).
                "process_count":           1u32,
                "process_count_available": false,
                "has_zombies":             false,
                // Surface hardening posture to operators/TUIs so they can assert
                // expected runtime policy (auth/privacy) without shell access.
                "rpc_auth_enabled":        state.auth_enabled,
                "metadata_minimized":      state.minimize_metadata,
                "stratum_public_bind_requested": state.stratum_public_bind_requested,
                "stratum_public_bind_ack": state.stratum_public_bind_ack,
                "stratum_native_tls_enabled": state.stratum_native_tls_enabled,
                "stratum_tls_proxy_ack": state.stratum_tls_proxy_ack,
                "stratum_transport_hardened": state.stratum_transport_hardened,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_peer_info ──────────────────────────────────────────
    // Returns each currently-connected peer with the chain tip they
    // most recently reported (height + tip_hash via their version
    // handshake). Operators use this to spot fleet divergence: poll
    // get_peer_info on every fleet node, compare reported tips, and
    // any deviation > 1 block is a sign of a stuck node, a fork, or
    // a P2P stall (the exact bug class barns1253 hit on 2026-06-01
    // and coincync-lon hit on 2026-06-02). Cheap to call: iterates
    // the live peer DashMap, no I/O. Useful as a periodic poll from
    // a monitoring dashboard, NOT as a hot-path query.
    // register_blocking_method — same rationale as get_info above.
    // Also touches parking_lot state (peer DashMap iteration + chain
    // tip read), should not run on tokio workers.
    module
        .register_blocking_method("get_peer_info", |_params, state, _ext| {
            // P7-R2 SURGICAL FIX (2026-07-03): honor minimize_metadata
            // on public listeners. Pre-fix code built its own peer JSON
            // that always exposed addr, user_agent, peer_id_prefix
            // regardless of the flag. Now redact them consistently.
            let minimize = state.minimize_metadata;
            let now = std::time::Instant::now();
            let peers: Vec<Value> = match state.p2p.as_ref() {
                Some(p2p) => p2p
                    .peer_snapshot()
                    .into_iter()
                    .map(|p| {
                        let last_seen_secs = now
                            .checked_duration_since(p.last_seen)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let connected_for_secs = now
                            .checked_duration_since(p.connected_at)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        // P7-R1 fix: peer_id_prefix is a per-session
                        // correlator. Redact in min mode.
                        let peer_id_field: Value = if minimize {
                            Value::String("[redacted]".to_string())
                        } else {
                            Value::String(hex::encode(&p.id[..8]))
                        };
                        let addr_field: Value = if minimize {
                            Value::String("[redacted]".to_string())
                        } else {
                            Value::String(p.addr.to_string())
                        };
                        let user_agent_field: Value = if minimize {
                            Value::String("[redacted]".to_string())
                        } else {
                            Value::String(p.user_agent.clone())
                        };
                        let bytes_recv_val = if minimize { 0u64 } else { p.bytes_recv };
                        let bytes_sent_val = if minimize { 0u64 } else { p.bytes_sent };
                        json!({
                            // Identity — redacted under min-metadata.
                            "peer_id_prefix":      peer_id_field,
                            "addr":                addr_field,
                            "outbound":            p.outbound,
                            // Reported chain tip — the actually-useful field.
                            // Defaults to 0 if the peer never sent a Version
                            // (still mid-handshake).
                            "reported_height":     p.height,
                            "reported_tip_hash":   hex::encode(p.tip_hash.as_bytes()),
                            // Identity / protocol
                            "protocol_version":    p.version,
                            "user_agent":          user_agent_field,
                            "encrypted":           p.encrypted,
                            // Health-ish
                            "reputation":          p.reputation,
                            "last_seen_secs_ago":  last_seen_secs,
                            "connected_for_secs":  connected_for_secs,
                            "bytes_recv":          bytes_recv_val,
                            "bytes_sent":          bytes_sent_val,
                            // State (Connecting / Connected / Disconnected)
                            "state":               format!("{:?}", p.state),
                            "metadata_minimized":  minimize,
                        })
                    })
                    .collect(),
                None => Vec::new(),
            };

            // Summary for monitoring dashboards that just want the
            // divergence signal, not the full per-peer detail.
            let local_tip = state.chain.tip();
            let reported_heights: Vec<u64> = peers
                .iter()
                .filter_map(|p| p.get("reported_height").and_then(|h| h.as_u64()))
                .filter(|&h| h > 0)
                .collect();
            let max_peer_height = reported_heights.iter().copied().max().unwrap_or(0);
            let min_peer_height = reported_heights.iter().copied().min().unwrap_or(0);
            let divergence_from_max = max_peer_height.saturating_sub(local_tip.height);

            Ok::<_, ErrorObjectOwned>(json!({
                "local_height":         local_tip.height,
                "local_tip_hash":       hex::encode(local_tip.hash.as_bytes()),
                "peer_count":           peers.len(),
                "peers":                peers,
                // Quick-glance divergence summary
                "max_peer_height":      max_peer_height,
                "min_peer_height":      min_peer_height,
                "divergence_from_max":  divergence_from_max,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_blockchain_info (alias with more fields) ───────────
    // register_blocking_method — same rationale as get_info above.
    module
        .register_blocking_method("get_blockchain_info", |_params, state, _ext| {
            let tip = state.chain.tip();
            let stats = state.chain.stats();
            Ok::<_, ErrorObjectOwned>(json!({
                "network":         state.network_name,
                "version":         env!("CARGO_PKG_VERSION"),
                "build_commit":    crate::build_info::git_commit(),
                "build_dirty":     crate::build_info::git_dirty(),
                "build_profile":   crate::build_info::build_profile(),
                "height":          tip.height,
                "tip_hash":        hex::encode(tip.hash.as_bytes()),
                "timestamp":       tip.timestamp,
                "difficulty":      stats.difficulty.to_string(),
                "total_difficulty": stats.total_difficulty.to_string(),
                "total_supply":    supply_atomic_decimal(stats.total_supply),
                "mempool_size":    state.mempool.len(),
                "is_synced":       state.chain.is_synced(),
                "rpc_auth_enabled": state.auth_enabled,
                "metadata_minimized": state.minimize_metadata,
                "stratum_public_bind_requested": state.stratum_public_bind_requested,
                "stratum_public_bind_ack": state.stratum_public_bind_ack,
                "stratum_native_tls_enabled": state.stratum_native_tls_enabled,
                "stratum_tls_proxy_ack": state.stratum_tls_proxy_ack,
                "stratum_transport_hardened": state.stratum_transport_hardened,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_network_info ──────────────────────────────────────
    //
    // P2P connection breakdown. `connections` is the total peer
    // count (always known). The per-direction breakdown
    // (`incoming` / `outgoing`) and per-bucket breakdown
    // (`white_peers` / `grey_peers`) are JSON `null` on the P0
    // server because the thin stats struct from `P2PNode`
    // doesn't surface the split yet — returning `null` rather
    // than `0` is the honest signal, per the silent-stub fix
    // in `rpc::node_api::get_network_info`.
    module
        .register_method("get_network_info", |_params, state, _ext| {
            let connections = state
                .p2p
                .as_ref()
                .map(|p| p.network_stats().peer_count)
                .unwrap_or(0);
            Ok::<_, ErrorObjectOwned>(json!({
                "network":          state.network_name,
                "version":          env!("CARGO_PKG_VERSION"),
                "protocol_version": crate::constants::PROTOCOL_VERSION,
                "connections":      connections,
                "incoming":         Value::Null,
                "outgoing":         Value::Null,
                "white_peers":      Value::Null,
                "grey_peers":       Value::Null,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_sync_status ───────────────────────────────────────
    module
        .register_method("get_sync_status", |_params, state, _ext| {
            let target = state.chain.target_height();
            let height = state.chain.height();
            let peers = state
                .p2p
                .as_ref()
                .map(|p| p.network_stats().peer_count as u32)
                .unwrap_or(0);
            let progress = if target > 0 {
                (height as f64 / target as f64).min(1.0)
            } else {
                1.0
            };
            Ok::<_, ErrorObjectOwned>(json!({
                "synced":        state.chain.is_synced(),
                "height":        height,
                "target_height": target,
                "progress":      progress,
                "peers":         peers,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_peers ─────────────────────────────────────────────
    //
    // Returns the live peer table. Used by the embedded
    // explorer's "Peers" tab in `app/03-network.js` to
    // render a per-peer card with addr / height / version /
    // user-agent and an inbound/outbound badge. Each entry
    // includes the per-direction byte counts so monitoring can
    // also consume this — the same payload feeds Grafana
    // dashboards via the REST proxy.
    //
    // On nodes started without a `P2PNode` (e.g. RPC-only test
    // harness), we honestly return an empty list rather than
    // synthesising fake peers.
    module
        .register_method("get_peers", |_params, state, _ext| {
            let peers_json: Vec<Value> = match state.p2p.as_ref() {
                Some(p2p) => p2p
                    .connected_peers()
                    .into_iter()
                    .map(|p| serialize_peer_info(&p, state.minimize_metadata))
                    .collect(),
                None => Vec::new(),
            };
            Ok::<_, ErrorObjectOwned>(json!({
                "count": peers_json.len(),
                "peers": peers_json,
                "metadata_minimized": state.minimize_metadata,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_metrics ──────────────────────────────────────────
    //
    // HARDENING (Layer 7): Prometheus-compatible metrics endpoint.
    // Returns key node metrics in a flat JSON format that can be
    // scraped by monitoring tools or displayed in the explorer.
    module
        .register_method("get_metrics", |_params, state, _ext| {
            let stats = state.chain.stats();
            let mp_stats = state.mempool.stats();
            let peer_count = state.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);

            Ok::<_, ErrorObjectOwned>(json!({
                // Chain metrics
                "chain_height": stats.height,
                "chain_difficulty": stats.difficulty.to_string(),
                "chain_total_difficulty": stats.total_difficulty.to_string(),
                "chain_total_blocks": stats.total_blocks,
                "chain_total_transactions": stats.total_transactions,
                "chain_supply_atomic": supply_atomic_decimal(stats.total_supply),

                // Mempool metrics
                "mempool_size": mp_stats.tx_count,
                "mempool_bytes": mp_stats.size_bytes,
                "mempool_total_fee": mp_stats.total_fee.as_atomic(),

                // Network metrics
                "peer_count": peer_count,

                // Node metadata
                "version": crate::VERSION,
                "network": &state.network_name,
                "uptime_estimate": "running",
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_health ──────────────────────────────────────────
    //
    // HARDENING (Layer 7): Simple health check endpoint.
    // Returns 200 OK if the node is running. Used by load balancers,
    // monitoring tools, and the explorer status page.
    module
        .register_method("get_health", |_params, state, _ext| {
            let stats = state.chain.stats();
            let synced = state.chain.is_synced();
            let peer_count = state.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);

            let healthy = synced && peer_count > 0;

            Ok::<_, ErrorObjectOwned>(json!({
                "status": if healthy { "healthy" } else { "degraded" },
                "synced": synced,
                "height": stats.height,
                "peers": peer_count,
                "checks": {
                    "chain_synced": synced,
                    "has_peers": peer_count > 0,
                    "has_tip": stats.height > 0,
                }
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_serialization_redacts_sensitive_fields_when_minimized() {
        let mut p = crate::network::peer::PeerInfo::new(
            [0x42; 32],
            "203.0.113.9:30303".parse().expect("socket"),
            true,
        );
        p.height = 1234;
        p.version = 1;
        p.user_agent = "CoinCync/Test-UA".to_string();
        p.bytes_recv = 777;
        p.bytes_sent = 888;
        p.reputation = 99;
        p.encrypted = true;

        let redacted = serialize_peer_info(&p, true);
        assert_eq!(redacted["addr"], "[redacted]");
        assert_eq!(redacted["user_agent"], "[redacted]");
        assert_eq!(redacted["bytes_recv"], 0);
        assert_eq!(redacted["bytes_sent"], 0);
        assert_eq!(redacted["metadata_minimized"], true);
    }
}
