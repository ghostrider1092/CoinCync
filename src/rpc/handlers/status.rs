//! Node-status / operational RPC handlers — node info, peers, network, sync,
//! metrics, health, mining-live, state snapshot. Extracted from
//! `start_rpc_server` (issue #107); bodies, response fields, and the
//! blocking-vs-async execution model are unchanged from the previous inline
//! closures. The shared `supply_atomic_decimal` and `serialize_peer_info`
//! helpers stay in `server` (they have unit tests there and other groups use
//! them) and are referenced here.
//!
//! ## Audit map
//! - **§1 node status posture** — INVARIANT: `get_info` / `get_blockchain_info`
//!   report the runtime hardening posture (auth_enabled, minimize_metadata,
//!   stratum bind/TLS flags) and aggregate supply as a canonical base-10 string,
//!   so operators can assert policy without shell access. THREAT: silent posture
//!   drift; u128 supply truncated through a JSON number.
//!   TESTS: `rpc_get_info_returns_result`, `rpc_public_bind_get_info_reports_posture`.
//! - **§2 peer metadata minimization** — INVARIANT: on a public listener,
//!   `get_peer_info` / `get_peers` redact addr / user-agent / peer-id / byte
//!   counts when `minimize_metadata` is set. THREAT: a public RPC scrape
//!   correlating peers. TESTS: `rpc_public_bind_get_peers_response_shape_is_privacy_safe`,
//!   `peer_serialization_redacts_sensitive_fields_when_minimized`.

use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{json, Value};

use crate::rpc::server::{serialize_peer_info, supply_atomic_decimal, RpcState};

pub(crate) fn get_info(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
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

    Ok(json!({
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
}

pub(crate) fn get_peer_info(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
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

    Ok(json!({
        "local_height":         local_tip.height,
        "local_tip_hash":       hex::encode(local_tip.hash.as_bytes()),
        "peer_count":           peers.len(),
        "peers":                peers,
        // Quick-glance divergence summary
        "max_peer_height":      max_peer_height,
        "min_peer_height":      min_peer_height,
        "divergence_from_max":  divergence_from_max,
    }))
}

pub(crate) fn get_blockchain_info(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    let tip = state.chain.tip();
    let stats = state.chain.stats();
    Ok(json!({
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
}

pub(crate) fn get_network_info(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    let connections = state
        .p2p
        .as_ref()
        .map(|p| p.network_stats().peer_count)
        .unwrap_or(0);
    Ok(json!({
        "network":          state.network_name,
        "version":          env!("CARGO_PKG_VERSION"),
        "protocol_version": crate::constants::PROTOCOL_VERSION,
        "connections":      connections,
        "incoming":         Value::Null,
        "outgoing":         Value::Null,
        "white_peers":      Value::Null,
        "grey_peers":       Value::Null,
    }))
}

pub(crate) fn get_sync_status(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
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
    Ok(json!({
        "synced":        state.chain.is_synced(),
        "height":        height,
        "target_height": target,
        "progress":      progress,
        "peers":         peers,
    }))
}

pub(crate) fn get_mining_live(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    let tip = state.chain.tip();
    let height = tip.height;
    // The ChainTip struct doesn't carry the target directly —
    // we'd have to fetch the full BlockHeader for that. Since
    // this handler reports "not mining" to non-miner nodes and
    // the `target_hex` field is display-only in the TUI, we
    // return an empty string; a future miner-sidecar variant
    // that provides a real template will set this from the
    // template's header target.
    let target_hex = String::new();
    Ok(json!({
        "is_mining":            false,
        "hashrate":             0.0,
        "hashes_total":         0u64,
        "blocks_found":         0u64,
        // CoinCync 1.0 is RandomX-only (algorithm index 0).
        "algorithm":            0u64,
        "algorithm_name":       "RandomX",
        "mining_height":        height + 1,
        "target_hex":           target_hex,
        "best_hash_hex":        "",
        "best_leading_zeros":   0u64,
        "target_leading_zeros": 0u64,
        "current_nonce":        0u64,
        "block_just_found":     false,
        "winning_nonce":        0u64,
        "winning_hash_hex":     "",
        "sample_hashes":        Value::Array(vec![]),
    }))
}

pub(crate) fn get_peers(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    let peers_json: Vec<Value> = match state.p2p.as_ref() {
        Some(p2p) => p2p
            .connected_peers()
            .into_iter()
            .map(|p| serialize_peer_info(&p, state.minimize_metadata))
            .collect(),
        None => Vec::new(),
    };
    Ok(json!({
        "count": peers_json.len(),
        "peers": peers_json,
        "metadata_minimized": state.minimize_metadata,
    }))
}

pub(crate) fn get_metrics(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    let stats = state.chain.stats();
    let mp_stats = state.mempool.stats();
    let peer_count = state.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);

    Ok(json!({
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
}

pub(crate) fn get_health(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    let stats = state.chain.stats();
    let synced = state.chain.is_synced();
    let peer_count = state.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);

    let healthy = synced && peer_count > 0;

    Ok(json!({
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
}

pub(crate) fn get_state_snapshot(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    let stats = state.chain.stats();
    let tip = state.chain.tip_hash();

    Ok(json!({
        "height": stats.height,
        "tip_hash": tip.to_hex(),
        "total_difficulty": stats.total_difficulty.to_string(),
        "total_supply": supply_atomic_decimal(stats.total_supply),
        "total_transactions": stats.total_transactions,
        "checkpoints": crate::testnet::testnet_checkpoints().iter()
            .map(|cp| json!({"height": cp.height, "hash": cp.hash.to_hex()}))
            .collect::<Vec<_>>(),
        "version": "1.0.0",
        "network": "testnet",
    }))
}
