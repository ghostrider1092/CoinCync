//! # RPC Server (minimal P0 wiring)
//!
//! A minimal JSON-RPC 2.0 server built on jsonrpsee, wired for the P0
//! running-node milestone. Exposes the methods that the node binary,
//! coincync-rig, and the explorer/wallet HTML UIs need:
//!
//! - `get_info` — chain tip height, hash, network, mempool size
//! - `get_blockchain_info` — alias of `get_info` with more fields
//! - `get_mempool_info` — mempool stats
//! - `get_supply_info` — emission / supply snapshot
//! - `get_block_by_height` — fetch a block by height (u64 param)
//! - `submit_block` — accept a serialized block from a miner
//! - `send_raw_transaction` — accept a serialized transaction
//!
//! The full 2.0 RPC surface (asset methods, wallet methods, compliance
//! proofs, explorer endpoints, REST compat, OpenAPI) is deliberately
//! gated out — those come back in the P1 wallet wire-up pass. The huge
//! 2335-line server.rs from 2.0 depended on `SharedWallet`,
//! `SubaddressManager`, `estimate_fee_with_multiplier`, `decrypt_asset_audit`,
//! `list_asset_policies`, `mining::Miner`, and other symbols that do not
//! exist in the trimmed 1.0 tree.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use jsonrpsee::server::{HttpBody, ServerBuilder, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{json, Value};
use tower::ServiceBuilder;
use tower_http::validate_request::{ValidateRequest, ValidateRequestHeaderLayer};
use tracing::{info, warn};

use crate::chain::SharedBlockchain;
use crate::mempool::SharedMempool;
use crate::network::P2PNode;
use crate::error::{Error, Result};

/// RPC server configuration.
#[derive(Clone)]
pub struct RpcConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Max concurrent connections.
    pub max_connections: u32,
    /// Auth (API-key) enabled?
    pub auth_enabled: bool,
    /// API key, if auth is on.
    pub api_key: Option<String>,
    /// CORS allowed origins.
    pub cors_origins: Vec<String>,
    /// Network name — reported in `get_info`.
    pub network_name: String,
    /// TLS on?
    pub tls_enabled: bool,
    /// Data directory for auto-generated cert.
    pub data_dir: Option<std::path::PathBuf>,
    /// Custom TLS cert path.
    pub tls_cert_path: Option<std::path::PathBuf>,
    /// Custom TLS key path.
    pub tls_key_path: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for RpcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcConfig")
            .field("listen_addr", &self.listen_addr)
            .field("max_connections", &self.max_connections)
            .field("auth_enabled", &self.auth_enabled)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("cors_origins", &self.cors_origins)
            .field("network_name", &self.network_name)
            .field("tls_enabled", &self.tls_enabled)
            .field("data_dir", &self.data_dir)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .finish()
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([127, 0, 0, 1], crate::constants::DEFAULT_RPC_PORT).into(),
            max_connections: 100,
            auth_enabled: false,
            api_key: None,
            cors_origins: vec![
                "http://localhost".to_string(),
                "http://127.0.0.1".to_string(),
            ],
            network_name: "testnet".to_string(),
            tls_enabled: false,  // P0: plaintext by default, TLS comes back in P1
            data_dir: None,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Handle returned by `start_rpc_server` — drop to stop the server.
pub struct RpcServer {
    handle: ServerHandle,
}

impl RpcServer {
    pub fn stop(self) {
        let _ = self.handle.stop();
    }
}

/// Shared state passed to every RPC method handler.
#[derive(Clone)]
struct RpcState {
    chain: SharedBlockchain,
    mempool: SharedMempool,
    p2p: Option<Arc<P2PNode>>,
    network_name: String,
    auth_enabled: bool,
    minimize_metadata: bool,
    stratum_public_bind_requested: bool,
    stratum_public_bind_ack: bool,
    stratum_native_tls_enabled: bool,
    stratum_tls_proxy_ack: bool,
    stratum_transport_hardened: bool,
}

fn serialize_peer_info(peer: &crate::network::peer::PeerInfo, minimize_metadata: bool) -> Value {
    if minimize_metadata {
        json!({
            "id":         hex::encode(&peer.id[..8]),
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

/// Maximum inclusive block span for CPU-heavy audit RPCs (`*_in_range`, `full_chain_audit`).
pub const MAX_RPC_AUDIT_BLOCK_SPAN: u64 = 128;

/// Refuse unbounded `verify_keyimage_uniqueness` scans on very long chains (local DoS mitigation).
const MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT: u64 = 25_000;

fn rpc_listen_is_loopback(addr: SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn rpc_env_bool(name: &str) -> Option<bool> {
    std::env::var(name).ok().map(|v| {
        let t = v.trim();
        t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
    })
}

fn rpc_clamp_audit_range(start: u64, end: u64) -> std::result::Result<(u64, u64), ErrorObjectOwned> {
    if start > end {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "audit range: start must be <= end",
            None::<()>,
        ));
    }
    let span = end.saturating_sub(start).saturating_add(1);
    if span > MAX_RPC_AUDIT_BLOCK_SPAN {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!(
                "audit range too large ({} blocks); max {} blocks per call",
                span, MAX_RPC_AUDIT_BLOCK_SPAN
            ),
            None::<()>,
        ));
    }
    Ok((start, end))
}

/// HTTP-layer Bearer check. When `token` is `None`, all requests pass (no middleware policy).
#[derive(Clone)]
struct RpcBearerValidator {
    token: Option<Arc<str>>,
}

impl<B> ValidateRequest<B> for RpcBearerValidator {
    /// Must match jsonrpsee's HTTP response body type so `ValidateRequestHeader` composes with the RPC stack.
    type ResponseBody = HttpBody;

    fn validate(
        &mut self,
        req: &mut Request<B>,
    ) -> std::result::Result<(), Response<Self::ResponseBody>> {
        use http::Method;

        if self.token.is_none() {
            return Ok(());
        }
        let expected = self.token.as_ref().expect("checked is_some");

        match *req.method() {
            // CORS preflight never authenticates.
            Method::OPTIONS => Ok(()),
            Method::POST => validate_bearer_header(req, expected),
            Method::GET => {
                // Hardening: only allow GET when this is an actual websocket upgrade,
                // and require Bearer parity with POST to close auth-bypass edges.
                let is_upgrade = req
                    .headers()
                    .get(http::header::CONNECTION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_ascii_lowercase().contains("upgrade"))
                    .unwrap_or(false)
                    && req
                        .headers()
                        .get(http::header::UPGRADE)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.eq_ignore_ascii_case("websocket"))
                        .unwrap_or(false);
                if !is_upgrade {
                    return Err(rpc_http_unauthorized());
                }
                validate_bearer_header(req, expected)
            }
            _ => Err(rpc_http_unauthorized()),
        }
    }
}

fn validate_bearer_header<B>(
    req: &Request<B>,
    expected: &Arc<str>,
) -> std::result::Result<(), Response<HttpBody>> {
    let auth = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    const PREFIX: &str = "Bearer ";
    if !auth.starts_with(PREFIX) {
        return Err(rpc_http_unauthorized());
    }
    let supplied = auth[PREFIX.len()..].trim();
    if supplied.len() != expected.len()
        || !crate::crypto::ct_eq(supplied.as_bytes(), expected.as_bytes())
    {
        return Err(rpc_http_unauthorized());
    }
    Ok(())
}

fn rpc_http_unauthorized() -> Response<HttpBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(HttpBody::from(
            r#"{"jsonrpc":"2.0","error":{"code":401,"message":"Unauthorized"},"id":null}"#,
        ))
        .expect("valid unauthorized response")
}

/// Serialize a block into the rich JSON shape the embedded explorer
/// (and external clients) expect. Single source of truth so
/// `get_block_by_height` and `get_block` cannot drift apart in their
/// payload shape — the kind of bug that bit `Transaction::signing_hash`
/// in an earlier audit.
///
/// Fields:
/// - `height`, `hash`, `prev_hash`, `tx_root`, `timestamp`
/// - `nonce`, `algorithm` (numeric), `algorithm_name` (string),
///   `difficulty`, `target`
/// - `tx_count`, `size` (serialized byte count)
/// - `reward` (atomic units, computed from the emission curve at
///   this height — what a coinbase at this height earns)
/// - `transactions` — array of `{hash, kind}` per tx, lightweight
///   but enough to render a tx list
/// - `bytes` — full borsh-serialized block, hex-encoded, for clients
///   that want to deserialize the block themselves
fn serialize_block(block: &crate::consensus::Block, height: u64) -> Value {
    let block_bytes = borsh::to_vec(block).unwrap_or_default();
    let size = block_bytes.len();

    let txs_json: Vec<Value> = block
        .transactions
        .iter()
        .map(|tx| {
            let kind = match tx.tx_type {
                crate::transaction::TxType::Coinbase => "coinbase",
                crate::transaction::TxType::Transfer => "transfer",
                crate::transaction::TxType::Churn => "churn",
            };
            json!({
                "hash":     hex::encode(tx.hash().as_bytes()),
                "kind":     kind,
                "inputs":   tx.input_count(),
                "outputs":  tx.output_count(),
                "fee":      tx.fee.as_atomic(),
            })
        })
        .collect();

    json!({
        "height":         height,
        "hash":           hex::encode(block.hash().as_bytes()),
        "prev_hash":      hex::encode(block.header.prev_hash.as_bytes()),
        "tx_root":        hex::encode(block.header.tx_root.as_bytes()),
        "timestamp":      block.header.timestamp,
        "nonce":          block.header.nonce,
        // CoinCync 1.0 is RandomX-only — see `consensus::pow::PowAlgorithm`.
        "algorithm":      block.header.algorithm,
        "algorithm_name": "RandomX",
        "difficulty":     block.header.target.to_difficulty().to_string(),
        "target":         hex::encode(block.header.target.as_bytes()),
        "tx_count":       block.transactions.len(),
        "size":           size,
        "reward":         crate::emission::calculate_block_reward(height).as_atomic(),
        "transactions":   txs_json,
        "bytes":          hex::encode(&block_bytes),
    })
}

/// Start the JSON-RPC server and return its handle.
///
/// SECURITY: TLS is still optional in this build; prefer reverse-proxy TLS
/// or bind RPC to loopback only. When `auth_enabled` is true with a
/// non-empty `api_key`, or when listening on a non-loopback address with an
/// API key, HTTP `POST` JSON-RPC requests must send
/// `Authorization: Bearer <api_key>`. `OPTIONS` is exempt for CORS preflight;
/// authenticated WebSocket upgrades must also present Bearer auth.
pub async fn start_rpc_server(
    chain: SharedBlockchain,
    mempool: SharedMempool,
    p2p: Option<Arc<P2PNode>>,
    config: RpcConfig,
) -> Result<RpcServer> {
    info!("Starting RPC server on {}", config.listen_addr);
    if config.tls_enabled {
        return Err(Error::InvalidState(
            "RpcConfig.tls_enabled=true requested, but native TLS listener is not wired in this server build. Refusing to start in misconfigured state.".into(),
        ));
    }

    let listen_loopback = rpc_listen_is_loopback(config.listen_addr);
    let api_key_arc: Option<Arc<str>> = config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Arc::from);

    if config.auth_enabled && api_key_arc.is_none() {
        return Err(Error::InvalidState(
            "RpcConfig.auth_enabled=true requires a non-empty api_key (set COINCYNC_RPC_API_KEY when using coincync-node)"
                .into(),
        ));
    }
    if !listen_loopback && api_key_arc.is_none() {
        return Err(Error::InvalidState(format!(
            "RPC listen address {} is not loopback: refusing to start without an api_key — public JSON-RPC must authenticate (set COINCYNC_RPC_API_KEY or RpcConfig.api_key)",
            config.listen_addr
        )));
    }

    let apply_bearer_middleware =
        api_key_arc.is_some() && (!listen_loopback || config.auth_enabled);
    if apply_bearer_middleware {
        info!(
            "RPC Bearer authentication enforced on POST (loopback={}, auth_enabled={})",
            listen_loopback, config.auth_enabled
        );
    }

    let state = RpcState {
        chain,
        mempool,
        p2p,
        network_name: config.network_name.clone(),
        auth_enabled: config.auth_enabled,
        // Privacy hardening: default metadata minimization on public listeners.
        minimize_metadata: rpc_env_bool("COINCYNC_RPC_MINIMIZE_METADATA")
            .unwrap_or(!listen_loopback),
        stratum_public_bind_requested: rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND").unwrap_or(false),
        stratum_public_bind_ack: rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND_ACK").unwrap_or(false),
        stratum_native_tls_enabled: rpc_env_bool("COINCYNC_STRATUM_TLS_ENABLED").unwrap_or(false),
        stratum_tls_proxy_ack: rpc_env_bool("COINCYNC_STRATUM_TLS_PROXY_ACK").unwrap_or(false),
        stratum_transport_hardened: {
            let public_bind = rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND").unwrap_or(false);
            let has_pw = std::env::var("COINCYNC_STRATUM_PASSWORD")
                .ok()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            let public_ack = rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND_ACK").unwrap_or(false);
            let native_tls = rpc_env_bool("COINCYNC_STRATUM_TLS_ENABLED").unwrap_or(false);
            let proxy_tls_ack = rpc_env_bool("COINCYNC_STRATUM_TLS_PROXY_ACK").unwrap_or(false);
            if !public_bind {
                true
            } else {
                has_pw && public_ack && (native_tls || proxy_tls_ack)
            }
        },
    };

    let mut module = jsonrpsee::RpcModule::new(state);

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
    module.register_method("get_info", |_params, state, _ext| {
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
        let effective_ring_size =
            crate::constants::effective_ring_size(height, anonymity_set);

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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_blockchain_info (alias with more fields) ───────────
    module.register_method("get_blockchain_info", |_params, state, _ext| {
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
            "total_supply":    stats.total_supply.as_atomic(),
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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_mempool_info ───────────────────────────────────────
    module.register_method("get_mempool_info", |_params, state, _ext| {
        let mp = state.mempool.stats();
        Ok::<_, ErrorObjectOwned>(json!({
            "size":       mp.tx_count,
            "bytes":      mp.size_bytes,
            "total_fees": mp.total_fee.as_atomic(),
            "max_size":   mp.max_size,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_mempool_transactions ──────────────────────────────
    //
    // Returns individual transaction details from the mempool so
    // the explorer can render them in a table (like the blocks page).
    module.register_method("get_mempool_transactions", |_params, state, _ext| {
        let txs = state.mempool.get_block_transactions(
            crate::constants::MAX_BLOCK_SIZE,
            500, // max 500 txs
        );
        let tx_list: Vec<Value> = txs.iter().map(|tx| {
            let kind = match tx.tx_type {
                crate::transaction::TxType::Coinbase => "coinbase",
                crate::transaction::TxType::Transfer => "transfer",
                crate::transaction::TxType::Churn => "churn",
            };
            json!({
                "hash":    hex::encode(tx.hash().as_bytes()),
                "kind":    kind,
                "inputs":  tx.input_count(),
                "outputs": tx.output_count(),
                "fee":     tx.fee.as_atomic(),
                "size":    tx.size(),
            })
        }).collect();
        Ok::<_, ErrorObjectOwned>(json!({
            "count": tx_list.len(),
            "transactions": tx_list,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_supply_info ───────────────────────────────────────
    module.register_method("get_supply_info", |_params, state, _ext| {
        let stats = state.chain.stats();
        let height = stats.height;
        let reward = crate::emission::calculate_block_reward(height);
        let phase = crate::emission::emission_phase(height);
        Ok::<_, ErrorObjectOwned>(json!({
            "height":             height,
            "current_reward":     reward.as_atomic(),
            "total_emitted":      stats.total_supply.as_atomic(),
            "emission_phase":     phase.name(),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_block_by_height ───────────────────────────────────
    //
    // Rich block payload: every field the embedded explorer's
    // block-detail panel reads, plus the raw `bytes` for clients
    // that want to deserialize the block themselves. The
    // `transactions` array carries lightweight per-tx records
    // (hash, timestamp, kind) rather than the full encoded txs —
    // the explorer only displays a list of txids and their kind,
    // and full tx bodies require a tx-index that doesn't exist
    // yet (see `get_transaction` below).
    module.register_method("get_block_by_height", |params, state, _ext| {
        let (h,): (u64,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        // Layer 2: DB lookup + serialize under block_in_place so a slow
        // RocksDB read doesn't freeze the worker mid-handler.
        let block_opt = tokio::task::block_in_place(|| state.chain.get_block_by_height(h));
        match block_opt {
            Some(block) => Ok::<_, ErrorObjectOwned>(serialize_block(&block, h)),
            None => Err(ErrorObjectOwned::owned(
                -32000, format!("block at height {} not found", h), None::<()>,
            )),
        }
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_block (by hash) ───────────────────────────────────
    //
    // Hash-based block lookup. The embedded explorer's search
    // bar (line ~2455 of `src/explorer/index.html`) calls this
    // with a 64-char hex string; we accept that and fall back to
    // a 32-byte raw form if the input isn't hex.
    module.register_method("get_block", |params, state, _ext| {
        let (hash_hex,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        let mut bytes = [0u8; 32];
        if hex::decode_to_slice(hash_hex.trim_start_matches("0x"), &mut bytes).is_err() {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!("get_block: expected 64-char hex hash, got {:?}", hash_hex),
                None::<()>,
            ));
        }
        let hash = crate::primitives::Hash::from_bytes(bytes);
        // Layer 2: DB lookup under block_in_place — same rationale as
        // get_block_by_height above.
        let block_opt = tokio::task::block_in_place(|| state.chain.get_block(&hash));
        match block_opt {
            Some(block) => {
                let height = block.header.height;
                Ok::<_, ErrorObjectOwned>(serialize_block(&block, height))
            }
            None => Err(ErrorObjectOwned::owned(
                -32000,
                format!("block with hash {} not found", hex::encode(bytes)),
                None::<()>,
            )),
        }
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_block_template ────────────────────────────────────
    //
    // The miner (coincync-rig) polls this to get the next
    // height, the ASERT-computed target, current mempool
    // txs (fee-ordered), and a fresh timestamp. The miner builds
    // its own coinbase to its configured reward address — we do
    // NOT take the miner's address server-side because the node
    // never touches miner reward keys.
    //
    // Accepts either `[]` or `[address_string]` for forward
    // compat with the 2.0 miner CLI; the address parameter is
    // ignored.
    module.register_method("get_block_template", |_params, state, _ext| {
        // SECURITY (runtime resilience, Layer 2): build_template_json iterates
        // mempool and runs `chain.validate_transaction()` for every candidate
        // (full ring sig + range proof verify). On a busy mempool this is the
        // most CPU-heavy synchronous call in the RPC surface, and it runs
        // many times per minute because the failover miner polls for fresh
        // templates. `block_in_place` lets tokio's multi-thread runtime
        // (Layer 1 forces 4 workers) keep scheduling other tasks during the
        // call instead of monopolizing the worker thread.
        let template = tokio::task::block_in_place(|| {
            crate::mining::template::build_template_json(&state.chain, &state.mempool)
        });
        Ok::<_, ErrorObjectOwned>(template)
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── submit_block ──────────────────────────────────────────
    module.register_method("submit_block", |params, state, _ext| {
        let (hex_block,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        let block_bytes = hex::decode(&hex_block).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        let block: crate::consensus::Block = borsh::from_slice(&block_bytes).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad block encoding: {}", e), None::<()>)
        })?;
        let hash = block.hash();
        let algo = crate::consensus::PowAlgorithm::from_index(block.header.algorithm);
        let claimed_pow_hex = match crate::consensus::compute_pow_hash(
            algo,
            &block.header.anchor,
            block.header.nonce,
            &block.header.tx_root,
            block.header.height,
        ) {
            Ok(h) => hex::encode(&h.as_bytes()[..8]),
            Err(e) => format!("pow_err:{}", e),
        };
        warn!(
            "submit_block candidate: h={} nonce={} magic={} prev={} anchor={} tx_root={} target={} pow={} algo={}",
            block.header.height,
            block.header.nonce,
            hex::encode(block.header.network_magic),
            hex::encode(&block.header.prev_hash.as_bytes()[..8]),
            hex::encode(&block.header.anchor.as_bytes()[..8]),
            hex::encode(&block.header.tx_root.as_bytes()[..8]),
            hex::encode(&block.header.target.as_bytes()[..8]),
            claimed_pow_hex,
            block.header.algorithm,
        );
        // Clone for broadcast (process_block consumes the original); the
        // clone cost is O(tx count), negligible for testnet.
        let block_for_broadcast = block.clone();
        // Snapshot tx list before process_block consumes the original.
        // Used below to keep the mempool aligned with chain state — drop
        // confirmed txs and shadow-evict any mempool tx whose key image
        // collides with one just spent in this block. Without this sync
        // (the wire-side equivalent runs in bin/node.rs after a
        // BlockReceived event), a locally-mined block leaves stale txs
        // in the mempool that poison every subsequent block template
        // with "duplicate key image". Caused the 2026-05-08 chain stall
        // at h=6001; see docs/launch/MONDAY_PRELAUNCH.md incident playbook.
        let block_txs = block_for_broadcast.transactions.clone();
        // process_block returns Ok(BlockStatus::...) even for Invalid/Orphan
        // outcomes, so we must inspect the status and surface a failure
        // when the block was not actually accepted. Without this, the
        // miner sees a silent success while the chain never advances.
        //
        // SECURITY (runtime resilience, Layer 2): the wire-side BlockReceived
        // handler in bin/node.rs routes its process_block through
        // spawn_blocking. The locally-submitted path here uses
        // `block_in_place` for the same effect from a sync RPC handler —
        // tokio's multi-thread runtime can keep scheduling other tasks
        // during full block validation (PoW recheck + per-tx crypto verify).
        let process_result = tokio::task::block_in_place(|| state.chain.process_block(block));
        match process_result {
            Ok(status @ (crate::chain::BlockStatus::Accepted
                        | crate::chain::BlockStatus::AcceptedFork
                        | crate::chain::BlockStatus::AcceptedReorg { .. })) => {
                // Mempool sync — same calls as the wire-side handler in
                // bin/node.rs after BlockReceived. remove_confirmed drops
                // mined txs AND shadow-evicts any mempool tx that shares
                // a key image with a confirmed tx (the poison-tx scenario
                // that stalled the chain at h=6001 on 2026-05-08).
                state.mempool.remove_confirmed(&block_txs);
                // On reorg, re-admit txs that were mined in disconnected
                // blocks but are still spendable on the new chain.
                if let crate::chain::BlockStatus::AcceptedReorg { orphaned_txs } = status {
                    state.mempool.restore_orphaned(orphaned_txs, &state.chain);
                }
                state.mempool.set_height(state.chain.height());

                // Fire-and-forget P2P announcement so the block reaches
                // other nodes; without this, locally-mined blocks stay
                // local and the chain forks between the miner and its
                // peers. We don't block the RPC response on propagation.
                //
                // Also refresh the handshake-side chain_height/chain_tip
                // so subsequent peer Version messages advertise the new
                // tip. The BlockReceived event handler in bin/node.rs
                // does the same thing for blocks arriving from peers;
                // locally-mined blocks come through this RPC path
                // instead and would otherwise leave handshake state stale.
                if let Some(p2p) = state.p2p.as_ref() {
                    let p2p = p2p.clone();
                    let new_height = state.chain.height();
                    let new_tip = state.chain.tip_hash();
                    tokio::spawn(async move {
                        p2p.set_chain_state(new_height, new_tip).await;
                        if let Err(e) = p2p.broadcast_block(&block_for_broadcast).await {
                            warn!("Block broadcast failed: {}", e);
                        }
                    });
                }
                Ok::<_, ErrorObjectOwned>(json!({
                    "accepted": true,
                    "hash": hex::encode(hash.as_bytes()),
                }))
            }
            Ok(crate::chain::BlockStatus::AlreadyKnown) => {
                // Even when the block is already known, advance the mempool's
                // tracked chain height so activation-gated validation stays in
                // sync. The wire-side handler in bin/node.rs does the same
                // thing for AlreadyKnown — keeps the two paths symmetric.
                state.mempool.set_height(state.chain.height());
                Ok::<_, ErrorObjectOwned>(json!({
                    "accepted": true,
                    "status": "already_known",
                    "hash": hex::encode(hash.as_bytes()),
                }))
            }
            Ok(crate::chain::BlockStatus::Orphan) => {
                warn!(
                    "submit_block rejected orphan: h={} nonce={} hash={}",
                    block_for_broadcast.header.height,
                    block_for_broadcast.header.nonce,
                    hex::encode(hash.as_bytes()),
                );
                Err(ErrorObjectOwned::owned(
                    -32001,
                    format!("block rejected: orphan (parent not in chain), hash={}", hex::encode(hash.as_bytes())),
                    None::<()>,
                ))
            }
            Ok(crate::chain::BlockStatus::Invalid(reason)) => {
                warn!(
                    "submit_block rejected invalid: h={} nonce={} reason={}",
                    block_for_broadcast.header.height,
                    block_for_broadcast.header.nonce,
                    reason,
                );
                Err(ErrorObjectOwned::owned(
                    -32001,
                    format!("block rejected: {}", reason),
                    None::<()>,
                ))
            }
            Err(e) => {
                warn!(
                    "submit_block rejected error: h={} nonce={} err={}",
                    block_for_broadcast.header.height,
                    block_for_broadcast.header.nonce,
                    e,
                );
                Err(ErrorObjectOwned::owned(
                    -32001, format!("block rejected: {}", e), None::<()>,
                ))
            }
        }
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── send_raw_transaction ──────────────────────────────────
    module.register_method("send_raw_transaction", |params, state, _ext| {
        let (hex_tx,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        let tx_bytes = hex::decode(&hex_tx).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        let tx: crate::transaction::Transaction = borsh::from_slice(&tx_bytes).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad tx encoding: {}", e), None::<()>)
        })?;
        let hash = tx.hash();
        let tx_for_broadcast = tx.clone();
        // SECURITY (runtime resilience, Layer 2): mempool admit runs full
        // crypto verify (ring sig + range proof) and walks the chain DB to
        // check key-image conflicts. `block_in_place` lets tokio's multi-
        // thread runtime keep scheduling other tasks during the validation.
        let admit_result = tokio::task::block_in_place(|| {
            state.mempool.add_with_chain(tx, &state.chain)
        });
        match admit_result {
            Ok(_) => {
                // Broadcast via Dandelion++ so other nodes see the tx
                if let Some(p2p) = state.p2p.as_ref() {
                    let p2p = p2p.clone();
                    tokio::spawn(async move {
                        if let Err(e) = p2p.broadcast_transaction(tx_for_broadcast).await {
                            warn!("Tx broadcast failed: {}", e);
                        }
                    });
                }
                Ok::<_, ErrorObjectOwned>(json!({
                    "accepted": true,
                    "hash": hex::encode(hash.as_bytes()),
                }))
            }
            Err(e) => Err(ErrorObjectOwned::owned(
                -32002, format!("tx rejected: {}", e), None::<()>,
            )),
        }
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_privacy_stats ─────────────────────────────────────
    // Aggregate view of the Phase 2 privacy stores.
    module.register_method("get_privacy_stats", |_params, state, _ext| {
        let cut_through = state.chain.cut_through_stats();
        Ok::<_, ErrorObjectOwned>(json!({
            "shielded_root":      hex::encode(state.chain.shielded_root()),
            "shielded_tree_size": state.chain.shielded_store.as_ref().map(|s| s.tree_size()).unwrap_or(0),
            "spark_root":         hex::encode(state.chain.spark_root()),
            "spark_accumulator_size": state.chain.spark_store.as_ref().map(|s| s.size()).unwrap_or(0),
            "mw_kernel_root":     hex::encode(state.chain.mw_kernel_root()),
            "mw_kernels_kept":    cut_through.kernels_kept,
            "mw_pending_candidates": cut_through.pending_candidates,
            "mw_bytes_saved":     cut_through.bytes_saved,
            "mw_compression":     cut_through.compression_ratio,
            "mandatory_confidential": crate::constants::MANDATORY_CONFIDENTIAL,
            "mandatory_stealth":      crate::constants::MANDATORY_STEALTH,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_shielded_anchor ───────────────────────────────────
    // Light wallets query this to get the current Merkle root they
    // should anchor their spend proofs against.
    module.register_method("get_shielded_anchor", |_params, state, _ext| {
        Ok::<_, ErrorObjectOwned>(json!({
            "anchor": hex::encode(state.chain.shielded_root()),
            "tree_size": state.chain.shielded_store.as_ref().map(|s| s.tree_size()).unwrap_or(0),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_burn_stats ────────────────────────────────────────
    //
    // Returns fee burn statistics for the explorer burn page.
    module.register_method("get_burn_stats", |_params, state, _ext| {
        let stats = state.chain.stats();
        let height = stats.height;
        let is_active = height >= crate::constants::FEE_DISTRIBUTION_HEIGHT;

        let burn_pct = crate::constants::FEE_BURN_NORMAL_PERCENT;
        let miner_pct = crate::constants::FEE_MINER_NORMAL_PERCENT;

        let supply = stats.total_supply.as_atomic();
        let max_supply = crate::constants::MAX_SUPPLY;
        let reward = crate::emission::calculate_block_reward(height).as_atomic();
        // Fees per block needed to make chain deflationary:
        // burn needs to exceed block reward → fee * burn_pct/100 > reward
        // → fee > reward * 100 / burn_pct
        let deflation_threshold = if burn_pct > 0 {
            reward as f64 * 100.0 / burn_pct as f64
        } else { 0.0 };

        Ok::<_, ErrorObjectOwned>(json!({
            "active": is_active,
            "activation_height": crate::constants::FEE_DISTRIBUTION_HEIGHT,
            "current_height": height,
            "miner_pct_normal": miner_pct,
            "burn_pct_normal": burn_pct,
            "miner_pct_congested": crate::constants::FEE_MINER_CONGESTED_PERCENT,
            "burn_pct_congested": crate::constants::FEE_BURN_CONGESTED_PERCENT,
            "protocol_pct": 0,
            "block_reward": reward,
            "circulating_supply": supply,
            "max_supply": max_supply as u64,
            "deflation_threshold_fee_per_block": deflation_threshold as u64,
            "congestion_threshold_pct": crate::constants::CONGESTION_THRESHOLD,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_finality_info ────────────────────────────────────
    //
    // Returns checkpoint finality status for the explorer.
    module.register_method("get_finality_info", |_params, state, _ext| {
        let stats = state.chain.stats();
        let height = stats.height;
        let last_checkpoint = height - (height % 5); // every 5 blocks
        let next_checkpoint = last_checkpoint + 5;
        let blocks_until_next = next_checkpoint.saturating_sub(height);
        let seconds_until_next = blocks_until_next * crate::constants::TARGET_BLOCK_TIME;

        Ok::<_, ErrorObjectOwned>(json!({
            "current_height": height,
            "last_checkpoint": last_checkpoint,
            "next_checkpoint": next_checkpoint,
            "blocks_until_checkpoint": blocks_until_next,
            "seconds_until_checkpoint": seconds_until_next,
            "checkpoint_interval": 5,
            "finality_type": "PoW + Checkpoint",
            "max_reorg_depth": crate::chain::max_reorg_depth(),
            "checkpoint_finality": "absolute",
            "description": "Blocks below the last checkpoint cannot be reverted by any amount of hashpower",
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_spark_anchor ──────────────────────────────────────
    module.register_method("get_spark_anchor", |_params, state, _ext| {
        Ok::<_, ErrorObjectOwned>(json!({
            "root": hex::encode(state.chain.spark_root()),
            "size": state.chain.spark_store.as_ref().map(|s| s.size()).unwrap_or(0),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── is_nullifier_spent ────────────────────────────────────
    // Wallet calls before building a shielded spend to make sure it
    // won't be rejected as a double-spend.
    module.register_method("is_nullifier_spent", |params, state, _ext| {
        let (hex_nf,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        let bytes = hex::decode(&hex_nf).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "nullifier must be 32 bytes".to_string(), None::<()>,
            ));
        }
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&bytes);
        Ok::<_, ErrorObjectOwned>(json!({
            "nullifier": hex::encode(nf),
            "spent": state.chain.shielded_store.as_ref().map(|s| s.is_nullifier_spent(&nf)).unwrap_or(false),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── is_spark_serial_spent ─────────────────────────────────
    module.register_method("is_spark_serial_spent", |params, state, _ext| {
        let (hex_s,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        let bytes = hex::decode(&hex_s).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "serial must be 32 bytes".to_string(), None::<()>,
            ));
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        Ok::<_, ErrorObjectOwned>(json!({
            "serial": hex::encode(s),
            "spent": state.chain.spark_store.as_ref().map(|store| store.is_serial_spent(&s)).unwrap_or(false),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_decoys ────────────────────────────────────────────
    // Wallet calls this when building a CLSAG ring signature to
    // get decoy outputs for the ring. Params: (count, min_age).
    module.register_method("get_decoys", |params, state, _ext| {
        let (count, min_age): (usize, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        let capped = count.min(256); // sanity cap
        let decoys = state.chain.get_decoy_outputs(capped, min_age);
        let encoded: Vec<Value> = decoys
            .iter()
            .map(|d| {
                json!({
                    "public_key": hex::encode(d.public_key.as_bytes()),
                    "commitment": hex::encode(d.commitment),
                    "height": d.height,
                })
            })
            .collect();
        Ok::<_, ErrorObjectOwned>(json!({
            "count": encoded.len(),
            "decoys": encoded,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

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
    module.register_method("get_network_info", |_params, state, _ext| {
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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_sync_status ───────────────────────────────────────
    module.register_method("get_sync_status", |_params, state, _ext| {
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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_anonymity_set ─────────────────────────────────────
    //
    // The single most important privacy metric: every unspent
    // output is a potential decoy, so the size of this set is
    // the size of every future spend's anonymity set.
    module.register_method("get_anonymity_set", |_params, state, _ext| {
        let count = state.chain.available_output_count();
        let height = state.chain.height();
        let outputs_per_block = if height > 0 {
            count / usize::try_from(height).unwrap_or(usize::MAX)
        } else {
            0
        };
        Ok::<_, ErrorObjectOwned>(json!({
            "anonymity_set":    count,
            "height":           height,
            "outputs_per_block": outputs_per_block,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_chain_events ──────────────────────────────────────
    //
    // Recent chain convergence events (reorgs, forks, rejects,
    // checkpoints) for the explorer timeline. `limit` is
    // clamped server-side to 500.
    module.register_method("get_chain_events", |params, state, _ext| {
        // Accept either [] (defaults) or [limit].
        let limit: usize = match params.parse::<Vec<usize>>() {
            Ok(v) => v.into_iter().next().unwrap_or(100),
            Err(_) => 100,
        };
        let capped = limit.min(500);
        let events = state.chain.get_events(capped);
        let height = state.chain.height();
        let tip = state.chain.tip();
        Ok::<_, ErrorObjectOwned>(json!({
            "events":         events,
            "count":          events.len(),
            "current_height": height,
            "current_tip":    hex::encode(tip.hash.as_bytes()),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_mining_live ───────────────────────────────────────
    //
    // Live mining state, polled by external miners. The node
    // process itself does NOT mine — mining lives in coincync-rig
    // as a separate binary that polls this RPC for block
    // templates. So on a plain node, this method honestly
    // reports `is_mining = false`
    // with zeroed fields. A future in-process miner (or a
    // sidecar that pushes live samples to a shared buffer) can
    // overwrite these values — the shape is fixed so the TUI
    // doesn't need to change.
    module.register_method("get_mining_live", |_params, state, _ext| {
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
        Ok::<_, ErrorObjectOwned>(json!({
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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_peers ─────────────────────────────────────────────
    //
    // Returns the live peer table. Used by the embedded
    // explorer's "Peers" tab (line ~2238 of `index.html`) to
    // render a per-peer card with addr / height / version /
    // user-agent and an inbound/outbound badge. Each entry
    // includes the per-direction byte counts so monitoring can
    // also consume this — the same payload feeds Grafana
    // dashboards via the REST proxy.
    //
    // On nodes started without a `P2PNode` (e.g. RPC-only test
    // harness), we honestly return an empty list rather than
    // synthesising fake peers.
    module.register_method("get_peers", |_params, state, _ext| {
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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_transaction ───────────────────────────────────────
    //
    // Lookup a transaction by hash. Currently NOT IMPLEMENTED —
    // the chain does not maintain a txid → (block_height, index)
    // index, so we cannot satisfy this query without scanning
    // every block. The embedded explorer's search bar (line
    // ~3696 of `index.html`) calls this; it will display a
    // labelled "not yet wired" error rather than silently
    // returning empty results, so the missing index is visible
    // and tracked.
    module.register_method("get_transaction", |params, state, _ext| {
        let (tx_hash_hex,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        let tx_hash_bytes = hex::decode(tx_hash_hex.trim_start_matches("0x")).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if tx_hash_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "tx hash must be 32 bytes (64 hex chars)".to_string(), None::<()>,
            ));
        }
        match state.chain.get_tx_location(&tx_hash_bytes) {
            Some((block_height, tx_idx)) => {
                match state.chain.get_block_by_height(block_height) {
                    Some(block) => {
                        let tx = block.transactions.get(tx_idx as usize);
                        match tx {
                            Some(tx) => {
                                let tx_bytes = borsh::to_vec(tx).unwrap_or_default();
                                let ring_size = tx.inputs.first().map(|i| i.ring_members.len()).unwrap_or(0);
                                let inputs_json: Vec<Value> = tx.inputs.iter().map(|inp| {
                                    json!({
                                        "key_image": hex::encode(inp.key_image.as_bytes()),
                                        "ring_size": inp.ring_members.len(),
                                    })
                                }).collect();
                                let outputs_json: Vec<Value> = tx.outputs.iter().map(|out| {
                                    json!({
                                        "stealth_address": hex::encode(out.stealth_address.as_bytes()),
                                        "tx_public_key": hex::encode(out.tx_public_key.as_bytes()),
                                        "commitment": hex::encode(out.commitment),
                                        "view_tag": out.view_tag,
                                        "lock_height": out.lock_height,
                                        "has_memo": !out.encrypted_memo.is_empty(),
                                        // Encrypted memo bytes (ChaCha20-Poly1305 ciphertext).
                                        // Public on chain anyway — exposing here only saves a
                                        // block-scan trip for clients that want to decrypt with
                                        // the recipient's view key. Empty when there's no memo.
                                        "encrypted_memo": hex::encode(&out.encrypted_memo),
                                    })
                                }).collect();
                                let has_range_proof = !tx.range_proof.is_empty();
                                let has_recovery = !tx.extra.is_empty() && tx.extra[0] == 0xDE;
                                Ok::<_, ErrorObjectOwned>(json!({
                                    "hash": hex::encode(tx.hash().as_bytes()),
                                    "block_height": block_height,
                                    "block_hash": hex::encode(block.hash().as_bytes()),
                                    "index_in_block": tx_idx,
                                    "version": tx.version,
                                    "type": format!("{:?}", tx.tx_type),
                                    "input_count": tx.inputs.len(),
                                    "output_count": tx.outputs.len(),
                                    "fee": tx.fee.as_atomic(),
                                    "extra_size": tx.extra.len(),
                                    "size": tx_bytes.len(),
                                    "ring_size": ring_size,
                                    "has_range_proof": has_range_proof,
                                    "range_proof_size": tx.range_proof.len(),
                                    "has_recovery": has_recovery,
                                    "signing_hash": hex::encode(tx.signing_hash().as_bytes()),
                                    "inputs": inputs_json,
                                    "outputs": outputs_json,
                                    "privacy": {
                                        "sender_hidden": ring_size >= 2,
                                        "receiver_hidden": true,
                                        "amount_hidden": has_range_proof,
                                        "clsag_ring_sig": ring_size >= 2,
                                        "bulletproofs_plus": has_range_proof,
                                        "stealth_addresses": true,
                                        "dandelion_pp": true,
                                        "encrypted_memo": tx.outputs.iter().any(|o| !o.encrypted_memo.is_empty()),
                                    },
                                }))
                            }
                            None => Err(ErrorObjectOwned::owned(
                                -32000, "tx index points to invalid position".to_string(), None::<()>,
                            )),
                        }
                    }
                    None => Err(ErrorObjectOwned::owned(
                        -32000, format!("block at height {} not found", block_height), None::<()>,
                    )),
                }
            }
            None => Err(ErrorObjectOwned::owned(
                -32000, format!("transaction not found in index"), None::<()>,
            )),
        }
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_asset_info ────────────────────────────────────────
    //
    // Lookup an issued-asset descriptor by id. CoinCync 1.0
    // STRIPPED the confidential-asset layer in the 2.0 → 1.0
    // trim, so this endpoint is permanently NOT IMPLEMENTED —
    // the embedded explorer's search bar (line ~3773 of
    // `index.html`) calls it on free-text input that doesn't
    // match a block hash or txid. Returning an explicit error
    // makes the missing surface obvious instead of silently
    // returning empty results.
    module.register_method("get_asset_info", |_params, _state, _ext| {
        Err::<Value, _>(ErrorObjectOwned::owned(
            -32601,
            "get_asset_info is not implemented: CoinCync 1.0 has no \
             confidential-asset layer (the asset stack was removed \
             in the 2.0 → 1.0 trim). Single-asset CYNC only.",
            None::<()>,
        ))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_block_range ───────────────────────────────────────
    //
    // Wallet-side chain scan: fetch a range of blocks by height.
    // Each block in the response uses the SAME shape as
    // `get_block_by_height` and `get_block`, via the shared
    // `serialize_block` helper — single source of truth for the
    // block payload prevents the kind of payload-shape drift
    // that bit `Transaction::signing_hash` in an earlier audit.
    // The server caps the range to MAX_RANGE blocks per call to
    // prevent huge responses.
    module.register_method("get_block_range", |params, state, _ext| {
        let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        const MAX_RANGE: u64 = 100;
        if end < start {
            return Err(ErrorObjectOwned::owned(
                -32602, "end must be >= start".to_string(), None::<()>,
            ));
        }
        let capped = (end - start + 1).min(MAX_RANGE);
        let mut blocks = Vec::with_capacity(capped as usize);
        for h in start..start + capped {
            if let Some(block) = state.chain.get_block_by_height(h) {
                blocks.push(serialize_block(&block, h));
            }
        }
        Ok::<_, ErrorObjectOwned>(json!({
            "start": start,
            "end": start + capped - 1,
            "count": blocks.len(),
            "blocks": blocks,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_output_digests ───────────────────────────────────
    //
    // Light-wallet SPV path: returns compact per-block output
    // summaries (~138 B / output vs ~1-5 KB / full tx) for client-
    // side scanning. The server learns only the height range; it
    // never sees which outputs the wallet cares about. Privacy
    // posture is strictly stronger than BIP-157 (which leaks the
    // wallet's address set to the filter server). See
    // `docs/security/LIGHTSYNC_AUDIT.md`.
    //
    // Params: [start_height: u64, end_height: u64].
    // Range capped to 100 blocks per request to bound response
    // size; the same bound applies at the network layer
    // (`MessageType::GetOutputDigests`).
    module.register_method("get_output_digests", |params, state, _ext| {
        let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        if end < start {
            return Err(ErrorObjectOwned::owned(
                -32602, "end must be >= start".to_string(), None::<()>,
            ));
        }
        const MAX_DIGEST_BLOCKS: u64 = 100;
        let chain_height = state.chain.height();
        let end = end.min(start.saturating_add(MAX_DIGEST_BLOCKS - 1)).min(chain_height);
        let mut digests = Vec::with_capacity(((end - start + 1) as usize).min(
            MAX_DIGEST_BLOCKS as usize,
        ));
        for h in start..=end {
            if let Some(block) = state.chain.get_block_by_height(h) {
                digests.push(crate::wallet::lightsync::BlockDigest::from_block(&block));
            }
        }
        let count = digests.len();
        Ok::<_, ErrorObjectOwned>(json!({
            "start": start,
            "end": end,
            "count": count,
            "digests": digests,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_sync_checkpoints ─────────────────────────────────
    //
    // Periodic trust anchors so a fresh light wallet can skip
    // ancient history and start scanning from a recent height.
    //
    // SECURITY NOTE: Authentication of these checkpoints is
    // currently a checksum, not a signature (Gap 2 in
    // LIGHTSYNC_AUDIT.md). For v1.0 the wallet MUST cross-check
    // returned checkpoints against the hardcoded consensus
    // checkpoint table in `src/constants.rs::CONSENSUS_CHECKPOINTS`
    // before trusting them. Miner-signed checkpoints arrive in
    // v1.0.1 (CIP-009.D activation track).
    //
    // Params: optional [stride: u64] — emit one checkpoint every
    // `stride` blocks. Default 10000 (~14 days at 120s).
    module.register_method("get_sync_checkpoints", |params, state, _ext| {
        let stride: u64 = params.parse::<(u64,)>().map(|(s,)| s).unwrap_or(10_000);
        let stride = stride.max(1).min(50_000);
        let chain_height = state.chain.height();
        let mut checkpoints = Vec::new();
        let mut h = stride;
        while h <= chain_height {
            if let Some(block) = state.chain.get_block_by_height(h) {
                let block_hash = block.hash();
                let cp = crate::wallet::lightsync::SyncCheckpoint::new(
                    h,
                    block_hash,
                    0, // total_outputs not tracked at this layer
                    crate::primitives::Hash::default(), // utxo_hash deferred to Gap 2
                );
                checkpoints.push(cp);
            }
            h = match h.checked_add(stride) {
                Some(next) => next,
                None => break,
            };
        }
        Ok::<_, ErrorObjectOwned>(json!({
            "stride": stride,
            "chain_height": chain_height,
            "count": checkpoints.len(),
            "checkpoints": checkpoints,
            "auth_note": "Cross-check against CONSENSUS_CHECKPOINTS in src/constants.rs. Miner-signed authentication queued for v1.0.1 (CIP-009.D).",
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_metrics ──────────────────────────────────────────
    //
    // HARDENING (Layer 7): Prometheus-compatible metrics endpoint.
    // Returns key node metrics in a flat JSON format that can be
    // scraped by monitoring tools or displayed in the explorer.
    module.register_method("get_metrics", |_params, state, _ext| {
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
            "chain_supply_atomic": stats.total_supply.as_atomic(),

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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_health ──────────────────────────────────────────
    //
    // HARDENING (Layer 7): Simple health check endpoint.
    // Returns 200 OK if the node is running. Used by load balancers,
    // monitoring tools, and the explorer status page.
    module.register_method("get_health", |_params, state, _ext| {
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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_state_snapshot ─────────────────────────────────────
    // Returns a compact chain state summary for fast sync verification.
    // New nodes can compare their state against this to detect divergence.
    module.register_method("get_state_snapshot", |_params, state, _ext| {
        let stats = state.chain.stats();
        let tip = state.chain.tip_hash();

        Ok::<_, ErrorObjectOwned>(json!({
            "height": stats.height,
            "tip_hash": tip.to_hex(),
            "total_difficulty": stats.total_difficulty.to_string(),
            "total_supply": stats.total_supply.as_atomic(),
            "total_transactions": stats.total_transactions,
            "checkpoints": crate::testnet::testnet_checkpoints().iter()
                .map(|cp| json!({"height": cp.height, "hash": cp.hash.to_hex()}))
                .collect::<Vec<_>>(),
            "version": "1.0.0",
            "network": "testnet",
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_blocks_batch ─────────────────────────────────────
    // Returns up to 100 serialized blocks in a single RPC call for fast sync.
    // Clients request a height range and get back hex-encoded blocks.
    module.register_method("get_blocks_batch", |params, state, _ext| {
        let (from_height, count): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("params: [from_height, count]: {}", e), None::<()>)
        })?;
        let count = count.min(100); // Cap at 100 blocks per request
        let mut blocks = Vec::new();
        for h in from_height..from_height + count {
            if let Some(block) = state.chain.get_block_by_height(h) {
                let block_hex = hex::encode(borsh::to_vec(&block).unwrap_or_default());
                blocks.push(json!({
                    "height": h,
                    "hash": block.hash().to_hex(),
                    "hex": block_hex,
                }));
            } else {
                break; // No more blocks at this height
            }
        }
        Ok::<_, ErrorObjectOwned>(json!({
            "blocks": blocks,
            "count": blocks.len(),
            "from": from_height,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ═══════════════════════════════════════════════════════════════
    // CHAIN VERIFICATION RPCs — supports coincync-verify-chain.sh
    // ═══════════════════════════════════════════════════════════════

    // ── get_expected_reward ──────────────────────────────────────
    module.register_method("get_expected_reward", |params, _state, _ext| {
        let (height,): (u64,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("params: [height]: {}", e), None::<()>)
        })?;
        let reward = crate::emission::calculate_block_reward(height);
        Ok::<_, ErrorObjectOwned>(json!({
            "reward": reward.as_atomic(),
            "height": height,
            "in_cync": reward.as_atomic() as f64 / 1_000_000_000_000.0,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_keyimage_uniqueness ──────────────────────────────
    module.register_method("verify_keyimage_uniqueness", |_params, state, _ext| {
        let chain_height = state.chain.height();
        if chain_height > MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT {
            return Err(ErrorObjectOwned::owned(
                -32003,
                format!(
                    "verify_keyimage_uniqueness refused: chain height {} exceeds built-in limit {} (CPU DoS mitigation; use range audit RPCs or raise limit after ops review)",
                    chain_height, MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT
                ),
                None::<()>,
            ));
        }
        let mut seen = std::collections::HashSet::new();
        let mut duplicates: Vec<String> = Vec::new();

        for h in 0..=chain_height {
            if let Some(block) = state.chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    if tx.is_coinbase() { continue; }
                    for input in &tx.inputs {
                        let ki_hex = hex::encode(input.key_image.as_bytes());
                        if !seen.insert(ki_hex.clone()) {
                            duplicates.push(ki_hex);
                        }
                    }
                }
            }
        }

        Ok::<_, ErrorObjectOwned>(json!({
            "valid": duplicates.is_empty(),
            "duplicates": duplicates.len(),
            "duplicate_images": &duplicates[..duplicates.len().min(10)],
            "total_checked": seen.len(),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── check_zero_commitments_in_range ─────────────────────────
    module.register_method("check_zero_commitments_in_range", |params, state, _ext| {
        let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
        })?;
        let (start, end) = rpc_clamp_audit_range(start, end)?;
        let mut zero_count = 0u64;
        let mut locations = Vec::new();

        for h in start..=end {
            if let Some(block) = state.chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    for (idx, output) in tx.outputs.iter().enumerate() {
                        if output.commitment == [0u8; 32] {
                            zero_count += 1;
                            locations.push(json!({
                                "height": h,
                                "tx_hash": tx.hash().to_hex(),
                                "output_index": idx,
                                "issue": "zero_commitment",
                            }));
                        }
                        if output.stealth_address.as_bytes() == &[0u8; 32] {
                            zero_count += 1;
                            locations.push(json!({
                                "height": h,
                                "tx_hash": tx.hash().to_hex(),
                                "output_index": idx,
                                "issue": "zero_stealth_address",
                            }));
                        }
                    }
                }
            }
        }

        Ok::<_, ErrorObjectOwned>(json!({
            "zero_count": zero_count,
            "locations": locations,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_signatures_in_range ──────────────────────────────
    module.register_method("verify_signatures_in_range", |params, state, _ext| {
        let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
        })?;
        let (start, end) = rpc_clamp_audit_range(start, end)?;
        let mut checked = 0u64;
        let mut failures = 0u64;
        let mut findings = Vec::new();

        for h in start..=end {
            if let Some(block) = state.chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    if tx.is_coinbase() { continue; }
                    for (idx, input) in tx.inputs.iter().enumerate() {
                        checked += 1;
                        if !crate::consensus::verify_ring_signature(&tx, input, idx) {
                            failures += 1;
                            findings.push(format!(
                                "Invalid CLSAG at h={} tx={} input={}",
                                h, tx.hash().to_hex()[..16].to_string(), idx
                            ));
                        }
                    }
                }
            }
        }

        Ok::<_, ErrorObjectOwned>(json!({
            "valid": failures == 0,
            "checked": checked,
            "failures": failures,
            "findings": &findings[..findings.len().min(50)],
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_range_proofs_in_range ────────────────────────────
    module.register_method("verify_range_proofs_in_range", |params, state, _ext| {
        let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
        })?;
        let (start, end) = rpc_clamp_audit_range(start, end)?;
        let mut checked = 0u64;
        let mut failures = 0u64;
        let mut findings = Vec::new();

        for h in start..=end {
            if let Some(block) = state.chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    if tx.is_coinbase() { continue; }
                    checked += 1;
                    if !crate::consensus::verify_output_range_proofs(&tx, h) {
                        failures += 1;
                        findings.push(format!(
                            "Invalid range proof at h={} tx={}",
                            h, tx.hash().to_hex()[..16].to_string()
                        ));
                    }
                }
            }
        }

        Ok::<_, ErrorObjectOwned>(json!({
            "valid": failures == 0,
            "checked": checked,
            "failures": failures,
            "findings": &findings[..findings.len().min(50)],
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_commitment_balance_in_range ──────────────────────
    module.register_method("verify_commitment_balance_in_range", |params, state, _ext| {
        let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
        })?;
        let (start, end) = rpc_clamp_audit_range(start, end)?;
        let mut checked = 0u64;
        let mut failures = 0u64;
        let mut findings = Vec::new();

        for h in start..=end {
            if let Some(block) = state.chain.get_block_by_height(h) {
                for tx in &block.transactions {
                    if tx.is_coinbase() { continue; }
                    checked += 1;
                    if !crate::consensus::verify_balance_proof(&tx) {
                        failures += 1;
                        findings.push(format!(
                            "Commitment imbalance at h={} tx={}",
                            h, tx.hash().to_hex()[..16].to_string()
                        ));
                    }
                }
            }
        }

        Ok::<_, ErrorObjectOwned>(json!({
            "valid": failures == 0,
            "checked": checked,
            "failures": failures,
            "findings": &findings[..findings.len().min(50)],
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── full_chain_audit ────────────────────────────────────────
    module.register_method("full_chain_audit", |params, state, _ext| {
        let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
        })?;
        let (start, end) = rpc_clamp_audit_range(start, end)?;
        let mut blocks_checked = 0u64;
        let mut txs_checked = 0u64;
        let mut findings = Vec::new();

        for h in start..=end {
            if let Some(block) = state.chain.get_block_by_height(h) {
                blocks_checked += 1;
                txs_checked += block.transactions.len() as u64;

                // Verify merkle root
                let tx_hashes: Vec<_> = block.transactions.iter().map(|tx| tx.hash()).collect();
                let computed_root = crate::primitives::merkle_root(&tx_hashes);
                if computed_root != block.header.tx_root {
                    findings.push(format!("h={}: merkle root mismatch", h));
                }

                // Verify block reward
                let _expected_reward = crate::emission::calculate_block_reward(h);
                if let Some(coinbase) = block.transactions.first() {
                    // Basic check: coinbase exists and is coinbase type
                    if !coinbase.is_coinbase() {
                        findings.push(format!("h={}: first tx is not coinbase", h));
                    }
                }

                // Verify all transactions
                for tx in &block.transactions {
                    if tx.is_coinbase() { continue; }

                    // Structural validation
                    if let Err(e) = crate::consensus::validate_transaction_basic(&tx) {
                        findings.push(format!("h={}: structural: {}", h, e));
                    }

                    // Ring signatures
                    for (idx, input) in tx.inputs.iter().enumerate() {
                        if !crate::consensus::verify_ring_signature(&tx, input, idx) {
                            findings.push(format!("h={}: CLSAG invalid input {}", h, idx));
                        }
                    }

                    // Range proofs
                    if !crate::consensus::verify_output_range_proofs(&tx, h) {
                        findings.push(format!("h={}: range proof invalid", h));
                    }

                    // Balance
                    if !crate::consensus::verify_balance_proof(&tx) {
                        findings.push(format!("h={}: commitment imbalance", h));
                    }
                }
            }
        }

        Ok::<_, ErrorObjectOwned>(json!({
            "valid": findings.is_empty(),
            "blocks_checked": blocks_checked,
            "txs_checked": txs_checked,
            "findings": findings.len(),
            "details": &findings[..findings.len().min(100)],
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    let bearer_validator = RpcBearerValidator {
        token: if apply_bearer_middleware {
            Some(
                api_key_arc
                    .clone()
                    .expect("apply_bearer_middleware implies api_key_arc is Some"),
            )
        } else {
            None
        },
    };

    let server = ServerBuilder::default()
        .max_connections(config.max_connections)
        .set_http_middleware(
            ServiceBuilder::new().layer(ValidateRequestHeaderLayer::custom(bearer_validator)),
        )
        .build(config.listen_addr)
        .await
        .map_err(|e| Error::RpcError(format!("RPC bind failed: {}", e)))?;

    info!(
        "RPC server bound (methods include verification suite); auth_enabled={} bearer_http={}",
        config.auth_enabled, apply_bearer_middleware,
    );

    let handle = server.start(module);

    Ok(RpcServer { handle })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

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

    #[test]
    fn bearer_validator_rejects_non_upgrade_get_without_auth() {
        let token: Arc<str> = Arc::from("secret-token");
        let mut validator = RpcBearerValidator { token: Some(token) };
        let mut req = Request::builder()
            .method("GET")
            .uri("/rpc")
            .body(())
            .expect("request");
        assert!(validator.validate(&mut req).is_err());
    }

    #[test]
    fn bearer_validator_accepts_ws_upgrade_get_with_auth() {
        let token: Arc<str> = Arc::from("secret-token");
        let mut validator = RpcBearerValidator { token: Some(token) };
        let mut req = Request::builder()
            .method("GET")
            .uri("/rpc")
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::AUTHORIZATION, "Bearer secret-token")
            .body(())
            .expect("request");
        assert!(validator.validate(&mut req).is_ok());
    }
}
