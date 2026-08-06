//! # Explorer REST API
//!
//! Full-featured REST API layer for the CoinCync block explorer.
//! Proxies read-only requests to the JSON-RPC backend and adds
//! explorer-specific endpoints: search, pagination, chain stats,
//! emission curve, network overview, and WebSocket streaming.
//!
//! ## Port layout
//! - RPC port (e.g. 28081): JSON-RPC 2.0 (jsonrpsee)
//! - RPC port + 1: Block explorer HTML
//! - RPC port + 2: This REST API
//!
//! ## Security
//! - Only read-only RPC methods are forwarded (allowlist)
//! - Input validation on all path/query parameters
//! - Response size caps to prevent OOM
//! - CORS restricted to known origins
//! - Rate limiting via X-RateLimit headers

use axum::{
    extract::{ws, Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum blocks returned in a single paginated response.
const MAX_PAGE_SIZE: u64 = 100;

/// Default page size for paginated endpoints.
const DEFAULT_PAGE_SIZE: u64 = 25;

/// Maximum search query length (prevents regex bombs / OOM).
const MAX_SEARCH_QUERY_LEN: usize = 128;

/// Maximum blocks to scan for chain-stats aggregation.
const STATS_WINDOW: u64 = 120;

/// Maximum emission curve data points returned.
const MAX_EMISSION_POINTS: u64 = 1000;

/// Hard cap on concurrent websocket clients (DoS guard).
const MAX_WS_CONNECTIONS: usize = 128;

/// Per-IP cap on concurrent websocket clients. Stops a single IP
/// (or a single trusted-proxy-forwarded IP) from monopolising the
/// 128 global slots. When proxy headers aren't trusted, every caller
/// shares the "unknown" bucket and this collapses to a global cap —
/// fine, the global cap above already handles that case.
const MAX_WS_PER_IP: u32 = 5;

/// Global websocket connection counter for this process.
static ACTIVE_WS_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Per-IP websocket connection counters. Keyed by whatever
/// `client_ip_from_headers` returns — a real client IP when proxy
/// headers are trusted, "unknown" otherwise.
static ACTIVE_WS_PER_IP: parking_lot::Mutex<Option<HashMap<String, u32>>> =
    parking_lot::Mutex::new(None);

fn ws_per_ip_check_and_increment(ip: &str) -> bool {
    let mut guard = ACTIVE_WS_PER_IP.lock();
    let map = guard.get_or_insert_with(HashMap::new);
    let count = map.entry(ip.to_string()).or_insert(0);
    if *count >= MAX_WS_PER_IP {
        return false;
    }
    *count += 1;
    true
}

fn ws_per_ip_decrement(ip: &str) {
    let mut guard = ACTIVE_WS_PER_IP.lock();
    if let Some(map) = guard.as_mut() {
        if let Some(count) = map.get_mut(ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(ip);
            }
        }
    }
}

/// Dependency-free fixed-window guards for high-risk endpoints.
const RPC_PROXY_MAX_REQ_PER_SEC: u32 = 60;
const STATS_MAX_REQ_PER_SEC: u32 = 20;
const EMISSION_MAX_REQ_PER_SEC: u32 = 20;

static RPC_PROXY_WINDOW_SEC: AtomicU64 = AtomicU64::new(0);
static RPC_PROXY_WINDOW_COUNT: AtomicU32 = AtomicU32::new(0);
static STATS_WINDOW_SEC: AtomicU64 = AtomicU64::new(0);
static STATS_WINDOW_COUNT: AtomicU32 = AtomicU32::new(0);
static EMISSION_WINDOW_SEC: AtomicU64 = AtomicU64::new(0);
static EMISSION_WINDOW_COUNT: AtomicU32 = AtomicU32::new(0);
static RPC_IP_WINDOW: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, (u64, u32)>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
static STATS_IP_WINDOW: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, (u64, u32)>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
static EMISSION_IP_WINDOW: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, (u64, u32)>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

// ─── Shared State ────────────────────────────────────────────────────────────

/// Shared state for the REST API handlers.
#[derive(Clone)]
struct RestState {
    jsonrpc_addr: SocketAddr,
    client: reqwest::Client,
    /// When set, forwarded as `Authorization: Bearer …` to the internal JSON-RPC server.
    rpc_bearer: Option<String>,
}

// ─── JSON-RPC proxy ────��─────────────────────────────────────────────────────

/// Send a JSON-RPC call to the internal backend and return the result.
///
/// SECURITY: Error messages are sanitized — internal details are logged
/// but never returned to the caller.
async fn jsonrpc_call(
    state: &RestState,
    method: &str,
    params: Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let url = format!("http://{}", state.jsonrpc_addr);
    let mut req = state.client.post(&url).json(&body);
    if let Some(ref key) = state.rpc_bearer {
        req = req.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", key.trim()),
        );
    }
    let resp = req.send().await.map_err(|e| {
        tracing::error!("REST backend unavailable: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "Service temporarily unavailable" })),
        )
    })?;

    let json: Value = resp.json().await.map_err(|e| {
        tracing::error!("REST invalid backend response: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "Service temporarily unavailable" })),
        )
    })?;

    if let Some(err) = json.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        let status = match code {
            -5 => StatusCode::NOT_FOUND,
            -32602 => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return Err((status, Json(serde_json::json!({ "error": msg }))));
    }

    Ok(json.get("result").cloned().unwrap_or(Value::Null))
}

// ─── RPC Proxy (public) ─────────────────────────────────────────────────────

/// SECURITY: Allowed RPC methods for the public /rpc proxy.
///
/// Only read-only methods are permitted. State-modifying methods
/// (send_raw_transaction, submit_block) and fingerprint-sensitive
/// methods (get_mining_live — leaks miner hardware identity to a
/// public observer) are blocked. Verify: `test_rpc_allowlist_blocks_sensitive`.
///
/// The entries below are grouped by whether they are actually
/// registered on the jsonrpsee server today (P0) or are forward-
/// compat reservations for methods the 2.0 surface exposed and
/// that will come back in P1 / P2. The `test_rpc_allowlist_has_*`
/// tests lock in which subset the block explorer actively depends
/// on right now.
const RPC_ALLOWED_METHODS: &[&str] = &[
    // ── P0 (currently registered on jsonrpsee server) ──────
    // Node info — exercised by explorer and TUIs.
    "get_info",
    "get_blockchain_info",
    "get_network_info",
    "get_sync_status",
    "get_anonymity_set",
    "get_chain_events",
    "get_supply_info",
    "get_privacy_stats",
    // Block queries — explorer uses get_block_range for "latest blocks".
    "get_block_by_height",
    "get_block", // by hash hex (embedded explorer search bar)
    "get_block_range",
    // Peer table for the explorer "Peers" tab.
    "get_peers",
    // Mempool
    "get_mempool_info",
    "get_mempool_transactions",
    // Stub-but-public methods. They return -32601 NotImplemented
    // with a labelled message, which is safer than 403-blocking
    // them — a `MethodNotFound` from the backend tells the
    // explorer to render "not yet wired" instead of "blocked".
    "get_transaction",
    "get_asset_info",
    // Shielded / Spark anchors (public, intentionally transparent)
    "get_shielded_anchor",
    "get_spark_anchor",
    // Nullifier / serial lookups (public — required for recipient-side
    // "is this coin spent" checks in light wallets).
    "is_nullifier_spent",
    "is_spark_serial_spent",
    // Decoy selection for wallet spend construction.
    "get_decoys",
    // ── Forward-compat reservations (P1+ — not yet registered) ─
    // Keeping these in the allowlist so the REST proxy doesn't
    // need to be re-edited when the P1 wallet wiring lands.
    "health",
    "rpc.discover",
    "get_block_count",
    "get_network_overview",
    "get_block",
    "get_block_hash",
    "get_transaction",
    "get_tx_pool",
    "get_peers",
    "get_asset_info",
    "list_assets",
    "get_asset_balance",
    "get_random_outputs",
    "get_output_digests",
    "get_sync_checkpoints",
];

/// Raw JSON-RPC proxy — forwards allowed read-only requests to jsonrpsee.
///
/// SECURITY: Only methods in RPC_ALLOWED_METHODS are forwarded.
/// All other methods return 403 Forbidden.
async fn rpc_proxy(
    State(st): State<RestState>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let client_ip = client_ip_from_headers(&headers);
    enforce_fixed_window_limit(
        &RPC_PROXY_WINDOW_SEC,
        &RPC_PROXY_WINDOW_COUNT,
        RPC_PROXY_MAX_REQ_PER_SEC,
    )?;
    enforce_ip_fixed_window_limit(&RPC_IP_WINDOW, &client_ip, RPC_PROXY_MAX_REQ_PER_SEC)?;

    // SECURITY: Cap request body size (already capped by axum layer, but belt-and-suspenders)
    if body.len() > 64 * 1024 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "Request body too large"})),
        ));
    }

    let parsed: Value = serde_json::from_str(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid JSON"})),
        )
    })?;

    let method = parsed["method"].as_str().unwrap_or("");
    if !RPC_ALLOWED_METHODS.contains(&method) {
        tracing::warn!("REST /rpc blocked disallowed method: {}", method);
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": format!("Method '{}' not allowed via public API", method)}),
            ),
        ));
    }

    let url = format!("http://{}", st.jsonrpc_addr);
    let mut req = st
        .client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body);
    if let Some(ref key) = st.rpc_bearer {
        req = req.header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", key.trim()),
        );
    }
    let resp = req.send().await.map_err(|e| {
        tracing::error!("REST /rpc backend error: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "Service temporarily unavailable"})),
        )
    })?;
    let mut json: Value = resp.json().await.map_err(|e| {
        tracing::error!("REST /rpc parse error: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "Service temporarily unavailable"})),
        )
    })?;

    // ITEM 5 (privacy): Strip anonymity-set / network-state stats from
    // get_info responses on the public proxy. These are useful for the
    // node operator on the local 127.0.0.1 endpoint, but exposing them
    // through the public REST gives chain analysts a cheap correlator
    // (e.g., "this tx with ring 11 was built when available_outputs was
    // exactly N") that they would otherwise have to compute themselves.
    // Local node RPC keeps the full payload; only the externally-fronted
    // public proxy redacts.
    if method == "get_info" {
        if let Some(result) = json.get_mut("result").and_then(Value::as_object_mut) {
            for redacted in &[
                "available_outputs",   // anonymity-set size; correlator for ring sizes
                "anonymity_set",       // alias of the same metric
                "effective_ring_size", // tells analyst what ring the wallet is actually using
                "mempool_size",        // useful for spam fingerprinting
                "tx_pool_size",        // alias
                "peer_count",          // network-state snapshot, not user-relevant
                "process_count",       // operator-only stat
                "process_count_available",
                "build_commit", // version fingerprinting
                "build_dirty",
                "build_profile",
                "metadata_minimized",
                "rpc_auth_enabled", // tells whether the node has auth at all
                "stratum_native_tls_enabled",
                "stratum_public_bind_ack",
                "stratum_public_bind_requested",
                "stratum_tls_proxy_ack",
                "stratum_transport_hardened",
                "has_zombies",
                "health_score",
                "clock_available",
                "total_difficulty",
            ] {
                result.remove(*redacted);
            }
        }
    }

    Ok(Json(json))
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUERY PARAMETER TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Pagination parameters for list endpoints.
#[derive(Debug, Deserialize)]
struct Pagination {
    /// Page number (1-indexed, default 1)
    page: Option<u64>,
    /// Items per page (default 25, max 100)
    limit: Option<u64>,
}

impl Pagination {
    fn page(&self) -> u64 {
        self.page.unwrap_or(1).max(1)
    }
    fn limit(&self) -> u64 {
        self.limit
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE)
    }
    fn offset(&self) -> u64 {
        (self.page() - 1) * self.limit()
    }
}

/// Search query parameter.
#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: String,
}

/// Emission curve query parameters.
#[derive(Debug, Deserialize)]
struct EmissionQuery {
    /// Start height (default 0)
    from: Option<u64>,
    /// End height (default current)
    to: Option<u64>,
    /// Step size (default 1)
    step: Option<u64>,
}

// ══��════════════════════════════════════════════════════════════════════════════
// HELPER: validate hex hash (64 hex chars)
// ═══════════════════════════════════════════════════════════════════════════════

fn validate_hex_hash(hash: &str) -> Result<(), (StatusCode, Json<Value>)> {
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid hash: must be 64 hex characters"})),
        ));
    }
    Ok(())
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn enforce_fixed_window_limit(
    window_sec: &AtomicU64,
    window_count: &AtomicU32,
    max_per_sec: u32,
) -> Result<(), (StatusCode, Json<Value>)> {
    let now = now_unix_secs();
    let current_window = window_sec.load(Ordering::Relaxed);
    if current_window != now
        && window_sec
            .compare_exchange(current_window, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        window_count.store(0, Ordering::Relaxed);
    }

    let n = window_count.fetch_add(1, Ordering::Relaxed) + 1;
    if n > max_per_sec {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Rate limit exceeded, retry shortly"})),
        ));
    }
    Ok(())
}

/// Whether to honor `X-Forwarded-For` / `X-Real-IP` headers from
/// inbound requests. Default: false. Operators running behind a
/// trusted reverse proxy (nginx, Caddy) that strips inbound forwarded
/// headers and re-sets them from the real client IP must opt in via
/// `COINCYNC_TRUST_PROXY_HEADERS=1`. Otherwise any direct client can
/// rotate IPs to bypass per-IP rate limits trivially.
fn trust_proxy_headers() -> bool {
    static TRUST: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRUST.get_or_init(|| {
        let value = std::env::var("COINCYNC_TRUST_PROXY_HEADERS").unwrap_or_default();
        matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")
    })
}

fn client_ip_from_headers(headers: &HeaderMap) -> String {
    // When proxy headers are not explicitly trusted, treat every
    // request as "unknown" so the per-IP rate limit collapses into a
    // global rate limit (all callers share one bucket). This is the
    // safer default than letting an unauthenticated client spoof
    // X-Forwarded-For to rotate through buckets.
    if !trust_proxy_headers() {
        return "unknown".to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string())
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Cap on entries retained in a per-IP rate-limit map. Beyond this
/// size the map is opportunistically pruned of stale entries (older
/// than `IP_WINDOW_STALE_SECS`). Chosen so that at ~1 caller/sec/IP
/// the map stays well below the cap even for a busy public endpoint.
const IP_WINDOW_MAX_ENTRIES: usize = 4096;

/// Entries whose recorded window-start is older than this are eligible
/// for opportunistic pruning. One second is enough — a stale entry's
/// count field is only re-armed on next hit anyway.
const IP_WINDOW_STALE_SECS: u64 = 5;

fn enforce_ip_fixed_window_limit(
    table: &parking_lot::Mutex<HashMap<String, (u64, u32)>>,
    client_ip: &str,
    max_per_sec: u32,
) -> Result<(), (StatusCode, Json<Value>)> {
    let now = now_unix_secs();
    let mut guard = table.lock();
    // P8-R1 (2026-07-03): opportunistic prune. Without this the map
    // grows without bound — one entry per unique client IP for the
    // lifetime of the process. Trigger only when the map crosses the
    // soft cap so the hot path (normal traffic) stays cheap.
    if guard.len() >= IP_WINDOW_MAX_ENTRIES {
        guard.retain(|_, entry| now.saturating_sub(entry.0) <= IP_WINDOW_STALE_SECS);
    }
    let entry = guard.entry(client_ip.to_string()).or_insert((now, 0));
    if entry.0 != now {
        *entry = (now, 0);
    }
    entry.1 = entry.1.saturating_add(1);
    if entry.1 > max_per_sec {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Rate limit exceeded, retry shortly"})),
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════���═══════════════════════
// HANDLERS — Core
// ═══════════════════���═══════════════════════════════���═══════════════════════════

async fn health() -> Json<Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// GET /api/v1/health/live — liveness probe for Cloudflare LB / nginx / k8s.
///
/// Returns HTTP 200 iff the REST process is up. Does NOT check the RPC
/// backend or the chain state. A wedged node whose async runtime is
/// still scheduling this handler will still return 200 here — that's
/// the point. Load balancers use liveness to decide whether to restart
/// the container; they use readiness (below) to decide whether to route
/// traffic.
///
/// Under 1KB response, no allocation of any RPC call.
async fn health_live() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "live",
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}

/// GET /api/v1/health/ready — readiness probe for load-balancer routing.
///
/// Returns HTTP 200 iff the node is healthy enough to serve queries:
///   - Backend RPC is reachable and answering (proves the jsonrpsee
///     event loop isn't wedged — the silent-hang class that took down
///     api.coincync.network for 41h on 2026-07-02)
///   - Peer count is at least MIN_PEERS_FOR_READY (default 3 — matches
///     the fleet minimum used elsewhere: sync-fleet-config.sh peer_count
///     ≥ 3 gate, and feedback_no_bulk_rolling_restart's between-restart
///     verification)
///   - Chain tip age is under MAX_TIP_AGE_FOR_READY (default 600s, 10
///     minutes — 5x the target block time so real chain silence is
///     caught but transient block-arrival gaps aren't)
///
/// Returns HTTP 503 SERVICE UNAVAILABLE otherwise, with a JSON body
/// naming which check failed. Cloudflare LB / nginx interprets 503 as
/// "route around this host" and the fleet gains automatic failover.
///
/// The body always includes the observed peer_count and tip_age_secs
/// so the LB dashboard shows the failing check without needing to
/// parse status codes.
async fn health_ready(State(st): State<RestState>) -> impl IntoResponse {
    const MIN_PEERS_FOR_READY: u64 = 3;
    const MAX_TIP_AGE_FOR_READY: u64 = 600;

    // Round-trip a get_info call so we prove BOTH the REST layer AND
    // the jsonrpsee backend are responsive. A wedged jsonrpsee event
    // loop (the 2026-07-02 api-box failure mode) times out here.
    let info = match jsonrpc_call(&st, "get_info", Value::Array(vec![])).await {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "not-ready",
                    "reason": "backend RPC unreachable — jsonrpsee event loop may be wedged",
                })),
            );
        }
    };

    let peer_count = info.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0);
    let tip_age_secs = info
        .get("tip_age_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let is_synced = info
        .get("synced")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Peer floor: a node with 0-2 peers can't reliably serve fresh
    // tip queries. LB should skip it until it recovers.
    if peer_count < MIN_PEERS_FOR_READY {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not-ready",
                "reason": format!("peer_count={} below floor {}", peer_count, MIN_PEERS_FOR_READY),
                "peer_count": peer_count,
                "tip_age_secs": tip_age_secs,
                "synced": is_synced,
            })),
        );
    }

    // Tip staleness: if the chain hasn't moved in 10+ min this node
    // is either partitioned or IBD-stuck. Don't route reads to it.
    if tip_age_secs > MAX_TIP_AGE_FOR_READY {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not-ready",
                "reason": format!("tip_age={}s exceeds ceiling {}s", tip_age_secs, MAX_TIP_AGE_FOR_READY),
                "peer_count": peer_count,
                "tip_age_secs": tip_age_secs,
                "synced": is_synced,
            })),
        );
    }

    // All checks green.
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ready",
            "peer_count": peer_count,
            "tip_age_secs": tip_age_secs,
            "synced": is_synced,
            "height": info.get("height"),
        })),
    )
}

/// GET /api/v1/status — node status summary for the explorer header bar
async fn get_status(State(st): State<RestState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let info = jsonrpc_call(&st, "get_info", Value::Array(vec![])).await?;
    // Privacy: deliberately omit `anonymity_set` and `effective_ring_size`
    // from this public REST endpoint. The /rpc proxy strips the same fields
    // at line ~291 of this file; an earlier version of /api/v1/status leaked
    // them, giving a passive observer a cheap correlator for the ring sizes
    // wallets are using. peer_count and mempool_size are mild
    // network-state stats kept here because the public status page wants
    // to render them; the strict-privacy fields are not.
    Ok(Json(serde_json::json!({
        "height": info["height"],
        "network": info["network"],
        "version": info["version"],
        "synced": info["synced"],
        "difficulty": info["difficulty"],
        "mempool_size": info["tx_pool_size"],
        "peer_count": info["peer_count"],
        "tip_hash": info["top_hash"],
        "tip_timestamp": info["tip_timestamp"],
        "tip_age_secs": info["tip_age_secs"],
    })))
}

/// GET /api/v1/supply — emission and supply data
async fn get_supply(State(st): State<RestState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let supply = jsonrpc_call(&st, "get_supply_info", Value::Array(vec![])).await?;
    Ok(Json(supply))
}

/// GET /api/v1/supply/circulating — circulating supply in CYNC, plain text.
///
/// CoinMarketCap and several exchange-listing pipelines poll a public
/// endpoint that returns the current circulating supply as a bare
/// decimal number with no JSON wrapping. Format is whole.micro
/// (6 fractional digits, matching the conventional display precision).
///
/// Uses integer arithmetic — the f64 cast that appeared in earlier
/// drafts loses precision above 2^53, and the u128 atomic-supply
/// accumulator sits well above that range.
async fn get_supply_circulating(
    State(st): State<RestState>,
) -> Result<String, (StatusCode, String)> {
    let info = jsonrpc_call(&st, "get_supply_info", Value::Array(vec![]))
        .await
        .map_err(|(code, body)| (code, body.0.to_string()))?;
    let atomic = parse_total_emitted_atomic(&info)
        .map_err(|message| (StatusCode::BAD_GATEWAY, message.to_string()))?;
    Ok(format_atomic_supply_micro(atomic))
}

fn parse_total_emitted_atomic(info: &Value) -> Result<u128, &'static str> {
    info.get("total_emitted")
        .and_then(Value::as_str)
        .ok_or("get_supply_info returned no decimal-string total_emitted")?
        .parse::<u128>()
        .map_err(|_| "get_supply_info returned an invalid total_emitted value")
}

fn format_atomic_supply_micro(atomic: u128) -> String {
    let coin = crate::constants::COIN as u128;
    let micro_per_coin = coin / 1_000_000; // 12 atomic decimals → 6 display decimals
    let whole = atomic / coin;
    let frac_micro = (atomic % coin) / micro_per_coin;
    format!("{}.{:06}", whole, frac_micro)
}

/// GET /api/v1/supply/max — supply target in CYNC, plain text.
///
/// CoinMarketCap "max supply" field. CoinCync has a 100M asymptotic
/// target (Constitution Article I) approached but never reached, plus
/// a 0.6 CYNC/block tail emission. (Prior comment characterized the
/// max-supply-with-tail reporting shape as "the convention CMC and
/// CoinGecko use for similar asymptotic chains (Monero etc.)"; the
/// specific listing-site conventions were not verified against
/// CMC/CoinGecko this session and are stated as a design intent
/// rather than an asserted parity claim.)
async fn get_supply_max() -> String {
    crate::constants::TOTAL_SUPPLY_TARGET.to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════
// HANDLERS — Blocks
// ═════════════════════════���═════════════════════��═══════════════════════════════

/// GET /api/v1/block/hash/:hash — single block by hash
async fn get_block_by_hash(
    State(st): State<RestState>,
    Path(hash): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    validate_hex_hash(&hash)?;
    let block = jsonrpc_call(&st, "get_block", Value::Array(vec![Value::String(hash)])).await?;
    Ok(Json(block))
}

/// GET /api/v1/block/height/:height — single block by height
async fn get_block_by_height(
    State(st): State<RestState>,
    Path(height): Path<u64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let block = jsonrpc_call(
        &st,
        "get_block_by_height",
        Value::Array(vec![Value::Number(height.into())]),
    )
    .await?;
    Ok(Json(block))
}

/// GET /api/v1/block/:height/transactions — all transactions in a block
async fn get_block_transactions(
    State(st): State<RestState>,
    Path(height): Path<u64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let block = jsonrpc_call(
        &st,
        "get_block_by_height",
        Value::Array(vec![Value::Number(height.into())]),
    )
    .await?;

    // get_block_by_height already returns transactions array
    let txs = block
        .get("transactions")
        .cloned()
        .unwrap_or(Value::Array(vec![]));
    let tx_count = block.get("tx_count").and_then(|v| v.as_u64()).unwrap_or(0);

    Ok(Json(serde_json::json!({
        "height": height,
        "hash": block.get("hash"),
        "tx_count": tx_count,
        "transactions": txs,
    })))
}

/// GET /api/v1/blocks/recent?page=1&limit=25 — paginated recent blocks
///
/// Returns blocks in descending height order (newest first).
/// The explorer home page uses this for the live block feed.
async fn get_recent_blocks(
    State(st): State<RestState>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Get current chain height
    let info = jsonrpc_call(&st, "get_info", Value::Array(vec![])).await?;
    let chain_height = info["height"].as_u64().unwrap_or(0);

    let limit = pagination.limit();
    let offset = pagination.offset();

    // Calculate the height range to fetch (descending)
    let start_height = chain_height.saturating_sub(offset);
    let end_height = start_height.saturating_sub(limit.saturating_sub(1));
    let end_height = if start_height < limit { 0 } else { end_height };

    let mut blocks = Vec::with_capacity(limit as usize);
    for h in (end_height..=start_height).rev() {
        if blocks.len() >= limit as usize {
            break;
        }
        match jsonrpc_call(
            &st,
            "get_block_by_height",
            Value::Array(vec![Value::Number(h.into())]),
        )
        .await
        {
            Ok(block) => blocks.push(block),
            Err(_) => continue, // skip missing blocks (shouldn't happen)
        }
    }

    let total_pages = if chain_height == 0 {
        1
    } else {
        (chain_height + limit - 1) / limit
    };

    Ok(Json(serde_json::json!({
        "blocks": blocks,
        "pagination": {
            "page": pagination.page(),
            "limit": limit,
            "total_blocks": chain_height + 1,
            "total_pages": total_pages,
            "has_next": pagination.page() < total_pages,
            "has_prev": pagination.page() > 1,
        }
    })))
}

// ════════════════════════════��══════════════════════════════════════════════════
// HANDLERS — Transactions
// ═══════════════════════════════════════════════���═══════════════════════════════

/// GET /api/v1/transaction/:hash — transaction by hash
async fn get_transaction(
    State(st): State<RestState>,
    Path(hash): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    validate_hex_hash(&hash)?;
    let tx = jsonrpc_call(
        &st,
        "get_transaction",
        Value::Array(vec![Value::String(hash)]),
    )
    .await?;
    Ok(Json(tx))
}

/// GET /api/v1/mempool — pending transactions
async fn get_mempool(
    State(st): State<RestState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let pool = jsonrpc_call(&st, "get_mempool_transactions", Value::Array(vec![])).await?;
    Ok(Json(pool))
}

/// GET /api/v1/mempool/stats — mempool statistics without full tx list
async fn get_mempool_stats(
    State(st): State<RestState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let info = jsonrpc_call(&st, "get_mempool_info", Value::Array(vec![])).await?;
    let size = info.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
    let bytes = info.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
    let total_fees = info.get("total_fees").and_then(|v| v.as_u64()).unwrap_or(0);
    let max_size = info.get("max_size").and_then(|v| v.as_u64()).unwrap_or(0);

    Ok(Json(serde_json::json!({
        "count": size,
        "bytes": bytes,
        "total_fees": total_fees,
        "max_size": max_size,
    })))
}

#[derive(Deserialize)]
struct SubmitTxBody {
    tx_hex: String,
}

/// POST /api/v1/transaction/submit — broadcast a transaction
async fn submit_transaction(
    State(st): State<RestState>,
    Json(body): Json<SubmitTxBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // SECURITY: Validate tx_hex is actually hex and not oversized
    if body.tx_hex.len() > 2 * 1024 * 1024 || !body.tx_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid tx_hex: must be hex, max 1MB"})),
        ));
    }
    let result = jsonrpc_call(
        &st,
        "send_raw_transaction",
        Value::Array(vec![Value::String(body.tx_hex)]),
    )
    .await?;
    Ok(Json(result))
}

// ════════════════════════════════════════════════════════════════════���══════════
// HANDLERS — Search
// ════���════════════��═════════════════════════════════════════════════════════════

/// GET /api/v1/search?q=<query> — universal search
///
/// Accepts:
/// - Block hash (64 hex chars)
/// - Transaction hash (64 hex chars)
/// - Block height (numeric string)
/// - Asset ID (64 hex chars, prefixed with "asset:")
///
/// Returns the type and data of the first match found.
async fn search(
    State(st): State<RestState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let q = query.q.trim();

    // SECURITY: Limit query length to prevent abuse
    if q.len() > MAX_SEARCH_QUERY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Search query too long"})),
        ));
    }

    if q.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Search query is empty"})),
        ));
    }

    // 1) Try as block height (pure numeric)
    if let Ok(height) = q.parse::<u64>() {
        if let Ok(block) = jsonrpc_call(
            &st,
            "get_block_by_height",
            Value::Array(vec![Value::Number(height.into())]),
        )
        .await
        {
            return Ok(Json(serde_json::json!({
                "type": "block",
                "query": q,
                "data": block,
            })));
        }
    }

    // 2) Try as 64-char hex (block hash or tx hash)
    if q.len() == 64 && q.chars().all(|c| c.is_ascii_hexdigit()) {
        // Try block first
        if let Ok(block) = jsonrpc_call(
            &st,
            "get_block",
            Value::Array(vec![Value::String(q.to_string())]),
        )
        .await
        {
            return Ok(Json(serde_json::json!({
                "type": "block",
                "query": q,
                "data": block,
            })));
        }

        // Try transaction
        if let Ok(tx) = jsonrpc_call(
            &st,
            "get_transaction",
            Value::Array(vec![Value::String(q.to_string())]),
        )
        .await
        {
            return Ok(Json(serde_json::json!({
                "type": "transaction",
                "query": q,
                "data": tx,
            })));
        }

        // Try asset
        if let Ok(asset) = jsonrpc_call(
            &st,
            "get_asset_info",
            Value::Array(vec![Value::String(q.to_string())]),
        )
        .await
        {
            return Ok(Json(serde_json::json!({
                "type": "asset",
                "query": q,
                "data": asset,
            })));
        }
    }

    Err((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "No results found",
            "query": q,
            "hint": "Search by block height, block hash, transaction hash, or asset ID (64 hex chars)"
        })),
    ))
}

// ════════════════════════════════════════════════════════��══════════════════════
// HANDLERS — Network & Privacy
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/network — network health overview
///
/// Powers the explorer's vital signs panel: health score, status text,
/// decay clock, zombie detection, anonymity set.
async fn get_network(
    State(st): State<RestState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // The explorer's vital-signs panel wants health / status / decay clock /
    // zombie detection / anonymity set — all carried by `get_info`. There is no
    // `get_network_overview` RPC method (calling it returned -32601 → the route
    // 500'd), so we curate a subset from `get_info`. We deliberately omit
    // `effective_ring_size` — the ring-size correlator that `/api/v1/status` also
    // withholds; `anonymity_set` is already published via `/api/v1/anonymity`, so
    // surfacing it here introduces no new leak.
    let info = jsonrpc_call(&st, "get_info", Value::Array(vec![])).await?;
    Ok(Json(serde_json::json!({
        "network": info["network"],
        "height": info["height"],
        "difficulty": info["difficulty"],
        "status": info["status"],
        "health_score": info["health_score"],
        "has_zombies": info["has_zombies"],
        "tip_age_secs": info["tip_age_secs"],
        "anonymity_set": info["anonymity_set"],
    })))
}

/// GET /api/v1/anonymity — anonymity set metrics
///
/// The headline privacy metric for CoinCync. Shows total unspent
/// outputs (every output in the UTXO set is a potential ring decoy).
async fn get_anonymity(
    State(st): State<RestState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let data = jsonrpc_call(&st, "get_anonymity_set", Value::Array(vec![])).await?;
    Ok(Json(data))
}

/// GET /api/v1/peers — connected peers (public subset only)
async fn get_peers(State(st): State<RestState>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // This calls the auth-gated get_peers which will return an error without auth.
    // For the public explorer, we return just the count from get_info.
    let info = jsonrpc_call(&st, "get_info", Value::Array(vec![])).await?;
    Ok(Json(serde_json::json!({
        "peer_count": info["peer_count"],
        "note": "Detailed peer info requires authentication to prevent network topology leaks"
    })))
}

// ═══════════════════════════════════════════════════════════════════════════════
// HANDLERS — Chain Statistics
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/stats — aggregated chain statistics
///
/// Computes rolling averages over the last STATS_WINDOW blocks:
/// - Average block time
/// - Estimated hashrate
/// - Transaction throughput
/// - Block size stats
///
/// This is the most expensive explorer endpoint (fetches up to 120 blocks).
/// Caching at the reverse-proxy layer is recommended.
async fn get_chain_stats(
    State(st): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let client_ip = client_ip_from_headers(&headers);
    enforce_fixed_window_limit(
        &STATS_WINDOW_SEC,
        &STATS_WINDOW_COUNT,
        STATS_MAX_REQ_PER_SEC,
    )?;
    enforce_ip_fixed_window_limit(&STATS_IP_WINDOW, &client_ip, STATS_MAX_REQ_PER_SEC)?;

    let info = jsonrpc_call(&st, "get_info", Value::Array(vec![])).await?;
    let chain_height = info["height"].as_u64().unwrap_or(0);
    let difficulty = info["difficulty"].as_str().unwrap_or("0");

    if chain_height < 2 {
        return Ok(Json(serde_json::json!({
            "height": chain_height,
            "avg_block_time_secs": 0,
            "estimated_hashrate": 0,
            "tx_per_block": 0,
            "total_transactions": 0,
            "avg_block_size": 0,
            "difficulty": difficulty,
            "window": 0,
            "note": "Insufficient blocks for statistics"
        })));
    }

    // Fetch blocks in the statistics window
    let window_start = chain_height.saturating_sub(STATS_WINDOW);
    let window_size = chain_height - window_start;

    let mut timestamps: Vec<u64> = Vec::with_capacity(window_size as usize + 1);
    let mut total_txs: u64 = 0;
    let mut algo_counts = [0u64; 3]; // [blake3, randomx, yescrypt]

    for h in window_start..=chain_height {
        if let Ok(block) = jsonrpc_call(
            &st,
            "get_block_by_height",
            Value::Array(vec![Value::Number(h.into())]),
        )
        .await
        {
            if let Some(ts) = block["timestamp"].as_u64() {
                timestamps.push(ts);
            }
            if let Some(tc) = block["tx_count"].as_u64() {
                total_txs += tc;
            }
            // Algorithm distribution
            if let Some(algo) = block["algorithm"].as_u64() {
                if (algo as usize) < algo_counts.len() {
                    algo_counts[algo as usize] += 1;
                }
            }
        }
    }

    // Average block time from timestamp differences
    let avg_block_time = if timestamps.len() >= 2 {
        let time_span = timestamps
            .last()
            .unwrap_or(&0)
            .saturating_sub(*timestamps.first().unwrap_or(&0));
        if timestamps.len() > 1 {
            time_span as f64 / (timestamps.len() - 1) as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Estimated hashrate: H/s = difficulty / block_time
    // This is a rough estimate based on the current difficulty and observed block times
    let diff_val: f64 = difficulty.parse().unwrap_or(1.0);
    let estimated_hashrate = if avg_block_time > 0.0 {
        diff_val / avg_block_time
    } else {
        0.0
    };

    let tx_per_block = if window_size > 0 {
        total_txs as f64 / window_size as f64
    } else {
        0.0
    };

    Ok(Json(serde_json::json!({
        "height": chain_height,
        "difficulty": difficulty,
        "window": window_size,
        "avg_block_time_secs": (avg_block_time * 100.0).round() / 100.0,
        "estimated_hashrate": estimated_hashrate.round(),
        "total_transactions_in_window": total_txs,
        "tx_per_block": (tx_per_block * 100.0).round() / 100.0,
        "algorithm_distribution": {
            "randomx": algo_counts[0],
            "yescrypt_heavy": algo_counts[1],
            "yescrypt_light": algo_counts[2],
        },
        "target_block_time_secs": 30,
    })))
}

// ═══════════════════════════════════════════════════════════════════════════════
// HANDLERS — Emission Curve
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/emission?from=0&to=1000000&step=1000 — emission curve data
///
/// Returns block reward and cumulative supply at each step.
/// Used by the explorer to render the emission/supply chart.
///
/// SECURITY: Computation is bounded — max MAX_EMISSION_POINTS data points.
async fn get_emission(
    State(st): State<RestState>,
    headers: HeaderMap,
    Query(query): Query<EmissionQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let client_ip = client_ip_from_headers(&headers);
    enforce_fixed_window_limit(
        &EMISSION_WINDOW_SEC,
        &EMISSION_WINDOW_COUNT,
        EMISSION_MAX_REQ_PER_SEC,
    )?;
    enforce_ip_fixed_window_limit(&EMISSION_IP_WINDOW, &client_ip, EMISSION_MAX_REQ_PER_SEC)?;

    // Get current height for defaults
    let info = jsonrpc_call(&st, "get_info", Value::Array(vec![])).await?;
    let chain_height = info["height"].as_u64().unwrap_or(0);

    let from = query.from.unwrap_or(0);
    let to = query.to.unwrap_or(chain_height).min(chain_height);
    let step = query.step.unwrap_or(1).max(1);

    // Clamp to prevent CPU abuse
    let total_points = if step > 0 { (to - from) / step + 1 } else { 1 };
    if total_points > MAX_EMISSION_POINTS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Too many data points ({}). Increase step size or narrow range. Max: {}", total_points, MAX_EMISSION_POINTS),
            })),
        ));
    }

    // Get supply info for the supply cap
    let supply = jsonrpc_call(&st, "get_supply_info", Value::Array(vec![])).await?;

    // Build data points by querying block rewards at each height
    // We use the emission curve directly rather than fetching blocks
    let mut points = Vec::with_capacity(total_points as usize);
    let mut cumulative: u64 = 0;

    // For efficiency, we approximate cumulative supply from block rewards.
    // The real cumulative is tracked by the chain, but computing it per-step
    // from the emission curve gives the explorer what it needs for charting.
    let mut h = from;
    while h <= to {
        // Fetch block reward at this height from the RPC
        // (returns the reward from the emission curve, not the actual mined block)
        if let Ok(block) = jsonrpc_call(
            &st,
            "get_block_by_height",
            Value::Array(vec![Value::Number(h.into())]),
        )
        .await
        {
            let reward = block["reward"].as_u64().unwrap_or(0);
            cumulative += reward * step; // Approximate: assume reward is constant within step
            points.push(serde_json::json!({
                "height": h,
                "reward": reward,
                "cumulative_approx": cumulative,
            }));
        } else {
            // Block doesn't exist yet (future height) — just report the emission curve
            // We can't call get_block_by_height for unmined blocks, so skip
            break;
        }
        h += step;
    }

    Ok(Json(serde_json::json!({
        "from": from,
        "to": to,
        "step": step,
        "points": points,
        "current_height": chain_height,
        "current_supply": supply.get("total_emitted"),
        "max_supply_cync": crate::constants::TOTAL_SUPPLY_TARGET,
        "units_per_cync": crate::constants::COIN,
    })))
}

// ═════════════════════════════════════════��═════════════════════════════════════
// HANDLERS — Assets
// ═════════════════���═════════════════════════════════════════════════════════════

/// GET /api/v1/asset/:id — asset info by ID
async fn get_asset(
    State(st): State<RestState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    validate_hex_hash(&id)?;
    let asset = jsonrpc_call(&st, "get_asset_info", Value::Array(vec![Value::String(id)])).await?;
    Ok(Json(asset))
}

/// GET /api/v1/assets — list all registered assets
async fn list_assets(
    State(st): State<RestState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let assets = jsonrpc_call(&st, "list_assets", Value::Array(vec![])).await?;
    Ok(Json(assets))
}

// ══════════════════════════════���════════════════════════════════════════════════
// HANDLERS — WebSocket (real-time streaming)
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/ws — WebSocket upgrade for real-time block/tx streaming
///
/// Streams events:
/// - `new_block` — when a new block is added
/// - `new_tx` — when a new transaction enters the mempool
/// - `status` — periodic node status updates
///
/// This is a polling-based WebSocket that queries the RPC every 3 seconds.
/// Future: connect to the native SubscriptionManager for push-based events.
async fn ws_upgrade(
    State(st): State<RestState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Per-IP cap first — cheaper than the global atomic CAS dance and
    // closes the easier DoS (one attacker eating all 128 slots).
    let client_ip = client_ip_from_headers(&headers);
    if !ws_per_ip_check_and_increment(&client_ip) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Global cap second. If we don't get a slot, we must release the
    // per-IP reservation we just took or it leaks.
    loop {
        let current = ACTIVE_WS_CONNECTIONS.load(Ordering::Relaxed);
        if current >= MAX_WS_CONNECTIONS {
            ws_per_ip_decrement(&client_ip);
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if ACTIVE_WS_CONNECTIONS
            .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
    ws.on_upgrade(move |socket| ws_handler(socket, st, client_ip))
}

async fn ws_handler(mut socket: ws::WebSocket, state: RestState, client_ip: String) {
    use tokio::time::{interval, Duration, Instant};

    // Close a client that hasn't sent us anything in this long. Prevents
    // an attacker from holding 128/128 WS slots open by reading bytes
    // but never speaking — TCP keepalives alone are slow and OS-tuned.
    const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

    struct WsConnGuard {
        client_ip: String,
    }
    impl Drop for WsConnGuard {
        fn drop(&mut self) {
            ACTIVE_WS_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            ws_per_ip_decrement(&self.client_ip);
        }
    }
    let _guard = WsConnGuard { client_ip };

    let mut tick = interval(Duration::from_secs(3));
    let mut idle_check = interval(Duration::from_secs(30));
    let mut last_client_activity = Instant::now();
    let mut last_height: u64 = 0;
    let mut last_mempool_count: u64 = 0;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Poll chain state and push updates
                let info = match jsonrpc_call(&state, "get_info", Value::Array(vec![])).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let height = info["height"].as_u64().unwrap_or(0);
                let mempool_size = info["tx_pool_size"].as_u64().unwrap_or(0);

                // New block detected
                if height > last_height && last_height > 0 {
                    // Fetch the new block details
                    if let Ok(block) = jsonrpc_call(
                        &state,
                        "get_block_by_height",
                        Value::Array(vec![Value::Number(height.into())]),
                    ).await {
                        let msg = serde_json::json!({
                            "type": "new_block",
                            "data": block,
                            "height": height,
                        });
                        if socket.send(ws::Message::Text(msg.to_string().into())).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                }

                // Mempool changed
                if mempool_size != last_mempool_count {
                    let msg = serde_json::json!({
                        "type": "mempool_update",
                        "data": {
                            "count": mempool_size,
                            "previous": last_mempool_count,
                        }
                    });
                    if socket.send(ws::Message::Text(msg.to_string().into())).await.is_err() {
                        break;
                    }
                }

                // Periodic status heartbeat
                let status_msg = serde_json::json!({
                    "type": "status",
                    "data": {
                        "height": height,
                        "synced": info["synced"],
                        "difficulty": info["difficulty"],
                        "peer_count": info["peer_count"],
                        "mempool_size": mempool_size,
                        "anonymity_set": info["anonymity_set"],
                        "tip_age_secs": info["tip_age_secs"],
                    }
                });
                if socket.send(ws::Message::Text(status_msg.to_string().into())).await.is_err() {
                    break;
                }

                last_height = height;
                last_mempool_count = mempool_size;
            }
            msg = socket.recv() => {
                last_client_activity = Instant::now();
                match msg {
                    Some(Ok(ws::Message::Text(text))) => {
                        // Handle client commands (ping, subscribe to specific events)
                        if text.as_str().trim() == "ping" {
                            let pong = serde_json::json!({"type": "pong", "timestamp": chrono::Utc::now().timestamp_millis()});
                            if socket.send(ws::Message::Text(pong.to_string().into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(ws::Message::Close(_))) | None => break,
                    Some(Err(_)) => break, // Protocol error — close the connection
                    _ => {} // Ignore binary frames, pings handled by axum
                }
            }
            _ = idle_check.tick() => {
                if last_client_activity.elapsed() >= WS_IDLE_TIMEOUT {
                    break;
                }
            }
        }
    }
}

// ═════════════════════════���═══════════════════════════════���═════════════════════
// HANDLERS — Chain Events
// ═══════════════════════════════════════════════════════════════════════════════

/// GET /api/v1/events — recent chain events (reorgs, rollbacks, forks)
///
/// Powers the convergence timeline in the explorer.
async fn get_chain_events(
    State(st): State<RestState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let events = jsonrpc_call(&st, "get_chain_events", Value::Array(vec![])).await?;
    Ok(Json(events))
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERVER ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════════

/// Start the REST API server.
///
/// Listens on `listen_addr` and proxies requests to `jsonrpc_addr`.
///
/// When `serve_explorer == true`, additionally mounts the embedded
/// block explorer assets (`crate::rpc::explorer`) at `GET /`
/// — this gives operators a one-flag local-development explorer
/// without any extra deployment infra. Default `false` because
/// shipping a new exposed route turned-on-by-default surprises
/// existing operators on upgrade.
///
/// The mounted explorer is **for local development only**. Production
/// public deployment should use the standalone Caddy stack in
/// `deploy/explorer/`, NOT this in-process mount, for the reasons
/// covered in that directory's README:
///
///   - DDoS hitting the explorer eats CPU/FDs the validator needs.
///   - One bug in axum/reqwest/serde_json crashes the consensus
///     binary, taking the validator down.
///   - TLS, cert renewal, edge caching, CDN integration are
///     standard web infra, not blockchain infra.
///   - You can't move/scale the explorer independently of the node.
///
/// At startup, if `serve_explorer == true` AND `listen_addr` is
/// not localhost, this function logs a loud WARN telling the
/// operator their explorer is reachable from non-localhost. It
/// does NOT refuse to start — sometimes that's what the operator
/// wants — but they cannot say they didn't know.
pub async fn run_rest_api(
    listen_addr: SocketAddr,
    jsonrpc_addr: SocketAddr,
    serve_explorer: bool,
) -> crate::error::Result<()> {
    let rpc_bearer = std::env::var("COINCYNC_RPC_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let state = RestState {
        jsonrpc_addr,
        // SECURITY: Timeout prevents DoS from hanging backend connections
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client must build"),
        rpc_bearer,
    };

    // SECURITY: Restricted CORS — only allow same-origin and the explorer.
    // CorsLayer::permissive() allows ANY website to call the RPC proxy from
    // a visitor's browser, enabling CSRF-like attacks on the node.
    let mut origins: Vec<axum::http::HeaderValue> = vec![
        "http://localhost:3000".parse().unwrap(),
        "http://127.0.0.1:3000".parse().unwrap(),
        "https://explorer.coincync.network".parse().unwrap(),
    ];
    // Allow explorer served from node's own ports
    let explorer_port = listen_addr.port().wrapping_sub(1);
    if let Ok(hv) = format!("http://127.0.0.1:{}", explorer_port).parse::<axum::http::HeaderValue>()
    {
        origins.push(hv);
    }
    if let Ok(hv) = format!("http://localhost:{}", explorer_port).parse::<axum::http::HeaderValue>()
    {
        origins.push(hv);
    }
    // Custom origins from environment
    if let Ok(extra) = std::env::var("COINCYNC_CORS_ORIGINS") {
        for origin in extra.split(',') {
            let trimmed = origin.trim();
            if let Ok(hv) = trimmed.parse::<axum::http::HeaderValue>() {
                origins.push(hv);
                tracing::info!("CORS: added custom origin '{}'", trimmed);
            }
        }
    }
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT]);

    let mut app = Router::new();

    // ─── Embedded block explorer (optional) ──────────────────
    //
    // When `serve_explorer == true`, mount the embedded HTML, CSS,
    // theme bootstrap, and application scripts. Every body is a
    // `&'static str` baked into the binary at compile time.
    //
    // SAFETY NOTE: this is a local-dev convenience. For public
    // production deployment, run the standalone Caddy stack in
    // `deploy/explorer/` instead — it isolates the explorer's
    // public-facing HTTP from the consensus binary, supports
    // TLS via Let's Encrypt, vendored CDN assets, rate limiting,
    // and persistent ACME state across container restarts.
    if serve_explorer {
        app = app
            .route(
                "/",
                get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        crate::rpc::explorer::EXPLORER_HTML,
                    )
                }),
            )
            .route(
                "/explorer.css",
                get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
                        crate::rpc::explorer::EXPLORER_CSS,
                    )
                }),
            )
            .route(
                "/theme-init.js",
                get(|| async {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/javascript; charset=utf-8",
                        )],
                        crate::rpc::explorer::EXPLORER_THEME_JS,
                    )
                }),
            );
        for &(path, source) in crate::rpc::explorer::EXPLORER_APP_ASSETS {
            let route = format!("/{path}");
            app = app.route(
                &route,
                get(move || async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/javascript; charset=utf-8",
                        )],
                        source,
                    )
                }),
            );
        }
    }

    let app = app
        // ─── Core ────────────────────────────────────────────
        .route("/api/v1/health", get(health))
        .route("/api/v1/health/live", get(health_live))
        .route("/api/v1/health/ready", get(health_ready))
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/supply", get(get_supply))
        .route("/api/v1/supply/circulating", get(get_supply_circulating))
        .route("/api/v1/supply/max", get(get_supply_max))
        // ─── Blocks ──────────────────────────────────────────
        .route("/api/v1/blocks/recent", get(get_recent_blocks))
        .route("/api/v1/block/hash/{hash}", get(get_block_by_hash))
        .route("/api/v1/block/height/{height}", get(get_block_by_height))
        .route(
            "/api/v1/block/{height}/transactions",
            get(get_block_transactions),
        )
        // ─── Transactions ────────────────────────────────────
        .route("/api/v1/transaction/{hash}", get(get_transaction))
        .route("/api/v1/transaction/submit", post(submit_transaction))
        // ─── Mempool ─────────────────────────────────────────
        .route("/api/v1/mempool", get(get_mempool))
        .route("/api/v1/mempool/stats", get(get_mempool_stats))
        // ─── Search ──────���───────────────────────────────────
        .route("/api/v1/search", get(search))
        // ─── Network & Privacy ───────────────────────────────
        .route("/api/v1/network", get(get_network))
        .route("/api/v1/anonymity", get(get_anonymity))
        .route("/api/v1/peers", get(get_peers))
        // ─── Statistics ──────────────────────────────────────
        .route("/api/v1/stats", get(get_chain_stats))
        .route("/api/v1/emission", get(get_emission))
        // ─── Events ──────────────────────────────────────────
        .route("/api/v1/events", get(get_chain_events))
        // ─── Assets ───────��──────────────────────────────────
        .route("/api/v1/asset/{id}", get(get_asset))
        .route("/api/v1/assets", get(list_assets))
        // ─── WebSocket ───────────────────────────────────────
        .route("/api/v1/ws", get(ws_upgrade))
        // ─── Raw RPC proxy ───────────────────────────────────
        .route("/rpc", post(rpc_proxy))
        .layer(cors)
        .with_state(state);

    info!("Explorer REST API listening on http://{}", listen_addr);
    info!("  Endpoints: /api/v1/{{status,blocks/recent,search,stats,network,ws,...}}");
    info!("  RPC proxy: POST /rpc (read-only methods only)");
    if serve_explorer {
        info!("  Embedded explorer mounted at GET /  (LOCAL DEV ONLY — see deploy/explorer/ for production)");

        // SECURITY: warn loudly if the explorer mount is reachable
        // from non-localhost. The local-dev mount is meant for
        // an operator iterating on their own machine; binding to
        // a public interface turns it into a public-facing HTTP
        // service that lives inside the consensus binary, which
        // is exactly the situation `deploy/explorer/` exists to
        // avoid. We don't refuse to start (sometimes the
        // operator really did mean it), but they cannot say they
        // didn't know.
        let ip = listen_addr.ip();
        let is_local = ip.is_loopback();
        if !is_local {
            warn!(
                "EXPLORER MOUNTED ON NON-LOCALHOST ({}). The embedded \
                 explorer is intended for local development only. \
                 Public deployments should use the standalone Caddy \
                 stack in deploy/explorer/ instead, which isolates \
                 the public HTTP surface from this consensus binary. \
                 If you really want to expose the explorer from the \
                 node process, this warning is your sign-off.",
                listen_addr
            );
        }
    }

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| crate::error::Error::RpcError(format!("REST bind failed: {}", e)))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::Error::RpcError(format!("REST server error: {}", e)))?;

    Ok(())
}

// ═���═════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn circulating_formatter_preserves_supply_above_u64() {
        let response = serde_json::json!({
            "total_emitted": ((u64::MAX as u128) + 1).to_string()
        });
        assert_eq!(
            parse_total_emitted_atomic(&response).unwrap(),
            (u64::MAX as u128) + 1
        );
        assert_eq!(
            format_atomic_supply_micro((u64::MAX as u128) + 1),
            "18446744.073709"
        );
        assert_eq!(
            format_atomic_supply_micro(crate::constants::MAX_SUPPLY),
            "100000000.000000"
        );
    }

    #[test]
    fn circulating_parser_rejects_lossy_or_invalid_rpc_values() {
        assert!(parse_total_emitted_atomic(&serde_json::json!({
            "total_emitted": u64::MAX
        }))
        .is_err());
        assert!(parse_total_emitted_atomic(&serde_json::json!({
            "total_emitted": "not-a-number"
        }))
        .is_err());
        assert!(parse_total_emitted_atomic(&serde_json::json!({})).is_err());
    }

    fn make_test_router() -> Router {
        let state = RestState {
            jsonrpc_addr: "127.0.0.1:19081".parse().unwrap(),
            client: reqwest::Client::new(),
            rpc_bearer: None,
        };
        Router::new()
            .route("/api/v1/health", get(health))
            .route("/api/v1/health/live", get(health_live))
            .route("/api/v1/health/ready", get(health_ready))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = make_test_router();
        let req = Request::builder()
            .uri("/api/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_live_returns_200_regardless_of_backend() {
        // Liveness only proves the REST process is up. It does NOT
        // reach out to the jsonrpsee backend. Even with a bogus
        // jsonrpc_addr (unreachable), /health/live must return 200
        // because the point of liveness is to answer "is the process
        // alive" for restart-if-dead deciders, not "is it functional"
        // for route-around-if-broken deciders.
        let app = make_test_router();
        let req = Request::builder()
            .uri("/api/v1/health/live")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_ready_returns_503_when_backend_unreachable() {
        // Readiness DOES reach the jsonrpsee backend. In this test the
        // backend at 127.0.0.1:19081 is not running, so the get_info
        // call inside health_ready must time out / fail, and the
        // handler must return 503. This is the exact signal a
        // Cloudflare LB uses to route around a wedged host — the
        // silent-hang class of failure that took api.coincync.network
        // down for 41 hours on 2026-07-02.
        let app = make_test_router();
        let req = Request::builder()
            .uri("/api/v1/health/ready")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_validate_hex_hash_valid() {
        let hash = "a".repeat(64);
        assert!(validate_hex_hash(&hash).is_ok());
    }

    #[test]
    fn test_validate_hex_hash_too_short() {
        assert!(validate_hex_hash("abc").is_err());
    }

    #[test]
    fn test_validate_hex_hash_non_hex() {
        let hash = "g".repeat(64);
        assert!(validate_hex_hash(&hash).is_err());
    }

    #[test]
    fn test_pagination_defaults() {
        let p = Pagination {
            page: None,
            limit: None,
        };
        assert_eq!(p.page(), 1);
        assert_eq!(p.limit(), DEFAULT_PAGE_SIZE);
        assert_eq!(p.offset(), 0);
    }

    #[test]
    fn test_pagination_clamp() {
        let p = Pagination {
            page: Some(0),
            limit: Some(500),
        };
        assert_eq!(p.page(), 1);
        assert_eq!(p.limit(), MAX_PAGE_SIZE);
    }

    #[test]
    fn test_rpc_allowlist_has_explorer_methods() {
        // These are the RPC methods that the embedded block-explorer
        // JavaScript (`src/explorer/app/*.js`, served via
        // `rpc::explorer::EXPLORER_APP_ASSETS`) actively calls via its
        // same-origin `fetch('/rpc', ...)` polls. When served through
        // the REST proxy, each one MUST be in the allowlist or the
        // corresponding panel goes blank. If you add a new
        // `rpc("...")` call in the explorer JS, add it here AND to
        // `RPC_ALLOWED_METHODS` above.
        //
        // Locked together with the explorer-side coverage test in
        // `crate::rpc::explorer::tests::explorer_js_calls_only_registered_methods`
        // so any drift between the two layers fails CI.
        for method in [
            "get_info",
            "get_block_by_height",
            "get_block",
            "get_peers",
            "get_transaction", // NotImplemented stub but still allowlisted
            "get_asset_info",  // NotImplemented stub but still allowlisted
        ] {
            assert!(
                RPC_ALLOWED_METHODS.contains(&method),
                "explorer method `{}` missing from RPC_ALLOWED_METHODS",
                method
            );
        }
    }

    #[test]
    fn test_rpc_allowlist_blocks_sensitive() {
        assert!(!RPC_ALLOWED_METHODS.contains(&"submit_transaction"));
        assert!(!RPC_ALLOWED_METHODS.contains(&"submit_block"));
        assert!(!RPC_ALLOWED_METHODS.contains(&"get_balance"));
        assert!(!RPC_ALLOWED_METHODS.contains(&"transfer"));
        assert!(!RPC_ALLOWED_METHODS.contains(&"get_mining_live"));
        assert!(!RPC_ALLOWED_METHODS.contains(&"get_metrics"));
    }
}
