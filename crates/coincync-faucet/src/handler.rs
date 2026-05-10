//! HTTP handlers for the faucet service.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize)]
pub struct DripRequest {
    pub address: String,
}

#[derive(Serialize)]
pub struct DripSuccess {
    pub success: bool, // always true here
    pub tx_hash: String,
    pub amount_atomic: u64,
}

#[derive(Serialize)]
pub struct DripError {
    pub success: bool, // always false here
    pub error: String,
    /// Seconds the caller must wait before retrying. Optional; only
    /// set on rate-limit errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<i64>,
}

impl DripError {
    fn new(msg: impl Into<String>) -> Self {
        Self { success: false, error: msg.into(), retry_after_secs: None }
    }
    fn rate_limited(msg: impl Into<String>, retry_after: i64) -> Self {
        Self { success: false, error: msg.into(), retry_after_secs: Some(retry_after) }
    }
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_drips: i64,
    pub total_atomic: i64,
    pub last_drip_ts: Option<i64>,
    pub drip_amount_atomic: u64,
}

/// `POST /faucet`
pub async fn drip(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<DripRequest>,
) -> impl IntoResponse {
    let cfg = state.cfg.clone();
    let db = state.db.clone();

    // Resolve the caller IP. Behind nginx + Cloudflare we trust the
    // X-Forwarded-For chain's first entry only when the immediate
    // peer is loopback (i.e. nginx). Direct binds use the real peer.
    let ip = resolve_ip(&headers, &remote);

    // Validate the address using the project's own codec.
    let parsed = match coincync::primitives::Address::from_string(req.address.trim()) {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(ip = %ip, error = %e, "rejected malformed address");
            return (StatusCode::BAD_REQUEST, Json(DripError::new(format!("invalid address: {e}")))).into_response();
        }
    };
    let canonical = parsed.to_string();

    // Network check: faucet only drips on its configured network.
    let expected_network = match cfg.network.as_str() {
        "testnet" => coincync::primitives::Network::Testnet,
        "mainnet" => coincync::primitives::Network::Mainnet,
        other => {
            tracing::error!(network = other, "faucet configured with unknown network");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DripError::new("server misconfigured"))).into_response();
        }
    };
    if parsed.network != expected_network {
        return (StatusCode::BAD_REQUEST, Json(DripError::new(format!(
            "wrong network — faucet drips {:?} only", expected_network
        )))).into_response();
    }

    let now = unix_now();

    // Per-address rate limit
    match db.last_drip_for_address(&canonical).await {
        Ok(Some(last_ts)) if (now - last_ts) < cfg.rate_limit_address_secs => {
            let retry_after = cfg.rate_limit_address_secs - (now - last_ts);
            tracing::info!(addr = %short(&canonical), retry_after, "rate-limited (per-address)");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(DripError::rate_limited(
                    format!("address rate-limited; try again in {retry_after}s"),
                    retry_after,
                )),
            ).into_response();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "db lookup failed (address)");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DripError::new("db error"))).into_response();
        }
    }

    // Per-IP rate limit
    match db.last_drip_for_ip(&ip).await {
        Ok(Some(last_ts)) if (now - last_ts) < cfg.rate_limit_ip_secs => {
            let retry_after = cfg.rate_limit_ip_secs - (now - last_ts);
            tracing::info!(ip = %ip, retry_after, "rate-limited (per-ip)");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(DripError::rate_limited(
                    format!("ip rate-limited; try again in {retry_after}s"),
                    retry_after,
                )),
            ).into_response();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "db lookup failed (ip)");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DripError::new("db error"))).into_response();
        }
    }

    // Send the drip
    let to_spend_hex = parsed.spend_public_key.to_hex();
    let to_view_hex  = parsed.view_public_key.to_hex();

    let send_result = crate::wallet::send(
        &cfg.wallet_bin,
        &cfg.wallet_path,
        &cfg.network,
        &cfg.node_rpc,
        &cfg.wallet_password,
        &to_spend_hex,
        &to_view_hex,
        cfg.drip_amount_atomic,
        Duration::from_secs(cfg.send_timeout_secs),
    ).await;

    match send_result {
        Ok(r) => {
            // Record the drip BEFORE returning success — better to
            // double-pay on a crash than to silently let the user
            // re-drip while the chain has already accepted theirs.
            if let Err(e) = db.record_drip(&canonical, &ip, now, Some(&r.tx_hash), cfg.drip_amount_atomic).await {
                tracing::error!(error = %e, tx_hash = %r.tx_hash, "drip succeeded but db insert failed");
                // Return success anyway; the chain has it.
            }
            tracing::info!(addr = %short(&canonical), ip = %ip, tx = %r.tx_hash, "drip OK");
            (
                StatusCode::OK,
                Json(DripSuccess {
                    success: true,
                    tx_hash: r.tx_hash,
                    amount_atomic: cfg.drip_amount_atomic,
                }),
            ).into_response()
        }
        Err(e) => {
            tracing::error!(addr = %short(&canonical), ip = %ip, error = %e, "wallet send failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(DripError::new(format!("wallet send failed: {e}"))),
            ).into_response()
        }
    }
}

/// `GET /faucet/stats`
pub async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.stats().await {
        Ok(s) => (StatusCode::OK, Json(StatsResponse {
            total_drips: s.total_drips,
            total_atomic: s.total_atomic,
            last_drip_ts: s.last_drip_ts,
            drip_amount_atomic: state.cfg.drip_amount_atomic,
        })).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "stats query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "stats error").into_response()
        }
    }
}

/// `GET /faucet/health` — text/plain `OK` when the wallet binary +
/// db file are present. Used by uptime monitors.
pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    if !state.cfg.wallet_bin.exists() {
        return (StatusCode::SERVICE_UNAVAILABLE, "wallet binary missing").into_response();
    }
    if !state.cfg.wallet_path.exists() {
        return (StatusCode::SERVICE_UNAVAILABLE, "wallet file missing").into_response();
    }
    if let Err(e) = state.db.stats().await {
        tracing::error!(error = %e, "health: db unreachable");
        return (StatusCode::SERVICE_UNAVAILABLE, "db unreachable").into_response();
    }
    (StatusCode::OK, "OK\n").into_response()
}

// ── helpers ─────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Short-form address for logs (first 12 chars + "…").
fn short(addr: &str) -> String {
    if addr.len() <= 12 { addr.to_string() } else { format!("{}…", &addr[..12]) }
}

/// Pick the right caller IP. Trust `X-Forwarded-For` only when the
/// immediate peer is loopback (== running behind a local reverse
/// proxy we put there). Direct binds fall through to the peer addr.
fn resolve_ip(headers: &HeaderMap, peer: &SocketAddr) -> String {
    let peer_is_local = peer.ip().is_loopback();
    if peer_is_local {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // X-Forwarded-For: client, proxy1, proxy2 → take the first.
            if let Some(first) = xff.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            return real.trim().to_string();
        }
    }
    peer.ip().to_string()
}
