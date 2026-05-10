//! # CoinCync Testnet Faucet
//!
//! HTTP service that drips a fixed amount of tCYNC to a requester's
//! address, gated by per-address and per-IP rate limits backed by
//! SQLite for persistence across restarts.
//!
//! ## Endpoints
//!
//! - `POST /faucet`
//!     - body:  `{"address": "tCYNC..."}`
//!     - 200:   `{"success": true, "tx_hash": "<hex>", "amount_atomic": 10000000000000}`
//!     - 4xx:   `{"success": false, "error": "<reason>"}`
//!
//! - `GET /faucet/stats`
//!     - 200:   `{"total_drips": <N>, "total_atomic": <N>, "drip_amount_atomic": <N>}`
//!
//! - `GET /faucet/health`
//!     - 200:   `OK\n` (200/text-plain) when wallet binary + DB are reachable
//!
//! ## Configuration
//!
//! All config via environment, typically loaded by systemd from
//! `/etc/coincync/faucet.env`. See `Config` for the exhaustive list.
//!
//! ## Security posture
//!
//! - Wallet password passed on the wallet's CLI (visible to root via `ps`
//!   but the api box is single-tenant root-only).
//! - SQLite rate-limit DB defends against per-address and per-IP spam;
//!   does not defend against IP rotation by an attacker with many proxies.
//! - Drip amount is bounded; even if the rate limit is bypassed entirely
//!   the hot wallet can serve at most `balance / drip_amount` requests.
//! - Front-of-house host (Cloudflare-proxied) hides the origin IP.

mod config;
mod db;
mod handler;
mod wallet;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::Config;
use crate::db::DripDb;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Arc<DripDb>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logging
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,coincync_faucet=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(false))
        .init();

    let cfg = Arc::new(Config::parse());
    cfg.validate_paths()?;

    tracing::info!(
        listen = %cfg.listen_addr,
        wallet = %cfg.wallet_path.display(),
        node   = %cfg.node_rpc,
        drip   = cfg.drip_amount_atomic,
        "starting coincync-faucet"
    );

    let db = Arc::new(DripDb::open(&cfg.db_path)?);
    let state = AppState { cfg: cfg.clone(), db };

    // CORS: allow the public sites that hit this endpoint cross-origin.
    // We are explicit about origins rather than '*' so abuse from
    // arbitrary sites is harder.
    let cors = CorsLayer::new()
        .allow_methods([axum::http::Method::POST, axum::http::Method::GET, axum::http::Method::OPTIONS])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_origin(cfg.cors_origins());

    let app = Router::new()
        .route("/faucet", post(handler::drip))
        .route("/faucet/stats", get(handler::stats))
        .route("/faucet/health", get(handler::health))
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr).await?;
    tracing::info!(local_addr = %listener.local_addr()?, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("install ctrl-c handler"); };
    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("ctrl-c received, shutting down"),
        _ = term => tracing::info!("SIGTERM received, shutting down"),
    }
}
