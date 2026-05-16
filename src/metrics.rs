//! src/metrics.rs
//!
//! Prometheus metrics for the full node.
//!
//! ## Architecture
//!
//! All metrics register against a process-global `Registry` (`REGISTRY`).
//! `serve_metrics(addr)` spawns a tiny axum HTTP server that gathers and
//! encodes the registry on every `/metrics` request — standard Prometheus
//! scrape pattern, no push.
//!
//! Counters and gauges live in the `dandelion` submodule (preserves the
//! 6 call sites that already use `.inc()` / `.set()` — production code
//! requires no changes). Histograms for the 4 hot paths
//! (block-receive-to-tip, tx-admit-to-mempool, peer-handshake,
//! RandomX-hash) live at module top level — instrument with
//! `metrics::BLOCK_RECEIVE_TO_TIP.observe(elapsed_secs)`.
//!
//! Replaces the 1.0-trim noop stubs that compiled but did nothing.
//! Phase 1 #6 of the post-launch campaign.

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder,
};

use crate::error::Result;

/// Global metric registry. All counters / gauges / histograms register
/// against this; `serve_metrics` gathers from this on every scrape.
pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

fn register_int_counter(name: &str, help: &str) -> IntCounter {
    let c = IntCounter::new(name, help).expect("metric name valid");
    REGISTRY
        .register(Box::new(c.clone()))
        .expect("metric not double-registered");
    c
}

fn register_int_gauge(name: &str, help: &str) -> IntGauge {
    let g = IntGauge::new(name, help).expect("metric name valid");
    REGISTRY
        .register(Box::new(g.clone()))
        .expect("metric not double-registered");
    g
}

fn register_histogram(name: &str, help: &str, buckets: Vec<f64>) -> Histogram {
    let opts = HistogramOpts::new(name, help).buckets(buckets);
    let h = Histogram::with_opts(opts).expect("metric name valid");
    REGISTRY
        .register(Box::new(h.clone()))
        .expect("metric not double-registered");
    h
}

// ─── Histograms for the four Phase-1 hot paths ────────────────────────
//
// Bucket boundaries chosen to bracket the baseline numbers from
// `benches/crypto_hot_paths.rs` (commits b2b260a + 740cfb5).

/// Wall-time from `NodeEvent::BlockReceived` to the chain tip being
/// updated. Captures the full block-validation + DB-write cost. Expected
/// median ~100ms on a busy block per bench math.
pub static BLOCK_RECEIVE_TO_TIP: Lazy<Histogram> = Lazy::new(|| {
    register_histogram(
        "coincync_block_receive_to_tip_seconds",
        "Time from BlockReceived event to chain tip update",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    )
});

/// Time to admit a fluffed transaction to the mempool (full crypto
/// verify path). Dominated by CLSAG + Bulletproof+ verification.
pub static TX_ADMIT_TO_MEMPOOL: Lazy<Histogram> = Lazy::new(|| {
    register_histogram(
        "coincync_tx_admit_to_mempool_seconds",
        "Time to admit a tx into the mempool (full crypto verify)",
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
    )
});

/// Wall-time for the Noise XX handshake + initial Version exchange.
/// Trips alarm if the network is slow or a peer is hostile-but-slow.
pub static PEER_HANDSHAKE: Lazy<Histogram> = Lazy::new(|| {
    register_histogram(
        "coincync_peer_handshake_seconds",
        "Time for Noise handshake + Version exchange",
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    )
});

/// Time for one RandomX hash computation (post-VM-init). Catches slow
/// CPU bursts and validates the VM cache is working.
pub static RANDOMX_HASH: Lazy<Histogram> = Lazy::new(|| {
    register_histogram(
        "coincync_randomx_hash_seconds",
        "Time for one RandomX hash computation",
        vec![0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5],
    )
});

// ─── HTTP scrape server ───────────────────────────────────────────────
//
// Spawn one per process via `serve_metrics`. Listens on the provided
// address and responds to `GET /metrics` with the standard
// Prometheus text-exposition format.

/// Render the current registry state to the Prometheus text format.
pub fn render_metrics() -> Vec<u8> {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    let _ = encoder.encode(&metric_families, &mut buffer);
    buffer
}

/// Spawn the metrics scrape server. Binds the provided address and
/// serves `GET /metrics` until cancelled.
///
/// Force-touches the four hot-path histograms (`BLOCK_RECEIVE_TO_TIP`,
/// `TX_ADMIT_TO_MEMPOOL`, `PEER_HANDSHAKE`, `RANDOMX_HASH`) so they
/// register with `REGISTRY` at process start. Without this, the
/// `Lazy<Histogram>` initialisers only fire on the first `.observe()`
/// call — meaning a fresh node with no traffic yet would show zero
/// histograms on its `/metrics` scrape, confusing dashboards into
/// thinking the metric doesn't exist. Touching `&*HISTOGRAM` is the
/// cheapest possible dereference (one atomic Lazy::get) and adds the
/// metric to the registry with empty buckets, which is the standard
/// Prometheus posture for a freshly-started process.
pub async fn serve_metrics(bind_addr: std::net::SocketAddr) -> Result<()> {
    use axum::{routing::get, Router};

    // Pre-register the four hot-path histograms.
    let _ = &*BLOCK_RECEIVE_TO_TIP;
    let _ = &*TX_ADMIT_TO_MEMPOOL;
    let _ = &*PEER_HANDSHAKE;
    let _ = &*RANDOMX_HASH;

    let app = Router::new().route(
        "/metrics",
        get(|| async {
            let body = render_metrics();
            (
                [("content-type", "text/plain; version=0.0.4")],
                body,
            )
        }),
    );

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("Metrics scrape endpoint listening on http://{}/metrics", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Legacy init stub kept for callers; the real lifecycle is now
/// `serve_metrics` spawned from `bin/node.rs`.
pub fn init(_bind_addr: &str) -> Result<()> {
    Ok(())
}

// ─── Dandelion submodule (preserves the 6 existing call sites) ───────
//
// The 6 callers (3 in src/network/dandelion.rs, 3 in src/network/node.rs)
// use `.inc()` and `.set()`. Real `IntCounter::inc(&self)` and
// `IntGauge::set(&self, i64)` match those signatures exactly, so no
// caller changes are required.
pub mod dandelion {
    use super::{register_int_counter, register_int_gauge, IntCounter, IntGauge, Lazy};

    pub static EPOCH_ROTATIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter(
            "coincync_dandelion_epoch_rotations_total",
            "Total Dandelion++ epoch rotations since process start",
        )
    });
    pub static CURRENT_EPOCH_MODE: Lazy<IntGauge> = Lazy::new(|| {
        register_int_gauge(
            "coincync_dandelion_current_epoch_mode",
            "Current epoch mode (1=fluff, 0=stem)",
        )
    });
    pub static EMBARGO_FLUFFS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter(
            "coincync_dandelion_embargo_fluffs_total",
            "Total embargo-expired fail-safe fluffs",
        )
    });
    pub static STEM_RELAYS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter(
            "coincync_dandelion_stem_relays_total",
            "Total stem-phase tx relays",
        )
    });
    pub static FLUFF_BROADCASTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
        register_int_counter(
            "coincync_dandelion_fluff_broadcasts_total",
            "Total fluff-phase tx broadcasts",
        )
    });
    pub static STEMPOOL_SIZE: Lazy<IntGauge> = Lazy::new(|| {
        register_int_gauge(
            "coincync_dandelion_stempool_size",
            "Current stempool size (pending stem-phase txs)",
        )
    });
}

// ─── Legacy thin-helper API (retained, callers are mostly absent) ────
//
// These were noop stubs in the 1.0 trim and have no production callers
// today. Kept as no-op signatures so future code that wants them as
// convenience helpers can write `metrics::block_height(h)` without
// reaching for the histogram types directly. When a real caller lands,
// re-implement the relevant fn to push to a registered metric.
pub fn block_height(_h: u64) {}
pub fn block_time_secs(_t: f64) {}
pub fn block_size_bytes(_s: usize) {}
pub fn orphan_block() {}
pub fn reorg(_depth: u64) {}
pub fn difficulty(_d: f64) {}
pub fn circulating_supply(_s: u64) {}

pub fn mempool_size(_n: usize) {}
pub fn mempool_bytes(_b: usize) {}
pub fn tx_accepted() {}
pub fn tx_rejected() {}

pub fn validation_ms(_ms: f64) {}
pub fn clsag_verify_ms(_ms: f64) {}
pub fn bp_verify_ms(_ms: f64) {}
pub fn halo2_verify_ms(_ms: f64) {}

pub fn peer_count(_n: usize) {}
pub fn inbound_peers(_n: usize) {}
pub fn outbound_peers(_n: usize) {}
pub fn bytes_sent(_b: u64) {}
pub fn bytes_recv(_b: u64) {}
pub fn msg_sent() {}
pub fn msg_recv() {}

pub fn hashrate(_hr: f64) {}
pub fn mined_block() {}

pub fn shielded_tx_count() {}
pub fn shielded_pool_size(_n: u64) {}
pub fn shielded_tx_ratio(_r: f64) {}
