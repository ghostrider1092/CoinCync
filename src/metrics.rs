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
    Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry, TextEncoder,
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

fn register_gauge(name: &str, help: &str) -> Gauge {
    let g = Gauge::new(name, help).expect("metric name valid");
    REGISTRY
        .register(Box::new(g.clone()))
        .expect("metric not double-registered");
    g
}

fn register_int_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).expect("metric name valid");
    REGISTRY
        .register(Box::new(c.clone()))
        .expect("metric not double-registered");
    c
}

#[allow(dead_code)]
fn register_gauge_vec(name: &str, help: &str, labels: &[&str]) -> GaugeVec {
    let g = GaugeVec::new(Opts::new(name, help), labels).expect("metric name valid");
    REGISTRY
        .register(Box::new(g.clone()))
        .expect("metric not double-registered");
    g
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
        vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ],
    )
});

/// Time to admit a fluffed transaction to the mempool (full crypto
/// verify path). Dominated by CLSAG + Bulletproof+ verification.
pub static TX_ADMIT_TO_MEMPOOL: Lazy<Histogram> = Lazy::new(|| {
    register_histogram(
        "coincync_tx_admit_to_mempool_seconds",
        "Time to admit a tx into the mempool (full crypto verify)",
        vec![
            0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
        ],
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

// ═══════════════════════════════════════════════════════════════════════
// Enterprise chain-health metrics (2026-08-22)
// ═══════════════════════════════════════════════════════════════════════
//
// State GAUGES are refreshed together by `record_chain_snapshot`, called from
// the node's periodic loop. Event COUNTERS/HISTOGRAMS are incremented at their
// event sites via the `record_*` helpers below. Ranges chosen for CoinCync's
// realistic operating envelope; big u128 values (difficulty, supply) are cast
// to f64 for the gauge — dashboard precision, not consensus.

// ── Consensus / chain state ──
/// Current chain tip height.
pub static CHAIN_HEIGHT: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_chain_height", "Current chain tip height"));
/// Seconds since the tip block's timestamp (staleness / liveness signal).
pub static TIP_AGE_SECONDS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge("coincync_tip_age_seconds", "Seconds since the tip block timestamp")
});
/// Current block difficulty (tip target).
pub static DIFFICULTY: Lazy<Gauge> =
    Lazy::new(|| register_gauge("coincync_difficulty", "Current block difficulty"));
/// Cumulative chain work (total difficulty).
pub static TOTAL_DIFFICULTY: Lazy<Gauge> =
    Lazy::new(|| register_gauge("coincync_total_difficulty", "Cumulative chain work"));
/// Total confirmed transactions seen on-chain.
pub static TOTAL_TRANSACTIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge("coincync_total_transactions", "Total on-chain transactions")
});

// ── Emission / supply (transparency for a 0%-tax fair-launch coin) ──
/// Circulating supply in atomic units (`total_supply - total_burned`).
pub static CIRCULATING_SUPPLY: Lazy<Gauge> = Lazy::new(|| {
    register_gauge("coincync_circulating_supply_atomic", "Circulating supply (atomic units)")
});
/// Total emitted supply in atomic units.
pub static TOTAL_SUPPLY: Lazy<Gauge> = Lazy::new(|| {
    register_gauge("coincync_total_supply_atomic", "Total emitted supply (atomic units)")
});
/// Cumulative fees burned in atomic units.
pub static FEE_BURNED_TOTAL: Lazy<Gauge> = Lazy::new(|| {
    register_gauge("coincync_fee_burned_total_atomic", "Cumulative fees burned (atomic units)")
});
/// Current per-block coinbase reward in atomic units.
pub static BLOCK_REWARD: Lazy<Gauge> = Lazy::new(|| {
    register_gauge("coincync_block_reward_atomic", "Current block reward (atomic units)")
});

// ── Sync / IBD (catches the wedge incidents) ──
/// 1 if the node considers itself synced, else 0.
pub static IS_SYNCED: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_is_synced", "1 if node is synced, else 0"));
/// Best-known height minus our height (blocks behind the network).
pub static BLOCKS_BEHIND: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_blocks_behind", "Blocks behind best-known peer"));
/// Sync progress as a percentage [0,100].
pub static SYNC_PROGRESS: Lazy<Gauge> =
    Lazy::new(|| register_gauge("coincync_sync_progress_percent", "Sync progress percent"));

// ── P2P ──
pub static PEERS: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_peers", "Connected peer count"));
pub static PEERS_INBOUND: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_peers_inbound", "Inbound peer count"));
pub static PEERS_OUTBOUND: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_peers_outbound", "Outbound peer count"));
/// Peers banned (cumulative).
pub static PEER_BANS_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter("coincync_peer_bans_total", "Cumulative peers banned"));

// ── Mempool ──
pub static MEMPOOL_SIZE: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_mempool_size", "Mempool transaction count"));
pub static MEMPOOL_BYTES: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_mempool_bytes", "Mempool size in bytes"));
/// Mempool admission rejections, labeled by reason.
pub static MEMPOOL_REJECTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec(
        "coincync_mempool_rejects_total",
        "Mempool admission rejections by reason",
        &["reason"],
    )
});

// ── Storage ──
pub static UTXO_SET_SIZE: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_utxo_set_size", "UTXO set size (outputs)"));
pub static DB_SIZE_BYTES: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge("coincync_db_size_bytes", "On-disk database size in bytes"));

// ── Reorg / finality (catches the reorg-deadlock / runaway-fork incidents) ──
pub static REORG_TOTAL: Lazy<IntCounter> =
    Lazy::new(|| register_int_counter("coincync_reorg_total", "Cumulative chain reorganizations"));
pub static ORPHAN_BLOCKS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter("coincync_orphan_blocks_total", "Cumulative orphan/stale blocks")
});
/// Depth of each reorganization (distribution).
pub static REORG_DEPTH: Lazy<Histogram> = Lazy::new(|| {
    register_histogram(
        "coincync_reorg_depth",
        "Depth of each chain reorganization",
        vec![1.0, 2.0, 3.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 1000.0],
    )
});
/// Observed interval between accepted blocks, in seconds.
pub static BLOCK_INTERVAL: Lazy<Histogram> = Lazy::new(|| {
    register_histogram(
        "coincync_block_interval_seconds",
        "Interval between accepted blocks",
        vec![1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0],
    )
});

/// A snapshot of chain state for the periodic gauge refresh. Built by the node
/// (which owns the chain/mempool/p2p handles) and passed to
/// [`record_chain_snapshot`]. Keeping this a plain-value struct keeps
/// `metrics.rs` free of chain/network type dependencies.
#[derive(Debug, Clone, Default)]
pub struct ChainSnapshot {
    pub height: u64,
    pub tip_age_seconds: f64,
    pub difficulty: f64,
    pub total_difficulty: f64,
    pub total_transactions: u64,
    pub circulating_supply_atomic: f64,
    pub total_supply_atomic: f64,
    pub fee_burned_total_atomic: f64,
    pub block_reward_atomic: f64,
    pub is_synced: bool,
    pub blocks_behind: i64,
    pub sync_progress_percent: f64,
    pub peers: i64,
    pub peers_inbound: i64,
    pub peers_outbound: i64,
    pub mempool_size: i64,
    pub mempool_bytes: i64,
    pub utxo_set_size: i64,
    pub db_size_bytes: i64,
}

/// Refresh all state gauges from a snapshot. Call periodically from the node.
pub fn record_chain_snapshot(s: &ChainSnapshot) {
    CHAIN_HEIGHT.set(s.height as i64);
    TIP_AGE_SECONDS.set(s.tip_age_seconds);
    DIFFICULTY.set(s.difficulty);
    TOTAL_DIFFICULTY.set(s.total_difficulty);
    TOTAL_TRANSACTIONS.set(s.total_transactions as i64);
    CIRCULATING_SUPPLY.set(s.circulating_supply_atomic);
    TOTAL_SUPPLY.set(s.total_supply_atomic);
    FEE_BURNED_TOTAL.set(s.fee_burned_total_atomic);
    BLOCK_REWARD.set(s.block_reward_atomic);
    IS_SYNCED.set(if s.is_synced { 1 } else { 0 });
    BLOCKS_BEHIND.set(s.blocks_behind);
    SYNC_PROGRESS.set(s.sync_progress_percent);
    PEERS.set(s.peers);
    PEERS_INBOUND.set(s.peers_inbound);
    PEERS_OUTBOUND.set(s.peers_outbound);
    MEMPOOL_SIZE.set(s.mempool_size);
    MEMPOOL_BYTES.set(s.mempool_bytes);
    UTXO_SET_SIZE.set(s.utxo_set_size);
    DB_SIZE_BYTES.set(s.db_size_bytes);
}

/// Record a chain reorganization of the given depth.
pub fn record_reorg(depth: u64) {
    REORG_TOTAL.inc();
    REORG_DEPTH.observe(depth as f64);
}

/// Record an orphan / stale block.
pub fn record_orphan_block() {
    ORPHAN_BLOCKS_TOTAL.inc();
}

/// Record a mempool admission rejection, labeled by a short stable reason.
pub fn record_mempool_reject(reason: &str) {
    MEMPOOL_REJECTS_TOTAL.with_label_values(&[reason]).inc();
}

/// Record a peer ban.
pub fn record_peer_ban() {
    PEER_BANS_TOTAL.inc();
}

/// Record the interval (seconds) between two accepted blocks.
pub fn record_block_interval(seconds: f64) {
    BLOCK_INTERVAL.observe(seconds);
}

/// Force-register the enterprise metrics so a freshly-started node exposes them
/// (at 0 / empty) before their first update — dashboards then see the series
/// exist immediately. Called from `serve_metrics`.
fn touch_enterprise_metrics() {
    Lazy::force(&CHAIN_HEIGHT);
    Lazy::force(&TIP_AGE_SECONDS);
    Lazy::force(&DIFFICULTY);
    Lazy::force(&TOTAL_DIFFICULTY);
    Lazy::force(&TOTAL_TRANSACTIONS);
    Lazy::force(&CIRCULATING_SUPPLY);
    Lazy::force(&TOTAL_SUPPLY);
    Lazy::force(&FEE_BURNED_TOTAL);
    Lazy::force(&BLOCK_REWARD);
    Lazy::force(&IS_SYNCED);
    Lazy::force(&BLOCKS_BEHIND);
    Lazy::force(&SYNC_PROGRESS);
    Lazy::force(&PEERS);
    Lazy::force(&PEERS_INBOUND);
    Lazy::force(&PEERS_OUTBOUND);
    Lazy::force(&PEER_BANS_TOTAL);
    Lazy::force(&MEMPOOL_SIZE);
    Lazy::force(&MEMPOOL_BYTES);
    Lazy::force(&MEMPOOL_REJECTS_TOTAL);
    Lazy::force(&UTXO_SET_SIZE);
    Lazy::force(&DB_SIZE_BYTES);
    Lazy::force(&REORG_TOTAL);
    Lazy::force(&ORPHAN_BLOCKS_TOTAL);
    Lazy::force(&REORG_DEPTH);
    Lazy::force(&BLOCK_INTERVAL);
}

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
    // Pre-register the enterprise chain-health metrics so they appear at 0
    // before their first update.
    touch_enterprise_metrics();

    let app = Router::new().route(
        "/metrics",
        get(|| async {
            let body = render_metrics();
            ([("content-type", "text/plain; version=0.0.4")], body)
        }),
    );

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(
        "Metrics scrape endpoint listening on http://{}/metrics",
        bind_addr
    );
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

// (Removed 2026-08-22) The "legacy thin-helper API" — ~30 no-op `pub fn`
// stubs (block_height, reorg, hashrate, …) — had zero call sites and did
// nothing when called. A no-op that looks like it records a metric is a
// footgun (silent data loss), so the dead surface was deleted. Real metrics
// live in the registered `Lazy<...>` gauges/histograms above; add a new one
// there and record to it directly when a producer actually exists.
