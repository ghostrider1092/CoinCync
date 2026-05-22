//! Prometheus /metrics endpoint.
//!
//! No external dep — tokio's TcpListener is enough. We expose six metrics
//! suitable for an operator dashboard or alertmanager rules:
//!
//!   coincync_rig_hashes_total              counter — total hashes computed
//!   coincync_rig_blocks_accepted_total     counter — blocks our submit was acked
//!   coincync_rig_blocks_rejected_total     counter — blocks the daemon rejected
//!   coincync_rig_blocks_found_total        counter — blocks we found locally
//!   coincync_rig_uptime_seconds            counter — wall seconds since start
//!   coincync_rig_current_template_height   gauge   — height we're mining toward
//!   coincync_rig_current_hashrate_hps      gauge   — hashes/sec last iteration
//!   coincync_rig_threads                   gauge   — active worker threads
//!
//! The only consumer cost is one TCP accept per scrape. Default Prometheus
//! scrape is 15s, so this is essentially free.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How many recent hashrate samples to keep for the TUI sparkline. One
/// sample per second of mining = 60s of trend visible.
pub const HASHRATE_RING_SIZE: usize = 60;

/// How many recent block-found timestamps (Unix seconds) to keep for the
/// TUI's 24-hour timeline strip. 24h × 3600s with a typical ~15-block-
/// per-hour testnet rate is ~360 entries; 512 is a comfortable upper
/// bound.
pub const BLOCK_FINDS_RING_SIZE: usize = 512;

/// Atomic counters/gauges shared between the orchestrator (writer) and
/// the metrics HTTP server / TUI (readers). Cheap to clone (one Arc
/// bump). Lock-protected fields are only the small VecDeques the TUI
/// reads — the hot path stays atomic-only.
pub struct MetricsState {
    pub started_unix_seconds: u64,
    pub hashes_total: AtomicU64,
    pub blocks_found_total: AtomicU64,
    pub blocks_accepted_total: AtomicU64,
    pub blocks_rejected_total: AtomicU64,
    pub current_template_height: AtomicU64,
    /// Hashrate from the most recent mining iteration, integer hps so
    /// it fits in an atomic. Updated on every iteration end.
    pub current_hashrate_hps: AtomicU64,
    pub threads: AtomicU64,

    // ── TUI-facing live state ─────────────────────────────────────
    /// Last-observed connected-node tip age in seconds. Used by the
    /// TUI's stale-chain warning banner. 0 means "never sampled".
    pub tip_age_secs: AtomicU64,
    /// Last-observed daemon RPC roundtrip in milliseconds. Drives the
    /// connection-quality dot in the header.
    pub rpc_latency_ms: AtomicU64,
    /// Total network hashrate as reported by the daemon's `get_info`.
    /// 0 means "not yet observed" — the TUI suppresses the share % stat
    /// until this is non-zero.
    pub network_hashrate_hps: AtomicU64,
    /// Operator-toggled pause flag. When `true`, the orchestrator sleeps
    /// instead of fetching a new template — visible to the user as a
    /// frozen hashrate + "PAUSED" status pill in the header.
    pub paused: AtomicBool,
    /// Most recent hashrate samples (one per second) for the sparkline.
    /// Mutex is uncontested 99% of the time — TUI reads at ~4 fps,
    /// orchestrator pushes at 1 Hz.
    pub hashrate_ring: Mutex<VecDeque<u64>>,
    /// Unix-seconds timestamps of recent block accepts for the 24-hour
    /// timeline strip.
    pub block_finds: Mutex<VecDeque<u64>>,
    /// Per-thread hashrate (H/s) from the most recent mining iteration,
    /// indexed by thread id. Length equals the active thread count.
    /// Empty until the first iteration completes. The TUI's worker
    /// heatmap reads this; thermal throttling on a single core surfaces
    /// here as a cool cell while siblings run hot.
    pub per_thread_hashrate_hps: Mutex<Vec<u64>>,
}

impl MetricsState {
    pub fn new(threads: usize) -> Arc<Self> {
        let started = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Arc::new(Self {
            started_unix_seconds: started,
            hashes_total: AtomicU64::new(0),
            blocks_found_total: AtomicU64::new(0),
            blocks_accepted_total: AtomicU64::new(0),
            blocks_rejected_total: AtomicU64::new(0),
            current_template_height: AtomicU64::new(0),
            current_hashrate_hps: AtomicU64::new(0),
            threads: AtomicU64::new(threads as u64),
            tip_age_secs: AtomicU64::new(0),
            rpc_latency_ms: AtomicU64::new(0),
            network_hashrate_hps: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            hashrate_ring: Mutex::new(VecDeque::with_capacity(HASHRATE_RING_SIZE)),
            block_finds: Mutex::new(VecDeque::with_capacity(BLOCK_FINDS_RING_SIZE)),
            per_thread_hashrate_hps: Mutex::new(Vec::new()),
        })
    }

    /// Replace the per-thread hashrate snapshot with a fresh reading.
    /// Called by the orchestrator at the end of every mining iteration.
    pub fn record_per_thread_hashrate(&self, samples: Vec<u64>) {
        if let Ok(mut v) = self.per_thread_hashrate_hps.lock() {
            *v = samples;
        }
    }

    /// Snapshot of the current per-thread hashrate samples for the TUI
    /// heatmap. Returns a fresh `Vec<u64>` so the TUI doesn't hold the
    /// mutex across its render frame.
    pub fn per_thread_hashrate_samples(&self) -> Vec<u64> {
        self.per_thread_hashrate_hps
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Push a hashrate sample into the sparkline ring, evicting the
    /// oldest if we're at capacity. Cheap; called once per second by
    /// the orchestrator (or whoever owns the sample cadence).
    pub fn record_hashrate_sample(&self, hps: u64) {
        if let Ok(mut ring) = self.hashrate_ring.lock() {
            if ring.len() >= HASHRATE_RING_SIZE {
                ring.pop_front();
            }
            ring.push_back(hps);
        }
    }

    /// Record a successful block-find timestamp for the 24h timeline.
    pub fn record_block_find(&self, unix_secs: u64) {
        if let Ok(mut ring) = self.block_finds.lock() {
            if ring.len() >= BLOCK_FINDS_RING_SIZE {
                ring.pop_front();
            }
            ring.push_back(unix_secs);
        }
    }

    /// Snapshot of the hashrate ring for the TUI sparkline. Returns a
    /// fresh `Vec<u64>` so the TUI doesn't hold the mutex across its
    /// render frame.
    pub fn hashrate_samples(&self) -> Vec<u64> {
        self.hashrate_ring
            .lock()
            .map(|r| r.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Snapshot of recent block-find timestamps within the last 24h.
    pub fn recent_block_finds(&self, now_unix: u64) -> Vec<u64> {
        let cutoff = now_unix.saturating_sub(24 * 3600);
        self.block_finds
            .lock()
            .map(|r| r.iter().copied().filter(|&t| t >= cutoff).collect())
            .unwrap_or_default()
    }

    /// Render the Prometheus text-format body for the current state.
    fn render(&self) -> String {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(self.started_unix_seconds);
        let uptime = now.saturating_sub(self.started_unix_seconds);

        let mut s = String::with_capacity(1024);
        let m = |s: &mut String, name: &str, kind: &str, help: &str, value: u64| {
            s.push_str("# HELP ");
            s.push_str(name);
            s.push(' ');
            s.push_str(help);
            s.push('\n');
            s.push_str("# TYPE ");
            s.push_str(name);
            s.push(' ');
            s.push_str(kind);
            s.push('\n');
            s.push_str(name);
            s.push(' ');
            s.push_str(&value.to_string());
            s.push('\n');
        };

        m(&mut s, "coincync_rig_hashes_total", "counter",
          "Total hashes computed since miner start.",
          self.hashes_total.load(Ordering::Relaxed));
        m(&mut s, "coincync_rig_blocks_found_total", "counter",
          "Blocks the miner found locally (before submit).",
          self.blocks_found_total.load(Ordering::Relaxed));
        m(&mut s, "coincync_rig_blocks_accepted_total", "counter",
          "Blocks the daemon accepted into the chain.",
          self.blocks_accepted_total.load(Ordering::Relaxed));
        m(&mut s, "coincync_rig_blocks_rejected_total", "counter",
          "Blocks the daemon rejected on submit (usually lost race).",
          self.blocks_rejected_total.load(Ordering::Relaxed));
        m(&mut s, "coincync_rig_uptime_seconds", "counter",
          "Wall seconds since miner start.",
          uptime);
        m(&mut s, "coincync_rig_current_template_height", "gauge",
          "Block height the current template targets.",
          self.current_template_height.load(Ordering::Relaxed));
        m(&mut s, "coincync_rig_current_hashrate_hps", "gauge",
          "Hashes per second from the last completed mining iteration.",
          self.current_hashrate_hps.load(Ordering::Relaxed));
        m(&mut s, "coincync_rig_threads", "gauge",
          "Active worker threads.",
          self.threads.load(Ordering::Relaxed));

        s
    }
}

/// Spawn the Prometheus /metrics server bound to `bind_addr:port`.
/// Returns once the listener is bound; the actual accept loop runs
/// forever in a tokio task. Errors are logged but do not bring down
/// mining — metrics is never allowed to interfere with the hot path.
///
/// `bind_addr` defaults to `127.0.0.1` at the CLI/config layer.
/// /metrics is unauthenticated; binding to a non-loopback address
/// publishes mining stats to anyone who can reach the port. Operators
/// who scrape from another host should bind to a specific internal IP
/// rather than `0.0.0.0`, and firewall the port.
pub async fn serve(bind_addr: &str, port: u16, state: Arc<MetricsState>) -> io::Result<()> {
    let listener = TcpListener::bind((bind_addr, port)).await?;
    if bind_addr == "0.0.0.0" || bind_addr == "::" {
        tracing::warn!(
            bind_addr,
            port,
            "metrics: /metrics endpoint is bound to all interfaces with no authentication — \
             firewall the port or bind to 127.0.0.1 / a specific internal IP",
        );
    } else {
        tracing::info!(bind_addr, port, "metrics: /metrics endpoint live");
    }

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle(stream, state).await {
                            // Don't escalate scrape errors — partial reads,
                            // closed sockets, etc. are routine for a /metrics
                            // endpoint exposed to the network.
                            tracing::trace!(error = %e, "metrics: scrape connection error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "metrics: accept failed, retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(())
}

async fn handle(mut stream: tokio::net::TcpStream, state: Arc<MetricsState>) -> io::Result<()> {
    // Drain the request line + headers (don't actually parse them — we
    // just need to read enough to let the client see we're listening).
    // Cap the read at 4 KB to defend against header-flood scrapers.
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    let is_metrics_get = n >= 12 && buf[..12].starts_with(b"GET /metrics");
    if !is_metrics_get {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Ok(());
    }

    let body = state.render();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}
