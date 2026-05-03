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

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Atomic counters/gauges shared between the orchestrator (writer) and
/// the metrics HTTP server (reader). Cheap to clone (one Arc bump).
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
        })
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

/// Spawn the Prometheus /metrics server on `port`. Returns once the
/// listener is bound; the actual accept loop runs forever in a tokio task.
/// Errors are logged but do not bring down mining — metrics is never
/// allowed to interfere with the hot path.
pub async fn serve(port: u16, state: Arc<MetricsState>) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "metrics: /metrics endpoint live");

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
