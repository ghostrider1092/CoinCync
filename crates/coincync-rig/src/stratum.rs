// See hasher.rs for the rustc 1.95 ICE explanation. Remove this allow
// once `coincync-rig run` consumes every public item below.
#![allow(dead_code)]

//! # Stratum client — Phase 2.
//!
//! Bitcoin-style Stratum (`mining.subscribe` / `mining.authorize` /
//! `mining.notify` / `mining.submit`). The pool ships line-delimited
//! JSON-RPC over a single TCP connection; we keep one persistent
//! connection per [`StratumClient`].
//!
//! ## What this module owns
//!
//! - the TCP socket + read/write halves
//! - reading inbound lines, parsing JSON-RPC, dispatching by `id` /
//!   `method`
//! - the outbound id counter and the pending-response map
//! - the inbound [`Job`] channel that workers consume
//! - share submission with id-tagged correlation back to a result
//!
//! ## What this module does NOT own (yet)
//!
//! - **Auto-reconnect / failover**. Add in Phase 5 (Tier 1 of the
//!   design doc — failover pool list, exponential backoff). For now, a
//!   disconnect surfaces as `recv()` returning `None` and the worker
//!   pool can choose to re-instantiate the client.
//! - **TLS**. Phase 5 (Tier 4) — add `tokio-rustls` and a `connect_tls`
//!   constructor.
//! - **Worker pool**. Phase 3 — workers consume from `JobReceiver` and
//!   call [`StratumClient::submit_share`].
//!
//! ## Wire-format note
//!
//! The pool sends each JSON object on its own line, terminated by `\n`.
//! Some pools send `\r\n`; we accept both. Our outbound writes always
//! end with a single `\n` (every documented Stratum pool tolerates
//! that).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, info, warn};

use coincync::primitives::Hash;

/// One mining job from the pool. Field names mirror the Stratum
/// `mining.notify` params, translated into types we actually use.
///
/// We collapse the Bitcoin-style `(coinb1, coinb2, merkle_branches,
/// version, nbits, ntime, clean_jobs)` tuple into a chain-specific
/// shape because for CoinCync the pool just hands the miner a ready-
/// to-hash blob plus the seed and target. Bitcoin's coinbase-merkle
/// reconstruction step doesn't apply — for a privacy chain the pool
/// must assemble the full block server-side anyway, so the miner only
/// ever sees an opaque blob.
#[derive(Clone, Debug)]
pub struct Job {
    /// Pool's job identifier; echoed back on share submission.
    pub job_id: String,
    /// Bytes to be RandomX-hashed (with the nonce patched in at the
    /// reserved offset by the worker).
    pub blob: Vec<u8>,
    /// Byte offset in `blob` where the worker writes its nonce.
    pub reserved_offset: usize,
    /// Difficulty target — passed through unmodified to the hasher's
    /// `meets_target` check.
    pub target: Hash,
    /// RandomX seed for the epoch this job belongs to. The worker
    /// reuses the same VM as long as the seed matches; on seed change,
    /// the VM reinit cost (~2 s on cold cache, ~0.5 s with parent
    /// crate's cache) is unavoidable.
    pub seed_hash: [u8; 32],
    /// Block height the pool thinks the job is for. Informational —
    /// the hasher doesn't need it (compute_pow_hash takes height to
    /// pick the seed, but we already have the seed above).
    pub height: u64,
    /// True if the pool says workers should drop in-flight work and
    /// pivot to this job. False = additive (use when current job is
    /// done). Most pools always send true.
    pub clean: bool,
}

/// Result of submitting a share back to the pool.
#[derive(Clone, Debug)]
pub enum ShareResult {
    Accepted,
    Rejected { reason: String },
}

/// Pool subscription identity returned from `mining.subscribe`.
#[derive(Clone, Debug)]
pub struct SubscribeInfo {
    pub session_id: String,
    pub extranonce1: Vec<u8>,
    pub extranonce2_size: usize,
}

#[derive(Serialize)]
struct StratumRequest<'a> {
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize, Debug)]
struct StratumResponse {
    id: Option<u64>,
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error: Value,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Value,
}

type PendingMap = Arc<Mutex<std::collections::HashMap<u64, oneshot::Sender<StratumResponse>>>>;

/// A Stratum-connected pool client. Spawns a background reader task
/// that demuxes responses by `id` and pushes pool-initiated job
/// notifications onto the `Job` channel.
pub struct StratumClient {
    writer: Arc<Mutex<OwnedWriteHalf>>,
    next_id: AtomicU64,
    pending: PendingMap,
    /// Workers receive jobs through this channel — cloned via
    /// [`StratumClient::take_job_receiver`] once at startup.
    job_rx: Option<mpsc::UnboundedReceiver<Job>>,
}

impl StratumClient {
    /// Connect to a `host:port` Stratum endpoint. The reader task is
    /// spawned immediately so subsequent calls can await responses.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to stratum endpoint {addr}"))?;
        // Disable Nagle — Stratum is request/response with tiny payloads;
        // bunching them up just adds latency on submit.
        stream.set_nodelay(true).ok();

        info!(target = %addr, "stratum: connected");
        let (reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let pending: PendingMap = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let (job_tx, job_rx) = mpsc::unbounded_channel();

        // Reader task — owns the read half for life of the connection
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            run_reader(reader, reader_pending, job_tx).await;
        });

        Ok(Self {
            writer,
            next_id: AtomicU64::new(1),
            pending,
            job_rx: Some(job_rx),
        })
    }

    /// Pull the job channel receiver. Panics if called twice — the
    /// channel has a single consumer (the worker pool dispatcher).
    pub fn take_job_receiver(&mut self) -> mpsc::UnboundedReceiver<Job> {
        self.job_rx
            .take()
            .expect("take_job_receiver called twice — only one consumer allowed")
    }

    /// Send `mining.subscribe` and parse the standard response shape:
    ///   `[[["mining.notify", id], ["mining.set_difficulty", id]],
    ///     extranonce1, extranonce2_size]`
    ///
    /// Some pools echo a flat session_id at index 0 instead of the
    /// notification-method tuple; we accept either.
    pub async fn subscribe(&mut self, user_agent: &str) -> Result<SubscribeInfo> {
        let resp = self
            .request("mining.subscribe", json!([user_agent]))
            .await?;
        let result = resp
            .result
            .as_array()
            .ok_or_else(|| anyhow!("subscribe response missing result array"))?;

        // index 1 = extranonce1 hex, index 2 = extranonce2_size int
        let extranonce1 = result
            .get(1)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("subscribe response missing extranonce1"))?;
        let extranonce2_size = result
            .get(2)
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("subscribe response missing extranonce2_size"))?
            as usize;

        // index 0 may be a session_id string OR a [[method,id]...] array
        let session_id = match result.first() {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(arr)) => arr
                .first()
                .and_then(|v| v.as_array())
                .and_then(|a| a.get(1))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            _ => String::new(),
        };

        let extranonce1_bytes = hex::decode(extranonce1)
            .with_context(|| format!("extranonce1 not valid hex: {extranonce1:?}"))?;
        Ok(SubscribeInfo {
            session_id,
            extranonce1: extranonce1_bytes,
            extranonce2_size,
        })
    }

    /// Send `mining.authorize`. Returns true on accept, false on reject
    /// (and a reject is usually a wrong worker password).
    pub async fn authorize(&mut self, worker: &str, password: &str) -> Result<bool> {
        let resp = self
            .request("mining.authorize", json!([worker, password]))
            .await?;
        Ok(resp.result.as_bool().unwrap_or(false))
    }

    /// Submit a found share. The worker passes `nonce` as a u32 because
    /// xmrig-shape Stratum uses 32-bit nonces; see the design doc for
    /// the testnet rationale.
    pub async fn submit_share(
        &mut self,
        worker: &str,
        job_id: &str,
        extranonce2: &[u8],
        ntime_unix: u32,
        nonce: u32,
    ) -> Result<ShareResult> {
        let resp = self
            .request(
                "mining.submit",
                json!([
                    worker,
                    job_id,
                    hex::encode(extranonce2),
                    format!("{:08x}", ntime_unix),
                    format!("{:08x}", nonce),
                ]),
            )
            .await?;
        if resp.result.as_bool().unwrap_or(false) {
            Ok(ShareResult::Accepted)
        } else {
            let reason = resp
                .error
                .as_array()
                .and_then(|a| a.get(1))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            warn!(%job_id, %reason, "stratum: share rejected");
            Ok(ShareResult::Rejected { reason })
        }
    }

    /// Send a request and wait for the matching response.
    async fn request(&self, method: &str, params: Value) -> Result<StratumResponse> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        let req = StratumRequest { id, method, params };
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        debug!(direction = "send", %method, "stratum");
        self.writer.lock().await.write_all(line.as_bytes()).await?;

        // 30 s response timeout — generous for pool round-trip; if the
        // pool stalls longer than that, treat the connection as dead.
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_canceled)) => Err(anyhow!("stratum reader closed before response")),
            Err(_) => Err(anyhow!("stratum {method} request timed out after 30s")),
        }
    }
}

/// Reader task — runs for the life of the connection. Demuxes inbound
/// lines into either:
///  - response to a pending request (matched by `id`)
///  - pool-initiated notification (`mining.notify` → push onto
///    `job_tx`; `mining.set_difficulty` → log and drop for now —
///    workers re-read target from the next job)
///
/// On EOF or read error the task exits, which causes pending oneshots
/// to error and the job channel to close. The owning client treats
/// either as "connection lost" and (in Phase 5) triggers reconnect.
async fn run_reader(
    reader: OwnedReadHalf,
    pending: PendingMap,
    job_tx: mpsc::UnboundedSender<Job>,
) {
    let mut lines = BufReader::new(reader).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => {
                info!("stratum: connection closed by pool (EOF)");
                break;
            }
            Err(e) => {
                warn!(error = %e, "stratum: read error, closing");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp: StratumResponse = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, raw = %trimmed, "stratum: failed to parse line");
                continue;
            }
        };

        // Response with id → resolve a pending request.
        if let Some(id) = resp.id {
            if let Some(tx) = pending.lock().await.remove(&id) {
                let _ = tx.send(resp);
                continue;
            }
        }

        // Notification (no id): dispatch by method.
        if let Some(method) = &resp.method {
            match method.as_str() {
                "mining.notify" => match parse_notify(&resp.params) {
                    Ok(job) => {
                        if job_tx.send(job).is_err() {
                            // No more consumers — bail out; nothing left to do.
                            info!("stratum: job channel closed, reader exiting");
                            return;
                        }
                    }
                    Err(e) => warn!(error = %e, "stratum: malformed mining.notify"),
                },
                "mining.set_difficulty" => {
                    debug!(?resp.params, "stratum: set_difficulty (workers re-read target on next job)");
                }
                other => debug!(method = %other, "stratum: unhandled notification"),
            }
        }
    }
}

/// Parse a `mining.notify` params array into a [`Job`].
///
/// CoinCync-flavoured Stratum: we expect the pool to send
///   `[job_id, blob_hex, target_hex, seed_hex, height_u64,
///     reserved_offset_u32, clean_bool]`
///
/// This is a small CoinCync-specific shape rather than the canonical
/// Bitcoin Stratum tuple because for a privacy chain the pool must
/// assemble the full block server-side; the miner only sees the
/// already-built blob. Mirrors what monero-pool does for Monero.
fn parse_notify(params: &Value) -> Result<Job> {
    let arr = params
        .as_array()
        .ok_or_else(|| anyhow!("mining.notify params is not an array"))?;
    let job_id = arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing job_id"))?
        .to_string();
    let blob_hex = arr
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing blob"))?;
    let target_hex = arr
        .get(2)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing target"))?;
    let seed_hex = arr
        .get(3)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing seed_hash"))?;
    let height = arr
        .get(4)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing height"))?;
    let reserved_offset = arr
        .get(5)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing reserved_offset"))? as usize;
    let clean = arr.get(6).and_then(Value::as_bool).unwrap_or(true);

    let blob = hex::decode(blob_hex).context("blob not valid hex")?;
    let target_bytes = hex_decode_32(target_hex).context("target not 32-byte hex")?;
    let seed_bytes = hex_decode_32(seed_hex).context("seed_hash not 32-byte hex")?;

    if reserved_offset
        .checked_add(4)
        .map(|end| end > blob.len())
        .unwrap_or(true)
    {
        return Err(anyhow!(
            "reserved_offset {reserved_offset} doesn't leave 4 bytes inside a {len}-byte blob",
            len = blob.len()
        ));
    }

    Ok(Job {
        job_id,
        blob,
        reserved_offset,
        target: Hash::from_bytes(target_bytes),
        seed_hash: seed_bytes,
        height,
        clean,
    })
}

fn hex_decode_32(s: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s)?;
    let arr: [u8; 32] = v
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_notify_happy_path() {
        // 76-byte blob (typical CryptoNote size); reserved_offset 39
        let blob_hex = "00".repeat(76);
        let target_hex = "ff".repeat(32);
        let seed_hex = "11".repeat(32);
        let params = json!(["abc123", blob_hex, target_hex, seed_hex, 1399u64, 39u64, true,]);
        let job = parse_notify(&params).expect("parse");
        assert_eq!(job.job_id, "abc123");
        assert_eq!(job.blob.len(), 76);
        assert_eq!(job.reserved_offset, 39);
        assert_eq!(job.height, 1399);
        assert!(job.clean);
        assert_eq!(job.target.as_bytes(), &[0xff; 32]);
        assert_eq!(job.seed_hash, [0x11; 32]);
    }

    #[test]
    fn parse_notify_rejects_offset_past_end() {
        let blob_hex = "00".repeat(40);
        let target_hex = "00".repeat(32);
        let seed_hex = "00".repeat(32);
        let params = json!([
            "j", blob_hex, target_hex, seed_hex, 1u64,
            38u64, // offset 38 + 4 = 42 > 40 → reject
            true,
        ]);
        let err = parse_notify(&params).unwrap_err().to_string();
        assert!(
            err.contains("reserved_offset"),
            "expected offset error, got: {err}"
        );
    }
}
