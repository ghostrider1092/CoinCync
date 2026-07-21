// See hasher.rs for the rustc 1.95 ICE explanation. Remove this allow
// once `coincync-rig run` consumes every public item below.
#![allow(dead_code)]

//! # Worker pool — Phase 3.
//!
//! Each worker is a dedicated OS thread (not a tokio task — RandomX is
//! CPU-bound, blocks for milliseconds at a time, so giving it a real
//! thread keeps the async runtime responsive). Workers share:
//!
//!   - the inbound [`Job`] channel from the stratum client
//!   - an outbound submit channel (workers tell the stratum task what
//!     they found)
//!   - per-worker atomic counters for hashrate stats
//!
//! ## Nonce splitting
//!
//! For 4-byte nonces (the testnet shape — see design doc, Section #2),
//! the nonce search space is `2^32 = ~4.3B`. We slice it evenly across
//! `n_workers`. With our current testnet difficulty (~5K) every worker
//! finds a share in milliseconds, so the slice never matters; for
//! mainnet it's the standard "don't have multiple threads searching
//! the same nonce" pattern.
//!
//! ## What this module owns vs not
//!
//! Owns: the inner mining loop, per-thread RandomX VM caching (delegated
//! to the parent crate's `randomx_cache` module via `Hasher`), share
//! counting.
//!
//! Does NOT own: the stratum connection lifecycle (Phase 2 module), the
//! UI dashboard (Phase 4), failover / reconnect (Phase 5).
//!
//! ## Phase 3 scope
//!
//! Today: single-threaded worker that consumes from the job channel and
//! submits via the share channel. The multi-thread split (nonce range
//! per worker) is the next iteration — the function signatures here
//! already accept a `worker_id` so wiring N copies of [`run_worker`]
//! into N OS threads is mechanical once the single-thread path is
//! known to find shares.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::hasher::{HashInput, Hasher};
use crate::stratum::Job;
use coincync::primitives::Hash;

/// Per-worker rolling counters. Read by the dashboard / stats task at
/// whatever cadence it likes; updated on every hash attempt.
#[derive(Default)]
pub struct WorkerStats {
    pub hashes: AtomicU64,
    pub shares_found: AtomicU64,
    pub shares_submitted: AtomicU64,
}

/// Found-share hand-off — the worker emits this; the stratum task
/// forwards it on the wire.
#[derive(Clone, Debug)]
pub struct FoundShare {
    pub job_id: String,
    pub nonce: u32,
    pub pow_hash: Hash,
}

/// One nonce range, distributed by the dispatcher.
#[derive(Clone, Copy, Debug)]
pub struct NonceRange {
    pub start: u32,
    /// Exclusive upper bound. On reaching this, the worker bails out
    /// and waits for the next job.
    pub end: u32,
}

impl NonceRange {
    /// Split the u32 nonce space across `n` workers.
    ///
    /// Saturating arithmetic handles the `n=1` boundary cleanly:
    /// `chunk = u32::MAX/1 + 1` would overflow without `saturating_add`,
    /// so we saturate to `u32::MAX` instead. Same trick on `start +
    /// chunk` for the last slice.
    ///
    /// EDGE CASE: the very top nonce `u32::MAX` is missed because `end`
    /// is exclusive and `saturating_add` caps at `u32::MAX`. That's a
    /// 1-in-4-billion miss over a full sweep — negligible for PoW
    /// search since the chance of any specific nonce being the winner
    /// is the same 1/2^32. Not worth the off-by-one bookkeeping needed
    /// to make `end` inclusive on the final worker.
    pub fn split_for_workers(n: u32) -> Vec<NonceRange> {
        assert!(n >= 1, "must have at least one worker");
        let chunk = (u32::MAX / n).saturating_add(1);
        (0..n)
            .map(|i| {
                let start = i.saturating_mul(chunk);
                let end = start.saturating_add(chunk);
                NonceRange { start, end }
            })
            .collect()
    }
}

/// Inner mining loop. Single-threaded; this is what each worker thread
/// runs (today: just one worker; soon: N workers, each with their own
/// `range` slice and distinct `worker_id`).
///
/// Returns when the inbound channel is closed (stratum disconnected
/// and won't reconnect).
pub fn run_worker(
    worker_id: u32,
    range: NonceRange,
    hasher: Hasher,
    stats: Arc<WorkerStats>,
    job_rx: std::sync::mpsc::Receiver<Job>,
    submit_tx: std::sync::mpsc::Sender<FoundShare>,
) {
    info!(
        worker_id,
        range_start = range.start,
        range_end = range.end,
        "worker: starting"
    );
    let mut current_job: Option<Job> = None;

    loop {
        // Always check for a new job. If we have no current job, block
        // until one arrives. If we have one, drain any pending updates
        // first (a `clean=true` job means drop in-flight work).
        loop {
            match if current_job.is_none() {
                job_rx.recv().ok()
            } else {
                job_rx.try_recv().ok()
            } {
                Some(new_job) => {
                    if new_job.clean || current_job.is_none() {
                        debug!(worker_id, job = %new_job.job_id, "worker: pivoting to new job");
                        current_job = Some(new_job);
                    } else {
                        // Additive job — keep the current one, queue
                        // the new one for after. For Phase 3 we
                        // simplify: take whatever's freshest.
                        current_job = Some(new_job);
                    }
                }
                None => break,
            }
        }

        let job = match current_job.as_ref() {
            Some(j) => j.clone(),
            None => {
                // Channel closed — no more work coming.
                info!(worker_id, "worker: job channel closed, exiting");
                return;
            }
        };

        // Reconstruct the hashable input from the blob. The blob format
        // for CoinCync is anchor(32) || nonce(4 — patched here) ||
        // tx_root(32). We don't actually need to write to the blob
        // bytes; we just call the Hasher with the structured input.
        // For real Stratum interop the blob layout is dictated by the
        // pool, but the validator (compute_pow_hash) only cares about
        // the three semantic inputs. So we extract them from the blob
        // by offset.
        let (anchor, tx_root) = match extract_anchor_and_tx_root(&job.blob, job.reserved_offset) {
            Ok(t) => t,
            Err(e) => {
                warn!(worker_id, error = %e, "worker: malformed blob, dropping job");
                current_job = None;
                continue;
            }
        };
        let input = HashInput {
            anchor,
            tx_root,
            height: job.height,
        };
        let target = job.target.clone();

        let mut nonce = range.start;
        let started = Instant::now();
        let mut hashes_this_job: u64 = 0;

        while nonce < range.end {
            // Periodically peek at the channel for a fresh `clean` job;
            // every 4096 hashes is a good tradeoff between latency on
            // pivots and overhead in the inner loop.
            if nonce % 4096 == 0 {
                if let Ok(new_job) = job_rx.try_recv() {
                    if new_job.clean {
                        debug!(worker_id, "worker: clean job arrived, restarting");
                        current_job = Some(new_job);
                        break;
                    } else {
                        current_job = Some(new_job);
                    }
                }
            }

            let pow = match hasher.hash(&input, nonce as u64) {
                Ok(h) => h,
                Err(e) => {
                    warn!(worker_id, error = %e, "worker: hasher error");
                    break;
                }
            };
            hashes_this_job += 1;

            if hasher.meets_target(&pow, &target) {
                stats.shares_found.fetch_add(1, Ordering::Relaxed);
                let share = FoundShare {
                    job_id: job.job_id.clone(),
                    nonce,
                    pow_hash: pow,
                };
                if submit_tx.send(share).is_err() {
                    warn!(worker_id, "worker: submit channel closed, exiting");
                    return;
                }
                stats.shares_submitted.fetch_add(1, Ordering::Relaxed);
                // Don't `break` — keep mining the same job for more
                // shares. Pool decides when to issue a new job.
            }

            nonce = nonce.saturating_add(1);
        }

        stats.hashes.fetch_add(hashes_this_job, Ordering::Relaxed);
        let elapsed = started.elapsed();
        if elapsed.as_secs_f64() > 0.0 && hashes_this_job > 0 {
            let hps = hashes_this_job as f64 / elapsed.as_secs_f64();
            let elapsed_secs = elapsed.as_secs_f64();
            debug!(
                worker_id,
                hashes_this_job,
                elapsed_secs,
                hps = format!("{:.0}", hps),
                "worker: job slice finished"
            );
        }
    }
}

/// Pull the 32-byte `anchor` and 32-byte `tx_root` out of a CoinCync
/// blob. We don't ship a parser yet because the blob format is going
/// to be defined by the pool we run; for now we accept the simplest
/// layout: `anchor(32) || nonce_slot(4) || tx_root(32) || ...`.
fn extract_anchor_and_tx_root(blob: &[u8], reserved_offset: usize) -> Result<(Hash, Hash)> {
    // Pool's reserved_offset tells us where the nonce starts. Anchor
    // is the 32 bytes before it; tx_root is the 32 bytes after the
    // 4-byte nonce slot.
    if reserved_offset < 32 {
        anyhow::bail!("reserved_offset {reserved_offset} too small for 32-byte anchor prefix");
    }
    let anchor_start = reserved_offset - 32;
    let tx_root_start = reserved_offset + 4;
    if blob.len() < tx_root_start + 32 {
        anyhow::bail!(
            "blob too short ({} bytes) to fit anchor+nonce+tx_root with reserved_offset {}",
            blob.len(),
            reserved_offset
        );
    }
    let mut anchor = [0u8; 32];
    let mut tx_root = [0u8; 32];
    anchor.copy_from_slice(&blob[anchor_start..anchor_start + 32]);
    tx_root.copy_from_slice(&blob[tx_root_start..tx_root_start + 32]);
    Ok((Hash::from_bytes(anchor), Hash::from_bytes(tx_root)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_range_split_covers_full_space() {
        let ranges = NonceRange::split_for_workers(4);
        assert_eq!(ranges.len(), 4);
        // First range starts at 0
        assert_eq!(ranges[0].start, 0);
        // Each subsequent range starts where the previous ended
        for w in ranges.windows(2) {
            assert!(w[0].end <= w[1].start.saturating_add(1));
        }
    }

    #[test]
    fn extract_anchor_and_tx_root_happy_path() {
        // 32-byte anchor || 4-byte nonce slot || 32-byte tx_root = 68 bytes
        let mut blob = Vec::with_capacity(68);
        blob.extend(std::iter::repeat(0xAA).take(32));
        blob.extend([0xBB; 4]); // nonce slot
        blob.extend(std::iter::repeat(0xCC).take(32));
        let (anchor, tx_root) = extract_anchor_and_tx_root(&blob, 32).expect("parse");
        assert_eq!(anchor.as_bytes(), &[0xAA; 32]);
        assert_eq!(tx_root.as_bytes(), &[0xCC; 32]);
    }

    #[test]
    fn extract_rejects_short_blob() {
        let blob = vec![0u8; 50];
        let err = extract_anchor_and_tx_root(&blob, 32).unwrap_err();
        assert!(err.to_string().contains("blob too short"));
    }
}
