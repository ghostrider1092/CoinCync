//! Light-wallet SPV RPC handlers, extracted from `start_rpc_server` (issue #107):
//! fork-point recovery, compact per-block output digests, and periodic sync
//! checkpoints. Behavior is unchanged from the previous inline closures —
//! journal/size DoS caps, the `block_in_place` around DB scans, 100-block digest
//! cap, and the stride-floor that bounds checkpoint work regardless of the
//! requested stride.
//!
//! ## Audit map
//! - **§1 find_fork_point** — INVARIANT: reject an oversized wallet journal
//!   (> MAX_JOURNAL) before any hex decode or chain lookup; canonical-hash
//!   lookups run under block_in_place. THREAT: journal-amplification DoS.
//! - **§2 get_output_digests / get_sync_checkpoints** — INVARIANT: ranges are
//!   saturating and capped (100 digests; checkpoints floored to ≤512 entries so
//!   an UNAUTHENTICATED `stride=1` can't force O(chain_height) work). THREAT:
//!   attacker damage scaling with chain height via a public REST endpoint.

use jsonrpsee::types::{ErrorObjectOwned, Params};
use serde_json::{json, Value};

use crate::rpc::server::RpcState;

pub(crate) fn find_fork_point(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (journal_hex,): (Vec<(u64, String)>,) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    // DoS guard: reject an oversized journal before any hex decode or
    // chain lookups. A real wallet journal is a few thousand entries at
    // most (see wallet::scanner::JOURNAL_MAX_DEFAULT).
    const MAX_JOURNAL: usize = 4096;
    if journal_hex.len() > MAX_JOURNAL {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!(
                "find_fork_point: journal too large ({} > {})",
                journal_hex.len(),
                MAX_JOURNAL
            ),
            None::<()>,
        ));
    }
    let journal = crate::rpc::lightwallet::parse_journal_hex(&journal_hex).map_err(|e| {
        ErrorObjectOwned::owned(-32602, format!("find_fork_point: {}", e), None::<()>)
    })?;
    // Layer 2: canonical-hash lookups under block_in_place — same
    // rationale as get_block_by_height.
    let fork = tokio::task::block_in_place(|| {
        crate::rpc::lightwallet::fork_point_in_journal(&journal, |h| state.chain.get_block_hash(h))
    });
    Ok(json!({ "fork_point": fork }))
}

pub(crate) fn get_output_digests(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    if end < start {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "end must be >= start".to_string(),
            None::<()>,
        ));
    }
    const MAX_DIGEST_BLOCKS: u64 = 100;
    let chain_height = state.chain.height();
    let end = end
        .min(start.saturating_add(MAX_DIGEST_BLOCKS - 1))
        .min(chain_height);
    // `end` was just clamped to `min(chain_height)`, which can drop it
    // below `start` when `start > chain_height` (the earlier guard saw
    // the pre-clamp `end`). Use saturating math — matching the sibling
    // range handlers — so the capacity calc can't underflow. The
    // `start..=end` loop below is simply empty in that case.
    let mut digests = Vec::with_capacity(
        (end.saturating_sub(start).saturating_add(1) as usize).min(MAX_DIGEST_BLOCKS as usize),
    );
    for h in start..=end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            digests.push(crate::wallet::lightsync::BlockDigest::from_block(&block));
        }
    }
    let count = digests.len();
    Ok(json!({
        "start": start,
        "end": end,
        "count": count,
        "digests": digests,
    }))
}

pub(crate) fn get_sync_checkpoints(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let requested: u64 = params.parse::<(u64,)>().map(|(s,)| s).unwrap_or(10_000);
    let chain_height = state.chain.height();
    // SECURITY (DoS): bound the work regardless of the requested stride.
    // This method is in the REST allowlist (reachable UNAUTHENTICATED via
    // POST /rpc), so a `stride=1` request must not force O(chain_height) DB
    // reads + a chain_height-sized Vec — that scales attacker damage with
    // chain height. Floor the stride so the loop yields at most
    // MAX_CHECKPOINTS entries; the actual stride used is returned to the
    // caller. Also run the synchronous DB scan under block_in_place so it
    // can't monopolize a tokio worker (matches the other DB-scan handlers).
    const MAX_CHECKPOINTS: u64 = 512;
    let min_stride = chain_height.div_ceil(MAX_CHECKPOINTS).max(1);
    let stride = requested.max(min_stride).min(50_000);
    let checkpoints = tokio::task::block_in_place(|| {
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
        checkpoints
    });
    Ok(json!({
        "stride": stride,
        "chain_height": chain_height,
        "count": checkpoints.len(),
        "checkpoints": checkpoints,
        "auth_note": "Cross-check against CONSENSUS_CHECKPOINTS in src/constants.rs. Miner-signed authentication queued for v1.0.1 (CIP-009.D).",
    }))
}
