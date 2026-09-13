//! Write-path + mining-template RPC handlers, extracted from `start_rpc_server`
//! (issue #107). These are the highest-care handlers: they admit blocks/txs and
//! fan out P2P broadcasts. Behavior is unchanged from the previous inline
//! closures — hex length caps, borsh decode, `block_in_place` around the
//! CPU-heavy validation, the mempool-sync sequence after a block, the
//! fire-and-forget `tokio::spawn` broadcasts, and every error code (-32001 block
//! rejected, -32002 tx rejected, -32602 bad params).
//!
//! ## Audit map
//! - **§1 submit_block (local block admission)** — INVARIANT: the hex input is
//!   length-capped before decode; the block is process_block'd under
//!   block_in_place; only Accepted/Fork/Reorg trigger the mempool sync
//!   (remove_confirmed + restore_orphaned on reorg + shadow_evict_invalid) and
//!   the P2P announce; Orphan/Invalid/Err surface -32001 and mutate nothing
//!   extra. THREAT: hex/borsh decode amplification; a locally-mined block
//!   leaving poison txs in the mempool (h=6001 stall).
//! - **§2 send_raw_transaction** — INVARIANT: length-capped, admitted via
//!   mempool.add_with_chain (full crypto verify) under block_in_place, then
//!   Dandelion++ broadcast only on success. THREAT: decode amplification.
//! - **§3 get_block_template** — INVARIANT: the CPU-heavy template build (per-tx
//!   validate) runs under block_in_place so it can't monopolize a tokio worker.

use jsonrpsee::types::{ErrorObjectOwned, Params};
use serde_json::{json, Value};
use tracing::warn;

use crate::rpc::server::RpcState;

pub(crate) fn get_block_template(state: &RpcState) -> std::result::Result<Value, ErrorObjectOwned> {
    // SECURITY (runtime resilience, Layer 2): build_template_json iterates
    // mempool and runs `chain.validate_transaction()` for every candidate
    // (full ring sig + range proof verify). On a busy mempool this is the
    // most CPU-heavy synchronous call in the RPC surface, and it runs
    // many times per minute because the failover miner polls for fresh
    // templates. `block_in_place` lets tokio's multi-thread runtime
    // (Layer 1 forces 4 workers) keep scheduling other tasks during the
    // call instead of monopolizing the worker thread.
    let template = tokio::task::block_in_place(|| {
        crate::mining::template::build_template_json(&state.chain, &state.mempool)
    });
    Ok(template)
}

pub(crate) fn submit_block(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (hex_block,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    // Bound the hex input length BEFORE hex::decode + borsh::from_slice.
    // hex::decode allocates a Vec of half the input length; without this
    // cap a caller could send a hex string many times larger than the
    // consensus block limit and force the node to allocate + parse +
    // borsh-decode data that would fail the block-size check anyway.
    // 2× MAX_BLOCK_SIZE covers hex-encoding overhead; 4× total (2 for
    // hex, 2 for slack) leaves headroom for a max-size valid block plus
    // any near-boundary encoding variance.
    const MAX_HEX_BLOCK: usize = 2 * 2 * crate::constants::MAX_BLOCK_SIZE;
    if hex_block.len() > MAX_HEX_BLOCK {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("hex block too large: {} chars (max {})", hex_block.len(), MAX_HEX_BLOCK),
            None::<()>,
        ));
    }
    let block_bytes = hex::decode(&hex_block)
        .map_err(|e| ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>))?;
    let block: crate::consensus::Block = borsh::from_slice(&block_bytes).map_err(|e| {
        ErrorObjectOwned::owned(-32602, format!("bad block encoding: {}", e), None::<()>)
    })?;
    let hash = block.hash();
    let algo = crate::consensus::PowAlgorithm::from_index(block.header.algorithm);
    let claimed_pow_hex = match crate::consensus::compute_pow_hash(
        algo,
        &block.header.anchor,
        block.header.nonce,
        &block.header.tx_root,
        block.header.height,
    ) {
        Ok(h) => hex::encode(&h.as_bytes()[..8]),
        Err(e) => format!("pow_err:{}", e),
    };
    warn!(
        "submit_block candidate: h={} nonce={} magic={} prev={} anchor={} tx_root={} target={} pow={} algo={}",
        block.header.height,
        block.header.nonce,
        hex::encode(block.header.network_magic),
        hex::encode(&block.header.prev_hash.as_bytes()[..8]),
        hex::encode(&block.header.anchor.as_bytes()[..8]),
        hex::encode(&block.header.tx_root.as_bytes()[..8]),
        hex::encode(&block.header.target.as_bytes()[..8]),
        claimed_pow_hex,
        block.header.algorithm,
    );
    // Clone for broadcast (process_block consumes the original); the
    // clone cost is O(tx count), negligible for testnet.
    let block_for_broadcast = block.clone();
    // Snapshot tx list before process_block consumes the original.
    // Used below to keep the mempool aligned with chain state — drop
    // confirmed txs and shadow-evict any mempool tx whose key image
    // collides with one just spent in this block. Without this sync
    // (the wire-side equivalent runs in bin/node.rs after a
    // BlockReceived event), a locally-mined block leaves stale txs
    // in the mempool that poison every subsequent block template
    // with "duplicate key image". Caused the 2026-05-08 chain stall
    // at h=6001; see docs/launch/MONDAY_PRELAUNCH.md incident playbook.
    let block_txs = block_for_broadcast.transactions.clone();
    // process_block returns Ok(BlockStatus::...) even for Invalid/Orphan
    // outcomes, so we must inspect the status and surface a failure
    // when the block was not actually accepted. Without this, the
    // miner sees a silent success while the chain never advances.
    //
    // SECURITY (runtime resilience, Layer 2): the wire-side BlockReceived
    // handler in bin/node.rs routes its process_block through
    // spawn_blocking. The locally-submitted path here uses
    // `block_in_place` for the same effect from a sync RPC handler —
    // tokio's multi-thread runtime can keep scheduling other tasks
    // during full block validation (PoW recheck + per-tx crypto verify).
    let process_result = tokio::task::block_in_place(|| state.chain.process_block(block));
    match process_result {
        Ok(status @ (crate::chain::BlockStatus::Accepted
                    | crate::chain::BlockStatus::AcceptedFork
                    | crate::chain::BlockStatus::AcceptedReorg { .. })) => {
            // Mempool sync — same calls as the wire-side handler in
            // bin/node.rs after BlockReceived. remove_confirmed drops
            // mined txs AND shadow-evicts any mempool tx that shares
            // a key image with a confirmed tx (the poison-tx scenario
            // that stalled the chain at h=6001 on 2026-05-08).
            state.mempool.remove_confirmed(&block_txs);
            // On reorg, re-admit txs that were mined in disconnected
            // blocks but are still spendable on the new chain.
            if let crate::chain::BlockStatus::AcceptedReorg { orphaned_txs } = status {
                state.mempool.restore_orphaned(orphaned_txs, &state.chain);
            }
            state.mempool.set_height(state.chain.height());
            // Shadow-evict mempool txs that no longer validate
            // against the new chain state. Catches the cases
            // remove_confirmed can't (hard-fork rule transition,
            // reorg-induced input-coinbase maturity changes).
            // Belt-and-suspenders for the miner-side filter in
            // mining/template.rs:70-95.
            state.mempool.shadow_evict_invalid(state.chain.as_ref());

            // Fire-and-forget P2P announcement so the block reaches
            // other nodes; without this, locally-mined blocks stay
            // local and the chain forks between the miner and its
            // peers. We don't block the RPC response on propagation.
            //
            // Also refresh the handshake-side chain_height/chain_tip
            // so subsequent peer Version messages advertise the new
            // tip. The BlockReceived event handler in bin/node.rs
            // does the same thing for blocks arriving from peers;
            // locally-mined blocks come through this RPC path
            // instead and would otherwise leave handshake state stale.
            if let Some(p2p) = state.p2p.as_ref() {
                let p2p = p2p.clone();
                // Capture the publication sequence BEFORE the detached
                // spawn so an out-of-order completion can't regress the
                // P2P shadow to a stale tip (issue #249).
                let update = p2p.next_chain_update();
                tokio::spawn(async move {
                    p2p.set_chain_state(update).await;
                    if let Err(e) = p2p.broadcast_block(&block_for_broadcast).await {
                        warn!("Block broadcast failed: {}", e);
                    }
                });
            }
            Ok(json!({
                "accepted": true,
                "hash": hex::encode(hash.as_bytes()),
            }))
        }
        Ok(crate::chain::BlockStatus::AlreadyKnown) => {
            // Even when the block is already known, advance the mempool's
            // tracked chain height so activation-gated validation stays in
            // sync. The wire-side handler in bin/node.rs does the same
            // thing for AlreadyKnown — keeps the two paths symmetric.
            state.mempool.set_height(state.chain.height());
            Ok(json!({
                "accepted": true,
                "status": "already_known",
                "hash": hex::encode(hash.as_bytes()),
            }))
        }
        Ok(crate::chain::BlockStatus::Orphan) => {
            warn!(
                "submit_block rejected orphan: h={} nonce={} hash={}",
                block_for_broadcast.header.height,
                block_for_broadcast.header.nonce,
                hex::encode(hash.as_bytes()),
            );
            Err(ErrorObjectOwned::owned(
                -32001,
                format!("block rejected: orphan (parent not in chain), hash={}", hex::encode(hash.as_bytes())),
                None::<()>,
            ))
        }
        Ok(crate::chain::BlockStatus::Invalid(reason)) => {
            warn!(
                "submit_block rejected invalid: h={} nonce={} reason={}",
                block_for_broadcast.header.height,
                block_for_broadcast.header.nonce,
                reason,
            );
            Err(ErrorObjectOwned::owned(
                -32001,
                format!("block rejected: {}", reason),
                None::<()>,
            ))
        }
        Err(e) => {
            warn!(
                "submit_block rejected error: h={} nonce={} err={}",
                block_for_broadcast.header.height,
                block_for_broadcast.header.nonce,
                e,
            );
            Err(ErrorObjectOwned::owned(
                -32001, format!("block rejected: {}", e), None::<()>,
            ))
        }
    }
}

pub(crate) fn send_raw_transaction(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (hex_tx,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    // Bound hex input length. Mirrors submit_block above: 2× MAX_TX_SIZE × 2
    // (2 for hex, 2 for slack); anything larger decodes to bytes larger than any
    // valid tx and is rejected downstream, but the pre-check saves the allocation
    // and the borsh parse.
    const MAX_HEX_TX: usize = 2 * 2 * crate::constants::MAX_TX_SIZE;
    if hex_tx.len() > MAX_HEX_TX {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("hex tx too large: {} chars (max {})", hex_tx.len(), MAX_HEX_TX),
            None::<()>,
        ));
    }
    let tx_bytes = hex::decode(&hex_tx)
        .map_err(|e| ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>))?;
    let tx: crate::transaction::Transaction = borsh::from_slice(&tx_bytes).map_err(|e| {
        ErrorObjectOwned::owned(-32602, format!("bad tx encoding: {}", e), None::<()>)
    })?;
    let hash = tx.hash();
    let tx_for_broadcast = tx.clone();
    // SECURITY (runtime resilience, Layer 2): mempool admit runs full
    // crypto verify (ring sig + range proof) and walks the chain DB to
    // check key-image conflicts. `block_in_place` lets tokio's multi-
    // thread runtime keep scheduling other tasks during the validation.
    let admit_result =
        tokio::task::block_in_place(|| state.mempool.add_with_chain(tx, &state.chain));
    match admit_result {
        Ok(_) => {
            // Broadcast via Dandelion++ so other nodes see the tx
            if let Some(p2p) = state.p2p.as_ref() {
                let p2p = p2p.clone();
                tokio::spawn(async move {
                    if let Err(e) = p2p.broadcast_transaction(tx_for_broadcast).await {
                        warn!("Tx broadcast failed: {}", e);
                    }
                });
            }
            Ok(json!({
                "accepted": true,
                "hash": hex::encode(hash.as_bytes()),
            }))
        }
        Err(e) => Err(ErrorObjectOwned::owned(
            -32002,
            format!("tx rejected: {}", e),
            None::<()>,
        )),
    }
}
