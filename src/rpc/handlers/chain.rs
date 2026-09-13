//! Chain-query RPC handlers — block and transaction retrieval. Registered as
//! async `register_method`s; DB reads that could stall a worker are wrapped in
//! `tokio::task::block_in_place` exactly as before. Extracted from
//! `start_rpc_server` (issue #107); bodies, response shapes, and error codes are
//! unchanged from the previous inline closures.
//!
//! ## Audit map
//! - **§1 `serialize_block`** — INVARIANT: the block payload has a single source
//!   of truth, so every block-returning RPC emits an identical shape (height,
//!   hash, header fields, tx summaries, reward, raw bytes). THREAT: payload-shape
//!   drift across endpoints (the class of bug that bit `signing_hash`).
//!   TESTS: `rpc_get_block_by_height_returns_result`, `rpc_get_block_range_inverted`.
//! - **§2 block/tx queries** — INVARIANT: height/hash/txid lookups return the
//!   canonical block/tx or a `-5` not-found; ranges saturate at `u64::MAX` and
//!   cap response size (100 blocks); hex inputs are length-capped before decode.
//!   THREAT: not-found masked as 500; range/hex amplification DoS.
//!   TESTS: `get_block_range_span_capped_at_100`, `get_block_range_u64_max_bounds_saturate`,
//!   `rpc_get_block_range_inverted`, `get_transaction_hex_hash_too_large_rejected`.

use jsonrpsee::types::{ErrorObjectOwned, Params};
use serde_json::{json, Value};

use crate::rpc::server::RpcState;

/// Single source of truth for the JSON shape of a block across every
/// block-returning RPC (get_block_by_height / get_block / get_block_range).
pub(crate) fn serialize_block(block: &crate::consensus::Block, height: u64) -> Value {
    let block_bytes = borsh::to_vec(block).unwrap_or_default();
    let size = block_bytes.len();

    let txs_json: Vec<Value> = block
        .transactions
        .iter()
        .map(|tx| {
            let kind = match tx.tx_type {
                crate::transaction::TxType::Coinbase => "coinbase",
                crate::transaction::TxType::Transfer => "transfer",
                crate::transaction::TxType::Churn => "churn",
            };
            json!({
                "hash":     hex::encode(tx.hash().as_bytes()),
                "kind":     kind,
                "inputs":   tx.input_count(),
                "outputs":  tx.output_count(),
                "fee":      tx.fee.as_atomic(),
            })
        })
        .collect();

    json!({
        "height":         height,
        "hash":           hex::encode(block.hash().as_bytes()),
        "prev_hash":      hex::encode(block.header.prev_hash.as_bytes()),
        "tx_root":        hex::encode(block.header.tx_root.as_bytes()),
        "timestamp":      block.header.timestamp,
        "nonce":          block.header.nonce,
        // CoinCync 1.0 is RandomX-only — see `consensus::pow::PowAlgorithm`.
        "algorithm":      block.header.algorithm,
        "algorithm_name": "RandomX",
        "difficulty":     block.header.target.to_difficulty().to_string(),
        "target":         hex::encode(block.header.target.as_bytes()),
        "tx_count":       block.transactions.len(),
        "size":           size,
        "reward":         crate::emission::calculate_block_reward(height).as_atomic(),
        "transactions":   txs_json,
        "bytes":          hex::encode(&block_bytes),
    })
}

pub(crate) fn get_block_by_height(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (h,): (u64,) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    // Layer 2: DB lookup + serialize under block_in_place so a slow
    // RocksDB read doesn't freeze the worker mid-handler.
    let block_opt = tokio::task::block_in_place(|| state.chain.get_block_by_height(h));
    match block_opt {
        Some(block) => Ok(serialize_block(&block, h)),
        None => Err(ErrorObjectOwned::owned(
            // -5 = not-found; the REST proxy maps it to HTTP 404 (not 500).
            -5,
            format!("block at height {} not found", h),
            None::<()>,
        )),
    }
}

pub(crate) fn get_block(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (hash_hex,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    let mut bytes = [0u8; 32];
    if hex::decode_to_slice(hash_hex.trim_start_matches("0x"), &mut bytes).is_err() {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("get_block: expected 64-char hex hash, got {:?}", hash_hex),
            None::<()>,
        ));
    }
    let hash = crate::primitives::Hash::from_bytes(bytes);
    // Layer 2: DB lookup under block_in_place — same rationale as
    // get_block_by_height above.
    let block_opt = tokio::task::block_in_place(|| state.chain.get_block(&hash));
    match block_opt {
        Some(block) => {
            let height = block.header.height;
            Ok(serialize_block(&block, height))
        }
        None => Err(ErrorObjectOwned::owned(
            // -5 = not-found; the REST proxy maps it to HTTP 404 (not 500).
            -5,
            format!("block with hash {} not found", hex::encode(bytes)),
            None::<()>,
        )),
    }
}

pub(crate) fn get_block_range(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    const MAX_RANGE: u64 = 100;
    if end < start {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "end must be >= start".to_string(),
            None::<()>,
        ));
    }
    // Saturating arithmetic on caller-controlled u64 height bounds.
    // Pre-fix `end - start + 1` overflowed when start=0/end=u64::MAX,
    // and `start + capped` overflowed near MAX. In debug builds the
    // bare addition panics; in release it wraps to give an empty
    // range — both wrong. With saturating math we degrade cleanly
    // to a small or empty range at the u64::MAX boundary, which is
    // the right semantics (no blocks exist that high anyway).
    let span = end.saturating_sub(start).saturating_add(1);
    let capped = span.min(MAX_RANGE);
    let mut blocks = Vec::with_capacity(capped as usize);
    let loop_end = start.saturating_add(capped);
    for h in start..loop_end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            blocks.push(serialize_block(&block, h));
        }
    }
    let response_end = start.saturating_add(capped).saturating_sub(1);
    Ok(json!({
        "start": start,
        "end": response_end,
        "count": blocks.len(),
        "blocks": blocks,
    }))
}

pub(crate) fn get_blocks_batch(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (from_height, count): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(
            -32602,
            format!("params: [from_height, count]: {}", e),
            None::<()>,
        )
    })?;
    let count = count.min(100); // Cap at 100 blocks per request
    let mut blocks = Vec::new();
    // Saturating arithmetic so from_height near u64::MAX doesn't
    // overflow. In debug builds the bare addition panics; in
    // release it wraps to an empty range. With saturating_add the
    // loop is simply empty at the saturation point, which is the
    // correct semantics (no blocks exist at u64::MAX anyway).
    let end = from_height.saturating_add(count);
    for h in from_height..end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            let block_hex = hex::encode(borsh::to_vec(&block).unwrap_or_default());
            blocks.push(json!({
                "height": h,
                "hash": block.hash().to_hex(),
                "hex": block_hex,
            }));
        } else {
            break; // No more blocks at this height
        }
    }
    Ok(json!({
        "blocks": blocks,
        "count": blocks.len(),
        "from": from_height,
    }))
}

pub(crate) fn get_transaction(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (tx_hash_hex,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
    })?;
    // AUDIT (2026-07-02): pre-decode length cap. Same class of bug as
    // submit_block / send_raw_transaction / is_nullifier_spent were
    // hardened against — hex::decode allocates a Vec of half the input
    // length BEFORE the downstream 32-byte length check can fire. Without
    // the cap, a caller sending a 1 GB hex string would force the node to
    // allocate ~500 MB just to reject it. A tx hash is 32 bytes = 64 hex
    // chars, plus an optional `0x` prefix; cap the input at 66 chars.
    let trimmed = tx_hash_hex.trim_start_matches("0x");
    if trimmed.len() > 64 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("tx hash hex too large: {} chars (max 64)", trimmed.len()),
            None::<()>,
        ));
    }
    let tx_hash_bytes = hex::decode(trimmed)
        .map_err(|e| ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>))?;
    if tx_hash_bytes.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "tx hash must be 32 bytes (64 hex chars)".to_string(),
            None::<()>,
        ));
    }
    // Layer 2: tx-location index lookup is the first chain DB read;
    // the subsequent block fetch is the second. Wrap each in
    // block_in_place so the worker thread is reusable across both
    // calls while preserving the original error-message distinction
    // between "tx not found" and "block missing for a known tx".
    let location_opt = tokio::task::block_in_place(|| state.chain.get_tx_location(&tx_hash_bytes));
    match location_opt {
        Some((block_height, tx_idx)) => {
            let block_opt =
                tokio::task::block_in_place(|| state.chain.get_block_by_height(block_height));
            match block_opt {
                Some(block) => {
                    let tx = block.transactions.get(tx_idx as usize);
                    match tx {
                        Some(tx) => {
                            let tx_bytes = borsh::to_vec(tx).unwrap_or_default();
                            let ring_size =
                                tx.inputs.first().map(|i| i.ring_members.len()).unwrap_or(0);
                            let inputs_json: Vec<Value> = tx
                                .inputs
                                .iter()
                                .map(|inp| {
                                    json!({
                                        "key_image": hex::encode(inp.key_image.as_bytes()),
                                        "ring_size": inp.ring_members.len(),
                                    })
                                })
                                .collect();
                            let outputs_json: Vec<Value> = tx
                                .outputs
                                .iter()
                                .map(|out| {
                                    json!({
                                        "stealth_address": hex::encode(out.stealth_address.as_bytes()),
                                        "tx_public_key": hex::encode(out.tx_public_key.as_bytes()),
                                        "commitment": hex::encode(out.commitment),
                                        "view_tag": out.view_tag,
                                        "lock_height": out.lock_height,
                                        "has_memo": !out.encrypted_memo.is_empty(),
                                        // Encrypted memo bytes (ChaCha20-Poly1305 ciphertext).
                                        // Public on chain anyway — exposing here only saves a
                                        // block-scan trip for clients that want to decrypt with
                                        // the recipient's view key. Empty when there's no memo.
                                        "encrypted_memo": hex::encode(&out.encrypted_memo),
                                    })
                                })
                                .collect();
                            let has_range_proof = !tx.range_proof.is_empty();
                            let has_recovery = !tx.extra.is_empty() && tx.extra[0] == 0xDE;
                            Ok(json!({
                                "hash": hex::encode(tx.hash().as_bytes()),
                                "block_height": block_height,
                                "block_hash": hex::encode(block.hash().as_bytes()),
                                "index_in_block": tx_idx,
                                "version": tx.version,
                                "type": format!("{:?}", tx.tx_type),
                                "input_count": tx.inputs.len(),
                                "output_count": tx.outputs.len(),
                                "fee": tx.fee.as_atomic(),
                                "extra_size": tx.extra.len(),
                                "size": tx_bytes.len(),
                                "ring_size": ring_size,
                                "has_range_proof": has_range_proof,
                                "range_proof_size": tx.range_proof.len(),
                                "has_recovery": has_recovery,
                                "signing_hash": hex::encode(tx.signing_hash().as_bytes()),
                                "inputs": inputs_json,
                                "outputs": outputs_json,
                                "privacy": {
                                    "sender_hidden": ring_size >= 2,
                                    "receiver_hidden": true,
                                    "amount_hidden": has_range_proof,
                                    "clsag_ring_sig": ring_size >= 2,
                                    "bulletproofs_plus": has_range_proof,
                                    "stealth_addresses": true,
                                    "dandelion_pp": true,
                                    "encrypted_memo": tx.outputs.iter().any(|o| !o.encrypted_memo.is_empty()),
                                },
                            }))
                        }
                        None => Err(ErrorObjectOwned::owned(
                            -32000,
                            "tx index points to invalid position".to_string(),
                            None::<()>,
                        )),
                    }
                }
                None => Err(ErrorObjectOwned::owned(
                    -32000,
                    format!("block at height {} not found", block_height),
                    None::<()>,
                )),
            }
        }
        None => Err(ErrorObjectOwned::owned(
            // -5 = not-found; the REST proxy maps it to HTTP 404 (not 500).
            -5,
            "transaction not found in index".to_string(),
            None::<()>,
        )),
    }
}
