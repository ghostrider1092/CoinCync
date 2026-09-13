//! Mempool queries, transaction submission, and transaction lookup RPCs.

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde_json::{json, Value};
use tracing::warn;

use crate::error::{Error, Result};

use super::RpcState;

pub(super) fn register(module: &mut RpcModule<RpcState>) -> Result<()> {
    // ── get_mempool_info ───────────────────────────────────────
    module
        .register_method("get_mempool_info", |_params, state, _ext| {
            let mp = state.mempool.stats();
            Ok::<_, ErrorObjectOwned>(json!({
                "size":       mp.tx_count,
                "bytes":      mp.size_bytes,
                "total_fees": mp.total_fee.as_atomic(),
                "max_size":   mp.max_size,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_mempool_transactions ──────────────────────────────
    //
    // Returns individual transaction details from the mempool so
    // the explorer can render them in a table (like the blocks page).
    module
        .register_method("get_mempool_transactions", |_params, state, _ext| {
            // Layer 2: mempool iteration up to 500 txs under block_in_place
            // keeps the worker thread reusable during the fetch.
            let txs = tokio::task::block_in_place(|| {
                state.mempool.get_block_transactions(
                    crate::constants::MAX_BLOCK_SIZE,
                    500, // max 500 txs
                )
            });
            let tx_list: Vec<Value> = txs
                .iter()
                .map(|tx| {
                    let kind = match tx.tx_type {
                        crate::transaction::TxType::Coinbase => "coinbase",
                        crate::transaction::TxType::Transfer => "transfer",
                        crate::transaction::TxType::Churn => "churn",
                    };
                    json!({
                        "hash":    hex::encode(tx.hash().as_bytes()),
                        "kind":    kind,
                        "inputs":  tx.input_count(),
                        "outputs": tx.output_count(),
                        "fee":     tx.fee.as_atomic(),
                        "size":    tx.size(),
                    })
                })
                .collect();
            Ok::<_, ErrorObjectOwned>(json!({
                "count": tx_list.len(),
                "transactions": tx_list,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── send_raw_transaction ──────────────────────────────────
    module
        .register_method("send_raw_transaction", |params, state, _ext| {
            let (hex_tx,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
            })?;
            // Bound hex input length. Mirrors submit_block above and
            // `is_nullifier_spent` at ~L1309. (Bitcoin Core exposes a
            // `sendrawtransaction` RPC; the prior comment specifically
            // cited `MAX_STANDARD_TX_WEIGHT` as the size cap primitive.
            // That specific constant was not re-verified against upstream
            // this session and is dropped. The 2× MAX_TX_SIZE × 2 cap
            // below stands on its own reasoning: 2 for hex, 2 for slack;
            // anything larger decodes to bytes larger than any valid tx
            // and is rejected downstream, but the pre-check saves the
            // allocation and the borsh parse.)
            const MAX_HEX_TX: usize = 2 * 2 * crate::constants::MAX_TX_SIZE;
            if hex_tx.len() > MAX_HEX_TX {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    format!(
                        "hex tx too large: {} chars (max {})",
                        hex_tx.len(),
                        MAX_HEX_TX
                    ),
                    None::<()>,
                ));
            }
            let tx_bytes = hex::decode(&hex_tx).map_err(|e| {
                ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
            })?;
            let tx: crate::transaction::Transaction =
                borsh::from_slice(&tx_bytes).map_err(|e| {
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
                    Ok::<_, ErrorObjectOwned>(json!({
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
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_transaction ───────────────────────────────────────
    //
    // Lookup a transaction by hash. Currently NOT IMPLEMENTED —
    // the chain does not maintain a txid → (block_height, index)
    // index, so we cannot satisfy this query without scanning
    // every block. The embedded explorer's search bar in
    // `app/11-router.js` calls this; it will display a
    // labelled "not yet wired" error rather than silently
    // returning empty results, so the missing index is visible
    // and tracked.
    module.register_method("get_transaction", |params, state, _ext| {
        let (tx_hash_hex,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        // AUDIT (2026-07-02): pre-decode length cap. Same class of bug as
        // submit_block / send_raw_transaction / is_nullifier_spent were
        // hardened against — hex::decode allocates a Vec of half the input
        // length BEFORE the downstream 32-byte length check at ~L1601 can
        // fire. Without the cap, a caller sending a 1 GB hex string would
        // force the node to allocate ~500 MB just to reject it. A tx hash
        // is 32 bytes = 64 hex chars, plus an optional `0x` prefix; cap
        // the input at 66 chars.
        let trimmed = tx_hash_hex.trim_start_matches("0x");
        if trimmed.len() > 64 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                format!("tx hash hex too large: {} chars (max 64)", trimmed.len()),
                None::<()>,
            ));
        }
        let tx_hash_bytes = hex::decode(trimmed).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if tx_hash_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "tx hash must be 32 bytes (64 hex chars)".to_string(), None::<()>,
            ));
        }
        // Layer 2: tx-location index lookup is the first chain DB read;
        // the subsequent block fetch is the second. Wrap each in
        // block_in_place so the worker thread is reusable across both
        // calls while preserving the original error-message distinction
        // between "tx not found" and "block missing for a known tx".
        let location_opt = tokio::task::block_in_place(|| {
            state.chain.get_tx_location(&tx_hash_bytes)
        });
        match location_opt {
            Some((block_height, tx_idx)) => {
                let block_opt = tokio::task::block_in_place(|| {
                    state.chain.get_block_by_height(block_height)
                });
                match block_opt {
                    Some(block) => {
                        let tx = block.transactions.get(tx_idx as usize);
                        match tx {
                            Some(tx) => {
                                let tx_bytes = borsh::to_vec(tx).unwrap_or_default();
                                let ring_size = tx.inputs.first().map(|i| i.ring_members.len()).unwrap_or(0);
                                let inputs_json: Vec<Value> = tx.inputs.iter().map(|inp| {
                                    json!({
                                        "key_image": hex::encode(inp.key_image.as_bytes()),
                                        "ring_size": inp.ring_members.len(),
                                    })
                                }).collect();
                                let outputs_json: Vec<Value> = tx.outputs.iter().map(|out| {
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
                                }).collect();
                                let has_range_proof = !tx.range_proof.is_empty();
                                let has_recovery = !tx.extra.is_empty() && tx.extra[0] == 0xDE;
                                Ok::<_, ErrorObjectOwned>(json!({
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
                                -32000, "tx index points to invalid position".to_string(), None::<()>,
                            )),
                        }
                    }
                    None => Err(ErrorObjectOwned::owned(
                        -32000, format!("block at height {} not found", block_height), None::<()>,
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
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_asset_info ────────────────────────────────────────
    //
    // Lookup an issued-asset descriptor by id. CoinCync 1.0
    // STRIPPED the confidential-asset layer in the 2.0 → 1.0
    // trim, so this endpoint is permanently NOT IMPLEMENTED —
    // the embedded explorer's search bar in `app/11-router.js` calls it
    // on free-text input that doesn't
    // match a block hash or txid. Returning an explicit error
    // makes the missing surface obvious instead of silently
    // returning empty results.
    module
        .register_method("get_asset_info", |_params, _state, _ext| {
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32601,
                "get_asset_info is not implemented: CoinCync 1.0 has no \
             confidential-asset layer (the asset stack was removed \
             in the 2.0 → 1.0 trim). Single-asset CYNC only.",
                None::<()>,
            ))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    Ok(())
}
