//! Privacy-store and wallet decoy snapshot RPCs.

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde_json::{json, Value};

use crate::decoy::OutputLocator;
use crate::error::{Error, Result};
use crate::primitives::Hash;

use super::RpcState;

pub(super) fn register(module: &mut RpcModule<RpcState>) -> Result<()> {
    // ── get_privacy_stats ─────────────────────────────────────
    // Aggregate view of the Phase 2 privacy stores.
    module.register_method("get_privacy_stats", |_params, state, _ext| {
        let cut_through = state.chain.cut_through_stats();
        Ok::<_, ErrorObjectOwned>(json!({
            "shielded_root":      hex::encode(state.chain.shielded_root()),
            "shielded_tree_size": state.chain.shielded_store.as_ref().map(|s| s.tree_size()).unwrap_or(0),
            "spark_root":         hex::encode(state.chain.spark_root()),
            "spark_accumulator_size": state.chain.spark_store.as_ref().map(|s| s.size()).unwrap_or(0),
            "mw_kernel_root":     hex::encode(state.chain.mw_kernel_root()),
            "mw_kernels_kept":    cut_through.kernels_kept,
            "mw_pending_candidates": cut_through.pending_candidates,
            "mw_bytes_saved":     cut_through.bytes_saved,
            "mw_compression":     cut_through.compression_ratio,
            "mandatory_confidential": crate::constants::MANDATORY_CONFIDENTIAL,
            "mandatory_stealth":      crate::constants::MANDATORY_STEALTH,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_shielded_anchor ───────────────────────────────────
    // Light wallets query this to get the current Merkle root they
    // should anchor their spend proofs against.
    module.register_method("get_shielded_anchor", |_params, state, _ext| {
        Ok::<_, ErrorObjectOwned>(json!({
            "anchor": hex::encode(state.chain.shielded_root()),
            "tree_size": state.chain.shielded_store.as_ref().map(|s| s.tree_size()).unwrap_or(0),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_spark_anchor ──────────────────────────────────────
    module
        .register_method("get_spark_anchor", |_params, state, _ext| {
            Ok::<_, ErrorObjectOwned>(json!({
                "root": hex::encode(state.chain.spark_root()),
                "size": state.chain.spark_store.as_ref().map(|s| s.size()).unwrap_or(0),
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── is_nullifier_spent ────────────────────────────────────
    // Wallet calls before building a shielded spend to make sure it
    // won't be rejected as a double-spend.
    module.register_method("is_nullifier_spent", |params, state, _ext| {
        let (hex_nf,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        // Pre-decode length cap: a 32-byte nullifier is 64 hex chars.
        // Reject inputs that are obviously oversized BEFORE allocating a
        // potentially huge Vec inside hex::decode. Prevents 1 GB hex →
        // 500 MB Vec alloc DoS. Audit-fix.
        if hex_nf.len() > 128 {
            return Err(ErrorObjectOwned::owned(
                -32602, "nullifier hex too long (max 128 chars)".to_string(), None::<()>,
            ));
        }
        let bytes = hex::decode(&hex_nf).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "nullifier must be 32 bytes".to_string(), None::<()>,
            ));
        }
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&bytes);
        Ok::<_, ErrorObjectOwned>(json!({
            "nullifier": hex::encode(nf),
            "spent": state.chain.shielded_store.as_ref().map(|s| s.is_nullifier_spent(&nf)).unwrap_or(false),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── is_spark_serial_spent ─────────────────────────────────
    module.register_method("is_spark_serial_spent", |params, state, _ext| {
        let (hex_s,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        // Same pre-decode length cap as is_nullifier_spent — see comment there.
        if hex_s.len() > 128 {
            return Err(ErrorObjectOwned::owned(
                -32602, "serial hex too long (max 128 chars)".to_string(), None::<()>,
            ));
        }
        let bytes = hex::decode(&hex_s).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "serial must be 32 bytes".to_string(), None::<()>,
            ));
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        Ok::<_, ErrorObjectOwned>(json!({
            "serial": hex::encode(s),
            "spent": state.chain.spark_store.as_ref().map(|store| store.is_serial_spent(&s)).unwrap_or(false),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // Deprecated node-selected decoy surface. Wallets construct covered,
    // snapshot-bound locator requests through the replacement methods below.
    module
        .register_method("get_decoys", |_params, _state, _ext| {
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32004,
                "get_decoys is deprecated; use get_decoy_distribution and get_outputs_by_locators",
                None::<()>,
            ))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    module
        .register_blocking_method("get_decoy_distribution", |_params, state, _ext| {
            Ok::<_, ErrorObjectOwned>(state.chain.decoy_distribution_snapshot())
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    module
        .register_blocking_method("get_outputs_by_locators", |params, state, _ext| {
            let (snapshot_height, snapshot_hash, policy_version, locators): (
                u64,
                Hash,
                u16,
                Vec<OutputLocator>,
            ) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("bad params: {e}"), None::<()>)
            })?;
            state
                .chain
                .resolve_decoy_snapshot(snapshot_height, snapshot_hash, policy_version, &locators)
                .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_anonymity_set ─────────────────────────────────────
    //
    // The single most important privacy metric: every unspent
    // output is a potential decoy, so the size of this set is
    // the size of every future spend's anonymity set.
    module
        .register_method("get_anonymity_set", |_params, state, _ext| {
            let count = state.chain.available_output_count();
            let height = state.chain.height();
            let outputs_per_block = if height > 0 {
                count / usize::try_from(height).unwrap_or(usize::MAX)
            } else {
                0
            };
            Ok::<_, ErrorObjectOwned>(json!({
                "anonymity_set":    count,
                "height":           height,
                "outputs_per_block": outputs_per_block,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    Ok(())
}
