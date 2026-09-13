//! Chain-audit RPC handlers — CPU-heavy, full/range chain scans. Registered as
//! `register_blocking_method`s so they run on the blocking pool. Extracted from
//! `start_rpc_server` (issue #107); bodies, response shapes, and error codes are
//! unchanged from the previous inline closures.
//!
//! ## Audit map
//! - **§6 `rpc_clamp_audit_range` (range-scan bounds)** — INVARIANT: audit/range
//!   RPCs scan at most `MAX_RPC_AUDIT_BLOCK_SPAN` blocks per call and require
//!   `start <= end`; `verify_keyimage_uniqueness` additionally refuses whole-chain
//!   scans above `MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT`. THREAT: a single RPC call
//!   pinning a node's CPU (local DoS). TESTS: `verify_signatures_in_range_rejects_oversized_span`,
//!   `full_chain_audit_rejects_reversed_range`, `verify_keyimage_uniqueness_refused_above_height_cap`.

use jsonrpsee::types::{ErrorObjectOwned, Params};
use serde_json::{json, Value};

use crate::rpc::server::{RpcState, MAX_RPC_AUDIT_BLOCK_SPAN};

/// Refuse unbounded `verify_keyimage_uniqueness` scans on very long chains (local DoS mitigation).
const MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT: u64 = 25_000;

/// Clamp/validate an inclusive `[start, end]` audit range to `MAX_RPC_AUDIT_BLOCK_SPAN`.
pub(crate) fn rpc_clamp_audit_range(
    start: u64,
    end: u64,
) -> std::result::Result<(u64, u64), ErrorObjectOwned> {
    if start > end {
        return Err(ErrorObjectOwned::owned(
            -32602,
            "audit range: start must be <= end",
            None::<()>,
        ));
    }
    let span = end.saturating_sub(start).saturating_add(1);
    if span > MAX_RPC_AUDIT_BLOCK_SPAN {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!(
                "audit range too large ({} blocks); max {} blocks per call",
                span, MAX_RPC_AUDIT_BLOCK_SPAN
            ),
            None::<()>,
        ));
    }
    Ok((start, end))
}

/// Parse the standard `[start, end]` u64 pair used by the range-audit methods.
fn parse_range(params: Params) -> std::result::Result<(u64, u64), ErrorObjectOwned> {
    params.parse().map_err(|e: ErrorObjectOwned| {
        ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
    })
}

pub(crate) fn verify_keyimage_uniqueness(
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let chain_height = state.chain.height();
    if chain_height > MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT {
        return Err(ErrorObjectOwned::owned(
            -32003,
            format!(
                "verify_keyimage_uniqueness refused: chain height {} exceeds built-in limit {} (CPU DoS mitigation; use range audit RPCs or raise limit after ops review)",
                chain_height, MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT
            ),
            None::<()>,
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut duplicates: Vec<String> = Vec::new();

    for h in 0..=chain_height {
        if let Some(block) = state.chain.get_block_by_height(h) {
            for tx in &block.transactions {
                if tx.is_coinbase() {
                    continue;
                }
                for input in &tx.inputs {
                    let ki_hex = hex::encode(input.key_image.as_bytes());
                    if !seen.insert(ki_hex.clone()) {
                        duplicates.push(ki_hex);
                    }
                }
            }
        }
    }

    Ok(json!({
        "valid": duplicates.is_empty(),
        "duplicates": duplicates.len(),
        "duplicate_images": &duplicates[..duplicates.len().min(10)],
        "total_checked": seen.len(),
    }))
}

pub(crate) fn check_zero_commitments_in_range(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (start, end) = parse_range(params)?;
    let (start, end) = rpc_clamp_audit_range(start, end)?;
    let mut zero_count = 0u64;
    let mut locations = Vec::new();

    for h in start..=end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            for tx in &block.transactions {
                for (idx, output) in tx.outputs.iter().enumerate() {
                    if output.commitment == [0u8; 32] {
                        zero_count += 1;
                        locations.push(json!({
                            "height": h,
                            "tx_hash": tx.hash().to_hex(),
                            "output_index": idx,
                            "issue": "zero_commitment",
                        }));
                    }
                    if output.stealth_address.as_bytes() == &[0u8; 32] {
                        zero_count += 1;
                        locations.push(json!({
                            "height": h,
                            "tx_hash": tx.hash().to_hex(),
                            "output_index": idx,
                            "issue": "zero_stealth_address",
                        }));
                    }
                }
            }
        }
    }

    Ok(json!({
        "zero_count": zero_count,
        "locations": locations,
    }))
}

pub(crate) fn verify_signatures_in_range(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (start, end) = parse_range(params)?;
    let (start, end) = rpc_clamp_audit_range(start, end)?;
    let mut checked = 0u64;
    let mut failures = 0u64;
    let mut findings = Vec::new();

    for h in start..=end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            for tx in &block.transactions {
                if tx.is_coinbase() {
                    continue;
                }
                for (idx, input) in tx.inputs.iter().enumerate() {
                    checked += 1;
                    if !crate::consensus::verify_ring_signature(&tx, input, idx) {
                        failures += 1;
                        findings.push(format!(
                            "Invalid CLSAG at h={} tx={} input={}",
                            h,
                            tx.hash().to_hex()[..16].to_string(),
                            idx
                        ));
                    }
                }
            }
        }
    }

    Ok(json!({
        "valid": failures == 0,
        "checked": checked,
        "failures": failures,
        "findings": &findings[..findings.len().min(50)],
    }))
}

pub(crate) fn verify_range_proofs_in_range(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (start, end) = parse_range(params)?;
    let (start, end) = rpc_clamp_audit_range(start, end)?;
    let mut checked = 0u64;
    let mut failures = 0u64;
    let mut findings = Vec::new();

    for h in start..=end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            for tx in &block.transactions {
                if tx.is_coinbase() {
                    continue;
                }
                checked += 1;
                if !crate::consensus::verify_output_range_proofs(&tx, h) {
                    failures += 1;
                    findings.push(format!(
                        "Invalid range proof at h={} tx={}",
                        h,
                        tx.hash().to_hex()[..16].to_string()
                    ));
                }
            }
        }
    }

    Ok(json!({
        "valid": failures == 0,
        "checked": checked,
        "failures": failures,
        "findings": &findings[..findings.len().min(50)],
    }))
}

pub(crate) fn verify_commitment_balance_in_range(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (start, end) = parse_range(params)?;
    let (start, end) = rpc_clamp_audit_range(start, end)?;
    let mut checked = 0u64;
    let mut failures = 0u64;
    let mut findings = Vec::new();

    for h in start..=end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            for tx in &block.transactions {
                if tx.is_coinbase() {
                    continue;
                }
                checked += 1;
                if !crate::consensus::verify_balance_proof(&tx) {
                    failures += 1;
                    findings.push(format!(
                        "Commitment imbalance at h={} tx={}",
                        h,
                        tx.hash().to_hex()[..16].to_string()
                    ));
                }
            }
        }
    }

    Ok(json!({
        "valid": failures == 0,
        "checked": checked,
        "failures": failures,
        "findings": &findings[..findings.len().min(50)],
    }))
}

pub(crate) fn full_chain_audit(
    params: Params,
    state: &RpcState,
) -> std::result::Result<Value, ErrorObjectOwned> {
    let (start, end) = parse_range(params)?;
    let (start, end) = rpc_clamp_audit_range(start, end)?;
    let mut blocks_checked = 0u64;
    let mut txs_checked = 0u64;
    let mut findings = Vec::new();

    for h in start..=end {
        if let Some(block) = state.chain.get_block_by_height(h) {
            blocks_checked += 1;
            txs_checked += block.transactions.len() as u64;

            // Verify merkle root
            let tx_hashes: Vec<_> = block.transactions.iter().map(|tx| tx.hash()).collect();
            let computed_root = crate::primitives::merkle_root(&tx_hashes);
            if computed_root != block.header.tx_root {
                findings.push(format!("h={}: merkle root mismatch", h));
            }

            // Verify block reward
            let _expected_reward = crate::emission::calculate_block_reward(h);
            if let Some(coinbase) = block.transactions.first() {
                // Basic check: coinbase exists and is coinbase type
                if !coinbase.is_coinbase() {
                    findings.push(format!("h={}: first tx is not coinbase", h));
                }
            }

            // Verify all transactions
            for tx in &block.transactions {
                if tx.is_coinbase() {
                    continue;
                }

                // Structural validation
                if let Err(e) = crate::consensus::validate_transaction_basic(&tx) {
                    findings.push(format!("h={}: structural: {}", h, e));
                }

                // Ring signatures
                for (idx, input) in tx.inputs.iter().enumerate() {
                    if !crate::consensus::verify_ring_signature(&tx, input, idx) {
                        findings.push(format!("h={}: CLSAG invalid input {}", h, idx));
                    }
                }

                // Range proofs
                if !crate::consensus::verify_output_range_proofs(&tx, h) {
                    findings.push(format!("h={}: range proof invalid", h));
                }

                // Balance
                if !crate::consensus::verify_balance_proof(&tx) {
                    findings.push(format!("h={}: commitment imbalance", h));
                }
            }
        }
    }

    Ok(json!({
        "valid": findings.is_empty(),
        "blocks_checked": blocks_checked,
        "txs_checked": txs_checked,
        "findings": findings.len(),
        "details": &findings[..findings.len().min(100)],
    }))
}
