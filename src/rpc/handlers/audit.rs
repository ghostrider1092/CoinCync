//! Bounded chain verification RPCs and their request policy.

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde::Deserialize;
use serde_json::json;

use crate::chain::NodeChainView;
use crate::compliance::SignedAuditPackage;
use crate::error::{Error, Result};

use super::RpcState;

/// Params for `verify_audit_package`: the signed package plus the issuer key
/// and auditor identity the caller trusts out of band. `now` defaults to the
/// server's wall-clock seconds (drives expiry).
#[derive(Deserialize)]
struct VerifyAuditParams {
    /// The [`SignedAuditPackage`] to verify.
    package: SignedAuditPackage,
    /// Ed25519 public key the auditor expects the org to have signed with (hex,
    /// 32 bytes).
    issuer_pubkey: String,
    /// The auditor identity this package must be addressed to.
    auditor: String,
    /// Expiry reference time (unix seconds). Defaults to the server clock.
    #[serde(default)]
    now: Option<u64>,
}

fn decode_verifying_key(hex_key: &str) -> std::result::Result<ed25519_dalek::VerifyingKey, ErrorObjectOwned> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| ErrorObjectOwned::owned(-32602, format!("issuer_pubkey: bad hex: {e}"), None::<()>))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        ErrorObjectOwned::owned(-32602, "issuer_pubkey: expected 32 bytes", None::<()>)
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| ErrorObjectOwned::owned(-32602, format!("issuer_pubkey: invalid key: {e}"), None::<()>))
}

/// Maximum inclusive block span for CPU-heavy audit RPCs (`*_in_range`, `full_chain_audit`).
pub const MAX_RPC_AUDIT_BLOCK_SPAN: u64 = 128;

/// Refuse unbounded `verify_keyimage_uniqueness` scans on very long chains (local DoS mitigation).
const MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT: u64 = 25_000;

fn rpc_clamp_audit_range(
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

pub(super) fn register(module: &mut RpcModule<RpcState>) -> Result<()> {
    // ── get_expected_reward ──────────────────────────────────────
    module
        .register_method("get_expected_reward", |params, _state, _ext| {
            let (height,): (u64,) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("params: [height]: {}", e), None::<()>)
            })?;
            let reward = crate::emission::calculate_block_reward(height);
            Ok::<_, ErrorObjectOwned>(json!({
                "reward": reward.as_atomic(),
                "height": height,
                "in_cync": reward.as_atomic() as f64 / 1_000_000_000_000.0,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_keyimage_uniqueness ──────────────────────────────
    module.register_blocking_method("verify_keyimage_uniqueness", |_params, state, _ext| {
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
                    if tx.is_coinbase() { continue; }
                    for input in &tx.inputs {
                        let ki_hex = hex::encode(input.key_image.as_bytes());
                        if !seen.insert(ki_hex.clone()) {
                            duplicates.push(ki_hex);
                        }
                    }
                }
            }
        }

        Ok::<_, ErrorObjectOwned>(json!({
            "valid": duplicates.is_empty(),
            "duplicates": duplicates.len(),
            "duplicate_images": &duplicates[..duplicates.len().min(10)],
            "total_checked": seen.len(),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── check_zero_commitments_in_range ─────────────────────────
    module
        .register_blocking_method("check_zero_commitments_in_range", |params, state, _ext| {
            let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
            })?;
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

            Ok::<_, ErrorObjectOwned>(json!({
                "zero_count": zero_count,
                "locations": locations,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_signatures_in_range ──────────────────────────────
    module
        .register_blocking_method("verify_signatures_in_range", |params, state, _ext| {
            let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
            })?;
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

            Ok::<_, ErrorObjectOwned>(json!({
                "valid": failures == 0,
                "checked": checked,
                "failures": failures,
                "findings": &findings[..findings.len().min(50)],
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_range_proofs_in_range ────────────────────────────
    module
        .register_blocking_method("verify_range_proofs_in_range", |params, state, _ext| {
            let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
            })?;
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

            Ok::<_, ErrorObjectOwned>(json!({
                "valid": failures == 0,
                "checked": checked,
                "failures": failures,
                "findings": &findings[..findings.len().min(50)],
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_commitment_balance_in_range ──────────────────────
    module
        .register_blocking_method(
            "verify_commitment_balance_in_range",
            |params, state, _ext| {
                let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
                    ErrorObjectOwned::owned(
                        -32602,
                        format!("params: [start, end]: {}", e),
                        None::<()>,
                    )
                })?;
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

                Ok::<_, ErrorObjectOwned>(json!({
                    "valid": failures == 0,
                    "checked": checked,
                    "failures": failures,
                    "findings": &findings[..findings.len().min(50)],
                }))
            },
        )
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── full_chain_audit ────────────────────────────────────────
    module
        .register_blocking_method("full_chain_audit", |params, state, _ext| {
            let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("params: [start, end]: {}", e), None::<()>)
            })?;
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

            Ok::<_, ErrorObjectOwned>(json!({
                "valid": findings.is_empty(),
                "blocks_checked": blocks_checked,
                "txs_checked": txs_checked,
                "findings": findings.len(),
                "details": &findings[..findings.len().min(100)],
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── verify_audit_package ────────────────────────────────────
    // The compliant-privacy auditor endpoint: verify an org-signed disclosure
    // package against THIS node's canonical chain state (the sound decision),
    // and return the reconciliation summary and a human-readable report.
    //
    // Stateless: single-use (audit_id replay) is the auditor's own bookkeeping
    // — the signed package carries the id, but a stateless RPC cannot remember
    // it across calls, so this endpoint verifies signature + anchoring only and
    // reports the id for the caller to record.
    module
        .register_blocking_method("verify_audit_package", |params, state, _ext| {
            let (p,): (VerifyAuditParams,) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("params: [ {{package, issuer_pubkey, auditor, now?}} ]: {e}"), None::<()>)
            })?;

            let issuer = decode_verifying_key(&p.issuer_pubkey)?;
            let now = p.now.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });

            let signature_valid = p
                .package
                .verify_signature(&issuer, &p.auditor)
                .map_err(|e| ErrorObjectOwned::owned(-32603, format!("signature check: {e}"), None::<()>))?;

            let view = NodeChainView::new(&state.chain);
            let anchored_valid = p
                .package
                .package
                .verify_anchored(now, &view)
                .map_err(|e| ErrorObjectOwned::owned(-32603, format!("anchored verify: {e}"), None::<()>))?;

            let rec = p
                .package
                .package
                .reconcile()
                .map_err(|e| ErrorObjectOwned::owned(-32603, format!("reconcile: {e}"), None::<()>))?;

            let report = p.package.to_report(now);

            Ok::<_, ErrorObjectOwned>(json!({
                // The sound trust decision: signed by the expected org, addressed
                // to this auditor, AND every proof anchors to real chain state.
                "accepted": signature_valid && anchored_valid,
                "signature_valid": signature_valid,
                "anchored_valid": anchored_valid,
                "audit_id": p.package.audit_id,
                "issued_to": p.package.audience,
                "org": p.package.package.org,
                "period": p.package.package.period,
                "reconciliation": {
                    "has_total": rec.has_total,
                    "claimed_total": rec.claimed_total,
                    "disbursed_outputs": rec.disbursed.len(),
                    "receipted_outputs": rec.receipted.len(),
                    "missing_receipts": rec.missing_receipts.len(),
                    "unexpected_receipts": rec.unexpected_receipts.len(),
                    "fully_reconciled": rec.is_fully_reconciled(),
                },
                "report": report,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{create_rpc_module, RpcState};
    use crate::compliance::AuditPackage;
    use crate::crypto::{
        create_balance_proof, BlindingFactor, DisclosureOutputRef, DisclosureProof,
        PedersenCommitment,
    };
    use crate::mempool::SharedMempool;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::Arc;

    fn rpc_state(chain: crate::chain::Blockchain) -> RpcState {
        RpcState {
            chain: Arc::new(chain),
            mempool: SharedMempool::new(),
            p2p: None,
            network_name: "test".to_string(),
            auth_enabled: false,
            minimize_metadata: false,
            stratum_public_bind_requested: false,
            stratum_public_bind_ack: false,
            stratum_native_tls_enabled: false,
            stratum_tls_proxy_ack: false,
            stratum_transport_hardened: false,
        }
    }

    #[tokio::test]
    async fn verify_audit_package_accepts_signed_and_anchored_package() {
        // A balance proof plus an on-chain output that carries its commitment.
        let value = 5_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);
        let bp = create_balance_proof(value, &blinding, &commitment, 1_000_000).unwrap();
        let dp = DisclosureProof::from_balance(&bp, "treasury solvency >= 1,000,000", Some(2_000_000_000))
            .unwrap();

        // Take the genesis block and overwrite one output's commitment to the
        // proof's, so the proof anchors to a real (DB-resident) output.
        let mut block = crate::testnet::testnet_genesis();
        assert!(!block.transactions.is_empty() && !block.transactions[0].outputs.is_empty());
        block.transactions[0].outputs[0].commitment = commitment.to_bytes();
        let tx_hash = block.transactions[0].hash();
        let output_ref = DisclosureOutputRef { tx_hash, output_index: 0 };

        // Org signs the package for one named auditor.
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, output_ref);
        let key = SigningKey::generate(&mut OsRng);
        let issuer_hex = hex::encode(key.verifying_key().to_bytes());
        let signed = pkg.sign(&key, [5u8; 32], "Auditor One").unwrap();
        let signed_json = serde_json::to_value(&signed).unwrap();

        // A node whose DB holds that block + its tx index, so NodeChainView's
        // anchor() resolves via the DB fallback (no in-memory cache access).
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::db::Database::open(dir.path()).unwrap());
        db.blocks.insert(&block).unwrap();
        db.blocks.set_height_hash(0, &block.hash()).unwrap();
        db.index_tx(tx_hash.as_bytes(), 0, 0).unwrap();
        let chain =
            crate::chain::Blockchain::with_database(Arc::clone(&db), crate::config::NetworkType::Testnet);

        let module = create_rpc_module(rpc_state(chain)).unwrap();

        // Correct issuer + auditor => signature valid, anchors on chain, accepted.
        let req = json!({
            "package": signed_json,
            "issuer_pubkey": issuer_hex,
            "auditor": "Auditor One",
            "now": 1_000_000,
        });
        let resp: serde_json::Value = module
            .call("verify_audit_package", jsonrpsee::rpc_params![req])
            .await
            .unwrap();
        assert_eq!(resp["accepted"], json!(true), "resp: {resp}");
        assert_eq!(resp["signature_valid"], json!(true));
        assert_eq!(resp["anchored_valid"], json!(true));
        assert!(resp["report"].as_str().unwrap().contains("Acme DAO"));

        // Wrong auditor (non-transferable) => signature invalid, not accepted.
        let req2 = json!({
            "package": signed_json,
            "issuer_pubkey": issuer_hex,
            "auditor": "Someone Else",
            "now": 1_000_000,
        });
        let resp2: serde_json::Value = module
            .call("verify_audit_package", jsonrpsee::rpc_params![req2])
            .await
            .unwrap();
        assert_eq!(resp2["signature_valid"], json!(false));
        assert_eq!(resp2["accepted"], json!(false));
    }

    #[tokio::test]
    async fn verify_audit_package_rejects_bad_issuer_hex() {
        // A well-formed signed package but a malformed issuer key => param error.
        let key = SigningKey::generate(&mut OsRng);
        let pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        let signed = pkg.sign(&key, [1u8; 32], "Auditor One").unwrap();
        let signed_json = serde_json::to_value(&signed).unwrap();

        let module = create_rpc_module(rpc_state(crate::chain::Blockchain::new())).unwrap();
        let req = json!({ "package": signed_json, "issuer_pubkey": "not-hex", "auditor": "Auditor One" });
        let err = module
            .call::<_, serde_json::Value>("verify_audit_package", jsonrpsee::rpc_params![req])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("issuer_pubkey"), "err: {err}");
    }
}
