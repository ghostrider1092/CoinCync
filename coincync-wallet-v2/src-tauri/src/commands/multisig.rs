use serde::{Deserialize, Serialize};

use crate::{active_node_url, wallet_cli, State, WalletError};

// ── Multi-sig (FROST M-of-N) ─────────────────────────────────────────
//
// These 6 Tauri commands wrap the wallet CLI's `multisig-*` subcommands.
// File-based flow: participants exchange JSON files (commitments,
// nonces, signature shares) out-of-band today. The coord-relayed
// variant (wss://api.coincync.network/coord/) will land in a later
// release; the file-based flow stays as the fallback / offline path.
//
// Auth: most commands don't need the session password (they operate on
// key-share files, not the wallet DB), but `multisig_send` does because
// it submits to the node and reads node URL from the same wallet
// context the existing `send_transaction` uses.

#[derive(Serialize)]
pub(crate) struct MultisigGenResult {
    /// Absolute path of each generated share file. Length = total.
    share_files: Vec<String>,
    threshold: u16,
    total: u16,
    output_dir: String,
}

#[derive(Deserialize)]
pub(crate) struct MultisigGenParams {
    threshold: u16,
    total: u16,
    output_dir: String,
}

#[tauri::command]
pub(crate) fn multisig_gen(
    params: MultisigGenParams,
    state: tauri::State<'_, State>,
) -> Result<MultisigGenResult, WalletError> {
    // Typed-error migration 2026-05-23 (recipe in
    // coincync-wallet-v2/docs/typed-errors-migration.md):
    //   - String error → WalletError variants
    //   - PoisonError → LockPoisoned via existing From impl
    //   - wallet_cli's String error → from_cli_error for the user-typo
    //     branch + WalletError::CliFailed fallback
    //   - "no shares produced" → WalletError::op (catch-all with msg)
    let bin = state.lock()?.wallet_bin.clone();
    let out = wallet_cli(
        &bin,
        &[
            "multisig-gen",
            "--threshold",
            &params.threshold.to_string(),
            "--total",
            &params.total.to_string(),
            "--output-dir",
            &params.output_dir,
        ],
        "",
    )
    .map_err(WalletError::from_cli_error)?;
    // CLI prints "share file: <path>" for each generated share — parse them.
    let share_files: Vec<String> = out
        .lines()
        .filter_map(|l| l.strip_prefix("share file: ").map(|s| s.trim().to_string()))
        .collect();
    if share_files.is_empty() {
        return Err(WalletError::op(format!(
            "multisig-gen produced no shares; CLI output:\n{}",
            out
        )));
    }
    Ok(MultisigGenResult {
        share_files,
        threshold: params.threshold,
        total: params.total,
        output_dir: params.output_dir,
    })
}

#[derive(Serialize)]
pub(crate) struct MultisigInfoResult {
    /// Raw `multisig-info` output — share metadata. Frontend renders verbatim.
    info: String,
}

#[derive(Deserialize)]
pub(crate) struct MultisigInfoParams {
    share_file: String,
}

#[tauri::command]
pub(crate) fn multisig_info(
    params: MultisigInfoParams,
    state: tauri::State<'_, State>,
) -> Result<MultisigInfoResult, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let info = wallet_cli(
        &bin,
        &["multisig-info", "--share-file", &params.share_file],
        "",
    )
    .map_err(WalletError::from_cli_error)?;
    Ok(MultisigInfoResult { info })
}

#[derive(Deserialize)]
pub(crate) struct MultisigRound1Params {
    share_file: String,
    output: String,
}

#[derive(Serialize)]
pub(crate) struct MultisigRound1Result {
    /// Path the commitment was written to (input `output` echoed back for confirmation).
    commitment_file: String,
    /// Path to the secret nonce file the CLI wrote alongside the commitment.
    /// Needed for round 2 — DO NOT share with anyone.
    nonce_file: String,
}

#[tauri::command]
pub(crate) fn multisig_round1(
    params: MultisigRound1Params,
    state: tauri::State<'_, State>,
) -> Result<MultisigRound1Result, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let out = wallet_cli(
        &bin,
        &[
            "multisig-round1",
            "--share-file",
            &params.share_file,
            "--output",
            &params.output,
        ],
        "",
    )
    .map_err(WalletError::from_cli_error)?;
    // CLI prints "nonce file: <path>" so the user knows which secret to keep.
    let nonce_file = out
        .lines()
        .find_map(|l| l.strip_prefix("nonce file: ").map(|s| s.trim().to_string()))
        .unwrap_or_else(|| format!("{}.nonce", params.output));
    Ok(MultisigRound1Result {
        commitment_file: params.output,
        nonce_file,
    })
}

#[derive(Deserialize)]
pub(crate) struct MultisigRound2Params {
    share_file: String,
    nonce_file: String,
    /// One path per participant's round-1 commitment (M paths for M-of-N).
    commitments: Vec<String>,
    /// Hex-encoded message to sign (typically a transaction hash).
    message: String,
    output: String,
}

#[derive(Serialize)]
pub(crate) struct MultisigRound2Result {
    sig_share_file: String,
}

#[tauri::command]
pub(crate) fn multisig_round2(
    params: MultisigRound2Params,
    state: tauri::State<'_, State>,
) -> Result<MultisigRound2Result, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let mut args: Vec<String> = vec![
        "multisig-round2".into(),
        "--share-file".into(),
        params.share_file,
        "--nonce-file".into(),
        params.nonce_file,
        "--message".into(),
        params.message,
        "--output".into(),
        params.output.clone(),
        "--commitments".into(),
    ];
    args.extend(params.commitments);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _out = wallet_cli(&bin, &args_ref, "").map_err(WalletError::from_cli_error)?;
    Ok(MultisigRound2Result {
        sig_share_file: params.output,
    })
}

#[derive(Deserialize)]
pub(crate) struct MultisigAggregateParams {
    commitments: Vec<String>,
    shares: Vec<String>,
    key_shares: Vec<String>,
    message: String,
}

#[derive(Serialize)]
pub(crate) struct MultisigAggregateResult {
    /// Hex-encoded aggregate signature, ready to attach to the tx.
    signature_hex: String,
    /// Raw CLI output for debugging.
    raw: String,
}

#[tauri::command]
pub(crate) fn multisig_aggregate(
    params: MultisigAggregateParams,
    state: tauri::State<'_, State>,
) -> Result<MultisigAggregateResult, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let mut args: Vec<String> = vec![
        "multisig-aggregate".into(),
        "--message".into(),
        params.message,
        "--commitments".into(),
    ];
    args.extend(params.commitments);
    args.push("--shares".into());
    args.extend(params.shares);
    args.push("--key-shares".into());
    args.extend(params.key_shares);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let raw = wallet_cli(&bin, &args_ref, "").map_err(WalletError::from_cli_error)?;
    let signature_hex = raw
        .lines()
        .find_map(|l| l.strip_prefix("signature: ").map(|s| s.trim().to_string()))
        .unwrap_or_default();
    Ok(MultisigAggregateResult { signature_hex, raw })
}

#[derive(Deserialize)]
pub(crate) struct MultisigSendParams {
    /// Paths to M key share files (minimum threshold count).
    key_shares: Vec<String>,
    to_spend: String,
    to_view: String,
    /// Amount in atomic units (1e12 atomic = 1 CYNC).
    amount: u64,
}

#[derive(Serialize)]
pub(crate) struct MultisigSendResult {
    txid: String,
    status: String,
}

#[tauri::command]
pub(crate) fn multisig_send(
    params: MultisigSendParams,
    state: tauri::State<'_, State>,
) -> Result<MultisigSendResult, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let node_url = active_node_url();
    let amount_str = params.amount.to_string();
    let mut args: Vec<String> = vec![
        "--node".into(),
        node_url,
        "multisig-send".into(),
        "--to-spend".into(),
        params.to_spend,
        "--to-view".into(),
        params.to_view,
        "--amount".into(),
        amount_str,
        "--key-shares".into(),
    ];
    args.extend(params.key_shares);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = wallet_cli(&bin, &args_ref, "").map_err(WalletError::from_cli_error)?;
    let txid = out
        .lines()
        .find_map(|l| l.strip_prefix("Hash: ").map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "submitted".to_string());
    Ok(MultisigSendResult {
        txid,
        status: "accepted".into(),
    })
}
