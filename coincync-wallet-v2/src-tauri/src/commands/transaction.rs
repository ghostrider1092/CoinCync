use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{active_node_url, wallet_cli, with_session_password, State, WalletError};

/// FIX #35: Parse tCYNC address into spend+view keys properly
#[derive(Deserialize)]
pub(crate) struct SendParams {
    to: String,
    amount: String,
    memo: Option<String>,
    priority: String,
}

#[derive(Serialize)]
pub(crate) struct SendResult {
    txid: String,
    status: String,
}

#[tauri::command]
pub(crate) fn send_transaction(
    params: SendParams,
    state: tauri::State<'_, State>,
) -> Result<SendResult, WalletError> {
    let (bin, path, pw) = {
        let s = state.lock()?;
        let pw = with_session_password(&s, |pw| Ok(pw.to_string()))?;
        (
            s.wallet_bin.clone(),
            s.wallet_path.to_string_lossy().to_string(),
            pw,
        )
    };

    // Parse + VALIDATE the amount. A bare `(f64 * 1e12) as u64` silently
    // saturates a negative/NaN to 0 and an absurd value to u64::MAX, so a
    // "-5"/"abc"/"1e999" input could become a 0-amount (or maxed) send with no
    // error. Reject anything not finite-and-positive, and reject amounts that
    // round below one atomic unit.
    let amount_cync = params
        .amount
        .parse::<f64>()
        .map_err(|e| WalletError::InvalidAmount {
            reason: e.to_string(),
        })?;
    if !amount_cync.is_finite() || amount_cync <= 0.0 {
        return Err(WalletError::InvalidAmount {
            reason: format!("amount must be a positive number (got {:?})", params.amount),
        });
    }
    let atomic_f = amount_cync * 1e12;
    if atomic_f < 1.0 || atomic_f >= u64::MAX as f64 {
        return Err(WalletError::InvalidAmount {
            reason: format!("amount out of range (got {:?} CYNC)", params.amount),
        });
    }
    let amount_atomic = atomic_f as u64;

    let node_url = active_node_url();

    // FIX #35: Get spend and view keys from the address and fail closed if parsing fails.
    // The wallet CLI 'send' command needs --to-spend and --to-view as hex public keys.
    let (spend_hex, view_hex) = if params.to.starts_with("tCYNC") || params.to.starts_with("CYNC") {
        let info = wallet_cli(&bin, &["address-info", &params.to], "")
            .map_err(WalletError::from_cli_error)?;
        let spend = info
            .lines()
            .find(|l| l.contains("Spend"))
            .and_then(|l| l.split_whitespace().last())
            .map(|s| s.to_string())
            .ok_or_else(|| WalletError::InvalidAddress {
                reason: "address-info output missing spend key".into(),
            })?;
        let view = info
            .lines()
            .find(|l| l.contains("View"))
            .and_then(|l| l.split_whitespace().last())
            .map(|s| s.to_string())
            .ok_or_else(|| WalletError::InvalidAddress {
                reason: "address-info output missing view key".into(),
            })?;
        (spend, view)
    } else {
        return Err(WalletError::InvalidAddress {
            reason: "recipient must start with 'tCYNC' or 'CYNC'".into(),
        });
    };

    let out = wallet_cli(
        &bin,
        &[
            "--wallet",
            &path,
            "--node",
            &node_url,
            "send",
            "--to-spend",
            &spend_hex,
            "--to-view",
            &view_hex,
            "--amount",
            &amount_atomic.to_string(),
        ],
        &pw,
    )
    .map_err(WalletError::from_cli_error)?;
    let mut pw = pw;
    pw.zeroize();

    let txid = out
        .lines()
        .find(|l| l.contains("Hash:"))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("submitted")
        .to_string();

    Ok(SendResult {
        txid,
        status: "accepted".into(),
    })
}
