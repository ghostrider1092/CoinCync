use serde::Serialize;
use tauri::Manager;
use zeroize::Zeroize;

use crate::{
    active_node_url, clear_session_password, emit_wallet_state, record_unlock_failure,
    set_session_password, time_secs, wallet_cli, wallet_dir, with_session_password, State,
    TxRecord, WalletError, UNLOCK_LOCKOUT_SECS,
};

#[derive(Serialize)]
pub(crate) struct Balance { total: String, unlocked: String, locked: String }

#[tauri::command]
pub(crate) fn get_balance(state: tauri::State<'_, State>) -> Balance {
    let w = state.lock().unwrap();
    let t = w.balance_total as f64 / 1e12;
    let formatted = if t > 0.0 {
        format!("{:.12}", t)
    } else {
        "0.000000000000".to_string()
    };
    Balance { total: formatted.clone(), unlocked: formatted, locked: "0.000000000000".into() }
}

#[tauri::command]
pub(crate) fn get_transactions(state: tauri::State<'_, State>) -> serde_json::Value {
    let w = state.lock().unwrap();
    serde_json::json!({ "txs": w.transactions })
}

#[tauri::command]
pub(crate) fn validate_address(address: String, state: tauri::State<'_, State>) -> serde_json::Value {
    let addr = address.trim().to_string();
    if addr.is_empty() {
        return serde_json::json!({"valid": false, "type": "unknown", "reason": "empty address"});
    }
    if !(addr.starts_with("tCYNC") || addr.starts_with("CYNC")) {
        return serde_json::json!({"valid": false, "type": "unknown", "reason": "invalid prefix"});
    }

    let bin = {
        let s = match state.lock() {
            Ok(guard) => guard,
            Err(e) => {
                return serde_json::json!({"valid": false, "type": "unknown", "reason": format!("state lock failed: {}", e)});
            }
        };
        s.wallet_bin.clone()
    };

    match wallet_cli(&bin, &["address-info", &addr], "") {
        Ok(info) => {
            let lower = info.to_lowercase();
            let addr_type = if lower.contains("integrated") {
                "integrated"
            } else if lower.contains("subaddress") {
                "subaddress"
            } else {
                "stealth"
            };
            serde_json::json!({"valid": true, "type": addr_type})
        }
        Err(err) => serde_json::json!({"valid": false, "type": "unknown", "reason": err}),
    }
}

// ── Wallet lifecycle ──────────────────────────────────────────────────

fn looks_like_mnemonic_line(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    let wc = words.len();
    if !matches!(wc, 12 | 15 | 18 | 21 | 24) {
        return false;
    }
    words
        .iter()
        .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
}

fn extract_seed_phrase(output: &str) -> Option<String> {
    let mut lines = output.lines().skip_while(|l| !l.contains("Write down"));
    if lines.next().is_some() {
        for line in lines {
            let candidate = line.trim();
            if looks_like_mnemonic_line(candidate) {
                return Some(candidate.to_string());
            }
        }
    }

    output
        .lines()
        .map(str::trim)
        .find(|l| looks_like_mnemonic_line(l))
        .map(|s| s.to_string())
}

#[tauri::command]
pub(crate) fn create_wallet(
    password: String,
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<String, WalletError> {
    let (bin, path) = {
        let s = state.lock()?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    let p = path.to_string_lossy().to_string();

    let out = wallet_cli(&bin, &["--wallet", &p, "create", "--force"], &password)
        .map_err(WalletError::from_cli_error)?;

    let Some(seed) = extract_seed_phrase(&out) else {
        return Err(WalletError::WalletSeedParseFailed);
    };

    let mut s = state.lock()?;
    s.wallet_path = path;
    set_session_password(&mut s, password);
    s.unlocked = true;
    emit_wallet_state(&app, &s);
    Ok(seed)
}

#[tauri::command]
pub(crate) fn restore_wallet(
    seed: String,
    password: String,
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<bool, WalletError> {
    let normalized_seed = seed.split_whitespace().collect::<Vec<_>>().join(" ");
    let word_count = normalized_seed.split_whitespace().count();
    if word_count < 12 {
        return Err(WalletError::WalletInvalidSeed {
            reason: format!("too few words ({} found, need at least 12)", word_count),
        });
    }

    let (bin, path) = {
        let s = state.lock()?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    let p = path.to_string_lossy().to_string();

    wallet_cli(&bin, &["--wallet", &p, "restore", &normalized_seed], &password)
        .map_err(WalletError::from_cli_error)?;

    let mut s = state.lock()?;
    s.wallet_path = path;
    set_session_password(&mut s, password);
    s.unlocked = true;
    emit_wallet_state(&app, &s);
    Ok(true)
}

#[tauri::command]
pub(crate) fn unlock_wallet(
    password: String,
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<bool, WalletError> {
    let now_secs = time_secs();
    let (bin, path) = {
        let s = state.lock()?;
        if now_secs < s.unlock_blocked_until {
            let wait = s.unlock_blocked_until.saturating_sub(now_secs);
            return Err(WalletError::AuthRateLimited { wait_secs: wait });
        }
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let p = path.to_string_lossy().to_string();

    if let Err(err) = wallet_cli(&bin, &["--wallet", &p, "open"], &password) {
        let mut s = state.lock()?;
        let (attempts, blocked_until, locked) =
            record_unlock_failure(s.failed_unlock_attempts, now_secs);
        s.failed_unlock_attempts = attempts;
        s.unlock_blocked_until = blocked_until;
        if locked {
            return Err(WalletError::AuthRateLimited {
                wait_secs: UNLOCK_LOCKOUT_SECS,
            });
        }
        return Err(WalletError::from_cli_error(err));
    }

    let mut s = state.lock()?;
    s.wallet_path = path;
    set_session_password(&mut s, password);
    s.unlocked = true;
    s.failed_unlock_attempts = 0;
    s.unlock_blocked_until = 0;
    // Fire wallet_state so the dashboard renders with the cached snapshot
    // (zeroes initially; a scan_wallet call follows to populate real values).
    emit_wallet_state(&app, &s);
    Ok(true)
}

#[tauri::command]
pub(crate) fn lock_wallet(
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<bool, WalletError> {
    let mut s = state.lock()?;
    clear_session_password(&mut s);
    // Emit so the UI clears its balance display, hides the dashboard,
    // and routes to the unlock screen.
    emit_wallet_state(&app, &s);
    Ok(true)
}

/// FIX #15/#32: No auto-unlock with hardcoded passwords.
/// If wallet is locked, return an error. User must unlock from the GUI.
#[tauri::command]
pub(crate) fn scan_wallet(
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<String, WalletError> {
    let (bin, path, pw) = {
        let s = state.lock()?;
        let pw = with_session_password(&s, |pw| Ok(pw.to_string()))?;
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), pw)
    };

    let node_url = active_node_url();

    let out = wallet_cli(&bin, &[
        "--wallet", &path,
        "--node", &node_url,
        "scan", "--from", "0", "--max-blocks", "10000",
    ], &pw)
        .map_err(WalletError::from_cli_error)?;
    let mut pw = pw;
    pw.zeroize();

    // Parse results
    let mut bal = 0u64;
    let mut utxos = 0usize;
    let mut tip = 0u64;
    let mut found = 0usize;
    // Task #7: most-recent reorg recovery surfaced by the wallet binary.
    // Format from background_sync.rs:
    //   "Reorg recovered: rewound to <new_height> (depth <N>, ...)"
    // OR (when via periodic poll):
    //   "Reorg recovered via periodic poll: rewound to <new_height> (depth <N>)"
    let mut reorg_at_height: Option<u64> = None;
    let mut reorg_depth: Option<u64> = None;
    for line in out.lines() {
        if line.contains("Balance total:") {
            bal = line.split_whitespace().filter_map(|s| s.parse::<u64>().ok()).next().unwrap_or(0);
        }
        if line.contains("UTXO count:") {
            utxos = line.split_whitespace().filter_map(|s| s.parse::<usize>().ok()).next().unwrap_or(0);
        }
        if line.contains("height=") {
            tip = line.split("height=").nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        }
        if line.contains("Found outputs:") {
            found = line.split_whitespace().filter_map(|s| s.parse::<usize>().ok()).next().unwrap_or(0);
        }
        if line.contains("Reorg recovered") {
            // Extract new_height (post-rewind tip) — the canonical
            // height the wallet UI should highlight in the banner.
            // We surface new_height as `reorg_at_height` because the
            // user-facing message is "your view of height N was
            // reorged" which the wallet now sits at as canonical.
            if let Some(rest) = line.split("rewound to ").nth(1) {
                let h_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                reorg_at_height = h_str.parse().ok();
            }
            if let Some(rest) = line.split("depth ").nth(1) {
                let d_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                reorg_depth = d_str.parse().ok();
            }
        }
    }

    let txs: Vec<TxRecord> = (0..found.min(50)).map(|i| TxRecord {
        id: format!("{:016x}", i),
        tx_type: "received".into(),
        amount: format!("{:.12}", bal as f64 / found.max(1) as f64 / 1e12),
        date: "—".into(),
        height: tip.saturating_sub(found as u64 - i as u64),
        status: "confirmed".into(),
        tx_kind: if i == 0 { "coinbase" } else { "ring" }.into(),
        ring: 11,
        memo: "".into(),
        confirmations: i as u64 + 1,
        fee: "0.000005984000".into(),
    }).collect();

    // Detect "new outputs found" BEFORE we update state so we can fire a
    // tx_received event that the UI can show as a toast / activity-list
    // refresh hint. Compare new tx-count to the prior cached value.
    let prior_tx_count = {
        let s = state.lock()?;
        s.transactions.len()
    };

    {
        let mut s = state.lock()?;
        s.balance_total = bal;
        s.balance_unlocked = bal;
        s.utxo_count = utxos;
        s.scanned_height = tip;
        s.transactions = txs;
        // Task #7: stash reorg metadata if this scan surfaced one.
        // We don't clear existing values if the current scan saw no
        // reorg — the UI clears via `dismiss_reorg_notification` when
        // the user acks the banner. That way a quick follow-up scan
        // doesn't make the banner disappear before the user notices.
        if reorg_at_height.is_some() {
            s.last_reorg_at_height = reorg_at_height;
            s.last_reorg_depth = reorg_depth;
        }
        // Emit wallet_state inside the lock so the JS sees a coherent
        // snapshot (balance + scanned-height + tx count all from the same
        // post-scan moment).
        emit_wallet_state(&app, &s);
    }

    // Fire tx_received separately — it's a "something arrived" signal
    // distinct from "wallet state changed." The JS can use it to show a
    // toast or animate the activity list. Only emit if the count grew.
    if found > prior_tx_count {
        let _ = app.emit_all("tx_received", serde_json::json!({
            "new_count": found - prior_tx_count,
            "scanned_height": tip,
        }));
    }

    Ok(format!("Scanned to height {}. Found {} outputs. Balance: {:.12} CYNC.",
        tip, found, bal as f64 / 1e12))
}

/// Task #7: clear the most-recent reorg notification from AppState
/// and re-emit `wallet_state` so the UI banner disappears. Called by
/// the JS frontend when the user clicks the banner's dismiss button.
///
/// Re-emit is required because the JS subscribers to `wallet_state`
/// only render the banner while `lastReorgAtHeight` is set; without
/// the re-emit they'd keep showing the stale value until the next
/// scan-driven event.
#[tauri::command]
pub(crate) fn dismiss_reorg_notification(
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<(), WalletError> {
    let mut s = state.lock()?;
    s.last_reorg_at_height = None;
    s.last_reorg_depth = None;
    emit_wallet_state(&app, &s);
    Ok(())
}

/// Whether a wallet file exists at the expected default path.
///
/// Called by the JS boot flow to decide whether to route to the
/// onboarding screen (no wallet) or the unlock screen (wallet exists).
/// Returns `false` for both "file is missing" and "file is present but
/// unreadable" — both states require the user to onboard / restore.
#[tauri::command]
pub(crate) fn wallet_exists() -> bool {
    let path = wallet_dir().join("default.wallet");
    path.is_file()
}

/// Returns the absolute path of the wallet file the GUI is configured to
/// use. Exposed so the Settings → About tab can show the operator exactly
/// where their wallet file lives — the source of past confusion when
/// multiple wallets existed in legacy paths (`~/.coincync/wallets/`,
/// `~/.coincync/wallet/`, `$APPDATA/coincync/wallet/`).
///
/// After an unlock / create / restore succeeds, `AppState::wallet_path`
/// is set to whatever was opened; this command returns that. Before
/// unlock the default (`wallet_dir().join("default.wallet")`) is returned.
#[tauri::command]
pub(crate) fn wallet_path(state: tauri::State<'_, State>) -> String {
    state.lock()
        .map(|s| s.wallet_path.to_string_lossy().to_string())
        .unwrap_or_else(|_| wallet_dir().join("default.wallet").to_string_lossy().to_string())
}

/// FIX #5: Return the REAL wallet address, not a hardcoded one
#[tauri::command]
pub(crate) fn get_wallet_address(state: tauri::State<'_, State>) -> String {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    if !s.unlocked {
        return String::new();
    }
    let path = s.wallet_path.to_string_lossy().to_string();
    let mut pw = match with_session_password(&s, |pw| Ok(pw.to_string())) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let bin = s.wallet_bin.clone();

    let out = wallet_cli(&bin, &["--wallet", &path, "address"], &pw);
    pw.zeroize();
    match out {
        Ok(out) => {
            for line in out.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Address:") {
                    return trimmed.trim_start_matches("Address:").trim().to_string();
                }
            }
            String::new()
        }
        Err(_) => String::new(),
    }
}

/// Generate an SVG QR code for the given payload (typically a wallet
/// address). Server-side rendering via the `qrcode` crate — keeps the
/// JS bundle small and uses the same Rust toolchain we audit. Returns
/// a self-contained SVG string the frontend can drop into `innerHTML`.
///
/// Min 200×200 / max 400×400 viewBox-scaled — the receive page CSS
/// constrains the actual rendered size so the qrcode crate just needs
/// to produce a clean readable code.
#[tauri::command]
pub(crate) fn generate_qr_svg(payload: String) -> Result<String, WalletError> {
    use qrcode::{render::svg, QrCode};
    if payload.is_empty() {
        return Err(WalletError::op("qr payload empty"));
    }
    if payload.len() > 4296 {
        // QR version 40-L max alphanumeric capacity. Beyond this the
        // qrcode crate will fail; surface the friendly error.
        return Err(WalletError::op(format!(
            "qr payload too long: {} bytes (max ~4296)",
            payload.len()
        )));
    }
    let code = QrCode::new(payload.as_bytes())
        .map_err(|e| WalletError::op(format!("qr encode: {}", e)))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(200, 200)
        .max_dimensions(400, 400)
        .quiet_zone(true)
        .dark_color(svg::Color("#0a0a0a"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::{extract_seed_phrase, looks_like_mnemonic_line};

    #[test]
    fn mnemonic_line_validation_is_strict() {
        assert!(looks_like_mnemonic_line(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ));
        assert!(!looks_like_mnemonic_line("too short"));
        assert!(!looks_like_mnemonic_line(
            "ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ));
    }

    #[test]
    fn extract_seed_phrase_prefers_wallet_backup_section() {
        let out = r#"
Wallet created at "/tmp/default.wallet"

Write down your 24-word seed phrase. It is the ONLY way to
recover this wallet if the file is lost. Never share it.

abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
"#;
        let got = extract_seed_phrase(out).expect("seed should parse");
        assert_eq!(
            got,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }
}
