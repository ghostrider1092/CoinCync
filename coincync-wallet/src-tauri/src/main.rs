#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::process::{Child, Command, Stdio};
use std::path::PathBuf;
use zeroize::Zeroize;

// ═══════════════════════════════════════════════════════════════════════
// Node RPC connection
//
// Local node first. Optional public RPC only via `COINCYNC_PUBLIC_RPC_URL`
// (must be `https://…`) — never ship a hardcoded cleartext remote endpoint.
// Optional `COINCYNC_RPC_API_KEY` sends `Authorization: Bearer …` when set.
// ═══════════════════════════════════════════════════════════════════════

const LOCAL_RPC_URL: &str = "http://127.0.0.1:28081";
const DEFAULT_RPC_PORT: u16 = 28081;
const DEFAULT_P2P_PORT: u16 = 28080;

fn optional_public_https_rpc() -> Option<String> {
    let v = std::env::var("COINCYNC_PUBLIC_RPC_URL").ok()?;
    let t = v.trim().to_string();
    if t.is_empty() {
        return None;
    }
    if !t.starts_with("https://") {
        tracing::warn!(
            "COINCYNC_PUBLIC_RPC_URL must start with https:// — ignoring unsafe URL"
        );
        return None;
    }
    Some(t)
}

fn rpc_url_candidates() -> Vec<String> {
    let mut urls = vec![LOCAL_RPC_URL.to_string()];
    if let Some(u) = optional_public_https_rpc() {
        urls.push(u);
    }
    urls
}

fn rpc_bearer_value() -> Option<String> {
    std::env::var("COINCYNC_RPC_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ═══════════════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════════════

struct AppState {
    wallet_path: PathBuf,
    /// Session password kept only while wallet is unlocked.
    /// Zeroized on replacement/clear and on process exit.
    password: Option<String>,
    balance_total: u64,
    balance_unlocked: u64,
    utxo_count: usize,
    scanned_height: u64,
    transactions: Vec<TxRecord>,
    unlocked: bool,
    node_bin: String,
    wallet_bin: String,
    miner_bin: String,
    node_process: Option<Child>,
    miner_process: Option<Child>,
    miner_running: bool,
    miner_hashrate: f64,
    miner_blocks: u64,
    miner_threads: u32,
    data_dir: PathBuf,
    /// Which RPC URL is currently working (cached after first successful call)
    active_rpc: Option<String>,
}

#[derive(Clone, Serialize)]
struct TxRecord {
    id: String,
    #[serde(rename = "type")]
    tx_type: String,
    amount: String,
    date: String,
    height: u64,
    status: String,
    #[serde(rename = "txType")]
    tx_kind: String,
    ring: u32,
    memo: String,
    confirmations: u64,
    fee: String,
}

type State = Arc<Mutex<AppState>>;

// ═══════════════════════════════════════════════════════════════════════
// Binary resolution
// ═══════════════════════════════════════════════════════════════════════

fn resolve_binary(name: &str) -> String {
    let exe_dir = std::env::current_exe().ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()));

    if let Some(dir) = &exe_dir {
        let candidates = vec![
            dir.join(format!("{}.exe", name)),
            dir.join(name),
            dir.join("binaries").join(format!("{}.exe", name)),
            dir.join("../../../target/release").join(format!("{}.exe", name)),
            dir.join("../../target/release").join(format!("{}.exe", name)),
            dir.join("../../../../target/release").join(format!("{}.exe", name)),
            dir.join("../Resources").join(name),
            dir.join("../lib").join(name),
        ];

        for path in &candidates {
            if let Ok(canonical) = path.canonicalize() {
                tracing::info!("Found binary '{}' at: {}", name, canonical.display());
                return canonical.to_string_lossy().to_string();
            }
        }
    }

    tracing::warn!("Binary '{}' not found in app directory, trying PATH", name);
    name.to_string()
}

fn data_dir() -> PathBuf {
    dirs_next::data_dir()
        .unwrap_or_else(|| dirs_next::home_dir().unwrap_or_else(|| PathBuf::from(".")))
        .join("coincync")
}

/// FIX #27: Single wallet directory used by BOTH GUI and CLI.
/// Always ~/.coincync/wallets/default.wallet
fn wallet_dir() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".coincync")
        .join("wallets")
}

// ═══════════════════════════════════════════════════════════════════════
// RPC client — FIX #6/#28: local first, remote fallback
// ═══════════════════════════════════════════════════════════════════════

fn rpc_call(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build().map_err(|e| e.to_string())?;

    let urls = rpc_url_candidates();
    let mut last_err = String::new();

    for url in &urls {
        let mut req = client.post(url).json(&body);
        if let Some(ref key) = rpc_bearer_value() {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        match req.send() {
            Ok(resp) => {
                match resp.json::<serde_json::Value>() {
                    Ok(json) => {
                        if let Some(err) = json.get("error") {
                            last_err = format!("RPC error: {}", err);
                            continue;
                        }
                        return Ok(json["result"].clone());
                    }
                    Err(e) => { last_err = e.to_string(); continue; }
                }
            }
            Err(e) => { last_err = format!("{}: {}", url, e); continue; }
        }
    }

    Err(format!("Node unreachable: {}", last_err))
}

/// Get the URL of the currently reachable node (for passing to CLI tools)
fn active_node_url() -> String {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build().ok();

    if let Some(ref c) = client {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"get_info"});
        for url in rpc_url_candidates() {
            let mut req = c.post(&url).json(&body);
            if let Some(ref key) = rpc_bearer_value() {
                req = req.header("Authorization", format!("Bearer {}", key));
            }
            if req.send().and_then(|r| r.json::<serde_json::Value>()).is_ok() {
                return url;
            }
        }
    }
    LOCAL_RPC_URL.to_string()
}

/// Get the node address for the miner (host:port, NOT http://)
/// FIX #4: Miner expects host:port, not http://host:port
fn active_node_addr() -> String {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build().ok();

    if let Some(ref c) = client {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"get_info"});
        for url in rpc_url_candidates() {
            let mut req = c.post(&url).json(&body);
            if let Some(ref key) = rpc_bearer_value() {
                req = req.header("Authorization", format!("Bearer {}", key));
            }
            if req.send().and_then(|r| r.json::<serde_json::Value>()).is_ok() {
                if url.starts_with(LOCAL_RPC_URL) {
                    return format!("127.0.0.1:{}", DEFAULT_RPC_PORT);
                }
                // https://host:port/... → host:port for miner TCP bridge
                let rest = url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://");
                let host_port = rest.split('/').next().unwrap_or(rest);
                return host_port.to_string();
            }
        }
    }
    format!("127.0.0.1:{}", DEFAULT_RPC_PORT)
}

fn wallet_cli(bin: &str, args: &[&str], password: &str) -> Result<String, String> {
    let output = Command::new(bin)
        .args(args)
        .env("COINCYNC_WALLET_PASSWORD", password)
        .stdout(Stdio::piped()).stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("CLI failed: {}", e))?;
    let out = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{}{}", out, err));
    }
    Ok(out)
}

fn set_session_password(state: &mut AppState, password: String) {
    if let Some(mut old) = state.password.take() {
        old.zeroize();
    }
    state.password = Some(password);
}

fn clear_session_password(state: &mut AppState) {
    if let Some(mut old) = state.password.take() {
        old.zeroize();
    }
    state.unlocked = false;
}

fn with_session_password<T, F>(state: &AppState, f: F) -> Result<T, String>
where
    F: FnOnce(&str) -> Result<T, String>,
{
    if !state.unlocked {
        return Err("Wallet is locked".into());
    }
    let Some(password) = state.password.as_ref() else {
        return Err("Wallet session password unavailable — unlock again".into());
    };
    f(password.as_str())
}

// ═══════════════════════════════════════════════════════════════════════
// Auto-start node — FIX #30: only if no remote node available
// ═══════════════════════════════════════════════════════════════════════

fn is_local_node_running() -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build().ok();
    if let Some(c) = client {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"get_info"});
        let mut req = c.post(LOCAL_RPC_URL).json(&body);
        if let Some(ref key) = rpc_bearer_value() {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        req.send()
            .and_then(|r| r.json::<serde_json::Value>()).is_ok()
    } else { false }
}

fn is_remote_node_running() -> bool {
    let Some(ref remote) = optional_public_https_rpc() else {
        return false;
    };
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build().ok();
    if let Some(c) = client {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"get_info"});
        let mut req = c.post(remote).json(&body);
        if let Some(ref key) = rpc_bearer_value() {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        req.send()
            .and_then(|r| r.json::<serde_json::Value>()).is_ok()
    } else { false }
}

fn start_node(state: &mut AppState) -> Result<(), String> {
    if is_local_node_running() {
        tracing::info!("Local node already running");
        return Ok(());
    }

    let data = state.data_dir.join("data");
    let _ = std::fs::create_dir_all(&data);

    let seeds = [
        "45.55.32.13", "165.245.161.62", "143.110.218.99",
        "165.245.140.113", "64.227.49.44", "138.68.172.80",
    ];

    let mut cmd = Command::new(&state.node_bin);
    cmd.arg("--network").arg("testnet")
       .arg("--data-dir").arg(data.to_string_lossy().as_ref())
       .arg("--rpc-bind").arg(format!("127.0.0.1:{}", DEFAULT_RPC_PORT));

    for seed in &seeds {
        cmd.arg("--addnode").arg(format!("{}:{}", seed, DEFAULT_P2P_PORT));
    }

    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    let child = cmd.spawn()
        .map_err(|e| format!("Failed to start node: {}", e))?;

    state.node_process = Some(child);

    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if is_local_node_running() {
            return Ok(());
        }
    }

    Err("Node started but not responding after 30 seconds".into())
}

// ═══════════════════════════════════════════════════════════════════════
// Tauri commands
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct Balance { total: String, unlocked: String, locked: String }

#[tauri::command]
fn get_balance(state: tauri::State<'_, State>) -> Balance {
    let w = state.lock().unwrap();
    let t = w.balance_total as f64 / 1e12;
    let formatted = if t > 0.0 {
        format!("{:.12}", t)
    } else {
        "0.000000000000".to_string()
    };
    Balance { total: formatted.clone(), unlocked: formatted, locked: "0.000000000000".into() }
}

#[derive(Serialize)]
struct BlockInfo { height: u64, #[serde(rename="chainHeight")] chain_height: u64, #[serde(rename="syncPct")] sync_pct: f64 }

#[tauri::command]
fn get_block_height() -> BlockInfo {
    match rpc_call("get_info", serde_json::json!([])) {
        Ok(i) => BlockInfo {
            height: i["height"].as_u64().unwrap_or(0),
            chain_height: i["height"].as_u64().unwrap_or(0),
            sync_pct: if i["is_synced"].as_bool().unwrap_or(false) { 100.0 } else { 50.0 },
        },
        Err(_) => BlockInfo { height:0, chain_height:0, sync_pct:0.0 },
    }
}

#[derive(Serialize)]
struct PeerInfo { peers: u32, outbound: u32, inbound: u32 }

#[tauri::command]
fn get_peer_count() -> PeerInfo {
    match rpc_call("get_info", serde_json::json!([])) {
        Ok(i) => PeerInfo {
            peers: i["peer_count"].as_u64().unwrap_or(0) as u32,
            outbound: 0,
            inbound: i["peer_count"].as_u64().unwrap_or(0) as u32,
        },
        Err(_) => PeerInfo { peers:0, outbound:0, inbound:0 },
    }
}

/// FIX #33: Query real fee data from mempool instead of hardcoded values
#[derive(Serialize)]
struct FeeEstimate { slow: String, normal: String, fast: String, flash: String }

#[tauri::command]
fn get_fee_estimate() -> FeeEstimate {
    let f = |x: u64| format!("{:.12}", x as f64 / 1e12);

    // Try to get real fee data from mempool
    if let Ok(info) = rpc_call("get_mempool_info", serde_json::json!([])) {
        if let Some(fee_per_byte) = info.get("min_fee_per_byte").and_then(|v| v.as_u64()) {
            let base = fee_per_byte * 2400; // ~2400 byte typical tx
            return FeeEstimate {
                slow: f(base / 2),
                normal: f(base),
                fast: f(base * 2),
                flash: f(base * 4),
            };
        }
    }

    // Fallback: estimate from MIN_FEE_PER_BYTE (1000) * typical tx size (2400)
    let base = 2_400_000u64;
    FeeEstimate { slow: f(base/2), normal: f(base), fast: f(base*2), flash: f(base*4) }
}

#[tauri::command]
fn get_transactions(state: tauri::State<'_, State>) -> serde_json::Value {
    let w = state.lock().unwrap();
    serde_json::json!({ "txs": w.transactions })
}

#[tauri::command]
fn get_rsa_state() -> serde_json::Value {
    match rpc_call("get_info", serde_json::json!([])) {
        Ok(i) => serde_json::json!({
            "root": "—",
            "count": i["available_outputs"].as_u64().unwrap_or(0),
            "height": i["height"].as_u64().unwrap_or(0),
            "ivcSteps": 0,
        }),
        Err(_) => serde_json::json!({"root":"—","count":0,"height":0,"ivcSteps":0}),
    }
}

#[tauri::command]
fn get_network_info() -> serde_json::Value {
    match rpc_call("get_info", serde_json::json!([])) {
        Ok(i) => serde_json::json!({
            "version": "1.0.0",
            "network": i["network"].as_str().unwrap_or("testnet"),
            "connections": i["peer_count"].as_u64().unwrap_or(0),
        }),
        Err(_) => serde_json::json!({"version":"1.0.0","network":"starting...","connections":0}),
    }
}

#[tauri::command]
fn validate_address(address: String, state: tauri::State<'_, State>) -> serde_json::Value {
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

#[tauri::command]
fn create_wallet(password: String, state: tauri::State<'_, State>) -> Result<String, String> {
    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    let p = path.to_string_lossy().to_string();

    let out = wallet_cli(&bin, &["--wallet", &p, "create", "--force"], &password)?;

    let seed = out.lines().skip_while(|l| !l.contains("Write down")).skip(2)
        .next().unwrap_or("(check terminal)").trim().to_string();

    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.wallet_path = path;
    set_session_password(&mut s, password);
    s.unlocked = true;
    Ok(seed)
}

#[tauri::command]
fn restore_wallet(seed: String, password: String, state: tauri::State<'_, State>) -> Result<String, String> {
    let normalized_seed = seed.split_whitespace().collect::<Vec<_>>().join(" ");
    let word_count = normalized_seed.split_whitespace().count();
    if word_count < 12 {
        return Err("Seed phrase appears invalid (too few words)".into());
    }

    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    let p = path.to_string_lossy().to_string();

    wallet_cli(&bin, &["--wallet", &p, "restore", &normalized_seed], &password)?;

    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.wallet_path = path;
    set_session_password(&mut s, password);
    s.unlocked = true;
    Ok("Wallet restored".into())
}

#[tauri::command]
fn unlock_wallet(password: String, state: tauri::State<'_, State>) -> Result<String, String> {
    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let p = path.to_string_lossy().to_string();

    wallet_cli(&bin, &["--wallet", &p, "open"], &password)?;

    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.wallet_path = path;
    set_session_password(&mut s, password);
    s.unlocked = true;
    Ok("Wallet unlocked".into())
}

#[tauri::command]
fn lock_wallet(state: tauri::State<'_, State>) -> Result<String, String> {
    let mut s = state.lock().map_err(|e| e.to_string())?;
    clear_session_password(&mut s);
    Ok("Wallet locked".into())
}

/// FIX #15/#32: No auto-unlock with hardcoded passwords.
/// If wallet is locked, return an error. User must unlock from the GUI.
#[tauri::command]
fn scan_wallet(state: tauri::State<'_, State>) -> Result<String, String> {
    let (bin, path, pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        let pw = with_session_password(&s, |pw| Ok(pw.to_string()))?;
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), pw)
    };

    let node_url = active_node_url();

    let out = wallet_cli(&bin, &[
        "--wallet", &path,
        "--node", &node_url,
        "scan", "--from", "0", "--max-blocks", "10000",
    ], &pw)?;
    let mut pw = pw;
    pw.zeroize();

    // Parse results
    let mut bal = 0u64;
    let mut utxos = 0usize;
    let mut tip = 0u64;
    let mut found = 0usize;
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

    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.balance_total = bal;
    s.balance_unlocked = bal;
    s.utxo_count = utxos;
    s.scanned_height = tip;
    s.transactions = txs;

    Ok(format!("Scanned to height {}. Found {} outputs. Balance: {:.12} CYNC.",
        tip, found, bal as f64 / 1e12))
}

/// FIX #35: Parse tCYNC address into spend+view keys properly
#[derive(Deserialize)]
struct SendParams { to: String, amount: String, memo: Option<String>, priority: String }

#[derive(Serialize)]
struct SendResult { txid: String, status: String }

#[tauri::command]
fn send_transaction(params: SendParams, state: tauri::State<'_, State>) -> Result<SendResult, String> {
    let (bin, path, pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        let pw = with_session_password(&s, |pw| Ok(pw.to_string()))?;
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), pw)
    };

    let amount_atomic = (params.amount.parse::<f64>().map_err(|e| format!("bad amount: {}", e))?
        * 1e12) as u64;

    let node_url = active_node_url();

    // FIX #35: Get spend and view keys from the address and fail closed if parsing fails.
    // The wallet CLI 'send' command needs --to-spend and --to-view as hex public keys.
    let (spend_hex, view_hex) = if params.to.starts_with("tCYNC") || params.to.starts_with("CYNC") {
        let info = wallet_cli(&bin, &["address-info", &params.to], "")?;
        let spend = info
            .lines()
            .find(|l| l.contains("Spend"))
            .and_then(|l| l.split_whitespace().last())
            .map(|s| s.to_string())
            .ok_or_else(|| "Address parsing failed: missing spend key".to_string())?;
        let view = info
            .lines()
            .find(|l| l.contains("View"))
            .and_then(|l| l.split_whitespace().last())
            .map(|s| s.to_string())
            .ok_or_else(|| "Address parsing failed: missing view key".to_string())?;
        (spend, view)
    } else {
        return Err("Recipient must be a valid CoinCync address".into());
    };

    let out = wallet_cli(&bin, &[
        "--wallet", &path,
        "--node", &node_url,
        "send",
        "--to-spend", &spend_hex,
        "--to-view", &view_hex,
        "--amount", &amount_atomic.to_string(),
    ], &pw)?;
    let mut pw = pw;
    pw.zeroize();

    let txid = out.lines().find(|l| l.contains("Hash:"))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("submitted").to_string();

    Ok(SendResult { txid, status: "accepted".into() })
}

// ── Mining ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct MiningStats { is_mining: bool, hashrate: f64, blocks_found: u64, threads: u32, algorithm: String }

#[tauri::command]
fn check_binaries(state: tauri::State<'_, State>) -> serde_json::Value {
    let s = state.lock().unwrap();
    let node_found = std::path::Path::new(&s.node_bin).exists() || find_binary("coincync-node").is_some();
    let wallet_found = std::path::Path::new(&s.wallet_bin).exists() || find_binary("coincync-wallet").is_some();
    let miner_found = std::path::Path::new(&s.miner_bin).exists() || find_binary("coincync-tui-miner").is_some();

    serde_json::json!({
        "node": node_found,
        "wallet_cli": wallet_found,
        "miner": miner_found,
        "all_installed": node_found && wallet_found && miner_found,
    })
}

fn find_binary(name: &str) -> Option<String> {
    let resolved = resolve_binary(name);
    let path = std::path::Path::new(&resolved);
    if path.exists() || path.canonicalize().is_ok() { Some(resolved) } else { None }
}

/// Launch the Mining TUI in its own console window.
/// The TUI internally spawns coincync-miner and displays a live dashboard.
#[tauri::command]
fn start_mining(address: String, threads: u32, state: tauri::State<'_, State>) -> Result<String, String> {
    let mut s = state.lock().map_err(|e| e.to_string())?;
    if s.miner_running { return Err("Already mining".into()); }
    if !address.starts_with("tCYNC") && !address.starts_with("CYNC") {
        return Err("Invalid address".into());
    }

    let miner_path = resolve_binary("coincync-tui-miner");
    let rpc_url = active_node_url(); // http://host:port

    let mut cmd = Command::new(&miner_path);
    cmd.args(&[
        "--testnet",
        "--address", &address,
        "--threads", &threads.to_string(),
        "--rpc", &rpc_url,
    ]);

    // Open the TUI in its own console window so the user sees the dashboard
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x00000010); // CREATE_NEW_CONSOLE
    }

    // TUI has its own terminal — don't inherit ours
    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    let child = cmd.spawn()
        .map_err(|e| format!("Miner TUI failed: {}", e))?;

    s.miner_process = Some(child);
    s.miner_running = true;
    s.miner_threads = threads;

    // Monitor TUI process liveness (the TUI handles its own display).
    let state_clone = state.inner().clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let running = {
                let s = state_clone.lock().unwrap();
                s.miner_running
            };
            if !running { break; }

            let alive = {
                let mut s = state_clone.lock().unwrap();
                if let Some(ref mut child) = s.miner_process {
                    matches!(child.try_wait(), Ok(None))
                } else { false }
            };

            if !alive {
                let mut s = state_clone.lock().unwrap();
                s.miner_running = false;
                s.miner_hashrate = 0.0;
                tracing::warn!("Miner process exited");
                break;
            }
        }
    });

    Ok(format!("Mining started · {} threads · RandomX", threads))
}

/// FIX #5: Return the REAL wallet address, not a hardcoded one
#[tauri::command]
fn get_wallet_address(state: tauri::State<'_, State>) -> String {
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

#[tauri::command]
fn stop_mining(state: tauri::State<'_, State>) -> Result<String, String> {
    let mut s = state.lock().map_err(|e| e.to_string())?;
    if let Some(ref mut c) = s.miner_process {
        // Kill the entire process tree (TUI + CLI miner subprocess)
        let pid = c.id();
        #[cfg(windows)]
        {
            let _ = Command::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(not(windows))]
        {
            let _ = c.kill();
        }
        let _ = c.wait();
    }
    s.miner_process = None;
    s.miner_running = false;
    s.miner_hashrate = 0.0;
    Ok("Mining stopped".into())
}

#[tauri::command]
fn get_mining_stats(state: tauri::State<'_, State>) -> MiningStats {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    MiningStats {
        is_mining: s.miner_running,
        hashrate: s.miner_hashrate,
        blocks_found: s.miner_blocks,
        threads: s.miner_threads,
        algorithm: "RandomX".into(),
    }
}

fn time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// FIX #30: Only auto-start local node if no remote node is reachable.
// ═══════════════════════════════════════════════════════════════════════

fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let node_bin = resolve_binary("coincync-node");
    let wallet_bin = resolve_binary("coincync-wallet-cli");
    let miner_bin = resolve_binary("coincync-tui-miner");
    let dd = data_dir();

    tracing::info!("CoinCync Wallet starting...");
    tracing::info!("  Node binary:   {}", node_bin);
    tracing::info!("  Wallet binary: {}", wallet_bin);
    tracing::info!("  Miner TUI:     {}", miner_bin);
    tracing::info!("  Data dir:      {}", dd.display());

    let state: State = Arc::new(Mutex::new(AppState {
        wallet_path: wallet_dir().join("default.wallet"),
        password: None,
        balance_total: 0,
        balance_unlocked: 0,
        utxo_count: 0,
        scanned_height: 0,
        transactions: Vec::new(),
        unlocked: false,
        node_bin,
        wallet_bin,
        miner_bin,
        node_process: None,
        miner_process: None,
        miner_running: false,
        miner_hashrate: 0.0,
        miner_blocks: 0,
        miner_threads: 1,
        data_dir: dd,
        active_rpc: None,
    }));

    // FIX #30: Check local first, then remote.
    // Only auto-start a local node if NOTHING is reachable.
    if is_local_node_running() {
        tracing::info!("Connected to local node at {}", LOCAL_RPC_URL);
    } else if is_remote_node_running() {
        if let Some(ref u) = optional_public_https_rpc() {
            tracing::info!("Connected to remote node at {}", u);
        }
        // Don't auto-start local node — remote is available
    } else {
        tracing::warn!("No node reachable — starting local node");
        let mut s = state.lock().unwrap();
        match start_node(&mut s) {
            Ok(()) => tracing::info!("Local node started"),
            Err(e) => tracing::warn!("Node auto-start failed: {}", e),
        }
    }

    let state_for_shutdown = state.clone();
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_balance, get_block_height, get_peer_count,
            get_fee_estimate, get_transactions, get_rsa_state,
            get_network_info, validate_address,
            create_wallet, restore_wallet, unlock_wallet, lock_wallet, scan_wallet, send_transaction,
            check_binaries, start_mining, stop_mining, get_mining_stats,
            get_wallet_address,
        ])
        .on_window_event(move |event| {
            if let tauri::WindowEvent::Destroyed = event.event() {
                tracing::info!("Shutting down...");
                if let Ok(mut s) = state_for_shutdown.lock() {
                    clear_session_password(&mut s);
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error running CoinCync wallet");
}
