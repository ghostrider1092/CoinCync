#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use tauri::Manager;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::process::{Child, Command, Stdio};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
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
const MAX_UNLOCK_ATTEMPTS: u32 = 5;
const UNLOCK_LOCKOUT_SECS: u64 = 30;

/// Public testnet RPC fallback when the local node is unreachable. nginx on
/// the API host gates this so unauth'd reads (get_info, etc.) work for new
/// users who haven't generated a local bearer yet. Override with env.
const DEFAULT_PUBLIC_RPC_URL: &str = "https://api.coincync.network/rpc/testnet";

fn optional_public_https_rpc() -> Option<String> {
    let env_v = std::env::var("COINCYNC_PUBLIC_RPC_URL").ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let v = env_v.unwrap_or_else(|| DEFAULT_PUBLIC_RPC_URL.to_string());
    if !v.starts_with("https://") {
        tracing::warn!(
            "Public RPC URL must start with https:// — ignoring unsafe URL"
        );
        return None;
    }
    Some(v)
}

fn rpc_url_candidates() -> Vec<String> {
    let mut urls = vec![LOCAL_RPC_URL.to_string()];
    if let Some(u) = optional_public_https_rpc() {
        urls.push(u);
    }
    urls
}

fn rpc_key_path() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("coincync").join("rpc.key"))
}

/// Generate a fresh 64-char hex bearer key, write to $APPDATA/coincync/rpc.key.
/// Called when the file doesn't exist yet so a first-time user has a working
/// key without manual setup.
fn generate_rpc_key() -> Option<String> {
    use rand::RngCore;
    let path = rpc_key_path()?;
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("Failed to create rpc.key parent dir: {}", e);
            return None;
        }
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    if let Err(e) = std::fs::write(&path, &hex) {
        tracing::warn!("Failed to write rpc.key: {}", e);
        return None;
    }
    tracing::info!("Generated new rpc.key at {}", path.display());
    Some(hex)
}

fn rpc_bearer_value() -> Option<String> {
    if let Some(v) = std::env::var("COINCYNC_RPC_API_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()) {
        return Some(v);
    }
    // Fallback: read from $APPDATA/coincync/rpc.key so users who launch the
    // wallet from File Explorer (no env var set) can still authenticate.
    let path = rpc_key_path()?;
    if let Ok(s) = std::fs::read_to_string(&path) {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    // First launch — generate one.
    generate_rpc_key()
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
    failed_unlock_attempts: u32,
    unlock_blocked_until: u64,
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
            dir.join("binaries").join(name),
            // Tauri `bundle.resources` (see `tauri.conf.json`) — shipped installers
            dir.join("resources").join("binaries").join(format!("{}.exe", name)),
            dir.join("resources").join("binaries").join(name),
            dir.join("../Resources/binaries").join(format!("{}.exe", name)),
            dir.join("../Resources/binaries").join(name),
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

/// Workspace ships `coincync-wallet`; some dev trees used `coincync-wallet-cli`.
fn resolve_wallet_cli_binary() -> String {
    for name in ["coincync-wallet-cli", "coincync-wallet"] {
        let resolved = resolve_binary(name);
        if std::path::Path::new(&resolved).exists() {
            return resolved;
        }
    }
    resolve_binary("coincync-wallet")
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
    let mut cmd = Command::new(bin);
    cmd.args(args)
       .env("COINCYNC_WALLET_PASSWORD", password)
       .stdout(Stdio::piped()).stderr(Stdio::piped());
    // Suppress the brief console flash on Windows when GUI parent shells out
    // to a console binary.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = cmd.output()
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
        return Err("[WALLET_LOCKED] Wallet is locked".into());
    }
    let Some(password) = state.password.as_ref() else {
        return Err("[WALLET_SESSION_MISSING] Wallet session password unavailable — unlock again".into());
    };
    f(password.as_str())
}

fn record_unlock_failure(failed_unlock_attempts: u32, now_secs: u64) -> (u32, u64, bool) {
    let next = failed_unlock_attempts.saturating_add(1);
    if next >= MAX_UNLOCK_ATTEMPTS {
        (0, now_secs.saturating_add(UNLOCK_LOCKOUT_SECS), true)
    } else {
        (next, 0, false)
    }
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

    // Current testnet fleet (post-2026-05-02 redeploy). SFO excluded
    // (divergent local history); ATL demoted to seed-only.
    let seeds = [
        "45.55.32.13",     // NYC3 — active miner + landing
        "138.68.172.80",   // LON — explorer host
        "143.110.218.99",  // TOR — public API
        "165.245.161.62",  // RIC — mirror explorer
        "192.34.59.42",    // NYC1 — mempool
        "46.101.138.120",  // FRA — mempool
        "165.245.140.113", // ATL — seed
        "164.92.153.24",   // AMS — seed
        "170.64.142.146",  // SYD — relay
    ];

    let mut cmd = Command::new(&state.node_bin);
    cmd.arg("--network").arg("testnet")
       .arg("--data-dir").arg(data.to_string_lossy().as_ref())
       .arg("--rpc-bind").arg(format!("127.0.0.1:{}", DEFAULT_RPC_PORT));

    for seed in &seeds {
        cmd.arg("--addnode").arg(format!("{}:{}", seed, DEFAULT_P2P_PORT));
    }

    // Pass bearer key so the wallet's own RPC calls (and the spawned TUI
    // miner) can authenticate to this node.
    if let Some(key) = rpc_bearer_value() {
        cmd.env("COINCYNC_RPC_API_KEY", key);
    }

    cmd.stdout(Stdio::null()).stderr(Stdio::null());

    // Run the node hidden — coincync-node is a console binary, so Windows
    // would otherwise allocate a blank console window when a GUI parent
    // (the wallet) spawns it. CREATE_NO_WINDOW suppresses that.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

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
fn create_wallet(password: String, state: tauri::State<'_, State>) -> Result<String, String> {
    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    let p = path.to_string_lossy().to_string();

    let out = wallet_cli(&bin, &["--wallet", &p, "create", "--force"], &password)?;

    let Some(seed) = extract_seed_phrase(&out) else {
        return Err(
            "[WALLET_SEED_PARSE_FAILED] Wallet file may have been created, but the seed phrase could not be read from the CLI output."
                .into(),
        );
    };

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
        return Err("[WALLET_INVALID_SEED] Seed phrase appears invalid (too few words)".into());
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
    let now_secs = time_secs();
    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if now_secs < s.unlock_blocked_until {
            let wait = s.unlock_blocked_until.saturating_sub(now_secs);
            return Err(format!(
                "[AUTH_RATE_LIMITED] Too many unlock attempts. Try again in {}s.",
                wait
            ));
        }
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let p = path.to_string_lossy().to_string();

    if let Err(err) = wallet_cli(&bin, &["--wallet", &p, "open"], &password) {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        let (attempts, blocked_until, locked) =
            record_unlock_failure(s.failed_unlock_attempts, now_secs);
        s.failed_unlock_attempts = attempts;
        s.unlock_blocked_until = blocked_until;
        if locked {
            return Err(format!(
                "[AUTH_RATE_LIMITED] Too many unlock attempts. Try again in {}s.",
                UNLOCK_LOCKOUT_SECS
            ));
        }
        let lower = err.to_lowercase();
        if lower.contains("password")
            || lower.contains("decrypt")
            || lower.contains("invalid")
            || lower.contains("authentication")
        {
            return Err("[AUTH_INVALID_PASSWORD] Incorrect password".into());
        }
        if lower.contains("not found") || lower.contains("no such file") {
            return Err("[WALLET_NOT_FOUND] Wallet file not found. Restore with your seed phrase.".into());
        }
        return Err(format!("[WALLET_UNLOCK_FAILED] {}", err));
    }

    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.wallet_path = path;
    set_session_password(&mut s, password);
    s.unlocked = true;
    s.failed_unlock_attempts = 0;
    s.unlock_blocked_until = 0;
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
struct MultisigGenResult {
    /// Absolute path of each generated share file. Length = total.
    share_files: Vec<String>,
    threshold: u16,
    total: u16,
    output_dir: String,
}

#[derive(Deserialize)]
struct MultisigGenParams {
    threshold: u16,
    total: u16,
    output_dir: String,
}

#[tauri::command]
fn multisig_gen(params: MultisigGenParams, state: tauri::State<'_, State>) -> Result<MultisigGenResult, String> {
    let bin = state.lock().map_err(|e| e.to_string())?.wallet_bin.clone();
    let out = wallet_cli(&bin, &[
        "multisig-gen",
        "--threshold", &params.threshold.to_string(),
        "--total", &params.total.to_string(),
        "--output-dir", &params.output_dir,
    ], "")?;
    // CLI prints "share file: <path>" for each generated share — parse them.
    let share_files: Vec<String> = out
        .lines()
        .filter_map(|l| l.strip_prefix("share file: ").map(|s| s.trim().to_string()))
        .collect();
    if share_files.is_empty() {
        return Err(format!("multisig-gen produced no shares; CLI output:\n{}", out));
    }
    Ok(MultisigGenResult {
        share_files,
        threshold: params.threshold,
        total: params.total,
        output_dir: params.output_dir,
    })
}

#[derive(Serialize)]
struct MultisigInfoResult {
    /// Raw `multisig-info` output — share metadata. Frontend renders verbatim.
    info: String,
}

#[derive(Deserialize)]
struct MultisigInfoParams {
    share_file: String,
}

#[tauri::command]
fn multisig_info(params: MultisigInfoParams, state: tauri::State<'_, State>) -> Result<MultisigInfoResult, String> {
    let bin = state.lock().map_err(|e| e.to_string())?.wallet_bin.clone();
    let info = wallet_cli(&bin, &["multisig-info", "--share-file", &params.share_file], "")?;
    Ok(MultisigInfoResult { info })
}

#[derive(Deserialize)]
struct MultisigRound1Params {
    share_file: String,
    output: String,
}

#[derive(Serialize)]
struct MultisigRound1Result {
    /// Path the commitment was written to (input `output` echoed back for confirmation).
    commitment_file: String,
    /// Path to the secret nonce file the CLI wrote alongside the commitment.
    /// Needed for round 2 — DO NOT share with anyone.
    nonce_file: String,
}

#[tauri::command]
fn multisig_round1(params: MultisigRound1Params, state: tauri::State<'_, State>) -> Result<MultisigRound1Result, String> {
    let bin = state.lock().map_err(|e| e.to_string())?.wallet_bin.clone();
    let out = wallet_cli(&bin, &[
        "multisig-round1",
        "--share-file", &params.share_file,
        "--output", &params.output,
    ], "")?;
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
struct MultisigRound2Params {
    share_file: String,
    nonce_file: String,
    /// One path per participant's round-1 commitment (M paths for M-of-N).
    commitments: Vec<String>,
    /// Hex-encoded message to sign (typically a transaction hash).
    message: String,
    output: String,
}

#[derive(Serialize)]
struct MultisigRound2Result {
    sig_share_file: String,
}

#[tauri::command]
fn multisig_round2(params: MultisigRound2Params, state: tauri::State<'_, State>) -> Result<MultisigRound2Result, String> {
    let bin = state.lock().map_err(|e| e.to_string())?.wallet_bin.clone();
    let mut args: Vec<String> = vec![
        "multisig-round2".into(),
        "--share-file".into(), params.share_file,
        "--nonce-file".into(), params.nonce_file,
        "--message".into(), params.message,
        "--output".into(), params.output.clone(),
        "--commitments".into(),
    ];
    args.extend(params.commitments);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _out = wallet_cli(&bin, &args_ref, "")?;
    Ok(MultisigRound2Result {
        sig_share_file: params.output,
    })
}

#[derive(Deserialize)]
struct MultisigAggregateParams {
    commitments: Vec<String>,
    shares: Vec<String>,
    key_shares: Vec<String>,
    message: String,
}

#[derive(Serialize)]
struct MultisigAggregateResult {
    /// Hex-encoded aggregate signature, ready to attach to the tx.
    signature_hex: String,
    /// Raw CLI output for debugging.
    raw: String,
}

#[tauri::command]
fn multisig_aggregate(params: MultisigAggregateParams, state: tauri::State<'_, State>) -> Result<MultisigAggregateResult, String> {
    let bin = state.lock().map_err(|e| e.to_string())?.wallet_bin.clone();
    let mut args: Vec<String> = vec![
        "multisig-aggregate".into(),
        "--message".into(), params.message,
        "--commitments".into(),
    ];
    args.extend(params.commitments);
    args.push("--shares".into());
    args.extend(params.shares);
    args.push("--key-shares".into());
    args.extend(params.key_shares);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let raw = wallet_cli(&bin, &args_ref, "")?;
    let signature_hex = raw
        .lines()
        .find_map(|l| l.strip_prefix("signature: ").map(|s| s.trim().to_string()))
        .unwrap_or_default();
    Ok(MultisigAggregateResult { signature_hex, raw })
}

#[derive(Deserialize)]
struct MultisigSendParams {
    /// Paths to M key share files (minimum threshold count).
    key_shares: Vec<String>,
    to_spend: String,
    to_view: String,
    /// Amount in atomic units (1e12 atomic = 1 CYNC).
    amount: u64,
}

#[derive(Serialize)]
struct MultisigSendResult {
    txid: String,
    status: String,
}

#[tauri::command]
fn multisig_send(params: MultisigSendParams, state: tauri::State<'_, State>) -> Result<MultisigSendResult, String> {
    let bin = state.lock().map_err(|e| e.to_string())?.wallet_bin.clone();
    let node_url = active_node_url();
    let amount_str = params.amount.to_string();
    let mut args: Vec<String> = vec![
        "--node".into(), node_url,
        "multisig-send".into(),
        "--to-spend".into(), params.to_spend,
        "--to-view".into(), params.to_view,
        "--amount".into(), amount_str,
        "--key-shares".into(),
    ];
    args.extend(params.key_shares);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = wallet_cli(&bin, &args_ref, "")?;
    let txid = out.lines()
        .find_map(|l| l.strip_prefix("Hash: ").map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "submitted".to_string());
    Ok(MultisigSendResult { txid, status: "accepted".into() })
}

// ── Atomic Swap (cyncswap / CIP-001) ──────────────────────────────────
//
// Shells out to the `cyncswap` CLI binary. The CLI has granular
// subcommands (lock-cync, lock-btc, btc-claim, etc.); these wallet
// commands expose a higher-level wizard flow to the UI. The current
// scaffold returns a "wiring-pending" error so the UI surfaces
// exactly which CLI plumbing remains to be wired (the cyncswap CLI
// needs a few thin "init / handshake / lock / claim / list / history"
// wrapper subcommands added on its end before this works end-to-end).
//
// Once those land, replace the `Err(...)` returns with `wallet_cli`
// invocations following the multisig_gen pattern above.

#[derive(Deserialize)]
struct SwapInitParams {
    role: String,
    cync_amount: u64,
    btc_amount_sats: u64,
    btc_address: Option<String>,
    listen: Option<String>,
}

#[derive(Serialize)]
struct SwapInitResult {
    id: String,
    role: String,
    state: String,
    invite_hex: String,
}

#[tauri::command]
fn swap_init(params: SwapInitParams, _state: tauri::State<'_, State>) -> Result<SwapInitResult, String> {
    if params.role != "alice" {
        // Bob's join flow runs through swap_handshake (paste invite +
        // call wallet-init-bob). swap_init is Alice-only.
        return Err(format!(
            "swap_init currently supports role=alice only; got role={}. \
             For role=bob, use the Handshake tab and paste your counterparty's invite.",
            params.role
        ));
    }
    if params.cync_amount == 0 {
        return Err("cync_amount must be > 0".into());
    }
    if params.btc_amount_sats == 0 {
        return Err("btc_amount_sats must be > 0".into());
    }

    let bin = resolve_binary("cyncswap");
    // Default the listen address for v0.1 (the actual coordinator
    // listening lands in a later slice; the value is recorded in the
    // state file and the invite blob only at this step).
    let listen = params.listen.unwrap_or_else(|| "127.0.0.1:9000".into());
    let cync_amount_s = params.cync_amount.to_string();
    let btc_amount_s = params.btc_amount_sats.to_string();

    let mut args = vec![
        "wallet-init-alice",
        "--listen", &listen,
        "--cync-amount", &cync_amount_s,
        "--btc-amount-sats", &btc_amount_s,
    ];
    if let Some(addr) = &params.btc_address {
        if !addr.is_empty() {
            args.push("--bob-btc-address");
            args.push(addr);
        }
    }
    let out = wallet_cli(&bin, &args, "")?;
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .map_err(|e| format!("cyncswap output not JSON: {}\n---output---\n{}", e, out))?;

    Ok(SwapInitResult {
        id: v.get("swap_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        role: v.get("role").and_then(|x| x.as_str()).unwrap_or("alice").to_string(),
        state: v.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        invite_hex: v.get("invite_hex").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

#[derive(Deserialize)]
struct SwapHandshakeParams {
    invite_hex: String,
    btc_address: Option<String>,
}

#[tauri::command]
fn swap_handshake(params: SwapHandshakeParams, _state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    if params.invite_hex.trim().is_empty() {
        return Err("invite_hex is required".into());
    }
    let bin = resolve_binary("cyncswap");
    let mut args = vec![
        "wallet-init-bob",
        "--invite-hex", params.invite_hex.trim(),
    ];
    if let Some(addr) = &params.btc_address {
        if !addr.is_empty() {
            args.push("--bob-btc-address");
            args.push(addr);
        }
    }
    let out = wallet_cli(&bin, &args, "")?;
    serde_json::from_str(out.trim())
        .map_err(|e| format!("cyncswap output not JSON: {}\n---output---\n{}", e, out))
}

#[derive(Deserialize)]
struct SwapIdParams { swap_id: String }

#[tauri::command]
fn swap_lock(_params: SwapIdParams, _state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    Err("swap_lock: pending cyncswap CLI orchestration (calls lock-btc or lock-cync depending on role).".into())
}

#[tauri::command]
fn swap_claim(_params: SwapIdParams, _state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    Err("swap_claim: pending cyncswap CLI orchestration (calls btc-claim or cync-claim depending on role).".into())
}

#[tauri::command]
fn swap_abort(_params: SwapIdParams, _state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    Err("swap_abort: pending. Pre-lock abort writes Aborted state; post-lock requires waiting for the CSV refund.".into())
}

#[derive(Serialize)]
struct SwapListResult { swaps: Vec<serde_json::Value> }

#[tauri::command]
fn swap_list(_state: tauri::State<'_, State>) -> Result<SwapListResult, String> {
    // Empty by design until the state-file directory iteration lands.
    Ok(SwapListResult { swaps: Vec::new() })
}

#[tauri::command]
fn swap_history(_state: tauri::State<'_, State>) -> Result<SwapListResult, String> {
    // Empty by design until the state-file directory iteration lands.
    Ok(SwapListResult { swaps: Vec::new() })
}

// ── Mining ────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct MiningStats { is_mining: bool, hashrate: f64, blocks_found: u64, threads: u32, algorithm: String }

#[tauri::command]
fn check_binaries(state: tauri::State<'_, State>) -> serde_json::Value {
    let s = state.lock().unwrap();
    let node_found = std::path::Path::new(&s.node_bin).exists() || find_binary("coincync-node").is_some();
    let wallet_found = std::path::Path::new(&s.wallet_bin).exists()
        || find_binary("coincync-wallet-cli").is_some()
        || find_binary("coincync-wallet").is_some();
    let miner_found = std::path::Path::new(&s.miner_bin).exists() || find_binary("coincync-rig").is_some();

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

/// Launch the coincync-rig solo miner in its own console window.
/// rig is the canonical retail miner — clean-room implementation, no
/// donation/telemetry, structured tracing-style log output (the user can
/// watch hashrate / accepted blocks scroll by in the spawned console).
#[tauri::command]
fn start_mining(address: String, threads: u32, state: tauri::State<'_, State>) -> Result<String, String> {
    let mut s = state.lock().map_err(|e| e.to_string())?;
    if s.miner_running { return Err("Already mining".into()); }
    if !address.starts_with("tCYNC") && !address.starts_with("CYNC") {
        return Err("Invalid address".into());
    }

    let miner_path = resolve_binary("coincync-rig");
    let rpc_url = active_node_url(); // http://host:port

    let mut cmd = Command::new(&miner_path);
    cmd.args(&[
        "run-solo",
        "--node", &rpc_url,
        "--address", &address,
        "--threads", &threads.to_string(),
        "--network", "testnet",
    ]);

    // Propagate the RPC bearer so rig can authenticate to a node that
    // requires it. coincync-rig reads this env var via clap's env binding
    // on --api-key — no need to pass it as a CLI arg.
    if let Some(key) = rpc_bearer_value() {
        cmd.env("COINCYNC_RPC_API_KEY", key);
    }

    // Open rig in its own console window so the user sees the live tracing
    // log (hashrate, accepted blocks, reconnect events). CREATE_NEW_CONSOLE
    // attaches fresh stdout/stderr handles; do NOT override those with
    // Stdio::null or the user gets a blank console.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x00000010); // CREATE_NEW_CONSOLE
    }

    let child = cmd.spawn()
        .map_err(|e| format!("coincync-rig failed: {}", e))?;

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
            use std::os::windows::process::CommandExt;
            let _ = Command::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
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
// ═══════════════════════════════════════════════════════════════════════
// Update check (CIP / Monero posture)
//
// Privacy: this command is user-invoked only — the frontend gates the
// call behind a Settings toggle that defaults to OFF, with a privacy
// warning on opt-in. For a privacy coin, an automatic startup
// phone-home to `api.github.com` from every wallet IP would leak
// "a CoinCync wallet is starting up here" to GitHub and any on-path
// observer on every launch. Mirrors `coincync-node check-update`.
// ═══════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct UpdateInfo {
    current: String,
    latest: String,
    tag: String,
    name: String,
    url: String,
    available: bool,
    prerelease: bool,
    /// `Some` carries a network/parse error message; `None` means the
    /// check succeeded. The frontend only surfaces `available` when
    /// `error` is `None`.
    error: Option<String>,
}

#[tauri::command]
fn check_for_update() -> UpdateInfo {
    const REPO: &str = "ghostrider1092/Coincync-Testnet-";
    let current = env!("CARGO_PKG_VERSION").to_string();

    let mut info = UpdateInfo {
        current: current.clone(),
        latest: String::new(),
        tag: String::new(),
        name: String::new(),
        url: String::new(),
        available: false,
        prerelease: false,
        error: None,
    };

    let client = match reqwest::blocking::Client::builder()
        .user_agent(format!("coincync-wallet/{}", current))
        .timeout(std::time::Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            info.error = Some(format!("HTTP client build failed: {}", e));
            return info;
        }
    };

    // `/releases/latest` returns the most recent NON-prerelease (the
    // "Latest"-badged one). All CoinCync releases are currently
    // prerelease, so that endpoint 404s — fall back to the most recent
    // release including prereleases.
    let latest_url = format!("https://api.github.com/repos/{}/releases/latest", REPO);
    let recent_url = format!("https://api.github.com/repos/{}/releases?per_page=1", REPO);

    let release = match client
        .get(&latest_url)
        .header("Accept", "application/vnd.github+json")
        .send()
    {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>() {
                Ok(v) => extract_release(&v),
                Err(e) => {
                    info.error = Some(format!("parse failed: {}", e));
                    return info;
                }
            }
        }
        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
            match client
                .get(&recent_url)
                .header("Accept", "application/vnd.github+json")
                .send()
            {
                Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>() {
                    Ok(serde_json::Value::Array(arr)) => arr.first().and_then(extract_release),
                    Ok(_) => None,
                    Err(e) => {
                        info.error = Some(format!("parse failed: {}", e));
                        return info;
                    }
                },
                Ok(r) => {
                    info.error = Some(format!("GitHub returned {}", r.status()));
                    return info;
                }
                Err(e) => {
                    info.error = Some(format!("network error: {}", e));
                    return info;
                }
            }
        }
        Ok(resp) => {
            info.error = Some(format!("GitHub returned {}", resp.status()));
            return info;
        }
        Err(e) => {
            info.error = Some(format!("network error: {}", e));
            return info;
        }
    };

    match release {
        Some((tag, name, url, is_pre)) => {
            // Normalise: strip leading `v` and anything after the first
            // `-` (e.g. `v1.0.7-testnet` → `1.0.7`). Plain string
            // equality is enough for "is the release different from
            // mine"; semver-aware compare can land later if needed.
            let latest_clean: String = tag
                .trim_start_matches('v')
                .split('-')
                .next()
                .unwrap_or(&tag)
                .to_string();
            info.available = current != latest_clean;
            info.latest = latest_clean;
            info.tag = tag;
            info.name = name;
            info.url = url;
            info.prerelease = is_pre;
            info
        }
        None => {
            info.error = Some("could not determine the latest release".into());
            info
        }
    }
}

/// Pull `(tag_name, name, html_url, prerelease)` out of a release JSON
/// object. Returns `None` if any of the load-bearing fields is missing
/// or the wrong type — better to fail closed than to render garbage.
fn extract_release(v: &serde_json::Value) -> Option<(String, String, String, bool)> {
    let tag = v.get("tag_name")?.as_str()?.to_string();
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or(&tag).to_string();
    let url = v.get("html_url").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let is_pre = v.get("prerelease").and_then(|x| x.as_bool()).unwrap_or(false);
    Some((tag, name, url, is_pre))
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
    let wallet_bin = resolve_wallet_cli_binary();
    let miner_bin = resolve_binary("coincync-rig");
    let dd = data_dir();

    tracing::info!("CoinCync Wallet starting...");
    tracing::info!("  Node binary:   {}", node_bin);
    tracing::info!("  Wallet binary: {}", wallet_bin);
    tracing::info!("  Miner:         {}", miner_bin);
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
        failed_unlock_attempts: 0,
        unlock_blocked_until: 0,
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
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            get_balance, get_block_height, get_peer_count,
            get_fee_estimate, get_transactions, get_rsa_state,
            get_network_info, validate_address,
            create_wallet, restore_wallet, unlock_wallet, lock_wallet, scan_wallet, send_transaction,
            check_binaries, start_mining, stop_mining, get_mining_stats,
            get_wallet_address,
            check_for_update,
            multisig_gen, multisig_info, multisig_round1, multisig_round2,
            multisig_aggregate, multisig_send,
            swap_init, swap_handshake, swap_lock, swap_claim,
            swap_abort, swap_list, swap_history,
        ])
        .on_window_event(move |event| {
            if let tauri::WindowEvent::Destroyed = event.event() {
                tracing::info!("Shutting down...");
                if let Ok(mut s) = state_for_shutdown.lock() {
                    clear_session_password(&mut s);
                    // Stop the spawned local node so it doesn't outlive the
                    // wallet window. Best-effort; ignore errors on already-dead
                    // children.
                    if let Some(mut child) = s.node_process.take() {
                        let _ = child.kill();
                        let _ = child.wait();
                        tracing::info!("Stopped spawned local node");
                    }
                    if let Some(mut child) = s.miner_process.take() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error running CoinCync wallet");
}

#[cfg(test)]
mod tests {
    use super::{extract_seed_phrase, looks_like_mnemonic_line, record_unlock_failure, UNLOCK_LOCKOUT_SECS};

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

    #[test]
    fn unlock_failure_locks_after_threshold() {
        let now = 1000u64;
        let (attempts, blocked_until, locked) = record_unlock_failure(4u32, now);
        assert!(locked);
        assert_eq!(attempts, 0);
        assert_eq!(blocked_until, now + UNLOCK_LOCKOUT_SECS);
    }
}
