#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

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
    /// Task #7: most-recent chain-reorg detection height + depth. The
    /// wallet binary's scan output surfaces a `Reorg recovered:` line
    /// when its background_sync layer applies a recovery; the Tauri
    /// wrapper parses that line and stashes the values here. The UI
    /// reads them via the `wallet_state` event and renders a banner
    /// (Task #8). Cleared via `dismiss_reorg_notification`.
    last_reorg_at_height: Option<u64>,
    last_reorg_depth: Option<u64>,
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

fn with_session_password<T, F>(state: &AppState, f: F) -> Result<T, WalletError>
where
    F: FnOnce(&str) -> Result<T, WalletError>,
{
    if !state.unlocked {
        return Err(WalletError::WalletLocked);
    }
    let Some(password) = state.password.as_ref() else {
        return Err(WalletError::SessionMissing);
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

    // Current testnet fleet (2026-06-06 rewrite — the previous list
    // referenced DO + dead-LON boxes that no longer exist).
    let seeds = [
        "66.135.23.193",   // seed1 — New York
        "140.82.57.168",   // seed2 — Amsterdam
        "207.148.6.50",    // explorer — Dallas
        "207.148.111.76",  // seed3 — Tokyo
        "95.179.165.225",  // api — Frankfurt
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

/// Typed error type for wallet operations. Serialized to the JS side
/// as `{ "code": "VARIANT_NAME", ...detail_fields }` so the frontend
/// pattern-matches on `err.code` instead of substring-matching error
/// strings (the v1 pattern, which broke whenever CLI output text shifted).
///
/// Convention:
///   - `code` is SCREAMING_SNAKE_CASE matching the variant name
///   - Variants with structured detail use named fields that serialize alongside
///
/// Example JS-side payloads:
///   - `{ code: "AUTH_INVALID_PASSWORD" }`
///   - `{ code: "AUTH_RATE_LIMITED", wait_secs: 30 }`
///   - `{ code: "WALLET_INVALID_SEED", reason: "too few words" }`
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::enum_variant_names, dead_code)]
enum WalletError {
    /// User typed the wrong password during unlock.
    AuthInvalidPassword,
    /// Too many failed unlock attempts; lockout active. `wait_secs` is
    /// the number of seconds until the next attempt is permitted.
    AuthRateLimited { wait_secs: u64 },
    /// No wallet file exists at the expected path.
    WalletNotFound,
    /// Restore path: seed phrase doesn't parse / has wrong word count.
    WalletInvalidSeed { reason: String },
    /// Wallet must be unlocked for this operation. UI should route to
    /// the unlock screen or surface "please unlock first" copy.
    WalletLocked,
    /// Wallet is marked unlocked in AppState but the session password
    /// has been zeroized — race or bug. UI should route to unlock.
    SessionMissing,
    /// Send / address-info path: target address malformed or unparseable.
    /// `reason` is operator-readable detail (e.g., "missing CYNC prefix",
    /// "missing spend key in address-info output").
    InvalidAddress { reason: String },
    /// Send path: amount string didn't parse to a positive number.
    InvalidAmount { reason: String },
    /// Create path: seed phrase couldn't be extracted from CLI output.
    /// The wallet file may have been created — operator should check the
    /// expected path before retrying (a retry with `--force` would overwrite).
    WalletSeedParseFailed,
    /// AppState mutex was poisoned (another thread panicked while holding it).
    /// Indicates a prior bug in another command. The user should restart the
    /// wallet; if it recurs, file a bug.
    LockPoisoned,
    /// CLI subprocess could not be invoked, or failed for a reason that
    /// doesn't fit the more specific variants. `msg` carries the raw
    /// error text from the wallet CLI for operator triage.
    CliFailed { msg: String },
    /// Wallet operation failed for a reason that doesn't fit other variants.
    /// Use sparingly — prefer adding a specific variant when a class of
    /// failure recurs.
    WalletOpFailed { msg: String },
}

impl WalletError {
    /// Constructor for the catch-all variant. Use when a specific variant
    /// doesn't apply (yet). If you use this twice in a row in the same
    /// area, add a specific variant instead.
    fn op(msg: impl Into<String>) -> Self {
        WalletError::WalletOpFailed { msg: msg.into() }
    }

    /// Map a CLI subprocess failure (currently a `String` error from
    /// `wallet_cli`) into the appropriate typed variant by inspecting the
    /// message. This is the boundary between v1's string-matching legacy
    /// and the typed-error future — eventually `wallet_cli` itself
    /// returns typed errors and this mapper goes away.
    fn from_cli_error(msg: String) -> Self {
        let lower = msg.to_lowercase();
        if lower.contains("password")
            || lower.contains("decrypt")
            || lower.contains("invalid")
            || lower.contains("authentication")
        {
            return WalletError::AuthInvalidPassword;
        }
        if lower.contains("not found") || lower.contains("no such file") {
            return WalletError::WalletNotFound;
        }
        WalletError::CliFailed { msg }
    }
}

impl<T> From<std::sync::PoisonError<T>> for WalletError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        WalletError::LockPoisoned
    }
}

/// Push-event payload for the chain-state poller (see `spawn_chain_state_poller`).
///
/// Emitted on the `chain_state` Tauri event whenever the polling thread
/// detects a change in any field. The JS UI subscribes once at boot and
/// updates the dashboard reactively — no need to poll via invoke().
///
/// `connected = false` is emitted when the node RPC is unreachable. That
/// lets the UI show a clear "node offline" indicator instead of stale data.
#[derive(Clone, Serialize)]
struct ChainState {
    connected: bool,
    height: u64,
    chain_height: u64,
    sync_pct: f64,
    is_synced: bool,
    peer_count: u32,
    mempool_size: u64,
}

/// Push-event payload for wallet-side state changes.
///
/// Emitted on the `wallet_state` Tauri event after any operation that
/// changes wallet-tracked state — unlock (initial values), scan
/// completion (new outputs detected), send (balance decreases).
/// Atomic units throughout — the UI divides by 10^12 to display CYNC.
///
/// `transactions_count` is the count of the cached tx records in
/// AppState; the JS UI fetches the full list via `get_transactions`
/// on history-page open.
#[derive(Clone, Serialize)]
struct WalletStateEvent {
    unlocked: bool,
    balance_total: u64,
    balance_unlocked: u64,
    utxo_count: usize,
    scanned_height: u64,
    transactions_count: usize,
    /// Task #7: most-recent reorg-recovery height. None when no reorg
    /// has been detected since unlock or since the user dismissed the
    /// banner via `dismiss_reorg_notification`.
    #[serde(rename = "lastReorgAtHeight", skip_serializing_if = "Option::is_none")]
    last_reorg_at_height: Option<u64>,
    /// Task #7: depth of the most-recent reorg in blocks. Renders in
    /// the UI banner as "Chain reorg detected at depth N — balance
    /// updated".
    #[serde(rename = "lastReorgDepth", skip_serializing_if = "Option::is_none")]
    last_reorg_depth: Option<u64>,
}

/// Emit a `wallet_state` event with the current AppState snapshot.
///
/// Called from any command that mutates wallet state (unlock, scan,
/// send, lock). Failures are logged at debug — the window may be
/// closing during emit, which is not actionable.
fn emit_wallet_state(handle: &tauri::AppHandle, s: &AppState) {
    let payload = WalletStateEvent {
        unlocked: s.unlocked,
        balance_total: s.balance_total,
        balance_unlocked: s.balance_unlocked,
        utxo_count: s.utxo_count,
        scanned_height: s.scanned_height,
        transactions_count: s.transactions.len(),
        last_reorg_at_height: s.last_reorg_at_height,
        last_reorg_depth: s.last_reorg_depth,
    };
    if let Err(e) = handle.emit_all("wallet_state", &payload) {
        tracing::debug!(error = %e, "wallet_state emit failed (window may be closing)");
    }
}

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
fn multisig_gen(params: MultisigGenParams, state: tauri::State<'_, State>) -> Result<MultisigGenResult, WalletError> {
    // Typed-error migration 2026-05-23 (recipe in
    // coincync-wallet-v2/docs/typed-errors-migration.md):
    //   - String error → WalletError variants
    //   - PoisonError → LockPoisoned via existing From impl
    //   - wallet_cli's String error → from_cli_error for the user-typo
    //     branch + WalletError::CliFailed fallback
    //   - "no shares produced" → WalletError::op (catch-all with msg)
    let bin = state.lock()?.wallet_bin.clone();
    let out = wallet_cli(&bin, &[
        "multisig-gen",
        "--threshold", &params.threshold.to_string(),
        "--total", &params.total.to_string(),
        "--output-dir", &params.output_dir,
    ], "").map_err(WalletError::from_cli_error)?;
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
struct MultisigInfoResult {
    /// Raw `multisig-info` output — share metadata. Frontend renders verbatim.
    info: String,
}

#[derive(Deserialize)]
struct MultisigInfoParams {
    share_file: String,
}

#[tauri::command]
fn multisig_info(params: MultisigInfoParams, state: tauri::State<'_, State>) -> Result<MultisigInfoResult, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let info = wallet_cli(&bin, &["multisig-info", "--share-file", &params.share_file], "")
        .map_err(WalletError::from_cli_error)?;
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
fn multisig_round1(params: MultisigRound1Params, state: tauri::State<'_, State>) -> Result<MultisigRound1Result, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let out = wallet_cli(&bin, &[
        "multisig-round1",
        "--share-file", &params.share_file,
        "--output", &params.output,
    ], "").map_err(WalletError::from_cli_error)?;
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
fn multisig_round2(params: MultisigRound2Params, state: tauri::State<'_, State>) -> Result<MultisigRound2Result, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
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
    let _out = wallet_cli(&bin, &args_ref, "").map_err(WalletError::from_cli_error)?;
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
fn multisig_aggregate(params: MultisigAggregateParams, state: tauri::State<'_, State>) -> Result<MultisigAggregateResult, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
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
    let raw = wallet_cli(&bin, &args_ref, "").map_err(WalletError::from_cli_error)?;
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
fn multisig_send(params: MultisigSendParams, state: tauri::State<'_, State>) -> Result<MultisigSendResult, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
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
    let out = wallet_cli(&bin, &args_ref, "").map_err(WalletError::from_cli_error)?;
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

#[cfg(feature = "cyncswap")]
#[derive(Deserialize)]
struct SwapInitParams {
    role: String,
    cync_amount: u64,
    btc_amount_sats: u64,
    btc_address: Option<String>,
    listen: Option<String>,
}

#[cfg(feature = "cyncswap")]
#[derive(Serialize)]
struct SwapInitResult {
    id: String,
    role: String,
    state: String,
    invite_hex: String,
}

#[cfg(feature = "cyncswap")]
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

#[cfg(feature = "cyncswap")]
#[derive(Deserialize)]
struct SwapHandshakeParams {
    invite_hex: String,
    btc_address: Option<String>,
}

#[cfg(feature = "cyncswap")]
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

#[cfg(feature = "cyncswap")]
#[derive(Deserialize)]
struct SwapIdParams { swap_id: String }

/// Determine the role of the active swap from the state file via
/// `cyncswap wallet-status`. Returns "Alice", "Bob", or an Err
/// describing why (no swap, bad path, parse failure).
#[cfg(feature = "cyncswap")]
fn active_swap_role(bin: &str) -> Result<(String, String), String> {
    let path = default_swap_state_path();
    let path_str = path.to_string_lossy().to_string();
    if !path.exists() {
        return Err(format!(
            "no active swap (state file {} does not exist). Run Setup or Handshake first.",
            path_str
        ));
    }
    let out = wallet_cli(bin, &["wallet-status", "--state-file", &path_str], "")?;
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .map_err(|e| format!("wallet-status output not JSON: {}\n---output---\n{}", e, out))?;
    let role = v
        .get("role")
        .and_then(|x| x.as_str())
        .ok_or("wallet-status missing role")?
        .to_string();
    Ok((role, path_str))
}

#[cfg(feature = "cyncswap")]
#[derive(Deserialize)]
struct SwapBroadcastParams {
    /// Operator-constructed signed tx hex. v0.1 expects the wallet
    /// operator to build + sign the tx out-of-band (via bitcoind /
    /// coincync-node CLI). A later slice will have the wallet
    /// construct + sign in-process.
    signed_tx_hex: String,
    /// "mainnet" / "testnet" / "regtest" / "signet".
    network: String,
    /// JSON-RPC endpoint for the chain we're broadcasting to.
    /// bitcoind for lock-btc/claim-btc; coincync-node for the others.
    rpc_url: String,
    /// BTC-side only: HTTP-basic auth pair for bitcoind.
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    /// CYNC-side only: bearer token for coincync-node.
    api_key: Option<String>,
}

#[cfg(feature = "cyncswap")]
#[tauri::command]
fn swap_lock(params: SwapBroadcastParams, _state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    if params.signed_tx_hex.trim().is_empty() {
        return Err("signed_tx_hex is required".into());
    }
    let bin = resolve_binary("cyncswap");
    let (role, path_str) = active_swap_role(&bin)?;

    // Dispatch to lock-cync (Alice locks CYNC) or lock-btc (Bob locks BTC).
    let signed = params.signed_tx_hex.trim().to_string();
    let out = match role.as_str() {
        "Alice" => {
            let mut args = vec![
                "lock-cync",
                "--state-file", &path_str,
                "--network", &params.network,
                "--rpc-url", &params.rpc_url,
                "--signed-tx-hex", &signed,
            ];
            let key_owned;
            if let Some(key) = &params.api_key {
                if !key.is_empty() {
                    key_owned = key.clone();
                    args.push("--api-key");
                    args.push(&key_owned);
                    return wallet_cli(&bin, &args, "")
                        .map(|out| serde_json::json!({ "output": out, "role": role }));
                }
            }
            wallet_cli(&bin, &args, "")?
        }
        "Bob" => {
            let mut args = vec![
                "lock-btc",
                "--state-file", &path_str,
                "--network", &params.network,
                "--rpc-url", &params.rpc_url,
                "--signed-tx-hex", &signed,
            ];
            let user_owned;
            let pass_owned;
            if let (Some(u), Some(p)) = (&params.rpc_user, &params.rpc_pass) {
                if !u.is_empty() && !p.is_empty() {
                    user_owned = u.clone();
                    pass_owned = p.clone();
                    args.push("--rpc-user");
                    args.push(&user_owned);
                    args.push("--rpc-pass");
                    args.push(&pass_owned);
                    return wallet_cli(&bin, &args, "")
                        .map(|out| serde_json::json!({ "output": out, "role": role }));
                }
            }
            wallet_cli(&bin, &args, "")?
        }
        other => return Err(format!("unexpected role from wallet-status: {}", other)),
    };
    Ok(serde_json::json!({ "output": out, "role": role }))
}

#[cfg(feature = "cyncswap")]
#[tauri::command]
fn swap_claim(params: SwapBroadcastParams, _state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    if params.signed_tx_hex.trim().is_empty() {
        return Err("signed_tx_hex is required".into());
    }
    let bin = resolve_binary("cyncswap");
    let (role, path_str) = active_swap_role(&bin)?;

    // Dispatch to claim-btc (Alice claims BTC) or claim-cync (Bob claims CYNC).
    let signed = params.signed_tx_hex.trim().to_string();
    let out = match role.as_str() {
        "Alice" => {
            let mut args = vec![
                "claim-btc",
                "--state-file", &path_str,
                "--network", &params.network,
                "--rpc-url", &params.rpc_url,
                "--signed-tx-hex", &signed,
            ];
            let user_owned;
            let pass_owned;
            if let (Some(u), Some(p)) = (&params.rpc_user, &params.rpc_pass) {
                if !u.is_empty() && !p.is_empty() {
                    user_owned = u.clone();
                    pass_owned = p.clone();
                    args.push("--rpc-user");
                    args.push(&user_owned);
                    args.push("--rpc-pass");
                    args.push(&pass_owned);
                    return wallet_cli(&bin, &args, "")
                        .map(|out| serde_json::json!({ "output": out, "role": role }));
                }
            }
            wallet_cli(&bin, &args, "")?
        }
        "Bob" => {
            let mut args = vec![
                "claim-cync",
                "--state-file", &path_str,
                "--network", &params.network,
                "--rpc-url", &params.rpc_url,
                "--signed-tx-hex", &signed,
            ];
            let key_owned;
            if let Some(key) = &params.api_key {
                if !key.is_empty() {
                    key_owned = key.clone();
                    args.push("--api-key");
                    args.push(&key_owned);
                    return wallet_cli(&bin, &args, "")
                        .map(|out| serde_json::json!({ "output": out, "role": role }));
                }
            }
            wallet_cli(&bin, &args, "")?
        }
        other => return Err(format!("unexpected role from wallet-status: {}", other)),
    };
    Ok(serde_json::json!({ "output": out, "role": role }))
}

#[cfg(feature = "cyncswap")]
#[tauri::command]
fn swap_abort(_params: SwapIdParams, _state: tauri::State<'_, State>) -> Result<serde_json::Value, String> {
    let bin = resolve_binary("cyncswap");
    let path = default_swap_state_path();
    let path_str = path.to_string_lossy().to_string();
    if !path.exists() {
        return Err(format!("no active swap at {}", path_str));
    }
    let out = wallet_cli(&bin, &["cancel", "--state-file", &path_str], "")?;
    Ok(serde_json::json!({ "output": out }))
}

#[cfg(feature = "cyncswap")]
#[derive(Serialize)]
struct SwapListResult { swaps: Vec<serde_json::Value> }

/// Default state-file path the cyncswap CLI uses (matches the CLI's
/// `resolve_state_path(None)` fallback). The wallet maintains exactly
/// one active swap at the default path today; multi-swap support
/// awaits a follow-up slice with a directory-iteration design.
#[cfg(feature = "cyncswap")]
fn default_swap_state_path() -> std::path::PathBuf {
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        std::path::PathBuf::from(home).join(".coincync").join("swap.json")
    } else {
        std::path::PathBuf::from("swap.json")
    }
}

#[cfg(feature = "cyncswap")]
#[tauri::command]
fn swap_list(_state: tauri::State<'_, State>) -> Result<SwapListResult, String> {
    let bin = resolve_binary("cyncswap");
    let path = default_swap_state_path();
    let path_str = path.to_string_lossy().to_string();
    // wallet-status exits 1 with "no swap state at..." when the file is
    // absent. That's the "no active swap" case — return empty rather
    // than propagating the error.
    if !path.exists() {
        return Ok(SwapListResult { swaps: Vec::new() });
    }
    match wallet_cli(&bin, &["wallet-status", "--state-file", &path_str], "") {
        Ok(out) => {
            let v: serde_json::Value = serde_json::from_str(out.trim()).map_err(|e| {
                format!("wallet-status output not JSON: {}\n---output---\n{}", e, out)
            })?;
            // Filter out terminal states from "active" — they belong in history.
            let terminal = v.get("terminal").and_then(|x| x.as_bool()).unwrap_or(false);
            if terminal {
                Ok(SwapListResult { swaps: Vec::new() })
            } else {
                Ok(SwapListResult { swaps: vec![v] })
            }
        }
        Err(_) => Ok(SwapListResult { swaps: Vec::new() }),
    }
}

#[cfg(feature = "cyncswap")]
#[tauri::command]
fn swap_history(_state: tauri::State<'_, State>) -> Result<SwapListResult, String> {
    // Mirror of swap_list but for terminal states. A future slice
    // will iterate a `~/.coincync/swap-history/` directory; today
    // the wallet only tracks one swap at a time, so history is the
    // current state file IF it's terminal, otherwise empty.
    let bin = resolve_binary("cyncswap");
    let path = default_swap_state_path();
    let path_str = path.to_string_lossy().to_string();
    if !path.exists() {
        return Ok(SwapListResult { swaps: Vec::new() });
    }
    match wallet_cli(&bin, &["wallet-status", "--state-file", &path_str], "") {
        Ok(out) => {
            let v: serde_json::Value = serde_json::from_str(out.trim()).map_err(|e| {
                format!("wallet-status output not JSON: {}\n---output---\n{}", e, out)
            })?;
            let terminal = v.get("terminal").and_then(|x| x.as_bool()).unwrap_or(false);
            if terminal {
                Ok(SwapListResult { swaps: vec![v] })
            } else {
                Ok(SwapListResult { swaps: Vec::new() })
            }
        }
        Err(_) => Ok(SwapListResult { swaps: Vec::new() }),
    }
}

// ── Mining ────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[derive(Clone)]
struct MiningStats { is_mining: bool, hashrate: f64, blocks_found: u64, threads: u32, algorithm: String }

/// Loopback port the rig binds its Prometheus /metrics endpoint to.
/// The wallet scrapes this port every monitor tick (3 s) to pull live
/// hashrate + blocks-found from the running rig subprocess. Fixed
/// rather than randomized so the wallet always knows where to look.
const RIG_METRICS_PORT: u16 = 28091;

/// Scrape the rig's /metrics endpoint and parse out the values we care
/// about. Returns `(hashrate_hps, blocks_found_total)`.
///
/// The endpoint emits Prometheus exposition format — plain text, one
/// metric per line. We only need two values, so a one-pass linear scan
/// is enough. Any failure (rig not yet bound, port collision, parse
/// fail) returns None and the caller keeps the prior cached values.
///
/// Reads via the existing `reqwest::blocking` client to avoid pulling
/// tokio into this path; the scrape runs from a `std::thread`, not the
/// Tauri runtime, so blocking I/O is fine.
fn fetch_rig_metrics() -> Option<(u64, u64)> {
    let url = format!("http://127.0.0.1:{}/metrics", RIG_METRICS_PORT);
    let body = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .ok()?
        .get(&url)
        .send()
        .ok()?
        .text()
        .ok()?;

    let mut hashrate = None;
    let mut blocks = None;
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        // Format: "metric_name value" (one space, possibly more).
        if let Some(rest) = line.strip_prefix("coincync_rig_current_hashrate_hps ") {
            hashrate = rest.trim().parse::<f64>().ok().map(|f| f as u64);
        } else if let Some(rest) = line.strip_prefix("coincync_rig_blocks_found_total ") {
            blocks = rest.trim().parse::<u64>().ok();
        }
    }
    // Even partial reads are useful — if hashrate parsed but blocks
    // didn't, we still return what we have with 0 as a placeholder.
    Some((hashrate.unwrap_or(0), blocks.unwrap_or(0)))
}

/// Emit a `mining_stats` event with the current AppState snapshot.
///
/// Called from `start_mining` (initial state), `stop_mining` (cleared
/// state), and the miner-liveness monitor thread (periodic ticks while
/// mining is on). The JS UI subscribes once at boot and updates the
/// mining-page hashrate / blocks-found displays reactively.
///
/// Hashrate is currently always 0.0 — the rig subprocess emits stats to
/// its own TUI rather than a queryable endpoint, so the wallet has no
/// way to read it back. Hooking that pipe is queued as future-work; the
/// event plumbing here is forward-compatible (when hashrate-reading
/// lands, the same event channel carries the real numbers).
fn emit_mining_stats(handle: &tauri::AppHandle, s: &AppState) {
    let stats = MiningStats {
        is_mining: s.miner_running,
        hashrate: s.miner_hashrate,
        blocks_found: s.miner_blocks,
        threads: s.miner_threads,
        algorithm: "RandomX".into(),
    };
    if let Err(e) = handle.emit_all("mining_stats", &stats) {
        tracing::debug!(error = %e, "mining_stats emit failed (window may be closing)");
    }
}

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
fn start_mining(
    address: String,
    threads: u32,
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<String, WalletError> {
    let mut s = state.lock()?;
    if s.miner_running {
        return Err(WalletError::op("Mining already running"));
    }
    if !s.unlocked {
        // Mining to an unlocked wallet's address ensures coinbase rewards
        // are spendable by the operator. Mining without unlock means we
        // can't be sure the supplied address corresponds to a key the
        // wallet can spend from — refuse at the boundary.
        return Err(WalletError::WalletLocked);
    }
    if address.is_empty() {
        return Err(WalletError::InvalidAddress {
            reason: "mining address is empty — unlock your wallet to load your address".into(),
        });
    }
    // Reject the JS-side placeholder defaulting that historically slipped
    // through. The literal string is the browser-preview mockup address
    // (see web/src/main.js); it has no spend key on any wallet, so any
    // coinbase rewards sent to it would be unspendable / lost.
    if address == "tCYNCxq8a4f1m12k7q4j5n2p3v9w6r4b2t8c1z0" {
        return Err(WalletError::InvalidAddress {
            reason: "mining address is the placeholder default; unlock your wallet to load your real address".into(),
        });
    }
    if !address.starts_with("tCYNC") && !address.starts_with("CYNC") {
        return Err(WalletError::InvalidAddress {
            reason: "mining address must start with 'tCYNC' or 'CYNC'".into(),
        });
    }

    let miner_path = resolve_binary("coincync-rig");
    let rpc_url = active_node_url(); // http://host:port

    // Expose the rig's Prometheus /metrics endpoint on a fixed loopback
    // port so the wallet's monitor thread can scrape hashrate + blocks-
    // found and surface them via the mining_stats push event.
    //
    // Bind defaults to 127.0.0.1 per the rig's `--metrics-bind` flag
    // (hardened 2026-05-21) — no listener visible off-machine, no auth
    // worry. Port 28091 is arbitrary but stable so the wallet always
    // knows where to look; a future enhancement could randomize and
    // pass it via env var to the spawned subprocess.
    let metrics_port_str = RIG_METRICS_PORT.to_string();
    let mut cmd = Command::new(&miner_path);
    cmd.args(&[
        "run-solo",
        "--node", &rpc_url,
        "--address", &address,
        "--threads", &threads.to_string(),
        "--network", "testnet",
        "--metrics-port", &metrics_port_str,
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
        .map_err(|e| WalletError::CliFailed {
            msg: format!("coincync-rig spawn failed: {}", e),
        })?;

    s.miner_process = Some(child);
    s.miner_running = true;
    s.miner_threads = threads;

    // Fire the initial mining_stats event so the UI flips into
    // "mining is on" state instantly — no wait for the first monitor tick.
    emit_mining_stats(&app, &s);

    // Monitor TUI process liveness (the TUI handles its own display).
    // Also emits periodic mining_stats so the UI stays in sync while the
    // miner runs — even at hashrate=0.0 today, the tick keeps the page
    // alive for thread count / blocks-found updates and is the channel
    // the eventual rig-stats-reader will publish hashrate on.
    let state_clone = state.inner().clone();
    let app_clone = app.clone();
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
                // Final emit so the UI flips out of "mining" state
                // immediately on subprocess death — not after the user
                // navigates to the mining page and triggers a re-fetch.
                emit_mining_stats(&app_clone, &s);
                break;
            }

            // Scrape the rig's /metrics endpoint for live hashrate +
            // blocks-found. Updates AppState IN PLACE so subsequent
            // get_mining_stats invokes also see the fresh numbers.
            // First-tick after start may return None (rig may still be
            // binding); subsequent ticks succeed. Any failure preserves
            // the prior cached values rather than zeroing them.
            //
            // Detect blocks-found increment so we can fire a one-off
            // `block_found` event the UI can attach a toast / animation
            // / auto-rescan trigger to. The mining_stats event still
            // carries the current count, but a distinct event keeps the
            // "something just arrived" signal separate from the general
            // tick.
            if let Some((hps, blocks)) = fetch_rig_metrics() {
                let mut s = state_clone.lock().unwrap();
                let prior_blocks = s.miner_blocks;
                s.miner_hashrate = hps as f64;
                s.miner_blocks = blocks;
                if blocks > prior_blocks {
                    let delta = blocks - prior_blocks;
                    drop(s); // release lock before emit
                    let _ = app_clone.emit_all("block_found", serde_json::json!({
                        "delta": delta,
                        "total": blocks,
                    }));
                }
            }

            // Periodic tick while mining is alive. Same event payload
            // as state-change emits — the UI just animates on receipt.
            let s = state_clone.lock().unwrap();
            emit_mining_stats(&app_clone, &s);
        }
    });

    Ok(format!("Mining started · {} threads · RandomX", threads))
}

#[tauri::command]
fn stop_mining(
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,
) -> Result<String, WalletError> {
    let mut s = state.lock()?;
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
    // Flip the UI out of "mining" state instantly; monitor thread will
    // exit on its next tick after seeing miner_running == false.
    emit_mining_stats(&app, &s);
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
        last_reorg_at_height: None,
        last_reorg_depth: None,
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
        .setup(|app| {
            // Background chain-state poller. Polls `get_info` every 2 s and
            // emits the `chain_state` Tauri event when any field changes.
            // The UI subscribes once at boot via `event.listen("chain_state",
            // ...)` and updates reactively — no per-component invoke() polls.
            //
            // Uses std::thread + std::thread::sleep (no tokio dependency).
            // 2 s cadence is the right balance: tight enough that the UI
            // feels alive, loose enough that the node RPC isn't hammered.
            let app_handle = app.handle();
            std::thread::spawn(move || {
                let mut last: Option<ChainState> = None;
                loop {
                    let next = match rpc_call("get_info", serde_json::json!([])) {
                        Ok(i) => {
                            let height = i["height"].as_u64().unwrap_or(0);
                            let chain_height = i["target_height"]
                                .as_u64()
                                .filter(|t| *t > height)
                                .unwrap_or(height);
                            let is_synced = i["is_synced"].as_bool().unwrap_or(false);
                            let sync_pct = if chain_height == 0 {
                                0.0
                            } else if is_synced || chain_height <= height {
                                100.0
                            } else {
                                (height as f64 / chain_height as f64) * 100.0
                            };
                            ChainState {
                                connected: true,
                                height,
                                chain_height,
                                sync_pct,
                                is_synced,
                                peer_count: i["peer_count"].as_u64().unwrap_or(0) as u32,
                                mempool_size: i["tx_pool_size"].as_u64().unwrap_or(0),
                            }
                        }
                        Err(_) => ChainState {
                            connected: false,
                            height: 0,
                            chain_height: 0,
                            sync_pct: 0.0,
                            is_synced: false,
                            peer_count: 0,
                            mempool_size: 0,
                        },
                    };

                    // Emit only on change — keeps the event stream quiet
                    // when nothing is happening, lets the UI animate
                    // transitions cleanly when something moves.
                    let changed = match &last {
                        None => true,
                        Some(prev) => {
                            prev.connected != next.connected
                                || prev.height != next.height
                                || prev.chain_height != next.chain_height
                                || prev.peer_count != next.peer_count
                                || prev.mempool_size != next.mempool_size
                                || prev.is_synced != next.is_synced
                        }
                    };
                    if changed {
                        if let Err(e) = app_handle.emit_all("chain_state", &next) {
                            tracing::debug!(error = %e, "chain_state emit failed (window may be closing)");
                        }
                        last = Some(next);
                    }

                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            });
            Ok(())
        })
        .invoke_handler({
            // Dual-list keyed on the `cyncswap` feature so v1.0 (default)
            // wallet doesn't expose the swap_* Tauri commands at all.
            // Once cyncswap clears its own audit in v1.1, build with
            // `--features cyncswap` to include them. The two arms must
            // stay in sync for the non-swap commands; only the trailing
            // swap_* block differs.
            #[cfg(feature = "cyncswap")]
            {
                tauri::generate_handler![
                    commands::wallet::get_balance, get_block_height, get_peer_count,
                    get_fee_estimate, commands::wallet::get_transactions, get_rsa_state,
                    get_network_info, commands::wallet::validate_address,
                    commands::wallet::wallet_exists, commands::wallet::wallet_path,
                    commands::wallet::create_wallet, commands::wallet::restore_wallet, commands::wallet::unlock_wallet, commands::wallet::lock_wallet, commands::wallet::scan_wallet, commands::transaction::send_transaction,
                    commands::wallet::dismiss_reorg_notification,
                    check_binaries, start_mining, stop_mining, get_mining_stats,
                    commands::wallet::get_wallet_address, commands::wallet::generate_qr_svg,
                    check_for_update,
                    multisig_gen, multisig_info, multisig_round1, multisig_round2,
                    multisig_aggregate, multisig_send,
                    swap_init, swap_handshake, swap_lock, swap_claim,
                    swap_abort, swap_list, swap_history,
                ]
            }
            #[cfg(not(feature = "cyncswap"))]
            {
                tauri::generate_handler![
                    commands::wallet::get_balance, get_block_height, get_peer_count,
                    get_fee_estimate, commands::wallet::get_transactions, get_rsa_state,
                    get_network_info, commands::wallet::validate_address,
                    commands::wallet::wallet_exists, commands::wallet::wallet_path,
                    commands::wallet::create_wallet, commands::wallet::restore_wallet, commands::wallet::unlock_wallet, commands::wallet::lock_wallet, commands::wallet::scan_wallet, commands::transaction::send_transaction,
                    commands::wallet::dismiss_reorg_notification,
                    check_binaries, start_mining, stop_mining, get_mining_stats,
                    commands::wallet::get_wallet_address, commands::wallet::generate_qr_svg,
                    check_for_update,
                    multisig_gen, multisig_info, multisig_round1, multisig_round2,
                    multisig_aggregate, multisig_send,
                ]
            }
        })
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
    use super::{record_unlock_failure, UNLOCK_LOCKOUT_SECS};

    #[test]
    fn unlock_failure_locks_after_threshold() {
        let now = 1000u64;
        let (attempts, blocked_until, locked) = record_unlock_failure(4u32, now);
        assert!(locked);
        assert_eq!(attempts, 0);
        assert_eq!(blocked_until, now + UNLOCK_LOCKOUT_SECS);
    }
}
