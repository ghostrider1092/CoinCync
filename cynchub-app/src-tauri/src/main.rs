#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! CyncHub desktop backend.
//!
//! Its own code (no wallet-v2). Talks to the CoinCync network's own
//! tools — the `coincync-node` RPC and the `coincync-wallet` CLI — which
//! are the chain's binaries, bundled with CyncHub.

use serde::Serialize;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

const LOCAL_RPC: &str = "http://127.0.0.1:28081";
/// Loopback port the bundled miner publishes Prometheus metrics on, so the
/// Mining screen can read a real hashrate instead of inventing one.
const MINER_METRICS_PORT: u16 = 28092;
/// Testnet height at which the shielded (Spark) pool activates. Before this the
/// pool is empty and shield / unshield cannot be built — the UI stays honest.
const FORK_HEIGHT: u64 = 29_000;
/// Target block time (s) used to estimate network hashrate from difficulty.
const TARGET_BLOCK_SECS: f64 = 120.0;
/// Smart-mining threshold: if your expected solo time-to-block is at or under
/// this, solo is worthwhile; above it, a pool earns steadier shares.
const AUTO_SOLO_THRESHOLD_SECS: f64 = 1800.0; // 30 min

// ── state ───────────────────────────────────────────────────────────
struct AppState {
    wallet_path: PathBuf,
    /// Session password; held only while unlocked, zeroized on clear/exit.
    password: Option<String>,
    unlocked: bool,
    wallet_bin: String,
    rig_bin: String,
    node_bin: String,
    /// Child `coincync-rig` process while mining; None when stopped.
    miner: Option<Child>,
    miner_threads: usize,
    /// Current mining mode: "solo" | "pool".
    miner_mode: String,
    /// Pool stratum address when mining pool (e.g. "127.0.0.1:3333").
    miner_pool: String,
    /// Last measured hashrate (H/s), cached so the advisor can reason while idle.
    last_hashrate: f64,
    /// Child `coincync-node` process when CyncHub started it; None when we did
    /// not launch it (an externally-run node is never ours to stop).
    node: Option<Child>,
    /// Child `coincync-wallet auto-churn` process (ghost-mode churn); None off.
    churn: Option<Child>,
}
impl Drop for AppState {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            p.zeroize();
        }
        if let Some(mut c) = self.miner.take() {
            let _ = c.kill();
        }
        if let Some(mut c) = self.node.take() {
            let _ = c.kill();
        }
        if let Some(mut c) = self.churn.take() {
            let _ = c.kill();
        }
        // clean exit: we killed our children, so clear the crash-recovery record.
        clear_children_pidfile();
    }
}
type State = Arc<Mutex<AppState>>;

fn wallet_dir() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".coincync")
        .join("wallets")
}

fn rpc_key() -> Option<String> {
    let p = dirs_next::config_dir()?.join("coincync").join("rpc.key");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve a bundled chain binary (coincync-node / coincync-wallet).
fn resolve_binary(name: &str) -> String {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()));
    if let Some(dir) = &exe_dir {
        let cands = [
            dir.join(format!("{}.exe", name)),
            dir.join(name),
            dir.join("resources/binaries").join(format!("{}.exe", name)),
            dir.join("resources/binaries").join(name),
            dir.join("../Resources/binaries").join(format!("{}.exe", name)),
        ];
        for c in &cands {
            if let Ok(x) = c.canonicalize() {
                return x.to_string_lossy().to_string();
            }
        }
    }
    exe_dir
        .map(|d| d.join(format!("{}.exe", name)))
        .unwrap_or_else(|| PathBuf::from(format!("{}.exe", name)))
        .to_string_lossy()
        .to_string()
}

fn resolve_wallet_bin() -> String {
    for n in ["coincync-wallet-cli", "coincync-wallet"] {
        let r = resolve_binary(n);
        if std::path::Path::new(&r).exists() {
            return r;
        }
    }
    resolve_binary("coincync-wallet")
}

fn resolve_rig_bin() -> String {
    resolve_binary("coincync-rig")
}

/// Where the bundled miner's stdout/stderr is logged (for support/diagnostics).
fn miner_log_path() -> Option<PathBuf> {
    let p = dirs_next::config_dir()?.join("coincync");
    let _ = std::fs::create_dir_all(&p);
    Some(p.join("cynchub-miner.log"))
}

fn resolve_node_bin() -> String {
    resolve_binary("coincync-node")
}

/// CyncHub's own node data dir. Kept separate so a managed node never collides
/// with a user's manually-run node datadir.
fn node_data_dir() -> PathBuf {
    dirs_next::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("coincync")
        .join("cynchub-node")
}

fn node_log_path() -> Option<PathBuf> {
    let p = dirs_next::config_dir()?.join("coincync");
    let _ = std::fs::create_dir_all(&p);
    Some(p.join("cynchub-node.log"))
}

fn churn_log_path() -> Option<PathBuf> {
    let p = dirs_next::config_dir()?.join("coincync");
    let _ = std::fs::create_dir_all(&p);
    Some(p.join("cynchub-churn.log"))
}

// ── child-process reaping across a crash/force-kill ─────────────────
// Rust's Drop kills child miner/node/churn processes on a clean exit, but NOT
// on a crash or a force-kill (SIGKILL/TerminateProcess) — those orphan the
// children. We record every spawned child's (pid, image) and, on the next
// launch, kill any that are still alive. taskkill's IMAGENAME filter makes this
// safe against PID reuse: it only kills a pid that is still that same binary.
fn children_pidfile() -> Option<PathBuf> {
    let p = dirs_next::config_dir()?.join("coincync");
    let _ = std::fs::create_dir_all(&p);
    Some(p.join("cynchub-children.pids"))
}
fn record_child(pid: u32, bin: &str) {
    let image = std::path::Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if image.is_empty() {
        return;
    }
    if let Some(p) = children_pidfile() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = writeln!(f, "{} {}", pid, image);
        }
    }
}
fn clear_children_pidfile() {
    if let Some(p) = children_pidfile() {
        let _ = std::fs::remove_file(p);
    }
}
#[cfg(windows)]
fn another_cynchub_running() -> bool {
    use std::os::windows::process::CommandExt;
    let out = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq cynchub.exe", "/NH", "/FO", "CSV"])
        .creation_flags(0x08000000)
        .output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).to_lowercase();
            s.lines().filter(|l| l.contains("cynchub.exe")).count() > 1
        }
        Err(_) => false,
    }
}
/// Kill orphaned children left by a previous crashed/force-killed instance.
/// Skipped when another CyncHub is running (its children are not ours to kill).
#[cfg(windows)]
fn cleanup_stale_children() {
    if another_cynchub_running() {
        return; // another instance owns the recorded children
    }
    let p = match children_pidfile() {
        Some(p) => p,
        None => return,
    };
    let body = std::fs::read_to_string(&p).unwrap_or_default();
    for line in body.lines() {
        let mut it = line.split_whitespace();
        if let (Some(pid), Some(image)) = (it.next(), it.next()) {
            if pid.parse::<u32>().is_ok() {
                use std::os::windows::process::CommandExt;
                let _ = Command::new("taskkill")
                    .args(["/F", "/PID", pid, "/FI", &format!("IMAGENAME eq {}", image)])
                    .creation_flags(0x08000000)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    let _ = std::fs::remove_file(p);
}
#[cfg(not(windows))]
fn cleanup_stale_children() {
    clear_children_pidfile();
}

/// True when the local node RPC answers `get_info` (reachable, whoever owns it).
fn node_rpc_reachable() -> bool {
    rpc_call("get_info", serde_json::json!([])).is_ok()
}

/// A data dir counts as "fresh" (needs --fast-sync bootstrap) when it does not
/// yet exist or holds no files. --fast-sync requires a fresh datadir; an
/// existing DB must continue normal IBD instead.
fn node_data_dir_fresh(dir: &std::path::Path) -> bool {
    match std::fs::read_dir(dir) {
        Ok(mut it) => it.next().is_none(),
        Err(_) => true, // missing dir == fresh
    }
}

fn rpc_call(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.post(LOCAL_RPC).json(&body);
    if let Some(k) = rpc_key() {
        req = req.header("Authorization", format!("Bearer {}", k));
    }
    let resp = req.send().map_err(|e| format!("node unreachable: {}", e))?;
    let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    if let Some(err) = json.get("error") {
        if !err.is_null() {
            return Err(format!("rpc error: {}", err));
        }
    }
    Ok(json.get("result").cloned().unwrap_or(json))
}

/// Strip ANSI escape sequences (the CLI colorizes its tracing output).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // skip until the terminating 'm' of a CSI sequence
            while let Some(&n) = chars.peek() {
                chars.next();
                if n == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Turn raw CLI stdout+stderr (which mixes tracing log lines — ISO timestamps,
/// WARN/INFO noise, the misleading "--password visible" warning) into a single
/// clean, human sentence for the UI. Keeps real ERROR text and non-log lines.
fn clean_cli_error(raw: &str) -> String {
    let mut msgs: Vec<String> = Vec::new();
    for line in strip_ansi(raw).lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        // tracing line looks like "2026-11-10T18:45:16.765637Z LEVEL message"
        let b = t.as_bytes();
        let is_log = t.len() > 20
            && b[0].is_ascii_digit()
            && b.get(4) == Some(&b'-')
            && t.contains('T')
            && t.contains('Z');
        if is_log {
            // keep only ERROR messages (drop WARN/INFO/DEBUG/TRACE entirely)
            if let Some(idx) = t.find("ERROR") {
                let msg = t[idx + 5..].trim();
                if !msg.is_empty() {
                    msgs.push(msg.to_string());
                }
            }
            continue;
        }
        msgs.push(t.to_string());
    }
    let joined = msgs.join(" — ").trim().to_string();
    if joined.is_empty() {
        raw.trim().to_string()
    } else {
        joined
    }
}

fn wallet_cli(bin: &str, args: &[&str], password: &str) -> Result<String, String> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("COINCYNC_WALLET_PASSWORD", password)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Node RPC auth: commands that reach the node (scan, send, …) authenticate
    // with the same Bearer key the node wrote. Without it the node answers
    // Unauthorized and scans silently return 0.
    if let Some(k) = rpc_key() {
        cmd.env("COINCYNC_RPC_API_KEY", k);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let out = cmd.output().map_err(|e| format!("CLI failed: {}", e))?;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(clean_cli_error(&format!(
            "{}\n{}",
            s,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(s)
}

fn active_node_url() -> String {
    LOCAL_RPC.to_string()
}

// ── chain / node ────────────────────────────────────────────────────
#[derive(Serialize)]
struct ChainInfo {
    connected: bool,
    height: u64,
    #[serde(rename = "isSynced")]
    is_synced: bool,
    peers: u32,
    #[serde(rename = "targetHeight")]
    target_height: u64,
    #[serde(rename = "anonSet")]
    anon_set: u64,
    #[serde(rename = "ringSize")]
    ring_size: u32,
    status: String,
    network: String,
    supply: f64,
    #[serde(rename = "tipAgeSecs")]
    tip_age_secs: u64,
}

#[tauri::command]
fn get_chain_info() -> ChainInfo {
    match rpc_call("get_info", serde_json::json!([])) {
        Ok(i) => ChainInfo {
            connected: true,
            height: i["height"].as_u64().unwrap_or(0),
            is_synced: i["is_synced"].as_bool().unwrap_or(false),
            peers: i["peer_count"].as_u64().unwrap_or(0) as u32,
            target_height: i["peer_target_height"]
                .as_u64()
                .or_else(|| i["target_height"].as_u64())
                .unwrap_or(0),
            anon_set: i["anonymity_set"].as_u64().unwrap_or(0),
            ring_size: i["effective_ring_size"].as_u64().unwrap_or(0) as u32,
            status: i["status"].as_str().unwrap_or("unknown").to_string(),
            network: i["network"].as_str().unwrap_or("").to_string(),
            supply: i["supply_atomic"].as_u64().unwrap_or(0) as f64 / 1e12,
            tip_age_secs: i["tip_age_secs"].as_u64().unwrap_or(0),
        },
        Err(_) => ChainInfo {
            connected: false,
            height: 0,
            is_synced: false,
            peers: 0,
            target_height: 0,
            anon_set: 0,
            ring_size: 0,
            status: "offline".to_string(),
            network: String::new(),
            supply: 0.0,
            tip_age_secs: 0,
        },
    }
}

// ── live metrics (a "the chain is working" dashboard) ───────────────
#[derive(Serialize)]
struct BlockRow {
    height: u64,
    timestamp: u64,
    #[serde(rename = "txCount")]
    tx_count: u64,
}
#[derive(Serialize)]
struct Metrics {
    connected: bool,
    height: u64,
    peers: u32,
    #[serde(rename = "targetHeight")]
    target_height: u64,
    #[serde(rename = "isSynced")]
    is_synced: bool,
    difficulty: f64,
    #[serde(rename = "netHashrate")]
    net_hashrate: f64,
    mempool: u64,
    supply: f64,
    #[serde(rename = "anonSet")]
    anon_set: u64,
    #[serde(rename = "ringSize")]
    ring_size: u32,
    #[serde(rename = "tipAgeSecs")]
    tip_age_secs: u64,
    status: String,
    network: String,
    #[serde(rename = "avgBlockSecs")]
    avg_block_secs: f64,
    /// Most recent blocks, newest first — a live feed so the user sees blocks land.
    blocks: Vec<BlockRow>,
}

fn difficulty_of(i: &serde_json::Value) -> f64 {
    let d = &i["difficulty"];
    d.as_f64()
        .or_else(|| d.as_u64().map(|v| v as f64))
        .or_else(|| d.as_str().and_then(|s| s.trim().parse::<f64>().ok()))
        .unwrap_or(0.0)
}

/// Parse `utxos --include-spent` stdout into rows. Data lines look like:
///   `idx amount height subaddr spent tx:out [payment_id]`
/// The CLI prints the spent column as "yes"/"no" (not "true"/"false"); matching
/// the wrong token silently mislabels every output, so it's pinned by tests.
fn parse_utxo_rows(out: &str) -> Vec<UtxoRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 6 && f[0].parse::<u64>().is_ok() {
            if let (Ok(idx), Ok(amount), Ok(height)) =
                (f[0].parse::<u64>(), f[1].parse::<f64>(), f[2].parse::<u64>())
            {
                rows.push(UtxoRow {
                    idx,
                    amount,
                    height,
                    tx_out: f[5].to_string(),
                    spent: f[4].eq_ignore_ascii_case("yes") || f[4].eq_ignore_ascii_case("true"),
                });
            }
        }
    }
    rows
}

/// Parse `shielded-balance` stdout into (balance_cync, notes). The "Balance: <n>
/// atomic" line is ATOMIC (÷1e12 → CYNC); "Owned notes: <n>" is a count. Keying
/// off the wrong line once reported a fabricated 0, so both are pinned by tests.
fn parse_shielded(out: &str) -> (f64, u64) {
    let (mut balance, mut notes) = (0.0f64, 0u64);
    for line in out.lines() {
        let l = line.trim();
        let low = l.to_ascii_lowercase();
        if low.contains("atomic") {
            if let Some(v) = l.split_whitespace().find_map(|t| t.parse::<u64>().ok()) {
                balance = v as f64 / 1e12;
            }
        } else if low.contains("note") {
            if let Some(v) = l.split_whitespace().find_map(|t| t.parse::<u64>().ok()) {
                notes = v;
            }
        }
    }
    (balance, notes)
}

#[tauri::command]
fn get_metrics() -> Metrics {
    let empty = || Metrics {
        connected: false, height: 0, peers: 0, target_height: 0, is_synced: false,
        difficulty: 0.0, net_hashrate: 0.0, mempool: 0, supply: 0.0, anon_set: 0,
        ring_size: 0, tip_age_secs: 0, status: "offline".into(), network: String::new(),
        avg_block_secs: 0.0, blocks: Vec::new(),
    };
    let i = match rpc_call("get_info", serde_json::json!([])) {
        Ok(i) => i,
        Err(_) => return empty(),
    };
    let height = i["height"].as_u64().unwrap_or(0);
    let diff = difficulty_of(&i);
    // Pull the last few blocks for a live feed + an observed block time.
    let mut blocks: Vec<BlockRow> = Vec::new();
    let n: u64 = 8;
    let start = height.saturating_sub(n.saturating_sub(1));
    for h in (start..=height).rev() {
        if let Ok(b) = rpc_call("get_block_by_height", serde_json::json!([h])) {
            let ts = b["block"]["timestamp"].as_u64().or_else(|| b["timestamp"].as_u64()).unwrap_or(0);
            let tx = b["block"]["transactions"].as_array().map(|a| a.len() as u64)
                .or_else(|| b["transactions"].as_array().map(|a| a.len() as u64))
                .or_else(|| b["block"]["tx_count"].as_u64())
                .or_else(|| b["tx_count"].as_u64())
                .unwrap_or(0);
            blocks.push(BlockRow { height: h, timestamp: ts, tx_count: tx });
        }
    }
    // observed average block time from the fetched timestamps
    let ts: Vec<u64> = blocks.iter().map(|b| b.timestamp).filter(|&t| t > 0).collect();
    let avg = if ts.len() >= 2 {
        let (mx, mn) = (*ts.iter().max().unwrap(), *ts.iter().min().unwrap());
        (mx - mn) as f64 / (ts.len() as f64 - 1.0)
    } else {
        0.0
    };
    Metrics {
        connected: true,
        height,
        peers: i["peer_count"].as_u64().unwrap_or(0) as u32,
        target_height: i["peer_target_height"].as_u64().or_else(|| i["target_height"].as_u64()).unwrap_or(0),
        is_synced: i["is_synced"].as_bool().unwrap_or(false),
        difficulty: diff,
        net_hashrate: if diff > 0.0 { diff / TARGET_BLOCK_SECS } else { 0.0 },
        mempool: i["mempool_size"].as_u64().or_else(|| i["tx_pool_size"].as_u64()).unwrap_or(0),
        supply: i["supply_atomic"].as_u64().unwrap_or(0) as f64 / 1e12,
        anon_set: i["anonymity_set"].as_u64().unwrap_or(0),
        ring_size: i["effective_ring_size"].as_u64().unwrap_or(0) as u32,
        tip_age_secs: i["tip_age_secs"].as_u64().unwrap_or(0),
        status: i["status"].as_str().unwrap_or("unknown").to_string(),
        network: i["network"].as_str().unwrap_or("").to_string(),
        avg_block_secs: avg,
        blocks,
    }
}

// ── wallet lifecycle ────────────────────────────────────────────────
#[tauri::command]
fn wallet_exists() -> bool {
    wallet_dir().join("default.wallet").is_file()
}

fn set_pw(s: &mut AppState, pw: String) {
    if let Some(mut old) = s.password.take() {
        old.zeroize();
    }
    s.password = Some(pw);
}

#[tauri::command]
fn unlock_wallet(password: String, state: tauri::State<'_, State>) -> Result<bool, String> {
    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let p = path.to_string_lossy().to_string();
    wallet_cli(&bin, &["--wallet", &p, "open"], &password).map_err(|_| "invalid password".to_string())?;
    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.wallet_path = path;
    set_pw(&mut s, password);
    s.unlocked = true;
    Ok(true)
}

#[tauri::command]
fn lock_wallet(state: tauri::State<'_, State>) -> bool {
    if let Ok(mut s) = state.lock() {
        if let Some(mut p) = s.password.take() {
            p.zeroize();
        }
        s.unlocked = false;
    }
    true
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
    let seed = out
        .lines()
        .map(str::trim)
        .find(|l| {
            let w = l.split_whitespace().count();
            matches!(w, 12 | 15 | 18 | 21 | 24)
                && l.split_whitespace().all(|x| x.chars().all(|c| c.is_ascii_lowercase()))
        })
        .unwrap_or("")
        .to_string();
    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.wallet_path = path;
    set_pw(&mut s, password);
    s.unlocked = true;
    Ok(seed)
}

#[tauri::command]
fn restore_wallet(seed: String, password: String, state: tauri::State<'_, State>) -> Result<bool, String> {
    let norm = seed.split_whitespace().collect::<Vec<_>>().join(" ");
    if norm.split_whitespace().count() < 12 {
        return Err("seed phrase must be at least 12 words".into());
    }
    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        (s.wallet_bin.clone(), wallet_dir().join("default.wallet"))
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    let p = path.to_string_lossy().to_string();
    wallet_cli(&bin, &["--wallet", &p, "restore", &norm], &password)?;
    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.wallet_path = path;
    set_pw(&mut s, password);
    s.unlocked = true;
    Ok(true)
}

#[derive(Serialize)]
struct Balance {
    total: f64,
    unlocked: f64,
    height: u64,
    #[serde(rename = "utxoCount")]
    utxo_count: usize,
}

/// Scan the wallet against the node and return the balance (CYNC).
#[tauri::command]
fn scan_wallet(state: tauri::State<'_, State>) -> Result<Balance, String> {
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("wallet locked".into());
        }
        let pw = s.password.clone().ok_or("session missing")?;
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), pw)
    };
    let node = active_node_url();
    let out = wallet_cli(
        &bin,
        &["--wallet", &path, "--node", &node, "scan", "--from", "0", "--max-blocks", "10000"],
        &pw,
    );
    pw.zeroize();
    let out = out?;
    let mut bal = 0u64;
    let mut utxos = 0usize;
    let mut tip = 0u64;
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
    }
    Ok(Balance {
        total: bal as f64 / 1e12,
        unlocked: bal as f64 / 1e12,
        height: tip,
        utxo_count: utxos,
    })
}

#[tauri::command]
fn get_wallet_address(state: tauri::State<'_, State>) -> String {
    let (bin, path, mut pw, unlocked) = match state.lock() {
        Ok(s) => (
            s.wallet_bin.clone(),
            s.wallet_path.to_string_lossy().to_string(),
            s.password.clone().unwrap_or_default(),
            s.unlocked,
        ),
        Err(_) => return String::new(),
    };
    if !unlocked {
        return String::new();
    }
    let out = wallet_cli(&bin, &["--wallet", &path, "address"], &pw);
    pw.zeroize();
    match out {
        Ok(o) => o
            .lines()
            .find(|l| l.trim_start().starts_with("Address:"))
            .map(|l| l.trim().trim_start_matches("Address:").trim().to_string())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Reveal the wallet's 24-word recovery phrase for backup. Requires the
/// password to be re-entered (this call re-authenticates it via `show-seed`),
/// so a glance at an unlocked screen can't expose it. Never logged or stored.
#[tauri::command]
fn reveal_seed(password: String, state: tauri::State<'_, State>) -> Result<Vec<String>, String> {
    let (bin, path) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string())
    };
    let mut pw = password;
    let out = wallet_cli(&bin, &["--wallet", &path, "show-seed"], &pw);
    pw.zeroize();
    let out = out.map_err(|_| "wrong password".to_string())?;
    // the mnemonic is the line of 12/15/18/21/24 lowercase words
    let words = out
        .lines()
        .map(str::trim)
        .find(|l| {
            let n = l.split_whitespace().count();
            matches!(n, 12 | 15 | 18 | 21 | 24)
                && l.split_whitespace().all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
        })
        .ok_or("could not read the recovery phrase")?;
    Ok(words.split_whitespace().map(|s| s.to_string()).collect())
}

// ── disclosure (Attest) ─────────────────────────────────────────────
#[derive(Serialize)]
struct Disclosure {
    kind: String,
    artifact: String,
}

fn hex_blob(out: &str) -> Option<String> {
    out.lines()
        .map(str::trim)
        .filter(|l| l.len() >= 32 && l.len() % 2 == 0 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .max_by_key(|l| l.len())
        .map(|s| s.to_string())
}
fn json_blob(out: &str) -> Option<String> {
    let a = out.find('{')?;
    let b = out.rfind('}')?;
    (b > a).then(|| out[a..=b].to_string())
}

#[tauri::command]
fn disclose_balance(
    threshold: String,
    utxo_index: Option<u64>,
    state: tauri::State<'_, State>,
) -> Result<Disclosure, String> {
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("wallet locked".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let cync: f64 = threshold.parse().map_err(|_| "invalid threshold".to_string())?;
    if !cync.is_finite() || cync <= 0.0 {
        return Err("threshold must be positive".into());
    }
    let atomic = (cync * 1e12) as u64;
    let idx = utxo_index.unwrap_or(0).to_string();
    let out = wallet_cli(
        &bin,
        &["--wallet", &path, "disclose", "balance", "--threshold", &atomic.to_string(), "--utxo-index", &idx],
        &pw,
    );
    pw.zeroize();
    let out = out?;
    Ok(Disclosure {
        kind: "balance".into(),
        artifact: hex_blob(&out).ok_or("could not parse proof")?,
    })
}

#[tauri::command]
fn disclose_scoped_view_key(
    from_height: u64,
    to_height: u64,
    state: tauri::State<'_, State>,
) -> Result<Disclosure, String> {
    if from_height > to_height {
        return Err("from_height must be <= to_height".into());
    }
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("wallet locked".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let (from, to) = (from_height.to_string(), to_height.to_string());
    let out = wallet_cli(
        &bin,
        &["--wallet", &path, "disclose", "scoped-view-key", "--from-height", &from, "--to-height", &to],
        &pw,
    );
    pw.zeroize();
    let out = out?;
    Ok(Disclosure {
        kind: "scoped-view-key".into(),
        artifact: json_blob(&out).ok_or("could not parse view key")?,
    })
}

#[tauri::command]
fn generate_qr_svg(payload: String) -> Result<String, String> {
    use qrcode::{render::svg, QrCode};
    if payload.is_empty() || payload.len() > 4000 {
        return Err("qr payload size".into());
    }
    let code = QrCode::new(payload.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(200, 200)
        .max_dimensions(400, 400)
        .quiet_zone(true)
        .dark_color(svg::Color("#0a0a0a"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

// ── send / receive ──────────────────────────────────────────────────
#[derive(Serialize)]
struct AddrInfo {
    valid: bool,
    network: String,
    kind: String,
    #[serde(rename = "paymentId")]
    payment_id: bool,
}

/// Decode/validate a recipient address (stateless `address-info`), so the Send
/// screen can confirm it's a real address on the right network before sending.
#[tauri::command]
fn validate_address(address: String, state: tauri::State<'_, State>) -> AddrInfo {
    let bad = || AddrInfo { valid: false, network: String::new(), kind: String::new(), payment_id: false };
    let address = address.trim().to_string();
    if address.is_empty() {
        return bad();
    }
    let bin = match state.lock() {
        Ok(s) => s.wallet_bin.clone(),
        Err(_) => return bad(),
    };
    // address-info needs no password; empty env password is ignored for it.
    match wallet_cli(&bin, &["address-info", &address, "--json"], "") {
        Ok(o) => {
            if let Some(j) = json_blob(&o).and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok()) {
                return AddrInfo {
                    valid: true,
                    network: j["network"].as_str().unwrap_or("").to_string(),
                    kind: j["address_type"].as_str().unwrap_or("").to_string(),
                    payment_id: !j["payment_id"].is_null(),
                };
            }
            bad()
        }
        Err(_) => bad(),
    }
}

/// Build + submit a transfer. `amount` is in CYNC; converted to atomic.
#[tauri::command]
fn send_transaction(
    address: String,
    amount: f64,
    memo: Option<String>,
    fee_multiplier: Option<f64>,
    state: tauri::State<'_, State>,
) -> Result<String, String> {
    let address = address.trim().to_string();
    if address.is_empty() {
        return Err("enter a recipient address".into());
    }
    if !amount.is_finite() || amount <= 0.0 {
        return Err("enter a positive amount".into());
    }
    let fee_mult = fee_multiplier.unwrap_or(1.0).clamp(1.0, 100.0);
    let atomic = (amount * 1e12).round() as u64;
    if atomic == 0 {
        return Err("amount is too small".into());
    }
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let node = active_node_url();
    let atomic_s = atomic.to_string();
    let fee_s = format!("{:.2}", fee_mult);
    let mut args: Vec<&str> = vec![
        "--wallet", &path, "--node", &node,
        "send", "--address", &address, "--amount", &atomic_s,
        "--fee-multiplier", &fee_s,
    ];
    let memo_val = memo.unwrap_or_default();
    let memo_trim = memo_val.trim();
    if memo_trim.len() > 256 {
        return Err("memo is too long (max 256 bytes)".into());
    }
    if !memo_trim.is_empty() {
        args.push("--memo");
        args.push(memo_trim);
    }
    let out = wallet_cli(&bin, &args, &pw);
    pw.zeroize();
    let out = out?;
    // Surface a tx id / hash if the CLI printed one; else a generic success.
    let txid = out
        .lines()
        .map(str::trim)
        .filter_map(|l| l.rsplit(|c: char| c.is_whitespace() || c == ':').next())
        .find(|t| t.len() >= 32 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|s| s.to_string());
    Ok(txid.unwrap_or_else(|| "submitted".to_string()))
}

#[tauri::command]
fn new_subaddress(state: tauri::State<'_, State>) -> Result<String, String> {
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let out = wallet_cli(&bin, &["--wallet", &path, "subaddress", "create"], &pw);
    pw.zeroize();
    let out = out?;
    out.lines()
        .map(str::trim)
        .find(|l| l.len() > 20 && (l.starts_with("tCYNC") || l.starts_with("CYNC")))
        .or_else(|| {
            out.lines().map(str::trim).find_map(|l| {
                l.rsplit(char::is_whitespace).next().filter(|t| t.starts_with("tCYNC") || t.starts_with("CYNC"))
            })
        })
        .map(|s| s.to_string())
        .ok_or_else(|| "could not read new subaddress".into())
}

#[tauri::command]
fn integrated_address(state: tauri::State<'_, State>) -> Result<String, String> {
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let out = wallet_cli(&bin, &["--wallet", &path, "integrated-address"], &pw);
    pw.zeroize();
    let out = out?;
    out.lines()
        .map(str::trim)
        .find_map(|l| l.split_whitespace().find(|t| t.starts_with("tCYNC") || t.starts_with("CYNC")))
        .map(|s| s.to_string())
        .ok_or_else(|| "could not read integrated address".into())
}

#[derive(Serialize)]
struct UtxoRow {
    /// positional index in the wallet's unspent list (for `disclose --utxo-index`)
    idx: u64,
    amount: f64,
    height: u64,
    #[serde(rename = "txOut")]
    tx_out: String,
    spent: bool,
}

/// Received outputs from the wallet's UTXO sidecar (run scan first). This is
/// the honest view of incoming funds; outgoing sends are not individually
/// logged by the CLI.
#[tauri::command]
fn list_received(state: tauri::State<'_, State>) -> Result<Vec<UtxoRow>, String> {
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let out = wallet_cli(&bin, &["--wallet", &path, "utxos", "--include-spent"], &pw);
    pw.zeroize();
    let out = out?;
    let mut rows = parse_utxo_rows(&out);
    rows.sort_by(|a, b| b.height.cmp(&a.height));
    Ok(rows)
}

// ── shielded pool (Spark) — activates at h29000 ─────────────────────
#[derive(Serialize)]
struct ShieldedInfo {
    /// Total shielded value in CYNC (0.0 pre-fork / with no notes).
    balance: f64,
    /// Number of owned shielded notes.
    notes: u64,
    /// The node's shielded pool is live (height >= fork). Until then shield /
    /// unshield cannot be built, so the UI keeps the controls inert.
    active: bool,
}

/// Read the wallet's shielded (Spark) balance from the node's cover set.
/// Honest pre-fork: the pool is empty, so this reports 0 — never a fake number.
#[tauri::command]
fn shielded_balance(state: tauri::State<'_, State>) -> Result<ShieldedInfo, String> {
    let active = {
        let info = get_chain_info();
        info.connected && info.height >= FORK_HEIGHT
    };
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    if !active {
        pw.zeroize();
        return Ok(ShieldedInfo { balance: 0.0, notes: 0, active: false });
    }
    let node = active_node_url();
    let out = wallet_cli(&bin, &["--wallet", &path, "--node", &node, "shielded-balance"], &pw);
    pw.zeroize();
    // Pre-activation the node rejects the cover-set call; treat as empty, not error.
    let out = match out {
        Ok(o) => o,
        Err(_) => return Ok(ShieldedInfo { balance: 0.0, notes: 0, active }),
    };
    // CLI output (sketch-gk-proof build):
    //   Shielded balance (anchor height 25607):
    //     Owned notes:   0
    //     Balance:       0 atomic          <- value is ATOMIC, not CYNC
    let (balance, notes) = parse_shielded(&out);
    Ok(ShieldedInfo { balance, notes, active })
}

/// Shield `amount` CYNC into the Spark pool (transparent -> shielded).
#[tauri::command]
fn shield_funds(amount: f64, state: tauri::State<'_, State>) -> Result<String, String> {
    shielded_move("shielded-mint", amount, state)
}

/// Unshield `amount` CYNC back to this wallet's transparent balance.
#[tauri::command]
fn unshield_funds(amount: f64, state: tauri::State<'_, State>) -> Result<String, String> {
    shielded_move("shielded-unshield", amount, state)
}

fn shielded_move(cmd: &str, amount: f64, state: tauri::State<'_, State>) -> Result<String, String> {
    if !amount.is_finite() || amount <= 0.0 {
        return Err("enter a positive amount".into());
    }
    {
        let info = get_chain_info();
        if !info.connected {
            return Err("node unreachable".into());
        }
        if info.height < FORK_HEIGHT {
            return Err(format!(
                "the shielded pool activates at h{} — not yet live ({} to go)",
                FORK_HEIGHT,
                FORK_HEIGHT.saturating_sub(info.height)
            ));
        }
    }
    let atomic = (amount * 1e12).round() as u64;
    if atomic == 0 {
        return Err("amount is too small".into());
    }
    let (bin, path, mut pw) = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let node = active_node_url();
    let atomic_s = atomic.to_string();
    let out = wallet_cli(
        &bin,
        &["--wallet", &path, "--node", &node, cmd, "--amount", &atomic_s],
        &pw,
    );
    pw.zeroize();
    let out = out?;
    let txid = out
        .lines()
        .map(str::trim)
        .filter_map(|l| l.rsplit(|c: char| c.is_whitespace() || c == ':').next())
        .find(|t| t.len() >= 32 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|s| s.to_string());
    Ok(txid.unwrap_or_else(|| "submitted".to_string()))
}

// ── auto-churn (ghost mode) — drives `coincync-wallet auto-churn` ───
#[derive(Serialize)]
struct ChurnStatus {
    running: bool,
}

#[tauri::command]
fn start_churn(state: tauri::State<'_, State>) -> Result<ChurnStatus, String> {
    let (bin, path, pw) = {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        if let Some(mut c) = s.churn.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if !s.unlocked {
            return Err("unlock your wallet first".into());
        }
        (s.wallet_bin.clone(), s.wallet_path.to_string_lossy().to_string(), s.password.clone().ok_or("session missing")?)
    };
    let node = active_node_url();
    let mut cmd = Command::new(&bin);
    cmd.args(["--wallet", &path, "--node", &node, "auto-churn"])
        .env("COINCYNC_WALLET_PASSWORD", &pw);
    // Optional interval / percentage overrides (read from this process's env).
    // Unset = the CLI's defaults (1800-7200s, 10-50%). Lets a power user — or a
    // demo — churn more frequently than the half-hour-to-two-hour default.
    for (var, flag) in [
        ("COINCYNC_CHURN_MIN", "--min-interval"),
        ("COINCYNC_CHURN_MAX", "--max-interval"),
        ("COINCYNC_CHURN_MIN_PCT", "--min-pct"),
        ("COINCYNC_CHURN_MAX_PCT", "--max-pct"),
    ] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                cmd.args([flag, &v]);
            }
        }
    }
    // Log churn output to a file so "is it actually churning?" is observable
    // (self-send attempts, skips when balance is too low, errors) instead of
    // vanishing into a null sink.
    match churn_log_path().and_then(|p| std::fs::File::create(p).ok()) {
        Some(f) => {
            let err = f.try_clone().map(Stdio::from).unwrap_or_else(|_| Stdio::null());
            cmd.stdout(Stdio::from(f)).stderr(err);
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    if let Some(k) = rpc_key() {
        cmd.env("COINCYNC_RPC_API_KEY", k);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let child = cmd.spawn().map_err(|e| format!("could not start auto-churn: {}", e))?;
    record_child(child.id(), &bin);
    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.churn = Some(child);
    Ok(ChurnStatus { running: true })
}

#[tauri::command]
fn stop_churn(state: tauri::State<'_, State>) -> Result<ChurnStatus, String> {
    let mut s = state.lock().map_err(|e| e.to_string())?;
    if let Some(mut c) = s.churn.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    Ok(ChurnStatus { running: false })
}

#[tauri::command]
fn churn_status(state: tauri::State<'_, State>) -> ChurnStatus {
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(_) => return ChurnStatus { running: false },
    };
    if let Some(c) = guard.churn.as_mut() {
        if let Ok(Some(_)) = c.try_wait() {
            guard.churn = None;
        }
    }
    ChurnStatus { running: guard.churn.is_some() }
}

// ── mining (drives the bundled coincync-rig) ────────────────────────
#[derive(Serialize)]
struct MiningStatus {
    mining: bool,
    threads: usize,
    #[serde(rename = "hashrate")]
    hashrate_hps: f64,
    #[serde(rename = "blocksFound")]
    blocks_found: u64,
    /// Max useful threads (logical CPUs) so the UI can bound the control.
    #[serde(rename = "maxThreads")]
    max_threads: usize,
    #[serde(rename = "rigAvailable")]
    rig_available: bool,
    /// "solo" | "pool" — the active (or last-chosen) mode.
    mode: String,
    #[serde(rename = "poolUrl")]
    pool_url: String,
    #[serde(rename = "sharesAccepted")]
    shares_accepted: u64,
    #[serde(rename = "sharesRejected")]
    shares_rejected: u64,
    /// Network difficulty from the node (0 if unreachable).
    difficulty: f64,
    /// Estimated whole-network hashrate (H/s) = difficulty / target block time.
    #[serde(rename = "netHashrate")]
    net_hashrate: f64,
    /// Expected seconds to find a block SOLO at your current hashrate
    /// (0 when hashrate is unknown — e.g. still building the dataset).
    #[serde(rename = "estSoloSecs")]
    est_solo_secs: f64,
    /// Smart-mining recommendation: "solo" | "pool" | "measuring".
    recommend: String,
}

/// Node difficulty (from get_info); 0.0 if unreachable.
/// The RPC serializes difficulty as a JSON STRING (it can exceed u64/f64 range
/// on mainnet), so accept both a number and a numeric string.
fn node_difficulty() -> f64 {
    match rpc_call("get_info", serde_json::json!([])) {
        Ok(i) => difficulty_of(&i),
        Err(_) => 0.0,
    }
}

/// The smart-mining advisor: from a measured hashrate + live difficulty, work
/// out expected solo time-to-block and whether solo or a pool is the better bet.
/// Returns (difficulty, net_hashrate, est_solo_secs, recommendation).
fn mining_advisor(hashrate: f64) -> (f64, f64, f64, String) {
    let diff = node_difficulty();
    let net = if diff > 0.0 { diff / TARGET_BLOCK_SECS } else { 0.0 };
    let est = if hashrate > 0.0 && diff > 0.0 { diff / hashrate } else { 0.0 };
    let rec = if hashrate <= 0.0 || diff <= 0.0 {
        "measuring".to_string()
    } else if est <= AUTO_SOLO_THRESHOLD_SECS {
        "solo".to_string()
    } else {
        "pool".to_string()
    };
    (diff, net, est, rec)
}

/// Parse the miner log for pool share counts (run-pool has no /metrics endpoint).
/// Best-effort: counts "accepted"/"rejected" share lines and reads the last
/// hashrate the rig printed. Returns (hashrate, accepted, rejected).
fn pool_log_stats() -> (f64, u64, u64) {
    let (mut hps, mut acc, mut rej) = (0.0f64, 0u64, 0u64);
    let path = match miner_log_path() {
        Some(p) => p,
        None => return (0.0, 0, 0),
    };
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    for line in body.lines() {
        let low = line.to_ascii_lowercase();
        if low.contains("share") && low.contains("accept") {
            acc += 1;
        } else if low.contains("share") && (low.contains("reject") || low.contains("stale")) {
            rej += 1;
        }
        // "... 812 H/s ..." — take the number immediately before an H/s token.
        if let Some(idx) = low.find("h/s") {
            let pre = &line[..idx];
            if let Some(v) = pre.split_whitespace().last().and_then(|t| t.parse::<f64>().ok()) {
                hps = v;
            }
        }
    }
    (hps, acc, rej)
}

fn cpu_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}

/// Read the wallet's receive address (payout target). Needs an unlocked wallet.
fn wallet_address(bin: &str, path: &str, pw: &str) -> Option<String> {
    let out = wallet_cli(bin, &["--wallet", path, "address"], pw).ok()?;
    out.lines()
        .find(|l| l.trim_start().starts_with("Address:"))
        .map(|l| l.trim().trim_start_matches("Address:").trim().to_string())
        .filter(|a| !a.is_empty())
}

/// Scrape the rig's loopback Prometheus endpoint for a live hashrate +
/// blocks-found. Returns (hashrate_hps, blocks_found); zeros if unreachable.
fn miner_metrics() -> (f64, u64) {
    let url = format!("http://127.0.0.1:{}/metrics", MINER_METRICS_PORT);
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(800))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (0.0, 0),
    };
    let body = match client.get(&url).send().and_then(|r| r.text()) {
        Ok(b) => b,
        Err(_) => return (0.0, 0),
    };
    let mut hps = 0.0;
    let mut blocks = 0u64;
    for line in body.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(v) = line.strip_prefix("coincync_rig_current_hashrate_hps") {
            hps = v.trim().parse::<f64>().unwrap_or(0.0);
        } else if let Some(v) = line.strip_prefix("coincync_rig_blocks_found_total") {
            blocks = v.trim().parse::<f64>().unwrap_or(0.0) as u64;
        }
    }
    (hps, blocks)
}

/// Assemble a MiningStatus and run the smart-mining advisor over `hashrate`.
fn make_mining_status(
    mining: bool,
    threads: usize,
    mode: &str,
    pool: &str,
    hashrate: f64,
    blocks: u64,
    acc: u64,
    rej: u64,
    rig_available: bool,
) -> MiningStatus {
    let (diff, net, est, rec) = mining_advisor(hashrate);
    MiningStatus {
        mining,
        threads,
        hashrate_hps: hashrate,
        blocks_found: blocks,
        max_threads: cpu_threads(),
        rig_available,
        mode: mode.to_string(),
        pool_url: pool.to_string(),
        shares_accepted: acc,
        shares_rejected: rej,
        difficulty: diff,
        net_hashrate: net,
        est_solo_secs: est,
        recommend: rec,
    }
}

/// Start mining. `mode` is "solo" (pay to your wallet) or "pool" (mine shares
/// against a stratum pool). `pool_url` is required for pool mode.
#[tauri::command]
fn start_mining(
    threads: usize,
    mode: String,
    pool_url: String,
    state: tauri::State<'_, State>,
) -> Result<MiningStatus, String> {
    let max = cpu_threads();
    let threads = threads.clamp(1, max);
    let mode = if mode == "pool" { "pool" } else { "solo" };
    let pool = pool_url.trim().to_string();
    if mode == "pool" {
        if pool.is_empty() {
            return Err("enter a pool address (host:port) to mine on a pool".into());
        }
        let ok = pool
            .rsplit_once(':')
            .map(|(h, p)| !h.is_empty() && p.parse::<u16>().map(|n| n > 0).unwrap_or(false))
            .unwrap_or(false);
        if !ok {
            return Err("pool address must be host:port (e.g. pool.coincync.network:3333)".into());
        }
    }
    // Extract what we need under the lock, then DROP it before the subprocess
    // call — never hold the global state mutex across a CLI invocation (it would
    // stall concurrent commands like the 2.5s mining_status poll / the UI).
    let (rig, wbin, path, mut pw) = {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        // already running? stop first so the change takes effect.
        if let Some(mut c) = s.miner.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if !s.unlocked {
            return Err("unlock your wallet first — mining pays to your wallet address".into());
        }
        (
            s.rig_bin.clone(),
            s.wallet_bin.clone(),
            s.wallet_path.to_string_lossy().to_string(),
            s.password.clone().ok_or("session missing")?,
        )
    };
    let addr = wallet_address(&wbin, &path, &pw);
    pw.zeroize();
    let addr = addr.ok_or("could not read your wallet address")?;
    if !std::path::Path::new(&rig).exists() {
        return Err("miner (coincync-rig) is not bundled with this build".into());
    }

    let mut cmd = Command::new(&rig);
    if mode == "pool" {
        // Pool: the pool assembles blocks; we submit shares. `--login` is the
        // worker label — we send the wallet address so address-aware pools pay
        // the user. run-pool has no /metrics endpoint, so stats come from the log.
        cmd.args([
            "run-pool",
            "--pool", &pool,
            "--login", &addr,
            "--network", "testnet",
            "--threads", &threads.to_string(),
        ]);
    } else {
        cmd.args([
            "run-solo",
            "--node", LOCAL_RPC,
            "--address", &addr,
            "--network", "testnet",
            "--threads", &threads.to_string(),
            // short window → the UI shows a live hashrate within a few seconds.
            "--poll-interval-secs", "5",
            "--metrics-port", &MINER_METRICS_PORT.to_string(),
            "--metrics-bind", "127.0.0.1",
        ]);
    }
    // Log the rig's output so a stall/crash is never invisible (and pool stats
    // can be parsed from it).
    match miner_log_path().and_then(|p| std::fs::File::create(p).ok()) {
        Some(f) => {
            let err = f.try_clone().map(Stdio::from).unwrap_or_else(|_| Stdio::null());
            cmd.stdout(Stdio::from(f)).stderr(err);
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    if let Some(k) = rpc_key() {
        cmd.env("COINCYNC_RPC_API_KEY", k);
    }
    // Full-mem RandomX (clear any inherited light-mode flag).
    cmd.env_remove("COINCYNC_RANDOMX_LIGHT_MODE");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let child = cmd.spawn().map_err(|e| format!("could not start miner: {}", e))?;
    record_child(child.id(), &rig);

    let mut s = state.lock().map_err(|e| e.to_string())?;
    s.miner = Some(child);
    s.miner_threads = threads;
    s.miner_mode = mode.to_string();
    s.miner_pool = pool.clone();
    Ok(make_mining_status(true, threads, mode, &pool, 0.0, 0, 0, 0, true))
}

#[tauri::command]
fn stop_mining(state: tauri::State<'_, State>) -> Result<MiningStatus, String> {
    let mut s = state.lock().map_err(|e| e.to_string())?;
    if let Some(mut c) = s.miner.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    let rig_ok = std::path::Path::new(&s.rig_bin).exists();
    let (mode, pool, threads) = (s.miner_mode.clone(), s.miner_pool.clone(), s.miner_threads);
    Ok(make_mining_status(false, threads, &mode, &pool, 0.0, 0, 0, 0, rig_ok))
}

#[tauri::command]
fn mining_status(state: tauri::State<'_, State>) -> MiningStatus {
    let (mining, threads, mode, pool, rig_available) = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => return make_mining_status(false, 0, "solo", "", 0.0, 0, 0, 0, false),
        };
        // reap the child if it exited on its own.
        let mut alive = false;
        if let Some(c) = guard.miner.as_mut() {
            match c.try_wait() {
                Ok(Some(_)) => guard.miner = None,
                Ok(None) => alive = true,
                Err(_) => alive = true,
            }
        }
        let avail = std::path::Path::new(&guard.rig_bin).exists();
        (alive, guard.miner_threads, guard.miner_mode.clone(), guard.miner_pool.clone(), avail)
    };
    // Solo publishes Prometheus metrics; pool only writes a log.
    let (hps, blocks, acc, rej) = if !mining {
        (0.0, 0, 0, 0)
    } else if mode == "pool" {
        let (h, a, r) = pool_log_stats();
        (h, 0, a, r)
    } else {
        let (h, b) = miner_metrics();
        (h, b, 0, 0)
    };
    // cache a nonzero hashrate so the advisor still reasons after you stop.
    if hps > 0.0 {
        if let Ok(mut g) = state.lock() {
            g.last_hashrate = hps;
        }
    }
    // when idle, advise from the last measured hashrate.
    let advisor_hps = if mining {
        hps
    } else {
        state.lock().map(|g| g.last_hashrate).unwrap_or(0.0)
    };
    let (diff, net, est, rec) = mining_advisor(advisor_hps);
    MiningStatus {
        mining,
        threads,
        hashrate_hps: hps,
        blocks_found: blocks,
        max_threads: cpu_threads(),
        rig_available,
        mode,
        pool_url: pool,
        shares_accepted: acc,
        shares_rejected: rej,
        difficulty: diff,
        net_hashrate: net,
        est_solo_secs: est,
        recommend: rec,
    }
}

// ── self-managed node ───────────────────────────────────────────────
#[derive(Serialize)]
struct NodeStatus {
    /// RPC is answering (node reachable — ours or external).
    running: bool,
    /// CyncHub launched this node (so Stop is allowed).
    managed: bool,
    /// The node binary is bundled and can be launched.
    #[serde(rename = "binAvailable")]
    bin_available: bool,
    height: u64,
    #[serde(rename = "targetHeight")]
    target_height: u64,
    #[serde(rename = "isSynced")]
    is_synced: bool,
    peers: u32,
    /// 0.0–1.0 sync progress toward the peer target (1.0 when synced/unknown).
    progress: f64,
    /// Human one-liner for the UI ("Syncing 24,050 / 25,270", "Starting…", …).
    phase: String,
}

fn build_node_status(managed: bool, bin_available: bool) -> NodeStatus {
    let info = get_chain_info();
    if !info.connected {
        return NodeStatus {
            running: false,
            managed,
            bin_available,
            height: 0,
            target_height: 0,
            is_synced: false,
            peers: 0,
            progress: 0.0,
            phase: if managed { "Starting…".into() } else { "Not running".into() },
        };
    }
    let (progress, phase) = if info.is_synced || info.target_height == 0 {
        (1.0, if info.is_synced { "Synced".to_string() } else { "Connecting to peers…".to_string() })
    } else if info.target_height > 0 && info.height <= info.target_height {
        let p = info.height as f64 / info.target_height as f64;
        (
            p.clamp(0.0, 1.0),
            format!("Syncing {} / {}", info.height, info.target_height),
        )
    } else {
        (1.0, "Synced".to_string())
    };
    NodeStatus {
        running: true,
        managed,
        bin_available,
        height: info.height,
        target_height: info.target_height,
        is_synced: info.is_synced,
        peers: info.peers,
        progress,
        phase,
    }
}

#[tauri::command]
fn node_status(state: tauri::State<'_, State>) -> NodeStatus {
    let (managed, bin) = {
        let mut guard = match state.lock() {
            Ok(g) => g,
            Err(_) => return build_node_status(false, false),
        };
        // reap a managed node that exited on its own.
        if let Some(c) = guard.node.as_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                guard.node = None;
            }
        }
        (guard.node.is_some(), guard.node_bin.clone())
    };
    build_node_status(managed, std::path::Path::new(&bin).exists())
}

#[tauri::command]
fn start_node(state: tauri::State<'_, State>) -> Result<NodeStatus, String> {
    // Never launch a second node onto the same RPC port / datadir — if one is
    // already answering, reuse it (prevents a DB-lock crash).
    if node_rpc_reachable() {
        let managed = state.lock().map(|s| s.node.is_some()).unwrap_or(false);
        return Ok(build_node_status(managed, true));
    }
    let bin = {
        let s = state.lock().map_err(|e| e.to_string())?;
        if s.node.is_some() {
            // we have a child but RPC isn't up yet — it's still booting.
            return Ok(build_node_status(true, true));
        }
        s.node_bin.clone()
    };
    if !std::path::Path::new(&bin).exists() {
        return Err("node (coincync-node) is not bundled with this build".into());
    }

    let data_dir = node_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);
    let fresh = node_data_dir_fresh(&data_dir);
    let data_dir_s = data_dir.to_string_lossy().to_string();

    let mut cmd = Command::new(&bin);
    cmd.args([
        "--network", "testnet",
        "--data-dir", &data_dir_s,
        "--rpc-bind", "127.0.0.1:28081",
        "--addnode", "2.29.34.197:28080",
        "--addnode", "37.27.185.37:28080",
        "--addnode", "77.42.64.199:28080",
        "--addnode", "89.167.93.52:28080",
    ]);
    // First run on an empty datadir: bootstrap from the signed snapshot so the
    // node reaches near-tip in seconds instead of a full genesis IBD. Falls
    // back to normal IBD on any snapshot error (fail-closed in the node).
    if fresh {
        cmd.arg("--fast-sync");
    }
    // The node verifies blocks with RandomX but never mines; light mode keeps
    // it to ~256 MB instead of ~2 GB with no correctness cost.
    cmd.env("COINCYNC_RANDOMX_LIGHT_MODE", "1");
    match node_log_path().and_then(|p| std::fs::File::create(p).ok()) {
        Some(f) => {
            let err = f.try_clone().map(Stdio::from).unwrap_or_else(|_| Stdio::null());
            cmd.stdout(Stdio::from(f)).stderr(err);
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let child = cmd.spawn().map_err(|e| format!("could not start node: {}", e))?;
    record_child(child.id(), &bin);
    {
        let mut s = state.lock().map_err(|e| e.to_string())?;
        s.node = Some(child);
    }
    Ok(build_node_status(true, true))
}

#[tauri::command]
fn stop_node(state: tauri::State<'_, State>) -> Result<NodeStatus, String> {
    let mut s = state.lock().map_err(|e| e.to_string())?;
    match s.node.take() {
        Some(mut c) => {
            let _ = c.kill();
            let _ = c.wait();
            Ok(NodeStatus {
                running: false,
                managed: false,
                bin_available: std::path::Path::new(&s.node_bin).exists(),
                height: 0,
                target_height: 0,
                is_synced: false,
                peers: 0,
                progress: 0.0,
                phase: "Stopped".into(),
            })
        }
        None => Err("this node was not started by CyncHub, so CyncHub won't stop it".into()),
    }
}

// ── app health (Diagnostics) ────────────────────────────────────────
#[derive(Serialize)]
struct AppHealth {
    #[serde(rename = "nodeBin")]
    node_bin: bool,
    #[serde(rename = "walletBin")]
    wallet_bin: bool,
    #[serde(rename = "rigBin")]
    rig_bin: bool,
    #[serde(rename = "rpcKey")]
    rpc_key: bool,
    #[serde(rename = "walletExists")]
    wallet_exists: bool,
    #[serde(rename = "dataDir")]
    data_dir: String,
    version: String,
}

#[tauri::command]
fn app_health(state: tauri::State<'_, State>) -> AppHealth {
    let (node_bin, wallet_bin, rig_bin, wallet_exists) = match state.lock() {
        Ok(s) => (
            std::path::Path::new(&s.node_bin).exists(),
            std::path::Path::new(&s.wallet_bin).exists(),
            std::path::Path::new(&s.rig_bin).exists(),
            s.wallet_path.exists(),
        ),
        Err(_) => (false, false, false, false),
    };
    AppHealth {
        node_bin,
        wallet_bin,
        rig_bin,
        rpc_key: rpc_key().is_some(),
        wallet_exists,
        data_dir: node_data_dir().to_string_lossy().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn main() {
    // Reap any child processes orphaned by a previous crash/force-kill.
    cleanup_stale_children();
    let state: State = Arc::new(Mutex::new(AppState {
        wallet_path: wallet_dir().join("default.wallet"),
        password: None,
        unlocked: false,
        wallet_bin: resolve_wallet_bin(),
        rig_bin: resolve_rig_bin(),
        node_bin: resolve_node_bin(),
        miner: None,
        miner_threads: cpu_threads().saturating_sub(1).max(1),
        miner_mode: "solo".to_string(),
        miner_pool: String::new(),
        last_hashrate: 0.0,
        node: None,
        churn: None,
    }));

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_chain_info,
            get_metrics,
            app_health,
            wallet_exists,
            create_wallet,
            restore_wallet,
            unlock_wallet,
            lock_wallet,
            scan_wallet,
            get_wallet_address,
            reveal_seed,
            disclose_balance,
            disclose_scoped_view_key,
            generate_qr_svg,
            send_transaction,
            validate_address,
            new_subaddress,
            integrated_address,
            list_received,
            start_mining,
            stop_mining,
            mining_status,
            start_node,
            stop_node,
            node_status,
            shielded_balance,
            shield_funds,
            unshield_funds,
            start_churn,
            stop_churn,
            churn_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running CyncHub");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_csi_sequences() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m text"), "red text");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn clean_cli_error_keeps_error_drops_warn() {
        // Real shape: a WARN "password visible" line we must never surface,
        // plus the actual ERROR we want.
        let raw = "2026-11-10T18:45:16.765637Z  WARN Password passed via `--password` is visible\n\
                   2026-11-10T18:45:17.000000Z ERROR insufficient funds: need 10, have 2\n";
        let msg = clean_cli_error(raw);
        assert!(msg.contains("insufficient funds"), "got: {msg}");
        assert!(!msg.to_lowercase().contains("password"), "warn leaked: {msg}");
    }

    #[test]
    fn clean_cli_error_passes_plain_text() {
        assert_eq!(clean_cli_error("just a message"), "just a message");
    }

    #[test]
    fn difficulty_of_handles_number_or_string() {
        assert_eq!(difficulty_of(&serde_json::json!({ "difficulty": 131072 })), 131072.0);
        // get_info returns difficulty as a STRING — the bug that stuck the advisor on "measuring".
        assert_eq!(difficulty_of(&serde_json::json!({ "difficulty": "239538" })), 239538.0);
        assert_eq!(difficulty_of(&serde_json::json!({ "difficulty": 1.5 })), 1.5);
        assert_eq!(difficulty_of(&serde_json::json!({})), 0.0);
    }

    #[test]
    fn parse_utxo_rows_spent_flag_and_filtering() {
        let out = "idx amount height subaddr spent tx:out\n\
                   0 1.500000 25600 tCYNCaaa no abcd:0\n\
                   1 2.000000 25610 tCYNCbbb yes ef12:1\n\
                   -- not a data row --\n";
        let rows = parse_utxo_rows(out);
        assert_eq!(rows.len(), 2, "header + junk lines must be skipped");
        assert_eq!(rows[0].idx, 0);
        assert_eq!(rows[0].height, 25600);
        assert!((rows[0].amount - 1.5).abs() < 1e-9);
        assert_eq!(rows[0].tx_out, "abcd:0");
        assert!(!rows[0].spent, "'no' must be unspent");
        assert!(rows[1].spent, "'yes' must be spent");
    }

    #[test]
    fn parse_shielded_atomic_units_and_notes() {
        let out = "Shielded balance (anchor height 25607):\n\
                   Owned notes:   3\n\
                   Balance:       1500000000000 atomic\n";
        let (bal, notes) = parse_shielded(out);
        assert!((bal - 1.5).abs() < 1e-9, "atomic->CYNC: got {bal}");
        assert_eq!(notes, 3);
    }

    #[test]
    fn parse_shielded_empty_is_zero() {
        let (bal, notes) = parse_shielded("Owned notes: 0\nBalance: 0 atomic\n");
        assert_eq!(bal, 0.0);
        assert_eq!(notes, 0);
    }
}
