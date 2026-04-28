#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::process::{Child, Command};
use tauri::State;

// ─── State ───

struct MinerState {
    process: Mutex<Option<Child>>,
    config: Mutex<MinerConfig>,
    stats: Mutex<MiningStats>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MinerConfig {
    mining_address: String,
    threads: u32,
    algorithm: String, // "auto", "randomx", "yescrypt-heavy", "yescrypt-light"
    seed_nodes: Vec<String>,
    data_dir: String,
    network: String,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            mining_address: String::new(),
            threads: 1,
            algorithm: "auto".into(),
            seed_nodes: vec![
                "seed1.coincync.network:28080".into(),
                "seed2.coincync.network:28080".into(),
                "seed3.coincync.network:28080".into(),
            ],
            data_dir: default_data_dir(),
            network: "testnet".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct MiningStats {
    is_mining: bool,
    hashrate: f64,
    blocks_found: u64,
    earned_cync: f64,
    uptime_secs: u64,
    height: u64,
    difficulty: String,
    algorithm: String,
    peers: u32,
    cpu_usage: f32,
    cpu_temp: Option<f32>,
    total_cores: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct SystemInfo {
    cpu_name: String,
    total_cores: u32,
    total_memory_mb: u64,
    os: String,
}

fn default_data_dir() -> String {
    dirs::data_dir()
        .map(|p| p.join("coincync-miner").to_string_lossy().to_string())
        .unwrap_or_else(|| "coincync-data".into())
}

// ─── Commands ───

#[tauri::command]
fn get_system_info() -> SystemInfo {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    SystemInfo {
        cpu_name: sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
        total_cores: sys.cpus().len() as u32,
        total_memory_mb: sys.total_memory() / 1024 / 1024,
        os: std::env::consts::OS.to_string(),
    }
}

#[tauri::command]
fn get_config(state: State<Arc<MinerState>>) -> MinerConfig {
    state.config.lock().unwrap().clone()
}

#[tauri::command]
fn set_config(state: State<Arc<MinerState>>, config: MinerConfig) {
    *state.config.lock().unwrap() = config;
}

#[tauri::command]
fn get_stats(state: State<Arc<MinerState>>) -> MiningStats {
    state.stats.lock().unwrap().clone()
}

#[tauri::command]
fn start_mining(state: State<Arc<MinerState>>) -> Result<String, String> {
    let config = state.config.lock().unwrap().clone();

    if config.mining_address.is_empty() {
        return Err("No mining address set. Create a wallet first.".into());
    }

    // Check if already mining
    {
        let proc = state.process.lock().unwrap();
        if proc.is_some() {
            return Err("Already mining".into());
        }
    }

    // Find cyncd binary
    let exe = find_cyncd().ok_or("Could not find cyncd binary. Download from GitHub.")?;

    let mut cmd = Command::new(&exe);
    cmd.arg("--network").arg(&config.network)
        .arg("--data-dir").arg(&config.data_dir)
        .arg("--mine")
        .arg("--mining-address").arg(&config.mining_address)
        .arg("--mining-threads").arg(config.threads.to_string())
        .arg("--no-rpc-tls")
        .arg("--rpc-bind").arg("127.0.0.1:28081");

    for seed in &config.seed_nodes {
        cmd.arg("--seed-node").arg(seed);
    }

    let child = cmd.spawn().map_err(|e| format!("Failed to start miner: {}", e))?;

    *state.process.lock().unwrap() = Some(child);
    state.stats.lock().unwrap().is_mining = true;

    Ok("Mining started".into())
}

#[tauri::command]
fn stop_mining(state: State<Arc<MinerState>>) -> Result<String, String> {
    let mut proc = state.process.lock().unwrap();
    if let Some(ref mut child) = *proc {
        let _ = child.kill();
        let _ = child.wait();
    }
    *proc = None;
    state.stats.lock().unwrap().is_mining = false;
    Ok("Mining stopped".into())
}

#[tauri::command]
async fn poll_rpc_stats(state: State<'_, Arc<MinerState>>) -> Result<MiningStats, String> {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:28081")
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}"#)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let result = &data["result"];

    let mut stats = state.stats.lock().unwrap();
    stats.height = result["height"].as_u64().unwrap_or(0);
    stats.difficulty = result["difficulty"].as_str().unwrap_or("0").to_string();
    stats.peers = result["peer_count"].as_u64().unwrap_or(0) as u32;

    // Get system CPU info
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_cpu_usage();
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu_usage();
    stats.cpu_usage = sys.global_cpu_usage();
    stats.total_cores = sys.cpus().len() as u32;

    Ok(stats.clone())
}

fn find_cyncd() -> Option<String> {
    // Check common locations
    let candidates = vec![
        "cyncd",
        "./cyncd",
        "./target/release/cyncd",
        "../target/release/cyncd",
    ];

    for c in candidates {
        let path = std::path::Path::new(c);
        if path.exists() {
            return Some(c.to_string());
        }
    }

    // Check PATH
    if let Ok(output) = Command::new("which").arg("cyncd").output() {
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }
    // Windows: where
    if let Ok(output) = Command::new("where").arg("cyncd").output() {
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).lines().next()?.to_string());
        }
    }

    None
}

fn main() {
    let state = Arc::new(MinerState {
        process: Mutex::new(None),
        config: Mutex::new(MinerConfig::default()),
        stats: Mutex::new(MiningStats::default()),
    });

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            get_config,
            set_config,
            get_stats,
            start_mining,
            stop_mining,
            poll_rpc_stats,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CoinCync Miner");
}
