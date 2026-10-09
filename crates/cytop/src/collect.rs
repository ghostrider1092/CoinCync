//! Data collection — the CoinCync node (RPC snapshot + log tailer) and the
//! chain-activity feed types. Host metrics (cpu/mem/net) come from `sysinfo`
//! directly in `App`; this module owns everything node-specific so the draw
//! layer only ever sees plain data.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use ratatui::style::Color;

/// A node snapshot parsed from the RPC (best-effort; `online=false` when down).
#[derive(Default, Clone)]
pub struct NodeInfo {
    pub online: bool,
    pub network: String,
    pub height: u64,
    pub target_height: u64,
    pub top_hash: String,
    pub synced: bool,
    pub fork_stuck: bool,
    pub sync_stall_secs: u64,
    pub mesh_degraded: bool,
    pub peers: u64,
    pub difficulty: String,
    pub mempool: u64,
    pub is_mining: bool,
    pub hashrate: f64,
    #[allow(dead_code)] // parsed and kept for completeness; not shown in the compact node panel
    pub hashes_total: u64,
    pub blocks_found: u64,
}

/// Read-only JSON-RPC client for the node.
pub struct NodeClient {
    client: reqwest::blocking::Client,
    rpc: String,
}

impl NodeClient {
    pub fn new(rpc: String) -> Self {
        NodeClient {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(800))
                .build()
                .expect("http client"),
            rpc,
        }
    }

    pub fn poll(&self) -> NodeInfo {
        let Some(info) = self.call("get_info") else {
            return NodeInfo::default();
        };
        let r = info.get("result").unwrap_or(&info);
        let m = self
            .call("get_mining_live")
            .and_then(|v| v.get("result").cloned())
            .unwrap_or(serde_json::Value::Null);
        let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let u = |k: &str| r.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let b = |k: &str| r.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
        NodeInfo {
            online: true,
            network: {
                let n = s("network");
                if n.is_empty() { "?".into() } else { n }
            },
            height: u("height"),
            target_height: u("target_height"),
            top_hash: s("top_hash"),
            synced: b("synced"),
            fork_stuck: b("fork_stuck"),
            sync_stall_secs: u("sync_stall_secs"),
            mesh_degraded: b("mesh_degraded"),
            peers: u("peer_count"),
            difficulty: {
                let d = s("difficulty");
                if d.is_empty() { "?".into() } else { d }
            },
            mempool: u("mempool_size"),
            is_mining: m.get("is_mining").and_then(|v| v.as_bool()).unwrap_or(false),
            hashrate: m.get("hashrate").and_then(|v| v.as_f64()).unwrap_or(0.0),
            hashes_total: m.get("hashes_total").and_then(|v| v.as_u64()).unwrap_or(0),
            blocks_found: m.get("blocks_found").and_then(|v| v.as_u64()).unwrap_or(0),
        }
    }

    fn call(&self, method: &str) -> Option<serde_json::Value> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]});
        self.client.post(&self.rpc).json(&body).send().ok()?.json().ok()
    }
}

/// One pre-coloured line in the chain-activity feed.
#[derive(Clone)]
pub struct FeedLine {
    pub spans: Vec<(String, Color)>,
}

pub const EVENTS_CAP: usize = 500;

/// A GPU snapshot. `present=false` when no GPU backend produced data.
#[derive(Clone, Default)]
pub struct GpuInfo {
    pub present: bool,
    pub name: String,
    pub util: f64,     // 0..=100
    pub mem_used: u64, // bytes
    pub mem_total: u64,
    pub temp: Option<f64>,  // °C
    pub power: Option<f64>, // W
    pub backend: &'static str,
}

/// Background GPU poller: every ~2s try `nvidia-smi` (rich), then Windows
/// `typeperf` GPU counters (util only), else report `present=false`. Runs off
/// the main loop because the CLI calls are slow. Returns the latest-value rx.
pub fn spawn_gpu_poller() -> Receiver<GpuInfo> {
    let (tx, rx) = mpsc::channel::<GpuInfo>();
    std::thread::spawn(move || loop {
        let info = nvidia_smi().or_else(typeperf_gpu).unwrap_or_default();
        if tx.send(info).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(2000));
    });
    rx
}

fn nvidia_smi() -> Option<GpuInfo> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next()?;
    let f: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if f.len() < 4 {
        return None;
    }
    let mib = |s: &str| s.parse::<f64>().ok().map(|v| (v * 1024.0 * 1024.0) as u64);
    Some(GpuInfo {
        present: true,
        name: f[0].to_string(),
        util: f.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0),
        mem_used: f.get(2).and_then(|s| mib(s)).unwrap_or(0),
        mem_total: f.get(3).and_then(|s| mib(s)).unwrap_or(0),
        temp: f.get(4).and_then(|s| s.parse().ok()),
        power: f.get(5).and_then(|s| s.parse().ok()),
        backend: "nvidia-smi",
    })
}

/// Vendor-agnostic utilisation via Windows PDH through `typeperf` (no extra
/// deps). Takes the MAX across GPU engine instances, like Task Manager.
fn typeperf_gpu() -> Option<GpuInfo> {
    let out = std::process::Command::new("typeperf")
        .args(["\\GPU Engine(*)\\Utilization Percentage", "-sc", "1"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // typeperf CSV: a header row of quoted counter names, then a data row:
    // "timestamp","v1","v2",... We take the max numeric value in the data row.
    let data = text.lines().find(|l| l.starts_with('"') && l.contains(','))?;
    let mut max = 0.0f64;
    let mut any = false;
    for tok in data.split(',').skip(1) {
        if let Ok(v) = tok.trim().trim_matches('"').parse::<f64>() {
            any = true;
            if v > max {
                max = v;
            }
        }
    }
    if !any {
        return None;
    }
    Some(GpuInfo {
        present: true,
        name: "GPU".into(),
        util: max.clamp(0.0, 100.0),
        backend: "pdh",
        ..Default::default()
    })
}

/// Follow a node log file (`tail -f`): seed with the recent tail, then stream
/// new lines. Survives the file not existing yet and truncation/rotation.
pub fn spawn_log_tailer(path: String) -> Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut file = loop {
            match File::open(&path) {
                Ok(f) => break f,
                Err(_) => {
                    if tx.send(String::new()).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        };
        let mut pos: u64 = 0;
        if let Ok(meta) = file.metadata() {
            pos = meta.len().saturating_sub(48 * 1024);
        }
        let _ = file.seek(SeekFrom::Start(pos));
        let mut reader = BufReader::new(file);
        if pos > 0 {
            let mut skip = String::new();
            let _ = reader.read_line(&mut skip);
        }
        loop {
            let mut buf = String::new();
            match reader.read_line(&mut buf) {
                Ok(0) => {
                    let cur = reader.stream_position().unwrap_or(0);
                    if let Ok(f) = File::open(&path) {
                        if let Ok(meta) = f.metadata() {
                            if meta.len() < cur {
                                let mut nf = f;
                                let _ = nf.seek(SeekFrom::Start(0));
                                reader = BufReader::new(nf);
                                continue;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                Ok(_) => {
                    if tx.send(buf.trim_end().to_string()).is_err() {
                        return;
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    });
    rx
}
