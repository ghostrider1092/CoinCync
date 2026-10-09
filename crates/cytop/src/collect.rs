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
