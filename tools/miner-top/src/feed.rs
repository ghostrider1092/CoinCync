//! Real-data feed: scrape the rig's Prometheus `/metrics` and poll the node's
//! `get_info` RPC, over a tiny std-only blocking HTTP/1.1 client (no async, no
//! HTTP crate). Read-only — it only GETs metrics and POSTs a `get_info` query.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One recorded poll sample. Block counts are PER-INTERVAL deltas so a bar chart
/// spikes exactly when a block is accepted/found (solo mining is rare).
#[derive(Clone, Debug)]
pub struct Sample {
    pub t: u64, // unix seconds
    pub hash: f64,
    pub accepted: u64,
    pub rejected: u64,
    pub found: u64,
    pub net_diff: f64,
    pub peers: u32,
}

/// Rolling history + cumulative-counter → delta bookkeeping, shared by the web
/// bridge and the native GUI so both show identical live series.
pub struct Tracker {
    history: VecDeque<Sample>,
    prev_accepted: u64,
    prev_rejected: u64,
    prev_found: u64,
    primed: bool,
    max: usize,
}

impl Tracker {
    pub fn new(max: usize) -> Self {
        Tracker {
            history: VecDeque::new(),
            prev_accepted: 0,
            prev_rejected: 0,
            prev_found: 0,
            primed: false,
            max: max.max(1),
        }
    }

    /// Record a poll. Only samples once the rig has answered, so the chart isn't
    /// filled with "offline" zeros before mining starts.
    pub fn record(&mut self, d: &RealData) {
        if !d.ok_rig {
            return;
        }
        let (da, dr, df) = if self.primed {
            (
                d.blocks_accepted.saturating_sub(self.prev_accepted),
                d.blocks_rejected.saturating_sub(self.prev_rejected),
                d.blocks_found.saturating_sub(self.prev_found),
            )
        } else {
            (0, 0, 0)
        };
        self.prev_accepted = d.blocks_accepted;
        self.prev_rejected = d.blocks_rejected;
        self.prev_found = d.blocks_found;
        self.primed = true;
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_secs())
            .unwrap_or(0);
        self.history.push_back(Sample {
            t,
            hash: d.hashrate,
            accepted: da,
            rejected: dr,
            found: df,
            net_diff: d.net_diff,
            peers: d.peers,
        });
        while self.history.len() > self.max {
            self.history.pop_front();
        }
    }

    pub fn samples(&self) -> &VecDeque<Sample> {
        &self.history
    }
}

/// Hard cap on a single response body. `/metrics` and `get_info` are a few KiB;
/// this bounds what a hostile, buggy, or MITM'd endpoint can make us allocate
/// (never allocate unbounded memory from a network peer).
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// A block this rig landed (from the rig's authoritative accepted-block
/// ledger). Reward isn't carried here — it's the fixed per-block emission the
/// dashboard already knows, and confirmations come from the current tip.
#[derive(Clone, Debug)]
pub struct FoundBlock {
    pub height: u64,
    pub ts: u64, // accept timestamp, unix seconds
}

/// A recent network block, from the node's `get_block_range`. Feeds the Chain
/// tab's mini block-explorer.
#[derive(Clone, Debug)]
pub struct ChainBlock {
    pub height: u64,
    pub ts: u64,
    pub difficulty: f64,
    pub reward_atomic: u64,
    pub tx_count: u64,
    pub size: u64,
    pub hash: String,
}

/// One round of real miner + chain data. Fields default to zero/false; the
/// `ok_*` flags say whether each source answered this round.
#[derive(Clone, Debug, Default)]
pub struct RealData {
    pub ok_rig: bool,
    pub ok_node: bool,
    // rig /metrics
    pub hashrate: f64,
    pub per_thread: Vec<f64>,
    pub threads: usize,
    pub blocks_found: u64,
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub net_hashrate: f64,
    pub uptime_s: u64,
    pub paused: bool,
    /// Heights this rig landed + accept timestamps (authoritative "your blocks").
    pub my_blocks: Vec<FoundBlock>,
    // node get_info
    pub net_height: u64,
    pub net_diff: f64, // per-block difficulty (drives est. time-to-block)
    pub tip_age_s: u64,
    pub synced: bool,
    pub peers: u32,
    // node get_block_range — recent chain blocks (Chain tab explorer)
    pub recent_blocks: Vec<ChainBlock>,
    // node get_mempool_info
    pub mempool_txs: u64,
    pub mempool_bytes: u64,
    pub mempool_fees: u64,
    // node get_network_info
    pub connections: u32,
    pub incoming: u32,
    pub outgoing: u32,
    pub white_peers: u32,
    pub grey_peers: u32,
}

/// Split `http://host:port/path` into `(host, port, path)`. Defaults: port 80,
/// path `/`.
fn parse_url(u: &str) -> Option<(String, u16, String)> {
    let rest = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .unwrap_or(u);
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80),
    };
    Some((host, port, if path.is_empty() { "/".into() } else { path.to_string() }))
}

/// Send a raw HTTP/1.1 request (Connection: close) and return the response body.
fn http(host: &str, port: u16, req: &str) -> Option<String> {
    let mut s = TcpStream::connect((host, port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(4))).ok()?;
    s.write_all(req.as_bytes()).ok()?;
    // Bounded read: cap the body so a hostile/broken endpoint can't OOM us.
    let mut raw = Vec::new();
    (&mut s).take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut raw).ok()?;
    if raw.len() as u64 > MAX_RESPONSE_BYTES {
        return None; // oversized — refuse rather than trust it
    }
    let buf = String::from_utf8_lossy(&raw);
    // Body is everything after the header terminator.
    buf.splitn(2, "\r\n\r\n").nth(1).map(|b| b.to_string())
}

fn http_get(host: &str, port: u16, path: &str) -> Option<String> {
    http(
        host,
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
    )
}

/// Like [`http`] but also returns the numeric HTTP status, so callers can tell
/// 200 from 401/503 (needed for the maintainer `/colony` auth states).
fn http_with_status(host: &str, port: u16, req: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect((host, port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(4))).ok()?;
    s.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    (&mut s).take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut raw).ok()?;
    if raw.len() as u64 > MAX_RESPONSE_BYTES {
        return None;
    }
    let buf = String::from_utf8_lossy(&raw);
    // Status is the 2nd token of the response line: "HTTP/1.1 200 OK".
    let status = buf
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())?;
    let body = buf.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string();
    Some((status, body))
}

/// Authenticated GET: sends `Authorization: Bearer <token>`. Returns
/// `(status, body)`.
fn http_get_auth(host: &str, port: u16, path: &str, token: &str) -> Option<(u16, String)> {
    http_with_status(
        host,
        port,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\n\
             Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    )
}

fn http_post_json(host: &str, port: u16, path: &str, body: &str) -> Option<String> {
    http(
        host,
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

/// Value of an unlabeled Prometheus metric line `name <value>`.
fn prom_val(text: &str, name: &str) -> Option<f64> {
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name) {
            // Guard against prefix collisions (name is a strict prefix of a
            // longer metric): the next char must be a space.
            if let Some(stripped) = rest.strip_prefix(' ') {
                return stripped.split_whitespace().next()?.parse().ok();
            }
        }
    }
    None
}

/// Per-thread series `coincync_rig_thread_hashrate_hps{thread="N"} <v>`, sorted
/// by thread index.
fn prom_per_thread(text: &str) -> Vec<f64> {
    let mut out: Vec<(usize, f64)> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("coincync_rig_thread_hashrate_hps{thread=\"") {
            if let Some((idx, val)) = rest.split_once("\"}") {
                if let (Ok(i), Ok(v)) = (idx.parse::<usize>(), val.trim().parse::<f64>()) {
                    out.push((i, v));
                }
            }
        }
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, v)| v).collect()
}

/// Parse the rig's accepted-block ledger:
/// `coincync_rig_accepted_block{height="216"} 1788771501` → `FoundBlock`s,
/// sorted newest-height first.
fn prom_accepted_blocks(text: &str) -> Vec<FoundBlock> {
    let mut out: Vec<FoundBlock> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("coincync_rig_accepted_block{height=\"") {
            if let Some((h, tail)) = rest.split_once("\"}") {
                if let (Ok(height), Some(ts)) = (
                    h.parse::<u64>(),
                    tail.split_whitespace().next().and_then(|v| v.parse::<u64>().ok()),
                ) {
                    out.push(FoundBlock { height, ts });
                }
            }
        }
    }
    out.sort_by(|a, b| b.height.cmp(&a.height));
    out
}

/// Fire a JSON-RPC call and return the `result` value. `params` is the raw JSON
/// array text (e.g. `"[]"` or `"[214,216]"`).
fn rpc(host: &str, port: u16, path: &str, method: &str, params: &str) -> Option<serde_json::Value> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let resp = http_post_json(host, port, path, &body)?;
    let v: serde_json::Value = serde_json::from_str(&resp).ok()?;
    v.get("result").cloned()
}

/// Poll both sources once. A source that is down leaves its fields zero and its
/// `ok_*` flag false, so the dashboard can show a "waiting" state instead of
/// stale numbers.
pub fn poll(rig_url: &str, node_url: &str) -> RealData {
    let mut d = RealData::default();

    if let Some((h, p, path)) = parse_url(rig_url) {
        if let Some(text) = http_get(&h, p, &path) {
            d.ok_rig = true;
            d.hashrate = prom_val(&text, "coincync_rig_current_hashrate_hps").unwrap_or(0.0);
            d.threads = prom_val(&text, "coincync_rig_threads").unwrap_or(0.0) as usize;
            d.blocks_found = prom_val(&text, "coincync_rig_blocks_found_total").unwrap_or(0.0) as u64;
            d.blocks_accepted =
                prom_val(&text, "coincync_rig_blocks_accepted_total").unwrap_or(0.0) as u64;
            d.blocks_rejected =
                prom_val(&text, "coincync_rig_blocks_rejected_total").unwrap_or(0.0) as u64;
            d.net_hashrate = prom_val(&text, "coincync_rig_network_hashrate_hps").unwrap_or(0.0);
            d.uptime_s = prom_val(&text, "coincync_rig_uptime_seconds").unwrap_or(0.0) as u64;
            d.paused = prom_val(&text, "coincync_rig_paused").unwrap_or(0.0) >= 0.5;
            d.per_thread = prom_per_thread(&text);
            // If the rig hasn't published per-thread yet (older build / first
            // iteration), fall back to an even split so the bars still render.
            if d.per_thread.is_empty() && d.threads > 0 {
                d.per_thread = vec![d.hashrate / d.threads as f64; d.threads];
            }
            d.my_blocks = prom_accepted_blocks(&text);
        }
    }

    if let Some((h, p, path)) = parse_url(node_url) {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}"#;
        if let Some(resp) = http_post_json(&h, p, &path, body) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                if let Some(r) = v.get("result") {
                    d.ok_node = true;
                    d.net_height = r.get("height").and_then(|x| x.as_u64()).unwrap_or(0);
                    // Per-block difficulty (not cumulative total_difficulty).
                    // The node may serialize it as a number OR a decimal string
                    // (u128-as-string), so accept both.
                    d.net_diff = r
                        .get("difficulty")
                        .and_then(|x| {
                            x.as_f64()
                                .or_else(|| x.as_u64().map(|n| n as f64))
                                .or_else(|| x.as_str().and_then(|s| s.parse::<f64>().ok()))
                        })
                        .unwrap_or(0.0);
                    d.tip_age_s = r.get("tip_age_secs").and_then(|x| x.as_u64()).unwrap_or(0);
                    d.synced = r
                        .get("is_synced")
                        .and_then(|x| x.as_bool())
                        .or_else(|| r.get("synced").and_then(|x| x.as_bool()))
                        .unwrap_or(false);
                    d.peers = r.get("peer_count").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                }
            }
        }

        // Number-or-string → f64 (the node serializes u128 difficulty as a
        // decimal string). Reused for the per-block difficulty in the explorer.
        let num = |x: &serde_json::Value| -> f64 {
            x.as_f64()
                .or_else(|| x.as_u64().map(|n| n as f64))
                .or_else(|| x.as_str().and_then(|s| s.parse::<f64>().ok()))
                .unwrap_or(0.0)
        };

        // Recent chain blocks for the explorer: the last ~15 by height. Only
        // when the node answered get_info (so we have a tip to anchor on).
        if d.ok_node && d.net_height > 0 {
            let start = d.net_height.saturating_sub(14).max(1);
            let params = format!("[{start},{}]", d.net_height);
            if let Some(res) = rpc(&h, p, &path, "get_block_range", &params) {
                if let Some(arr) = res.get("blocks").and_then(|b| b.as_array()) {
                    for b in arr {
                        d.recent_blocks.push(ChainBlock {
                            height: b.get("height").and_then(|x| x.as_u64()).unwrap_or(0),
                            ts: b.get("timestamp").and_then(|x| x.as_u64()).unwrap_or(0),
                            difficulty: b.get("difficulty").map(num).unwrap_or(0.0),
                            reward_atomic: b.get("reward").and_then(|x| x.as_u64()).unwrap_or(0),
                            tx_count: b
                                .get("tx_count")
                                .or_else(|| b.get("transactions"))
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0),
                            size: b
                                .get("size")
                                .or_else(|| b.get("bytes"))
                                .and_then(|x| x.as_u64())
                                .unwrap_or(0),
                            hash: b
                                .get("hash")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .to_string(),
                        });
                    }
                    // Newest first for the table.
                    d.recent_blocks.sort_by(|a, b| b.height.cmp(&a.height));
                }
            }

            if let Some(res) = rpc(&h, p, &path, "get_mempool_info", "[]") {
                d.mempool_txs = res.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
                d.mempool_bytes = res.get("bytes").and_then(|x| x.as_u64()).unwrap_or(0);
                d.mempool_fees = res.get("total_fees").and_then(|x| x.as_u64()).unwrap_or(0);
            }

            if let Some(res) = rpc(&h, p, &path, "get_network_info", "[]") {
                d.connections = res.get("connections").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                d.incoming = res.get("incoming").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                d.outgoing = res.get("outgoing").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                d.white_peers = res.get("white_peers").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                d.grey_peers = res.get("grey_peers").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                // get_info's peer_count can be absent; the network view is a
                // better source, so backfill the header peer count from it.
                if d.peers == 0 {
                    d.peers = d.connections;
                }
            }
        }
    }

    d
}

/// One guard-gated colony action from the maintainer `/colony` view. For an
/// allowed action `reason` is empty; for a gated one it carries the guard's
/// reason string.
#[derive(Clone, Debug, Default)]
pub struct ColonyAction {
    pub action: String,
    pub reason: String,
}

/// Snapshot of the maintainer-only colony/guard status (advisory, non-consensus).
/// The `reachable`/`authorized`/`disabled` flags let the GUI show the right
/// state (offline / bad token / endpoint disabled / live) instead of blanks.
#[derive(Clone, Debug, Default)]
pub struct Colony {
    pub reachable: bool,  // the tick answered at all
    pub authorized: bool, // 200 (token accepted); false on 401
    pub disabled: bool,   // 503 (tick has no maintainer token configured)
    pub present: bool,    // a colony Act round has been published
    pub armed: bool,      // kill switch armed?
    pub tick: u64,
    pub uptime_s: u64,
    pub ram_pct: u16,
    pub swap_pct: u16,
    pub mempool: u32,
    pub peers_scored: u32,
    pub relay_mode: String,
    pub next_housekeeping_s: u32,
    pub allowed: Vec<String>,
    pub denied: Vec<ColonyAction>,
    pub total_allowed: u64,
    pub total_denied: u64,
}

/// Poll the sidecar's authenticated `/colony` endpoint. Read-only. The token is
/// sent as a Bearer header; a 401 leaves `authorized=false`, a 503 sets
/// `disabled=true`, a network failure leaves `reachable=false` — the GUI renders
/// each distinctly. `tick_url` should point at the tick's metrics origin (e.g.
/// `http://127.0.0.1:9109`); the `/colony` path is appended here.
pub fn poll_colony(tick_url: &str, token: &str) -> Colony {
    let mut c = Colony::default();
    let (host, port, base) = match parse_url(tick_url) {
        Some(v) => v,
        None => return c,
    };
    // Append /colony to the origin (ignore any path in tick_url).
    let _ = base;
    let (status, body) = match http_get_auth(&host, port, "/colony", token) {
        Some(v) => v,
        None => return c, // unreachable
    };
    c.reachable = true;
    match status {
        401 => return c,                      // authorized stays false
        503 => {
            c.disabled = true;
            return c;
        }
        200 => {}
        _ => return c,
    }
    let v: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return c,
    };
    c.authorized = true;
    c.present = v.get("present").and_then(|x| x.as_bool()).unwrap_or(false);
    c.armed = v.get("armed").and_then(|x| x.as_bool()).unwrap_or(false);
    c.tick = v.get("tick").and_then(|x| x.as_u64()).unwrap_or(0);
    c.uptime_s = v.get("uptime_secs").and_then(|x| x.as_u64()).unwrap_or(0);
    c.ram_pct = v.get("ram_pct").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    c.swap_pct = v.get("swap_pct").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    c.mempool = v.get("mempool").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    c.peers_scored = v.get("peers_scored").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    c.relay_mode = v
        .get("relay_mode")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    c.next_housekeeping_s = v
        .get("next_housekeeping_secs")
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;
    c.total_allowed = v.get("total_allowed").and_then(|x| x.as_u64()).unwrap_or(0);
    c.total_denied = v.get("total_denied").and_then(|x| x.as_u64()).unwrap_or(0);
    if let Some(arr) = v.get("allowed").and_then(|x| x.as_array()) {
        c.allowed = arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect();
    }
    if let Some(arr) = v.get("denied").and_then(|x| x.as_array()) {
        c.denied = arr
            .iter()
            .map(|d| ColonyAction {
                action: d
                    .get("action")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                reason: d
                    .get("reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
            .collect();
    }
    c
}
