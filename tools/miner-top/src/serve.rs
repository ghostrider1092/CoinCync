//! `miner-top serve` — a tiny local HTTP bridge that serves the web dashboard
//! and a live `/data` JSON endpoint driven by [`crate::feed::poll`] (real rig
//! `/metrics` + node `get_info`). Page and data share one origin, so the browser
//! hits no CORS wall; the whole thing stays loopback / self-hosted (no telemetry).
//!
//! std-only HTTP (blocking `TcpListener` + a thread per connection) plus
//! `serde_json` for the response — matching the crate's minimal-deps posture.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::feed::{self, RealData};

/// The dashboard page, embedded so the binary is self-contained.
const PAGE: &str = include_str!("dashboard.html");

/// Bounded history ring (one entry per poll). At a 3s cadence, 3000 samples is
/// ~2.5h of real history for the charts — plenty, and memory-cheap.
const MAX_HISTORY: usize = 3000;

/// Coinbase maturity in blocks (Bitcoin's `COINBASE_MATURITY = 100`, matched by
/// the node's `min_output_age`). A mined reward is spendable only once its block
/// is this deep, so the balance card splits mined coins matured vs pending on
/// this threshold.
const COINBASE_MATURITY: u64 = 100;

/// One polled sample. Block counts are stored as PER-INTERVAL deltas so the bar
/// chart spikes exactly when a block is accepted/found (solo mining is rare).
struct Sample {
    t: u64, // unix seconds
    hash: f64,
    accepted: u64,
    rejected: u64,
    found: u64,
    net_diff: f64,
    peers: u32,
}

struct State {
    latest: RealData,
    history: VecDeque<Sample>,
    prev_accepted: u64,
    prev_rejected: u64,
    prev_found: u64,
    primed: bool,
    address: String,
    reward: f64,
    /// Maintainer colony status (only populated when a `--tick` URL is set).
    /// `None` ⇒ this build isn't wired to a sidecar, so `/data` omits colony
    /// entirely and the dashboard never shows the Colony tab.
    colony: Option<crate::feed::Colony>,
}

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the bridge until the process is killed. Spawns a background poller that
/// scrapes the rig + node every `interval_secs`, then serves the page + `/data`.
#[allow(clippy::too_many_arguments)]
pub fn serve(
    port: u16,
    rig_url: String,
    node_url: String,
    address: String,
    reward: f64,
    interval_secs: u64,
    tick_url: Option<String>,
    tick_token: String,
) -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(State {
        latest: RealData::default(),
        history: VecDeque::new(),
        prev_accepted: 0,
        prev_rejected: 0,
        prev_found: 0,
        primed: false,
        address,
        reward,
        colony: tick_url.as_ref().map(|_| crate::feed::Colony::default()),
    }));

    // Background poller.
    {
        let state = Arc::clone(&state);
        let interval = Duration::from_secs(interval_secs.max(1));
        std::thread::spawn(move || loop {
            let d = feed::poll(&rig_url, &node_url);
            // Maintainer colony status, only when wired to a sidecar.
            let colony = tick_url
                .as_ref()
                .map(|url| feed::poll_colony(url, &tick_token));
            {
                let mut s = state.lock().unwrap();
                // Only record a sample once the rig has answered, so we don't
                // fill the chart with "offline" zeros before mining starts.
                if d.ok_rig {
                    let (da, dr, df) = if s.primed {
                        (
                            d.blocks_accepted.saturating_sub(s.prev_accepted),
                            d.blocks_rejected.saturating_sub(s.prev_rejected),
                            d.blocks_found.saturating_sub(s.prev_found),
                        )
                    } else {
                        (0, 0, 0)
                    };
                    s.prev_accepted = d.blocks_accepted;
                    s.prev_rejected = d.blocks_rejected;
                    s.prev_found = d.blocks_found;
                    s.primed = true;
                    s.history.push_back(Sample {
                        t: unix(),
                        hash: d.hashrate,
                        accepted: da,
                        rejected: dr,
                        found: df,
                        net_diff: d.net_diff,
                        peers: d.peers,
                    });
                    while s.history.len() > MAX_HISTORY {
                        s.history.pop_front();
                    }
                }
                s.latest = d;
                if colony.is_some() {
                    s.colony = colony;
                }
            }
            std::thread::sleep(interval);
        });
    }

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("miner-top web terminal: http://127.0.0.1:{port}");
    for stream in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = handle(stream, &state);
        });
    }
    Ok(())
}

fn handle(mut stream: TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, ctype, body) = if path.starts_with("/data") {
        ("200 OK", "application/json", data_json(state))
    } else if path == "/" || path.starts_with("/?") || path.starts_with("/index") {
        ("200 OK", "text/html; charset=utf-8", PAGE.to_string())
    } else {
        ("404 Not Found", "text/plain; charset=utf-8", "not found".to_string())
    };

    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())
}

fn data_json(state: &Mutex<State>) -> String {
    let s = state.lock().unwrap();
    let d = &s.latest;
    // Per-block reward for the mined estimate: an explicit `--reward` (s.reward > 0)
    // wins; otherwise derive it from the node's OWN latest block so the estimate is
    // populated automatically. Without this, a dashboard launched without `--reward`
    // shows 0.0000 CYNC next to real accepted blocks, which reads as a bug when it is
    // not one. `recent_blocks` is already fetched, so this needs no extra RPC; it
    // falls back to 0 (honestly "unknown") only when the node is unreachable.
    const ATOMIC_PER_CYNC: f64 = 1_000_000_000_000.0; // 1 CYNC = 1e12 atomic
    let reward = if s.reward > 0.0 {
        s.reward
    } else {
        d.recent_blocks
            .iter()
            .max_by_key(|b| b.height)
            .map(|b| b.reward_atomic as f64 / ATOMIC_PER_CYNC)
            .unwrap_or(0.0)
    };
    let history: Vec<serde_json::Value> = s
        .history
        .iter()
        .map(|x| {
            serde_json::json!({
                "t": x.t,
                "hash": x.hash,
                "accepted": x.accepted,
                "rejected": x.rejected,
                "found": x.found,
                "net_diff": x.net_diff,
                "peers": x.peers,
            })
        })
        .collect();

    // ── "Your blocks" ledger + mined balance ──────────────────────────────
    // Confirmations/depth measured against the current tip; matured once a
    // block is COINBASE_MATURITY deep. Reward is the fixed per-block emission
    // passed at launch (`--reward`), so no spend keys ever touch this box.
    let tip = d.net_height;
    // Pending = blocks still inside the COINBASE_MATURITY window. Those are always
    // the most-recent blocks, so they are ALWAYS present in the rig's accepted-
    // block ledger ring (the 100-block window is far smaller than the 256-entry
    // ring) — making this count EXACT even after older, matured blocks were
    // evicted from the ring. The per-block rows below are the recent ledger
    // history the table renders.
    let mut pending_blocks = 0u64;
    let my_blocks: Vec<serde_json::Value> = d
        .my_blocks
        .iter()
        .map(|b| {
            let depth = tip.saturating_sub(b.height);
            let matured = depth >= COINBASE_MATURITY;
            if !matured {
                pending_blocks += 1;
            }
            serde_json::json!({
                "height": b.height,
                "ts": b.ts,
                "confirmations": depth,
                "matured": matured,
                "reward": reward,
            })
        })
        .collect();
    // Total from the CUMULATIVE accepted counter (accurate past the 256-block
    // ring cap), clamped to at least the pending count for safety. Matured =
    // total − pending: everything no longer in the maturity window is spendable.
    // This is why the balance stays correct even after 835+ blocks, while the
    // table above only shows the most recent ~256.
    let total_blocks = d.blocks_accepted.max(pending_blocks);
    let matured_blocks = total_blocks.saturating_sub(pending_blocks);
    let ledger_shown = d.my_blocks.len() as u64;
    let mined_total = total_blocks as f64 * reward;
    let mined_matured = matured_blocks as f64 * reward;
    let mined_pending = pending_blocks as f64 * reward;

    // ── Derived operator stats ────────────────────────────────────────────
    // Expected solo seconds to a block = difficulty / hashrate. Undefined
    // (null) when we aren't hashing yet, so the UI shows "—" rather than ∞.
    let eta_seconds = if d.hashrate > 0.0 && d.net_diff > 0.0 {
        Some(d.net_diff / d.hashrate)
    } else {
        None
    };
    // Luck = blocks actually landed ÷ blocks expected over this uptime at the
    // current hashrate and difficulty. >100% = running lucky. Needs a warm-up
    // (some uptime + a hashrate) before it means anything.
    let expected_blocks = if d.net_diff > 0.0 {
        (d.hashrate * d.uptime_s as f64) / d.net_diff
    } else {
        0.0
    };
    let luck_pct = if expected_blocks > 0.0 {
        Some(100.0 * d.blocks_accepted as f64 / expected_blocks)
    } else {
        None
    };
    // Reliability: share of submits the daemon accepted (vs lost-race rejects).
    let submits = d.blocks_accepted + d.blocks_rejected;
    let accept_rate = if submits > 0 {
        Some(100.0 * d.blocks_accepted as f64 / submits as f64)
    } else {
        None
    };

    let recent_blocks: Vec<serde_json::Value> = d
        .recent_blocks
        .iter()
        .map(|b| {
            serde_json::json!({
                "height": b.height,
                "ts": b.ts,
                "difficulty": b.difficulty,
                "reward": b.reward_atomic,
                "tx_count": b.tx_count,
                "size": b.size,
                "hash": b.hash,
                "mine": d.my_blocks.iter().any(|m| m.height == b.height),
            })
        })
        .collect();

    // Estimated network hashrate from ACTUAL recent block intervals (honest for
    // a small off-equilibrium testnet, vs difficulty/target-time which assumes
    // blocks land on schedule). net_hashrate ≈ difficulty ÷ avg block interval.
    let net_hashrate_est = {
        let rb = &d.recent_blocks; // newest-first
        if rb.len() >= 2 && d.net_diff > 0.0 {
            let newest = rb.first().map(|b| b.ts).unwrap_or(0);
            let oldest = rb.last().map(|b| b.ts).unwrap_or(0);
            let span = newest.saturating_sub(oldest) as f64;
            let n = (rb.len() - 1) as f64;
            if span > 0.0 {
                Some(d.net_diff / (span / n))
            } else {
                None
            }
        } else {
            None
        }
    };
    // health_score < 0 means the node didn't report it → null (show "—").
    let health = if d.health_score < 0.0 {
        None
    } else {
        Some(d.health_score)
    };

    // Maintainer colony/guard status → JSON (null when no sidecar is wired, so
    // the dashboard never shows the Colony tab in the community build).
    let colony = s.colony.as_ref().map(|c| {
        let denied: Vec<serde_json::Value> = c
            .denied
            .iter()
            .map(|a| serde_json::json!({ "action": a.action, "reason": a.reason }))
            .collect();
        serde_json::json!({
            "reachable": c.reachable,
            "authorized": c.authorized,
            "disabled": c.disabled,
            "present": c.present,
            "armed": c.armed,
            "tick": c.tick,
            "uptime_s": c.uptime_s,
            "ram_pct": c.ram_pct,
            "swap_pct": c.swap_pct,
            "mempool": c.mempool,
            "peers_scored": c.peers_scored,
            "relay_mode": c.relay_mode,
            "next_housekeeping_s": c.next_housekeeping_s,
            "allowed": c.allowed,
            "denied": denied,
            "total_allowed": c.total_allowed,
            "total_denied": c.total_denied,
        })
    });

    serde_json::json!({
        "ok_rig": d.ok_rig,
        "ok_node": d.ok_node,
        "hashrate": d.hashrate,
        "threads": d.threads,
        "per_thread": d.per_thread,
        "blocks_found": d.blocks_found,
        "blocks_accepted": d.blocks_accepted,
        "blocks_rejected": d.blocks_rejected,
        "net_hashrate": d.net_hashrate,
        "uptime_s": d.uptime_s,
        "paused": d.paused,
        "net_height": d.net_height,
        "net_diff": d.net_diff,
        "tip_age_s": d.tip_age_s,
        "synced": d.synced,
        "peers": d.peers,
        "address": s.address,
        "reward": reward,
        "history": history,
        // chain / mempool / network (Chain tab)
        "recent_blocks": recent_blocks,
        "mempool_txs": d.mempool_txs,
        "mempool_bytes": d.mempool_bytes,
        "mempool_fees": d.mempool_fees,
        "connections": d.connections,
        "incoming": d.incoming,
        "outgoing": d.outgoing,
        "white_peers": d.white_peers,
        "grey_peers": d.grey_peers,
        // privacy + node health (Chain tab)
        "anon_set": d.anon_set,
        "ring_size": d.ring_size,
        "available_outputs": d.available_outputs,
        "health_score": health,
        "node_status": d.node_status,
        "net_hashrate_est": net_hashrate_est,
        // your blocks + mined balance (Blocks tab)
        "my_blocks": my_blocks,
        "mined_blocks": total_blocks,
        "ledger_shown": ledger_shown,
        "matured_blocks": matured_blocks,
        "pending_blocks": pending_blocks,
        "mined_total": mined_total,
        "mined_matured": mined_matured,
        "mined_pending": mined_pending,
        "maturity": COINBASE_MATURITY,
        // derived operator stats
        "eta_seconds": eta_seconds,
        "luck_pct": luck_pct,
        "accept_rate": accept_rate,
        // maintainer-only colony/guard status (null unless a --tick is wired)
        "colony": colony,
    })
    .to_string()
}
