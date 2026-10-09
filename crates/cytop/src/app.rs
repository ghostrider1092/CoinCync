//! Application state and the per-tick update: host metrics (via sysinfo), the
//! node snapshot, rolling histories and the chain-activity feed.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::time::Instant;

use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::widgets::ListState;
use sysinfo::{Disks, Networks, System};

use crate::collect::{
    spawn_gpu_poller, spawn_log_tailer, FeedLine, GpuInfo, NodeClient, NodeInfo, EVENTS_CAP,
};
use crate::draw::{clock_hms, icon_for, parse_log_line, short_hash, BRAND};
use crate::theme::Theme;

pub const HIST: usize = 120;

pub struct App {
    pub sys: System,
    pub nets: Networks,
    pub disks: Disks,
    pub theme: Theme,
    themes: Vec<(String, Theme)>,
    theme_idx: usize,
    pub theme_name: String,
    file_theme: Option<(usize, String)>, // (index, path) of a --theme/config file theme
    client: NodeClient,
    pub node: NodeInfo,
    pub gpu: GpuInfo,
    gpu_rx: Receiver<GpuInfo>,
    // host history
    pub cpu_hist: VecDeque<u64>,
    pub down_hist: VecDeque<u64>,
    pub up_hist: VecDeque<u64>,
    // node history
    pub hash_hist: VecDeque<u64>,
    pub mempool_hist: VecDeque<u64>,
    // chain-activity feed
    pub events: VecDeque<FeedLine>,
    pub feed_state: ListState,
    pub feed_follow: bool,
    pub feed_area: Rect, // inner area of the feed list, for mouse hit-testing
    log_rx: Option<Receiver<String>>,
    // bookkeeping
    pub last_poll: Instant,
    pub paused: bool,
    pub frame: u64,
    prev_blocks: Option<u64>,
    pub block_flash: Option<Instant>,
    prev_net: Option<(u64, u64)>,
}

impl App {
    pub fn new(
        rpc: String,
        log: Option<String>,
        themes: Vec<(String, Theme)>,
        theme_idx: usize,
        file_theme: Option<(usize, String)>,
    ) -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        let theme_idx = theme_idx.min(themes.len().saturating_sub(1));
        let theme = themes[theme_idx].1.clone();
        let theme_name = themes[theme_idx].0.clone();
        App {
            sys,
            nets: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            theme,
            themes,
            theme_idx,
            theme_name,
            file_theme,
            client: NodeClient::new(rpc),
            node: NodeInfo::default(),
            gpu: GpuInfo::default(),
            gpu_rx: spawn_gpu_poller(),
            cpu_hist: VecDeque::from(vec![0; HIST]),
            down_hist: VecDeque::from(vec![0; HIST]),
            up_hist: VecDeque::from(vec![0; HIST]),
            hash_hist: VecDeque::from(vec![0; HIST]),
            mempool_hist: VecDeque::from(vec![0; HIST]),
            events: VecDeque::new(),
            feed_state: ListState::default(),
            feed_follow: true,
            feed_area: Rect::default(),
            log_rx: log.map(spawn_log_tailer),
            last_poll: Instant::now(),
            paused: false,
            frame: 0,
            prev_blocks: None,
            block_flash: None,
            prev_net: None,
        }
    }

    /// Cycle to the next built-in/loaded theme.
    pub fn next_theme(&mut self) {
        if self.themes.is_empty() {
            return;
        }
        self.theme_idx = (self.theme_idx + 1) % self.themes.len();
        self.theme = self.themes[self.theme_idx].1.clone();
        self.theme_name = self.themes[self.theme_idx].0.clone();
    }

    /// The theme string to persist: a file path if the active theme came from a
    /// file, otherwise the built-in name.
    pub fn config_theme(&self) -> String {
        match &self.file_theme {
            Some((i, path)) if *i == self.theme_idx => path.clone(),
            _ => self.theme_name.clone(),
        }
    }

    pub fn tick(&mut self) {
        self.sys.refresh_all();
        self.nets.refresh();
        self.disks.refresh();
        while let Ok(g) = self.gpu_rx.try_recv() {
            self.gpu = g;
        }

        // CPU average across cores.
        let cpus = self.sys.cpus();
        let cpu = if cpus.is_empty() {
            0.0
        } else {
            cpus.iter().map(|c| c.cpu_usage() as f64).sum::<f64>() / cpus.len() as f64
        };
        push(&mut self.cpu_hist, cpu.round().max(0.0) as u64);

        // Network deltas (KiB/s), summed across interfaces.
        let (mut rx, mut tx) = (0u64, 0u64);
        for (_, d) in self.nets.iter() {
            rx += d.total_received();
            tx += d.total_transmitted();
        }
        if let Some((prx, ptx)) = self.prev_net {
            push(&mut self.down_hist, rx.saturating_sub(prx) / 1024);
            push(&mut self.up_hist, tx.saturating_sub(ptx) / 1024);
        }
        self.prev_net = Some((rx, tx));

        // Node snapshot + feed.
        let fresh = self.client.poll();
        let prev = std::mem::replace(&mut self.node, fresh);
        if self.log_rx.is_none() {
            self.derive_events(&prev);
        }
        if self.node.online {
            let bf = self.node.blocks_found;
            if matches!(self.prev_blocks, Some(p) if bf > p) {
                self.block_flash = Some(Instant::now());
            }
            self.prev_blocks = Some(bf);
        }
        push(&mut self.hash_hist, self.node.hashrate.round().max(0.0) as u64);
        push(&mut self.mempool_hist, self.node.mempool);
    }

    /// Pull queued node-log lines into the feed (called every frame).
    pub fn drain_log(&mut self) {
        if let Some(rx) = self.log_rx.take() {
            let theme = self.theme.clone();
            while let Ok(line) = rx.try_recv() {
                if !line.trim().is_empty() {
                    self.push_feed(parse_log_line(&theme, &line));
                }
            }
            self.log_rx = Some(rx);
        }
    }

    pub fn log_mode(&self) -> bool {
        self.log_rx.is_some()
    }

    fn derive_events(&mut self, prev: &NodeInfo) {
        let now = self.node.clone();
        if now.online && !prev.online {
            self.push_event("node", self.theme.c("proc_misc"), format!("rpc up — {} height={}", now.network, now.height));
        } else if !now.online && prev.online {
            self.push_event("node", self.theme.g("used", 100.0), "rpc unreachable — node down?".into());
        }
        if !now.online {
            return;
        }
        if prev.online && now.height > prev.height {
            let delta = now.height - prev.height;
            let short = short_hash(&now.top_hash);
            if delta == 1 {
                self.push_event("chain::commit", BRAND, format!("BLOCK height={} diff={} tip={}", now.height, now.difficulty, short));
            } else {
                self.push_event("sync_driver", self.theme.g("available", 60.0), format!("IBD +{delta} blocks → height={} tip={short}", now.height));
            }
        }
        if prev.online && now.blocks_found > prev.blocks_found {
            self.push_event("miner", self.theme.g("available", 80.0), format!("⛏ block at height {} — Accepted", now.height));
        }
        if prev.online && now.peers != prev.peers {
            self.push_event("net", self.theme.c("proc_misc"), format!("peers {}→{}", prev.peers, now.peers));
        }
        if now.fork_stuck && !prev.fork_stuck {
            self.push_event("sync", self.theme.g("used", 100.0), format!("FORK-STUCK — behind & stalled {}s", now.sync_stall_secs));
        }
        if now.synced && !prev.synced {
            self.push_event("sync", self.theme.g("free", 80.0), format!("fully synced at height {}", now.height));
        }
    }

    fn push_event(&mut self, tag: &str, color: Color, msg: String) {
        let (icon, icon_color) = icon_for(&self.theme, "INFO", tag, &msg);
        self.push_feed(FeedLine {
            spans: vec![
                (format!("{icon} "), icon_color),
                (format!("{} ", clock_hms()), self.theme.c("inactive_fg")),
                (format!("{tag:<13} "), BRAND),
                (msg, color),
            ],
        });
    }

    fn push_feed(&mut self, line: FeedLine) {
        if self.events.len() >= EVENTS_CAP {
            self.events.pop_front();
        }
        self.events.push_back(line);
    }

    pub fn feed_scroll(&mut self, delta: isize) {
        let len = self.events.len();
        if len == 0 {
            return;
        }
        let cur = self.feed_state.selected().unwrap_or(len - 1) as isize;
        let next = (cur + delta).clamp(0, len as isize - 1) as usize;
        self.feed_state.select(Some(next));
        self.feed_follow = next >= len - 1;
    }

    /// Select the feed line under a click at (col, row), if inside the feed.
    pub fn click_feed(&mut self, col: u16, row: u16) {
        let a = self.feed_area;
        if a.width == 0 || a.height == 0 {
            return;
        }
        if col < a.x || col >= a.x + a.width || row < a.y || row >= a.y + a.height {
            return;
        }
        let idx = self.feed_state.offset() + (row - a.y) as usize;
        if idx < self.events.len() {
            self.feed_state.select(Some(idx));
            self.feed_follow = idx + 1 >= self.events.len();
        }
    }
}

pub fn push(q: &mut VecDeque<u64>, v: u64) {
    if q.len() >= HIST {
        q.pop_front();
    }
    q.push_back(v);
}
