//! Miner model + a demo simulator.
//!
//! `Miner` is the integration seam: in the real tool you fill it from your
//! RandomX worker + stratum/p2pool client each refresh instead of `simulate()`.

use std::collections::VecDeque;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ShareKind { Accepted, Rejected, Stale, Block }

impl ShareKind {
    pub fn tag(self) -> &'static str {
        match self { ShareKind::Accepted => "ACCEPT", ShareKind::Rejected => "REJECT",
                     ShareKind::Stale => "STALE ", ShareKind::Block => "BLOCK!" }
    }
}

pub struct ShareRow { pub ts: String, pub kind: ShareKind, pub detail: String }

pub struct Miner {
    pub rig: String,
    pub algo: &'static str,
    pub connection: String,
    pub cpu_model: String,
    pub freq_ghz: f64,
    pub threads: usize,
    pub cpu_temp_c: u16,
    pub load: [f64; 3],

    pub hashrate: f64,          // H/s now
    pub hr_avg: f64,
    pub hr_max: f64,
    pub hr_hist: VecDeque<f64>, // hero chart
    pub per_core: Vec<f64>,     // H/s per thread

    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,
    pub blocks_found: u64,
    pub share_diff: f64,        // pool/share difficulty
    pub effort_pct: f64,        // running luck

    pub net_height: u64,
    pub net_diff: f64,
    pub tip_age_s: u64,

    pub uptime_s: u64,
    pub paused: bool,
    pub ledger: VecDeque<ShareRow>,

    // ── solo / real-data fields (populated by `apply_real`) ──────────────
    pub solo: bool,             // true in real mode: solo mining, not pool
    pub online: bool,           // did the rig /metrics answer this round
    pub blocks_accepted: u64,   // blocks the daemon accepted (solo)
    pub blocks_rejected: u64,   // blocks the daemon rejected (lost race)
    pub net_hashrate: f64,      // network hashrate (H/s)
    pub est_ttb_s: u64,         // estimated time-to-block, seconds
    pub coins_earned: f64,      // blocks_accepted × reward (0 if reward unknown)
    pub reward: f64,            // per-block reward (CYNC), for the earned figure
    pub synced: bool,           // node sync state
    pub peers: u32,             // node peer count
    pub address: String,        // payout address

    seed: u64,
    since_share: u32,
    since_block: u32,
    prev_found: u64,
    prev_accepted: u64,
    real_primed: bool,
}

fn lcg(seed: &mut u64) -> f64 {
    // tiny deterministic PRNG so the demo needs no rand crate
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    ((*seed >> 33) as f64) / (u32::MAX as f64)
}

impl Miner {
    pub fn new(rig: &str, threads: usize) -> Self {
        let per = 552.0;
        Miner {
            rig: rig.into(),
            algo: "RandomX",
            connection: "p2pool @ 127.0.0.1:3333".into(),
            cpu_model: "AMD Ryzen 7 (CPU-only)".into(),
            freq_ghz: 3.8,
            threads,
            cpu_temp_c: 54,
            load: [threads as f64 * 0.9, threads as f64 * 0.85, threads as f64 * 0.7],
            hashrate: per * threads as f64,
            hr_avg: per * threads as f64,
            hr_max: per * threads as f64,
            hr_hist: VecDeque::new(),
            per_core: vec![per; threads],
            accepted: 0, rejected: 0, stale: 0, blocks_found: 0,
            share_diff: 48_000.0,
            effort_pct: 100.0,
            net_height: 128_640,
            net_diff: 3.41e8,
            tip_age_s: 12,
            uptime_s: 0,
            paused: false,
            ledger: VecDeque::new(),
            solo: false,
            online: true,
            blocks_accepted: 0,
            blocks_rejected: 0,
            net_hashrate: 0.0,
            est_ttb_s: 0,
            coins_earned: 0.0,
            reward: 0.0,
            synced: false,
            peers: 0,
            address: String::new(),
            seed: 0x1234_5678_9abc_def0,
            since_share: 0,
            since_block: 0,
            prev_found: 0,
            prev_accepted: 0,
            real_primed: false,
        }
    }

    /// Fill from real rig + node data (solo mining). `reward` is the CYNC-per-block
    /// override from `--reward`; when it is `0` (the default) the per-block reward is
    /// derived automatically from the node's own latest block reward, so the earned
    /// estimate is populated without the operator having to pass `--reward`. New
    /// block-count increments push ledger rows; the first real round primes the
    /// counters silently so a rig that already found blocks doesn't spam.
    pub fn apply_real(&mut self, d: &crate::feed::RealData, reward: f64, clock: String) {
        self.solo = true;
        self.online = d.ok_rig;
        self.uptime_s = d.uptime_s;
        self.paused = d.paused;

        if d.threads > 0 { self.threads = d.threads; }
        self.hashrate = d.hashrate;
        // Assign directly (not "only when non-empty"): when the rig is offline
        // the feed has no per-thread sample, so this clears any stale bars rather
        // than leaving the demo-init values on screen while "waiting for rig".
        self.per_core = d.per_thread.clone();
        // Reset the demo-init average/peak on the first real round so they reflect
        // real data (not the constructor's placeholder 552×threads).
        self.hr_avg = if self.real_primed { self.hr_avg * 0.9 + d.hashrate * 0.1 } else { d.hashrate };
        self.hr_max = if self.real_primed { self.hr_max.max(d.hashrate) } else { d.hashrate };
        self.hr_hist.push_back(d.hashrate);
        while self.hr_hist.len() > 120 { self.hr_hist.pop_front(); }

        self.blocks_found = d.blocks_found;
        self.blocks_accepted = d.blocks_accepted;
        self.blocks_rejected = d.blocks_rejected;
        self.net_hashrate = d.net_hashrate;
        // Per-block reward: an explicit `--reward` (CYNC) wins; otherwise derive it
        // from the node's OWN latest block reward so the earned estimate is never a
        // misleading 0.0000 next to a nonzero accepted-block count (which reads as a
        // bug). `recent_blocks` is populated whenever the node answered, so this
        // needs no extra RPC. Falls back to 0 only when the node is unreachable.
        const ATOMIC_PER_CYNC: f64 = 1_000_000_000_000.0; // 1 CYNC = 1e12 atomic
        let node_reward = d
            .recent_blocks
            .iter()
            .max_by_key(|b| b.height)
            .map(|b| b.reward_atomic as f64 / ATOMIC_PER_CYNC)
            .unwrap_or(0.0);
        let effective_reward = if reward > 0.0 { reward } else { node_reward };
        self.reward = effective_reward;
        self.coins_earned = d.blocks_accepted as f64 * effective_reward;

        self.net_height = d.net_height;
        self.net_diff = d.net_diff;
        self.tip_age_s = d.tip_age_s;
        self.synced = d.synced;
        self.peers = d.peers;

        // Estimated solo time-to-block: per-block difficulty ÷ your hashrate.
        self.est_ttb_s = if d.hashrate > 1.0 { (d.net_diff / d.hashrate) as u64 } else { 0 };

        // Ledger rows on counter increments (after the first, priming, round).
        if self.real_primed {
            if d.blocks_accepted > self.prev_accepted {
                self.ledger.push_front(ShareRow {
                    ts: clock.clone(),
                    kind: ShareKind::Block,
                    detail: format!("accepted · height {}", d.net_height),
                });
            }
            let new_found = d.blocks_found.saturating_sub(self.prev_found);
            let already = d.blocks_accepted.saturating_sub(self.prev_accepted);
            // A found-but-not-yet-accepted block = a lost race (rejected).
            if new_found > already && d.blocks_rejected > self.prev_accepted {
                self.ledger.push_front(ShareRow {
                    ts: clock,
                    kind: ShareKind::Rejected,
                    detail: "block found but not accepted (lost race)".into(),
                });
            }
            self.trim();
        }
        self.prev_found = d.blocks_found;
        self.prev_accepted = d.blocks_accepted;
        self.real_primed = true;
    }

    pub fn toggle_pause(&mut self) { self.paused = !self.paused; }

    /// Force a block-found event (demo key `b`).
    pub fn force_block(&mut self, clock: String) {
        self.blocks_found += 1;
        self.net_height += 1;
        self.tip_age_s = 0;
        self.effort_pct = 60.0 + lcg(&mut self.seed) * 90.0;
        self.ledger.push_front(ShareRow {
            ts: clock,
            kind: ShareKind::Block,
            detail: format!("height {}  ·  effort {:.0}%", self.net_height, self.effort_pct),
        });
        self.trim();
    }

    fn trim(&mut self) { while self.ledger.len() > 200 { self.ledger.pop_back(); } }

    pub fn simulate(&mut self, clock: String) {
        self.uptime_s += 1;
        self.tip_age_s += 1;

        if self.paused {
            self.hashrate = 0.0;
            for c in self.per_core.iter_mut() { *c = 0.0; }
            self.hr_hist.push_back(0.0);
            while self.hr_hist.len() > 120 { self.hr_hist.pop_front(); }
            return;
        }

        // per-core hashrate jitter around base
        let base = 552.0;
        let mut total = 0.0;
        for c in self.per_core.iter_mut() {
            let j = 0.90 + lcg(&mut self.seed) * 0.16; // 0.90..1.06
            *c = base * j;
            total += *c;
        }
        self.hashrate = total;
        self.hr_avg = self.hr_avg * 0.95 + total * 0.05;
        if total > self.hr_max { self.hr_max = total; }
        self.hr_hist.push_back(total);
        while self.hr_hist.len() > 120 { self.hr_hist.pop_front(); }

        // temp/load wander
        let t = 52.0 + lcg(&mut self.seed) * 10.0;
        self.cpu_temp_c = t as u16;
        self.load[0] = self.threads as f64 * (0.82 + lcg(&mut self.seed) * 0.18);

        // shares: roughly one every few ticks
        self.since_share += 1;
        if self.since_share >= 3 {
            self.since_share = 0;
            let r = lcg(&mut self.seed);
            if r < 0.90 {
                self.accepted += 1;
                self.ledger.push_front(ShareRow { ts: clock.clone(), kind: ShareKind::Accepted,
                    detail: format!("diff {:.0}  ·  {} thr", self.share_diff, self.threads) });
            } else if r < 0.965 {
                self.stale += 1;
                self.ledger.push_front(ShareRow { ts: clock.clone(), kind: ShareKind::Stale,
                    detail: "arrived after tip advanced".into() });
            } else {
                self.rejected += 1;
                self.ledger.push_front(ShareRow { ts: clock.clone(), kind: ShareKind::Rejected,
                    detail: "low diff / duplicate".into() });
            }
            self.trim();
        }

        // occasional network tip advance
        if self.tip_age_s > 20 && lcg(&mut self.seed) < 0.25 {
            self.net_height += 1;
            self.tip_age_s = 0;
        }

        // very rare block (or use force_block)
        self.since_block += 1;
        if self.since_block > 400 && lcg(&mut self.seed) < 0.02 {
            self.since_block = 0;
            self.force_block(clock);
        }

        let acc = self.accepted.max(1) as f64;
        self.effort_pct = 100.0 * (acc / (acc + self.rejected as f64 + self.stale as f64));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::{ChainBlock, RealData};

    fn block(height: u64, reward_atomic: u64) -> ChainBlock {
        ChainBlock {
            height,
            ts: 0,
            difficulty: 0.0,
            reward_atomic,
            tx_count: 1,
            size: 0,
            hash: String::new(),
        }
    }

    fn data(blocks_accepted: u64, recent: Vec<ChainBlock>) -> RealData {
        let mut d = RealData::default();
        d.ok_rig = true;
        d.blocks_accepted = blocks_accepted;
        d.recent_blocks = recent;
        d
    }

    /// The bug this fixes: launched WITHOUT `--reward`, the dashboard showed
    /// 0.0000 CYNC next to a nonzero accepted-block count, which reads as a bug.
    /// It must instead derive the reward from the node's OWN latest block.
    #[test]
    fn reward_auto_derives_from_node_latest_block_when_not_overridden() {
        // Two blocks; the higher-height one (the real current reward) must win.
        let d = data(
            10,
            vec![block(100, 49_000_000_000_000), block(101, 49_954_021_038_617)],
        );
        let mut m = Miner::new("rig-01", 8);
        m.apply_real(&d, 0.0, "00:00:00".into()); // no --reward
        assert!(
            (m.reward - 49.954_021_038_617).abs() < 1e-6,
            "reward auto-derived from node latest block, got {}",
            m.reward
        );
        assert!(
            (m.coins_earned - 499.540_210_386_17).abs() < 1e-3,
            "10 blocks must estimate ~499.5 CYNC, not 0; got {}",
            m.coins_earned
        );
    }

    /// An explicit `--reward` is still honoured as an override.
    #[test]
    fn explicit_reward_flag_overrides_node_value() {
        let d = data(4, vec![block(101, 49_954_021_038_617)]);
        let mut m = Miner::new("rig-01", 8);
        m.apply_real(&d, 50.0, "00:00:00".into());
        assert_eq!(m.reward, 50.0);
        assert_eq!(m.coins_earned, 200.0);
    }

    /// Node unreachable (no recent blocks) and no override → reward is honestly
    /// unknown (0), not a fabricated figure.
    #[test]
    fn reward_zero_when_node_unreachable_and_no_override() {
        let d = data(7, vec![]);
        let mut m = Miner::new("rig-01", 8);
        m.apply_real(&d, 0.0, "00:00:00".into());
        assert_eq!(m.reward, 0.0);
        assert_eq!(m.coins_earned, 0.0);
    }
}
