//! Share-informed hashrate telemetry (Observe-only, gated).
//!
//! Shares below `tau_share` arrive about `C_SHARE·K` (~60) times per block, so
//! the share stream is a ~60× denser hashrate signal than block intervals. An
//! estimate built from shares therefore has ~60× more samples, so its noise
//! (std ∝ 1/√N) is ~√60 ≈ 7.7× lower, and it reacts ~60× faster — the lag and
//! oscillation a block-interval estimate feeds into the difficulty retarget.
//!
//! This module only MEASURES, during Observe, to prove the signal with real data
//! before any consensus change. Feeding it into the ASERT retarget is a gated,
//! post-audit step (`bobtail-spec.md`: "share-informed difficulty").
//!
//! Estimator: each share at `tau_share` represents `work(tau_share)` expected
//! RandomX evaluations (it cleared a 1-in-`work` target), so over a window the
//! hashrate is `Σ work / elapsed` (the standard pool "shares × share-difficulty
//! / time" estimator).

use crate::consensus::work_from_target;
use crate::primitives::Hash;
use std::collections::VecDeque;

/// Default sliding window: ~a couple of block intervals.
pub const DEFAULT_WINDOW_SECS: u64 = 120;

/// Expected RandomX evaluations one share at `tau_share` represents (its work =
/// `max_target / tau_share`).
pub fn share_work(tau_share: &Hash) -> u128 {
    work_from_target(tau_share)
}

/// Point estimate: `share_count` shares over `window_secs` at `tau_share`
/// ⇒ hashrate ≈ `count · work(tau_share) / window` (H/s).
pub fn hashrate_from_shares(share_count: u64, window_secs: f64, tau_share: &Hash) -> f64 {
    if window_secs <= 0.0 {
        return 0.0;
    }
    (share_count as f64) * (share_work(tau_share) as f64) / window_secs
}

/// How much tighter a share-based estimate is than a block-based one over the
/// same window: estimator std ∝ 1/√N, so the ratio is `√(block/share)`. Returns
/// the fraction of the block-based std the share-based estimate achieves (e.g.
/// ~0.13 at 60× density = ~87% lower noise).
pub fn std_ratio_vs_blocks(share_samples: u64, block_samples: u64) -> f64 {
    if share_samples == 0 {
        return 1.0;
    }
    ((block_samples.max(1) as f64) / (share_samples as f64)).sqrt()
}

/// A sliding-window hashrate estimator fed by share arrivals. `tau_share` is
/// recorded per arrival (it tracks the retarget, so it can shift over the window).
pub struct ShareHashrate {
    window_secs: u64,
    arrivals: VecDeque<(u64, u128)>, // (unix_ts, work)
}

impl ShareHashrate {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            arrivals: VecDeque::new(),
        }
    }

    /// Record `count` shares admitted at `now` whose threshold was `tau_share`.
    pub fn record_batch(&mut self, now: u64, count: u64, tau_share: &Hash) {
        let w = share_work(tau_share);
        for _ in 0..count {
            self.arrivals.push_back((now, w));
        }
        self.prune(now);
    }

    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.window_secs);
        while let Some(&(ts, _)) = self.arrivals.front() {
            if ts < cutoff {
                self.arrivals.pop_front();
            } else {
                break;
            }
        }
    }

    /// Shares currently in the window — the sampling-density advantage.
    pub fn sample_count(&self) -> usize {
        self.arrivals.len()
    }

    /// Estimated hashrate (H/s) over the observed span ending at `now`.
    pub fn estimate(&mut self, now: u64) -> f64 {
        self.prune(now);
        if self.arrivals.is_empty() {
            return 0.0;
        }
        let total_work: u128 = self.arrivals.iter().map(|&(_, w)| w).sum();
        let oldest = self.arrivals.front().map(|&(ts, _)| ts).unwrap_or(now);
        let span = now.saturating_sub(oldest).max(1) as f64;
        total_work as f64 / span
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tgt(d: u64) -> Hash {
        Hash::from_difficulty(d)
    }

    #[test]
    fn point_estimate_is_count_times_work_over_window() {
        let t = tgt(1000);
        let w = share_work(&t) as f64;
        let hr = hashrate_from_shares(60, 120.0, &t);
        assert!((hr - 60.0 * w / 120.0).abs() < 1e-6);
        assert_eq!(hashrate_from_shares(10, 0.0, &t), 0.0, "guard div-by-zero");
    }

    #[test]
    fn denser_sampling_is_tighter() {
        // 60 shares vs 1 block over the same window: √60 ≈ 7.7× lower std.
        let r = std_ratio_vs_blocks(60, 1);
        assert!((r - (1.0f64 / 60.0).sqrt()).abs() < 1e-9);
        assert!(r < 0.14, "~87% lower noise at 60x density");
    }

    #[test]
    fn window_prunes_old_arrivals() {
        let t = tgt(1000);
        let mut hr = ShareHashrate::new(100);
        hr.record_batch(1_000, 30, &t);
        assert_eq!(hr.sample_count(), 30);
        // 150s later: the 1_000-era arrivals are outside the 100s window.
        hr.record_batch(1_150, 5, &t);
        assert_eq!(hr.sample_count(), 5, "old arrivals pruned");
    }

    #[test]
    fn estimate_scales_with_work_and_rate() {
        let t = tgt(4096);
        let mut hr = ShareHashrate::new(DEFAULT_WINDOW_SECS);
        hr.record_batch(2_000, 1, &t);
        hr.record_batch(2_010, 1, &t);
        // 2 shares spanning 10s → ~ 2·work / 10.
        let est = hr.estimate(2_010);
        let expect = 2.0 * share_work(&t) as f64 / 10.0;
        assert!((est - expect).abs() / expect < 1e-6);
    }
}
