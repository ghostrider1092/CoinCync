//! Non-consensus difficulty / block-production telemetry.
//!
//! Deliberately lives OUTSIDE the hash-locked `difficulty.rs`: these are
//! informational statistics over historical block timestamps (f64 math), never
//! consensus inputs, so they must not sit in a file whose byte-hash gates
//! consensus review. See `docs/design/difficulty-health-telemetry.md`.
//!
//! The block-oscillation analysis found the testnet's difficulty trouble is a
//! calibration problem, not an algorithm one — so the useful thing to expose is
//! the *observable*: how regular block production actually is.

use crate::consensus::difficulty::DifficultyBlock;

/// Inter-block interval statistics over a window of blocks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IntervalStats {
    /// Number of inter-block intervals measured (window length - 1).
    pub samples: usize,
    /// Mean interval in seconds.
    pub mean_secs: f64,
    /// Population standard deviation of intervals in seconds.
    pub stddev_secs: f64,
    /// Smallest observed interval.
    pub min_secs: u64,
    /// Largest observed interval.
    pub max_secs: u64,
    /// Most recent interval (between the last two blocks in the window).
    pub last_secs: u64,
}

impl IntervalStats {
    /// The empty/degenerate result for a window too small to have an interval.
    pub const EMPTY: IntervalStats = IntervalStats {
        samples: 0,
        mean_secs: 0.0,
        stddev_secs: 0.0,
        min_secs: 0,
        max_secs: 0,
        last_secs: 0,
    };
}

/// Compute inter-block interval statistics from a window of `DifficultyBlock`s
/// ordered by ascending height. Uses saturating subtraction so a non-monotonic
/// timestamp (possible under the +1s rule / MTP) yields a 0 interval rather than
/// underflowing. A window of fewer than 2 blocks returns [`IntervalStats::EMPTY`].
/// Never panics.
pub fn interval_stats(blocks: &[DifficultyBlock]) -> IntervalStats {
    if blocks.len() < 2 {
        return IntervalStats::EMPTY;
    }
    let intervals: Vec<u64> = blocks
        .windows(2)
        .map(|w| w[1].timestamp.saturating_sub(w[0].timestamp))
        .collect();
    let n = intervals.len();
    let sum: u64 = intervals.iter().copied().sum();
    let mean = sum as f64 / n as f64;
    let variance = intervals
        .iter()
        .map(|&x| {
            let d = x as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n as f64;
    IntervalStats {
        samples: n,
        mean_secs: mean,
        stddev_secs: variance.sqrt(),
        min_secs: intervals.iter().copied().min().unwrap_or(0),
        max_secs: intervals.iter().copied().max().unwrap_or(0),
        last_secs: intervals.last().copied().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Hash;

    fn blk(height: u64, timestamp: u64) -> DifficultyBlock {
        // `target` is irrelevant to interval statistics.
        DifficultyBlock {
            height,
            timestamp,
            target: Hash::zero(),
        }
    }

    #[test]
    fn regular_spacing_zero_variance() {
        let blocks: Vec<_> = (0..5u64).map(|i| blk(i, i * 120)).collect();
        let s = interval_stats(&blocks);
        assert_eq!(s.samples, 4);
        assert_eq!(s.mean_secs, 120.0);
        assert_eq!(s.stddev_secs, 0.0);
        assert_eq!(s.min_secs, 120);
        assert_eq!(s.max_secs, 120);
        assert_eq!(s.last_secs, 120);
    }

    #[test]
    fn degenerate_and_nonmonotonic_no_panic() {
        assert_eq!(interval_stats(&[]), IntervalStats::EMPTY);
        assert_eq!(interval_stats(&[blk(0, 100)]), IntervalStats::EMPTY);
        // Non-monotonic timestamp saturates to a 0 interval instead of underflowing.
        let s = interval_stats(&[blk(0, 200), blk(1, 100)]);
        assert_eq!(s.samples, 1);
        assert_eq!(s.last_secs, 0);
        assert_eq!(s.mean_secs, 0.0);
    }

    #[test]
    fn variance_for_irregular_spacing() {
        // timestamps 0,60,240 -> intervals 60,180 -> mean 120, stddev 60.
        let s = interval_stats(&[blk(0, 0), blk(1, 60), blk(2, 240)]);
        assert_eq!(s.samples, 2);
        assert_eq!(s.mean_secs, 120.0);
        assert!((s.stddev_secs - 60.0).abs() < 1e-9);
        assert_eq!(s.min_secs, 60);
        assert_eq!(s.max_secs, 180);
    }
}
