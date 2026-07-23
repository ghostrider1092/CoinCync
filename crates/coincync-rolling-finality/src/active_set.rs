//! The rolling active miner set.
//!
//! A miner is "active at height H" iff they have produced at least
//! one block in `[H - WINDOW, H)`. Active miners' attestations count
//! toward the 2/3 quorum threshold; inactive miners' attestations
//! are rejected with `MinerNotActive`.
//!
//! Why blocks-not-time: the chain's notion of time is the chain
//! itself. Wall-clock-based windowing reintroduces the time-warp
//! vulnerability the CIP exists to avoid (CIP-009.D §"Time-warp
//! attacks").

use std::collections::BTreeMap;

use crate::types::MinerPubkey;

/// What we know about a miner: when they were first seen, when they
/// were most recently seen. Both are block heights; we never store
/// timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MinerRecord {
    /// First block this miner produced (immutable once set).
    pub first_seen_height: u64,
    /// Most recent block this miner produced. Updated every time
    /// they mine a new block.
    pub last_seen_height: u64,
}

/// Tracks the rolling-window set of active miners.
///
/// Internally stores every miner ever seen. The "active" predicate
/// is computed dynamically from `last_seen_height` and the query
/// height. Storing inactive miners is cheap (one record per miner)
/// and lets us tell "this is a known miner who lapsed" apart from
/// "this is a brand-new miner" — useful for the eventual rotation
/// flow.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveMinerSet {
    miners: BTreeMap<MinerPubkey, MinerRecord>,
    /// `WINDOW` from the CIP: a miner who hasn't mined a block in
    /// the last `window` blocks is considered inactive. CIP-009.D
    /// default is 10000 (~14 days at 120s blocks).
    window: u64,
}

impl ActiveMinerSet {
    /// Construct a new (empty) active miner set with the given
    /// window. Window must be > 0; passing 0 means "no miner is
    /// ever active," which would jam the system.
    pub fn new(window: u64) -> Self {
        assert!(window > 0, "ActiveMinerSet window must be > 0");
        ActiveMinerSet {
            miners: BTreeMap::new(),
            window,
        }
    }

    /// Record that `miner` produced a block at `height`. Idempotent:
    /// calling this twice with the same (miner, height) leaves the
    /// state unchanged. Calling with an OLDER `height` than the
    /// miner's `last_seen_height` is also a no-op (we never
    /// regress).
    pub fn record_block(&mut self, miner: MinerPubkey, height: u64) {
        match self.miners.get_mut(&miner) {
            Some(record) => {
                if height > record.last_seen_height {
                    record.last_seen_height = height;
                }
                // first_seen_height is immutable; we never lower it.
            }
            None => {
                self.miners.insert(
                    miner,
                    MinerRecord {
                        first_seen_height: height,
                        last_seen_height: height,
                    },
                );
            }
        }
    }

    /// Is `miner` active at `at_height`?
    pub fn is_active(&self, miner: &MinerPubkey, at_height: u64) -> bool {
        self.miners
            .get(miner)
            .map(|r| Self::is_active_record(r, at_height, self.window))
            .unwrap_or(false)
    }

    /// Number of distinct miners active at `at_height`.
    pub fn active_count(&self, at_height: u64) -> usize {
        self.miners
            .values()
            .filter(|r| Self::is_active_record(r, at_height, self.window))
            .count()
    }

    /// Return the set of pubkeys active at `at_height`, in the
    /// canonical BTreeMap ordering. Used by tests and by reporting.
    pub fn active_miners(&self, at_height: u64) -> Vec<MinerPubkey> {
        self.miners
            .iter()
            .filter(|(_, r)| Self::is_active_record(r, at_height, self.window))
            .map(|(k, _)| *k)
            .collect()
    }

    /// Total miner count (including inactive — i.e., everyone we've
    /// ever seen). Useful for diagnostics; do not use this for the
    /// quorum threshold.
    pub fn total_count(&self) -> usize {
        self.miners.len()
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    /// Inner: is this record active at this height?
    ///
    /// A miner is active at `at_height` iff they mined at least one
    /// block in `(at_height - window, at_height]`. We don't store
    /// every block height, only `first_seen` and `last_seen`. Two
    /// cases give us evidence the miner is active:
    ///
    /// 1. `first_seen` itself is in the window. The miner mined at
    ///    `first_seen`; if that block is in `(at_height - window,
    ///    at_height]`, they were active.
    /// 2. `last_seen` is in the window AND `last_seen <= at_height`.
    ///    The miner mined at `last_seen`; if that's in the window
    ///    and not in the future, they were active.
    ///
    /// What this MISSES: a miner with `first_seen` way old and
    /// `last_seen` way in the future and a silent gap covering the
    /// window. Without per-block heights we can't detect that case;
    /// we conservatively return `false` (no false positives). For
    /// the (much more common) case of a miner who mined recently
    /// but `last_seen` has since advanced past `at_height`, we now
    /// correctly accept based on `first_seen` — earlier code rejected
    /// these legitimate retrospective attestations.
    fn is_active_record(record: &MinerRecord, at_height: u64, window: u64) -> bool {
        // Miner hadn't appeared yet at the query height.
        if record.first_seen_height > at_height {
            return false;
        }
        // first_seen is at-or-before at_height by the check above.
        // If first_seen lies inside the window, we have evidence
        // of activity: that block is in (at_height - window, at_height].
        if at_height - record.first_seen_height < window {
            return true;
        }
        // first_seen is too far back to count by itself. Check
        // whether last_seen lies in the window AND isn't in the
        // future relative to the query.
        if at_height >= record.last_seen_height && at_height - record.last_seen_height < window {
            return true;
        }
        // Otherwise we have no evidence either way (miner's known
        // blocks straddle at_height with a silent gap covering the
        // window). Conservative: inactive.
        false
    }

    /// Borrow the underlying map. Used by serialization integration
    /// and by tests; not part of the principal API.
    pub fn raw_miners(&self) -> &BTreeMap<MinerPubkey, MinerRecord> {
        &self.miners
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> MinerPubkey {
        [byte; 32]
    }

    #[test]
    fn record_block_inserts_new_miner() {
        let mut set = ActiveMinerSet::new(100);
        set.record_block(pk(1), 50);
        assert_eq!(set.total_count(), 1);
        assert!(set.is_active(&pk(1), 50));
        assert!(set.is_active(&pk(1), 100));
        // miner who's been gone for window-or-more is inactive
        assert!(!set.is_active(&pk(1), 150));
    }

    #[test]
    fn record_block_updates_last_seen() {
        let mut set = ActiveMinerSet::new(100);
        set.record_block(pk(1), 50);
        set.record_block(pk(1), 75);
        let record = set.raw_miners().get(&pk(1)).unwrap();
        assert_eq!(record.first_seen_height, 50);
        assert_eq!(record.last_seen_height, 75);
    }

    #[test]
    fn record_block_idempotent_at_same_height() {
        let mut set = ActiveMinerSet::new(100);
        set.record_block(pk(1), 50);
        set.record_block(pk(1), 50);
        assert_eq!(set.total_count(), 1);
    }

    #[test]
    fn out_of_order_block_does_not_regress_last_seen() {
        let mut set = ActiveMinerSet::new(100);
        set.record_block(pk(1), 75);
        set.record_block(pk(1), 50); // older — must not lower last_seen
        let record = set.raw_miners().get(&pk(1)).unwrap();
        assert_eq!(record.last_seen_height, 75);
    }

    #[test]
    fn active_count_excludes_lapsed_miners() {
        let mut set = ActiveMinerSet::new(100);
        set.record_block(pk(1), 10); // mined long ago
        set.record_block(pk(2), 90); // mined recently
                                     // At height 200, miner 1 lapsed (200 - 10 = 190 >= window 100)
                                     // but miner 2 is still active (200 - 90 = 110 >= window 100, also lapsed)
        assert_eq!(set.active_count(200), 0);
        // At height 100, miner 2 is active (100 - 90 = 10 < 100)
        // miner 1 lapsed (100 - 10 = 90 < 100, so still active actually)
        // Both active.
        assert_eq!(set.active_count(100), 2);
        // At height 110, miner 1 is right on the boundary
        // (110 - 10 = 100, NOT < 100 — boundary EXCLUDES oldest)
        // miner 2 still active.
        assert_eq!(set.active_count(110), 1);
    }
}
