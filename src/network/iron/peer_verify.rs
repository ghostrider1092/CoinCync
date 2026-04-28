//! # Peer Verification Layer
//!
//! Fast O(1) checks that run BEFORE a block enters the full validation pipeline.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use crate::network::peer::PeerId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuickCheckResult {
    Pass,
    Reject(String),
    Ban(String),
}

#[derive(Debug, Default)]
pub struct PeerHeightRecord {
    pub announced: u64,
    pub proven:    u64,
    pub overreach_count: u32,
}

impl PeerHeightRecord {
    /// Record a height announcement. Returns false if suspiciously high.
    /// Bootstrap grace: if proven == 0, any height is accepted (peer hasn't
    /// had a chance to prove anything yet — e.g. fresh node at height 0
    /// connecting to a peer at height 500).
    pub fn on_announce(&mut self, height: u64, max_lead: u64) -> bool {
        self.announced = height;
        // Bootstrap grace: don't penalize before first proven block
        if self.proven == 0 {
            return true;
        }
        if height > self.proven + max_lead {
            self.overreach_count += 1;
            return false;
        }
        true
    }

    pub fn on_block_proven(&mut self, height: u64) {
        if height > self.proven {
            self.proven = height;
        }
    }
}

pub struct PeerVerifier {
    heights: HashMap<PeerId, PeerHeightRecord>,
    max_height_lead: u64,
    min_difficulty: u128,
    future_tolerance_secs: u64,
}

impl PeerVerifier {
    pub fn new(max_height_lead: u64, min_difficulty: u128, future_tolerance_secs: u64) -> Self {
        PeerVerifier {
            heights: HashMap::new(),
            max_height_lead,
            min_difficulty,
            future_tolerance_secs,
        }
    }

    pub fn record_announced_height(&mut self, peer: PeerId, height: u64) -> bool {
        let rec = self.heights.entry(peer).or_default();
        let ok = rec.on_announce(height, self.max_height_lead);
        if !ok {
            // Not a bad-block strike and not a ban trigger — informational only
            debug!(
                "PeerVerifier: peer announced height {height} but only proved {}  \
                 (overreach #{})  max_lead={}",
                rec.proven, rec.overreach_count, self.max_height_lead
            );
        }
        ok
    }

    pub fn confirm_block(&mut self, peer: PeerId, height: u64) {
        self.heights.entry(peer).or_default().on_block_proven(height);
    }

    pub fn proven_height(&self, peer: &PeerId) -> u64 {
        self.heights.get(peer).map(|r| r.proven).unwrap_or(0)
    }

    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.heights.remove(peer);
    }

    /// Run all quick checks on an incoming block header.
    pub fn quick_check(
        &self,
        header_hash:      &[u8; 32],
        target:           &[u8; 32],
        block_timestamp:  u64,
        parent_timestamp: u64,
        difficulty:       u128,
    ) -> QuickCheckResult {
        if let Some(r) = self.check_difficulty(difficulty) { return r; }
        if let Some(r) = self.check_timestamp(block_timestamp, parent_timestamp) { return r; }
        if let Some(r) = self.check_pow(header_hash, target) { return r; }
        QuickCheckResult::Pass
    }

    fn check_difficulty(&self, difficulty: u128) -> Option<QuickCheckResult> {
        if difficulty < self.min_difficulty {
            return Some(QuickCheckResult::Ban(format!(
                "block difficulty {difficulty} below minimum {}",
                self.min_difficulty
            )));
        }
        None
    }

    fn check_timestamp(&self, block_ts: u64, parent_ts: u64) -> Option<QuickCheckResult> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if block_ts > now + self.future_tolerance_secs {
            return Some(QuickCheckResult::Reject(format!(
                "block timestamp {block_ts} is {} seconds in the future",
                block_ts.saturating_sub(now),
            )));
        }

        if block_ts <= parent_ts {
            return Some(QuickCheckResult::Ban(format!(
                "block timestamp {block_ts} is not after parent {parent_ts}"
            )));
        }

        None
    }

    fn check_pow(&self, header_hash: &[u8; 32], target: &[u8; 32]) -> Option<QuickCheckResult> {
        if header_hash > target {
            return Some(QuickCheckResult::Ban(format!(
                "invalid PoW: hash {:?}... > target {:?}...",
                &header_hash[..4], &target[..4]
            )));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> PeerVerifier {
        PeerVerifier::new(10, 100, 7_200)
    }

    #[test]
    fn bootstrap_grace_allows_any_height_when_proven_zero() {
        let mut v = verifier();
        let peer = [1u8; 32];
        // proven=0, should accept any height (bootstrap grace)
        assert!(v.record_announced_height(peer, 100));
        assert_eq!(v.heights[&peer].overreach_count, 0);
    }

    #[test]
    fn height_overreach_detected_after_proven() {
        let mut v = verifier();
        let peer = [1u8; 32];
        v.confirm_block(peer, 5); // proven=5
        // announce 100 (lead = 95 > 10) — now overreach applies
        assert!(!v.record_announced_height(peer, 100));
        assert_eq!(v.heights[&peer].overreach_count, 1);
    }

    #[test]
    fn height_within_lead_accepted() {
        let mut v = verifier();
        let peer = [2u8; 32];
        v.confirm_block(peer, 50);
        assert!(v.record_announced_height(peer, 55));
    }

    #[test]
    fn pow_invalid_banned() {
        let v = verifier();
        let hash   = [0xFF; 32];
        let target = [0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(matches!(v.check_pow(&hash, &target), Some(QuickCheckResult::Ban(_))));
    }

    #[test]
    fn difficulty_below_floor_banned() {
        let v = verifier();
        assert!(matches!(v.check_difficulty(50), Some(QuickCheckResult::Ban(_))));
    }

    #[test]
    fn timestamp_before_parent_banned() {
        let v = verifier();
        assert!(matches!(v.check_timestamp(1000, 2000), Some(QuickCheckResult::Ban(_))));
    }
}
