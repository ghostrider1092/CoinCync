// src/consensus/fork_signal.rs
//
// BIP9-style soft-fork signaling.
//
// Miners signal readiness by setting bits in the coinbase extra_nonce field.
// When >= SIGNAL_THRESHOLD% of blocks in a SIGNAL_WINDOW-block window signal
// for a deployment, it "locks in" and activates the following window.

use serde::{Deserialize, Serialize};
use borsh::{BorshSerialize, BorshDeserialize};
use crate::constants::{SIGNAL_WINDOW, SIGNAL_THRESHOLD};

// ── Bit assignments ───────────────────────────────────────────
// Each bit corresponds to one pending CoinCync Improvement Proposal.
// Add new bits here as CIPs are accepted for signaling.
pub mod bits {
    /// CIP-001: View tags for fast wallet scanning
    pub const VIEW_TAGS:      u32 = 1 << 0;
    /// CIP-002: Increase ring size to 16
    pub const RING_SIZE_16:   u32 = 1 << 1;
    /// CIP-003: Fee market improvements
    pub const FEE_MARKET_V2:  u32 = 1 << 2;
    /// CIP-004: Halo2 shielded pool activation (Zcash Orchard style)
    pub const HALO2_SHIELDED: u32 = 1 << 3;
    /// CIP-005: Lelantus Spark large-anonymity-set pool (Firo style)
    pub const LELANTUS_SPARK: u32 = 1 << 4;
    /// CIP-006: MimbleWimble cut-through (Grin style)
    pub const MW_CUTTHROUGH:  u32 = 1 << 5;
    // Bits 6–30: reserved for future CIPs
    /// Must always be set (identifies CoinCync 1.0 blocks)
    pub const MUST_SET:       u32 = 1 << 31;
}

/// A 32-bit field embedded in every coinbase's extra_nonce area.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SignalBits(pub u32);

impl SignalBits {
    pub fn new(raw: u32) -> Self { Self(raw | bits::MUST_SET) }
    pub fn signals(&self, bit: u32) -> bool { self.0 & bit != 0 }
    pub fn raw(&self) -> u32 { self.0 }
}

/// Describes a single protocol upgrade deployment.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub name:                 &'static str,
    pub bit:                  u32,
    /// Height at which signaling window opens
    pub start_height:         u64,
    /// Height at which deployment times out if not activated
    pub timeout_height:       u64,
    /// Minimum height at which activation can occur
    pub min_activation_height: u64,
}

/// All registered protocol deployments.
pub static DEPLOYMENTS: &[Deployment] = &[
    Deployment {
        name:                 "view-tags",
        bit:                  bits::VIEW_TAGS,
        start_height:         0,
        timeout_height:       1_000_000,
        min_activation_height: 2016,
    },
    // M-5 FIX: Phase 2 features disabled until external audit complete
    Deployment {
        name:                 "halo2-shielded",
        bit:                  bits::HALO2_SHIELDED,
        start_height:         u64::MAX,
        timeout_height:       u64::MAX,
        min_activation_height: u64::MAX,
    },
    Deployment {
        name:                 "lelantus-spark",
        bit:                  bits::LELANTUS_SPARK,
        start_height:         u64::MAX,
        timeout_height:       u64::MAX,
        min_activation_height: u64::MAX,
    },
    Deployment {
        name:                 "mw-cutthrough",
        bit:                  bits::MW_CUTTHROUGH,
        start_height:         u64::MAX,
        timeout_height:       u64::MAX,
        min_activation_height: u64::MAX,
    },
];

/// The current state of a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentState {
    /// Before start_height
    Defined,
    /// Signaling in progress
    Started { signaling_pct: u32 },
    /// Threshold met — activates at the beginning of the NEXT window
    LockedIn { at_height: u64 },
    /// Active — protocol upgrade is enforced
    Active,
    /// Timed out without reaching threshold
    Failed,
}

/// Tracks signaling state for all deployments.
pub struct ForkSignaler {
    /// For each deployment bit, the height at which it locked in (if any).
    locked_in: std::collections::HashMap<u32, u64>,
}

impl ForkSignaler {
    pub fn new() -> Self {
        Self { locked_in: Default::default() }
    }

    /// Query the state of a deployment at `current_height`.
    ///
    /// `signal_count_fn` returns the number of blocks in the window
    /// `[window_start, current_height)` that have the given bit set.
    pub fn state<F>(
        &self,
        deployment: &Deployment,
        current_height: u64,
        signal_count_fn: F,
    ) -> DeploymentState
    where
        F: Fn(u64, u64, u32) -> u64,   // (window_start, window_end, bit) -> count
    {
        if current_height < deployment.start_height {
            return DeploymentState::Defined;
        }
        if current_height >= deployment.timeout_height {
            if !self.locked_in.contains_key(&deployment.bit) {
                return DeploymentState::Failed;
            }
        }

        // Already locked in?
        if let Some(&locked_at) = self.locked_in.get(&deployment.bit) {
            let activation = self.next_window_start(locked_at);
            if current_height >= activation.max(deployment.min_activation_height) {
                return DeploymentState::Active;
            }
            return DeploymentState::LockedIn { at_height: activation };
        }

        // Count signaling in current window.
        //
        // BUG FIX: `SIGNAL_THRESHOLD` is an ABSOLUTE block count (e.g. 1814
        // out of 2016 = ~90%), not a percentage. Pre-fix this function
        // computed `pct = count * 100 / total` (a 0..=100 integer) and
        // compared it against `SIGNAL_THRESHOLD` (value 1814) — a check
        // that could never be true. That meant BIP9 soft-fork activation
        // was silently broken: no CIP would ever reach `LockedIn` through
        // signaling, no matter how many blocks voted. The `signaling_pct`
        // in `DeploymentState::Started` is still reported as a 0..=100
        // percentage because that's what a UI/explorer wants to display.
        let window_start = self.window_start(current_height);
        let count = signal_count_fn(window_start, current_height, deployment.bit);
        let total = current_height.saturating_sub(window_start).max(1);
        let pct = (count * 100 / total) as u32;

        if count >= SIGNAL_THRESHOLD {
            DeploymentState::LockedIn { at_height: self.next_window_start(current_height) }
        } else {
            DeploymentState::Started { signaling_pct: pct }
        }
    }

    /// Record that a deployment locked in at `height`.
    pub fn record_lock_in(&mut self, bit: u32, height: u64) {
        self.locked_in.insert(bit, height);
    }

    fn window_start(&self, height: u64) -> u64 {
        (height / SIGNAL_WINDOW) * SIGNAL_WINDOW
    }

    fn next_window_start(&self, height: u64) -> u64 {
        self.window_start(height) + SIGNAL_WINDOW
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_bits_must_set() {
        let s = SignalBits::new(0);
        assert!(s.signals(bits::MUST_SET));
    }

    #[test]
    fn signals_specific_bit() {
        let s = SignalBits::new(bits::VIEW_TAGS);
        assert!(s.signals(bits::VIEW_TAGS));
        assert!(!s.signals(bits::HALO2_SHIELDED));
    }

    /// Synthetic deployment used by the state-machine tests below. We
    /// deliberately do NOT use `DEPLOYMENTS[0]` because that's "view-tags",
    /// which has `start_height: 0` — it can never be observed in the
    /// `Defined` state, so any test that tries to exercise that state
    /// against it is fundamentally mis-coupled. Using a synthetic
    /// deployment with an explicit start_height makes the test's intent
    /// explicit and robust to future production deployment edits.
    fn synthetic_deployment() -> Deployment {
        Deployment {
            name: "test-cip",
            bit: 1 << 20,
            start_height: 5_000,
            timeout_height: 1_000_000,
            min_activation_height: 10_000,
        }
    }

    #[test]
    fn defined_before_start() {
        let signaler = ForkSignaler::new();
        let d = synthetic_deployment();
        // current_height < start_height → must be Defined.
        let state = signaler.state(&d, 1_000, |_, _, _| 0);
        assert_eq!(state, DeploymentState::Defined);
    }

    #[test]
    fn locks_in_at_threshold() {
        let signaler = ForkSignaler::new();
        let d = synthetic_deployment();
        // At current_height = 6_000 we're past start_height = 5_000 and still
        // before timeout_height. Report exactly `SIGNAL_THRESHOLD` signaling
        // blocks so the state machine crosses the activation bar precisely.
        //
        // Important: this check now compares `count >= SIGNAL_THRESHOLD`
        // (absolute block count), not a percentage — see the bug fix in
        // `ForkSignaler::state`.
        let state = signaler.state(&d, 6_000, |_, _, _| SIGNAL_THRESHOLD);
        assert!(
            matches!(state, DeploymentState::LockedIn { .. }),
            "expected LockedIn, got {:?}", state
        );
    }

    #[test]
    fn below_threshold_stays_started() {
        let signaler = ForkSignaler::new();
        let d = synthetic_deployment();
        // One below the absolute threshold — must still be Started.
        let state = signaler.state(&d, 6_000, |_, _, _| SIGNAL_THRESHOLD - 1);
        assert!(
            matches!(state, DeploymentState::Started { .. }),
            "expected Started, got {:?}", state
        );
    }
}
