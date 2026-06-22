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
    /// CIP-012: v1.0.12 hard-fork bundle.
    ///
    /// Composite bit signaling miner readiness for the v1.0.12 consensus
    /// upgrades (already implemented + gated by `HARD_FORK_V1_0_12_HEIGHT`
    /// on `feat/v1012-hard-fork-forward-port` / PR #68):
    ///
    ///   - encrypted_amount tightened to exactly 8 bytes
    ///   - per-output size caps at block-level validation
    ///   - reject duplicate stealth addresses within a single tx
    ///   - reject cross-tx duplicate stealth addresses within a block
    ///   - ring-size uses monotonic `total_outputs_ever()` (H1 release blocker)
    ///
    /// Bundled into a SINGLE bit because these all activate together as
    /// the v1.0.12 release — they share the same release tag, same
    /// deployment cadence, same test matrix. Bitcoin Core's BIP 9 uses
    /// the bundle-per-bit pattern for the same reason (Taproot was a
    /// single bit for BIP 340 + 341 + 342 even though those are 3 BIPs).
    ///
    /// Activation gate is currently `HARD_FORK_V1_0_12_HEIGHT = u64::MAX`
    /// (height-based, dormant). Future: add BIP-9 state-machine wiring
    /// in `validation.rs` so activation requires BOTH the height gate
    /// AND `SIGNAL_THRESHOLD` blocks in a `SIGNAL_WINDOW` window having
    /// this bit set — closes the "premature activation while miners
    /// still on old binaries" risk that BIP 8 (LOT=true) covers in
    /// Bitcoin Core. Until that wiring lands, this bit is informational
    /// only — miners CAN signal but the validator doesn't yet consult
    /// the signal state.
    pub const V1_0_12_BUNDLE: u32 = 1 << 6;
    // Bits 7–30: reserved for future CIPs
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
    // v1.0.12 hard-fork bundle. Currently dormant (start_height = u64::MAX)
    // — operator sets real values when the fork release schedule firms up.
    //
    // When activating, the canonical Bitcoin BIP 9 pattern is to align
    // `start_height` to a SIGNAL_WINDOW boundary (multiple of 2016) so the
    // first signaling window is a complete window. timeout_height is then
    // start_height + N*SIGNAL_WINDOW for some N giving miners enough cadence
    // to upgrade. min_activation_height is typically timeout_height + 1 grace
    // window so even a last-window lock-in has time to propagate before any
    // node enforces the new rules. Example for a 3-window deployment:
    //
    //   start_height: 100_800          // 50 * 2016
    //   timeout_height: 106_848        // start + 3 * 2016
    //   min_activation_height: 108_864 // timeout + 1 * 2016 (grace)
    //
    // (Those numbers are illustrative — actual values pending operator
    // release-schedule decision; see [[project_roadmap_v1_0_13_to_16]].)
    Deployment {
        name:                  "v1.0.12-bundle",
        bit:                   bits::V1_0_12_BUNDLE,
        start_height:          u64::MAX,
        timeout_height:        u64::MAX,
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
        // INVARIANT: `count <= total` under normal operation, since
        // signal_count_fn returns the count of blocks in the
        // [window_start, current_height) range that signaled. But if
        // we land here at the start of a window with `total` clamped
        // to 1 by `.max(1)` above (current_height == window_start,
        // no blocks in the window yet), a non-zero count would
        // produce a nonsensical >100% pct. `.min(100)` clamps the
        // UI-facing value so explorers/dashboards never see "500%
        // signaling" briefly during window transitions.
        let pct = ((count * 100 / total) as u32).min(100);

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

    #[test]
    fn v1_0_12_bundle_bit_distinct_from_other_cips() {
        // Each CIP must use a distinct bit. A typo that gave V1_0_12_BUNDLE
        // the same value as an existing CIP would cause double-signaling
        // (a single miner block would appear to signal for both at once),
        // which would corrupt the activation state machines for both
        // deployments. This test makes that mistake compile-fail-loud.
        let all_cips = [
            ("VIEW_TAGS",      bits::VIEW_TAGS),
            ("RING_SIZE_16",   bits::RING_SIZE_16),
            ("FEE_MARKET_V2",  bits::FEE_MARKET_V2),
            ("HALO2_SHIELDED", bits::HALO2_SHIELDED),
            ("LELANTUS_SPARK", bits::LELANTUS_SPARK),
            ("MW_CUTTHROUGH",  bits::MW_CUTTHROUGH),
            ("V1_0_12_BUNDLE", bits::V1_0_12_BUNDLE),
            ("MUST_SET",       bits::MUST_SET),
        ];
        for (i, (name_a, bit_a)) in all_cips.iter().enumerate() {
            for (name_b, bit_b) in &all_cips[i + 1..] {
                assert_ne!(
                    bit_a, bit_b,
                    "CIP bit collision: {} and {} both = 0x{:08x}",
                    name_a, name_b, bit_a,
                );
            }
        }
    }

    #[test]
    fn v1_0_12_bundle_signaled_by_dedicated_bit_only() {
        // A coinbase signaling for ONLY the v1.0.12 bundle must NOT
        // accidentally signal for any other CIP. Guards against the
        // case where SignalBits::new() OR's in unintended bits, or
        // where the bit constant is defined as a mask covering more
        // than its intended bit.
        let s = SignalBits::new(bits::V1_0_12_BUNDLE);
        assert!(s.signals(bits::V1_0_12_BUNDLE), "must signal own bit");
        assert!(s.signals(bits::MUST_SET),       "MUST_SET always implicit");
        for other in [
            bits::VIEW_TAGS,
            bits::RING_SIZE_16,
            bits::FEE_MARKET_V2,
            bits::HALO2_SHIELDED,
            bits::LELANTUS_SPARK,
            bits::MW_CUTTHROUGH,
        ] {
            assert!(
                !s.signals(other),
                "v1.0.12 signal leaked into other CIP bit 0x{:08x}", other,
            );
        }
    }

    #[test]
    fn v1_0_12_bundle_deployment_registered_dormant() {
        // The deployment must be present in DEPLOYMENTS so callers can
        // iterate them, but all three height fields MUST be u64::MAX
        // until an operator deliberately enables the schedule. A
        // misconfigured non-MAX value would let the BIP 9 state machine
        // begin transitioning state silently against production
        // chains — exactly the premature-activation class the deployment
        // schedule exists to prevent.
        let d = DEPLOYMENTS
            .iter()
            .find(|d| d.bit == bits::V1_0_12_BUNDLE)
            .expect("V1_0_12_BUNDLE must be registered in DEPLOYMENTS");
        assert_eq!(d.name, "v1.0.12-bundle");
        assert_eq!(d.start_height, u64::MAX, "must ship dormant");
        assert_eq!(d.timeout_height, u64::MAX, "must ship dormant");
        assert_eq!(d.min_activation_height, u64::MAX, "must ship dormant");
    }
}
