// src/consensus/fork_signal.rs
//
// BIP9-style soft-fork signaling.
//
// Miners signal readiness by setting bits in the coinbase extra_nonce field.
// When >= SIGNAL_THRESHOLD% of blocks in a SIGNAL_WINDOW-block window signal
// for a deployment, it "locks in" and activates the following window.

use crate::constants::{SIGNAL_THRESHOLD, SIGNAL_WINDOW};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

// ── Bit assignments ───────────────────────────────────────────
// Each bit corresponds to one pending CoinCync Improvement Proposal.
// Add new bits here as CIPs are accepted for signaling.
pub mod bits {
    /// CIP-001: View tags for fast wallet scanning
    pub const VIEW_TAGS: u32 = 1 << 0;
    /// CIP-002: Increase ring size to 16
    pub const RING_SIZE_16: u32 = 1 << 1;
    /// CIP-003: Fee market improvements
    pub const FEE_MARKET_V2: u32 = 1 << 2;
    /// CIP-004: Halo2 shielded pool activation (Zcash Orchard style)
    pub const HALO2_SHIELDED: u32 = 1 << 3;
    /// CIP-005: Lelantus Spark large-anonymity-set pool (Firo style)
    pub const LELANTUS_SPARK: u32 = 1 << 4;
    /// CIP-006: MimbleWimble cut-through (Grin style)
    pub const MW_CUTTHROUGH: u32 = 1 << 5;
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
    pub const MUST_SET: u32 = 1 << 31;
}

/// A 32-bit field embedded in every coinbase's extra_nonce area.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SignalBits(pub u32);

impl SignalBits {
    pub fn new(raw: u32) -> Self {
        Self(raw | bits::MUST_SET)
    }
    pub fn signals(&self, bit: u32) -> bool {
        self.0 & bit != 0
    }
    pub fn raw(&self) -> u32 {
        self.0
    }
}

/// Describes a single protocol upgrade deployment.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub name: &'static str,
    pub bit: u32,
    /// Height at which signaling window opens
    pub start_height: u64,
    /// Height at which deployment times out if not activated
    pub timeout_height: u64,
    /// Minimum height at which activation can occur
    pub min_activation_height: u64,
}

/// All registered protocol deployments.
pub static DEPLOYMENTS: &[Deployment] = &[
    Deployment {
        name: "view-tags",
        bit: bits::VIEW_TAGS,
        start_height: 0,
        timeout_height: 1_000_000,
        min_activation_height: 2016,
    },
    // M-5 FIX: Phase 2 features disabled until external audit complete
    Deployment {
        name: "halo2-shielded",
        bit: bits::HALO2_SHIELDED,
        start_height: u64::MAX,
        timeout_height: u64::MAX,
        min_activation_height: u64::MAX,
    },
    Deployment {
        name: "lelantus-spark",
        bit: bits::LELANTUS_SPARK,
        start_height: u64::MAX,
        timeout_height: u64::MAX,
        min_activation_height: u64::MAX,
    },
    Deployment {
        name: "mw-cutthrough",
        bit: bits::MW_CUTTHROUGH,
        start_height: u64::MAX,
        timeout_height: u64::MAX,
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
        name: "v1.0.12-bundle",
        bit: bits::V1_0_12_BUNDLE,
        start_height: u64::MAX,
        timeout_height: u64::MAX,
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

// ── Coinbase `extra` field encoding ───────────────────────────────
//
// Miners signal their CIP votes by embedding `SignalBits` in the
// coinbase transaction's `extra` field. The layout is:
//
//    [0..8]    height_le_u64       (existing; same as pre-CIP-012)
//    [8..12]   signal_bits_le_u32  (new; OMITTED when raw bits = 0)
//
// Backward-compat: a coinbase with `extra.len() == 8` (no trailing
// signal bytes) is interpreted as "no signal" (SignalBits(0)). This
// is what every pre-CIP-012 coinbase looks like. New miners that
// pass `--signal-v1012` produce 12-byte extra; new miners that
// don't pass any signal flag produce 8-byte extra (unchanged from
// today). Validators accept BOTH lengths and decode accordingly —
// the encoding is purely additive, no schema-versioning needed,
// no hard-fork required for the encoding itself.
//
// Prior art:
// - **Bitcoin Core (BIP 9)**: signal bits live in the `nVersion`
//   field of the block header (4 bytes, upper bits reserved for
//   the versionbits state machine per the BIP 9 spec). CoinCync's
//   BlockHeader uses a narrower version field (see header.rs), so
//   we route signalling through the coinbase `extra` field instead
//   — same conceptual mechanism, different on-wire location. (The
//   "28 usable bits" specific count was not re-verified against
//   the BIP text this session; retained here loosely as "upper
//   bits" per the BIP-9 shape.)
// - **Monero**: miners signal hardfork-readiness via a coinbase-
//   embedded field rather than the block header. (The prior comment
//   named this as a `vote` field and claimed "our pattern follows
//   Monero's more directly than Bitcoin's". The specific `vote`
//   field name was not re-located in current Monero source this
//   session and the comparative claim is downgraded to qualitative
//   — both Monero and CoinCync route through coinbase; Bitcoin
//   Core routes through the header.)

/// Encode the `extra` field of a coinbase transaction with optional signal bits.
///
/// Always emits the 8-byte height prefix. Appends 4 bytes of signal-bit
/// little-endian u32 IFF the raw signal value is non-zero — keeps
/// pre-CIP-012 no-signal coinbases byte-identical to their historical
/// encoding.
///
/// ## "Non-zero" semantics — important distinction
///
/// `SignalBits` has TWO constructors:
///   - `SignalBits(0)` — the literal default; raw() == 0; no MUST_SET bit.
///   - `SignalBits::new(raw)` — OR's in MUST_SET (bit 31) so raw() != 0
///     even if the caller passes 0.
///
/// The encoder branches on `signal_bits.raw() != 0`, NOT on "the caller
/// chose to signal." A caller that wants TRULY no signal (legacy byte
/// layout) must pass `SignalBits(0)` directly — that's what the rig's
/// `run_solo_cli` does when no `--signal-vX` flag is set:
///
///   if raw == 0 { SignalBits(0) } else { SignalBits::new(raw) }
///
/// This guarantees:
///   - Operator doesn't pass `--signal-v1012` → SignalBits(0) → 8-byte
///     extra → byte-identical to pre-CIP-012 coinbase, no block-hash drift
///   - Operator passes `--signal-v1012` → SignalBits::new(V1_0_12_BUNDLE)
///     → raw() = 0x80000040 (MUST_SET | V1_0_12_BUNDLE) → 12-byte extra
///     with the signal trailer
///
/// Calling `SignalBits::new(0)` would emit a 4-byte trailer of just
/// MUST_SET — that's a valid CIP-012-era no-CIP-signaled coinbase
/// (different from legacy but technically valid). The rig avoids this
/// case via the explicit zero-check above; downstream callers should
/// either pass `SignalBits(0)` for "absolutely no signal bytes" or
/// `SignalBits::new(raw)` for "I want to opt into the new format and
/// signal these specific bits."
pub fn encode_coinbase_extra(height: u64, signal_bits: SignalBits) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&height.to_le_bytes());
    if signal_bits.raw() != 0 {
        out.extend_from_slice(&signal_bits.raw().to_le_bytes());
    }
    out
}

/// Decode signal bits from a coinbase transaction's `extra` field.
///
/// Returns `SignalBits(0)` for pre-CIP-012 coinbases (`extra.len() == 8`
/// or shorter) or any extra without the trailing 4 signal bytes. Returns
/// the decoded bits for new-format coinbases (`extra.len() >= 12`).
///
/// Never panics: short slices return the no-signal default; longer-than-12
/// slices ignore trailing bytes (forward-compat for future fields).
pub fn decode_signal_bits(extra: &[u8]) -> SignalBits {
    if extra.len() < 12 {
        return SignalBits(0);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&extra[8..12]);
    SignalBits(u32::from_le_bytes(buf))
}

/// Tracks signaling state for all deployments.
pub struct ForkSignaler {
    /// For each deployment bit, the height at which it locked in (if any).
    locked_in: std::collections::HashMap<u32, u64>,
}

impl ForkSignaler {
    pub fn new() -> Self {
        Self {
            locked_in: Default::default(),
        }
    }

    /// Query the state of a deployment at `current_height`. Read-only.
    ///
    /// # ⚠ CONTRACT — CALLER MUST OBSERVE THE LOCK-IN
    ///
    /// This function does NOT persist lock-in observations. If it returns
    /// `DeploymentState::LockedIn { at_height }` and the caller does not
    /// subsequently call [`record_lock_in`](Self::record_lock_in) with the
    /// same bit, the lock-in status is **lost at the next window
    /// boundary** because a re-query will count signals in the new
    /// (fresh) window from scratch. This violates BIP-9 semantics —
    /// under BIP-9, LOCKED_IN is a persistent state.
    ///
    /// The safe pattern for callers driving BIP-9 activation from
    /// block processing is [`state_and_record`](Self::state_and_record),
    /// which combines the query with the persistence in one atomic step.
    /// Only reach for `state()` if you need a side-effect-free query
    /// (e.g. RPC surface exposing "what state does the network think
    /// this deployment is in right now?").
    ///
    /// # Arguments
    /// * `signal_count_fn` — closure that returns the number of blocks
    ///   in `[window_start, current_height)` with the given bit set.
    ///   The window is aligned to `SIGNAL_WINDOW` boundaries.
    pub fn state<F>(
        &self,
        deployment: &Deployment,
        current_height: u64,
        signal_count_fn: F,
    ) -> DeploymentState
    where
        F: Fn(u64, u64, u32) -> u64, // (window_start, window_end, bit) -> count
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
            return DeploymentState::LockedIn {
                at_height: activation,
            };
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
            DeploymentState::LockedIn {
                at_height: self.next_window_start(current_height),
            }
        } else {
            DeploymentState::Started { signaling_pct: pct }
        }
    }

    /// Record that a deployment locked in at `height`. Once recorded,
    /// subsequent [`state`](Self::state) queries for this deployment
    /// return `LockedIn` or `Active` (depending on `current_height` vs
    /// `min_activation_height`) rather than re-counting signals.
    pub fn record_lock_in(&mut self, bit: u32, height: u64) {
        self.locked_in.insert(bit, height);
    }

    /// Query state AND persist a fresh lock-in atomically.
    ///
    /// Preferred over `state()` for callers driving activation from block
    /// processing: eliminates the "forgot to record" bug class where a
    /// deployment reaches LOCKED_IN in one window but the caller doesn't
    /// call `record_lock_in` before the next window, causing the state
    /// machine to re-check signals in the new window and (if signals
    /// dropped) revert to `Started`. Under BIP-9 semantics that's
    /// incorrect — LOCKED_IN must be persistent once reached.
    ///
    /// Returns the same `DeploymentState` as `state()`. If the returned
    /// state is `LockedIn { at_height }` and this observation is fresh
    /// (not previously recorded), the lock-in is persisted before
    /// returning. Multiple calls in the same window are idempotent —
    /// only the first `LockedIn` transition records; subsequent calls
    /// hit the fast path via the internal HashMap check.
    pub fn state_and_record<F>(
        &mut self,
        deployment: &Deployment,
        current_height: u64,
        signal_count_fn: F,
    ) -> DeploymentState
    where
        F: Fn(u64, u64, u32) -> u64,
    {
        let state = self.state(deployment, current_height, &signal_count_fn);
        if matches!(state, DeploymentState::LockedIn { .. })
            && !self.locked_in.contains_key(&deployment.bit)
        {
            self.record_lock_in(deployment.bit, current_height);
        }
        state
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
            "expected LockedIn, got {:?}",
            state
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
            "expected Started, got {:?}",
            state
        );
    }

    /// The "forgot to record_lock_in" bug: `state()` returns LockedIn
    /// but doesn't persist. Re-querying in the next window with the
    /// signal count dropped below threshold reverts to Started —
    /// violating BIP-9's persistent-LOCKED_IN semantics. This test
    /// documents that the bug exists in the read-only `state()` API
    /// so callers know they must use `state_and_record` or manually
    /// call `record_lock_in`.
    #[test]
    fn state_alone_does_not_persist_lock_in_across_window_boundary() {
        let signaler = ForkSignaler::new();
        let d = synthetic_deployment();
        // Window W: threshold met — state() sees LockedIn.
        let s1 = signaler.state(&d, 6_000, |_, _, _| SIGNAL_THRESHOLD);
        assert!(matches!(s1, DeploymentState::LockedIn { .. }));
        // Cross into window W+1 with signals below threshold: because
        // we did NOT call record_lock_in, the state machine re-counts
        // from scratch and sees Started.
        let s2 = signaler.state(&d, 6_000 + SIGNAL_WINDOW, |_, _, _| 0);
        assert!(
            matches!(s2, DeploymentState::Started { .. }),
            "read-only state() must not persist lock-in — actual: {:?}",
            s2
        );
    }

    /// The fix: `state_and_record` persists the lock-in atomically, so
    /// crossing into the next window with dropped signals still
    /// reports LockedIn (or Active after min_activation_height).
    #[test]
    fn state_and_record_persists_lock_in_across_window_boundary() {
        let mut signaler = ForkSignaler::new();
        let d = synthetic_deployment();
        // Window W: threshold met — state_and_record sees LockedIn AND
        // persists it.
        let s1 = signaler.state_and_record(&d, 6_000, |_, _, _| SIGNAL_THRESHOLD);
        assert!(matches!(s1, DeploymentState::LockedIn { .. }));
        // Cross into window W+1 with zero signals: still LockedIn
        // because the persistence held.
        let s2 = signaler.state(&d, 6_000 + SIGNAL_WINDOW, |_, _, _| 0);
        assert!(
            matches!(
                s2,
                DeploymentState::LockedIn { .. } | DeploymentState::Active
            ),
            "state_and_record must persist lock-in — actual: {:?}",
            s2
        );
    }

    /// state_and_record is idempotent — multiple calls in the same or
    /// later windows don't corrupt the persisted lock-in height.
    #[test]
    fn state_and_record_is_idempotent() {
        let mut signaler = ForkSignaler::new();
        let d = synthetic_deployment();
        let s1 = signaler.state_and_record(&d, 6_000, |_, _, _| SIGNAL_THRESHOLD);
        let s2 = signaler.state_and_record(&d, 6_100, |_, _, _| SIGNAL_THRESHOLD);
        assert_eq!(s1, s2, "same-window repeated queries must match");
    }

    #[test]
    fn v1_0_12_bundle_bit_distinct_from_other_cips() {
        // Each CIP must use a distinct bit. A typo that gave V1_0_12_BUNDLE
        // the same value as an existing CIP would cause double-signaling
        // (a single miner block would appear to signal for both at once),
        // which would corrupt the activation state machines for both
        // deployments. This test makes that mistake compile-fail-loud.
        let all_cips = [
            ("VIEW_TAGS", bits::VIEW_TAGS),
            ("RING_SIZE_16", bits::RING_SIZE_16),
            ("FEE_MARKET_V2", bits::FEE_MARKET_V2),
            ("HALO2_SHIELDED", bits::HALO2_SHIELDED),
            ("LELANTUS_SPARK", bits::LELANTUS_SPARK),
            ("MW_CUTTHROUGH", bits::MW_CUTTHROUGH),
            ("V1_0_12_BUNDLE", bits::V1_0_12_BUNDLE),
            ("MUST_SET", bits::MUST_SET),
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
        assert!(s.signals(bits::MUST_SET), "MUST_SET always implicit");
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
                "v1.0.12 signal leaked into other CIP bit 0x{:08x}",
                other,
            );
        }
    }

    #[test]
    fn encode_no_signal_matches_legacy_format() {
        // A coinbase that signals nothing must produce the SAME byte
        // sequence as pre-CIP-012 miners (just 8 height-bytes). This
        // preserves byte-for-byte block-hash compatibility for blocks
        // produced by an upgraded miner that doesn't opt in to signaling.
        let encoded = encode_coinbase_extra(12345, SignalBits(0));
        assert_eq!(encoded.len(), 8, "no-signal extra must be 8 bytes");
        assert_eq!(encoded, 12345u64.to_le_bytes().to_vec());
    }

    #[test]
    fn encode_with_signal_appends_4_bytes() {
        let bits = SignalBits::new(bits::V1_0_12_BUNDLE);
        let encoded = encode_coinbase_extra(12345, bits);
        assert_eq!(encoded.len(), 12, "signal extra must be 12 bytes");
        // Height in first 8 bytes — must match legacy format.
        assert_eq!(&encoded[0..8], &12345u64.to_le_bytes()[..]);
        // Signal bits in last 4 bytes.
        let trailer = u32::from_le_bytes(encoded[8..12].try_into().unwrap());
        assert_eq!(trailer, bits.raw());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let bits = SignalBits::new(bits::V1_0_12_BUNDLE | bits::VIEW_TAGS);
        let encoded = encode_coinbase_extra(99, bits);
        let decoded = decode_signal_bits(&encoded);
        assert_eq!(decoded.raw(), bits.raw());
        assert!(decoded.signals(bits::V1_0_12_BUNDLE));
        assert!(decoded.signals(bits::VIEW_TAGS));
        assert!(decoded.signals(bits::MUST_SET));
    }

    #[test]
    fn decode_legacy_8byte_extra_returns_no_signal() {
        // The exact pattern every coinbase prior to CIP-012 produces.
        let legacy = 555u64.to_le_bytes().to_vec();
        let decoded = decode_signal_bits(&legacy);
        assert_eq!(decoded.raw(), 0, "pre-CIP-012 coinbase = no signal");
        // Verify it doesn't accidentally signal any CIP bit.
        for bit in [
            bits::VIEW_TAGS,
            bits::RING_SIZE_16,
            bits::FEE_MARKET_V2,
            bits::HALO2_SHIELDED,
            bits::LELANTUS_SPARK,
            bits::MW_CUTTHROUGH,
            bits::V1_0_12_BUNDLE,
            bits::MUST_SET,
        ] {
            assert!(
                !decoded.signals(bit),
                "legacy extra signaled bit 0x{:08x}",
                bit
            );
        }
    }

    #[test]
    fn decode_short_extra_returns_no_signal() {
        // Defensive: 0-, 1-, 7-byte extras must not panic; must return
        // no-signal default. Should never occur in practice (every
        // valid coinbase has at least 8 bytes for the height), but
        // the decoder is consumed by the validator on potentially
        // attacker-controlled input — must not panic.
        for short in [vec![], vec![0u8], (0..7).map(|i| i as u8).collect()] {
            let decoded = decode_signal_bits(&short);
            assert_eq!(decoded.raw(), 0);
        }
    }

    #[test]
    fn decode_ignores_trailing_bytes_beyond_12() {
        // Forward-compat: future CIPs may extend extra with additional
        // fields after the signal bits. Decoder must read exactly
        // bytes 8..12 as signal and IGNORE anything after — not error.
        let mut extra = encode_coinbase_extra(42, SignalBits::new(bits::V1_0_12_BUNDLE));
        extra.extend_from_slice(b"future-cip-data"); // trailing garbage
        let decoded = decode_signal_bits(&extra);
        assert!(decoded.signals(bits::V1_0_12_BUNDLE));
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
