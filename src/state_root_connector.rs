//! Rung-2 **state-root commitment connector** — a fail-closed, default-OFF
//! policy slot that lets the chain commit to (and, once activated, enforce) its
//! UTXO state root, **without editing the hash-locked consensus core**
//! (`validation.rs`, `header.rs`, `constants.rs`).
//!
//! ## What Rung 2 is
//!
//! The trustless light-sync foundation: the chain commits to its UTXO-set state
//! root so that a light client can trust the state by trusting *block validity
//! itself* — no key, no committee, no miner vote. See
//! `docs/design/cip-rung2-state-root.md`.
//!
//! ## Why a connector (not a core edit)
//!
//! Enforcing a new committed value is a consensus change, and a live testnet is
//! running. So this is a self-contained **seam**, not a patch to the tuned/
//! locked validation path:
//!
//!   - **Carriage is coinbase extra, not a new header field.** The root rides as
//!     a tagged TLV in the coinbase `extra` bytes, so the block-header format is
//!     unchanged and no block hashes move → **no fork** from merely populating
//!     it.
//!   - **Default policy is [`Observe`](StateRootPolicy::Observe)** — compute and
//!     compare for observability, **never reject**. Consensus-neutral.
//!   - **Enforcement is gated** behind [`Enforce`](StateRootPolicy::Enforce) with
//!     an `activation_height` that defaults to [`NEVER`] (`u64::MAX`). Flipping
//!     it on is a deliberate, audited, planned fork — done elsewhere, not here.
//!   - **Fail-closed:** once enforcing, a missing or mismatched commitment is a
//!     rejection; before activation (or in Observe), nothing is rejected.
//!
//! The connector exposes pure functions over values the caller already has (the
//! actual UTXO commitment, the block height, the coinbase extra bytes); wiring
//! the single call into the connect path is the activation step and is **not**
//! performed in this module.

use crate::primitives::Hash;

/// The committed UTXO state root — the chain's canonical UTXO-set commitment
/// (e.g. `Blockchain::utxo_commitment_at_tip` after the block is applied).
pub type StateRoot = Hash;

/// Activation height meaning "never" — the default, so the connector is inert on
/// the live chain until a planned post-audit fork sets a real height.
pub const NEVER: u64 = u64::MAX;

/// TLV tag identifying a state-root entry inside coinbase `extra`. Distinct from
/// other `extra` tags so it never collides with recovery-meta / view-tag bytes.
pub const STATE_ROOT_TAG: u8 = 0x53; // 'S' — state-root TLV tag in coinbase extra

/// The enforcement policy for the state-root commitment. **Default is
/// [`Observe`](Self::Observe)** — consensus-neutral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRootPolicy {
    /// Compute + compare for observability only; **never reject**. The default,
    /// and the only policy that is safe to run on the live chain pre-activation.
    Observe,
    /// Enforce from `activation_height` onward: at/after that height a present
    /// commitment MUST match and a missing one is rejected (fail-closed). Below
    /// it, behaves like `Observe`. `activation_height` defaults to [`NEVER`].
    Enforce { activation_height: u64 },
}

impl Default for StateRootPolicy {
    fn default() -> Self {
        StateRootPolicy::Observe
    }
}

impl StateRootPolicy {
    /// The fail-closed default: enforcement compiled but never active.
    pub fn disabled() -> Self {
        StateRootPolicy::Enforce { activation_height: NEVER }
    }
}

/// The outcome of checking a block's state-root commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRootCheck {
    /// Not enforced at this height (Observe mode, or below the activation
    /// height). The block is unaffected.
    Inactive,
    /// Enforced, a commitment is present, and it matches the actual UTXO root.
    Match,
    /// Enforced and the committed root does NOT match the actual root → reject.
    Mismatch,
    /// Enforced but the block carries no commitment → reject (fail-closed).
    Missing,
}

impl StateRootCheck {
    /// Whether this outcome means the block must be rejected. `Inactive`/`Match`
    /// never reject; `Mismatch`/`Missing` do.
    pub fn rejects(self) -> bool {
        matches!(self, StateRootCheck::Mismatch | StateRootCheck::Missing)
    }
}

/// The connector's core decision: given the policy, the block `height`, the
/// commitment the block carries (if any), and the `actual` UTXO root the node
/// computed, decide the outcome. Pure and total — it reaches into no chain
/// state, so it can never perturb the locked validation path.
pub fn check(
    policy: StateRootPolicy,
    height: u64,
    committed: Option<StateRoot>,
    actual: StateRoot,
) -> StateRootCheck {
    let activation = match policy {
        StateRootPolicy::Observe => return StateRootCheck::Inactive,
        StateRootPolicy::Enforce { activation_height } => activation_height,
    };
    if height < activation {
        return StateRootCheck::Inactive;
    }
    match committed {
        None => StateRootCheck::Missing,
        Some(c) if c == actual => StateRootCheck::Match,
        Some(_) => StateRootCheck::Mismatch,
    }
}

// ── Carriage: a tagged TLV inside coinbase `extra` (no header-format change) ──

/// Append a state-root TLV (`[TAG][32][root…]`) to coinbase `extra`. Additive:
/// existing `extra` entries are preserved, and because this lives in the
/// coinbase body (not the header) it does not change the header format.
pub fn embed_in_extra(mut extra: Vec<u8>, root: &StateRoot) -> Vec<u8> {
    extra.push(STATE_ROOT_TAG);
    extra.push(Hash::LEN as u8); // 32
    extra.extend_from_slice(root.as_bytes());
    extra
}

/// Extract the state root from a coinbase `extra` byte string, scanning its
/// `[tag][len][value…]` TLV entries for the state-root tag. Returns `None` if
/// absent or malformed — callers treat `None` under enforcement as `Missing`
/// (fail-closed), never as a pass.
pub fn extract_from_extra(extra: &[u8]) -> Option<StateRoot> {
    let mut i = 0usize;
    while i + 2 <= extra.len() {
        let tag = extra[i];
        let len = extra[i + 1] as usize;
        let val_start = i + 2;
        let val_end = val_start.checked_add(len)?;
        if val_end > extra.len() {
            return None; // malformed / truncated TLV
        }
        if tag == STATE_ROOT_TAG && len == Hash::LEN {
            let mut b = [0u8; 32];
            b.copy_from_slice(&extra[val_start..val_end]);
            return Some(Hash::from_bytes(b));
        }
        i = val_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(b: u8) -> StateRoot {
        Hash::from_bytes([b; 32])
    }

    #[test]
    fn observe_never_rejects_even_on_mismatch() {
        let c = check(StateRootPolicy::Observe, 1_000, Some(root(1)), root(2));
        assert_eq!(c, StateRootCheck::Inactive);
        assert!(!c.rejects());
    }

    #[test]
    fn default_policy_is_observe_and_disabled_never_activates() {
        assert_eq!(StateRootPolicy::default(), StateRootPolicy::Observe);
        // disabled() = Enforce@NEVER: inert at any realistic height.
        let c = check(StateRootPolicy::disabled(), u64::MAX - 1, None, root(9));
        assert_eq!(c, StateRootCheck::Inactive);
    }

    #[test]
    fn enforce_below_activation_is_inactive() {
        let p = StateRootPolicy::Enforce { activation_height: 5_000 };
        assert_eq!(check(p, 4_999, None, root(1)), StateRootCheck::Inactive);
    }

    #[test]
    fn enforce_matches_and_mismatches() {
        let p = StateRootPolicy::Enforce { activation_height: 5_000 };
        assert_eq!(check(p, 5_000, Some(root(7)), root(7)), StateRootCheck::Match);
        let bad = check(p, 6_000, Some(root(7)), root(8));
        assert_eq!(bad, StateRootCheck::Mismatch);
        assert!(bad.rejects());
    }

    #[test]
    fn enforce_missing_commitment_is_fail_closed() {
        let p = StateRootPolicy::Enforce { activation_height: 5_000 };
        let m = check(p, 5_001, None, root(7));
        assert_eq!(m, StateRootCheck::Missing);
        assert!(m.rejects());
    }

    #[test]
    fn extra_round_trips_and_ignores_other_tlvs() {
        // A foreign TLV entry before ours must be skipped, not misread.
        let foreign = vec![0x11u8, 3, 0xAA, 0xBB, 0xCC];
        let extra = embed_in_extra(foreign.clone(), &root(0x5A));
        assert_eq!(extract_from_extra(&extra), Some(root(0x5A)));
        // Empty / absent → None (→ Missing under enforcement, never a pass).
        assert_eq!(extract_from_extra(&[]), None);
        assert_eq!(extract_from_extra(&foreign), None);
    }

    #[test]
    fn extract_rejects_truncated_tlv() {
        // tag + claimed len 32 but no bytes → None, never a partial/garbage root.
        assert_eq!(extract_from_extra(&[STATE_ROOT_TAG, 32]), None);
    }

    #[test]
    fn end_to_end_observe_then_enforce() {
        // The lifecycle: produce a block carrying the real root; Observe is inert;
        // once enforced at activation it validates; a tampered root is caught.
        let actual = root(0xC0);
        let extra = embed_in_extra(Vec::new(), &actual);
        let committed = extract_from_extra(&extra);

        // Pre-activation / Observe: inert.
        assert_eq!(
            check(StateRootPolicy::Observe, 10_000, committed, actual),
            StateRootCheck::Inactive
        );
        // Enforced at activation: matches.
        let p = StateRootPolicy::Enforce { activation_height: 10_000 };
        assert_eq!(check(p, 10_000, committed, actual), StateRootCheck::Match);
        // Tampered actual (node computed a different root) → reject.
        assert!(check(p, 10_000, committed, root(0xC1)).rejects());
    }
}
