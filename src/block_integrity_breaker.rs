//! CoinCync block-connect / apply **integrity breaker** — the state-corruption
//! bulkhead.
//!
//! Precaution, not a known bug: applying a block mutates the UTXO set, and no
//! apply path is provably bug-free. If a connect ever produces an *inconsistent*
//! post-apply state, this breaker isolates that block so corruption is never
//! persisted — rather than silently carrying a broken UTXO set forward. It is a
//! consensus/money-integrity surface, so recovery is **Latch** (a corrupt apply
//! does not "heal" on the next block; a human/governance must re-arm).
//!
//! Same connector discipline as the other breakers (`docs/design/cip-circuit-
//! breakers.md`): a pure `detect(observation) -> faults` that reaches into no
//! chain state, declared from `lib.rs`, feature-gated, default policy `Observe`,
//! no edit to the hash-locked core. Observe-mode on a live chain is pure
//! telemetry; isolating a block is consensus and stays a coordinated, post-audit
//! activation.
//!
//! Invariants (match the chain's own post-apply guarantees):
//!   - `total_outputs_ever` is **monotonic** (outputs are only ever created, the
//!     counter never decreases across a connect),
//!   - **availability** (`total_outputs_ever − reorg_disconnects_total`) never
//!     underflows (you can't disconnect more than were ever created),
//!   - the computed UTXO-set commitment matches any committed root (ties to the
//!     Rung-2 state-root connector),
//!   - `output_count` (live set) never exceeds `total_outputs_ever`.

use crate::primitives::Hash;

/// A post-apply state-integrity violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityFault {
    /// `total_outputs_ever` decreased across a connect — the monotonic
    /// output counter went backwards (impossible for a correct apply).
    NonMonotonicOutputs,
    /// `reorg_disconnects_total > total_outputs_ever` — more outputs disconnected
    /// than were ever created (availability underflow).
    AvailabilityUnderflow,
    /// The live UTXO `output_count` exceeds `total_outputs_ever`.
    LiveSetExceedsEver,
    /// The computed UTXO commitment disagrees with the committed root.
    UtxoRootMismatch,
}

/// What the node observed about state right after applying a block. All already
/// computed by the chain; the breaker only reasons over it.
#[derive(Clone, Copy, Debug, Default)]
pub struct IntegrityObservation {
    /// `total_outputs_ever` before and after the connect (monotonic → after ≥ before).
    pub prev_total_outputs_ever: u64,
    pub total_outputs_ever: u64,
    /// Cumulative reorg disconnects (availability = ever − disconnects ≥ 0).
    pub reorg_disconnects_total: u64,
    /// Current live output-set size.
    pub output_count: u64,
    /// The UTXO commitment the node computed at this tip.
    pub computed_utxo_root: Hash,
    /// A committed root to check against, if the block carries one.
    pub committed_utxo_root: Option<Hash>,
}

/// Collect every post-apply integrity violation (empty = sound). Pure.
pub fn detect(o: &IntegrityObservation) -> Vec<IntegrityFault> {
    let mut f = Vec::new();
    if o.total_outputs_ever < o.prev_total_outputs_ever {
        f.push(IntegrityFault::NonMonotonicOutputs);
    }
    if o.reorg_disconnects_total > o.total_outputs_ever {
        f.push(IntegrityFault::AvailabilityUnderflow);
    }
    if o.output_count > o.total_outputs_ever {
        f.push(IntegrityFault::LiveSetExceedsEver);
    }
    if let Some(c) = o.committed_utxo_root {
        if c != o.computed_utxo_root {
            f.push(IntegrityFault::UtxoRootMismatch);
        }
    }
    f
}

/// Breaker policy. **Default `Observe`** — detect + log, never reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerPolicy {
    /// Detect + log only; never reject. Safe default for the live chain.
    Observe,
    /// Reject the block on any integrity fault. CONSENSUS — live arming is a
    /// coordinated, activation-gated decision.
    Armed,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy::Observe
    }
}

/// The breaker's decision. A corrupt apply is block-fatal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerAction {
    /// The post-apply state is consistent.
    AllowBlock,
    /// Reject the block — applying it corrupts state. Carries the faults.
    RejectBlock { faults: Vec<IntegrityFault> },
}

impl BreakerAction {
    pub fn rejects_block(&self) -> bool {
        matches!(self, BreakerAction::RejectBlock { .. })
    }
}

/// Evaluate: detect faults, apply policy. `Observe` always allows (logs); `Armed`
/// rejects iff any fault is present. Fail-closed: a detected corruption under
/// `Armed` is never persisted.
pub fn evaluate(policy: BreakerPolicy, o: &IntegrityObservation) -> BreakerAction {
    let faults = detect(o);
    match policy {
        BreakerPolicy::Observe => BreakerAction::AllowBlock,
        BreakerPolicy::Armed if faults.is_empty() => BreakerAction::AllowBlock,
        BreakerPolicy::Armed => BreakerAction::RejectBlock { faults },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sound() -> IntegrityObservation {
        IntegrityObservation {
            prev_total_outputs_ever: 1_000,
            total_outputs_ever: 1_002, // +2 this block (monotonic)
            reorg_disconnects_total: 10,
            output_count: 500,
            computed_utxo_root: Hash::from_bytes([7u8; 32]),
            committed_utxo_root: Some(Hash::from_bytes([7u8; 32])),
        }
    }

    #[test]
    fn default_policy_is_observe() {
        assert_eq!(BreakerPolicy::default(), BreakerPolicy::Observe);
    }

    #[test]
    fn sound_apply_passes_both_modes() {
        assert!(detect(&sound()).is_empty());
        assert_eq!(evaluate(BreakerPolicy::Observe, &sound()), BreakerAction::AllowBlock);
        assert_eq!(evaluate(BreakerPolicy::Armed, &sound()), BreakerAction::AllowBlock);
    }

    #[test]
    fn non_monotonic_outputs_is_fatal() {
        let mut o = sound();
        o.total_outputs_ever = o.prev_total_outputs_ever - 1; // counter went backwards
        assert!(detect(&o).contains(&IntegrityFault::NonMonotonicOutputs));
        assert!(evaluate(BreakerPolicy::Armed, &o).rejects_block());
        assert!(!evaluate(BreakerPolicy::Observe, &o).rejects_block()); // observe logs only
    }

    #[test]
    fn availability_underflow_and_live_set_overflow() {
        let mut o = sound();
        o.reorg_disconnects_total = o.total_outputs_ever + 1;
        assert!(detect(&o).contains(&IntegrityFault::AvailabilityUnderflow));

        let mut o2 = sound();
        o2.output_count = o2.total_outputs_ever + 1;
        assert!(detect(&o2).contains(&IntegrityFault::LiveSetExceedsEver));
    }

    #[test]
    fn utxo_root_mismatch_detected() {
        let mut o = sound();
        o.committed_utxo_root = Some(Hash::from_bytes([0xEE; 32]));
        assert!(detect(&o).contains(&IntegrityFault::UtxoRootMismatch));
        assert!(evaluate(BreakerPolicy::Armed, &o).rejects_block());
    }

    #[test]
    fn multiple_faults_all_reported() {
        let mut o = sound();
        o.total_outputs_ever = 0; // non-monotonic + availability underflow + live>ever
        if let BreakerAction::RejectBlock { faults } = evaluate(BreakerPolicy::Armed, &o) {
            assert!(faults.len() >= 3);
        } else {
            panic!("expected RejectBlock");
        }
    }
}
