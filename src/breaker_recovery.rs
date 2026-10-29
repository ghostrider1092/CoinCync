//! Shared **recovery state machine** for the circuit breakers — the piece that
//! decides whether (and how) a tripped breaker *reconnects*.
//!
//! The per-surface breakers (`shielded_circuit_breaker`, `supply_breaker`,
//! `mempool_breaker`, `p2p_breaker`, `reorg_breaker`, `rpc_breaker`) are pure:
//! `detect(observation)` says whether the surface is *faulty right now*. This
//! module adds the missing half — **state over time**: a classic three-state
//! circuit breaker (Closed → Open → Half-Open → Closed) with a per-surface
//! [`RecoveryPolicy`]. It composes with any breaker (feed it
//! `!detect(obs).is_empty()` each tick), so there is one recovery implementation,
//! not six.
//!
//! ## Why the policy differs by surface (the whole point of the question)
//!
//! - **Transient / load faults** (mempool flood, RPC abuse, peer churn, reorg
//!   churn) *do* go away. Here [`RecoveryPolicy::AutoReset`] is correct: after a
//!   streak of healthy observations the breaker re-closes on its own — with
//!   **hysteresis** (require N consecutive healthy ticks) so it can't *flap* on
//!   and off at the threshold.
//! - **Vulnerability / money faults** (a shielded crypto break, supply
//!   inflation) do **not** go away just because the next block looks clean.
//!   Auto-reconnecting a known-broken money pool is a footgun. Here
//!   [`RecoveryPolicy::Latch`] is correct: once tripped the breaker stays Open
//!   until a human/governance explicitly [`rearm`](RecoveryBreaker::rearm)s it.
//!
//! Same connector discipline as the breakers: pure, fail-closed, feature-gated,
//! declared from `lib.rs` (not the hash-locked consensus core). See
//! `docs/design/cip-circuit-breakers.md`.

/// How a tripped breaker is allowed to recover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPolicy {
    /// Auto-reconnect after `heal_streak` consecutive healthy observations
    /// (hysteresis against flapping). For transient / load / attack surfaces.
    AutoReset { heal_streak: u32 },
    /// Never auto-reconnect; stay Open until an explicit `rearm()`. For
    /// vulnerability / money surfaces where a clean-looking next tick does NOT
    /// mean the fault is gone.
    Latch,
}

/// The three classic circuit-breaker states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    /// Normal operation — the compartment is open for business.
    Closed,
    /// Tripped — the compartment is isolated.
    Open,
    /// Probing recovery — healthy for a full streak; one more clean tick closes
    /// it, any fault reopens it. (AutoReset only.)
    HalfOpen,
}

/// A stateful breaker wrapper: feed it, each tick, whether the surface is faulty
/// (`!detect(obs).is_empty()`), and it tracks Closed/Open/Half-Open per its
/// [`RecoveryPolicy`]. `is_isolating()` is the thing a caller acts on.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryBreaker {
    state: BreakerState,
    policy: RecoveryPolicy,
    heal_count: u32,
}

impl RecoveryBreaker {
    /// A fresh breaker, Closed, with the given recovery policy.
    pub fn new(policy: RecoveryPolicy) -> Self {
        Self { state: BreakerState::Closed, policy, heal_count: 0 }
    }

    /// Build with the recommended policy for a surface.
    pub fn for_surface(surface: BreakerSurface) -> Self {
        Self::new(recommended_recovery(surface))
    }

    /// Current state.
    pub fn state(&self) -> BreakerState {
        self.state
    }

    /// The policy in force.
    pub fn policy(&self) -> RecoveryPolicy {
        self.policy
    }

    /// Whether the compartment is currently isolated. Isolation lifts only on a
    /// full return to `Closed` — `HalfOpen` still isolates (conservative: it is
    /// only *probing* recovery, not recovered).
    pub fn is_isolating(&self) -> bool {
        !matches!(self.state, BreakerState::Closed)
    }

    /// Advance the state machine by one observation. `faulty` = the surface's
    /// `detect` found at least one fault this tick.
    pub fn observe(&mut self, faulty: bool) -> BreakerState {
        if faulty {
            // Any fault trips (or re-trips) immediately, regardless of state or
            // policy — fail-closed.
            self.state = BreakerState::Open;
            self.heal_count = 0;
            return self.state;
        }
        match self.state {
            BreakerState::Closed => {} // healthy + already closed: nothing to do
            BreakerState::Open => match self.policy {
                // Latched surfaces never auto-recover: a clean tick is NOT proof
                // the vulnerability is gone. Needs rearm().
                RecoveryPolicy::Latch => {}
                RecoveryPolicy::AutoReset { heal_streak } => {
                    self.heal_count = self.heal_count.saturating_add(1);
                    if self.heal_count >= heal_streak.max(1) {
                        self.state = BreakerState::HalfOpen;
                    }
                }
            },
            // A clean probe tick in Half-Open fully recovers.
            BreakerState::HalfOpen => {
                self.state = BreakerState::Closed;
                self.heal_count = 0;
            }
        }
        self.state
    }

    /// Manual recovery — force back to `Closed`. The ONLY way a `Latch` breaker
    /// reconnects; for `AutoReset` it's an operator override. This models the
    /// human/governance "we've fixed it, re-enable" decision.
    pub fn rearm(&mut self) {
        self.state = BreakerState::Closed;
        self.heal_count = 0;
    }
}

/// The critical surfaces, for mapping to a recommended recovery policy.
///
/// `Hash`/`Eq` so the universal [`FuseBox`](crate::fuse::FuseBox) can key one
/// registry of breakers by surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BreakerSurface {
    /// Shielded pool — crypto/money. Latch.
    Shielded,
    /// Supply / emission — money. Latch.
    Supply,
    /// Mempool — transient load. AutoReset.
    Mempool,
    /// P2P / IBD — transient / attack. AutoReset.
    P2p,
    /// RPC service — transient load. AutoReset.
    Rpc,
    /// Reorg / finality — the danger passes once the honest chain wins. AutoReset.
    Reorg,
    /// Block-connect / apply integrity — a corrupt apply (broken UTXO-set
    /// invariant) is NOT transient: a clean-looking next block does not undo the
    /// corruption. Latch (needs an explicit rearm after investigation).
    BlockIntegrity,
}

impl BreakerSurface {
    /// Every surface, for installing the universal fuse box in one call.
    pub const ALL: [BreakerSurface; 7] = [
        BreakerSurface::Shielded,
        BreakerSurface::Supply,
        BreakerSurface::Mempool,
        BreakerSurface::P2p,
        BreakerSurface::Rpc,
        BreakerSurface::Reorg,
        BreakerSurface::BlockIntegrity,
    ];
}

/// Default anti-flap streak for auto-resetting surfaces.
pub const DEFAULT_HEAL_STREAK: u32 = 3;

/// The recommended recovery policy per surface: **Latch** for the crypto/money
/// surfaces (never auto-reconnect a known-broken pool), **AutoReset** for the
/// transient load/attack surfaces.
pub fn recommended_recovery(surface: BreakerSurface) -> RecoveryPolicy {
    match surface {
        // Crypto/money and corrupt-state surfaces latch: a clean next tick is not
        // proof the fault is gone, so they wait for an explicit human rearm.
        BreakerSurface::Shielded
        | BreakerSurface::Supply
        | BreakerSurface::BlockIntegrity => RecoveryPolicy::Latch,
        BreakerSurface::Mempool
        | BreakerSurface::P2p
        | BreakerSurface::Rpc
        | BreakerSurface::Reorg => RecoveryPolicy::AutoReset { heal_streak: DEFAULT_HEAL_STREAK },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latch_trips_and_never_auto_recovers_until_rearm() {
        let mut b = RecoveryBreaker::new(RecoveryPolicy::Latch);
        assert!(!b.is_isolating());
        // Fault trips it.
        b.observe(true);
        assert_eq!(b.state(), BreakerState::Open);
        assert!(b.is_isolating());
        // Many clean ticks do NOT reconnect a latched (vulnerability) surface.
        for _ in 0..100 {
            b.observe(false);
            assert_eq!(b.state(), BreakerState::Open, "latch must stay open on clean ticks");
        }
        // Only an explicit rearm reconnects.
        b.rearm();
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(!b.is_isolating());
    }

    #[test]
    fn autoreset_recovers_after_a_healthy_streak() {
        let mut b = RecoveryBreaker::new(RecoveryPolicy::AutoReset { heal_streak: 3 });
        b.observe(true); // trip
        assert_eq!(b.state(), BreakerState::Open);
        // Needs a full streak, then a probe tick, to fully close.
        b.observe(false); // 1
        assert_eq!(b.state(), BreakerState::Open);
        b.observe(false); // 2
        assert_eq!(b.state(), BreakerState::Open);
        b.observe(false); // 3 → reached streak → HalfOpen (still isolating)
        assert_eq!(b.state(), BreakerState::HalfOpen);
        assert!(b.is_isolating());
        b.observe(false); // clean probe → Closed
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(!b.is_isolating());
    }

    #[test]
    fn autoreset_reopens_on_fault_during_healing_no_flap() {
        let mut b = RecoveryBreaker::new(RecoveryPolicy::AutoReset { heal_streak: 3 });
        b.observe(true); // Open
        b.observe(false); // heal 1
        b.observe(false); // heal 2
        b.observe(true); // fault again → back to Open, heal count reset
        assert_eq!(b.state(), BreakerState::Open);
        // Must start the streak over — proves hysteresis (no flapping near the edge).
        b.observe(false);
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn halfopen_reopens_immediately_on_a_fault() {
        let mut b = RecoveryBreaker::new(RecoveryPolicy::AutoReset { heal_streak: 1 });
        b.observe(true); // Open
        b.observe(false); // streak 1 (>=1) → HalfOpen
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.observe(true); // probe sees a fault → back to Open
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn surface_policies_are_latch_for_money_autoreset_for_load() {
        assert_eq!(recommended_recovery(BreakerSurface::Shielded), RecoveryPolicy::Latch);
        assert_eq!(recommended_recovery(BreakerSurface::Supply), RecoveryPolicy::Latch);
        // Block-integrity (corrupt apply) latches too — not transient.
        assert_eq!(recommended_recovery(BreakerSurface::BlockIntegrity), RecoveryPolicy::Latch);
        for s in [BreakerSurface::Mempool, BreakerSurface::P2p, BreakerSurface::Rpc, BreakerSurface::Reorg] {
            assert!(matches!(recommended_recovery(s), RecoveryPolicy::AutoReset { .. }));
        }
    }

    #[test]
    fn all_surfaces_have_a_policy_and_are_distinct() {
        // ALL must list every surface exactly once (keeps the universal fuse box
        // install in sync with the enum).
        assert_eq!(BreakerSurface::ALL.len(), 7);
        for (i, a) in BreakerSurface::ALL.iter().enumerate() {
            for b in &BreakerSurface::ALL[i + 1..] {
                assert_ne!(a, b, "ALL must not repeat a surface");
            }
            // recommended_recovery is total over ALL (compiles ⇒ exhaustive).
            let _ = recommended_recovery(*a);
        }
    }

    #[test]
    fn healthy_from_the_start_never_isolates() {
        let mut b = RecoveryBreaker::for_surface(BreakerSurface::Mempool);
        for _ in 0..10 {
            b.observe(false);
            assert!(!b.is_isolating());
            assert_eq!(b.state(), BreakerState::Closed);
        }
    }
}
