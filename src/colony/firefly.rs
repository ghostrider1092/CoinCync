//! firefly — pulse-coupled synchronization for cover traffic.
//!
//! Fireflies flash in unison by *pulse coupling* (Mirollo–Strogatz): each
//! insect runs an internal phase; when it flashes it nudges its neighbours'
//! phases forward a touch, and a population started out of step converges
//! to flashing together. This caste borrows that to synchronize **cover
//! traffic**: if every node emits padding/decoy pulses on its own private
//! clock, a burst stands out; if the whole network flashes *together*, a
//! real transaction slipped into a synchronized global flash is maximally
//! camouflaged. Uniformity is anonymity.
//!
//! ## Scope: pure oscillator math only (observe-first)
//!
//! This module is the **phase engine** — advance the phase, absorb a
//! neighbour pulse, report when it fires. It emits **no traffic** and has
//! no socket; wiring it to the live [`super::super::network::traffic_shaping`]
//! cover-packet layer is a later, separately-reviewed phase. Building the
//! math first, off to the side, keeps the always-on traffic path untouched
//! while the synchronization behaviour is proven in tests.
//!
//! ## Coupling is an attack surface — so it is bounded (rules D.2/D.4)
//!
//! Pulse coupling means *other peers can influence when we flash*. An
//! attacker who could spam unlimited "pulses" could drag our flash timing
//! to a rhythm of their choosing — the opposite of privacy. So each
//! oscillator honours at most [`MAX_NUDGES_PER_CYCLE`] pulses per cycle;
//! beyond that, extra pulses are ignored. That caps any peer's influence
//! to a bounded phase advance per cycle no matter how many pulses they
//! send. Live wiring must additionally only accept pulses from
//! authenticated peers and rate-limit them — this cap is the last line,
//! not the only one.
//!
//! Integer / deterministic fixed-point phase — same rationale as
//! [`super::pheromone`]; no float, trivially testable.

/// Fixed-point phase ceiling. A firefly "fires" when its phase reaches
/// this and wraps back toward zero. 10_000 gives 0.01% phase resolution —
/// ample for scheduling, and keeps all arithmetic far inside `u32`.
pub const PHASE_MAX: u32 = 10_000;

/// Phase a single absorbed pulse advances us by (fixed-point). 5% of a
/// full cycle: enough that coupling visibly pulls a laggard forward,
/// small enough that one pulse can't yank the phase across the dial.
pub const COUPLING_NUDGE: u32 = PHASE_MAX / 20;

/// Maximum neighbour pulses honoured per cycle. Bounds total external
/// influence to `MAX_NUDGES_PER_CYCLE * COUPLING_NUDGE` phase per cycle
/// (here 4 * 500 = 2000 = 20% of a cycle), so no pulse flood can drive
/// our flash timing arbitrarily.
pub const MAX_NUDGES_PER_CYCLE: u32 = 4;

/// A pulse-coupled oscillator. Advance it each tick with [`tick`](Firefly::tick);
/// when a neighbour flashes, call [`absorb_pulse`](Firefly::absorb_pulse).
/// Both return `true` on the tick/pulse that makes *this* firefly fire.
#[derive(Clone, Debug)]
pub struct Firefly {
    phase: u32,
    /// Phase advance per [`tick`](Self::tick). Cycle length is
    /// `ceil(PHASE_MAX / increment)` ticks. Clamped to `1..=PHASE_MAX`.
    increment: u32,
    nudges_this_cycle: u32,
}

impl Firefly {
    /// New oscillator at phase 0 with the given per-tick `increment`
    /// (clamped to `1..=PHASE_MAX`, so it always eventually fires and
    /// never fires more than once per tick from free-running advance).
    pub fn new(increment: u32) -> Self {
        Self {
            phase: 0,
            increment: increment.clamp(1, PHASE_MAX),
            nudges_this_cycle: 0,
        }
    }

    /// New oscillator seeded at a specific phase (used to model a
    /// population that starts out of step). Phase is taken modulo
    /// [`PHASE_MAX`].
    pub fn new_at_phase(increment: u32, phase: u32) -> Self {
        let mut f = Self::new(increment);
        f.phase = phase % PHASE_MAX;
        f
    }

    /// Advance one tick of the free-running clock. Returns `true` if this
    /// tick made the firefly fire (phase wrapped), which also refreshes
    /// the per-cycle nudge budget.
    pub fn tick(&mut self) -> bool {
        self.advance(self.increment)
    }

    /// Absorb a neighbour's flash. Honoured only while under the
    /// per-cycle cap; a pulse over budget is ignored and returns `false`.
    /// An honoured pulse advances the phase and returns `true` if it
    /// pushed us over threshold into firing (a synchronizing cascade).
    pub fn absorb_pulse(&mut self) -> bool {
        if self.nudges_this_cycle >= MAX_NUDGES_PER_CYCLE {
            return false;
        }
        self.nudges_this_cycle += 1;
        self.advance(COUPLING_NUDGE)
    }

    /// Advance the phase by `delta`, firing (and resetting phase + nudge
    /// budget) if it reaches threshold. `delta` here is always small
    /// (`increment <= PHASE_MAX` or `COUPLING_NUDGE`), and `phase <
    /// PHASE_MAX`, so `phase + delta < 2*PHASE_MAX` — no `u32` overflow.
    fn advance(&mut self, delta: u32) -> bool {
        self.phase += delta;
        if self.phase >= PHASE_MAX {
            self.phase %= PHASE_MAX;
            self.nudges_this_cycle = 0;
            true
        } else {
            false
        }
    }

    /// Current phase in `0..PHASE_MAX`.
    pub fn phase(&self) -> u32 {
        self.phase
    }
}

/// Shortest distance between two phases on the circular `0..PHASE_MAX`
/// dial. Two synchronized fireflies have a gap near 0.
pub fn phase_gap(a: u32, b: u32) -> u32 {
    let d = a.abs_diff(b);
    d.min(PHASE_MAX - d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_running_period_matches_increment() {
        // increment 1000 -> fires every 10 ticks (10 * 1000 = PHASE_MAX).
        let mut f = Firefly::new(1000);
        let mut fires = 0;
        for _ in 0..100 {
            if f.tick() {
                fires += 1;
            }
        }
        assert_eq!(fires, 10, "100 ticks / period 10 == 10 flashes");
    }

    #[test]
    fn increment_is_clamped_so_it_always_fires() {
        // increment 0 would never fire; must clamp to >= 1.
        let mut f = Firefly::new(0);
        let mut fired = false;
        for _ in 0..PHASE_MAX {
            if f.tick() {
                fired = true;
                break;
            }
        }
        assert!(fired, "clamped increment must eventually fire");
    }

    #[test]
    fn a_pulse_advances_phase_toward_firing() {
        let mut f = Firefly::new_at_phase(1000, 2000);
        let before = f.phase();
        let fired = f.absorb_pulse();
        assert!(!fired, "one small pulse from phase 2000 shouldn't fire");
        assert_eq!(f.phase(), before + COUPLING_NUDGE);
    }

    #[test]
    fn pulse_influence_is_capped_per_cycle() {
        // Beyond MAX_NUDGES_PER_CYCLE, extra pulses are ignored — an
        // attacker cannot drive unlimited phase advance.
        let mut f = Firefly::new_at_phase(1, 0); // near-frozen free clock
        let start = f.phase();
        for _ in 0..(MAX_NUDGES_PER_CYCLE + 20) {
            f.absorb_pulse();
        }
        let max_advance = MAX_NUDGES_PER_CYCLE * COUPLING_NUDGE;
        assert_eq!(
            f.phase(),
            start + max_advance,
            "external influence must be bounded to MAX_NUDGES_PER_CYCLE * COUPLING_NUDGE"
        );
    }

    #[test]
    fn nudge_budget_refreshes_after_a_fire() {
        let mut f = Firefly::new_at_phase(1, 0);
        // Exhaust the budget.
        for _ in 0..MAX_NUDGES_PER_CYCLE {
            f.absorb_pulse();
        }
        assert!(!f.absorb_pulse(), "over budget: ignored");
        // Drive a free-running fire to reset the cycle, then pulses count
        // again. increment 1, phase now = MAX_NUDGES*COUPLING = 2000, need
        // to reach PHASE_MAX via ticks.
        let mut fired = false;
        for _ in 0..PHASE_MAX {
            if f.tick() {
                fired = true;
                break;
            }
        }
        assert!(fired);
        let p = f.phase();
        assert!(
            f.absorb_pulse() || f.phase() == p + COUPLING_NUDGE,
            "after a fire the nudge budget must be refreshed"
        );
    }

    #[test]
    fn firing_wraps_phase_not_overshoots() {
        let mut f = Firefly::new_at_phase(1000, 9500);
        let fired = f.tick(); // 9500 + 1000 = 10500 -> fire, wrap to 500
        assert!(fired);
        assert_eq!(f.phase(), 500);
    }

    #[test]
    fn phase_gap_is_circular() {
        assert_eq!(phase_gap(100, 400), 300);
        // 200 and 9800 are 400 apart the short way, not 9600.
        assert_eq!(phase_gap(200, 9_800), 400);
        assert_eq!(phase_gap(5000, 5000), 0);
    }

    #[test]
    fn coupled_pair_converges_toward_sync() {
        // Two identical-frequency fireflies started far out of phase.
        // Each pulses the other when it fires. The population must end
        // MORE synchronized than it started (gap shrinks).
        let inc = 250; // period 40 ticks — room for coupling to act
        let mut a = Firefly::new_at_phase(inc, 0);
        let mut b = Firefly::new_at_phase(inc, 4_000);
        let initial_gap = phase_gap(a.phase(), b.phase());

        for _ in 0..2_000 {
            let a_fired = a.tick();
            let b_fired = b.tick();
            // Cross-couple: a flash nudges the other.
            if a_fired {
                b.absorb_pulse();
            }
            if b_fired {
                a.absorb_pulse();
            }
        }

        let final_gap = phase_gap(a.phase(), b.phase());
        assert!(
            final_gap < initial_gap,
            "coupling must reduce the phase gap: {initial_gap} -> {final_gap}"
        );
    }
}
