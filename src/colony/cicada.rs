//! cicada — prime-interval anti-correlation scheduling.
//!
//! Periodical cicadas (*Magicicada*) emerge on **prime**-numbered year
//! cycles — 13 and 17 — so that no predator with a shorter, regular life
//! cycle can phase-lock onto them. This caste borrows that trick for
//! **timing privacy**: any periodic node activity that leaves the box on a
//! fixed clock (cover-traffic bursts, peer churn, rebroadcast sweeps,
//! view-key rescans) is a rhythm a passive observer can lock onto and use
//! to fingerprint or correlate the node across sessions. Cicada spaces
//! those events on *prime-varied* intervals so there is **no single period
//! to lock onto**.
//!
//! ## What it schedules — and what it must NOT
//!
//! Cicada only ever paces **node-local, non-transaction** housekeeping.
//! It is structurally incapable of touching transaction or stem-phase
//! timing: it produces a *delay in seconds*, nothing more, and has no
//! access to the mempool, Dandelion++ router, or any tx. Transaction
//! propagation timing stays 100% under the node's Dandelion++ logic
//! (see the colony Prime Privacy Invariant in `mod.rs`). Using cicada to
//! pace tx broadcast would be a P4.4 violation — never wire it there.
//!
//! ## Determinism vs. unpredictability (honest scope)
//!
//! This core is **deterministic**: `(base, counter)` always yields the
//! same delay, which is what makes it unit-testable and free of any RNG /
//! crypto surface. Its privacy value is the *structural* one — the emitted
//! series has **no period equal to `base`**, which is the single rhythm a
//! naive fixed-interval scheduler hands to an observer.
//!
//! The residual predictability (the prime permutation repeats every
//! [`CICADA_PRIMES`]`.len()` steps) is closed in the **live sidecar**, not
//! here: the `coincync-tick` scheduler adds a CSPRNG jitter term on top of
//! this base interval before sleeping.
//! RNG SOURCE: OS CSPRNG, applied in the sidecar — **not** in this module
//! (kept out deliberately so this core stays pure and testable).
//!
//! Deliberately **integer and deterministic** — same rationale as
//! [`super::pheromone`]: no float non-determinism, trivially testable,
//! non-consensus advisory state.

/// Prime multipliers cycled to vary the interval. 13 and 17 are the real
/// *Magicicada* emergence primes; the rest extend the range so successive
/// intervals spread widely around the base. All prime, none sharing a
/// small common factor, so the derived intervals don't collapse onto a
/// short common sub-period.
pub const CICADA_PRIMES: [u64; 8] = [13, 17, 19, 23, 29, 31, 37, 41];

/// Reference divisor the prime multiplier is taken relative to. Chosen as
/// the median-ish prime in the table so intervals swing *around* `base`
/// (roughly `0.56×base` .. `1.78×base`) rather than only stretching it.
const REFERENCE_PRIME: u64 = 23;

/// Stride used to walk [`CICADA_PRIMES`]. Coprime to the table length (8),
/// so stepping `counter` visits every prime but in a **non-monotonic**
/// order (0,3,6,1,4,7,2,5,…) — adjacent intervals therefore jump between
/// far-apart primes instead of ramping 13→17→19…, which would itself be a
/// recognisable slope.
const WALK_STRIDE: u64 = 3;

/// Floor on any emitted delay. A zero delay would busy-loop the caller;
/// clamp to at least one second so a mis-configured `base_secs == 0` fails
/// safe (slow) rather than spinning.
pub const MIN_DELAY_SECS: u64 = 1;

/// The prime-varied interval (seconds) for a given `base_secs` and step
/// `counter`, as a pure function.
///
/// Behaviour at the boundaries (stated per the integer-discipline rule):
/// - `base_secs == 0` → [`MIN_DELAY_SECS`] (never 0; no busy-loop).
/// - large `base_secs`: the multiply is done in `u64` and saturates, so a
///   pathological base can never overflow or wrap — it just pins near
///   `u64::MAX / 1` and the caller sleeps effectively "forever" rather
///   than firing early.
/// - `counter` wraps naturally (`% len`); every value is valid.
pub fn prime_interval_secs(base_secs: u64, counter: u64) -> u64 {
    let n = CICADA_PRIMES.len() as u64;
    let idx = counter.wrapping_mul(WALK_STRIDE) % n;
    // `idx < n <= CICADA_PRIMES.len()`, so the conversion is always in
    // range; `unwrap_or(0)` is a safe total fallback that can never be hit.
    // `usize::try_from` (not `as usize`) keeps this clear of the
    // `cast_possible_truncation` lint enforced project-wide.
    let prime = CICADA_PRIMES[usize::try_from(idx).unwrap_or(0)];
    // u64 multiply + saturating: base up to ~4.5e17 is fine; beyond that we
    // saturate rather than wrap (fail-safe slow, never fires early).
    let scaled = base_secs.saturating_mul(prime) / REFERENCE_PRIME;
    scaled.max(MIN_DELAY_SECS)
}

/// A running cicada schedule: a base interval plus a step counter. Each
/// [`advance`](CicadaSchedule::advance) yields the next prime-varied delay
/// and bumps the counter, so the caller just sleeps the returned value and
/// calls again.
#[derive(Clone, Debug)]
pub struct CicadaSchedule {
    base_secs: u64,
    counter: u64,
}

impl CicadaSchedule {
    /// New schedule around `base_secs`, starting at step 0.
    pub fn new(base_secs: u64) -> Self {
        Self { base_secs, counter: 0 }
    }

    /// The delay the next [`advance`](Self::advance) will return, without
    /// consuming the step. Useful for logging/metrics.
    pub fn peek(&self) -> u64 {
        prime_interval_secs(self.base_secs, self.counter)
    }

    /// Next prime-varied delay (seconds); advances the internal step.
    pub fn advance(&mut self) -> u64 {
        let d = prime_interval_secs(self.base_secs, self.counter);
        self.counter = self.counter.wrapping_add(1);
        d
    }

    /// The base interval this schedule varies around.
    pub fn base_secs(&self) -> u64 {
        self.base_secs
    }

    /// How many steps have been consumed.
    pub fn step(&self) -> u64 {
        self.counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_inputs_same_delay() {
        // The core property that makes it testable: pure in (base, counter).
        for base in [30u64, 300, 3600] {
            for c in 0..64u64 {
                assert_eq!(
                    prime_interval_secs(base, c),
                    prime_interval_secs(base, c),
                    "must be a pure function of (base, counter)"
                );
            }
        }
    }

    #[test]
    fn zero_base_never_busy_loops() {
        for c in 0..16u64 {
            assert!(
                prime_interval_secs(0, c) >= MIN_DELAY_SECS,
                "base 0 must clamp to >= MIN_DELAY_SECS, never 0"
            );
        }
    }

    #[test]
    fn large_base_saturates_not_wraps() {
        // base * 41 would overflow u64 here; saturating_mul must keep it
        // huge (fail-safe slow) rather than wrapping to a tiny early fire.
        let big = u64::MAX / 2;
        let d = prime_interval_secs(big, 7); // idx picks a large prime
        assert!(d > big / REFERENCE_PRIME, "must not wrap to a small value");
    }

    #[test]
    fn intervals_stay_within_prime_bounds() {
        let base = 300u64;
        let lo = base * CICADA_PRIMES.iter().copied().min().unwrap() / REFERENCE_PRIME;
        let hi = base * CICADA_PRIMES.iter().copied().max().unwrap() / REFERENCE_PRIME;
        for c in 0..256u64 {
            let d = prime_interval_secs(base, c);
            assert!(d >= lo && d <= hi, "delay {d} out of [{lo},{hi}] at step {c}");
        }
    }

    #[test]
    fn walk_visits_every_prime_within_one_cycle() {
        // Stride coprime to the table length must hit all 8 primes across
        // 8 consecutive steps — otherwise the anonymity of the interval
        // set shrinks to a subset.
        let base = 230u64; // 230/23 = 10, so interval == prime exactly, easy to read
        let mut seen = std::collections::BTreeSet::new();
        for c in 0..CICADA_PRIMES.len() as u64 {
            seen.insert(prime_interval_secs(base, c));
        }
        let expected: std::collections::BTreeSet<u64> =
            CICADA_PRIMES.iter().map(|p| p * 10).collect();
        assert_eq!(seen, expected, "one cycle must visit every prime-derived interval");
    }

    #[test]
    fn adjacent_intervals_differ_no_fixed_rhythm() {
        // The whole point: consecutive fires are never the same length, so
        // there is no single period an observer can phase-lock onto.
        let base = 300u64;
        for c in 0..64u64 {
            assert_ne!(
                prime_interval_secs(base, c),
                prime_interval_secs(base, c + 1),
                "adjacent intervals must differ (step {c})"
            );
        }
    }

    #[test]
    fn walk_is_non_monotonic() {
        // Non-monotonic ordering is what breaks the recognisable 13→17→19…
        // ramp. Assert the first cycle is not sorted ascending.
        let base = 230u64;
        let seq: Vec<u64> = (0..CICADA_PRIMES.len() as u64)
            .map(|c| prime_interval_secs(base, c))
            .collect();
        let mut sorted = seq.clone();
        sorted.sort_unstable();
        assert_ne!(seq, sorted, "prime walk must not emerge as a monotonic ramp");
    }

    #[test]
    fn schedule_advances_and_peek_matches() {
        let mut s = CicadaSchedule::new(300);
        assert_eq!(s.step(), 0);
        let peeked = s.peek();
        let advanced = s.advance();
        assert_eq!(peeked, advanced, "peek must equal the value advance() returns");
        assert_eq!(s.step(), 1);
        // Second advance yields a different step's delay.
        let second = s.advance();
        assert_eq!(s.step(), 2);
        assert_eq!(second, prime_interval_secs(300, 1));
    }

    #[test]
    fn counter_wraps_without_panic() {
        // Near u64::MAX the wrapping_mul/add must not panic in debug.
        let mut s = CicadaSchedule { base_secs: 300, counter: u64::MAX - 2 };
        for _ in 0..8 {
            let _ = s.advance();
        }
    }
}
