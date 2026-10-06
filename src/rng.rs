//! Canonical **non-security** RNG source — the single place non-cryptographic
//! randomness is drawn, so the deterministic-simulation harness can make it
//! reproducible (correctness-program enabler **E3**; see
//! docs/design/correctness-program.md). The time analogue is [`crate::clock`].
//!
//! # CRYPTO MUST NOT USE THIS
//! Key generation, nonces, blinding factors, CLSAG ring decoy selection, and the
//! Lelantus-Spark anonymity-set shuffle draw from `OsRng` directly and MUST keep
//! doing so — injecting a known seed into security randomness would be a critical
//! vulnerability (predictable nonces leak keys; a predictable decoy/anon-set
//! shuffle deanonymizes spends). This module is ONLY for randomness whose
//! predictability is not a security property: timing jitter, cover-traffic
//! padding bytes, tie-breaks, backoff spreading.
//!
//! # No production behavior change
//! With no override installed (always, in production) it draws from
//! `rand::thread_rng()` — a ChaCha12 CSPRNG reseeded from the OS — so production
//! randomness is byte-for-byte what it was before this module existed. Under an
//! explicit sim-seed override (tests / DST ONLY, never set in production) it
//! draws from a seeded ChaCha20 stream, making the non-security randomness
//! reproducible so a failing simulation replays identically.

use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::sync::atomic::{AtomicI64, Ordering};

/// `-1` = no override, draw from the real CSPRNG (production). Any value `>= 0`
/// is the installed simulation seed.
static SIM_SEED: AtomicI64 = AtomicI64::new(-1);

thread_local! {
    /// The per-thread seeded stream while an override is installed. Thread-local
    /// so draws don't contend a lock; a thread spawned mid-simulation seeds
    /// lazily from the global seed (see [`with_rng`]), so it is still
    /// deterministic for a given seed as long as the simulation is single-
    /// threaded through its randomness (which the DST harness is).
    static SIM_RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
}

/// Whether a simulation seed is currently installed.
pub fn is_overridden() -> bool {
    SIM_SEED.load(Ordering::Relaxed) >= 0
}

/// Install (or reset) the simulation seed: every non-security draw on this thread
/// becomes a deterministic function of `seed` until cleared. Tests / DST only.
pub fn set_sim_seed(seed: u64) {
    SIM_SEED.store(seed as i64, Ordering::Relaxed);
    SIM_RNG.with(|c| *c.borrow_mut() = Some(ChaCha20Rng::seed_from_u64(seed)));
}

/// Clear the override, restoring the real CSPRNG.
pub fn clear_sim() {
    SIM_SEED.store(-1, Ordering::Relaxed);
    SIM_RNG.with(|c| *c.borrow_mut() = None);
}

/// Install a seed and return a guard that restores the real CSPRNG on drop — the
/// RAII form for scoped test use.
#[must_use = "dropping the guard immediately restores the real RNG"]
pub fn override_scope(seed: u64) -> RngGuard {
    set_sim_seed(seed);
    RngGuard { _priv: () }
}

/// Restores the real CSPRNG on drop. See [`override_scope`].
pub struct RngGuard {
    _priv: (),
}

impl Drop for RngGuard {
    fn drop(&mut self) {
        clear_sim();
    }
}

/// Run `f` with the active RNG — the seeded stream under an override, else a
/// fresh `thread_rng`. The single branch point every public helper routes
/// through.
fn with_rng<T>(f: impl FnOnce(&mut dyn RngCore) -> T) -> T {
    if is_overridden() {
        SIM_RNG.with(|c| {
            let mut b = c.borrow_mut();
            let r = b.get_or_insert_with(|| {
                ChaCha20Rng::seed_from_u64(SIM_SEED.load(Ordering::Relaxed).max(0) as u64)
            });
            f(r)
        })
    } else {
        f(&mut rand::thread_rng())
    }
}

/// Fill `dst` with non-security random bytes (cover-traffic padding, etc.).
pub fn fill_bytes(dst: &mut [u8]) {
    with_rng(|r| r.fill_bytes(dst));
}

/// A non-security random `u64`.
pub fn next_u64() -> u64 {
    with_rng(|r| r.next_u64())
}

/// Uniform integer in the inclusive range `[low, high]` (mirrors
/// `Rng::gen_range(low..=high)`). Returns `low` if `low >= high`.
pub fn gen_range_u64(low: u64, high: u64) -> u64 {
    if low >= high {
        return low;
    }
    with_rng(|r| r.gen_range(low..=high))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate the process-global seed, so they serialize on a guard
    // and always restore the real RNG afterwards.
    static TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn production_mode_is_not_overridden_by_default() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear_sim();
        assert!(!is_overridden());
        // Two draws almost never collide — just assert it runs and varies shape.
        let a = next_u64();
        let b = next_u64();
        let _ = (a, b); // non-deterministic in prod; only assert no panic
    }

    #[test]
    fn same_seed_replays_identically() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());

        let seq1 = {
            let _s = override_scope(0xC0FFEE);
            let mut buf = [0u8; 16];
            fill_bytes(&mut buf);
            (buf, next_u64(), gen_range_u64(0, 1_000_000))
        };
        // Guard dropped → cleared.
        assert!(!is_overridden());
        let seq2 = {
            let _s = override_scope(0xC0FFEE);
            let mut buf = [0u8; 16];
            fill_bytes(&mut buf);
            (buf, next_u64(), gen_range_u64(0, 1_000_000))
        };
        assert_eq!(seq1, seq2, "same seed must reproduce the same draws");
    }

    #[test]
    fn different_seeds_diverge() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let a = {
            let _s = override_scope(1);
            next_u64()
        };
        let b = {
            let _s = override_scope(2);
            next_u64()
        };
        assert_ne!(a, b, "different seeds should (overwhelmingly) differ");
    }

    #[test]
    fn gen_range_is_bounded_and_handles_degenerate() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let _s = override_scope(7);
        for _ in 0..1000 {
            let v = gen_range_u64(10, 20);
            assert!((10..=20).contains(&v));
        }
        // Degenerate range returns the low bound, never panics.
        assert_eq!(gen_range_u64(5, 5), 5);
        assert_eq!(gen_range_u64(9, 3), 9);
    }

    #[test]
    fn guard_restores_real_rng() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        {
            let _s = override_scope(99);
            assert!(is_overridden());
        }
        assert!(!is_overridden());
    }
}
