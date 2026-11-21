//! The Bobtail k-mean acceptance bar.
//!
//! A multi-sample block is valid (on the PoW axis) iff the mean of its `K`
//! lowest sample hashes clears a bar derived from the per-height ASERT target
//! `T`:
//!
//! ```text
//!     mean(h_0 … h_{K-1})  ≤  τ,     τ = T · (K+1) / 2
//! ```
//!
//! `τ = T·(K+1)/2` is the **work-preserving** conversion constant
//! (`bobtail-multisample-pow.md` §10.1): it keeps the expected number of RandomX
//! hashes per block equal to standard single-sample PoW at the same target `T`,
//! so difficulty — and with it the 51 % bound and emission schedule — is
//! unchanged by the switch to multi-sample. `K = 1` recovers ordinary PoW
//! exactly (`τ = T`, so the test becomes `h_0 ≤ T`).
//!
//! This module computes **only the bar**. It does not recompute RandomX, select
//! the canonical set, or touch the hash-locked core (`pow.rs` / `difficulty.rs`)
//! — the caller resolves each sample's hash via the existing `compute_pow_hash`
//! and passes the resolved hashes in.

use super::biguint::U512;
use crate::primitives::Hash;

/// True iff the `samples`' arithmetic mean clears the Bobtail bar derived from
/// `target` (`T`): `mean(samples) ≤ T·(K+1)/2`, where `K = samples.len()`.
///
/// Evaluated in exact integer arithmetic with no rounding. Starting from
/// `mean ≤ T·(K+1)/2` and clearing both denominators (`K` from the mean, `2`
/// from `τ`):
///
/// ```text
///     (Σ hᵢ)/K ≤ T·(K+1)/2   ⟺   2·Σ hᵢ ≤ T·K·(K+1)
/// ```
///
/// An empty sample set never clears the bar (returns `false`): a block must
/// carry `K ≥ 1` samples.
///
/// Boundary: `≤` is inclusive (equality clears), matching
/// [`Hash::meets_difficulty`]'s inclusive target boundary, so `K = 1` is
/// bit-for-bit equivalent to the single-sample rule.
pub fn k_mean_meets_target(samples: &[Hash], target: &Hash) -> bool {
    let k = samples.len();
    if k == 0 {
        return false;
    }

    // Σ hᵢ  — each hash is a 256-bit big-endian integer; the sum of K of them
    // needs up to 256 + ⌈log2 K⌉ bits, hence U512.
    let mut sum = U512::zero();
    for h in samples {
        sum += U512::from_big_endian(h.as_bytes());
    }

    let t = U512::from_big_endian(target.as_bytes());
    let k = k as u64;

    // 2·Σ hᵢ  ≤  T·K·(K+1)
    let lhs = sum * U512::from(2u64);
    let rhs = t * U512::from(k) * U512::from(k + 1);
    lhs <= rhs
}

/// How "full" the k-mean bar is, in basis points: `2·Σh / (T·K·(K+1)) · 10000`.
///
/// `10000` = exactly at `τ`; `< 10000` = headroom below `τ` (a healthy block,
/// cleared the bar with room to spare); `> 10000` = over `τ` (would fail
/// [`k_mean_meets_target`]). A detection-only health metric for the Observe
/// gauge — it says how close the current candidate is to the acceptance edge.
/// Saturates at `u64::MAX` (degenerate target / far over bar); empty set → MAX.
///
/// Consistency: `bar_fill_bps(s, t) <= 10000` iff `k_mean_meets_target(s, t)`.
pub fn bar_fill_bps(samples: &[Hash], target: &Hash) -> u64 {
    let k = samples.len();
    if k == 0 {
        return u64::MAX;
    }
    let mut sum = U512::zero();
    for h in samples {
        sum += U512::from_big_endian(h.as_bytes());
    }
    let t = U512::from_big_endian(target.as_bytes());
    let k = k as u64;
    let lhs = sum * U512::from(2u64);
    let rhs = t * U512::from(k) * U512::from(k + 1);
    if rhs.is_zero() {
        return u64::MAX;
    }
    let q = lhs * U512::from(10_000u64) / rhs;
    if q > U512::from(u64::MAX) {
        u64::MAX
    } else {
        q.low_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte0: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = byte0;
        Hash::from_bytes(b)
    }

    /// K=1 must be bit-for-bit the single-sample rule: τ = T·2/2 = T, so the
    /// test is exactly `h_0 ≤ T` = `Hash::meets_difficulty`.
    #[test]
    fn k1_matches_single_sample_rule() {
        let target = h(0x80);
        for v in [0x00u8, 0x7F, 0x80, 0x81, 0xFF] {
            let s = h(v);
            assert_eq!(
                k_mean_meets_target(&[s], &target),
                s.meets_difficulty(&target),
                "K=1 must equal meets_difficulty at sample byte {v:#x}",
            );
        }
    }

    /// Empty sample set never clears the bar.
    #[test]
    fn empty_set_fails() {
        assert!(!k_mean_meets_target(&[], &h(0xFF)));
    }

    /// A set whose mean is below τ clears; one above fails. Real targets are
    /// *small* (hard), so τ = T·(K+1)/2 stays below the max hash and the bar
    /// bites. With K=4 and T=0x10·2^248, τ = 2.5·T = 0x28·2^248:
    ///   - mean 0x08·2^248 (= 0.5·T) ≪ τ  → pass;
    ///   - mean 0x80·2^248 (= 8·T)   ≫ τ  → fail.
    #[test]
    fn mean_below_passes_above_fails() {
        let target = h(0x10);
        let k = 4usize;

        let low = vec![h(0x08); k];
        assert!(k_mean_meets_target(&low, &target), "mean 0.5·T < τ must pass");

        let high = vec![h(0x80); k];
        assert!(
            !k_mean_meets_target(&high, &target),
            "mean 8·T > τ must fail",
        );
    }

    /// Exact boundary: τ = T·(K+1)/2. If every sample equals τ/1 scaled so the
    /// mean is exactly τ, the inclusive `≤` must pass; one atomic unit over must
    /// fail. We construct the boundary directly: K identical samples each equal
    /// to τ ⇒ mean = τ. τ = T·(K+1)/2; pick T and K so τ is representable.
    #[test]
    fn inclusive_boundary() {
        // K=3, T first-byte 0x10 → τ = T·4/2 = 2T → per-sample value 2T gives
        // mean exactly 2T = τ. 2T has first byte 0x20.
        let k = 3usize;
        let target = h(0x10);
        let at_tau = vec![h(0x20); k]; // mean = 0x20 = 2·0x10 = τ
        assert!(
            k_mean_meets_target(&at_tau, &target),
            "mean exactly at τ must pass (inclusive)",
        );

        // One unit over on a single sample pushes the mean above τ.
        let mut over = at_tau.clone();
        let mut b = [0u8; 32];
        b[0] = 0x20;
        b[31] = 0x01; // +1 atomic unit on the least-significant byte
        over[0] = Hash::from_bytes(b);
        assert!(
            !k_mean_meets_target(&over, &target),
            "one unit over τ must fail",
        );
    }

    /// `bar_fill_bps <= 10000` must agree exactly with `k_mean_meets_target`,
    /// and report headroom below τ / overshoot above it.
    #[test]
    fn bar_fill_tracks_the_bar() {
        let target = h(0x10); // small (hard) target so τ bites
        let k = 4usize;

        // Mean 0.5·T, τ = 2.5·T → well under: fill < 10000 and meets.
        let low = vec![h(0x08); k];
        assert!(bar_fill_bps(&low, &target) < 10_000);
        assert!(k_mean_meets_target(&low, &target));

        // Mean 8·T ≫ τ → fill > 10000 and fails.
        let high = vec![h(0x80); k];
        assert!(bar_fill_bps(&high, &target) > 10_000);
        assert!(!k_mean_meets_target(&high, &target));

        // Exactly at τ (K=3, T=0x10 → τ=2T=0x20): fill == 10000 and meets.
        let at = vec![h(0x20); 3];
        assert_eq!(bar_fill_bps(&at, &h(0x10)), 10_000);
        assert!(k_mean_meets_target(&at, &h(0x10)));
    }

    /// No overflow / panic at the extreme: K large, all samples max, max target.
    #[test]
    fn no_overflow_at_extremes() {
        let target = Hash::from_bytes([0xFF; 32]);
        let samples = vec![Hash::from_bytes([0xFF; 32]); 64];
        // mean = MAX, τ = MAX·(K+1)/2 ≫ MAX → must pass, and must not panic.
        assert!(k_mean_meets_target(&samples, &target));
    }
}
