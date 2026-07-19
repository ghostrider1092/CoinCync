//! Property-based invariants for `coincync::crypto::stealth`.
//!
//! Stealth addresses are the **privacy primitive** of every payment:
//! each output has a freshly-derived one-time stealth public key, so
//! a chain observer cannot link payments by address. A regression
//! here breaks the receiver-privacy property at the heart of the
//! constitutional posture (Article XIV).
//!
//! Properties exercised:
//!
//! - **Detection roundtrip:** an address generated for (spend, view)
//!   keys is detected by is_output_ours with the matching view_secret.
//! - **Detection rejection:** an address generated for one recipient
//!   is NOT detected by a different recipient's view_secret.
//! - **Output-index sensitivity:** detection respects the output_idx —
//!   an address for idx=3 is not detected at idx=5.
//! - **Spending invariant:** the spender's one-time secret S satisfies
//!   S·G == stealth.public_key. This is the load-bearing math: a
//!   regression means the recipient can detect the payment but cannot
//!   spend it.
//! - **Determinism:** all detection functions are deterministic.
//!
//! Every property is grounded in `src/crypto/stealth.rs` (lines
//! 761-1000), not assumed.

#![cfg(not(miri))]

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

use coincync::crypto::{compute_one_time_secret, generate_stealth_address_checked, is_output_ours};
use coincync::crypto::{PublicPoint, SecretScalar};
use coincync::primitives::{PublicKey, SecretKey};

// ─── Helper: deterministic keypair from seed ──────────────────────

fn keypair_from_seed(seed: u64) -> (SecretKey, PublicKey) {
    let mut rng = StdRng::seed_from_u64(seed);
    let s = SecretScalar::random(&mut rng);
    let p = s.to_public();
    (
        SecretKey::from_bytes(s.to_bytes()),
        PublicKey::from_bytes(p.to_bytes()),
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,  // stealth-address ops are heavier — 64 cases ≈ 1-2 sec
        .. ProptestConfig::default()
    })]

    // ─── Detection roundtrip (positive) ──────────────────────────

    /// A stealth address generated for recipient (spend_pub, view_pub)
    /// must be detected by `is_output_ours` when called with the
    /// matching `view_secret` and `spend_public`.
    ///
    /// This is the **fundamental privacy primitive** — if it fails,
    /// the recipient cannot receive payments at all.
    #[test]
    fn generated_address_is_detected_by_recipient(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        gen_seed in any::<u64>(),
        output_idx in any::<u8>(),
    ) {
        prop_assume!(spend_seed != view_seed);
        let (_spend_secret, spend_public) = keypair_from_seed(spend_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let mut gen_rng = StdRng::seed_from_u64(gen_seed);
        let (stealth, _) = generate_stealth_address_checked(
            &spend_public, &view_public, output_idx, &mut gen_rng,
        ).expect("generation must succeed for valid keys");

        // Recipient detection: must return true.
        prop_assert!(
            is_output_ours(&stealth, &view_secret, &spend_public, output_idx),
            "recipient could not detect their own stealth address (seed: spend={} view={} gen={} idx={})",
            spend_seed, view_seed, gen_seed, output_idx
        );
    }

    // ─── Detection rejection (negative — privacy property) ───────

    /// A stealth address generated for recipient A must NOT be
    /// detected by a different recipient B (with different view_secret
    /// or different spend_public). This is the privacy guarantee.
    #[test]
    fn stealth_address_not_detected_by_other_recipient(
        recipient_a_spend_seed in any::<u64>(),
        recipient_a_view_seed in any::<u64>(),
        recipient_b_spend_seed in any::<u64>(),
        recipient_b_view_seed in any::<u64>(),
        gen_seed in any::<u64>(),
        output_idx in any::<u8>(),
    ) {
        // Different recipients means at least one of (spend, view) differs.
        prop_assume!(
            recipient_a_spend_seed != recipient_b_spend_seed
            || recipient_a_view_seed != recipient_b_view_seed
        );
        prop_assume!(recipient_a_spend_seed != recipient_a_view_seed);
        prop_assume!(recipient_b_spend_seed != recipient_b_view_seed);

        let (_a_spend_secret, a_spend_public) = keypair_from_seed(recipient_a_spend_seed);
        let (_a_view_secret, a_view_public) = keypair_from_seed(recipient_a_view_seed);
        let (b_view_secret, _) = keypair_from_seed(recipient_b_view_seed);
        let (_, b_spend_public) = keypair_from_seed(recipient_b_spend_seed);

        // Generate stealth address for A.
        let mut gen_rng = StdRng::seed_from_u64(gen_seed);
        let (stealth, _) = generate_stealth_address_checked(
            &a_spend_public, &a_view_public, output_idx, &mut gen_rng,
        ).expect("generation");

        // B tries to detect with their own view_secret + spend_public.
        // Must return false.
        prop_assert!(
            !is_output_ours(&stealth, &b_view_secret, &b_spend_public, output_idx),
            "wrong-recipient detection returned true — privacy leak!"
        );
    }

    // ─── Output-index sensitivity ─────────────────────────────────

    /// A stealth address generated for output_idx=X must NOT be
    /// detected at output_idx=Y when X != Y. The output_idx is
    /// folded into the one-time-key derivation; different idx →
    /// different stealth pubkey.
    #[test]
    fn stealth_address_is_output_index_sensitive(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        gen_seed in any::<u64>(),
        idx_a in any::<u8>(),
        idx_b in any::<u8>(),
    ) {
        prop_assume!(idx_a != idx_b);
        prop_assume!(spend_seed != view_seed);

        let (_spend_secret, spend_public) = keypair_from_seed(spend_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let mut gen_rng = StdRng::seed_from_u64(gen_seed);
        let (stealth, _) = generate_stealth_address_checked(
            &spend_public, &view_public, idx_a, &mut gen_rng,
        ).expect("generation");

        // Detection at the CORRECT idx must succeed.
        prop_assert!(
            is_output_ours(&stealth, &view_secret, &spend_public, idx_a),
            "self-detection failed at correct idx={}", idx_a
        );
        // Detection at a DIFFERENT idx must fail.
        prop_assert!(
            !is_output_ours(&stealth, &view_secret, &spend_public, idx_b),
            "false-positive detection at wrong idx={} (correct: {})", idx_b, idx_a
        );
    }

    // ─── Spending invariant ───────────────────────────────────────

    /// **The load-bearing math.** The one-time secret returned by
    /// `compute_one_time_secret` must satisfy:
    ///
    ///     one_time_secret · G == stealth.public_key
    ///
    /// I.e., the secret is the discrete log of the stealth address's
    /// public key, so the holder can construct a valid signature
    /// spending the output. A regression here means the recipient
    /// detects the payment but the bytes they sign don't match the
    /// chain — the output is unspendable.
    ///
    /// Verification: derive one_time_secret, multiply by G, compare
    /// bytes to stealth.public_key.
    #[test]
    fn one_time_secret_satisfies_spending_equation(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        gen_seed in any::<u64>(),
        output_idx in any::<u8>(),
    ) {
        prop_assume!(spend_seed != view_seed);

        let (spend_secret, spend_public) = keypair_from_seed(spend_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let mut gen_rng = StdRng::seed_from_u64(gen_seed);
        let (stealth, _) = generate_stealth_address_checked(
            &spend_public, &view_public, output_idx, &mut gen_rng,
        ).expect("generation");

        // Compute the one-time secret.
        let one_time = compute_one_time_secret(
            &stealth, &view_secret, &spend_secret, output_idx,
        ).expect("one-time secret derivation");

        // Multiply one_time by G to get the expected public key.
        let one_time_scalar = SecretScalar::from_bytes(*one_time.as_bytes());
        let derived_pub = one_time_scalar.to_public().to_bytes();

        // Compare to stealth.public_key.
        prop_assert_eq!(
            derived_pub, *stealth.public_key.as_bytes(),
            "one_time_secret · G != stealth.public_key — recipient cannot spend!"
        );
    }

    // ─── Determinism ─────────────────────────────────────────────

    /// `is_output_ours` is deterministic — same inputs, same answer.
    /// A regression introducing randomness would break consensus on
    /// what's "yours."
    #[test]
    fn is_output_ours_is_deterministic(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        gen_seed in any::<u64>(),
        output_idx in any::<u8>(),
    ) {
        prop_assume!(spend_seed != view_seed);
        let (_spend_secret, spend_public) = keypair_from_seed(spend_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let mut gen_rng = StdRng::seed_from_u64(gen_seed);
        let (stealth, _) = generate_stealth_address_checked(
            &spend_public, &view_public, output_idx, &mut gen_rng,
        ).expect("generation");

        let r1 = is_output_ours(&stealth, &view_secret, &spend_public, output_idx);
        let r2 = is_output_ours(&stealth, &view_secret, &spend_public, output_idx);
        prop_assert_eq!(r1, r2);
    }

    /// `compute_one_time_secret` is deterministic.
    #[test]
    fn compute_one_time_secret_is_deterministic(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        gen_seed in any::<u64>(),
        output_idx in any::<u8>(),
    ) {
        prop_assume!(spend_seed != view_seed);
        let (spend_secret, spend_public) = keypair_from_seed(spend_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let mut gen_rng = StdRng::seed_from_u64(gen_seed);
        let (stealth, _) = generate_stealth_address_checked(
            &spend_public, &view_public, output_idx, &mut gen_rng,
        ).expect("generation");

        let s1 = compute_one_time_secret(&stealth, &view_secret, &spend_secret, output_idx)
            .expect("ots");
        let s2 = compute_one_time_secret(&stealth, &view_secret, &spend_secret, output_idx)
            .expect("ots");
        prop_assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    // ─── Invalid-input handling ──────────────────────────────────

    /// `is_output_ours` with non-curve-point bytes in `stealth.tx_public_key`
    /// must return false (not panic). The impl checks `PublicPoint::from_bytes`
    /// at line 921-923 and returns false on invalid points.
    #[test]
    fn is_output_ours_rejects_non_curve_tx_public(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        gen_seed in any::<u64>(),
        output_idx in any::<u8>(),
        invalid_tx_pub in any::<[u8; 32]>(),
    ) {
        prop_assume!(spend_seed != view_seed);
        // Skip cases where the random bytes happen to be on-curve.
        prop_assume!(PublicPoint::from_bytes(invalid_tx_pub).is_none());

        let (_spend_secret, spend_public) = keypair_from_seed(spend_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let mut gen_rng = StdRng::seed_from_u64(gen_seed);
        let (mut stealth, _) = generate_stealth_address_checked(
            &spend_public, &view_public, output_idx, &mut gen_rng,
        ).expect("generation");

        // Corrupt the stealth's tx_public_key to non-curve bytes.
        stealth.tx_public_key = PublicKey::from_bytes(invalid_tx_pub);

        // Must return false, not panic.
        let result = is_output_ours(&stealth, &view_secret, &spend_public, output_idx);
        prop_assert!(!result, "is_output_ours returned true on invalid tx_public_key");
    }
}
