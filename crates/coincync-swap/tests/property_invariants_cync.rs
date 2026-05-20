//! Property-based invariants for the CYNC-side swap key derivation.
//!
//! These complement `tests/property_invariants.rs` (which covers the
//! adaptor-signature math in `src/adaptor.rs`) by targeting the
//! CYNC chain-side primitives in `src/cync.rs`:
//!
//! - `cync_adaptor_point_from_secret` — `T = t·G_cync` from t's bytes
//! - `derive_swap_recipient_spend_pub` — `P + T` from compressed bytes
//! - `derive_swap_spender_secret` — `s + t` from scalar bytes
//! - `compute_swap_lock_recipient` — wallet-ready recipient bundle
//! - `CyncTxid` hex round-trip
//!
//! ## The load-bearing invariant
//!
//! `derivation_consistency` is the property the swap actually rests
//! on: the recipient's "effective spend pubkey" computed in two
//! different ways MUST be the same. If it fails:
//!
//! 1. Alice locks CYNC at `P + T` (recipient pubkey method)
//! 2. Bob later derives spend secret `s + t` (combined scalar method)
//! 3. Bob computes `(s+t)·G` and tries to spend the output at `P + T`
//! 4. Math fails → Bob has the WRONG key → Bob cannot spend Alice's
//!    locked CYNC → Bob loses the trade
//!
//! Without this property holding, every cyncswap silently fails to
//! complete on the CYNC side. The cap doesn't bound this loss —
//! it's a per-trade arithmetic correctness bug.
//!
//! Coverage target: this file aims to take `cync.rs` from the
//! baseline 77.86% region coverage measured 2026-05-19 up toward
//! the 90%+ level the rest of the crate enjoys.

#![cfg(not(miri))]

use proptest::prelude::*;

use coincync_swap::cync::{
    compute_swap_lock_recipient, cync_adaptor_point_from_secret,
    derive_swap_recipient_spend_pub, derive_swap_spender_secret, CyncTxid,
};

// ─── Strategies ────────────────────────────────────────────────

/// 32 bytes that are a canonical Ristretto255 scalar (< ℓ).
///
/// About 1 in 8 random byte sequences are non-canonical; the impl
/// rejects them with `Verification`. We filter so each property
/// case is "happy path."
fn arb_ristretto_canonical() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("Ristretto-canonical", |b| {
        cync_adaptor_point_from_secret(b).is_ok()
    })
}

// ─── Properties ────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// **The load-bearing swap-derivation property.**
    ///
    /// For any valid (spend_secret s, adaptor_secret t):
    ///   `derive_swap_recipient_spend_pub(s·G, t·G)  ==  (s + t)·G`
    ///
    /// I.e. the recipient pubkey method and the combined-secret method
    /// agree on what the effective spend pubkey is. A regression that
    /// broke either side of this equation would silently break every
    /// CYNC-side claim — Bob would have a secret that doesn't open the
    /// output Alice locked.
    #[test]
    fn derivation_consistency(
        s_bytes in arb_ristretto_canonical(),
        t_bytes in arb_ristretto_canonical(),
    ) {
        // Pubs from individual secrets.
        let p_pub = cync_adaptor_point_from_secret(&s_bytes)
            .expect("filtered to canonical");
        let t_pub = cync_adaptor_point_from_secret(&t_bytes)
            .expect("filtered to canonical");

        // Method 1: derive_swap_recipient_spend_pub(P, T) = P + T
        let recipient_pub = derive_swap_recipient_spend_pub(&p_pub, &t_pub)
            .expect("valid points must combine");

        // Method 2: (s + t)·G via the combined-secret derivation
        let combined_secret = derive_swap_spender_secret(&s_bytes, &t_bytes)
            .expect("valid scalars must combine");
        let combined_pub = cync_adaptor_point_from_secret(&combined_secret)
            .expect("combined scalar must be canonical");

        prop_assert_eq!(
            &recipient_pub, &combined_pub,
            "swap derivation inconsistent: P+T ({:?}) != (s+t)·G ({:?})",
            recipient_pub, combined_pub
        );
    }

    /// **Adaptor-point determinism.**
    ///
    /// `cync_adaptor_point_from_secret(t)` must yield the same bytes
    /// for the same `t` on repeated invocations. A regression that
    /// introduced any nondeterminism (e.g., RNG leak, time-based)
    /// would mean Alice and Bob compute different T points and the
    /// swap fails at lock-construction.
    #[test]
    fn adaptor_point_is_deterministic(t_bytes in arb_ristretto_canonical()) {
        let t_pub_1 = cync_adaptor_point_from_secret(&t_bytes).expect("canonical");
        let t_pub_2 = cync_adaptor_point_from_secret(&t_bytes).expect("canonical");
        prop_assert_eq!(t_pub_1, t_pub_2,
            "adaptor point computation is nondeterministic on input {:?}", t_bytes);
    }

    /// **Spender-secret commutativity.**
    ///
    /// `derive_swap_spender_secret(s, t) == derive_swap_spender_secret(t, s)`
    /// because scalar addition is commutative. A regression that
    /// broke this would mean role swapping (Alice ↔ Bob) computes
    /// different effective spend secrets, which is a silent
    /// asymmetry bug.
    #[test]
    fn spender_secret_is_commutative(
        a in arb_ristretto_canonical(),
        b in arb_ristretto_canonical(),
    ) {
        let sum_ab = derive_swap_spender_secret(&a, &b).expect("a + b");
        let sum_ba = derive_swap_spender_secret(&b, &a).expect("b + a");
        prop_assert_eq!(sum_ab, sum_ba,
            "derive_swap_spender_secret should be commutative");
    }

    /// **compute_swap_lock_recipient round-trips view + amount + lock_height.**
    ///
    /// The recipient bundle must carry the inputs through verbatim
    /// (view pub, amount, lock_height) and must produce a
    /// spend_public_bytes that matches what `derive_swap_recipient_spend_pub`
    /// would give. This is the integration property — the bundle is
    /// just a structured wrapper.
    #[test]
    fn lock_recipient_passes_through_metadata(
        counterparty_spend_pub_bytes in arb_ristretto_canonical(),
        counterparty_view_pub in any::<[u8; 32]>(),
        adaptor_secret in arb_ristretto_canonical(),
        amount in 1u64..u64::MAX, // non-zero per the input check
        lock_height in proptest::option::of(any::<u64>()),
    ) {
        // The "counterparty spend pub" must be a valid Ristretto point.
        // We pick a secret + compute the point so the test input is
        // always valid (the prop_filter via arb_ristretto_canonical
        // gives us a scalar; we treat it as a secret here and compute
        // its corresponding pub).
        let p_pub = cync_adaptor_point_from_secret(&counterparty_spend_pub_bytes)
            .expect("filtered");
        let t_pub = cync_adaptor_point_from_secret(&adaptor_secret)
            .expect("filtered");

        let bundle = compute_swap_lock_recipient(
            &p_pub, &counterparty_view_pub, &t_pub, amount, lock_height,
        ).expect("valid inputs must produce a bundle");

        // View pub passes through unchanged.
        prop_assert_eq!(bundle.view_public_bytes, counterparty_view_pub);
        // Amount passes through.
        prop_assert_eq!(bundle.amount_atomic, amount);
        // Lock height passes through.
        prop_assert_eq!(bundle.lock_height, lock_height);

        // spend_public matches independent derivation.
        let expected_spend = derive_swap_recipient_spend_pub(&p_pub, &t_pub)
            .expect("valid combination");
        prop_assert_eq!(bundle.spend_public_bytes, expected_spend);
    }

    /// **Zero amount is rejected.**
    ///
    /// Documented invariant from `compute_swap_lock_recipient`: amount
    /// must be > 0. Easy to regress if someone removes the check
    /// thinking it's redundant.
    #[test]
    fn lock_recipient_rejects_zero_amount(
        counterparty_spend in arb_ristretto_canonical(),
        counterparty_view in any::<[u8; 32]>(),
        adaptor_secret in arb_ristretto_canonical(),
        lock_height in proptest::option::of(any::<u64>()),
    ) {
        let p_pub = cync_adaptor_point_from_secret(&counterparty_spend).unwrap();
        let t_pub = cync_adaptor_point_from_secret(&adaptor_secret).unwrap();
        let result = compute_swap_lock_recipient(
            &p_pub, &counterparty_view, &t_pub, 0u64, lock_height,
        );
        prop_assert!(result.is_err(),
            "compute_swap_lock_recipient must reject amount = 0");
    }

    /// **CyncTxid hex round-trip.**
    ///
    /// `CyncTxid::from_hex(t.to_hex())` must reproduce the original
    /// txid byte-for-byte for any 32-byte input. Catches case-
    /// sensitivity or padding bugs in the hex helpers.
    #[test]
    fn txid_hex_roundtrip(bytes in any::<[u8; 32]>()) {
        let txid = CyncTxid(bytes);
        let hex_str = txid.to_hex();
        let back = CyncTxid::from_hex(&hex_str).expect("valid hex");
        prop_assert_eq!(back.0, bytes);
    }

    /// **CyncTxid::from_hex rejects wrong length.**
    ///
    /// Any hex string whose byte count isn't 32 must be rejected.
    /// Documented in the impl; protected here against accidental
    /// relaxation.
    #[test]
    fn txid_from_hex_rejects_wrong_length(
        // Generate hex strings whose byte content is NOT 32. Use
        // various byte-counts 0..=64 except exactly 32.
        bytes in proptest::collection::vec(any::<u8>(), 0..=64)
            .prop_filter("wrong length", |b| b.len() != 32),
    ) {
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let result = CyncTxid::from_hex(&hex_str);
        prop_assert!(result.is_err(),
            "CyncTxid::from_hex should reject {} bytes", bytes.len());
    }
}
