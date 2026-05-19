//! Property-based invariants for `coincync::primitives::Hash` +
//! the top-level `hash_data` / `hash_concat` / `hash_domain` /
//! `merkle_root` helpers.
//!
//! Hashes are the foundation: block IDs, tx IDs, merkle roots, key
//! commitments, view-tag derivation, every domain-separated tag the
//! protocol uses. A regression that breaks determinism breaks the
//! entire chain.
//!
//! Coverage target: take `src/primitives/hash.rs` from baseline
//! 73.59% region coverage to 90%+.

#![cfg(not(miri))]

use proptest::prelude::*;

use coincync::primitives::{hash_concat, hash_data, hash_domain, merkle_root, Hash};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    // ─── Byte roundtrip ───────────────────────────────────────────

    /// `Hash::from_bytes(b).as_bytes() == &b` byte-for-byte.
    #[test]
    fn from_bytes_as_bytes_roundtrip(bytes in any::<[u8; 32]>()) {
        let h = Hash::from_bytes(bytes);
        prop_assert_eq!(h.as_bytes(), &bytes);
    }

    /// `Hash::from_slice(&[u8; 32]) == Some(Hash::from_bytes(...))`.
    #[test]
    fn from_slice_matches_from_bytes(bytes in any::<[u8; 32]>()) {
        let from_slice = Hash::from_slice(&bytes).expect("32-byte slice must succeed");
        let from_bytes = Hash::from_bytes(bytes);
        prop_assert_eq!(from_slice, from_bytes);
    }

    /// `Hash::from_slice` returns `None` for any non-32-byte length.
    #[test]
    fn from_slice_rejects_wrong_length(
        bytes in proptest::collection::vec(any::<u8>(), 0..=64)
            .prop_filter("wrong length", |b| b.len() != 32),
    ) {
        prop_assert!(Hash::from_slice(&bytes).is_none(),
            "from_slice must reject {} bytes", bytes.len());
    }

    // ─── Hex roundtrip ────────────────────────────────────────────

    /// `Hash::from_hex(h.to_hex()) == Some(h)` byte-for-byte.
    #[test]
    fn hex_roundtrip(bytes in any::<[u8; 32]>()) {
        let h = Hash::from_bytes(bytes);
        let hex_s = h.to_hex();
        let back = Hash::from_hex(&hex_s).expect("valid hex must round-trip");
        prop_assert_eq!(back, h);
    }

    /// `to_hex()` is exactly 64 lowercase-hex chars.
    #[test]
    fn to_hex_is_64_lowercase_hex_chars(bytes in any::<[u8; 32]>()) {
        let s = Hash::from_bytes(bytes).to_hex();
        prop_assert_eq!(s.len(), 64);
        prop_assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "to_hex produced non-lowercase-hex chars: {}", s);
    }

    // ─── Hash function: determinism ───────────────────────────────

    /// `hash_data` is deterministic — same input, same output, every time.
    /// A regression that introduces nondeterminism (e.g., from a leaky
    /// timestamp or RNG) breaks block hashing entirely.
    #[test]
    fn hash_data_is_deterministic(input in proptest::collection::vec(any::<u8>(), 0..=1024)) {
        let h1 = hash_data(&input);
        let h2 = hash_data(&input);
        prop_assert_eq!(h1, h2);
    }

    /// Different inputs → different outputs (with overwhelming probability).
    /// We only assert that EQUAL inputs produce EQUAL hashes; collisions
    /// would require breaking blake3 itself, not something a property test
    /// in 256 cases will surface. So we assert the inverse weakly: two
    /// random ≥1-byte inputs differing by ≥1 byte produce hashes that
    /// usually differ.
    #[test]
    fn hash_data_distinguishes_different_inputs(
        a in proptest::collection::vec(any::<u8>(), 1..=64),
        b in proptest::collection::vec(any::<u8>(), 1..=64),
    ) {
        prop_assume!(a != b);
        let h_a = hash_data(&a);
        let h_b = hash_data(&b);
        // A collision is astronomically unlikely (2^-256). If this ever
        // fails, blake3 is broken — not us.
        prop_assert_ne!(h_a, h_b, "blake3 collision on a={:?} b={:?}", a, b);
    }

    /// `hash_concat(&[a, b])` is deterministic.
    #[test]
    fn hash_concat_is_deterministic(
        a in proptest::collection::vec(any::<u8>(), 0..=64),
        b in proptest::collection::vec(any::<u8>(), 0..=64),
    ) {
        let h1 = hash_concat(&[&a, &b]);
        let h2 = hash_concat(&[&a, &b]);
        prop_assert_eq!(h1, h2);
    }

    /// `hash_concat(&[a, b])` distinguishes from `hash_concat(&[b, a])`
    /// when a != b. (Order-sensitivity.)
    #[test]
    fn hash_concat_is_order_sensitive(
        a in proptest::collection::vec(any::<u8>(), 1..=32),
        b in proptest::collection::vec(any::<u8>(), 1..=32),
    ) {
        prop_assume!(a != b);
        let ab = hash_concat(&[&a, &b]);
        let ba = hash_concat(&[&b, &a]);
        prop_assert_ne!(ab, ba,
            "hash_concat order-collision on a={:?} b={:?}", a, b);
    }

    /// `hash_domain(domain, data)` is deterministic.
    #[test]
    fn hash_domain_is_deterministic(
        domain in proptest::collection::vec(any::<u8>(), 0..=32),
        data in proptest::collection::vec(any::<u8>(), 0..=64),
    ) {
        let h1 = hash_domain(&domain, &data);
        let h2 = hash_domain(&domain, &data);
        prop_assert_eq!(h1, h2);
    }

    /// Different domains must produce different hashes for the same data
    /// (domain separation). A regression that breaks domain separation
    /// can let attackers replay hash collisions across different
    /// protocol contexts.
    #[test]
    fn hash_domain_separates_distinct_domains(
        domain_a in proptest::collection::vec(any::<u8>(), 1..=32),
        domain_b in proptest::collection::vec(any::<u8>(), 1..=32),
        data in proptest::collection::vec(any::<u8>(), 0..=64),
    ) {
        prop_assume!(domain_a != domain_b);
        let h_a = hash_domain(&domain_a, &data);
        let h_b = hash_domain(&domain_b, &data);
        prop_assert_ne!(h_a, h_b,
            "hash_domain failed to separate domains {:?} vs {:?} on data {:?}",
            domain_a, domain_b, data);
    }

    // ─── Merkle root ──────────────────────────────────────────────

    /// `merkle_root` is deterministic given the same input slice.
    #[test]
    fn merkle_root_is_deterministic(
        n in 0usize..=8usize,
        seeds in proptest::collection::vec(any::<[u8; 32]>(), 0..=8),
    ) {
        let n = n.min(seeds.len());
        let hashes: Vec<Hash> = seeds.iter().take(n).map(|b| Hash::from_bytes(*b)).collect();
        let r1 = merkle_root(&hashes);
        let r2 = merkle_root(&hashes);
        prop_assert_eq!(r1, r2);
    }

    /// `merkle_root` of a single-element input applies RFC 6962 leaf
    /// domain separation: `merkle_root([h]) = blake3(0x00 || h)`, NOT
    /// the bare `h`. This defends against merkle-malleability
    /// (CVE-2012-2459) where an attacker could craft a tree whose
    /// internal nodes equal leaf hashes.
    ///
    /// We verify by computing the expected domain-separated value
    /// independently. If a regression strips the `0x00` prefix, this
    /// test fails before consensus does.
    #[test]
    fn merkle_root_single_leaf_is_domain_separated(bytes in any::<[u8; 32]>()) {
        let h = Hash::from_bytes(bytes);
        let root = merkle_root(&[h]);
        // Domain-separated leaf hash: blake3(0x00 || h.bytes)
        let expected = hash_concat(&[&[0x00u8], h.as_slice()]);
        prop_assert_eq!(root, expected,
            "single-leaf merkle root must be domain-separated (RFC 6962)");
        // And — critically — must NOT equal the bare leaf hash.
        prop_assert_ne!(root, h,
            "single-leaf merkle root must differ from the bare leaf (malleability defense)");
    }

    /// `merkle_root([]) == Hash::zero()` (well-defined for the empty input).
    /// Documented in the impl; protected here against accidental change.
    #[test]
    fn merkle_root_empty_is_zero(_unused in 0u8..1) {
        let empty: [Hash; 0] = [];
        let r = merkle_root(&empty);
        prop_assert_eq!(r, Hash::zero());
    }

    // ─── Zero / equality ─────────────────────────────────────────

    /// `Hash::zero().is_zero() == true`.
    #[test]
    fn zero_is_zero(_unused in 0u8..1) {
        prop_assert!(Hash::zero().is_zero());
    }

    /// Any non-zero byte array produces a non-zero hash.
    #[test]
    fn nonzero_bytes_means_nonzero_hash(bytes in any::<[u8; 32]>()) {
        prop_assume!(bytes != [0u8; 32]);
        let h = Hash::from_bytes(bytes);
        prop_assert!(!h.is_zero());
    }

    /// `ct_eq` agrees with `==` on every byte array.
    #[test]
    fn ct_eq_matches_eq(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let ha = Hash::from_bytes(a);
        let hb = Hash::from_bytes(b);
        prop_assert_eq!(ha.ct_eq(&hb), ha == hb);
    }
}
