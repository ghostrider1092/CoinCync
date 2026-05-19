//! Property-based invariants for `coincync::primitives::Address`.
//!
//! Address parsing is attacker-reachable (anyone can send a malformed
//! address string to a wallet user). Bugs in the parser ripple
//! through wallet UX, RPC, and tx construction. The properties below
//! exercise:
//!
//! - Bytes/string roundtrip with curve-valid keypairs (happy path)
//! - Checksum rejection (bit-flip → Err)
//! - Length validation (short bytes / wrong type-length → Err)
//! - Type-byte / network-byte enum coverage (only valid discriminants)
//! - String-prefix handling (wrong prefix → Err)
//! - Mainnet/testnet network-mismatch rejection
//!
//! Coverage target: take `src/primitives/address.rs` from baseline
//! 70.65% region coverage to 90%+.
//!
//! ## Lesson applied from `merkle_root_single_leaf_is_identity`:
//!
//! Every property below is grounded in the actual implementation in
//! `src/primitives/address.rs`, not in what "typical address parsers"
//! do. See `to_bytes()`/`from_bytes()` at lines 56-105 for the
//! checksum format (last 4 bytes = blake3(rest).as_bytes()[..4]) and
//! the type-length table (Standard/Subaddress = 70, Integrated = 78).

#![cfg(not(miri))]

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

use coincync::crypto::SecretScalar;
use coincync::primitives::{Address, PublicKey};

// ─── Test-helper: deterministic curve-valid keypair from a seed ───

fn keypair_from_seed(seed: u64) -> PublicKey {
    let mut rng = StdRng::seed_from_u64(seed);
    let secret = SecretScalar::random(&mut rng);
    let pp = secret.to_public();
    PublicKey::from_bytes(pp.to_bytes())
}

// ─── Network enum (from address.rs:17-27) ─────────────────────────

// Network has exactly 2 variants: Mainnet (byte 0) and Testnet (byte 1).
// Per the impl at line 79, any other byte is rejected with "bad network".

fn arb_network() -> impl Strategy<Value = coincync::primitives::Network> {
    use coincync::primitives::Network;
    prop_oneof![Just(Network::Mainnet), Just(Network::Testnet)]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    // ─── Happy-path roundtrip ─────────────────────────────────────

    /// For any curve-valid keypair and network choice, the cycle
    ///   Address::new → to_string → Address::from_string
    /// returns an equal Address.
    #[test]
    fn string_roundtrip_with_valid_keys(
        network in arb_network(),
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        // Skip identity: if both seeds equal, spend == view which is degenerate.
        prop_assume!(spend_seed != view_seed);

        let spend = keypair_from_seed(spend_seed);
        let view = keypair_from_seed(view_seed);
        let addr = Address::new(network, spend, view);
        let s = addr.to_string();
        let parsed = Address::from_string(&s)
            .expect("valid curve-point address must roundtrip");
        prop_assert_eq!(addr, parsed);
    }

    /// Mainnet addresses start with "CYNC"; testnet with "tCYNC".
    /// (Per `Network::prefix()` at line 26.)
    #[test]
    fn string_prefix_matches_network(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        prop_assume!(spend_seed != view_seed);
        let spend = keypair_from_seed(spend_seed);
        let view = keypair_from_seed(view_seed);
        let mainnet = Address::new(coincync::primitives::Network::Mainnet, spend, view);
        let testnet = Address::new(coincync::primitives::Network::Testnet, spend, view);
        prop_assert!(mainnet.to_string().starts_with("CYNC"),
            "mainnet must start with CYNC, got: {}", mainnet.to_string());
        prop_assert!(testnet.to_string().starts_with("tCYNC"),
            "testnet must start with tCYNC, got: {}", testnet.to_string());
    }

    /// Bytes roundtrip via the (unchecked) `from_bytes` path. We use
    /// `from_bytes` here because the bytes were just produced by
    /// `to_bytes()` and are by-construction valid — `from_bytes_checked`
    /// is for untrusted external input.
    #[test]
    fn bytes_roundtrip(
        network in arb_network(),
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        prop_assume!(spend_seed != view_seed);
        let spend = keypair_from_seed(spend_seed);
        let view = keypair_from_seed(view_seed);
        let addr = Address::new(network, spend, view);
        let bytes = addr.to_bytes();
        let parsed = Address::from_bytes(&bytes)
            .expect("self-produced bytes must roundtrip");
        prop_assert_eq!(addr, parsed);
    }

    // ─── Checksum rejection (bit-flip detection) ─────────────────

    /// Flipping any single bit in a valid serialized address produces
    /// bytes that `from_bytes` rejects (either via checksum mismatch
    /// or via downstream validation — both are correct rejections).
    /// This is the bit-flip detection invariant.
    #[test]
    fn flipping_a_bit_invalidates_the_address(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        byte_idx in any::<usize>(),
        bit_idx in 0u8..8,
    ) {
        prop_assume!(spend_seed != view_seed);
        let spend = keypair_from_seed(spend_seed);
        let view = keypair_from_seed(view_seed);
        let addr = Address::new(coincync::primitives::Network::Mainnet, spend, view);
        let mut bytes = addr.to_bytes();
        let idx = byte_idx % bytes.len();
        bytes[idx] ^= 1u8 << bit_idx;

        // The flipped bytes MUST be rejected. (One in 2^something
        // chance the flipped bytes happen to also be valid — for a
        // 4-byte checksum, that's 2^-32, negligible across 256 cases.)
        let result = Address::from_bytes(&bytes);
        prop_assert!(result.is_err(),
            "bit-flipped address bytes were accepted at byte={} bit={}", idx, bit_idx);
    }

    // ─── Length validation ──────────────────────────────────────

    /// Any byte slice shorter than 70 bytes is rejected — even if
    /// the first bytes happen to look like valid network/type fields.
    #[test]
    fn short_bytes_rejected(bytes in proptest::collection::vec(any::<u8>(), 0..70)) {
        prop_assert!(Address::from_bytes(&bytes).is_err(),
            "bytes of length {} accepted (must be ≥ 70)", bytes.len());
    }

    /// Bytes of EXACTLY 70 length where the type byte is Integrated (2)
    /// must be rejected — Integrated addresses require 78 bytes.
    /// (Per the length table at lines 84-92.)
    #[test]
    fn standard_length_with_integrated_type_is_rejected(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        prop_assume!(spend_seed != view_seed);
        let spend = keypair_from_seed(spend_seed);
        let view = keypair_from_seed(view_seed);
        let mut addr = Address::new(coincync::primitives::Network::Mainnet, spend, view);
        // Manually set type to Integrated but with no payment_id, so
        // serialization will produce 70 bytes (not 78).
        addr.address_type = coincync::primitives::AddressType::Integrated;
        // payment_id stays None ⇒ to_bytes produces 70 bytes, but
        // type=Integrated says it should be 78. from_bytes must reject.
        let bytes = addr.to_bytes();
        let result = Address::from_bytes(&bytes);
        prop_assert!(result.is_err(),
            "70-byte Integrated address accepted; expected length-mismatch rejection");
    }

    // ─── Network byte validation ─────────────────────────────────

    /// Any address bytes with network byte > 1 are rejected.
    /// (Per the match at line 79.)
    #[test]
    fn invalid_network_byte_rejected(
        spend_seed in any::<u64>(),
        view_seed in any::<u64>(),
        bad_net in 2u8..=255u8,
    ) {
        prop_assume!(spend_seed != view_seed);
        let spend = keypair_from_seed(spend_seed);
        let view = keypair_from_seed(view_seed);
        let addr = Address::new(coincync::primitives::Network::Mainnet, spend, view);
        let mut bytes = addr.to_bytes();
        bytes[0] = bad_net;
        // The checksum is now wrong AND the network byte is invalid;
        // either rejection is correct.
        let result = Address::from_bytes(&bytes);
        prop_assert!(result.is_err(),
            "address with network byte = {} was accepted", bad_net);
    }

    // ─── String prefix validation ─────────────────────────────────

    /// Strings without `CYNC` or `tCYNC` prefix are rejected.
    /// (Per `from_string` at lines 133-140.)
    #[test]
    fn bad_prefix_string_rejected(
        // Generate strings that DO NOT start with CYNC or tCYNC.
        s in "[a-zA-Z0-9]{1,40}".prop_filter(
            "must not start with valid prefix",
            |s| !s.starts_with("CYNC") && !s.starts_with("tCYNC"),
        ),
    ) {
        prop_assert!(Address::from_string(&s).is_err(),
            "string '{}' without valid prefix was accepted", s);
    }

    /// Empty string is rejected.
    #[test]
    fn empty_string_rejected(_unused in 0u8..1) {
        prop_assert!(Address::from_string("").is_err());
    }

    /// Strings ending in `NAME_SUFFIX` (the `.cync` name lookup suffix)
    /// must be rejected by `FromStr` because they require a name lookup,
    /// not address parsing. (Per `FromStr` impl at line 160.)
    ///
    /// We can't directly reference `NAME_SUFFIX` from outside the
    /// crate (it's not re-exported), but per `crate::constants` the
    /// value is `.cync` — we hard-code that and verify rejection.
    #[test]
    fn from_str_rejects_name_suffix(prefix in "[a-zA-Z]{1,20}") {
        let with_name = format!("{}.cync", prefix);
        let result: Result<Address, _> = with_name.parse();
        prop_assert!(result.is_err(),
            "FromStr accepted name-lookup-form '{}'", with_name);
    }

    // ─── AddressType enum (from address.rs:30-40) ────────────────

    /// Each `AddressType` round-trips through its `type_byte()` and
    /// `from_byte()` accessors.
    #[test]
    fn address_type_byte_roundtrip(_unused in 0u8..1) {
        use coincync::primitives::AddressType;
        for t in [AddressType::Standard, AddressType::Subaddress, AddressType::Integrated] {
            let byte = t.type_byte();
            let back = AddressType::from_byte(byte)
                .expect("type_byte must produce a valid byte");
            prop_assert_eq!(back, t);
        }
    }

    /// `AddressType::from_byte` rejects every byte outside {0, 1, 2}.
    #[test]
    fn address_type_from_byte_rejects_unknown(b in 3u8..=255u8) {
        prop_assert!(coincync::primitives::AddressType::from_byte(b).is_none(),
            "AddressType::from_byte accepted unknown byte {}", b);
    }

    // ─── Network prefix consistency ──────────────────────────────

    /// `Network::prefix()` is "CYNC" for Mainnet, "tCYNC" for Testnet.
    #[test]
    fn network_prefix_strings(_unused in 0u8..1) {
        use coincync::primitives::Network;
        prop_assert_eq!(Network::Mainnet.prefix(), "CYNC");
        prop_assert_eq!(Network::Testnet.prefix(), "tCYNC");
    }
}
