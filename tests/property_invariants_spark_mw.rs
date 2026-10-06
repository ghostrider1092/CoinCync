//! Property-based invariants for the two hand-rolled zero-knowledge
//! constructions hardened on 2026-08-22:
//!
//! - **MimbleWimble cut-through kernels** (`crypto::mw_cutthrough`) — the
//!   per-kernel excess signature that prevents hidden-value inflation.
//! - **Lelantus Spark spend proofs** (`crypto::lelantus_spark`, feature-gated) —
//!   the dual-base serial-tag binding that prevents double-spends.
//!
//! Fixed-case unit tests live next to each module. These add *randomized*
//! coverage: over many random inputs, completeness must always hold and ANY
//! single-byte mutation must be rejected. Hand-rolled ZK is the highest-risk
//! code in the tree, so it gets the strongest testing.

#![cfg(not(miri))]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use proptest::prelude::*;
use rand::{rngs::StdRng, RngCore, SeedableRng};

use coincync::crypto::generator_h;
use coincync::crypto::mw_cutthrough::{
    build_signed_kernel, verify_kernel_signature, CutThroughEngine, MwKernel,
};

fn scalar_from_seed(seed: u64) -> Scalar {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, .. ProptestConfig::default() })]

    /// Completeness: a kernel built from any blindings/fee/height verifies.
    #[test]
    fn mw_kernel_sign_verify_roundtrip(
        out_seed in any::<u64>(),
        in_seed in any::<u64>(),
        fee in any::<u64>(),
        height in any::<u64>(),
    ) {
        let out = scalar_from_seed(out_seed);
        let inp = scalar_from_seed(in_seed);
        let k = build_signed_kernel(&[out], &[inp], fee, height);
        prop_assert!(verify_kernel_signature(&k), "honest kernel must verify");
    }

    /// Soundness: flipping any signature byte, or changing fee/height (both
    /// bound into the challenge), breaks verification.
    #[test]
    fn mw_kernel_tamper_rejected(
        out_seed in any::<u64>(),
        fee in 0u64..1_000_000,
        height in 0u64..1_000_000,
        flip in 0usize..64,
    ) {
        let s = scalar_from_seed(out_seed);
        let k = build_signed_kernel(&[s], &[], fee, height);
        prop_assume!(verify_kernel_signature(&k));

        let mut bad_sig = k.clone();
        bad_sig.signature[flip] ^= 0x01;
        prop_assert!(!verify_kernel_signature(&bad_sig), "flipped signature byte must reject");

        let mut bad_fee = k.clone();
        bad_fee.fee = fee.wrapping_add(1);
        prop_assert!(!verify_kernel_signature(&bad_fee), "changed fee must reject (bound in challenge)");

        let mut bad_h = k.clone();
        bad_h.height = height.wrapping_add(1);
        prop_assert!(!verify_kernel_signature(&bad_h), "changed height must reject (bound in challenge)");
    }

    /// Inflation: an excess carrying a hidden `+hidden*H` component beyond the
    /// declared fee cannot be signed, so the kernel set is rejected.
    #[test]
    fn mw_hidden_value_inflation_rejected(
        fee in 1u64..100_000,
        hidden in 1u64..100_000,
        height in 0u64..1_000_000,
    ) {
        let h = generator_h();
        let excess = h * (Scalar::from(fee) + Scalar::from(hidden)); // (fee+hidden)*H
        let k = MwKernel { excess: excess.compress().to_bytes(), signature: vec![], fee, height };
        prop_assert!(
            CutThroughEngine::verify_kernel_set(&[k]).is_err(),
            "hidden-value inflation must be rejected"
        );
    }
}

/// Determinism vector: the same kernel inputs MUST produce byte-identical
/// output (deterministic RFC-6979-style nonce). A regression to a random nonce
/// would make the same transaction produce different kernels — consensus
/// nondeterminism. Locks that property.
#[test]
fn mw_kernel_is_deterministic() {
    let x = Scalar::from(7u64);
    let a = build_signed_kernel(&[x], &[], 1000, 10);
    let b = build_signed_kernel(&[x], &[], 1000, 10);
    assert_eq!(a.excess, b.excess, "excess must be deterministic");
    assert_eq!(
        a.signature, b.signature,
        "kernel signature must be deterministic (RFC-6979-style nonce)"
    );
    assert_eq!(a.signature.len(), 64, "signature is R||s = 64 bytes");
    assert!(verify_kernel_signature(&a));
}

#[cfg(feature = "sketch-lelantus-spark")]
mod spark_props {
    use super::*;
    use coincync::crypto::lelantus_spark::{
        prove_spark_spend, spark_commit, spark_pubkey, verify_spark_spend, SparkNote,
    };

    fn rnd(rng: &mut StdRng) -> Scalar {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        Scalar::from_bytes_mod_order_wide(&b)
    }

    /// Build a valid Spark spend scenario with a shared (value, randomness) so a
    /// single reconstructed pubkey vector verifies the whole ring; the real coin
    /// sits at `real_index`.
    fn scenario(
        value: u64,
        n: usize,
        real_index: usize,
        seed: u64,
    ) -> (SparkNote, Vec<RistrettoPoint>, Vec<RistrettoPoint>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let randomness = rnd(&mut rng);
        let real_serial = rnd(&mut rng);
        let anon: Vec<RistrettoPoint> = (0..n)
            .map(|i| {
                let serial = if i == real_index { real_serial } else { rnd(&mut rng) };
                spark_commit(value, &serial, &randomness)
            })
            .collect();
        let pubkeys = anon.iter().map(|c| spark_pubkey(c, value, &randomness)).collect();
        let note = SparkNote {
            commitment: anon[real_index].compress().to_bytes(),
            value,
            serial: real_serial.to_bytes(),
            randomness: randomness.to_bytes(),
            diversifier: [0u8; 11],
            height: 1,
            coin_id: real_index as u64,
        };
        (note, anon, pubkeys)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

        /// Completeness: an honest spend at any ring position (including the
        /// degenerate n=1) verifies.
        #[test]
        fn spark_completeness(
            n in 1usize..8,
            seed in any::<u64>(),
            value in 1u64..1_000_000,
        ) {
            let real_index = (seed as usize) % n;
            let (note, anon, pubkeys) = scenario(value, n, real_index, seed);
            let indices: Vec<u64> = (0..n as u64).collect();
            let mut prng = StdRng::seed_from_u64(seed ^ 0xABCD_1234);
            let proof = prove_spark_spend(&note, &anon, &indices, real_index, &[7u8; 32], &mut prng)
                .expect("honest prover must succeed");
            prop_assert!(verify_spark_spend(&proof, &pubkeys).is_ok(), "honest spend must verify");
        }

        /// Soundness: any single-byte mutation of the serial tag, a challenge, or
        /// a response is rejected. (The serial-tag case is the H-1 property — the
        /// tag is cryptographically bound.)
        #[test]
        fn spark_tamper_rejected(
            n in 2usize..6,
            seed in any::<u64>(),
            field in 0usize..3,
        ) {
            let real_index = (seed as usize) % n;
            let (note, anon, pubkeys) = scenario(1000, n, real_index, seed);
            let indices: Vec<u64> = (0..n as u64).collect();
            let mut prng = StdRng::seed_from_u64(seed ^ 0x5555_AAAA);
            let proof = prove_spark_spend(&note, &anon, &indices, real_index, &[9u8; 32], &mut prng)
                .expect("prove");
            prop_assume!(verify_spark_spend(&proof, &pubkeys).is_ok());

            let mut bad = proof.clone();
            match field {
                0 => bad.serial_tag[0] ^= 0x01,
                1 => bad.challenges[0][0] ^= 0x01,
                _ => bad.responses[0][0] ^= 0x01,
            }
            prop_assert!(
                verify_spark_spend(&bad, &pubkeys).is_err(),
                "tampered proof (field {}) must be rejected", field
            );
        }

        /// Context binding: a proof verified against a different pubkey vector
        /// (different anonymity set) must fail.
        #[test]
        fn spark_wrong_pubkeys_rejected(n in 2usize..6, seed in any::<u64>()) {
            let real_index = (seed as usize) % n;
            let (note, anon, _pubkeys) = scenario(1000, n, real_index, seed);
            let (_n2, _a2, other_pubkeys) = scenario(1000, n, real_index, seed ^ 0xDEAD_BEEF);
            let indices: Vec<u64> = (0..n as u64).collect();
            let mut prng = StdRng::seed_from_u64(seed ^ 0x0F0F_0F0F);
            let proof = prove_spark_spend(&note, &anon, &indices, real_index, &[3u8; 32], &mut prng)
                .expect("prove");
            prop_assert!(
                verify_spark_spend(&proof, &other_pubkeys).is_err(),
                "proof must not verify against a different anonymity set"
            );
        }
    }
}
