//! Zcash NU5 Orchard conformance test suite.
//!
//! Asserts byte-for-byte equality between every non-circuit primitive
//! shipped in `crates/orchard-side/` and the Zcash-canonical reference
//! values in [`zcash_test_vectors_keys_upstream`] (vendored from the
//! reference `orchard` 0.12 crate's `src/test_vectors/keys.rs`).
//!
//! **Why this test suite exists.** Orchard is consensus-critical
//! cryptography. A subtle byte-mismatch in any of the primitives —
//! the spending-key hierarchy, IVK derivation, address derivation,
//! note commitment, or nullifier — produces a chain that diverges
//! from Zcash NU5 at the very first shielded transaction. Worse, the
//! divergence is silent: our prover + our verifier might agree with
//! each other (so all our other tests pass) while disagreeing with
//! every other Orchard implementation on the planet. The only way
//! to catch this class of bug is to validate against an **independent
//! oracle** — the 11 Zcash-canonical key-component vectors.
//!
//! **Coverage:** 11 vectors × 7 byte-equality checks per vector =
//! **77 assertions** spanning every non-circuit primitive:
//! `ak`, `nk`, `rivk`, `ovk`, `ivk`, `default_pk_d`, `note_cmx`,
//! `note_nf`. (The vendored vectors also carry `ask`, `dk`, internal-
//! scope variants, and a few other fields our current API doesn't
//! expose as public outputs — those are noted in `#6` below.)
//!
//! **What this DOES NOT cover.** Strict subset:
//! - `ask` (we don't expose it as a public field; it's derived
//!   inside `full_viewing_key()` to produce `ak`).
//! - `dk` (we don't derive it; our `address_at` takes a `d`
//!   directly. See note (6) below.)
//! - Internal-scope keys (`internal_rivk`, etc.) — we don't yet
//!   ship internal-scope derivation. Adding it would be a forward-
//!   compat extension; current API only exposes external scope.
//!
//! Each missing check is flagged in code so the audit team can see
//! exactly where we don't yet validate against the oracle.

mod zcash_test_vectors_keys_upstream;
use zcash_test_vectors_keys_upstream::test_vectors;

use orchard_side::commitment::NoteCommitment;
use orchard_side::note::Note;
use orchard_side::nullifier::{derive_nullifier, NullifierDerivingKey};
use orchard_side::spend_key::SpendingKey;

/// Lift each test vector through `SpendingKey::full_viewing_key()`
/// and assert that the resulting `ak`, `nk`, `rivk`, `ovk` bytes
/// match the Zcash-canonical reference.
#[test]
fn spending_key_full_viewing_key_matches_zcash_nu5() {
    for (i, v) in test_vectors().iter().enumerate() {
        let sk = SpendingKey::from_bytes(v.sk)
            .unwrap_or_else(|e| panic!("vector {i}: SpendingKey::from_bytes: {e:?}"));
        let fvk = sk
            .full_viewing_key()
            .unwrap_or_else(|e| panic!("vector {i}: full_viewing_key: {e:?}"));

        assert_eq!(
            fvk.ak,
            v.ak,
            "vector {i}: ak mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.ak),
            hex::encode(fvk.ak)
        );
        assert_eq!(
            fvk.nk,
            v.nk,
            "vector {i}: nk mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.nk),
            hex::encode(fvk.nk)
        );
        assert_eq!(
            fvk.rivk,
            v.rivk,
            "vector {i}: rivk mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.rivk),
            hex::encode(fvk.rivk)
        );
        assert_eq!(
            fvk.ovk,
            v.ovk,
            "vector {i}: ovk mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.ovk),
            hex::encode(fvk.ovk)
        );
    }
}

/// `FullViewingKey::to_ivk()` produces the canonical 32-byte IVK.
/// Orchard's `IncomingViewingKey` is 64 bytes (`dk || ivk`); our
/// `IncomingViewingKey` is just the 32-byte `ivk` portion. The
/// Zcash NU5 reference `ivk` field is the 32-byte ivk only — so
/// these compare directly.
#[test]
fn full_viewing_key_to_ivk_matches_zcash_nu5() {
    for (i, v) in test_vectors().iter().enumerate() {
        let sk = SpendingKey::from_bytes(v.sk).unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        let ivk = fvk
            .to_ivk()
            .unwrap_or_else(|e| panic!("vector {i}: to_ivk: {e:?}"));

        let ivk_bytes = ivk.as_bytes();
        assert_eq!(
            ivk_bytes,
            &v.ivk,
            "vector {i}: ivk mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.ivk),
            hex::encode(ivk_bytes)
        );
    }
}

/// `IncomingViewingKey::address_at(default_d)` produces a `pk_d`
/// that byte-matches the Zcash-canonical `default_pk_d`. The
/// `default_d` from the vector was derived in orchard via
/// `DiversifierKey::diversifier(0)` (FF1-AES on index 0); we
/// don't currently expose `dk` so we re-use the canonical `d`
/// directly. The `pk_d` comparison validates our `DiversifyHash`
/// (Sinsemilla on the `"z.cash:Orchard-gd"` domain) + `ivk * gd`
/// scalar multiplication.
#[test]
fn address_at_default_d_matches_zcash_nu5() {
    for (i, v) in test_vectors().iter().enumerate() {
        let sk = SpendingKey::from_bytes(v.sk).unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        let ivk = fvk.to_ivk().unwrap();

        let (_gd_bytes, pk_d_bytes) = ivk
            .address_at(v.default_d)
            .unwrap_or_else(|e| panic!("vector {i}: address_at: {e:?}"));

        assert_eq!(
            pk_d_bytes,
            v.default_pk_d,
            "vector {i}: default_pk_d mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.default_pk_d),
            hex::encode(pk_d_bytes)
        );
    }
}

/// `NoteCommitment::derive(note)` produces a `cmx` (extracted
/// x-coordinate) that byte-matches the Zcash-canonical `note_cmx`.
/// This validates the entire commitment pipeline: Sinsemilla
/// `CommitDomain::commit` on the `"z.cash:Orchard-NoteCommit"`
/// domain + the 255-bit LE encoding of every field + the `psi`
/// + `rcm` PRF_expand derivations from `rseed`.
#[test]
fn note_commitment_matches_zcash_nu5() {
    for (i, v) in test_vectors().iter().enumerate() {
        let sk = SpendingKey::from_bytes(v.sk).unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        let ivk = fvk.to_ivk().unwrap();
        let (gd_bytes, pk_d_bytes) = ivk.address_at(v.default_d).unwrap();

        // Bypass `Note::new`'s `BridgeValue::MAX_MONEY` cap — the
        // Zcash NU5 vectors use unbounded u64 values that exceed
        // CoinCync's 2.1e15 supply ceiling. We're validating the
        // commitment/nullifier *math* here, not our chain's value
        // policy. Direct struct-literal construction bypasses the
        // constructor while exercising the exact same commitment +
        // nullifier code paths a production Note would.
        let note = Note {
            recipient_d: gd_bytes,
            recipient_pkd: pk_d_bytes,
            value: v.note_v,
            rho: v.note_rho,
            rseed: v.note_rseed,
        };

        let cmx = NoteCommitment::derive(&note)
            .unwrap_or_else(|e| panic!("vector {i}: NoteCommitment::derive: {e:?}"));
        let cmx_bytes = cmx.to_bytes();

        assert_eq!(
            cmx_bytes,
            v.note_cmx,
            "vector {i}: note_cmx mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.note_cmx),
            hex::encode(cmx_bytes)
        );
    }
}

/// `derive_nullifier(note, nk)` produces a nullifier that
/// byte-matches the Zcash-canonical `note_nf`. This validates:
/// Poseidon P128Pow5T3 `PRF_nf^{nk}(ρ)`, the addition with `psi`,
/// the scalar-multiplication by `K^Orchard`, the point-addition
/// with the commitment point, and the final `Extract_P` (x-only
/// projection).
#[test]
fn nullifier_matches_zcash_nu5() {
    for (i, v) in test_vectors().iter().enumerate() {
        let sk = SpendingKey::from_bytes(v.sk).unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        let ivk = fvk.to_ivk().unwrap();
        let (gd_bytes, pk_d_bytes) = ivk.address_at(v.default_d).unwrap();

        // Bypass `Note::new`'s `BridgeValue::MAX_MONEY` cap — the
        // Zcash NU5 vectors use unbounded u64 values that exceed
        // CoinCync's 2.1e15 supply ceiling. We're validating the
        // commitment/nullifier *math* here, not our chain's value
        // policy. Direct struct-literal construction bypasses the
        // constructor while exercising the exact same commitment +
        // nullifier code paths a production Note would.
        let note = Note {
            recipient_d: gd_bytes,
            recipient_pkd: pk_d_bytes,
            value: v.note_v,
            rho: v.note_rho,
            rseed: v.note_rseed,
        };

        let nk = NullifierDerivingKey::from_bytes(fvk.nk)
            .unwrap_or_else(|e| panic!("vector {i}: NullifierDerivingKey::from_bytes: {e:?}"));
        let nf = derive_nullifier(&note, &nk)
            .unwrap_or_else(|e| panic!("vector {i}: derive_nullifier: {e:?}"));
        let nf_bytes = nf.0.to_bytes();

        assert_eq!(
            nf_bytes,
            v.note_nf,
            "vector {i}: note_nf mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.note_nf),
            hex::encode(nf_bytes)
        );
    }
}

/// Meta-check: there must be at least one vector loaded — guards
/// against a parsing error silently rendering every other test
/// a no-op pass.
#[test]
fn at_least_one_vector_loaded() {
    let v = test_vectors();
    assert!(
        !v.is_empty(),
        "no vectors loaded — check zcash_test_vectors_keys_upstream.rs parse"
    );
    assert!(
        v.len() >= 10,
        "expected ≥ 10 vendored Zcash NU5 vectors, got {}",
        v.len()
    );
}

/// `ask` (spend authorizing key, the scalar that signs spend-auth
/// signatures) is derived inside `full_viewing_key()` as
/// `ToScalar(PRF_expand(sk, [0x06]))`. Validate against the
/// Zcash-canonical bytes.
#[test]
fn ask_matches_zcash_nu5() {
    for (i, v) in test_vectors().iter().enumerate() {
        let sk = SpendingKey::from_bytes(v.sk).unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        // Use the doc-hidden test accessor.
        let ask_bytes = sk._test_only_ask_bytes();
        let _ = fvk;
        assert_eq!(
            ask_bytes,
            v.ask,
            "vector {i}: ask mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.ask),
            hex::encode(ask_bytes)
        );
    }
}

/// `dk` (diversifier key) is the first 32 bytes of the same
/// Blake2b output that produces `ovk` (NU5 §5.4.1.6). Free
/// additional coverage on the same code path the OVK fix touched.
#[test]
fn dk_matches_zcash_nu5() {
    for (i, v) in test_vectors().iter().enumerate() {
        let sk = SpendingKey::from_bytes(v.sk).unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        assert_eq!(
            fvk.dk,
            v.dk,
            "vector {i}: dk mismatch — Zcash NU5 reference produces {} but we got {}",
            hex::encode(v.dk),
            hex::encode(fvk.dk)
        );
    }
}

// ─── Property-based tests (randomized; many iterations) ──────────────
//
// These don't use proptest (avoiding a new dep); they use the
// already-in-tree `rand_chacha` for deterministic randomness across
// runs so any failure is bisectable.

use orchard_side::value_commit::{TrapdoorRandomness, ValueCommitment};
use rand_chacha::rand_core::SeedableRng;

const PROPTEST_ITERATIONS: u32 = 50;

fn seeded_rng(seed: u8) -> rand_chacha::ChaCha20Rng {
    let mut s = [0u8; 32];
    s[0] = seed;
    rand_chacha::ChaCha20Rng::from_seed(s)
}

/// Helper: a canonical-Pallas-scalar `TrapdoorRandomness` derived
/// from RNG. We mask the high 2 bits to stay safely within the
/// Pallas scalar field order; rejection-sample on the off-chance
/// the result is zero (which `from_bytes` rejects).
fn random_trapdoor(rng: &mut rand_chacha::ChaCha20Rng) -> TrapdoorRandomness {
    use rand_chacha::rand_core::RngCore;
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes[31] &= 0x3F; // < 2^254 → comfortably canonical
        if let Ok(t) = TrapdoorRandomness::from_bytes(bytes) {
            return t;
        }
    }
}

/// Property: value commitments are additively homomorphic.
/// `commit(v1, r1) + commit(v2, r2) == commit(v1+v2, r3)` where
/// `r3 = r1 + r2`. This is the load-bearing property for the
/// binding signature + sum-of-Actions value conservation.
#[test]
fn property_value_commit_homomorphism() {
    use rand_chacha::rand_core::RngCore;

    let mut rng = seeded_rng(0xA1);
    for iter in 0..PROPTEST_ITERATIONS {
        // Small values keep the sum within u64 (Orchard handles
        // signed sums via ValueSum; we cover the basic case here).
        let v1 = (rng.next_u64() >> 32) & 0xFFFF;
        let v2 = (rng.next_u64() >> 32) & 0xFFFF;
        let r1 = random_trapdoor(&mut rng);
        let r2 = random_trapdoor(&mut rng);
        let r3 = r1.add(&r2);

        let c1 = ValueCommitment::commit(v1, &r1).unwrap();
        let c2 = ValueCommitment::commit(v2, &r2).unwrap();
        let c3 = ValueCommitment::commit(v1 + v2, &r3).unwrap();

        let sum = c1.add(&c2).unwrap();
        assert!(
            sum.point_eq(&c3),
            "iter {iter}: homomorphism broken: commit({v1},r1)+commit({v2},r2) ≠ commit({},r1+r2)",
            v1 + v2
        );
    }
}

/// Property: same `(value, rcv)` → same commitment bytes.
/// Determinism is load-bearing for chain-replay consistency.
#[test]
fn property_value_commit_determinism() {
    use rand_chacha::rand_core::RngCore;
    let mut rng = seeded_rng(0xA2);
    for iter in 0..PROPTEST_ITERATIONS {
        let v = rng.next_u64() & 0xFFFFFFFF;
        let r = random_trapdoor(&mut rng);
        let c1 = ValueCommitment::commit(v, &r).unwrap();
        let c2 = ValueCommitment::commit(v, &r).unwrap();
        assert_eq!(
            c1.to_bytes(),
            c2.to_bytes(),
            "iter {iter}: non-deterministic commit"
        );
    }
}

/// Property: different `rcv` → different commitment (even for
/// the same value). Catches the bug class "commitment accidentally
/// ignores the trapdoor input."
#[test]
fn property_value_commit_randomization() {
    use rand_chacha::rand_core::RngCore;
    let mut rng = seeded_rng(0xA3);
    for iter in 0..PROPTEST_ITERATIONS {
        let v = (rng.next_u64() >> 1) & 0x7FFFFFFF;
        let r1 = random_trapdoor(&mut rng);
        let r2 = random_trapdoor(&mut rng);
        let c1 = ValueCommitment::commit(v, &r1).unwrap();
        let c2 = ValueCommitment::commit(v, &r2).unwrap();
        assert_ne!(
            c1.to_bytes(),
            c2.to_bytes(),
            "iter {iter}: same value with different rcv produced same commitment — randomization broken"
        );
    }
}

/// Property: distinct `(nk, rho, rseed, recipient, value)` produce
/// distinct nullifiers. Tests the nullifier function's collision
/// resistance against random inputs.
#[test]
fn property_nullifier_uniqueness() {
    use orchard_side::nullifier::NullifierDerivingKey;
    use rand_chacha::rand_core::RngCore;
    use std::collections::HashSet;

    let mut rng = seeded_rng(0xA4);
    let mut seen = HashSet::new();
    // Use a single known canonical nk + a known recipient (pulled
    // from the first vector) so we exercise the nullifier under
    // random (rho, rseed) variation rather than synthesizing every
    // input from scratch.
    let v = &test_vectors()[0];
    let sk = SpendingKey::from_bytes(v.sk).unwrap();
    let fvk = sk.full_viewing_key().unwrap();
    let ivk = fvk.to_ivk().unwrap();
    let (gd, pkd) = ivk.address_at(v.default_d).unwrap();
    let nk = NullifierDerivingKey::from_bytes(fvk.nk).unwrap();

    for iter in 0..PROPTEST_ITERATIONS {
        // Random rho + rseed. Mask high bits to stay canonical
        // Pallas-base for rho (the nullifier requires this).
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut rho);
        rho[31] &= 0x3F; // clear top 2 bits to stay < q_P with comfortable margin
        let mut rseed = [0u8; 32];
        rng.fill_bytes(&mut rseed);
        if rseed == [0u8; 32] {
            rseed[0] = 1; // Note rejects zero
        }
        // Value tiny enough to skip the BridgeValue cap (we bypass
        // the constructor via direct struct literal anyway).
        let value = (rng.next_u64() & 0xFF).max(1);

        let note = Note {
            recipient_d: gd,
            recipient_pkd: pkd,
            value,
            rho,
            rseed,
        };

        if let Ok(nf) = orchard_side::nullifier::derive_nullifier(&note, &nk) {
            let nf_bytes = nf.0.to_bytes();
            assert!(
                seen.insert(nf_bytes),
                "iter {iter}: collision detected — same nullifier from different (rho, rseed)"
            );
        }
        // If derive_nullifier errored (non-canonical rho slipped
        // through the mask), skip — that's an input-validation
        // path, not a nullifier-correctness path.
    }
}

/// Property: PRF_expand is deterministic + tag-distinguishing.
/// Caught the bug class where a tag-byte-off-by-one would silently
/// produce different output but still pass other tests.
#[test]
fn property_prf_expand_tag_distinguishing() {
    let mut rng = seeded_rng(0xA5);
    use rand_chacha::rand_core::RngCore;
    use std::collections::HashSet;

    for iter in 0..PROPTEST_ITERATIONS {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        if sk == [0u8; 32] {
            sk[0] = 1;
        }
        let sk_obj = SpendingKey::from_bytes(sk).unwrap();
        let fvk = sk_obj.full_viewing_key().unwrap();

        // ak, nk, ovk, dk, rivk all come from different PRF tags +
        // formulas. They must all be pairwise distinct for any
        // sk. (Collision between, e.g., nk and ovk would mean two
        // tags collapsed.)
        let mut keys = HashSet::new();
        keys.insert(fvk.ak);
        keys.insert(fvk.nk);
        keys.insert(fvk.ovk);
        keys.insert(fvk.dk);
        keys.insert(fvk.rivk);
        assert_eq!(
            keys.len(),
            5,
            "iter {iter}: not all 5 FVK fields are distinct — PRF tag collision likely"
        );
    }
}

// ─── Boundary tests ─────────────────────────────────────────────────

/// Zero SK is rejected at construction.
#[test]
fn boundary_zero_sk_rejected() {
    assert!(SpendingKey::from_bytes([0u8; 32]).is_err());
}

/// Maximum-byte SK is accepted at construction (no spec rule against
/// it — the spec only rejects zero) but downstream validation must
/// still work.
#[test]
fn boundary_max_sk_derivation_works() {
    let sk = SpendingKey::from_bytes([0xFFu8; 32]).expect("max sk is non-zero");
    let fvk = sk.full_viewing_key().expect("max sk derives a valid FVK");
    // All five output bytes are non-zero (with vanishingly small
    // probability they accidentally are; this is a regression guard
    // for a "PRF returned zero" bug class).
    assert_ne!(fvk.ak, [0u8; 32], "ak should not be zero from max sk");
    assert_ne!(fvk.nk, [0u8; 32], "nk should not be zero from max sk");
    assert_ne!(fvk.ovk, [0u8; 32], "ovk should not be zero from max sk");
    assert_ne!(fvk.dk, [0u8; 32], "dk should not be zero from max sk");
    assert_ne!(fvk.rivk, [0u8; 32], "rivk should not be zero from max sk");
}

/// Non-canonical Pallas-base input is rejected by
/// NullifierDerivingKey::from_bytes. Catches the class of bug
/// where a `from_repr` failure path is silently treated as canonical.
#[test]
fn boundary_non_canonical_nk_rejected() {
    use orchard_side::nullifier::NullifierDerivingKey;
    // Pallas base prime q_P has high byte 0x40 (= 2^254). Setting
    // byte 31 to 0xFF makes the value > q_P → non-canonical.
    let mut bad = [0xFFu8; 32];
    bad[31] = 0xFF; // top byte set → exceeds q_P
    let r = NullifierDerivingKey::from_bytes(bad);
    assert!(
        r.is_err(),
        "non-canonical Pallas-base nk should be rejected, was accepted: {:?}",
        r.map(|_| "()")
    );
}

/// Empty diversifier (all zero bytes) is a valid input — orchard
/// uses substitute-with-hash(&[]) when the resulting gd is the
/// identity, but the input itself isn't rejected. Verify our
/// address_at handles this without panicking.
#[test]
fn boundary_zero_diversifier_does_not_panic() {
    let v = &test_vectors()[0];
    let sk = SpendingKey::from_bytes(v.sk).unwrap();
    let fvk = sk.full_viewing_key().unwrap();
    let ivk = fvk.to_ivk().unwrap();
    // Should produce some valid (gd, pkd) tuple — the spec's
    // identity-substitution fallback covers the edge case.
    let r = ivk.address_at([0u8; 11]);
    assert!(
        r.is_ok(),
        "zero diversifier should resolve via substitution, got: {r:?}"
    );
}
