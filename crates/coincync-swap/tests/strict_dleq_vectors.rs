//! External test-vectors for the strict-binding cross-curve DLEQ
//! (Noether 2018) implementation.
//!
//! ## What this file does
//!
//! Two complementary purposes:
//!
//! 1. **Golden-file regression test** (always-on): asserts that the
//!    checked-in [`STRICT_DLEQ_VECTORS_PATH`] file matches what the
//!    current code derives from the same `(secret, seed)` inputs.
//!    Any drift in the strict-DLEQ wire format will fail this test
//!    so it can't slip through unnoticed.
//!
//! 2. **External-vector authoring** for the audit: the JSON file is
//!    a portable artifact any independent re-implementation can use
//!    to validate byte-for-byte interoperability. Each vector
//!    captures: the input `secret` + `seed`, the derived adaptor
//!    points `T_btc` + `T_cync`, the full 129-byte fast-floor proof
//!    in hex, and the SHA-256 of the ~81 KB strict proof. An
//!    independent implementation seeded identically should produce
//!    identical bytes; the SHA-256 lets them check that without
//!    inlining 81 KB into JSON.
//!
//! ## Re-baselining when an intentional wire-format change lands
//!
//! Delete the JSON file + re-run the test. The
//! `vectors_match_checked_in_file` test enters its "no file present
//! → generate it" branch, writes a fresh one, and (because the file
//! now exists) passes. Inspect the diff, commit if intentional.
//!
//! Audit signal: a non-intentional diff on this file is exactly the
//! kind of regression the audit firm wants to catch via CI.
//!
//! This module is **only compiled when `strict-dleq` is enabled** —
//! the test depends on `prove_cross_curve_strict` which is itself
//! feature-gated.

#![cfg(feature = "strict-dleq")]

use coincync_swap::adaptor::{prove_cross_curve, AdaptorSecret, CrossCurveDlProof};
use coincync_swap::strict_dleq::{prove_cross_curve_strict, CrossCurveDlProofStrict};

use std::path::PathBuf;

/// Path to the checked-in vectors file, relative to the crate root.
/// Kept inside the crate's `test-vectors/` subdirectory so the
/// artifact ships alongside the source it validates.
const STRICT_DLEQ_VECTORS_PATH: &str = "test-vectors/strict-dleq-vectors.json";

/// One audit-target vector. All fields are derivable from `secret_le_hex`
/// and `seed_hex`; the rest are checked-in expected outputs so an
/// independent implementation can verify byte-equality without
/// re-running the prover.
#[derive(Debug)]
struct Vector {
    /// Human-readable label, e.g. `"small-secret-66"`.
    name: &'static str,
    /// Secret scalar in Ristretto-LE byte form, 32 bytes hex.
    secret_le_hex: &'static str,
    /// Master seed for the strict-DLEQ PRF, 32 bytes hex.
    seed_hex: &'static str,
}

/// The set of vectors we publish. Three vectors covers the
/// interesting cases: tiny secret (bit 0 only), middle-of-range,
/// and a boundary case with the high allowed bit set.
const VECTORS: &[Vector] = &[
    Vector {
        name: "small-secret-66",
        // Ristretto-LE 0x42 in byte 0 (= 66 = 0b01000010, 7 bits set).
        secret_le_hex: "4200000000000000000000000000000000000000000000000000000000000000",
        // Distinct from any other test seed, repeatable.
        seed_hex: "7777777777777777777777777777777777777777777777777777777777777777",
    },
    Vector {
        name: "middle-range-2pow128-plus-1",
        // 2^128 + 1 in Ristretto-LE: bit 0 + bit 128 set.
        secret_le_hex: "0100000000000000000000000000000001000000000000000000000000000000",
        seed_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    Vector {
        name: "near-bit-251-boundary",
        // Bit 251 set (high bit allowed by STRICT_BIT_COUNT=252) plus bit 0.
        // Byte 31 = 0x08 (bit 251 = bit (8*31+3) → bit 3 of byte 31).
        secret_le_hex: "0100000000000000000000000000000000000000000000000000000000000008",
        seed_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
];

/// Build the JSON body for one vector by re-deriving everything from
/// the inputs.
fn derive_vector_json(v: &Vector) -> String {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let secret_le = decode_hex_32(v.secret_le_hex);
    let secret = AdaptorSecret::from_ristretto_bytes(secret_le)
        .expect("vector secret must be canonical Ristretto");
    let seed = decode_hex_32(v.seed_hex);

    // T_btc = secret · G_btc
    let secp = Secp256k1::new();
    let t_btc_pk = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&secret.secp256k1_bytes()).unwrap(),
    );
    let t_btc = t_btc_pk.serialize();

    // T_cync = secret · G_cync
    let s = Scalar::from_canonical_bytes(secret.ristretto_bytes()).unwrap();
    let t_cync = (&s * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();

    // Fast-floor proof. We use the SAME nonce-derivation discipline
    // strict's `prove_cross_curve_strict` does internally so the
    // external vector + the strict-proof internal-fast-floor are
    // byte-identical when re-derived independently. The PRF tag is
    // crate-private though, so for the external vector we just use
    // the seed bytes as the nonce — documented as the "stable
    // external derivation" rule. The strict variant's internal fast
    // floor uses a different PRF tag and is asserted separately
    // below via the SHA-256.
    let fast_nonce = derive_fast_nonce_external(&seed);
    let fast =
        prove_cross_curve(&secret, &t_btc, &t_cync, &fast_nonce).expect("vector fast-floor prove");
    let fast_bytes = fast.canonical_bytes();

    // Strict proof — derived from the same `seed` the production
    // entrypoint uses internally.
    let strict =
        prove_cross_curve_strict(&secret, &t_btc, &t_cync, &seed).expect("vector strict prove");
    let strict_sha256 = strict.canonical_sha256();

    // Stable JSON layout. Hand-formatted (rather than serde) so the
    // file diff stays readable — extra fields can be added without
    // a serde-derive cascade.
    format!(
        r#"  {{
    "name": "{}",
    "secret_le_hex": "{}",
    "seed_hex": "{}",
    "t_btc_hex": "{}",
    "t_cync_hex": "{}",
    "fast_proof_canonical_hex": "{}",
    "strict_proof_canonical_sha256_hex": "{}",
    "strict_proof_canonical_len_bytes": {}
  }}"#,
        v.name,
        v.secret_le_hex,
        v.seed_hex,
        hex::encode(t_btc),
        hex::encode(t_cync),
        hex::encode(fast_bytes),
        hex::encode(strict_sha256),
        CrossCurveDlProofStrict::CANONICAL_LEN,
    )
}

/// External-vector nonce derivation: SHA-256 of `b"external-fast-nonce-v1" ‖ seed`,
/// reduced via `Scalar::from_bytes_mod_order_wide` on a 64-byte
/// expansion (always canonical on Ristretto). Distinct from the
/// strict prover's internal `b"fast_nonce"` derivation so the two
/// don't collide at the byte level.
fn derive_fast_nonce_external(seed: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha256};
    let mut h1 = Sha256::new();
    h1.update(b"external-fast-nonce-v1");
    h1.update(b"expand-1");
    h1.update(seed);
    let mut h2 = Sha256::new();
    h2.update(b"external-fast-nonce-v1");
    h2.update(b"expand-2");
    h2.update(seed);
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&h1.finalize());
    wide[32..].copy_from_slice(&h2.finalize());
    Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    let v = hex::decode(hex).expect("hex");
    v.try_into().expect("32 bytes")
}

/// Build the entire vectors JSON file body.
fn build_vectors_json() -> String {
    let bodies: Vec<String> = VECTORS.iter().map(derive_vector_json).collect();
    format!(
        r#"{{
  "_comment": "Strict-binding cross-curve DLEQ test vectors (Noether 2018). Re-derived from (secret_le_hex, seed_hex) under the same PRF construction the prover uses internally. The strict-proof body is too large to inline (~81 KB) — verifiers should hash their own output via CrossCurveDlProofStrict::canonical_sha256() and byte-compare against the published SHA-256. Format version: 1.",
  "format_version": 1,
  "vectors": [
{}
  ]
}}
"#,
        bodies.join(",\n")
    )
}

/// Helper: compute the absolute path to the vectors file. The test
/// runs from the crate root, so we resolve relative to `CARGO_MANIFEST_DIR`.
fn vectors_path() -> PathBuf {
    let crate_root =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set by cargo test");
    PathBuf::from(crate_root).join(STRICT_DLEQ_VECTORS_PATH)
}

/// Golden-file test: either generate the vectors file on first run
/// (and pass — the operator commits the new file) or assert
/// byte-equality with the checked-in version.
///
/// This is the load-bearing test for the external-vector audit
/// deliverable: a change in the strict-DLEQ wire format MUST fail
/// this test, forcing an explicit re-baseline review.
#[test]
fn vectors_match_checked_in_file() {
    let path = vectors_path();
    let derived = build_vectors_json();

    if !path.exists() {
        // First-run / re-baseline path. Create the parent dir,
        // write the file, pass — the operator commits it.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create test-vectors dir");
        }
        std::fs::write(&path, &derived).expect("write vectors file");
        eprintln!(
            "wrote initial vectors file to {} ({} bytes)",
            path.display(),
            derived.len()
        );
        // Don't fail — the next run will exercise the byte-compare
        // branch. The operator commits this file as the baseline.
        return;
    }

    let on_disk = std::fs::read_to_string(&path).expect("read vectors file");
    assert_eq!(
        on_disk,
        derived,
        "checked-in {} drifted from re-derived output. Either the strict-DLEQ wire format changed (intentional — re-baseline by deleting the file + re-running this test + committing the new file) or a regression slipped through. Diff before committing.",
        STRICT_DLEQ_VECTORS_PATH
    );
}

/// Sanity check: each vector's strict proof must verify against the
/// derived adaptor points. Catches a class of accidents where
/// the vectors are internally consistent (re-derivation matches
/// itself) but actually broken (the proof doesn't verify).
#[test]
fn each_vector_round_trips() {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use coincync_swap::strict_dleq::verify_cross_curve_strict;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let secp = Secp256k1::new();
    for v in VECTORS {
        let secret_le = decode_hex_32(v.secret_le_hex);
        let secret = AdaptorSecret::from_ristretto_bytes(secret_le).unwrap();
        let seed = decode_hex_32(v.seed_hex);

        let t_btc_pk = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secret.secp256k1_bytes()).unwrap(),
        );
        let t_btc = t_btc_pk.serialize();
        let s = Scalar::from_canonical_bytes(secret.ristretto_bytes()).unwrap();
        let t_cync = (&s * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();

        let strict = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &seed).unwrap();
        verify_cross_curve_strict(&strict, &t_btc, &t_cync)
            .unwrap_or_else(|e| panic!("vector {} fails verify: {:?}", v.name, e));

        // Canonical-len invariant.
        assert_eq!(
            strict.canonical_bytes().len(),
            CrossCurveDlProofStrict::CANONICAL_LEN
        );
    }
}

/// Sanity check: canonical_bytes is stable across calls.
#[test]
fn canonical_bytes_is_deterministic() {
    let v = &VECTORS[0];
    let secret = AdaptorSecret::from_ristretto_bytes(decode_hex_32(v.secret_le_hex)).unwrap();
    let seed = decode_hex_32(v.seed_hex);

    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let secp = Secp256k1::new();
    let t_btc = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&secret.secp256k1_bytes()).unwrap(),
    )
    .serialize();
    let s = Scalar::from_canonical_bytes(secret.ristretto_bytes()).unwrap();
    let t_cync = (&s * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();

    let p1 = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &seed).unwrap();
    let p2 = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &seed).unwrap();
    assert_eq!(p1.canonical_bytes(), p2.canonical_bytes());
    assert_eq!(p1.canonical_sha256(), p2.canonical_sha256());
}

/// Quick fast-floor canonical round-trip (no I/O — keeps the
/// production fast-prove path under the same lens as strict).
#[test]
fn fast_proof_canonical_round_trip() {
    let v = &VECTORS[0];
    let secret = AdaptorSecret::from_ristretto_bytes(decode_hex_32(v.secret_le_hex)).unwrap();
    let seed = decode_hex_32(v.seed_hex);

    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let secp = Secp256k1::new();
    let t_btc = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&secret.secp256k1_bytes()).unwrap(),
    )
    .serialize();
    let s = Scalar::from_canonical_bytes(secret.ristretto_bytes()).unwrap();
    let t_cync = (&s * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();

    let nonce = derive_fast_nonce_external(&seed);
    let p = prove_cross_curve(&secret, &t_btc, &t_cync, &nonce).unwrap();
    let bytes = p.canonical_bytes();
    assert_eq!(bytes.len(), CrossCurveDlProof::CANONICAL_LEN);
    assert_eq!(bytes[..33], p.a_btc);
    assert_eq!(bytes[33..65], p.a_cync);
    assert_eq!(bytes[65..97], p.s_btc);
    assert_eq!(bytes[97..129], p.s_cync);
}
