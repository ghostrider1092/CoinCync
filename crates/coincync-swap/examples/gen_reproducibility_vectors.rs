//! Emit deterministic reproducibility test vectors.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p coincync-swap --example gen_reproducibility_vectors
//! ```
//!
//! This iterates a fixed table of test inputs (signer key, adaptor
//! secret, message, aux randomness), runs each one through the
//! adapter-sig + DLEQ primitives in `coincync_swap::adaptor`, and
//! writes one JSON file per vector to
//! `test-vectors/reproducibility/`.
//!
//! These vectors are NOT independently-derived — they record what our
//! current implementation produces. Their value is regression
//! protection: any change to the primitives that alters output bytes
//! fails the harness in `tests/external_vectors.rs` on the next CI
//! run. See `test-vectors/reproducibility/README.md`.

use std::fs;
use std::path::PathBuf;

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::json;

use coincync_swap::adaptor::{
    cync_adaptor_point, cync_create_pre_sig, cync_decrypt_adaptor, cync_recover_secret,
    create_pre_sig_bip340, decrypt_btc_adaptor, prove_cross_curve, recover_secret_from_btc_sig,
    verify_cross_curve_proof, verify_pre_sig, AdaptorSecret,
};

/// Table of deterministic test inputs. Each row produces a complete
/// set of vectors (BTC adaptor + CYNC adaptor + DLEQ) for one swap.
///
/// **Important constraint:** the `adaptor_secret` and `dleq_nonce_k`
/// fields MUST be Ristretto-canonical (scalar < ℓ ≈ 2^252.39). Bytes
/// in little-endian whose top byte (byte 31) is ≥ 0x10 land near or
/// above ℓ and are rejected. Therefore the patterns below keep the
/// top byte of those fields ≤ 0x0f. The `signer_seckey`, `message`,
/// and `aux_rand` fields have no such constraint (signer_seckey needs
/// secp256k1 validity only; the others are opaque bytes).
const TEST_CASES: &[(&str, [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])] = &[
    //  vector_id           signer_seckey      adaptor_secret(*)  message             aux_rand           dleq_nonce_k(*)
    //  (*) = top byte must be ≤ 0x0f for Ristretto-canonical
    ("vec-001-canonical",   [0x01; 32],        [0x02; 32],        [0x03; 32],         [0x04; 32],        [0x05; 32]),
    ("vec-002-low-scalars", [0x11; 32],        [0x01; 32],        [0x13; 32],         [0x14; 32],        [0x07; 32]),
    ("vec-003-mid-scalars", [0x42; 32],        [0x08; 32],        [0x44; 32],         [0x45; 32],        [0x09; 32]),
    ("vec-004-alt-msg",     [0x01; 32],        [0x02; 32],        [0xff; 32],         [0x04; 32],        [0x05; 32]),
    ("vec-005-alt-aux",     [0x01; 32],        [0x02; 32],        [0x03; 32],         [0xa0; 32],        [0x05; 32]),
];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Compute the output dir relative to the crate root.
/// `CARGO_MANIFEST_DIR` points at `crates/coincync-swap/`.
fn out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join("reproducibility")
}

fn emit_btc_adaptor(
    vec_id: &str,
    signer_sk_bytes: &[u8; 32],
    secret_bytes: &[u8; 32],
    msg: &[u8; 32],
    aux_rand: &[u8; 32],
) {
    let secp = Secp256k1::new();
    let signer_sk = SecretKey::from_slice(signer_sk_bytes).expect("test signer_sk must be valid");
    let secret = AdaptorSecret::from_ristretto_bytes(*secret_bytes)
        .expect("test secret must be Ristretto-canonical");
    let t_sk = SecretKey::from_slice(&secret.secp256k1_bytes()).unwrap();
    let t_pub = PublicKey::from_secret_key(&secp, &t_sk);

    let Ok((adaptor_sig, signer_x)) =
        create_pre_sig_bip340(&signer_sk, msg, &t_pub, aux_rand)
    else {
        eprintln!("vec {}: create_pre_sig_bip340 failed (8 retries all odd-y); skipping", vec_id);
        return;
    };

    // Re-verify, decrypt, recover — record all artifacts.
    verify_pre_sig(&adaptor_sig, &signer_x, &t_pub, msg).expect("pre-sig must verify");
    let final_sig = decrypt_btc_adaptor(&adaptor_sig, &secret, &t_pub).expect("decrypt");
    let recovered = recover_secret_from_btc_sig(&adaptor_sig, &final_sig).expect("recover");
    assert_eq!(&recovered, &secret, "roundtrip must hold");

    // Serialize R-point as 33-byte compressed for the vector record.
    let r_point_compressed = adaptor_sig.r_point.serialize();

    let vec_json = json!({
        "primitive": "btc-adaptor",
        "operation": "create_then_recover_secret",
        "source_file": "crates/coincync-swap/src/adaptor.rs",
        "source_test": "examples/gen_reproducibility_vectors.rs",
        "inputs": {
            "signer_seckey_secp256k1": hex(signer_sk_bytes),
            "adaptor_secret_ristretto": hex(secret_bytes),
            "message_hash": hex(msg),
            "aux_rand": hex(aux_rand),
        },
        "expected": {
            "adaptor_r_point_compressed": hex(&r_point_compressed),
            "adaptor_s_pre": hex(&adaptor_sig.s_pre),
            "signer_x_only_pubkey": hex(&signer_x.serialize()),
            "adaptor_pubkey_t_secp": hex(&t_pub.serialize()),
            "final_sig_64": hex(&final_sig),
            "recovered_secret_secp": hex(&recovered.secp256k1_bytes()),
        },
        "notes": "Self-generated regression vector. Locks the output bytes of create_pre_sig_bip340 + decrypt_btc_adaptor + recover_secret_from_btc_sig for fixed inputs. Any change in the impl that alters these output bytes fails the harness."
    });

    let path = out_dir().join("btc-adaptor").join(format!("{}.json", vec_id));
    fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
    fs::write(&path, serde_json::to_string_pretty(&vec_json).unwrap()).expect("write");
    println!("emitted {}", path.display());
}

fn emit_cync_adaptor(
    vec_id: &str,
    signer_sk_bytes: &[u8; 32],
    secret_bytes: &[u8; 32],
    msg: &[u8; 32],
    nonce_bytes: &[u8; 32],
) {
    let secret = AdaptorSecret::from_ristretto_bytes(*secret_bytes)
        .expect("Ristretto-canonical");
    let t_point = cync_adaptor_point(&secret).expect("adaptor point");

    let Ok((adaptor_sig, signer_pub)) =
        cync_create_pre_sig(signer_sk_bytes, msg, &t_point, nonce_bytes)
    else {
        eprintln!("vec {}: cync_create_pre_sig failed (non-canonical input?); skipping", vec_id);
        return;
    };

    let final_sig = cync_decrypt_adaptor(&adaptor_sig, &secret, &t_point).expect("decrypt");
    let recovered = cync_recover_secret(&adaptor_sig, &final_sig).expect("recover");
    assert_eq!(&recovered, &secret, "roundtrip must hold");

    let vec_json = json!({
        "primitive": "ristretto-adaptor",
        "operation": "create_then_recover_secret",
        "source_file": "crates/coincync-swap/src/adaptor.rs",
        "source_test": "examples/gen_reproducibility_vectors.rs",
        "inputs": {
            "signer_seckey_ristretto": hex(signer_sk_bytes),
            "adaptor_secret_ristretto": hex(secret_bytes),
            "message_hash": hex(msg),
            "nonce": hex(nonce_bytes),
        },
        "expected": {
            "adaptor_r_point_ristretto": hex(&adaptor_sig.r_point),
            "adaptor_s_pre": hex(&adaptor_sig.s_pre),
            "signer_pub_ristretto": hex(&signer_pub),
            "adaptor_pubkey_t_ristretto": hex(&t_point),
            "final_sig_64": hex(&final_sig),
            "recovered_secret_ristretto": hex(&recovered.ristretto_bytes()),
        },
        "notes": "Self-generated regression vector. Same shape as btc-adaptor on the Ristretto255 side."
    });

    let path = out_dir().join("ristretto-adaptor").join(format!("{}.json", vec_id));
    fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
    fs::write(&path, serde_json::to_string_pretty(&vec_json).unwrap()).expect("write");
    println!("emitted {}", path.display());
}

fn emit_dleq(vec_id: &str, secret_bytes: &[u8; 32], nonce_k_bytes: &[u8; 32]) {
    let secp = Secp256k1::new();
    let secret = AdaptorSecret::from_ristretto_bytes(*secret_bytes)
        .expect("Ristretto-canonical");
    let t_sk = SecretKey::from_slice(&secret.secp256k1_bytes()).unwrap();
    let t_btc_bytes = PublicKey::from_secret_key(&secp, &t_sk).serialize();
    let t_cync_bytes = cync_adaptor_point(&secret).expect("cync pt");

    let Ok(proof) = prove_cross_curve(&secret, &t_btc_bytes, &t_cync_bytes, nonce_k_bytes) else {
        eprintln!("vec {}: prove_cross_curve failed; skipping", vec_id);
        return;
    };
    verify_cross_curve_proof(&proof, &t_btc_bytes, &t_cync_bytes).expect("verify");

    let vec_json = json!({
        "primitive": "dleq-cross-curve",
        "operation": "prove_then_verify",
        "source_file": "crates/coincync-swap/src/adaptor.rs",
        "source_test": "examples/gen_reproducibility_vectors.rs",
        "inputs": {
            "adaptor_secret_ristretto": hex(secret_bytes),
            "nonce_k_ristretto": hex(nonce_k_bytes),
        },
        "expected": {
            "t_btc_compressed": hex(&t_btc_bytes),
            "t_cync_ristretto": hex(&t_cync_bytes),
            "proof_a_btc": hex(&proof.a_btc),
            "proof_a_cync": hex(&proof.a_cync),
            "proof_s_btc": hex(&proof.s_btc),
            "proof_s_cync": hex(&proof.s_cync),
        },
        "notes": "Self-generated regression vector for Maxwell-Poelstra cross-curve DLEQ."
    });

    let path = out_dir().join("dleq-cross-curve").join(format!("{}.json", vec_id));
    fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
    fs::write(&path, serde_json::to_string_pretty(&vec_json).unwrap()).expect("write");
    println!("emitted {}", path.display());
}

fn main() {
    println!("Generating reproducibility vectors → {}", out_dir().display());
    println!();

    for &(id, signer_sk, secret, msg, aux_rand, dleq_nonce) in TEST_CASES {
        emit_btc_adaptor(id, &signer_sk, &secret, &msg, &aux_rand);
        emit_cync_adaptor(id, &signer_sk, &secret, &msg, &aux_rand); // reuse aux_rand as nonce
        emit_dleq(id, &secret, &dleq_nonce);
    }

    println!();
    println!("done.");
}
