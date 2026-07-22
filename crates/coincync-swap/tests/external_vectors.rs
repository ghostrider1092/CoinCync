//! Loads + runs every cryptographic test vector under
//! `crates/coincync-swap/test-vectors/{reproducibility,comit,farcaster}/<primitive>/*.json`
//! through our primitive implementations, asserting bit-for-bit byte equality.
//!
//! This is the load-bearing harness for the
//! [`docs/cyncswap-farcaster-comit-alignment.md`](../../../docs/cyncswap-farcaster-comit-alignment.md)
//! Step 1.
//!
//! ## Vendor categories
//!
//! - **`reproducibility/`** — Self-generated from our own impl by
//!   `examples/gen_reproducibility_vectors.rs`. Locks output bytes
//!   against unintended regressions. NOT independent correctness
//!   validation.
//! - **`comit/`** — From Comit's `xmr-btc-swap` test suite.
//!   Independent reference impl audited by Kudelski 2021. Currently
//!   empty; import path is in `comit/README.md`.
//! - **`farcaster/`** — From Farcaster's `farcaster-core`. Independent
//!   ed25519 + secp256k1 adaptor + DLEQ reference. Currently empty;
//!   import path is in `farcaster/README.md`.
//!
//! ## Failure mode
//!
//! If our implementation produces output that differs from a vendor
//! vector by a single byte, `cargo test --test external_vectors` fails
//! the build. No "approximately equal" — `assert_eq!` on raw bytes.
//! This is intentional and audit-protective.

use std::fs;
use std::path::{Path, PathBuf};

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::Value;

use coincync_swap::adaptor::{
    create_pre_sig_bip340, cync_adaptor_point, cync_create_pre_sig, cync_decrypt_adaptor,
    cync_recover_secret, decrypt_btc_adaptor, prove_cross_curve, recover_secret_from_btc_sig,
    verify_pre_sig, AdaptorSecret,
};

/// Root of the vendor vector tree, relative to the workspace member dir.
const VENDOR_ROOTS: &[&str] = &[
    "test-vectors/reproducibility",
    "test-vectors/comit",
    "test-vectors/farcaster",
];

// ─── Walking the vendor tree ──────────────────────────────────

fn collect_vector_files(crate_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for vendor_rel in VENDOR_ROOTS {
        let vendor_dir = crate_root.join(vendor_rel);
        if !vendor_dir.exists() {
            continue;
        }
        collect_json_recursive(&vendor_dir, &mut out);
    }
    out.sort();
    out
}

fn collect_json_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_json_recursive(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(path);
        }
    }
}

// ─── Hex helpers ───────────────────────────────────────────────

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn hex_field(json: &Value, path: &[&str]) -> Result<Vec<u8>, String> {
    let mut cur = json;
    for &key in path {
        cur = cur
            .get(key)
            .ok_or_else(|| format!("missing field path {path:?}"))?;
    }
    let s = cur
        .as_str()
        .ok_or_else(|| format!("field {path:?} not a string"))?;
    hex_decode(s)
}

fn array<const N: usize>(v: Vec<u8>) -> Result<[u8; N], String> {
    let len = v.len();
    v.try_into()
        .map_err(|_| format!("expected {N} bytes, got {len}"))
}

// ─── Primitive runners ─────────────────────────────────────────

fn run_btc_adaptor(vec_path: &Path, json: &Value) -> Result<(), String> {
    let signer_sk_bytes: [u8; 32] =
        array(hex_field(json, &["inputs", "signer_seckey_secp256k1"])?)?;
    let adaptor_secret_bytes: [u8; 32] =
        array(hex_field(json, &["inputs", "adaptor_secret_ristretto"])?)?;
    let msg: [u8; 32] = array(hex_field(json, &["inputs", "message_hash"])?)?;
    let aux_rand: [u8; 32] = array(hex_field(json, &["inputs", "aux_rand"])?)?;

    let expected_r_point = hex_field(json, &["expected", "adaptor_r_point_compressed"])?;
    let expected_s_pre: [u8; 32] = array(hex_field(json, &["expected", "adaptor_s_pre"])?)?;
    let expected_signer_x = hex_field(json, &["expected", "signer_x_only_pubkey"])?;
    let expected_t_pub = hex_field(json, &["expected", "adaptor_pubkey_t_secp"])?;
    let expected_final_sig = hex_field(json, &["expected", "final_sig_64"])?;
    let expected_recovered: [u8; 32] =
        array(hex_field(json, &["expected", "recovered_secret_secp"])?)?;

    let secp = Secp256k1::new();
    let signer_sk = SecretKey::from_slice(&signer_sk_bytes)
        .map_err(|e| format!("invalid signer seckey: {e}"))?;
    let secret = AdaptorSecret::from_ristretto_bytes(adaptor_secret_bytes)
        .map_err(|e| format!("invalid adaptor secret: {e:?}"))?;
    let t_sk = SecretKey::from_slice(&secret.secp256k1_bytes())
        .map_err(|e| format!("secret not valid secp scalar: {e}"))?;
    let t_pub = PublicKey::from_secret_key(&secp, &t_sk);

    let (adaptor_sig, signer_x) = create_pre_sig_bip340(&signer_sk, &msg, &t_pub, &aux_rand)
        .map_err(|e| format!("create_pre_sig_bip340 failed: {e:?}"))?;

    if adaptor_sig.r_point.serialize().to_vec() != expected_r_point {
        return Err(format!("{}: r_point byte mismatch", vec_path.display()));
    }
    if adaptor_sig.s_pre != expected_s_pre {
        return Err(format!("{}: s_pre byte mismatch", vec_path.display()));
    }
    if signer_x.serialize().to_vec() != expected_signer_x {
        return Err(format!("{}: signer_x mismatch", vec_path.display()));
    }
    if t_pub.serialize().to_vec() != expected_t_pub {
        return Err(format!("{}: t_pub mismatch", vec_path.display()));
    }

    verify_pre_sig(&adaptor_sig, &signer_x, &t_pub, &msg)
        .map_err(|e| format!("verify_pre_sig: {e:?}"))?;

    let final_sig = decrypt_btc_adaptor(&adaptor_sig, &secret, &t_pub)
        .map_err(|e| format!("decrypt_btc_adaptor: {e:?}"))?;
    if final_sig.to_vec() != expected_final_sig {
        return Err(format!("{}: final_sig mismatch", vec_path.display()));
    }

    let recovered = recover_secret_from_btc_sig(&adaptor_sig, &final_sig)
        .map_err(|e| format!("recover: {e:?}"))?;
    if recovered.secp256k1_bytes() != expected_recovered {
        return Err(format!("{}: recovered secret mismatch", vec_path.display()));
    }
    Ok(())
}

fn run_ristretto_adaptor(vec_path: &Path, json: &Value) -> Result<(), String> {
    let signer_sk_bytes: [u8; 32] =
        array(hex_field(json, &["inputs", "signer_seckey_ristretto"])?)?;
    let adaptor_secret_bytes: [u8; 32] =
        array(hex_field(json, &["inputs", "adaptor_secret_ristretto"])?)?;
    let msg: [u8; 32] = array(hex_field(json, &["inputs", "message_hash"])?)?;
    let nonce_bytes: [u8; 32] = array(hex_field(json, &["inputs", "nonce"])?)?;

    let expected_r_point: [u8; 32] =
        array(hex_field(json, &["expected", "adaptor_r_point_ristretto"])?)?;
    let expected_s_pre: [u8; 32] = array(hex_field(json, &["expected", "adaptor_s_pre"])?)?;
    let expected_signer_pub: [u8; 32] =
        array(hex_field(json, &["expected", "signer_pub_ristretto"])?)?;
    let expected_t_point: [u8; 32] = array(hex_field(
        json,
        &["expected", "adaptor_pubkey_t_ristretto"],
    )?)?;
    let expected_final_sig = hex_field(json, &["expected", "final_sig_64"])?;
    let expected_recovered: [u8; 32] = array(hex_field(
        json,
        &["expected", "recovered_secret_ristretto"],
    )?)?;

    let secret = AdaptorSecret::from_ristretto_bytes(adaptor_secret_bytes)
        .map_err(|e| format!("invalid adaptor secret: {e:?}"))?;
    let t_point =
        cync_adaptor_point(&secret).map_err(|e| format!("cync_adaptor_point: {e:?}"))?;
    if t_point != expected_t_point {
        return Err(format!("{}: t_point mismatch", vec_path.display()));
    }

    let (adaptor_sig, signer_pub) =
        cync_create_pre_sig(&signer_sk_bytes, &msg, &t_point, &nonce_bytes)
            .map_err(|e| format!("cync_create_pre_sig: {e:?}"))?;

    if adaptor_sig.r_point != expected_r_point {
        return Err(format!(
            "{}: ristretto r_point mismatch",
            vec_path.display()
        ));
    }
    if adaptor_sig.s_pre != expected_s_pre {
        return Err(format!("{}: ristretto s_pre mismatch", vec_path.display()));
    }
    if signer_pub != expected_signer_pub {
        return Err(format!(
            "{}: ristretto signer_pub mismatch",
            vec_path.display()
        ));
    }

    let final_sig = cync_decrypt_adaptor(&adaptor_sig, &secret, &t_point)
        .map_err(|e| format!("cync_decrypt_adaptor: {e:?}"))?;
    if final_sig.to_vec() != expected_final_sig {
        return Err(format!(
            "{}: ristretto final_sig mismatch",
            vec_path.display()
        ));
    }
    let recovered = cync_recover_secret(&adaptor_sig, &final_sig)
        .map_err(|e| format!("cync_recover_secret: {e:?}"))?;
    if recovered.ristretto_bytes() != expected_recovered {
        return Err(format!(
            "{}: ristretto recovered mismatch",
            vec_path.display()
        ));
    }
    Ok(())
}

fn run_dleq(vec_path: &Path, json: &Value) -> Result<(), String> {
    let adaptor_secret_bytes: [u8; 32] =
        array(hex_field(json, &["inputs", "adaptor_secret_ristretto"])?)?;
    let nonce_k_bytes: [u8; 32] = array(hex_field(json, &["inputs", "nonce_k_ristretto"])?)?;

    let expected_t_btc: [u8; 33] = array(hex_field(json, &["expected", "t_btc_compressed"])?)?;
    let expected_t_cync: [u8; 32] = array(hex_field(json, &["expected", "t_cync_ristretto"])?)?;
    let expected_a_btc = hex_field(json, &["expected", "proof_a_btc"])?;
    let expected_a_cync = hex_field(json, &["expected", "proof_a_cync"])?;
    let expected_s_btc = hex_field(json, &["expected", "proof_s_btc"])?;
    let expected_s_cync = hex_field(json, &["expected", "proof_s_cync"])?;

    let secret = AdaptorSecret::from_ristretto_bytes(adaptor_secret_bytes)
        .map_err(|e| format!("adaptor secret: {e:?}"))?;
    let secp = Secp256k1::new();
    let t_sk =
        SecretKey::from_slice(&secret.secp256k1_bytes()).map_err(|e| format!("t_sk: {e}"))?;
    let t_btc_bytes = PublicKey::from_secret_key(&secp, &t_sk).serialize();
    if t_btc_bytes != expected_t_btc {
        return Err(format!("{}: t_btc mismatch", vec_path.display()));
    }
    let t_cync_bytes =
        cync_adaptor_point(&secret).map_err(|e| format!("cync_adaptor_point: {e:?}"))?;
    if t_cync_bytes != expected_t_cync {
        return Err(format!("{}: t_cync mismatch", vec_path.display()));
    }

    let proof = prove_cross_curve(&secret, &t_btc_bytes, &t_cync_bytes, &nonce_k_bytes)
        .map_err(|e| format!("prove_cross_curve: {e:?}"))?;

    if proof.a_btc.to_vec() != expected_a_btc {
        return Err(format!("{}: dleq a_btc mismatch", vec_path.display()));
    }
    if proof.a_cync.to_vec() != expected_a_cync {
        return Err(format!("{}: dleq a_cync mismatch", vec_path.display()));
    }
    if proof.s_btc.to_vec() != expected_s_btc {
        return Err(format!("{}: dleq s_btc mismatch", vec_path.display()));
    }
    if proof.s_cync.to_vec() != expected_s_cync {
        return Err(format!("{}: dleq s_cync mismatch", vec_path.display()));
    }
    Ok(())
}

// ─── Dispatch ──────────────────────────────────────────────────

fn run_vector(vector_path: &Path, vector_json: &Value) -> Result<(), String> {
    let primitive = vector_json
        .get("primitive")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{}: missing `primitive` field", vector_path.display()))?;

    match primitive {
        "btc-adaptor" => run_btc_adaptor(vector_path, vector_json),
        "ristretto-adaptor" | "ed25519-adaptor" => run_ristretto_adaptor(vector_path, vector_json),
        "dleq-cross-curve" => run_dleq(vector_path, vector_json),
        other => Err(format!(
            "{}: unknown primitive `{}` — extend run_vector() match arms",
            vector_path.display(),
            other
        )),
    }
}

#[test]
fn external_vectors_match_byte_for_byte() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vector_files = collect_vector_files(crate_root);

    if vector_files.is_empty() {
        eprintln!(
            "external_vectors: no vendor vector files found under {VENDOR_ROOTS:?} \
             — scaffolding present, import not yet done.",
        );
        return;
    }

    let mut failures: Vec<String> = Vec::new();
    let mut ran = 0usize;

    for vector_path in &vector_files {
        let bytes = match fs::read(vector_path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: read error: {e}", vector_path.display()));
                continue;
            }
        };
        let json: Value = match serde_json::from_slice(&bytes) {
            Ok(j) => j,
            Err(e) => {
                failures.push(format!("{}: parse error: {e}", vector_path.display()));
                continue;
            }
        };
        if let Err(reason) = run_vector(vector_path, &json) {
            failures.push(reason);
        }
        ran += 1;
    }

    eprintln!(
        "external_vectors: ran {ran} vectors from {} files",
        vector_files.len()
    );

    if !failures.is_empty() {
        panic!(
            "external_vectors: {} failure(s):\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
}
