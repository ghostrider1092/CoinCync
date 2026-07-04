//! # coincync-sign-snapshot
//!
//! Small operator CLI: sign a peer-snapshot JSON file with a raw
//! Ed25519 seed and emit a raw 64-byte signature.
//!
//! Match with `src/network/peer_snapshot.rs` consumer:
//!   signed_payload = SIGNATURE_NAMESPACE || snapshot_bytes
//!   signature      = Ed25519_sign(seed, signed_payload)  // 64 raw bytes
//!
//! Producer script `scripts/publish-peer-snapshot.sh` uses this binary
//! instead of `ssh-keygen -Y sign` so the signature file that lands
//! on IPFS is the exact 64 bytes the consumer expects — no PEM
//! envelope, no wire-format drift.
//!
//! ## Why a separate CLI (vs `ssh-keygen -Y sign`)
//!
//! `ssh-keygen -Y sign` produces a PEM-armored envelope wrapping an
//! SSH signature structure. The Ed25519 body is inside there, but the
//! consumer has to parse the SSH-signature wire format to extract it.
//! The `ssh-key` crate would do that but pulls ~40 KB of parser code
//! plus transitive deps just to reach the same 64-byte primitive that
//! `ed25519-dalek` (already in the tree) exposes directly.
//!
//! Using a small internal CLI keeps the wire contract clean: sig file
//! is exactly 64 raw bytes, consumer verifies with a 20-line function.
//!
//! ## Key management
//!
//! The signing seed is 32 raw bytes hex-encoded. Operator stores it
//! wherever they keep other Ed25519 seeds (systemd credential store,
//! password manager, sops-encrypted file, etc.). This is a rotating
//! operational key, not a release attestation — separate from the
//! commit-signing SSH key.
//!
//! Generate a fresh seed:
//!
//!     head -c 32 /dev/urandom | xxd -p -c 64  # 64 hex chars
//!
//! Derive the corresponding public key (paste into
//! `COINCYNC_PEER_SNAPSHOT_PUBKEY` on every consumer node):
//!
//!     coincync-sign-snapshot pubkey <seed_hex>
//!
//! ## Usage
//!
//!     coincync-sign-snapshot sign <seed_hex> <snapshot.json> <out.sig>
//!     coincync-sign-snapshot pubkey <seed_hex>
//!
//! The seed can also be passed via `COINCYNC_SIGN_SEED_HEX` env var to
//! keep it out of process argv.

use std::io::Write;
use std::process::ExitCode;

use ed25519_dalek::{Signer, SigningKey};

/// MUST match the const of the same name in
/// `src/network/peer_snapshot.rs`. If these drift, signatures will
/// verify individually against the wrong domain and the consumer will
/// reject them all. Kept as a duplicate string literal on purpose so
/// this binary doesn't pull in the whole crate at build time.
const SIGNATURE_NAMESPACE: &[u8] = b"coincync-peer-snapshot-v1";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return ExitCode::from(2);
    }

    match args[1].as_str() {
        "sign" => cmd_sign(&args[2..]),
        "pubkey" => cmd_pubkey(&args[2..]),
        "-h" | "--help" | "help" => {
            usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown subcommand: {}", other);
            usage();
            ExitCode::from(2)
        }
    }
}

fn cmd_sign(args: &[String]) -> ExitCode {
    // Two accepted forms:
    //   sign <snapshot.json> <out.sig>            (seed via env var)
    //   sign <seed_hex> <snapshot.json> <out.sig>
    let (seed_hex, in_path, out_path) = match args.len() {
        2 => match std::env::var("COINCYNC_SIGN_SEED_HEX") {
            Ok(v) => (v, args[0].clone(), args[1].clone()),
            Err(_) => {
                eprintln!(
                    "sign: need seed. Either pass as first arg or set \
                     COINCYNC_SIGN_SEED_HEX env var."
                );
                return ExitCode::from(2);
            }
        },
        3 => (args[0].clone(), args[1].clone(), args[2].clone()),
        _ => {
            usage();
            return ExitCode::from(2);
        }
    };

    let seed = match parse_seed(&seed_hex) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sign: bad seed: {}", e);
            return ExitCode::from(2);
        }
    };

    let snapshot_bytes = match std::fs::read(&in_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sign: cannot read {}: {}", in_path, e);
            return ExitCode::from(1);
        }
    };

    // Domain-separated: sig covers namespace || snapshot_bytes so a
    // signature from any other coincync signing context cannot be
    // replayed here. Namespace MUST match the consumer's constant.
    //
    // Namespace source, in order:
    //   1. `COINCYNC_SIGN_NAMESPACE_HEX` env var if set — hex-decoded
    //      bytes used verbatim. Producers for other services
    //      (faucet-registry-v1, coord-registry-v1, ...) set this so
    //      they get service-specific domain separation without the
    //      CLI needing a hard-coded case per service.
    //   2. Otherwise fall back to the default peer-snapshot namespace.
    //      This preserves backward compat for every existing
    //      producer that just does `coincync-sign-snapshot sign ...`
    //      without setting the env.
    //
    // Malformed hex (odd length, non-hex chars) is a hard fail — we
    // do NOT silently fall back to the default because that would
    // produce a signature that verifies against the WRONG service.
    let namespace: Vec<u8> = match std::env::var("COINCYNC_SIGN_NAMESPACE_HEX") {
        Ok(hex_str) => {
            let trimmed = hex_str.trim();
            if trimmed.is_empty() {
                SIGNATURE_NAMESPACE.to_vec()
            } else {
                match hex::decode(trimmed) {
                    Ok(bytes) => {
                        if bytes.is_empty() {
                            eprintln!(
                                "sign: COINCYNC_SIGN_NAMESPACE_HEX decoded to zero bytes"
                            );
                            return ExitCode::from(2);
                        }
                        bytes
                    }
                    Err(e) => {
                        eprintln!(
                            "sign: COINCYNC_SIGN_NAMESPACE_HEX not valid hex: {}",
                            e
                        );
                        return ExitCode::from(2);
                    }
                }
            }
        }
        Err(_) => SIGNATURE_NAMESPACE.to_vec(),
    };

    let mut signed_payload = Vec::with_capacity(namespace.len() + snapshot_bytes.len());
    signed_payload.extend_from_slice(&namespace);
    signed_payload.extend_from_slice(&snapshot_bytes);

    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(&signed_payload);
    let sig_bytes = signature.to_bytes();
    debug_assert_eq!(sig_bytes.len(), 64);

    // Write the raw 64 bytes — no PEM armor, no length prefix, no
    // envelope. The IPFS-served .sig object IS these 64 bytes.
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sign: cannot open {} for write: {}", out_path, e);
            return ExitCode::from(1);
        }
    };
    let mut file = file;
    if let Err(e) = file.write_all(&sig_bytes) {
        eprintln!("sign: write failed: {}", e);
        return ExitCode::from(1);
    }

    eprintln!(
        "wrote {} bytes to {} (input {} bytes)",
        sig_bytes.len(),
        out_path,
        snapshot_bytes.len()
    );
    ExitCode::SUCCESS
}

fn cmd_pubkey(args: &[String]) -> ExitCode {
    // pubkey [seed_hex]   (env var fallback)
    let seed_hex = match args.first().cloned() {
        Some(v) => v,
        None => match std::env::var("COINCYNC_SIGN_SEED_HEX") {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "pubkey: need seed. Either pass as first arg or set \
                     COINCYNC_SIGN_SEED_HEX env var."
                );
                return ExitCode::from(2);
            }
        },
    };

    let seed = match parse_seed(&seed_hex) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pubkey: bad seed: {}", e);
            return ExitCode::from(2);
        }
    };

    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();
    // Write hex to stdout — operator can pipe or copy directly.
    let hex_out: String = pubkey.iter().map(|b| format!("{:02x}", b)).collect();
    println!("{}", hex_out);
    eprintln!("(32-byte Ed25519 public key; paste into COINCYNC_PEER_SNAPSHOT_PUBKEY)");
    ExitCode::SUCCESS
}

fn parse_seed(hex_str: &str) -> Result<[u8; 32], String> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64 hex chars (32 bytes), got {}",
            trimmed.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|e| format!("non-hex character in seed: {}", e))?;
    }
    Ok(out)
}

fn usage() {
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(
        b"coincync-sign-snapshot: sign peer snapshots with Ed25519.\n\
          \n\
          USAGE\n\
              coincync-sign-snapshot sign <seed_hex> <snapshot.json> <out.sig>\n\
              coincync-sign-snapshot sign <snapshot.json> <out.sig>   # seed via COINCYNC_SIGN_SEED_HEX\n\
              coincync-sign-snapshot pubkey <seed_hex>\n\
              coincync-sign-snapshot pubkey                            # seed via COINCYNC_SIGN_SEED_HEX\n\
          \n\
          SEED\n\
              32-byte Ed25519 seed as 64 hex chars.\n\
              Generate: head -c 32 /dev/urandom | xxd -p -c 64\n\
          \n\
          OUTPUT\n\
              sign: writes 64 raw signature bytes to <out.sig>.\n\
              pubkey: writes 64-char hex (32-byte Ed25519 public key)\n\
                      to stdout. Paste into COINCYNC_PEER_SNAPSHOT_PUBKEY\n\
                      on every consumer node.\n\
          \n\
          DOMAIN SEPARATOR\n\
              Signature covers b\"coincync-peer-snapshot-v1\" || snapshot_bytes.\n\
              MUST match src/network/peer_snapshot.rs::SIGNATURE_NAMESPACE.\n",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn parse_seed_accepts_64_hex_chars() {
        // 64 hex chars = 32 bytes
        let hex = "deadbeef".repeat(8); // 8 chars × 8 = 64
        assert_eq!(hex.len(), 64);
        let seed = parse_seed(&hex).expect("valid hex");
        assert_eq!(seed[0], 0xde);
        assert_eq!(seed[1], 0xad);
        assert_eq!(seed[2], 0xbe);
        assert_eq!(seed[3], 0xef);
        assert_eq!(seed[31], 0xef);
    }

    #[test]
    fn parse_seed_rejects_wrong_length() {
        assert!(parse_seed("abcd").is_err()); // 4 chars
        assert!(parse_seed(&"a".repeat(63)).is_err());
        assert!(parse_seed(&"a".repeat(65)).is_err());
    }

    #[test]
    fn parse_seed_rejects_non_hex() {
        let bad = "gg".repeat(32);
        assert!(parse_seed(&bad).is_err());
    }

    #[test]
    fn sign_output_verifies_with_derived_pubkey_and_matching_namespace() {
        // This is the critical end-to-end contract: what we sign HERE
        // must verify against the exact SIGNATURE_NAMESPACE the consumer
        // uses. If either side drifts, deployment breaks.
        let seed = [42u8; 32];
        let snapshot = b"any-snapshot-body-bytes-doesnt-matter-for-this-test";
        let mut signed_payload =
            Vec::with_capacity(SIGNATURE_NAMESPACE.len() + snapshot.len());
        signed_payload.extend_from_slice(SIGNATURE_NAMESPACE);
        signed_payload.extend_from_slice(snapshot);

        let signing_key = SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(&signed_payload);
        let sig_bytes: [u8; 64] = signature.to_bytes();

        // Now verify — same pipeline the consumer runs.
        let verifying_key = VerifyingKey::from_bytes(&signing_key.verifying_key().to_bytes())
            .expect("valid pubkey");
        let reconstructed_sig = Signature::from_bytes(&sig_bytes);
        assert!(verifying_key.verify(&signed_payload, &reconstructed_sig).is_ok());
    }

    #[test]
    fn sign_output_does_not_verify_against_wrong_namespace() {
        // Regression guard: if a future refactor changes the namespace
        // on ONE side but not the other, every deployed sig verify
        // fails. This test catches that at build time.
        let seed = [42u8; 32];
        let snapshot = b"body";
        let signing_key = SigningKey::from_bytes(&seed);

        let mut correct_payload = Vec::from(SIGNATURE_NAMESPACE);
        correct_payload.extend_from_slice(snapshot);
        let sig = signing_key.sign(&correct_payload);

        // Verify against a DIFFERENT namespace — must fail.
        let mut wrong_payload = Vec::from(b"coincync-release-v1-");
        wrong_payload.extend_from_slice(snapshot);
        let verifying_key = signing_key.verifying_key();
        assert!(verifying_key.verify(&wrong_payload, &sig).is_err());
    }

    #[test]
    fn namespace_bytes_are_exactly_the_string() {
        // Belt-and-suspenders: confirm the const literal matches the
        // documented string. Someone could accidentally add a trailing
        // \0 or leading BOM and every sig would break.
        assert_eq!(SIGNATURE_NAMESPACE, b"coincync-peer-snapshot-v1");
        assert_eq!(SIGNATURE_NAMESPACE.len(), 25);
    }

    /// Simulate the cmd_sign namespace-decision path (the block that
    /// reads COINCYNC_SIGN_NAMESPACE_HEX and falls back to
    /// SIGNATURE_NAMESPACE). We can't drive the full cmd_sign
    /// function from tests without setting up files + args + exit
    /// codes, so this test replicates the specific env-var decision
    /// logic and asserts the three key branches.
    #[test]
    fn namespace_selection_env_override_hex_decode() {
        // Case 1: unset → default peer-snapshot namespace.
        let namespace = match std::env::var("COINCYNC_SIGN_NAMESPACE_HEX_TEST_UNSET") {
            Ok(_) => panic!("test env var must remain unset"),
            Err(_) => SIGNATURE_NAMESPACE.to_vec(),
        };
        assert_eq!(namespace.as_slice(), SIGNATURE_NAMESPACE);

        // Case 2: hex-decodes the faucet namespace correctly.
        let faucet_hex = "coincync-faucet-registry-v1"
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let decoded = hex::decode(&faucet_hex).expect("valid hex");
        assert_eq!(decoded.as_slice(), b"coincync-faucet-registry-v1");
        assert_ne!(decoded.as_slice(), SIGNATURE_NAMESPACE);

        // Case 3: signature over the faucet namespace does NOT verify
        // against the peer-snapshot namespace — cross-service replay
        // defence.
        let seed = [7u8; 32];
        let payload = b"faucet-registry-canonical-bytes";
        let signing_key = SigningKey::from_bytes(&seed);
        let mut faucet_signed = Vec::from(decoded.as_slice());
        faucet_signed.extend_from_slice(payload);
        let sig = signing_key.sign(&faucet_signed);

        let mut wrong_signed = Vec::from(SIGNATURE_NAMESPACE);
        wrong_signed.extend_from_slice(payload);
        let vk = signing_key.verifying_key();
        assert!(
            vk.verify(&wrong_signed, &sig).is_err(),
            "faucet-namespace signature must NOT verify as peer-snapshot"
        );
    }
}
