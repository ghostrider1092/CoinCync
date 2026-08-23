//! # coincync-release-attest
//!
//! Supply-chain release tooling (Bitcoin/Monero-style multi-signer attestation):
//!
//!   1. `manifest` — hash every artifact in a directory into a signed-able
//!      manifest (SHA-256 + size, version + commit).
//!   2. `sign`     — a maintainer signs the manifest with their ed25519 seed.
//!   3. `verify`   — check the artifacts match the manifest AND that an N-of-M
//!      set of KNOWN maintainer signatures is valid.
//!
//! No single machine or maintainer can pass a backdoored binary: verification
//! requires a threshold of independent maintainer signatures over the exact
//! artifact hashes. See `src/release.rs` for the verified core.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use coincync::release::{sha256_hex, verify_signatures, ArtifactHash, ReleaseManifest};

#[derive(Parser)]
#[command(name = "coincync-release-attest", about = "Reproducible-build release attestation")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Hash every file in DIR into a manifest (JSON to stdout).
    Manifest {
        #[arg(long)]
        version: String,
        #[arg(long)]
        commit: String,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Sign a manifest JSON with an ed25519 seed (64-hex in a file). Prints
    /// `<pubkey_hex>:<sig_hex>` — pass that to `verify --sig`.
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        /// Path to a file containing the 64-hex (32-byte) ed25519 seed.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Verify artifacts against the manifest + an N-of-M maintainer signature set.
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        dir: PathBuf,
        /// Maintainer public keys (64-hex). Repeatable.
        #[arg(long = "maintainer")]
        maintainers: Vec<String>,
        #[arg(long)]
        threshold: usize,
        /// Signatures as `<pubkey_hex>:<sig_hex>`. Repeatable.
        #[arg(long = "sig")]
        sigs: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_pubkey(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("bad pubkey hex: {e}"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "pubkey must be 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519 pubkey: {e}"))
}

fn run() -> Result<(), String> {
    match Cli::parse().cmd {
        Cmd::Manifest { version, commit, dir } => {
            let mut artifacts = Vec::new();
            let entries = std::fs::read_dir(&dir).map_err(|e| format!("read_dir {dir:?}: {e}"))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path();
                if !path.is_file() {
                    continue; // top-level artifacts only
                }
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("non-utf8 filename")?
                    .to_string();
                let bytes = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
                artifacts.push(ArtifactHash {
                    name,
                    sha256: sha256_hex(&bytes),
                    size: bytes.len() as u64,
                });
            }
            if artifacts.is_empty() {
                return Err(format!("no files found in {dir:?}"));
            }
            let manifest = ReleaseManifest::new(version, commit, artifacts);
            let json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
            println!("{json}");
            Ok(())
        }
        Cmd::Sign { manifest, key_file } => {
            let manifest: ReleaseManifest = serde_json::from_slice(
                &std::fs::read(&manifest).map_err(|e| format!("read manifest: {e}"))?,
            )
            .map_err(|e| format!("parse manifest: {e}"))?;
            let seed_hex = std::fs::read_to_string(&key_file).map_err(|e| format!("read key: {e}"))?;
            let seed = hex::decode(seed_hex.trim()).map_err(|e| format!("bad seed hex: {e}"))?;
            let seed: [u8; 32] = seed.try_into().map_err(|_| "seed must be 32 bytes".to_string())?;
            let key = SigningKey::from_bytes(&seed);
            let sig = manifest.sign(&key);
            println!(
                "{}:{}",
                hex::encode(key.verifying_key().to_bytes()),
                hex::encode(sig.to_bytes())
            );
            Ok(())
        }
        Cmd::Verify {
            manifest,
            dir,
            maintainers,
            threshold,
            sigs,
        } => {
            let manifest: ReleaseManifest = serde_json::from_slice(
                &std::fs::read(&manifest).map_err(|e| format!("read manifest: {e}"))?,
            )
            .map_err(|e| format!("parse manifest: {e}"))?;

            // 1. Every manifest artifact must be present on disk with a matching hash.
            for a in &manifest.artifacts {
                let path = dir.join(&a.name);
                let bytes = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
                manifest.verify_artifact(&a.name, &bytes)?;
            }

            // 2. Parse maintainers + signatures, then enforce the N-of-M threshold.
            let maintainer_keys: Vec<VerifyingKey> =
                maintainers.iter().map(|m| parse_pubkey(m)).collect::<Result<_, _>>()?;
            let mut sig_pairs: Vec<(VerifyingKey, Signature)> = Vec::new();
            for s in &sigs {
                let (pk, sg) = s.split_once(':').ok_or("sig must be <pubkey_hex>:<sig_hex>")?;
                let vk = parse_pubkey(pk)?;
                let sg = hex::decode(sg.trim()).map_err(|e| format!("bad sig hex: {e}"))?;
                let sg: [u8; 64] = sg.try_into().map_err(|_| "signature must be 64 bytes".to_string())?;
                sig_pairs.push((vk, Signature::from_bytes(&sg)));
            }
            let n = verify_signatures(&manifest, &sig_pairs, &maintainer_keys, threshold)?;

            println!(
                "OK: {} artifact(s) match; {} of {} maintainer signatures valid (threshold {}).",
                manifest.artifacts.len(),
                n,
                maintainer_keys.len(),
                threshold
            );
            Ok(())
        }
    }
}
