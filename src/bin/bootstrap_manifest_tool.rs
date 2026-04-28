//! Bootstrap manifest signing helper.
//!
//! Usage examples:
//!   cargo run --bin bootstrap_manifest_tool -- keygen --secret-out signing.key --public-out signing.pub
//!   cargo run --bin bootstrap_manifest_tool -- create --out seeds.json --peer 1.2.3.4:28333 --peer 5.6.7.8:28333
//!   cargo run --bin bootstrap_manifest_tool -- sign --manifest seeds.json --secret-key signing.key --sig-out seeds.json.sig
//!   cargo run --bin bootstrap_manifest_tool -- verify --manifest seeds.json --public-key signing.pub --signature seeds.json.sig

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;

const BOOTSTRAP_MANIFEST_DOMAIN: &[u8] = b"coincync/bootstrap-manifest/v1";

#[derive(Parser)]
#[command(name = "bootstrap_manifest_tool")]
#[command(about = "Generate/sign/verify CoinCync bootstrap seed manifests")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 signing keypair.
    Keygen {
        /// Secret key output path (32-byte raw file).
        #[arg(long)]
        secret_out: PathBuf,
        /// Public key output path (32-byte hex text file).
        #[arg(long)]
        public_out: PathBuf,
    },
    /// Create a signed-manifest JSON skeleton.
    Create {
        /// Output manifest path.
        #[arg(long)]
        out: PathBuf,
        /// Peer entries (ip:port). Repeat flag for multiple.
        #[arg(long = "peer", required = true)]
        peers: Vec<String>,
    },
    /// Sign a manifest with an Ed25519 secret key.
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        /// Secret key path (32-byte raw file or 64-char hex).
        #[arg(long)]
        secret_key: PathBuf,
        /// Signature output path (64-byte raw file).
        #[arg(long)]
        sig_out: PathBuf,
    },
    /// Verify a signed manifest.
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        /// Public key path (32-byte raw file or 64-char hex text).
        #[arg(long)]
        public_key: PathBuf,
        /// Signature path (64-byte raw file or 128-char hex text).
        #[arg(long)]
        signature: PathBuf,
    },
}

#[derive(Serialize)]
struct SignedSeedManifest {
    peers: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Keygen {
            secret_out,
            public_out,
        } => {
            let secret_bytes = rand::random::<[u8; 32]>();
            let signing_key = SigningKey::from_bytes(&secret_bytes);
            let verify_key = signing_key.verifying_key();

            fs::write(&secret_out, secret_bytes)?;
            fs::write(&public_out, hex::encode(verify_key.to_bytes()))?;

            println!("Wrote secret key: {}", secret_out.display());
            println!("Wrote public key: {}", public_out.display());
            println!("Public key hex: {}", hex::encode(verify_key.to_bytes()));
        }
        Command::Create { out, peers } => {
            let manifest = SignedSeedManifest { peers };
            let bytes = serde_json::to_vec_pretty(&manifest)?;
            fs::write(&out, bytes)?;
            println!("Wrote manifest: {}", out.display());
        }
        Command::Sign {
            manifest,
            secret_key,
            sig_out,
        } => {
            let sk = load_32(&secret_key)?;
            let signing_key = SigningKey::from_bytes(&sk);
            let manifest_bytes = fs::read(&manifest)?;
            let msg = signing_message(&manifest_bytes);
            let sig = signing_key.sign(&msg);
            fs::write(&sig_out, sig.to_bytes())?;
            println!("Wrote signature: {}", sig_out.display());
        }
        Command::Verify {
            manifest,
            public_key,
            signature,
        } => {
            let pk = load_32(&public_key)?;
            let verify_key = VerifyingKey::from_bytes(&pk)?;
            let sig_bytes = load_64(&signature)?;
            let signature = Signature::from_bytes(&sig_bytes);
            let manifest_bytes = fs::read(&manifest)?;
            let msg = signing_message(&manifest_bytes);
            verify_key.verify(&msg, &signature)?;
            println!("Signature OK");
        }
    }
    Ok(())
}

fn signing_message(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BOOTSTRAP_MANIFEST_DOMAIN.len() + manifest_bytes.len());
    msg.extend_from_slice(BOOTSTRAP_MANIFEST_DOMAIN);
    msg.extend_from_slice(manifest_bytes);
    msg
}

fn load_32(path: &PathBuf) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let text = std::str::from_utf8(&bytes)?.trim();
    let decoded = hex::decode(text)?;
    if decoded.len() != 32 {
        return Err(format!("expected 32-byte value at {}", path.display()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn load_64(path: &PathBuf) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    if bytes.len() == 64 {
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    let text = std::str::from_utf8(&bytes)?.trim();
    let decoded = hex::decode(text)?;
    if decoded.len() != 64 {
        return Err(format!("expected 64-byte value at {}", path.display()).into());
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&decoded);
    Ok(out)
}
