//! Snapshot manifest signing — the "trusted source" layer.
//!
//! Checkpoint binding (see [`super::verify`]) proves a snapshot *is our chain*.
//! This module proves it came from a source you *trust*: the producer signs the
//! manifest with an Ed25519 key, and import can require that signature verify
//! against a configured allowlist of trusted signer public keys.
//!
//! Why this matters: the blake3 hash in the manifest catches accidental
//! corruption, but a malicious producer can rewrite the DB *and* recompute a
//! matching blake3 in a forged manifest. A signature over the manifest — by a
//! key the importer trusts — is what upgrades that hash from anti-corruption to
//! anti-tampering: the signer vouches for the manifest, the manifest pins the
//! `db_blake3`, and the blake3 pins the DB bytes.
//!
//! ## Wire contract
//!
//! Deliberately identical in shape to peer-snapshot signing
//! (`network::peer_snapshot`): a domain-separated namespace prefix and a raw
//! 64-byte Ed25519 signature. The namespace is **distinct** so a signature for
//! one artifact can never verify for the other. The signature lives in a
//! sidecar `manifest.sig` (JSON) next to `manifest.json`; the signed bytes are
//! the exact on-disk bytes of `manifest.json`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Domain separation for chain-snapshot manifest signatures. Distinct from
/// `network::peer_snapshot::SIGNATURE_NAMESPACE` so the two artifacts' sigs can
/// never cross-verify.
pub const SNAPSHOT_MANIFEST_NAMESPACE: &[u8] = b"coincync-chain-snapshot-manifest-v1";

/// Signature sidecar, written next to `manifest.json` as `manifest.sig`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSignature {
    /// Signer's Ed25519 public key (hex, 32 bytes).
    pub signer_pubkey: String,
    /// Ed25519 signature over `NAMESPACE || manifest.json` bytes (hex, 64 bytes).
    pub signature: String,
}

fn signed_payload(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(SNAPSHOT_MANIFEST_NAMESPACE.len() + manifest_bytes.len());
    p.extend_from_slice(SNAPSHOT_MANIFEST_NAMESPACE);
    p.extend_from_slice(manifest_bytes);
    p
}

fn decode_fixed<const N: usize>(hexstr: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(hexstr.trim()).ok()?;
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Sign the exact bytes of a `manifest.json` with a raw 32-byte Ed25519 seed.
/// Returns the sidecar to persist as `manifest.sig`.
pub fn sign_manifest(seed: &[u8; 32], manifest_bytes: &[u8]) -> ManifestSignature {
    let sk = SigningKey::from_bytes(seed);
    let sig = sk.sign(&signed_payload(manifest_bytes));
    ManifestSignature {
        signer_pubkey: hex::encode(sk.verifying_key().to_bytes()),
        signature: hex::encode(sig.to_bytes()),
    }
}

/// Derive the hex public key for a raw 32-byte Ed25519 seed — the value an
/// operator pins into the importer's trusted-signer allowlist.
pub fn pubkey_for_seed(seed: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Verify a manifest signature and require the signer be on `trusted_pubkeys`
/// (hex Ed25519 keys). Returns `Ok` only when BOTH hold: the signature is
/// cryptographically valid over `NAMESPACE || manifest_bytes`, and the signer
/// is in the allowlist. Order matters: an untrusted signer is rejected before
/// any crypto work, and a trusted-but-invalid signature is rejected after.
pub fn verify_manifest_signature(
    manifest_bytes: &[u8],
    sig: &ManifestSignature,
    trusted_pubkeys: &[String],
) -> Result<()> {
    let pubkey_bytes: [u8; 32] = decode_fixed(&sig.signer_pubkey).ok_or_else(|| {
        Error::InvalidState("snapshot signature: signer pubkey is not 32-byte hex".into())
    })?;

    // Trust gate first: is this signer on the allowlist? (Compare decoded bytes
    // so hex case / whitespace never matters.)
    let trusted = trusted_pubkeys
        .iter()
        .filter_map(|t| decode_fixed::<32>(t))
        .any(|t| t == pubkey_bytes);
    if !trusted {
        return Err(Error::InvalidState(format!(
            "snapshot is signed by {} which is NOT in the trusted-signer allowlist — refusing",
            sig.signer_pubkey
        )));
    }

    let sig_bytes: [u8; 64] = decode_fixed(&sig.signature)
        .ok_or_else(|| Error::InvalidState("snapshot signature: not 64-byte hex".into()))?;
    let vk = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| Error::InvalidState(format!("snapshot signature: invalid pubkey: {}", e)))?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify(&signed_payload(manifest_bytes), &signature).map_err(|_| {
        Error::InvalidState(
            "snapshot signature verification FAILED — refusing (tampered manifest or wrong key)"
                .into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &[u8] = br#"{"network":"testnet","height":42}"#;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn sign_then_verify_roundtrips_for_trusted_signer() {
        let s = seed(1);
        let sig = sign_manifest(&s, MANIFEST);
        let trusted = vec![pubkey_for_seed(&s)];
        assert!(verify_manifest_signature(MANIFEST, &sig, &trusted).is_ok());
    }

    #[test]
    fn rejects_signer_not_in_allowlist() {
        let s = seed(1);
        let sig = sign_manifest(&s, MANIFEST);
        // A different key is trusted; the actual signer is not.
        let trusted = vec![pubkey_for_seed(&seed(2))];
        let err = verify_manifest_signature(MANIFEST, &sig, &trusted).unwrap_err();
        assert!(format!("{:?}", err).contains("trusted-signer allowlist"));
    }

    #[test]
    fn rejects_empty_allowlist() {
        let s = seed(1);
        let sig = sign_manifest(&s, MANIFEST);
        let err = verify_manifest_signature(MANIFEST, &sig, &[]).unwrap_err();
        assert!(format!("{:?}", err).contains("trusted-signer allowlist"));
    }

    #[test]
    fn rejects_tampered_manifest() {
        let s = seed(1);
        let sig = sign_manifest(&s, MANIFEST);
        let trusted = vec![pubkey_for_seed(&s)];
        // Same (trusted) signer, but the manifest bytes changed after signing.
        let tampered = br#"{"network":"testnet","height":999999}"#;
        let err = verify_manifest_signature(tampered, &sig, &trusted).unwrap_err();
        assert!(format!("{:?}", err).to_lowercase().contains("verification failed"));
    }

    #[test]
    fn rejects_signature_from_a_different_namespace() {
        // A signature produced over a DIFFERENT domain (e.g. the peer-snapshot
        // namespace) must not verify as a chain-snapshot manifest signature.
        let s = seed(1);
        let sk = SigningKey::from_bytes(&s);
        let mut foreign = Vec::new();
        foreign.extend_from_slice(b"coincync-peer-snapshot-v1");
        foreign.extend_from_slice(MANIFEST);
        let foreign_sig = sk.sign(&foreign);
        let sig = ManifestSignature {
            signer_pubkey: pubkey_for_seed(&s),
            signature: hex::encode(foreign_sig.to_bytes()),
        };
        let trusted = vec![pubkey_for_seed(&s)];
        assert!(verify_manifest_signature(MANIFEST, &sig, &trusted).is_err());
    }

    #[test]
    fn rejects_malformed_pubkey_and_sig() {
        let bad_pk = ManifestSignature {
            signer_pubkey: "xyz".into(),
            signature: hex::encode([0u8; 64]),
        };
        assert!(verify_manifest_signature(MANIFEST, &bad_pk, &["xyz".into()]).is_err());

        let s = seed(3);
        let bad_sig = ManifestSignature {
            signer_pubkey: pubkey_for_seed(&s),
            signature: "00".into(), // not 64 bytes
        };
        let trusted = vec![pubkey_for_seed(&s)];
        assert!(verify_manifest_signature(MANIFEST, &bad_sig, &trusted).is_err());
    }
}
