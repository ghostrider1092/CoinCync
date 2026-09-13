//! Signed sync checkpoints — the authenticity layer for light-client sync
//! (gap #3, slice 2).
//!
//! [`SyncCheckpoint::verify_hash`](crate::wallet::lightsync::SyncCheckpoint::verify_hash)
//! is a self-consistency checksum: it proves the four fields weren't mangled in
//! transit, NOT that the checkpoint is legitimate — a malicious server can craft
//! a perfectly self-consistent but forged checkpoint. This module adds the
//! missing half: an Ed25519 signature over the checkpoint by a key the light
//! wallet trusts, verified against an allowlist. A signed checkpoint is
//! **advisory** (a wallet cross-checks it to fast-skip scanning); it is NOT a
//! consensus rule and enforces nothing on the network.
//!
//! Deliberately identical in shape to [`crate::snapshot::signing`] — a
//! domain-separated namespace prefix + a raw 64-byte Ed25519 signature in a hex
//! sidecar. The namespace is **distinct** so a sync-checkpoint signature can
//! never cross-verify as a snapshot-manifest (or peer-snapshot) signature.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::wallet::lightsync::SyncCheckpoint;

/// Domain separation for sync-checkpoint signatures. Distinct from the snapshot
/// and peer-snapshot namespaces so signatures can never cross-verify.
pub const SYNC_CHECKPOINT_NAMESPACE: &[u8] = b"coincync-sync-checkpoint-v1";

/// Signature sidecar for a [`SyncCheckpoint`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncCheckpointSignature {
    /// Signer's Ed25519 public key (hex, 32 bytes).
    pub signer_pubkey: String,
    /// Ed25519 signature over `NAMESPACE || checkpoint_signing_bytes` (hex, 64 bytes).
    pub signature: String,
}

/// Canonical bytes a signature commits to: the four checkpoint fields in the
/// exact order and encoding [`SyncCheckpoint::verify_hash`] uses, so the
/// signature binds `height`, `block_hash`, `total_outputs`, and `utxo_hash`.
pub fn checkpoint_signing_bytes(cp: &SyncCheckpoint) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + 32 + 8 + 32);
    b.extend_from_slice(&cp.height.to_le_bytes());
    b.extend_from_slice(cp.block_hash.as_bytes());
    b.extend_from_slice(&cp.total_outputs.to_le_bytes());
    b.extend_from_slice(cp.utxo_hash.as_bytes());
    b
}

fn signed_payload(cp: &SyncCheckpoint) -> Vec<u8> {
    let body = checkpoint_signing_bytes(cp);
    let mut p = Vec::with_capacity(SYNC_CHECKPOINT_NAMESPACE.len() + body.len());
    p.extend_from_slice(SYNC_CHECKPOINT_NAMESPACE);
    p.extend_from_slice(&body);
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

/// Sign a checkpoint with a raw 32-byte Ed25519 seed. Returns the sidecar.
pub fn sign_checkpoint(seed: &[u8; 32], cp: &SyncCheckpoint) -> SyncCheckpointSignature {
    let sk = SigningKey::from_bytes(seed);
    let sig = sk.sign(&signed_payload(cp));
    SyncCheckpointSignature {
        signer_pubkey: hex::encode(sk.verifying_key().to_bytes()),
        signature: hex::encode(sig.to_bytes()),
    }
}

/// The hex public key for a raw 32-byte Ed25519 seed — the value a wallet pins
/// into its trusted-signer allowlist.
pub fn pubkey_for_seed(seed: &[u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Verify a checkpoint signature and require the signer be on `trusted_pubkeys`
/// (hex Ed25519 keys). Returns `Ok` only when BOTH hold: the signature is
/// cryptographically valid over `NAMESPACE || checkpoint_signing_bytes`, and the
/// signer is in the allowlist. Order matters: an untrusted signer is rejected
/// before any crypto work, a trusted-but-invalid signature after.
pub fn verify_checkpoint_signature(
    cp: &SyncCheckpoint,
    sig: &SyncCheckpointSignature,
    trusted_pubkeys: &[String],
) -> Result<()> {
    let pubkey_bytes: [u8; 32] = decode_fixed(&sig.signer_pubkey).ok_or_else(|| {
        Error::InvalidState("checkpoint signature: signer pubkey is not 32-byte hex".into())
    })?;

    // Trust gate first: is this signer on the allowlist? (Compare decoded bytes
    // so hex case / whitespace never matters.)
    let trusted = trusted_pubkeys
        .iter()
        .filter_map(|t| decode_fixed::<32>(t))
        .any(|t| t == pubkey_bytes);
    if !trusted {
        return Err(Error::InvalidState(format!(
            "sync checkpoint is signed by {} which is NOT in the trusted-signer allowlist — refusing",
            sig.signer_pubkey
        )));
    }

    let sig_bytes: [u8; 64] = decode_fixed(&sig.signature)
        .ok_or_else(|| Error::InvalidState("checkpoint signature: not 64-byte hex".into()))?;
    let vk = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
        Error::InvalidState(format!("checkpoint signature: invalid pubkey: {}", e))
    })?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify(&signed_payload(cp), &signature).map_err(|_| {
        Error::InvalidState(
            "sync checkpoint signature verification FAILED — refusing (tampered checkpoint or wrong key)"
                .into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Hash;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn checkpoint() -> SyncCheckpoint {
        SyncCheckpoint::new(
            12_345,
            Hash::from_bytes([0xAB; 32]),
            98_765,
            Hash::from_bytes([0xCD; 32]),
        )
    }

    #[test]
    fn sign_then_verify_roundtrips_for_trusted_signer() {
        let s = seed(1);
        let cp = checkpoint();
        let sig = sign_checkpoint(&s, &cp);
        let trusted = vec![pubkey_for_seed(&s)];
        assert!(verify_checkpoint_signature(&cp, &sig, &trusted).is_ok());
    }

    #[test]
    fn rejects_signer_not_in_allowlist() {
        let s = seed(1);
        let cp = checkpoint();
        let sig = sign_checkpoint(&s, &cp);
        let trusted = vec![pubkey_for_seed(&seed(2))];
        let err = verify_checkpoint_signature(&cp, &sig, &trusted).unwrap_err();
        assert!(format!("{:?}", err).contains("trusted-signer allowlist"));
    }

    #[test]
    fn rejects_empty_allowlist() {
        let s = seed(1);
        let cp = checkpoint();
        let sig = sign_checkpoint(&s, &cp);
        assert!(verify_checkpoint_signature(&cp, &sig, &[]).is_err());
    }

    #[test]
    fn rejects_tampered_checkpoint_utxo_hash() {
        // The whole point of gap #3: a forged utxo_hash under a valid block_hash
        // signature must fail — the signature binds utxo_hash too.
        let s = seed(1);
        let cp = checkpoint();
        let sig = sign_checkpoint(&s, &cp);
        let mut forged = cp.clone();
        forged.utxo_hash = Hash::from_bytes([0xEE; 32]); // swap the UTXO commitment
        let trusted = vec![pubkey_for_seed(&s)];
        let err = verify_checkpoint_signature(&forged, &sig, &trusted).unwrap_err();
        assert!(format!("{:?}", err).to_lowercase().contains("verification failed"));
    }

    #[test]
    fn rejects_signature_from_a_different_namespace() {
        // A signature over a DIFFERENT domain must not verify as a sync-checkpoint
        // signature, even from a trusted signer over identical field bytes.
        let s = seed(1);
        let cp = checkpoint();
        let sk = SigningKey::from_bytes(&s);
        let mut foreign = Vec::new();
        foreign.extend_from_slice(crate::snapshot::signing::SNAPSHOT_MANIFEST_NAMESPACE);
        foreign.extend_from_slice(&checkpoint_signing_bytes(&cp));
        let foreign_sig = sk.sign(&foreign);
        let sig = SyncCheckpointSignature {
            signer_pubkey: pubkey_for_seed(&s),
            signature: hex::encode(foreign_sig.to_bytes()),
        };
        let trusted = vec![pubkey_for_seed(&s)];
        assert!(verify_checkpoint_signature(&cp, &sig, &trusted).is_err());
    }

    #[test]
    fn rejects_malformed_pubkey_and_sig() {
        let cp = checkpoint();
        let bad_pk = SyncCheckpointSignature {
            signer_pubkey: "xyz".into(),
            signature: hex::encode([0u8; 64]),
        };
        assert!(verify_checkpoint_signature(&cp, &bad_pk, &["xyz".into()]).is_err());

        let s = seed(3);
        let bad_sig = SyncCheckpointSignature {
            signer_pubkey: pubkey_for_seed(&s),
            signature: "00".into(),
        };
        let trusted = vec![pubkey_for_seed(&s)];
        assert!(verify_checkpoint_signature(&cp, &bad_sig, &trusted).is_err());
    }
}
