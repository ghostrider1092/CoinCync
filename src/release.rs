//! # Release attestation — reproducible-build manifests + multi-signer verify
//!
//! Supply-chain trust for CoinCync binaries, like Bitcoin/Monero's Guix/Gitian
//! + multi-maintainer signing. A [`ReleaseManifest`] pins the exact SHA-256 (and
//! size) of every release artifact for a given `version` + `commit`. Multiple
//! maintainers sign the manifest's canonical bytes with their ed25519 keys, and
//! [`verify_signatures`] enforces an **N-of-M** threshold against a committed set
//! of maintainer public keys — so no single machine or person can slip a
//! backdoored binary past release verification.
//!
//! This module is the format + verification core (no I/O). The `release-attest`
//! binary wraps it for hashing artifacts, signing, and verifying.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation tag for the release-manifest signing preimage. Never reuse
/// for any other signature in the protocol.
pub const RELEASE_MANIFEST_DOMAIN: &[u8] = b"coincync/release-manifest/v1";

/// One artifact's pinned identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactHash {
    pub name: String,
    /// Lower-case hex SHA-256 of the artifact bytes.
    pub sha256: String,
    pub size: u64,
}

/// The signed release manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub version: String,
    pub commit: String,
    /// Sorted by `name` for a canonical, deterministic signing preimage.
    pub artifacts: Vec<ArtifactHash>,
}

impl ReleaseManifest {
    pub fn new(version: String, commit: String, mut artifacts: Vec<ArtifactHash>) -> Self {
        artifacts.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            version,
            commit,
            artifacts,
        }
    }

    /// Canonical bytes maintainers sign. Length-prefixed + domain-tagged so it
    /// is deterministic and unambiguous (no field-boundary collisions), and
    /// order-independent because `new` sorts the artifacts.
    pub fn signing_bytes(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(RELEASE_MANIFEST_DOMAIN);
        h.update((self.version.len() as u32).to_le_bytes());
        h.update(self.version.as_bytes());
        h.update((self.commit.len() as u32).to_le_bytes());
        h.update(self.commit.as_bytes());
        h.update((self.artifacts.len() as u32).to_le_bytes());
        for a in &self.artifacts {
            h.update((a.name.len() as u32).to_le_bytes());
            h.update(a.name.as_bytes());
            h.update(a.size.to_le_bytes());
            h.update((a.sha256.len() as u32).to_le_bytes());
            h.update(a.sha256.as_bytes());
        }
        h.finalize().into()
    }

    /// Sign the manifest with a maintainer's ed25519 key.
    pub fn sign(&self, key: &SigningKey) -> Signature {
        key.sign(&self.signing_bytes())
    }

    /// Verify one artifact's on-disk bytes against its pinned hash + size.
    pub fn verify_artifact(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let entry = self
            .artifacts
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| format!("artifact '{name}' not in manifest"))?;
        if bytes.len() as u64 != entry.size {
            return Err(format!(
                "artifact '{name}': size {} != manifest {}",
                bytes.len(),
                entry.size
            ));
        }
        let actual = sha256_hex(bytes);
        if actual != entry.sha256 {
            return Err(format!("artifact '{name}': sha256 mismatch"));
        }
        Ok(())
    }
}

/// Lower-case hex SHA-256 of some bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Verify an **N-of-M** maintainer signature set over a manifest.
///
/// Only signatures from keys in `maintainers` count, each maintainer counts at
/// most once, and each must verify over the manifest's canonical bytes. Returns
/// the number of distinct valid maintainer signatures on success, or an error
/// if fewer than `threshold` are valid.
pub fn verify_signatures(
    manifest: &ReleaseManifest,
    sigs: &[(VerifyingKey, Signature)],
    maintainers: &[VerifyingKey],
    threshold: usize,
) -> Result<usize, String> {
    if threshold == 0 {
        return Err("threshold must be >= 1".into());
    }
    let msg = manifest.signing_bytes();
    let mut valid: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for (vk, sig) in sigs {
        let is_maintainer = maintainers.iter().any(|m| m.to_bytes() == vk.to_bytes());
        if !is_maintainer {
            continue; // signature from a non-maintainer key does not count
        }
        if vk.verify(&msg, sig).is_ok() {
            valid.insert(vk.to_bytes());
        }
    }
    if valid.len() >= threshold {
        Ok(valid.len())
    } else {
        Err(format!(
            "insufficient maintainer signatures: {} valid, {} required",
            valid.len(),
            threshold
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn manifest() -> ReleaseManifest {
        ReleaseManifest::new(
            "2.0.0".into(),
            "cfb979a1".into(),
            vec![
                ArtifactHash { name: "coincync-node".into(), sha256: sha256_hex(b"node-bytes"), size: 10 },
                ArtifactHash { name: "coincync-wallet".into(), sha256: sha256_hex(b"wallet-bytes"), size: 12 },
            ],
        )
    }

    #[test]
    fn signing_bytes_are_order_independent_and_deterministic() {
        let a = ReleaseManifest::new(
            "1".into(),
            "c".into(),
            vec![
                ArtifactHash { name: "b".into(), sha256: "x".into(), size: 1 },
                ArtifactHash { name: "a".into(), sha256: "y".into(), size: 2 },
            ],
        );
        let b = ReleaseManifest::new(
            "1".into(),
            "c".into(),
            vec![
                ArtifactHash { name: "a".into(), sha256: "y".into(), size: 2 },
                ArtifactHash { name: "b".into(), sha256: "x".into(), size: 1 },
            ],
        );
        assert_eq!(a.signing_bytes(), b.signing_bytes(), "artifact order must not affect the preimage");
        assert_eq!(a.signing_bytes(), a.signing_bytes());
    }

    #[test]
    fn n_of_m_threshold_enforced() {
        let m = manifest();
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let k3 = SigningKey::generate(&mut OsRng);
        let maintainers = vec![k1.verifying_key(), k2.verifying_key(), k3.verifying_key()];

        // One signature: below a 2-of-3 threshold.
        let sigs1 = vec![(k1.verifying_key(), m.sign(&k1))];
        assert!(verify_signatures(&m, &sigs1, &maintainers, 2).is_err());

        // Two distinct maintainers: meets 2-of-3.
        let sigs2 = vec![(k1.verifying_key(), m.sign(&k1)), (k2.verifying_key(), m.sign(&k2))];
        assert_eq!(verify_signatures(&m, &sigs2, &maintainers, 2).unwrap(), 2);
    }

    #[test]
    fn non_maintainer_and_duplicate_signatures_do_not_count() {
        let m = manifest();
        let k1 = SigningKey::generate(&mut OsRng);
        let outsider = SigningKey::generate(&mut OsRng);
        let maintainers = vec![k1.verifying_key()];

        // Outsider signature is ignored; k1 signing twice counts once.
        let sigs = vec![
            (k1.verifying_key(), m.sign(&k1)),
            (k1.verifying_key(), m.sign(&k1)),
            (outsider.verifying_key(), m.sign(&outsider)),
        ];
        assert_eq!(verify_signatures(&m, &sigs, &maintainers, 1).unwrap(), 1);
        assert!(verify_signatures(&m, &sigs, &maintainers, 2).is_err());
    }

    #[test]
    fn tampered_manifest_breaks_signatures() {
        let m = manifest();
        let k1 = SigningKey::generate(&mut OsRng);
        let maintainers = vec![k1.verifying_key()];
        let sig = m.sign(&k1);

        // Same signature against a manifest with a changed version must fail.
        let mut tampered = m.clone();
        tampered.version = "2.0.1".into();
        assert!(verify_signatures(&tampered, &[(k1.verifying_key(), sig)], &maintainers, 1).is_err());
    }

    #[test]
    fn verify_artifact_detects_tampering() {
        let m = manifest();
        assert!(m.verify_artifact("coincync-node", b"node-bytes").is_ok());
        assert!(m.verify_artifact("coincync-node", b"evil-bytes!").is_err()); // hash mismatch
        assert!(m.verify_artifact("coincync-node", b"node-byteX").is_err()); // same len, diff bytes
        assert!(m.verify_artifact("unknown", b"x").is_err());
    }
}
