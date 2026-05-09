//! Core type aliases + the `FinalityAttestation` payload + the
//! verifier trait.
//!
//! The verifier trait is the seam between this pure-state crate and
//! the actual cryptographic primitive. Phase 1 ships a `NoopVerifier`
//! that accepts every attestation regardless of signature bytes;
//! phase 2 swaps in a real `Ed25519Verifier`.

use serde::{Deserialize, Serialize};

/// 32-byte ed25519 public key identifying a miner. Aliased rather
/// than newtyped so the consensus integration can accept whatever
/// `PublicKey` shape it already uses without a conversion ceremony.
pub type MinerPubkey = [u8; 32];

/// 32-byte block hash. Aliased rather than newtyped for the same
/// reason as `MinerPubkey`.
pub type BlockHash = [u8; 32];

/// Expected length of an ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// The per-block payload that a miner attaches to coinbase
/// post-CIP-009.D activation. Verifies (target_height, target_hash)
/// is the canonical chain at that height, from the miner's
/// perspective.
///
/// On the wire (phase 2+) this is appended to the coinbase tx's
/// `extra` field. Phase 1 deals only with the in-memory struct.
///
/// The `signature` field is a `Vec<u8>` of expected length
/// `SIGNATURE_LEN`. Storing as `Vec` rather than `[u8; 64]` keeps
/// `serde::Deserialize` derivable without extra crates; phase 2's
/// wire codec will reject any signature whose length isn't exactly
/// `SIGNATURE_LEN`. The phase 1 `NoopVerifier` ignores the bytes
/// entirely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityAttestation {
    /// The miner's long-term ed25519 finality key. NOT the same as
    /// their wallet / payout / stealth keys — the finality key is
    /// purely for chain attestation and lives a different lifetime
    /// (rotated via the rotation message specified in CIP-009.D §6;
    /// rotation is phase 2+).
    pub miner_pubkey: MinerPubkey,

    /// The height being attested to. Per the CIP, miners attest to
    /// `current_block_height - LAG` (LAG = 100), so the
    /// attestation is always for a confirmed past block.
    pub target_height: u64,

    /// The hash of the block at `target_height` from the miner's
    /// perspective. Miners on different forks at this height
    /// naturally sign different hashes — that's the mechanism
    /// that makes the rule work.
    pub target_hash: BlockHash,

    /// ed25519 signature over `signing_bytes()`. Expected length
    /// `SIGNATURE_LEN` (= 64); phase 2 wire codec enforces.
    pub signature: Vec<u8>,
}

impl FinalityAttestation {
    /// The bytes the signature should be computed over. Used by both
    /// the signer (when constructing) and the verifier (when
    /// validating). Domain-separated with a constant prefix so a
    /// FinalityAttestation signature can never be replayed as some
    /// other ed25519 signature in the protocol.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 32 + 32);
        buf.extend_from_slice(b"CYNC.CIP-009-D.\0");
        buf.extend_from_slice(&self.target_height.to_le_bytes());
        buf.extend_from_slice(&self.target_hash);
        buf
    }
}

/// What we record once an attestation has been accepted: the
/// (miner, height, hash) triple, without the signature (the
/// signature served its purpose at acceptance time and isn't
/// needed for quorum counting).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordedAttestation {
    pub miner_pubkey: MinerPubkey,
    pub target_height: u64,
    pub target_hash: BlockHash,
}

// ────────────────────────────────────────────────────────────────
// Verifier trait — the boundary between this crate and real crypto
// ────────────────────────────────────────────────────────────────

/// Trait for verifying a finality attestation's signature.
///
/// This crate calls `AttestationVerifier::verify` instead of
/// invoking ed25519 directly. The intent: keep this crate's
/// dependency footprint minimal and let the consensus layer plug
/// in whatever ed25519 implementation it already uses (typically
/// `ed25519-dalek` from the main `coincync` crate).
///
/// Phase 1 uses [`NoopVerifier`] in tests and as the documented
/// stub. Phase 2 ships a real verifier.
pub trait AttestationVerifier {
    /// Return `true` if the attestation's signature is a valid
    /// ed25519 signature over its `signing_bytes()` by its
    /// `miner_pubkey`. Return `false` otherwise.
    ///
    /// Implementations MUST NOT have side effects. The trait is
    /// pure verification — caching, key parsing, etc. are an
    /// implementation detail.
    fn verify(&self, attestation: &FinalityAttestation) -> bool;
}

/// Stub verifier that accepts every attestation. Used in phase 1
/// tests and as the default-when-not-yet-activated behavior.
///
/// **DO NOT** use this in production. The `FinalityTracker` accepts
/// the verifier as a generic so the consensus layer can substitute
/// a real verifier without changing the tracker's API.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopVerifier;

impl AttestationVerifier for NoopVerifier {
    fn verify(&self, _attestation: &FinalityAttestation) -> bool {
        true
    }
}

/// Test-only verifier that rejects every attestation. Used to
/// exercise the rejection path in property tests. Public so
/// downstream integration tests can use it too; not gated behind a
/// feature flag because there's no production confusion risk
/// (a verifier that rejects everything is never the right thing to
/// ship).
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAllVerifier;

impl AttestationVerifier for RejectAllVerifier {
    fn verify(&self, _attestation: &FinalityAttestation) -> bool {
        false
    }
}
