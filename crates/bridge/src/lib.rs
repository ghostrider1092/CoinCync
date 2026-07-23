//! # Tari ↔ Orchard bridge layer
//!
//! The only safe serialization boundary between our two cryptographic
//! subsystems. The rule: **no Tari type crosses into Orchard code, no
//! Orchard type crosses into Tari code**. Only 32-byte opaque
//! identifiers travel across this layer, validated at every entry
//! point.
//!
//! ```text
//!   Tari stack          bridge          Orchard stack
//!   (Ristretto)   ─────────────▶  BridgeCommitment  ─────────────▶  (Pallas)
//!                                 BridgeNullifier
//!                                 BridgeRangeProof
//!                                 BridgeValue
//! ```
//!
//! ## Why this module is always compiled
//!
//! Neither `orchard` nor `tari_bulletproofs_plus` is imported here.
//! The whole point of the bridge is that it speaks *only* in raw
//! `[u8; 32]`. Callers on either side convert their native types to
//! bytes before crossing, and the adapter sub-modules never touch the
//! Tari or Orchard crates directly. That means the bridge compiles
//! even under the default feature set, where the `halo2-orchard`
//! feature is off and `orchard` is not in the dep tree at all.
//!
//! ## Scope
//!
//! 1. [`BridgeCommitment`] — 32-byte validated commitment identifier.
//! 2. [`BridgeNullifier`] — 32-byte validated nullifier identifier.
//! 3. [`BridgeRangeProof`] — tagged range-proof envelope that
//!    remembers which system produced it, so the wrong verifier is
//!    refused via [`assert_correct_verifier`].
//! 4. [`BridgeValue`] — bounded u64 sanity-capped at `MAX_MONEY`.
//! 5. [`BridgeLedger`] — the cross-system replay/double-spend set.
//!
//! The constant-time equality comes from `subtle::ConstantTimeEq` so
//! identifier comparisons don't leak timing side channels.

use std::collections::HashSet;
use std::fmt;

use subtle::ConstantTimeEq;

// ─────────────────────────────────────────────────────────────
// Canonical byte types
// ─────────────────────────────────────────────────────────────

/// A 32-byte commitment that has been validated at the serialization
/// boundary and is safe to pass between Tari and Orchard subsystems.
/// Construction rejects the all-zero point (identity element is
/// unsafe on both Ristretto and Pallas).
#[derive(Clone)]
pub struct BridgeCommitment([u8; 32]);

/// A 32-byte nullifier marking a note or coin as spent. Rejects the
/// all-zero value.
#[derive(Clone)]
pub struct BridgeNullifier([u8; 32]);

/// Envelope around range-proof bytes, tagged with the system that
/// produced them so the matching verifier is always called.
#[derive(Clone, Debug)]
pub struct BridgeRangeProof {
    pub bytes: Vec<u8>,
    pub origin: ProofOrigin,
}

/// Which cryptographic system generated a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofOrigin {
    /// Bulletproofs+ on Ristretto (Tari stack).
    TariBulletproofsPlus,
    /// Halo2 Action circuit on Pallas (Orchard stack).
    OrchardHalo2,
}

/// A bounded monetary amount. Hard-capped at [`BridgeValue::MAX_MONEY`]
/// so cross-system transfers can't exceed either stack's supply limit.
#[derive(Clone, Copy, Debug)]
pub struct BridgeValue(u64);

// ─────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("bridge: zero bytes are not a valid commitment")]
    ZeroBytes,
    #[error("bridge: value exceeds supply cap")]
    ValueExceedsCap,
    #[error("bridge: proof bytes are empty")]
    EmptyProof,
    #[error("bridge: proof bytes are malformed")]
    MalformedProof,
    #[error("bridge: identifier already recorded (double spend or replay)")]
    AlreadySeen,
    #[error("bridge: tari serialization failed: {0}")]
    TariSerializationFailed(String),
    #[error("bridge: orchard serialization failed: {0}")]
    OrchardSerializationFailed(String),
    #[error("bridge: wrong verifier — expected {expected:?}, got {got:?}")]
    WrongVerifier {
        expected: ProofOrigin,
        got: ProofOrigin,
    },
}

// ─────────────────────────────────────────────────────────────
// BridgeCommitment
// ─────────────────────────────────────────────────────────────

impl BridgeCommitment {
    /// Construct from raw bytes. Rejects the all-zero input because
    /// the identity element is not a meaningful commitment on either
    /// Ristretto or Pallas.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BridgeError> {
        if bool::from(bytes.ct_eq(&[0u8; 32])) {
            return Err(BridgeError::ZeroBytes);
        }
        Ok(Self(bytes))
    }

    /// Raw bytes — the only form either subsystem should consume.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Constant-time equality so callers don't leak identifier
    /// matches through timing.
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for BridgeCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Log only the first 4 bytes. Full commitments are
        // privacy-sensitive even when valid.
        write!(
            f,
            "BridgeCommitment({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

// ─────────────────────────────────────────────────────────────
// BridgeNullifier
// ─────────────────────────────────────────────────────────────

impl BridgeNullifier {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BridgeError> {
        if bool::from(bytes.ct_eq(&[0u8; 32])) {
            return Err(BridgeError::ZeroBytes);
        }
        Ok(Self(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for BridgeNullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BridgeNullifier({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

// ─────────────────────────────────────────────────────────────
// BridgeValue
// ─────────────────────────────────────────────────────────────

impl BridgeValue {
    /// 21M base coins × 10^8 subunits. Fits both the Zcash and the
    /// Tari supply caps; callers should narrow further if a specific
    /// asset uses a smaller ceiling.
    pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

    pub fn new(value: u64) -> Result<Self, BridgeError> {
        if value > Self::MAX_MONEY {
            return Err(BridgeError::ValueExceedsCap);
        }
        Ok(Self(value))
    }

    pub fn inner(&self) -> u64 {
        self.0
    }
}

// ─────────────────────────────────────────────────────────────
// Tari adapter
// ─────────────────────────────────────────────────────────────

/// Conversions from the Tari stack (Ristretto / Bulletproofs+). The
/// functions take raw bytes and return bridge types — no Tari crate
/// imports live in this module, so it compiles even without the
/// Tari stack enabled.
pub mod tari_adapter {
    use super::*;

    /// Wrap a Tari Pedersen commitment's 32-byte compressed
    /// serialization for bridge transport.
    pub fn commitment_to_bridge(
        commitment_bytes: [u8; 32],
    ) -> Result<BridgeCommitment, BridgeError> {
        BridgeCommitment::from_bytes(commitment_bytes).map_err(|_| {
            BridgeError::TariSerializationFailed("tari commitment is zero point".into())
        })
    }

    /// Wrap a Tari kernel-excess style nullifier.
    pub fn nullifier_to_bridge(nullifier_bytes: [u8; 32]) -> Result<BridgeNullifier, BridgeError> {
        BridgeNullifier::from_bytes(nullifier_bytes)
    }

    /// Wrap a Bulletproofs+ proof for transport. Minimum length is a
    /// weak sanity check: a real BP+ proof is hundreds of bytes.
    pub fn range_proof_to_bridge(proof_bytes: Vec<u8>) -> Result<BridgeRangeProof, BridgeError> {
        if proof_bytes.is_empty() {
            return Err(BridgeError::EmptyProof);
        }
        if proof_bytes.len() < 64 {
            return Err(BridgeError::MalformedProof);
        }
        Ok(BridgeRangeProof {
            bytes: proof_bytes,
            origin: ProofOrigin::TariBulletproofsPlus,
        })
    }

    /// Receive a `BridgeCommitment` from the Orchard side. The Tari
    /// side must treat these bytes as an opaque cross-chain reference,
    /// not a spendable Ristretto commitment.
    pub fn commitment_from_bridge(bridge: &BridgeCommitment) -> [u8; 32] {
        bridge.to_bytes()
    }
}

// ─────────────────────────────────────────────────────────────
// Orchard adapter
// ─────────────────────────────────────────────────────────────

/// Conversions from the Orchard stack (Pallas / Halo2). Same shape
/// as [`tari_adapter`]; no Orchard crate imports live here.
pub mod orchard_adapter {
    use super::*;

    /// Wrap an Orchard note commitment's byte serialization.
    pub fn commitment_to_bridge(
        commitment_bytes: [u8; 32],
    ) -> Result<BridgeCommitment, BridgeError> {
        BridgeCommitment::from_bytes(commitment_bytes).map_err(|_| {
            BridgeError::OrchardSerializationFailed("orchard commitment is zero point".into())
        })
    }

    /// Wrap an Orchard note nullifier.
    pub fn nullifier_to_bridge(nullifier_bytes: [u8; 32]) -> Result<BridgeNullifier, BridgeError> {
        BridgeNullifier::from_bytes(nullifier_bytes)
    }

    /// Wrap a Halo2 proof for transport. Tagged with `OrchardHalo2`
    /// so [`assert_correct_verifier`] can refuse to route it through
    /// a Bulletproofs verifier.
    pub fn range_proof_to_bridge(proof_bytes: Vec<u8>) -> Result<BridgeRangeProof, BridgeError> {
        if proof_bytes.is_empty() {
            return Err(BridgeError::EmptyProof);
        }
        Ok(BridgeRangeProof {
            bytes: proof_bytes,
            origin: ProofOrigin::OrchardHalo2,
        })
    }

    /// Receive a `BridgeCommitment` from the Tari side. Treat the
    /// bytes as an opaque cross-chain reference, not a Pallas point.
    pub fn commitment_from_bridge(bridge: &BridgeCommitment) -> [u8; 32] {
        bridge.to_bytes()
    }
}

// ─────────────────────────────────────────────────────────────
// Bridge ledger — cross-system replay/double-spend set
// ─────────────────────────────────────────────────────────────

/// Tracks which commitments have crossed the bridge and which
/// nullifiers have been seen. A nullifier marked spent here is
/// spent everywhere — whichever side first submits it, the other
/// side must reject a later replay.
#[derive(Default)]
pub struct BridgeLedger {
    tari_to_orchard: HashSet<[u8; 32]>,
    orchard_to_tari: HashSet<[u8; 32]>,
    seen_nullifiers: HashSet<[u8; 32]>,
}

impl BridgeLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a Tari→Orchard commitment crossing. Returns an error
    /// if this exact commitment has already crossed in this direction.
    pub fn record_tari_to_orchard(
        &mut self,
        commitment: &BridgeCommitment,
    ) -> Result<(), BridgeError> {
        if !self.tari_to_orchard.insert(commitment.to_bytes()) {
            return Err(BridgeError::AlreadySeen);
        }
        Ok(())
    }

    /// Record an Orchard→Tari commitment crossing.
    pub fn record_orchard_to_tari(
        &mut self,
        commitment: &BridgeCommitment,
    ) -> Result<(), BridgeError> {
        if !self.orchard_to_tari.insert(commitment.to_bytes()) {
            return Err(BridgeError::AlreadySeen);
        }
        Ok(())
    }

    /// Record a nullifier from either side. Once recorded, the same
    /// nullifier can never be accepted again — this is the global
    /// double-spend prevention for the entire bridge.
    pub fn record_nullifier(&mut self, nullifier: &BridgeNullifier) -> Result<(), BridgeError> {
        if !self.seen_nullifiers.insert(nullifier.to_bytes()) {
            return Err(BridgeError::AlreadySeen);
        }
        Ok(())
    }

    /// Check whether a nullifier has already been recorded.
    pub fn is_spent(&self, nullifier: &BridgeNullifier) -> bool {
        self.seen_nullifiers.contains(&nullifier.to_bytes())
    }

    pub fn stats(&self) -> BridgeStats {
        BridgeStats {
            tari_to_orchard_count: self.tari_to_orchard.len(),
            orchard_to_tari_count: self.orchard_to_tari.len(),
            total_nullifiers: self.seen_nullifiers.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BridgeStats {
    pub tari_to_orchard_count: usize,
    pub orchard_to_tari_count: usize,
    pub total_nullifiers: usize,
}

// ─────────────────────────────────────────────────────────────
// Proof routing
// ─────────────────────────────────────────────────────────────

/// Refuse to route a proof through the wrong verifier. Tari can't
/// verify a Halo2 proof and Orchard can't verify a Bulletproofs+
/// proof; crossing those wires is a soundness failure, not a runtime
/// bug, so it's caught at the bridge boundary.
pub fn assert_correct_verifier(
    proof: &BridgeRangeProof,
    intended_verifier: ProofOrigin,
) -> Result<(), BridgeError> {
    if proof.origin != intended_verifier {
        return Err(BridgeError::WrongVerifier {
            expected: intended_verifier,
            got: proof.origin,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn non_zero_bytes(lead: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = lead;
        b
    }

    #[test]
    fn commitment_rejects_zero() {
        assert!(BridgeCommitment::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn commitment_accepts_nonzero() {
        let c = BridgeCommitment::from_bytes(non_zero_bytes(1)).unwrap();
        assert_eq!(c.to_bytes()[0], 1);
    }

    #[test]
    fn nullifier_rejects_zero() {
        assert!(BridgeNullifier::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn value_rejects_overflow() {
        assert!(BridgeValue::new(BridgeValue::MAX_MONEY + 1).is_err());
        assert_eq!(
            BridgeValue::new(BridgeValue::MAX_MONEY).unwrap().inner(),
            BridgeValue::MAX_MONEY
        );
    }

    #[test]
    fn commitment_round_trip_tari_to_orchard() {
        let bytes = non_zero_bytes(42);
        let bridge = tari_adapter::commitment_to_bridge(bytes).unwrap();
        assert_eq!(orchard_adapter::commitment_from_bridge(&bridge), bytes);
    }

    #[test]
    fn commitment_round_trip_orchard_to_tari() {
        let bytes = non_zero_bytes(99);
        let bridge = orchard_adapter::commitment_to_bridge(bytes).unwrap();
        assert_eq!(tari_adapter::commitment_from_bridge(&bridge), bytes);
    }

    #[test]
    fn ledger_rejects_repeat_crossing() {
        let mut ledger = BridgeLedger::new();
        let c = BridgeCommitment::from_bytes(non_zero_bytes(1)).unwrap();
        assert!(ledger.record_tari_to_orchard(&c).is_ok());
        assert!(ledger.record_tari_to_orchard(&c).is_err());
    }

    #[test]
    fn ledger_rejects_cross_system_replay() {
        let mut ledger = BridgeLedger::new();
        let nf = BridgeNullifier::from_bytes(non_zero_bytes(5)).unwrap();
        assert!(ledger.record_nullifier(&nf).is_ok());
        // Same nullifier cannot be replayed even from the "other" side
        // — the ledger is global.
        assert!(ledger.record_nullifier(&nf).is_err());
        assert!(ledger.is_spent(&nf));
    }

    #[test]
    fn verifier_routing_catches_mismatch() {
        let tari_proof = BridgeRangeProof {
            bytes: vec![0u8; 674],
            origin: ProofOrigin::TariBulletproofsPlus,
        };
        assert!(
            assert_correct_verifier(&tari_proof, ProofOrigin::OrchardHalo2).is_err(),
            "routing a Tari proof to the Orchard verifier must fail"
        );
        assert!(assert_correct_verifier(&tari_proof, ProofOrigin::TariBulletproofsPlus).is_ok());
    }

    #[test]
    fn verifier_routing_catches_reverse_mismatch() {
        let orchard_proof = BridgeRangeProof {
            bytes: vec![0u8; 1024],
            origin: ProofOrigin::OrchardHalo2,
        };
        assert!(
            assert_correct_verifier(&orchard_proof, ProofOrigin::TariBulletproofsPlus).is_err()
        );
    }

    #[test]
    fn tari_range_proof_rejects_tiny_blob() {
        assert!(tari_adapter::range_proof_to_bridge(vec![]).is_err());
        assert!(tari_adapter::range_proof_to_bridge(vec![0u8; 10]).is_err());
        assert!(tari_adapter::range_proof_to_bridge(vec![0u8; 674]).is_ok());
    }

    #[test]
    fn bridge_stats_count_independently() {
        let mut ledger = BridgeLedger::new();
        let c1 = BridgeCommitment::from_bytes(non_zero_bytes(1)).unwrap();
        let c2 = BridgeCommitment::from_bytes(non_zero_bytes(2)).unwrap();
        let c3 = BridgeCommitment::from_bytes(non_zero_bytes(3)).unwrap();
        let nf1 = BridgeNullifier::from_bytes(non_zero_bytes(10)).unwrap();
        let nf2 = BridgeNullifier::from_bytes(non_zero_bytes(11)).unwrap();

        ledger.record_tari_to_orchard(&c1).unwrap();
        ledger.record_tari_to_orchard(&c2).unwrap();
        ledger.record_orchard_to_tari(&c3).unwrap();
        ledger.record_nullifier(&nf1).unwrap();
        ledger.record_nullifier(&nf2).unwrap();

        let s = ledger.stats();
        assert_eq!(s.tari_to_orchard_count, 2);
        assert_eq!(s.orchard_to_tari_count, 1);
        assert_eq!(s.total_nullifiers, 2);
    }
}
