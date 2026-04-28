//! # Halo2 Shielded Action Circuit (Phase 2 stub)
//!
//! Placeholder for the shielded-pool Halo2 circuit. The real circuit will
//! model a single shielded action (nullifier + commitment + value balance)
//! and is scheduled for Phase 2 of the CoinCync 1.0 build (see
//! `coincync 1.0_build_guide.md` §7.4). Until then this file only exposes
//! type stubs so the rest of the crate compiles.
//!
//! The previous draft used an older `pasta_curves` API (`Ep::to_bytes`,
//! `Fp::from_bytes`) that has since been removed upstream. We stub here
//! rather than patch — the real circuit will be written against the
//! current `halo2_proofs` / `halo2_gadgets` APIs when Phase 2 starts.

/// Stub: public inputs a verifier sees for each shielded action.
/// Real version will hold anchor, nullifier, commitment, value commitment.
#[derive(Debug, Clone, Default)]
pub struct ActionPublicInputs {
    pub anchor: [u8; 32],
    pub nullifier: [u8; 32],
    pub commitment: [u8; 32],
    pub value_commitment: [u8; 32],
}

/// Stub: a shielded action proof as an opaque byte blob.
#[derive(Clone, Debug, Default)]
pub struct ShieldedActionProof {
    pub bytes: Vec<u8>,
}

impl ShieldedActionProof {
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Stub verifier — always returns false until Phase 2.
    pub fn verify(&self, _inputs: &ActionPublicInputs) -> bool {
        false
    }
}
