//! Halo2 proof envelope + serialization.
//!
//! A `Proof` is the opaque byte string a Halo2 prover produces and a
//! Halo2 verifier consumes. Wrapped here in a typed envelope so the
//! chain code can't accidentally hand a non-Orchard proof to the
//! Orchard verifier (the bridge already tags proofs by origin via
//! [`bridge::ProofOrigin`]; this wrapper enforces it on the orchard
//! side).
//!
//! ## Status: SKELETON

use crate::{Error, Result};

/// Orchard Action proof. ~3 KB compressed in the shipped Zcash
/// implementation; bytes here are opaque to the rest of the
/// codebase.
#[derive(Clone, Debug)]
pub struct Proof {
    pub bytes: Vec<u8>,
}

impl Proof {
    /// Wrap raw bytes. Rejects empty; everything else is "valid
    /// shape" — actual crypto validity is checked by the
    /// verifier.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::MalformedWireFormat("empty proof bytes"));
        }
        Ok(Self { bytes })
    }

    /// Convert to the bridge's tagged-proof envelope. This is the
    /// form that crosses into chain code and the verifier router.
    pub fn to_bridge(&self) -> bridge::BridgeRangeProof {
        bridge::BridgeRangeProof {
            bytes: self.bytes.clone(),
            origin: bridge::ProofOrigin::OrchardHalo2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_bytes() {
        assert!(Proof::from_bytes(vec![]).is_err());
    }

    #[test]
    fn bridge_envelope_carries_orchard_origin() {
        let p = Proof::from_bytes(vec![1, 2, 3]).unwrap();
        let env = p.to_bridge();
        assert_eq!(env.origin, bridge::ProofOrigin::OrchardHalo2);
        assert_eq!(env.bytes, vec![1, 2, 3]);
    }
}
