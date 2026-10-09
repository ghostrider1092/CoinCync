//! Cross-chain on-ramp: the peg-in TURNSTILE seam (CIP-Cross-Chain-Onramp).
//!
//! DESIGN SCAFFOLD ONLY — gated `feature = "crosschain-onramp"`, off by default,
//! and FAIL-CLOSED. No real peg logic, no mint path, nothing calls this. It
//! freezes the interfaces (attestation shape + verify seam) for review ahead of
//! the post-audit implementation. It is NOT sound and MUST NOT be activated.
//!
//! See `docs/design/cip-crosschain-onramp.md`. Sequenced AFTER the Spark audit;
//! scope-sprawl discipline (`coincync-strategy-narrow-shielded`) applies.

use borsh::{BorshDeserialize, BorshSerialize};

/// A claim that value was locked/burned on a source chain, authorizing a 1:1
/// shielded mint into the Spark pool. The authorization proof is opaque here — a
/// threshold signature, a bonded claim, or a light-client proof, per the trust
/// model — so the wire shape is stable as the trust model decentralizes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PegAttestation {
    /// Source chain identifier (domain-separated).
    pub source_chain_id: u32,
    /// Unique id of the source-chain lock/burn (replay key — mints at most once).
    pub source_lock_id: Vec<u8>,
    /// Pegged amount (atomic units) to mint into the pool.
    pub amount: u64,
    /// Recipient CoinCync Spark address (bech32m bytes).
    pub recipient: Vec<u8>,
    /// A CoinCync anchor (e.g. a recent block hash) binding the attestation to
    /// this chain's history, to bound the cross-chain reorg window.
    pub coincync_anchor: [u8; 32],
    /// Opaque authorization proof (threshold sig / bonded claim / light-client
    /// proof), interpreted by the active [`PegAttestor`].
    pub authorization: Vec<u8>,
}

/// An authorized peg-in extracted from a verified attestation: the value and
/// recipient to mint, plus the lock id for replay bookkeeping. It carries no
/// authority beyond "mint this shielded coin" — never any spend authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedPegIn {
    pub amount: u64,
    pub recipient: Vec<u8>,
    pub source_lock_id: Vec<u8>,
}

/// Verifier for peg attestations. Implementations bind the trust model
/// (federated threshold → bonded → light client); the consensus mint-auth check
/// will call this against the active peg authority. `None` means "not a valid
/// peg-in" (fail-closed). A returned [`AuthorizedPegIn`] is NOT a mint authority
/// by itself — the caller still enforces the solvency + replay invariants.
pub trait PegAttestor {
    fn verify(&self, attestation: &PegAttestation) -> Option<AuthorizedPegIn>;
}

/// Production default: rejects every attestation. The on-ramp stays off until a
/// real attestor is built, reviewed, and activated post-audit — a node with the
/// feature compiled in still mints nothing.
pub struct FailClosedAttestor;

impl PegAttestor for FailClosedAttestor {
    fn verify(&self, _attestation: &PegAttestation) -> Option<AuthorizedPegIn> {
        None // fail-closed: the scaffold authorizes no peg-in
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PegAttestation {
        PegAttestation {
            source_chain_id: 1,
            source_lock_id: vec![0xab; 16],
            amount: 1_000,
            recipient: b"st1recipient".to_vec(),
            coincync_anchor: [7u8; 32],
            authorization: vec![0u8; 64],
        }
    }

    #[test]
    fn fail_closed_attestor_authorizes_nothing() {
        assert!(FailClosedAttestor.verify(&sample()).is_none());
    }

    #[test]
    fn attestation_borsh_round_trips() {
        let a = sample();
        let bytes = borsh::to_vec(&a).unwrap();
        let b: PegAttestation = borsh::from_slice(&bytes).unwrap();
        assert_eq!(a, b);
    }
}
