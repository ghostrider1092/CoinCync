//! Compliance connector — auditor-facing disclosure packages.
//!
//! Use-case glue for CoinCync's compliant-privacy proposition (private payroll,
//! confidential B2B settlement): it composes the **native** selective-disclosure
//! suite ([`crate::crypto`] disclosure proofs) into the single artifact an
//! organization hands an auditor — a labeled, time-boxed bundle of disclosure
//! proofs that reconcile a period **without exposing individuals to each other
//! or to the public.**
//!
//! Works on the **live transparent layer today** (Pedersen commitments +
//! bulletproofs), independent of the gated Spark shielded pool. Spark is the
//! stronger-shielding upgrade underneath the same disclosure model.
//!
//! ## Two levels of check (this is the important part)
//! - [`AuditPackage::check_offline_consistency`] — the offline cryptographic
//!   check. Confirms each proof is well-formed. **NOT a trust decision:** a
//!   prover could pass it with a commitment they invented.
//! - [`AuditPackage::verify_anchored`] — the **sound** auditor decision. Each
//!   proof is verified against a [`ChainAnchor`] the auditor resolves from their
//!   own trusted chain view, so the proof must correspond to a real on-chain
//!   output. This is what an audit actually relies on.

use crate::crypto::{
    verify_balance_proof_anchored, verify_ownership_proof_anchored, ChainAnchor,
    DisclosureBalanceProof, DisclosureProof, DisclosureType, OwnershipProof,
};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// One entry in an audit package: a disclosure proof plus a plain-language
/// statement of what it attests, so the auditor reads intent, not just crypto.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditItem {
    /// What this proof shows, in words: "treasury solvency ≥ 1,000,000",
    /// "total payroll disbursed for 2026-Q3", "receipt for contributor alice".
    pub statement: String,
    /// The disclosure proof backing the statement.
    pub proof: DisclosureProof,
}

/// What an org hands an auditor to reconcile a payroll run or settlement period.
/// Private to the public and to other recipients; provable to the auditor, and
/// time-boxed so access expires.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditPackage {
    pub org: String,
    pub period: String,
    pub created_at: u64,
    /// Whole-package expiry — the auditor's window closes after this.
    pub expires_at: Option<u64>,
    pub items: Vec<AuditItem>,
}

impl AuditPackage {
    pub fn new(
        org: impl Into<String>,
        period: impl Into<String>,
        created_at: u64,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            org: org.into(),
            period: period.into(),
            created_at,
            expires_at,
            items: Vec::new(),
        }
    }

    /// Attach a disclosure proof with a plain-language statement of what it shows.
    pub fn add(&mut self, statement: impl Into<String>, proof: DisclosureProof) -> &mut Self {
        self.items.push(AuditItem { statement: statement.into(), proof });
        self
    }

    /// The JSON the auditor receives.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// OFFLINE consistency check at time `now`: package and proofs unexpired, and
    /// every proof cryptographically well-formed. **Not a trust decision** — use
    /// it as a fast pre-check; a real audit calls [`verify_anchored`].
    /// `Ok(false)` on any expiry, empty package, or malformed proof.
    pub fn check_offline_consistency(&self, now: u64) -> Result<bool> {
        if !self.unexpired_and_nonempty(now) {
            return Ok(false);
        }
        for item in &self.items {
            if !item.proof.verify_internal_consistency()? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The SOUND auditor decision at time `now`. For each item, `resolve` returns
    /// the [`ChainAnchor`] the auditor read from their trusted chain view; the
    /// proof is verified against it, so it must correspond to a real on-chain
    /// output. `Ok(false)` if anything is expired, unanchored, or fails to
    /// verify (fail-closed). Sum proofs need a multi-output resolver and are not
    /// yet wired here (they return an error).
    pub fn verify_anchored<F>(&self, now: u64, resolve: F) -> Result<bool>
    where
        F: Fn(&AuditItem) -> Option<ChainAnchor>,
    {
        if !self.unexpired_and_nonempty(now) {
            return Ok(false);
        }
        for item in &self.items {
            let anchor = match resolve(item) {
                Some(a) => a,
                None => return Ok(false), // no trusted anchor => cannot be trusted
            };
            let valid = match item.proof.proof_type {
                DisclosureType::Balance => {
                    let inner: DisclosureBalanceProof = decode_inner(&item.proof)?;
                    verify_balance_proof_anchored(&inner, &anchor)?.is_valid()
                }
                DisclosureType::Ownership => {
                    let inner: OwnershipProof = decode_inner(&item.proof)?;
                    verify_ownership_proof_anchored(&inner, &anchor)?.is_valid()
                }
                DisclosureType::Sum | DisclosureType::Source => {
                    // Sum needs a multi-output resolver; Source anchors on
                    // key-image provenance (a different resolver shape). Balance
                    // + Ownership (treasury solvency + recipient receipt) cover
                    // the core payroll workflow; the other two are a follow-up.
                    return Err(Error::CryptoError(
                        "Sum/Source anchored verification is not yet wired in the \
                         compliance connector (Balance and Ownership are)"
                            .into(),
                    ));
                }
            };
            if !valid {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn unexpired_and_nonempty(&self, now: u64) -> bool {
        if self.items.is_empty() {
            return false;
        }
        if let Some(exp) = self.expires_at {
            if now > exp {
                return false;
            }
        }
        self.items
            .iter()
            .all(|i| i.proof.expires_at.map_or(true, |exp| now <= exp))
    }
}

fn decode_inner<T: for<'de> Deserialize<'de>>(proof: &DisclosureProof) -> Result<T> {
    serde_json::from_slice(&proof.proof_data).map_err(|e| Error::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_balance_proof, BlindingFactor, PedersenCommitment};
    use crate::primitives::Hash;
    use rand::rngs::OsRng;

    /// A treasury-solvency disclosure (prove balance ≥ `threshold`) and the
    /// on-chain commitment it was built over, for anchoring.
    fn treasury_solvency(threshold: u64) -> (DisclosureProof, [u8; 32]) {
        let value = 5_000_000u64; // actual (hidden) treasury balance
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);
        let bp = create_balance_proof(value, &blinding, &commitment, threshold).unwrap();
        let dp = DisclosureProof::from_balance(&bp, "treasury solvency", Some(2_000_000_000)).unwrap();
        (dp, commitment.to_bytes())
    }

    fn anchor_for(commitment: [u8; 32]) -> ChainAnchor {
        ChainAnchor::new(
            crate::crypto::DisclosureOutputRef { tx_hash: Hash::from_bytes([1u8; 32]), output_index: 0 },
            commitment,
            [0u8; 32],
            10,
        )
    }

    #[test]
    fn offline_consistency_and_json_round_trip() {
        let (dp, _c) = treasury_solvency(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add("treasury solvency >= 1,000,000", dp);

        assert!(pkg.check_offline_consistency(1_000_000).unwrap(), "well-formed package");
        let json = pkg.to_json().unwrap();
        let received = AuditPackage::from_json(&json).unwrap();
        assert!(received.check_offline_consistency(1_000_000).unwrap(), "survives JSON");
        assert_eq!(received.org, "Acme DAO");
    }

    #[test]
    fn anchored_verify_is_the_sound_check() {
        let (dp, commitment) = treasury_solvency(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add("treasury solvency >= 1,000,000", dp);

        // Correct anchor (the on-chain commitment the proof was built over) => valid.
        let good = anchor_for(commitment);
        assert!(pkg.verify_anchored(1_000_000, |_| Some(good.clone())).unwrap(), "sound anchor verifies");

        // Anchor pointing at a different on-chain commitment => rejected (a prover
        // can't pass off a proof against an output that isn't theirs).
        let wrong = anchor_for([9u8; 32]);
        assert!(!pkg.verify_anchored(1_000_000, |_| Some(wrong.clone())).unwrap(), "wrong anchor rejected");

        // No anchor available => cannot be trusted.
        assert!(!pkg.verify_anchored(1_000_000, |_| None).unwrap(), "unanchored is not trusted");
    }

    #[test]
    fn expired_and_empty_fail_closed() {
        let (dp, _c) = treasury_solvency(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(5_000));
        pkg.add("treasury solvency", dp);
        assert!(!pkg.check_offline_consistency(10_000).unwrap(), "past window fails closed");

        let empty = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, None);
        assert!(!empty.check_offline_consistency(1_000_000).unwrap(), "empty proves nothing");
    }
}
