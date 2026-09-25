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
//! ## Two levels of check
//! - [`AuditPackage::check_offline_consistency`] — offline cryptographic
//!   well-formedness. **NOT a trust decision** (a prover could invent a
//!   commitment); Sum proofs can't be checked offline at all and are skipped.
//! - [`AuditPackage::verify_anchored`] — the **sound** auditor decision. Every
//!   proof is verified against a [`ChainAnchor`] resolved from the auditor's own
//!   trusted chain view (a `resolve: OutputRef -> ChainAnchor` closure), so each
//!   proof must correspond to a real on-chain output. Covers Balance, Ownership,
//!   and Sum; Source (key-image provenance) anchors differently and is a follow-up.

use crate::crypto::{
    create_balance_proof, create_sum_proof, verify_balance_proof_anchored,
    verify_ownership_proof_anchored, verify_sum_proof_anchored, BlindingFactor, ChainAnchor,
    DisclosureBalanceProof, DisclosureOutputRef, DisclosureProof, DisclosureType, OwnershipProof,
    PedersenCommitment, SumProof,
};
use crate::error::{Error, Result};
use crate::primitives::Hash;
use serde::{Deserialize, Serialize};

/// One entry in an audit package: a disclosure proof, a plain-language statement
/// of what it attests, and (for proofs that don't carry their own on-chain
/// reference) which output the auditor should anchor it to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditItem {
    /// What this proof shows, in words: "treasury solvency ≥ 1,000,000",
    /// "total payroll disbursed for 2026-Q3", "receipt for contributor alice".
    pub statement: String,
    /// The disclosure proof backing the statement.
    pub proof: DisclosureProof,
    /// The on-chain output this proof anchors to, when the proof doesn't already
    /// name it. Balance proofs need it (a commitment isn't tied to an output in
    /// the proof); Ownership proofs carry their own ref; Sum proofs carry many.
    pub output_ref: Option<DisclosureOutputRef>,
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

    /// Attach a proof whose on-chain reference is carried by the proof itself
    /// (Ownership) or which references many outputs (Sum).
    pub fn add(&mut self, statement: impl Into<String>, proof: DisclosureProof) -> &mut Self {
        self.items.push(AuditItem { statement: statement.into(), proof, output_ref: None });
        self
    }

    /// Attach a proof and the on-chain output the auditor should anchor it to
    /// (needed for Balance proofs).
    pub fn add_anchored(
        &mut self,
        statement: impl Into<String>,
        proof: DisclosureProof,
        output_ref: DisclosureOutputRef,
    ) -> &mut Self {
        self.items.push(AuditItem {
            statement: statement.into(),
            proof,
            output_ref: Some(output_ref),
        });
        self
    }

    /// The JSON the auditor receives.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// OFFLINE well-formedness at time `now`. **Not a trust decision.** Sum
    /// proofs are inherently anchored-only (they need the on-chain commitments
    /// they sum over) and are skipped here. `Ok(false)` on expiry, empty package,
    /// or a malformed offline-checkable proof.
    pub fn check_offline_consistency(&self, now: u64) -> Result<bool> {
        if !self.unexpired_and_nonempty(now) {
            return Ok(false);
        }
        for item in &self.items {
            if matches!(item.proof.proof_type, DisclosureType::Sum) {
                continue; // anchored-only; covered by verify_anchored
            }
            if !item.proof.verify_internal_consistency()? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The SOUND auditor decision at time `now`. `resolve` maps an on-chain
    /// [`DisclosureOutputRef`] to the [`ChainAnchor`] the auditor read from their
    /// trusted chain view. Every proof is verified against real on-chain outputs.
    /// `Ok(false)` on expiry, a missing anchor, or any failed proof (fail-closed).
    /// Source proofs are not yet wired (they anchor on key-image provenance).
    pub fn verify_anchored<F>(&self, now: u64, resolve: F) -> Result<bool>
    where
        F: Fn(&DisclosureOutputRef) -> Result<Option<ChainAnchor>>,
    {
        if !self.unexpired_and_nonempty(now) {
            return Ok(false);
        }
        for item in &self.items {
            let ok = match item.proof.proof_type {
                DisclosureType::Balance => {
                    let inner: DisclosureBalanceProof = decode_inner(&item.proof)?;
                    let oref = match &item.output_ref {
                        Some(r) => r,
                        None => return Ok(false), // Balance needs its output ref
                    };
                    match resolve(oref)? {
                        Some(anchor) => verify_balance_proof_anchored(&inner, &anchor)?.is_valid(),
                        None => return Ok(false),
                    }
                }
                DisclosureType::Ownership => {
                    let inner: OwnershipProof = decode_inner(&item.proof)?;
                    let oref = DisclosureOutputRef {
                        tx_hash: inner.tx_hash,
                        output_index: inner.output_index,
                    };
                    match resolve(&oref)? {
                        Some(anchor) => verify_ownership_proof_anchored(&inner, &anchor)?.is_valid(),
                        None => return Ok(false),
                    }
                }
                DisclosureType::Sum => {
                    let inner: SumProof = decode_inner(&item.proof)?;
                    verify_sum_proof_anchored(&inner, |r| resolve(r))?.is_valid()
                }
                DisclosureType::Source => {
                    return Err(Error::CryptoError(
                        "Source anchored verification (key-image provenance) is not yet \
                         wired in the compliance connector"
                            .into(),
                    ));
                }
            };
            if !ok {
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

/// Builds a payroll run's [`AuditPackage`] — the product workflow. The org proves
/// the **org-side** facts (treasury solvency, total disbursed); each **recipient**
/// contributes their own receipt (an ownership proof only they can produce). One
/// flow for a treasurer, one package for an auditor, no contributor's pay exposed
/// to another.
pub struct PayrollRun {
    package: AuditPackage,
}

impl PayrollRun {
    pub fn new(
        org: impl Into<String>,
        period: impl Into<String>,
        created_at: u64,
        expires_at: Option<u64>,
    ) -> Self {
        Self { package: AuditPackage::new(org, period, created_at, expires_at) }
    }

    /// Prove the treasury (its on-chain output `output_ref`, commitment
    /// `commitment`) holds at least `threshold`, without revealing the balance.
    pub fn treasury_solvency(
        &mut self,
        value: u64,
        blinding: &BlindingFactor,
        commitment: &PedersenCommitment,
        threshold: u64,
        output_ref: DisclosureOutputRef,
    ) -> Result<&mut Self> {
        let bp = create_balance_proof(value, blinding, commitment, threshold)?;
        let stmt = format!("treasury solvency >= {threshold}");
        let dp = DisclosureProof::from_balance(&bp, &stmt, self.package.expires_at)?;
        self.package.add_anchored(stmt, dp, output_ref);
        Ok(self)
    }

    /// Prove the total disbursed in this run — the sum of the payment outputs —
    /// without revealing individual amounts. Each output is
    /// `(amount, blinding, tx_hash, output_index)`.
    pub fn total_disbursed(
        &mut self,
        outputs: &[(u64, BlindingFactor, Hash, u8)],
        height_range: (u64, u64),
    ) -> Result<&mut Self> {
        let sp = create_sum_proof(outputs, height_range)?;
        let stmt = format!("total disbursed = {}", sp.claimed_total);
        let dp = DisclosureProof::from_sum(&sp, &stmt, self.package.expires_at)?;
        self.package.add(stmt, dp);
        Ok(self)
    }

    /// A recipient adds their own receipt (an ownership [`DisclosureProof`] they
    /// built with their one-time key — the org cannot forge it).
    pub fn add_recipient_receipt(&mut self, recipient: &str, receipt: DisclosureProof) -> &mut Self {
        self.package.add(format!("receipt for {recipient}"), receipt);
        self
    }

    /// The assembled audit package.
    pub fn finish(self) -> AuditPackage {
        self.package
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_balance_proof, BlindingFactor, PedersenCommitment};
    use rand::rngs::OsRng;

    fn oref(tag: u8, idx: u8) -> DisclosureOutputRef {
        DisclosureOutputRef { tx_hash: Hash::from_bytes([tag; 32]), output_index: idx }
    }

    fn treasury_solvency_proof(threshold: u64) -> (DisclosureProof, [u8; 32]) {
        let value = 5_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);
        let bp = create_balance_proof(value, &blinding, &commitment, threshold).unwrap();
        let dp = DisclosureProof::from_balance(&bp, "treasury solvency", Some(2_000_000_000)).unwrap();
        (dp, commitment.to_bytes())
    }

    #[test]
    fn offline_consistency_and_json_round_trip() {
        let (dp, _c) = treasury_solvency_proof(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, oref(9, 0));

        assert!(pkg.check_offline_consistency(1_000_000).unwrap());
        let json = pkg.to_json().unwrap();
        let received = AuditPackage::from_json(&json).unwrap();
        assert!(received.check_offline_consistency(1_000_000).unwrap());
        assert_eq!(received.org, "Acme DAO");
    }

    #[test]
    fn anchored_verify_is_the_sound_check() {
        let (dp, commitment) = treasury_solvency_proof(1_000_000);
        let t_ref = oref(9, 0);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, t_ref.clone());

        // Correct anchor (the on-chain commitment the proof was built over).
        let good = ChainAnchor::new(t_ref.clone(), commitment, [0u8; 32], 10);
        assert!(pkg
            .verify_anchored(1_000_000, |_r| Ok(Some(good.clone())))
            .unwrap());

        // Anchor at a different commitment => rejected.
        let wrong = ChainAnchor::new(t_ref.clone(), [9u8; 32], [0u8; 32], 10);
        assert!(!pkg
            .verify_anchored(1_000_000, |_r| Ok(Some(wrong.clone())))
            .unwrap());

        // No anchor => not trusted.
        assert!(!pkg.verify_anchored(1_000_000, |_r| Ok(None)).unwrap());
    }

    #[test]
    fn expired_and_empty_fail_closed() {
        let (dp, _c) = treasury_solvency_proof(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(5_000));
        pkg.add_anchored("treasury solvency", dp, oref(9, 0));
        assert!(!pkg.check_offline_consistency(10_000).unwrap());

        let empty = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, None);
        assert!(!empty.check_offline_consistency(1_000_000).unwrap());
    }

    #[test]
    fn payroll_run_builds_and_fully_anchored_verifies() {
        // Payment outputs disbursed this run (compute commitments before moving blindings).
        let (a1, a2) = (300_000u64, 200_000u64);
        let b1 = BlindingFactor::random(&mut OsRng);
        let b2 = BlindingFactor::random(&mut OsRng);
        let c1 = PedersenCommitment::commit(a1, &b1).to_bytes();
        let c2 = PedersenCommitment::commit(a2, &b2).to_bytes();
        let (r1, r2) = (oref(1, 0), oref(2, 1));
        let outputs = vec![(a1, b1, r1.tx_hash, r1.output_index), (a2, b2, r2.tx_hash, r2.output_index)];

        // Treasury.
        let tv = 10_000_000u64;
        let tb = BlindingFactor::random(&mut OsRng);
        let tc = PedersenCommitment::commit(tv, &tb);
        let t_ref = oref(9, 0);

        let mut run = PayrollRun::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        run.treasury_solvency(tv, &tb, &tc, 1_000_000, t_ref.clone()).unwrap();
        run.total_disbursed(&outputs, (0, 100)).unwrap();
        let pkg = run.finish();

        assert_eq!(pkg.items.len(), 2);
        assert!(pkg.items[1].statement.contains("500000"), "total = 300k + 200k");

        // The auditor's trusted chain view: each output ref -> its on-chain anchor.
        let tc_bytes = tc.to_bytes();
        let resolve = |r: &DisclosureOutputRef| -> Result<Option<ChainAnchor>> {
            let a = if *r == t_ref {
                ChainAnchor::new(t_ref.clone(), tc_bytes, [0u8; 32], 50)
            } else if *r == r1 {
                ChainAnchor::new(r1.clone(), c1, [0u8; 32], 50)
            } else if *r == r2 {
                ChainAnchor::new(r2.clone(), c2, [0u8; 32], 50)
            } else {
                return Ok(None);
            };
            Ok(Some(a))
        };

        // The WHOLE payroll package (solvency + total-disbursed) verifies anchored.
        assert!(pkg.verify_anchored(1_000_000, resolve).unwrap(), "payroll package must fully anchor-verify");
    }
}
