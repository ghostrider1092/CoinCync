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
//! bulletproofs); Spark is the stronger-shielding upgrade under the same model.
//!
//! ## Two levels of check
//! - [`AuditPackage::check_offline_consistency`] — offline well-formedness.
//!   **NOT a trust decision.** Sum proofs are anchored-only and skipped here.
//! - [`AuditPackage::verify_anchored`] — the **sound** auditor decision. Every
//!   proof is checked against a [`ChainView`] the auditor trusts (its real UTXO
//!   set + spent-key-image index): Balance/Ownership/Sum resolve on-chain
//!   anchors, Source checks key-image spentness. Covers all four proof types.

use crate::crypto::{
    create_balance_proof, create_ownership_proof, create_source_proof, create_sum_proof,
    verify_balance_proof_anchored, verify_ownership_proof_anchored, verify_source_proof_anchored,
    verify_sum_proof_anchored, BlindingFactor, ChainAnchor, DisclosureBalanceProof,
    DisclosureOutputRef, DisclosureProof, DisclosureType, KeyImage, OwnershipProof,
    PedersenCommitment, SourceProof, SumProof,
};
use crate::error::{Error, Result};
use crate::primitives::{Hash, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The auditor's trusted view of the chain, against which disclosure proofs are
/// anchored. A running node implements this over its real UTXO set + spent-key-
/// image index; [`InMemoryChainView`] is the in-process implementation for tools
/// and tests. A proof is only trustworthy relative to a view like this — an
/// offline proof alone can be passed with an invented commitment/key.
pub trait ChainView {
    /// The on-chain anchor for an output (its commitment, stealth address, and
    /// canonical height), or `None` if the output isn't in the trusted view.
    fn anchor(&self, output_ref: &DisclosureOutputRef) -> Result<Option<ChainAnchor>>;

    /// Whether `key_image` has been spent on the canonical chain (for source
    /// proofs — provenance of a spend).
    fn key_image_spent(&self, key_image: &KeyImage) -> Result<bool>;
}

/// In-process [`ChainView`] for tools and tests. A node wires a real one over
/// its chain state; this one is populated explicitly.
#[derive(Default, Clone, Debug)]
pub struct InMemoryChainView {
    anchors: HashMap<DisclosureOutputRef, ChainAnchor>,
    spent_key_images: HashSet<KeyImage>,
}

impl InMemoryChainView {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record an output's on-chain anchor.
    pub fn with_anchor(mut self, anchor: ChainAnchor) -> Self {
        self.anchors.insert(anchor.output_ref.clone(), anchor);
        self
    }
    /// Record a key image as spent on-chain.
    pub fn with_spent_key_image(mut self, key_image: KeyImage) -> Self {
        self.spent_key_images.insert(key_image);
        self
    }
}

impl ChainView for InMemoryChainView {
    fn anchor(&self, output_ref: &DisclosureOutputRef) -> Result<Option<ChainAnchor>> {
        Ok(self.anchors.get(output_ref).cloned())
    }
    fn key_image_spent(&self, key_image: &KeyImage) -> Result<bool> {
        Ok(self.spent_key_images.contains(key_image))
    }
}

/// One entry in an audit package: a disclosure proof, a plain-language statement,
/// and (for proofs that don't carry their own on-chain reference) which output
/// the auditor anchors it to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditItem {
    pub statement: String,
    pub proof: DisclosureProof,
    /// The on-chain output this proof anchors to, when the proof doesn't name it
    /// (Balance). Ownership carries its own ref; Sum carries many; Source uses a
    /// key image instead.
    pub output_ref: Option<DisclosureOutputRef>,
}

/// What an org hands an auditor to reconcile a payroll run or settlement period.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditPackage {
    pub org: String,
    pub period: String,
    pub created_at: u64,
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
        Self { org: org.into(), period: period.into(), created_at, expires_at, items: Vec::new() }
    }

    /// Attach a proof whose on-chain reference is carried by the proof (Ownership,
    /// Source) or which references many outputs (Sum).
    pub fn add(&mut self, statement: impl Into<String>, proof: DisclosureProof) -> &mut Self {
        self.items.push(AuditItem { statement: statement.into(), proof, output_ref: None });
        self
    }

    /// Attach a proof plus the on-chain output the auditor should anchor it to
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

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// OFFLINE well-formedness at time `now`. **Not a trust decision.** Sum
    /// proofs are anchored-only and skipped. `Ok(false)` on expiry, empty
    /// package, or a malformed offline-checkable proof.
    pub fn check_offline_consistency(&self, now: u64) -> Result<bool> {
        if !self.unexpired_and_nonempty(now) {
            return Ok(false);
        }
        for item in &self.items {
            if matches!(item.proof.proof_type, DisclosureType::Sum) {
                continue;
            }
            if !item.proof.verify_internal_consistency()? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The SOUND auditor decision at time `now`, against a trusted [`ChainView`].
    /// Every proof is verified relative to real on-chain state, so it must
    /// correspond to actual outputs / spends. `Ok(false)` on expiry, a missing
    /// anchor, or any failed proof (fail-closed).
    pub fn verify_anchored<V: ChainView>(&self, now: u64, chain: &V) -> Result<bool> {
        if !self.unexpired_and_nonempty(now) {
            return Ok(false);
        }
        for item in &self.items {
            let ok = match item.proof.proof_type {
                DisclosureType::Balance => {
                    let inner: DisclosureBalanceProof = decode_inner(&item.proof)?;
                    let oref = match &item.output_ref {
                        Some(r) => r,
                        None => return Ok(false),
                    };
                    match chain.anchor(oref)? {
                        Some(a) => verify_balance_proof_anchored(&inner, &a)?.is_valid(),
                        None => return Ok(false),
                    }
                }
                DisclosureType::Ownership => {
                    let inner: OwnershipProof = decode_inner(&item.proof)?;
                    let oref = DisclosureOutputRef {
                        tx_hash: inner.tx_hash,
                        output_index: inner.output_index,
                    };
                    match chain.anchor(&oref)? {
                        Some(a) => verify_ownership_proof_anchored(&inner, &a)?.is_valid(),
                        None => return Ok(false),
                    }
                }
                DisclosureType::Sum => {
                    let inner: SumProof = decode_inner(&item.proof)?;
                    verify_sum_proof_anchored(&inner, |r| chain.anchor(r))?.is_valid()
                }
                DisclosureType::Source => {
                    let inner: SourceProof = decode_inner(&item.proof)?;
                    let spent = chain.key_image_spent(&inner.key_image)?;
                    verify_source_proof_anchored(&inner, spent)?.is_valid()
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

/// Build a **recipient's own receipt** for a payment they received: an ownership
/// disclosure proof, built with their one-time key (the org cannot forge it).
/// The recipient hands this to the org (or auditor) to prove "I received the
/// output at `(tx_hash, output_index)`" — e.g. for their taxes.
pub fn recipient_receipt(
    tx_hash: &Hash,
    output_index: u8,
    stealth_address: &PublicKey,
    one_time_secret: &SecretKey,
    memo: &[u8],
    expires_at: Option<u64>,
) -> Result<DisclosureProof> {
    let op = create_ownership_proof(tx_hash, output_index, stealth_address, one_time_secret, memo)?;
    DisclosureProof::from_ownership(&op, "payment receipt", expires_at)
}

/// Build a **funds-source** disclosure: proves a spend's key image came from the
/// prover's wallet (provenance), without revealing the key. Verified against a
/// [`ChainView`] that confirms the key image was actually spent on-chain.
pub fn source_disclosure(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    key_image: &KeyImage,
    message: &[u8],
    expires_at: Option<u64>,
) -> Result<DisclosureProof> {
    let sp = create_source_proof(secret_key, public_key, key_image, message)?;
    DisclosureProof::from_source(&sp, "funds source", expires_at)
}

/// Builds a payroll run's [`AuditPackage`] — the product workflow. The org proves
/// the **org-side** facts (treasury solvency, total disbursed); each **recipient**
/// contributes their own receipt via [`recipient_receipt`].
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

    pub fn add_recipient_receipt(&mut self, recipient: &str, receipt: DisclosureProof) -> &mut Self {
        self.package.add(format!("receipt for {recipient}"), receipt);
        self
    }

    pub fn finish(self) -> AuditPackage {
        self.package
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        create_balance_proof, BlindingFactor, KeyImage, PedersenCommitment, SecretScalar,
    };
    use rand::rngs::OsRng;

    fn oref(tag: u8, idx: u8) -> DisclosureOutputRef {
        DisclosureOutputRef { tx_hash: Hash::from_bytes([tag; 32]), output_index: idx }
    }

    /// A fresh (secret, public) keypair in the crate's key types.
    fn keypair() -> (SecretKey, PublicKey, SecretScalar) {
        let secret = SecretScalar::random(&mut OsRng);
        let sk = SecretKey::from_bytes(secret.to_bytes());
        let pk = PublicKey::from_bytes(secret.to_public().to_bytes());
        (sk, pk, secret)
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
        let received = AuditPackage::from_json(&pkg.to_json().unwrap()).unwrap();
        assert!(received.check_offline_consistency(1_000_000).unwrap());
        assert_eq!(received.org, "Acme DAO");
    }

    #[test]
    fn anchored_balance_is_the_sound_check() {
        let (dp, commitment) = treasury_solvency_proof(1_000_000);
        let t_ref = oref(9, 0);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, t_ref.clone());

        let good = InMemoryChainView::new()
            .with_anchor(ChainAnchor::new(t_ref.clone(), commitment, [0u8; 32], 10));
        assert!(pkg.verify_anchored(1_000_000, &good).unwrap());

        // Wrong on-chain commitment => rejected; empty view => not trusted.
        let wrong = InMemoryChainView::new()
            .with_anchor(ChainAnchor::new(t_ref, [9u8; 32], [0u8; 32], 10));
        assert!(!pkg.verify_anchored(1_000_000, &wrong).unwrap());
        assert!(!pkg.verify_anchored(1_000_000, &InMemoryChainView::new()).unwrap());
    }

    #[test]
    fn recipient_receipt_round_trips_org_to_auditor() {
        // A contributor's one-time key for the output they received.
        let (sk, pk, _s) = keypair();
        let tx_hash = Hash::from_bytes([7u8; 32]);
        let idx = 0u8;

        // Recipient builds their own receipt.
        let receipt = recipient_receipt(&tx_hash, idx, &pk, &sk, b"alice pay", Some(2_000_000_000)).unwrap();

        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add("receipt for alice", receipt);

        // Auditor's chain view: the output exists with alice's stealth address.
        let chain = InMemoryChainView::new().with_anchor(ChainAnchor::new(
            DisclosureOutputRef { tx_hash, output_index: idx },
            [0u8; 32],
            *pk.as_bytes(),
            5,
        ));
        assert!(pkg.verify_anchored(1_000_000, &chain).unwrap(), "recipient receipt must verify");

        // A view that doesn't know the output => not trusted.
        assert!(!pkg.verify_anchored(1_000_000, &InMemoryChainView::new()).unwrap());
    }

    #[test]
    fn source_disclosure_verifies_only_when_key_image_is_spent() {
        let (sk, pk, secret) = keypair();
        let key_image = KeyImage::from_secret(&secret);
        let dp = source_disclosure(&sk, &pk, &key_image, b"payroll funding", Some(2_000_000_000)).unwrap();

        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add("funds source", dp);

        // Key image spent on-chain => valid provenance.
        let spent = InMemoryChainView::new().with_spent_key_image(key_image);
        assert!(pkg.verify_anchored(1_000_000, &spent).unwrap());

        // Not spent in the trusted view => rejected.
        assert!(!pkg.verify_anchored(1_000_000, &InMemoryChainView::new()).unwrap());
    }

    #[test]
    fn payroll_run_fully_anchored_verifies() {
        let (a1, a2) = (300_000u64, 200_000u64);
        let b1 = BlindingFactor::random(&mut OsRng);
        let b2 = BlindingFactor::random(&mut OsRng);
        let c1 = PedersenCommitment::commit(a1, &b1).to_bytes();
        let c2 = PedersenCommitment::commit(a2, &b2).to_bytes();
        let (r1, r2) = (oref(1, 0), oref(2, 1));
        let outputs = vec![(a1, b1, r1.tx_hash, r1.output_index), (a2, b2, r2.tx_hash, r2.output_index)];

        let tv = 10_000_000u64;
        let tb = BlindingFactor::random(&mut OsRng);
        let tc = PedersenCommitment::commit(tv, &tb);
        let t_ref = oref(9, 0);

        let mut run = PayrollRun::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        run.treasury_solvency(tv, &tb, &tc, 1_000_000, t_ref.clone()).unwrap();
        run.total_disbursed(&outputs, (0, 100)).unwrap();
        let pkg = run.finish();
        assert!(pkg.items[1].statement.contains("500000"));

        let chain = InMemoryChainView::new()
            .with_anchor(ChainAnchor::new(t_ref, tc.to_bytes(), [0u8; 32], 50))
            .with_anchor(ChainAnchor::new(r1, c1, [0u8; 32], 50))
            .with_anchor(ChainAnchor::new(r2, c2, [0u8; 32], 50));
        assert!(pkg.verify_anchored(1_000_000, &chain).unwrap(), "whole payroll package anchors");
    }
}
