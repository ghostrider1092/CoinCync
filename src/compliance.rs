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
use crate::wallet::multisig::{
    aggregate_signature, signing_round1, signing_round2, verify_signature as verify_multisig,
    KeyShare, MultisigConfig, MultisigSignature,
};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

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
    /// Optional proof that the treasury is under M-of-N custody (no single key
    /// can move it). `None` = custody not attested in this package.
    #[serde(default)]
    pub custody: Option<CustodyAttestation>,
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
            custody: None,
        }
    }

    /// Attach a treasury custody attestation (M-of-N control). It is covered by
    /// the package signature, so it cannot be swapped without breaking it.
    pub fn attach_custody(&mut self, custody: CustodyAttestation) -> &mut Self {
        self.custody = Some(custody);
        self
    }

    /// Verify the treasury custody attestation against the group key the auditor
    /// trusts out of band: the treasury is genuinely M-of-N controlled and at
    /// least M signers approved the policy. `Ok(false)` if there is no
    /// attestation, the group key mismatches, or the threshold signature fails.
    pub fn verify_custody(&self, expected_group_pubkey: &[u8; 32]) -> Result<bool> {
        match &self.custody {
            Some(att) => att.verify(expected_group_pubkey),
            None => Ok(false),
        }
    }

    /// Whether the custody attestation governs the SAME on-chain output a
    /// Balance (treasury solvency) proof anchors to — so "the treasury is M-of-N
    /// controlled" and "the treasury holds >= X" are about one output, not two.
    pub fn custody_governs_solvency(&self) -> bool {
        let att = match &self.custody {
            Some(a) => a,
            None => return false,
        };
        self.items.iter().any(|it| {
            matches!(it.proof.proof_type, DisclosureType::Balance)
                && it.output_ref.as_ref() == Some(&att.treasury_ref)
        })
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

    /// Reconcile the recipient receipts against the total-disbursed proof.
    ///
    /// The total-disbursed [`SumProof`] names the exact set of on-chain outputs
    /// it sums; each recipient receipt ([`OwnershipProof`]) attests one output.
    /// This cross-checks those two sets: which disbursements have a receipt,
    /// which are missing one, and which receipts fall outside the sum. It is a
    /// **structural** check of the outputs the proofs *name* — amounts stay
    /// hidden, and each proof is only trustworthy once [`Self::verify_anchored`]
    /// checks it against the chain. Uses the first Sum proof in the package.
    ///
    /// `Ok` even when nothing reconciles; inspect [`Reconciliation`]. Errors only
    /// if a proof's bytes are malformed.
    pub fn reconcile(&self) -> Result<Reconciliation> {
        let mut disbursed: Vec<DisclosureOutputRef> = Vec::new();
        let mut claimed_total = 0u64;
        let mut has_total = false;
        for item in &self.items {
            if matches!(item.proof.proof_type, DisclosureType::Sum) {
                let inner: SumProof = decode_inner(&item.proof)?;
                disbursed = inner.output_refs.clone();
                claimed_total = inner.claimed_total;
                has_total = true;
                break;
            }
        }

        let mut receipted: Vec<DisclosureOutputRef> = Vec::new();
        for item in &self.items {
            if matches!(item.proof.proof_type, DisclosureType::Ownership) {
                let inner: OwnershipProof = decode_inner(&item.proof)?;
                receipted.push(DisclosureOutputRef {
                    tx_hash: inner.tx_hash,
                    output_index: inner.output_index,
                });
            }
        }

        // Diffs only mean something when there is a total to reconcile against.
        let (missing_receipts, unexpected_receipts) = if has_total {
            let disbursed_set: HashSet<&DisclosureOutputRef> = disbursed.iter().collect();
            let receipted_set: HashSet<&DisclosureOutputRef> = receipted.iter().collect();
            let missing = disbursed
                .iter()
                .filter(|r| !receipted_set.contains(*r))
                .cloned()
                .collect();
            let unexpected = receipted
                .iter()
                .filter(|r| !disbursed_set.contains(*r))
                .cloned()
                .collect();
            (missing, unexpected)
        } else {
            (Vec::new(), Vec::new())
        };

        Ok(Reconciliation {
            disbursed,
            receipted,
            missing_receipts,
            unexpected_receipts,
            claimed_total,
            has_total,
        })
    }

    /// Render a human-readable Markdown report for a treasurer or auditor:
    /// the org and period, the validity window, every item's statement and
    /// proof type, and the reconciliation summary.
    ///
    /// **Descriptive only** — the report itself verifies nothing. The sound
    /// decision is [`Self::verify_anchored`] against a trusted [`ChainView`];
    /// `now` only drives the expiry note.
    pub fn to_report(&self, now: u64) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "# Audit package — {}", self.org);
        let _ = writeln!(s);
        let _ = writeln!(s, "- **Period:** {}", self.period);
        let _ = writeln!(s, "- **Created at:** {}", self.created_at);
        match self.expires_at {
            Some(exp) if now > exp => {
                let _ = writeln!(s, "- **Expires at:** {exp} — ⚠️ EXPIRED (now {now})");
            }
            Some(exp) => {
                let _ = writeln!(s, "- **Expires at:** {exp}");
            }
            None => {
                let _ = writeln!(s, "- **Expires at:** never");
            }
        }
        let _ = writeln!(s, "- **Items:** {}", self.items.len());
        let _ = writeln!(s);

        let _ = writeln!(s, "## Statements");
        let _ = writeln!(s);
        let _ = writeln!(s, "| # | Type | Statement |");
        let _ = writeln!(s, "|---|------|-----------|");
        for (i, item) in self.items.iter().enumerate() {
            let _ = writeln!(
                s,
                "| {} | {} | {} |",
                i + 1,
                type_name(&item.proof.proof_type),
                item.statement.replace('|', "\\|"),
            );
        }
        let _ = writeln!(s);

        let _ = writeln!(s, "## Reconciliation");
        let _ = writeln!(s);
        match self.reconcile() {
            Ok(r) if r.has_total => {
                let _ = writeln!(s, "- **Total disbursed (claimed):** {}", r.claimed_total);
                let _ = writeln!(s, "- **Disbursed outputs:** {}", r.disbursed.len());
                let _ = writeln!(
                    s,
                    "- **Receipts matched:** {} of {}",
                    r.disbursed.len() - r.missing_receipts.len(),
                    r.disbursed.len(),
                );
                let _ = writeln!(s, "- **Missing receipts:** {}", r.missing_receipts.len());
                let _ = writeln!(
                    s,
                    "- **Receipts outside the sum:** {}",
                    r.unexpected_receipts.len()
                );
                let verdict = if r.is_fully_reconciled() {
                    "✅ fully reconciled (every disbursement has a receipt; no extras)"
                } else {
                    "⚠️ not fully reconciled"
                };
                let _ = writeln!(s, "- **Status:** {verdict}");
            }
            Ok(_) => {
                let _ = writeln!(
                    s,
                    "- No total-disbursed proof in this package; nothing to reconcile."
                );
            }
            Err(_) => {
                let _ = writeln!(s, "- Reconciliation unavailable (a proof is malformed).");
            }
        }
        let _ = writeln!(s);

        if let Some(att) = &self.custody {
            let _ = writeln!(s, "## Treasury custody");
            let _ = writeln!(s);
            let _ = writeln!(
                s,
                "- **Policy:** {}-of-{} multisig — no single key can move the treasury",
                att.threshold, att.participants
            );
            let _ = writeln!(s, "- **Group key:** `{}`", hex::encode(att.group_pubkey));
            let _ = writeln!(
                s,
                "- **Governs treasury output:** tx {} · index {}",
                hex::encode(att.treasury_ref.tx_hash.as_bytes()),
                att.treasury_ref.output_index
            );
            let tie = if self.custody_governs_solvency() {
                "✅ same output as the solvency proof"
            } else {
                "⚠️ not tied to a solvency proof in this package"
            };
            let _ = writeln!(s, "- **Solvency binding:** {tie}");
            let _ = writeln!(s);
        }

        let _ = writeln!(
            s,
            "> Verification note: this report is descriptive. Trust requires \
             anchored verification of each proof against the chain \
             (`verify_anchored`); offline well-formedness is not a trust decision."
        );
        s
    }

    /// Canonical bytes bound by an issuer signature: a domain tag, the compact
    /// package JSON, and the length-prefixed binding fields (issuer key, audit
    /// id, audience). Deterministic — [`AuditPackage`] contains no maps, so
    /// compact JSON is stable. Length prefixes stop adjacent fields from
    /// blurring into one another.
    fn signing_bytes(
        &self,
        issuer_pubkey: &[u8; 32],
        audit_id: &[u8; 32],
        audience: &str,
    ) -> Result<Vec<u8>> {
        let pkg = serde_json::to_vec(self).map_err(|e| Error::SerializationError(e.to_string()))?;
        let mut m = Vec::with_capacity(pkg.len() + 128);
        m.extend_from_slice(b"coincync/audit-package/v1");
        m.extend_from_slice(&(pkg.len() as u64).to_le_bytes());
        m.extend_from_slice(&pkg);
        m.extend_from_slice(issuer_pubkey);
        m.extend_from_slice(audit_id);
        m.extend_from_slice(&(audience.len() as u64).to_le_bytes());
        m.extend_from_slice(audience.as_bytes());
        Ok(m)
    }

    /// Sign this package as the issuing org, binding it to a single named
    /// `audience` (auditor) and a unique `audit_id` nonce — producing a
    /// [`SignedAuditPackage`] that is attributable, non-transferable, and
    /// single-use. The signature covers the package **and** the binding fields,
    /// so none can be swapped without breaking it.
    pub fn sign(
        self,
        signing_key: &SigningKey,
        audit_id: [u8; 32],
        audience: impl Into<String>,
    ) -> Result<SignedAuditPackage> {
        let issuer_pubkey = signing_key.verifying_key().to_bytes();
        let audience = audience.into();
        let msg = self.signing_bytes(&issuer_pubkey, &audit_id, &audience)?;
        let signature = signing_key.sign(&msg).to_bytes();
        Ok(SignedAuditPackage {
            package: self,
            issuer_pubkey: hex::encode(issuer_pubkey),
            audit_id: hex::encode(audit_id),
            audience,
            signature: hex::encode(signature),
        })
    }
}

/// Which disbursed outputs are covered by recipient receipts, and which are not.
///
/// Produced by [`AuditPackage::reconcile`]. The total-disbursed proof names the
/// exact set of outputs it sums; the receipts attest ownership of individual
/// outputs. A package is **fully reconciled** when those two sets are equal:
/// every disbursement has a receipt and no receipt falls outside the sum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reconciliation {
    /// Outputs named by the total-disbursed Sum proof.
    pub disbursed: Vec<DisclosureOutputRef>,
    /// Outputs receipted by recipients (Ownership proofs).
    pub receipted: Vec<DisclosureOutputRef>,
    /// In the disbursed sum but with no matching receipt.
    pub missing_receipts: Vec<DisclosureOutputRef>,
    /// Receipted but not part of the disbursed sum.
    pub unexpected_receipts: Vec<DisclosureOutputRef>,
    /// The total the Sum proof binds (0 when absent).
    pub claimed_total: u64,
    /// Whether a total-disbursed Sum proof was present to reconcile against.
    pub has_total: bool,
}

impl Reconciliation {
    /// Every disbursed output has a receipt and every receipt is for a disbursed
    /// output — the package reconciles against itself. Requires a total.
    pub fn is_fully_reconciled(&self) -> bool {
        self.has_total && self.missing_receipts.is_empty() && self.unexpected_receipts.is_empty()
    }
}

/// A threshold-signed attestation that an org's treasury is under **M-of-N
/// custody** — no single key can move the funds. The custody group (holders of
/// the FROST shares for `group_pubkey`) threshold-signs a statement binding the
/// org, the policy (M of N), the group key, and the treasury output it governs.
///
/// ## What it proves
/// An auditor who knows `group_pubkey` out of band verifies that **at least M**
/// signers approved the statement: a single compromised share cannot forge it,
/// because a threshold Schnorr signature for the group key requires M shares.
/// Pair it with the package's anchored solvency proof over the same
/// `treasury_ref` (see [`AuditPackage::custody_governs_solvency`]) so the
/// protected key and the funded output are one and the same — a single-key
/// wallet cannot produce this signature for a group key it does not control.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyAttestation {
    pub org: String,
    /// Signers required to move funds (M).
    pub threshold: u16,
    /// Total signers in the custody group (N).
    pub participants: u16,
    /// FROST group verifying key the treasury is controlled by.
    pub group_pubkey: [u8; 32],
    /// The on-chain treasury output this policy governs.
    pub treasury_ref: DisclosureOutputRef,
    /// Threshold signature over [`Self::statement_bytes`] by the custody group.
    pub signature: MultisigSignature,
}

impl CustodyAttestation {
    /// Canonical, domain-separated bytes the custody group threshold-signs.
    /// Deterministic; length-prefixed so fields cannot blur together.
    pub fn statement_bytes(
        org: &str,
        threshold: u16,
        participants: u16,
        group_pubkey: &[u8; 32],
        treasury_ref: &DisclosureOutputRef,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(org.len() + 96);
        m.extend_from_slice(b"coincync/treasury-custody/v1");
        m.extend_from_slice(&(org.len() as u64).to_le_bytes());
        m.extend_from_slice(org.as_bytes());
        m.extend_from_slice(&threshold.to_le_bytes());
        m.extend_from_slice(&participants.to_le_bytes());
        m.extend_from_slice(group_pubkey);
        m.extend_from_slice(treasury_ref.tx_hash.as_bytes());
        m.push(treasury_ref.output_index);
        m
    }

    /// The exact message this attestation's signature must cover.
    pub fn message(&self) -> Vec<u8> {
        Self::statement_bytes(
            &self.org,
            self.threshold,
            self.participants,
            &self.group_pubkey,
            &self.treasury_ref,
        )
    }

    /// Produce an attestation by running the FROST signing flow over the custody
    /// statement with `signers` (at least `config.threshold` of the group's
    /// shares). In production these signers are separate parties coordinating
    /// through the multisig coordinator; here they are the shares in hand.
    pub fn create_with_shares(
        org: impl Into<String>,
        treasury_ref: DisclosureOutputRef,
        config: &MultisigConfig,
        signers: &[KeyShare],
    ) -> Result<Self> {
        let org = org.into();
        if (signers.len() as u16) < config.threshold {
            return Err(Error::InvalidState(format!(
                "custody attestation needs >= {} signers, got {}",
                config.threshold,
                signers.len()
            )));
        }
        let msg = Self::statement_bytes(
            &org,
            config.threshold,
            config.total,
            &config.group_public_key,
            &treasury_ref,
        );

        let mut commitments = Vec::with_capacity(signers.len());
        let mut secrets = Vec::with_capacity(signers.len());
        for s in signers {
            let (out, secret) = signing_round1(s)?;
            commitments.push(out);
            secrets.push(secret);
        }
        let mut shares = Vec::with_capacity(signers.len());
        for (s, secret) in signers.iter().zip(secrets) {
            shares.push(signing_round2(s, secret, &commitments, &msg)?);
        }
        let signature = aggregate_signature(&commitments, &shares, config, signers, &msg)?;

        Ok(Self {
            org,
            threshold: config.threshold,
            participants: config.total,
            group_pubkey: config.group_public_key,
            treasury_ref,
            signature,
        })
    }

    /// Verify against the treasury group key the auditor trusts out of band.
    /// Fail-closed: rejects a non-custody policy (`M < 2` or `N < M`), a group
    /// mismatch, or an invalid threshold signature.
    pub fn verify(&self, expected_group_pubkey: &[u8; 32]) -> Result<bool> {
        if self.threshold < 2 || self.participants < self.threshold {
            return Ok(false);
        }
        if &self.group_pubkey != expected_group_pubkey {
            return Ok(false);
        }
        // The signature must itself carry the expected group key, not a different
        // group the prover happens to control.
        if &self.signature.group_public_key != expected_group_pubkey {
            return Ok(false);
        }
        // Fail-closed: a bad/forged signature makes multisig verify return Err;
        // treat that as "not verified", never a hard error.
        Ok(verify_multisig(&self.signature, &self.message()).unwrap_or(false))
    }
}

/// An [`AuditPackage`] signed by the issuing org and bound to one named auditor
/// plus a unique id — so it is **attributable** (the org's signature),
/// **non-transferable** (bound to one `audience`), and **single-use** (the
/// `audit_id` an auditor records to reject replays). Binding fields are hex for
/// readable JSON; the signature covers the package together with all of them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAuditPackage {
    pub package: AuditPackage,
    /// Ed25519 public key of the issuing org (hex, 32 bytes).
    pub issuer_pubkey: String,
    /// Unique issuance nonce the auditor records for single-use (hex, 32 bytes).
    pub audit_id: String,
    /// The single auditor this package is issued to (non-transferable).
    pub audience: String,
    /// Ed25519 signature over the canonical signing bytes (hex, 64 bytes).
    pub signature: String,
}

impl SignedAuditPackage {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Verify the org's signature and that this package was issued **by**
    /// `expected_issuer` **to** `expected_auditor`. The auditor knows the org's
    /// real key out of band and checks against it, rejecting a package that
    /// claims any other issuer or audience. Fail-closed: `Ok(false)` on any
    /// mismatch or bad signature.
    pub fn verify_signature(
        &self,
        expected_issuer: &VerifyingKey,
        expected_auditor: &str,
    ) -> Result<bool> {
        let issuer_bytes = decode_hex_array::<32>(&self.issuer_pubkey)?;
        if issuer_bytes != expected_issuer.to_bytes() {
            return Ok(false);
        }
        if self.audience != expected_auditor {
            return Ok(false);
        }
        let audit_id = decode_hex_array::<32>(&self.audit_id)?;
        let sig_bytes = decode_hex_array::<64>(&self.signature)?;
        let sig = EdSignature::from_bytes(&sig_bytes);
        let msg = self
            .package
            .signing_bytes(&issuer_bytes, &audit_id, &self.audience)?;
        Ok(expected_issuer.verify(&msg, &sig).is_ok())
    }

    /// Record single use against a set of already-consumed `audit_id`s: `true`
    /// (and marks it consumed) the first time this id is seen, `false` on replay.
    /// The auditor persists this set across packages.
    pub fn claim_single_use(&self, consumed: &mut HashSet<String>) -> bool {
        consumed.insert(self.audit_id.clone())
    }

    /// Full auditor acceptance: the signature is valid for `(expected_issuer,
    /// expected_auditor)`, the package verifies anchored against `chain` at
    /// `now`, and this `audit_id` has not been used before. Single-use is
    /// claimed only after the other checks pass, so a package that fails to
    /// verify does not burn its id. Fail-closed.
    pub fn accept<V: ChainView>(
        &self,
        expected_issuer: &VerifyingKey,
        expected_auditor: &str,
        consumed: &mut HashSet<String>,
        now: u64,
        chain: &V,
    ) -> Result<bool> {
        if !self.verify_signature(expected_issuer, expected_auditor)? {
            return Ok(false);
        }
        if !self.package.verify_anchored(now, chain)? {
            return Ok(false);
        }
        Ok(self.claim_single_use(consumed))
    }

    /// Human-readable report for the signed package: issuer, audience and audit
    /// id, then the underlying package's [`AuditPackage::to_report`].
    pub fn to_report(&self, now: u64) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "**Issued by:** `{}`", self.issuer_pubkey);
        let _ = writeln!(s, "**Issued to:** {}", self.audience);
        let _ = writeln!(s, "**Audit id:** `{}`", self.audit_id);
        let _ = writeln!(s);
        s.push_str(&self.package.to_report(now));
        s
    }
}

/// A [`SignedAuditPackage`] sealed to one auditor's public key — an encrypted
/// envelope only that auditor can open. This is the **leak barrier**: if the
/// sealed file is intercepted, forwarded, or left at rest, it reveals nothing
/// (not the org, the amounts, the treasury output, nor the receipts) without
/// the auditor's secret key. Sealing is ECDH (a fresh ephemeral key × the
/// auditor's key) into ChaCha20-Poly1305 — the same construction CoinCync uses
/// for on-chain memos, with a fresh random nonce per seal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedAuditPackage {
    /// Ephemeral public key for the ECDH (hex, 32 bytes).
    pub ephemeral_pubkey: String,
    /// nonce (12 bytes) || ChaCha20-Poly1305 ciphertext+tag (hex).
    pub blob: String,
}

/// Derive the seal's AEAD key from the ECDH shared point, domain-separated so it
/// can never collide with the memo key or any other derived key.
fn derive_seal_key(shared_bytes: &[u8; 32]) -> [u8; 32] {
    *crate::primitives::hash_domain(b"COINCYNC_AUDIT_SEAL_v1", shared_bytes).as_bytes()
}

impl SignedAuditPackage {
    /// Seal this signed package to `auditor_pubkey` so only the holder of the
    /// matching secret key can open it. The signature and every disclosure stay
    /// intact inside the envelope; the envelope adds confidentiality on top.
    pub fn seal_to(&self, auditor_pubkey: &PublicKey) -> Result<SealedAuditPackage> {
        use crate::crypto::{PublicPoint, SecretScalar};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        use rand::{rngs::OsRng, RngCore};
        use zeroize::Zeroize;

        let plaintext =
            serde_json::to_vec(self).map_err(|e| Error::SerializationError(e.to_string()))?;
        let recipient = PublicPoint::from_bytes(*auditor_pubkey.as_bytes())
            .ok_or_else(|| Error::CryptoError("invalid auditor public key".into()))?;

        let eph_secret = SecretScalar::random(&mut OsRng);
        let eph_public = eph_secret.to_public().to_bytes();
        let mut shared = recipient.mul(&eph_secret);
        let mut shared_bytes = shared.to_bytes();
        let mut key = derive_seal_key(&shared_bytes);
        shared_bytes.zeroize();
        shared.zeroize();

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_slice())
            .map_err(|e| Error::CryptoError(format!("seal failed: {e}")))?;
        key.zeroize();

        let mut blob = Vec::with_capacity(12 + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        Ok(SealedAuditPackage {
            ephemeral_pubkey: hex::encode(eph_public),
            blob: hex::encode(blob),
        })
    }
}

impl SealedAuditPackage {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Open the sealed package with the auditor's secret key. Fails closed on a
    /// wrong key or any tampering (the AEAD tag will not verify).
    pub fn open(&self, auditor_secret: &SecretKey) -> Result<SignedAuditPackage> {
        use crate::crypto::{PublicPoint, SecretScalar};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
        use zeroize::Zeroize;

        let eph_bytes = decode_hex_array::<32>(&self.ephemeral_pubkey)?;
        let eph_point = PublicPoint::from_bytes(eph_bytes)
            .ok_or_else(|| Error::CryptoError("invalid ephemeral key".into()))?;
        let secret = SecretScalar::from_bytes(*auditor_secret.as_bytes());
        let mut shared = eph_point.mul(&secret);
        let mut shared_bytes = shared.to_bytes();
        let mut key = derive_seal_key(&shared_bytes);
        shared_bytes.zeroize();
        shared.zeroize();

        let raw = hex::decode(&self.blob).map_err(|e| Error::SerializationError(e.to_string()))?;
        if raw.len() < 12 + 16 {
            return Err(Error::CryptoError("sealed blob too short".into()));
        }
        let (nonce, ct) = raw.split_at(12);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let pt = cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| Error::CryptoError("seal open failed (wrong key or tampered)".into()));
        key.zeroize();
        let pt = pt?;

        let json = String::from_utf8(pt).map_err(|e| Error::SerializationError(e.to_string()))?;
        SignedAuditPackage::from_json(&json)
    }
}

/// Decode a hex string into a fixed-size byte array, erroring on wrong length.
fn decode_hex_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = hex::decode(s).map_err(|e| Error::SerializationError(e.to_string()))?;
    if v.len() != N {
        return Err(Error::SerializationError(format!(
            "expected {N} bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Short label for a disclosure proof type, for reports.
fn type_name(t: &DisclosureType) -> &'static str {
    match t {
        DisclosureType::Balance => "Balance",
        DisclosureType::Ownership => "Ownership",
        DisclosureType::Sum => "Sum",
        DisclosureType::Source => "Source",
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
    use ed25519_dalek::SigningKey;
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

    /// Build a payroll package: total-disbursed over `outputs`, plus a receipt
    /// for each `receipt_ref`. Receipts reuse one throwaway key (reconcile only
    /// looks at the output each names, not its key).
    fn payroll_with_receipts(
        outputs: &[(u64, BlindingFactor, Hash, u8)],
        receipt_refs: &[DisclosureOutputRef],
    ) -> AuditPackage {
        let mut run = PayrollRun::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        run.total_disbursed(outputs, (0, 100)).unwrap();
        let (sk, pk, _s) = keypair();
        for r in receipt_refs {
            let rc = recipient_receipt(&r.tx_hash, r.output_index, &pk, &sk, b"pay", Some(2_000_000_000))
                .unwrap();
            run.add_recipient_receipt("recipient", rc);
        }
        run.finish()
    }

    fn sum_outputs() -> (Vec<(u64, BlindingFactor, Hash, u8)>, DisclosureOutputRef, DisclosureOutputRef) {
        let (r1, r2) = (oref(1, 0), oref(2, 1));
        let outputs = vec![
            (300_000u64, BlindingFactor::random(&mut OsRng), r1.tx_hash, r1.output_index),
            (200_000u64, BlindingFactor::random(&mut OsRng), r2.tx_hash, r2.output_index),
        ];
        (outputs, r1, r2)
    }

    #[test]
    fn reconcile_full_missing_and_unexpected() {
        let (outputs, r1, r2) = sum_outputs();

        // Every disbursement receipted => fully reconciled.
        let full = payroll_with_receipts(&outputs, &[r1.clone(), r2.clone()]);
        let rec = full.reconcile().unwrap();
        assert!(rec.has_total);
        assert_eq!(rec.claimed_total, 500_000);
        assert!(rec.is_fully_reconciled());
        assert!(rec.missing_receipts.is_empty() && rec.unexpected_receipts.is_empty());

        // One receipt missing => flagged, not reconciled.
        let partial = payroll_with_receipts(&outputs, &[r1.clone()]);
        let rec = partial.reconcile().unwrap();
        assert!(!rec.is_fully_reconciled());
        assert_eq!(rec.missing_receipts, vec![r2.clone()]);
        assert!(rec.unexpected_receipts.is_empty());

        // A receipt for an output outside the sum => flagged as unexpected.
        let stray = oref(3, 0);
        let extra = payroll_with_receipts(&outputs, &[r1, r2, stray.clone()]);
        let rec = extra.reconcile().unwrap();
        assert!(!rec.is_fully_reconciled());
        assert_eq!(rec.unexpected_receipts, vec![stray]);
        assert!(rec.missing_receipts.is_empty());
    }

    #[test]
    fn reconcile_without_total_reconciles_nothing() {
        // Package with only a receipt and no total-disbursed proof.
        let (sk, pk, _s) = keypair();
        let rc = recipient_receipt(&Hash::from_bytes([4u8; 32]), 0, &pk, &sk, b"x", Some(2_000_000_000))
            .unwrap();
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add("receipt", rc);
        let rec = pkg.reconcile().unwrap();
        assert!(!rec.has_total);
        assert!(!rec.is_fully_reconciled());
        // No total to reconcile against => a lone receipt is not "unexpected".
        assert!(rec.unexpected_receipts.is_empty());
        assert_eq!(rec.receipted.len(), 1);
    }

    #[test]
    fn signature_is_attributable_and_tamper_evident() {
        let (dp, _c) = treasury_solvency_proof(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, oref(9, 0));

        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let audit_id = [7u8; 32];
        let signed = pkg.sign(&key, audit_id, "Auditor One").unwrap();

        // Valid for the right issuer + audience; survives a JSON round trip.
        assert!(signed.verify_signature(&vk, "Auditor One").unwrap());
        let received = SignedAuditPackage::from_json(&signed.to_json().unwrap()).unwrap();
        assert!(received.verify_signature(&vk, "Auditor One").unwrap());

        // Wrong audience (non-transferable) and wrong issuer are rejected.
        assert!(!signed.verify_signature(&vk, "Auditor Two").unwrap());
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(!signed.verify_signature(&other, "Auditor One").unwrap());

        // Tampering with the package after signing breaks the signature.
        let mut tampered = signed.clone();
        tampered.package.org = "Evil DAO".to_string();
        assert!(!tampered.verify_signature(&vk, "Auditor One").unwrap());
    }

    #[test]
    fn accept_verifies_signs_and_enforces_single_use() {
        let (dp, commitment) = treasury_solvency_proof(1_000_000);
        let t_ref = oref(9, 0);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, t_ref.clone());

        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let signed = pkg.sign(&key, [11u8; 32], "Auditor One").unwrap();

        let chain = InMemoryChainView::new()
            .with_anchor(ChainAnchor::new(t_ref, commitment, [0u8; 32], 10));
        let mut consumed = HashSet::new();

        // First acceptance: signature + anchored + fresh id => accepted.
        assert!(signed
            .accept(&vk, "Auditor One", &mut consumed, 1_000_000, &chain)
            .unwrap());
        // Replay of the same id => rejected (single-use).
        assert!(!signed
            .accept(&vk, "Auditor One", &mut consumed, 1_000_000, &chain)
            .unwrap());

        // A failed anchored check must NOT burn the id: fresh consumed set,
        // empty chain => rejected, and the id stays available.
        let mut fresh = HashSet::new();
        assert!(!signed
            .accept(&vk, "Auditor One", &mut fresh, 1_000_000, &InMemoryChainView::new())
            .unwrap());
        assert!(!fresh.contains(&signed.audit_id), "id must not be consumed on failure");
    }

    #[test]
    fn report_renders_statements_and_reconciliation() {
        let (outputs, r1, r2) = sum_outputs();
        let pkg = payroll_with_receipts(&outputs, &[r1, r2]);
        let report = pkg.to_report(1_000_000);
        assert!(report.contains("# Audit package — Acme DAO"));
        assert!(report.contains("## Statements"));
        assert!(report.contains("## Reconciliation"));
        assert!(report.contains("fully reconciled"));
        assert!(report.contains("Sum"));
        assert!(report.contains("Ownership"));
        // Expiry note fires past the window.
        assert!(pkg.to_report(3_000_000_000).contains("EXPIRED"));
    }

    #[test]
    fn custody_attestation_proves_m_of_n_and_is_tamper_evident() {
        use crate::wallet::multisig::generate_shares;

        let t_ref = oref(9, 0);
        // A 2-of-3 treasury custody group.
        let kg = generate_shares(2, 3).unwrap();
        let att = CustodyAttestation::create_with_shares(
            "Acme DAO",
            t_ref.clone(),
            &kg.config,
            &kg.shares[..2], // any 2 of 3 signers
        )
        .unwrap();

        // Verifies against the true group key.
        assert!(att.verify(&kg.config.group_public_key).unwrap());
        assert_eq!(att.threshold, 2);
        assert_eq!(att.participants, 3);

        // Wrong group key => rejected.
        assert!(!att.verify(&[9u8; 32]).unwrap());

        // Tampering with any bound field breaks the threshold signature.
        let mut tampered = att.clone();
        tampered.org = "Evil DAO".to_string();
        assert!(!tampered.verify(&kg.config.group_public_key).unwrap());
        let mut tampered2 = att.clone();
        tampered2.threshold = 1; // a non-custody policy is refused outright
        assert!(!tampered2.verify(&kg.config.group_public_key).unwrap());

        // In a package: custody ties to the solvency proof over the same output.
        let (dp, _c) = treasury_solvency_proof(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, t_ref.clone());
        pkg.attach_custody(att);
        assert!(pkg.verify_custody(&kg.config.group_public_key).unwrap());
        assert!(pkg.custody_governs_solvency(), "custody governs the solvency output");
        assert!(pkg.to_report(1_000_000).contains("2-of-3 multisig"));

        // Custody rides inside the signed package: tampering breaks the signature.
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let signed = pkg.sign(&key, [3u8; 32], "Auditor One").unwrap();
        assert!(signed.verify_signature(&vk, "Auditor One").unwrap());
        let mut swapped = signed.clone();
        swapped.package.custody = None; // drop the custody proof
        assert!(!swapped.verify_signature(&vk, "Auditor One").unwrap());
    }

    #[test]
    fn sealed_package_opens_only_for_the_intended_auditor() {
        let (dp, _c) = treasury_solvency_proof(1_000_000);
        let mut pkg = AuditPackage::new("Acme DAO", "2026-Q3", 1_000, Some(2_000_000_000));
        pkg.add_anchored("treasury solvency >= 1,000,000", dp, oref(9, 0));
        let orgkey = SigningKey::generate(&mut OsRng);
        let signed = pkg.sign(&orgkey, [7u8; 32], "Auditor One").unwrap();

        // Auditor's encryption keypair.
        let (aud_sk, aud_pk, _) = keypair();
        let sealed = signed.seal_to(&aud_pk).unwrap();

        // The sealed envelope leaks nothing in the clear.
        let j = sealed.to_json().unwrap();
        assert!(!j.contains("Acme DAO"), "org name must not appear in the sealed blob");
        assert!(!j.contains("Auditor One"));
        assert!(!j.contains("solvency"));

        // The intended auditor opens it and recovers the exact signed package.
        let opened = sealed.open(&aud_sk).unwrap();
        assert_eq!(opened.package.org, "Acme DAO");
        assert!(opened
            .verify_signature(&orgkey.verifying_key(), "Auditor One")
            .unwrap());
        // Survives a JSON round trip of the sealed form.
        let received = SealedAuditPackage::from_json(&sealed.to_json().unwrap()).unwrap();
        assert_eq!(received.open(&aud_sk).unwrap().package.org, "Acme DAO");

        // A different key cannot open it.
        let (other_sk, _o, _) = keypair();
        assert!(sealed.open(&other_sk).is_err(), "wrong auditor key must fail");

        // Tampering with the ciphertext fails the AEAD tag.
        let mut tampered = sealed.clone();
        let mut b = hex::decode(&tampered.blob).unwrap();
        let n = b.len();
        b[n - 1] ^= 0x01;
        tampered.blob = hex::encode(b);
        assert!(tampered.open(&aud_sk).is_err(), "tampered ciphertext must fail");
    }
}
