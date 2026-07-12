//! # Blockchain Auditing for CoinCync 1.0
//!
//! "The privacy coin you can audit"
//! Verify supply, fees, and ring quality without seeing private data.

use crate::primitives::{Hash, Amount, hash_domain};
use crate::crypto::PedersenCommitment;
use crate::constants::{FEE_BURN_NORMAL_PERCENT, FEE_BURN_CONGESTED_PERCENT};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SupplyState {
    pub height: u64,
    pub total_minted: u64,
    pub total_burned: u64,
    pub supply_commitment: [u8; 32],
}

impl SupplyState {
    pub fn genesis() -> Self { SupplyState::default() }

    pub fn circulating(&self) -> u64 {
        self.total_minted.saturating_sub(self.total_burned)
    }

    /// Apply a block's emission and burn.
    ///
    /// AUDIT (R-32 fix site 1/3, 2026-07-02): saturating arithmetic
    /// on supply totals is a silent-catastrophe risk — if either
    /// total_minted or total_burned saturates at u64::MAX, subsequent
    /// blocks become invisible to the audit chain. At CoinCync's
    /// max emission per block, saturation would take
    /// (u64::MAX / max_block_emission) blocks ≈ billions of years,
    /// so the reachability is via bug / attack rather than natural
    /// growth. We now detect a would-saturate condition via
    /// `checked_add` first and emit a LOUD ERROR log if it fires.
    /// The state is left at the saturation value (the same as
    /// before) so the caller doesn't crash; but ops can now see the
    /// event in structured logs and page immediately.
    pub fn apply_block(&mut self, emission: u64, burned: u64, height: u64) {
        self.height = height;
        match self.total_minted.checked_add(emission) {
            Some(v) => self.total_minted = v,
            None => {
                tracing::error!(
                    target: "audit_supply",
                    event = "total_minted_saturated",
                    total_minted = self.total_minted,
                    emission = emission,
                    height = height,
                    "SUPPLY AUDIT: total_minted would overflow u64 at height {} \
                     (current {}, +emission {}). Clamping at u64::MAX; every future \
                     emission from this height forward will silently vanish from the \
                     audit. This is either a chain bug or an attack — investigate NOW.",
                    height, self.total_minted, emission,
                );
                self.total_minted = u64::MAX;
            }
        }
        match self.total_burned.checked_add(burned) {
            Some(v) => self.total_burned = v,
            None => {
                tracing::error!(
                    target: "audit_supply",
                    event = "total_burned_saturated",
                    total_burned = self.total_burned,
                    burned = burned,
                    height = height,
                    "SUPPLY AUDIT: total_burned would overflow u64 at height {} \
                     (current {}, +burned {}). Clamping at u64::MAX.",
                    height, self.total_burned, burned,
                );
                self.total_burned = u64::MAX;
            }
        }
        self.update_commitment();
    }

    pub fn verify(&self, expected_supply: u64) -> bool {
        self.circulating() == expected_supply
    }

    fn update_commitment(&mut self) {
        self.supply_commitment = *hash_domain(
            b"supply_commitment",
            &[self.total_minted.to_le_bytes().as_slice(), self.total_burned.to_le_bytes().as_slice()].concat(),
        ).as_bytes();
    }
}

#[derive(Clone, Debug)]
pub struct BlockAudit {
    pub height: u64,
    pub supply_valid: bool,
    pub fees_valid: bool,
    pub emission_valid: bool,
    pub issues: Vec<String>,
}

impl BlockAudit {
    pub fn is_valid(&self) -> bool {
        self.supply_valid && self.fees_valid && self.emission_valid && self.issues.is_empty()
    }

    pub fn summary(&self) -> String {
        if self.is_valid() { format!("Block {} audit: PASSED", self.height) }
        else { format!("Block {} audit: FAILED - {}", self.height, self.issues.join(", ")) }
    }
}

/// Audit a block's supply, fees, and emission.
/// FIX: Uses constants for burn%, tolerance=0, height check separate from supply_valid.
#[allow(dead_code)]
pub fn audit_block(
    height: u64, emission: Amount, expected_emission: Amount,
    total_fees: Amount, fee_distribution_valid: bool, congested: bool,
    supply_before: &SupplyState, supply_after: &SupplyState,
) -> BlockAudit {
    let mut issues = Vec::new();
    let emission_valid = emission == expected_emission;
    if !emission_valid { issues.push(format!("Emission mismatch: got {}, expected {}", emission, expected_emission)); }
    if !fee_distribution_valid { issues.push("Fee distribution invalid".into()); }

    let burn_pct = if congested { FEE_BURN_CONGESTED_PERCENT } else { FEE_BURN_NORMAL_PERCENT };
    // R-32 site 2/3: use u128 intermediate to keep `total_fees * burn_pct`
    // representable up to u64::MAX * 100; then narrow back. `burn_pct` is
    // 0..=100 by construction of the constant, so the u128 result is
    // <= total_fees.as_atomic() and always fits in u64.
    let approximate_burn = ((total_fees.as_atomic() as u128) * (burn_pct as u128) / 100) as u64;
    // R-32 site 2/3 (continued): saturating arithmetic on the expected
    // circulating supply matches SupplyState's saturating semantics —
    // if the underlying arithmetic saturates in apply_block, the audit
    // math here must match, otherwise supply_valid would false-flag.
    // The `apply_block` fix emits a loud log on saturation; the audit
    // path here inherits that visibility because a supply mismatch at
    // saturation triggers the "Supply mismatch" issue below.
    let expected_circulating = supply_before.circulating()
        .saturating_add(emission.as_atomic())
        .saturating_sub(approximate_burn);

    if supply_after.height != height {
        issues.push(format!("Supply height mismatch: expected {}, got {}", height, supply_after.height));
    }

    let diff = supply_after.circulating().abs_diff(expected_circulating);
    let supply_valid = diff == 0;
    if diff > 0 { issues.push(format!("Supply mismatch: expected {}, got {}", expected_circulating, supply_after.circulating())); }

    BlockAudit { height, supply_valid, fees_valid: fee_distribution_valid, emission_valid, issues }
}

/// A self-consistent checksum over a [`SupplyState`] snapshot — **not** an
/// authenticated proof (issue #252).
///
/// `proof_hash` is an *unkeyed*, domain-separated hash over the snapshot's
/// own public fields (`height`, `total_minted`, `total_burned`). Because
/// every input is public and there is no secret key or chain-anchored
/// binding, [`verify`](Self::verify) only confirms the snapshot is
/// internally consistent (the hash matches the fields, and `circulating`
/// is the correct derived value). It does **not** prove the figures
/// reflect the real chain state: anyone can construct a snapshot with
/// arbitrary supply numbers that passes `verify()`.
///
/// Use it as a tamper-evident checksum for transporting a supply reading,
/// not as evidence of authenticity. Binding `proof_hash` to the block
/// header's `supply_commitment` would make it a real proof; that is
/// deferred until a consumer needs it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupplySnapshot {
    pub height: u64, pub circulating: u64, pub total_minted: u64, pub total_burned: u64, pub proof_hash: Hash,
}

/// Deprecated: the type was never an authenticated proof. See
/// [`SupplySnapshot`] and issue #252. Kept one release as a compat shim.
#[deprecated(note = "renamed to SupplySnapshot: it is a self-consistent checksum, not an authenticated proof (issue #252)")]
#[allow(dead_code)]
pub type SupplyProof = SupplySnapshot;

impl SupplySnapshot {
    pub fn from_state(state: &SupplyState) -> Self {
        let proof_hash = hash_domain(b"supply_proof",
            &[state.height.to_le_bytes().as_slice(), state.total_minted.to_le_bytes().as_slice(), state.total_burned.to_le_bytes().as_slice()].concat());
        SupplySnapshot { height: state.height, circulating: state.circulating(), total_minted: state.total_minted, total_burned: state.total_burned, proof_hash }
    }

    /// Confirm the snapshot is internally self-consistent. Returns `true`
    /// iff `circulating == total_minted - total_burned` and `proof_hash`
    /// matches the recomputed checksum over the public fields.
    ///
    /// This is a checksum check, not authentication — see the type-level
    /// docs. A `true` result does **not** attest that these figures came
    /// from the canonical chain.
    pub fn verify(&self) -> bool {
        // AUDIT (2026-07-01): `circulating` is not covered by `proof_hash`
        // (only height, total_minted, total_burned are). Without this
        // invariant check, a caller could hand out a snapshot whose
        // `circulating` field is arbitrary while the hash still verifies,
        // and any consumer that reads `.circulating` directly would trust
        // it. Enforce the derivation here so `verify() == true` implies
        // `circulating == total_minted - total_burned`.
        if self.circulating != self.total_minted.saturating_sub(self.total_burned) {
            return false;
        }
        let expected = hash_domain(b"supply_proof",
            &[self.height.to_le_bytes().as_slice(), self.total_minted.to_le_bytes().as_slice(), self.total_burned.to_le_bytes().as_slice()].concat());
        self.proof_hash == expected
    }
}

#[allow(dead_code)]
pub fn verify_commitment_balance(input_commitments: &[PedersenCommitment], output_commitments: &[PedersenCommitment], fee: Amount) -> bool {
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::traits::Identity;
    use crate::crypto::BlindingFactor;

    if input_commitments.is_empty() { return false; }
    let mut input_sum = RistrettoPoint::identity();
    for c in input_commitments {
        match CompressedRistretto(c.to_bytes()).decompress() { Some(p) => input_sum += p, None => return false }
    }
    let mut output_sum = RistrettoPoint::identity();
    for c in output_commitments {
        match CompressedRistretto(c.to_bytes()).decompress() { Some(p) => output_sum += p, None => return false }
    }
    let fee_commitment = PedersenCommitment::commit(fee.as_atomic(), &BlindingFactor::zero());
    let fee_point = match CompressedRistretto(fee_commitment.to_bytes()).decompress() { Some(p) => p, None => return false };
    input_sum == output_sum + fee_point
}

pub type SupplyCommitment = SupplyState;
pub type SupplyAuditResult = BlockAudit;
/// Deprecated: the "audit proof" was never authenticated. See
/// [`SupplySnapshot`] and issue #252.
#[deprecated(note = "renamed to SupplySnapshot: self-consistent checksum, not an authenticated proof (issue #252)")]
#[allow(deprecated)]
pub type SupplyAuditProof = SupplySnapshot;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockSupplyDelta { pub height: u64, pub emission: u64, pub burned: u64, pub net_change: i64 }

impl BlockSupplyDelta {
    /// AUDIT (R-32 site 3/3, 2026-07-02): `net_change` uses i128
    /// intermediate + clamp to i64 because a single block's
    /// (emission - burned) always fits well within i64 for any
    /// realistic block, but a corrupt/adversarial input could
    /// exercise the clamp. The clamp is CORRECT (matches the
    /// `saturating` semantics of `apply_block`), but a silent clamp
    /// hides the underlying corruption. Log an error on clamp so
    /// ops see the event.
    pub fn new(height: u64, emission: Amount, burned: Amount) -> Self {
        let net_i128 = (emission.as_atomic() as i128) - (burned.as_atomic() as i128);
        let clamped = net_i128.clamp(i64::MIN as i128, i64::MAX as i128);
        if clamped != net_i128 {
            tracing::error!(
                target: "audit_supply",
                event = "net_change_clamped",
                emission = emission.as_atomic(),
                burned = burned.as_atomic(),
                height = height,
                "SUPPLY AUDIT: net_change ({}) clamped to fit i64 at height {}. \
                 A single block's emission-burn should never approach i64 range; \
                 this indicates upstream input corruption.",
                net_i128, height,
            );
        }
        BlockSupplyDelta {
            height, emission: emission.as_atomic(), burned: burned.as_atomic(),
            net_change: clamped as i64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_state() {
        let mut state = SupplyState::genesis();
        assert_eq!(state.circulating(), 0);
        state.apply_block(1_000_000, 100_000, 1);
        assert_eq!(state.circulating(), 900_000);
    }

    #[test]
    fn test_supply_proof() {
        let mut state = SupplyState::genesis();
        state.apply_block(5_000_000, 500_000, 100);
        let proof = SupplySnapshot::from_state(&state);
        assert!(proof.verify());
    }

    #[test]
    fn test_multi_block_accumulation() {
        let mut state = SupplyState::genesis();
        state.apply_block(1_000_000, 0, 1);
        assert_eq!(state.total_minted, 1_000_000);
        state.apply_block(2_000_000, 100_000, 2);
        assert_eq!(state.total_minted, 3_000_000);
        assert_eq!(state.circulating(), 2_900_000);
    }

    #[test]
    fn test_supply_proof_tamper() {
        let mut state = SupplyState::genesis();
        state.apply_block(1_000_000, 50_000, 5);
        let mut proof = SupplySnapshot::from_state(&state);
        assert!(proof.verify());
        proof.total_minted += 1;
        assert!(!proof.verify());
    }

    #[test]
    fn test_supply_proof_circulating_tamper_rejected() {
        // AUDIT (2026-07-01): regression for the soundness gap where
        // `circulating` was inside SupplyProof but not covered by the hash.
        // Verify() must reject a proof whose `circulating` field disagrees
        // with total_minted - total_burned, even though proof_hash is valid.
        let mut state = SupplyState::genesis();
        state.apply_block(1_000_000, 50_000, 5);
        let mut proof = SupplySnapshot::from_state(&state);
        assert!(proof.verify(), "clean proof should verify");
        // Tamper only the derived field. The hash is untouched.
        proof.circulating = proof.circulating.saturating_add(1);
        assert!(!proof.verify(), "verify() must reject inconsistent circulating");
    }
}
