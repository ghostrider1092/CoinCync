//! # Blockchain Auditing for CoinCync 2.0
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

    pub fn apply_block(&mut self, emission: u64, burned: u64, height: u64) {
        self.height = height;
        self.total_minted = self.total_minted.saturating_add(emission);
        self.total_burned = self.total_burned.saturating_add(burned);
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
    let approximate_burn = total_fees.as_atomic() * burn_pct / 100;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupplyProof {
    pub height: u64, pub circulating: u64, pub total_minted: u64, pub total_burned: u64, pub proof_hash: Hash,
}

impl SupplyProof {
    pub fn from_state(state: &SupplyState) -> Self {
        let proof_hash = hash_domain(b"supply_proof",
            &[state.height.to_le_bytes().as_slice(), state.total_minted.to_le_bytes().as_slice(), state.total_burned.to_le_bytes().as_slice()].concat());
        SupplyProof { height: state.height, circulating: state.circulating(), total_minted: state.total_minted, total_burned: state.total_burned, proof_hash }
    }

    pub fn verify(&self) -> bool {
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
pub type SupplyAuditProof = SupplyProof;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockSupplyDelta { pub height: u64, pub emission: u64, pub burned: u64, pub net_change: i64 }

impl BlockSupplyDelta {
    pub fn new(height: u64, emission: Amount, burned: Amount) -> Self {
        BlockSupplyDelta {
            height, emission: emission.as_atomic(), burned: burned.as_atomic(),
            net_change: ((emission.as_atomic() as i128) - (burned.as_atomic() as i128)).clamp(i64::MIN as i128, i64::MAX as i128) as i64,
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
        let proof = SupplyProof::from_state(&state);
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
        let mut proof = SupplyProof::from_state(&state);
        assert!(proof.verify());
        proof.total_minted += 1;
        assert!(!proof.verify());
    }
}
