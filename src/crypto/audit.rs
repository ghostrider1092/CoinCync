//! # Blockchain Auditing for CoinCync 1.0
//!
//! "The privacy coin you can audit"
//! Verify supply, fees, and ring quality without seeing private data.

use crate::primitives::{Hash, Amount, hash_domain};
use crate::crypto::PedersenCommitment;
use crate::constants::{FEE_BURN_NORMAL_PERCENT, FEE_BURN_CONGESTED_PERCENT};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

/// Aggregate totals use `u128` because the protocol supply can reach 10^20 atomic units.
#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SupplyState {
    pub height: u64,
    pub total_minted: u128,
    pub total_burned: u128,
    pub supply_commitment: [u8; 32],
}

impl SupplyState {
    pub fn genesis() -> Self { SupplyState::default() }

    pub fn circulating(&self) -> u128 {
        self.total_minted.saturating_sub(self.total_burned)
    }

    /// Apply a block's emission and burn.
    pub fn apply_block(&mut self, emission: u64, burned: u64, height: u64) {
        let total_minted = self
            .total_minted
            .checked_add(u128::from(emission))
            .expect("valid protocol supply fits in u128");
        let total_burned = self
            .total_burned
            .checked_add(u128::from(burned))
            .expect("valid protocol burn total fits in u128");

        self.height = height;
        self.total_minted = total_minted;
        self.total_burned = total_burned;
        self.update_commitment();
    }

    pub fn verify(&self, expected_supply: u128) -> bool {
        self.circulating() == expected_supply
    }

    fn update_commitment(&mut self) {
        self.supply_commitment = *hash_domain(
            b"supply_commitment",
            &[
                self.total_minted.to_le_bytes().as_slice(),
                self.total_burned.to_le_bytes().as_slice(),
            ]
            .concat(),
        )
        .as_bytes();
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
    let approximate_burn = u128::from(total_fees.as_atomic()) * u128::from(burn_pct) / 100;
    let expected_circulating = supply_before
        .circulating()
        .checked_add(u128::from(emission.as_atomic()))
        .expect("valid protocol supply fits in u128")
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
    pub height: u64, pub circulating: u128, pub total_minted: u128, pub total_burned: u128, pub proof_hash: Hash,
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
    fn test_supply_state_preserves_values_above_u64_max() {
        let mut state = SupplyState {
            total_minted: u128::from(u64::MAX) - 5,
            total_burned: u128::from(u64::MAX) - 100,
            ..SupplyState::genesis()
        };

        state.apply_block(200, 150, 1);

        assert_eq!(state.total_minted, u128::from(u64::MAX) + 195);
        assert_eq!(state.total_burned, u128::from(u64::MAX) + 50);
        assert_eq!(state.circulating(), 145);

        let encoded = borsh::to_vec(&state).expect("serialize supply state");
        let decoded: SupplyState = borsh::from_slice(&encoded).expect("deserialize supply state");
        assert_eq!(decoded.total_minted, state.total_minted);
        assert_eq!(decoded.total_burned, state.total_burned);

        let snapshot = SupplySnapshot::from_state(&state);
        let json = serde_json::to_string(&snapshot).expect("serialize supply snapshot");
        let decoded: SupplySnapshot =
            serde_json::from_str(&json).expect("deserialize supply snapshot");
        assert_eq!(decoded.total_minted, snapshot.total_minted);
        assert_eq!(decoded.total_burned, snapshot.total_burned);
        assert!(decoded.verify());
    }

    #[test]
    fn test_block_audit_accepts_circulating_supply_above_u64_max() {
        let total_fees = 1_000u64;
        let burned = total_fees * FEE_BURN_NORMAL_PERCENT / 100;
        let before = SupplyState {
            total_minted: u128::from(u64::MAX) - 100,
            ..SupplyState::genesis()
        };
        let mut after = before.clone();
        after.apply_block(1_000, burned, 1);

        let audit = audit_block(
            1,
            Amount::from_atomic(total_fees),
            Amount::from_atomic(1_000),
            Amount::from_atomic(1_000),
            true,
            false,
            &before,
            &after,
        );

        assert!(after.circulating() > u128::from(u64::MAX));
        assert!(audit.is_valid(), "{}", audit.summary());
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
