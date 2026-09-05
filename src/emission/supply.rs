//! Supply auditability: the canonical supply commitment.
//!
//! # What this is
//!
//! [`supply_commitment`] is **the single definition** of the value carried in
//! `BlockHeader::supply_commitment`. It binds a block header to the chain's
//! cumulative issuance and burn at that height, so a supply reading can be
//! *verified against a block* instead of trusted from an RPC.
//!
//! Because the field is part of the header pre-image, the commitment is covered
//! by the block's proof of work: a chain claiming different cumulative supply at
//! a height must redo the work for that block and every block after it.
//!
//! # Why there is exactly one function
//!
//! This module previously carried `calculate_supply_commitment(&SupplyStats)` —
//! a hash over `emitted ‖ burned ‖ circulating ‖ emission_remaining` under the
//! domain `"COINCYNC_SUPPLY_COMMITMENT"` — while `crypto::audit::SupplyState`
//! carried a *different* commitment over `minted ‖ burned` under the domain
//! `"supply_commitment"`. Neither had a caller, neither populated the header,
//! and the two disagreed on both inputs and domain separator.
//!
//! Two implementations of one consensus value that must agree is the failure
//! shape documented in `docs/whitepapers/WP-006-cumulative-work-determinism.md`
//! §4.4 — it has already cost this project a fleet-wide divergence once. The
//! rule adopted there is: **when a value is computed in more than one place, one
//! of them is the definition and the others must call it.** Both former
//! implementations are gone; this function is the definition, and the miner
//! (`mining::block_builder`) and the validator (`Blockchain::connect`) both call
//! it.
//!
//! The dropped fields were redundant in any case: `circulating` is
//! `minted − burned` and `emission_remaining` is a pure function of height, so
//! committing to them added no information and two more ways to disagree.
//!
//! (The removed function's doc-comment described it as a "Pedersen commitment to
//! supply". It was a plain domain-separated hash, not a Pedersen commitment.
//! This one is also a hash, and says so.)

use crate::primitives::hash_domain;

/// Domain separator for the block-header supply commitment.
///
/// Versioned: any change to the committed field set or their encoding requires
/// a new domain (`_v2`), never a silent redefinition of this one.
pub const SUPPLY_COMMITMENT_DOMAIN: &[u8] = b"CYNC_SUPPLY_COMMITMENT_v1";

/// The canonical block-header supply commitment.
///
/// `total_minted` and `total_burned` are the chain's **cumulative** atomic-unit
/// totals *after* applying the block at `height`:
///
/// ```text
/// total_minted(h) = total_minted(h-1) + calculate_block_reward(h)
/// total_burned(h) = total_burned(h-1) + block_fee_burn(block_h)
/// ```
///
/// Both per-block deltas are pure functions of public data — the reward of the
/// height, and the fee-burn of the block itself — so any party holding the chain
/// can recompute the whole series independently.
///
/// # Genesis
///
/// Height 0 returns all-zero. Genesis is already pinned by its hard-coded
/// `GENESIS_HASH` constant, so its header content needs no separate commitment,
/// and special-casing it here (rather than at each call site) keeps the miner
/// and the validator from disagreeing about the exception — the whole point of
/// having one function.
///
/// # Encoding
///
/// Little-endian, fixed width, in order: `height` (u64), `total_minted` (u128),
/// `total_burned` (u128). Fixed-width fields concatenated in a fixed order are
/// unambiguous without a length prefix.
pub fn supply_commitment(height: u64, total_minted: u128, total_burned: u128) -> [u8; 32] {
    if height == 0 {
        return [0u8; 32];
    }

    let mut buf = [0u8; 8 + 16 + 16];
    buf[..8].copy_from_slice(&height.to_le_bytes());
    buf[8..24].copy_from_slice(&total_minted.to_le_bytes());
    buf[24..].copy_from_slice(&total_burned.to_le_bytes());

    *hash_domain(SUPPLY_COMMITMENT_DOMAIN, &buf).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_commitment_is_zero() {
        // Genesis keeps the all-zero placeholder so the pinned GENESIS_HASH
        // constants stay valid. Non-zero totals at height 0 are impossible, but
        // the height check must dominate regardless.
        assert_eq!(supply_commitment(0, 0, 0), [0u8; 32]);
        assert_eq!(supply_commitment(0, 12_345, 678), [0u8; 32]);
    }

    #[test]
    fn commitment_is_deterministic() {
        let a = supply_commitment(100, 5_000_000, 1_234);
        let b = supply_commitment(100, 5_000_000, 1_234);
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn every_field_changes_the_commitment() {
        let base = supply_commitment(100, 5_000_000, 1_234);
        assert_ne!(base, supply_commitment(101, 5_000_000, 1_234), "height");
        assert_ne!(base, supply_commitment(100, 5_000_001, 1_234), "minted");
        assert_ne!(base, supply_commitment(100, 5_000_000, 1_235), "burned");
    }

    #[test]
    fn minted_and_burned_are_not_interchangeable() {
        // A concatenation without fixed widths could let a shift in one field
        // be absorbed by the other. Fixed-width encoding must prevent that.
        assert_ne!(supply_commitment(7, 1, 0), supply_commitment(7, 0, 1));
    }

    #[test]
    fn large_totals_do_not_truncate() {
        // Supply is tracked in u128 precisely so the protocol total (~10^20
        // atomic units) cannot overflow. Values above u64::MAX must still be
        // distinguishable — a u64 truncation bug would collide these.
        let a = supply_commitment(1, u128::from(u64::MAX) + 1, 0);
        let b = supply_commitment(1, 0, 0);
        assert_ne!(a, b);
        let c = supply_commitment(1, u128::from(u64::MAX) + 2, 0);
        assert_ne!(a, c);
    }
}
