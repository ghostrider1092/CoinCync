//! Transaction-wide ring allocation from a validated covered response.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `real-set match`** — INVARIANT: the supplied real outputs must equal
//!   the request's real locators as an ordered set. THREAT: substituting or
//!   reordering the real member being spent.
//!   TESTS: `allocation_rejects_real_output_order_mismatch`,
//!   `allocation_reports_missing_real_output_when_response_index_omits_it`.
//! - **§2 `real identity binding`** — INVARIANT: each real output's resolved
//!   public key and commitment must equal the wallet-supplied identity, and no
//!   two reals may share a public key. THREAT: a forged or mismatched real
//!   member slips into the ring. TESTS: `allocation_rejects_real_identity_mismatch`,
//!   `allocation_rejects_duplicate_real_public_key`.
//! - **§3 `candidate filtering`** — INVARIANT: decoys above `max_decoy_height`
//!   (min-age) or locked at the spend height are excluded. THREAT: immature or
//!   locked decoys produce invalid rings or leak spend timing.
//!   TESTS: `allocation_filters_decoys_above_the_max_decoy_height`,
//!   `allocation_filters_a_locked_decoy_but_still_allocates`,
//!   `lock_height_is_checked_at_the_next_spend_height`.
//! - **§4 `identity-point exclusion`** — INVARIANT: an all-zero (identity-point)
//!   public key or commitment is never placed in a ring, mirroring the CLSAG
//!   verifier. THREAT: the genesis placeholder in a ring fails the whole input's
//!   signature. TESTS: `allocation_excludes_identity_point_decoys`.
//! - **§5 `decoy uniqueness / sufficiency`** — INVARIANT: each decoy public key
//!   is used at most once across the transaction; too few candidates or a size
//!   overflow are rejected, never panicked. THREAT: cross-ring decoy reuse links
//!   inputs. TESTS: `allocation_uses_no_repeated_decoy_public_key_across_rings`,
//!   `allocation_reports_insufficient_decoys_when_candidate_pool_too_small`,
//!   `allocation_reports_ring_allocation_size_overflow`.
//! - **§6 `real member placement`** — INVARIANT: every ring has the same ring
//!   size and the real member sits at a uniformly random secret index within
//!   bounds. THREAT: a predictable real position defeats ring privacy; ring-size
//!   divergence (incident 1d27d3c8).
//!   TESTS: `allocation_places_real_member_at_the_secret_index_in_every_ring`,
//!   `allocation_places_the_real_index_within_ring_bounds`.

use super::error::{DecoySelectionError, DecoySelectionResult};
use super::types::{
    AllocatedRing, AllocatedRings, RealOutputIdentity, ValidatedCoveredResponse,
};
use crate::transaction::DecoyOutput;
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use std::collections::HashSet;

pub fn allocate_unique_rings<R: RngCore + CryptoRng + ?Sized>(
    response: ValidatedCoveredResponse,
    real_outputs: &[RealOutputIdentity],
    rng: &mut R,
) -> DecoySelectionResult<AllocatedRings> {
    let request = response.request();
    if real_outputs.len() != request.real_locators().len()
        || !real_outputs
            .iter()
            .map(|output| output.locator())
            .eq(request.real_locators().iter().copied())
    {
        return Err(DecoySelectionError::RealOutputSetMismatch);
    }

    let mut used_public_keys = HashSet::with_capacity(real_outputs.len());
    for real in real_outputs {
        let resolved = response
            .resolved(&real.locator())
            .ok_or(DecoySelectionError::MissingRealOutput(real.locator()))?;
        if resolved.public_key != real.public_key()
            || resolved.commitment != real.commitment()
        {
            return Err(DecoySelectionError::RealOutputIdentityMismatch(
                real.locator(),
            ));
        }
        if !used_public_keys.insert(*real.public_key().as_bytes()) {
            return Err(DecoySelectionError::DuplicateRealPublicKey);
        }
    }

    let spend_height = request.spend_height();
    let max_decoy_height = request.max_decoy_height();
    let mut candidates: Vec<_> = response
        .outputs()
        .iter()
        .filter(|output| !request.real_locator_set().contains(&output.locator))
        .filter(|output| {
            max_decoy_height.is_some_and(|height| output.locator.height <= height)
        })
        .filter(|output| {
            output
                .lock_height
                .map_or(true, |height| spend_height >= height)
        })
        // Never select an identity-point output as a decoy. The genesis
        // coinbase is a placeholder with an all-zero (identity-point) public
        // key and commitment (testnet.rs / mainnet.rs create_genesis_coinbase),
        // and it is added to the canonical output catalog like any other
        // output, so the sampler can draw it — most likely early in a chain's
        // life when the eligible pool is small. The CLSAG verifier rejects any
        // ring member whose public key OR commitment is the identity point
        // (crypto/clsag.rs), so a ring containing it fails with "Ring signature
        // verification failed" for that one input. Mirror that guard here at
        // selection time so such an output is never placed in a ring.
        .filter(|output| {
            *output.public_key.as_bytes() != [0u8; 32] && output.commitment != [0u8; 32]
        })
        .filter(|output| used_public_keys.insert(*output.public_key.as_bytes()))
        .collect();

    let ring_size = request.ring_size();
    let decoys_per_ring = ring_size - 1;
    let needed = real_outputs
        .len()
        .checked_mul(decoys_per_ring)
        .ok_or(DecoySelectionError::RingAllocationSizeOverflow {
            input_count: real_outputs.len(),
            ring_size,
        })?;
    if candidates.len() < needed {
        return Err(DecoySelectionError::InsufficientDecoys {
            available: candidates.len(),
            needed,
        });
    }
    candidates.shuffle(rng);

    let rings = (0..real_outputs.len())
        .map(|ring_index| {
            let start = ring_index * decoys_per_ring;
            let decoys = candidates[start..start + decoys_per_ring]
                .iter()
                .map(|output| DecoyOutput {
                    public_key: output.public_key,
                    commitment: output.commitment,
                    height: output.locator.height,
                })
                .collect();
            AllocatedRing::new(decoys, rng.gen_range(0..ring_size))
        })
        .collect();

    Ok(AllocatedRings::new(
        ring_size,
        real_outputs.to_vec(),
        rings,
    ))
}
