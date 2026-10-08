//! # Transparent heavy-verify through the Sluice (Warren Phase 0 — §3.0/§3.7)
//!
//! Brings the two TRANSPARENT heavy-verify primitives — Bulletproofs range
//! proofs and CLSAG ring signatures — under the same
//! [`HeavyVerify`](crate::crypto::heavy_verify::HeavyVerify) / Sluice valve that
//! governs Spark (`crypto::spark_sluice`). With this, the valve is genuinely
//! unified across ALL heavy paths in the §3.0 inventory, not Spark-only, and
//! adding a future engine is "implement one trait", not "touch the block
//! validator".
//!
//! ## These are ADAPTERS, not replacements
//! Each `verify_one` wraps the existing, audited single-item verify
//! (`verify_range_proof`, `clsag_verify`) with byte-for-byte the same logic the
//! live paths use (the range-proof adapter mirrors
//! `ParallelProofVerifier::verify_single` exactly: parse → checked commitment
//! decode → verify). They do NOT replace `parallel_proofs.rs` or the ring-sig
//! batch in the block validator — they are the seam a future migration drops
//! into, and the tests here prove the Sluice path yields the IDENTICAL
//! accept/reject verdict as the existing verifier at every valve width.
//!
//! Non-gated: transparent verification is production, so (unlike Spark) there is
//! no backend-reentrancy question — these primitives are pure Rust and safe to
//! fan out on any valve.

use crate::crypto::cache::{proof_cache_key, ring_sig_statement_cache_key};
use crate::crypto::heavy_verify::{HeavyVerify, Sluice};
use crate::crypto::verify_cache::VerifyResultCache;
use crate::crypto::{
    clsag_verify, verify_range_proof, ClsagRingMember, ClsagSignature, EcCommitment,
    PedersenCommitment, RangeProof,
};

// ── Bulletproofs range proofs ───────────────────────────────────────────────

/// One range-proof verification unit: a Pedersen commitment (32 bytes) and the
/// serialized range proof. Mirrors `parallel_proofs::ProofTask`'s two fields.
#[derive(Clone)]
pub struct RangeProofItem {
    pub commitment: [u8; 32],
    pub proof_bytes: Vec<u8>,
}

/// `HeavyVerify` adapter for Bulletproofs range proofs.
pub struct RangeProofVerify;

impl HeavyVerify for RangeProofVerify {
    type Item = RangeProofItem;
    type Output = ();
    type Error = ();

    /// Byte-for-byte the logic of `ParallelProofVerifier::verify_single`: parse
    /// the proof, checked-decode the commitment (rejects non-Ristretto points —
    /// A6-COMMITMENT), then verify. Pure over `&self` + `item`.
    fn verify_one(&self, item: &RangeProofItem) -> Result<(), ()> {
        let proof = RangeProof::from_bytes(&item.proof_bytes).map_err(|_| ())?;
        let commitment = PedersenCommitment::from_bytes_checked(item.commitment).ok_or(())?;
        if verify_range_proof(&commitment, &proof) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Cacheable: a range proof's validity is a pure function of (proof,
    /// commitment). Same key the existing `ParallelProofVerifier` uses, so the
    /// two engines share cache slots.
    fn cache_key(&self, item: &RangeProofItem) -> Option<[u8; 32]> {
        Some(proof_cache_key(&item.proof_bytes, &item.commitment))
    }
}

/// Verify a batch of range proofs through the valve, consulting `cache` to skip
/// re-verification of previously-valid proofs (mempool→block→reorg). Positive
/// results are recorded. Identical verdict with or without the cache.
pub fn verify_range_proofs_cached(
    items: &[RangeProofItem],
    valve: &Sluice,
    cache: &dyn VerifyResultCache,
) -> Vec<bool> {
    valve.verify_valid_cached(&RangeProofVerify, items, cache)
}

/// Verify a batch of range proofs through the valve, returning per-item validity
/// in input order. Identical verdict at any valve width (the Sluice invariant).
pub fn verify_range_proofs_via_sluice(items: &[RangeProofItem], valve: &Sluice) -> Vec<bool> {
    valve
        .verify(&RangeProofVerify, items, || ())
        .into_iter()
        .map(|r| r.is_ok())
        .collect()
}

// ── CLSAG ring signatures ───────────────────────────────────────────────────

/// One CLSAG verification unit. Owned (not borrowed) so it is `Sync` and can be
/// moved into the verify pool; the curve types are plain data.
#[derive(Clone)]
pub struct ClsagItem {
    pub message: Vec<u8>,
    pub ring: Vec<ClsagRingMember>,
    pub pseudo_output: EcCommitment,
    pub signature: ClsagSignature,
}

/// `HeavyVerify` adapter for CLSAG ring signatures.
pub struct ClsagVerify;

impl HeavyVerify for ClsagVerify {
    type Item = ClsagItem;
    type Output = ();
    type Error = ();

    fn verify_one(&self, item: &ClsagItem) -> Result<(), ()> {
        if clsag_verify(&item.message, &item.ring, &item.pseudo_output, &item.signature) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Cacheable: a CLSAG verdict is a pure function of (message, signature,
    /// ring, pseudo-output). The key commits to all four (the audited
    /// `ring_sig_statement_cache_key`), so distinct statements never share a
    /// slot. `None` only if serialization fails (then the item is simply never
    /// cached — fail-safe).
    fn cache_key(&self, item: &ClsagItem) -> Option<[u8; 32]> {
        let sig_data = borsh::to_vec(&item.signature).ok()?;
        let ring_data = borsh::to_vec(&item.ring).ok()?;
        let pseudo = item.pseudo_output.to_bytes();
        Some(ring_sig_statement_cache_key(&item.message, &sig_data, &ring_data, &pseudo))
    }
}

/// Verify a batch of CLSAG signatures through the valve, consulting `cache` to
/// skip re-verification of previously-valid signatures. Identical verdict with
/// or without the cache.
pub fn verify_clsag_cached(
    items: &[ClsagItem],
    valve: &Sluice,
    cache: &dyn VerifyResultCache,
) -> Vec<bool> {
    valve.verify_valid_cached(&ClsagVerify, items, cache)
}

/// Verify a batch of CLSAG signatures through the valve, in input order.
pub fn verify_clsag_via_sluice(items: &[ClsagItem], valve: &Sluice) -> Vec<bool> {
    valve
        .verify(&ClsagVerify, items, || ())
        .into_iter()
        .map(|r| r.is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::heavy_verify::assert_valve_invariant;

    /// Range-proof adapter ≡ the EXISTING `ParallelProofVerifier` engine, at
    /// every valve width: same valid set, same flagged-invalid positions.
    #[test]
    fn range_proof_sluice_matches_existing_engine_at_every_width() {
        use crate::crypto::{
            create_range_proof, BlindingFactor, ParallelProofVerifier, PedersenCommitment, ProofTask,
        };
        use crate::primitives::Amount;
        use rand::rngs::OsRng;

        let mk_valid = |v: u64| -> RangeProofItem {
            let blinding = BlindingFactor::random(&mut OsRng);
            let proof = create_range_proof(Amount::from_atomic(v), &blinding, &mut OsRng).unwrap();
            RangeProofItem {
                commitment: PedersenCommitment::commit(v, &blinding).to_bytes(),
                proof_bytes: proof.try_to_bytes().unwrap(),
            }
        };
        // Invalid: a well-formed proof paired with a valid-but-MISMATCHED
        // commitment (exercises the real range check, not just point decode).
        let invalid = RangeProofItem {
            commitment: PedersenCommitment::commit(999, &BlindingFactor::random(&mut OsRng))
                .to_bytes(),
            proof_bytes: mk_valid(500).proof_bytes,
        };
        let items = vec![mk_valid(1000), mk_valid(2_000_000), invalid, mk_valid(42)];

        // Ground truth from the EXISTING engine (cache off → deterministic).
        let mut engine = ParallelProofVerifier::without_cache();
        engine.add_all(
            items
                .iter()
                .map(|it| ProofTask::new(it.commitment, it.proof_bytes.clone()))
                .collect(),
        );
        let expected_invalid = engine.verify_all().invalid_indices; // [2]
        assert_eq!(expected_invalid, vec![2]);

        // The Sluice adapter must reproduce it exactly at every width.
        for valve in [Sluice::serial(), Sluice::with_threads(2), Sluice::with_threads(4)] {
            let valid = verify_range_proofs_via_sluice(&items, &valve);
            let got_invalid: Vec<usize> =
                valid.iter().enumerate().filter(|(_, ok)| !**ok).map(|(i, _)| i).collect();
            assert_eq!(got_invalid, expected_invalid, "sluice diverged from existing engine");
        }
        assert_valve_invariant(&RangeProofVerify, &items, || ());
    }

    /// The verify-result cache skips re-verification of previously-valid proofs
    /// (mempool→block→reorg) WITHOUT changing the verdict: cold and warm passes
    /// agree with the uncached result, only VALID proofs are cached
    /// (positive-only), and the warm pass is width-independent.
    #[test]
    fn range_proof_cache_skips_reverify_and_matches_uncached() {
        use crate::crypto::verify_cache::{LruVerifyCache, VerifyResultCache};
        use crate::crypto::{create_range_proof, BlindingFactor, PedersenCommitment};
        use crate::primitives::Amount;
        use rand::rngs::OsRng;

        let mk_valid = |v: u64| -> RangeProofItem {
            let blinding = BlindingFactor::random(&mut OsRng);
            let proof = create_range_proof(Amount::from_atomic(v), &blinding, &mut OsRng).unwrap();
            RangeProofItem {
                commitment: PedersenCommitment::commit(v, &blinding).to_bytes(),
                proof_bytes: proof.try_to_bytes().unwrap(),
            }
        };
        let invalid = RangeProofItem {
            commitment: PedersenCommitment::commit(999, &BlindingFactor::random(&mut OsRng))
                .to_bytes(),
            proof_bytes: mk_valid(500).proof_bytes,
        };
        let items = vec![mk_valid(10), mk_valid(20), invalid, mk_valid(30)];

        let uncached = verify_range_proofs_via_sluice(&items, &Sluice::with_threads(4));
        assert_eq!(uncached, vec![true, true, false, true]);

        let cache = LruVerifyCache::default();
        // Cold pass (mempool): populates the cache with the valid proofs only.
        let cold = verify_range_proofs_cached(&items, &Sluice::with_threads(4), &cache);
        assert_eq!(cold, uncached, "cached cold pass matches the uncached verdict");
        assert_eq!(cache.len(), 3, "positive-only: only the 3 valid proofs are cached");

        // Warm pass (same tx lands in a block / reorg replay), different width:
        // the valid proofs are hits, the invalid one is re-verified; verdict
        // identical.
        let warm = verify_range_proofs_cached(&items, &Sluice::serial(), &cache);
        assert_eq!(warm, uncached, "warm cache yields the identical verdict at a different width");
        assert_eq!(cache.len(), 3, "a reject is never cached, so the count is unchanged");
    }

    /// CLSAG adapter: a valid signature verifies and a tampered one is rejected,
    /// identically at every valve width.
    #[test]
    fn clsag_sluice_accepts_valid_rejects_tampered_at_every_width() {
        use crate::crypto::{SecretScalar, EcCommitment as Commitment, ClsagRingMember as RingMember, clsag_sign};
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let secret = SecretScalar::from_bytes([0x22u8; 32]);
        let value = 1000u64;
        let z_real = SecretScalar::from_bytes([0x33u8; 32]);
        let real_commitment = Commitment::commit(value, &z_real);
        let z_pseudo = SecretScalar::from_bytes([0x44u8; 32]);
        let pseudo_output = Commitment::commit(value, &z_pseudo);
        let blinding_diff = SecretScalar::from_scalar(z_real.as_scalar() - z_pseudo.as_scalar());
        let d1 = SecretScalar::from_bytes([0x55u8; 32]);
        let d2 = SecretScalar::from_bytes([0x66u8; 32]);
        let ring = vec![
            RingMember::new(secret.to_public(), real_commitment),
            RingMember::new(d1.to_public(), Commitment::commit(value, &SecretScalar::from_bytes([0x77u8; 32]))),
            RingMember::new(d2.to_public(), Commitment::commit(value, &SecretScalar::from_bytes([0x88u8; 32]))),
        ];
        let message = b"coincync-sluice-clsag".to_vec();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let sig = clsag_sign(&message, &ring, 0, &secret, &blinding_diff, &pseudo_output, &mut rng).unwrap();

        let valid_item = ClsagItem {
            message: message.clone(),
            ring: ring.clone(),
            pseudo_output,
            signature: sig.clone(),
        };
        // Tamper: verify the valid signature against a DIFFERENT message → reject.
        let tampered_item = ClsagItem {
            message: b"different-message".to_vec(),
            ..valid_item.clone()
        };
        let items = vec![valid_item, tampered_item];

        for valve in [Sluice::serial(), Sluice::with_threads(2), Sluice::with_threads(4)] {
            let got = verify_clsag_via_sluice(&items, &valve);
            assert_eq!(got, vec![true, false], "sluice CLSAG verdict wrong/width-dependent");
        }
        assert_valve_invariant(&ClsagVerify, &items, || ());
    }
}
