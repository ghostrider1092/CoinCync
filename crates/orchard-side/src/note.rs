//! Shielded note structure.
//!
//! A *note* in Orchard is the privacy-preserving analogue of a UTXO:
//! it encodes "address X owns Y CYNC, identified by randomness ρ".
//! Notes never appear on-chain in plaintext; only their
//! [`crate::commitment::NoteCommitment`] does. When spent, a
//! [`crate::nullifier::Nullifier`] derived from the note + the
//! spender's nullifier key is published, but the link back to the
//! original commitment is hidden by the Action proof.
//!
//! ## Stored fields vs. derived fields
//!
//! Per Zcash NU5 §4.7.2, a note is conceptually `(d, pkd, v, ρ, ψ, rcm)`.
//! Only some of these are independent randomness:
//!
//! - `(d, pkd, v, ρ)` are independent inputs — the recipient
//!   address, the value, and the uniqueness nonce ρ (derived in
//!   real spends from the spent-parent's nullifier).
//! - `(ψ, rcm)` are **derived** from a single `rseed` via
//!   `PRF_expand`:
//!
//! ```text
//!   ψ   = pallas::Base::from_uniform_bytes(PRF_expand(rseed, [0x09]))
//!   rcm = pallas::Scalar::from_uniform_bytes(PRF_expand(rseed, [0x05]))
//! ```
//!
//! Storing only `rseed` and deriving `(ψ, rcm)` matches the
//! reference orchard crate's `Note` and keeps the on-disk
//! note size to its minimum 96 bytes
//! (d || pkd || v || ρ || rseed = 32+32+8+32+32 — value as 8 bytes).
//! This module accepts `rseed` and exposes `psi()` / `rcm()`
//! accessors for the derived halves.

use ff::PrimeField;
use pasta_curves::{group::ff::FromUniformBytes, pallas};

use crate::spend_key::{PRF_EXPAND_PSI_TAG, PRF_EXPAND_RCM_TAG};
use crate::{Error, Result};

/// A shielded note — the in-memory representation of a UTXO in the
/// Phase-2 pool. `(d, pkd)` placeholders are still 32-byte byte
/// arrays pending the `address_at`-from-real-pallas-points path;
/// `(v, ρ, rseed)` are real.
#[derive(Clone, Debug)]
pub struct Note {
    /// Recipient diversifier base, x-only serialized. In a real
    /// note this comes from
    /// [`crate::spend_key::IncomingViewingKey::address_at`]'s
    /// `gd_bytes` output.
    pub recipient_d: [u8; 32],
    /// Recipient transmission key `pkd = ivk · gd`. In a real
    /// note this comes from `address_at`'s `pkd_bytes` output.
    pub recipient_pkd: [u8; 32],

    /// Note value in CYNC base units (the same denomination used by
    /// the transparent pool's `MIN_OUTPUT_AMOUNT`).
    pub value: u64,

    /// `ρ` — uniqueness randomness. For real spends, ρ equals the
    /// nullifier of the spent parent note (binds the new note to
    /// its predecessor). For genesis / mint, the issuer chooses ρ.
    /// The Note module accepts ρ as an independent input rather
    /// than re-deriving it from spend context.
    pub rho: [u8; 32],

    /// `rseed` — root randomness from which `ψ` and `rcm` derive
    /// via PRF_expand. The note's only true secret randomness;
    /// `(ψ, rcm)` are deterministic functions of `rseed`.
    pub rseed: [u8; 32],
}

impl Note {
    /// Construct a new note.
    ///
    /// # Validation
    /// - `value` must not exceed `bridge::BridgeValue::MAX_MONEY`.
    /// - `recipient_d`, `recipient_pkd`, `rho`, `rseed` must each
    ///   be non-zero. Zero is reserved as "uninitialized"
    ///   throughout the bridge layer.
    pub fn new(
        recipient_d: [u8; 32],
        recipient_pkd: [u8; 32],
        value: u64,
        rho: [u8; 32],
        rseed: [u8; 32],
    ) -> Result<Self> {
        let _ = bridge::BridgeValue::new(value)?;
        let nonzero = |b: &[u8; 32], name: &'static str| -> Result<()> {
            if b == &[0u8; 32] {
                Err(Error::DomainRule(name))
            } else {
                Ok(())
            }
        };
        nonzero(&recipient_d, "note.recipient_d must be non-zero")?;
        nonzero(&recipient_pkd, "note.recipient_pkd must be non-zero")?;
        nonzero(&rho, "note.rho must be non-zero")?;
        nonzero(&rseed, "note.rseed must be non-zero")?;

        Ok(Self {
            recipient_d,
            recipient_pkd,
            value,
            rho,
            rseed,
        })
    }

    /// Construct a new note **derived from a real Orchard recipient
    /// address**.
    ///
    /// Calls [`crate::spend_key::IncomingViewingKey::address_at`]
    /// to compute the diversified address `(gd, pkd)` for the given
    /// `(ivk, diversifier)` pair, then stores the resulting byte
    /// representations in the Note's recipient fields. This is the
    /// production-grade constructor a wallet uses when building a
    /// note for a known recipient — the alternative
    /// [`new`](Self::new) is for tests and protocol experiments
    /// that already hold derived `gd`/`pkd` bytes.
    ///
    /// # Errors
    /// - Forwards any error from
    ///   [`IncomingViewingKey::address_at`] (non-canonical ivk,
    ///   identity-point DiversifyHash output).
    /// - Forwards any error from [`new`](Self::new) (value cap,
    ///   zero fields).
    pub fn new_for_address(
        ivk: &crate::spend_key::IncomingViewingKey,
        diversifier: [u8; 11],
        value: u64,
        rho: [u8; 32],
        rseed: [u8; 32],
    ) -> Result<Self> {
        let (gd_bytes, pkd_bytes) = ivk.address_at(diversifier)?;
        Self::new(gd_bytes, pkd_bytes, value, rho, rseed)
    }

    /// Derive `ψ = pallas::Base::from_uniform_bytes(PRF_expand(rseed, [0x09] || rho_bytes))`.
    ///
    /// Per Zcash NU5 §4.7.3 ("Sending Notes (Orchard)"), the PSI
    /// derivation feeds **both** `rseed` AND `rho_bytes` into the
    /// PRF input — `rho` makes the derived `ψ` tx-position-bound
    /// rather than rseed-bound. Reference: orchard 0.12
    /// `src/note.rs::RandomSeed::psi`. Earlier our impl omitted
    /// the rho input, producing notes incompatible with Zcash NU5
    /// (caught by `tests/zcash_conformance.rs::note_commitment_matches_zcash_nu5`).
    pub fn psi(&self) -> pallas::Base {
        let wide = crate::spend_key::prf_expand_with(&self.rseed, PRF_EXPAND_PSI_TAG, &self.rho);
        pallas::Base::from_uniform_bytes(&wide)
    }

    /// Derive `rcm = pallas::Scalar::from_uniform_bytes(PRF_expand(rseed, [0x05] || rho_bytes))`.
    ///
    /// Same `rho`-binding pattern as [`psi`](Self::psi) per Zcash
    /// NU5 §4.7.3. Reference: orchard 0.12 `src/note.rs::RandomSeed::rcm`.
    pub fn rcm(&self) -> pallas::Scalar {
        let wide = crate::spend_key::prf_expand_with(&self.rseed, PRF_EXPAND_RCM_TAG, &self.rho);
        pallas::Scalar::from_uniform_bytes(&wide)
    }

    /// 32-byte canonical serialization of `ψ` — convenience for
    /// the nullifier path which currently expects a byte array.
    pub fn psi_bytes(&self) -> [u8; 32] {
        self.psi().to_repr()
    }

    /// Derive the note's commitment via Sinsemilla.
    pub fn commitment(&self) -> Result<crate::commitment::NoteCommitment> {
        crate::commitment::NoteCommitment::derive(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonzero(b: u8) -> [u8; 32] {
        let mut out = [b; 32];
        out[31] = 0;
        out
    }

    #[test]
    fn new_rejects_zero_recipient_d() {
        let r = Note::new([0u8; 32], nonzero(2), 100, nonzero(3), nonzero(5));
        assert!(matches!(r, Err(Error::DomainRule(_))));
    }

    #[test]
    fn new_rejects_zero_rseed() {
        let r = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), [0u8; 32]);
        assert!(matches!(r, Err(Error::DomainRule(_))));
    }

    #[test]
    fn new_rejects_zero_rho() {
        let r = Note::new(nonzero(1), nonzero(2), 100, [0u8; 32], nonzero(5));
        assert!(matches!(r, Err(Error::DomainRule(_))));
    }

    #[test]
    fn new_rejects_value_over_supply_cap() {
        let r = Note::new(
            nonzero(1),
            nonzero(2),
            bridge::BridgeValue::MAX_MONEY + 1,
            nonzero(3),
            nonzero(5),
        );
        assert!(matches!(r, Err(Error::Bridge(_))));
    }

    #[test]
    fn new_accepts_valid_note() {
        let note = Note::new(nonzero(1), nonzero(2), 1_000_000, nonzero(3), nonzero(5))
            .expect("valid note");
        assert_eq!(note.value, 1_000_000);
    }

    #[test]
    fn psi_is_deterministic_from_rseed() {
        let note = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), nonzero(5)).unwrap();
        let psi_a = note.psi();
        let psi_b = note.psi();
        assert_eq!(psi_a, psi_b, "same rseed → same psi");
    }

    #[test]
    fn rcm_is_deterministic_from_rseed() {
        let note = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), nonzero(5)).unwrap();
        let rcm_a = note.rcm();
        let rcm_b = note.rcm();
        assert_eq!(rcm_a, rcm_b, "same rseed → same rcm");
    }

    #[test]
    fn psi_differs_per_rseed() {
        let note_a = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), nonzero(5)).unwrap();
        let note_b = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), nonzero(6)).unwrap();
        assert_ne!(
            note_a.psi(),
            note_b.psi(),
            "different rseed → different psi"
        );
    }

    #[test]
    fn rcm_differs_per_rseed() {
        let note_a = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), nonzero(5)).unwrap();
        let note_b = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), nonzero(6)).unwrap();
        assert_ne!(
            note_a.rcm(),
            note_b.rcm(),
            "different rseed → different rcm"
        );
    }

    #[test]
    fn psi_and_rcm_are_independent_for_same_rseed() {
        // Same rseed → ψ and rcm should be distinct values (they
        // use different PRF_expand tags). If the tags ever
        // collided, ψ == rcm.as_base() would be a silent breakage.
        let note = Note::new(nonzero(1), nonzero(2), 100, nonzero(3), nonzero(5)).unwrap();
        let psi_bytes = note.psi_bytes();
        let rcm_bytes: [u8; 32] = note.rcm().to_repr();
        assert_ne!(
            psi_bytes, rcm_bytes,
            "ψ and rcm must come from different PRF_expand tags"
        );
    }

    #[test]
    fn new_for_address_walks_sk_through_to_commitment() {
        // The closing integration test for the non-circuit
        // primitive set: a single chain `sk → fvk → ivk →
        // Note::new_for_address → cm → nf` exercises every
        // module shipped today. If any link in that chain ever
        // breaks (key derivation, address derivation, note
        // construction, commitment, nullifier), this test
        // surfaces it as a single clean failure rather than the
        // user finding out at chain-validation time.
        use crate::nullifier::{derive_nullifier, NullifierDerivingKey};
        use crate::spend_key::SpendingKey;

        // Use a stable seed so future regressions are bisectable.
        let sk_bytes = {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = (i as u8).wrapping_mul(11).wrapping_add(3);
            }
            b
        };
        let sk = SpendingKey::from_bytes(sk_bytes).expect("sk");

        // Some seeds produce an ivk that's non-canonical-as-scalar
        // (rare; ~2^-128). Sweep until we land on a canonical one
        // — same pattern address_at's own tests use.
        let mut ivk = None;
        let mut nk_bytes_chosen = [0u8; 32];
        for offset in 0..32u8 {
            let mut perturbed = sk_bytes;
            perturbed[0] = perturbed[0].wrapping_add(offset);
            let sk_try = SpendingKey::from_bytes(perturbed).expect("sk");
            let fvk = sk_try.full_viewing_key().expect("fvk");
            if let Ok(ivk_candidate) = fvk.to_ivk() {
                if ivk_candidate.address_at([5u8; 11]).is_ok() {
                    ivk = Some(ivk_candidate);
                    nk_bytes_chosen = fvk.nk;
                    break;
                }
            }
            let _ = sk; // silence unused-binding warning for the outer sk
        }
        let ivk = ivk.expect("find a canonical ivk via seed sweep");

        // Build the note from the real recipient address.
        let diversifier = [5u8; 11];
        let rho = {
            let mut r = [3u8; 32];
            r[31] = 0; // canonical Pallas base
            r
        };
        let rseed = {
            let mut r = [7u8; 32];
            r[31] = 0;
            r
        };
        let note = Note::new_for_address(&ivk, diversifier, 1_000_000, rho, rseed)
            .expect("note construction via address_at");

        // The note's commitment derives without error and is
        // deterministic.
        let cm = note.commitment().expect("commitment");
        let cm2 = note.commitment().unwrap();
        assert_eq!(cm.to_bytes(), cm2.to_bytes(), "cm must be deterministic");

        // The nullifier derives without error using the same FVK's
        // nk — closing the loop on the full receive→spend flow.
        let nk = NullifierDerivingKey::from_bytes(nk_bytes_chosen).expect("nk");
        let nf = derive_nullifier(&note, &nk).expect("nullifier derives");
        let nf2 = derive_nullifier(&note, &nk).unwrap();
        assert_eq!(
            nf.0.to_bytes(),
            nf2.0.to_bytes(),
            "nf must be deterministic"
        );

        // Different diversifier → different address → different
        // note → different commitment. Sanity for the address
        // derivation actually flowing through.
        let note_alt =
            Note::new_for_address(&ivk, [6u8; 11], 1_000_000, rho, rseed).expect("alt note");
        assert_ne!(
            note.commitment().unwrap().to_bytes(),
            note_alt.commitment().unwrap().to_bytes(),
            "different diversifier must produce different commitment"
        );
    }

    #[test]
    fn commitment_round_trip_via_note() {
        let note = Note::new(
            nonzero(10),
            nonzero(20),
            5_000_000,
            nonzero(30),
            nonzero(50),
        )
        .unwrap();
        let cm = note.commitment().expect("commitment derivation");
        let cm2 = note.commitment().unwrap();
        assert_eq!(cm.to_bytes(), cm2.to_bytes());
    }
}
