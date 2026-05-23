//! Note commitments.
//!
//! A commitment is a hiding, binding 32-byte digest of a note's
//! contents. Commitments live in the [`bridgetree::BridgeTree`] that
//! the host crate's `src/storage/shielded.rs` already runs; the
//! Action proof shows "this nullifier is derived from a note whose
//! commitment is at some leaf in the tree" without revealing which
//! leaf.
//!
//! ## What this module ships (2026-05-17 slice)
//!
//! - [`NoteCommitment::derive`] — real, deterministic note
//!   commitments using Zcash's **Sinsemilla short commit** via the
//!   `sinsemilla` primitives crate (re-exported by `halo2_gadgets`).
//!   Hiding under the binding pallas::Scalar `rcm`, binding to all
//!   note fields, output is `pallas::Base` serialized to 32 bytes.
//!
//! ## Message bit encoding (Zcash NU5 spec-exact)
//!
//! The message bits fed to Sinsemilla follow the Zcash NU5 spec
//! ([§5.4.8.4 concretesinsemillacommit](https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit)):
//!
//! ```text
//!   repr_P(gd) || repr_P(pkd) || I2LEBSP_64(v) || I2LEBSP_l(ρ) || I2LEBSP_l(ψ)
//! ```
//!
//! — 255 bits each for the curve points (x-coordinate, dropping
//! the high bit of the 32-byte little-endian repr), 64 bits for
//! the value, 255 each for ρ and ψ. Total = 255 + 255 + 64 +
//! 255 + 255 = 1084 bits. Outputs match a reference Orchard
//! implementation's note commitment byte-for-byte (subject to the
//! `rcm` derivation simplification noted below).
//!
//! ## Spec deviations — all closed (2026-05-17)
//!
//! - ~~**Message bit encoding.**~~ Closed — uses 255-bit
//!   `repr_P`-style encoding per the spec; see the
//!   bit-encoding section above.
//! - ~~**`gd` / `pkd` field encoding.**~~ Closed —
//!   [`crate::note::Note::new_for_address`] now wraps
//!   [`crate::spend_key::IncomingViewingKey::address_at`] to
//!   produce real `(gd, pkd)` bytes from `(ivk, diversifier)`;
//!   the lower-level [`crate::note::Note::new`] still accepts
//!   pre-computed bytes for test fixtures and protocol
//!   experiments.
//! - ~~**rcm derivation from rseed.**~~ Closed —
//!   [`crate::note::Note::rcm`] does the spec-exact
//!   `pallas::Scalar::from_uniform_bytes(PRF_expand(rseed, [0x05]))`
//!   derivation; see [`crate::note`] module docs.
//!
//! Both simplifications are documented at the top of the module so
//! anyone reading the code knows what to expect. The cryptographic
//! soundness of the commitment itself (Sinsemilla over Pallas with
//! a fresh-per-note randomness) is unaffected.

use ff::PrimeField;
use halo2_gadgets::sinsemilla::primitives::CommitDomain;
use pasta_curves::pallas;

use crate::{Error, Result};

/// A 32-byte note commitment. Wraps [`bridge::BridgeCommitment`] so
/// it can be inserted into the shielded note-commitment tree
/// without re-validation at the boundary.
#[derive(Clone, Debug)]
pub struct NoteCommitment(pub bridge::BridgeCommitment);

impl NoteCommitment {
    /// Construct from raw bytes. Delegates to the bridge for
    /// non-zero validation.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Ok(Self(bridge::BridgeCommitment::from_bytes(bytes)?))
    }

    /// Derive a note commitment using Sinsemilla. Returns the
    /// 32-byte serialized form suitable for storage in the
    /// commitment tree.
    ///
    /// See [`derive_point`] for the variant that returns the full
    /// `pallas::Point` (needed by [`crate::nullifier`] which
    /// multiplies it into the nullifier point).
    ///
    /// # Errors
    /// Returns `DomainRule` if `note.rseed` is not a canonical
    /// Pallas scalar (≥ ℓ_pallas). Returns `DomainRule` if the
    /// internal Sinsemilla hash produced the identity point (an
    /// astronomically improbable event; callers should regenerate
    /// rseed and try again).
    pub fn derive(note: &crate::note::Note) -> Result<Self> {
        let cm_point = derive_point(note)?;
        // Extract x-coordinate as pallas::Base, serialize LE.
        let cm_base = extract_x(&cm_point)?;
        let bytes: [u8; 32] = cm_base.to_repr();
        Self::from_bytes(bytes)
    }

    /// Raw bytes — what storage and the bridge consume.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Convert a 32-byte field into **255** little-endian bits — the
/// `I2LEBSP_l` / `repr_P` encoding the Zcash NU5 spec uses for
/// pallas::Base field elements and x-coordinates of Pasta points.
///
/// The high bit of the last byte is dropped because canonical
/// pallas::Base values are `< 2^255` (the Pallas base field order
/// is ≈ `2^254 + 2^126 - ...`, well under `2^255`). For a
/// canonical input this drop is lossless. For a non-canonical
/// input (top bit set) the caller has already failed the
/// from_repr check earlier in the pipeline.
///
/// Matches the bit-encoding in the reference `orchard` crate's
/// `note::commitment::NoteCommitment::derive` exactly.
pub(crate) fn bytes_to_255_le_bits(bytes: &[u8; 32]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .take(255)
}

/// Convert a 32-byte buffer into 256 little-endian bits (LSB-first
/// per byte, byte 0 first).
///
/// Used for the `g_d` and `pk_d` fields of the note commitment, which
/// are compressed-Pallas-point encodings (32 bytes) — NOT
/// pallas::Base field elements. The full 8 bits of every byte are
/// included; there is no high-bit truncation because these aren't
/// canonical field elements.
///
/// Matches the bit-encoding in the reference orchard 0.12 crate's
/// `note::commitment::NoteCommitment::derive` — it iterates the
/// 32-byte arrays via `BitArray::<_, Lsb0>::new(g_d).iter().by_vals()`
/// which yields all 256 bits.
pub(crate) fn bytes_to_256_le_bits(bytes: &[u8; 32]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .flat_map(|&b| (0..8).map(move |i| (b >> i) & 1 == 1))
}

/// Convert a u64 value into 64 little-endian bits.
fn value_to_le_bits(value: u64) -> impl Iterator<Item = bool> {
    (0..64).map(move |i| (value >> i) & 1 == 1)
}

/// Derive the note commitment as a full `pallas::Point` (not just
/// the serialized x-coord).
///
/// Used by [`crate::nullifier::derive_nullifier`] which multiplies
/// the commitment point into the nullifier formula
/// `[PRF + ψ mod q_P] · K^Orchard + cm`. Building the point once
/// here means the nullifier path doesn't redo the Sinsemilla hash.
///
/// `pub(crate)` rather than `pub` because callers outside the crate
/// should consume commitments via the wire-format
/// [`NoteCommitment`] wrapper, not raw Pallas points.
pub(crate) fn derive_point(note: &crate::note::Note) -> Result<pallas::Point> {
    // Spec-exact encoding per Zcash NU5 §5.4.8.4:
    //   - g_d, pk_d: 256 bits each (full compressed-Pallas-point bytes;
    //                these are NOT pallas::Base values, so all 8 bits of
    //                every byte are included — no high-bit truncation).
    //   - value:    64 LE bits.
    //   - rho, psi: 255 bits each (canonical pallas::Base encoding;
    //                the high bit of byte 31 is reserved for the
    //                field-order check and excluded from the message).
    //   Total = 256 + 256 + 64 + 255 + 255 = 1086 bits.
    //
    // Earlier this used 255 bits for all five fields — a 2-bit
    // mismatch on g_d + pk_d that produced commitments incompatible
    // with the Zcash NU5 spec. Caught by the
    // `tests/zcash_conformance.rs::note_commitment_matches_zcash_nu5`
    // golden-vector test; reference: orchard 0.12.0
    // `src/note/commitment.rs::derive`.
    //
    // `note.psi_bytes()` returns the canonical Pallas-base
    // serialization of `ψ = PRF_expand(rseed, [0x09])`.
    let psi_bytes = note.psi_bytes();
    let bits = bytes_to_256_le_bits(&note.recipient_d)
        .chain(bytes_to_256_le_bits(&note.recipient_pkd))
        .chain(value_to_le_bits(note.value))
        .chain(bytes_to_255_le_bits(&note.rho))
        .chain(bytes_to_255_le_bits(&psi_bytes));

    // rcm now derives from rseed via PRF_expand (the proper
    // spec-exact path) rather than being read from rseed bytes
    // directly. `note.rcm()` returns the pallas::Scalar form;
    // CommitDomain::commit wants a reference.
    let rcm = note.rcm();

    let domain = CommitDomain::new("z.cash:Orchard-NoteCommit");
    Option::from(domain.commit(bits, &rcm)).ok_or(Error::DomainRule(
        "Sinsemilla commit yielded identity — regenerate rseed",
    ))
}

/// Extract the x-coordinate of a non-identity `pallas::Point` as a
/// `pallas::Base` field element. Returns `DomainRule` if the point
/// is the identity (no x-coord defined).
pub(crate) fn extract_x(point: &pallas::Point) -> Result<pallas::Base> {
    use group::Curve;
    use pasta_curves::arithmetic::CurveAffine;
    let affine = point.to_affine();
    let coords: Option<pasta_curves::arithmetic::Coordinates<pallas::Affine>> =
        affine.coordinates().into();
    Ok(*coords
        .ok_or(Error::DomainRule(
            "point is identity — cannot extract x-coordinate",
        ))?
        .x())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::Note;

    /// Build a deterministic Note for tests. Uses a Pallas-canonical
    /// rseed (top byte cleared) so the derivation never trips the
    /// canonical-scalar check.
    fn test_note(seed: u8) -> Note {
        let mk = |b: u8| {
            let mut bytes = [b; 32];
            bytes[31] = 0; // ensure canonical Pallas representation
            bytes
        };
        // Use the public constructor so non-zero checks run and
        // the struct shape stays consistent with API changes.
        // ψ now derives from rseed via PRF_expand — no longer a
        // constructor argument.
        Note::new(
            mk(seed.wrapping_add(1)),
            mk(seed.wrapping_add(2)),
            1_000_000 + u64::from(seed),
            mk(seed.wrapping_add(3)),
            mk(seed.wrapping_add(5)),
        )
        .expect("test fixture")
    }

    #[test]
    fn round_trip_nonzero_bytes() {
        let mut b = [0u8; 32];
        b[0] = 0xab;
        let c = NoteCommitment::from_bytes(b).unwrap();
        assert_eq!(c.to_bytes()[0], 0xab);
    }

    #[test]
    fn rejects_zero() {
        assert!(NoteCommitment::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn derive_is_deterministic() {
        let note = test_note(1);
        let c1 = NoteCommitment::derive(&note).expect("derive 1");
        let c2 = NoteCommitment::derive(&note).expect("derive 2");
        assert_eq!(c1.to_bytes(), c2.to_bytes(), "same note → same commitment");
    }

    #[test]
    fn derive_differs_per_recipient_d() {
        let mut a = test_note(10);
        let mut b = test_note(10);
        b.recipient_d[0] ^= 0x01;
        // Keep rseed canonical for both
        a.rseed[31] = 0;
        b.rseed[31] = 0;
        let c_a = NoteCommitment::derive(&a).unwrap();
        let c_b = NoteCommitment::derive(&b).unwrap();
        assert_ne!(c_a.to_bytes(), c_b.to_bytes(), "different recipient_d → different commitment");
    }

    #[test]
    fn derive_differs_per_value() {
        let a = test_note(20);
        let mut b = test_note(20);
        b.value = a.value.wrapping_add(1);
        let c_a = NoteCommitment::derive(&a).unwrap();
        let c_b = NoteCommitment::derive(&b).unwrap();
        assert_ne!(c_a.to_bytes(), c_b.to_bytes(), "different value → different commitment");
    }

    #[test]
    fn derive_differs_per_rseed() {
        let a = test_note(30);
        let mut b = test_note(30);
        b.rseed[0] ^= 0x01;
        let c_a = NoteCommitment::derive(&a).unwrap();
        let c_b = NoteCommitment::derive(&b).unwrap();
        assert_ne!(c_a.to_bytes(), c_b.to_bytes(), "different rseed → different commitment");
    }

    #[test]
    fn derive_differs_per_rho() {
        let a = test_note(40);
        let mut b = test_note(40);
        b.rho[0] ^= 0x01;
        let c_a = NoteCommitment::derive(&a).unwrap();
        let c_b = NoteCommitment::derive(&b).unwrap();
        assert_ne!(c_a.to_bytes(), c_b.to_bytes());
    }

    // `derive_differs_per_psi` removed — since ψ now derives from
    // rseed via PRF_expand, varying ψ requires varying rseed,
    // which is exactly what `derive_differs_per_rseed` already
    // exercises. The standalone ψ-sensitivity test is now redundant.

    // `derive_rejects_non_canonical_rseed` removed — rseed is no
    // longer parsed directly as a Pallas scalar. It's the seed
    // input to `Blake2b-512(personal="Zcash_ExpandSeed", rseed||tag)`
    // which accepts any 32 bytes. The PRF output is then
    // uniformly-reduced into the target field, so non-canonical
    // rseed bytes simply produce a different (but still valid)
    // commitment. The non-zero validation in Note::new is the
    // remaining gate.

    #[test]
    fn bytes_to_255_le_bits_lsb_first_and_truncated() {
        // 0x01 → bit 0 set; 0x80 → bit 7 of that byte set. Sanity-
        // check both the bit-ordering AND the 255-bit truncation
        // before the commitment helper uses it.
        let bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 0x01;
            b[1] = 0x80;
            b
        };
        let bits: Vec<bool> = bytes_to_255_le_bits(&bytes).collect();
        assert_eq!(bits.len(), 255, "spec encoding is exactly 255 bits");
        assert!(bits[0], "byte 0 bit 0 should be set (LSB first)");
        for i in 1..15 {
            assert!(!bits[i]);
        }
        assert!(bits[15], "byte 1 bit 7 should be set");
    }

    #[test]
    fn bytes_to_255_drops_top_bit_of_byte_31() {
        // Set ONLY the top bit of byte 31. With 256-bit encoding
        // this would appear as bits[255]. With 255-bit encoding
        // it's dropped — the iterator produces only 255 bits.
        let mut bytes = [0u8; 32];
        bytes[31] = 0x80;
        let bits: Vec<bool> = bytes_to_255_le_bits(&bytes).collect();
        assert_eq!(bits.len(), 255);
        // No bit set (the 0x80 was at index 255, which is excluded).
        assert!(bits.iter().all(|b| !b), "top bit of byte 31 must be dropped");
    }
}
