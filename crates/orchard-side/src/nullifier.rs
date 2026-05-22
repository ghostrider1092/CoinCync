//! Nullifier derivation.
//!
//! A nullifier is the spent-note marker: when a note is consumed in
//! an Action, the spender publishes the note's nullifier. Anyone
//! who tries to spend the same note later finds the nullifier
//! already in the [`bridge::BridgeLedger`] and the spend is
//! rejected.
//!
//! The privacy property is that **the nullifier does not reveal
//! which note was spent** — it is a one-way derivation from
//! `(note, nk)` where `nk` is the spender's nullifier deriving
//! key. Only someone with `nk` can compute it; from the chain's
//! view it is just a 32-byte opaque value.
//!
//! ## What this module ships (2026-05-17 slice)
//!
//! Real Orchard nullifier derivation per
//! [Zcash NU5 §4.16.3](https://zips.z.cash/protocol/nu5.pdf#orchardandsaplingkeycomponents):
//!
//! ```text
//!   nf = Extract_P([PRF_nfOrchard^{nk}(ρ) + ψ mod q_P] · K^Orchard + cm)
//! ```
//!
//! where:
//! - `PRF_nfOrchard` is Poseidon (P128Pow5T3) over Pallas with
//!   `ConstantLength<2>` input — i.e. Poseidon hash of `(nk, ρ)`.
//! - `K^Orchard` is `pallas::Point::hash_to_curve("z.cash:Orchard")(&[])` —
//!   a fixed, publicly-known nullifier base point.
//! - `cm` is the note's commitment as a full Pallas point (from
//!   [`crate::commitment::derive_point`], not just the serialized
//!   x-coordinate).
//! - `Extract_P` is the x-coordinate projection.
//!
//! ## Cross-field reduction
//!
//! Step 2's `mod q_P` notation reflects that the addition is in the
//! Pallas **base** field, then the result is treated as a scalar.
//! Since `q_P ≠ q_S`, this requires the standard 256-bit-to-scalar
//! reduction (place the 32-byte base repr into the low half of a
//! 64-byte buffer, reduce via [`pallas::Scalar::from_uniform_bytes`]).
//! The same construction the reference `orchard` crate uses.

use bridge::BridgeNullifier;
use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use pasta_curves::{
    arithmetic::CurveExt,
    pallas,
};

use crate::{commitment, Error, Result};

/// A note nullifier. Wraps [`bridge::BridgeNullifier`] so the
/// chain-side double-spend set stays consistent with what the
/// transparent pool already uses.
#[derive(Clone, Debug)]
pub struct Nullifier(pub BridgeNullifier);

/// Spender's nullifier deriving key `nk`. Held by the spender; the
/// chain never sees it.
#[derive(Clone, Debug)]
pub struct NullifierDerivingKey(#[allow(dead_code)] pub(crate) [u8; 32]);

impl NullifierDerivingKey {
    /// Construct from raw bytes. Validates non-zero (the all-zero
    /// `nk` would produce degenerate Poseidon outputs) and
    /// canonical-as-pallas-base (`< q_P`).
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0u8; 32] {
            return Err(Error::DomainRule("nk must be non-zero"));
        }
        // Canonical-Pallas-Base check via from_repr (CtOption that's
        // None iff bytes ≥ q_P).
        let _: pallas::Base = Option::from(pallas::Base::from_repr(bytes))
            .ok_or(Error::DomainRule("nk is not canonical Pallas base"))?;
        Ok(Self(bytes))
    }
}

/// Derive the Orchard nullifier for a spent note.
///
/// # Errors
/// - `DomainRule` if `note.rho` is not a canonical Pallas base
///   element (`≥ q_P`). ψ is no longer a possible failure
///   mode — it derives from `rseed` via PRF_expand and is
///   always canonical.
/// - `DomainRule` if the commitment derivation surfaces a problem
///   (see [`commitment::derive_point`]).
/// - `DomainRule` if the final nullifier point is the identity
///   (no x-coordinate to extract — astronomically improbable;
///   collision-resistant under the discrete-log assumption).
pub fn derive_nullifier(
    note: &crate::note::Note,
    nk: &NullifierDerivingKey,
) -> Result<Nullifier> {
    // ── Parse note fields into Pallas base elements ──────────────
    //
    // nk was canonical-checked at construction; from_repr can't
    // fail here. rho / psi are unchecked at the Note level (the
    // skeleton doesn't enforce Pallas-canonicality there) so we
    // validate during the nullifier derivation and surface a
    // clear error if a non-canonical value sneaks in.
    let nk_base: pallas::Base = Option::from(pallas::Base::from_repr(nk.0))
        .ok_or(Error::DomainRule("nk parse failed — should not happen post-validation"))?;
    let rho_base: pallas::Base = Option::from(pallas::Base::from_repr(note.rho))
        .ok_or(Error::DomainRule("note.rho is not a canonical Pallas base"))?;
    // ψ now derives from rseed via PRF_expand — `note.psi()`
    // returns a pallas::Base directly (uniform-bytes reduced,
    // always in-range). No canonical-byte parse needed.
    let psi_base: pallas::Base = note.psi();

    // ── Step 1: PRF_nfOrchard^{nk}(ρ) = Poseidon([nk, ρ]) ────────
    //
    // P128Pow5T3 is the Orchard / Halo2 Poseidon spec: T=3 (state
    // width), RATE=2, ConstantLength<2> means a 2-input message
    // with standard length-domain padding.
    let prf_output: pallas::Base =
        PoseidonHash::<pallas::Base, P128Pow5T3, ConstantLength<2>, 3, 2>::init()
            .hash([nk_base, rho_base]);

    // ── Step 2: scalar = mod_r_p(PRF + ψ) ────────────────────────
    //
    // Per orchard 0.12 `src/spec.rs::mod_r_p`: Pallas' base field is
    // **smaller** than its scalar field (q_P < q_S), so every
    // canonical base-field byte representation is also a valid
    // scalar — direct `from_repr` always succeeds.
    //
    // Earlier this used `from_uniform_bytes` on the base bytes
    // zero-padded to 64 — that's a 512-bit wide reduction over
    // ZEROS, producing a different scalar than `from_repr` does.
    // Caught by `tests/zcash_conformance.rs::nullifier_matches_zcash_nu5`.
    let base_scalar = prf_output + psi_base;
    let scalar = pallas::Scalar::from_repr(base_scalar.to_repr())
        .into_option()
        .expect("Pallas base canonical → scalar canonical: q_P < q_S guaranteed");

    // ── Step 3: K^Orchard = hash_to_curve("z.cash:Orchard")(b"K") ─
    //
    // Per Zcash NU5 §5.4.1.1 + orchard 0.12 `src/note/nullifier.rs::derive`,
    // the K^Orchard generator is `hash_to_curve` of the single byte
    // **`b"K"`**, NOT the empty input. Earlier this used `&[]`
    // which produces a completely different point — silent
    // consensus-incompatibility, caught by the conformance test.
    let k_orchard: pallas::Point = pallas::Point::hash_to_curve("z.cash:Orchard")(b"K");

    // ── Step 4: cm point + scalar·K + Extract_P ──────────────────
    let cm_point = commitment::derive_point(note)?;
    let nf_point = (k_orchard * scalar) + cm_point;
    let nf_base = commitment::extract_x(&nf_point)?;

    // 32-byte little-endian serialization.
    let nf_bytes: [u8; 32] = nf_base.to_repr();
    Ok(Nullifier(BridgeNullifier::from_bytes(nf_bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::Note;

    /// 32-byte field that's canonical as Pallas Base (top byte
    /// cleared, low bytes filled with seed).
    fn pallas_canonical(b: u8) -> [u8; 32] {
        let mut out = [b; 32];
        out[31] = 0;
        out
    }

    fn test_note(seed: u8) -> Note {
        // ψ now derives from rseed via PRF_expand — no longer
        // a constructor argument.
        Note::new(
            pallas_canonical(seed.wrapping_add(1)),
            pallas_canonical(seed.wrapping_add(2)),
            1_000_000 + u64::from(seed),
            pallas_canonical(seed.wrapping_add(3)),
            pallas_canonical(seed.wrapping_add(5)),
        )
        .expect("test note construction")
    }

    fn test_nk(seed: u8) -> NullifierDerivingKey {
        NullifierDerivingKey::from_bytes(pallas_canonical(seed.wrapping_add(7))).unwrap()
    }

    #[test]
    fn nk_rejects_zero() {
        assert!(NullifierDerivingKey::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn nk_accepts_nonzero() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert!(NullifierDerivingKey::from_bytes(bytes).is_ok());
    }

    #[test]
    fn nk_rejects_non_canonical_pallas_base() {
        // All 0xFF exceeds q_P → must reject (canonical check).
        let bytes = [0xff; 32];
        assert!(NullifierDerivingKey::from_bytes(bytes).is_err());
    }

    #[test]
    fn derive_is_deterministic() {
        let note = test_note(1);
        let nk = test_nk(1);
        let nf1 = derive_nullifier(&note, &nk).expect("derive 1");
        let nf2 = derive_nullifier(&note, &nk).expect("derive 2");
        assert_eq!(nf1.0.to_bytes(), nf2.0.to_bytes(), "same (note, nk) → same nullifier");
    }

    #[test]
    fn derive_differs_per_nk() {
        // Same note, different nk → different nullifier. This is
        // the property that says "the same note has a different
        // nullifier for each owner" — load-bearing for the
        // unlinkability of receivers.
        let note = test_note(2);
        let nk_a = test_nk(2);
        let nk_b = test_nk(3);
        let nf_a = derive_nullifier(&note, &nk_a).unwrap();
        let nf_b = derive_nullifier(&note, &nk_b).unwrap();
        assert_ne!(nf_a.0.to_bytes(), nf_b.0.to_bytes());
    }

    #[test]
    fn derive_differs_per_rho() {
        // Different rho → different nullifier even with same nk.
        // This is what guarantees two-notes-same-recipient have
        // distinct nullifiers.
        let mut a = test_note(4);
        let mut b = test_note(4);
        b.rho = pallas_canonical(99);
        // Keep rseed canonical for both
        a.rseed[31] = 0;
        b.rseed[31] = 0;
        let nk = test_nk(4);
        let nf_a = derive_nullifier(&a, &nk).unwrap();
        let nf_b = derive_nullifier(&b, &nk).unwrap();
        assert_ne!(nf_a.0.to_bytes(), nf_b.0.to_bytes());
    }

    #[test]
    fn derive_differs_per_rseed_via_psi_change() {
        // ψ now derives from rseed via PRF_expand. Varying rseed
        // changes ψ (and rcm, which affects cm). Both flow into
        // the nullifier formula, so the result must differ.
        let a = test_note(5);
        let mut b = test_note(5);
        b.rseed = pallas_canonical(99);
        let nk = test_nk(5);
        let nf_a = derive_nullifier(&a, &nk).unwrap();
        let nf_b = derive_nullifier(&b, &nk).unwrap();
        assert_ne!(nf_a.0.to_bytes(), nf_b.0.to_bytes());
    }

    #[test]
    fn derive_differs_per_value() {
        // Value is part of cm (via Sinsemilla input bits), so two
        // notes with otherwise-identical fields but different
        // values must produce different nullifiers.
        let a = test_note(6);
        let mut b = test_note(6);
        b.value = a.value + 1;
        let nk = test_nk(6);
        let nf_a = derive_nullifier(&a, &nk).unwrap();
        let nf_b = derive_nullifier(&b, &nk).unwrap();
        assert_ne!(nf_a.0.to_bytes(), nf_b.0.to_bytes());
    }

    #[test]
    fn derive_rejects_non_canonical_rho() {
        let mut note = test_note(7);
        note.rho = [0xff; 32]; // exceeds q_P
        let nk = test_nk(7);
        let r = derive_nullifier(&note, &nk);
        assert!(matches!(r, Err(Error::DomainRule(_))));
    }

    // `derive_rejects_non_canonical_psi` removed — ψ now derives
    // from `note.rseed` via `pallas::Base::from_uniform_bytes` of
    // a 64-byte PRF output, which is **always** canonical. There
    // is no path for ψ to be out-of-range, so the rejection test
    // has no failure mode left to exercise.
}
