//! Spending key hierarchy.
//!
//! Per [Zcash NU5 §4.2.3](https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents),
//! the spending key `sk` is the seed-grade root from which everything
//! else derives:
//!
//! ```text
//!   sk  ─ spending key (seed-grade secret)
//!    │
//!    ├─ ask   = ToScalar(PRF_expand(sk, [0x06])) ─ spend auth key
//!    │   └─ ak = ask · G^Orchard_SpendAuth ─ spend auth validating key
//!    ├─ nk    = ToBase  (PRF_expand(sk, [0x07])) ─ nullifier deriving key
//!    ├─ rivk  = ToScalar(PRF_expand(sk, [0x08])) ─ ivk randomizer
//!    │
//!    ├─ ovk   ─ outgoing viewing key (derived from ak/nk/rivk via Blake2b)
//!    └─ ivk   ─ incoming viewing key (= CommitIvk(ak, nk, rivk))
//!         └─ diversified addresses (d, pk_d)
//! ```
//!
//! Wallet UI typically holds `sk` (or a 32-byte seed that derives
//! it); chain code only ever sees `ak`, `nk`, and the public side
//! of the address.
//!
//! ## What this slice ships (2026-05-17)
//!
//! Real derivations for the **upper half** of the hierarchy — the
//! parts that come straight from PRF_expand:
//!
//! - [`SpendingKey::from_bytes`] / [`SpendingKey::nullifier_key`] /
//!   [`SpendingKey::full_viewing_key`] — real Blake2b-based
//!   `PRF_expand` (`Zcash_ExpandSeed` personalization) feeding
//!   pallas::Scalar / pallas::Base via uniform-bytes reduction.
//! - `ak = ask · G^Orchard_SpendAuth` where
//!   `G^Orchard_SpendAuth = hash_to_curve("z.cash:Orchard")(b"G")`.
//! - `ovk` derived via `Blake2b-512(personalization="Zcashderiveovk",
//!   input = ak.x || nk || rivk.bytes)`. This is the NU5
//!   derivation; the 32-byte output is truncated to the 32-byte
//!   ovk per the spec.
//!
//! ## What is still skeleton
//!
//! - [`FullViewingKey::to_ivk`] — requires `CommitIvk`, a Sinsemilla
//!   short-commit over `(ak.x || nk)` keyed by `rivk`. The
//!   Sinsemilla machinery is already in [`crate::commitment`];
//!   wiring up the specific commit-ivk domain and ivk truncation
//!   is the natural next sub-slice.
//! - [`IncomingViewingKey::address_at`] — requires `DiversifyHash`
//!   (a Sinsemilla hash_to_point construction) and ivk·gd
//!   multiplication. Lands with the to_ivk slice.

use blake2b_simd::Params as Blake2bParams;
use ff::PrimeField;
use pasta_curves::{arithmetic::CurveExt, group::ff::FromUniformBytes, pallas};
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::nullifier::NullifierDerivingKey;
use crate::{Error, Result};

// ── PRF_expand (Zcash NU5 §5.4.1.2) ──────────────────────────────────
//
// Blake2b-512 keyed with the 16-byte personalization
// `"Zcash_ExpandSeed"`, input is `sk || tag`. Output is 64 bytes,
// reduced into the target field via uniform-bytes reduction.

const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

const PRF_EXPAND_ASK_TAG: u8 = 0x06;
const PRF_EXPAND_NK_TAG: u8 = 0x07;
const PRF_EXPAND_RIVK_TAG: u8 = 0x08;
/// Tag for the joint `dk || ovk` derivation per NU5 §5.4.1.6:
///   R = PRF_expand(rivk, [0x82] || ak.x || nk),  dk=R[0..32],  ovk=R[32..64].
const PRF_EXPAND_DK_OVK_TAG: u8 = 0x82;

/// PRF_expand tag for the note's `rcm` (commitment trapdoor) derivation
/// from `rseed`. Used by [`crate::note::Note::rcm`].
pub(crate) const PRF_EXPAND_RCM_TAG: u8 = 0x05;

/// PRF_expand tag for the note's `ψ` (psi nonce) derivation from
/// `rseed`. Used by [`crate::note::Note::psi`].
pub(crate) const PRF_EXPAND_PSI_TAG: u8 = 0x09;

/// `Blake2b-512(personal="Zcash_ExpandSeed", input=sk||tag)` reducing
/// nowhere — returns the raw 64-byte digest. Crate-private because
/// the various consumers (key derivation, note randomness) want
/// the output reduced into different fields.
pub(crate) fn prf_expand(sk: &[u8; 32], tag: u8) -> [u8; 64] {
    prf_expand_with(sk, tag, &[])
}

/// Generalized PRF_expand: `Blake2b-512(personal="Zcash_ExpandSeed",
/// input = key || [tag] || additional)`. The single-byte-tag variant
/// [`prf_expand`] is the special case `additional = &[]`. The
/// extended variant covers spec calls like the OVK derivation
/// (NU5 §5.4.1.6):
///
/// ```text
///   R = PRF_expand(rivk, [0x82] || ak.x || nk)
///   dk  = R[0..32]
///   ovk = R[32..64]
/// ```
///
/// which feeds `ak.x || nk` (64 bytes) as `additional` alongside
/// the tag byte `0x82`.
pub(crate) fn prf_expand_with(sk: &[u8; 32], tag: u8, additional: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    hasher.update(sk);
    hasher.update(&[tag]);
    hasher.update(additional);
    let result = hasher.finalize();
    let bytes = result.as_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(bytes);
    out
}

fn to_scalar(wide: [u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(&wide)
}

fn to_base(wide: [u8; 64]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(&wide)
}

/// `G^Orchard_SpendAuth = hash_to_curve("z.cash:Orchard")(b"G")`.
/// Fixed Pallas point shared across all spend-auth derivations.
/// Memoized — the ~30µs hash-to-curve cost is paid only once.
fn spend_auth_generator() -> pallas::Point {
    static G: OnceLock<pallas::Point> = OnceLock::new();
    *G.get_or_init(|| pallas::Point::hash_to_curve("z.cash:Orchard")(b"G"))
}

// ── Spending key + derived keys ──────────────────────────────────────

/// Root spending secret. **Treat as seed-grade — never log.**
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey(pub(crate) [u8; 32]);

impl SpendingKey {
    /// Construct from raw bytes. Rejects zero (would derive
    /// degenerate downstream keys).
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0u8; 32] {
            return Err(Error::DomainRule("spending key must be non-zero"));
        }
        Ok(Self(bytes))
    }

    /// Derive `ask = ToScalar(PRF_expand(sk, [0x06]))`, then
    /// parity-normalize: if `ak = ask · G_SpendAuth` has odd y
    /// (high bit of compressed-byte-31 set), negate `ask`. The
    /// resulting `ask` is the **spec-canonical** spend-authorizing
    /// scalar — what an orchard-compatible verifier expects to
    /// see signed against.
    ///
    /// Per orchard 0.12 `src/keys.rs::SpendAuthorizingKey::from`
    /// + NU5 §4.2.3. Catching this is the difference between
    /// "ak.x matches orchard byte-for-byte" (always true even
    /// without the negation) and "ask bytes match orchard"
    /// (only true with the negation). Affects spend-auth signing
    /// interop — without this fix, our signatures wouldn't
    /// verify under an orchard-implementing verifier.
    ///
    /// Internal — callers should use [`full_viewing_key`] for the
    /// public surface.
    ///
    /// [`full_viewing_key`]: Self::full_viewing_key
    fn ask(&self) -> pallas::Scalar {
        use group::{Curve, GroupEncoding};
        let raw_ask = to_scalar(prf_expand(&self.0, PRF_EXPAND_ASK_TAG));
        let ak_point = spend_auth_generator() * raw_ask;
        // Compressed encoding: bit 7 of byte 31 indicates y is odd.
        // If so, negate ask so the canonical point has even y.
        let ak_compressed = ak_point.to_affine().to_bytes();
        if (ak_compressed[31] >> 7) == 1 {
            -raw_ask
        } else {
            raw_ask
        }
    }

    /// Derive `nk = ToBase(PRF_expand(sk, [0x07]))`.
    fn nk_base(&self) -> pallas::Base {
        to_base(prf_expand(&self.0, PRF_EXPAND_NK_TAG))
    }

    /// Derive `rivk = ToScalar(PRF_expand(sk, [0x08]))`.
    fn rivk(&self) -> pallas::Scalar {
        to_scalar(prf_expand(&self.0, PRF_EXPAND_RIVK_TAG))
    }

    /// Derive the nullifier-deriving key in the [`NullifierDerivingKey`]
    /// wire form (32-byte canonical Pallas base bytes).
    pub fn nullifier_key(&self) -> Result<NullifierDerivingKey> {
        let nk = self.nk_base();
        // `from_repr` on the same bytes will round-trip — by
        // construction we're handing it a canonical Pallas base
        // value, so the NullifierDerivingKey canonical check
        // passes.
        NullifierDerivingKey::from_bytes(nk.to_repr())
    }

    /// Derive the full viewing key bundle: `(ak, nk, ovk, rivk)`.
    ///
    /// Per Zcash NU5 §5.4.1.6, the OVK + DK pair is derived from
    /// `rivk` (as PRF key), tag `0x82`, and the concatenated
    /// `ak.x || nk` (as PRF additional input):
    ///
    /// ```text
    ///   R   = PRF_expand(rivk, [0x82] || ak.x || nk)   (64 bytes)
    ///   dk  = R[0..32]
    ///   ovk = R[32..64]
    /// ```
    ///
    /// Note: `dk` (the diversifier key, used by orchard's
    /// `IncomingViewingKey` to derive a diversifier from an index
    /// via FF1-AES) is computed alongside but we don't currently
    /// expose it — our `address_at` takes the diversifier `d`
    /// directly, leaving `d`-from-index derivation to whatever
    /// scope-management layer the wallet uses. Future expansion of
    /// `FullViewingKey` to carry `dk` is a forward-compat addition.
    pub fn full_viewing_key(&self) -> Result<FullViewingKey> {
        // ak = ask · G^Orchard_SpendAuth, then take the x-only
        // serialization. ak is published as 32-byte x-coord per
        // the spec.
        let ask = self.ask();
        let ak_point = spend_auth_generator() * ask;
        let ak_bytes = crate::commitment::extract_x(&ak_point)?.to_repr();

        // nk as 32-byte canonical Pallas base bytes.
        let nk_bytes = self.nk_base().to_repr();

        let rivk = self.rivk();
        let rivk_bytes = rivk.to_repr();

        // Spec-correct DK + OVK derivation per NU5 §5.4.1.6.
        // The same 64-byte Blake2b output yields both: dk in the
        // first half, ovk in the second.
        let mut additional = [0u8; 64];
        additional[..32].copy_from_slice(&ak_bytes);
        additional[32..].copy_from_slice(&nk_bytes);
        let r = prf_expand_with(&rivk_bytes, PRF_EXPAND_DK_OVK_TAG, &additional);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&r[0..32]);
        let mut ovk = [0u8; 32];
        ovk.copy_from_slice(&r[32..64]);

        Ok(FullViewingKey {
            ak: ak_bytes,
            nk: nk_bytes,
            ovk,
            dk,
            rivk: rivk_bytes,
        })
    }

    /// Test-only accessor for the `ask` scalar derived inside
    /// [`full_viewing_key`](Self::full_viewing_key). Exposed for
    /// the Zcash conformance suite, which validates `ask` bytes
    /// against the canonical test vectors. Not part of the public
    /// API in production — callers should use the full viewing
    /// key bundle.
    #[doc(hidden)]
    pub fn _test_only_ask_bytes(&self) -> [u8; 32] {
        self.ask().to_repr()
    }
}

impl std::fmt::Debug for SpendingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the actual bytes.
        write!(f, "SpendingKey(<redacted>)")
    }
}

/// Full viewing key — Bob hands this to e.g. an auditor to grant
/// outgoing-AND-incoming visibility without giving up spend
/// authority.
///
/// Per Zcash NU5 §4.2.3 the FVK carries `rivk` alongside `(ak, nk,
/// ovk, dk)`: the FVK holder needs `rivk` to derive `ivk` via
/// `CommitIvk(ak, nk, rivk)`. Without `rivk` the FVK couldn't
/// produce incoming addresses, which would defeat the
/// "view-incoming-payments" half of its purpose.
///
/// The `dk` (diversifier key) sits alongside `ovk` in the same
/// Blake2b output — we expose both for completeness even though
/// our current `address_at` takes a diversifier `d` directly
/// rather than deriving it from `dk + index`. A future scope-
/// management layer (`dk + FF1-AES(index) → d`) would consume
/// `dk` to produce per-scope diversifiers.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FullViewingKey {
    /// x-only serialization of `ak = ask · G^Orchard_SpendAuth`.
    pub ak: [u8; 32],
    /// Canonical Pallas base bytes of `nk`.
    pub nk: [u8; 32],
    /// Outgoing viewing key — second 32 bytes (`R[32..64]`) of the
    /// NU5 §5.4.1.6 `(dk || ovk)` Blake2b output.
    pub ovk: [u8; 32],
    /// Diversifier key — first 32 bytes (`R[0..32]`) of the
    /// NU5 §5.4.1.6 `(dk || ovk)` Blake2b output. Used by a
    /// future diversifier-from-index layer (FF1-AES); not
    /// consumed by `address_at` directly.
    pub dk: [u8; 32],
    /// IVK randomizer (canonical Pallas scalar bytes). Fed into
    /// `CommitIvk` together with `ak` and `nk` to produce the
    /// incoming viewing key.
    pub rivk: [u8; 32],
}

impl std::fmt::Debug for FullViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the actual bytes — a single `tracing::debug!(\"{fvk:?}\")`
        // would emit the full FVK to logs, journald, and aggregators. Pairs with
        // the redacted Debug on SpendingKey above. See
        // audit-suite/findings/CYNC-AUDIT-2026-05-17-orchard-fvk-debug-leak.md.
        write!(f, "FullViewingKey(<redacted>)")
    }
}

/// Incoming viewing key — narrower than FullViewingKey: lets the
/// holder see incoming notes only. The form used by a typical
/// "view-only" wallet.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IncomingViewingKey(pub(crate) [u8; 32]);

impl std::fmt::Debug for IncomingViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the actual bytes — same rationale as FullViewingKey.
        write!(f, "IncomingViewingKey(<redacted>)")
    }
}

impl IncomingViewingKey {
    /// The 32 canonical Pallas-base bytes of this IVK. Useful for
    /// serialization, persistence, and byte-for-byte conformance
    /// checks against the Zcash NU5 reference (which encodes the
    /// IVK as the same 32 bytes in the second half of its 64-byte
    /// `dk || ivk` envelope).
    ///
    /// Note: orchard's `IncomingViewingKey` is 64 bytes
    /// (`dk || ivk`); ours is the 32-byte `ivk` half only. Callers
    /// that need `dk` derive it separately (we don't currently
    /// expose `dk` — see `tests/zcash_conformance.rs` for the
    /// architectural-difference note).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FullViewingKey {
    /// Derive the incoming viewing key:
    ///
    /// ```text
    ///   ivk = CommitIvk_rivk(ak, nk)
    ///       = SinsemillaShortCommit^{"z.cash:Orchard-CommitIvk"}(
    ///             ak.x || nk, rivk)
    /// ```
    ///
    /// per Zcash NU5 §5.4.8.4. The output is a Pallas base element
    /// canonical-serialized to 32 bytes — when used downstream for
    /// `ivk · gd`, the bytes are re-parsed as a Pallas scalar
    /// (which works because the base field is larger than the
    /// scalar field; a small fraction of base values are
    /// non-canonical as scalars and the spec handles that case
    /// by re-deriving rivk).
    ///
    /// # Errors
    /// - `DomainRule` if `rivk` is non-canonical
    /// - `DomainRule` if the Sinsemilla commit hits the
    ///   identity point (astronomically improbable)
    pub fn to_ivk(&self) -> Result<IncomingViewingKey> {
        use halo2_gadgets::sinsemilla::primitives::CommitDomain;

        let rivk: pallas::Scalar = Option::from(pallas::Scalar::from_repr(self.rivk))
            .ok_or(Error::DomainRule("rivk is not a canonical Pallas scalar"))?;

        // Message bits: ak.x (255 LE) || nk (255 LE) per the Zcash
        // NU5 spec — reusing the same 255-bit encoding helper
        // commitment.rs uses to keep the two modules consistent.
        let bits = crate::commitment::bytes_to_255_le_bits(&self.ak)
            .chain(crate::commitment::bytes_to_255_le_bits(&self.nk));

        let domain = CommitDomain::new("z.cash:Orchard-CommitIvk");
        let ivk_base: pallas::Base =
            Option::from(domain.short_commit(bits, &rivk)).ok_or(Error::DomainRule(
                "CommitIvk yielded identity — regenerate seed (rotate rivk via fresh sk)",
            ))?;

        Ok(IncomingViewingKey(ivk_base.to_repr()))
    }
}

impl IncomingViewingKey {
    /// Derive a diversified address `(gd, pkd)` for the given
    /// 11-byte diversifier.
    ///
    /// ```text
    ///   gd  = DiversifyHash(d)
    ///       = SinsemillaHashToPoint^{"z.cash:Orchard-gd"}(d_bits)
    ///   pkd = ivk · gd
    /// ```
    ///
    /// per Zcash NU5 §5.4.1.6 / §4.2.3. Returns
    /// `(gd_compressed, pkd_compressed)` as 32-byte Pallas point
    /// encodings — the caller already has `d` (the input).
    ///
    /// # Errors
    /// - `DomainRule` if `ivk` is non-canonical as a Pallas
    ///   scalar (small fraction of `to_ivk` outputs hit this and
    ///   the spec says to rotate `rivk` via a fresh sk).
    /// - `DomainRule` if `DiversifyHash` hits the identity
    ///   (astronomically improbable for a fresh `d`).
    pub fn address_at(&self, diversifier: [u8; 11]) -> Result<([u8; 32], [u8; 32])> {
        use group::{Curve, Group, GroupEncoding};
        use pasta_curves::arithmetic::CurveExt;

        // ivk as a Pallas scalar. Per the spec, a small fraction
        // of CommitIvk outputs are ≥ q_S and must be rejected;
        // the wallet should rotate the seed and retry.
        let ivk_scalar: pallas::Scalar = Option::from(pallas::Scalar::from_repr(self.0)).ok_or(
            Error::DomainRule("ivk is not a canonical Pallas scalar — rotate sk and retry"),
        )?;

        // gd = DiversifyHash(d). Per Zcash NU5 §5.4.1.6, this is
        // the IETF Simplified-SWU **hash-to-curve** on Pallas with
        // personalization "z.cash:Orchard-gd" — NOT the in-circuit
        // Sinsemilla hash. Sinsemilla is used for CommitIvk +
        // NoteCommit (cheap in-circuit) but the diversifier hash
        // uses the standard hash-to-curve because it's only
        // ever evaluated out-of-circuit.
        //
        // Reference: orchard 0.12 src/spec.rs:225-231 `diversify_hash`
        let hasher = pallas::Point::hash_to_curve("z.cash:Orchard-gd");
        let gd_raw = hasher(&diversifier);
        // Spec says: if the result is the identity, substitute a
        // different fixed point. Orchard 0.12 uses `hasher(&[])`
        // as the substitute — match that.
        let gd: pallas::Point = if bool::from(gd_raw.is_identity()) {
            hasher(&[])
        } else {
            gd_raw
        };

        // pkd = ivk · gd.
        let pkd: pallas::Point = gd * ivk_scalar;

        // Serialize both as compressed Pallas bytes (affine form).
        let to_bytes = |p: pallas::Point| -> [u8; 32] {
            let mut out = [0u8; 32];
            out.copy_from_slice(p.to_affine().to_bytes().as_ref());
            out
        };
        Ok((to_bytes(gd), to_bytes(pkd)))
    }
}

// The local `bytes_to_le_bits` helper used to live here as a
// byte-aligned 256-bit decomposition. With the bit-encoding
// unification slice (2026-05-17), both this module and
// `commitment.rs` use `crate::commitment::bytes_to_255_le_bits`
// for the spec-exact 255-bit encoding. The duplicate is gone.

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sk(seed: u8) -> SpendingKey {
        let mut bytes = [seed; 32];
        // Vary the first byte so different seeds give different sk.
        bytes[0] = seed.wrapping_add(1);
        SpendingKey::from_bytes(bytes).unwrap()
    }

    #[test]
    fn spending_key_rejects_zero() {
        assert!(SpendingKey::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn spending_key_debug_redacts() {
        let sk = SpendingKey::from_bytes([7u8; 32]).unwrap();
        let dbg = format!("{:?}", sk);
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("07"), "must not leak raw bytes");
    }

    #[test]
    fn prf_expand_is_deterministic() {
        let sk = [1u8; 32];
        let out1 = prf_expand(&sk, PRF_EXPAND_NK_TAG);
        let out2 = prf_expand(&sk, PRF_EXPAND_NK_TAG);
        assert_eq!(out1, out2);
    }

    #[test]
    fn prf_expand_differs_per_tag() {
        let sk = [1u8; 32];
        let ask_out = prf_expand(&sk, PRF_EXPAND_ASK_TAG);
        let nk_out = prf_expand(&sk, PRF_EXPAND_NK_TAG);
        let rivk_out = prf_expand(&sk, PRF_EXPAND_RIVK_TAG);
        assert_ne!(ask_out, nk_out);
        assert_ne!(ask_out, rivk_out);
        assert_ne!(nk_out, rivk_out);
    }

    #[test]
    fn prf_expand_differs_per_sk() {
        let out_a = prf_expand(&[1u8; 32], PRF_EXPAND_ASK_TAG);
        let out_b = prf_expand(&[2u8; 32], PRF_EXPAND_ASK_TAG);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn nullifier_key_is_deterministic_and_canonical() {
        let sk = test_sk(10);
        let nk1 = sk.nullifier_key().unwrap();
        let nk2 = sk.nullifier_key().unwrap();
        // Same sk → same nk (load-bearing for scanning).
        assert_eq!(nk1.0, nk2.0);
        // The bytes must parse as a canonical Pallas base — which
        // NullifierDerivingKey::from_bytes enforces. If derivation
        // ever produced non-canonical bytes, .unwrap() above
        // would panic.
    }

    #[test]
    fn nullifier_key_differs_per_sk() {
        let nk_a = test_sk(20).nullifier_key().unwrap();
        let nk_b = test_sk(21).nullifier_key().unwrap();
        assert_ne!(nk_a.0, nk_b.0);
    }

    #[test]
    fn full_viewing_key_is_deterministic() {
        let sk = test_sk(30);
        let fvk1 = sk.full_viewing_key().unwrap();
        let fvk2 = sk.full_viewing_key().unwrap();
        assert_eq!(fvk1.ak, fvk2.ak);
        assert_eq!(fvk1.nk, fvk2.nk);
        assert_eq!(fvk1.ovk, fvk2.ovk);
    }

    #[test]
    fn full_viewing_key_components_are_distinct() {
        // ak, nk, ovk are different 32-byte values for a typical
        // sk — they're derived from different PRF outputs and
        // post-processed through different functions.
        let sk = test_sk(40);
        let fvk = sk.full_viewing_key().unwrap();
        assert_ne!(fvk.ak, fvk.nk);
        assert_ne!(fvk.ak, fvk.ovk);
        assert_ne!(fvk.nk, fvk.ovk);
    }

    #[test]
    fn full_viewing_key_differs_per_sk() {
        let fvk_a = test_sk(50).full_viewing_key().unwrap();
        let fvk_b = test_sk(51).full_viewing_key().unwrap();
        assert_ne!(fvk_a.ak, fvk_b.ak);
        assert_ne!(fvk_a.nk, fvk_b.nk);
        assert_ne!(fvk_a.ovk, fvk_b.ovk);
    }

    #[test]
    fn fvk_nk_matches_nullifier_key() {
        // Sanity: the nk in the FVK must equal what
        // SpendingKey::nullifier_key() returns. If the two
        // derivation paths ever diverge, the wallet's stored FVK
        // would scan for a different set of nullifiers than the
        // spender produces.
        let sk = test_sk(60);
        let fvk = sk.full_viewing_key().unwrap();
        let nk = sk.nullifier_key().unwrap();
        assert_eq!(fvk.nk, nk.0);
    }

    #[test]
    fn ak_lives_on_pallas_curve() {
        // ak should be the x-coord of a real Pallas point.
        // Reconstruct the point and verify it's on-curve by
        // checking from_repr succeeds for the x-coord as a
        // canonical Pallas base element.
        let sk = test_sk(70);
        let fvk = sk.full_viewing_key().unwrap();
        let ak_base = pallas::Base::from_repr(fvk.ak);
        let opt: Option<pallas::Base> = ak_base.into();
        assert!(opt.is_some(), "ak must be a canonical Pallas base value");
    }

    #[test]
    fn spend_auth_generator_is_stable_and_nonidentity() {
        use group::Group;
        let g1 = spend_auth_generator();
        let g2 = spend_auth_generator();
        assert_eq!(g1, g2);
        assert_ne!(g1, pallas::Point::identity());
    }

    // ── to_ivk + address_at (real implementations) ───────────────

    /// Derive an FVK for a test sk and return both. Useful for
    /// tests that need to thread the same FVK through multiple
    /// derivations.
    fn fvk_for(seed: u8) -> (SpendingKey, FullViewingKey) {
        let sk = test_sk(seed);
        let fvk = sk.full_viewing_key().unwrap();
        (sk, fvk)
    }

    #[test]
    fn fvk_carries_rivk() {
        // After the rivk addition, the FVK should expose it. If it
        // ever vanishes, ivk derivation breaks silently.
        let (_, fvk) = fvk_for(100);
        assert_ne!(fvk.rivk, [0u8; 32]);
    }

    #[test]
    fn to_ivk_is_deterministic() {
        let (_, fvk) = fvk_for(101);
        let ivk1 = fvk.to_ivk().unwrap();
        let ivk2 = fvk.to_ivk().unwrap();
        assert_eq!(ivk1.0, ivk2.0);
    }

    #[test]
    fn to_ivk_differs_per_sk() {
        let (_, fvk_a) = fvk_for(110);
        let (_, fvk_b) = fvk_for(111);
        let ivk_a = fvk_a.to_ivk().unwrap();
        let ivk_b = fvk_b.to_ivk().unwrap();
        assert_ne!(ivk_a.0, ivk_b.0);
    }

    #[test]
    fn to_ivk_rejects_non_canonical_rivk() {
        let (_, mut fvk) = fvk_for(120);
        fvk.rivk = [0xff; 32]; // exceeds q_pallas_scalar
        let r = fvk.to_ivk();
        assert!(matches!(r, Err(Error::DomainRule(_))));
    }

    /// Sweep test_sk seeds looking for one whose derived ivk
    /// happens to be canonical as a Pallas scalar (most are; the
    /// fraction that aren't is on the order of 2^-128). Returns
    /// the seed and the IVK.
    fn canonical_ivk_fixture(seed_start: u8) -> Option<(u8, IncomingViewingKey)> {
        for seed in seed_start..seed_start.saturating_add(32) {
            let (_, fvk) = fvk_for(seed);
            let ivk = fvk.to_ivk().ok()?;
            // Try address_at with a fixed diversifier — if it
            // succeeds the ivk is canonical-as-scalar.
            if ivk.address_at([1u8; 11]).is_ok() {
                return Some((seed, ivk));
            }
        }
        None
    }

    #[test]
    fn address_at_is_deterministic_for_canonical_ivk() {
        let (_, ivk) = canonical_ivk_fixture(130).expect("find canonical ivk");
        let d = [7u8; 11];
        let (gd_1, pkd_1) = ivk.address_at(d).unwrap();
        let (gd_2, pkd_2) = ivk.address_at(d).unwrap();
        assert_eq!(gd_1, gd_2);
        assert_eq!(pkd_1, pkd_2);
    }

    #[test]
    fn address_at_differs_per_diversifier() {
        let (_, ivk) = canonical_ivk_fixture(140).expect("find canonical ivk");
        let (gd_a, pkd_a) = ivk.address_at([1u8; 11]).unwrap();
        let (gd_b, pkd_b) = ivk.address_at([2u8; 11]).unwrap();
        assert_ne!(gd_a, gd_b, "different d → different gd");
        assert_ne!(pkd_a, pkd_b, "different d → different pkd");
    }

    #[test]
    fn address_at_differs_per_ivk() {
        let (_, ivk_a) = canonical_ivk_fixture(150).expect("ivk a");
        let (_, ivk_b) = canonical_ivk_fixture(160).expect("ivk b");
        let d = [3u8; 11];
        let (gd_a, pkd_a) = ivk_a.address_at(d).unwrap();
        let (gd_b, pkd_b) = ivk_b.address_at(d).unwrap();
        // gd is derived from d alone — same for both ivks.
        assert_eq!(gd_a, gd_b, "gd depends only on d");
        // But pkd = ivk·gd — different ivk → different pkd.
        assert_ne!(pkd_a, pkd_b, "different ivk → different pkd");
    }

    #[test]
    fn pkd_is_on_pallas_curve() {
        // The returned pkd bytes must decode back to a valid Pallas
        // point. If our point-serialization shape ever drifts from
        // what GroupEncoding::from_bytes expects, this catches it.
        use group::GroupEncoding;
        let (_, ivk) = canonical_ivk_fixture(170).expect("find canonical ivk");
        let (gd_bytes, pkd_bytes) = ivk.address_at([5u8; 11]).unwrap();
        let gd_bytes_arr: <pallas::Point as GroupEncoding>::Repr = gd_bytes.into();
        let pkd_bytes_arr: <pallas::Point as GroupEncoding>::Repr = pkd_bytes.into();
        assert!(
            bool::from(pallas::Point::from_bytes(&gd_bytes_arr).is_some()),
            "gd bytes must roundtrip through GroupEncoding"
        );
        assert!(
            bool::from(pallas::Point::from_bytes(&pkd_bytes_arr).is_some()),
            "pkd bytes must roundtrip through GroupEncoding"
        );
    }

    #[test]
    fn full_address_derivation_chain_holds() {
        // End-to-end: sk → fvk → ivk → (gd, pkd) → same on
        // re-derivation. The load-bearing property for the wallet:
        // a 32-byte seed must reproducibly identify the same
        // address (otherwise an on-disk wallet's seed couldn't
        // re-derive the recipient's addresses).
        let sk_bytes = [
            0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
            0x5e, 0x5f, 0x60, 0x61,
        ];
        let sk = SpendingKey::from_bytes(sk_bytes).unwrap();
        let fvk = sk.full_viewing_key().unwrap();
        let Ok(ivk) = fvk.to_ivk() else {
            // Some sk values produce an ivk that isn't canonical
            // as a scalar; for this test we picked a stable seed
            // but if it ever lands in the bad range we want to
            // surface the issue rather than silently skip.
            panic!("test seed produced non-canonical ivk — pick a different seed");
        };
        let d = [9u8; 11];
        let Ok((gd_1, pkd_1)) = ivk.address_at(d) else {
            panic!("test ivk not canonical as scalar — pick a different seed");
        };

        // Re-derive from scratch — must match byte-for-byte.
        let sk2 = SpendingKey::from_bytes(sk_bytes).unwrap();
        let fvk2 = sk2.full_viewing_key().unwrap();
        let ivk2 = fvk2.to_ivk().unwrap();
        let (gd_2, pkd_2) = ivk2.address_at(d).unwrap();
        assert_eq!(gd_1, gd_2);
        assert_eq!(pkd_1, pkd_2);
    }
}
