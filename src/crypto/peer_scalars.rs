//! # PeerScalar / PeerPoint — canonical-decode-enforced wrappers
//!
//! Every scalar or curve point that arrives from a peer (via a network
//! message, an RPC request, or any wire-decoded proof) MUST go through
//! canonical byte validation before it enters the crypto math. Two classes
//! of bug become possible when it doesn't:
//!
//!   1. **Non-canonical scalar acceptance** (Monero CVE-2017-14428 class).
//!      `Scalar::from_bytes_mod_order` silently reduces any 32 bytes modulo
//!      the group order, so a bit-distinct byte sequence maps to the same
//!      underlying scalar. On a chain where the txid or a cache key is a
//!      function of the raw proof bytes, that lets an attacker produce two
//!      DIFFERENT txids for the SAME underlying spend — txid confusion
//!      double-spend or cache poisoning.
//!
//!   2. **Non-canonical point acceptance**. `CompressedRistretto` accepts
//!      arbitrary bytes at construction; the check that they encode a
//!      valid Ristretto element happens at `decompress()`, and the
//!      identity point ([0; 32]) is a valid Ristretto encoding.
//!      Downstream code that assumes "if this decompressed, it's not
//!      identity" is wrong.
//!
//! Prior audit passes fixed these one site at a time (Wave 15 landed
//! from_canonical_bytes at 3 sites in disclosure.rs, 1 in lelantus_spark;
//! Address serde/borsh paths were fixed in Waves 6 + 12). The one-at-a-
//! time approach is fragile: any NEW verifier can silently regress.
//! `PeerScalar` and `PeerPoint` make the fix structural — the only way to
//! obtain one is `decode`, and that fails on non-canonical input.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::crypto::{PeerScalar, PeerPoint};
//!
//! fn verify_something(bytes: [u8; 32], point_bytes: [u8; 32]) -> Result<bool> {
//!     let s: PeerScalar = PeerScalar::decode(bytes)?;
//!     let p: PeerPoint = PeerPoint::decode_non_identity(point_bytes)?;
//!     // Math uses .as_scalar() / .as_point().
//!     let result = p.as_point() * s.as_scalar();
//!     Ok(true)
//! }
//! ```
//!
//! ## Design notes
//!
//! - `PeerScalar` and `PeerPoint` implement `Serialize` / `Deserialize`
//!   (serde) and `BorshSerialize` / `BorshDeserialize` (borsh). The
//!   `Deserialize` and `BorshDeserialize` impls RUN THE CANONICAL DECODE
//!   CHECK — so any struct with a `PeerScalar` or `PeerPoint` field
//!   automatically validates its peer-controlled input at parse time.
//!   This is the strongest form of the fix: no path from wire bytes to
//!   typed proof value can skip the check.
//!
//!   (An earlier draft of this module doc said "deliberately no serde
//!   impls, so callers must decode explicitly" — that reasoning was
//!   BACKWARDS. If the impls exist AND validate, then a caller can't
//!   accidentally skip the check by holding the newtype. If the impls
//!   don't exist, containers can't hold the newtype at all, and every
//!   proof struct keeps its `[u8; 32]` fields with the decode as a
//!   convention that a new site can silently forget. Validating impls
//!   is the class-closing form.)
//!
//! - `PeerPoint` has two decoders and the SAFER one is the default:
//!   * `decode_non_identity(bytes)` rejects both invalid encodings AND
//!     the identity element. This is what `Deserialize` and
//!     `BorshDeserialize` use — the sane default for public keys,
//!     commitments, challenge points, and any other position where
//!     identity would break a protocol invariant.
//!   * `decode(bytes)` accepts any valid Ristretto element including
//!     identity. Available for the rare case where identity is
//!     semantically meaningful; callers of this variant must be able
//!     to explain (in a comment) WHY identity is admissible.
//!
//! - The wrapper is zero-cost at runtime: `#[repr(transparent)]` plus
//!   inline `as_scalar()` / `as_point()` accessors.
//!
//! ## What this replaces
//!
//! - `Scalar::from_bytes_mod_order(bytes)`  →  `PeerScalar::decode(bytes)?`
//! - `Scalar::from_canonical_bytes(bytes)`  →  same, but returns Result
//!   instead of the awkward `Option<Scalar>` -> `.into()` dance.
//! - `CompressedRistretto(bytes).decompress()` on peer input  →
//!   `PeerPoint::decode_non_identity(bytes)?` (or `::decode` when identity
//!   is admissible — with a comment justifying it).
//!
//! ## What this does NOT close (yet)
//!
//! The point-side check on Fiat-Shamir Schnorr `R` values in
//! `disclosure.rs` (BalanceProof.schnorr_r, OwnershipProof.schnorr_r) is
//! still using raw `CompressedRistretto(bytes).decompress()` — identity
//! is not rejected. Whether identity-R breaks Schnorr soundness in each
//! specific proof is per-proof cryptographic analysis that this pass
//! deliberately does NOT attempt. Migrating those fields to PeerPoint
//! (which rejects identity) is safe DEFENSE IN DEPTH — if identity was
//! legitimate for some proof, tests would catch the change. That
//! migration is called out in the todo list for a follow-up commit
//! after cryptographic-soundness analysis. See the operator's rule:
//! "some things should be complex and some things should be simple" —
//! the scalar side is simple prior art; the point-identity question is
//! genuine complexity that deserves its own care.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};

use crate::error::{Error, Result};

/// A curve25519-dalek Scalar that has been verified to be in canonical
/// byte form. Only constructible via `decode`. The wrapper carries no
/// runtime overhead vs `Scalar` and can be treated as `&Scalar` via
/// `as_scalar()`.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct PeerScalar(Scalar);

impl PeerScalar {
    /// Decode a peer-controlled 32-byte value into a Scalar, REJECTING
    /// non-canonical encodings (byte sequences that reduce mod the group
    /// order to a different scalar than they nominally represent).
    ///
    /// This is what every peer-facing verifier should call, and what
    /// `Scalar::from_bytes_mod_order` is emphatically NOT — the mod-order
    /// variant silently accepts non-canonical input.
    ///
    /// Prior art:
    ///   • Monero CVE-2017-14428 (RCT nullification via non-canonical scalar)
    ///   • Zcash NU5 canonical-encoding discriminants on Halo2 proofs
    ///   • BIP-62 low-S / canonical-encoding enforcement
    ///   • `dalek`'s own `from_canonical_bytes` — this is a thin wrapper
    ///     that surfaces the failure as a typed `Error` instead of
    ///     `Option<Scalar>`.
    #[inline]
    pub fn decode(bytes: [u8; 32]) -> Result<Self> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .map(PeerScalar)
            .ok_or_else(|| {
                Error::CryptoError(
                    "peer-supplied scalar is not a canonical curve25519 encoding".into(),
                )
            })
    }

    /// Zero constant — canonical by definition. Handy for tests and for
    /// verifier corner-cases where the equation needs an explicit zero.
    #[inline]
    pub fn zero() -> Self {
        PeerScalar(Scalar::ZERO)
    }

    /// Access the underlying Scalar for math. Read-only by construction.
    #[inline]
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Consume the wrapper and return the raw Scalar. Prefer `as_scalar`
    /// where a reference suffices; use this only when passing to APIs that
    /// take Scalar by value.
    #[inline]
    pub fn into_scalar(self) -> Scalar {
        self.0
    }
}

/// A curve25519-dalek RistrettoPoint that has been verified to decompress
/// from canonical bytes. Two decoders: `decode` (any valid Ristretto
/// point) and `decode_non_identity` (rejects the identity element).
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct PeerPoint(RistrettoPoint);

impl PeerPoint {
    /// Decode a peer-controlled 32-byte value into a RistrettoPoint. Fails
    /// if the bytes do not encode a valid Ristretto element. Accepts the
    /// identity point — use `decode_non_identity` when identity would be
    /// a protocol violation (public keys, commitments, challenge points).
    #[inline]
    pub fn decode(bytes: [u8; 32]) -> Result<Self> {
        CompressedRistretto(bytes)
            .decompress()
            .map(PeerPoint)
            .ok_or_else(|| {
                Error::CryptoError(
                    "peer-supplied point is not a valid Ristretto encoding".into(),
                )
            })
    }

    /// Decode a peer-controlled 32-byte value into a RistrettoPoint, ALSO
    /// rejecting the identity element.
    ///
    /// The identity point is a valid Ristretto encoding, but accepting it
    /// as a public key / commitment / challenge point breaks downstream
    /// invariants:
    ///   • CLSAG with an identity ring member is trivially distinguishable
    ///   • ECDH shared-secret with identity is publicly computable
    ///   • Pedersen commitment to identity factors out of the balance
    ///     equation, enabling forgery
    ///
    /// This is the same identity rejection `PublicKey::from_bytes_checked`
    /// already does — this wrapper provides it at the primitive level so
    /// all peer-facing paths get it uniformly.
    ///
    /// Prior art: `PublicKey::from_bytes_checked` at
    /// src/primitives/keys.rs; the Wave 6/12 Address serde+borsh fixes at
    /// src/primitives/address.rs.
    #[inline]
    pub fn decode_non_identity(bytes: [u8; 32]) -> Result<Self> {
        let p = Self::decode(bytes)?;
        if p.0 == RistrettoPoint::identity() {
            return Err(Error::CryptoError(
                "peer-supplied point is the identity element (not admissible here)".into(),
            ));
        }
        Ok(p)
    }

    /// Access the underlying RistrettoPoint for math.
    #[inline]
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    /// Consume the wrapper and return the raw RistrettoPoint.
    #[inline]
    pub fn into_point(self) -> RistrettoPoint {
        self.0
    }
}

// ── Validating serde + borsh impls ───────────────────────────────────
//
// Closes C31 (audit-catalogue). The module docstring at the top of this
// file promised these impls — they were missing, so structs with a
// `PeerScalar`/`PeerPoint` field fell back to raw-bytes decode at
// serde/borsh time (no canonical check when a wire message hit them
// through borsh::from_slice). With the impls landed, every wire→typed
// path routes through `decode` / `decode_non_identity`, making the
// canonical-decode enforcement structural.
//
// Serialize/BorshSerialize emit raw 32-byte canonical bytes (Scalar
// bytes are canonical for a valid PeerScalar; Ristretto compress
// produces the canonical form for PeerPoint).
//
// Deserialize/BorshDeserialize:
//   • PeerScalar → decode(): rejects non-canonical scalars.
//   • PeerPoint  → decode_non_identity(): rejects identity as well.
//     This is the safer default per the module docstring §"Design
//     notes". Callers that legitimately need identity should
//     deserialize as `[u8; 32]` and call `PeerPoint::decode(bytes)?`
//     explicitly, with a comment justifying identity admission.
//
// Prior art: `curve::Commitment` and `curve::KeyImage` implement this
// exact pattern via `PublicPoint`'s validating serde/borsh
// (src/crypto/curve.rs:343-430). Same recipe here.

impl serde::Serialize for PeerScalar {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        // Scalar::to_bytes returns the canonical encoding for a valid
        // (post-decode) PeerScalar. serde format decides wire shape.
        self.0.to_bytes().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PeerScalar {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let bytes = <[u8; 32] as serde::Deserialize>::deserialize(deserializer)?;
        Self::decode(bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl borsh::BorshSerialize for PeerScalar {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }
}

impl borsh::BorshDeserialize for PeerScalar {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Self::decode(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl serde::Serialize for PeerPoint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.0.compress().to_bytes().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PeerPoint {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let bytes = <[u8; 32] as serde::Deserialize>::deserialize(deserializer)?;
        // Safer default: reject identity at parse time. See design-notes
        // block above for why this is the default and how to opt out.
        Self::decode_non_identity(bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl borsh::BorshSerialize for PeerPoint {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.compress().to_bytes())
    }
}

impl borsh::BorshDeserialize for PeerPoint {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Self::decode_non_identity(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn scalar_decode_accepts_canonical() {
        // The zero scalar is canonical.
        assert!(PeerScalar::decode([0u8; 32]).is_ok());
        // A random-generated scalar's bytes are canonical by construction.
        let s = Scalar::random(&mut OsRng);
        assert!(PeerScalar::decode(s.to_bytes()).is_ok());
    }

    #[test]
    fn scalar_decode_rejects_non_canonical() {
        // The group order + 1 encoded as bytes is non-canonical:
        // `l` is the order; representing `l + 1` would reduce to 1, but
        // the specific bit sequence is not the canonical encoding of 1.
        // curve25519's `l` is 2^252 + 27742317777372353535851937790883648493.
        // Any 32-byte sequence with the high bit of byte 31 (index 31) set
        // above 0x10 is non-canonical.
        let mut bytes = [0xffu8; 32];
        bytes[31] = 0xff;
        assert!(PeerScalar::decode(bytes).is_err());
    }

    #[test]
    fn point_decode_accepts_valid_ristretto() {
        // Identity is a valid Ristretto encoding (accepted by `decode`,
        // rejected by `decode_non_identity`).
        assert!(PeerPoint::decode([0u8; 32]).is_ok());
        // A random-generated point's bytes are canonical by construction.
        let p = RistrettoPoint::random(&mut OsRng);
        assert!(PeerPoint::decode(p.compress().to_bytes()).is_ok());
    }

    #[test]
    fn point_decode_rejects_junk() {
        // Bytes that don't encode any Ristretto element: high bit set
        // in a position that violates the encoding invariants.
        let bytes = [0xffu8; 32];
        assert!(PeerPoint::decode(bytes).is_err());
    }

    #[test]
    fn point_decode_non_identity_rejects_identity() {
        // [0; 32] IS a valid Ristretto encoding (the identity element),
        // but the non-identity decoder must refuse it.
        assert!(PeerPoint::decode([0u8; 32]).is_ok());
        assert!(PeerPoint::decode_non_identity([0u8; 32]).is_err());
    }

    #[test]
    fn point_decode_non_identity_accepts_random() {
        let p = RistrettoPoint::random(&mut OsRng);
        assert!(PeerPoint::decode_non_identity(p.compress().to_bytes()).is_ok());
    }

    #[test]
    fn scalar_zero_roundtrips() {
        let z = PeerScalar::zero();
        assert_eq!(z.as_scalar().to_bytes(), [0u8; 32]);
    }

    // ── C31 close: validating serde + borsh roundtrips ───────────────

    #[test]
    fn scalar_borsh_roundtrip_valid() {
        let s = Scalar::random(&mut OsRng);
        let ps = PeerScalar::decode(s.to_bytes()).unwrap();
        let mut buf = Vec::new();
        borsh::BorshSerialize::serialize(&ps, &mut buf).unwrap();
        assert_eq!(buf.len(), 32);
        assert_eq!(buf, s.to_bytes().to_vec());
        let ps2: PeerScalar = borsh::from_slice(&buf).unwrap();
        assert_eq!(ps2.as_scalar().to_bytes(), s.to_bytes());
    }

    #[test]
    fn scalar_borsh_rejects_non_canonical() {
        // Non-canonical: high bits of byte 31 set well past the group order.
        let mut bytes = [0xffu8; 32];
        bytes[31] = 0xff;
        let result: std::result::Result<PeerScalar, _> = borsh::from_slice(&bytes);
        assert!(
            result.is_err(),
            "borsh MUST reject non-canonical scalar via decode()"
        );
    }

    #[test]
    fn scalar_serde_json_roundtrip_valid() {
        let s = Scalar::random(&mut OsRng);
        let ps = PeerScalar::decode(s.to_bytes()).unwrap();
        let json = serde_json::to_string(&ps).unwrap();
        let ps2: PeerScalar = serde_json::from_str(&json).unwrap();
        assert_eq!(ps2.as_scalar().to_bytes(), s.to_bytes());
    }

    #[test]
    fn scalar_serde_json_rejects_non_canonical() {
        // Serialize a raw [u8; 32] that isn't a canonical scalar, then try
        // to deserialize it as PeerScalar via the same JSON format.
        let mut bytes = [0xffu8; 32];
        bytes[31] = 0xff;
        let json = serde_json::to_string(&bytes).unwrap();
        let result: std::result::Result<PeerScalar, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "serde JSON MUST reject non-canonical scalar bytes"
        );
    }

    #[test]
    fn point_borsh_roundtrip_valid() {
        let p = RistrettoPoint::random(&mut OsRng);
        let pp = PeerPoint::decode_non_identity(p.compress().to_bytes()).unwrap();
        let mut buf = Vec::new();
        borsh::BorshSerialize::serialize(&pp, &mut buf).unwrap();
        assert_eq!(buf.len(), 32);
        let pp2: PeerPoint = borsh::from_slice(&buf).unwrap();
        assert_eq!(
            pp2.as_point().compress().to_bytes(),
            p.compress().to_bytes()
        );
    }

    #[test]
    fn point_borsh_rejects_identity_via_non_identity_default() {
        // Identity ([0; 32]) is a valid Ristretto encoding, but the borsh
        // path uses decode_non_identity as the safer default (per module
        // docstring). Wire-level identity MUST be rejected at parse time.
        let bytes = [0u8; 32];
        let result: std::result::Result<PeerPoint, _> = borsh::from_slice(&bytes);
        assert!(
            result.is_err(),
            "borsh MUST reject identity via decode_non_identity"
        );
    }

    #[test]
    fn point_borsh_rejects_junk_bytes() {
        // Bytes that don't encode any Ristretto element.
        let bytes = [0xffu8; 32];
        let result: std::result::Result<PeerPoint, _> = borsh::from_slice(&bytes);
        assert!(result.is_err(), "borsh MUST reject non-Ristretto bytes");
    }

    #[test]
    fn point_serde_json_roundtrip_valid() {
        let p = RistrettoPoint::random(&mut OsRng);
        let pp = PeerPoint::decode_non_identity(p.compress().to_bytes()).unwrap();
        let json = serde_json::to_string(&pp).unwrap();
        let pp2: PeerPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(
            pp2.as_point().compress().to_bytes(),
            p.compress().to_bytes()
        );
    }

    #[test]
    fn point_serde_json_rejects_identity() {
        let bytes = [0u8; 32];
        let json = serde_json::to_string(&bytes).unwrap();
        let result: std::result::Result<PeerPoint, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "serde JSON MUST reject identity via decode_non_identity"
        );
    }

    /// The whole point of the C31 fix: a struct containing a `PeerPoint`
    /// field, deserialized via borsh, MUST fail if the wire bytes at that
    /// field position are non-canonical (or identity, for the default
    /// PeerPoint path). This is what makes the check STRUCTURAL — no
    /// container-side discipline required.
    #[test]
    fn peerpoint_field_in_struct_rejected_at_borsh_parse() {
        use borsh::{BorshDeserialize, BorshSerialize};

        #[derive(BorshSerialize, BorshDeserialize)]
        struct Carrier {
            tag: u8,
            point: PeerPoint,
        }

        // Round-trip a valid Carrier first (sanity).
        let p = RistrettoPoint::random(&mut OsRng);
        let good = Carrier {
            tag: 7,
            point: PeerPoint::decode_non_identity(p.compress().to_bytes()).unwrap(),
        };
        let mut buf = Vec::new();
        good.serialize(&mut buf).unwrap();
        let parsed: Carrier = borsh::from_slice(&buf).unwrap();
        assert_eq!(parsed.tag, 7);
        assert_eq!(
            parsed.point.as_point().compress().to_bytes(),
            p.compress().to_bytes()
        );

        // Now craft a wire message with tag=7 and identity in the point
        // slot. Parse MUST fail — the check is structural.
        let mut bad = vec![7u8];
        bad.extend_from_slice(&[0u8; 32]);
        let result: std::result::Result<Carrier, _> = borsh::from_slice(&bad);
        assert!(
            result.is_err(),
            "struct with PeerPoint field MUST reject identity at borsh parse"
        );
    }

    /// Same shape for PeerScalar-in-struct — non-canonical scalar wire
    /// bytes must reject at parse time when contained in a struct.
    #[test]
    fn peerscalar_field_in_struct_rejected_at_borsh_parse() {
        use borsh::{BorshDeserialize, BorshSerialize};

        #[derive(BorshSerialize, BorshDeserialize)]
        struct Carrier {
            tag: u8,
            scalar: PeerScalar,
        }

        // Craft wire bytes with a non-canonical scalar in the scalar slot.
        let mut bad = vec![7u8];
        let mut scalar_bytes = [0xffu8; 32];
        scalar_bytes[31] = 0xff;
        bad.extend_from_slice(&scalar_bytes);
        let result: std::result::Result<Carrier, _> = borsh::from_slice(&bad);
        assert!(
            result.is_err(),
            "struct with PeerScalar field MUST reject non-canonical bytes at borsh parse"
        );
    }
}
