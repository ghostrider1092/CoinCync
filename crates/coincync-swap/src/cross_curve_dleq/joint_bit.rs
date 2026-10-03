//! One bit: `(BTC=0 AND CYNC=0) OR (BTC=1 AND CYNC=1)`.
//!
//! Follows the pinned sigma_fun reference in the parent module: commitments
//! have form `C = r*G + b*W`, where `W = 2^i*H` is a trusted bit weight. This
//! differs from the legacy `b*G + r*H` layout. Branch `j` is the statement
//! "`C - j*W` is a multiple of `G`" on BOTH curves at once.
//!
//! Each branch uses ONE challenge for both curves, with independent responses
//! to independent blinding witnesses. The two OR challenges obey e0 XOR e1 = e.
//! Challenges are 31-byte big-endian integers, below both scalar orders; no
//! per-curve reduction is needed. This does not permit sharing prover nonces.
//!
//! Soundness: two accepting transcripts with different `e` differ in at least
//! one branch challenge, and that branch yields `r_btc` and `r_cync` for the
//! SAME `j`. A mixed pair (BTC=0, CYNC=1) has no such branch.
//!
//! Prover side channels: simulated announcements for both public branch
//! statements are computed before the bit selects the final announcements.
//! The SEC1 selection helper reparses only selected public outputs, never a
//! secret-selected branch statement. Secret scalars multiply non-generator
//! points through libsecp256k1's ECDH (`ecmult_const`), never through
//! `PublicKey::mul_tweak` (variable-time).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as RistrettoScalar;
use curve25519_dalek::traits::IsIdentity;
use rand::{CryptoRng, RngCore};
use secp256k1::{All, PublicKey, Scalar as BtcScalar, Secp256k1, SecretKey};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

use crate::{Error, Result};

const DEGENERATE: Error =
    Error::Verification("cross-curve prover hit negligible-probability degenerate randomness");

/// A public 248-bit challenge in a common space, including zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Challenge(pub(super) [u8; 31]);

impl Challenge {
    pub(super) fn xor(self, other: Self) -> Self {
        let mut bytes = self.0;
        for (byte, rhs) in bytes.iter_mut().zip(other.0) {
            *byte ^= rhs;
        }
        Self(bytes)
    }

    /// `a` when `choice` is 0, `b` when it is 1, in constant time.
    fn select(a: Self, b: Self, choice: Choice) -> Self {
        Self(select_bytes(&a.0, &b.0, choice))
    }

    /// Uniform nonzero challenge for the simulated branch. Rejecting zero
    /// changes the distribution by 2^-248 and lets the scalar enter ECDH.
    fn random_nonzero(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        loop {
            let mut bytes = [0u8; 31];
            rng.fill_bytes(&mut bytes);
            if bytes != [0u8; 31] {
                return Self(bytes);
            }
        }
    }

    /// Interpret exactly the same integer in both fields, with explicit endian
    /// conversion. These parsers accept zero and never reduce modulo an order.
    pub(super) fn scalars(self) -> Result<(BtcScalar, RistrettoScalar)> {
        let mut bytes = [0; 32];
        bytes[1..].copy_from_slice(&self.0);
        let btc = BtcScalar::from_be_bytes(bytes)
            .map_err(|_| Error::Verification("joint-bit BTC challenge out of range"))?;
        bytes.reverse();
        let cync = Option::<RistrettoScalar>::from(RistrettoScalar::from_canonical_bytes(bytes))
            .ok_or(Error::Verification("joint-bit CYNC challenge out of range"))?;
        Ok((btc, cync))
    }

    /// The same integer as a secret-scalar type, for the simulated branch
    /// before the proof is published. Rejects zero.
    fn secret_scalars(self) -> Result<(SecretKey, RistrettoScalar)> {
        let mut bytes = [0; 32];
        bytes[1..].copy_from_slice(&self.0);
        let btc = SecretKey::from_slice(&bytes).map_err(|_| DEGENERATE)?;
        bytes.reverse();
        let cync = Option::<RistrettoScalar>::from(RistrettoScalar::from_canonical_bytes(bytes))
            .ok_or(DEGENERATE)?;
        Ok((btc, cync))
    }
}

/// Public Schnorr responses for one shared branch; never secret witnesses.
/// No `Debug`: `secp256k1::Scalar` deliberately has none.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Responses {
    pub(super) btc: BtcScalar,
    pub(super) cync: RistrettoScalar,
}

impl Responses {
    /// Responses may be zero. SecretKey parsing would incorrectly reject that
    /// valid case; reducing noncanonical attacker input would be wrong too.
    pub(super) fn from_bytes(btc_be: [u8; 32], cync_le: [u8; 32]) -> Result<Self> {
        let btc = BtcScalar::from_be_bytes(btc_be)
            .map_err(|_| Error::Verification("joint-bit BTC response is not canonical"))?;
        let cync = Option::<RistrettoScalar>::from(RistrettoScalar::from_canonical_bytes(cync_le))
            .ok_or(Error::Verification("joint-bit CYNC response is not canonical"))?;
        Ok(Self { btc, cync })
    }

    /// `(BTC big-endian, CYNC little-endian)`, the inverse of `from_bytes`.
    pub(super) fn to_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (self.btc.to_be_bytes(), self.cync.to_bytes())
    }

    /// `a` when `choice` is 0, `b` when it is 1, in constant time.
    fn select(a: &Self, b: &Self, choice: Choice) -> Result<Self> {
        let btc = select_bytes(&a.btc.to_be_bytes(), &b.btc.to_be_bytes(), choice);
        Ok(Self {
            // Both inputs are canonical, so the selected bytes are too.
            btc: BtcScalar::from_be_bytes(btc).map_err(|_| DEGENERATE)?,
            cync: RistrettoScalar::conditional_select(&a.cync, &b.cync, choice),
        })
    }
}

/// Compact OR response. There is no separate per-curve branch challenge.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct JointBitResponse {
    pub(super) zero_challenge: Challenge,
    pub(super) zero: Responses,
    pub(super) one: Responses,
}

/// Points in a branch statement or its reconstructed announcement.
/// `None` represents secp256k1's identity internally, not malformed input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PointPair {
    pub(super) btc: Option<PublicKey>,
    pub(super) cync: RistrettoPoint,
}

pub(super) struct JointBitStatement {
    zero: PointPair,
    one: PointPair,
}

impl JointBitStatement {
    /// Caller supplies decoded commitments and locally derived weights at the
    /// SAME bit index. Weights come from `generators`, never from a peer.
    pub(super) fn new(
        secp: &Secp256k1<All>,
        btc_commitment: PublicKey,
        cync_commitment: RistrettoPoint,
        btc_weight: PublicKey,
        cync_weight: RistrettoPoint,
    ) -> Result<Self> {
        if cync_commitment.is_identity() || cync_weight.is_identity() {
            return Err(Error::Verification(
                "joint-bit commitment or weight is identity",
            ));
        }
        Ok(Self {
            zero: PointPair {
                btc: Some(btc_commitment),
                cync: cync_commitment,
            },
            one: PointPair {
                btc: btc_sub(secp, Some(btc_commitment), Some(btc_weight))?,
                cync: cync_commitment - cync_weight,
            },
        })
    }

    /// Reconstruct A_j = s_j*G - e_j*X_j on BOTH curves for branch j.
    ///
    /// Order is [zero branch, one branch]. Reconstruction works for arbitrary
    /// canonical responses, including forged ones: success proves nothing.
    /// The verifier hashes these announcements with the full statement and
    /// compares the derived challenge with `challenge` before acceptance.
    pub(super) fn reconstruct(
        &self,
        secp: &Secp256k1<All>,
        challenge: Challenge,
        response: &JointBitResponse,
    ) -> Result<[PointPair; 2]> {
        let challenges = [
            response.zero_challenge,
            challenge.xor(response.zero_challenge),
        ];
        Ok([
            reconstruct_branch(secp, &self.zero, &response.zero, challenges[0])?,
            reconstruct_branch(secp, &self.one, &response.one, challenges[1])?,
        ])
    }
}

fn reconstruct_branch(
    secp: &Secp256k1<All>,
    point: &PointPair,
    responses: &Responses,
    e: Challenge,
) -> Result<PointPair> {
    let (e_btc, e_cync) = e.scalars()?;
    let s_g = btc_mul(secp, Some(btc_generator(secp)?), &responses.btc)?;
    let e_x = btc_mul(secp, point.btc, &e_btc)?;
    Ok(PointPair {
        btc: btc_sub(secp, s_g, e_x)?,
        cync: RistrettoPoint::vartime_double_scalar_mul_basepoint(
            &-e_cync,
            &point.cync,
            &responses.cync,
        ),
    })
}

// ─── Prover ──────────────────────────────────────────────────────────

/// Secret per-bit prover state between the announcement and the response.
/// Holds the bit itself; never serialized, logged, or cloned.
pub(super) struct BitWitness {
    bit: Choice,
    blinding_btc: SecretKey,
    blinding_cync: RistrettoScalar,
    nonce_btc: SecretKey,
    nonce_cync: RistrettoScalar,
    simulated_btc: SecretKey,
    simulated_cync: RistrettoScalar,
    simulated_challenge: Challenge,
}

impl BitWitness {
    pub(super) fn blinding_btc(&self) -> &SecretKey {
        &self.blinding_btc
    }

    pub(super) fn blinding_cync(&self) -> &RistrettoScalar {
        &self.blinding_cync
    }
}

impl Drop for BitWitness {
    fn drop(&mut self) {
        self.bit = Choice::from(0);
        self.blinding_btc.non_secure_erase();
        self.nonce_btc.non_secure_erase();
        self.simulated_btc.non_secure_erase();
        self.blinding_cync.zeroize();
        self.nonce_cync.zeroize();
        self.simulated_cync.zeroize();
        self.simulated_challenge.0.zeroize();
    }
}

/// Public output of the announcement phase for one bit.
pub(super) struct BitCommitment {
    pub(super) commitment_btc: PublicKey,
    pub(super) commitment_cync: RistrettoPoint,
    pub(super) announcements: [PointPair; 2],
}

/// Commit to `bit` on both curves with independent blindings and produce the
/// OR announcements. All randomness is fresh and independent per curve.
pub(super) fn commit_bit(
    secp: &Secp256k1<All>,
    bit: Choice,
    btc_weight: &PublicKey,
    cync_weight: &RistrettoPoint,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(BitWitness, BitCommitment)> {
    let witness = BitWitness {
        bit,
        blinding_btc: SecretKey::new(rng),
        blinding_cync: RistrettoScalar::random(rng),
        nonce_btc: SecretKey::new(rng),
        nonce_cync: RistrettoScalar::random(rng),
        simulated_btc: SecretKey::new(rng),
        simulated_cync: RistrettoScalar::random(rng),
        simulated_challenge: Challenge::random_nonzero(rng),
    };

    // C = r*G + b*W. Compute both candidates, select in constant time.
    let blind_btc = PublicKey::from_secret_key(secp, &witness.blinding_btc);
    let shifted_btc = blind_btc.combine(btc_weight).map_err(|_| DEGENERATE)?;
    let commitment_btc = select_public_btc(&blind_btc, &shifted_btc, bit)?;
    let blind_cync = &witness.blinding_cync * RISTRETTO_BASEPOINT_TABLE;
    let commitment_cync =
        RistrettoPoint::conditional_select(&blind_cync, &(blind_cync + cync_weight), bit);

    let statement =
        JointBitStatement::new(secp, commitment_btc, commitment_cync, *btc_weight, *cync_weight)?;
    let zero_btc = statement.zero.btc.ok_or(DEGENERATE)?;
    let one_btc = statement.one.btc.ok_or(DEGENERATE)?;

    // Real branch j = bit: A = k*G with k uniform.
    let real_btc = PublicKey::from_secret_key(secp, &witness.nonce_btc);
    let real_cync = &witness.nonce_cync * RISTRETTO_BASEPOINT_TABLE;

    // Compute A = s*G - e*X for BOTH branch statements before selecting
    // the published announcements. Selecting X by the secret bit and then
    // decompressing it would expose that choice to the variable-time SEC1
    // parser: C and C-W are both derivable from the public commitment.
    let (e_btc, e_cync) = witness.simulated_challenge.secret_scalars()?;
    let s_g_btc = PublicKey::from_secret_key(secp, &witness.simulated_btc);
    let e_zero_btc = btc_mul_secret(&zero_btc, &e_btc)?;
    let e_one_btc = btc_mul_secret(&one_btc, &e_btc)?;
    let simulated_zero_btc =
        btc_sub(secp, Some(s_g_btc), Some(e_zero_btc))?.ok_or(DEGENERATE)?;
    let simulated_one_btc =
        btc_sub(secp, Some(s_g_btc), Some(e_one_btc))?.ok_or(DEGENERATE)?;
    let s_g_cync = &witness.simulated_cync * RISTRETTO_BASEPOINT_TABLE;
    let simulated_zero_cync = s_g_cync - e_cync * statement.zero.cync;
    let simulated_one_cync = s_g_cync - e_cync * statement.one.cync;

    let announcements = [
        PointPair {
            btc: Some(select_public_btc(&real_btc, &simulated_zero_btc, bit)?),
            cync: RistrettoPoint::conditional_select(&real_cync, &simulated_zero_cync, bit),
        },
        PointPair {
            btc: Some(select_public_btc(&simulated_one_btc, &real_btc, bit)?),
            cync: RistrettoPoint::conditional_select(&simulated_one_cync, &real_cync, bit),
        },
    ];

    Ok((
        witness,
        BitCommitment {
            commitment_btc,
            commitment_cync,
            announcements,
        },
    ))
}

/// Answer the global challenge `e` for one bit.
pub(super) fn respond_bit(witness: &BitWitness, challenge: Challenge) -> Result<JointBitResponse> {
    let bit = witness.bit;
    let real_challenge = challenge.xor(witness.simulated_challenge);
    let (e_btc, e_cync) = real_challenge.scalars()?;

    // s = k + e_real*r on each curve, with each curve's own modulus.
    let real = Responses {
        btc: btc_mul_add(&witness.nonce_btc, &e_btc, &witness.blinding_btc)?,
        cync: witness.nonce_cync + e_cync * witness.blinding_cync,
    };
    let simulated = Responses {
        btc: BtcScalar::from(witness.simulated_btc),
        cync: witness.simulated_cync,
    };

    Ok(JointBitResponse {
        zero_challenge: Challenge::select(real_challenge, witness.simulated_challenge, bit),
        zero: Responses::select(&real, &simulated, bit)?,
        one: Responses::select(&simulated, &real, bit)?,
    })
}

// ─── secp256k1 helpers ───────────────────────────────────────────────

/// `base + factor * witness (mod n)`. `factor` is public; `base` and
/// `witness` are secret and stay in libsecp256k1's constant-time scalar code.
pub(super) fn btc_mul_add(
    base: &SecretKey,
    factor: &BtcScalar,
    witness: &SecretKey,
) -> Result<BtcScalar> {
    if *factor == BtcScalar::ZERO {
        return Ok(BtcScalar::from(*base));
    }
    // A nonzero factor times a nonzero witness is nonzero modulo the prime n.
    let product = witness.mul_tweak(factor).map_err(|_| DEGENERATE)?;
    Ok(match base.add_tweak(&BtcScalar::from(product)) {
        Ok(sum) => BtcScalar::from(sum),
        // add_tweak fails only when the sum is zero: a valid response value.
        Err(_) => BtcScalar::ZERO,
    })
}

/// `scalar * point` with a SECRET scalar, via ECDH's constant-time ladder.
pub(super) fn btc_mul_secret(point: &PublicKey, scalar: &SecretKey) -> Result<PublicKey> {
    let mut xy = secp256k1::ecdh::shared_secret_point(point, scalar);
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(&xy);
    xy.zeroize();
    let product = PublicKey::from_slice(&uncompressed).map_err(|_| DEGENERATE);
    uncompressed.zeroize();
    product
}

/// The secp256k1 base point `G`.
pub(super) fn btc_generator(secp: &Secp256k1<All>) -> Result<PublicKey> {
    let one = SecretKey::from_slice(&BtcScalar::ONE.to_be_bytes())
        .map_err(|_| Error::Verification("joint-bit basepoint scalar invalid"))?;
    Ok(PublicKey::from_secret_key(secp, &one))
}

/// Select a point that will be published verbatim in the proof/transcript.
/// Only the byte selection is constant time; SEC1 parsing is variable time.
/// Never use this for a secret intermediate such as the simulated branch's
/// statement: publishing both candidates does not make their selection public.
fn select_public_btc(a: &PublicKey, b: &PublicKey, choice: Choice) -> Result<PublicKey> {
    let selected = select_bytes(&a.serialize(), &b.serialize(), choice);
    PublicKey::from_slice(&selected).map_err(|_| DEGENERATE)
}

fn select_bytes<const N: usize>(a: &[u8; N], b: &[u8; N], choice: Choice) -> [u8; N] {
    let mut out = [0u8; N];
    for ((slot, a), b) in out.iter_mut().zip(a).zip(b) {
        *slot = u8::conditional_select(a, b, choice);
    }
    out
}

// Public-input arithmetic only. These helpers branch on scalars/points and
// MUST NOT be reused for secret prover nonces or blinding witnesses. The
// transcript encoding distinguishes identity from a compressed SEC1 point.
pub(super) fn btc_mul(
    secp: &Secp256k1<All>,
    point: Option<PublicKey>,
    scalar: &BtcScalar,
) -> Result<Option<PublicKey>> {
    match point {
        None => Ok(None),
        Some(_) if *scalar == BtcScalar::ZERO => Ok(None),
        Some(point) => point
            .mul_tweak(secp, scalar)
            .map(Some)
            .map_err(|_| Error::Verification("joint-bit public scalar multiplication failed")),
    }
}

pub(super) fn btc_add(
    secp: &Secp256k1<All>,
    lhs: Option<PublicKey>,
    rhs: Option<PublicKey>,
) -> Result<Option<PublicKey>> {
    match (lhs, rhs) {
        (point, None) | (None, point) => Ok(point),
        (Some(lhs), Some(rhs)) if lhs == rhs.negate(secp) => Ok(None),
        (Some(lhs), Some(rhs)) => lhs
            .combine(&rhs)
            .map(Some)
            .map_err(|_| Error::Verification("joint-bit public point addition failed")),
    }
}

pub(super) fn btc_sub(
    secp: &Secp256k1<All>,
    lhs: Option<PublicKey>,
    rhs: Option<PublicKey>,
) -> Result<Option<PublicKey>> {
    btc_add(secp, lhs, rhs.map(|point| point.negate(secp)))
}

#[cfg(test)]
mod tests;
