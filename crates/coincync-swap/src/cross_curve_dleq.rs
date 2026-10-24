//! Cross-curve discrete-log equality: secp256k1 + Ristretto255.
//!
//! Proves knowledge of ONE integer `0 < t < 2^252` with `T_btc = t*G_btc` and
//! `T_cync = t*G_cync`, without revealing `t`. This is the only cross-curve
//! proof in the crate. It replaces the v1 "fast" proof (one nonce shared by
//! both curves, responses reduced separately mod n and mod l: a single proof
//! let anyone recover `t` with CRT plus a 2-D lattice) and the v1 "strict"
//! proof (independent per-curve bit proofs that never tied the curves to the
//! same bits, and that embedded the fast proof).
//!
//! Design reference: `sigma_fun`'s cross-curve Sigma composition:
//! <https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/sigma_fun/src/ext/dl_secp256k1_ed25519_eq.rs>.
//! That implementation uses Edwards points; this one uses Ristretto points
//! throughout (prime order, so no torsion check). The two point encodings are
//! not interchangeable. This reference is a design starting point, not an
//! audit of this implementation.
//!
//! ## Statement and proof
//!
//! Fixed NUMS generators `H_btc`, `H_cync`; bit weights `W_i = 2^i * H`.
//! For `i = 0..252` the prover commits on both curves with independent
//! blindings: `C_i = r_i*G + b_i*W_i`, and publishes the blinding sums
//! `R = sum r_i` (one per curve). One Sigma protocol, made non-interactive
//! with ONE Fiat-Shamir challenge `e` (248 bits, a common integer below both
//! group orders), proves:
//!
//! 1. Per bit, `(C_btc, C_cync)` both commit to 0 OR both commit to 1
//!    (`joint_bit`: an OR of ANDs, sharing each branch challenge between
//!    the curves).
//! 2. Per curve, `log_G(T) = log_H(U)` with `U = sum C_i - R*G = t*H`
//!    (Chaum-Pedersen with an independent nonce per curve).
//!
//! Extraction yields bits `b_i` common to both curves, so `t = sum b_i 2^i`
//! is the same integer `< 2^252` on both; part 2 then forces
//! `T = t*G` on each curve unless `log_G(H)` is known.
//!
//! No nonce, blinding, or response is shared between curves. Each curve's
//! responses are reduced only modulo that curve's own order, from fresh
//! uniform nonces, so the two never combine into a CRT relation.
//!
//! ## Wire format (v2, fixed length [`CrossCurveProof::ENCODED_LEN`])
//!
//! ```text
//! version         u8 = 2
//! challenge       31 bytes, big-endian integer
//! R_btc           32 bytes, big-endian scalar (may be zero)
//! R_cync          32 bytes, little-endian canonical scalar
//! 252 x bit record, i = 0..252:
//!   C_btc         33 bytes, SEC1 compressed
//!   C_cync        32 bytes, compressed Ristretto
//!   e0            31 bytes, branch-0 challenge (e1 = e XOR e0)
//!   s0_btc s0_cync s1_btc s1_cync   4 x 32 bytes
//! z_btc           32 bytes, link response, big-endian
//! z_cync          32 bytes, link response, little-endian
//! ```
//!
//! Parsing rejects any other length or version, noncanonical scalars, and
//! invalid points; the verifier recomputes every announcement and compares
//! the challenge in constant time.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as RistrettoScalar;
use curve25519_dalek::traits::IsIdentity;
use rand::{CryptoRng, RngCore};
use secp256k1::{PublicKey, Scalar as BtcScalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::adaptor::AdaptorSecret;
use crate::{Error, Result};

mod generators;
mod joint_bit;
mod transcript;

use generators::generators;
use joint_bit::{
    btc_add, btc_generator, btc_mul, btc_mul_add, btc_mul_secret, btc_sub, commit_bit,
    respond_bit, Challenge, JointBitResponse, JointBitStatement, PointPair, Responses,
};
use transcript::{derive_challenge, TranscriptInput};

/// Number of committed bits. `2^252` is below both group orders, so a
/// 252-bit integer has the same value, and the same bits, on both curves.
pub const BIT_COUNT: usize = 252;

/// Wire-format and transcript version. v1 (the fast and strict proofs) is
/// not accepted under any encoding.
pub const PROOF_VERSION: u8 = 2;

const STATEMENT_DOMAIN: &[u8] = b"CoinCync/Swap/CrossCurveDLEQ-v2/statement";

const CHALLENGE_LEN: usize = 31;
const BIT_RECORD_LEN: usize = 33 + 32 + CHALLENGE_LEN + 4 * 32;

/// Validated public keys and a commitment to the caller's session context.
///
/// Construction checks point encodings, not equality of discrete logarithms.
/// Private fields ensure prove and verify consume the same validated statement.
/// There is deliberately no serde/Default path bypassing these checks.
pub struct CrossCurveStatement {
    btc_point: PublicKey,
    cync_point: RistrettoPoint,
    commitment: [u8; 32],
}

impl CrossCurveStatement {
    /// Construct from locally expected public keys and session context.
    ///
    /// The caller must encode the network, session identifier, and agreed swap
    /// parameters unambiguously in `context`. Do not take the expected context
    /// from the untrusted proof. Empty context is permitted for isolated tests;
    /// it does not provide session separation.
    pub fn new(btc_pub: &[u8; 33], cync_pub: &[u8; 32], context: &[u8]) -> Result<Self> {
        let (btc_point, cync_point) = parse_public_keys(btc_pub, cync_pub)?;
        let context_len = u64::try_from(context.len())
            .map_err(|_| Error::Verification("cross-curve context is too large"))?;

        // Fixed domain, LE u64 context length, exact context bytes, then the
        // two canonical fixed-width point encodings in BTC/CYNC order. No
        // implicit string conversion, delimiter, or field reduction is used.
        let mut hash = Sha256::new();
        hash.update(STATEMENT_DOMAIN);
        hash.update(context_len.to_le_bytes());
        hash.update(context);
        hash.update(btc_point.serialize());
        hash.update(cync_point.compress().to_bytes());
        Ok(Self {
            btc_point,
            cync_point,
            commitment: hash.finalize().into(),
        })
    }

    /// Public statement digest. Absorbed first into the proof transcript, so a
    /// proof made for other keys or another context fails to verify. It is
    /// neither a proof nor a challenge.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

/// One committed bit: the commitment pair and its OR response.
#[derive(Clone, PartialEq, Eq)]
struct BitProof {
    commitment_btc: PublicKey,
    commitment_cync: RistrettoPoint,
    response: JointBitResponse,
}

/// A v2 cross-curve proof. Construct with [`prove`] or
/// [`CrossCurveProof::from_bytes`]; every instance has canonical fields.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCurveProof {
    challenge: Challenge,
    blinding_sum_btc: BtcScalar,
    blinding_sum_cync: RistrettoScalar,
    bits: Vec<BitProof>,
    link: Responses,
}

impl core::fmt::Debug for CrossCurveProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CrossCurveProof")
            .field("version", &PROOF_VERSION)
            .field("challenge", &hex::encode(self.challenge.0))
            .field("bits", &self.bits.len())
            .finish_non_exhaustive()
    }
}

impl CrossCurveProof {
    /// Exact length of the v2 encoding (56,608 bytes).
    pub const ENCODED_LEN: usize =
        1 + CHALLENGE_LEN + 32 + 32 + BIT_COUNT * BIT_RECORD_LEN + 32 + 32;

    /// Canonical v2 encoding; see the module docs for the layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.push(PROOF_VERSION);
        out.extend_from_slice(&self.challenge.0);
        out.extend_from_slice(&self.blinding_sum_btc.to_be_bytes());
        out.extend_from_slice(self.blinding_sum_cync.as_bytes());
        for bit in &self.bits {
            out.extend_from_slice(&bit.commitment_btc.serialize());
            out.extend_from_slice(bit.commitment_cync.compress().as_bytes());
            out.extend_from_slice(&bit.response.zero_challenge.0);
            let (s0_btc, s0_cync) = bit.response.zero.to_bytes();
            let (s1_btc, s1_cync) = bit.response.one.to_bytes();
            out.extend_from_slice(&s0_btc);
            out.extend_from_slice(&s0_cync);
            out.extend_from_slice(&s1_btc);
            out.extend_from_slice(&s1_cync);
        }
        let (z_btc, z_cync) = self.link.to_bytes();
        out.extend_from_slice(&z_btc);
        out.extend_from_slice(&z_cync);
        debug_assert_eq!(out.len(), Self::ENCODED_LEN);
        out
    }

    /// Strict v2 decoding. Rejects wrong length or version, noncanonical
    /// scalars, invalid or identity points. Decoding is not verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(Error::Verification(
                "cross-curve proof has the wrong length",
            ));
        }
        let mut reader = Reader { bytes };
        if reader.take::<1>()? != [PROOF_VERSION] {
            return Err(Error::Verification(
                "cross-curve proof has an unsupported version",
            ));
        }
        let challenge = Challenge(reader.take::<CHALLENGE_LEN>()?);
        let blinding_sum_btc = BtcScalar::from_be_bytes(reader.take::<32>()?)
            .map_err(|_| Error::Verification("cross-curve blinding sum is not canonical"))?;
        let blinding_sum_cync = Option::<RistrettoScalar>::from(
            RistrettoScalar::from_canonical_bytes(reader.take::<32>()?),
        )
        .ok_or(Error::Verification("cross-curve blinding sum is not canonical"))?;

        let mut bits = Vec::with_capacity(BIT_COUNT);
        for _ in 0..BIT_COUNT {
            let commitment_btc = PublicKey::from_slice(&reader.take::<33>()?)
                .map_err(|_| Error::Verification("cross-curve BTC commitment is invalid"))?;
            let commitment_cync = CompressedRistretto(reader.take::<32>()?)
                .decompress()
                .ok_or(Error::Verification("cross-curve CYNC commitment is invalid"))?;
            if commitment_cync.is_identity() {
                return Err(Error::Verification(
                    "cross-curve CYNC commitment is identity",
                ));
            }
            let zero_challenge = Challenge(reader.take::<CHALLENGE_LEN>()?);
            let zero = Responses::from_bytes(reader.take::<32>()?, reader.take::<32>()?)?;
            let one = Responses::from_bytes(reader.take::<32>()?, reader.take::<32>()?)?;
            bits.push(BitProof {
                commitment_btc,
                commitment_cync,
                response: JointBitResponse {
                    zero_challenge,
                    zero,
                    one,
                },
            });
        }
        let link = Responses::from_bytes(reader.take::<32>()?, reader.take::<32>()?)?;
        debug_assert!(reader.bytes.is_empty());
        Ok(Self {
            challenge,
            blinding_sum_btc,
            blinding_sum_cync,
            bits,
            link,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.bytes.len() < N {
            return Err(Error::Verification("cross-curve proof is truncated"));
        }
        let (head, tail) = self.bytes.split_at(N);
        self.bytes = tail;
        let mut out = [0u8; N];
        out.copy_from_slice(head);
        Ok(out)
    }
}

/// Prove the same bounded secret under both public keys.
///
/// All randomness comes from `rng`, independently per curve; there is no
/// caller-supplied nonce. Rejects secrets outside `0 < t < 2^252` and keys
/// inconsistent with the secret. Public keys were already validated by
/// `CrossCurveStatement::new`.
pub fn prove(
    secret: &AdaptorSecret,
    statement: &CrossCurveStatement,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CrossCurveProof> {
    let mut witness = validate_witness(secret, &statement.btc_point, &statement.cync_point)?;
    let result = prove_with_witness(&witness, statement, rng);
    witness.erase();
    result
}

fn prove_with_witness(
    witness: &Witness,
    statement: &CrossCurveStatement,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CrossCurveProof> {
    let secp = Secp256k1::new();
    let generators = generators();
    let mut bits = witness.bits();

    // Announcement phase: commit every bit on both curves.
    let mut bit_witnesses = Vec::with_capacity(BIT_COUNT);
    let mut commitments = Vec::with_capacity(BIT_COUNT);
    let mut bit_announcements = Vec::with_capacity(BIT_COUNT);
    for (index, bit) in bits.iter().enumerate() {
        let (btc_weight, cync_weight) = generators.weight(index);
        let (bit_witness, commitment) =
            commit_bit(&secp, Choice::from(*bit), btc_weight, cync_weight, rng)?;
        commitments.push((commitment.commitment_btc, commitment.commitment_cync));
        bit_announcements.push(commitment.announcements);
        bit_witnesses.push(bit_witness);
    }
    bits.zeroize();

    // Blinding sums. Published: U = sum C - R*G = t*H reveals no more about
    // t than T does (DDH), and the link proof needs it.
    let blinding_sum_btc = btc_secret_sum(bit_witnesses.iter().map(|w| w.blinding_btc()));
    let blinding_sum_cync: RistrettoScalar = bit_witnesses.iter().map(|w| w.blinding_cync()).sum();

    // Link announcements, independent nonce per curve.
    let mut link_nonce_btc = SecretKey::new(rng);
    let mut link_nonce_cync = RistrettoScalar::random(rng);
    let link_announcements = [
        PointPair {
            btc: Some(PublicKey::from_secret_key(&secp, &link_nonce_btc)),
            cync: &link_nonce_cync * RISTRETTO_BASEPOINT_TABLE,
        },
        PointPair {
            btc: Some(btc_mul_secret(&generators.h_btc, &link_nonce_btc)?),
            cync: link_nonce_cync * generators.h_cync,
        },
    ];

    let challenge = derive_challenge(
        generators,
        &TranscriptInput {
            statement: &statement.commitment,
            blinding_sum_btc: &blinding_sum_btc,
            blinding_sum_cync: &blinding_sum_cync,
            commitments: &commitments,
            bit_announcements: &bit_announcements,
            link_announcements: &link_announcements,
        },
    )?;

    // Response phase.
    let (e_btc, e_cync) = challenge.scalars()?;
    let link = Responses {
        btc: btc_mul_add(&link_nonce_btc, &e_btc, &witness.btc)?,
        cync: link_nonce_cync + e_cync * witness.cync,
    };
    link_nonce_btc.non_secure_erase();
    link_nonce_cync.zeroize();

    let bits = bit_witnesses
        .iter()
        .zip(commitments)
        .map(|(bit_witness, (commitment_btc, commitment_cync))| {
            Ok(BitProof {
                commitment_btc,
                commitment_cync,
                response: respond_bit(bit_witness, challenge)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CrossCurveProof {
        challenge,
        blinding_sum_btc,
        blinding_sum_cync,
        bits,
        link,
    })
}

/// Verify against the caller's expected public keys and session context.
///
/// Uses only public data: the statement built locally from the expected keys
/// and context, the fixed generators, and the proof. Accepts only if the
/// recomputed Fiat-Shamir challenge equals the proof's challenge.
pub fn verify(proof: &CrossCurveProof, statement: &CrossCurveStatement) -> Result<()> {
    if proof.bits.len() != BIT_COUNT {
        return Err(Error::Verification(
            "cross-curve proof has the wrong number of bits",
        ));
    }
    let secp = Secp256k1::new();
    let generators = generators();

    let mut commitments = Vec::with_capacity(BIT_COUNT);
    let mut bit_announcements = Vec::with_capacity(BIT_COUNT);
    let mut sum_btc = None;
    let mut sum_cync = RistrettoPoint::default();
    for (index, bit) in proof.bits.iter().enumerate() {
        let (btc_weight, cync_weight) = generators.weight(index);
        let joint = JointBitStatement::new(
            &secp,
            bit.commitment_btc,
            bit.commitment_cync,
            *btc_weight,
            *cync_weight,
        )?;
        bit_announcements.push(joint.reconstruct(&secp, proof.challenge, &bit.response)?);
        commitments.push((bit.commitment_btc, bit.commitment_cync));
        sum_btc = btc_add(&secp, sum_btc, Some(bit.commitment_btc))?;
        sum_cync += bit.commitment_cync;
    }

    // U = sum C - R*G, which equals t*H for an honest prover (t != 0).
    let g_btc = btc_generator(&secp)?;
    let unblinded_btc = btc_sub(
        &secp,
        sum_btc,
        btc_mul(&secp, Some(g_btc), &proof.blinding_sum_btc)?,
    )?
    .ok_or(Error::Verification("cross-curve BTC unblinded sum is identity"))?;
    let unblinded_cync = sum_cync - &proof.blinding_sum_cync * RISTRETTO_BASEPOINT_TABLE;
    if unblinded_cync.is_identity() {
        return Err(Error::Verification(
            "cross-curve CYNC unblinded sum is identity",
        ));
    }

    // Link: z*G - e*T and z*H - e*U on each curve.
    let (e_btc, e_cync) = proof.challenge.scalars()?;
    let z_g_btc = btc_mul(&secp, Some(g_btc), &proof.link.btc)?;
    let z_h_btc = btc_mul(&secp, Some(generators.h_btc), &proof.link.btc)?;
    let link_announcements = [
        PointPair {
            btc: btc_sub(
                &secp,
                z_g_btc,
                btc_mul(&secp, Some(statement.btc_point), &e_btc)?,
            )?,
            cync: RistrettoPoint::vartime_double_scalar_mul_basepoint(
                &-e_cync,
                &statement.cync_point,
                &proof.link.cync,
            ),
        },
        PointPair {
            btc: btc_sub(&secp, z_h_btc, btc_mul(&secp, Some(unblinded_btc), &e_btc)?)?,
            cync: proof.link.cync * generators.h_cync - e_cync * unblinded_cync,
        },
    ];

    let expected = derive_challenge(
        generators,
        &TranscriptInput {
            statement: &statement.commitment,
            blinding_sum_btc: &proof.blinding_sum_btc,
            blinding_sum_cync: &proof.blinding_sum_cync,
            commitments: &commitments,
            bit_announcements: &bit_announcements,
            link_announcements: &link_announcements,
        },
    )?;
    if bool::from(expected.0.ct_eq(&proof.challenge.0)) {
        Ok(())
    } else {
        Err(Error::Verification("cross-curve proof does not verify"))
    }
}

/// Parse the expected statement identically for the prover and verifier.
fn parse_public_keys(
    btc_pub: &[u8; 33],
    cync_pub: &[u8; 32],
) -> Result<(PublicKey, RistrettoPoint)> {
    // The 33-byte SEC1 parser accepts compressed curve points and rejects the
    // point at infinity. Do not interpret Ristretto bytes as Edwards points.
    let btc_point = PublicKey::from_slice(btc_pub)
        .map_err(|_| Error::Verification("cross-curve BTC public key is invalid"))?;
    let cync_point = CompressedRistretto(*cync_pub)
        .decompress()
        .ok_or(Error::Verification("cross-curve CYNC public key is invalid"))?;
    if cync_point.is_identity() {
        return Err(Error::Verification(
            "cross-curve CYNC public key must not be identity",
        ));
    }
    Ok((btc_point, cync_point))
}

/// The secret `t` on both curves, already checked against the statement.
struct Witness {
    btc: SecretKey,
    cync: RistrettoScalar,
    le_bytes: [u8; 32],
}

impl Witness {
    /// Little-endian bits `b_0..b_251` of `t`.
    fn bits(&self) -> [u8; BIT_COUNT] {
        let mut bits = [0u8; BIT_COUNT];
        for (index, bit) in bits.iter_mut().enumerate() {
            *bit = (self.le_bytes[index / 8] >> (index % 8)) & 1;
        }
        bits
    }

    fn erase(&mut self) {
        self.btc.non_secure_erase();
        self.cync.zeroize();
        self.le_bytes.zeroize();
    }
}

/// Local consistency check only; the verifier proves the same relation
/// independently. A malicious peer need not use our prover.
fn validate_witness(
    secret: &AdaptorSecret,
    btc_point: &PublicKey,
    cync_point: &RistrettoPoint,
) -> Result<Witness> {
    // The accessor handles either stored byte order. A 252-bit positive integer
    // is below both group orders. Check the integer BEFORE parsing any scalar;
    // never truncate or reduce an out-of-range secret into an accepted witness.
    let mut bytes = secret.ristretto_bytes();
    if bytes[31] & 0xf0 != 0 || bool::from(bytes.ct_eq(&[0u8; 32])) {
        bytes.zeroize();
        return Err(Error::Verification(
            "cross-curve secret must satisfy 0 < t < 2^252",
        ));
    }
    let cync = Option::<RistrettoScalar>::from(RistrettoScalar::from_canonical_bytes(bytes))
        .ok_or(Error::Verification("cross-curve secret is not canonical"))?;
    let btc = SecretKey::from_slice(&secret.secp256k1_bytes())
        .map_err(|_| Error::Verification("cross-curve secret is invalid for BTC"))?;
    let mut witness = Witness {
        btc,
        cync,
        le_bytes: bytes,
    };
    bytes.zeroize();

    let expected_btc = PublicKey::from_secret_key(&Secp256k1::new(), &witness.btc);
    let expected_cync = &witness.cync * RISTRETTO_BASEPOINT_TABLE;
    if &expected_btc != btc_point || &expected_cync != cync_point {
        witness.erase();
        return Err(Error::Verification(
            "cross-curve public keys do not match the supplied secret",
        ));
    }
    Ok(witness)
}

/// `sum r_i (mod n)` for secret blindings; the result is published.
fn btc_secret_sum<'a>(blindings: impl Iterator<Item = &'a SecretKey>) -> BtcScalar {
    // `None` stands for zero, which SecretKey cannot hold.
    let mut acc: Option<SecretKey> = None;
    for blinding in blindings {
        acc = match acc {
            None => Some(*blinding),
            // add_tweak fails only when the running sum is exactly zero.
            Some(sum) => sum.add_tweak(&BtcScalar::from(*blinding)).ok(),
        };
    }
    acc.map_or(BtcScalar::ZERO, BtcScalar::from)
}

#[cfg(test)]
mod tests;
