//! Fiat-Shamir challenge for the complete composed proof.
//!
//! ONE challenge covers all 252 bit proofs and both link proofs. Prover and
//! verifier call [`derive_challenge`] with the same arguments: every input is
//! either the locally constructed statement, a fixed generator, or proof
//! data. Every field is fixed-width and the counts are fixed, so the encoding
//! is unambiguous without length prefixes.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as RistrettoScalar;
use secp256k1::{PublicKey, Scalar as BtcScalar};
use sha2::{Digest, Sha256};

use super::generators::Generators;
use super::joint_bit::{Challenge, PointPair};
use super::{BIT_COUNT, PROOF_VERSION};
use crate::{Error, Result};

const CHALLENGE_DOMAIN: &[u8] = b"CoinCync/Swap/CrossCurveDLEQ-v2/challenge";

/// Public proof data absorbed before the challenge, in wire order.
pub(super) struct TranscriptInput<'a> {
    /// `CrossCurveStatement::commitment`: domain, context, both public keys.
    pub(super) statement: &'a [u8; 32],
    pub(super) blinding_sum_btc: &'a BtcScalar,
    pub(super) blinding_sum_cync: &'a RistrettoScalar,
    /// Bit commitments `C_i = r_i*G + b_i*2^i*H`, one pair per bit.
    pub(super) commitments: &'a [(PublicKey, RistrettoPoint)],
    /// Reconstructed (verifier) or chosen (prover) OR announcements:
    /// `[zero branch, one branch]` per bit.
    pub(super) bit_announcements: &'a [[PointPair; 2]],
    /// Link announcements on base `G` and on base `H`.
    pub(super) link_announcements: &'a [PointPair; 2],
}

pub(super) fn derive_challenge(
    generators: &Generators,
    input: &TranscriptInput<'_>,
) -> Result<Challenge> {
    if input.commitments.len() != BIT_COUNT || input.bit_announcements.len() != BIT_COUNT {
        return Err(Error::Verification(
            "cross-curve transcript has the wrong number of bits",
        ));
    }
    let bit_count =
        u16::try_from(BIT_COUNT).map_err(|_| Error::Verification("bit count overflow"))?;

    let mut hash = Sha256::new();
    hash.update(CHALLENGE_DOMAIN);
    hash.update([PROOF_VERSION]);
    hash.update(bit_count.to_le_bytes());
    hash.update(input.statement);
    hash.update(generators.h_btc.serialize());
    hash.update(generators.h_cync.compress().as_bytes());
    hash.update(input.blinding_sum_btc.to_be_bytes());
    hash.update(input.blinding_sum_cync.as_bytes());
    for (btc, cync) in input.commitments {
        hash.update(btc.serialize());
        hash.update(cync.compress().as_bytes());
    }
    for announcements in input.bit_announcements {
        for pair in announcements {
            absorb_pair(&mut hash, pair);
        }
    }
    for pair in input.link_announcements {
        absorb_pair(&mut hash, pair);
    }

    let digest = hash.finalize();
    let mut challenge = [0u8; 31];
    challenge.copy_from_slice(&digest[..31]);
    Ok(Challenge(challenge))
}

fn absorb_pair(hash: &mut Sha256, pair: &PointPair) {
    hash.update(encode_btc_point(pair.btc.as_ref()));
    hash.update(pair.cync.compress().as_bytes());
}

/// SEC1 compressed encoding, or 33 zero bytes for the identity. A compressed
/// point always starts with 0x02 or 0x03, so the two cannot collide. Honest
/// announcements are never the identity; forged ones may be, and must hash
/// deterministically instead of aborting verification with a parse error.
fn encode_btc_point(point: Option<&PublicKey>) -> [u8; 33] {
    point.map_or([0u8; 33], PublicKey::serialize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_curve_dleq::generators::generators;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use secp256k1::{Secp256k1, SecretKey};

    fn sample_point(value: u8) -> (PublicKey, RistrettoPoint) {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        let secret = SecretKey::from_slice(&bytes).unwrap();
        (
            PublicKey::from_secret_key(&Secp256k1::new(), &secret),
            RistrettoScalar::from(value) * RISTRETTO_BASEPOINT_POINT,
        )
    }

    fn pair(value: u8) -> PointPair {
        let (btc, cync) = sample_point(value);
        PointPair {
            btc: Some(btc),
            cync,
        }
    }

    #[test]
    fn identity_and_each_field_change_the_challenge() {
        let generators = generators();
        let statement = [7u8; 32];
        let commitments = vec![sample_point(3); BIT_COUNT];
        let announcements = vec![[pair(5), pair(6)]; BIT_COUNT];
        let link = [pair(8), pair(9)];
        let base = TranscriptInput {
            statement: &statement,
            blinding_sum_btc: &BtcScalar::ONE,
            blinding_sum_cync: &RistrettoScalar::ONE,
            commitments: &commitments,
            bit_announcements: &announcements,
            link_announcements: &link,
        };
        let original = derive_challenge(generators, &base).unwrap();
        assert_eq!(original, derive_challenge(generators, &base).unwrap());

        let other_statement = [8u8; 32];
        let changed = TranscriptInput {
            statement: &other_statement,
            ..base
        };
        assert_ne!(original, derive_challenge(generators, &changed).unwrap());

        let mut identity_announcements = announcements.clone();
        identity_announcements[BIT_COUNT - 1][1].btc = None;
        let changed = TranscriptInput {
            bit_announcements: &identity_announcements,
            ..base
        };
        assert_ne!(original, derive_challenge(generators, &changed).unwrap());

        let other_link = [pair(8), pair(10)];
        let changed = TranscriptInput {
            link_announcements: &other_link,
            ..base
        };
        assert_ne!(original, derive_challenge(generators, &changed).unwrap());

        let changed = TranscriptInput {
            blinding_sum_btc: &BtcScalar::ZERO,
            ..base
        };
        assert_ne!(original, derive_challenge(generators, &changed).unwrap());
    }

    #[test]
    fn wrong_bit_counts_are_rejected() {
        let generators = generators();
        let statement = [0u8; 32];
        let commitments = vec![sample_point(3); BIT_COUNT - 1];
        let announcements = vec![[pair(5), pair(6)]; BIT_COUNT];
        let link = [pair(8), pair(9)];
        let input = TranscriptInput {
            statement: &statement,
            blinding_sum_btc: &BtcScalar::ONE,
            blinding_sum_cync: &RistrettoScalar::ONE,
            commitments: &commitments,
            bit_announcements: &announcements,
            link_announcements: &link,
        };
        assert!(derive_challenge(generators, &input).is_err());
    }
}
