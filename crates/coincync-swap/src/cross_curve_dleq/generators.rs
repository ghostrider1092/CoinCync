//! Fixed Pedersen generators for the cross-curve proof.
//!
//! `H_btc` and `H_cync` are nothing-up-my-sleeve points derived from public,
//! versioned domain strings. Nobody knows `log_G(H)` on either curve; the
//! binding of every bit commitment and of the final link proof relies on it.
//! The verifier derives these points and the bit weights `W_i = 2^i * H`
//! itself. They are never read from a proof or chosen by a peer.

use std::sync::OnceLock;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as RistrettoScalar;
use secp256k1::{PublicKey, Scalar as BtcScalar, Secp256k1};
use sha2::{Digest, Sha256, Sha512};

use super::BIT_COUNT;

// Frozen with the v2 proof format. A new derivation needs a new version: the
// old points would otherwise keep verifying proofs under a different meaning.
const H_BTC_DOMAIN: &[u8] = b"CoinCync/Swap/CrossCurveDLEQ-v2/H_btc";
const H_CYNC_DOMAIN: &[u8] = b"CoinCync/Swap/CrossCurveDLEQ-v2/H_cync";

/// Generators and the per-bit weights `W_i = 2^i * H`, `i = 0..BIT_COUNT`.
pub(super) struct Generators {
    pub(super) h_btc: PublicKey,
    pub(super) h_cync: RistrettoPoint,
    weights: Vec<(PublicKey, RistrettoPoint)>,
}

impl Generators {
    /// Weights for bit `index` on both curves. `index < BIT_COUNT`.
    pub(super) fn weight(&self, index: usize) -> (&PublicKey, &RistrettoPoint) {
        let (btc, cync) = &self.weights[index];
        (btc, cync)
    }
}

/// Process-wide memoized generators. Derivation is deterministic.
pub(super) fn generators() -> &'static Generators {
    static GENERATORS: OnceLock<Generators> = OnceLock::new();
    GENERATORS.get_or_init(derive)
}

fn derive() -> Generators {
    let secp = Secp256k1::verification_only();
    let h_btc = derive_h_btc();
    let h_cync = derive_h_cync();
    let weights = (0..BIT_COUNT)
        .map(|index| {
            // 2^index < 2^252, below both group orders: a direct encoding,
            // not a reduction, on either curve.
            let mut be = [0u8; 32];
            be[31 - index / 8] = 1 << (index % 8);
            let btc_factor =
                BtcScalar::from_be_bytes(be).expect("2^index is below the secp256k1 order");
            let mut le = be;
            le.reverse();
            let cync_factor = Option::<RistrettoScalar>::from(RistrettoScalar::from_canonical_bytes(
                le,
            ))
            .expect("2^index is below the Ristretto order");
            let btc = h_btc
                .mul_tweak(&secp, &btc_factor)
                .expect("nonzero multiple of a prime-order generator");
            (btc, cync_factor * h_cync)
        })
        .collect();
    Generators {
        h_btc,
        h_cync,
        weights,
    }
}

/// Try-and-increment: the first `x = SHA256(domain || counter_le32)` that is
/// a secp256k1 x-coordinate, lifted to the point with even y (SEC1 prefix 2).
fn derive_h_btc() -> PublicKey {
    for counter in 0u32..=u32::MAX {
        let mut hash = Sha256::new();
        hash.update(H_BTC_DOMAIN);
        hash.update(counter.to_le_bytes());
        let mut encoded = [0u8; 33];
        encoded[0] = 0x02;
        encoded[1..].copy_from_slice(&hash.finalize());
        if let Ok(point) = PublicKey::from_slice(&encoded) {
            return point;
        }
    }
    // About half of all x-coordinates are on the curve.
    unreachable!("no secp256k1 point found for the fixed H_btc domain")
}

/// Elligator-based uniform map of `SHA512(domain)`; prime-order by
/// construction, so no cofactor handling is needed.
fn derive_h_cync() -> RistrettoPoint {
    let digest: [u8; 64] = Sha512::digest(H_CYNC_DOMAIN).into();
    RistrettoPoint::from_uniform_bytes(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::traits::IsIdentity;

    #[test]
    fn generators_are_deterministic_and_distinct_from_base_points() {
        let first = derive();
        let again = generators();
        assert_eq!(first.h_btc, again.h_btc);
        assert_eq!(first.h_cync, again.h_cync);

        let secp = Secp256k1::new();
        let one = secp256k1::SecretKey::from_slice(&BtcScalar::ONE.to_be_bytes()).unwrap();
        assert_ne!(first.h_btc, PublicKey::from_secret_key(&secp, &one));
        assert_ne!(first.h_cync, RISTRETTO_BASEPOINT_POINT);
        assert!(!first.h_cync.is_identity());

        // The derivation is versioned; it must not coincide with the legacy
        // proof's generator domain or with each other's encoding.
        assert_ne!(H_BTC_DOMAIN, H_CYNC_DOMAIN);
    }

    #[test]
    fn weights_double_at_each_index() {
        let generators = generators();
        let (w0_btc, w0_cync) = generators.weight(0);
        assert_eq!(*w0_btc, generators.h_btc);
        assert_eq!(*w0_cync, generators.h_cync);
        for index in 1..BIT_COUNT {
            let (prev_btc, prev_cync) = generators.weight(index - 1);
            let (btc, cync) = generators.weight(index);
            assert_eq!(*btc, prev_btc.combine(prev_btc).unwrap());
            assert_eq!(*cync, prev_cync + prev_cync);
        }
    }
}
