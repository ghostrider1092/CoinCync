//! Full-proof tests. Adversarial cases build proofs without the honest
//! prover; passing them is evidence, not a proof, of soundness or privacy.

use super::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn fixture(bytes: [u8; 32]) -> (AdaptorSecret, [u8; 33], [u8; 32]) {
    let secret = AdaptorSecret::from_ristretto_bytes(bytes).unwrap();
    let btc = secret.public_point().serialize();
    let cync = crate::adaptor::cync_adaptor_point(&secret).unwrap();
    (secret, btc, cync)
}

fn largest_secret() -> [u8; 32] {
    let mut largest = [0xff; 32];
    largest[31] = 0x0f; // 2^252 - 1, strictly below both scalar orders.
    largest
}

fn honest_proof(seed: u64, context: &[u8]) -> (CrossCurveProof, CrossCurveStatement) {
    let (secret, btc, cync) = fixture(RistrettoScalar::from(0x5eed_u64 + seed).to_bytes());
    let statement = CrossCurveStatement::new(&btc, &cync, context).unwrap();
    let proof = prove(&secret, &statement, &mut rng(seed)).unwrap();
    (proof, statement)
}

// ─── Completeness and encoding ───────────────────────────────────────

#[test]
fn boundary_secrets_in_both_byte_orders_prove_and_verify() {
    for bytes in [RistrettoScalar::ONE.to_bytes(), largest_secret()] {
        let (little_endian, btc, cync) = fixture(bytes);
        let mut reversed = bytes;
        reversed.reverse();
        let big_endian = AdaptorSecret::from_secp256k1_bytes(reversed).unwrap();
        let statement = CrossCurveStatement::new(&btc, &cync, b"boundary-session").unwrap();
        for (seed, secret) in [(1, &little_endian), (2, &big_endian)] {
            let proof = prove(secret, &statement, &mut rng(seed)).unwrap();
            verify(&proof, &statement).unwrap();
        }
    }
}

#[test]
fn encoding_round_trips_with_fixed_length_and_version() {
    let (proof, statement) = honest_proof(3, b"encoding");
    let bytes = proof.to_bytes();
    assert_eq!(bytes.len(), CrossCurveProof::ENCODED_LEN);
    assert_eq!(CrossCurveProof::ENCODED_LEN, 56_608);
    assert_eq!(bytes[0], PROOF_VERSION);
    let decoded = CrossCurveProof::from_bytes(&bytes).unwrap();
    assert!(decoded == proof);
    assert_eq!(decoded.to_bytes(), bytes);
    verify(&decoded, &statement).unwrap();
}

#[test]
fn proofs_are_randomized_and_reproducible_only_from_the_same_rng() {
    let (secret, btc, cync) = fixture(RistrettoScalar::from(77u64).to_bytes());
    let statement = CrossCurveStatement::new(&btc, &cync, b"rng").unwrap();
    let first = prove(&secret, &statement, &mut rng(9)).unwrap();
    let again = prove(&secret, &statement, &mut rng(9)).unwrap();
    let other = prove(&secret, &statement, &mut rng(10)).unwrap();
    assert!(first == again);
    assert!(first != other);
    assert_ne!(first.challenge, other.challenge);
}

// ─── Prover input checks ─────────────────────────────────────────────

#[test]
fn zero_and_out_of_range_secrets_are_rejected_without_reduction() {
    let (_, btc, cync) = fixture(RistrettoScalar::ONE.to_bytes());
    let statement = CrossCurveStatement::new(&btc, &cync, b"range-session").unwrap();
    let zero = AdaptorSecret::from_ristretto_bytes([0; 32]).unwrap();
    let mut limit = [0; 32];
    limit[0] = 0x10; // Big-endian 2^252, still canonical on both curves.
    let at_limit = AdaptorSecret::from_secp256k1_bytes(limit).unwrap();
    let mut large = [0; 32];
    large[0] = 0x20; // 2^253: valid on secp256k1, not on Ristretto.
    let above_ristretto = AdaptorSecret::from_secp256k1_bytes(large).unwrap();
    for secret in [&zero, &at_limit, &above_ristretto] {
        assert!(matches!(
            prove(secret, &statement, &mut rng(0)),
            Err(Error::Verification(
                "cross-curve secret must satisfy 0 < t < 2^252"
            ))
        ));
    }
}

#[test]
fn prover_rejects_each_mismatched_public_key() {
    let (secret, btc, cync) = fixture(RistrettoScalar::from(7u64).to_bytes());
    let (_, other_btc, other_cync) = fixture(RistrettoScalar::from(11u64).to_bytes());
    for (btc_key, cync_key) in [(other_btc, cync), (btc, other_cync)] {
        // Each point is valid: this must fail witness consistency, not parsing.
        let statement = CrossCurveStatement::new(&btc_key, &cync_key, b"swap").unwrap();
        assert!(matches!(
            prove(&secret, &statement, &mut rng(0)),
            Err(Error::Verification(
                "cross-curve public keys do not match the supplied secret"
            ))
        ));
    }
}

#[test]
fn statement_rejects_invalid_encodings_and_identity() {
    let (_, btc, cync) = fixture(RistrettoScalar::ONE.to_bytes());
    assert!(matches!(
        CrossCurveStatement::new(&[0; 33], &cync, b"swap"),
        Err(Error::Verification("cross-curve BTC public key is invalid"))
    ));
    assert!(matches!(
        CrossCurveStatement::new(&btc, &[0xff; 32], b"swap"),
        Err(Error::Verification("cross-curve CYNC public key is invalid"))
    ));
    // Ristretto's identity has a valid encoding, but is not a valid swap key.
    assert!(matches!(
        CrossCurveStatement::new(&btc, &[0; 32], b"swap"),
        Err(Error::Verification(
            "cross-curve CYNC public key must not be identity"
        ))
    ));
}

#[test]
fn statement_commitment_binds_both_keys_and_exact_context_bytes() {
    let (_, btc, cync) = fixture(RistrettoScalar::from(7u64).to_bytes());
    let (_, other_btc, other_cync) = fixture(RistrettoScalar::from(11u64).to_bytes());
    let digest = |b: &[u8; 33], c: &[u8; 32], context: &[u8]| {
        CrossCurveStatement::new(b, c, context).unwrap().commitment()
    };
    let original = digest(&btc, &cync, b"swap\0a");
    assert_eq!(original, digest(&btc, &cync, b"swap\0a"));
    assert_ne!(original, digest(&other_btc, &cync, b"swap\0a"));
    assert_ne!(original, digest(&btc, &other_cync, b"swap\0a"));
    assert_ne!(original, digest(&btc, &cync, b"swap\0b"));
    assert_ne!(original, digest(&btc, &cync, b"swap\0a\0"));
    assert_ne!(original, digest(&btc, &cync, b""));
}

// ─── Verifier: substituted statement ─────────────────────────────────

#[test]
fn proof_is_bound_to_context_and_to_each_public_key() {
    let (secret, btc, cync) = fixture(RistrettoScalar::from(7u64).to_bytes());
    let (_, other_btc, other_cync) = fixture(RistrettoScalar::from(11u64).to_bytes());
    let statement = CrossCurveStatement::new(&btc, &cync, b"session-a").unwrap();
    let proof = prove(&secret, &statement, &mut rng(4)).unwrap();
    verify(&proof, &statement).unwrap();
    for (b, c, context) in [
        (btc, cync, &b"session-b"[..]),
        (other_btc, cync, &b"session-a"[..]),
        (btc, other_cync, &b"session-a"[..]),
        (other_btc, other_cync, &b"session-a"[..]),
    ] {
        let substituted = CrossCurveStatement::new(&b, &c, context).unwrap();
        assert!(verify(&proof, &substituted).is_err());
    }
}

// ─── Verifier: malformed and tampered encodings ──────────────────────

#[test]
fn wrong_length_version_and_legacy_proofs_are_rejected() {
    let (proof, _) = honest_proof(5, b"format");
    let bytes = proof.to_bytes();
    assert!(CrossCurveProof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(CrossCurveProof::from_bytes(&longer).is_err());
    assert!(CrossCurveProof::from_bytes(&[]).is_err());
    // The v1 fast proof was 129 bytes; any v1 encoding fails on length.
    assert!(CrossCurveProof::from_bytes(&[0u8; 129]).is_err());
    for version in [0u8, 1, 3, 0xff] {
        let mut wrong = bytes.clone();
        wrong[0] = version;
        assert!(matches!(
            CrossCurveProof::from_bytes(&wrong),
            Err(Error::Verification(
                "cross-curve proof has an unsupported version"
            ))
        ));
    }
}

#[test]
fn noncanonical_scalars_and_invalid_points_are_rejected_at_decode() {
    let (proof, _) = honest_proof(6, b"decode");
    let bytes = proof.to_bytes();
    let first_bit = 1 + CHALLENGE_LEN + 64;
    let link = CrossCurveProof::ENCODED_LEN - 64;
    for (offset, len, fill) in [
        (1 + CHALLENGE_LEN, 32, 0xff),      // R_btc >= n
        (1 + CHALLENGE_LEN + 32, 32, 0xff), // R_cync >= l
        (first_bit, 33, 0x00),              // C_btc: not a SEC1 point
        (first_bit + 33, 32, 0xff),         // C_cync: not a Ristretto encoding
        (first_bit + 33, 32, 0x00),         // C_cync: identity
        (first_bit + 96, 32, 0xff),         // s0_btc >= n
        (first_bit + 128, 32, 0xff),        // s0_cync >= l
        (link, 32, 0xff),                   // z_btc >= n
        (link + 32, 32, 0xff),              // z_cync >= l
    ] {
        let mut corrupted = bytes.clone();
        corrupted[offset..offset + len].fill(fill);
        assert!(
            CrossCurveProof::from_bytes(&corrupted).is_err(),
            "offset {offset} decoded"
        );
    }
}

#[test]
fn every_tampered_region_fails_decode_or_verification() {
    let (proof, statement) = honest_proof(7, b"tamper");
    let bytes = proof.to_bytes();
    let first_bit = 1 + CHALLENGE_LEN + 64;
    let last_bit = first_bit + (BIT_COUNT - 1) * BIT_RECORD_LEN;
    let link = CrossCurveProof::ENCODED_LEN - 64;
    // Low bytes keep scalars canonical, so verification itself must reject.
    for offset in [
        1,                               // challenge
        1 + CHALLENGE_LEN + 31,          // R_btc (big-endian low byte)
        1 + CHALLENGE_LEN + 32,          // R_cync (little-endian low byte)
        first_bit + 32,                  // C_btc
        last_bit + 33,                   // C_cync of bit 251
        first_bit + 33 + 32 + 30,        // e0
        first_bit + 96 + 31,             // s0_btc
        last_bit + 96 + 32,              // s0_cync
        last_bit + 96 + 64 + 31,         // s1_btc
        first_bit + 96 + 96,             // s1_cync
        link + 31,                       // z_btc
        link + 32,                       // z_cync
    ] {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 0x01;
        if let Ok(decoded) = CrossCurveProof::from_bytes(&tampered) {
            assert!(
                verify(&decoded, &statement).is_err(),
                "tampered offset {offset} still verifies"
            );
        }
    }
}

#[test]
fn swapping_bit_records_or_mixing_two_proofs_fails() {
    let (proof, statement) = honest_proof(8, b"mix");
    let (other, _) = honest_proof(9, b"mix");

    let mut swapped = proof.clone();
    swapped.bits.swap(0, 1);
    assert!(verify(&swapped, &statement).is_err());

    let mut spliced = proof.clone();
    spliced.bits[100] = other.bits[100].clone();
    assert!(verify(&spliced, &statement).is_err());

    let mut relinked = proof.clone();
    relinked.link = other.link.clone();
    assert!(verify(&relinked, &statement).is_err());

    let mut truncated = proof;
    truncated.bits.pop();
    assert!(verify(&truncated, &statement).is_err());
}

// ─── Soundness: different secrets on the two curves ──────────────────

/// A cheating prover with `t_btc` on secp256k1 and `t_cync` on Ristretto.
/// It commits to each curve's own bits and runs an honest link proof per
/// curve. Where the bits agree it answers honestly; where they differ no
/// joint branch can be opened on both curves, so it fixes both branch
/// challenges in advance (the best possible strategy). With equal secrets
/// this builds a valid proof, which checks the forger itself.
fn forge_with_per_curve_secrets(
    t_btc: [u8; 32],
    t_cync: [u8; 32],
    statement: &CrossCurveStatement,
    rng: &mut StdRng,
) -> CrossCurveProof {
    let secp = Secp256k1::new();
    let generators = generators();
    let bit_of = |le: &[u8; 32], index: usize| (le[index / 8] >> (index % 8)) & 1;
    let t_btc_sk = {
        let mut be = t_btc;
        be.reverse();
        SecretKey::from_slice(&be).unwrap()
    };
    let t_cync_scalar = RistrettoScalar::from_canonical_bytes(t_cync).unwrap();

    let mut commitments = Vec::new();
    let mut announcements = Vec::new();
    let mut honest = Vec::new();
    let mut forged = Vec::new();
    let mut blinding_btc = Vec::new();
    let mut blinding_cync = RistrettoScalar::ZERO;
    for index in 0..BIT_COUNT {
        let (w_btc, w_cync) = generators.weight(index);
        let (b_btc, b_cync) = (bit_of(&t_btc, index), bit_of(&t_cync, index));
        if b_btc == b_cync {
            let (witness, commitment) =
                commit_bit(&secp, Choice::from(b_btc), w_btc, w_cync, rng).unwrap();
            blinding_btc.push(*witness.blinding_btc());
            blinding_cync += witness.blinding_cync();
            commitments.push((commitment.commitment_btc, commitment.commitment_cync));
            announcements.push(commitment.announcements);
            honest.push(Some(witness));
            forged.push(None);
        } else {
            let r_btc = SecretKey::new(rng);
            let r_cync = RistrettoScalar::random(rng);
            let mut c_btc = PublicKey::from_secret_key(&secp, &r_btc);
            if b_btc == 1 {
                c_btc = c_btc.combine(w_btc).unwrap();
            }
            let mut c_cync = &r_cync * RISTRETTO_BASEPOINT_TABLE;
            if b_cync == 1 {
                c_cync += w_cync;
            }
            let joint = JointBitStatement::new(&secp, c_btc, c_cync, *w_btc, *w_cync).unwrap();
            let mut guess = [0u8; CHALLENGE_LEN];
            let mut zero = [0u8; CHALLENGE_LEN];
            rng.fill_bytes(&mut guess);
            rng.fill_bytes(&mut zero);
            let response = JointBitResponse {
                zero_challenge: Challenge(zero),
                zero: Responses {
                    btc: BtcScalar::from(SecretKey::new(rng)),
                    cync: RistrettoScalar::random(rng),
                },
                one: Responses {
                    btc: BtcScalar::from(SecretKey::new(rng)),
                    cync: RistrettoScalar::random(rng),
                },
            };
            blinding_btc.push(r_btc);
            blinding_cync += r_cync;
            commitments.push((c_btc, c_cync));
            announcements.push(
                joint
                    .reconstruct(&secp, Challenge(guess), &response)
                    .unwrap(),
            );
            honest.push(None);
            forged.push(Some(response));
        }
    }
    let blinding_sum_btc = btc_secret_sum(blinding_btc.iter());

    // Honest Chaum-Pedersen per curve with that curve's own secret.
    let k_btc = SecretKey::new(rng);
    let k_cync = RistrettoScalar::random(rng);
    let link_announcements = [
        PointPair {
            btc: Some(PublicKey::from_secret_key(&secp, &k_btc)),
            cync: &k_cync * RISTRETTO_BASEPOINT_TABLE,
        },
        PointPair {
            btc: Some(btc_mul_secret(&generators.h_btc, &k_btc).unwrap()),
            cync: k_cync * generators.h_cync,
        },
    ];
    let challenge = derive_challenge(
        generators,
        &TranscriptInput {
            statement: &statement.commitment(),
            blinding_sum_btc: &blinding_sum_btc,
            blinding_sum_cync: &blinding_cync,
            commitments: &commitments,
            bit_announcements: &announcements,
            link_announcements: &link_announcements,
        },
    )
    .unwrap();
    let (e_btc, e_cync) = challenge.scalars().unwrap();
    let bits = commitments
        .iter()
        .zip(honest.iter().zip(forged))
        .map(|(&(commitment_btc, commitment_cync), (witness, response))| BitProof {
            commitment_btc,
            commitment_cync,
            response: match (witness, response) {
                (Some(witness), None) => respond_bit(witness, challenge).unwrap(),
                (None, Some(response)) => response,
                _ => unreachable!(),
            },
        })
        .collect();
    CrossCurveProof {
        challenge,
        blinding_sum_btc,
        blinding_sum_cync: blinding_cync,
        bits,
        link: Responses {
            btc: btc_mul_add(&k_btc, &e_btc, &t_btc_sk).unwrap(),
            cync: k_cync + e_cync * t_cync_scalar,
        },
    }
}

#[test]
fn forger_with_equal_secrets_produces_a_valid_proof() {
    let (_, btc, cync) = fixture(RistrettoScalar::from(1234u64).to_bytes());
    let statement = CrossCurveStatement::new(&btc, &cync, b"forger-check").unwrap();
    let t = RistrettoScalar::from(1234u64).to_bytes();
    let proof = forge_with_per_curve_secrets(t, t, &statement, &mut rng(11));
    verify(&proof, &statement).unwrap();
}

#[test]
fn different_secrets_on_the_two_curves_are_rejected() {
    // T_btc = t1*G_btc and T_cync = t2*G_cync. The v1 strict proof accepted
    // exactly this statement, because its per-curve bit proofs were never
    // tied together.
    for (t1, t2) in [(7u64, 11u64), (1, 2), (0x8000_0000_0000_0000, 0x8000_0000_0000_0001)] {
        let (s1, btc, _) = fixture(RistrettoScalar::from(t1).to_bytes());
        let (s2, _, cync) = fixture(RistrettoScalar::from(t2).to_bytes());
        let statement = CrossCurveStatement::new(&btc, &cync, b"two-secrets").unwrap();
        // The honest prover refuses with either secret.
        assert!(prove(&s1, &statement, &mut rng(0)).is_err());
        assert!(prove(&s2, &statement, &mut rng(0)).is_err());
        let proof = forge_with_per_curve_secrets(
            RistrettoScalar::from(t1).to_bytes(),
            RistrettoScalar::from(t2).to_bytes(),
            &statement,
            &mut rng(t1 ^ t2),
        );
        assert!(verify(&proof, &statement).is_err());
    }
}

// ─── Zero-knowledge regression: no shared nonces across curves ───────

/// Nonce recovered from a response with the known witness:
/// `k = s - e*w` on each curve, as canonical little-endian integers.
fn recovered_nonces(
    s_btc: &BtcScalar,
    s_cync: &RistrettoScalar,
    e: Challenge,
    w_btc: &SecretKey,
    w_cync: &RistrettoScalar,
) -> ([u8; 32], [u8; 32]) {
    let (e_btc, e_cync) = e.scalars().unwrap();
    let mut k_btc = w_btc
        .mul_tweak(&e_btc)
        .unwrap()
        .negate()
        .add_tweak(s_btc)
        .unwrap()
        .secret_bytes();
    k_btc.reverse();
    let k_cync = (s_cync - e_cync * w_cync).to_bytes();
    (k_btc, k_cync)
}

#[test]
fn link_and_bit_nonces_are_independent_across_curves() {
    // The v1 fast proof used one integer nonce for both curves; with t known
    // the recovered nonces were equal, and without it the pair of responses
    // leaked t through CRT. Independent nonces differ with prob 1 - 2^-252.
    let t = RistrettoScalar::from(0x0dd5_eedu64);
    let (secret, btc, cync) = fixture(t.to_bytes());
    let statement = CrossCurveStatement::new(&btc, &cync, b"nonces").unwrap();
    let proof = prove(&secret, &statement, &mut rng(13)).unwrap();
    let mut t_be = t.to_bytes();
    t_be.reverse();
    let t_btc = SecretKey::from_slice(&t_be).unwrap();
    let (k_btc, k_cync) =
        recovered_nonces(&proof.link.btc, &proof.link.cync, proof.challenge, &t_btc, &t);
    assert_ne!(k_btc, k_cync);

    // Per bit: the real-branch nonce on each curve, from the prover's state.
    let secp = Secp256k1::new();
    let generators = generators();
    let (w_btc, w_cync) = generators.weight(0);
    let mut prng = rng(14);
    for bit in [0u8, 1] {
        let (witness, _) = commit_bit(&secp, Choice::from(bit), w_btc, w_cync, &mut prng).unwrap();
        let e = Challenge([0x5a; CHALLENGE_LEN]);
        let response = respond_bit(&witness, e).unwrap();
        let real = if bit == 0 {
            &response.zero
        } else {
            &response.one
        };
        let real_challenge = if bit == 0 {
            response.zero_challenge
        } else {
            e.xor(response.zero_challenge)
        };
        let (k_btc, k_cync) = recovered_nonces(
            &real.btc,
            &real.cync,
            real_challenge,
            witness.blinding_btc(),
            witness.blinding_cync(),
        );
        assert_ne!(k_btc, k_cync);
    }
}

#[test]
fn proof_bytes_do_not_contain_the_secret() {
    let t = largest_secret();
    let (secret, btc, cync) = fixture(t);
    let statement = CrossCurveStatement::new(&btc, &cync, b"leak").unwrap();
    let bytes = prove(&secret, &statement, &mut rng(15)).unwrap().to_bytes();
    let mut t_be = t;
    t_be.reverse();
    for needle in [t, t_be] {
        assert!(!bytes.windows(32).any(|window| window == needle));
    }
}
