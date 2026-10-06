//! Equation and per-bit prover tests, not full proof tests. Known-discrete-log
//! weights below are test fixtures ONLY; production weights come from the
//! NUMS generators in `generators.rs`.

use super::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn btc_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn points(btc_value: u64, cync_value: u64) -> (PublicKey, RistrettoPoint) {
    let btc = PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&btc_bytes(btc_value)).unwrap(),
    );
    let cync = &RistrettoScalar::from(cync_value) * RISTRETTO_BASEPOINT_TABLE;
    (btc, cync)
}

fn responses(btc: u64, cync: u64) -> Responses {
    Responses::from_bytes(btc_bytes(btc), RistrettoScalar::from(cync).to_bytes()).unwrap()
}

fn challenge(value: u8) -> Challenge {
    let mut bytes = [0; 31];
    bytes[30] = value;
    Challenge(bytes)
}

#[test]
fn challenge_has_identical_integer_value_on_both_curves() {
    let mut asymmetric = [0; 31];
    asymmetric[0] = 1;
    asymmetric[30] = 2;
    for bytes in [[0; 31], [0xff; 31], asymmetric] {
        let (btc, cync) = Challenge(bytes).scalars().unwrap();
        assert_eq!(btc.to_le_bytes(), cync.to_bytes());
        let mut expected = [0; 32];
        expected[1..].copy_from_slice(&bytes);
        assert_eq!(btc.to_be_bytes(), expected);
    }
    assert_eq!(challenge(5).xor(challenge(9)), challenge(12));
}

#[test]
fn either_joint_branch_reconstructs_independent_honest_nonces() {
    // C = r*G + b*W: independent r=(3,11), k=(17,19), and W=(7G,13G).
    let secp = Secp256k1::new();
    let (btc_weight, cync_weight) = points(7, 13);
    let (expected_btc, expected_cync) = points(17, 19);
    for bit in [0u64, 1] {
        let (btc_commitment, cync_commitment) = points(3 + bit * 7, 11 + bit * 13);
        let statement = JointBitStatement::new(
            &secp,
            btc_commitment,
            cync_commitment,
            btc_weight,
            cync_weight,
        )
        .unwrap();
        let e = if bit == 0 { 5 } else { 9 };
        let honest = responses(17 + e * 3, 19 + e * 11);
        let simulated = responses(29, 31);
        let (zero, one) = if bit == 0 {
            (honest, simulated)
        } else {
            (simulated, honest)
        };
        let mut response = JointBitResponse {
            zero_challenge: challenge(5),
            zero,
            one,
        };
        let announcements = statement
            .reconstruct(&secp, challenge(12), &response)
            .unwrap();
        assert_eq!(
            announcements[bit as usize],
            PointPair {
                btc: Some(expected_btc),
                cync: expected_cync,
            }
        );

        // Changing the shared branch split changes BOTH reconstructed points.
        response.zero_challenge = challenge(6);
        let changed = statement
            .reconstruct(&secp, challenge(12), &response)
            .unwrap();
        assert_ne!(changed[bit as usize].btc, announcements[bit as usize].btc);
        assert_ne!(changed[bit as usize].cync, announcements[bit as usize].cync);
    }
}

#[test]
fn zero_scalars_and_point_cancellation_remain_valid_equations() {
    let secp = Secp256k1::new();
    let (btc_commitment, cync_commitment) = points(3, 11);
    let (btc_weight, cync_weight) = points(7, 13);
    let statement = JointBitStatement::new(
        &secp,
        btc_commitment,
        cync_commitment,
        btc_weight,
        cync_weight,
    )
    .unwrap();
    for (e0, zero) in [(0, responses(0, 0)), (1, responses(3, 11))] {
        let response = JointBitResponse {
            zero_challenge: challenge(e0),
            zero,
            one: responses(0, 0),
        };
        let announcements = statement
            .reconstruct(&secp, challenge(e0), &response)
            .unwrap();
        for announcement in announcements {
            assert_eq!(announcement.btc, None);
            assert!(announcement.cync.is_identity());
        }
    }
}

#[test]
fn identity_branch_statement_is_handled_without_tweak_errors() {
    let secp = Secp256k1::new();
    let (btc, cync) = points(7, 13);
    let statement = JointBitStatement::new(&secp, btc, cync, btc, cync).unwrap();
    let response = JointBitResponse {
        zero_challenge: challenge(5),
        zero: responses(0, 0),
        one: responses(17, 19),
    };
    let announcements = statement
        .reconstruct(&secp, challenge(12), &response)
        .unwrap();
    let (expected_btc, expected_cync) = points(17, 19);
    assert_eq!(
        announcements[1],
        PointPair {
            btc: Some(expected_btc),
            cync: expected_cync,
        }
    );
}

#[test]
fn noncanonical_responses_are_rejected_not_reduced() {
    assert!(Responses::from_bytes([0; 32], [0; 32]).is_ok());
    assert!(Responses::from_bytes(BtcScalar::MAX.to_be_bytes(), [0; 32]).is_ok());
    assert!(Responses::from_bytes([0xff; 32], [0; 32]).is_err());
    assert!(Responses::from_bytes([0; 32], [0xff; 32]).is_err());
}

#[test]
fn honest_prover_announcements_match_verifier_reconstruction_for_both_bits() {
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(0x0b17);
    let (btc_weight, cync_weight) = points(7, 13);
    for bit in [0u8, 1] {
        for round in 0..4u8 {
            let (witness, commitment) = commit_bit(
                &secp,
                Choice::from(bit),
                &btc_weight,
                &cync_weight,
                &mut rng,
            )
            .unwrap();
            let statement = JointBitStatement::new(
                &secp,
                commitment.commitment_btc,
                commitment.commitment_cync,
                btc_weight,
                cync_weight,
            )
            .unwrap();
            let mut bytes = [round.wrapping_mul(37); 31];
            bytes[0] = bit;
            let e = Challenge(bytes);
            let response = respond_bit(&witness, e).unwrap();
            let reconstructed = statement.reconstruct(&secp, e, &response).unwrap();
            assert_eq!(reconstructed, commitment.announcements);

            // The honest commitment opens to the claimed bit on both curves.
            let blind_btc = PublicKey::from_secret_key(&secp, witness.blinding_btc());
            let blind_cync = witness.blinding_cync() * RISTRETTO_BASEPOINT_TABLE;
            if bit == 0 {
                assert_eq!(commitment.commitment_btc, blind_btc);
                assert_eq!(commitment.commitment_cync, blind_cync);
            } else {
                assert_eq!(commitment.commitment_btc, blind_btc.combine(&btc_weight).unwrap());
                assert_eq!(commitment.commitment_cync, blind_cync + cync_weight);
            }

            // Any other global challenge breaks the reconstruction.
            let other = e.xor(challenge(1));
            let forged = statement.reconstruct(&secp, other, &response).unwrap();
            assert_ne!(forged, commitment.announcements);
        }
    }
}

#[test]
fn mixed_bit_commitment_cannot_answer_a_fresh_challenge() {
    let secp = Secp256k1::new();
    let sk = |value: u64| SecretKey::from_slice(&btc_bytes(value)).unwrap();
    let (btc_weight, cync_weight) = points(7, 13);
    // BTC commits to 0 with r = 3; CYNC commits to 1 with r = 11.
    let (btc_commitment, _) = points(3, 1);
    let cync_commitment = &RistrettoScalar::from(11u64) * RISTRETTO_BASEPOINT_TABLE + cync_weight;
    let statement = JointBitStatement::new(
        &secp,
        btc_commitment,
        cync_commitment,
        btc_weight,
        cync_weight,
    )
    .unwrap();
    let btc_one_branch = btc_sub(&secp, Some(btc_commitment), Some(btc_weight)).unwrap();

    // Announcements are fixed BEFORE e. Each branch has one half the cheater
    // can open (nonce 17 on BTC/branch 0, nonce 19 on CYNC/branch 1) and one
    // half it must simulate with a challenge chosen in advance (sim0 on
    // CYNC/branch 0, sim1 on BTC/branch 1).
    let mut sim0_bytes = [0u8; 31];
    sim0_bytes[0] = 0xaa; // keeps sim0 XOR sim1 outside the tested e range
    sim0_bytes[30] = 40;
    let (sim0, sim1) = (Challenge(sim0_bytes), challenge(41));
    let (s_cync0, s_btc1) = (RistrettoScalar::from(29u64), BtcScalar::from(sk(31)));
    let announced = [
        PointPair {
            btc: Some(PublicKey::from_secret_key(&secp, &sk(17))),
            cync: &s_cync0 * RISTRETTO_BASEPOINT_TABLE
                - sim0.scalars().unwrap().1 * cync_commitment,
        },
        PointPair {
            btc: btc_sub(
                &secp,
                btc_mul(&secp, Some(btc_generator(&secp).unwrap()), &s_btc1).unwrap(),
                btc_mul(&secp, btc_one_branch, &sim1.scalars().unwrap().0).unwrap(),
            )
            .unwrap(),
            cync: &RistrettoScalar::from(19u64) * RISTRETTO_BASEPOINT_TABLE,
        },
    ];

    for e_value in 0..=255u8 {
        let e = challenge(e_value);
        assert_ne!(e, sim0.xor(sim1)); // the 2^-248 event the cheater needs
        for zero_challenge in [sim0, e.xor(sim1)] {
            let e0 = zero_challenge;
            let e1 = e.xor(e0);
            let response = JointBitResponse {
                zero_challenge: e0,
                zero: Responses {
                    btc: btc_mul_add(&sk(17), &e0.scalars().unwrap().0, &sk(3)).unwrap(),
                    cync: s_cync0,
                },
                one: Responses {
                    btc: s_btc1,
                    cync: RistrettoScalar::from(19u64)
                        + e1.scalars().unwrap().1 * RistrettoScalar::from(11u64),
                },
            };
            let reconstructed = statement.reconstruct(&secp, e, &response).unwrap();
            // The halves the cheater can open always match...
            assert_eq!(reconstructed[0].btc, announced[0].btc);
            assert_eq!(reconstructed[1].cync, announced[1].cync);
            // ...but no split matches both simulated halves.
            assert_ne!(
                reconstructed, announced,
                "a mixed bit pair answered challenge {e_value}"
            );
        }
    }
}
