    use super::*;
    use crate::decoy::{ResolvedDecoyOutput, DECOY_LOCATOR_POLICY_VERSION};
    use crate::primitives::{Hash, PublicKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn snapshot(height: u64, count_per_height: u32) -> DecoyDistributionSnapshot {
        DecoyDistributionSnapshot {
            snapshot_height: height,
            snapshot_hash: Hash::from_bytes([7; 32]),
            policy_version: DECOY_LOCATOR_POLICY_VERSION,
            heights: (0..=height)
                .map(|height| HeightOutputCount {
                    height,
                    count: count_per_height,
                })
                .collect(),
        }
    }

    fn resolved(locator: OutputLocator) -> ResolvedDecoyOutput {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&locator.height.to_le_bytes());
        bytes[8..12].copy_from_slice(&locator.ordinal.to_le_bytes());
        ResolvedDecoyOutput {
            locator,
            public_key: PublicKey::from_bytes(bytes),
            commitment: bytes,
            height: locator.height,
            is_coinbase: false,
            lock_height: None,
        }
    }

    #[test]
    fn gamma_sampling_is_conditioned_and_unique() {
        let snapshot = snapshot(30_000, 1);
        let spend_height = snapshot.snapshot_height + 1;
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut observed = Vec::with_capacity(2_000);
        for _ in 0..125 {
            let selected =
                sample_candidate_locators(&snapshot, 100, 16, &HashSet::new(), &mut rng).unwrap();
            assert_eq!(selected.iter().copied().collect::<HashSet<_>>().len(), 16);
            assert!(selected.iter().all(|locator| locator.height <= 29_901));
            observed.extend(
                selected
                    .iter()
                    .map(|locator| spend_height - locator.height),
            );
        }

        let gamma = Gamma::new(DECOY_GAMMA_SHAPE, DECOY_GAMMA_SCALE).unwrap();
        let block_time = crate::constants::TARGET_BLOCK_TIME as f64;
        let mut target_rng = ChaCha20Rng::seed_from_u64(3);
        let mut expected = Vec::with_capacity(observed.len());
        while expected.len() < observed.len() {
            let age = (gamma.sample(&mut target_rng).exp() / block_time) as u64;
            if (100..=30_001).contains(&age) {
                expected.push(age);
            }
        }
        observed.sort_unstable();
        expected.sort_unstable();
        for percentile in [10, 50, 90] {
            let index = (observed.len() - 1) * percentile / 100;
            let actual = observed[index] as f64;
            let target = expected[index] as f64;
            assert!((actual.ln() - target.ln()).abs() < 0.20);
        }
        assert!(observed.iter().filter(|age| **age == 100).count() < 20);
    }

    #[test]
    fn minimum_age_is_measured_at_the_next_spend_height() {
        let snapshot = DecoyDistributionSnapshot {
            snapshot_height: 100,
            snapshot_hash: Hash::from_bytes([7; 32]),
            policy_version: DECOY_LOCATOR_POLICY_VERSION,
            heights: vec![HeightOutputCount {
                height: 91,
                count: 1,
            }],
        };
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let selected =
            sample_candidate_locators(&snapshot, 10, 1, &HashSet::new(), &mut rng).unwrap();
        assert_eq!(
            selected,
            vec![OutputLocator {
                height: 91,
                ordinal: 0,
            }]
        );
    }

    #[test]
    fn lock_height_is_checked_at_the_next_spend_height() {
        let snapshot = DecoyDistributionSnapshot {
            snapshot_height: 100,
            snapshot_hash: Hash::from_bytes([7; 32]),
            policy_version: DECOY_LOCATOR_POLICY_VERSION,
            heights: vec![
                HeightOutputCount {
                    height: 90,
                    count: 1,
                },
                HeightOutputCount {
                    height: 91,
                    count: 1,
                },
            ],
        };
        let real_locator = OutputLocator {
            height: 90,
            ordinal: 0,
        };
        let candidate_locator = OutputLocator {
            height: 91,
            ordinal: 0,
        };
        let request = vec![real_locator, candidate_locator];
        let real = resolved(real_locator);
        let real_identity = [RealOutputIdentity {
            locator: real_locator,
            public_key: real.public_key,
            commitment: real.commitment,
        }];
        let mut response = ResolvedDecoySnapshot {
            snapshot_height: snapshot.snapshot_height,
            snapshot_hash: snapshot.snapshot_hash,
            policy_version: snapshot.policy_version,
            outputs: request.iter().copied().map(resolved).collect(),
        };
        response.outputs[1].lock_height = Some(101);

        let mut rng = ChaCha20Rng::seed_from_u64(9);
        assert!(allocate_unique_rings(
            &snapshot,
            &request,
            &response,
            &real_identity,
            2,
            10,
            &mut rng,
        )
        .is_ok());

        response.outputs[1].lock_height = Some(102);
        assert!(allocate_unique_rings(
            &snapshot,
            &request,
            &response,
            &real_identity,
            2,
            10,
            &mut rng,
        )
        .is_err());
    }

    #[test]
    fn covered_lookup_allocates_transaction_wide_unique_decoys() {
        let snapshot = snapshot(1_000, 1);
        let real = [
            OutputLocator {
                height: 100,
                ordinal: 0,
            },
            OutputLocator {
                height: 200,
                ordinal: 0,
            },
        ];
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
        assert_eq!(request.len(), COVERED_LOOKUP_SIZE);
        assert!(real.iter().all(|locator| request.contains(locator)));
        assert_eq!(
            request.iter().copied().collect::<HashSet<_>>().len(),
            request.len()
        );

        let mut response = ResolvedDecoySnapshot {
            snapshot_height: snapshot.snapshot_height,
            snapshot_hash: snapshot.snapshot_hash,
            policy_version: snapshot.policy_version,
            outputs: request.iter().copied().map(resolved).collect(),
        };
        let real_outputs: Vec<_> = real
            .iter()
            .copied()
            .map(|locator| {
                let output = resolved(locator);
                RealOutputIdentity {
                    locator,
                    public_key: output.public_key,
                    commitment: output.commitment,
                }
            })
            .collect();
        let colliding = response
            .outputs
            .iter_mut()
            .find(|output| !real.contains(&output.locator))
            .unwrap();
        colliding.public_key = real_outputs[0].public_key;
        let rings = allocate_unique_rings(
            &snapshot,
            &request,
            &response,
            &real_outputs,
            16,
            10,
            &mut rng,
        )
        .unwrap();
        assert_eq!(rings.len(), 2);
        assert!(rings.iter().all(|ring| ring.decoys.len() == 15));
        let left: HashSet<_> = rings[0]
            .decoys
            .iter()
            .map(|decoy| *decoy.public_key.as_bytes())
            .collect();
        let right: HashSet<_> = rings[1]
            .decoys
            .iter()
            .map(|decoy| *decoy.public_key.as_bytes())
            .collect();
        assert!(left.is_disjoint(&right));
        assert!(rings.iter().flat_map(|ring| &ring.decoys).all(|decoy| {
            real_outputs
                .iter()
                .all(|real| decoy.public_key != real.public_key)
        }));
    }

    #[test]
    fn covered_request_rejects_a_real_locator_outside_the_snapshot() {
        let snapshot = snapshot(1_000, 1);
        let real = [OutputLocator {
            height: 1_000,
            ordinal: 1,
        }];
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        assert!(build_covered_request(&snapshot, &real, 16, 10, &mut rng).is_err());
    }

    #[test]
    fn covered_response_rejects_mismatch_and_unusable_request_shape() {
        let snapshot = snapshot(1_000, 1);
        let mut unsupported = snapshot.clone();
        unsupported.policy_version += 1;
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        assert!(sample_candidate_locators(&unsupported, 10, 1, &HashSet::new(), &mut rng).is_err());

        let real: Vec<_> = (0..9)
            .map(|ordinal| OutputLocator {
                height: ordinal,
                ordinal: 0,
            })
            .collect();
        assert!(build_covered_request(&snapshot, &real, 16, 10, &mut rng).is_err());

        let real = [OutputLocator {
            height: 100,
            ordinal: 0,
        }];
        let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
        let mut response = ResolvedDecoySnapshot {
            snapshot_height: snapshot.snapshot_height,
            snapshot_hash: snapshot.snapshot_hash,
            policy_version: snapshot.policy_version,
            outputs: request.iter().copied().map(resolved).collect(),
        };
        response.outputs.swap(0, 1);
        assert!(validate_covered_response(&snapshot, &request, &response).is_err());

        response.outputs = request.iter().copied().map(resolved).collect();
        let expected = resolved(real[0]);
        let real_identity = [RealOutputIdentity {
            locator: real[0],
            public_key: expected.public_key,
            commitment: expected.commitment,
        }];
        let real_output = response
            .outputs
            .iter_mut()
            .find(|output| output.locator == real[0])
            .unwrap();
        real_output.public_key = PublicKey::from_bytes([0xFF; 32]);
        assert!(allocate_unique_rings(
            &snapshot,
            &request,
            &response,
            &real_identity,
            16,
            10,
            &mut rng,
        )
        .is_err());
    }
