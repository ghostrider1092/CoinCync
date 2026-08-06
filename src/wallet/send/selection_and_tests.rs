fn select_utxos<'a, R: RngCore + CryptoRng>(
    utxos: &[&'a UTXO],
    target: Amount,
    strategy: CoinSelection,
    rng: &mut R,
) -> Result<Vec<&'a UTXO>> {
    if utxos.is_empty() {
        return Err(Error::NoOutputsAvailable);
    }

    let mut sorted: Vec<&UTXO> = utxos.to_vec();
    sorted.shuffle(rng);
    match strategy {
        CoinSelection::OldestFirst => sorted.sort_by_key(|utxo| utxo.height),
        CoinSelection::NewestFirst => {
            sorted.sort_by_key(|utxo| std::cmp::Reverse(utxo.height));
        }
        CoinSelection::LargestFirst => {
            sorted.sort_by_key(|utxo| std::cmp::Reverse(utxo.amount.as_atomic()));
        }
        CoinSelection::SmallestFirst => {
            sorted.sort_by_key(|utxo| utxo.amount.as_atomic());
        }
        CoinSelection::Random => {}
    }

    let mut selected = Vec::new();
    let mut sum = Amount::ZERO;
    for utxo in sorted {
        selected.push(utxo);
        sum = sum.saturating_add(utxo.amount);
        if sum >= target {
            return Ok(selected);
        }
    }

    Err(Error::InsufficientBalance {
        have: sum.as_atomic(),
        need: target.as_atomic(),
    })
}

/// Select exactly two UTXOs whose combined value covers `target`.
fn select_utxos_uniform<'a, R: RngCore + CryptoRng>(
    utxos: &[&'a UTXO],
    target: Amount,
    rng: &mut R,
) -> Result<Vec<&'a UTXO>> {
    if utxos.len() < STANDARD_INPUT_COUNT {
        return Err(Error::InsufficientInputs {
            have: utxos.len(),
            need: STANDARD_INPUT_COUNT,
        });
    }

    let target_value = target.as_atomic();
    let mut indices: Vec<usize> = (0..utxos.len()).collect();
    indices.sort_by(|left, right| {
        utxos[*right]
            .amount
            .as_atomic()
            .cmp(&utxos[*left].amount.as_atomic())
    });

    let largest_pair_sum = utxos[indices[0]]
        .amount
        .as_atomic()
        .saturating_add(utxos[indices[1]].amount.as_atomic());
    if largest_pair_sum < target_value {
        let total: u64 = utxos.iter().map(|utxo| utxo.amount.as_atomic()).sum();
        return Err(Error::NoUtxoPairCovers {
            target_atomic: target_value,
            utxo_count: utxos.len(),
            total_atomic: total,
            largest_pair_atomic: largest_pair_sum,
            max_safe_atomic: largest_pair_sum.saturating_sub(50_000_000),
        });
    }

    let mut candidates: Vec<(usize, usize, u64)> = Vec::new();
    let mut best_excess = u64::MAX;
    for left in 0..indices.len() {
        for right in (left + 1)..indices.len() {
            let sum = utxos[indices[left]]
                .amount
                .as_atomic()
                .saturating_add(utxos[indices[right]].amount.as_atomic());
            if sum >= target_value {
                let excess = sum - target_value;
                best_excess = best_excess.min(excess);
                candidates.push((indices[left], indices[right], excess));
            }
        }
    }

    if candidates.is_empty() {
        let total: u64 = utxos.iter().map(|utxo| utxo.amount.as_atomic()).sum();
        return Err(Error::NoUtxoPairCovers {
            target_atomic: target_value,
            utxo_count: utxos.len(),
            total_atomic: total,
            largest_pair_atomic: largest_pair_sum,
            max_safe_atomic: largest_pair_sum.saturating_sub(50_000_000),
        });
    }

    let threshold = best_excess
        .saturating_add(best_excess / 5)
        .max(best_excess.saturating_add(1));
    let good_candidates: Vec<_> = candidates
        .iter()
        .filter(|(_, _, excess)| *excess <= threshold)
        .collect();
    let &&(left, right, _) = good_candidates.choose(rng).unwrap_or(&&candidates[0]);
    Ok(vec![utxos[left], utxos[right]])
}

/// Estimate transaction size in bytes.
pub fn estimate_tx_size(input_count: usize, output_count: usize, ring_size: usize) -> usize {
    let base = 32;
    let input_size = 32 + 4 + 64 * ring_size + 32 + 32 + 32 + 4 + 32 * ring_size + 32 + 32;
    let inputs_total = input_count * input_size;
    let output_size = 32 + 32 + 32 + 12 + 1 + 9;
    let outputs_total = output_count * output_size;
    let range_proof = 672 + 64 * output_count;
    (base + inputs_total + outputs_total + range_proof) * 2
}

#[allow(dead_code)]
pub fn calculate_fee(input_count: usize, output_count: usize, current_height: u64) -> Amount {
    let ring_size = ring_size_at_height(current_height);
    let size = estimate_tx_size(input_count, output_count, ring_size);
    Amount::from_atomic(size as u64 * MIN_FEE_PER_BYTE)
}

pub fn estimate_fee_with_multiplier(
    input_count: usize,
    output_count: usize,
    current_height: u64,
    fee_multiplier: f64,
) -> Amount {
    let ring_size = ring_size_at_height(current_height);
    let size = estimate_tx_size(input_count, output_count, ring_size);
    let base_fee = size as u64 * MIN_FEE_PER_BYTE;
    let multiplier = if fee_multiplier.is_nan() {
        1.0
    } else {
        fee_multiplier
    };
    let multiplier_x100 = (multiplier.max(1.0) * 100.0).min(10_000.0) as u64;
    Amount::from_atomic(base_fee.saturating_mul(multiplier_x100) / 100)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_tx_size() {
        let size = estimate_tx_size(1, 2, 11);
        assert!(size > 1_000);
        assert!(size < 5_000);
    }

    #[test]
    fn test_calculate_fee() {
        let fee = calculate_fee(1, 2, 0);
        assert!(fee.as_atomic() > 0);
    }

    #[test]
    fn test_coin_selection_empty() {
        let utxos: Vec<&UTXO> = vec![];
        let result = select_utxos(
            &utxos,
            Amount::from_atomic(100),
            CoinSelection::OldestFirst,
            &mut rand::rngs::OsRng,
        );
        assert!(result.is_err());
    }

    fn make_utxo(amount: u64, index: u8) -> UTXO {
        UTXO {
            tx_hash: crate::primitives::Hash::from_bytes([index; 32]),
            output_index: index,
            output_locator: None,
            amount: Amount::from_atomic(amount),
            height: 100,
            key_image: crate::primitives::KeyImage::from_bytes([index; 32]),
            spent: false,
            amount_blinding_bytes: [0u8; 32],
            tx_public_key: PublicKey::from_bytes([0u8; 32]),
            lock_height: None,
        }
    }

    #[test]
    fn test_uniform_select_no_pair_covers_returns_diagnostic_error() {
        let utxos: Vec<UTXO> = (0..4).map(|index| make_utxo(50, index)).collect();
        let refs: Vec<&UTXO> = utxos.iter().collect();
        let err = select_utxos_uniform(
            &refs,
            Amount::from_atomic(101),
            &mut rand::rngs::OsRng,
        )
        .unwrap_err();
        match err {
            Error::NoUtxoPairCovers {
                target_atomic,
                utxo_count,
                total_atomic,
                largest_pair_atomic,
                max_safe_atomic: _,
            } => {
                assert_eq!(target_atomic, 101);
                assert_eq!(utxo_count, 4);
                assert_eq!(total_atomic, 200);
                assert_eq!(largest_pair_atomic, 100);
            }
            other => panic!("expected NoUtxoPairCovers, got {other:?}"),
        }
    }

    #[test]
    fn test_uniform_select_insufficient_inputs_only_when_too_few_utxos() {
        let single = vec![make_utxo(1_000_000, 0)];
        let refs: Vec<&UTXO> = single.iter().collect();
        let err = select_utxos_uniform(
            &refs,
            Amount::from_atomic(100),
            &mut rand::rngs::OsRng,
        )
        .unwrap_err();
        match err {
            Error::InsufficientInputs { have, need } => {
                assert_eq!(have, 1);
                assert_eq!(need, STANDARD_INPUT_COUNT);
            }
            other => panic!("expected InsufficientInputs, got {other:?}"),
        }
    }

    #[test]
    fn test_uniform_select_finds_optimal_non_largest_pair() {
        let utxos = vec![
            make_utxo(100, 0),
            make_utxo(80, 1),
            make_utxo(60, 2),
            make_utxo(40, 3),
        ];
        let refs: Vec<&UTXO> = utxos.iter().collect();
        let chosen = select_utxos_uniform(
            &refs,
            Amount::from_atomic(90),
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        assert_eq!(chosen.len(), 2);
        assert_eq!(
            chosen
                .iter()
                .map(|utxo| utxo.amount.as_atomic())
                .sum::<u64>(),
            100
        );
    }

    #[test]
    fn test_uniform_select_happy_path() {
        let utxos = vec![
            make_utxo(1_000_000, 0),
            make_utxo(2_000_000, 1),
            make_utxo(3_000_000, 2),
        ];
        let refs: Vec<&UTXO> = utxos.iter().collect();
        let chosen = select_utxos_uniform(
            &refs,
            Amount::from_atomic(2_500_000),
            &mut rand::rngs::OsRng,
        )
        .unwrap();
        assert_eq!(chosen.len(), 2);
        assert!(
            chosen
                .iter()
                .map(|utxo| utxo.amount.as_atomic())
                .sum::<u64>()
                >= 2_500_000
        );
    }
}
