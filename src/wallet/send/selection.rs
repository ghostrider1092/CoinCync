use super::super::{Balance, UTXO};
use super::types::CoinSelection;
use crate::constants::{STANDARD_INPUT_COUNT, TARGET_BLOCK_TIME};
use crate::error::{Error, Result};
use crate::primitives::Amount;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use std::cmp::Reverse;

const UNIFORM_PAIR_FEE_RESERVE_ATOMIC: u64 = 50_000_000;

pub(super) fn select_utxos<'a, R: RngCore + CryptoRng>(
    utxos: &[&'a UTXO],
    target: Amount,
    strategy: CoinSelection,
    rng: &mut R,
) -> Result<Vec<&'a UTXO>> {
    if utxos.is_empty() {
        return Err(Error::NoOutputsAvailable);
    }

    let mut sorted = utxos.to_vec();
    sorted.shuffle(rng);
    match strategy {
        CoinSelection::OldestFirst => sorted.sort_by_key(|utxo| utxo.height),
        CoinSelection::NewestFirst => sorted.sort_by_key(|utxo| Reverse(utxo.height)),
        CoinSelection::LargestFirst => {
            sorted.sort_by_key(|utxo| Reverse(utxo.amount.as_atomic()));
        }
        CoinSelection::SmallestFirst => sorted.sort_by_key(|utxo| utxo.amount.as_atomic()),
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

pub(super) fn select_utxos_uniform<'a, R: RngCore + CryptoRng>(
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
        return Err(no_pair_covers_error(
            utxos,
            target_value,
            largest_pair_sum,
        ));
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
        return Err(no_pair_covers_error(
            utxos,
            target_value,
            largest_pair_sum,
        ));
    }

    let threshold = best_excess
        .saturating_add(best_excess / 5)
        .max(best_excess.saturating_add(1));
    let good_candidates: Vec<_> = candidates
        .iter()
        .filter(|(_, _, excess)| *excess <= threshold)
        .collect();
    let &&(left, right, _) = good_candidates
        .choose(rng)
        .unwrap_or(&&candidates[0]);
    Ok(vec![utxos[left], utxos[right]])
}

fn no_pair_covers_error(
    utxos: &[&UTXO],
    target_atomic: u64,
    largest_pair_atomic: u64,
) -> Error {
    Error::NoUtxoPairCovers {
        target_atomic,
        utxo_count: utxos.len(),
        total_atomic: utxos.iter().map(|utxo| utxo.amount.as_atomic()).sum(),
        largest_pair_atomic,
        max_safe_atomic: largest_pair_atomic.saturating_sub(UNIFORM_PAIR_FEE_RESERVE_ATOMIC),
    }
}

pub(super) fn ensure_spendable(
    balance: &Balance,
    current_height: u64,
    min_age: u64,
    need: Amount,
) -> Result<()> {
    let available = balance.spendable(current_height, min_age);
    if available >= need {
        return Ok(());
    }

    if balance.total() >= need {
        let pending_utxos: Vec<&UTXO> = balance
            .unspent_utxos()
            .into_iter()
            .filter(|utxo| current_height < utxo.height.saturating_add(min_age))
            .collect();
        let pending_atomic = pending_utxos
            .iter()
            .map(|utxo| utxo.amount.as_atomic())
            .sum();
        let latest_pending_height = pending_utxos
            .iter()
            .map(|utxo| utxo.height)
            .max()
            .unwrap_or(current_height);
        let blocks_to_wait = latest_pending_height
            .saturating_add(min_age)
            .saturating_sub(current_height);
        return Err(Error::BalancePendingMaturity {
            spendable_atomic: available.as_atomic(),
            pending_atomic,
            pending_utxos: pending_utxos.len(),
            need_atomic: need.as_atomic(),
            blocks_to_wait,
            seconds_to_wait: blocks_to_wait.saturating_mul(TARGET_BLOCK_TIME),
        });
    }

    Err(Error::InsufficientBalance {
        have: available.as_atomic(),
        need: need.as_atomic(),
    })
}
