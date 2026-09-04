use super::fee::{calculate_fee, estimate_tx_size};
use super::selection::{select_utxos, select_utxos_uniform};
use super::types::CoinSelection;
use crate::constants::STANDARD_INPUT_COUNT;
use crate::error::Error;
use crate::primitives::{Amount, PublicKey};
use crate::wallet::UTXO;

#[test]
fn estimate_tx_size_is_within_expected_range() {
    let size = estimate_tx_size(1, 2, 11);
    assert!(size > 1_000);
    assert!(size < 5_000);
}

#[test]
fn calculate_fee_is_non_zero() {
    let fee = calculate_fee(1, 2, 0);
    assert!(fee.as_atomic() > 0);
}

#[test]
fn coin_selection_rejects_empty_pool() {
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
        subaddress_account: None,
        subaddress_index: None,
        payment_id: None,
    }
}

#[test]
fn uniform_selection_reports_when_no_pair_covers() {
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
fn uniform_selection_requires_two_inputs() {
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
fn uniform_selection_finds_optimal_non_largest_pair() {
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
fn uniform_selection_happy_path() {
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
