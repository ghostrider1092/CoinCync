use super::assembly::build_prepared_privacy_transaction;
use super::fee::{calculate_fee, estimate_fee_with_multiplier, estimate_tx_size, scaled_fee, FeeMultiplier};
use super::inputs::add_prepared_inputs;
use super::prepare::prepare_privacy_transaction;
use super::selection::{select_utxos, select_utxos_uniform};
use super::types::{
    CoinSelection, Payment, PreparedInput, PreparedPrivacyTransaction, SendRequest, SpendContext,
    TransferShape, VestingRequest,
};
use super::vesting::{build_prepared_vesting_transaction, prepare_vesting};
use crate::constants::{MIN_OUTPUT_AMOUNT, STANDARD_INPUT_COUNT};
use crate::crypto::{BlindingFactor, PedersenCommitment, SecretScalar};
use crate::decoy::{
    DecoyDistributionSnapshot, HeightOutputCount, OutputLocator, ResolvedDecoyOutput,
    ResolvedDecoySnapshot, DECOY_LOCATOR_POLICY_VERSION,
};
use crate::error::Error;
use crate::primitives::{Amount, Hash, KeyImage, PublicKey, SecretKey};
use crate::transaction::SpendableInput;
use crate::wallet::decoy_selection::{
    allocate_unique_rings, build_covered_request, validate_covered_response, AllocatedRings,
    RealOutputIdentity, ValidatedDecoySnapshot,
};
use crate::wallet::{Balance, KeyEpoch, UTXO};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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

// ===========================================================================
// Shared helpers for the prepare / assembly tests below.
// ===========================================================================

/// A spendable `KeyEpoch` with real (deterministic) curve keys.
fn epoch_from_seed(seed: u8) -> KeyEpoch {
    let spend_secret = SecretKey::from_bytes([seed; 32]);
    let view_secret = SecretKey::from_bytes([seed ^ 0x55; 32]);
    let spend_public = spend_secret.public_key();
    let view_public = view_secret.public_key();
    KeyEpoch {
        epoch: 0,
        spend_secret,
        spend_public,
        view_secret,
        view_public,
    }
}

/// An owned UTXO with a canonical locator so it can flow through
/// `prepare_privacy_transaction` (which requires `output_locator`). The
/// `tx_public_key` is the identity point (a valid curve point), which is all
/// `prepare_input`'s one-time-secret derivation needs.
fn utxo_with_locator(amount: u64, tx_tag: u8, out_index: u8, height: u64, loc_height: u64) -> UTXO {
    UTXO {
        tx_hash: Hash::from_bytes([tx_tag; 32]),
        output_index: out_index,
        output_locator: Some(OutputLocator {
            height: loc_height,
            ordinal: 0,
        }),
        amount: Amount::from_atomic(amount),
        height,
        key_image: KeyImage::from_bytes([tx_tag; 32]),
        spent: false,
        amount_blinding_bytes: [tx_tag; 32],
        tx_public_key: PublicKey::from_bytes([0u8; 32]),
        lock_height: None,
        subaddress_account: None,
        subaddress_index: None,
    }
}

/// Build `PreparedInput`s directly (bypassing the wallet) from
/// `(amount, tx_tag, output_index, locator_height)` specs. Each input carries a
/// real one-time secret whose public key + commitment define its
/// `RealOutputIdentity`, so the rings produced by [`rings_for`] validate
/// against it.
fn synthetic_inputs(specs: &[(u64, u8, u8, u64)]) -> (Vec<PreparedInput>, Vec<RealOutputIdentity>) {
    let mut inputs = Vec::new();
    let mut reals = Vec::new();
    for &(amount, tag, out_index, loc_height) in specs {
        let one_time_secret = SecretKey::from_bytes([tag; 32]);
        let real_public = one_time_secret.public_key();
        let blinding = BlindingFactor::from_bytes([tag ^ 0x0F; 32]);
        let commitment = PedersenCommitment::commit(amount, &blinding).to_bytes();
        let locator = OutputLocator {
            height: loc_height,
            ordinal: 0,
        };
        let real = RealOutputIdentity::new(locator, real_public, commitment);
        let input = SpendableInput {
            tx_hash: Hash::from_bytes([tag; 32]),
            output_index: out_index,
            amount: Amount::from_atomic(amount),
            one_time_secret,
            blinding,
            height: loc_height,
        };
        inputs.push(PreparedInput {
            input,
            real_output: real,
        });
        reals.push(real);
    }
    (inputs, reals)
}

/// Allocate transaction-wide rings for a set of real outputs via the real
/// decoy-selection pipeline. Real locators resolve to their true identity;
/// every decoy locator resolves to a fresh, valid (non-identity) curve point so
/// the built transaction's CLSAG signing succeeds. Mirrors the helper style in
/// `decoy_selection::tests`.
fn rings_for(
    real_outputs: &[RealOutputIdentity],
    ring_size: usize,
    rng: &mut ChaCha20Rng,
) -> AllocatedRings {
    let raw = DecoyDistributionSnapshot {
        snapshot_height: 1_000,
        snapshot_hash: Hash::from_bytes([7; 32]),
        policy_version: DECOY_LOCATOR_POLICY_VERSION,
        heights: (0..=1_000)
            .map(|height| HeightOutputCount { height, count: 1 })
            .collect(),
    };
    let snapshot = ValidatedDecoySnapshot::try_from(raw).expect("valid snapshot");
    let real_locators: Vec<OutputLocator> =
        real_outputs.iter().map(|real| real.locator()).collect();
    let request = build_covered_request(&snapshot, &real_locators, ring_size, 10, rng)
        .expect("covered request");

    let real_by_locator: std::collections::HashMap<OutputLocator, &RealOutputIdentity> =
        real_outputs.iter().map(|real| (real.locator(), real)).collect();
    let outputs: Vec<ResolvedDecoyOutput> = request
        .locators()
        .iter()
        .map(|locator| {
            if let Some(real) = real_by_locator.get(locator) {
                ResolvedDecoyOutput {
                    locator: *locator,
                    public_key: real.public_key(),
                    commitment: real.commitment(),
                    height: locator.height,
                    is_coinbase: false,
                    lock_height: None,
                }
            } else {
                let public_key =
                    PublicKey::from_bytes(SecretScalar::random(rng).to_public().to_bytes());
                let commitment =
                    PedersenCommitment::commit(0, &BlindingFactor::random(rng)).to_bytes();
                ResolvedDecoyOutput {
                    locator: *locator,
                    public_key,
                    commitment,
                    height: locator.height,
                    is_coinbase: false,
                    lock_height: None,
                }
            }
        })
        .collect();
    let snapshot_id = request.snapshot_id();
    let response = ResolvedDecoySnapshot {
        snapshot_height: snapshot_id.height(),
        snapshot_hash: snapshot_id.hash(),
        policy_version: snapshot_id.policy_version(),
        outputs,
    };
    let validated = validate_covered_response(request, response).expect("validated response");
    allocate_unique_rings(validated, real_outputs, rng).expect("rings allocate")
}

// ===========================================================================
// prepare_privacy_transaction — arithmetic invariants + fee handling
// ===========================================================================

/// The core funds-correctness invariant: for a standard uniform send with a
/// real change output, `inputs == payments + change + fee` must hold exactly.
#[test]
fn prepare_uniform_standard_satisfies_inputs_equal_payments_plus_change_plus_fee() {
    let mut rng = ChaCha20Rng::seed_from_u64(101);
    let keys = epoch_from_seed(0x77);
    let recipient = epoch_from_seed(0x88);
    let context = SpendContext::for_target_height(500);
    let total_send = 50_000_000u64;
    let pay = Payment::new(
        recipient.spend_public,
        recipient.view_public,
        Amount::from_atomic(total_send),
    );
    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(40_000_000, 0xA0, 0, 10, 100));
    balance.add_utxo(utxo_with_locator(40_000_000, 0xB0, 1, 10, 110));

    let prepared =
        prepare_privacy_transaction(&balance, SendRequest::new(vec![pay], context), &keys, &mut rng)
            .expect("prepare");
    assert_eq!(prepared.shape, TransferShape::UniformStandard);

    let input_sum: u64 = prepared
        .inputs
        .iter()
        .map(|prepared_input| prepared_input.input.amount.as_atomic())
        .sum();
    let payments_sum: u64 = prepared.payments.iter().map(|p| p.amount.as_atomic()).sum();
    assert_eq!(
        input_sum,
        payments_sum + prepared.change_amount + prepared.estimated_fee.as_atomic(),
        "inputs == payments + change + fee must hold exactly"
    );
    assert!(
        prepared.change_amount >= MIN_OUTPUT_AMOUNT,
        "this scenario is sized to leave a real change output"
    );
}

/// When the leftover change is below `MIN_OUTPUT_AMOUNT`, `prepare` still
/// balances (the raw change rides in `change_amount`) and the invariant holds;
/// the fold-into-fee happens later at assembly time.
#[test]
fn prepare_change_below_min_still_balances_inputs_equal_payments_plus_change_plus_fee() {
    let mut rng = ChaCha20Rng::seed_from_u64(102);
    let keys = epoch_from_seed(0x33);
    let recipient = epoch_from_seed(0x44);
    let target_height = 500;
    let context = SpendContext::for_target_height(target_height);
    let total_send = 10_000_000u64;
    let fee = estimate_fee_with_multiplier(2, 2, target_height, 1.0).as_atomic();
    let change = MIN_OUTPUT_AMOUNT / 2; // strictly below MIN
    let sum = total_send + fee + change;
    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(sum / 2, 0xA0, 0, 10, 100));
    balance.add_utxo(utxo_with_locator(sum - sum / 2, 0xB0, 1, 10, 110));
    let pay = Payment::new(
        recipient.spend_public,
        recipient.view_public,
        Amount::from_atomic(total_send),
    );

    let prepared =
        prepare_privacy_transaction(&balance, SendRequest::new(vec![pay], context), &keys, &mut rng)
            .expect("prepare");
    assert_eq!(prepared.change_amount, change);
    assert!(prepared.change_amount < MIN_OUTPUT_AMOUNT);

    let input_sum: u64 = prepared
        .inputs
        .iter()
        .map(|prepared_input| prepared_input.input.amount.as_atomic())
        .sum();
    let payments_sum: u64 = prepared.payments.iter().map(|p| p.amount.as_atomic()).sum();
    assert_eq!(
        input_sum,
        payments_sum + prepared.change_amount + prepared.estimated_fee.as_atomic()
    );
}

/// Insufficient funds must error out of `prepare` and — critically — leave the
/// balance's reservation set untouched (reservation is the submission layer's
/// job, never prepare's).
#[test]
fn prepare_insufficient_funds_errors_without_reserving() {
    let mut rng = ChaCha20Rng::seed_from_u64(103);
    let keys = epoch_from_seed(0x99);
    let recipient = epoch_from_seed(0xAA);
    let context = SpendContext::for_target_height(500);
    let pay = Payment::new(
        recipient.spend_public,
        recipient.view_public,
        Amount::from_atomic(100_000_000),
    );
    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(1_000_000, 0xA0, 0, 10, 100));
    balance.add_utxo(utxo_with_locator(1_000_000, 0xB0, 1, 10, 110));

    let result =
        prepare_privacy_transaction(&balance, SendRequest::new(vec![pay], context), &keys, &mut rng);
    assert!(result.is_err(), "insufficient balance must error");
    assert!(
        balance.all_reservations().is_empty(),
        "prepare must never write a reservation"
    );
}

/// A near-`u64::MAX` send makes `total_send + fee` saturate at `u64::MAX`. The
/// saturating add must NOT wrap into a small, satisfiable `required` — the call
/// errors instead.
#[test]
fn prepare_saturating_total_plus_fee_does_not_wrap_into_satisfiable_required() {
    let mut rng = ChaCha20Rng::seed_from_u64(104);
    let keys = epoch_from_seed(0xBB);
    let recipient = epoch_from_seed(0xCC);
    let context = SpendContext::for_target_height(500);
    let pay = Payment::new(
        recipient.spend_public,
        recipient.view_public,
        Amount::from_atomic(u64::MAX - 1),
    );
    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(1_000_000, 0xA0, 0, 10, 100));
    balance.add_utxo(utxo_with_locator(1_000_000, 0xB0, 1, 10, 110));

    let result =
        prepare_privacy_transaction(&balance, SendRequest::new(vec![pay], context), &keys, &mut rng);
    assert!(
        result.is_err(),
        "a saturated required must fail closed, not wrap to a satisfiable target"
    );
}

/// `fee_multiplier == NaN` falls back to the neutral 1.0 multiplier.
#[test]
fn fee_multiplier_nan_falls_back_to_neutral_one() {
    let neutral = estimate_fee_with_multiplier(2, 2, 500, 1.0).as_atomic();
    assert_eq!(
        estimate_fee_with_multiplier(2, 2, 500, f64::NAN).as_atomic(),
        neutral,
        "NaN multiplier must behave like 1.0"
    );
}

/// Negative/zero multipliers clamp up to the neutral floor; a huge multiplier
/// clamps down to the fixed ceiling.
#[test]
fn fee_multiplier_negative_zero_and_huge_are_clamped() {
    let neutral = estimate_fee_with_multiplier(2, 2, 500, 1.0).as_atomic();
    assert_eq!(estimate_fee_with_multiplier(2, 2, 500, -5.0).as_atomic(), neutral);
    assert_eq!(estimate_fee_with_multiplier(2, 2, 500, 0.0).as_atomic(), neutral);

    let ceiling = estimate_fee_with_multiplier(2, 2, 500, 100.0).as_atomic();
    let huge = estimate_fee_with_multiplier(2, 2, 500, 1_000_000.0).as_atomic();
    assert_eq!(huge, ceiling, "huge multiplier clamps to the 100x ceiling");
    assert!(huge > neutral);
}

/// `scaled_fee` is monotonically non-decreasing in each size dimension.
#[test]
fn scaled_fee_is_monotonic_in_input_output_and_ring_counts() {
    let multiplier = FeeMultiplier::from_f64(1.0);
    let base = scaled_fee(2, 2, 11, multiplier).as_atomic();
    assert!(
        scaled_fee(3, 2, 11, multiplier).as_atomic() > base,
        "more inputs → higher fee"
    );
    assert!(
        scaled_fee(2, 3, 11, multiplier).as_atomic() > base,
        "more outputs → higher fee"
    );
    assert!(
        scaled_fee(2, 2, 16, multiplier).as_atomic() > base,
        "larger ring → higher fee"
    );
}

// ===========================================================================
// build_prepared_privacy_transaction — output shapes
// ===========================================================================

/// UniformDripPair: two equal same-destination payments produce exactly two
/// outputs and NO change output (the excess is folded into the fee).
#[test]
fn build_prepared_uniform_drip_pair_emits_two_outputs_no_change() {
    let mut rng = ChaCha20Rng::seed_from_u64(201);
    let keys = epoch_from_seed(0x11);
    let recipient = epoch_from_seed(0x22);
    let target_height = 500;
    let context = SpendContext::for_target_height(target_height);
    let ring_size = context.ring_size();

    let per_output = 20_000_000u64;
    let total_send = per_output * 2;
    let fee = estimate_fee_with_multiplier(2, 2, target_height, 1.0).as_atomic();
    let excess = 1_000_000u64; // folded to fee; must be <= total_send
    let sum = total_send + fee + excess;
    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(sum / 2, 0xA0, 0, 10, 100));
    balance.add_utxo(utxo_with_locator(sum - sum / 2, 0xB0, 1, 10, 110));

    let pay = Payment::new(
        recipient.spend_public,
        recipient.view_public,
        Amount::from_atomic(per_output),
    );
    let request = SendRequest::new(vec![pay, pay], context);
    let prepared = prepare_privacy_transaction(&balance, request, &keys, &mut rng).expect("prepare");
    assert_eq!(prepared.shape, TransferShape::UniformDripPair);
    assert_eq!(prepared.change_amount, excess);

    let rings = rings_for(&prepared.real_outputs(), ring_size, &mut rng);
    let tx = build_prepared_privacy_transaction(prepared, rings, &mut rng).expect("build");
    assert_eq!(
        tx.outputs.len(),
        2,
        "drip pair emits exactly two outputs and no change output"
    );
}

/// UniformStandard with change below MIN: a dummy output is added and the change
/// is folded into the fee (so still exactly two outputs: payment + dummy).
#[test]
fn build_prepared_uniform_standard_change_below_min_adds_dummy_and_folds_to_fee() {
    let mut rng = ChaCha20Rng::seed_from_u64(202);
    let keys = epoch_from_seed(0x33);
    let recipient = epoch_from_seed(0x44);
    let target_height = 500;
    let context = SpendContext::for_target_height(target_height);
    let ring_size = context.ring_size();

    let total_send = 10_000_000u64;
    let fee = estimate_fee_with_multiplier(2, 2, target_height, 1.0).as_atomic();
    let change = MIN_OUTPUT_AMOUNT / 2;
    let sum = total_send + fee + change;
    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(sum / 2, 0xA0, 0, 10, 100));
    balance.add_utxo(utxo_with_locator(sum - sum / 2, 0xB0, 1, 10, 110));

    let pay = Payment::new(
        recipient.spend_public,
        recipient.view_public,
        Amount::from_atomic(total_send),
    );
    let prepared =
        prepare_privacy_transaction(&balance, SendRequest::new(vec![pay], context), &keys, &mut rng)
            .expect("prepare");
    assert_eq!(prepared.shape, TransferShape::UniformStandard);
    assert!(prepared.change_amount < MIN_OUTPUT_AMOUNT);

    let rings = rings_for(&prepared.real_outputs(), ring_size, &mut rng);
    let tx = build_prepared_privacy_transaction(prepared, rings, &mut rng).expect("build");
    assert_eq!(
        tx.outputs.len(),
        2,
        "payment + dummy output (change folded into fee, no change output)"
    );
}

/// Legacy shape (constructed directly, since it is unreachable through
/// `classify` while `UNIFORM_TX_SHAPE_HEIGHT == 0`): a change output plus 0..=2
/// dummy outputs, with the fee left as the estimated fee (change went to an
/// output, not into the fee).
#[test]
fn build_prepared_legacy_shape_adds_change_and_up_to_two_dummies() {
    let mut rng = ChaCha20Rng::seed_from_u64(203);
    let keys = epoch_from_seed(0x55);
    let recipient = epoch_from_seed(0x66);
    let context = SpendContext::for_target_height(500);
    let ring_size = context.ring_size();

    let payment_amount = 10_000_000u64;
    let change = 5_000_000u64; // >= MIN → a change output is added
    let estimated_fee = 1_000_000u64;
    // The builder enforces sum(inputs) == sum(outputs) + fee, so the single
    // input must equal payment + change + fee exactly.
    let input_amount = payment_amount + change + estimated_fee;
    let (inputs, reals) = synthetic_inputs(&[(input_amount, 0xC0, 0, 100)]);
    let rings = rings_for(&reals, ring_size, &mut rng);

    let prepared = PreparedPrivacyTransaction {
        inputs,
        payments: vec![Payment::new(
            recipient.spend_public,
            recipient.view_public,
            Amount::from_atomic(payment_amount),
        )],
        change_amount: change,
        estimated_fee: Amount::from_atomic(estimated_fee),
        context,
        shape: TransferShape::Legacy,
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        memo: None,
        extra: Vec::new(),
    };
    let tx = build_prepared_privacy_transaction(prepared, rings, &mut rng).expect("build");

    // payment (1) + change (1) + 0..=2 dummies.
    assert!(
        (2..=4).contains(&tx.outputs.len()),
        "legacy adds a change output plus 0..=2 dummies, got {} outputs",
        tx.outputs.len()
    );
    assert_eq!(
        tx.fee,
        Amount::from_atomic(estimated_fee),
        "change >= MIN → change is its own output, fee stays the estimated fee"
    );
}

/// `add_prepared_inputs` rejects a mismatch between the number of selected
/// inputs and the number of allocated rings.
#[test]
fn add_prepared_inputs_rejects_ring_count_mismatch() {
    let mut rng = ChaCha20Rng::seed_from_u64(204);
    let ring_size = 4usize;
    // Two prepared inputs...
    let (two_inputs, _two_reals) =
        synthetic_inputs(&[(1_000_000, 0xD0, 0, 100), (2_000_000, 0xD1, 1, 110)]);
    // ...but rings allocated for only one.
    let (_one_input, one_real) = synthetic_inputs(&[(3_000_000, 0xD2, 2, 120)]);
    let rings = rings_for(&one_real, ring_size, &mut rng);

    let mut builder = crate::transaction::TransactionBuilder::transfer();
    let err = add_prepared_inputs(&mut builder, two_inputs, rings, ring_size).unwrap_err();
    match err {
        Error::InvalidState(message) => assert!(
            message.contains("ring"),
            "expected a ring-count mismatch message, got {message}"
        ),
        other => panic!("expected InvalidState(ring count mismatch), got {other:?}"),
    }
}

// ===========================================================================
// SpendContext / Payment / vesting / legacy path
// ===========================================================================

/// `SpendContext::with_ring_size` rejects a ring size below 2 and otherwise
/// derives `min_output_age` from the target height.
#[test]
fn spend_context_with_ring_size_rejects_small_ring_and_derives_min_age() {
    let err = SpendContext::with_ring_size(500, 1).unwrap_err();
    match err {
        Error::InvalidRingSize { expected: 2, got: 1 } => {}
        other => panic!("expected InvalidRingSize{{2,1}}, got {other:?}"),
    }
    let context = SpendContext::with_ring_size(500, 8).expect("valid ring size");
    assert_eq!(context.ring_size(), 8);
    assert_eq!(context.target_height(), 500);
    assert_eq!(
        context.min_output_age(),
        crate::constants::min_output_age_at_height(500)
    );
}

/// `Payment::new_subaddress` sets the subaddress flag and stores the keys;
/// the plain constructor defaults to a main-address payment.
#[test]
fn payment_new_subaddress_sets_flag_and_keys() {
    let spend = SecretKey::from_bytes([1; 32]).public_key();
    let view = SecretKey::from_bytes([2; 32]).public_key();
    let amount = Amount::from_atomic(7_000_000);

    let sub = Payment::new_subaddress(spend, view, amount);
    assert!(sub.is_subaddress, "new_subaddress must set is_subaddress");
    assert_eq!(sub.spend_public.as_bytes(), spend.as_bytes());
    assert_eq!(sub.view_public.as_bytes(), view.as_bytes());
    assert_eq!(sub.amount, amount);

    assert!(
        !Payment::new(spend, view, amount).is_subaddress,
        "plain new() defaults to a main-address payment"
    );
}

/// `prepare_vesting` + assembly stamp the requested `unlock_height` onto the
/// vesting output's `lock_height`.
#[test]
fn prepare_vesting_stamps_unlock_height_onto_output_lock_height() {
    let mut rng = ChaCha20Rng::seed_from_u64(301);
    let keys = epoch_from_seed(0xDD);
    let recipient = epoch_from_seed(0xEE);
    let target_height = 500;
    let unlock_height = 5_000u64;
    let context = SpendContext::for_target_height(target_height);
    let ring_size = context.ring_size();

    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(60_000_000, 0xA0, 0, 10, 100));

    let request = VestingRequest::new(
        Payment::new(
            recipient.spend_public,
            recipient.view_public,
            Amount::from_atomic(10_000_000),
        ),
        unlock_height,
        context,
    );
    let prepared = prepare_vesting(&balance, request, &keys, &mut rng).expect("prepare vesting");
    let rings = rings_for(&prepared.real_outputs(), ring_size, &mut rng);
    let tx = build_prepared_vesting_transaction(prepared, rings, &mut rng).expect("build vesting");

    let locked: Vec<_> = tx
        .outputs
        .iter()
        .filter(|output| output.lock_height == Some(unlock_height))
        .collect();
    assert_eq!(
        locked.len(),
        1,
        "exactly one output must carry lock_height == unlock_height"
    );
}

/// Exercises the fee-growth re-selection loop (the same loop shape as
/// `prepare_privacy_transaction`, which is structurally dead for the uniform
/// shapes because they always select exactly two inputs at a fixed fee).
/// `prepare_vesting` uses `select_utxos`, whose input count grows: each added
/// input raises the fee, so the outer loop must re-select until
/// `input_sum >= amount + estimated_fee`.
#[test]
fn prepare_vesting_fee_growth_loop_reselects_until_inputs_cover_fee() {
    let mut rng = ChaCha20Rng::seed_from_u64(302);
    let keys = epoch_from_seed(0x21);
    let recipient = epoch_from_seed(0x22);
    let context = SpendContext::for_target_height(500);
    let amount = 8_000_000u64;
    // Many small UTXOs: each adds value but also raises the per-input fee, so
    // covering `amount + fee` needs several inputs.
    let mut balance = Balance::new();
    for i in 0..20u8 {
        balance.add_utxo(utxo_with_locator(4_000_000, 0xC0 + i, i, 10, 100 + i as u64));
    }
    let request = VestingRequest::new(
        Payment::new(
            recipient.spend_public,
            recipient.view_public,
            Amount::from_atomic(amount),
        ),
        5_000,
        context,
    );
    let prepared = prepare_vesting(&balance, request, &keys, &mut rng).expect("prepare vesting");
    let input_sum: u64 = prepared
        .inputs
        .iter()
        .map(|prepared_input| prepared_input.input.amount.as_atomic())
        .sum();
    assert!(
        prepared.inputs.len() >= 2,
        "fee growth must force more than a single input"
    );
    assert!(
        input_sum >= amount + prepared.estimated_fee.as_atomic(),
        "the re-selection loop must settle with inputs covering amount + fee"
    );
}

/// The property a received vesting output must honor in the balance layer:
/// unspendable before `unlock_height`, spendable at/after it.
#[test]
fn vesting_output_lock_height_gates_spendability_at_unlock_boundary() {
    let unlock_height = 5_000u64;
    let mut balance = Balance::new();
    let mut utxo = utxo_with_locator(10_000_000, 0xF0, 0, 10, 100);
    utxo.lock_height = Some(unlock_height);
    balance.add_utxo(utxo);

    // min_age 0 → the lock is the only gate.
    assert_eq!(balance.spendable(unlock_height - 1, 0), Amount::ZERO);
    assert_eq!(
        balance.locked_balance(unlock_height - 1),
        Amount::from_atomic(10_000_000)
    );
    assert_eq!(
        balance.spendable(unlock_height, 0),
        Amount::from_atomic(10_000_000)
    );
}

/// The deprecated `legacy::create_transaction` selects inputs, computes a fee,
/// and emits a recipient output plus a change output.
#[test]
#[allow(deprecated)]
fn legacy_create_transaction_produces_recipient_and_change_outputs() {
    use crate::primitives::{Address, Network};

    let recipient_spend = SecretKey::from_bytes([1; 32]).public_key();
    let recipient_view = SecretKey::from_bytes([2; 32]).public_key();
    let address = Address::new(Network::Testnet, recipient_spend, recipient_view);

    let mut balance = Balance::new();
    balance.add_utxo(utxo_with_locator(60_000_000, 0xA0, 0, 10, 100));

    let tx = super::legacy::create_transaction(
        &balance,
        &[(address, Amount::from_atomic(10_000_000))],
        500,
    )
    .expect("legacy create_transaction");
    assert_eq!(
        tx.outputs.len(),
        2,
        "one recipient output + one change output (change >= MIN)"
    );
    assert!(tx.fee.as_atomic() > 0, "legacy path sets a non-zero fee");
}
