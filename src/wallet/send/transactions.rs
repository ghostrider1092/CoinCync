/// Create a structurally valid transaction without ring signatures or stealth
/// address cryptography.
///
/// Production callers must use `SharedWallet::create_transfer`, or the
/// prepare/covered-allocation/build flow in this module.
#[deprecated(
    note = "Use SharedWallet::create_transfer or the prepared covered-allocation flow; \
    this builder emits placeholder commitments that fail consensus validation"
)]
#[allow(dead_code, deprecated)]
pub fn create_transaction(
    balance: &Balance,
    recipients: &[(Address, Amount)],
    current_height: u64,
) -> Result<Transaction> {
    let min_age = min_output_age_at_height(current_height);
    let total_send: Amount = recipients.iter().map(|(_, amount)| *amount).sum();
    let available = balance.spendable(current_height, min_age);
    let ring_size = ring_size_at_height(current_height);
    let estimated_size = estimate_tx_size(1, recipients.len() + 1, ring_size);
    let fee = Amount::from_atomic(estimated_size as u64 * MIN_FEE_PER_BYTE);
    let total_needed = total_send.saturating_add(fee);

    if available < total_needed {
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: total_needed.as_atomic(),
        });
    }

    let utxos = balance.available_utxos(current_height, min_age);
    let selected = select_utxos(
        &utxos,
        total_needed,
        CoinSelection::OldestFirst,
        &mut rand::rngs::OsRng,
    )?;

    let mut builder = crate::transaction::SimpleTransactionBuilder::new(TxType::Transfer);
    builder.set_fee(fee);
    for (address, amount) in recipients {
        builder.add_output(
            address.spend_public_key,
            address.view_public_key,
            [0u8; 32],
            amount.as_atomic().to_le_bytes().to_vec(),
            0,
        );
    }

    let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
    let change = input_sum
        .as_atomic()
        .saturating_sub(total_needed.as_atomic());
    if change >= MIN_OUTPUT_AMOUNT {
        builder.add_output(
            PublicKey::from_bytes([0u8; 32]),
            PublicKey::from_bytes([0u8; 32]),
            [0u8; 32],
            change.to_le_bytes().to_vec(),
            0,
        );
    }

    builder.build()
}

pub fn prepare_privacy_transaction_with_options<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipients: &[(PublicKey, PublicKey, Amount)],
    keys: &KeyEpoch,
    current_height: u64,
    ring_size: usize,
    fee_multiplier: f64,
    memo: Option<&[u8]>,
    extra: Vec<u8>,
    rng: &mut R,
) -> Result<PreparedPrivacyTransaction> {
    if ring_size < 2 {
        return Err(Error::InvalidRingSize {
            expected: 2,
            got: ring_size,
        });
    }

    let min_age = min_output_age_at_height(current_height);
    let total_send: Amount = recipients.iter().map(|(_, _, amount)| *amount).sum();
    let uniform = current_height >= UNIFORM_TX_SHAPE_HEIGHT;
    let drip_pair = uniform
        && recipients.len() == STANDARD_OUTPUT_COUNT
        && recipients.windows(2).all(|pair| {
            pair[0].0.as_bytes() == pair[1].0.as_bytes()
                && pair[0].1.as_bytes() == pair[1].1.as_bytes()
        });
    if uniform && recipients.len() > 1 && !drip_pair {
        return Err(Error::InvalidState(
            "Post-activation transfers must have one recipient or a same-address drip pair".into(),
        ));
    }

    let input_count_estimate = if uniform { STANDARD_INPUT_COUNT } else { 1 };
    let output_count = if uniform {
        STANDARD_OUTPUT_COUNT
    } else {
        recipients.len() + 3
    };
    let multiplier = if fee_multiplier.is_nan() {
        tracing::warn!(
            target: "wallet::send",
            "fee multiplier is NaN; using the neutral 1.0 multiplier"
        );
        1.0
    } else {
        fee_multiplier
    };
    let multiplier_x100 = (multiplier.max(1.0) * 100.0).min(10_000.0) as u64;
    let initial_fee = scaled_fee(
        input_count_estimate,
        output_count,
        ring_size,
        multiplier_x100,
    );
    let mut required = total_send.saturating_add(initial_fee);
    ensure_spendable(balance, current_height, min_age, required)?;

    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);
    let (selected, estimated_fee, total_needed, input_sum) = loop {
        ensure_spendable(balance, current_height, min_age, required)?;
        let selected = if uniform {
            select_utxos_uniform(&utxos, required, rng)?
        } else {
            select_utxos(&utxos, required, CoinSelection::OldestFirst, rng)?
        };
        let estimated_fee = scaled_fee(
            selected.len(),
            output_count,
            ring_size,
            multiplier_x100,
        );
        let total_needed = total_send.saturating_add(estimated_fee);
        let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
        if input_sum >= total_needed {
            break (selected, estimated_fee, total_needed, input_sum);
        }
        required = total_needed;
    };

    Ok(PreparedPrivacyTransaction {
        inputs: selected
            .into_iter()
            .map(|utxo| prepare_input(utxo, keys))
            .collect::<Result<_>>()?,
        recipients: recipients.to_vec(),
        change_amount: input_sum
            .as_atomic()
            .saturating_sub(total_needed.as_atomic()),
        estimated_fee,
        current_height,
        uniform,
        drip_pair,
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        memo: memo.map(ToOwned::to_owned),
        extra,
        ring_size,
    })
}

pub fn build_prepared_privacy_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedPrivacyTransaction,
    rings: Vec<AllocatedRing>,
    rng: &mut R,
) -> Result<Transaction> {
    let PreparedPrivacyTransaction {
        inputs,
        recipients,
        change_amount,
        estimated_fee,
        current_height,
        uniform,
        drip_pair,
        spend_public,
        view_public,
        memo,
        extra,
        ring_size,
    } = prepared;

    let mut builder = TransactionBuilder::transfer().with_target_height(current_height);
    if let Some(memo) = memo.as_deref() {
        builder = builder.with_memo(memo);
    }
    if !extra.is_empty() {
        builder = builder.with_extra(extra);
    }
    add_prepared_inputs(&mut builder, inputs, rings, ring_size)?;

    for (index, (recipient_spend, recipient_view, amount)) in recipients.iter().enumerate() {
        builder.add_output(
            &Recipient {
                spend_public: *recipient_spend,
                view_public: *recipient_view,
                amount: *amount,
                lock_height: None,
            },
            index as u8,
            rng,
        )?;
    }

    let final_fee = if uniform {
        if drip_pair {
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        } else if change_amount >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &spend_public,
                &view_public,
                Amount::from_atomic(change_amount),
                recipients.len() as u8,
                rng,
            )?;
            estimated_fee
        } else {
            let _ = builder.add_dummy_output(rng);
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        }
    } else {
        let fee = if change_amount >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &spend_public,
                &view_public,
                Amount::from_atomic(change_amount),
                recipients.len() as u8,
                rng,
            )?;
            estimated_fee
        } else {
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        };
        for _ in 0..rng.gen_range(0..=2usize) {
            let _ = builder.add_dummy_output(rng);
        }
        fee
    };
    builder.set_fee(final_fee);
    builder.build(rng)
}

