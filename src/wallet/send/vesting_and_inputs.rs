pub fn prepare_vesting_transaction<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipient_spend: PublicKey,
    recipient_view: PublicKey,
    amount: Amount,
    unlock_height: u64,
    keys: &KeyEpoch,
    current_height: u64,
    ring_size: usize,
    rng: &mut R,
) -> Result<PreparedVestingTransaction> {
    if ring_size < 2 {
        return Err(Error::InvalidRingSize {
            expected: 2,
            got: ring_size,
        });
    }

    let min_age = min_output_age_at_height(current_height);
    let mut required = amount.saturating_add(Amount::from_atomic(
        estimate_tx_size(1, 4, ring_size) as u64 * MIN_FEE_PER_BYTE,
    ));
    ensure_spendable(balance, current_height, min_age, required)?;
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);

    let (selected, estimated_fee, output_total, input_sum) = loop {
        ensure_spendable(balance, current_height, min_age, required)?;
        let selected = select_utxos(&utxos, required, CoinSelection::OldestFirst, rng)?;
        let estimated_fee = Amount::from_atomic(
            estimate_tx_size(selected.len(), 4, ring_size) as u64 * MIN_FEE_PER_BYTE,
        );
        let output_total = amount
            .as_atomic()
            .saturating_add(estimated_fee.as_atomic());
        let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
        if input_sum.as_atomic() >= output_total {
            break (selected, estimated_fee, output_total, input_sum);
        }
        required = Amount::from_atomic(output_total);
    };

    Ok(PreparedVestingTransaction {
        inputs: selected
            .into_iter()
            .map(|utxo| prepare_input(utxo, keys))
            .collect::<Result<_>>()?,
        recipient_spend,
        recipient_view,
        amount,
        unlock_height,
        change_amount: input_sum.as_atomic().saturating_sub(output_total),
        estimated_fee,
        current_height,
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        ring_size,
    })
}

pub fn build_prepared_vesting_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedVestingTransaction,
    rings: Vec<AllocatedRing>,
    rng: &mut R,
) -> Result<Transaction> {
    let PreparedVestingTransaction {
        inputs,
        recipient_spend,
        recipient_view,
        amount,
        unlock_height,
        change_amount,
        estimated_fee,
        current_height,
        spend_public,
        view_public,
        ring_size,
    } = prepared;

    let mut builder = TransactionBuilder::transfer().with_target_height(current_height);
    add_prepared_inputs(&mut builder, inputs, rings, ring_size)?;
    builder.add_output(
        &Recipient {
            spend_public: recipient_spend,
            view_public: recipient_view,
            amount,
            lock_height: Some(unlock_height),
        },
        0,
        rng,
    )?;

    let final_fee = if change_amount >= MIN_OUTPUT_AMOUNT {
        builder.add_change(
            &spend_public,
            &view_public,
            Amount::from_atomic(change_amount),
            1,
            rng,
        )?;
        estimated_fee
    } else {
        Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
    };
    for _ in 0..rng.gen_range(0..=2usize) {
        let _ = builder.add_dummy_output(rng);
    }
    builder.set_fee(final_fee);
    builder.build(rng)
}

fn prepare_input(utxo: &UTXO, keys: &KeyEpoch) -> Result<PreparedInput> {
    let locator = utxo.output_locator.ok_or_else(|| {
        Error::InvalidState(
            "wallet output has no canonical locator; run a full wallet rescan before spending"
                .into(),
        )
    })?;
    let stealth = StealthAddress {
        public_key: utxo.tx_public_key,
        tx_public_key: utxo.tx_public_key,
    };
    let one_time_secret = compute_one_time_secret(
        &stealth,
        &keys.view_secret,
        &keys.spend_secret,
        utxo.output_index,
    )?;
    let blinding = BlindingFactor::from_bytes(utxo.amount_blinding_bytes);
    Ok(PreparedInput {
        real_output: RealOutputIdentity {
            locator,
            public_key: one_time_secret.public_key(),
            commitment: PedersenCommitment::commit(utxo.amount.as_atomic(), &blinding).to_bytes(),
        },
        input: SpendableInput {
            tx_hash: utxo.tx_hash,
            output_index: utxo.output_index,
            amount: utxo.amount,
            one_time_secret,
            blinding,
            height: utxo.height,
        },
    })
}

fn add_prepared_inputs(
    builder: &mut TransactionBuilder,
    inputs: Vec<PreparedInput>,
    rings: Vec<AllocatedRing>,
    ring_size: usize,
) -> Result<()> {
    if inputs.len() != rings.len() {
        return Err(Error::InvalidState(
            "ring allocation does not match selected inputs".into(),
        ));
    }

    let real_public_keys: HashSet<_> = inputs
        .iter()
        .map(|prepared| *prepared.real_output.public_key.as_bytes())
        .collect();
    let mut decoy_public_keys = HashSet::new();

    for (prepared, ring) in inputs.into_iter().zip(rings) {
        if ring.decoys.len() + 1 != ring_size {
            return Err(Error::InvalidRingSize {
                expected: ring_size,
                got: ring.decoys.len() + 1,
            });
        }
        if ring.real_position >= ring_size {
            return Err(Error::InvalidState(format!(
                "real position {} is outside ring size {}",
                ring.real_position, ring_size
            )));
        }
        for decoy in &ring.decoys {
            let key = *decoy.public_key.as_bytes();
            if real_public_keys.contains(&key) {
                return Err(Error::InvalidState(
                    "allocated decoy duplicates a transaction real output".into(),
                ));
            }
            if !decoy_public_keys.insert(key) {
                return Err(Error::InvalidState(
                    "allocated decoy is reused across transaction inputs".into(),
                ));
            }
        }
        builder.add_input(prepared.input, ring.decoys, ring.real_position)?;
    }
    Ok(())
}

fn scaled_fee(
    input_count: usize,
    output_count: usize,
    ring_size: usize,
    multiplier_x100: u64,
) -> Amount {
    Amount::from_atomic(
        (estimate_tx_size(input_count, output_count, ring_size) as u64)
            .saturating_mul(MIN_FEE_PER_BYTE)
            .saturating_mul(multiplier_x100)
            / 100,
    )
}

fn ensure_spendable(
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
            seconds_to_wait: blocks_to_wait.saturating_mul(crate::constants::TARGET_BLOCK_TIME),
        });
    }

    Err(Error::InsufficientBalance {
        have: available.as_atomic(),
        need: need.as_atomic(),
    })
}

/// Select UTXOs to cover the required amount.
