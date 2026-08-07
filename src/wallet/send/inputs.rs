use super::super::decoy_selection::{AllocatedRing, RealOutputIdentity};
use super::super::{KeyEpoch, UTXO};
use super::types::PreparedInput;
use crate::crypto::{compute_one_time_secret, BlindingFactor, PedersenCommitment, StealthAddress};
use crate::error::{Error, Result};
use crate::transaction::{SpendableInput, TransactionBuilder};
use std::collections::HashSet;

pub(super) fn prepare_input(utxo: &UTXO, keys: &KeyEpoch) -> Result<PreparedInput> {
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

pub(super) fn add_prepared_inputs(
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
