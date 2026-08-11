use super::super::decoy_selection::{
    AllocatedRings, DecoySelectionError, RealOutputIdentity,
};
use super::super::{KeyEpoch, UTXO};
use super::types::PreparedInput;
use crate::crypto::{compute_one_time_secret, BlindingFactor, PedersenCommitment, StealthAddress};
use crate::error::{Error, Result};
use crate::transaction::{SpendableInput, TransactionBuilder};

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
        real_output: RealOutputIdentity::new(
            locator,
            one_time_secret.public_key(),
            PedersenCommitment::commit(utxo.amount.as_atomic(), &blinding).to_bytes(),
        ),
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
    rings: AllocatedRings,
    expected_ring_size: usize,
) -> Result<()> {
    if inputs.len() != rings.len() {
        return Err(DecoySelectionError::RingCountMismatch {
            expected: inputs.len(),
            got: rings.len(),
        }
        .into());
    }
    if rings.ring_size() != expected_ring_size {
        return Err(DecoySelectionError::RingSizeMismatch {
            expected: expected_ring_size,
            got: rings.ring_size(),
        }
        .into());
    }
    if !inputs
        .iter()
        .map(|prepared| prepared.real_output)
        .eq(rings.real_outputs().iter().copied())
    {
        return Err(DecoySelectionError::RingInputMismatch.into());
    }

    for (prepared, ring) in inputs.into_iter().zip(rings) {
        let (decoys, real_position) = ring.into_parts();
        builder.add_input(prepared.input, decoys, real_position)?;
    }

    Ok(())
}
