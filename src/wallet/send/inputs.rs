//! # Spendable-input preparation and ring binding
//!
//! Derives the one-time secret / key material for each owned UTXO and binds the
//! prepared inputs to their allocated rings before they reach the builder.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `prepare_input` (one-time secret)** — INVARIANT: the derived one-time
//!   secret satisfies `x·G == P` for the output's stealth key, so the spend is provable.
//!   THREAT: a wrong secret makes owned funds unspendable (CLSAG rejects).
//!   TESTS: `symmetry_subaddress_payment_detected_spendable_and_decrypts`.
//! - **§2 `prepare_input` (subaddress offset)** — INVARIANT: subaddress outputs thread the
//!   per-subaddress offset `m` (`x = H(shared) + b + m`); main outputs stay byte-identical.
//!   THREAT: W-A — omitting `m` yields the wrong key image → funds unspendable.
//!   TESTS: `subaddress_output_is_spendable_wa_regression`.
//! - **§3 `prepare_input` (locator requirement)** — INVARIANT: an output with no canonical
//!   locator is refused, forcing a full rescan before it can be spent.
//!   THREAT: spending without a canonical locator would leak identity via a lookup.
//!   TESTS: (gap — no unit test pins the missing-locator error path).
//! - **§4 `add_prepared_inputs` (ring count)** — INVARIANT: the number of rings must equal the
//!   number of prepared inputs, else the call fails closed.
//!   THREAT: count mismatch → an input signs against the wrong ring.
//!   TESTS: `add_prepared_inputs_rejects_ring_count_mismatch`.
//! - **§5 `add_prepared_inputs` (ring size)** — INVARIANT: every ring's size equals the
//!   context's `expected_ring_size` (the consensus size at that height).
//!   THREAT: a wrong-sized ring is rejected by the validator → fork/liveness edge.
//!   TESTS: `build_prepared_uniform_drip_pair_emits_two_outputs_no_change`.
//! - **§6 `add_prepared_inputs` (identity binding)** — INVARIANT: rings are accepted only when
//!   their real outputs equal the prepared inputs' — no recombining across snapshots.
//!   THREAT: mixing rings from another snapshot → unprovable ring signature.
//!   TESTS: `build_prepared_uniform_standard_change_below_min_adds_dummy_and_folds_to_fee`.

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
    // W-A: a subaddress output's one-time secret needs the per-subaddress offset
    // m (H(shared) + spend_secret + m), threaded from the UTXO's recorded
    // (account,index). Main outputs (subaddress fields None) stay byte-identical.
    let effective_spend = match (utxo.subaddress_account, utxo.subaddress_index) {
        (Some(account), Some(index)) => crate::wallet::subaddress::compute_subaddress_spend_secret(
            &keys.spend_secret,
            &keys.view_secret,
            crate::wallet::subaddress::SubaddressIndex::new(account, index),
        ),
        _ => keys.spend_secret.clone(),
    };
    let one_time_secret = compute_one_time_secret(
        &stealth,
        &keys.view_secret,
        &effective_spend,
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
