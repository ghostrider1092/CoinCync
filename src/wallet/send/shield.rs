//! # Shield-in (transparent → shielded) transaction assembly
//!
//! Builds a **shield-in** transaction: a normal CLSAG spend of transparent
//! UTXOs whose value, instead of (or in addition to) going to transparent
//! outputs, is *minted into the Lelantus-Spark pool*. It is the send-side
//! counterpart to the consensus **value bridge**
//! (`chain::verify_transparent_shielded_balance` +
//! `spark_payload::verify_mint_shield_in`).
//!
//! ## What makes a shield-in valid (and why this is the only safe way to build one)
//!
//! A shield-in is `TxType::Shielded` and carries a [`SparkPayload`] in
//! `tx.extra` with:
//!   * `mint = Some(bundle)` — an authenticated libspark `MintTransaction` over
//!     the shielded value (per-coin Schnorr value proof), and
//!   * `value_balance = -(shield_amount)` — value leaving the transparent side.
//!
//! Consensus (Step-1 shield-in authentication + the value bridge) then enforces:
//!   1. the transparent inputs are real spends — CLSAG, key images, ring
//!      membership, range proofs on the *change* outputs — exactly like a
//!      transfer (so value cannot be conjured on the transparent side), and
//!   2. `Σ pseudo_outputs = Σ transparent_outputs + (fee − value_balance)·H`,
//!      i.e. `Σ pseudo = Σ change + (fee + shield_amount)·H` — the shielded
//!      amount leaves as *public* value committed with **zero blinding**,
//!      exactly like the fee, and
//!   3. the mint bundle's authenticated value equals `−value_balance`
//!      (`verify_mint_shield_in`), so the pool grows by precisely what left the
//!      transparent side — no inflation, no burn.
//!
//! The pseudo-output blinding balance (`Σ r'ᵢ = Σ r_change`) is therefore
//! **unchanged** from an ordinary transfer; [`TransactionBuilder`] only needs to
//! know that `shield_amount` is extra public value on the output side, which it
//! is told via [`TransactionBuilder::with_shielded_value_out`]. The mint bundle
//! is bound to *these exact inputs* through its serial context
//! (`serial_context(derive_outpoint(input_key_images, 0))`); consensus
//! re-derives the identical context from the tx's inputs at apply, so a bundle
//! built for one set of inputs cannot be replayed onto another.

#[cfg(feature = "libspark-ffi")]
use crate::constants::MIN_OUTPUT_AMOUNT;
#[cfg(feature = "libspark-ffi")]
use crate::error::{Error, Result};
#[cfg(feature = "libspark-ffi")]
use crate::primitives::{Amount, PublicKey};
#[cfg(feature = "libspark-ffi")]
use crate::transaction::{
    DecoyOutput, OneTimeKeyRef, SoftwareSigner, SpendableInput, Transaction, TransactionBuilder,
    TxSigner, TxType,
};
#[cfg(feature = "libspark-ffi")]
use rand::{CryptoRng, RngCore};

/// Build a signed shield-in transaction that moves `shield_amount` of a
/// transparent UTXO into the Spark pool, returning any remainder as transparent
/// change to the wallet's own (`change_spend_public`, `change_view_public`).
///
/// `input` is the transparent UTXO being spent; `decoys` are its ring decoys
/// (ring size = `decoys.len() + 1`, selected by the caller from a covered
/// locator snapshot, exactly as a transfer). `spark_seed` is the wallet's
/// Spark key seed (the mint coins are recoverable from it).
///
/// Balance: `input.amount == shield_amount + fee + change`. If the change would
/// be below [`MIN_OUTPUT_AMOUNT`] it is folded into the fee and a dummy output
/// is emitted instead (never a dust change output), matching the privacy rules
/// used by the transparent assembly path.
///
/// Errors:
///   * [`Error::InsufficientBalance`] if the input cannot cover
///     `shield_amount + fee`,
///   * [`Error::AmountOverflow`] on arithmetic overflow,
///   * [`Error::CryptoError`] if the libspark mint bundle cannot be built.
///
/// Submit the returned transaction via the generic `send_raw_transaction` RPC
/// (borsh-encoded); it propagates through the mempool and Dandelion++ like any
/// other transaction.
#[cfg(feature = "libspark-ffi")]
#[allow(clippy::too_many_arguments)]
pub fn build_shield_in<R: RngCore + CryptoRng>(
    change_spend_public: &PublicKey,
    change_view_public: &PublicKey,
    input: SpendableInput,
    decoys: Vec<DecoyOutput>,
    shield_amount: Amount,
    fee: Amount,
    target_height: u64,
    spark_seed: &[u8],
    rng: &mut R,
) -> Result<Transaction> {
    let input_atomic = input.amount.as_atomic();
    let shield_atomic = shield_amount.as_atomic();
    let fee_atomic = fee.as_atomic();

    // Value check: the input must cover the shielded amount plus the fee.
    let need = shield_atomic
        .checked_add(fee_atomic)
        .ok_or(Error::AmountOverflow)?;
    let change = input_atomic
        .checked_sub(need)
        .ok_or(Error::InsufficientBalance {
            have: input_atomic,
            need,
        })?;

    // Derive the input's key image EXACTLY as the builder will (software signer,
    // from the per-output one-time secret). Consensus derives each coin's serial
    // context from `borsh(key_image)` of every input (chain::apply, value
    // bridge), so the mint bundle MUST be bound to this same value or the
    // re-derived context will not match and `verify_mint_shield_in` fails. This
    // is why the bundle is built here, after we know the real input — not ahead
    // of time.
    let key_ref = OneTimeKeyRef::from_secret(input.one_time_secret.clone());
    let key_image = SoftwareSigner.key_image(&key_ref)?;
    let input_outpoints: Vec<Vec<u8>> = vec![borsh::to_vec(&key_image)
        .map_err(|e| Error::SerializationError(format!("shield-in key-image encode: {e}")))?];

    // Build the authenticated mint payload (one coin of `shield_atomic`),
    // value_balance = -(shield_atomic). The coin's serial context binds to the
    // input key image above.
    let (payload, _contexts) = crate::consensus::spark_payload::build::build_mint_payload(
        spark_seed,
        &[shield_atomic],
        &input_outpoints,
    )
    .ok_or_else(|| Error::CryptoError("shield-in: libspark mint bundle build failed".into()))?;
    debug_assert_eq!(payload.value_balance, -(shield_atomic as i64));
    let extra = payload.encode();

    // Assemble the transparent spend. `with_shielded_value_out` tells the
    // builder that `shield_atomic` is extra PUBLIC value on the output side (so
    // the plaintext balance is inputs == outputs + fee + shield_atomic) while
    // leaving the pseudo-output blinding balance unchanged. `extra` carries the
    // SparkPayload and is bound into the CLSAG signing hash, so it cannot be
    // stripped or altered.
    let mut builder = TransactionBuilder::new(TxType::Shielded)
        .with_target_height(target_height)
        .with_extra(extra)
        .with_shielded_value_out(shield_atomic);

    builder.add_input_random_position(input, decoys, rng)?;

    let final_fee = if change >= MIN_OUTPUT_AMOUNT {
        builder.add_change(
            change_spend_public,
            change_view_public,
            Amount::from_atomic(change),
            0,
            rng,
        )?;
        fee
    } else {
        // Dust change would be an unspendable, fingerprinting output: emit a
        // zero-value dummy for output-count privacy and fold the dust into the
        // fee instead. Balance still holds:
        //   inputs == 0 (dummy) + (fee + change) + shield_atomic == inputs.
        builder.add_dummy_output(rng)?;
        Amount::from_atomic(fee_atomic.checked_add(change).ok_or(Error::AmountOverflow)?)
    };

    builder.set_fee(final_fee);
    builder.build(rng)
}
