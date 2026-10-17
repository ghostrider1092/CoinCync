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
#[cfg(feature = "libspark-ffi")]
use super::super::decoy_selection::{AllocatedRings, RealOutputIdentity};
#[cfg(feature = "libspark-ffi")]
use super::super::{KeyEpoch, UTXO};
#[cfg(feature = "libspark-ffi")]
use super::fee::{estimate_tx_size, scaled_fee_for_size, FeeMultiplier};
#[cfg(feature = "libspark-ffi")]
use super::inputs::prepare_input;
#[cfg(feature = "libspark-ffi")]
use super::types::PreparedInput;
#[cfg(feature = "libspark-ffi")]
use crate::constants::ring_size_at_height;

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

/// Conservative upper bound (bytes) for the libspark mint bundle a 1-coin
/// shield-in carries in `tx.extra`, added to the count-based size estimate when
/// SELECTING the funding UTXO so the chosen note always covers the real,
/// `tx.size()`-based fee (the estimator itself is blind to `extra`). Deliberately
/// generous: the final fee is computed from the ACTUAL built size, so an
/// over-estimate here only widens UTXO eligibility — it is never overpaid.
#[cfg(feature = "libspark-ffi")]
const SHIELD_IN_MINT_BUNDLE_ALLOWANCE_BYTES: usize = 4096;

/// A selected-but-not-yet-built shield-in: one funding UTXO prepared for signing,
/// plus the change destination, shield amount, and a conservative fee seed. The
/// caller resolves decoys for [`real_outputs`](Self::real_outputs) (exactly as a
/// transfer), then calls [`build_prepared_shield_in`] with the allocated ring.
///
/// Split into prepare/build so the network round-trip that fetches decoys sits
/// between them, mirroring the transparent `prepare_privacy_transaction` /
/// `build_prepared_privacy_transaction` pair.
#[cfg(feature = "libspark-ffi")]
pub struct PreparedShieldIn {
    prepared_input: PreparedInput,
    change_spend_public: PublicKey,
    change_view_public: PublicKey,
    shield_amount: Amount,
    /// Conservative fee used ONLY for UTXO coverage; the built tx pays the exact
    /// `tx.size()`-based fee, which is ≤ this by construction.
    fee_seed: Amount,
    target_height: u64,
    input_amount: Amount,
}

#[cfg(feature = "libspark-ffi")]
impl PreparedShieldIn {
    /// The single real output whose ring the caller must resolve decoys for
    /// (one-element vec so it drops straight into `build_covered_request` /
    /// `allocate_unique_rings`, exactly like a transfer's `real_outputs()`).
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        vec![self.prepared_input.real_output]
    }
    /// Consensus ring size at the target height (the ring the caller must build).
    pub fn ring_size(&self) -> usize {
        ring_size_at_height(self.target_height)
    }
    /// The funding note's value (for display).
    pub fn input_amount(&self) -> Amount {
        self.input_amount
    }
}

/// Select ONE transparent UTXO that covers `shield_amount` + fee and prepare it
/// for a shield-in spend. `build_shield_in` is single-input, so a shield-in
/// larger than any one note errors (multi-input shield-in is a follow-up). Picks
/// the SMALLEST covering note to keep larger notes intact and change minimal.
///
/// The fee seeded here is deliberately conservative (count estimate + a mint-
/// bundle allowance): it only governs which notes are eligible. The exact fee,
/// charged on the real `tx.size()`, is computed in [`build_prepared_shield_in`].
#[cfg(feature = "libspark-ffi")]
pub fn prepare_shield_in(
    utxos: &[&UTXO],
    keys: &KeyEpoch,
    shield_amount: Amount,
    fee_multiplier: f64,
    target_height: u64,
) -> Result<PreparedShieldIn> {
    if shield_amount.as_atomic() == 0 {
        return Err(Error::InvalidState("shield-in amount must be > 0".into()));
    }
    let ring_size = ring_size_at_height(target_height);
    // Coverage fee seed: the count-based estimate (1 input, 1 change/dummy
    // output) PLUS a mint-bundle allowance for the libspark bytes in tx.extra.
    let seed_bytes = estimate_tx_size(1, 1, ring_size)
        .saturating_add(SHIELD_IN_MINT_BUNDLE_ALLOWANCE_BYTES);
    let fee_seed = scaled_fee_for_size(seed_bytes, FeeMultiplier::from_f64(fee_multiplier));
    let need = shield_amount
        .as_atomic()
        .checked_add(fee_seed.as_atomic())
        .ok_or(Error::AmountOverflow)?;

    let chosen = utxos
        .iter()
        .copied()
        .filter(|u| !u.spent && u.amount.as_atomic() >= need)
        .min_by_key(|u| u.amount.as_atomic())
        .ok_or_else(|| {
            let largest = utxos
                .iter()
                .filter(|u| !u.spent)
                .map(|u| u.amount.as_atomic())
                .max()
                .unwrap_or(0);
            Error::InsufficientBalance { have: largest, need }
        })?;

    let input_amount = chosen.amount;
    let prepared_input = prepare_input(chosen, keys)?;
    Ok(PreparedShieldIn {
        prepared_input,
        change_spend_public: keys.spend_public,
        change_view_public: keys.view_public,
        shield_amount,
        fee_seed,
        target_height,
        input_amount,
    })
}

/// Finish a shield-in: convert the allocated single ring into its decoys and
/// build the signed transaction, charging the EXACT `tx.size()`-based fee.
///
/// Builds once with the conservative seed fee to measure the real serialized
/// size (the mint bundle in `tx.extra` dominates and is invisible to the count
/// estimate), then rebuilds with `size·MIN_FEE_PER_BYTE·mult`. That exact fee is
/// ≤ the seed by construction (the seed over-covers via the ×2 size margin and
/// the mint-bundle allowance), so the funding note still covers it and no fee is
/// overpaid. Returns the final transaction, ready for `send_raw_transaction`.
#[cfg(feature = "libspark-ffi")]
pub fn build_prepared_shield_in<R: RngCore + CryptoRng>(
    prepared: PreparedShieldIn,
    rings: AllocatedRings,
    fee_multiplier: f64,
    spark_seed: &[u8],
    rng: &mut R,
) -> Result<Transaction> {
    let mut iter = rings.into_iter();
    let ring = iter
        .next()
        .ok_or_else(|| Error::InvalidState("shield-in: no ring allocated for the input".into()))?;
    if iter.next().is_some() {
        return Err(Error::InvalidState(
            "shield-in: more than one ring allocated for a single input".into(),
        ));
    }
    // `into_parts` yields the ring's decoys (real excluded); `build_shield_in`
    // re-inserts the real at a random position, so the ring position is dropped.
    let (decoys, _real_position) = ring.into_parts();
    let input = prepared.prepared_input.input;
    let mult = FeeMultiplier::from_f64(fee_multiplier);

    // Pass 1: build with the conservative seed fee to learn the real size.
    let measured = build_shield_in(
        &prepared.change_spend_public,
        &prepared.change_view_public,
        input.clone(),
        decoys.clone(),
        prepared.shield_amount,
        prepared.fee_seed,
        prepared.target_height,
        spark_seed,
        rng,
    )?;
    let exact_fee = scaled_fee_for_size(measured.size(), mult);

    // The exact fee should never exceed the seed (seed over-covers). If a larger
    // mint bundle ever breaks that assumption, pay the seed fee rather than
    // underpay — the note already covers it and overpaying is always valid.
    let final_fee = if exact_fee.as_atomic() <= prepared.fee_seed.as_atomic() {
        exact_fee
    } else {
        prepared.fee_seed
    };

    // Pass 2: rebuild with the final fee. Rebuilding (rather than reusing
    // `measured`) keeps the change output exact for the fee actually charged.
    build_shield_in(
        &prepared.change_spend_public,
        &prepared.change_view_public,
        input,
        decoys,
        prepared.shield_amount,
        final_fee,
        prepared.target_height,
        spark_seed,
        rng,
    )
}
