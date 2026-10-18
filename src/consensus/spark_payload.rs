//! # Spark payload (v2) — libspark coins & tags in a `TxType::Shielded` tx
//!
//! Implements [[cip-spark-block-format]]: the block/tx format that carries the
//! audited libspark engine's data (serialized `Coin`s for mints, a
//! `SpendBytes` bundle for spends) so the chain can FEED
//! [`SparkPoolStore`](crate::storage::spark_pool::SparkPoolStore) — `add_coin`
//! per mint, `mark_tag_spent` per spend — and verify against the live pool.
//!
//! Everything here is gated `sketch-gk-proof` and inert: `TxType::Shielded`
//! stays fail-closed and `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` until
//! externally audited. The functions are pure over `(store, backend)` so they
//! unit-test without touching the live chain; the actual verification uses
//! whatever `SparkBackend` the caller passes (the fail-closed `StubBackend`
//! without `libspark-ffi`, the real libspark backend with it).

use borsh::{BorshDeserialize, BorshSerialize};
use spark_connector::{CoinBytes, Nullifier, SparkBackend, SpendBytes};

use crate::error::{Error, Result};
use crate::storage::spark_pool::SparkPoolStore;

/// Payload version for the libspark Spark format. `1` is the native sketch
/// ([`ShieldedPayload`](crate::consensus::shielded)); `2` is this.
pub const SPARK_PAYLOAD_VERSION: u8 = 2;

/// A shielded spend: the pool anchor its Grootle membership is over, plus the
/// libspark verify bundle (`S1/C1/T` + Grootle + Chaum + range + balance).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SpendBundle {
    /// The cover-set group this spend anchors to (reserved; one group today).
    pub cover_set_id: u64,
    /// The pool snapshot height the cover set is resolved at (reorg-stable).
    pub anchor_height: u64,
    /// The libspark `SpendBytes` verify bundle.
    pub bundle: Vec<u8>,
}

/// The v2 shielded payload carried in `Transaction::extra` (borsh).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SparkPayload {
    /// Format version — must be [`SPARK_PAYLOAD_VERSION`].
    pub version: u8,
    /// An AUTHENTICATED shield-in mint bundle (a libspark `MintTransaction`,
    /// carrying the coins + a Schnorr value proof), when this tx shields value
    /// in. Its total authenticated value must equal the shield-in amount
    /// (`−value_balance`); the coins are fed to the pool at apply. Preferred
    /// over `outputs` — loose coins carry no value proof.
    pub mint: Option<Vec<u8>>,
    /// Legacy loose libspark-serialized coins (unauthenticated). Retained for
    /// the pre-mint-bundle path; empty for an authenticated shield-in. Superseded
    /// by `mint`.
    pub outputs: Vec<Vec<u8>>,
    /// The spend, if this tx spends shielded value.
    pub spend: Option<SpendBundle>,
    /// Transparent↔shielded value bridge (Sapling-style).
    pub value_balance: i64,
}

impl SparkPayload {
    /// Decode + version-gate a v2 payload from a tx's `extra` bytes. Rejects a
    /// wrong version or trailing bytes (fail-closed).
    pub fn decode(extra: &[u8]) -> Result<Self> {
        let payload: SparkPayload = borsh::from_slice(extra)
            .map_err(|e| Error::SerializationError(format!("spark payload v2 decode: {e}")))?;
        if payload.version != SPARK_PAYLOAD_VERSION {
            return Err(Error::SerializationError(format!(
                "spark payload version {} != {}",
                payload.version, SPARK_PAYLOAD_VERSION
            )));
        }
        Ok(payload)
    }

    /// Encode to `extra` bytes.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("SparkPayload borsh serialize is infallible")
    }
}

/// Derive a coin's deterministic outpoint from the creating tx's TRANSPARENT
/// input outpoints (fixed before the shielded outputs exist, so this is
/// non-circular — see cip-spark-block-format §serial-context) plus its vout.
/// Order-independent in the inputs (they are sorted), so every node computes the
/// same value. The coin's serial context is `serial_context(outpoint)`.
pub fn derive_outpoint(input_outpoints: &[Vec<u8>], vout: u32) -> Vec<u8> {
    let mut sorted: Vec<&Vec<u8>> = input_outpoints.iter().collect();
    sorted.sort();
    let mut h = blake3::Hasher::new();
    h.update(b"COINCYNC_SPARK_OUTPOINT_v1");
    h.update(&(sorted.len() as u64).to_le_bytes());
    for op in sorted {
        h.update(&(op.len() as u64).to_le_bytes());
        h.update(op);
    }
    h.update(&vout.to_le_bytes());
    h.finalize().as_bytes().to_vec()
}

/// Verify a v2 payload's spend against the live pool and return its VRF tags
/// (empty for a mint-only tx). Resolves the cover set from `store` at the
/// bundle's anchor, then runs `backend.verify_solvency` — which verifies the
/// libspark spend AND enforces every revealed tag `T ∉ store.spent_tags()`.
/// Fail-closed: any verification failure (including the fail-closed
/// `StubBackend`) is an `Err`. This is the store-aware, pre-apply check.
pub fn verify_spark_payload<B: SparkBackend>(
    store: &SparkPoolStore,
    backend: &B,
    payload: &SparkPayload,
    fee: u64,
) -> Result<Vec<Nullifier>> {
    if payload.version != SPARK_PAYLOAD_VERSION {
        return Err(Error::SparkVerifyFailed);
    }
    let Some(sb) = &payload.spend else {
        // Mint-only tx: no spend bundle to verify here. Each mint coin's own
        // value/range binding is authenticated by `verify_mint_shield_in`
        // (libspark `verify_mint_bundle`) at the block-verify caller, which also
        // requires a shield-in to carry that bundle and rejects bare outputs.
        return Ok(Vec::new());
    };
    let cover = store.cover_set_at(sb.cover_set_id, sb.anchor_height);
    let tags = backend
        .verify_solvency(
            &cover,
            &SpendBytes(sb.bundle.clone()),
            fee,
            payload.value_balance,
            &store.spent_tags(),
        )
        .map_err(|e| Error::CryptoError(format!("spark v2 verify: {e}")))?;
    Ok(tags)
}

/// BATCH-verify a block's v2 payloads. Groups the spend payloads by
/// `(cover_set_id, anchor_height)`, reconstructs each group's node-authoritative
/// cover set ONCE, and verifies the group's spend proofs TOGETHER via
/// [`SparkBackend::verify_spend_batch`] — one shared cover-set multiexp
/// amortized across the group (~Kx cheaper than K single verifies; see
/// docs/design/cip-shielded-anonset.md). Mint-only payloads (no spend)
/// contribute no proof. Each spend's revealed linking tags are checked UNSPENT
/// against the pool's spent set (the solvency half of `verify_solvency`).
///
/// Returns per-payload tags in the SAME order as `items` (mint-only → empty),
/// so the caller can run its own within-block duplicate-tag check. Fail-closed:
/// any group failing (bad proof, or a tag already spent) rejects the whole batch
/// — matching block-level all-or-nothing verification. Equivalent to calling
/// [`verify_spark_payload`] per item, but amortized.
pub fn verify_spark_payloads_batch<B: SparkBackend>(
    store: &SparkPoolStore,
    backend: &B,
    items: &[(SparkPayload, u64)],
) -> Result<Vec<Vec<Nullifier>>> {
    use std::collections::HashMap;
    let mut out: Vec<Vec<Nullifier>> = vec![Vec::new(); items.len()];
    // Group spend payloads by their anchored cover set; mint-only items are left
    // with empty tags (as `verify_spark_payload` returns for them).
    let mut groups: HashMap<(u64, u64), Vec<usize>> = HashMap::new();
    for (i, (payload, _fee)) in items.iter().enumerate() {
        if payload.version != SPARK_PAYLOAD_VERSION {
            return Err(Error::SparkVerifyFailed);
        }
        if let Some(sb) = &payload.spend {
            groups
                .entry((sb.cover_set_id, sb.anchor_height))
                .or_default()
                .push(i);
        }
    }
    let spent = store.spent_tags();
    for ((cover_set_id, anchor_height), idxs) in groups {
        let cover = store.cover_set_at(cover_set_id, anchor_height);
        let bundles: Vec<SpendBytes> = idxs
            .iter()
            .map(|&i| SpendBytes(items[i].0.spend.as_ref().unwrap().bundle.clone()))
            .collect();
        let fees: Vec<u64> = idxs.iter().map(|&i| items[i].1).collect();
        let vbs: Vec<i64> = idxs.iter().map(|&i| items[i].0.value_balance).collect();
        let group_tags = backend
            .verify_spend_batch(&cover, &bundles, &fees, &vbs)
            .map_err(|e| Error::CryptoError(format!("spark v2 batch verify: {e}")))?;
        if group_tags.len() != idxs.len() {
            return Err(Error::CryptoError(
                "spark v2 batch: tag-list count != spend count".into(),
            ));
        }
        for (slot, &i) in idxs.iter().enumerate() {
            let tags = &group_tags[slot];
            for t in tags {
                if spent.contains(t) {
                    return Err(Error::CryptoError(
                        "spark v2 batch: linking tag already spent (coin is not unspent)".into(),
                    ));
                }
            }
            out[i] = tags.clone();
        }
    }
    Ok(out)
}

/// Apply an ALREADY-VERIFIED v2 payload to the pool, in the chain's apply path
/// (after the block's checkpoint). Marks each spend tag spent (with a
/// double-spend guard) FIRST, then adds each mint coin keyed by its derived
/// outpoint with the caller-supplied context. `output_contexts[i]` must be
/// `serial_context(derive_outpoint(input_outpoints, i))` — the caller computes
/// it (the FFI lives at the edge, keeping this function pure).
///
/// A double-spend here means validation admitted an invalid block; the caller
/// treats the `Err` as a consensus fault (halt), mirroring `apply_shielded_txs`.
pub fn apply_spark_payload(
    store: &SparkPoolStore,
    payload: &SparkPayload,
    input_outpoints: &[Vec<u8>],
    output_contexts: &[Vec<u8>],
    tags: &[Nullifier],
    height: u64,
) -> Result<()> {
    if payload.outputs.len() != output_contexts.len() {
        return Err(Error::CryptoError(
            "spark v2 apply: output_contexts length mismatch".into(),
        ));
    }
    // Spends first: a double-spend must add no coins.
    for tag in tags {
        if !store.mark_tag_spent(tag, height) {
            return Err(Error::CryptoError(
                "spark v2 apply: linking tag already spent (validation should have rejected)".into(),
            ));
        }
    }
    // Then mints: each coin keyed by its deterministic outpoint.
    for (vout, coin) in payload.outputs.iter().enumerate() {
        let outpoint = derive_outpoint(input_outpoints, vout as u32);
        if store
            .add_coin(
                outpoint,
                CoinBytes(coin.clone()),
                output_contexts[vout].clone(),
                height,
            )
            .is_none()
        {
            return Err(Error::CryptoError(
                "spark v2 apply: duplicate coin outpoint (validation should have rejected)".into(),
            ));
        }
    }
    Ok(())
}

/// The transparent↔shielded value BRIDGE. A shielded tx's public
/// `value_balance` must be backed by its transparent commitments, or value
/// could be shielded/unshielded that the transparent side never moved. This
/// extends the homomorphic transparent balance equation
/// `Σ pseudo_outputs == Σ outputs + fee·H` with the value crossing the veil:
///
/// ```text
///   Σ pseudo_outputs == Σ outputs + (fee − value_balance)·H
/// ```
///
/// - `value_balance > 0` (UNSHIELD out): transparent outputs exceed inputs by
///   it — the pool paid it out.
/// - `value_balance < 0` (SHIELD in): transparent inputs exceed outputs+fee by
///   |it| — that value went into the pool.
/// - `value_balance == 0`: reduces exactly to the plain transparent balance.
///
/// This is the CoinCync-side half of value conservation: it ties `value_balance`
/// to the transparent commitments. The SHIELDED-side half (that the shielded
/// inputs/outputs themselves net to `value_balance`) is proven by the libspark
/// spend bundle's own internal balance proof; the per-MINT value/range binding
/// (mint coin values sum to the shielded-in amount) is the remaining
/// libspark-value-model follow-up noted in cip-spark-block-format.md.
///
/// Blinding factors must still balance (`Σ in_blinding == Σ out_blinding`), since
/// the `(fee − value_balance)·H` term carries zero blinding — exactly as the
/// transparent equation requires. Fail-closed on any non-canonical point or a
/// mismatch.
pub fn verify_transparent_shielded_balance(
    pseudo_outputs: &[[u8; 32]],
    output_commitments: &[[u8; 32]],
    fee: u64,
    value_balance: i64,
) -> Result<()> {
    use crate::crypto::{BlindingFactor, PedersenCommitment};
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::traits::Identity;

    let decode = |b: &[u8; 32]| -> Result<RistrettoPoint> {
        CompressedRistretto(*b)
            .decompress()
            .ok_or(Error::SparkVerifyFailed)
    };

    // Σ pseudo-output commitments (reject identity — an identity input collapses
    // the balance equation, the same inflation hole §44 guards in validation).
    let mut input_sum = RistrettoPoint::identity();
    for p in pseudo_outputs {
        let pt = decode(p)?;
        if pt == RistrettoPoint::identity() {
            return Err(Error::SparkVerifyFailed);
        }
        input_sum += pt;
    }
    let mut output_sum = RistrettoPoint::identity();
    for c in output_commitments {
        output_sum += decode(c)?;
    }

    let fee_pt = PedersenCommitment::commit(fee, &BlindingFactor::zero())
        .as_point()
        .decompress()
        .ok_or(Error::SparkVerifyFailed)?;
    let vb_pt = PedersenCommitment::commit(value_balance.unsigned_abs(), &BlindingFactor::zero())
        .as_point()
        .decompress()
        .ok_or(Error::SparkVerifyFailed)?;

    // expected = Σ outputs + (fee − value_balance)·H
    let expected = if value_balance >= 0 {
        output_sum + fee_pt - vb_pt
    } else {
        output_sum + fee_pt + vb_pt
    };
    if input_sum != expected {
        return Err(Error::CryptoError(
            "shielded value bridge: transparent commitments do not back value_balance \
             (possible cross-veil inflation)"
                .into(),
        ));
    }
    Ok(())
}

/// The SHIELDED-side half of shield-in value conservation: the value entering
/// the pool (`−value_balance`, a shield has `value_balance < 0`) must equal the
/// total AUTHENTICATED value of the minted coins. `verify_mint_bundle` verifies
/// the libspark Schnorr value proof (each coin's commitment opens to its public
/// value) and returns `Σ v`; this requires that sum to match the shield-in
/// amount. Combined with `verify_transparent_shielded_balance` (which ties
/// `value_balance` to the transparent commitments), shield-in fully conserves:
/// `transparent in == value_balance == Σ authenticated mint v`. Gated
/// `libspark-ffi` (needs the real backend). Fail-closed.
#[cfg(feature = "libspark-ffi")]
pub fn verify_mint_shield_in(mint_bundle: &[u8], value_balance: i64) -> Result<()> {
    if value_balance >= 0 {
        return Err(Error::CryptoError(
            "mint shield-in requires value_balance < 0 (value entering the pool)".into(),
        ));
    }
    let (total, _coins) = spark_connector::ffi::verify_mint_bundle(mint_bundle)
        .ok_or_else(|| Error::CryptoError("mint bundle failed value-proof verification".into()))?;
    let shield_in = (value_balance as i128).unsigned_abs();
    if (total as u128) != shield_in {
        return Err(Error::CryptoError(format!(
            "mint total {total} != shield-in amount {shield_in} (value_balance {value_balance})"
        )));
    }
    Ok(())
}

/// Mint- and spend-side v2 payload BUILDERS (the wallet side). Gated on
/// `libspark-ffi` — they call the real backend to mint coins and build spend
/// bundles. This is the send-side counterpart to the verify/apply feed:
/// together they let a full mint → pool → spend → verify → apply loop be
/// assembled (cip-spark-block-format build-order step 5 prep).
#[cfg(feature = "libspark-ffi")]
pub mod build {
    use super::*;
    use spark_connector::ffi::{
        build_mint_bundle, build_spend_over_set, build_spend_to_address, serial_context,
    };

    /// Build an AUTHENTICATED mint-side (shield-in) payload: one libspark
    /// `MintTransaction` over `values`, carrying a per-coin Schnorr value proof
    /// so a verifier trusts each coin's public value (the per-mint value/range
    /// binding). All coins share ONE tx-level serial context
    /// `serial_context(derive_outpoint(tx_input_outpoints, 0))` — safe because
    /// each coin's serial (hence linking tag) is made distinct by libspark's
    /// per-coin random nonce, not the context (verified against the vendored
    /// serial derivation, `coin.cpp` s = hash_ser(k, ctx) + …). The coins are
    /// extracted from the verified bundle at apply, so `outputs` stays EMPTY;
    /// `value_balance = -(Σ values)` (shield-IN is negative). Returns the payload
    /// plus the shared context (apply re-derives the identical one). `None` on
    /// any FFI failure.
    pub fn build_mint_payload(
        seed: &[u8],
        values: &[u64],
        tx_input_outpoints: &[Vec<u8>],
    ) -> Option<(SparkPayload, Vec<Vec<u8>>)> {
        let shared_ctx = serial_context(&derive_outpoint(tx_input_outpoints, 0))?;
        let bundle = build_mint_bundle(seed, values, &shared_ctx)?;
        let value_balance = -(values.iter().sum::<u64>() as i64);
        Some((
            SparkPayload {
                version: SPARK_PAYLOAD_VERSION,
                mint: Some(bundle),
                // Coins enter via the verified mint bundle at apply, not bare
                // outputs — an unauthenticated `outputs` entry is rejected at
                // verify (no value proof).
                outputs: Vec::new(),
                spend: None,
                value_balance,
            },
            vec![shared_ctx; values.len()],
        ))
    }

    /// Build a spend-side payload spending the pool coin at `owned_outpoint`,
    /// paying `output_value` back to the wallet, anchored at `(cover_set_id,
    /// anchor_height)`. `None` if the coin is not in the anchored cover set or
    /// the FFI fails. (The owned coin's index within the anchored set must equal
    /// its store index — true when the anchor includes it; a partial-height
    /// anchor that reorders is a follow-up.)
    pub fn build_spend_payload(
        seed: &[u8],
        store: &SparkPoolStore,
        owned_outpoint: &[u8],
        output_value: u64,
        fee: u64,
        cover_set_id: u64,
        anchor_height: u64,
    ) -> Option<SparkPayload> {
        build_spend_payload_inner(
            seed,
            store,
            owned_outpoint,
            output_value,
            fee,
            cover_set_id,
            anchor_height,
            None,
        )
    }

    /// Build a TRANSFER payload: spend the pool coin at `owned_outpoint`, pay
    /// `output_value` to `recipient_addr` (a bech32m Spark address, as bytes) —
    /// a shielded→shielded send to another wallet — and burn `fee`. The remainder
    /// (`input − output_value − fee`) returns to the SENDER as a change coin, so
    /// nothing beyond `fee` is burned. Both output coins re-enter the pool at
    /// apply (recoverable by the recipient and sender respectively);
    /// `value_balance = 0` — nothing crosses the veil. `None` if the coin is not
    /// in the anchored cover set, the recipient is empty, or the FFI fails.
    pub fn build_transfer_payload(
        seed: &[u8],
        store: &SparkPoolStore,
        owned_outpoint: &[u8],
        output_value: u64,
        fee: u64,
        cover_set_id: u64,
        anchor_height: u64,
        recipient_addr: &[u8],
    ) -> Option<SparkPayload> {
        if recipient_addr.is_empty() {
            return None;
        }
        build_spend_payload_inner(
            seed,
            store,
            owned_outpoint,
            output_value,
            fee,
            cover_set_id,
            anchor_height,
            Some(recipient_addr),
        )
    }

    /// Build an UNSHIELD payload: spend the pool coin at `owned_outpoint`, send
    /// `unshield_value` OUT of the pool to the transparent side (the wallet
    /// materializes it as a value-revealing transparent output — public value,
    /// ZERO blinding, exactly like a coinbase output), and pay `miner_fee` to
    /// the miner. The remainder (`note_value − unshield_value − miner_fee`)
    /// returns to the spender as a pool CHANGE coin.
    ///
    /// `value_balance = unshield_value + miner_fee` — POSITIVE: the WHOLE amount
    /// crossing the veil OUT of the pool (unshielded value + miner fee). This is
    /// exactly the spend bundle's internal fee (`input − Σ pool outputs`), so the
    /// `value_balance == spend_fee(bundle)` inflation guard in
    /// `chain::verify_block_spark_v2` holds with no new branch — unshield and a
    /// pure transfer differ only in the WALLET's transparent assembly:
    ///   * transfer: `tx.fee == value_balance`, no transparent outputs; the
    ///     transparent value bridge forces `Σ out = 0`.
    ///   * unshield: `tx.fee == miner_fee` and ONE transparent output committing
    ///     `unshield_value` with zero blinding; the bridge
    ///     `Σ pseudo == Σ out + (fee − value_balance)·H` reduces to
    ///     `0 == unshield·H + (miner_fee − (unshield + miner_fee))·H = 0`. ✓
    ///
    /// `None` if the coin is not in the anchored cover set, the note cannot cover
    /// `unshield_value + miner_fee` with a positive pool change, or the FFI fails.
    /// A FULL unshield (no pool change) is rejected here — it would need a
    /// zero-value pool output; splitting the note first is the workaround (a
    /// change-less-unshield is a follow-up).
    #[allow(clippy::too_many_arguments)]
    pub fn build_unshield_payload(
        seed: &[u8],
        store: &SparkPoolStore,
        owned_outpoint: &[u8],
        note_value: u64,
        unshield_value: u64,
        miner_fee: u64,
        cover_set_id: u64,
        anchor_height: u64,
    ) -> Option<SparkPayload> {
        if unshield_value == 0 {
            return None;
        }
        // Total value leaving the pool across the veil = the bundle's internal
        // fee. The pool change (what stays in the pool) must be strictly
        // positive — a zero-value pool output is rejected (see docstring).
        let leaving = unshield_value.checked_add(miner_fee)?;
        let pool_change = note_value.checked_sub(leaving)?;
        if pool_change == 0 {
            return None;
        }
        build_spend_payload_inner(
            seed,
            store,
            owned_outpoint,
            pool_change, // output_value: the change coin re-entering the pool
            leaving,     // fee: the whole amount leaving the pool (bundle getFee)
            cover_set_id,
            anchor_height,
            None, // self-spend: the pool change returns to the spender
        )
        // value_balance = `leaving` = unshield_value + miner_fee (set by inner).
    }

    /// Shared spend/transfer builder. `recipient_addr = None` → self-spend
    /// (change back to the spender); `Some(addr)` → transfer to that address.
    /// `fee` is the pool-internal fee burned; the remainder returns to the
    /// spender as change.
    #[allow(clippy::too_many_arguments)]
    fn build_spend_payload_inner(
        seed: &[u8],
        store: &SparkPoolStore,
        owned_outpoint: &[u8],
        output_value: u64,
        fee: u64,
        cover_set_id: u64,
        anchor_height: u64,
        recipient_addr: Option<&[u8]>,
    ) -> Option<SparkPayload> {
        let cover = store.cover_set_at(cover_set_id, anchor_height);
        let ctx = store.context_for(owned_outpoint)?;
        let idx = store.index_of(owned_outpoint)? as usize;
        if idx >= cover.len() {
            return None; // owned coin not inside the anchored cover set
        }
        let bundle = match recipient_addr {
            Some(addr) => build_spend_to_address(seed, &cover, idx, &ctx, output_value, fee, addr)?,
            None => build_spend_over_set(seed, &cover, idx, &ctx, output_value, fee)?,
        };
        Some(SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            mint: None,
            outputs: vec![],
            spend: Some(SpendBundle {
                cover_set_id,
                anchor_height,
                bundle: bundle.0,
            }),
            // The value crossing the veil on a pure pool→pool spend is exactly
            // the bundle's internal fee (`input − Σ pool outputs`), which goes to
            // the miner. `value_balance` must equal it (consensus binds the two in
            // `chain::verify_block_spark_v2`), and the Transaction wrapper sets
            // `tx.fee == value_balance` so the transparent value bridge holds and
            // `total_fees` claims the fee. For a free transfer `fee == 0`.
            value_balance: fee as i64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit_bytes(value: u64, blinding: [u8; 32]) -> [u8; 32] {
        use crate::crypto::{BlindingFactor, PedersenCommitment};
        PedersenCommitment::commit(value, &BlindingFactor::from_bytes(blinding)).to_bytes()
    }

    #[test]
    fn value_bridge_balances_shield_unshield_and_zero() {
        let r = [7u8; 32]; // equal blinding in/out so the blinding side cancels

        // SHIELD 100 in (value_balance = -100), fee 0: transparent inputs (150)
        // exceed outputs (50) by 100 → that 100 went into the pool.
        assert!(verify_transparent_shielded_balance(
            &[commit_bytes(150, r)],
            &[commit_bytes(50, r)],
            0,
            -100,
        )
        .is_ok());

        // UNSHIELD 120 out (value_balance = +120), fee 0: outputs (170) exceed
        // inputs (50) by 120 → the pool paid 120 out.
        assert!(verify_transparent_shielded_balance(
            &[commit_bytes(50, r)],
            &[commit_bytes(170, r)],
            0,
            120,
        )
        .is_ok());

        // value_balance 0 with a fee: reduces to the plain transparent balance
        // (input == output + fee).
        assert!(verify_transparent_shielded_balance(
            &[commit_bytes(100, r)],
            &[commit_bytes(90, r)],
            10,
            0,
        )
        .is_ok());
    }

    #[test]
    fn value_bridge_rejects_unbacked_value_and_identity() {
        let r = [9u8; 32];
        // Claim to shield 100 but transparent side only moved 99 → rejected
        // (cross-veil inflation of 1).
        assert!(verify_transparent_shielded_balance(
            &[commit_bytes(150, r)],
            &[commit_bytes(50, r)],
            0,
            -99,
        )
        .is_err());
        // Wrong sign (claims unshield when the transparent side shielded).
        assert!(verify_transparent_shielded_balance(
            &[commit_bytes(150, r)],
            &[commit_bytes(50, r)],
            0,
            100,
        )
        .is_err());
        // Identity pseudo-output is rejected (balance-collapse guard).
        assert!(verify_transparent_shielded_balance(
            &[[0u8; 32]],
            &[commit_bytes(50, r)],
            0,
            -100,
        )
        .is_err());
    }

    #[test]
    fn payload_round_trips_and_version_gate() {
        let p = SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            mint: None,
            outputs: vec![vec![1u8; 40], vec![2u8; 40]],
            spend: Some(SpendBundle {
                cover_set_id: 7,
                anchor_height: 100,
                bundle: vec![9u8; 64],
            }),
            value_balance: -500,
        };
        let bytes = p.encode();
        assert_eq!(SparkPayload::decode(&bytes).unwrap(), p);

        // Wrong version → rejected.
        let mut bad = p.clone();
        bad.version = 1;
        assert!(SparkPayload::decode(&bad.encode()).is_err());
        // Garbage → rejected.
        assert!(SparkPayload::decode(&[0xFFu8; 3]).is_err());
    }

    #[test]
    fn derive_outpoint_is_deterministic_and_order_independent() {
        let a = vec![1u8; 36];
        let b = vec![2u8; 36];
        let o1 = derive_outpoint(&[a.clone(), b.clone()], 0);
        let o2 = derive_outpoint(&[b.clone(), a.clone()], 0); // reversed order
        assert_eq!(o1, o2, "input order must not change the outpoint");
        assert_ne!(o1, derive_outpoint(&[a.clone(), b.clone()], 1), "vout distinguishes");
        assert_eq!(o1.len(), 32);
    }

    #[test]
    fn mint_only_payload_verifies_to_no_tags() {
        // A mint-only payload (no spend) needs no spend verification → empty tags.
        use spark_connector::StubBackend;
        let store = SparkPoolStore::new();
        let p = SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            mint: None,
            outputs: vec![vec![1u8; 40]],
            spend: None,
            value_balance: 1000,
        };
        let tags = verify_spark_payload(&store, &StubBackend, &p, 0).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn spend_payload_is_fail_closed_under_stub_backend() {
        // With no real backend, a spend payload must fail closed (StubBackend
        // rejects verify_spend), so the tx is never admitted.
        use spark_connector::StubBackend;
        let store = SparkPoolStore::new();
        let p = SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            mint: None,
            outputs: vec![],
            spend: Some(SpendBundle {
                cover_set_id: 0,
                anchor_height: 0,
                bundle: vec![0u8; 32],
            }),
            value_balance: 0,
        };
        assert!(verify_spark_payload(&store, &StubBackend, &p, 0).is_err());
    }

    #[test]
    fn apply_feeds_pool_and_guards_double_spend() {
        // apply_spark_payload: mints get added by outpoint; a tag already in the
        // pool's spent-set is rejected (double-spend guard).
        let store = SparkPoolStore::new();
        let inputs = vec![vec![0xABu8; 36]];
        let payload = SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            mint: None,
            outputs: vec![vec![1u8; 40], vec![2u8; 40]],
            spend: None,
            value_balance: 0,
        };
        let ctxs = vec![b"ctx0".to_vec(), b"ctx1".to_vec()];
        let tags = vec![Nullifier(vec![0x55u8; 34])];
        apply_spark_payload(&store, &payload, &inputs, &ctxs, &tags, 10).unwrap();
        assert_eq!(store.coin_count(), 2, "both mints added");
        assert!(store.is_tag_spent(&Nullifier(vec![0x55u8; 34])), "tag marked spent");

        // Re-applying the same tag → double-spend error.
        let empty = SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            mint: None,
            outputs: vec![],
            spend: None,
            value_balance: 0,
        };
        assert!(apply_spark_payload(&store, &empty, &inputs, &[], &tags, 11).is_err());
    }

    // Full loop over the REAL libspark backend: mint into the pool → build a v2
    // spend payload → verify_spark_payload returns the tag → apply feeds the
    // pool → the tag is now spent, so a re-verify fails.
    #[cfg(feature = "libspark-ffi")]
    #[test]
    fn end_to_end_v2_payload_verify_then_apply() {
        use spark_connector::ffi::{
            build_spend_over_set, cover_set_size, mint_to_seed, serial_context, LibsparkBackend,
        };

        let store = SparkPoolStore::new();
        let seed = b"v2-payload-seed";
        let n = cover_set_size().unwrap();
        // Seed the pool with N coins at height 1 (each keyed by a synthetic outpoint).
        for i in 0..n {
            let outpoint = format!("v2:seed:{i}").into_bytes();
            let ctx = serial_context(&outpoint).unwrap();
            let coin = mint_to_seed(seed, 10_000 + i as u64, &ctx).unwrap();
            store.add_coin(outpoint, coin, ctx, 1).unwrap();
        }

        // Build a spend over the anchored cover set, spending index 2.
        let spend_index = 2usize;
        let owned_op = format!("v2:seed:{spend_index}").into_bytes();
        let ctx = store.context_for(&owned_op).unwrap();
        let cover = store.cover_set_at(0, 1);
        let bundle = build_spend_over_set(seed, &cover, spend_index, &ctx, 3_000, 0).unwrap();

        let payload = SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            mint: None,
            outputs: vec![], // spend-only for this test
            spend: Some(SpendBundle {
                cover_set_id: 0,
                anchor_height: 1,
                bundle: bundle.0,
            }),
            value_balance: 0,
        };

        let backend = LibsparkBackend;
        // Verify → returns exactly one tag; unspent so it passes.
        let tags = verify_spark_payload(&store, &backend, &payload, 0).unwrap();
        assert_eq!(tags.len(), 1);

        // Apply → marks the tag spent at height 2.
        apply_spark_payload(&store, &payload, &[], &[], &tags, 2).unwrap();
        assert!(store.is_tag_spent(&tags[0]));

        // Re-verify now fails: the tag is in the spent-set (no longer unspent).
        assert!(verify_spark_payload(&store, &backend, &payload, 0).is_err());
    }

    // Shield-in value conservation: Σ(authenticated mint v) must equal
    // −value_balance, closing the loop with the transparent bridge.
    #[cfg(feature = "libspark-ffi")]
    #[test]
    fn mint_shield_in_binds_value_balance_to_authenticated_mint_total() {
        use spark_connector::ffi::{build_mint_bundle, serial_context};
        let seed = b"shield-in-seed";
        let ctx = serial_context(b"shield:tx:0").unwrap();
        let bundle = build_mint_bundle(seed, &[100, 200, 300], &ctx).unwrap(); // total 600

        // value_balance = -600 (shield 600 in) → matches the authenticated total.
        assert!(verify_mint_shield_in(&bundle, -600).is_ok());
        // Understated shield-in (mint 600 but claim only 500 entered) → rejected.
        assert!(verify_mint_shield_in(&bundle, -500).is_err());
        // Wrong sign (unshield) → rejected.
        assert!(verify_mint_shield_in(&bundle, 600).is_err());
    }

    // The full wallet loop: mint BUILDER → apply feed → spend BUILDER → verify →
    // apply → tag spent → re-verify fails. Contexts are derived from the mint
    // tx's (synthetic) transparent inputs, exercising the non-circular
    // serial-context scheme end-to-end.
    #[cfg(feature = "libspark-ffi")]
    #[test]
    fn mint_builder_then_spend_builder_full_loop() {
        use super::build::{build_mint_payload, build_spend_payload};
        use spark_connector::ffi::{cover_set_size, LibsparkBackend};

        let store = SparkPoolStore::new();
        let seed = b"mint-builder-seed";
        let n = cover_set_size().unwrap();

        // Mint N coins via the builder, funded by a synthetic transparent input.
        let mint_inputs = vec![vec![0xEEu8; 36]];
        let values: Vec<u64> = (0..n as u64).map(|i| 10_000 + i).collect();
        let (mint_payload, contexts) =
            build_mint_payload(seed, &values, &mint_inputs).expect("build mint payload");

        // Authenticated mint: coins come from the verified mint bundle (not bare
        // `outputs`), fed with the shared tx-level serial context — exactly as
        // the chain's apply hook does (the FFI extraction lives at the edge;
        // `apply_spark_payload` stays pure). `contexts` holds that shared ctx.
        let mint = mint_payload.mint.as_ref().expect("authenticated mint bundle");
        let (_total, coins) =
            spark_connector::ffi::verify_mint_bundle(mint).expect("verify mint bundle");
        let shared_ctx = contexts[0].clone();
        for (i, coin) in coins.iter().enumerate() {
            let op = derive_outpoint(&mint_inputs, i as u32);
            assert!(store.add_coin(op, coin.clone(), shared_ctx.clone(), 1).is_some());
        }
        assert_eq!(store.coin_count(), n);

        // Spend the coin at vout 2 (its outpoint is deterministic from the mint).
        let owned_op = derive_outpoint(&mint_inputs, 2);
        let spend_payload =
            build_spend_payload(seed, &store, &owned_op, 3_000, 0, 0, 1).expect("build spend payload");

        let backend = LibsparkBackend;
        let tags = verify_spark_payload(&store, &backend, &spend_payload, 0).expect("verify spend");
        assert_eq!(tags.len(), 1);

        apply_spark_payload(&store, &spend_payload, &[], &[], &tags, 2).expect("apply spend");
        assert!(store.is_tag_spent(&tags[0]));
        assert!(
            verify_spark_payload(&store, &backend, &spend_payload, 0).is_err(),
            "double-spend of the built spend is rejected once its tag is recorded"
        );
    }
}
