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
    /// libspark-serialized mint coins created by this tx (one per shielded vout).
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
        // Mint-only tx: no spend to verify here. (Each mint coin's own
        // value/range binding is checked separately — TODO in the mint path.)
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

/// Mint- and spend-side v2 payload BUILDERS (the wallet side). Gated on
/// `libspark-ffi` — they call the real backend to mint coins and build spend
/// bundles. This is the send-side counterpart to the verify/apply feed:
/// together they let a full mint → pool → spend → verify → apply loop be
/// assembled (cip-spark-block-format build-order step 5 prep).
#[cfg(feature = "libspark-ffi")]
pub mod build {
    use super::*;
    use spark_connector::ffi::{build_spend_over_set, mint_to_seed, serial_context};

    /// Build a mint-side payload: one coin per value, minted to the `seed`
    /// wallet and bound to the deterministic context
    /// `serial_context(derive_outpoint(tx_input_outpoints, vout))`. Returns the
    /// payload plus the per-output contexts the apply feed stores. `None` on any
    /// FFI failure.
    pub fn build_mint_payload(
        seed: &[u8],
        values: &[u64],
        tx_input_outpoints: &[Vec<u8>],
        value_balance: i64,
    ) -> Option<(SparkPayload, Vec<Vec<u8>>)> {
        let mut outputs = Vec::with_capacity(values.len());
        let mut contexts = Vec::with_capacity(values.len());
        for (vout, &v) in values.iter().enumerate() {
            let op = derive_outpoint(tx_input_outpoints, vout as u32);
            let ctx = serial_context(&op)?;
            let coin = mint_to_seed(seed, v, &ctx)?;
            outputs.push(coin.0);
            contexts.push(ctx);
        }
        Some((
            SparkPayload {
                version: SPARK_PAYLOAD_VERSION,
                outputs,
                spend: None,
                value_balance,
            },
            contexts,
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
        cover_set_id: u64,
        anchor_height: u64,
    ) -> Option<SparkPayload> {
        let cover = store.cover_set_at(cover_set_id, anchor_height);
        let ctx = store.context_for(owned_outpoint)?;
        let idx = store.index_of(owned_outpoint)? as usize;
        if idx >= cover.len() {
            return None; // owned coin not inside the anchored cover set
        }
        let bundle = build_spend_over_set(seed, &cover, idx, &ctx, output_value)?;
        Some(SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
            outputs: vec![],
            spend: Some(SpendBundle {
                cover_set_id,
                anchor_height,
                bundle: bundle.0,
            }),
            value_balance: 0,
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
        let bundle = build_spend_over_set(seed, &cover, spend_index, &ctx, 3_000).unwrap();

        let payload = SparkPayload {
            version: SPARK_PAYLOAD_VERSION,
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
        let vb: i64 = values.iter().sum::<u64>() as i64;
        let (mint_payload, contexts) =
            build_mint_payload(seed, &values, &mint_inputs, vb).expect("build mint payload");

        // Apply the mint payload → feeds the pool at height 1.
        apply_spark_payload(&store, &mint_payload, &mint_inputs, &contexts, &[], 1)
            .expect("apply mint payload");
        assert_eq!(store.coin_count(), n);

        // Spend the coin at vout 2 (its outpoint is deterministic from the mint).
        let owned_op = derive_outpoint(&mint_inputs, 2);
        let spend_payload =
            build_spend_payload(seed, &store, &owned_op, 3_000, 0, 1).expect("build spend payload");

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
