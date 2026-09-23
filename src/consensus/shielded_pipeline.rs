//! The shielded-transaction **assembly line** — the typed seams ("connectors")
//! every station on the shielded path plugs into.
//!
//! The shielded spend lifecycle is a conveyor: the wallet selects a note,
//! resolves the anonymity set it will prove membership in, builds a proof bound
//! to a spend message, and packs a [`crate::consensus::shielded::ShieldedPayload`];
//! consensus decodes it, re-resolves the *same* anonymity set, verifies the
//! proof, guards double-spends, and applies it. Each stage is a station with a
//! typed input tray and output tray, and each fails closed.
//!
//! This module owns the two **shared rails** the prover and the verifier must
//! agree on byte-for-byte, and the **swappable proof stations**:
//!
//! - [`AnonSetResolver`] — resolve the exact ordered commitment set + root a
//!   proof is built/verified against. Prover and verifier call the *same* impl,
//!   so they cannot drift. ([`StoreAnonSetResolver`] resolves it from the live
//!   [`ShieldedStore`].)
//! - [`spend_challenge`] / [`derive_serial_tag`] — the Fiat-Shamir transcript
//!   rail and serial-tag derivation, again shared by both sides.
//! - [`SpendVerifier`] — THE activation slot. The production default is
//!   [`FailClosedVerifier`] (always rejects), so no shielded tx can verify on any
//!   build until the audited compound proof is bound in here. The real
//!   Groth-Kohlweiss + compound implementation lands behind `sketch-gk-proof`.
//! - [`SpendProver`] — the wallet side, mirror of the verifier.
//!
//! Everything here speaks in **opaque proof bytes** (`&[u8]`, the bytes carried
//! in `ShieldedPayload::proof`) rather than the gated `SparkSpendProofV2` type,
//! so the assembly line compiles and is testable in the *default* build while
//! the audit-critical crypto stays gated off. See
//! docs/design/cip-shielded-txtype.md.

use crate::error::{Error, Result};
use crate::storage::shielded::ShieldedStore;

/// An anonymity set resolved from the note-commitment accumulator: the ordered
/// commitments a one-out-of-many proof is proven against, plus the accumulator
/// `root` they anchor to. Prover and verifier MUST resolve an *identical*
/// `AnonSet` (same commitments, same order, same root) or the proof cannot
/// verify — that agreement is the whole point of routing both through one
/// [`AnonSetResolver`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonSet {
    /// Commitments in canonical (leaf-position) order.
    pub commitments: Vec<[u8; 32]>,
    /// The accumulator root these commitments anchor to.
    pub root: [u8; 32],
}

/// Connector: resolve the anonymity set a shielded spend proves membership in.
///
/// The one hard requirement is **determinism**: given the same accumulator
/// state, `resolve` must return the byte-identical `AnonSet` on the prover and
/// on every validating node. That is why selection is a shared seam and not
/// ad-hoc code on either side.
pub trait AnonSetResolver {
    /// Resolve the anonymity set anchored at the accumulator's current root.
    fn resolve(&self) -> Result<AnonSet>;
}

/// [`AnonSetResolver`] over the live [`ShieldedStore`]: the ordered note
/// commitments (leaf positions `0..tree_size`) plus the current accumulator
/// root.
///
/// PROVISIONAL: this resolves the *full* commitment set in position order — a
/// deterministic, testable rail. The **windowing + power-of-two padding** the
/// Groth-Kohlweiss proof needs (`N = 2^m`), and the exact anchor-window policy
/// (which historical roots a spend may anchor to), are the consensus-critical
/// *determinism contract* still to be ratified before activation; they layer on
/// top of this ordering as a pure transform. Not wired into consensus yet — the
/// production [`SpendVerifier`] is fail-closed.
pub struct StoreAnonSetResolver<'a> {
    store: &'a ShieldedStore,
}

impl<'a> StoreAnonSetResolver<'a> {
    pub fn new(store: &'a ShieldedStore) -> Self {
        Self { store }
    }
}

impl AnonSetResolver for StoreAnonSetResolver<'_> {
    fn resolve(&self) -> Result<AnonSet> {
        let size = self.store.tree_size() as u64;
        let mut commitments = Vec::with_capacity(size as usize);
        for pos in 0..size {
            // Entries are dense over `0..tree_size` (see ShieldedStore §6), so
            // every position resolves; a gap would be a store-invariant break.
            let entry = self.store.entry_at(pos).ok_or_else(|| {
                Error::CryptoError(format!(
                    "anon-set resolve: missing commitment at dense position {pos} \
                     (tree_size {size}) — shielded store invariant violated"
                ))
            })?;
            commitments.push(entry.commitment);
        }
        Ok(AnonSet {
            commitments,
            root: self.store.current_root(),
        })
    }
}

// ── Anonymity-set determinism contract ──────────────────────────────────────
// See docs/design/cip-shielded-anonset.md. A shielded spend proves membership
// in a FIXED-SIZE position bucket of the note-commitment tree: N = 2^m
// consecutive leaves. A coin at leaf position `p` lives in bucket `p / N` at
// offset `p % N`. Both prover and verifier derive the SAME bucket from the
// spent coin's position and resolve the SAME N commitments, padding positions
// past the frontier with a deterministic NUMS filler — so the GK one-of-many
// sees a byte-identical N-sized set on both sides. PROVISIONAL: `N` and the
// anchor-recency policy are unratified; nothing here is wired into consensus.

/// `m` in `N = 2^m` — the anonymity-set (bucket) size exponent. PROVISIONAL:
/// `m = 8` (N = 256) pending the ratification in cip-shielded-anonset.md.
pub const GK_ANON_SET_LOG2: u32 = 8;
/// The fixed anonymity-set (bucket) size `N = 2^GK_ANON_SET_LOG2`.
pub const GK_ANON_SET_SIZE: usize = 1 << GK_ANON_SET_LOG2;

/// The bucket a leaf position belongs to (`p / N`).
pub fn bucket_of(position: u64) -> u64 {
    position / GK_ANON_SET_SIZE as u64
}

/// Deterministic NUMS filler for an unfilled bucket slot — a nothing-up-my-sleeve
/// point with no known opening, so it can never be a spent coin, and is
/// identical on every node.
pub fn anon_pad(bucket: u64, offset: usize) -> [u8; 32] {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use sha3::{Digest, Sha3_512};
    let mut h = Sha3_512::new();
    h.update(b"COINCYNC_SPARK_ANON_PAD_v1");
    h.update(bucket.to_le_bytes());
    h.update((offset as u64).to_le_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    RistrettoPoint::from_uniform_bytes(&wide).compress().to_bytes()
}

/// Resolve bucket `bucket_index`'s ordered `N`-commitment window from the full
/// position-ordered commitment list, padding slots past the frontier with
/// [`anon_pad`]. Pure and deterministic — the shared rail both prover and
/// verifier call so their one-of-many sets cannot diverge.
pub fn bucket_window(ordered_full: &[[u8; 32]], bucket_index: u64) -> Vec<[u8; 32]> {
    let start = bucket_index as usize * GK_ANON_SET_SIZE;
    (0..GK_ANON_SET_SIZE)
        .map(|i| {
            ordered_full
                .get(start + i)
                .copied()
                .unwrap_or_else(|| anon_pad(bucket_index, i))
        })
        .collect()
}

/// The anon-set identifier bound into the spend transcript for a bucket: a
/// digest over the bucket index, `N`, and the ordered `N` commitments. Binds a
/// proof to exactly this bucket's contents, so it cannot be replayed against
/// another bucket. Used as [`AnonSet::root`] for a bucketed spend.
pub fn bucket_root(bucket_index: u64, window: &[[u8; 32]]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"COINCYNC_SPARK_ANON_ROOT_v1");
    h.update(bucket_index.to_le_bytes());
    h.update((window.len() as u64).to_le_bytes());
    for c in window {
        h.update(c);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

impl StoreAnonSetResolver<'_> {
    /// Resolve the [`AnonSet`] for a specific bucket (the contract in
    /// cip-shielded-anonset.md): the bucket's `N`-commitment window (NUMS-padded)
    /// plus its [`bucket_root`] identifier. This is what a bucketed GK spend
    /// proves against; both prover and verifier call it with the same
    /// `bucket_index`.
    pub fn resolve_bucket(&self, bucket_index: u64) -> Result<AnonSet> {
        let full = self.resolve()?.commitments;
        let commitments = bucket_window(&full, bucket_index);
        let root = bucket_root(bucket_index, &commitments);
        Ok(AnonSet { commitments, root })
    }
}

/// Domain tag for the shielded spend transcript. Bumping this is a hard fork of
/// the spend proof (every prior proof stops verifying), so it is versioned.
const SPEND_TRANSCRIPT_DOMAIN: &[u8] = b"COINCYNC_SHIELDED_SPEND_FS_v1";
/// Domain tag for serial-tag derivation.
const SERIAL_TAG_DOMAIN: &[u8] = b"COINCYNC_SHIELDED_SERIAL_TAG_v1";

/// Shared rail: the spend transcript digest binding a proof to its exact
/// context — the anonymity-set root, the ordered commitments, the revealed
/// serial tag, and the spend `message` (the fee/outputs/anchor digest). Prover
/// and verifier compute this identically; a single-byte disagreement here is
/// the classic "every proof fails" (or, worse, malleability) bug, so both sides
/// call this one function.
///
/// This is the *spend-level* Fiat-Shamir input; the Groth-Kohlweiss proof folds
/// it into its own challenge when the compound prover/verifier land.
pub fn spend_challenge(
    root: &[u8; 32],
    commitments: &[[u8; 32]],
    serial_tag: &[u8; 32],
    message: &[u8; 32],
) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(SPEND_TRANSCRIPT_DOMAIN);
    h.update(root);
    // Length-prefix the set so it cannot be confused with a different
    // partition of the same bytes.
    h.update((commitments.len() as u64).to_le_bytes());
    for c in commitments {
        h.update(c);
    }
    h.update(serial_tag);
    h.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Shared rail: the canonical spend `message` a shielded input's proof is bound
/// to — the tx-wide `fee` and output `note_commitments` (so a valid proof can't
/// be replayed with different outputs or fee) plus this input's anchor
/// `bucket_index`. Wallet and consensus compute it identically and feed it to
/// [`SpendProver::prove`] / [`SpendVerifier::verify`], so a mismatch on any of
/// these fails verification.
pub fn shielded_spend_message(
    fee: u64,
    note_commitments: &[[u8; 32]],
    bucket_index: u64,
) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"COINCYNC_SHIELDED_SPEND_MSG_v1");
    h.update(fee.to_le_bytes());
    h.update(bucket_index.to_le_bytes());
    h.update((note_commitments.len() as u64).to_le_bytes());
    for c in note_commitments {
        h.update(c);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// The canonical tx-wide spend message every input's spend proof and the balance
/// proof bind to: the `fee` plus every output's `(note_commitment ‖
/// value_commitment)`. Wallet and consensus compute it identically, so the whole
/// transaction (its outputs and fee) is non-malleable.
pub fn shielded_tx_message(
    fee: u64,
    value_balance: i64,
    outputs: &[crate::consensus::shielded::ShieldedOutput],
) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"COINCYNC_SHIELDED_TX_MSG_v1");
    h.update(fee.to_le_bytes());
    h.update(value_balance.to_le_bytes());
    h.update((outputs.len() as u64).to_le_bytes());
    for o in outputs {
        h.update(o.note_commitment);
        h.update(o.value_commitment);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Shared rail: derive the revealed serial tag `T = s·G` (the double-spend
/// nullifier) from a coin serial `s`. Both the wallet (to publish it in
/// `ShieldedPayload::serial_tags`) and the compound proof (to bind it) derive it
/// the same way. Domain-separated so `s` is a spend secret, never the tag.
pub fn derive_serial_tag(serial: &[u8; 32]) -> [u8; 32] {
    use crate::crypto::spark_generators::gen_g;
    use curve25519_dalek::scalar::Scalar;
    use sha3::{Digest, Sha3_512};
    // Map the serial into a scalar via a wide reduction (self-computed, so a
    // wide reduction is correct — this is not peer-input decoding).
    let mut h = Sha3_512::new();
    h.update(SERIAL_TAG_DOMAIN);
    h.update(serial);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    (gen_g() * s).compress().to_bytes()
}

/// Connector: verify a shielded spend proof. THE activation slot — the one place
/// a shielded tx becomes valid. `verify` is handed the opaque proof bytes from
/// `ShieldedPayload::proof`, the [`AnonSet`] re-resolved by consensus, the
/// revealed serial tag, and the spend message.
pub trait SpendVerifier {
    /// `Ok(())` iff the proof is a valid spend of a member of `anon_set` bound
    /// to `serial_tag` and `message`. Fail-closed on any error.
    fn verify(
        &self,
        proof: &[u8],
        anon_set: &AnonSet,
        serial_tag: &[u8; 32],
        message: &[u8; 32],
    ) -> Result<()>;
}

/// The production [`SpendVerifier`]: **rejects every proof**. This is what
/// consensus binds until the audited compound verifier is wired in, and is a
/// second, independent layer under `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`:
/// even if activation were flipped by mistake, no shielded tx could verify.
pub struct FailClosedVerifier;

impl SpendVerifier for FailClosedVerifier {
    fn verify(
        &self,
        _proof: &[u8],
        _anon_set: &AnonSet,
        _serial_tag: &[u8; 32],
        _message: &[u8; 32],
    ) -> Result<()> {
        Err(Error::SparkVerifyFailed)
    }
}

/// Connector: build a shielded spend proof (wallet side, mirror of
/// [`SpendVerifier`]). Returns the opaque bytes to place in
/// `ShieldedPayload::proof`.
pub trait SpendProver {
    fn prove(
        &self,
        witness: &SpendWitness,
        anon_set: &AnonSet,
        message: &[u8; 32],
    ) -> Result<Vec<u8>>;
}

/// The wallet's secret inputs to a spend. PROVISIONAL — the compound proof will
/// grow this (value, value-blinding) as its statement is finalized; the fields
/// here are the ones every form of the proof needs.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    /// Index of the spent coin within `anon_set.commitments`.
    pub member_index: usize,
    /// Coin serial `s`; the published tag is [`derive_serial_tag`]`(s)`.
    pub serial: [u8; 32],
    /// Blinding factor of the spent coin's commitment-to-zero form.
    pub blinding: [u8; 32],
}

/// Assembly-line soak driver: an **inert** prover/verifier pair that agree via
/// the shared [`spend_challenge`] rail but perform NO real zero-knowledge. It
/// exists only to drive the full shielded conveyor under load (mempool → block
/// → apply → reorg → RPC) so the *non-crypto* plumbing can be stress-tested
/// before the real proof exists, and to prove the two shared rails
/// (`AnonSetResolver` + `spend_challenge`) agree end-to-end. Gated behind
/// `cfg(test)`/`feature = "shielded-soak-stub"` — it can NEVER be compiled into
/// a production node, where the verifier is always [`FailClosedVerifier`].
#[cfg(any(test, feature = "shielded-soak-stub"))]
pub mod soak_stub {
    use super::*;

    /// Inert prover: the "proof" is just the shared transcript digest.
    pub struct StubProver;
    /// Inert verifier: accepts iff the proof equals the recomputed transcript
    /// digest for the same set/tag/message — i.e. iff both sides resolved the
    /// identical [`AnonSet`] and computed the identical [`spend_challenge`].
    pub struct StubVerifier;

    impl SpendProver for StubProver {
        fn prove(
            &self,
            witness: &SpendWitness,
            anon_set: &AnonSet,
            message: &[u8; 32],
        ) -> Result<Vec<u8>> {
            let tag = derive_serial_tag(&witness.serial);
            Ok(spend_challenge(&anon_set.root, &anon_set.commitments, &tag, message).to_vec())
        }
    }

    impl SpendVerifier for StubVerifier {
        fn verify(
            &self,
            proof: &[u8],
            anon_set: &AnonSet,
            serial_tag: &[u8; 32],
            message: &[u8; 32],
        ) -> Result<()> {
            let expect = spend_challenge(&anon_set.root, &anon_set.commitments, serial_tag, message);
            if proof == expect {
                Ok(())
            } else {
                Err(Error::SparkVerifyFailed)
            }
        }
    }
}

/// The REAL Spark spend prover/verifier — the impls that drop into the
/// [`FailClosedVerifier`] slot once externally audited and activated. Gated
/// behind `sketch-gk-proof` (OFF by default), so a production node NEVER
/// compiles them and the bound verifier stays [`FailClosedVerifier`]. NOT wired
/// into `check_shielded_tx` yet — `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` and
/// the consensus slot remains fail-closed until audit + the 24h soak pass.
#[cfg(feature = "sketch-gk-proof")]
pub mod gk {
    use super::*;
    use crate::crypto::groth_kohlweiss::{prove_spend, verify_spend, SparkSpendProofV2};
    use crate::crypto::{PeerPoint, PeerScalar};
    use crate::storage::shielded::ShieldedStore;
    use curve25519_dalek::ristretto::RistrettoPoint;

    /// Canonically decode an anon-set's `[u8; 32]` commitments to curve points,
    /// rejecting any non-canonical or identity encoding.
    fn decode_set(anon: &AnonSet) -> Result<Vec<RistrettoPoint>> {
        anon.commitments
            .iter()
            .copied()
            .map(|c| PeerPoint::decode_non_identity(c).map(|p| p.into_point()))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| Error::SparkVerifyFailed)
    }

    /// The real consensus-side spend verifier.
    pub struct GkSpendVerifier;

    impl SpendVerifier for GkSpendVerifier {
        fn verify(
            &self,
            proof: &[u8],
            anon_set: &AnonSet,
            serial_tag: &[u8; 32],
            message: &[u8; 32],
        ) -> Result<()> {
            let p = SparkSpendProofV2::from_bytes(proof).map_err(|_| Error::SparkVerifyFailed)?;
            // The published nullifier must be exactly the one this proof commits
            // to — binds the double-spend tag in the payload to the proof.
            if &p.nullifier() != serial_tag {
                return Err(Error::SparkVerifyFailed);
            }
            let set = decode_set(anon_set)?;
            verify_spend(&set, &p, message)
        }
    }

    /// The real wallet-side spend prover.
    pub struct GkSpendProver;

    impl SpendProver for GkSpendProver {
        fn prove(
            &self,
            witness: &SpendWitness,
            anon_set: &AnonSet,
            message: &[u8; 32],
        ) -> Result<Vec<u8>> {
            let set = decode_set(anon_set)?;
            let serial = *PeerScalar::decode(witness.serial)
                .map_err(|_| Error::CryptoError("prover: non-canonical serial".into()))?
                .as_scalar();
            let blinding = *PeerScalar::decode(witness.blinding)
                .map_err(|_| Error::CryptoError("prover: non-canonical blinding".into()))?
                .as_scalar();
            let proof = prove_spend(
                &set,
                witness.member_index,
                &serial,
                &blinding,
                message,
                &mut rand::rngs::OsRng,
            )?;
            Ok(proof.encode())
        }
    }

    /// Stateful consensus entry point: verify one shielded spend against the live
    /// note-commitment accumulator. Resolves the SAME anonymity-set bucket the
    /// prover used (through the shared [`StoreAnonSetResolver`]), then runs
    /// [`GkSpendVerifier`] — binding the published `nullifier` to the proof and
    /// checking membership + serial + `message`.
    ///
    /// This is the function the `check_shielded_tx` ACTIVATION SLOT will call
    /// (behind this gate), once the value-balance proof is added and the scheme
    /// is externally audited. It is gated OFF and NOT wired into consensus today,
    /// so the production path stays fail-closed (`FailClosedVerifier`,
    /// `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`).
    ///
    /// NOTE (scope): verifies MEMBERSHIP + SERIAL/NULLIFIER only — value
    /// conservation (balance + range) is a separate, still-required proof.
    pub fn verify_shielded_spend(
        store: &ShieldedStore,
        bucket_index: u64,
        nullifier: &[u8; 32],
        proof: &[u8],
        message: &[u8; 32],
    ) -> Result<()> {
        let anon = StoreAnonSetResolver::new(store).resolve_bucket(bucket_index)?;
        GkSpendVerifier.verify(proof, &anon, nullifier, message)
    }

    // ── The COMPLETE shielded payload verifier (all proofs composed) ──────────
    use crate::consensus::shielded::{
        ShieldedInput, ShieldedOutput, ShieldedPayload, SHIELDED_PAYLOAD_VERSION,
    };
    use crate::crypto::groth_kohlweiss::{
        bound_coin_commitment, prove_mint_binding, prove_spend_bound, verify_mint_binding,
        verify_spend_bound, MintBindingProof, SparkSpendProofV3,
    };
    use crate::crypto::spark_balance::{prove_balance_with_delta, value_commitment, BalanceProof};
    use crate::crypto::spark_range::{
        prove_value_range, BulletproofSparkBridge, RangeTranslator, ShieldedRangeProof,
    };
    use curve25519_dalek::scalar::Scalar;
    use rand::{CryptoRng, RngCore};

    /// A shielded note the wallet owns and is spending: which bucket + leaf offset
    /// it sits at, and its full opening `(value, serial m, blinding r)` of the
    /// bound coin `C = value·Gv + m·H + r·K`.
    pub struct SpendNote {
        pub bucket_index: u64,
        pub member_index: usize,
        pub value: u64,
        pub serial: Scalar,
        pub blinding: Scalar,
    }

    /// A new shielded coin to create: value + a fresh serial and coin blinding.
    pub struct NewNote {
        pub value: u64,
        pub serial: Scalar,
        pub coin_blinding: Scalar,
    }

    /// The shielded transaction BUILDER — the prover-side counterpart to
    /// [`verify_shielded_payload`]. Given wallet-owned `inputs`, the `outputs` to
    /// create, the `fee`, and a public `value_balance` (shield/unshield), it
    /// assembles a complete [`ShieldedPayload`] whose every proof
    /// (`verify_shielded_payload`) will accept: per-input value-bound spend +
    /// range, per-output mint-binding + range, and the tx balance. The per-value
    /// commitment blindings for the balance are drawn fresh here. This is the core
    /// the wallet's shielded send path drives. Gated `sketch-gk-proof`.
    pub fn build_shielded_payload<R: CryptoRng + RngCore>(
        store: &ShieldedStore,
        inputs: &[SpendNote],
        outputs: &[NewNote],
        fee: u64,
        value_balance: i64,
        rng: &mut R,
    ) -> Result<ShieldedPayload> {
        // Conservation must hold before we spend effort proving anything.
        let sin: i128 = inputs.iter().map(|n| n.value as i128).sum();
        let sout: i128 = outputs.iter().map(|n| n.value as i128).sum();
        if sin - sout - fee as i128 - value_balance as i128 != 0 {
            return Err(Error::CryptoError(
                "build: Σ in must equal Σ out + fee + value_balance".into(),
            ));
        }

        // Outputs first (the message binds them). Each output publishes a value
        // commitment V_out (blinding drawn here) bound to its tree coin.
        let mut out_structs = Vec::with_capacity(outputs.len());
        let mut out_values = Vec::with_capacity(outputs.len());
        let mut out_vblinds = Vec::with_capacity(outputs.len());
        for o in outputs {
            let ob = Scalar::random(&mut *rng);
            out_structs.push(ShieldedOutput {
                note_commitment: bound_coin_commitment(o.value, &o.serial, &o.coin_blinding)
                    .compress()
                    .to_bytes(),
                value_commitment: value_commitment(o.value, &ob).compress().to_bytes(),
                range_proof: prove_value_range(o.value, &ob, rng)?.encode(),
                mint_binding: prove_mint_binding(o.value, &o.serial, &o.coin_blinding, &ob, rng)
                    .encode(),
            });
            out_values.push(o.value);
            out_vblinds.push(ob);
        }

        let message = shielded_tx_message(fee, value_balance, &out_structs);

        // Inputs: each spend publishes V_in (blinding drawn here) bound to the
        // spent coin, plus its range.
        let mut in_structs = Vec::with_capacity(inputs.len());
        let mut in_values = Vec::with_capacity(inputs.len());
        let mut in_vblinds = Vec::with_capacity(inputs.len());
        for inp in inputs {
            let anon = StoreAnonSetResolver::new(store).resolve_bucket(inp.bucket_index)?;
            let coins = decode_set(&anon)?;
            let vb = Scalar::random(&mut *rng);
            let sp = prove_spend_bound(
                &coins,
                inp.member_index,
                inp.value,
                &inp.serial,
                &inp.blinding,
                &vb,
                &message,
                rng,
            )?;
            in_structs.push(ShieldedInput {
                bucket_index: inp.bucket_index,
                nullifier: sp.nullifier(),
                spend_proof: sp.encode(),
                range_proof: prove_value_range(inp.value, &vb, rng)?.encode(),
            });
            in_values.push(inp.value);
            in_vblinds.push(vb);
        }

        let balance = prove_balance_with_delta(
            &in_values,
            &in_vblinds,
            &out_values,
            &out_vblinds,
            fee,
            value_balance,
            &message,
            rng,
        )?;

        Ok(ShieldedPayload {
            version: SHIELDED_PAYLOAD_VERSION,
            inputs: in_structs,
            outputs: out_structs,
            value_balance,
            balance_proof: balance.encode(),
        })
    }

    /// The COMPLETE shielded-transaction verifier — every proof composed into the
    /// full value-conservation + privacy check for one shielded tx:
    ///   - per input: value-bound spend (membership + serial + value↔coin
    ///     binding) against the resolved bucket → `V_in`, published nullifier
    ///     matches the proof, and `V_in`'s range (via the bulletproof↔Spark
    ///     translator);
    ///   - per output: `V_out`'s range, and the mint-binding tying the new tree
    ///     coin's value to `V_out`;
    ///   - whole tx: balance `Σ V_in = Σ V_out + fee` over exactly those
    ///     commitments.
    /// All bound to `shielded_tx_message(fee, outputs)`. Fail-closed throughout.
    /// Nullifier double-spend is enforced separately against the store by
    /// `consensus::shielded::check_block_shielded_double_spends`.
    pub fn verify_shielded_payload(
        store: &ShieldedStore,
        payload: &ShieldedPayload,
        fee: u64,
    ) -> Result<()> {
        let message = shielded_tx_message(fee, payload.value_balance, &payload.outputs);
        let bridge = BulletproofSparkBridge;

        let mut v_ins = Vec::with_capacity(payload.inputs.len());
        for inp in &payload.inputs {
            let anon = StoreAnonSetResolver::new(store).resolve_bucket(inp.bucket_index)?;
            let coins = decode_set(&anon)?;
            let v3 = SparkSpendProofV3::from_bytes(&inp.spend_proof)
                .map_err(|_| Error::SparkVerifyFailed)?;
            if v3.nullifier() != inp.nullifier {
                return Err(Error::SparkVerifyFailed);
            }
            let v_in = verify_spend_bound(&coins, &v3, &message)?;
            let range = ShieldedRangeProof::from_bytes(&inp.range_proof)
                .map_err(|_| Error::SparkVerifyFailed)?;
            bridge.verify(&v_in, &range)?;
            v_ins.push(v_in);
        }

        let mut v_outs = Vec::with_capacity(payload.outputs.len());
        for out in &payload.outputs {
            let v_out = PeerPoint::decode_non_identity(out.value_commitment)
                .map_err(|_| Error::SparkVerifyFailed)?
                .into_point();
            let c_out = PeerPoint::decode_non_identity(out.note_commitment)
                .map_err(|_| Error::SparkVerifyFailed)?
                .into_point();
            let range = ShieldedRangeProof::from_bytes(&out.range_proof)
                .map_err(|_| Error::SparkVerifyFailed)?;
            bridge.verify(&v_out, &range)?;
            let mint = MintBindingProof::from_bytes(&out.mint_binding)
                .map_err(|_| Error::SparkVerifyFailed)?;
            verify_mint_binding(&c_out, &v_out, &mint)?;
            v_outs.push(v_out);
        }

        let balance = BalanceProof::from_bytes(&payload.balance_proof)
            .map_err(|_| Error::SparkVerifyFailed)?;
        crate::crypto::spark_balance::verify_balance_with_delta(
            &v_ins,
            &v_outs,
            fee,
            payload.value_balance,
            &balance,
            &message,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::shielded::{NoteCommitmentEntry, ShieldedStore};

    fn entry(commitment: [u8; 32]) -> NoteCommitmentEntry {
        NoteCommitmentEntry {
            commitment,
            height: 1,
            tx_index: 0,
            position: 0,
        }
    }

    #[test]
    fn resolver_is_deterministic_and_ordered() {
        let store = ShieldedStore::new();
        store.append_commitment(entry([1u8; 32]));
        store.append_commitment(entry([2u8; 32]));
        store.append_commitment(entry([3u8; 32]));

        let r = StoreAnonSetResolver::new(&store);
        let a = r.resolve().unwrap();
        // Ordered by leaf position, root is the store's current root.
        assert_eq!(a.commitments, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert_eq!(a.root, store.current_root());
        // Deterministic: same store → same set.
        assert_eq!(r.resolve().unwrap(), a);
    }

    #[test]
    fn resolver_tracks_appends_and_root_changes() {
        let store = ShieldedStore::new();
        let r = StoreAnonSetResolver::new(&store);
        let empty = r.resolve().unwrap();
        assert!(empty.commitments.is_empty());

        store.append_commitment(entry([9u8; 32]));
        let after = r.resolve().unwrap();
        assert_eq!(after.commitments, vec![[9u8; 32]]);
        assert_ne!(after.root, empty.root, "root moves once a note is appended");
    }

    #[test]
    fn spend_challenge_binds_every_input() {
        let root = [7u8; 32];
        let set = vec![[1u8; 32], [2u8; 32]];
        let tag = [3u8; 32];
        let msg = [4u8; 32];
        let base = spend_challenge(&root, &set, &tag, &msg);

        // Deterministic.
        assert_eq!(base, spend_challenge(&root, &set, &tag, &msg));
        // Every field is bound: changing any one changes the digest.
        assert_ne!(base, spend_challenge(&[8u8; 32], &set, &tag, &msg));
        assert_ne!(base, spend_challenge(&root, &[[1u8; 32]], &tag, &msg));
        assert_ne!(base, spend_challenge(&root, &set, &[9u8; 32], &msg));
        assert_ne!(base, spend_challenge(&root, &set, &tag, &[9u8; 32]));
        // Set ordering is bound (length-prefixed, so a reorder is a different set).
        assert_ne!(base, spend_challenge(&root, &[[2u8; 32], [1u8; 32]], &tag, &msg));
    }

    #[test]
    fn serial_tag_is_deterministic_distinct_and_nonidentity() {
        let t1 = derive_serial_tag(&[1u8; 32]);
        let t2 = derive_serial_tag(&[2u8; 32]);
        assert_eq!(t1, derive_serial_tag(&[1u8; 32]), "deterministic");
        assert_ne!(t1, t2, "distinct serials → distinct tags");
        assert_ne!(t1, [0u8; 32], "tag is never the identity encoding");
        // The tag is not the serial itself (it is s·G, domain-separated).
        assert_ne!(t1, [1u8; 32]);
    }

    #[test]
    fn fail_closed_verifier_rejects_everything() {
        let v = FailClosedVerifier;
        let anon = AnonSet {
            commitments: vec![[1u8; 32]],
            root: [0u8; 32],
        };
        // Even a "proof" that would satisfy the soak stub is rejected in prod.
        let stub_proof = spend_challenge(&anon.root, &anon.commitments, &[2u8; 32], &[3u8; 32]);
        assert!(matches!(
            v.verify(&stub_proof, &anon, &[2u8; 32], &[3u8; 32]).unwrap_err(),
            Error::SparkVerifyFailed
        ));
        assert!(v.verify(&[], &anon, &[0u8; 32], &[0u8; 32]).is_err());
    }

    #[test]
    fn bucket_math_is_deterministic_and_partitions_positions() {
        assert_eq!(GK_ANON_SET_SIZE, 256);
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(255), 0);
        assert_eq!(bucket_of(256), 1);
        assert_eq!(bucket_of(700), 2);
        // NUMS pad: deterministic, distinct per (bucket, offset), non-identity.
        assert_eq!(anon_pad(1, 5), anon_pad(1, 5));
        assert_ne!(anon_pad(1, 5), anon_pad(1, 6));
        assert_ne!(anon_pad(2, 5), anon_pad(1, 5));
        assert_ne!(anon_pad(0, 0), [0u8; 32]);
    }

    #[test]
    fn bucket_window_is_full_size_ordered_and_nums_padded() {
        // Two full buckets' worth minus a bit, so bucket 1 is partial.
        let full: Vec<[u8; 32]> = (0..300u32).map(|i| {
            let mut c = [0u8; 32];
            c[..4].copy_from_slice(&i.to_le_bytes());
            c
        }).collect();

        // Bucket 0: fully populated, exact position order.
        let b0 = bucket_window(&full, 0);
        assert_eq!(b0.len(), GK_ANON_SET_SIZE);
        assert_eq!(b0[0], full[0]);
        assert_eq!(b0[255], full[255]);

        // Bucket 1: positions 256..300 are real, 300..512 are NUMS pads.
        let b1 = bucket_window(&full, 1);
        assert_eq!(b1.len(), GK_ANON_SET_SIZE);
        assert_eq!(b1[0], full[256], "offset 0 of bucket 1 is leaf position 256");
        assert_eq!(b1[43], full[299], "last real leaf");
        assert_eq!(b1[44], anon_pad(1, 44), "first pad slot is the NUMS filler");
        // Deterministic: identical inputs → identical window (prover == verifier).
        assert_eq!(bucket_window(&full, 1), b1);

        // A wholly-past-the-frontier bucket is all pads (still N-sized, sound).
        let b9 = bucket_window(&full, 9);
        assert_eq!(b9.len(), GK_ANON_SET_SIZE);
        assert_eq!(b9[0], anon_pad(9, 0));
    }

    #[test]
    fn bucket_root_binds_index_and_contents() {
        let w1 = vec![[1u8; 32], [2u8; 32]];
        let w2 = vec![[1u8; 32], [3u8; 32]];
        let base = bucket_root(0, &w1);
        assert_eq!(base, bucket_root(0, &w1), "deterministic");
        assert_ne!(base, bucket_root(1, &w1), "bound to bucket index");
        assert_ne!(base, bucket_root(0, &w2), "bound to contents");
    }

    #[test]
    fn resolve_bucket_matches_the_pure_transform() {
        let store = ShieldedStore::new();
        for i in 0..300u32 {
            let mut c = [0u8; 32];
            c[..4].copy_from_slice(&i.to_le_bytes());
            store.append_commitment(entry(c));
        }
        let r = StoreAnonSetResolver::new(&store);
        let full = r.resolve().unwrap().commitments;

        for b in [0u64, 1, 5] {
            let via_resolver = r.resolve_bucket(b).unwrap();
            let expect_window = bucket_window(&full, b);
            assert_eq!(via_resolver.commitments, expect_window);
            assert_eq!(via_resolver.root, bucket_root(b, &expect_window));
            assert_eq!(via_resolver.commitments.len(), GK_ANON_SET_SIZE);
        }
    }

    #[test]
    fn soak_stub_prover_and_verifier_agree_over_the_shared_rails() {
        use soak_stub::{StubProver, StubVerifier};
        let store = ShieldedStore::new();
        store.append_commitment(entry([1u8; 32]));
        store.append_commitment(entry([2u8; 32]));

        // Both sides resolve the anon-set through the SAME resolver seam.
        let anon = StoreAnonSetResolver::new(&store).resolve().unwrap();
        let witness = SpendWitness {
            member_index: 0,
            serial: [42u8; 32],
            blinding: [7u8; 32],
        };
        let message = [5u8; 32];

        let proof = StubProver.prove(&witness, &anon, &message).unwrap();
        let tag = derive_serial_tag(&witness.serial);

        // Verifier re-resolves independently and agrees.
        let anon_v = StoreAnonSetResolver::new(&store).resolve().unwrap();
        assert!(StubVerifier.verify(&proof, &anon_v, &tag, &message).is_ok());

        // A drifted anon-set (an extra appended note moves the root) breaks it —
        // exactly the prover/verifier set-agreement failure the rails guard.
        store.append_commitment(entry([3u8; 32]));
        let anon_drift = StoreAnonSetResolver::new(&store).resolve().unwrap();
        assert!(StubVerifier.verify(&proof, &anon_drift, &tag, &message).is_err());
        // Wrong tag / wrong message also rejected.
        assert!(StubVerifier.verify(&proof, &anon, &[0u8; 32], &message).is_err());
        assert!(StubVerifier.verify(&proof, &anon, &tag, &[0u8; 32]).is_err());
    }

    /// End-to-end through the WHOLE assembly line with the REAL proof: mint Spark
    /// coins into the store, resolve a bucket anon-set via the shared resolver,
    /// prove a spend with `GkSpendProver`, and verify it with `GkSpendVerifier`
    /// after an independent re-resolve — exactly the prover→consensus path. Also
    /// confirms the published nullifier is bound to the proof and that the
    /// production `FailClosedVerifier` still rejects a valid proof.
    #[cfg(feature = "sketch-gk-proof")]
    #[test]
    fn real_gk_prover_and_verifier_round_trip_through_the_bucket_seam() {
        use super::gk::{GkSpendProver, GkSpendVerifier};
        use crate::crypto::groth_kohlweiss::SparkSpendProofV2;
        use crate::crypto::spark_generators::{gen_g, gen_k};
        use curve25519_dalek::scalar::Scalar;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let store = ShieldedStore::new();

        // Mint real Spark coins C = m·G + r·K at leaf positions 0..k.
        let k = 5usize;
        let openings: Vec<(Scalar, Scalar)> = (0..k)
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();
        for (m, r) in &openings {
            let c = (gen_g() * m + gen_k() * r).compress().to_bytes();
            store.append_commitment(entry(c));
        }

        // Resolve bucket 0 (real coins + NUMS pads → N commitments) via the seam.
        let anon = StoreAnonSetResolver::new(&store).resolve_bucket(0).unwrap();
        assert_eq!(anon.commitments.len(), GK_ANON_SET_SIZE);

        // Spend the coin at leaf position l (== its offset in bucket 0).
        let l = 3usize;
        let (ml, rl) = (openings[l].0, openings[l].1);
        let witness = SpendWitness {
            member_index: l,
            serial: ml.to_bytes(),
            blinding: rl.to_bytes(),
        };
        let message = [0x5A; 32];

        let proof_bytes = GkSpendProver.prove(&witness, &anon, &message).unwrap();
        let nullifier = SparkSpendProofV2::from_bytes(&proof_bytes).unwrap().nullifier();

        // Consensus independently re-resolves the same bucket and verifies.
        let anon_v = StoreAnonSetResolver::new(&store).resolve_bucket(0).unwrap();
        assert!(GkSpendVerifier
            .verify(&proof_bytes, &anon_v, &nullifier, &message)
            .is_ok());

        // Published nullifier is bound to the proof; message is bound; and the
        // production default rejects even a valid proof (gated off).
        assert!(GkSpendVerifier
            .verify(&proof_bytes, &anon_v, &[0u8; 32], &message)
            .is_err());
        assert!(GkSpendVerifier
            .verify(&proof_bytes, &anon_v, &nullifier, &[0u8; 32])
            .is_err());
        assert!(FailClosedVerifier
            .verify(&proof_bytes, &anon_v, &nullifier, &message)
            .is_err());
    }

    /// 24-hour SOAK harness for the shielded crypto stack. Continuously builds
    /// random *valid* complete shielded payloads (bound spends + range +
    /// mint-binding + balance over a minted anon-set) and asserts the complete
    /// verifier ACCEPTS them, then asserts an adversarial variant (wrong fee →
    /// broken balance binding) is REJECTED. Any deviation panics with the seed so
    /// the failing case is reproducible. Ignored by default; run explicitly:
    ///   SOAK_SECS=86400 cargo test --release --features "testnet sketch-gk-proof" \
    ///       soak_shielded_verifier -- --ignored --nocapture
    #[cfg(feature = "sketch-gk-proof")]
    #[test]
    #[ignore]
    fn soak_shielded_verifier() {
        use super::gk::verify_shielded_payload;
        use crate::consensus::shielded::{ShieldedInput, ShieldedOutput, ShieldedPayload};
        use crate::crypto::groth_kohlweiss::{
            bound_coin_commitment, prove_mint_binding, prove_spend_bound,
        };
        use crate::crypto::spark_balance::{prove_balance_with_delta, value_commitment};
        use crate::crypto::spark_range::prove_value_range;
        use crate::crypto::PeerPoint;
        use crate::storage::shielded::NoteCommitmentEntry;
        use curve25519_dalek::scalar::Scalar;
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        use std::time::{Duration, Instant};

        let budget = std::env::var("SOAK_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60u64);
        let base_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        eprintln!("[soak] starting: budget={budget}s base_seed={base_seed}");

        // Mint a fixed anon-set of bound coins once (values 1..=N).
        let n_coins = 20usize;
        let store = ShieldedStore::new();
        let mut seed_rng = StdRng::seed_from_u64(base_seed);
        let mut coin_openings: Vec<(u64, Scalar, Scalar)> = Vec::new();
        for i in 0..n_coins {
            let v = (i as u64 + 1) * 1000;
            let s = Scalar::random(&mut seed_rng);
            let r = Scalar::random(&mut seed_rng);
            store.append_commitment(NoteCommitmentEntry {
                commitment: bound_coin_commitment(v, &s, &r).compress().to_bytes(),
                height: 1,
                tx_index: 0,
                position: 0,
            });
            coin_openings.push((v, s, r));
        }
        let coins: Vec<_> = StoreAnonSetResolver::new(&store)
            .resolve_bucket(0)
            .unwrap()
            .commitments
            .iter()
            .map(|c| PeerPoint::decode_non_identity(*c).unwrap().into_point())
            .collect();

        let deadline = Instant::now() + Duration::from_secs(budget);
        let (mut accepted, mut rejected, mut iters) = (0u64, 0u64, 0u64);
        let mut last_report = Instant::now();

        while Instant::now() < deadline {
            let iter_seed = base_seed ^ iters.wrapping_mul(0x9E3779B97F4A7C15);
            let mut rng = StdRng::seed_from_u64(iter_seed);

            // k inputs (1..=4), m outputs (1..=3), random shield/unshield value_balance.
            let k = 1 + (rng.gen::<usize>() % 4);
            let mut idxs: Vec<usize> = (0..n_coins).collect();
            for i in 0..k {
                let j = i + rng.gen::<usize>() % (n_coins - i);
                idxs.swap(i, j);
            }
            let spend: Vec<usize> = idxs[..k].to_vec();
            let total_in: u64 = spend.iter().map(|&i| coin_openings[i].0).sum();
            let fee = rng.gen::<u64>() % (total_in / 4).max(1);

            // value_balance: pure (0), unshield (+, value leaves), or shield (−,
            // value enters). Chosen so Σ out = total_in − fee − value_balance ≥ 0.
            let max_unshield = (total_in - fee) as i64;
            let value_balance: i64 = match rng.gen::<u8>() % 3 {
                0 => 0,
                1 => (rng.gen::<u64>() % (max_unshield as u64 + 1)) as i64,
                _ => -((rng.gen::<u64>() % (total_in + 1)) as i64),
            };
            let out_total = (total_in as i64 - fee as i64 - value_balance) as u64;

            // Split Σ out across m outputs (parts may be zero).
            let m = 1 + (rng.gen::<usize>() % 3);
            let mut out_vals = Vec::with_capacity(m);
            let mut remaining = out_total;
            for i in 0..m {
                let v = if i == m - 1 { remaining } else { rng.gen::<u64>() % (remaining + 1) };
                remaining -= v;
                out_vals.push(v);
            }

            // Build outputs (bound coin + value commitment + range + mint-binding).
            let mut outputs = Vec::with_capacity(m);
            let mut out_blinds = Vec::with_capacity(m);
            for &ov in &out_vals {
                let ob = Scalar::random(&mut rng);
                let (s_out, r_out) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
                outputs.push(ShieldedOutput {
                    note_commitment: bound_coin_commitment(ov, &s_out, &r_out).compress().to_bytes(),
                    value_commitment: value_commitment(ov, &ob).compress().to_bytes(),
                    range_proof: prove_value_range(ov, &ob, &mut rng).unwrap().encode(),
                    mint_binding: prove_mint_binding(ov, &s_out, &r_out, &ob, &mut rng).encode(),
                });
                out_blinds.push(ob);
            }
            let message = shielded_tx_message(fee, value_balance, &outputs);

            // Inputs (value-bound spend + range).
            let mut in_vals = Vec::new();
            let mut in_blinds = Vec::new();
            let mut inputs = Vec::new();
            for &i in &spend {
                let (v, s, r) = &coin_openings[i];
                let ib = Scalar::random(&mut rng);
                let sp = prove_spend_bound(&coins, i, *v, s, r, &ib, &message, &mut rng).unwrap();
                inputs.push(ShieldedInput {
                    bucket_index: 0,
                    nullifier: sp.nullifier(),
                    spend_proof: sp.encode(),
                    range_proof: prove_value_range(*v, &ib, &mut rng).unwrap().encode(),
                });
                in_vals.push(*v);
                in_blinds.push(ib);
            }
            let bal = prove_balance_with_delta(
                &in_vals, &in_blinds, &out_vals, &out_blinds, fee, value_balance, &message, &mut rng,
            )
            .unwrap();
            let payload = ShieldedPayload {
                version: crate::consensus::shielded::SHIELDED_PAYLOAD_VERSION,
                inputs,
                outputs,
                value_balance,
                balance_proof: bal.encode(),
            };

            // Valid payload MUST verify.
            if let Err(e) = verify_shielded_payload(&store, &payload, fee) {
                panic!("[soak] FALSE REJECT iter {iters} (seed {iter_seed}, k={k} m={m} vb={value_balance}): {e:?}");
            }
            accepted += 1;
            // Adversarial #1: wrong fee → balance/message binding breaks → MUST fail.
            if verify_shielded_payload(&store, &payload, fee.wrapping_add(1)).is_ok() {
                panic!("[soak] FALSE ACCEPT wrong-fee iter {iters} (seed {iter_seed})");
            }
            // Adversarial #2: tampered value_balance → message + balance break → MUST fail.
            let mut tampered = payload.clone();
            tampered.value_balance = value_balance.wrapping_add(1);
            if verify_shielded_payload(&store, &tampered, fee).is_ok() {
                panic!("[soak] FALSE ACCEPT tampered-value_balance iter {iters} (seed {iter_seed})");
            }
            rejected += 2;

            iters += 1;
            if last_report.elapsed() >= Duration::from_secs(30) {
                eprintln!(
                    "[soak] {iters} iters | {accepted} accepted | {rejected} adversarial rejected | \
                     {}s left",
                    (deadline.saturating_duration_since(Instant::now())).as_secs()
                );
                last_report = Instant::now();
            }
        }
        eprintln!(
            "[soak] DONE: {iters} iters, {accepted} valid accepted, {rejected} adversarial rejected, \
             0 anomalies"
        );
        assert!(iters > 0, "soak ran zero iterations");
    }

    /// The stateful consensus entry point: verify a spend given only the store +
    /// bucket index + published nullifier + proof + message (the shape the
    /// activation slot will use). Resolves the anon-set internally.
    #[cfg(feature = "sketch-gk-proof")]
    #[test]
    fn stateful_verify_shielded_spend_resolves_and_checks() {
        use super::gk::{verify_shielded_spend, GkSpendProver};
        use crate::crypto::groth_kohlweiss::SparkSpendProofV2;
        use crate::crypto::spark_generators::{gen_g, gen_k};
        use curve25519_dalek::scalar::Scalar;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::seed_from_u64(123);
        let store = ShieldedStore::new();
        let openings: Vec<(Scalar, Scalar)> = (0..6)
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();
        for (m, r) in &openings {
            store.append_commitment(entry((gen_g() * m + gen_k() * r).compress().to_bytes()));
        }

        let l = 4usize;
        let (ml, rl) = (openings[l].0, openings[l].1);
        let anon = StoreAnonSetResolver::new(&store).resolve_bucket(0).unwrap();
        let witness = SpendWitness {
            member_index: l,
            serial: ml.to_bytes(),
            blinding: rl.to_bytes(),
        };
        let message = [0x33; 32];
        let proof = GkSpendProver.prove(&witness, &anon, &message).unwrap();
        let nullifier = SparkSpendProofV2::from_bytes(&proof).unwrap().nullifier();

        // Verifies against the live store, resolving bucket 0 internally.
        assert!(verify_shielded_spend(&store, 0, &nullifier, &proof, &message).is_ok());
        // Wrong bucket → different anon-set → membership fails.
        assert!(verify_shielded_spend(&store, 1, &nullifier, &proof, &message).is_err());
        // Wrong nullifier / message → rejected.
        assert!(verify_shielded_spend(&store, 0, &[0u8; 32], &proof, &message).is_err());
        assert!(verify_shielded_spend(&store, 0, &nullifier, &proof, &[0u8; 32]).is_err());
    }

    /// The COMPLETE payload verifier end-to-end: build a real `ShieldedPayload`
    /// (2 value-bound inputs, 1 minted output, fee) with membership + serial +
    /// value-binding + range + mint-binding + balance all composed, and verify it
    /// against the live store — then confirm an inflated output is rejected.
    #[cfg(feature = "sketch-gk-proof")]
    #[test]
    fn complete_shielded_payload_verifies_and_prevents_inflation() {
        use super::gk::verify_shielded_payload;
        use crate::consensus::shielded::{ShieldedInput, ShieldedOutput, ShieldedPayload};
        use crate::crypto::groth_kohlweiss::{
            bound_coin_commitment, prove_mint_binding, prove_spend_bound,
        };
        use crate::crypto::spark_balance::{prove_balance, value_commitment};
        use crate::crypto::spark_range::prove_value_range;
        use crate::crypto::PeerPoint;
        use curve25519_dalek::scalar::Scalar;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::seed_from_u64(314);
        let store = ShieldedStore::new();
        // Mint bound coins C = v·Gv + s·H + r·K (values 5, 3, 11, 2).
        let vals = [5u64, 3, 11, 2];
        let sers: Vec<Scalar> = (0..4).map(|_| Scalar::random(&mut rng)).collect();
        let blinds: Vec<Scalar> = (0..4).map(|_| Scalar::random(&mut rng)).collect();
        for i in 0..4 {
            store.append_commitment(NoteCommitmentEntry {
                commitment: bound_coin_commitment(vals[i], &sers[i], &blinds[i]).compress().to_bytes(),
                height: 1,
                tx_index: 0,
                position: 0,
            });
        }
        let fee = 2u64;

        // Build the output first (message binds it): mint a coin of value 6.
        let (vb0, vb1) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let build_output = |value: u64, ob: &Scalar, rng: &mut ChaCha20Rng| {
            let s_out = Scalar::random(rng);
            let r_out = Scalar::random(rng);
            let c_out = bound_coin_commitment(value, &s_out, &r_out);
            ShieldedOutput {
                note_commitment: c_out.compress().to_bytes(),
                value_commitment: value_commitment(value, ob).compress().to_bytes(),
                range_proof: prove_value_range(value, ob, rng).unwrap().encode(),
                mint_binding: prove_mint_binding(value, &s_out, &r_out, ob, rng).encode(),
            }
        };
        let ob = Scalar::random(&mut rng);
        let outputs = vec![build_output(6, &ob, &mut rng)];
        let message = shielded_tx_message(fee, 0, &outputs);

        // Inputs: spend coins 0 and 1 (5 + 3 = 8 in), bound to `message`.
        let coins: Vec<_> = StoreAnonSetResolver::new(&store)
            .resolve_bucket(0)
            .unwrap()
            .commitments
            .iter()
            .map(|c| PeerPoint::decode_non_identity(*c).unwrap().into_point())
            .collect();
        let mk_input = |l: usize, vb: &Scalar, rng: &mut ChaCha20Rng| {
            let sp =
                prove_spend_bound(&coins, l, vals[l], &sers[l], &blinds[l], vb, &message, rng)
                    .unwrap();
            ShieldedInput {
                bucket_index: 0,
                nullifier: sp.nullifier(),
                spend_proof: sp.encode(),
                range_proof: prove_value_range(vals[l], vb, rng).unwrap().encode(),
            }
        };
        let inputs = vec![mk_input(0, &vb0, &mut rng), mk_input(1, &vb1, &mut rng)];

        let bal = prove_balance(&[5, 3], &[vb0, vb1], &[6], &[ob], fee, &message, &mut rng).unwrap();
        let payload = ShieldedPayload {
            version: crate::consensus::shielded::SHIELDED_PAYLOAD_VERSION,
            inputs,
            outputs,
            value_balance: 0,
            balance_proof: bal.encode(),
        };

        // Complete honest payload verifies against the live store.
        assert!(verify_shielded_payload(&store, &payload, fee).is_ok());

        // INFLATION: swap the output for a 100-value coin (balance breaks; and the
        // message changes, so the inputs' proofs no longer bind either).
        let big_outputs = vec![build_output(100, &ob, &mut rng)];
        let mut inflated = payload.clone();
        inflated.outputs = big_outputs;
        assert!(
            verify_shielded_payload(&store, &inflated, fee).is_err(),
            "inflated output must fail the composed payload verifier"
        );
    }

    /// The BUILDER round-trip: `build_shielded_payload` (the wallet/prover side)
    /// produces a payload the complete verifier accepts, and it enforces value
    /// conservation up front.
    #[cfg(feature = "sketch-gk-proof")]
    #[test]
    fn builder_produces_a_payload_the_verifier_accepts() {
        use super::gk::{build_shielded_payload, verify_shielded_payload, NewNote, SpendNote};
        use crate::crypto::groth_kohlweiss::bound_coin_commitment;
        use curve25519_dalek::scalar::Scalar;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::seed_from_u64(2718);
        let store = ShieldedStore::new();
        let mut openings = Vec::new();
        for i in 0..5u64 {
            let value = (i + 1) * 1000;
            let serial = Scalar::random(&mut rng);
            let blinding = Scalar::random(&mut rng);
            store.append_commitment(NoteCommitmentEntry {
                commitment: bound_coin_commitment(value, &serial, &blinding).compress().to_bytes(),
                height: 1,
                tx_index: 0,
                position: 0,
            });
            openings.push((value, serial, blinding));
        }
        // Spend coins at offsets 1 (2000) and 3 (4000) = 6000 in; fee 500; one 5500 output.
        let inputs = vec![
            SpendNote { bucket_index: 0, member_index: 1, value: openings[1].0, serial: openings[1].1, blinding: openings[1].2 },
            SpendNote { bucket_index: 0, member_index: 3, value: openings[3].0, serial: openings[3].1, blinding: openings[3].2 },
        ];
        let fee = 500u64;
        let outputs = vec![NewNote { value: 5500, serial: Scalar::random(&mut rng), coin_blinding: Scalar::random(&mut rng) }];

        let payload = build_shielded_payload(&store, &inputs, &outputs, fee, 0, &mut rng).unwrap();
        assert!(verify_shielded_payload(&store, &payload, fee).is_ok(), "built payload must verify");

        // Builder rejects a non-conserving tx up front.
        let bad = vec![NewNote { value: 9999, serial: Scalar::random(&mut rng), coin_blinding: Scalar::random(&mut rng) }];
        assert!(build_shielded_payload(&store, &inputs, &bad, fee, 0, &mut rng).is_err());
    }
}
