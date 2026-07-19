//! Action circuit — proof construction and verification.
//!
//! An *Action* is the Phase-2 transaction primitive: one Action
//! consumes one note (publishing its nullifier) and creates one new
//! note (publishing its commitment). A shielded transaction is a
//! bundle of Actions plus a transparent `value_balance` that
//! crosses the bridge to the transparent pool.
//!
//! The Halo2 Action circuit proves, per action, that:
//!
//! 1. `cm_new` is a valid commitment to a note with stated
//!    `(recipient, value, ρ, ψ)`.
//! 2. `nf_old` is the correct nullifier for some old note whose
//!    commitment is at position P in the note-commitment tree
//!    with current anchor `rt`.
//! 3. The spender knows `ak`, the spend-authorisation validating
//!    key tied to the old note's recipient.
//! 4. The value commitments `cv_old` and `cv_new` open to the
//!    stated `value_balance` contribution.
//! 5. The proof is bound to a transaction-wide
//!    `sighash` so it can't be replayed in another tx.
//!
//! See Orchard §4.7 for the full statement.
//!
//! ## What this slice ships (2026-05-17)
//!
//! - A real [`ActionCircuit`] implementing
//!   `halo2_proofs::plonk::Circuit<pallas::Base>` with
//!   `SimpleFloorPlanner`.
//! - Real [`prove_action`] / [`verify_action`] wired through
//!   halo2's IPA prover/verifier, Blake2b transcripts, and
//!   memoized [`Params`] + [`ProvingKey`] / [`VerifyingKey`]
//!   artifacts.
//! - **Zero constraints** — the circuit's `synthesize` is a
//!   passthrough that returns `Ok(())`. This is the structural
//!   skeleton; the constraint set lands incrementally per the
//!   roadmap in [`ConstraintRoadmap`].
//!
//! ## Why ship an empty-constraint circuit first
//!
//! The Halo2 prover/verifier wiring (IPA params construction,
//! keygen, transcript management, Blake2b serialization) is
//! independent of the constraints themselves. Getting it working
//! against an empty circuit:
//! - Validates the dep tree (halo2_proofs 0.3 + pasta_curves 0.5
//!   compose correctly against our existing crate deps).
//! - Pins the prove/verify API contract so downstream code
//!   (chain validator, wallet) can call into a stable surface.
//! - Lets future constraint slices focus on the gadget composition
//!   without re-deriving the wiring boilerplate.
//! - Catches keygen/transcript-format mismatches early — any
//!   future constraint addition that breaks the prove/verify
//!   round-trip surfaces against this baseline first.
//!
//! The empty circuit produces a real ~3-5 KB IPA proof that
//! verifies; it's just trivially true (proves nothing useful).
//! [`is_implemented`] stays `false` until the constraint set is
//! complete and audit-reviewed.
//!
//! ## Curve choice
//!
//! `Circuit<pallas::Base>` — the circuit data lives over Pallas's
//! base field. The IPA polynomial commitment uses the **Vesta**
//! curve (whose scalar field equals `pallas::Base`, satisfying
//! halo2's `C::Scalar = F` requirement). This is the standard
//! pasta_curves cycle, matching every reference Orchard
//! implementation.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error as PlonkError, Fixed, Instance, ProvingKey, SingleVerifier,
        VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{group::ff::FromUniformBytes, pallas, vesta};
use std::sync::OnceLock;

use crate::commitment::NoteCommitment;
use crate::nullifier::Nullifier;
use crate::proof::Proof;
use crate::value_commit::ValueCommitment;
use crate::{Error, Result};

/// Log2 of the circuit row count. `k = 11` → 2048 rows — enough
/// for the empty skeleton with comfortable headroom. The real
/// Orchard Action circuit uses `k = 11` per the Zcash spec.
const ACTION_K: u32 = 11;

/// Number of advice columns the Action circuit allocates. The ECC,
/// Sinsemilla, Poseidon, and Merkle chips from `halo2_gadgets` share
/// these 10 columns per the reference Orchard layout
/// (orchard-0.12 `src/circuit.rs`). Allocating them up-front in
/// [`ActionConfig`] means Step 2's `EccChip::configure` (and the
/// later chips) can be wired without re-shaping `ActionConfig`'s
/// public surface each time.
pub const ACTION_ADVICE_COLUMNS: usize = 10;

/// Number of fixed columns the Action circuit allocates for
/// Lagrange-coefficient lookup tables consumed by the
/// `mul_fixed` family of ECC gadgets. The reference Orchard
/// layout pins this at 8, with two of the slots shared with
/// the Poseidon chip's round constants. Step 2 wires the actual
/// `EccChip::configure(meta, advices, lagrange_coeffs, ...)` call;
/// today the columns are allocated but unused (no gates reference
/// them).
pub const ACTION_FIXED_LAGRANGE_COLUMNS: usize = 8;

/// Public inputs to the Action circuit. All visible on-chain;
/// the circuit proves the corresponding private witness exists.
#[derive(Clone, Debug)]
pub struct ActionStatement {
    /// Spent note's nullifier.
    pub nf_old: Nullifier,
    /// New note's commitment.
    pub cm_new: NoteCommitment,
    /// Spent note's value commitment.
    pub cv_old: ValueCommitment,
    /// New note's value commitment.
    pub cv_new: ValueCommitment,
    /// Current note-commitment-tree anchor at proof time.
    pub anchor: bridge::BridgeCommitment,
    /// Transaction-wide sighash binding this proof to the tx.
    pub sighash: [u8; 32],
    /// Spend authorisation validating key (32 bytes Pallas).
    pub ak: [u8; 32],
    /// Randomised verification key — re-randomised `ak` per proof
    /// for unlinkability, alongside `RedPallas` spend auth sig.
    pub rk: [u8; 32],
}

/// Private witness held by the prover. Never reaches chain code.
#[derive(Clone, Debug)]
pub struct ActionWitness {
    /// The full spent-note value (the circuit checks `cv_old`
    /// opens to this).
    pub old_value: u64,
    /// The full new-note value.
    pub new_value: u64,
    /// Merkle authentication path for the spent note's commitment.
    /// 32 nodes for a depth-32 tree (matches `bridgetree`).
    pub merkle_path: [[u8; 32]; 32],
    /// Position of the spent note's commitment in the tree.
    pub merkle_position: u64,
    /// Spent note's randomness `(ρ, ψ, rseed)`.
    pub old_rho: [u8; 32],
    pub old_psi: [u8; 32],
    pub old_rseed: [u8; 32],
    /// New note's `rseed`.
    pub new_rseed: [u8; 32],
    /// Value-commitment trapdoors.
    pub rcv_old: [u8; 32],
    pub rcv_new: [u8; 32],
    /// Spend-auth signing key (ask). Only used inside the
    /// circuit; never serialised to the witness file.
    pub ask: [u8; 32],
}

// ── Circuit ──────────────────────────────────────────────────────────

/// The Halo2 Action circuit. Wraps an optional witness — `None`
/// for keygen + `without_witnesses`, `Some` for proof creation.
#[derive(Default, Clone)]
pub struct ActionCircuit {
    pub witness: Option<ActionWitness>,
}

/// The instance-column rows the Action circuit's public inputs
/// occupy, in the canonical order matching the reference Zcash
/// Orchard implementation (NU5 §6.7). Constraint slices that
/// add gates referencing public inputs use these row indices
/// via `meta.query_instance(config.instance, Rotation(idx))`.
pub mod public_input_rows {
    pub const AK: usize = 0;
    pub const NF_OLD: usize = 1;
    pub const RK: usize = 2;
    pub const CM_NEW: usize = 3;
    pub const ANCHOR: usize = 4;
    pub const CV_NET_X: usize = 5;
    pub const CV_NET_Y: usize = 6;
    pub const SIGHASH: usize = 7;

    /// Number of public-input rows the Action circuit declares.
    /// Verifier must pass an instances slice of this exact length.
    pub const COUNT: usize = 8;
}

/// Circuit configuration — columns + gates allocated during
/// `configure`. This slice ships:
///
/// - The **public-input scaffolding** (one instance column with
///   [`public_input_rows::COUNT`] rows).
/// - The **column-layout scaffolding** for the chip set the
///   constraint roadmap composes:
///   - `advices`: [`ACTION_ADVICE_COLUMNS`] (10) columns, shared
///     by every gadget chip (ECC, Sinsemilla, Poseidon, Merkle).
///   - `lagrange_coeffs`: [`ACTION_FIXED_LAGRANGE_COLUMNS`] (8)
///     fixed columns for the ECC `mul_fixed` family's
///     precomputed-base Lagrange interpolation.
///
/// The columns are allocated but unused today — no gates reference
/// them. Step 2 of [`ConstraintRoadmap`] is the first slice that
/// actually consumes them (via `EccChip::configure(...)`). Pinning
/// the layout NOW means subsequent constraint slices don't have to
/// re-shape `ActionConfig`'s public surface each time a chip lands.
///
/// Why one instance column rather than N: matches the reference
/// orchard crate's convention. A single instance column keeps the
/// public-input layout simple and makes the row indices in
/// [`public_input_rows`] the stable identifier any future gate
/// references when it consumes public inputs.
#[derive(Clone, Debug)]
pub struct ActionConfig {
    /// Single instance column carrying all Action public inputs.
    pub instance: Column<Instance>,

    /// 10 advice columns shared by every gadget chip. Reference:
    /// orchard-0.12 `src/circuit.rs::Config.advices`.
    pub advices: [Column<Advice>; ACTION_ADVICE_COLUMNS],

    /// 8 fixed columns holding Lagrange coefficients for fixed-base
    /// EC multiplication tables. Reference: orchard-0.12
    /// `src/circuit.rs` ECC chip configuration.
    pub lagrange_coeffs: [Column<Fixed>; ACTION_FIXED_LAGRANGE_COLUMNS],
}

impl Circuit<pallas::Base> for ActionCircuit {
    type Config = ActionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { witness: None }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Allocate the single instance column the public inputs
        // live in. enable_equality lets future gates wire
        // assigned cells to specific instance-column rows for
        // equality constraints (the standard pattern for
        // "this advice cell equals this public input").
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // Allocate the gadget-chip column scaffolding. Each
        // column is allocated but no gates reference them yet —
        // the ECC chip in Step 2 will be the first consumer.
        // `enable_equality` on every advice column matches the
        // reference orchard layout (the chip set needs cross-region
        // equality on every column).
        let advices: [Column<Advice>; ACTION_ADVICE_COLUMNS] = (0..ACTION_ADVICE_COLUMNS)
            .map(|_| {
                let c = meta.advice_column();
                meta.enable_equality(c);
                c
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("ACTION_ADVICE_COLUMNS-sized vec must convert");

        let lagrange_coeffs: [Column<Fixed>; ACTION_FIXED_LAGRANGE_COLUMNS] =
            (0..ACTION_FIXED_LAGRANGE_COLUMNS)
                .map(|_| meta.fixed_column())
                .collect::<Vec<_>>()
                .try_into()
                .expect("ACTION_FIXED_LAGRANGE_COLUMNS-sized vec must convert");

        ActionConfig {
            instance,
            advices,
            lagrange_coeffs,
        }
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<pallas::Base>,
    ) -> std::result::Result<(), PlonkError> {
        // Zero constraints today. The constraint roadmap steps
        // each add a chip + the corresponding region/assignment
        // logic here. With no chips configured this is a no-op
        // that the prover happily proves and the verifier
        // happily accepts.
        //
        // Note: the prover's instance values (from
        // `pack_statement`) ARE supplied to halo2 regardless of
        // whether the circuit constrains them. With zero
        // constraints the verifier accepts any instance values;
        // once constraints land, the equality gates will reject
        // a mismatch.
        Ok(())
    }
}

// ── Setup: params + key memoization ──────────────────────────────────

/// One-time IPA parameters of size `2^ACTION_K`. Computing these
/// takes ~hundreds of milliseconds (hash-to-curve for each of the
/// `n + 1` group elements), so we memoize across all calls.
fn action_params() -> &'static Params<vesta::Affine> {
    static PARAMS: OnceLock<Params<vesta::Affine>> = OnceLock::new();
    PARAMS.get_or_init(|| Params::<vesta::Affine>::new(ACTION_K))
}

/// Verifying key for the empty Action circuit. Will change when
/// constraints are added; memoizing is safe today because the
/// circuit shape is fixed for the empty skeleton.
fn action_vk() -> Result<&'static VerifyingKey<vesta::Affine>> {
    static VK: OnceLock<VerifyingKey<vesta::Affine>> = OnceLock::new();
    if let Some(vk) = VK.get() {
        return Ok(vk);
    }
    let vk = keygen_vk(action_params(), &ActionCircuit::default())
        .map_err(|e| Error::InvalidProof(format!("keygen_vk: {e:?}")))?;
    Ok(VK.get_or_init(|| vk))
}

/// Proving key for the empty Action circuit. Same memoization
/// rationale as [`action_vk`].
fn action_pk() -> Result<&'static ProvingKey<vesta::Affine>> {
    static PK: OnceLock<ProvingKey<vesta::Affine>> = OnceLock::new();
    if let Some(pk) = PK.get() {
        return Ok(pk);
    }
    let vk = action_vk()?.clone();
    let pk = keygen_pk(action_params(), vk, &ActionCircuit::default())
        .map_err(|e| Error::InvalidProof(format!("keygen_pk: {e:?}")))?;
    Ok(PK.get_or_init(|| pk))
}

// ── Public-input packing ─────────────────────────────────────────────

/// Pack an [`ActionStatement`] into the 8 pallas::Base values the
/// circuit's instance column expects, in the canonical
/// [`public_input_rows`] order.
///
/// 32-byte fields parse to a `pallas::Base` via `from_repr` (the
/// canonical path) with a fall-back to `from_uniform_bytes` when
/// the bytes aren't a canonical base-field representative — the
/// sighash in particular is opaque transaction-hash bytes that
/// can land anywhere in `[0, 2^256)`.
///
/// `cv_net = cv_old - cv_new` is computed from the two value
/// commitments — this is the canonical Orchard public-input
/// representation per NU5 §6.7 (rather than carrying both cv_old
/// and cv_new independently).
///
/// Returns the 8-element vector ordered as
/// `[ak, nf_old, rk, cm_new, anchor, cv_net.x, cv_net.y, sighash]`.
fn pack_statement(stmt: &ActionStatement) -> Vec<pallas::Base> {
    use group::Curve;
    use pasta_curves::arithmetic::CurveAffine;

    let parse_base = |bytes: &[u8; 32]| -> pallas::Base {
        // Canonical fast path: bytes < q_P (Pallas base field
        // order). Falls back to 64-byte uniform reduction for
        // arbitrary 32-byte inputs (sighash, ak from secp-style
        // domains, etc.).
        match Option::<pallas::Base>::from(pallas::Base::from_repr(*bytes)) {
            Some(b) => b,
            None => {
                let mut wide = [0u8; 64];
                wide[..32].copy_from_slice(bytes);
                pallas::Base::from_uniform_bytes(&wide)
            }
        }
    };

    let ak = parse_base(&stmt.ak);
    let nf_old = parse_base(&stmt.nf_old.0.to_bytes());
    let rk = parse_base(&stmt.rk);
    let cm_new = parse_base(&stmt.cm_new.to_bytes());
    let anchor = parse_base(&stmt.anchor.to_bytes());
    let sighash = parse_base(&stmt.sighash);

    // cv_net = cv_old - cv_new. Extract x and y coordinates of
    // the resulting Pallas point; map identity to (0, 0) so the
    // verifier sees a stable representation regardless of the
    // edge case.
    let cv_net_point = *stmt.cv_old.point() - stmt.cv_new.point();
    let (cv_net_x, cv_net_y) = {
        let affine = cv_net_point.to_affine();
        let coords: Option<pasta_curves::arithmetic::Coordinates<pallas::Affine>> =
            affine.coordinates().into();
        match coords {
            Some(c) => (*c.x(), *c.y()),
            None => (pallas::Base::ZERO, pallas::Base::ZERO),
        }
    };

    let mut out = vec![pallas::Base::ZERO; public_input_rows::COUNT];
    out[public_input_rows::AK] = ak;
    out[public_input_rows::NF_OLD] = nf_old;
    out[public_input_rows::RK] = rk;
    out[public_input_rows::CM_NEW] = cm_new;
    out[public_input_rows::ANCHOR] = anchor;
    out[public_input_rows::CV_NET_X] = cv_net_x;
    out[public_input_rows::CV_NET_Y] = cv_net_y;
    out[public_input_rows::SIGHASH] = sighash;
    out
}

// ── Public prove / verify ────────────────────────────────────────────

/// Construct an Action proof.
///
/// **Today this proves a trivial (empty-constraint) circuit** —
/// the wiring is real (Blake2b transcript, IPA polynomial
/// commitments, memoized keys), but the constraint set is
/// `Ok(())`. The proof is ~3-5 KB and verifies, but it doesn't
/// say anything cryptographically interesting about the
/// statement/witness yet.
///
/// Returns the serialized proof bytes wrapped in the bridge
/// envelope ([`Proof`]) so chain code can route it via the
/// existing `bridge::ProofOrigin::OrchardHalo2` tag.
pub fn prove_action(stmt: &ActionStatement, witness: &ActionWitness) -> Result<Proof> {
    use rand::rngs::OsRng;

    let circuit = ActionCircuit {
        witness: Some(witness.clone()),
    };
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(Vec::new());

    // halo2's `create_proof` instance layout: `&[&[&[F]]]`
    // shaped per (circuit, instance_column, row). One circuit,
    // one instance column (per ActionConfig), eight rows per
    // public_input_rows::COUNT.
    let instances = pack_statement(stmt);
    create_proof(
        action_params(),
        action_pk()?,
        &[circuit],
        &[&[&instances]],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| Error::InvalidProof(format!("create_proof: {e:?}")))?;

    let bytes = transcript.finalize();
    Proof::from_bytes(bytes)
}

/// Verify an Action proof against its public inputs.
///
/// Today: verifies the empty-constraint proof against an empty
/// instance vector. When the constraint roadmap lands public
/// inputs, this function will pack `stmt` fields into the
/// instance shape `&[&[&[Fr]]]` (one inner vec per instance
/// column declared in `Config`).
pub fn verify_action(proof: &Proof, stmt: &ActionStatement) -> Result<()> {
    let params = action_params();
    let vk = action_vk()?;
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof.bytes[..]);

    // Verifier-side packing MUST use the same canonical layout
    // [`pack_statement`] uses on the prover side. Today the
    // circuit has zero constraints so the verifier would accept
    // any instances shape that matches the column count — but
    // pinning the layout here means future constraint slices
    // can't accidentally mismatch.
    let instances = pack_statement(stmt);
    verify_proof(params, vk, strategy, &[&[&instances]], &mut transcript)
        .map_err(|e| Error::InvalidProof(format!("verify_proof: {e:?}")))?;
    Ok(())
}

// ── Roadmap (documentation marker) ───────────────────────────────────

/// Documentation-only marker for the multi-step constraint
/// roadmap. Each step adds a chip + region/assignment logic to
/// [`ActionCircuit::synthesize`], advances the proof's
/// cryptographic meaning, and updates [`is_implemented`] when
/// the full set is done.
///
/// Steps (in roughly the order the reference Zcash Orchard
/// crate's circuit was built):
///
/// 1. **Column scaffolding** (✅ shipped 2026-05-17) — allocate
///    the 10 advice columns + 8 fixed Lagrange-coefficient
///    columns the chip set will share. See
///    [`ACTION_ADVICE_COLUMNS`] / [`ACTION_FIXED_LAGRANGE_COLUMNS`]
///    and the `advices` / `lagrange_coeffs` fields on
///    [`ActionConfig`]. Columns are allocated but no gates
///    reference them yet — Step 2 lights up the first gate.
/// 2. **ECC chip** (`halo2_gadgets::ecc::chip`) — basic point
///    arithmetic for value commitments, spend-auth signature
///    randomization, K^Orchard multiplication. Wires
///    `EccChip::configure(meta, config.advices,
///    config.lagrange_coeffs, range_check)` using the columns
///    Step 1 laid down; requires adding `LookupRangeCheckConfig`
///    plus a lookup table column and a `FixedPoints` impl for the
///    precomputed Lagrange-coefficient tables.
///
///    **Dep-graph constraint discovered 2026-05-17:** the
///    natural source for the precomputed tables is the
///    reference `orchard = "0.12"` crate (re-exports
///    `OrchardFixedBases` from `orchard::constants::fixed_bases`,
///    gated behind its `circuit` feature). However, orchard 0.12
///    pins `halo2_gadgets = "0.4"` while our crate is on `0.3` —
///    the resolver picks both versions and the `EccChip` types
///    from each become incompatible. Two paths forward:
///    - **Path A (low-risk upgrade):** bump our
///      `halo2_gadgets` pin from `0.3` to `0.4` to share orchard
///      0.12's resolver tree. API change: `EccChip::configure`'s
///      4th arg changes from `LookupRangeCheckConfig<F, K>` to a
///      generic `Lookup` trait. The other API surface we use
///      (`witness_point`, `mul_fixed`, etc.) appears stable but
///      needs a full compile test.
///    - **Path B (no new dep):** implement a local `FixedPoints`
///      enum + `FixedPoint` for each base we need (`NullifierK`,
///      `ValueCommitV`, etc.). Lagrange tables are deterministic
///      from the generator but ~32 KB of constants per base —
///      either compute at runtime via `OnceLock` (slow first
///      call) or hardcode by copying orchard's tables (cleanest
///      but bulky source).
///
///    Path A is recommended unless the 0.3→0.4 upgrade breaks
///    the existing prove/verify round-trip in a way the column-
///    scaffolding slice didn't catch.
/// 3. **Sinsemilla chip** (`halo2_gadgets::sinsemilla::chip`) —
///    in-circuit short-commit for CommitIvk + NoteCommit, plus
///    the Merkle path checks.
/// 3. **Merkle chip** (`halo2_gadgets::sinsemilla::merkle`) —
///    the 32-deep authentication path against `anchor`.
/// 4. **Poseidon chip** (`halo2_gadgets::poseidon::chip`) — the
///    PRF_nfOrchard nullifier derivation in-circuit.
/// 5. **Lookup tables** for the gadgets above.
/// 6. **Range checks** for value (64-bit) and field reductions.
/// 7. **Public input columns** for `(anchor, nf, cm, cv_old,
///    cv_new, rk, sighash)`.
/// 8. **Audit pass** — Zcash NU5 §6.7 specifies the exact
///    constraints; cross-reference each gate against the
///    reference orchard crate.
///
/// Each step is its own multi-week slice. The reference orchard
/// crate's circuit is ~3000 lines of synthesize logic; this
/// skeleton is the first 50 of those lines.
pub struct ConstraintRoadmap;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dummy_statement() -> ActionStatement {
        use group::Group;
        let placeholder_point = pasta_curves::pallas::Point::generator();
        ActionStatement {
            nf_old: Nullifier(bridge::BridgeNullifier::from_bytes([1u8; 32]).unwrap()),
            cm_new: NoteCommitment::from_bytes([2u8; 32]).unwrap(),
            cv_old: ValueCommitment::from_point(placeholder_point),
            cv_new: ValueCommitment::from_point(placeholder_point),
            anchor: bridge::BridgeCommitment::from_bytes([5u8; 32]).unwrap(),
            sighash: [6u8; 32],
            ak: [7u8; 32],
            rk: [8u8; 32],
        }
    }

    fn make_dummy_witness() -> ActionWitness {
        ActionWitness {
            old_value: 100,
            new_value: 100,
            merkle_path: [[0u8; 32]; 32],
            merkle_position: 0,
            old_rho: [9u8; 32],
            old_psi: [10u8; 32],
            old_rseed: [11u8; 32],
            new_rseed: [12u8; 32],
            rcv_old: [13u8; 32],
            rcv_new: [14u8; 32],
            ask: [15u8; 32],
        }
    }

    #[test]
    fn end_to_end_trivial_proof_verifies() {
        // The load-bearing test for this skeleton slice: prove +
        // verify a circuit with zero constraints. This exercises
        // every piece of the halo2 wiring — params generation,
        // keygen, transcript, IPA polynomial commitments — and
        // pins the API contract for future constraint slices.
        //
        // Slow first call (~hundreds of ms for params + keygen),
        // sub-millisecond on warm OnceLock cache. Marked with the
        // `ignore = "slow"` attribute would be reasonable for CI
        // but we keep it active here so the wiring is verified on
        // every test run.
        let stmt = make_dummy_statement();
        let witness = make_dummy_witness();
        let proof = prove_action(&stmt, &witness).expect("prove");
        verify_action(&proof, &stmt).expect("verify");

        // Sanity: the proof envelope carries the OrchardHalo2 tag
        // when it crosses the bridge.
        let env = proof.to_bridge();
        assert_eq!(env.origin, bridge::ProofOrigin::OrchardHalo2);
        // Proofs are non-trivial in size even for an empty
        // circuit — the IPA commitment + Blake2b transcript add
        // structural bytes.
        assert!(proof.bytes.len() > 16, "real halo2 proof has at least the IPA scaffold bytes");
    }

    #[test]
    fn second_proof_after_keys_cached_is_fast() {
        // After the first prove_action call has warmed the
        // OnceLock-cached params/pk/vk, subsequent calls should
        // be substantially faster. This isn't a strict timing
        // test (CI variance) but at minimum the call should not
        // re-run keygen.
        let stmt = make_dummy_statement();
        let witness = make_dummy_witness();
        let _ = prove_action(&stmt, &witness).expect("warm-up prove");
        // Second call uses the cached keys.
        let proof2 = prove_action(&stmt, &witness).expect("warm prove");
        verify_action(&proof2, &stmt).expect("warm verify");
    }

    #[test]
    fn pack_statement_returns_expected_layout() {
        // Shape contract: 8 elements in canonical row order.
        let stmt = make_dummy_statement();
        let packed = pack_statement(&stmt);
        assert_eq!(
            packed.len(),
            public_input_rows::COUNT,
            "instance layout must have exactly the documented row count"
        );
        // Sighash row holds the parsed sighash bytes (the only
        // public input with no canonicality requirement — it
        // hits the from_uniform_bytes fallback path for arbitrary
        // 32-byte tx-hash inputs).
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&stmt.sighash);
        let expected_sighash = pallas::Base::from_uniform_bytes(&wide);
        // The dummy sighash [6u8; 32] happens to be canonical
        // (top byte < the Pallas prime), so it hits from_repr
        // first and matches the canonical parse. Either path
        // would give the same value here.
        let canonical_sighash =
            Option::<pallas::Base>::from(pallas::Base::from_repr(stmt.sighash)).unwrap();
        assert_eq!(canonical_sighash, expected_sighash);
        assert_eq!(packed[public_input_rows::SIGHASH], canonical_sighash);
    }

    #[test]
    fn prove_then_verify_with_packed_instances() {
        // The e2e test extended: prove + verify now flow real
        // public inputs through the instance column. With zero
        // constraints the verifier still accepts anything, but
        // the packing API contract is exercised end-to-end.
        let stmt = make_dummy_statement();
        let witness = make_dummy_witness();
        let proof = prove_action(&stmt, &witness).expect("prove");
        verify_action(&proof, &stmt).expect("verify with same statement");

        // Cross-check: a DIFFERENT statement packs into different
        // instance values. Sanity for the packing helper.
        let mut other_stmt = stmt.clone();
        other_stmt.sighash = [0x99; 32];
        assert_ne!(
            pack_statement(&stmt),
            pack_statement(&other_stmt),
            "different statements must produce different packed instances"
        );
    }

    #[test]
    fn is_implemented_stays_false_until_constraints_land() {
        // Crate-level activation sentinel. Wallets and UI should
        // gate Phase-2 features on this. Even though prove/verify
        // are now wired, the constraint set is empty — the proof
        // doesn't prove anything. Keep `is_implemented = false`
        // until the constraint roadmap is complete and audited.
        assert!(!crate::is_implemented());
    }
}
