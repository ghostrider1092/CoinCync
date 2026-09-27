# CIP — Unlinkable treasury solvency

**Status:** design (grounded in existing primitives; not yet built)
**Layer:** app-layer disclosure (no consensus change → regtest-testable, not soak-gated)
**Goal:** let an org prove *treasury ≥ threshold* to an auditor **without revealing
which on-chain output is the treasury** — removing the last on-chain linkage the
current anchored solvency proof exposes (today `verify_audit_package` anchors the
treasury by its exact `(tx_hash, output_index)`).

## What we have

- `crypto::groth_kohlweiss::prove_one_of_many` / `verify_one_of_many`
  — proves `commitments[l]` is a commitment to zero **`= r·K`** among a set,
  hiding `l`. Generator is **K** (`gen_k()`).
- `crypto::disclosure::create_balance_proof` / `verify_balance_proof`
  — proves a Pedersen commitment hides `value ≥ threshold`
  (`C' = (v−threshold)·H + r'·G` + bulletproof), in the **(H, G)** basis.
- `prove_spend_value_hidden` (`SparkSpendProofV4`) — membership + hidden value,
  but in the **Spark coin basis** `(Gv, H, K)`, for shielded coins.
- On-chain transparent output commitment: `pedersen_commit(v, r) = v·H + r·G`
  (value on **H**, blinding on **G**).

## The intended composition

Let `{Cᵢ}` be a set of real on-chain output commitments (the treasury `C_l`
plus decoys). Prover knows `C_l = value·H + r_l·G` with `value ≥ threshold`.

1. Draw fresh `value_blinding`; publish `V = value·H + value_blinding·G`.
2. **Membership (hides l):** prove `∃ l : C_l − V ∈ ⟨blinding-generator⟩`, i.e.
   `C_l` and `V` commit to the **same value**. Here `Cᵢ − V` has residual
   `(r_l − value_blinding)·G` at `l` — on **G**.
3. **Threshold:** `create_balance_proof(value, value_blinding, V, threshold)` —
   `V` is in the (H, G) basis, so this reuses the existing balance proof verbatim.

Verifier (anchored): every `Cᵢ` is a real on-chain commitment (via the node);
`verify_one_of_many` over `{Cᵢ − V}`; `verify_balance_proof` over `V, threshold`;
`V` equals the balance proof's `original_commitment`. Nothing reveals `l`.

## The obstacle (why it is NOT a trivial reuse)

Step 2 needs a one-of-many whose commitment-to-zero is on **G** (the transparent
blinding generator). `prove_one_of_many` hardcodes **K**. So the clean build is:

**Option A (preferred): generalize the generator.** Add
`prove_one_of_many_gen(commitments, l, r, zero_gen, ctx, rng)` /
`verify_one_of_many_gen(..)` that take the zero-commitment generator as a
parameter; keep `prove_one_of_many` as the `zero_gen = gen_k()` wrapper so the
**shielded consensus path is byte-for-byte unchanged**. Then unlinkable solvency
calls it with `zero_gen = g_point()` over `{Cᵢ − V}`.
- Risk: `groth_kohlweiss.rs` is consensus-shared. The change must be a pure
  refactor (existing callers unchanged) with the full GK test suite green plus a
  new G-generator round-trip test.

**Option B: basis bridge.** Keep GK on K: re-commit each candidate value in a
K-blinded form `C'ᵢ = value·H + r'ᵢ·K`, prove (Schnorr) `C'_l` and `C_l` open to
the same value, one-of-many over `{C'ᵢ}` on K, balance proof over the H/G `V`.
More moving parts (an extra equality proof per the hidden member) → larger
surface. Prefer A.

## Soundness checklist (must hold before shipping)

- `V` binds exactly `value` (balance proof) AND is the same value as a real
  on-chain output (one-of-many) — both bound to the *same* `V`.
- Fail-closed on: wrong value, non-member `V`, tampered proof, an anonymity-set
  member that is not anchored on-chain.
- Anonymity-set selection is not trivially linkable (decoy policy).
- Honesty: like every disclosure, the proof is only a trust decision **anchored**
  — all `Cᵢ` verified against the node's real UTXO commitments.

## Why this is its own focused effort

Editing the Groth-Kohlweiss one-of-many (consensus-shared, used by the shielded
spend) is soundness-critical and must not be rushed. A broken solvency proof is
worse than none. Build order: (1) generalize + prove GK generator refactor is
inert for K and correct for G; (2) `UnlinkableSolvencyProof` type + create/verify;
(3) anchored verification over a set + wire into `AuditPackage`; (4) regtest e2e
(prove treasury ≥ X hidden among N real outputs; wrong-value and non-member
rejected). Related: [[coincync-shielded-txtype-wip]], [[coincync-treasury-protection]].
