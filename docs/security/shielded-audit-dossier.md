# CoinCync shielded surfaces — audit-prep dossier

**Purpose.** A starting map for external auditors of the shielded (Lelantus-Spark)
stack: the privacy-by-default pool, its transparent⇄shielded turnstile, and the
selective-disclosure surface. Each invariant below is stated as a *claim*, then
mapped to its *enforcement site*, *mechanism*, *tests*, *fuse coverage*, and
*diagnostic code*, and ends with **Audit focus** — what we most want the auditors
to try to break.

**Scope / status.** The entire shielded stack is gated behind `sketch-gk-proof`
(+ `libspark-ffi`), is **not wired into live consensus**, and the fuse breakers on
it are **detection-only**. Activation (Observe → Enforcing, fuses armed) is a
separate, reviewed, post-audit step. Nothing here is live on mainnet.

**Confidence labels.** `[STRUCTURAL]` = we verified the enforcement exists and is
shaped correctly by reading the code. `[DEEP-AUDIT]` = the soundness of the
underlying crypto was *not* line-audited by us and is exactly where external
review is needed.

---

## INV-1 — Value conservation across the veil ("no inflation")  `[STRUCTURAL]`

**Claim.** Value crossing transparent⇄shielded is neither created nor destroyed;
the only net change is the *public* `value_balance`.

- **Enforcement.** `src/consensus/shielded_pipeline.rs:554` —
  `Σ_in − Σ_out − fee − value_balance == 0`, evaluated in **i128** (no wrap). A
  shield is `value_balance < 0` (value enters the pool), an unshield `> 0`.
- **Non-malleability.** `value_balance` is bound into the Fiat-Shamir message
  (`shielded_tx_message`, `shielded_pipeline.rs:~580`, hashed at `:263`), so it
  cannot be altered after the proof is formed.
- **Cross-basis equality.** The turnstile proves the transparent commitment
  `T = v·H + r·G` and the shielded value commitment `V = v·Gv + b·K` hide the
  **same `v`** via `crypto/spark_range.rs::verify_value_bridge` (Schnorr-style
  equality, FS challenge `eq_challenge` over `(V, T, R1, R2)` — binds the proof to
  those exact commitments). `crypto/spark_turnstile.rs` is the thin connector.
- **Tests.** `spark_turnstile::tests::{shield_crossing_conserves_value,
  crossing_rejects_value_mismatch_and_tampering}`;
  `chain::tests::unshield_with_cancelling_blindings_is_rejected_at_every_gate`.
- **Fuse.** `src/fuse.rs` — `shielded` surface, detection-only pre-arming.
- **Diagnostic.** `CYNC-SHLD-001` (pool value ≥ 0, running `Σ value_balance`).
- **Audit focus `[DEEP-AUDIT]`.** (a) `verify_value_bridge` soundness — can a
  prover satisfy it for `T.value ≠ V.value`? (b) Does *every* activation gate
  enforce the balance equation **and** both range proofs together (the
  "every gate" test is the intended guard — confirm no path admits one without
  the others)? (c) `value_balance` sign/range handling at the i64↔i128 boundary.

## INV-2 — Shielded pool value ≥ 0  `[STRUCTURAL]`

**Claim.** The running shielded pool value can never go negative (no spending
value that was never shielded).

- **Enforcement.** `src/chain.rs::verify_block_shielded_spends`; the pool-value
  accumulator is maintained by `SparkPoolStore::apply_value_balance`
  (`src/storage/spark_pool.rs`), which rejects a balance that would underflow.
- **Crash-atomicity.** Pool writes commit inside the block's atomic `WriteBatch`
  (PR #384 + the sibling-store follow-up), so the pool can't persist ahead of the
  committed tip.
- **Diagnostic.** `CYNC-SHLD-001` (invariant, enforcing site, repro soak seed).
- **Audit focus.** Reorg paths: the pool rewind vs. `value_balance` restore —
  confirm a deep reorg can't strand a pool value inconsistent with the tip.

## INV-3 — No shielded double-spend (serial/linking-tag uniqueness)  `[STRUCTURAL]`

**Claim.** A shielded note can be spent at most once; a revealed serial / linking
tag is rejected on reuse.

- **Enforcement.** `SparkPoolStore::mark_tag_spent` / the spent-serial set in
  `storage/spark.rs` and `storage/spark_pool.rs`; the one-of-many proof binds the
  spend to a pool member (`crypto/groth_kohlweiss.rs`).
- **Tests.** `groth_kohlweiss::tests::{one_of_many_soundness,
  nullifier_is_deterministic_per_coin_and_message_independent,
  ki_binding_rejects_split_output}`.
- **Audit focus `[DEEP-AUDIT]`.** Tag/serial derivation binding — can two distinct
  spends share a tag, or one spend forge a tag that misses the spent set? The
  key-image/linking-tag binding (`ki_binding_*`) is the critical surface.

## INV-4 — Scoped view keys cannot exceed their authority  `[STRUCTURAL]`

**Claim.** A disclosed (scoped) view key scans only the epochs/range it was issued
for, and fails **closed** otherwise.

- **Enforcement.** `src/crypto/view_keys.rs` — `ViewKeyScope`; stateful scopes
  return `false` (fail-closed) when out of range; documented threat: "a scope that
  authorizes beyond its bound lets a view key scan epochs it shouldn't."
- **Tests.** `view_keys::tests::{authorize_scan_rejects_epoch_mismatch_for_each_scope,
  is_valid_for_epoch_is_failclosed_for_stateful_scopes, test_view_key_epoch_validity}`;
  CLI: `cmd_disclose_scoped_view_key_rejects_inverted_range`,
  `scoped_view_key_from_epoch_honors_inclusive_height_range`.
- **Audit focus.** Can a scoped key be *widened* (crafted/edited scope) and still
  pass `authorize_scan`? Serialization round-trips of the scope are the attack
  surface.

## INV-5 — Disclosure / audit packages are unforgeable and scope-bounded  `[DEEP-AUDIT]`

**Claim.** A balance / ownership / audit-package disclosure cannot be forged, and
reveals no more than its declared scope (e.g. a payroll audit discloses only the
intended outputs).

- **Surface.** `src/crypto/disclosure.rs` (**2,643 lines**), `src/compliance.rs`
  (**1,869 lines**; `seal_to` / `open` sealed-to-auditor packages, `source_disclosure`,
  payroll audit), `src/chain/compliance_view.rs`.
- **Tests.** `cmd_disclose_verify_{balance,ownership,audit_package}`,
  `cmd_disclose_build_payroll_audit`, receipt/export tests.
- **Audit focus `[DEEP-AUDIT]`.** This is the surface we did **not** line-audit and
  most want external eyes on: forgery resistance of each disclosure proof, that a
  verifier is convinced only of true statements, and that no package leaks beyond
  its declared scope (no incidental linkage across disclosures).

---

## Activation & fail-safe posture

- **Gated + unwired.** Everything above is `#[cfg(feature = "sketch-gk-proof")]`
  and not called from live block validation. Turning it on is a reviewed
  Observe → Enforcing step.
- **Fuses detection-only.** `src/fuse.rs` treats `shielded` like `reorg` /
  `block-integrity`: observed, not acting, until post-audit arming — so a
  mis-arming can't itself halt or corrupt consensus pre-audit.
- **Diagnostics.** `CYNC-SHLD-*` codes (`src/diagnostics.rs`) give auditors a
  stable catalog (invariant, enforcing site, spec pointer, repro seed) via
  `coincync-diag explain <code>`.

## Open items for the external audit (priority order)

1. `[DEEP-AUDIT]` **Disclosure soundness** (`disclosure.rs`, `compliance.rs`) —
   forgery + scope-leak resistance. Largest unaudited surface.
2. `[DEEP-AUDIT]` **`verify_value_bridge`** cross-basis equality soundness (INV-1).
3. `[DEEP-AUDIT]` **Linking-tag / key-image binding** (INV-3).
4. `[STRUCTURAL→confirm]` **Activation wiring** enforces *all* gates per tx
   (balance + both ranges + bridge), no admit-path bypass.
5. `[STRUCTURAL→confirm]` **Reorg atomicity** of pool value vs. tip (INV-2).

---

*This dossier is a map, not an assurance. Items marked `[STRUCTURAL]` were verified
to exist and be shaped correctly by code reading; the cryptographic soundness of
`[DEEP-AUDIT]` items is the external audit's job and is not asserted here.*
