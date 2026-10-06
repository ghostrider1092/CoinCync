# CIP — Shielded one-pool consolidation

**Status:** decision record + phase-1 (safe) marking. Homogenize the shielded
pool on a single canonical store; retire the two legacy engines' stores — but
delete nothing until after the libspark external audit.

## Decision

The shielded ("Spark") design homogenizes on **`storage::spark_pool::SparkPoolStore`**
as the single canonical pool store. It is the **libspark-FFI-aligned** store:
variable-length `CoinBytes` (S, K, C), 34-byte VRF linking tags, deterministic
serial context, dense ordered cover set, spent-tag set, and the running
`pool_value ≥ 0` no-cross-veil-inflation invariant — i.e. the exact shapes the
audited libspark spend path needs.

Two earlier stores are **legacy / superseded**:

| Store | What it was | Why retired |
|---|---|---|
| `storage::shielded::ShieldedStore` | Halo2/native-GK note store (depth-32 `BridgeTree` + nullifier set) | its Halo2 ZK spend circuit was never implemented |
| `storage::spark::SparkStore` | native pre-FFI sketch accumulator (32-byte commitments + serials) | fixed-shape model doesn't match libspark's `CoinBytes` / VRF tags |

This follows the narrow-scope strategy: **one audited Spark pool, homogenize,
don't run multiple engines**.

## Current state (why phase 1 is safe, not a rip-out)

The **runtime is already one-pool**: a production node instantiates only
`SparkPoolStore` (gated `sketch-gk-proof`); `spark_store` and `shielded_store`
are `None` in the production constructors and only `Some` in some gated tests.
So the "multi-engine" is a *code-level* fact (two verify paths + two stores
exist in source), not a runtime one — both shielded paths are gated off with
`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`.

**Phase 1 (this change) is documentation/marking only** — no behaviour change,
no hash-locked files, reversible:
- `storage/shielded.rs` and `storage/spark.rs` module docs marked LEGACY, pointing
  to `SparkPoolStore`.
- the `Blockchain::{spark_store, shielded_store}` fields documented as legacy.
- this record.

No `#[deprecated]` attribute is used: the legacy stores are still referenced by
the gated v1 native-GK path, and the attribute would only spam warnings across
those internal call sites.

## What is deliberately RETAINED (and why deletion is deferred)

The **native-GK engine** — `crypto/groth_kohlweiss.rs` (~2150 lines) +
`consensus/shielded_pipeline.rs` (~1300) + `consensus/shielded.rs` — is **real,
tested cryptography**, not a sketch. It is kept, gated off, on purpose:

- It is a genuine **independent second implementation** of the shielded proof
  system. The strongest implementation-level check available for the libspark
  proofs is a **differential**: verify the same statement with both the native
  GK path and libspark and require agreement (cf. the CLSAG optimization-layer
  differential already shipped). Deleting native-GK throws that away.
- It is a fallback if the libspark FFI path hits an audit finding.

**Full deletion (the ~4,000-line rip-out, which also touches hash-locked
`validation.rs`) is deferred until after the libspark external audit** — and
even then, native-GK may be worth keeping purely as a differential oracle rather
than deleted.

## Deferred: phase 2 (post-audit full consolidation)

Once the libspark path is externally audited and (regtest-)activated:
1. Decide keep-as-differential-oracle vs delete.
2. If deleting: remove `ShieldedStore` + `SparkStore` + the native-GK engine,
   rewire the v1 references in `validation.rs` (HASH-LOCKED → `COINCYNC_REGEN_LOCK`),
   `chain.rs`, `node.rs`, and the privacy RPC handler, and drop the fields.
3. Full test regime green (production + sketch-gk + FFI) at each step.

Related: [[coincync-strategy-narrow-shielded]], [[coincync-shielded-txtype-wip]].
