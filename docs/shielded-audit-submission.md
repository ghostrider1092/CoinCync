<!-- markdownlint-disable MD036 MD013 -->
# CoinCync Shielded (Spark) Engine — Audit Submission Packet

**Audit perimeter:** the **integration** of Firo's `libspark` Lelantus-Spark pool
into CoinCync consensus — the v2 libspark shielded engine. The vendored libspark
*cryptography* inherits Firo's own audit; **this submission covers the glue**
(FFI shim, Rust connector, consensus verify, pool store, value turnstile, gating),
plus confirmation that the vendoring is faithful.
**Submission date:** _draft — not yet submitted._
**Commit SHA at submission:** _operator passes the live `git rev-parse HEAD` at audit start (see §6)._

> **Honesty first.** Every claim below cites a file/test/doc; the code is ground
> truth. Open items and pending evidence are listed alongside the done work.
> Shielded is **gated OFF** (`activation height = u64::MAX`) on testnet/mainnet —
> nothing here is on the live consensus path until this audit clears.

---

## 1. What this document is

The **front door** for the shielded-engine audit. Companion documents, in
increasing depth:

| Document | Read it for |
| --- | --- |
| [`docs/AUDIT_READINESS.md`](AUDIT_READINESS.md) | Whole-project readiness; §5 "Shielded (Spark) engine". |
| [`docs/design/cip-shielded-libspark-ffi.md`](design/cip-shielded-libspark-ffi.md) | The engine spec — "Implemented (v2)" reviewer map + the FFI boundary. |
| [`docs/design/cip-shielded-anonset.md`](design/cip-shielded-anonset.md) | The anonymity-set determinism contract — "Shipped engine (v2 libspark)". |
| [`crates/spark-connector/vendor/NOTICE.md`](../crates/spark-connector/vendor/NOTICE.md) | Provenance: what is verbatim Firo vs a build shim. |

---

## 2. Scope

**In scope — the integration glue:**

1. **FFI shim** — `crates/spark-connector/csrc/shim.cpp`: the `extern "C"` boundary
   over byte buffers. Does it preserve libspark's guarantees (exception
   containment, buffer bounds, param lock-step via the single `cc_params()`
   accessor)?
2. **Rust connector** — `crates/spark-connector/src/lib.rs`: `SparkBackend` trait,
   `LibsparkBackend`, `StubBackend` (fail-closed), marshalling.
3. **Consensus verify** — `src/consensus/spark_payload.rs`
   (`verify_spark_payload` / `verify_solvency` / `apply_spark_payload`) and
   `src/chain.rs` (`verify_block_spark_v2`, `apply_spark_v2_txs`).
4. **Pool store** — `src/storage/spark_pool.rs` (`SparkPoolStore`, `cover_set_at`
   N-group bucketing, the spent-tag set).
5. **Value turnstile** — `verify_transparent_shielded_balance` (the public
   `value_balance` bridge between the transparent supply and the pool).
6. **Gating** — `shielded_activation_height` / `shielded_tx_active_at_height`;
   the `sketch-gk-proof` + `libspark-ffi` feature gates.

**Inherits Firo's audit (confirm faithfulness + provenance, don't re-audit the
math):** the vendored `libspark` crypto (Grootle one-of-many, Chaum, BPPlus,
Schnorr) and `secp256k1` C++ primitives under
`crates/spark-connector/vendor/src/`. See §7.

**Explicitly out of scope:**

- The **v1 native-GK path** (`src/consensus/shielded_pipeline.rs`,
  `src/crypto/groth_kohlweiss.rs`, `src/storage/shielded.rs`) — **superseded** by
  v2, retained gated for reference only (`cip-shielded-anonset.md`).
- The base RingCT/CLSAG consensus layer — audited separately (see `AUDIT_READINESS.md`).
- `coincync-swap` (cyncswap) — its own audit (`docs/audit-submission.md`).
- The wallet UI.

---

## 3. Highest-risk surfaces (start here)

1. **Node-authoritative cover-set verify (#258).** The spend's Grootle proof must
   be verified against the **node's** resolved cover set, not the spender's
   bundle. `verify_spark_payload` resolves `SparkPoolStore::cover_set_at(...)` and
   the shim recomputes the cover-set representation deterministically
   (`cc_cover_set_rep`) so a substituted set fails. A regression here is a
   soundness/inflation break. Hardened by #258; empty-group side-door closed by
   #308.
2. **The FFI shim boundary** (`shim.cpp`). Fail-closed on any libspark error,
   exception containment at `extern "C"`, buffer-length checks, and the single
   `cc_params()` accessor keeping prove/verify on identical params (N=32768).
3. **Transparent↔shielded value turnstile** (`verify_transparent_shielded_balance`
   + the `value_balance`/`vout` binding). Cross-veil inflation is the fund-safety
   class here. `vout` is bound to `value_balance` (#258).
4. **Double-spend** — keyed on libspark's linking tag `T`; the in-block +
   cross-block spent-tag guards.
5. **N-group bucketing determinism (#259).** Every node must resolve a
   byte-identical cover set for a given `(cover_set_id, anchor_height)`.

---

## 4. Build + reproduce

The libspark backend is **Windows/MSVC only** (the vendored C++ does not compile
on the Linux toolchain) and needs an MSVC-static OpenSSL via `SPARK_OPENSSL_DIR`.

```bash
# Connector tests (shim + LibsparkBackend), incl. the #258 strict tests.
cargo test --release -p spark-connector --features libspark-ffi

# Consensus verify path (store-aware verify + guards), incl. the #308 empty-cover
# guard and the real-libspark end-to-end verify→apply.
cargo test --release --features "testnet sketch-gk-proof libspark-ffi" --lib spark_payload

# 24h in-block consensus soak (mint→transfer→self-spend→double-spend→reorg via the
# real block hooks, live libspark proofs) at production params.
bash scripts/soak-24h-shielded.sh 86400     # expect: SHIELDED SOAK OK: <n> cycles
```

If any count/result differs from §5, the baseline shifted — re-derive before proceeding.

---

## 5. Test-evidence summary

| Evidence | What it covers | Status |
| --- | --- | --- |
| `-p spark-connector --features libspark-ffi` | Shim + `LibsparkBackend`; incl. #258 strict tests (`verify_rejects_a_substituted_cover_set`, `verify_rejects_value_balance_the_spend_does_not_release`) | **25 passing** (Windows/MSVC, production params) |
| `--lib spark_payload` | Store-aware verify + guards; incl. the #308 empty-cover guard and `end_to_end_v2_payload_verify_then_apply` (real libspark) | **12 passing** (Windows/MSVC, production params) |
| 24h in-block soak (test params, N≤16) | mint/transfer/spend/double-spend/reorg state machine via the real block hooks | **PASSED 2026-10-01: 329,214 cycles, 0 anomalies** over 24h |
| 24h in-block soak (**production params, N=32768**) | same, at the shipped Grootle params | **IN PROGRESS** — this is the pre-audit gate; result to be pinned here |
| Vendored crypto | Grootle/Chaum/BPPlus soundness | Inherits **Firo's libspark audit** (§7) |

---

## 6. Operator-supplied out-of-band materials

| Material | Form |
| --- | --- |
| Commit SHA being audited | `git rev-parse HEAD` |
| Local patches not yet pushed | `git log <upstream-base>..HEAD --oneline` |
| `Cargo.lock` hash | `sha256sum Cargo.lock` |
| `SPARK_OPENSSL_DIR` prefix + OpenSSL version | path + `openssl version` |
| Threat-model exclusions | free-text |

---

## 7. Provenance + license (vendored libspark)

- **License: MIT** (Firo `COPYING`; Bitcoin-core portions also MIT). Vendoring +
  linking is fine with attribution — see `crates/spark-connector/vendor/NOTICE.md`.
- **Crypto is verbatim / unmodified.** Only build-environment shims differ
  (`util.h`/`sync.h`/boost-optional/chainparams stubs); no cryptographic code is
  changed. NOTICE.md gives the verbatim-vs-shim breakdown.
- ✅ **Provenance pinned (verified):** Firo tag **`v0.14.18.1`** = commit
  **`c03cd0a1c68e1af8274349d1234d142ae7d02d1e`**. Confirmed by `version.h`
  (`PROTOCOL_VERSION=90031`, `MIN_FIRO_CLIENT_VERSION=141000`) and a
  byte-identical (LF-normalized) SHA-256 match of `grootle.cpp` / `chaum.cpp` /
  `spend_transaction.cpp` against that tag. The only vendored-side departures are
  the build-environment shims and the additive `getVout()` getter (#258, no
  crypto change). Reproduction recipe in
  `crates/spark-connector/vendor/NOTICE.md` → "Provenance verification".

---

## 8. Known gaps (declared, not hidden)

> ⛔ **MUST-FIX BEFORE ACTIVATION — F4: shielded transparent outputs are not
> range-proven (cross-veil inflation). Tracked as issue #314.**
> A shielded tx early-returns from `validate_transaction` (`validation.rs:1601`)
> before the output-curve / range-proof / balance checks; `check_shielded_tx` is
> stateless; the range-proof requirement is relaxed for shielded
> (`validation.rs:3012`); and `verify_block_spark_v2` feeds `tx.outputs`
> commitments into `verify_transparent_shielded_balance` with **no range proof and
> no requirement that `tx.outputs` be empty**. The code relies on "the transparent
> output set is empty" (comment at `validation.rs:3008–3011`) but that is
> **assumed, not enforced** — a shielded tx carrying a transparent output with a
> wrapped ("negative") value can balance the Pedersen bridge equation while minting
> value across the veil on an unshield.
> **Not live:** activation is `u64::MAX` and today's engine only uses
> `value_balance = 0` / empty transparent I/O (the soak); reachable only once
> shielded activates.
> **Fix (design decision, consensus-critical — CIP + two-of-N):** (A) enforce
> `is_shielded ⇒ tx.inputs.is_empty() && tx.outputs.is_empty()` (pure-shielded +
> mint-bundle only), or (B) range-prove `tx.outputs` on the shielded path before
> the value bridge consumes them. Must be resolved **and re-soaked** before
> activation.

- **Activation is `u64::MAX`** on testnet/mainnet — shielded is off until this
  audit clears. Regtest activation (height 100) exists only under `sketch-gk-proof`.
- **Production-param soak in progress** (§5) — the audit baseline is not final
  until it completes clean and its cycle count is pinned.
- **Shielded-specific fuzz coverage** is not yet enumerated here — to be added or
  declared explicitly before submission.
- **Value conservation across the veil** is enforced by the transparent bridge
  (`verify_transparent_shielded_balance`) plus the spend's own libspark
  balance/range proof; confirm this composition is complete for every tx shape.
- **Value-bridge (F4 follow-ons).** The identity-rejection asymmetry (input vs
  output commitments) first noted in review is **not benign — it is the surface
  of F4 above**: transparent outputs are unproven, so an identity/zero output is
  just the trivial case of the broader "any unproven transparent output" hole.
  Also confirm `value_balance` is bounded to a sane range (≤ total supply) by
  validation, or that Pedersen-equation failure suffices (incl. the
  `i64::MIN`/`unsigned_abs` edge) — largely subsumed if the F4 fix takes path (B)
  (range-proofs on transparent outputs).

---

## 9. Contact + scope changes

Discrepancies between this packet and the code resolve **in favor of the code**.
Point at the file:line and the operator updates both this packet and the engine
spec (`cip-shielded-libspark-ffi.md`).

---

*Draft submission packet. Source of truth: the code, then the CIP-shielded design
docs. This packet is regenerated on audit-relevant changes to the shielded engine.*
