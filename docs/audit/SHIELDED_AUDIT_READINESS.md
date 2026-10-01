# CoinCync — Shielded (Lelantus-Spark) Engine: Audit-Readiness Dossier

> Companion to the chain-wide `docs/AUDIT_READINESS.md`, which places the shielded
> path **out of its scope** ("dormant / feature-gated... must be re-audited when
> wired"). This dossier scopes the shielded engine's **own** external audit — the
> gate that must pass before any activation.

**Status:** testnet-only; shielded tx **permanently gated OFF** on testnet and
mainnet (`shielded_activation_height(Testnet|Mainnet) == u64::MAX`). This dossier
is for the audit that must clear *before* an activation height is ever proposed.

---

## 1. Audit target (in scope) vs. exploration (out of scope)

**IN SCOPE — the production engine: the vendored Firo `libspark` FFI path.**
- `crates/spark-connector/` — the shielded engine's isolated section:
  - `vendor/` — Firo `libspark` (secp256k1 C++ Lelantus-Spark), **MIT**, vendored
    verbatim for the crypto/proof files; see `vendor/NOTICE.md` for provenance and
    the exact list of **node-infra shims** (`util.h`, `sync.h`, `boost/optional`,
    `chainparams`) that are the *only* non-verbatim files.
  - `csrc/shim.cpp` — the flat `extern "C"` boundary (build/verify/create/identify
    over byte buffers), wrapping every libspark call in `try/catch` so a C++ throw
    returns an error code rather than crossing into Rust.
  - `src/ffi/` — `LibsparkBackend : SparkBackend`.
- `src/consensus/shielded_connector.rs` — `backend()` cfg-swaps `LibsparkBackend`
  (under `libspark-ffi`) **else the fail-closed `StubBackend`**; `verify_bundle`
  is the node-side entry.
- `src/consensus/shielded.rs` — the on-wire `ShieldedPayload` / `ShieldedInput` /
  `ShieldedOutput` and `ShieldedPoolValue` accounting primitive.
- `src/consensus/validation.rs::check_shielded_tx` + `src/chain.rs`
  `verify_block_shielded_spends` — the consensus routing + double-spend/pool-value
  enforcement + reorg handling (main and fork paths).
- The activation + root gates in `src/constants.rs`
  (`shielded_activation_height`, `spark_set_root` permitted-zero rule).
- The shielded store / accumulator: `src/storage/shielded.rs`,
  `SparkPoolStore`, and the `Phase2Store` reorg surface (`src/storage/phase2.rs`).

**OUT OF SCOPE — native-Rust exploration / differential oracle.**
`src/crypto/groth_kohlweiss.rs` (feature `sketch-gk-proof`) is an **independent,
unaudited, exploratory** Groth–Kohlweiss reimplementation retained as a
cross-check. It is **not** the production spend. In particular the
`SparkSpendProofV5`/`V6` constructions and their nullifiers (`V6`'s `T = s·U`) are
**NOT** the Lelantus-Spark nullifier (the DY-VRF `T = (U−D)·s⁻¹`). The auditor
should not spend effort treating the native GK path as production; it is noted
here only so its presence in the tree is not mistaken for the audited engine.

---

## 2. Construction (specifications)

The real Lelantus-Spark construction as implemented by the vendored libspark:
two-commitment coins (value `C` + serial `S`), a Grootle log-size one-of-many,
a Chaum spend proof binding serial + spend key without revealing them, BPPlus
range proofs, a balance proof, and the Dodis–Yampolskiy VRF nullifier
`T = (U−D)·s⁻¹`. CoinCync CIPs:

- `docs/design/cip-shielded-txtype.md` — the `TxType::Shielded` wire hard fork,
  validation dispatch, fail-closed invariants.
- `docs/design/cip-shielded-proof.md`, `cip-shielded-spend-composition.md` — the
  spend construction and the pinned Firo relations.
- `docs/design/cip-shielded-libspark-ffi.md` — the FFI integration, build, and
  curve-split rationale (libspark is secp256k1; CoinCync consensus is Ristretto;
  the boundary carries only public `value_balance`, no cross-curve ZK).
- `docs/design/cip-spark-block-format.md` — the on-chain payload/bundle format.
- `docs/design/cip-shielded-anonset.md` — the deterministic anonymity-set
  (cover-set) resolution both prover and verifier must agree on.
- `docs/design/cip-shielded-one-pool-consolidation.md` — why libspark is the
  single production engine and the native GK path is a retained oracle.
- `docs/design/cip-shielded-notes.md` — the note/scan/spend key model.

---

## 3. Security invariants the audit must confirm

1. **Inert until activated.** `shielded_activation_height(Testnet|Mainnet) ==
   u64::MAX`; no height activates shielded on a public network. Verified by
   `constants.rs` tests (e.g. `shielded_activation_height(Testnet) == u64::MAX`).
2. **Fail-closed by default.** Without the `libspark-ffi` feature, `backend()` is
   `StubBackend`, which rejects every payload. The verifier is fail-closed on any
   malformed/invalid/exception path (the shim `try/catch` returns an error, never
   aborts).
3. **No shielded tx can enter a block pre-activation**, on any build — the
   activation-height gate AND the verifier gate both hold.
4. **`spark_set_root == 0` pre-activation** — the header accumulator-root field is
   PoW-bound; no producer commits a non-zero root while shielded is inactive, and
   `shielded_root_permitted` rejects a non-zero root pre-activation.
5. **Double-spend prevention** — each spend publishes its DY-VRF nullifier; the
   spent-tag set rejects a repeat. Deterministic in the coin ⇒ a second spend
   collides.
6. **Value conservation (no inflation, no inflation-across-the-veil)** — per-tx
   balance + BPPlus range on every value commitment + the `value_balance`
   turnstile, and `ShieldedPoolValue` (running pool total = Σ value_balance) that
   **rejects going negative**. The audit should confirm these compose to full
   conservation on shield / unshield / pure-shielded txs.
7. **Reorg consistency** — the pool/accumulator is `Phase2Store`-checkpointed and
   rewound lock-step with the UTXO set on both the main-apply and fork/reorg
   paths; restart-durable checkpoints persist the rewind boundary.

---

## 4. Reproducible build

- Feature: `--features "testnet,libspark-ffi"` (adds the C++ toolchain).
- Env: `SPARK_OPENSSL_DIR` → a static-MD OpenSSL prefix (the project uses a vcpkg
  `x64-windows-static-md` build; see `docs/design/cip-shielded-libspark-ffi.md`
  and `[[coincync-build-and-test]]`). libspark pulls OpenSSL EVP + its own
  secp256k1 C primitives; both are vendored/compiled via `cc`.
- Default/production build (no `libspark-ffi`) compiles with the fail-closed stub
  and is byte-unaffected by the shielded engine.

## 5. Evidence (to re-run against the audit commit)

- **libspark in-block / verify soak** — a 24h build→verify→tamper→reject soak
  stressing the FFI boundary has been run on the libspark path; re-run against the
  exact audit commit and attach the log.
- **Native-GK crypto soak** (`soak_shielded_verifier`, the differential oracle,
  NOT the audited engine) — most recent run this cycle: 310,034 iterations,
  620,068 adversarial rejections, **0 anomalies** over 24h. Included only as a
  cross-check data point.
- **Unit coverage** — the `libspark-ffi` shielded test suite (create/build/verify/
  identify round-trips, proof-tamper rejection, node-verifies-real-bundle). List
  the exact count at the audit commit.

## 6. Known open items (honest)

- **View-only key** — true watch-only scanning needs an `IncomingViewKey`
  reconstruction ctor that upstream libspark lacks (a small vendored addition
  exists on `feat/shielded-viewkey`); confirm its soundness if in scope.
- **Shielded submission RPC** — the write path (accept + mempool a shielded tx) is
  intentionally **not built** pre-activation (it would reject all txs while gated);
  it is deferred activation plumbing, not in this audit.
- **Anon-set parameters** (`GK_ANON_SET_LOG2`, bucket policy) — the cover-set size
  and windowing are provisional; ratify before activation.
- **Native GK path** — see §1; present but out of scope.

## 7. Suggested audit focus

1. **The FFI boundary** — serialize/deserialize/verify round-trip, exception
   safety across the C/Rust boundary, and the verifier-state contract (cover-set
   sizes/representations, out-coins, external SpendTransaction version).
2. **Vendored-libspark diff vs. upstream Firo** — confirm the crypto/proof files
   are verbatim and only node-infra files are shimmed (per `vendor/NOTICE.md`).
3. **Consensus wiring** — the activation gate, fail-closed default, double-spend
   tag-set, value conservation (balance + range + turnstile + pool-value), and the
   reorg paths (main + fork).
4. **Anon-set determinism** — prover and verifier derive the identical cover set.
5. **Activation safety** — the eventual flip from `u64::MAX` is a coordinated hard
   fork; confirm no pre-activation block can carry shielded state.
