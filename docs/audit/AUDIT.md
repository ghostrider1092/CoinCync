# CoinCync — Security Audit Runbook

The single entry point for a reviewer/auditor. Start here.

CoinCync is a Rust privacy cryptocurrency (Monero/Firo-family: CLSAG rings, RingCT,
Bulletproofs+, stealth addresses, RandomX PoW, Dandelion++). **Testnet-only until
this audit completes; mainnet is parked.**

---

## 1. What to review (scope, in priority order)

The v1.0 base chain: **consensus, P2P, wallet, mining, reorg defense.** Cyncswap
(atomic swap) and the Orchard Phase-2 shielded pool are **out of scope** — they
ship in their own releases behind their own audits, and their machinery is
feature-gated OFF (see §7).

Highest-value review targets (each file carries an in-code **Audit map** — see §4):
1. `src/consensus/validation.rs` — block & transaction validation (13 sections).
2. `src/consensus/{difficulty,pow,pow_cache}.rs` — ASERT difficulty + RandomX PoW binding.
3. `src/chain.rs` — the state machine: add_block, fork choice, reorg, rollback (14 sections).
4. `src/storage/utxos.rs`, `src/db/*` — UTXO set + atomic DB commits + crash consistency.
5. `src/crypto/*` — CLSAG, Bulletproofs+, stealth, disclosure.
6. `src/network/*` — Noise transport, sync state machine, message handlers, Dandelion++.
7. `src/wallet/*` — scanning, spend construction, decoy selection, key management.

---

## 2. Reproducible build

```bash
git clone <repo> && cd CoinCync
git checkout <audited-commit>

# Toolchain: the pinned Rust in rust-toolchain.toml. Native deps: a C toolchain
# + libclang (RandomX/RocksDB bindgen). On Windows set LIBCLANG_PATH to the LLVM
# bin dir and prepend it to PATH.
export LIBCLANG_PATH="/path/to/llvm/bin"          # e.g. C:/Program Files/LLVM/bin
export COINCYNC_RANDOMX_LIGHT_MODE=1              # RandomX light mode (fast, for tests)
export RUST_MIN_STACK=268435456                   # deep recursion in proof types

cargo build --release --features testnet
```

### Integrity lock (do this first — it is the audit baseline)
The build **refuses to compile** if any consensus-critical file's bytes drift
from `critical_files.lock` (enforced by `build.rs`). The lock covers:
`CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md`, `src/testnet.rs`, `src/mainnet.rs`,
`src/constants.rs`, `src/consensus/{difficulty,pow,validation,header,block,finality}.rs`,
`src/emission/{curve,mod}.rs`, and `src/primitives/hash.rs`.

> Lock coverage was widened 2026-09-12 to add the consensus-critical files that
> were previously unprotected: **`src/mainnet.rs`** (mainnet genesis + initial
> difficulty — its testnet twin was already locked), **`src/emission/mod.rs`**
> (`calculate_block_reward` — the subsidy/halving schedule), **`consensus/header.rs`**
> (`BlockHeader` + `pow_binding`), **`consensus/block.rs`** (block validation),
> **`primitives/hash.rs`** (`merkle_root` + difficulty↔target encoding), and
> **`consensus/finality.rs`** (max-reorg-depth). A silent change to any of these
> forks the chain, so they now break the build on drift like the rest.

```bash
# A clean build IS the integrity check. If it fails on critical_files.lock the
# audited tree has drifted from the baseline — stop and reconcile.
cargo build --release --features testnet
```
Hashes are SHA-256 over the file bytes with CRLF normalized to LF (so Windows and
Linux agree). To intentionally change a locked file:
`COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes`.

---

## 3. Run the test suite

```bash
# Full library suite (unit + in-module tests):
cargo test --lib --features testnet
# Expect: all pass, some ignored (real-PoW e2e, gated below).

# Integration suites (per file under tests/):
cargo test --features testnet --test <name>          # e.g. rpc_endpoints, mempool_extra

# Real-PoW end-to-end (slow; opt in):
cargo test --features testnet -- --ignored --nocapture
```

Behavioral coverage is enumerated in **`docs/audit/test-plan.md`** and its eight
per-subsystem checklists in `docs/audit/test-plan/` — every behavior is marked
EXISTS (with the test fn named) or MISSING. This is the test-vector inventory.

---

## 4. Navigating the code: in-code Audit Maps

Consensus and chain-storage source files open with a module-level
**`//! ## Audit map`** (renders in `cargo doc`). Each `§` section states, in the
file where you're already reading:
- the **INVARIANT** it guarantees (plain English),
- the **THREAT / incident** it defends,
- the **TESTS** that prove it (real fn names; known gaps marked `(gap — …)`).

The code's `// §N …` section banners align with the map, so you can read one
section of logic and its tests together. Start with the audit map at the top of
`src/consensus/validation.rs` and `src/chain.rs`.

Incident tags you'll see reference real history, e.g.: ASERT **S1** unit-confusion
(a testnet wipe), **C-2** key-image↔signature binding (supply inflation), **#44**
identity pseudo-output (balance collapse), **1d27d3c8** ring-size determinism
(fork risk), **R-2** genesis binding, **H1–H8** (this cycle's hardening).

---

## 5. Threat model & incident history
- `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md` — the design constraints.
- `docs/v1.0-mainnet-audit-prep.md` — cryptographic-primitive map, review targets,
  what v1.0 ships vs. defers, fuzz/property-test inventory.
- `docs/audit/bug-hunt-2026-09-10.md` — the internal bug hunt (2 critical, 9 high,
  16 medium, ~11 low) and remediation status.

---

## 6. Reproducing a finding
1. Locate the section in the relevant file's Audit map (§4) → the function + its tests.
2. Run just that test: `cargo test --lib --features testnet <test_fn_substring>`.
3. For an adversarial/e2e path, the test doc-comment names the exact scenario;
   `#[ignore]` tests are run with `-- --ignored`.

---

## 7. Deliberately deferred / feature-gated (NOT gaps)
- **Cyncswap / atomic swap** (v1.1), **Orchard Phase-2 shielded pool** (v1.x) —
  their own releases + audits. Feature-gated OFF.
- **Lelantus Spark, privacy manifold, MimbleWimble cut-through** — `sketch-*`
  Cargo features, OFF by default; stores wired but not appended in v1.0.
- **Rolling finality (CIP-009.D)** — machinery present, ships dormant.
- Test gaps requiring machinery that doesn't exist yet (process-kill crash
  harness, some fault injection, node/socket mocks) are enumerated with reasons
  in `docs/audit/test-plan/` and the in-code `(gap — …)` markers.

---

## 8. Findings register
Log issues in `docs/audit/findings.md` (or the auditor's own tracker) — one row
per finding: ID · severity · `file:line` · description · PoC · recommendation ·
status · response.
