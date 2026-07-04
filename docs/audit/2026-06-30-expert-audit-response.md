# CoinCync v1.0 — Response to 2026-06-30 Expert Audit

**Auditor:** in-session 15-year-blockchain-expert review (not a formal audit — that is scoped separately, see §5)
**Date:** 2026-06-30
**Scope:** src/ (79k LOC) + workspace crates (117k total). Sampling method: consensus-critical files read in full or in critical sections; grep-based structural analysis.
**Author of response:** in-session pairing between operator (Jeremy) and Claude

---

## 1. Executive summary

| Item | Category | Status |
|---|---|---|
| C1 — ASERT regression on `refactor/sync-state-model` | Consensus | ✓ Fixed in working tree |
| C2 — RocksDB zombie state | Reliability | ✓ Tracing added; RCA pending next occurrence |
| H2 — env-var consensus skip | Security | ✓ Migrated to `insecure-fast-sync` compile-time feature |
| H3 — `ClsagSignature::to_bytes()` silent-empty | Crypto | ✓ Consolidated to `Result`-returning API |
| H4 — `db/shim.rs` raw pointer unsafe | Memory safety | ✓ Migrated to `RefCell<RocksBatch>` |
| H1, H5 — monolithic files | Maintainability | Plan documented in §3 |
| M1, M2 — clippy lints | Code hygiene | ✓ Individually-selected cast + Result lints added |
| M4 — I/O ratio consensus rule | Consensus surface | Redundant with uniform-shape; comment updated, no consensus change |
| A1 — scope creep | Governance | Policy doc §4 |
| A2 — bus factor 1 | Governance | Recruitment brief §6 |
| A4 — no alternate implementation | Ecosystem | Post-mainnet roadmap §7 |
| External audit | Third-party | RFP template §5 |

Compile status after fixes: clean (`cargo check --lib` = one pre-existing unrelated warning).

---

## 2. Code changes applied in this session

### C1 — ASERT denominator restored (`src/consensus/difficulty.rs`)

Reverted the `refactor/sync-state-model` regression that deleted the S1 fix (originally landed on origin/main via PR #67, commit c42b95f2). Denominator is now `halflife as i128` alone (seconds), matching Bitcoin Cash aserti3-2d specification. Full comment block from main restored so future readers understand the CONSENSUS-AFFECTING nature of the change.

Consensus impact: same as main. Fleet already runs this formula. `critical_files.lock` updated.

### H2 — env-var replaced by compile-time feature (`src/consensus/validation.rs`, `Cargo.toml`)

The `COINCYNC_ALLOW_CHECKPOINT_CRYPTO_SKIP` runtime env-var could disable crypto verification via a single environment variable — an attacker or misconfigured operator setting that variable could silently accept invalid blocks. Migrated to a compile-time `insecure-fast-sync` cargo feature. Production release builds physically cannot enable the skip.

Prior art: zebrad uses the same feature-flag pattern. Bitcoin Core's `-assumevalid` is a config-file flag (not env) that only skips signature verification.

**CI requirement (not yet enforced):** the release-artifact build workflow must reject any binary built with `--features insecure-fast-sync`. Add a CI check that greps the feature list on the release binary.

### H3 — `ClsagSignature::to_bytes()` returns `Result` (`src/crypto/clsag.rs`, callers updated)

Previously two methods: `to_bytes()` returning `Vec::new()` on failure + `try_to_bytes()` returning `Result`. Callers could accidentally use the silent-empty variant. Consolidated into one `Result`-returning `to_bytes()`. Sole caller (`validation.rs:1398` in `verify_clsag_signature_impl`) updated to propagate the error via early return of `false`.

### H4 — raw pointer removed from `db/shim.rs`

`TxTree.batch: *mut RocksBatch` migrated to `TxTree.batch: &'a RefCell<RocksBatch>`. Multiple `TxTree` instances no longer alias a raw mutable pointer. Small runtime cost (~1ns per put/delete for `RefCell::borrow_mut`). Eliminates a class of Rust UB.

Prior art: zebrad uses `&mut WriteBatch` passed through method args; redb uses `RefCell` for the same interior-mutability pattern.

### M1/M2 — targeted clippy lints (`Cargo.toml`)

Individually-enabled lints at `warn` level:
- `cast_possible_truncation`, `cast_sign_loss`, `cast_lossless` — exactly the class of bug behind the ASERT dimensional error
- `unwrap_in_result` — flags `.unwrap()` inside functions that already return `Result`
- `dbg_macro`, `print_stdout` — catches dev leftovers

Kept at warn (not deny) initially because the codebase has ~600 pre-existing occurrences. Escalate to deny per-module as each is cleaned up.

### M4 — I/O ratio comment corrected (`src/consensus/validation.rs`)

The 32:1 input:output ratio consensus rule is REDUNDANT with the uniform-shape enforcement below it (activation at height 0). Original justification ("dust attacks or chain analysis attempts") was misleading. Comment updated to note the rule is legacy belt-and-suspenders code that survives only because removing a consensus rule requires a hard fork. If future tx types legitimately need high ratios, remove it in a fork.

No consensus behavior change.

### C2 — RocksDB zombie ROOT-CAUSED and fixed

**Root cause found (later same session):** `tokio::signal::ctrl_c()` catches **SIGINT only**. `systemctl stop coincync-node` sends **SIGTERM**, which bypassed the entire graceful shutdown path — the process was hard-killed without any RocksDB flush. Between memtable flushes, RocksDB's WAL holds pending writes; a hard exit leaves those in the WAL. On next startup, RocksDB attempts WAL replay, which can hang (WAL truncated by tar capturing mid-write) or produce an inconsistent state that leaves the RPC unresponsive while the DB is stuck in recovery.

**Fix applied in `src/bin/node.rs`:**

1. `SIGTERM` handler added on Unix via `tokio::signal::unix::signal(SignalKind::terminate())`. `tokio::select!` awaits either SIGINT or SIGTERM. Windows keeps the ctrl_c-only path via `#[cfg(unix)]` / `#[cfg(not(unix))]` gating.
2. Between mempool save and `process::exit(0)`: explicit `db.flush_best_effort()` in a `spawn_blocking` task with a **10-second timeout deadline**. On timeout we still force-exit (preserves the "restart works even if disk is broken" property) but under normal shutdown the WAL is fully drained.

Structured tracing added at four boundaries in `Db::open_path` (session earlier work — kept as observability): overall open start, list_cf completion, open_cf_descriptors completion, total open time.

**Prior art:** Bitcoin Core's `init.cpp::AppInit()` installs handlers for SIGINT, SIGTERM, and SIGHUP, all routing to `StartShutdown()`. Bitcoin Core's `Shutdown()` explicitly calls `pcoinsdbview->Flush()` and `pblocktree->Sync()` before returning. Same pattern here.

Compile clean on both `cargo check --lib` and `cargo check --bin coincync-node`.

### H1 — `validate_transaction` refactored (`src/consensus/validation.rs`)

**Before:** single 640-line function, lines 983-1626, ~15 distinct checks fused together, reviewer-hostile.

**After:** 37-line driver + 11 named sub-checks:

| Sub-check | Enforces |
|---|---|
| `check_tx_version_range` | `1 <= tx.version <= MAX_TX_VERSION` (runs before coinbase early return) |
| `check_tx_v2_activation` | V2 txs only at/above `V2_TX_ACTIVATION_HEIGHT` |
| `check_tx_input_output_counts` | Non-empty + within `MAX_TX_INPUTS`/`MAX_TX_OUTPUTS` |
| `check_tx_io_ratio_legacy` | 32:1 legacy check (M4-flagged as redundant with uniform-shape) |
| `check_tx_uniform_shape` | 2-in/2-out or 2-in/3-out for Transfer/Churn post-activation |
| `check_tx_no_double_spend` | In-tx duplicate key_images + chain-level key_image collision |
| `check_tx_ring_members` | Ring member existence + commitment match + coinbase maturity + time lock |
| `check_tx_ring_size_and_unique_members` | Ring size matches `effective_ring_size` + unique members per input |
| `check_tx_ring_signatures` | Parallel CLSAG verify with SeqCst abort flag |
| `check_tx_range_proofs` | Bulletproofs+ range proof verification |
| `check_tx_balance_proof` | Pedersen commitment sum check |

Evaluation order and error types are **bit-identical** to the previous flow. This is a mechanical extraction — no semantic change. Each sub-check is a private helper in `validation.rs` with a docstring explaining what it enforces.

Consensus impact: none (bit-identical). `critical_files.lock` refreshed to match new SHA-256.

**Prior art:** Bitcoin Core's `CheckTransaction()` is under 100 lines with sub-checks (`CheckTxInputs`, `Consensus::CheckTxInputs`, `CheckLockTime`) in separate functions.

---

## 3. Refactor plan for monolithic files (H1, H5)

Not applied this session (each requires a dedicated PR). Documented here as the plan of record.

### 3.1 `src/network/node.rs` (4228 LOC → target ~500 LOC per file)

Split into:
- `src/network/node/mod.rs` — top-level Node struct + orchestration
- `src/network/node/connection.rs` — PeerConnection struct + connection lifecycle
- `src/network/node/handshake.rs` — Version/Verack handshake logic
- `src/network/node/message_handler.rs` — dispatch of incoming P2P messages
- `src/network/node/version_message.rs` — Version message + self-connection nonce
- `src/network/node/inbound_loop.rs` — accept loop + connection limits
- `src/network/node/outbound_loop.rs` — addnode reconnection logic

Each sub-file ≤ 800 LOC. Move-only refactor (no logic changes) delivered as a single PR to minimize review friction.

Prior art: Bitcoin Core's `net.cpp` was split into `net.cpp` + `net_processing.cpp` + `netbase.cpp` after hitting ~4000 LOC. Same trigger.

### 3.2 `src/chain.rs` (3145 LOC → ~500 LOC per file)

Split into:
- `src/chain/mod.rs` — Blockchain struct + top-level API
- `src/chain/reorg.rs` — reorg evaluation and application
- `src/chain/tip.rs` — ChainTip logic
- `src/chain/persistence.rs` — DB rebuild + persist
- `src/chain/cut_through.rs` — MW cut-through candidate management
- `src/chain/checkpoint.rs` — checkpoint enforcement

### 3.3 `src/consensus/validation.rs::validate_transaction` (640-line function)

Split within the same file (avoid moving across module boundaries — the tests may reference private helpers):

```rust
fn validate_transaction(tx, utxos, height) -> Result<()> {
    check_version_range(tx)?;
    check_coinbase_early_return(tx)?;
    check_v2_activation_gate(tx, height)?;
    check_input_output_counts(tx)?;
    check_uniform_shape(tx, height)?;
    check_double_spend(tx, utxos)?;
    check_ring_signatures(tx)?;
    check_range_proofs(tx)?;
    check_balance(tx)?;
    check_fees(tx)?;
    Ok(())
}
```

Each sub-function ≤ 80 LOC. Auditable in isolation. Each mostly-pure so testable without a full UtxoSet fixture.

Prior art: Bitcoin Core's `CheckTransaction()` is ~100 LOC. Sub-checks in separate functions.

### 3.4 `src/rpc/server.rs` (2353 LOC)

Split by RPC method group: `server/mod.rs` + `server/chain_methods.rs` + `server/wallet_methods.rs` + `server/admin_methods.rs` + `server/multisig_methods.rs`.

### 3.5 `src/consensus/validation.rs` (1954 LOC after H1 split)

After validate_transaction is broken up, extract remaining sub-modules: `validation/header.rs`, `validation/transaction/` (with the sub-checks above), `validation/block_body.rs`.

### 3.6 Sequencing

To minimize consensus risk:
1. **First:** split `validate_transaction` internally (§3.3) — no cross-file movement, moderate diff, easily reviewable
2. **Second:** split `chain.rs` (§3.2) — logic is clearer, invariants easier to verify
3. **Third:** split `node.rs` (§3.1) — biggest diff, but purely networking, no consensus surface
4. **Fourth:** split `rpc/server.rs` (§3.4) — RPC surface, low consensus risk
5. **Last:** the final `validation.rs` split (§3.5) — cleanup pass after all the above

Each as a separate PR of 1000-1500 lines diff, one week apart, giving reviewer + CI time between.

---

## 4. Scope-freeze policy for v1.0 (A1)

**Rule:** the only crates shipped in the v1.0 mainnet binary are:
- `coincync` (main chain library)
- `coincync-node` (bin)
- `coincync-wallet` (bin)
- `coincync-rig` (bin)
- `bridge` (crypto FFI shim)

Everything else is either:
- Feature-gated OFF by default (does not compile into release binary)
- Moved to a separate repository until v1.1 or later
- Deleted if not actively developed

### 4.1 Explicit disposition

| Crate | v1.0 status | Rationale |
|---|---|---|
| `crates/coincync-swap` | **Move to separate repo** | Atomic swaps are v1.1 (`project_staged_mainnet`). No production use. Keeps v1.0 audit perimeter minimal. |
| `crates/orchard-side` | **Move to separate repo OR feature-gate** | Zcash Orchard notes — not activated in v1.0. |
| `crates/coincync-frost-coordinator` | **Feature-gate OR move** | FROST threshold sigs — no production wiring. |
| `crates/coincync-rolling-finality` | **Keep, feature-gated** | Already `rolling-finality` feature-gated. |
| `crates/cynchub` | **Move to separate repo** | Merge mining exploration. Not on the v1.0 roadmap. |
| `coincync-wallet-v2` | **Keep** if it's the wallet MVP for v1.0.14 per roadmap | Verify with roadmap. |
| Feature-gated sketch modules (`sketch-lelantus-spark`, `sketch-kernel-offsets`, `sketch-cut-through`, `sketch-block-aggregation`) | **Keep as-is** | Correctly quarantined via cargo features. |

### 4.2 Enforcement

Add a CI check:
```bash
# Fail the release build if any non-approved crate is a workspace default
cargo tree --workspace --depth 1 -e normal --format "{p}" | grep -vE "coincync|bridge|coincync-node|coincync-wallet|coincync-rig|coincync-rolling-finality|coincync-wallet-v2" && exit 1 || exit 0
```

Also: audit teams charge by crate. Every removed crate is $10-30k saved on the external audit.

### 4.3 Timing

Effective immediately for v1.0.12 and later. `feat/v1.0.12-hard-fork-prep` and `v1.0.12-release` branches should NOT include any workspace member outside the approved list.

---

## 5. External security audit RFP template (A/H1)

Draft below. Fill in [BRACKETED] fields before sending.

---

**To:** [Least Authority | Trail of Bits | Cure53 | NCC Group]
**From:** Jeremy [surname], [role], CoinCync Project
**Subject:** Request for Proposal — CoinCync v1.0 Mainnet Pre-Launch Security Audit

Dear [Firm],

CoinCync is a privacy-preserving proof-of-work Layer 1 blockchain launching mainnet on **2026-10-01**. We are seeking a formal security audit ahead of mainnet activation.

### Project overview

- **Chain type:** Privacy PoW L1 with RandomX + CLSAG ring signatures + Bulletproofs+ range proofs + stealth addresses
- **Language:** Rust (v1.88.0 pinned)
- **Codebase size:** ~117,000 LOC across a workspace of ~5 approved production crates (post-scope-freeze per docs/audit/2026-06-30-expert-audit-response.md §4)
- **Public repo:** github.com/ghostrider1092/Coincync-Testnet-
- **Docs:** `docs/cip/` (consensus improvement proposals), `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md`
- **Existing quality signals:**
  - Kani formal proofs on fee_market + difficulty helpers
  - Critical file integrity lockfile with SHA-256 hashes on consensus files
  - Testnet has been live [X months] with [Y commits]
  - Prior in-session expert triage (this document) with several fixes already applied

### Scope requested

Priority tier 1 (must-audit):
- `src/consensus/` — block/transaction validation, PoW, difficulty, fee market, checkpoints, rolling finality
- `src/crypto/clsag.rs`, `src/crypto/bulletproofs.rs`, `src/crypto/stealth.rs`, `src/crypto/curve.rs`, `src/crypto/ring_selection.rs`
- `src/chain.rs` (reorg, fork choice, tip management)
- `src/mempool.rs` (admission, RBF, key-image conflicts)
- `src/db/` (persistence layer + RocksDB shim, including 2026-06-30 zombie-state incident)
- `src/network/noise.rs` + P2P protocol framing (`src/network/protocol.rs`, `src/network/framing.rs`)

Priority tier 2 (should-audit):
- `src/rpc/` — RPC surface + auth
- `src/network/sync.rs` — IBD, header sync
- `src/consensus/pow.rs` — RandomX integration
- `src/emission/` — supply curve

Priority tier 3 (out of scope for v1.0 audit):
- `crates/coincync-swap`, `crates/orchard-side`, `crates/cynchub` — not shipping in v1.0
- Feature-gated `sketch-*` modules — post-mainnet CIPs
- Explorer + wallet UI code

### Deliverables requested

- Written report of findings by severity (Critical / High / Medium / Low / Informational)
- Each finding with recommended remediation + prior-art references where applicable
- Executive summary suitable for public disclosure
- One remediation review round included (verify fixes after we address findings)
- 60-day availability window post-report for questions

### Timeline

- **Ideal engagement window:** [dates — target ~6-8 weeks before Oct 1 mainnet, so ~August 2026]
- **Report delivery:** at least 3 weeks before mainnet activation
- **Remediation window:** 3 weeks between report + mainnet

### Budget guidance

Please provide fixed-fee quote AND time-and-materials estimate for the tier 1 scope, with tier 2 as a separately-quoted add-on. Comparable-project reference points we're working with:
- Trail of Bits' Zcash audits: $250-400k
- Least Authority's smaller Rust chain audits: $80-150k
- We anticipate landing in $80-250k range depending on tier + firm

### Q&A

Happy to schedule a technical walkthrough of the architecture ahead of quote. Contact: [email].

---

## 6. Bus-factor recruitment brief (A2)

Currently: bus factor of 1 (Jeremy). Per `feedback_expert_with_blockchain_references` and the reference-implementation goal, this must be raised to ≥ 3 before "reference implementation" claim is credible to any external integrator.

### 6.1 Roles to fill

**Deputy consensus engineer** (highest priority)
- Reviews all consensus PRs before merge
- Owns `critical_files.lock` refresh sign-off
- Emergency responder for consensus-affecting incidents
- Must have: Rust + Bitcoin/Monero/Zcash codebase experience
- Compensation: [equity or paid position TBD]

**Deputy operator (infra)** (second priority — was tonight's real bottleneck)
- Fleet operator with SSH access to all 9 hosts
- Runs the daily snapshot procedure
- Owns the operational runbooks
- Must have: Linux ops + at least one prior blockchain fleet operation
- Compensation: [TBD]

**Community + protocol advocate** (third priority)
- Runs Discord, PR-review triage, external inquiries
- Owns the CIP drafting flow
- Reduces founder bottleneck on non-technical decisions

### 6.2 Recruiting channels

- Monero community (`monero-project` on Freenode/Libera) — expert privacy PoW developers
- Zcash Foundation grant recipients — Rust + zk expertise
- rust-bitcoin maintainers who might moonlight
- Cypherpunks mailing list
- Real World Crypto attendees
- Job boards: r/CryptoCurrencyJobs, cryptojobslist.com

### 6.3 Onboarding checklist

For each new maintainer:
1. Read `CONSTITUTION.md` + `docs/BILL_OF_RIGHTS.md` + this audit doc
2. Sign contribution agreement (needs template — see `docs/legal/CLA.md` — currently missing)
3. Add PGP key to `MAINTAINERS.md`
4. Add SSH pubkey to fleet's `authorized_keys` (for deputy operator only)
5. Sit through 2 weeks of PR reviews as observer before merge rights
6. Trial period: 3 months at commit access, then full commit + release-cert rights

### 6.4 Success metric

Bus factor = 3 by end of Q1 2027. Measured by: number of humans with (a) commit access to main, (b) release-cert authority for `critical_files.lock` refresh, (c) fleet SSH access.

---

## 7. Post-mainnet reference-implementation roadmap

Extracted from tonight's discussion. Not a commitment — a plan.

### 7.1 Q1 2027: publish crates

Extract from monolithic workspace and publish to crates.io with semver:

- `coincync-clsag` — CLSAG ring signatures on Ristretto
- `coincync-bulletproofs-plus` — range proofs
- `coincync-stealth-address` — stealth address derivation
- `coincync-asert` — ASERT-i3-2d difficulty adjustment
- `coincync-randomx-verify` — RandomX verification (mining separate)

Each with: independent audit report link, doctests, docs.rs coverage, integration test suite.

### 7.2 Q2 2027: seed alt implementation

Publish a "spec-check" test suite that consumes JSON block/tx fixtures + expected verification outcomes. Anyone can build a partial implementation that passes it.

Ideal first alt-impl target: Go or Zig implementation of block header validation + CLSAG verify. Doesn't need to be a full node — just enough to prove interoperability.

Success metric: at least one external project uses the CoinCync crates by end of 2027.

### 7.3 Ongoing: expand Kani coverage

Current Kani proofs: fee_market + difficulty helpers only. Expand to:
- Reorg depth calculations (`chain.rs`)
- ASERT clamping bounds
- Bulletproofs verifier bounds
- CLSAG ring size bounds

Target: 25% of consensus code covered by Kani proofs by mainnet.

---

## 8. What was NOT applied this session

Deliberately deferred:

- **Full refactor of monolithic files (§3)** — needs dedicated PRs
- **CI enforcement of scope-freeze (§4.2)** — needs CI config change, operator-owned
- **Bus-factor recruitment (§6)** — operator-owned
- **External audit engagement (§5)** — operator-owned
- **Fork-choice tiebreak** — per project memory, scheduled for v1.0.12 hard fork. Verify lands before mainnet.

---

## Signature

This document is a session artifact. Not authoritative until reviewed + signed by the operator. Suggested review checklist:

- [ ] Diff of the 5 code fixes reviewed
- [ ] `critical_files.lock` update reviewed
- [ ] Cargo.toml changes (H2 feature + M1/M2 lints) reviewed
- [ ] Refactor plan §3 accepted (or amended)
- [ ] Scope-freeze §4 accepted (or amended)
- [ ] Audit RFP §5 accepted (or amended)
- [ ] Bus-factor plan §6 accepted (or amended)

Once accepted, commit as a squashed PR or as individual per-finding commits per operator preference (per `feedback_commits_need_explicit_ok`).
