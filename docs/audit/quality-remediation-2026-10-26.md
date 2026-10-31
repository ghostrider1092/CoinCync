# Quality remediation — 2026-10-26

Scope: the four risks raised in review of the blockchain + code quality. This
doc classifies each as a **bug** (fix it), a **milestone** (sequence/decide it),
or **process** (change how we work), gives current status, and names what is
HELD vs done vs a decision. Two of the four turned out to be based on stale
notes and are **corrected** here — flagged honestly so the record is accurate.

---

## 1. Shielded pool gated / bridge pre-audit — MILESTONE, not a bug

The shielded pool (Option-B bridge: shield-in / shielded-send / unshield) is
`regtest`/`Beta`-gated, `value_balance` relaxations compile to `const false` in
production, and activation height is `u64::MAX`. **This is correct right now** —
flipping it on pre-audit would be the reckless move. Production binaries are
byte-identical with or without the bridge code.

- **Not a code fix.** The next real step is a **coordinated testnet hard fork**
  that sets a finite shielded-activation height and drives real traffic, per the
  audit firm's directive (the bridge must be live on public testnet *before*
  the audit). Mainnet stays `u64::MAX`.
- **Decision/coordination gate**, owned by the maintainers + the fleet, not an
  edit to make unilaterally. Do not let schedule pressure push shielded
  activation onto mainnet ahead of the audit.
- Status: **on track, gated-by-design.** The 8h chaos soak + the bridge
  end-to-end proofs (shield-in / shielded-send / unshield / stealth) are the
  evidence this is ready for the testnet-activation milestone.

## 2. W-A subaddress spend "disabled on mainnet" — CORRECTION: already FIXED

**This was stale.** The claim that subaddress-received funds can't be spent on
mainnet is **no longer true** and hasn't been since 2026-08-18.

- The W-1 disable gate was **lifted**; the mainnet-disable arm was **removed**
  (`src/bin/wallet_support/legacy.rs`, `Command::Subaddress` arm).
- The spend-side fix is in: `wallet::subaddress::compute_subaddress_spend_secret`
  derives `x_i = x + m_i`, where `m_i = crypto::subaddress_scalar(view, account,
  index)` — the per-subaddress offset is threaded into the spend secret (and
  therefore the key image), from the SAME function the `D_i` receive pubkey uses
  (single source of truth, cannot diverge).
- Coverage: regression test `subaddress_output_is_spendable_wa_regression`
  (`scanner.rs`), mainnet round-trip `subaddress_roundtrips_on_mainnet_and_testnet_after_w1_gate_lift`
  (`address.rs`), and the real-crypto e2e `real_crypto_subaddress_output_spendable_e2e`
  (`tests/full_pipeline_real_crypto.rs`).
- The one *remaining* subaddress hole — the vesting→subaddress path using
  `add_output` instead of `add_output_ext` (silent fund loss) — was fixed in the
  2026-10-26 audit sweep (Wallet-2).

- **Action:** none (no bug). The only follow-up is to **run the e2e test to
  confirm green on this branch** — deferred until the 8h soak finishes so the
  test build doesn't contend with the running node. Stale memory lines were
  corrected (MEMORY.md index + next-gen-roadmap).

## 3. "16 bugs of one class / features ahead of implications" — PROCESS

Real and fair: the Option-B bridge landed before all its cross-cutting
consequences were traced, and the audit sweep caught 16 bugs of the class
"a shielded tx has no transparent side" (decoy #2 among them). The review
process *did* catch them, but retroactively.

Forward guards (partly cultural, partly items 1 & 4):
- **Invariant-first before landing bridge-touching code**: enumerate every site
  that assumes pure-shielded shape *before* merging a change that breaks that
  assumption (the sweep had to do this retroactively; do it as a pre-merge step).
- The **external audit** is the backstop; do not treat the sweep as a substitute.
- **CI coverage of the gated surface** (item 4) makes a regression in this exact
  class fail automatically instead of being found by the next sweep.
- Status: the decoy-#2 class is swept (16 fixes + Wallet-1 + the unshield port,
  all HELD pending 2-of-N). The habit change is the open part.

## 4. "No CI" — CORRECTION: CI exists; the real gap is narrower

**This was stale too.** There IS comprehensive GitHub Actions CI (added
2026-10-24): `integration-tests.yml` runs 600+ unit/lib/bin tests + ~480
integration tests (reorg, p2p/DoS, crypto, historical-attack, `consensus_edges`,
`regression_critical`, `full_pipeline_real_crypto`) sharded on every PR and push
to main, with an aggregate `all-shards` gate for branch protection;
`critical-lock.yml` enforces `critical_files.lock` on consensus-file changes;
plus lint, audit, coverage, fuzz, hardening-baseline, verify-reproducible. The
"green subset broke main" risk is largely addressed for the transparent core.

**The precise remaining gap:** every workflow builds with
`--features "randomx testnet"`. **Nothing enables the gated shielded/breaker
features** (`sketch-gk-proof`, `libspark-ffi`, the `*-breaker`s, `regtest-chaos`).
So the Option-B bridge, shielded pool, unshield, and all 7 breakers — the newest,
highest-churn surface (item 3's 16 bugs) — are built and tested **only on a
maintainer's laptop**. A PR can be CI-green and still regress the bridge.

- **Fix (HELD): `.github/workflows/shielded-gate.yml`** — a new workflow that
  runs the gated unit suite (`cargo test --release --lib --features "<gated>"`,
  **no** `test-fast-pow`) + the gated real-crypto integration test + a gated
  `cargo check` (which also runs the lock-integrity build.rs under the real
  feature set). spark-connector builds on `ubuntu-22.04` with system OpenSSL
  (`SPARK_OPENSSL_DIR=/usr` + the `clang`/`libssl-dev` the runners already
  install), per the Linux portability work.
- **Needs first-run validation on GitHub** (Actions-only; can't be run locally).
  If the hosted runner's OpenSSL layout differs, the only change needed is the
  `SPARK_OPENSSL_DIR`/apt step in that workflow — never the pinned Firo crypto.
- Consistent with existing posture: CI already runs consensus code on GH Actions
  runners, so this is coverage extension, not new exposure.

---

## Priority / sequence

1. **CI gated coverage** (`shielded-gate.yml`) — highest leverage; prevents the
   item-3 regression class automatically. HELD; validate on first GitHub run.
2. **Finish the in-flight hold**: 8h soak verdict → 2-of-N sign-off on the
   locked `validation.rs` (audit sweep + unshield) → then merge is unblocked.
3. **Testnet shielded activation** (item 1) — coordinated fork + real traffic,
   the pre-audit milestone. Decision/coordination, not a unilateral edit.
4. **External audit** — the backstop for item 3; nothing here substitutes for it.

## What is HELD vs done vs a decision

- **Done (verified):** W-A subaddress spend (item 2); the audit-sweep + unshield
  port (gated 2400/0, SMOKE triad green) — committed, signed, HELD.
- **HELD (needs 2-of-N / your push):** the locked `validation.rs` changes;
  `shielded-gate.yml`.
- **Decision/coordination (not code):** testnet shielded activation; the external
  audit engagement; whether/when to push `shielded-gate.yml`.

_Nothing in this remediation is pushed or merged. Everything stays held until the
2-of-N sign-off lands and you authorize the push._
