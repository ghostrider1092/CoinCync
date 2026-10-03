# CoinCync correctness program

A staged program to raise CoinCync's correctness ceiling to the standard a
security audit (and mainnet) demands, modeled on the practices of
correctness-first engineering shops: make illegal states unrepresentable, prove
the consensus holds under adversarial simulation, enforce invariants fail-closed,
gate risk with explicit circuit breakers, and measure everything.

None of this adds user-facing features. It hardens what exists and produces the
*evidence* an auditor needs. It is deliberately incremental: every item below
ships as its own PR, gated green on the full `--features testnet` suite, so the
live testnet is never destabilized. No big-bang refactors.

Status legend: ✅ landed · 🔜 in flight · ⬜ planned.

## Context: what's already landed

- ✅ **#177** — checkpoint single-source-of-truth: one resolver
  (`NetworkType::consensus_checkpoints`) feeds validation, the fingerprint,
  snapshot-import and light-wallet auth, so a checkpoint can't be enforced in one
  path and invisible to another (issue #173).
- ✅ **#178** — dedup sweep: removed a dead 1000×-wrong emission constant and
  collapsed duplicate network-identity definitions (magic/ports/seeds) to one
  source, with drift-guards.
- ✅ **#179** — consensus-invariant registry (policy + glue over the diagnostic
  CATALOG): `fail_closed` policy, the coded-`Report` `check()` helper, the
  consensus-domain view.
- 🔜 **#180** — deterministic-simulation (DST) harness, Phases A–D: extracted
  reusable harness, network partitions, the `Withhold` behavior, and `check_safety`
  wired to emit the coded `CYNC-CONS-003` report.

## Cross-cutting enablers

### E1 — Clock abstraction  ⬜  *(first build item)*
One canonical time source, `src/clock.rs`: `clock::unix_now()` /
`clock::instant_now()`, reading the real clock in production and
**deterministically overridable** (the sim sets virtual time). Migrate the raw
`SystemTime::now()` / `Instant::now()` sites (~13 consensus, ~59 network, the
rest observability) and the ~8 scattered `unix_now()` / `now_secs()` helpers onto
it, in gated batches (consensus/chain first, then network). This is the enabler
for **full-node** DST and is itself a #173-style single-source-of-truth dedup.

### E2 — Transport seam  ⬜
A `Transport` trait with a real-socket implementation and an in-memory
implementation, so the simulator drives the **actual** P2P/sync stack rather than
a re-implementation.

### E3 — Seeded RNG injection  ⬜
A single injectable entropy source so the whole node — not just the sim driver —
is reproducible from a seed.

## Feature 1 — Make illegal states unrepresentable

**End-state.** Consensus-critical primitives are newtypes (`Height`, `BlockHash`,
`KeyImage`, `Target`, `Difficulty`, `Timestamp`, `NetGroup`) so the wrong one
can't be passed; booleans in state machines become enums (sync state, peer state,
validation outcome); every consensus parameter has exactly one definition.

**Deliverables.** The newtype set + migration; the dup-source audit (#173 class)
run to completion with a recurring guard; a test forbidding a bare `u64` height in
consensus signatures.

**Verify.** Compile-enforced; the #178-style dedup anti-regression tests extended.

## Feature 2 — Full-node deterministic simulation (flagship)

**End-state.** The harness runs the real node's components on a deterministic
executor under E1 virtual time + E2 in-memory transport. Behavior library: Honest,
Equivocate ✅, Withhold ✅, InvalidSpam, ClockSkew/demon-timing, Eclipse, Censoring,
Lazy. Faults: latency ✅, drop ✅, dup ✅, reorder ✅, partition ✅ + heal with block
backfill, asymmetric links. The executable invariant registry (Feature 3) runs
after every event; a failure prints the seed and a minimized schedule.

**Deliverables.** `tests/common/sim/` buildout (Phases B–E), a CI seed-sweep
corpus, schedule-shrinking on failure.

**Verify.** Nightly N-seed sweep; every failure is a one-command replay artifact.

**Targets (Phase E).** The bug classes that actually hit the live net:
clock-poisoning (#59), post-restart partition-stall, reorg-stranded pool state.

## Feature 3 — Invariants fail-closed (executable)

**End-state.** Every consensus invariant has an executable check + CYNC code,
wired into validation hot paths (reject with a coded `Report`) and runtime guards
(`debug_assert` in debug; coded reject/halt in release). Coverage: supply
conservation, key-image uniqueness, work monotonicity, difficulty bounds,
timestamp rules, finality monotonicity, coinbase maturity, ring validity, shielded
pool value ≥ 0, storage lock-step.

**Deliverables.** Stage 2 v2 — the check implementations + site wiring, consumed by
Feature 2.

**Verify.** Each invariant has a positive + negative test; a test asserts every
`Error`-severity consensus diagnostic has a live enforcement site **and** a DST
scenario that exercises it.

## Feature 4 — Circuit breakers / risk controls

**End-state.** One `guard` framework — named, typed limits, each with a trip
condition, a fail-closed action (reject / pause / halt / alarm), a CYNC code, and
observable state. Unifies the scattered controls: the solo-mine gate, the mesh
gate, treasury velocity/allowlist, mempool admission, peer scoring/eviction, rate
limits. A tested kill-switch registry (what can halt the node, and why).

**Verify.** DST scenarios trip each breaker; a test asserts every breaker has a
code + a trip test.

## Feature 5 — Measure everything

**End-state.** Every rejection/stall/trip emits a coded event; a flight recorder
(ring buffer of recent coded events) dumps on a fault and feeds DST replay;
per-code counters/rates + a domain-decomposed health score, queryable via RPC and
the `coincync-diag` CLI.

**Verify.** Every CYNC code is emitted by a real site or a test; catalog-integrity
+ coverage tests.

## Build order (dependency-correct; each a gated PR)

1. **E1 Clock** + **E3 RNG** — groundwork.
2. **Feature 3** executable invariants — needed by DST hooks + breakers.
3. **E2 Transport** → **Feature 2** full-node DST (flagship) — consumes 3.
4. **Feature 4** breakers — use 3's registry + 5's codes.
5. **Feature 5** diagnostics full — finalized last (cross-cutting).
6. **Feature 1** type-safety — ongoing parallel batches.

## Discipline / non-goals

- Every change is a small, independently-gated PR. Lock-protected consensus files
  get a fresh `critical_files.lock` regen per change.
- No consensus-rule changes without audit-gate clearance; this program is about
  *enforcing and proving* the existing rules, not changing them.
- Realistic scope: ~15–25 PRs over multiple sessions.
