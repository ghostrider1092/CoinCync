# Warren — PoW-native modular privacy architecture

**Status:** DRAFT / design (vision + phased roadmap). Not a CIP yet; the only
piece that touches consensus rules (the L1 batch verifier, Phase 2) will get its
own CIP.
**Last updated:** 2026-10-07

---

## 0. TL;DR

Decouple CoinCync into a lean **PoW settlement layer** and a **privacy execution
layer** connected by a cryptographic bridge, so heavy zero-knowledge / stealth
payloads no longer force every node to store and re-verify everything. Keep it
**fully permissionless PoW** — no BFT committee, no validator set, no
proof-of-history clock. The one piece of the popular "DAG-BFT + DA" design that
does not fit PoW (the ordering committee) is exactly the piece PoW replaces:
heaviest-work gives a canonical total order for free; we only make blocks carry
*commitments* instead of *payloads* so that ordering stays cheap.

This document names the layers, specs the components, is honest about the one
genuinely hard part (a recursive proof over the shielded state transition), and
phases the work so it **does not derail the "finish one audited Spark pool →
audit" path**. Most of Phase 0 is shippable inside the current scope.

Named layers:

| Name | Role |
|---|---|
| **Surface** | the lightweight commitment view on the PoW chain |
| **Bedrock** | PoW settlement L1 — security, ordering, finality |
| **Warren** | privacy execution L2 — heavy ZK, batched |
| **Burrow** | the bridge/connector — proofs down, value across the veil |
| **Sluice** | the self-regulating parallel-verify valve (Phase 0) |
| **Dig-Out** | self-healing fork recovery (Phase 0, also a Warren prerequisite) |

---

## 1. Motivation

Privacy payloads are heavy. A Lelantus-Spark spend carries Grootle membership +
Chaum tag-binding + range + balance proofs; verifying one is CPU-expensive, and
storing all of them forever is the real long-term bloat. A monolithic design
forces **every** full node to (a) store every proof and (b) re-run every verify,
which bounds throughput to the slowest verifier and grows storage without limit.

Three problems follow, and this design addresses each with a PoW-native tool:

1. **Verification cost** → verify in parallel, off the block-apply hot path
   (**Sluice**, Phase 0), and eventually behind one succinct batch proof
   (**Warren**, Phase 2).
2. **Storage bloat** → prune proof bytes after finality, keep only
   commitments/nullifiers (Phase 0); move the heavy payload off-chain into a DA
   fabric (Phase 3).
3. **Fault isolation + fork fragility** → a bug in the heavy privacy logic must
   not fork or crash the base chain. Decoupling gives that; **Dig-Out** makes the
   base chain self-heal from the forks that *do* happen (observed live on
   testnet, 2026-10-07).

### Non-goals

- **No DAG-BFT committee.** DAG-BFT (Mysticeti/Bullshark) needs a known
  validator set for a 2/3 quorum. Electing it "by mining performance" or syncing
  it via a PoH clock reintroduces a permissioned, slashable set. PoW already
  gives a canonical order; we do not import a committee to re-derive one.
- **No auto-wipe on "peers claim higher work."** Trusting peer-advertised work to
  self-destruct and resync is an eclipse vector. Deep-fork recovery stays
  operator-initiated or checkpoint-anchored (§6.2).
- **No abandonment of the UTXO privacy model.** Warren wraps the existing Spark
  pool; it does not replace it with an account model.

---

## 2. Architecture overview

```
          users submit shielded txs
                     │
                     ▼
        ┌───────────────────────────┐
        │   WARREN  (privacy L2)     │   heavy ZK, batched, isolated
        │   verify → batch → prove   │   a bug here cannot fork Bedrock
        └──────────────┬────────────┘
                 batch proof + new_root + DA commitment
                     │  (the BURROW)
                     ▼
        ┌───────────────────────────┐
        │   BEDROCK (PoW L1)         │   order (heaviest-work), verify ONE
        │   verify_batch + settle    │   proof, update shielded_state_root
        │   + transparent txs        │   — never re-runs per-tx Spark math
        └───────────────────────────┘
                     ▲
            SURFACE = what everyone sees on Bedrock:
            commitments, nullifiers, payload_root, value_balance
```

Value crosses the veil through the Burrow using CoinCync's **existing**
transparent↔shielded bridge (`verify_transparent_shielded_balance`): a deposit
is a shield-in (`value_balance < 0`), a withdrawal is an unshield
(`value_balance > 0`). That equation is already implemented and tested — it is
the conceptual load-bearing wall and it is already standing.

---

## 3. Components

### 3.0 Heavy privacy-verify inventory (Spark is not the only one)

The bloat/verify-cost problem spans several crypto surfaces, not just Spark. The
design must treat them uniformly:

| Feature | Where verified | Weight | Parallel today? | Prunable after finality? |
|---|---|---|---|---|
| **Bulletproofs** range proofs (`crypto/bulletproofs.rs`) | per transparent tx, block validation | heavy | ✅ `par_iter` (validation.rs) | yes (keep commitment) |
| **CLSAG** ring sigs (`crypto/clsag.rs`) | per transparent input | heavy | ✅ `par_iter` (`check_tx_ring_signatures`) | no (needed for key-image audit) |
| **Spark** bundles (`spark-connector`, Grootle/Chaum) | per shielded tx, `verify_block_spark_v2` | **heaviest** | ❌ **serial** — the gap | yes (keep nullifier + commitment) |
| native GK sketch (`crypto/lelantus_spark.rs`, `groth_kohlweiss.rs`) | gated off, unsound | heavy | n/a (inert) | n/a |
| Orchard/Halo2 (`crates/orchard-side`) | gated off, non-consensus | heavy | n/a (inert) | n/a |
| Swap adaptor sigs (`crates/coincync-swap`) | per-swap protocol, not block validation | moderate | n/a | n/a |

Two consequences:
1. **The transparent heavy paths are already parallel; only Spark is serial.** So
   Sluice is not "parallelize from scratch" — it extends an established pattern to
   the shielded path.
2. **Today's transparent `par_iter` runs on rayon's global pool, uncapped.** Add
   parallel Spark while a node mines (RandomX on all cores) and you oversubscribe.
   So Sluice must govern **one bounded verify pool across every heavy path**, kept
   separate from mining — which also fixes the existing uncapped risk.

### 3.1 Surface (commitments only)

Bedrock blocks carry, per shielded settlement: nullifiers, output commitments, a
**payload root** (Merkle/erasure root over the heavy bundles), the public
`value_balance`, and (Phase 2) the batch proof. Kilobytes, not megabytes. This is
an evolution of today's `tx.extra`: the heavy Spark bundle moves *out* of the
block and leaves a commitment behind.

### 3.2 Bedrock (PoW settlement L1)

Jobs: order blocks (RandomX heaviest-work, unchanged), validate transparent txs
(CLSAG rings, unchanged), and — in Phase 2 — verify **one** succinct batch proof
and advance a single `shielded_state_root`. It never runs per-tx Spark
verification. Finality is PoW-native: heaviest-work + the existing reorg-depth /
finality-floor gate (`CHECKPOINT_INTERVAL = 144`), optionally tightened by
miner-attested rolling finality (`coincync-rolling-finality` +
`coincync-frost-coordinator`). No new trust assumptions.

### 3.3 Warren (privacy execution L2)

All heavy crypto lives here, isolated. Users submit shielded txs; Warren batches
them, verifies each, and (Phase 2) produces one succinct proof that the whole
batch is a valid state transition — every nullifier unspent, every membership/
range/balance proof valid, commitments appended — emitting the new root. A faulty
batch fails Bedrock's verifier and is rejected; it cannot fork or crash the base.

### 3.4 Burrow (the bridge/connector)

Carries the batch proof *down* to Bedrock for settlement and *value* across the
veil (deposits/withdrawals via the value bridge). Maps onto the existing
`crates/bridge`, `shielded_connector`, and `crates/orchard-side` connector
surfaces.

### 3.5 Sluice (the unified verify valve) — Phase 0, buildable now

One self-regulating concurrency valve governing **every** heavy privacy-verify
path (Bulletproofs, CLSAG, Spark), on a **dedicated bounded pool kept separate
from the RandomX mining pool**. Not "parallelize Spark" — "one governed valve
across all of §3.0."

**Invariant (the whole point):** the valve setting controls *throughput, never
the result*. Any node — 1 core clamped or 32 cores wide-open, mining or idle —
computes the **same** accept/reject on every path. Consensus never depends on the
valve. This is what makes it set-and-forget.

Mechanics:
- **Dedicated verify pool, mining-separate.** All heavy verify runs on a bounded
  pool sized `max(1, cores − headroom)`; RandomX mining threads are *not* drawn
  from it, so the two never oversubscribe (fixes the current uncapped global-pool
  behaviour on the transparent paths too).
- **Adaptive.** Shrinks the verify pool while `NODE_MINING_ACTIVE` (RandomX is
  hogging cores), grows it when idle/syncing.
- **Circuit-breaker.** If a parallel path fails — a panic, or the libspark
  thread-safety self-check returns false at startup — that path's valve closes to
  **serial**. Same results, slower. Self-healing, per-path.
- **One optional override:** `COINCYNC_VERIFY_THREADS` (0 = auto).

The parallel split (matches a parallel-process flowchart: fan-out branches →
single convergence gate). For the Spark path specifically:
- **Parallel (independent, pure):** decode, `verify_transparent_shielded_balance`,
  `verify_mint_shield_in`, `verify_spark_payload` — against a **snapshot** of
  `store.spent_tags()` taken once before fan-out, so each verify is race-free.
- **Serial Conclusion gate (ordered, deterministic):** within-block linking-tag
  uniqueness (`seen_tags`) + the `simulated_pool -= value_balance` accumulator.

The transparent paths (Bulletproofs, CLSAG) already have this shape; Sluice just
moves them onto the governed pool.

Two safety checks before trusting the Spark path: libspark verify FFI must be
reentrant (no global mutable C state); `SparkPoolStore` reads must be
concurrent-safe (immutable snapshot during the parallel phase). Both are small to
verify/fix.

Test that locks the invariant (for *each* path): a block with valid +
double-spend + bad-proof txs returns byte-identical accept/reject for valve ∈
{serial, 1, 2, all}.

### 3.6 Dig-Out (self-healing fork recovery) — Phase 0, buildable now

A node on a **minority fork** requests the majority chain's block spans; peers
that lack a speculative span return empty → after 5 empties each peer is
GetBlocks-banned for 1 h → all peers banned → `[IBD] No live peers for GetBlocks`
loops forever; **no recovery tier clears the ban.** (Diagnosed live on the seed,
2026-10-07 — wedged 35 h, fixed only by a manual data-dir wipe.)

Fix (networking only — the reorg-depth/finality gate is unchanged, so **not a
CIP**):
1. **`PeerScorer::clear_get_blocks_bans()`** — reset `get_blocks_banned_until` +
   `consecutive_empty_blocks` across scores; called from the emergency-recovery
   tier when stuck-but-not-synced with connected peers (emptiness is purely bans,
   not disconnection). Auto-recovers **shallow** forks.
2. **Coverage-aware span assignment** — in `send_block_spans`, only assign a
   height range to a peer whose advertised height/work covers it. Empty replies
   ≈ 0 → bans stop accumulating at the source (prevention > cure).
3. **Deep fork = loud + observable, never silent.** When stuck beyond the
   finality floor (`tip − 144`, unreorgable), emit one definite remedy line and a
   `get_info` `fork_stuck: bool` + `blocks_behind` so the rig's MESH strip and
   monitors light up. **No auto-wipe** (eclipse). Operator-initiated
   `reset-to-network` is a follow-up.

### 3.7 Enabling infrastructure — making it flow smoothly

Shared seams so each piece slots in cleanly instead of being re-plumbed per
feature:

- **`HeavyVerify` trait** — one interface every heavy path (Bulletproofs, CLSAG,
  Spark, future engines) implements: `verify_parallel(items) -> Result<Outcome>`
  with an explicit "what's parallel vs the serial gate" contract. Sluice governs
  anything behind this trait uniformly; adding a proof engine is implementing one
  trait, not touching the block validator.
- **Sluice `VerifyPool`** — the bounded, adaptive, mining-separate pool (§3.5) as
  a reusable component, not an ad-hoc `par_iter`.
- **Verify-result cache (LRU, by proof hash)** — a proof verified in the mempool
  is not re-verified when the tx lands in a block, nor again on a reorg replay.
  Keyed by the proof/bundle hash; bounded size. Big smoothness + throughput win,
  and safe (a hash collision is infeasible; cache miss just re-verifies).
- **Determinism harness** — a test helper that runs *any* `HeavyVerify` path
  serial vs parallel (every valve setting) and asserts identical results. Makes
  parallelizing any future path safe-by-construction.
- **Pruning scheduler** — one finality-triggered hook that drops prunable proof
  bytes (§3.0) and keeps commitments/nullifiers, with a snapshot escape so an
  archival node can opt out.
- **Connector registry** — the `SparkBackend` pattern generalized so engines
  (libspark, a future recursive prover, StubBackend) register and swap cleanly.
- **Metrics + benches** — per-path verify timings, pool utilization, cache
  hit-rate (feeds the adaptive valve *and* operators), plus criterion benches so
  the parallel speedup is measured and regressions caught.
- **Fixtures/builders** — reuse the synthetic-input/shielded-tx builders
  (`send/tests.rs`, `spark_payload.rs` builders) so e2e tests are cheap to write.

### 3.8 Protections — the guards that keep it safe

Each enabling piece ships with its guard; none is optional:

- **Determinism IS consensus safety.** The valve-invariant test (§3.5) + a hard
  rule: the parallel phase touches **no shared mutable state** (only immutable
  snapshots). Different core counts/valve settings must never diverge on
  accept/reject. This is the single most important protection.
- **Panic isolation.** Every parallel verify worker runs under `catch_unwind`; a
  panic trips the per-path circuit-breaker to serial and is logged — it never
  crashes the node or, worse, is misread as a verify *result*.
- **Thread-safety gate.** The libspark FFI reentrancy self-check runs at startup;
  if it can't be proven safe, the Spark path starts **serial** (closed valve) —
  parallel is opt-in on a proven-safe backend only.
- **DoS bounds everywhere.** Bounded verify pool (no thread-bomb), per-block tx
  caps (exist), bounded proof/bundle sizes (the `spend_ltags` `output_count`
  bound is the template), bounded orphan/header/cache memory (LRU + caps), and —
  the economic guard — **verification-weighted fees** so forcing expensive verify
  on every node costs the sender.
- **Fail-closed by default.** Activation stays `u64::MAX` until audit; the
  `StubBackend` rejects; the Phase-2 L1 batch verifier rejects any malformed or
  unverifiable batch; the Warren cannot move value without a settled Bedrock
  proof.
- **Fault isolation (the core benefit).** An L2 / Warren bug fails Bedrock's
  verifier and is rejected — it cannot fork or crash the base chain. This is why
  we decouple at all.
- **Eclipse + fork protection.** Dig-Out keeps the base chain on the canonical
  tip; deep forks are loud, never silent, and recovery is **checkpoint-anchored**
  — we never trust peer-advertised work to take a destructive action (no
  auto-wipe). Phase-1 outbound/netgroup diversity closes the inbound-only wedge
  that bit the seed.
- **Reorg/finality guard unchanged.** `max_reorg_depth` + the finality floor
  (`CHECKPOINT_INTERVAL`) stay exactly as they are; Warren adds no new reorg
  surface.
- **DA honesty (Phase 3).** Availability must be *proven* (erasure + sampling),
  never assumed; a false availability guarantee is worse than none, so that phase
  gets the hardest review and does not ship on trust.

---

## 4. The genuinely hard part — be clear-eyed

Everything above is plumbing. The crux — "bundle thousands of private txs into a
single tiny proof" (Phase 2) — is **the** research problem, and it is hard for a
*Spark/UTXO* model specifically:

- Spark's native proofs (Grootle / Groth-Kohlweiss) **do not recursively
  aggregate cheaply.** You can batch-verify N of them, but you cannot squish N
  into a constant-size proof for free.
- A real rollup therefore needs a **recursive proof system**: a Halo2/Nova-style
  circuit ("I verified N shielded transitions") or a STARK over the state
  machine. That is Zcash-Orchard-scale work. (The `crates/orchard-side` name
  suggests this has already been poked at — the right instinct.)

If that proof system is not ready, Warren is a **batched sidechain** (less
broadcast, still useful) but **not** a succinct-proof rollup. This single result
determines which one you have, so it is prototyped and reviewed **before**
committing to Phase 2.

---

## 5. Threat model / open risks

- **Data availability (Phase 3).** If L2 tx data is not provably available, users
  cannot reconstruct state or force-exit — "privacy rollup" degrades to "trust
  the sequencer." DA done *wrong* (false availability guarantees) is worse than
  no DA. Needs erasure coding + sampling, its own spec, the hardest review.
- **Sequencer / prover centralization.** A single batcher/prover is a censorship
  + liveness chokepoint. Needs permissionless proving and/or L1 forced-inclusion
  + an escape hatch.
- **Eclipse.** A node with only inbound peers (the seed's failure mode) cannot
  heal and is eclipse-prone. Phase 1 adds outbound-peer maintenance across
  diverse netgroups (/16 buckets).
- **Upgrade keys.** "Upgradeable privacy engine" is also an admin-key attack
  surface; governance must be designed, not assumed.
- **L1 verifier bugs (Phase 2).** The batch verifier runs in consensus → a bug is
  a chain split. Versioned activation + heavy review + an audited verifier.

---

## 6. Phased roadmap (audit-first; does not sprawl)

The project rule stands: **one audited Spark pool, finish → audit, scope sprawl
is the risk.** This design is phased so the audit is not derailed.

### Phase 0 — now, inside current scope (no new trust, mostly perf/robustness)
- **Foundations (§3.7/§3.8):** the `HeavyVerify` trait, the Sluice `VerifyPool`,
  the determinism harness, and the per-path circuit-breaker + panic isolation.
  These are the seams everything else slots into — build them first.
- **Sluice** — the unified verify valve across Bulletproofs/CLSAG/Spark on the
  mining-separate pool, with the valve-invariant test per path.
- **Dig-Out** — self-healing fork recovery (#1–#3 above).
- **Verify-result cache** — skip re-verify on mempool→block and reorg replay.
- **Proof pruning after finality** — keep commitments/nullifiers, drop prunable
  proof bytes past the finality depth. Bounded storage.
- **Verification-weighted fees** — a shielded tx's fee floor scales with the
  verify work it forces on every node (anti-ZK-spam; the honest "anchor heavy
  data to energy").

### Phase 1 — eclipse / resilience hardening
- Outbound-peer maintenance across diverse netgroups.
- Checkpoint-pinned bootstrap + **safe** (checkpoint-anchored) auto-resync.
- Operator `reset-to-network` one-shot.
- Rolling-finality integration to narrow the reorg window.

### Research track (parallel, low commitment, gates everything after)
- Recursive proof over the shielded state transition (§4). Prototype + review
  **before** Phase 2 is committed.

### Phase 2 — post-audit, needs the research result + a CIP
- `ShieldedBatch` object + the L1 batch verifier in Bedrock consensus.
- Burrow deposit/withdraw via the value bridge; `shielded_state_root`.

### Phase 3 — hardest, last
- Warren DA fabric (erasure + sampling), decentralized proving, force-exit.

---

## 7. Relationship to existing code

- Value bridge: `src/consensus/spark_payload.rs::verify_transparent_shielded_balance`,
  `verify_mint_shield_in` (done, tested).
- Shielded verify/apply: `verify_spark_payload` / `apply_spark_payload`;
  block hooks `Blockchain::verify_block_spark_v2` / `apply_spark_v2_txs`.
- Connector surfaces: `crates/spark-connector` (`SparkBackend`), `crates/bridge`,
  `crates/orchard-side`, `shielded_connector`.
- Finality: `coincync-rolling-finality`, `coincync-frost-coordinator`,
  `CHECKPOINT_INTERVAL`, `max_reorg_depth`.
- Sync/fork: `src/network/node/sync_driver.rs`, `src/network/scoring.rs`.
- Activation stays `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` (regtest at 100)
  until the shielded pool is externally audited — Warren does not change that.

---

## 8. Open questions

1. Which recursive proof system (Halo2/Nova vs STARK) over the Spark transition,
   and what is the honest prover time per batch?
2. On-chain DA (post to Bedrock) vs off-chain Warren DA — for the testnet/early
   phase, is batched-sidechain (no succinct proof) an acceptable interim?
3. Decentralized proving model and the force-exit design.
4. Does rolling-finality narrow the window enough that Dig-Out's deep-fork path
   is rarely hit in practice?
