# CIP — Security-detail threat model: what the guards catch, and what they don't

**Status:** reference (grounded in the shipped `src/security/` + per-subsystem
details). Purpose: make the residual risk **explicit**. 100% is impossible; this
document is how we keep the remaining ~1% named instead of pretended-away.

## The model in one paragraph
Each subsystem fields a [`SecurityDetail`](../../src/security/mod.rs): **guards**
(deterministic, O(1), consensus-critical — safe to *halt/reject* on) and
**scan** anomalies (heuristic, operational — *page*, never halt). A
`SecurityCommand` aggregates them; alerts flow to a durable `IncidentLog` (+
`tracing`) and a Bearer-gated RPC console, with graduated response
(Accept<Log<Throttle<Quarantine<BanPeer<Halt`) and cross-surface correlation.
**This is defense-in-depth, not the primary defense** — per-tx validation and
the crypto proofs are. The guards catch *corruption/state* classes; they do not
re-verify cryptography.

## Per-detail ledger

### supply
- **Catches:** `total_burned > total_supply` (burn-counter inflation / accounting
  corruption) → halt. `total_supply > MAX_SUPPLY` → operational warning.
  **Schedule reconciliation** (added 2026-09-26): `total_supply == Σ
  reward(0..=tip)`, recomputed independently by
  [`emission::supply::cumulative_emission`] and reconciled in `supply_security`
  → operational/Critical (pages, never halts). This closes the previously-named
  "exact adherence to the emission schedule" gap: the block-connect path
  maintains `total_supply` as this running sum, so any drift from the
  deterministic schedule across connects, disconnects, reorgs, or restart replay
  is now surfaced live and is auditor-verifiable via `get_supply_info` +
  `get_pool_security`. It was previously a *test-only* invariant
  (`tests/invariant_pipeline.rs`, `tests/common/simkit.rs`).
- **Does NOT catch:** inflation *within* the cap at the **scheduled coin count**
  — a block emits exactly its scheduled reward, but the coins themselves carry
  inflated value via a balance/range proof that verifies-but-shouldn't. The
  reconciliation checks the *schedule accounting*, not the *cryptography*, and it
  shares the `base_reward` primitive with the counter it reconciles (a bug
  *inside* `base_reward` is invisible to it). Per-block over-emission is caught at
  validation (`calculate_block_reward`), not here. The schedule check is
  operational, not a halt — promoting it would take an O(1) independently
  maintained accumulator. Value created by a proof that verifies but shouldn't
  (crypto) remains the audit's job.

### utxo-set
- **Catches:** live output count `>` ever-created; distinct spent key-images `>`
  ever-created (count-level double-spend / inflation) → halt.
- **Does NOT catch:** value inflation with *correct counts* (a bad balance proof
  minting value) — enforced per-tx by `verify_balance_proof`, not here. A
  specific double-spend (the key-image spent-set check at validation catches
  that). Commitment-sum imbalance — uncheckable without the secret blindings.

### phase2-lockstep
- **Catches:** the shielded / spark / kernel accumulator stores' checkpoint
  stacks diverging (a reorg would then unwind them to different heights and
  diverge state) → halt. **Root integrity** (added 2026-09-26,
  `phase2-root-integrity` detail): for each store that can independently
  recompute its root from retained contents (**kernel**, **spark**), the
  maintained cached root is reconciled against a fresh recompute
  (`check_root_integrity`) → operational/Critical (pages, never halts). This
  closes the "wrong accumulator *contents* while stack depths stay aligned" gap:
  a cached root that drifted from its contents (maintenance bug, partial rewind,
  corruption) is now surfaced live via `get_pool_security`.
- **Does NOT catch:** the **shielded** store's contents — its `BridgeTree` state
  *is* the accumulator, so there is no cheap independent recompute
  (`recompute_root()` → `None`, skipped); its integrity rests on validation's
  committed-root check + replay-on-open. The root-integrity check is O(Σ
  contents), so it is operational (off the block hot path), not a per-block
  consensus halt — the O(1) upgrade is reconciling each store root against the
  committed **header** root (`mw_kernel_root` / `spark_set_root`) every block.

### shielded-pool
- **Catches (halt):** coins/tags dated above tip (`coin/tag-from-future`);
  checkpoint-stack overflow; `pool_value < 0` (unshielding more than was ever
  shielded — inflation across the veil), enforced pre-apply (reject) + at apply
  (halt) + as a guard.
- **Catches (operational):** abnormal mint velocity; high spend ratio.
- **Does NOT catch:** an unsound Grootle/Chaum/range proof that **verifies** — no
  guard re-derives the crypto; a coin whose committed value is wrong but whose
  proof passes; a broken hidden-index↔tag binding. These are the audit's job.

### mempool (operational only — node-local, never consensus)
- **Catches:** the mempool at/over its byte cap (flood/DoS pressure) → page.
- **Does NOT catch:** sophisticated fee manipulation; eviction-policy bugs; tx
  validity (that is mempool admission). Never halts the chain.

### peer-set (operational only — node-local, never consensus)
- **Catches:** isolation (0 peers) and under-connection (`< 3`) — partition /
  eclipse risk → page. **Netgroup diversity** (added 2026-09-26,
  `peer_diversity`): a peer set whose *count* looks healthy but is concentrated
  in few `/16` netgroups — all peers in one `/16` → Critical, a single `/16`
  holding a strict majority (≥ 4 peers) → Warning. Same
  [`eviction::netgroup`] keying (IPv4 `/16`, IPv6 `/32`) as the connection-level
  eclipse defenses. This partially closes the "well-connected but
  all-adversarial (count looks healthy)" gap for the common *single-subnet*
  sybil.
- **Does NOT catch:** a sybil *spread across many `/16`s* (a resourced adversary
  renting diverse subnets / ASNs — `/16` grouping is coarser than ASN, which
  needs an external GeoIP DB not pulled in for testnet); traffic analysis; the
  *content* peers send (validation handles that). Still operational — never
  halts.

## Systemic limits — the honest ~1%
1. **Unsound crypto that verifies.** No monitor catches a broken proof accepted
   as valid. The unaudited Spark/GK crypto is the real risk. **Only an external
   audit closes this** — it is not a guard we can add. *Partial coverage added
   2026-09-26:* `crypto::differential_ring_sig_check` differentials the
   optimized ring-signature path (verification cache + rayon parallel) against a
   fresh, uncached, serial reference, catching the **optimization/caching-layer**
   bug class (cache poisoning, a mis-keyed cache, parallel/index errors) — a
   cached "valid" for an invalid signature is an inflation vector. It does NOT
   reach the core `clsag_verify` (both paths call it) or the proof system's
   spec-level soundness; CoinCync has a single implementation of each verifier,
   so a true independent-implementation differential would require a second
   verifier (itself unaudited) and remains out of scope. A companion
   **adversarial soundness harness** for the BP+ **range-proof verifier** (the
   transparent chain's no-negative-value inflation guard) was added the same day
   — systematic bit-flips, truncation/extension, exact-commitment binding (same
   value / different blinding must reject), and aggregated commitment
   swap / reorder / count-mismatch. Both harden verifier *implementation*
   robustness (reject-the-malformed); neither establishes the proof systems'
   *spec-level* soundness. The audit is still the ceiling.
2. **Trusted computing base.** The node code, the libspark FFI, the OS, the
   keys. Guards cannot watch the thing that runs the guards.
3. **Determinism boundary.** Only consensus-class guards may halt (deterministic,
   O(1), no floats/wall-clock/iteration-order). Operational guards use heuristics
   and **never** halt — so a false positive can't wedge the chain, but a subtle
   attack that stays within the heuristics' tolerance also won't be stopped by
   them (only surfaced, at most).
4. **Monitoring ≠ prevention.** Most guards observe post-apply (halt to preserve
   state) or reject pre-apply where wired (shielded). The *primary* prevention is
   per-tx validation; the guards are defense-in-depth over it, not a replacement.
5. **Unknown-unknowns.** Novel attack classes no invariant anticipates. Naming
   this is the point of the document; the mitigation is audit + a widening set of
   invariants over time, not a claim of completeness.

## What is explicitly NOT the security layer's job
- Re-verifying cryptographic proofs (that is the proof systems + the audit).
- Per-tx consensus validation (balance, signatures, key-image spent-set).
- Being a substitute for the shielded **external audit** before activation.

## Bottom line
The guards make **state corruption, double-spend/inflation accounting, reorg
desync, cross-veil underflow, flooding, and isolation** loud and (where
consensus-safe) halting. They do **not** make unsound cryptography safe. The path
to production remains: finish the shielded activation arc → 24h soak → **external
audit**. The guards raise the floor; the audit is the ceiling.
