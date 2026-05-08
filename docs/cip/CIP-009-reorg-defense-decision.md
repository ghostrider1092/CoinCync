<!-- markdownlint-disable MD036 -->
# CIP-009 — Reorg Defense: decision document

**Status:** Path B SHIPPED (2026-05-08, commit `45e621d`).
Path A (MESS) REJECTED as too risky. A successor for live-tip
defense is specified in **CIP-009.D — Miner-signed rolling
checkpoints** (`docs/cip/CIP-009-D-miner-signed-rolling-checkpoints.md`),
queued for post-launch activation.
**Type:** Standards Track (consensus rule)
**Created:** 2026-05-08
**Layer:** Consensus
**Depends on:** CIP-007 (activation policy)
**See also:** CIP-009.D (better-than-MESS replacement)

---

## Problem statement

The H-16 reorg defense is currently "mitigated, not closed" — the
mainnet `MIN_OUTPUT_AGE` is set to 100 blocks (~3.3 hours at 120s)
which makes a deep reorg expensive but not impossible. CoinCync, as
a privacy coin with a small committed userbase, has structurally
less hashpower than Bitcoin — meaning a >51% attack is more
feasible relative to the network's defensive resources.

Three paths exist. They differ in complexity, security guarantees,
and consensus surface area. The right choice depends on what we're
optimizing for: simplicity, decentralization, or strong
short-range defense.

This doc lays them out. **You pick A, B, or C. I implement.**

---

## Path A — MESS (Monero-style Modified Exponential Subjective Scoring)

**Principle:** alternative chains are penalized by an exponential
function of how far behind the current tip they are in time. The
further behind, the more work an attacker must accumulate to
override the canonical chain.

**Math:**
```
score(alt_chain) = work(alt_chain) * exp(-(t_now - t_alt) / TAU)
```

If `score(alt_chain) > score(canonical)`, the alt chain wins.
Otherwise, the canonical chain stays. `TAU` is a tunable
half-life (Monero uses ~24 hours).

**Implementation cost:** 1-2 weeks.

- New consensus rule in `validate_block`.
- New state: tip-set tracking with timestamps.
- Tuning the decay constant requires testnet experiments.
- Edge cases: clock-skew handling, time-warp attacks, the
  exp-decay precision (must be deterministic — no floats).
- New attack surface: a cleverly-timed reorg attack might
  exploit the decay function; needs cryptographic-style
  analysis before mainnet.

**Pros:**

- Strong continuous defense at all reorg depths.
- Mathematically elegant; well-studied (Monero has run it for
  years).
- No "trusted operator" centralization point.
- An attacker's cost grows superlinearly with depth.

**Cons:**

- Adds significant consensus surface — every node must compute
  the score deterministically.
- Tuning errors are mainnet-fatal.
- Attack analysis requires real cryptographers; no community
  audit completed yet.
- Adds ~600-800 LOC of new consensus code that needs auditing.

**Suitability:** good fit for a launch-already-public chain
that has hashpower competition. CoinCync mainnet may not be
there yet.

---

## Path B — Checkpoint + escape hatch (Bitcoin Cash style)

**Principle:** every N blocks, a hardcoded checkpoint locks in the
chain state. Reorgs past a checkpoint are impossible by consensus
rule. The "escape hatch" is the ability to invalidate a
checkpoint via a coordinated upgrade if a checkpoint mistakenly
locks in a bad chain.

**Implementation:**

- `CHECKPOINTS: &[(height, block_hash)]` table in
  `src/constants.rs`. ~50 entries for 100 days of mainnet at
  one checkpoint every ~2-3 days.
- Validator: any block proposing a different `block_hash` at a
  known checkpoint height is rejected.
- Checkpoint setter: project-run release process. Every release
  bakes in checkpoints up to ~2 weeks before the release date.
- Escape hatch: a checkpoint can be removed in a future release
  if it's discovered to be wrong. Same fork-coordination
  mechanism as any other rule change (CIP-007 Mode A).

**Implementation cost:** 3-5 days.

- ~150 LOC for the validator rule.
- A maintenance script that pulls the chain head every ~2 weeks
  and appends to the table.
- Release-process documentation.

**Pros:**

- Simple. Easily audited. Self-evidently correct.
- Reorgs past a checkpoint are STRUCTURALLY impossible.
- Common pattern: Bitcoin Core uses checkpoints for early-history
  protection; Bitcoin Cash uses live checkpoints; Monero uses
  them.
- Implementation cost is contained.

**Cons:**

- Centralization concern: the checkpoint setter (project) can
  unilaterally freeze the chain at a particular hash. Mitigated
  by:
  - Public release process.
  - Conservative 2-week lag (don't checkpoint blocks that
    haven't had time for community review).
  - Multi-sig release signing (project + community auditors).
- Requires regular operator action; if releases stall, the
  protection window shrinks.
- A determined attacker who can compromise the release
  pipeline can poison checkpoints. (Mitigated by signing; same
  trust model as a binary release.)

**Suitability:** ideal for a pre-mainnet or early-mainnet chain
where the project still does the operator work. Defers more
sophisticated defense (MESS) to a post-mainnet window when
hashpower has grown and operator-coordination is a real cost.

---

## Path C — PoW-only + deeper confirmations (current state, formalized)

**Principle:** no special reorg defense. Honest nodes always follow
the longest valid chain. Users protect themselves by waiting
N confirmations before trusting a tx.

**Implementation:**

- This is the CURRENT state. `MIN_OUTPUT_AGE = 100` already
  enforces 100 confirmations before outputs are spendable.
- The only doc work needed: write down the assumption clearly
  and the threat-model implications.

**Implementation cost:** zero (already shipped).

**Pros:**

- Zero new consensus surface.
- Bitcoin's model — the most-audited PoW security in existence.
- No operator involvement. No release-pipeline risk.
- Easy to reason about and audit.

**Cons:**

- A 51% attacker can rewrite ANY history they have hashpower to
  overcome. With CoinCync's likely small mainnet hashpower
  early on, this is a real risk.
- Recovery from a successful 51% attack requires social
  consensus + (usually) a hard-fork to invalidate the attack
  chain. ETC has done this; Bitcoin SV has done this. It's
  ugly but possible.
- Users must wait 100 confirmations (~3.3 hours) for high-value
  spends. Already a UX cost.

**Suitability:** acceptable as a temporary stance for testnet and
very early mainnet; not viable for a privacy coin with low
hashpower at scale. If we ship this, we're committing to upgrade
later (probably to A or B in the first contentious-attack
recovery).

---

## Recommendation

Given:

- Mainnet launches October 2026 — 5 months away.
- Hashpower at launch is unknown but likely modest.
- The audit window before mainnet is tight; adding 600-800 LOC of
  novel consensus code at this point is high-risk.
- Operator presence is high (single project, single team).
- Reorg-defense gap was flagged in the 2026-05-07 review as the
  one outstanding consensus concern.

**My recommendation: Path B (checkpoints) for v1.0 mainnet, with
a planned upgrade to Path A (MESS) post-launch when the network
matures.**

Rationale:

- **B is cheap and known-good.** 3-5 days of work, well-trodden
  pattern, minimal new consensus risk. Ships before mainnet
  freeze.
- **B leaves the door open to A.** A future activation (CIP-009.A
  or similar) can layer MESS on top of checkpoints. Both can
  coexist (Monero already does).
- **A's risk is real.** Tuning the decay constant wrong on
  mainnet is catastrophic. Without a community audit, shipping
  it for the first time is too risky.
- **C is unacceptable for mainnet.** Privacy-coin economics make
  CoinCync's hashpower a bigger relative target than Bitcoin's,
  and 100-block confirmation isn't enough for high-value
  recipients.

**Hybrid B+A path (post-launch):**

1. v1.0 ships with B alone.
2. v1.1 (3-6 months post-launch) adds A as a layered defense,
   activated via CIP-007 Mode A at a future height. Both rules
   apply: a reorg must beat checkpoints AND MESS.

---

## Decision

Pick one:

- ☐ **Path A (MESS only)** — strong defense, high implementation
  cost, accepts post-launch tuning risk.
- ☐ **Path B (checkpoints)** — recommended. Simple, contained,
  ships before mainnet, leaves door open to A.
- ☐ **Path C (PoW only)** — accept the 51% risk; rely on social
  consensus for recovery.
- ☐ **Hybrid B + A path** — recommended for post-mainnet. v1.0
  ships B, v1.1 adds A.

If you pick B or B+A, I implement B in the next session (3-5
days). The implementation lives in:

- `src/constants.rs` (CHECKPOINTS table).
- `src/consensus/validation.rs` (the rejection rule).
- `scripts/update-checkpoints.sh` (maintenance script).
- `docs/operations/CHECKPOINT_PROCEDURE.md` (release-process doc).

If you pick A, the implementation is significantly larger and
needs an audit pass. We schedule it as a 2-week project with
external review.

If you pick C, no code change needed; document the threat
model decision in `docs/THREAT_MODEL.md` (already half-written
under the >51% adversary section).

---

## Out of scope

- **Soft-forks for reorg defense.** Not possible — reorg defense
  is structurally a HARD-fork concept (changing what blocks are
  valid). Activation goes through CIP-007 Mode A always.
- **Stake-weighted finality (Casper FFG-style).** CoinCync is
  PoW. Adding a PoS finality layer is a different project; out
  of scope for this CIP.
- **Watchtowers / fraud proofs.** L2 / app-layer concerns; not
  consensus.
