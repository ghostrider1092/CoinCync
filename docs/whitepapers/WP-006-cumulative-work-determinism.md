# WP-006 · Cumulative-Work Determinism
### Why two honest nodes on the same tip must agree on total work

**Status:** Shipped · **Layer:** Consensus · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

"Heaviest chain wins" is the rule every proof-of-work system runs on. It is
usually stated as though *cumulative work* were an obvious quantity — sum the
difficulty of every block and compare.

It is not obvious, because in a real node the quantity is computed **twice, by
two different code paths**:

- **Incrementally**, as blocks connect: `total_difficulty += difficulty(block)`.
- **From scratch**, when evaluating a fork: walk back from a candidate tip to
  genesis and sum.

Both must produce the same number for the same chain. If they disagree by even a
constant, the node compares a fork's work against its own tip's work using two
different rulers — and every conclusion downstream is wrong.

This paper documents a failure where they disagreed by exactly one term, and the
cascade that produced.

---

## 2. Threat addressed

| Failure | Assumption it needs | What we removed |
|---|---|---|
| **Spurious reorg on equal work** — an equal-work fork measures heavier and wins | Both work computations share a base | Genesis contributes a fixed base of `1` in **both** paths |
| **Path-dependent stored state** — two nodes on an identical tip hold different cumulative work | Cumulative work is a function of the chain | Recompute-on-load self-heal makes the stored value a function of the tip, not of reorg history |
| **False-positive mining veto** — a node refuses to mine because it believes it is behind | A work comparison between peers is meaningful | Both sides now measure with the same ruler |
| **Infinite walk on a corrupt DB** — a `prev_hash` cycle hangs the fork evaluation | The block index is acyclic | Bounded step count; partial work returned and the fork rejected |

---

## 3. The failure

### 3.1 One term, two rulers

The incremental path initialises `total_difficulty = 1` at genesis and adds
`difficulty(block)` for every block at height ≥ 1. Genesis therefore contributes
the constant **1**, not its own difficulty.

The from-scratch fork walk added `difficulty(genesis_target)` instead.

So for any chain, the fork walk exceeded the incrementally accumulated value by
exactly `difficulty(genesis) − 1`. A constant — which sounds harmless, and was
not.

### 3.2 The cascade

The constant is only harmless if you never compare the two quantities. The node
compares them on every fork evaluation:

1. **An equal-work fork looks heavier.** The fork's from-scratch total carries
   the extra term; the current tip's incremental total does not. The comparison
   `fork_cumulative > current_total_difficulty` succeeds on a fork that is
   genuinely *equal*, and the node reorgs.
2. **The reorg latches the inflated value.** After taking the fork, the node
   stores the higher number as its new `total_difficulty`. The error is now
   persistent, and it accumulated again on the next spurious reorg.
3. **Nodes diverge on identical tips.** Because the stored value now depended on
   *how many reorgs a node happened to experience*, two nodes sitting on the exact
   same tip hash held **different** cumulative work. Cumulative work had become
   path-dependent — a function of history rather than of the chain.
4. **Miners refused to mine.** The mining gate vetoes when a node believes it is
   behind on work (`work_behind`). With fleet-wide divergence, that check
   false-positived and follower miners locked themselves out — the visible symptom,
   four steps removed from the cause.

The instructive part is the distance between symptom and root. The report was
"miners won't mine." The cause was one term in a summation. Nothing in between
looked like a bug: the fork comparison was correct code, the reorg was a correct
response to the numbers it was given, and persisting the new total was correct
bookkeeping.

### 3.3 Why review missed it

Both implementations were individually defensible. Summing `difficulty(genesis)`
is arguably the *more* natural reading of "total work of the chain." The defect
existed only in the **relationship** between two functions that no single review
looked at together — the same shape as the decoy-sampler/verifier asymmetry
(WP-009 §3.2) and the miner/validator difficulty split (§4 below).

---

## 4. Design

### 4.1 One canonical definition

Genesis contributes the fixed base `1`. Every block at height ≥ 1 contributes
`difficulty_from_target(block.target)`. Both the incremental path and the
from-scratch walk implement exactly this, and the fork walk carries an in-code
reference to `recompute_total_difficulty` as the canonical definition it must
agree with — so the relationship is documented at the point where it can break.

### 4.2 Self-heal on load

On startup, the node recomputes cumulative work from the active chain and
compares it to the stored value. A mismatch is logged with the delta and the
**recomputed** value wins.

This is what converts the property from "correct going forward" to "correct now."
Nodes that already latched an inflated total during the buggy period repair
themselves on the next restart, without operator action or a chain resync. A fix
that leaves corrupted state in the field is only half a fix.

It also makes the invariant continuously checkable: any future divergence
surfaces as a logged delta rather than as silent misbehaviour.

### 4.3 Bounded walk

The fork walk is bounded at `height + 100` steps. Exceeding the bound means a
`prev_hash` cycle in the database — corruption, not a valid fork. The walk logs an
error, returns the partial work, and the caller's consensus classifier rejects the
fork. Failing closed on a corrupt index is correct: a cycle must never be able to
hang block processing.

### 4.4 The same lesson, three times

CoinCync has now hit this failure shape three times, which is why it has its own
paper:

| Occurrence | Two paths that had to agree | Symptom |
|---|---|---|
| Cumulative work (this paper) | Incremental sum vs. from-scratch walk | Miners refuse to mine |
| Difficulty target | Miner used the network-aware rule; header validation used the raw one | Nodes rejected every header |
| Decoy eligibility (WP-009 §3.2) | Wallet's sampler vs. CLSAG verifier's rejection rules | Intermittent "ring signature verification failed" |

The rule we now apply: **when a value is computed in more than one place, one of
them is the definition and the others must call it.** The difficulty case was
fixed exactly that way — a single `expected_next_target` that both the miner and
header validation route through. Where a second implementation is genuinely
necessary (the fork walk cannot reuse the incremental accumulator), it must carry
an explicit cross-reference and a test that pins the two together.

---

## 5. Security analysis

**What holds.** Cumulative work is now a pure function of the chain, identical
across nodes on the same tip; equal-work forks do not trigger reorgs; stored
divergence self-repairs on load; corrupt indices fail closed.

**What this does not protect against.**

- **A genuinely heavier attacker chain.** Determinism makes the comparison
  *correct*; it does not make a heavier chain lose. That is WP-005's subject
  (MESS tiers, finality floor, checkpoints).
- **Deep-fork evaluation cost.** Walking a long fork to genesis is O(height); the
  bound caps pathology, not expense.
- **Other divergence sources.** This paper fixes cumulative work specifically.
  The general class — two paths that must agree — is a *process* risk, addressed
  by §4.4's rule rather than by any single mechanism.
- **The bound is heuristic.** `height + 100` is generous enough to be
  unreachable in practice, not a derived limit.

---

## 6. Implementation

| Component | Location |
|---|---|
| Incremental accumulation (`total_difficulty += …`) | `src/chain.rs` |
| `calculate_fork_cumulative_work` — the bounded from-scratch walk | `src/chain.rs` |
| `recompute_total_difficulty` — the canonical definition | `src/chain.rs` |
| Self-heal on load (logged delta, recomputed wins) | `src/chain.rs` |
| Rollback path (`saturating_sub` on disconnect) | `src/chain.rs` |
| Single-sourced difficulty target (`expected_next_target`) | `src/chain.rs`, `src/network/node/dispatch/headers.rs` |

**Failure record.** WP-100 — fleet-wide `total_difficulty` divergence and the
`work_behind` mining veto.

---

## 7. Known limits

- Fork evaluation is linear in height.
- The step bound is a policy number.
- Self-heal repairs the *active chain's* total; it does not audit stored side
  branches.
- The §4.4 rule is a review discipline, not an enforced invariant — no tooling
  currently detects a newly-introduced duplicate implementation.

---

## 8. References

- Nakamoto (2008) — the heaviest-chain rule this paper makes computable
  consistently.
- Bitcoin Core `CBlockIndex::nChainWork` — prior art for storing cumulative work
  in the index rather than recomputing it.
- Internal: [WP-001 Difficulty stability](WP-001-difficulty-stability.md),
  [WP-005 Reorg defense](WP-005-layered-reorg-defense.md),
  [WP-009 §3.2](WP-009-privacy-feature-composition.md),
  [WP-100](WP-100-solved-issues-ledger.md).
