# WP-005 · Layered Reorg Defense
### MESS, the finality floor, and checkpoints

**Status:** Shipped · **Layer:** Consensus · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

A young proof-of-work chain's defining vulnerability is that its security budget
is small and rentable. Ethereum Classic and Bitcoin Gold were both reorganised by
attackers who simply bought hashpower for an afternoon. The attack does not
require breaking any cryptography; it requires out-mining a chain that does not
have much mining.

The naive defence — "reject deep reorgs" — has a failure mode of its own: a hard
depth cap partitions the network permanently the first time an honest deep reorg
is legitimate, and it turns an ordinary fork into a chain split. The design
problem is therefore not "how do we stop reorgs" but **how do we make deep
rewrites economically irrational while keeping shallow, honest reorgs free.**

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **51% / rented-hashpower deep reorg** | Rewriting settled history costs the same as extending the tip | Depth-scaled cost: beyond a shallow band, a fork must carry exponentially more work than the chain it replaces |
| **Long-range rewrite** | No absolute limit exists | A hard rejection tier and a checkpoint floor put settled history out of reach at any cost |
| **Honest-peer banning during forks** | A policy rejection and an invalid block are the same outcome | Depth rejections return a distinct "too deep" result — the peer serving the heavier chain is not punished |
| **Finality-window collapse** | A boundary-anchored floor always leaves a usable window | The floor is a fixed distance below the tip, so a full reorg window always exists (see WP-100 §3.4) |

---

## 3. Design

Four mechanisms compose, deliberately, from cheapest to most absolute.

### 3.1 Tier 1 — free shallow reorgs (depth ≤ 10)

Reorgs up to depth 10 are accepted unconditionally on cumulative work. This is
the normal operation of a proof-of-work chain: brief competing tips, network
latency, two miners finding blocks nearly simultaneously. Making this band free
is what prevents the defence from causing splits.

### 3.2 Tier 2 — MESS exponential cost (depth 11–100)

In this band a replacing fork must carry **exponentially more work** than the
chain it would displace, with the required multiplier growing in the depth of the
rewrite (governed by `MESS_EXPONENT_DIVISOR`). The principle is borrowed from
Ethereum Classic's post-attack response — *Modified Exponential Subjective
Scoring* — and its logic is economic rather than cryptographic: an attacker who
wants to rewrite `n` blocks must pay a cost that rises far faster than `n`, so
the depth at which a double-spend becomes profitable is pushed past the point of
economic sense.

Subjectivity is the honest trade-off here: nodes weigh forks partly by *when they
saw them*. That is what makes the cost real, and it is why this tier is bounded
rather than unbounded.

### 3.3 Tier 3 — hard rejection (depth > 100)

Beyond depth 100 a reorg is refused outright. No amount of work buys a rewrite
this deep. This converts the deepest attacks from an economic question into an
impossible one, at the cost of accepting that a genuinely partitioned network
deeper than 100 blocks requires operator intervention rather than automatic
resolution — a trade we make deliberately.

### 3.4 The finality floor

Layered above the tiers, a floor forbids any reorg whose fork point lies more
than `CHECKPOINT_INTERVAL` (144) blocks below the tip. Critically, the floor is
computed as **`tip − interval`**, a fixed distance below the current tip — *not*
anchored to the last checkpoint boundary. The boundary-anchored form is a real
bug we shipped and removed: it collapsed the reorg window to zero whenever the
tip sat exactly on a boundary (WP-100 §3.4).

The floor is a pure function of tip height, which matters for determinism: two
nodes on the same tip compute the same floor regardless of the path each took to
get there.

### 3.5 Checkpoints

Hardcoded checkpoints (and an auto-checkpoint cadence at `CHECKPOINT_INTERVAL`)
short-circuit long-range attacks: any chain disagreeing with a checkpoint at or
below its height is rejected immediately, without evaluating work at all. This is
the crudest and most absolute layer, and it exists because for a young chain the
alternative to a small amount of trusted history is no history worth trusting.

### 3.6 Rejections are not accusations

A reorg refused by depth policy returns `ReorgTooDeep`, distinct from `Invalid`.
This distinction is load-bearing: the peer offering the deep fork is behaving
correctly by its own view of the chain, and banning it would fragment the network
exactly when reconciliation is most needed.

---

## 4. Security analysis

**What holds.** A double-spend requires a reorg past the confirmation depth of
the target transaction. Under this stack, an attacker at depth 11–100 pays an
exponentially growing work premium, and beyond 100 cannot succeed at any price.
For a merchant, this converts "how much hashpower does the attacker have" into
"how many confirmations did I wait" — with a bounded answer.

**Live validation.** The stack was exercised on a running two-node network: nodes
were partitioned, mined competing chains to a genuine 203-block divergence, and
reconnected. The lighter node abandoned its fork and converged on the heavier
chain with matching tip hashes, no state corruption, no panic, and no stall.
Shallow-reorg handling is covered by 22 unit tests.

**What this does not protect against.**

- **Sustained majority hashpower.** If an attacker simply out-mines the network
  continuously, they extend the tip rather than rewriting it, and no depth policy
  applies. That threat is answered by the PoW choice and the miner base, not here.
- **Subjectivity is real.** Tier 2 means nodes that observed a fork at different
  times can weigh it differently. This is inherent to MESS-style scoring; we bound
  it rather than pretend it away.
- **Tier 3 and checkpoints trade automation for safety.** A legitimate partition
  deeper than the caps will not self-heal. We consider an operator-resolved split
  strictly better than an attacker-resolved rewrite.
- **Checkpoints are a trust input.** They are a deliberate, declared reduction in
  "trustlessness" appropriate to a chain's early life, and they should recede in
  importance as accumulated work grows.

---

## 5. Implementation

| Component | Location |
|---|---|
| Tier policy, MESS scoring, depth caps | `src/consensus/finality.rs` (`evaluate_reorg_acceptability`, `max_reorg_depth_for`, `MESS_EXPONENT_DIVISOR`, `REORG_UNCONDITIONAL_DEPTH`, `BOOTSTRAP_MESS_HEIGHT`) |
| Tier application + finality floor | `src/chain.rs` (fork-choice path) |
| Checkpoints + auto-checkpoint cadence | `src/chain.rs`, `src/testnet.rs`, `src/mainnet.rs` |
| `CHECKPOINT_INTERVAL = 144` | `src/constants.rs` |
| Atomic reorg application | `src/chain.rs` (`apply_reorg_atomic`), `src/db/` |

**Related design record.** [reorg-defense.md](../security/reorg-defense.md) (the
H-16 six-layer decision), CIP-009 (reorg-defense decision), CIP-009-D
(miner-signed rolling checkpoints — see WP-008).

**Failures found and removed in this area** are catalogued in WP-100 §3.3, §3.4,
and §6.5 (deep-rollback DB gap, finality-floor collapse, reorg self-deadlock).

---

## 6. Known limits

- Tier boundaries (10 / 100 / 144) are **policy choices**, not derived optima.
  They encode a judgement about a young chain's risk appetite and should be
  revisited as the chain matures.
- MESS subjectivity is a genuine trade-off, not a solved problem.
- Checkpoint reliance is highest exactly when the chain is weakest, which is also
  when it is least verifiable by an outsider. We disclose it rather than minimise
  it.
- Rolling soft finality (WP-008) is implemented but **gated**; it is not part of
  the shipped defence today.

---

## 7. References

- Ethereum Classic 51% attack post-mortems (2019–2020) and the MESS response.
- Bitcoin Gold 51% incident reports.
- Internal: [reorg-defense.md](../security/reorg-defense.md), CIP-009,
  [WP-006 Cumulative-work determinism](WP-006-cumulative-work-determinism.md),
  [WP-100](WP-100-solved-issues-ledger.md).
