<!-- markdownlint-disable MD013 MD036 -->
# Reorg Defense — Threat Model and Design

**Status:** Authoritative as of 2026-05-14. Supersedes the scattered
and partially-drifted state across CIP-009, the `H-16` memory note,
and the `src/consensus/finality.rs` placeholder.
**Type:** Security design document (descriptive — documents shipped
behaviour; proposes no consensus change)
**Audience:** Auditors, consensus reviewers, node operators
**Companion CIPs:** CIP-009 (the original A/B/C decision),
CIP-009.D (miner-signed rolling checkpoints — the queued live-tip
layer), CIP-011 (CIP-009.D activation plan)

---

## 1. Why this document exists

Three sources describe CoinCync's reorg defense and **they do not
agree with each other or, in two places, with the code**:

- The `H-16 reorg defense status` project memory says a 3-tier
  MESS-inspired hybrid was *implemented* and H-16 marked **CLOSED**.
- `docs/cip/CIP-009-reorg-defense-decision.md` frames the choice as
  a binary "pick A, B, or C", says **Path A (MESS) was REJECTED**,
  and says **Path B (checkpoints) shipped** at commit `45e621d`.
- `src/consensus/finality.rs` (an intentional docs-only placeholder)
  describes a live 3-tier MESS hybrid in `crate::chain`.

An auditor reading CIP-009 ("MESS rejected") and then reading
`src/chain.rs` (which contains `evaluate_reorg_acceptability`, a
working 3-tier MESS implementation) would reasonably conclude the
documentation cannot be trusted. The post-launch fix campaign flags
this explicitly: *"the answer to 'why MAX_REORG_DEPTH=100' needs to
be more than 'feels right.'"*

This document is the reconciliation. It describes **what the code
actually does** (verified against `src/chain.rs` and
`src/constants.rs` at 2026-05-14), justifies every parameter, states
the threat model, and lists the residual gaps honestly. It changes
no code and proposes no consensus change — it is the design record
that should have existed alongside the implementation.

---

## 2. The actual defense — six layers

CoinCync's reorg defense is **not** "Path A or Path B". It is a
layered system. Some layers were inherited from the original H-16
fix; CIP-009 added one more; CIP-009.D will add a sixth. A reorg
must satisfy **every active layer** to be accepted.

### Layer 1 — Tier-1 Nakamoto (depth ≤ 10)

`REORG_UNCONDITIONAL_DEPTH = 10` (`src/chain.rs::REORG_UNCONDITIONAL_DEPTH`). For reorgs at
depth 10 or shallower, the standard Nakamoto longest-(most-work)-
chain rule applies unconditionally: the fork wins iff
`fork_work > honest_work`. This is the normal-operation path —
network jitter, propagation races, brief connectivity blips all
resolve within a handful of blocks and must not be impeded.

### Layer 2 — Tier-2 MESS (depth 11–100, tip height ≥ 1000)

`MESS_EXPONENT_DIVISOR = 20` (`src/chain.rs::MESS_EXPONENT_DIVISOR`). For reorgs deeper
than 10, the fork must demonstrate **exponentially** more cumulative
work than the honest chain:

```
required_work = honest_work × 2^((depth − 10) / 20)
```

| Reorg depth | Work multiplier the fork must beat |
|---|---|
| 30 | 2× |
| 50 | 4× |
| 70 | 8× |
| 90 | 16× |

This is Modified Exponential Subjective Scoring, the Ethereum
Classic ECIP-1100 construction. The exponent is integer-divided
(`(depth − 10) / 20`) and capped at 40 to prevent `u128` overflow
(the `capped_exponent` clamp in `src/chain.rs::evaluate_reorg_acceptability`);
all arithmetic is integer — **no floats
in consensus**. The implementing function is
`evaluate_reorg_acceptability` (`src/chain.rs::evaluate_reorg_acceptability`), called from the
reorg path in `src/chain.rs::add_block`.

### Layer 3 — Tier-3 hard cap (depth > max)

`max_reorg_depth()` returns **100 on mainnet, 1000 on
testnet/regtest** (`src/chain.rs::max_reorg_depth_for`). A reorg deeper than this
is rejected outright — no quantity of work can override it. This is
the absolute-finality backstop.

### Layer 4 — Per-node rolling checkpoints

`CHECKPOINT_INTERVAL = 144` blocks (`src/constants.rs::CHECKPOINT_INTERVAL`, ≈ 5
hours at 120 s). Each node records a checkpoint of its own canonical
chain every interval (`db.state.add_checkpoint`, called during
genesis initialization in `src/chain.rs`). A reorg whose fork point is below the node's
`last_checkpoint` is rejected (`src/chain.rs::rollback_to_height`). This is a
*local*, *subjective* finality layer — it does not require
coordination, and it bounds how far back any single node will ever
reorganise regardless of work.

### Layer 5 — Hardcoded consensus checkpoints (CIP-009 "Path B")

`CONSENSUS_CHECKPOINTS: &[(u64, [u8; 32])]` (`src/constants.rs::CONSENSUS_CHECKPOINTS`,
feature-gated mainnet and testnet variants). A network-wide, release-shipped table of
`(height, block_hash)` pairs; any block proposing a different hash
at a checkpointed height is rejected. **The table is empty as of
2026-05-08** on both networks — it is populated post-launch via the
release process (`scripts/update-checkpoints.sh`,
`docs/operations/CHECKPOINT_PROCEDURE.md`), each release baking in
checkpoints up to ≈ 2 weeks behind the tip. An empty table is a
valid state: `expected_checkpoint_hash` returns `None` and the
validator treats "no checkpoint here" as "accept any consistent
block" (`src/constants.rs::expected_checkpoint_hash`). This is the layer CIP-009 decided
to *add*; see §3.

### Layer 6 — Miner-signed rolling finality (CIP-009.D, queued)

Specified in CIP-009.D, activation planned in CIP-011, consensus
adapter built behind the off-by-default `rolling-finality` feature
(`src/consensus/rolling_finality.rs`). When active, miners attest to
`height − LAG`; once a height is signed by ≥ ⌈2/3⌉ of the active
miner set it becomes *soft-final* and reorgs past it are rejected.
**Not active** — it is post-launch work and gated behind a
two-phase activation. Listed here for completeness because it is the
intended live-tip layer; everything in §2 Layers 1–5 is what
defends the chain *today*.

---

## 3. Reconciling the contradictions

### 3.1 "CIP-009 says MESS was rejected, but MESS is in the code"

Both are true once the framing is corrected. The 3-tier MESS hybrid
(Layers 1–3) was the **original H-16 fix**, implemented before
CIP-009 was written (session `63379c83`, the "H-16 FIX" comment
block, the `HYBRID REORG DEFENSE (H-16 FIX)` banner in `src/chain.rs`). CIP-009 was not deciding whether to
*keep* MESS — it was deciding what *additional* defense to **add**
before mainnet. Its "Path A (MESS)" meant "add a *new, larger* MESS
construction as the primary defense"; that was rejected as too much
novel consensus surface for the pre-mainnet audit window. "Path B
(checkpoints)" — adding Layer 5 — was chosen and shipped.

CIP-009's binary "pick A, B, or C" framing is therefore **misleading
in retrospect**: the layers are not mutually exclusive, and the
shipped reality is "inherited MESS hybrid + added checkpoints + the
pre-existing per-node rolling checkpoints". CIP-009 should be read
as a historical decision record for *one* layer (Layer 5), not as a
description of the whole defense. This document is the description
of the whole defense.

### 3.2 "The memory says H-16 is CLOSED, the campaign says a design decision is still needed"

Also both true, for different senses of "closed". The *code* is
closed: the 3-tier hybrid is implemented and carries 17 regression
tests (the `evaluate_reorg_acceptability` unit tests in `src/chain.rs`).
What was **not** closed is the *design rationale documentation* —
the artefact an auditor needs to evaluate whether the parameters are
sound. That artefact is this document. With it written, the
campaign's item #3 is closed.

### 3.3 `MIN_OUTPUT_AGE` — CIP-009 says 100, the code says 10

CIP-009's problem statement asserts "the mainnet `MIN_OUTPUT_AGE` is
set to 100 blocks (~3.3 hours)". **The code says `MIN_OUTPUT_AGE =
10`** (`src/constants.rs::MIN_OUTPUT_AGE`). The code is authoritative. CIP-009's
figure is either stale or was written against a planned value that
did not ship.

This matters: CIP-009 leaned on the 100-block output age as part of
its argument that "Path C (PoW only) is unacceptable" — i.e. that
100 confirmations is the *de facto* finality users already wait. If
the real value is 10, that argument is weaker than CIP-009 presents,
and the case for Layers 4–6 is correspondingly *stronger*, not
weaker. **Action item:** confirm whether `MIN_OUTPUT_AGE = 10` is
intentional for mainnet or a testnet-tuning value that needs a
network split before mainnet. Flagged in §6.

---

## 4. Parameter justification

Every consensus constant in the reorg path, and why it holds the
value it does. This is the section the campaign item demanded —
"more than 'feels right.'"

### `REORG_UNCONDITIONAL_DEPTH = 10`

Below this depth, reorgs are pure Nakamoto. The value is chosen so
that **normal network events never trip the MESS curve**: block
propagation races, a node briefly behind a slow link, a 2–3 block
natural fork from near-simultaneous mining. At a 120 s target,
10 blocks is ≈ 20 minutes — comfortably longer than any benign
propagation anomaly, and aligned with the ≥ 6-confirmation
convention Bitcoin established for ordinary-value finality. Setting
it lower would risk MESS rejecting honest deep-ish forks; setting it
higher would hand an attacker a larger free-reorg window.

### `MESS_EXPONENT_DIVISOR = 20`

Controls the steepness of the Tier-2 cost curve: the required work
multiplier doubles every 20 blocks of depth above the threshold. The
value is a deliberate middle ground. A *smaller* divisor (steeper
curve) reaches infeasible multipliers fast but risks locking in a
legitimate fork that happens to be deep — e.g. a 40-block honest
reorg after a real partition would need 4× work and might be
permanently rejected. A *larger* divisor (gentler curve) is more
forgiving of honest deep forks but gives a rental attacker more
room. At 20, an attacker reorging 90 blocks deep needs 16× the
honest chain's work for that span — renting that much hashpower for
that long is the economic infeasibility the layer is built to
create, while a 30-block honest reorg only needs 2×, which a genuine
majority-work fork clears easily.

### `max_reorg_depth = 100` (mainnet) / `1000` (testnet)

The Tier-3 hard finality boundary. **Mainnet = 100** (≈ 3.3 hours at
120 s): deep enough to absorb any partition a production network
should realistically experience, shallow enough to strictly bound
an attacker's reach — past 100 blocks, *no* work overrides the
chain. The precedents in the "Historical precedent" comment of the `src/chain.rs` reorg-defense banner are the argument: ETC
(2019, 100+ block reorg, $1.1 M), Bitcoin Gold (2018, $18 M),
Horizen (2018, $550 K) — all low-hashrate PoW chains with **no** hard
cap. **Testnet = 1000** because testnet partitions during
multi-node test cycles are deliberately long, a permanent testnet
fork is not financially catastrophic, and testnet resets between
cycles anyway. The cost of the split value is real and noted in
§6: testnet and mainnet run *different consensus rules*, which
reduces testnet's predictive value for mainnet behaviour.

### `BOOTSTRAP_MESS_HEIGHT = 1000`

Below tip height 1000, Tier-2 MESS is **disabled** and the chain
falls back to plain longest-chain (the bootstrap fallback in `src/chain.rs::evaluate_reorg_acceptability`). Reason: on a
freshly-genesised chain, every node that boots independently mines
its own height-1 at floor difficulty. If MESS were active from
height 1, none of those parallel low-work forks could ever satisfy
`2^x` of any other — they would be **permanently locked apart**, and
the network could never converge. The bootstrap exemption mirrors
the `BOOTSTRAP_MIN_RING_SIZE` relaxation: a young chain has too
little cumulative work for an exponential-work test to be
meaningful, and Layers 3 (hard cap) + 4 (per-node checkpoints) still
bound an attacker during the bootstrap window.

### `CHECKPOINT_INTERVAL = 144`

Per-node rolling-checkpoint cadence (≈ 5 hours at 120 s). The "C-5
fix" comment above `max_reorg_depth_for` in `src/chain.rs` records the history: this was
**5** (≈ 10 minutes), which caused *permanent chain splits on any
network partition longer than 10 minutes* — the checkpoint locked in
before the partition could heal. Raised to 144 so the interval
absorbs realistic partitions while still bounding long-range reorg.
The value trades off subjective-finality tightness against
partition tolerance; 144 sits on the partition-tolerant side
deliberately, because a permanent split is a worse failure than a
slightly looser finality window.

---

## 5. Threat model

### 5.1 The adversary that matters: rental hashrate against a low-hashpower chain

CoinCync is a privacy coin. Privacy coins structurally attract
*less* hashpower than Bitcoin relative to their market value —
fewer exchanges, fewer large holders running mining operations,
RandomX's CPU-friendliness spreading hashpower thin. That makes the
network's hashpower a **larger relative target**: an attacker does
not need a fab or a warehouse of ASICs, only a credit card and a
hashrate-rental marketplace (NiceHash and equivalents). The
historical victims in the "Historical precedent" comment of the `src/chain.rs` reorg-defense banner were all attacked exactly
this way. This is the adversary every layer in §2 is built against.

### 5.2 What each layer defends

| Adversary action | Defeated by |
|---|---|
| Shallow double-spend (≤ 10 blocks), majority work for a few minutes | Nothing — Layer 1 accepts it. This is the irreducible Nakamoto window; users wait confirmations. |
| Rental-hashrate reorg, 11–100 blocks deep | Layer 2 (MESS) — the `2^((depth−10)/20)` multiplier makes the rental cost grow superlinearly with depth. |
| Reorg deeper than 100 (mainnet) | Layer 3 (hard cap) — rejected outright regardless of work. |
| Long-range / "history rewrite" attack on a single node from old chain state | Layer 4 (per-node rolling checkpoints) — the node will not reorg below its own `last_checkpoint`. |
| Network-wide attempt to present a different chain at a known height | Layer 5 (consensus checkpoints) — once the table is populated post-launch. |
| Live-tip equivocation / selfish-mining at the chain head | Layer 6 (CIP-009.D rolling finality) — *when activated*. Today the head is defended only by Layers 1–3. |

### 5.3 Out-of-scope adversaries

Consistent with `docs/THREAT_MODEL.md`:

- **Eclipse / network-isolation attacks** are a P2P-layer concern,
  defended elsewhere (peer diversity, anchor connections); the
  reorg layers assume a node sees the honest chain's work.
- **Sustained > 51 % honest-rejection** — an attacker with durable
  majority hashpower for hours can still double-spend within the
  Layer-1 window every time. No PoW chain solves this; the layers
  raise the *cost* and *bound the depth*, they do not make a
  majority attacker harmless.

---

## 6. Residual gaps — stated honestly for the auditor

1. **Rental within the Tier-2 window is *expensive*, not
   *impossible*.** An attacker who can afford `2^((depth−10)/20) ×`
   the honest chain's work for the relevant span can still reorg up
   to depth 100. MESS makes this economically irrational for almost
   all attackers; it does not make it cryptographically forbidden.
   Layer 6 (CIP-009.D) is the intended closure for the live-tip
   portion of this gap.

2. **Partitions longer than the hard-cap window cause permanent
   forks needing manual intervention.** If a network partition
   lasts longer than `max_reorg_depth` blocks (mainnet: ≈ 3.3
   hours), the two sides can each pass their own Tier-3 cap and
   neither will reorg to the other on heal. Recovery is operator
   action (invalidate one side, restart). This is a deliberate
   trade: a bounded permanent-fork risk in exchange for hard
   finality. `CHECKPOINT_INTERVAL = 144` is tuned to make sub-cap
   partitions self-heal; supra-cap partitions are accepted as a
   known operational risk.

3. **Testnet and mainnet run different consensus rules.**
   `max_reorg_depth` (1000 vs 100) and the practical effect of
   `BOOTSTRAP_MESS_HEIGHT` differ between networks. Testnet's
   predictive value for mainnet reorg behaviour is therefore
   *reduced* — a reorg scenario that resolves cleanly on testnet may
   behave differently on mainnet. Any pre-mainnet reorg rehearsal
   must be interpreted with this caveat.

4. **`MIN_OUTPUT_AGE = 10`, not 100.** See §3.3. This needs an
   explicit decision before mainnet: is 10 the intended mainnet
   value, or a testnet-tuning value that should be raised (and
   network-split) for mainnet? CIP-009's threat argument assumed
   100.

5. **Layer 5 ships empty.** `CONSENSUS_CHECKPOINTS` is `&[]` on both
   networks today. Until the post-launch release process begins
   populating it, the network-wide checkpoint layer contributes
   *nothing* — the live defense is Layers 1–4 only. The release
   process that populates it (`scripts/update-checkpoints.sh`) is
   itself a trust assumption: a compromised release pipeline can
   poison a checkpoint. Mitigated by the same signing trust model
   as any binary release, and by the ≈ 2-week review lag, but it is
   a real surface and an auditor should treat the checkpoint layer's
   integrity as no stronger than the release-signing process.

---

## 7. How the layers compose — the defense-in-depth argument

No single layer is sufficient; the design is that an attacker must
beat **all active layers simultaneously**, and the layers fail
*independently*:

- Layers 1–3 (MESS hybrid) are **objective** — every node computes
  the same accept/reject from work and depth alone, no coordination,
  no trust. They bound an attacker by *cost* (Layer 2) and by
  *depth* (Layer 3).
- Layer 4 (per-node checkpoints) is **subjective but
  trust-free** — each node bounds its own reorg history without
  needing anyone else. It defends a node that has been online and
  following the honest chain even if the objective layers were
  somehow satisfied.
- Layer 5 (consensus checkpoints) is **coordinated** — it adds a
  network-wide constraint, at the cost of a release-process trust
  assumption.
- Layer 6 (CIP-009.D, future) is **miner-attested** — it closes the
  live-tip gap the objective layers structurally leave open.

The objective layers carry the load today. The coordinated and
attested layers (5 and 6) are the post-launch hardening path, and
both can coexist with the MESS hybrid — they are additional
constraints, never replacements. This is the same layered posture
Monero runs (MESS-equivalent scoring *and* checkpoints).

---

## 8. Action items surfaced by this reconciliation

1. **Correct CIP-009's framing.** Add a status note to CIP-009
   pointing here, clarifying that "Path B shipped" describes Layer 5
   only and that the MESS hybrid (Layers 1–3) was inherited, not
   rejected.
2. **Decide `MIN_OUTPUT_AGE` for mainnet** (§3.3, §6.4). Code value
   is 10; CIP-009 assumed 100.
3. **Update `src/consensus/finality.rs`** — its placeholder
   doc-comment describes the defense reasonably but points at a
   non-existent path (`docs/src/security/reorg-defense.md`). Point
   it here.
4. **Refresh the `H-16` memory note** — mark the *code* closed and
   the *design doc* (this file) as the closure of the documentation
   gap.
5. **Schedule the Layer-5 population** — `CONSENSUS_CHECKPOINTS` is
   empty; the first post-launch release should begin the checkpoint
   cadence per `CHECKPOINT_PROCEDURE.md`.

None of these are code changes to the consensus path. The reorg
*mechanism* is shipped and tested; what this document closes is the
*explanation*.

---

## 9. Changelog

- **2026-05-14** — Created. Reconciles CIP-009, the H-16 memory, and
  `consensus/finality.rs` against the verified state of
  `src/chain.rs` + `src/constants.rs`. Documents all six layers,
  justifies every parameter, states the threat model and the five
  residual gaps. Closes post-launch campaign item #3 (the
  documentation half of H-16 reorg defense).
