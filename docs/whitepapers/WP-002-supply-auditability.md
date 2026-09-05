# WP-002 · Supply Auditability
### Proving no silent inflation on a confidential-amount chain

**Status:** **Shipped** — genesis-active on both networks ·
**Layer:** Consensus · **Series:** [CoinCync Whitepapers](README.md)

> **Status change (2026-09-04).** This paper was written as a *proposal*, while
> the header's `supply_commitment` was 32 zero bytes and the only helper was
> documented in its own source as *a self-consistent checksum, not a proof*. It
> is now implemented and active from block 0 on both networks (`c0b9f407`,
> `909fe059`). §3.5 argued that enabling it before mainnet genesis "avoids the
> fork entirely and is the strongly preferred path" — that is the path taken,
> and the window it depended on closes at mainnet launch.
>
> Two findings from implementation are recorded rather than smoothed over:
> there were **three** disconnected attempts at this mechanism, two of which
> disagreed with each other, and a block is connected by **two** independent
> code paths, so verifying in one would have left a hole. Both are in §5.

---

## 1. Motivation

On a transparent chain, anyone can add up the UTXO set and check the money
supply. On a confidential-amount chain, they cannot — every amount is hidden
inside a Pedersen commitment. That is the privacy property working as intended,
and it is also the single most dangerous blind spot a privacy chain has.

The precedent is not hypothetical. CryptoNote shipped a key-image flaw that
permitted double-spends. Zcash disclosed a counterfeiting vulnerability that had
existed, unexploited and undetected, for years. In both cases the failure was a
subtle error in cryptographic machinery, and in both cases **the chain could not
tell it was being inflated.** A privacy chain whose supply cannot be checked is
one proof bug away from silent, unbounded, invisible counterfeiting.

Supply auditability is therefore not a nice-to-have feature. It is the safety
property that bounds the blast radius of every other cryptographic mistake.

---

## 2. Threat addressed

| Attack | Assumption it needs | What the design removes |
|---|---|---|
| **Silent inflation via range-proof bug** — a malformed proof admits a negative or wrapped amount, minting coins | Nobody can observe total supply, so minting is invisible | Not fully removable by accounting — see §4 — but detection of *emission-side* inflation becomes possible and continuous |
| **Coinbase over-issuance** — a block pays itself more than the schedule allows | Reward correctness is checked only at the moment of validation and never re-derivable afterwards | Every block commits to a running supply state; any node can recompute the schedule and compare, at any height, forever |
| **Retroactive supply rewrite** — history is edited so past emission looks legitimate | Supply claims are not committed to in the hashed header | The commitment is inside the header pre-image, so altering it changes the block hash and breaks proof-of-work |
| **Divergent supply beliefs between nodes** — nodes disagree on how much exists | Supply is tracked incrementally, path-dependently, per node | Supply is a pure function of height, committed per block, and recomputable from the chain alone |

---

## 3. Design

### 3.1 What is already sound (and why it is the foundation)

Two properties already hold and the design builds on them rather than replacing
them:

**Coinbase amounts are public and exactly checked.** Every coinbase output
commitment must equal `commit(declared_amount, 0)` — a zero-blinding commitment
to a plaintext value — with identity and off-curve commitments rejected, a
`checked_add` running total, and a requirement that the declared total equals the
scheduled maximum *exactly*. Emission is therefore not confidential at all: it is
public, and already validated per block.

**Every transaction balances.** Confidential transfers prove
`inputs = outputs + fee` in commitment space, with range proofs bounding every
output. Blinding factors cancel *within* a transaction by construction.

The consequence is important and often misunderstood: **on this design, newly
created value enters only through coinbase, and coinbase is public.** Confidential
transactions move value; they do not create it — provided the range proofs and
balance checks are sound.

### 3.2 The committed supply state

Define a per-block `SupplyState` containing at minimum:

- `total_emitted` — cumulative coinbase issuance through this height,
- `total_burned` — cumulative fee burn through this height,
- `height`, and
- a binding to the previous state (a hash chain).

Each block header commits to
`supply_commitment = H("supply_commitment" ‖ prev_commitment ‖ total_emitted ‖ total_burned ‖ height)`,
using a domain-separated hash. The field is already part of the header hash
pre-image, so the commitment inherits proof-of-work protection: rewriting a past
supply claim invalidates the block.

### 3.3 The audit procedure

Any participant — with no keys, no trust, and no privileged data — can:

1. Recompute the expected emission at every height from the published schedule
   (`reward = max(TAIL_EMISSION, (cap − already_mined) / DIVISOR)`), which is a
   deterministic pure function of height.
2. Recompute the supply-state chain from genesis.
3. Compare against each block's committed `supply_commitment`.

A mismatch at any height localises the divergence to a specific block. This is
the property that was missing: today a supply bug is *validated away* at the
moment it happens and leaves no re-checkable trace; afterwards, it leaves a
permanent, hash-committed record that any node can independently re-derive.

### 3.4 Validation rule

Consensus requires the committed state to equal the state derived from applying
the block to its parent's state. Because both sides are pure functions of the
chain, all honest nodes compute identically — the same determinism discipline
applied to cumulative work in WP-006.

### 3.5 Activation — resolved: genesis-active, no fork

The field is in the header pre-image, so turning it on changes header semantics.
That normally forces a height-gated hard fork under CIP-007, with the legacy zero
accepted below the activation height.

**It did not, because the rule landed while both chains were still resettable.**
Mainnet had not launched, and testnet genesis had just been reset by the
difficulty-calibration change (`852d07cf`), so both networks start from height 0
on current software. The rule is therefore active from block 0 with **no
activation constant, no rollout, and no change to the hash-locked
`constants.rs`** — it is simply how these chains work.

The transition cost is real and is pinned as a test
(`zero_placeholder_commitment_is_rejected_above_genesis`): a block carrying the
old all-zero placeholder is now **invalid above genesis**, so any pre-existing
chain data is discarded. That cost was acceptable only because it was paid inside
a window that was already open. **After mainnet launch this becomes a permanent
hard fork** — which is the whole reason it was worth doing now rather than later.

Genesis itself keeps the all-zero commitment, handled inside the shared
commitment function rather than at each call site, so the pinned `GENESIS_HASH`
constants stay valid and no genesis rebuild was needed.

---

## 4. Security analysis

### 4.1 What this proves

- **Emission followed the schedule**, verifiable by anyone, at any time, for
  every historical height — not just at validation time.
- **Supply claims are tamper-evident**, because they are inside the hashed
  header and therefore under proof-of-work.
- **Nodes cannot silently disagree** about total supply.

### 4.2 What this does *not* prove — stated plainly

**It does not prove the confidential portion is sound.** If a range proof admits
a wrapped or negative amount, value can be created inside a *transfer* without
touching coinbase, and a supply commitment over emission will not detect it. The
aggregate of UTXO commitments cannot be checked against a claimed total, because
the sum of unspent blinding factors is unknown to an auditor — that is precisely
the property that makes amounts confidential. There is no accounting trick that
recovers it.

This is the honest boundary of the mechanism, and it dictates the rest of the
strategy:

1. **The range proofs and balance checks are the actual inflation defence.** They
   must be published, reviewed constructions (Bulletproofs+ here), not novel
   math — and they must be externally audited before mainnet. This paper does not
   substitute for that audit; it bounds what happens if the audit misses
   something.
2. **Detection is still valuable.** Most historical inflation incidents involved
   an error in emission/issuance logic or an implementation slip that a
   recomputable supply record would have surfaced. Making one whole class
   continuously auditable is worth doing even though it does not cover all
   classes.
3. **Optional strengthening.** A chain may additionally publish the *count* of
   outputs and key images and require monotonicity, which catches structural
   anomalies (mass output creation) without revealing amounts.

### 4.3 Privacy impact

None. Every quantity committed — cumulative emission, burn, height — is already
public or derivable from public data. The commitment adds no per-user
information and does not touch the transaction graph.

---

## 5. Implementation

| Piece | Location |
|---|---|
| `supply_commitment(height, minted, burned)` — **the** definition | `src/emission/supply.rs` |
| `advance_supply_totals` — the shared arithmetic (miner + both validators) | `src/chain.rs` |
| `advance_and_verify_supply` — totals + commitment check | `src/chain.rs` |
| Verification on the linear tip-extend path | `src/chain.rs` (`add_block`) |
| Verification on the reorg fork-block re-apply path | `src/chain.rs` |
| Miner population from the assembled block | `src/mining/block_builder.rs` |
| `parent_total_minted` / `parent_total_burned` in the template | `src/mining/template.rs` |
| `supply_commitment` + domain + encoding in `get_supply_info` | `src/rpc/server.rs` |
| `supply_commitment` header field (in the hash pre-image) | `src/consensus/header.rs` |
| Coinbase exact-amount validation | `src/consensus/validation.rs` |
| Emission schedule (pure function of height) | `src/emission/curve.rs` (WP-003) |
| Supply accounting, `checked_add`/`checked_sub` + halt-on-overflow | `src/chain.rs` |

### 5.1 Three attempts, two of which disagreed

Scoping found the mechanism had been started **three** times and finished zero:
the header field (always zero), `crypto::audit::SupplyState` (zero callers), and
`emission::supply::calculate_supply_commitment` (zero callers, re-exported only,
and documented as a "Pedersen commitment" when it was a plain hash).

The two implementations **disagreed on both inputs and domain separator** —
`minted ‖ burned` under `"supply_commitment"` versus
`emitted ‖ burned ‖ circulating ‖ emission_remaining` under
`"COINCYNC_SUPPLY_COMMITMENT"`. Two implementations of one consensus value that
must agree is the WP-006 §4.4 shape, the one that already produced a fleet-wide
`total_difficulty` divergence. It cost nothing to fix here because nothing
depended on it yet; the same defect discovered after launch is a chain split.

The derived fields were dropped: `circulating` is `minted − burned` and
`emission_remaining` is a function of height, so committing to them added no
information and two more ways to diverge.

### 5.2 Two connect paths, not one

A block reaches the chain through **two** independent loops: the linear
tip-extend path and the reorg fork-block re-apply path. They already duplicated
the emission and burn arithmetic. Verifying in only the linear path would have
let a block enter the chain unverified **simply by arriving as part of a reorg** —
a hole an attacker chooses freely, since they control whether their block arrives
as an extension or a fork.

Both paths now call one routine. Ordering is load-bearing on each: the check runs
before *any* mutation — before tip and `height_to_hash` on the linear path, and
before the height mapping, the Phase-2 checkpoint and the UTXO batch on the reorg
path — so a rejection leaves nothing to unwind. The reorg rollback unwinds by
index and its site-5a guard keys on `height_to_hash`, both of which assume a
block is either fully applied or untouched.

### 5.3 Why the template ships parent totals, not a commitment

`get_block_template` sends `parent_total_minted` / `parent_total_burned` rather
than a finished commitment. A template is a suggestion, not a mandate: a miner may
assemble a different transaction set, and the block's fee-burn depends on that
set. Handing over the parent totals lets the miner compute the correct commitment
for whatever block it actually builds. A pre-computed commitment would be valid
only for that exact transaction list and would turn any legitimate deviation into
an unsubmittable block.

### 5.4 Tests

`miner_commitment_round_trips_through_the_validator` is the drift guard — it
pins the miner's computation to the validator's, the same role
`builder_and_validator_use_identical_floor` plays for the fee floor. Plus
mismatch rejection, genesis acceptance, and the transition cost stated as an
assertion. Full lib suite 1177 passed / 0 failed.

**Still open:** an audit RPC returning the supply state *at an arbitrary past
height* (today's `get_supply_info` reports the tip), and a from-genesis
recomputation harness that checks every committed state in one pass.

---

## 6. Known limits

- It bounds **emission-side** inflation only; confidential-transfer soundness
  rests on the range proofs (§4.2). This is the most important limit in the
  paper and is unchanged by shipping.
- **No historical audit endpoint yet.** `get_supply_info` reports the tip; there
  is no RPC for the supply state at an arbitrary past height, and no
  from-genesis recomputation harness (§5.4).
- The commitment is verified **on connect**, so it binds the chain a node
  actually builds. A light client still needs the header to check a claimed
  reading against — see WP-017 for what light clients can and cannot verify.
- Live-fire coverage is thin: the logic is unit-tested and the wiring is
  review-verified, but the chain test module cannot yet drive real `add_block`
  calls with valid PoW, so no test exercises rejection end-to-end through a
  running node.
- The mechanism detects divergence; it does not automatically repair a chain that
  has already inflated. Response is an operational decision.

---

## 7. References

- CryptoNote key-image flaw — double-spend via unchecked key images.
- Zcash counterfeiting vulnerability disclosure (2019) — an inflation bug that
  existed undetected because supply could not be checked.
- Monero supply-audit discussions and the "sum of commitments" limitation.
- Bulletproofs+ — the range-proof construction this chain relies on for the
  confidential half of the argument.
- Internal: [WP-003 Emission](WP-003-emission.md),
  [WP-100 §3](WP-100-solved-issues-ledger.md) (supply underflow and the u64
  overflow halt).
