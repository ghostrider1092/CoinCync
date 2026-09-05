# WP-002 · Supply Auditability
### Proving no silent inflation on a confidential-amount chain

**Status:** **Proposed** — scaffolding exists, the mechanism does not yet ·
**Layer:** Consensus · **Series:** [CoinCync Whitepapers](README.md)

> **Honest status up front.** The header carries a `supply_commitment` field and
> `src/crypto/audit.rs` defines a `SupplyState`, but the field is currently
> written as 32 zero bytes and the existing helper is documented in its own
> source as *a self-consistent checksum, not a proof*. This paper specifies what
> must be built. Nothing in it should be read as shipped.

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

### 3.5 Activation

The field exists and is hashed today with a zero value, so turning it on changes
the header pre-image semantics and must be **height-gated** as a hard fork under
the standard activation policy (CIP-007), with the legacy zero accepted below the
activation height. Doing this **before mainnet genesis** avoids the fork entirely
and is the strongly preferred path.

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

**Existing scaffolding (not the mechanism):**

| Piece | Location | Status |
|---|---|---|
| `supply_commitment` header field | `src/consensus/header.rs` (in the hash pre-image) | Present, written as zeros |
| `SupplyState`, domain-separated commitment, `verify()` | `src/crypto/audit.rs` | Present; documented as a checksum, not a proof |
| Coinbase exact-amount validation | `src/consensus/validation.rs` | **Shipped** |
| Emission schedule (pure function of height) | `src/emission/curve.rs` | **Shipped** (see WP-003) |
| Supply accounting with `checked_add`/`checked_sub` + halt-on-underflow | `src/chain.rs` | **Shipped** |

**Work required:**

1. Populate `supply_commitment` from the derived `SupplyState` at block
   construction.
2. Add the consensus check that the committed value equals the derived value.
3. Height-gate the rule (or set it at genesis, preferred).
4. Expose an audit RPC returning the supply state and its derivation at any
   height, so third parties can verify without running custom code.
5. Add regression tests: a block claiming inflated emission must be rejected; a
   recomputation from genesis must match every committed state.

---

## 6. Known limits

- **This is a proposal.** Nothing in §3 is implemented today beyond the field and
  the helper struct.
- It bounds **emission-side** inflation only; confidential-transfer soundness
  rests on the range proofs (§4.2).
- Enabling it after mainnet genesis is a hard fork; the intended path is to
  enable it at genesis.
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
