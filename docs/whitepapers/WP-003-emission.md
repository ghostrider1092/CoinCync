# WP-003 · Emission
### Asymptotic tail, zero dev tax, height-determined reward

**Status:** Shipped · **Layer:** Consensus · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Emission is the one consensus rule every holder can check and every holder cares
about. It determines whether the chain's scarcity claim is true, whether miners
are paid after the subsidy era, and — through the "dev tax" question — who the
chain actually serves.

Two failure modes matter. The first is **dishonesty**: a supply curve marketed as
a hard cap that is not one, or a founder allocation described as something else.
The second is **fragility**: an emission function that overflows, halts, or
diverges between nodes. CoinCync has hit the second, in production logic, and the
fix is part of this record.

---

## 2. Threat addressed

| Attack / failure | Assumption it needs | What we removed |
|---|---|---|
| **Emission divergence** — nodes disagree on the reward for a height | Reward derived from mutable local state (e.g. an accumulated supply variable) | Reward is a pure, deterministic function of **height** — miner and every validator compute identically |
| **Supply-accumulator overflow halt** | A 64-bit accumulator suffices for a running total | Widened to `u128` with migration (WP-100 §3.7) |
| **Silent supply corruption** | Underflow can be safely clamped | `checked_sub` with an explicit halt rather than `saturating_sub` (WP-100 §3.6) |
| **Coinbase over-issuance** | Reward correctness need only be checked loosely | Each coinbase output must commit to its declared plaintext amount with zero blinding, and the declared total must equal the scheduled maximum **exactly** |
| **Hidden founder allocation** | Users do not read the genesis block | Genesis reward goes to a burn address no one holds the key to; zero premine, constitutionally fixed 0% dev tax |

---

## 3. Design

### 3.1 The curve

```
reward(height) = max( TAIL_EMISSION , (SUPPLY_CAP − already_mined) / EMISSION_DIVISOR )
```

with `SUPPLY_CAP = 100,000,000 CYNC` (× 10¹² atomic units),
`TAIL_EMISSION = 0.6 CYNC`, and `EMISSION_DIVISOR = 2,000,000`.

This is a **smooth asymptotic decay**, not a halving schedule. Each block pays a
fixed fraction of the remaining un-mined supply, so the reward glides downward
continuously instead of stepping by 50% every few years. Two consequences:

- **No halving cliffs.** Halving-based chains subject their miners to an abrupt
  50% revenue cut on a known date, which is a recurring security event — hashrate
  leaves, difficulty lags, and the chain is briefly weaker. A smooth curve removes
  the cliff entirely.
- **The cap is an asymptote.** The supply approaches 100M and never reaches it
  under the decay term alone.

### 3.2 The tail is a floor, and the cap is therefore a *statement of intent*

Because `reward` is floored at `TAIL_EMISSION`, emission never stops. Once the
decay term falls below 0.6 CYNC, every block pays exactly 0.6 CYNC forever. This
is deliberate — a chain with zero block subsidy must fund security purely from
fees, which is an unsolved problem, and we prefer a small permanent inflation to
an unfunded security budget.

**Honest phrasing matters here.** "100,000,000 cap" is accurate as the asymptote
of the decay term, but the tail means total supply grows without bound in the
very long run. Describing it as an absolute hard cap would be inaccurate, and
project materials should say *asymptotic cap with a perpetual tail*. This
correction is recorded because earlier project wording was imprecise about it.

### 3.3 Height-determined, not state-determined

The reward is computed from **height**, via a deterministic integer estimate of
supply at that height, rather than from a node's accumulated supply variable.
This is the property that makes emission consensus-safe: two nodes with different
histories, caches, or reorg paths still compute the same reward for the same
height. The miner uses the identical function as every validator.

The trade-off is explicit: the height-based estimate steps at defined boundaries
and drifts by roughly 0.1% from a continuously-accumulated figure. We accept a
tiny, deterministic, universally-agreed drift over an exact figure that nodes
could disagree about — determinism beats precision in consensus.

### 3.4 Arithmetic discipline

All emission and supply arithmetic is `u128` with saturating or checked
operations, a fast-path for the tail era (so a query at an absurd height cannot
become an unbounded loop), and no floating point anywhere.

### 3.5 Zero dev tax

There is no founder reward, no premine, and no protocol-level developer
allocation — fixed by the project constitution rather than by convention. The
genesis coinbase pays to a burn address with no known key. This is a funding
constraint as much as a fairness statement: it is why grant funding, rather than
an emission cut, is the sustainability path.

---

## 4. Security analysis

**What holds.** Emission is deterministic, overflow-safe, exactly enforced at
validation, and publicly verifiable — coinbase amounts are plaintext with
zero-blinding commitments, so anyone can check what a block paid itself without
any keys.

**Verified.** Emission unit tests cover the curve shape (50 CYNC at genesis,
halved-scale checkpoints, the 0.6 tail floor), overflow behaviour at extreme
heights, and the invariant that reward never drops below the tail. An independent
adversarial review of emission during the 2026-09 base audit found no
overflow, panic, or divergence path.

**What this does not protect against.**

- **The cap is not a hard cap** (§3.2). Long-run supply grows linearly at the
  tail rate. Anyone modelling scarcity must model the tail.
- **Emission correctness does not imply supply correctness.** Coinbase issuance
  being exact says nothing about whether a confidential-transfer bug mints value
  elsewhere. That is WP-002's subject, and its limits section is the honest
  answer.
- **Zero dev tax is a sustainability risk**, not just a virtue. A chain with no
  protocol funding must find another way to pay for audits and infrastructure, and
  should say so rather than treat it purely as a marketing point.

---

## 5. Implementation

| Component | Location |
|---|---|
| Reward curve, tail floor, height-based estimate, tail fast-path | `src/emission/curve.rs` |
| `SUPPLY_CAP`, `TAIL_EMISSION`, `EMISSION_DIVISOR` | `src/constants.rs` |
| Coinbase exact-amount + zero-blinding validation | `src/consensus/validation.rs` |
| Supply accounting (`checked_add` / `checked_sub` + halt) | `src/chain.rs` |
| Genesis burn-address coinbase | `src/mainnet.rs`, `src/testnet.rs` |

`src/emission/curve.rs` is **hash-locked** (WP-007): it cannot be edited without
regenerating the consensus lock, which makes an accidental emission change
impossible to merge silently.

**Failure record.** WP-100 §3.6 (underflow clamp) and §3.7 (u64 overflow halt at
~height 407,828).

---

## 6. Known limits

- The asymptotic cap plus perpetual tail must be described accurately in all
  public material; it is not a Bitcoin-style hard cap.
- The ~0.1% height-estimate drift is a deliberate determinism trade-off.
- Tail-era security economics (fees plus 0.6 CYNC/block) are unproven for this
  chain, as they are for every chain that has not reached that era.
- Zero dev tax means audit funding is external and must be secured
  independently.

---

## 7. References

- Bitcoin halving-schedule security discussions (the cliff problem this design
  avoids).
- Monero tail-emission rationale — perpetual minimum subsidy as a security
  budget.
- Internal: [WP-002 Supply auditability](WP-002-supply-auditability.md),
  [WP-007 Critical-files hash lock](WP-007-critical-files-hash-lock.md),
  [WP-100 §3](WP-100-solved-issues-ledger.md).
