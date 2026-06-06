# ASERT halflife = 3600 s: rationale

**Date:** 2026-06-05
**Status:** Documented (existing parameter, formalizing the choice)
**Authors:** maintainer (audit-prompted)

## Context

`src/constants.rs:62` declares:

```rust
/// ASERT halflife in seconds (1 hour)
pub const ASERT_HALFLIFE: u64 = 3600;
```

with `TARGET_BLOCK_TIME = 120 s` (`src/constants.rs:35`).

ASERT (Absolutely Scheduled Exponentially-weighted Rising Targets) is the
Bitcoin Cash difficulty-adjustment algorithm. The canonical BCH parameter
choice is **halflife = 2 × target_block_time** — for BCH that's 1200 s
(20 min); the published rationale is that a halflife much shorter than a
typical hashrate excursion makes the chain track real hashrate quickly,
while a halflife much longer leaves the chain underpowered after sudden
hashrate drops.

CoinCync uses **3600 s (1 hour) = 30 × target_block_time**. That's a
deliberate divergence from the BCH convention. This document records
why.

## Decision

ASERT halflife stays at 3600 s for both testnet and mainnet at launch.

## Rationale

Three properties of the CoinCync threat model and operating posture
push toward a longer halflife than BCH's:

### 1. Small, deliberately-bounded hashrate at launch

The constitutional posture has CPU-only RandomX mining (Article V) and
no premine / no founder allocation. Mainnet launches with whatever
hashrate organically attaches — likely in the low-MH/s to single-digit
GH/s range for months, not the tens of TH/s a tuned mature PoW chain
sees.

In that regime, the dominant difficulty risk is a single large miner
attaching for a few hours, dragging difficulty up, then leaving — and
the chain getting stuck at the inflated difficulty until enough time
passes for the algorithm to catch back down. With BCH's 1200 s
halflife, "catching back down" from a 10× hashrate spike that lasted
30 minutes takes hours of underproduced blocks. With 3600 s halflife,
that same spike-and-leave still costs the chain catch-down time but
the integrated harm is smaller because the algorithm refused to chase
the spike as aggressively in the first place.

This is the **"don't chase, hold steady"** posture. Apt for small
chains; unnecessary for mature chains with thick hashrate floors.

### 2. Resistance to "hashrate marketplace" attacks

Renting hashrate from NiceHash-style marketplaces to attack a small
PoW chain is a known, repeatable pattern (Ethereum Classic 2019, Bitcoin
Gold 2018, Horizen 2018 — all cited in `src/chain.rs:70-73` for the
MESS context). The attacker's economics improve when the target's
difficulty adjusts fast: rent for an hour, drag difficulty up,
unleash an attack at the inflated rate, leave before the chain has
a chance to adapt.

A longer halflife dampens this. The attacker has to pay for hashrate
across a longer integration window before difficulty meaningfully
moves; the marginal economics of the attack get worse the longer the
halflife is.

### 3. Composes with MESS

CoinCync already deploys progressive reorg resistance via the MESS
variant at `src/chain.rs:84`. MESS makes deep reorgs require
exponentially more cumulative work than the local chain has. Combined
with a slow-adjusting difficulty, this gives an attacker who builds a
private chain a worst-case integration window measured in hours, not
minutes — they can't quickly "catch up" on difficulty after rejoining
a privately-mined branch because public-chain difficulty has barely
moved.

## What we give up

The cost of 3600 s halflife is real. If the honest network loses 90 %
of its hashrate suddenly (e.g. a Vultr regional outage takes the seed
fleet offline), the chain produces blocks at ~10 × the target interval
until difficulty adjusts. With 3600 s halflife the algorithm takes
~7 hours to halve the difficulty, vs ~1 hour at the BCH-canonical
1200 s. During that 7-hour window, transactions confirm slowly and the
mempool builds up.

For testnet this is acceptable. For mainnet at launch this is also
acceptable — there is no economic activity dependent on sub-hour
confirmation latency. As the network matures (real merchant flows,
exchange listings, atomic swap volume), this calculus changes and the
halflife may need to come down. That's a hard fork; the
`HardForkSchedule` mechanism in `src/consensus/` already exists for
this kind of consensus parameter migration.

## Bounds on this decision

This document covers the launch-window choice. It does NOT commit:

- That 3600 s is correct for mature-network conditions
- That a future halving (e.g. to 1800 s) is or isn't appropriate
- That ASERT itself is the right long-term difficulty algorithm

All three of those are open for re-evaluation as the chain accumulates
operational history.

## References

- BCH ASERT spec (Mark Lundeberg, Jonathan Toomim, 2020):
  <https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/>
- ASERT halflife rationale: same doc, "halflife" section
- CoinCync MESS variant: `src/chain.rs:55-105` and
  `docs/decisions/2026-05-23-reorg-handling-v1.0-scope.md`
- NiceHash-rental attack history: cited in `src/chain.rs:70-73`

## Followup

- Audit item from the 2026-06-05 cross-reference sweep — see
  `docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md`
  (audit section in the eventual amendment) for the full 16-item list
  this addresses.
- Revisit at the v1.1+ planning window once `cyncswap` brings real
  cross-chain economic activity.
