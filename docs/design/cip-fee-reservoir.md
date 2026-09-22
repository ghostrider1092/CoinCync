# CIP-Fee-Reservoir — the "Water Battery" for the Security Budget

Status: **DRAFT / idea** (not implemented; not scheduled). Testnet-only when built,
gated, fail-closed, externally reviewed before any activation.

## Motivation — the grid-load analogy

A hydroelectric **pumped-storage** plant is a battery: it pumps water uphill when
electricity is cheap and abundant (night, solar glut), then lets it fall to
generate power when the grid is stressed and prices spike. It is a *net consumer*
of energy (70–80% round-trip) but hugely valuable because it **absorbs surplus
that would be wasted and deploys it exactly when the grid needs it**.

A proof-of-work chain has the same problem the grid has: **volatile demand**.
Fee revenue — and therefore the security budget that pays miners — spikes during
congestion and collapses during quiet periods. As CoinCync's emission tapers to
the tail, fees become the dominant security incentive, and their volatility
becomes a security risk: a fee drought is a cheap-to-attack window. Nothing today
carries a surplus *across time*; ASERT re-targets difficulty instantly but stores
nothing.

The **fee reservoir** is the pumped-storage analogue: it stores fee surplus when
demand is low and releases it when demand is high, smoothing the security budget.

## Mapping

| Pumped storage | Fee reservoir |
|---|---|
| Upper reservoir (charged) | On-chain **reservoir balance** — escrowed, unminted fees |
| Lower reservoir (spent) | The baseline coinbase / miner reward |
| Grid demand signal | Block **congestion** (`consensus::fee_market`, `CONGESTION_THRESHOLD`) |
| **Charging** (cheap surplus) | Low congestion → divert a fraction of collected fees *into* the reservoir instead of paying it all to the miner |
| **Discharging** (peak demand) | High congestion / fee drought → pay reservoir *out* to miners, topping up the security budget |
| Reversible turbine | One rule, both directions, keyed on the congestion signal |
| 70–80% round-trip (net consumer) | A small **decay/burn** per epoch on the reservoir — deflationary, discourages hoarding, models the loss |

## Mechanism

State: a single consensus-tracked `reservoir: Amount`, updated deterministically
per block as a pure function of that block's fees and congestion (so every node
computes the same value — a *shared rail*, like every other consensus quantity).

Per block at height `h` with total fees `F` and congestion `c ∈ [0,100]`:

```
if c < LOW_WATER:                 # charging — surplus, pump uphill
    store   = F * CHARGE_BPS / 10_000
    miner   = F - store
    reservoir += store
elif c > HIGH_WATER:              # discharging — peak, generate
    draw    = min(reservoir, F * DISCHARGE_BPS / 10_000)
    miner   = F + draw
    reservoir -= draw
else:                             # nominal — pass through
    miner   = F
reservoir -= reservoir * DECAY_BPS / 10_000   # round-trip loss (burn)
```

`miner` is added to the coinbase claim via the existing
`fee_market::distribute_fee` seam; `reservoir` and the burn are new consensus
state. The decay burn is what keeps this a *net consumer* (sound: the reservoir
can never pay out more than was stored, and decay strictly reduces it), so it
cannot become an inflation path — total issuance stays PoW/emission-bounded.

## Consensus integration points

- `consensus::fee_market` — the charge/discharge/decay rule (pure, unit-testable
  like `distribute_fee`).
- Block validation — recompute the reservoir transition and check the coinbase's
  fee claim against it (producer and validator share the one rule → no drift).
- Header/state — the reservoir balance must be committed (a new hashed field, or
  folded into the supply commitment) so it is PoW-bound and reorg-consistent;
  reorgs rewind it exactly like the other Phase-2 state (`Phase2Store`-style
  checkpoint/rewind).
- The burn interacts with the emission accounting / supply invariant — must be
  reflected there.

## Parameters (to model, then ratify)

`LOW_WATER`, `HIGH_WATER` (congestion thresholds), `CHARGE_BPS`, `DISCHARGE_BPS`,
`DECAY_BPS`, and a reservoir cap. Choose by simulating against recorded/synthetic
fee series (the same replay style as `tests/difficulty_replay.rs`) to target a
smoothed miner-revenue variance without starving the miner in quiet periods.

## Safety / open questions

- **Miner-manipulation:** can a miner game the congestion signal to force
  discharge (self-pay) or avoid charging? Congestion must be measured from
  committed block contents, not miner-declared, and thresholds chosen so gaming
  is unprofitable after the decay.
- **Supply invariant:** the reservoir + burn must be provably issuance-neutral
  (never mints; only redistributes already-collected fees minus decay).
- **Reorg consistency:** reservoir transitions must rewind exactly with the chain.
- **Interaction with the fee market / congestion pricing** already in place.

## Status

Idea only. If pursued: implement behind an off-by-default feature, model the
parameters via replay, prove the supply-neutrality + reorg invariants, external
review, testnet soak — then propose activation. This is a "small hidden thing":
invisible in normal operation, but it smooths the security budget the way
pumped storage smooths the grid.
