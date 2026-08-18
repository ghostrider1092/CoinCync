# Emission curve

The amount of CYNC paid out per block as the coinbase reward, as a function of cumulative mined supply. This is the **only** way new coins enter circulation — there is no premine, no founder allocation, no ICO, no airdrop, no dev tax. These properties are locked by [Article I (Transparent Emission)](../governance/constitution.md#article-i--transparent-emission-no-hidden-inflation) and [Article II (No Pre-mine, No Developer Tax)](../governance/constitution.md#article-ii--no-pre-mine-no-developer-tax) of the Constitution.

## Parameters

| Parameter | Value | Source |
|---|---|---|
| Target block time | **120 seconds** (2 minutes) | `TARGET_BLOCK_TIME` in `src/constants.rs` |
| Blocks per year | **262,800** | `BLOCKS_PER_YEAR = 365 * 24 * 60 * 60 / 120` |
| Base unit | **1 CYNC = 10¹² atomic units** | `COIN` in `src/constants.rs` |
| Supply asymptote (soft target) | **100,000,000 CYNC** | `TOTAL_SUPPLY_TARGET` (whole units), `MAX_SUPPLY` (atomic) |
| Emission divisor | **2,000,000** | `EMISSION_DIVISOR` in `src/constants.rs` |
| Genesis block reward | **50 CYNC** | `base_reward_from_supply(0)` in `src/emission/curve.rs` |
| Tail emission | **0.6 CYNC / block** (perpetual floor) | `TAIL_EMISSION = 600_000_000_000` atomic |
| Curve type | **Geometric decay** (Monero-style, supply-proportional) | `src/emission/curve.rs::base_reward_from_supply` |

## The emission formula

CoinCync has **no halvings and no eras**. A single line of code determines all of monetary policy:

```text
reward = max( TAIL_EMISSION, (100,000,000·COIN − already_mined) / EMISSION_DIVISOR )
```

where `already_mined` is the cumulative supply in atomic units, `COIN = 10¹²`, and `EMISSION_DIVISOR = 2,000,000`. The reward is **proportional to the remaining distance to the 100M asymptote**, so every coin that is mined makes the next one slightly harder to earn. The decay is smooth and continuous — there are no cliff edges, no discrete steps, no activation heights.

| Cumulative mined supply | Block reward |
|---|---|
| 0 (genesis) | **50 CYNC** |
| 50,000,000 CYNC | 25 CYNC |
| 75,000,000 CYNC | 12.5 CYNC |
| ~98,800,000 CYNC | **0.6 CYNC** (tail floor takes over) |

The reward halves in size each time the *remaining* gap to 100M halves: 50 → 25 → 12.5 → … until the formula would drop below the **0.6 CYNC tail floor**, at a cumulative supply of about **98,800,000 CYNC** (where `(100M − 98.8M)/2,000,000 = 0.6`). From that point on, every block pays exactly the tail.

```text
Reward (CYNC)
50 ●
   │●
   │ ●●
25 │   ●●        (50M mined)
   │     ●●●
12.5│        ●●●●   (75M mined)
   │            ●●●●●●
0.6 ├──────────────────────●●●●●●●●●●●●●●●●●●●→  perpetual 0.6 tail
   └──────────────────────────────────────────────→
   0            cumulative mined supply →        ~98.8M
```

### Why supply-proportional decay instead of halvings

Halvings create predictable supply shocks — every four years, Bitcoin's block reward drops by 50% in a single block. That causes forced-seller events at hash-power equilibria and strong psychological effects on price discovery. A smooth geometric decay distributes issuance continuously, removing the cliff edges and giving miners continuous rather than discrete incentive changes. Because the reward depends on *how much has already been mined* rather than on a block-height schedule, the curve is self-adjusting: it does not care how fast or slow blocks were actually found.

The formula and its constants are what the Constitution fixes. They live as compile-time constants in `src/constants.rs`:

```rust
pub const TOTAL_SUPPLY_TARGET: u64 = 100_000_000;   // whole CYNC (the asymptote)
pub const EMISSION_DIVISOR:    u64 = 2_000_000;
pub const TAIL_EMISSION:       u64 = 600_000_000_000; // 0.6 CYNC in atomic units
```

Changing any of these numbers is a hard fork and a constitutional violation — mechanically blocked by the compile-time assertions and the `critical_files.lock` hash of `src/constants.rs` and `src/emission/curve.rs`.

## 100M is an asymptote, not a hard cap

This is the single most important thing to understand about CYNC's monetary policy: **100,000,000 CYNC is the asymptote the issuance curve approaches, not a ceiling on total supply.**

The supply-proportional part of the curve decays toward 100M but never quite reaches it — as `already_mined` closes in on 100M, the numerator `(100M·COIN − already_mined)` shrinks toward zero. But it never gets there, because the **0.6 CYNC/block tail floor always wins first.** Once the curve would fall below 0.6 CYNC (at ~98.8M mined), the `max(TAIL_EMISSION, …)` clamp pins the reward at exactly 0.6 CYNC forever.

Because the tail is perpetual, total *emitted* supply keeps growing: it crosses 100M and continues past it, slowly and without bound, at 0.6 CYNC × 262,800 blocks/year ≈ **157,680 CYNC of gross issuance per year** after the tail begins. There is no block at which issuance stops. The `TOTAL_SUPPLY_TARGET` constant names the curve's asymptote — it is *not* enforced as a maximum coin count, and no code clamps total supply to it.

## Why a tail emission instead of zero

This is one of the load-bearing design decisions.

A blockchain's security budget is the value of the block reward that miners earn. As Bitcoin's reward halves toward zero, security is supposed to come from transaction fees alone. But fee markets are notoriously volatile, and a chain whose security depends on a healthy fee market is a chain whose security is hostage to its short-term throughput.

A **fixed tail emission** removes that dependency. Once cumulative supply passes ~98.8M CYNC, there is always a constant 0.6 CYNC / block flowing to miners regardless of fee market conditions. This:

- Guarantees a baseline security budget forever
- Removes the moral hazard of a "fee market crisis" decades from now where the network has to choose between underpaying miners and mining empty blocks
- Keeps the long-term gross inflation rate positive but ever-shrinking as a *percentage* of a growing supply (0.6 CYNC/block is a smaller and smaller fraction of the total each year)

Monero pioneered this design. CoinCync adopts the same reasoning: a fee-only future is a security risk, so the protocol pays a small, predictable perpetual subsidy instead.

## Fee burn and net supply

Independent of the coinbase reward, CoinCync **burns a fraction of every transaction fee** — permanently destroying those coins rather than paying them to anyone.

- **Normal conditions:** 70% of fees to the miner, **30% burned** (`FEE_MINER_NORMAL_PERCENT = 70`, `FEE_BURN_NORMAL_PERCENT = 30`).
- **Congested conditions:** 50% to the miner, **50% burned** (`FEE_MINER_CONGESTED_PERCENT = 50`, `FEE_BURN_CONGESTED_PERCENT = 50`) — spam gets more expensive, and the burn strengthens exactly when the network is contended.
- **No third destination.** Fees are either paid to the miner or burned. `FEE_PROTOCOL_*_PERCENT = 0` — Article II forbids any developer or protocol fee.

Burning destroys coins, which pushes *net* circulating supply **below** the gross-emission curve. Whether the chain is net-deflationary at any given moment depends on how the burn compares to the tail:

- If burned fees exceed the 0.6 CYNC/block tail — i.e. total fees run above **~2 CYNC/block** (30% of which is burned) — net supply *shrinks*.
- If burned fees are below that, the tail out-issues the burn and net supply still grows, just more slowly than gross emission.

So CYNC is **deflationary only under sufficient sustained usage**, not structurally deflationary at any usage level. The burn is a protocol invariant, not a tunable parameter; the 30% normal-condition floor is itself locked by a compile-time assertion.

## Coinbase outputs

The coinbase transaction in every block pays `base_reward + collected_fees − burned_fees` to the miner's stealth address. Even the coinbase uses the privacy machinery — the miner's address is a one-time stealth output, not a reusable transparent address. The view key for the miner's wallet recognizes the output; nobody else can.

The miner's static pubkey is published in the block header for the explorer to display, but the *output* is a one-time stealth output derived from that pubkey plus a per-block transaction secret. It is not a re-identifiable wallet address — a miner can only show the world "I mined this block" if they choose to disclose, never "I am the same miner who mined block N − 5" unless they voluntarily link them off-chain.

The coinbase amount is minted with a **zero blinding factor**, so every block's issued amount is transparent and is checked by every node to equal exactly `base_reward_from_supply(cumulative_supply)`. This is what makes total supply independently auditable: it provably equals the summed deterministic emission, recomputable via `get_supply_info` / `/api/v1/emission`.

## Verifying the curve

The block explorer at [explorer.coincync.network](https://explorer.coincync.network) renders the emission curve on its supply panel. The same data is queryable via JSON-RPC:

```bash
curl -sX POST https://api.coincync.network/rpc \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_supply_info"}' | jq .
```

Returns something like:

```json
{
  "height":         12345,
  "current_reward": 50000000000000,
  "total_emitted":  "616000000000000000",
  "emission_phase": "Distribution"
}
```

Atomic units: 1 CYNC = 10¹² atomic. `50000000000000` atomic = 50 CYNC (the genesis-era reward, still near 50 CYNC while cumulative supply is small).

## What can change about emission

Nothing, by design. The emission formula is locked by [Constitution Article I](../governance/constitution.md#article-i--transparent-emission-no-hidden-inflation). Changing the genesis reward, the emission divisor, the tail, the block time, or the 100M asymptote would require:

- A hard fork (the resulting chain is incompatible with the old chain)
- A deliberate constitutional violation (mechanically blocked by the compile-time assertions)
- Every operator on the network to deliberately opt in to a chain that is, by definition, no longer CoinCync

There is **no operator key**, **no admin key**, and **no DAO** that can modify the emission. The numbers are baked into `src/constants.rs` and `src/emission/curve.rs` and into every node binary that anyone has ever built. Any binary that tries to ship with altered numbers fails the constitutional `assert!`s at compile time:

```rust
const _: () = assert!(TOTAL_SUPPLY_TARGET == 100_000_000,
    "UNCONSTITUTIONAL: Article I — Supply target must be exactly 100,000,000 CYNC");
const _: () = assert!(TAIL_EMISSION == 600_000_000_000,
    "Asymptotic curve: tail emission is 0.6 CYNC/block = 600_000_000_000 atomic");
```

## Implementation references

- `src/constants.rs::TOTAL_SUPPLY_TARGET`, `MAX_SUPPLY`, `EMISSION_DIVISOR`, `TAIL_EMISSION`, `TARGET_BLOCK_TIME`, `BLOCKS_PER_YEAR`
- `src/emission/curve.rs::base_reward_from_supply` — the canonical, consensus-critical reward function (supply-proportional geometric decay with the tail floor)
- `src/emission/curve.rs::base_reward` — height-based estimate used for templates/explorer/tests (numerically integrates the curve)
- `src/emission/curve.rs::emission_phase` — the Distribution / Mature / Tail phase classifier
- `src/mining/template.rs` — coinbase construction

## Next reading

- [Constitution Article I](../governance/constitution.md#article-i--transparent-emission-no-hidden-inflation) — the rule that locks the emission schedule
- [Consensus & PoW](./consensus.md) — how blocks are produced and validated
- [Transaction format](./transaction-format.md) — what a coinbase output looks like on the wire
