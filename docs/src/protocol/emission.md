# Emission curve

The amount of CYNC paid out per block as the coinbase reward, as a function of block height. This is the **only** way new coins enter circulation — there is no premine, no founder allocation, no ICO, no airdrop, no dev tax. These properties are locked by [Article I (Fixed Supply)](../governance/constitution.md#article-i--fixed-supply) and [Article II (No Pre-mine, No Developer Tax)](../governance/constitution.md#article-ii--no-pre-mine-no-developer-tax) of the Constitution.

## Parameters

| Parameter | Value | Source |
|---|---|---|
| Target block time | **120 seconds** (2 minutes) | `TARGET_BLOCK_TIME` in `src/constants.rs` |
| Blocks per year | **262,800** | `BLOCKS_PER_YEAR = 365 * 24 * 60 * 60 / 120` |
| Base unit | **1 CYNC = 10¹² atomic units** | `COIN` in `src/constants.rs` |
| Hard supply cap | **250,000,000 CYNC** | `TOTAL_SUPPLY_TARGET` + `MAX_SUPPLY` |
| Tail emission | **1.0 CYNC / block** (perpetual) | `TAIL_EMISSION = 1_000_000_000` atomic |
| Tail starts at | **Year 20** (~height 5,256,000) | `EMISSION_ANCHORS` in `src/constants.rs` |
| Curve type | **Mountain curve** (anchor-point interpolation) | `src/emission/curve.rs::base_reward` |

## The mountain curve

Unlike Bitcoin's step-function halving, CoinCync uses a **mountain curve** — five anchor points with linear interpolation between them. This produces a smooth, monotonically-decreasing reward from the launch phase all the way into the tail.

| Year | Block reward | Cumulative supply (approx) |
|---|---|---|
| 0 (launch) | **143 CYNC / block** | 0 |
| 1 | 143 CYNC / block (flat) | ~37.6 M |
| 5 | 86 CYNC / block | ~157 M |
| 10 | 28 CYNC / block | ~232 M |
| 13 | 7 CYNC / block | ~246 M |
| 15 | ~3 CYNC / block | ~249.5 M (cap approached) |
| 20+ | **1 CYNC / block** (tail) | ~250 M |

After year 20 the reward floors at the **tail emission** of 1 CYNC / block and stays there forever. The 250M cap is reached asymptotically; no issuance beyond it is possible because the [consensus code enforces the cap directly](../governance/constitution.md#article-i--fixed-supply).

```text
Reward
   ↑
143 ●●●● (years 0-1, flat launch)
   │    ●●●
   │       ●●●●
 86│           ● (year 5)
   │            ●●●
   │               ●●●
 28│                  ● (year 10)
   │                   ●●
  7│                     ● (year 13)
  1├──────────────────────────●●●●●●●●●●●●●●●●●→ (year 20+ tail)
   └─────────────────────────────────────────────→
   0                                            height
```

### Why a mountain curve instead of halvings

Halvings create predictable supply shocks — every four years, Bitcoin's block reward drops by 50% in a single block. That causes forced-seller events at hash-power equilibria and strong psychological effects on price discovery. A mountain curve distributes the same total issuance smoothly, removing the cliff edges and giving miners continuous rather than discrete incentive changes.

The **anchor points** (not the interpolation formula) are what the constitution fixes. They're stored as a compile-time constant in `src/constants.rs`:

```rust
pub const EMISSION_ANCHORS: &[(u64, u64)] = &[
    (0,                          143 * COIN),
    (BLOCKS_PER_YEAR,            143 * COIN),
    (BLOCKS_PER_YEAR *  5,        86 * COIN),
    (BLOCKS_PER_YEAR * 10,        28 * COIN),
    (BLOCKS_PER_YEAR * 13,         7 * COIN),
    (BLOCKS_PER_YEAR * 20,  TAIL_EMISSION),
];
```

Changing any of these numbers is a hard fork and a constitutional amendment — not permitted under any circumstances per [Article X](../governance/constitution.md#article-x--immutability).

## Why a tail emission instead of zero

This is one of the load-bearing design decisions.

A blockchain's security budget is the value of the block reward that miners earn. As Bitcoin's reward halves every four years and approaches zero, security is supposed to come from transaction fees alone. But fee markets are notoriously volatile, and a chain whose security depends on a healthy fee market is a chain whose security is hostage to its short-term throughput.

A **fixed tail emission** removes that dependency. After block year 20, there is always a constant 1 CYNC / block flowing to miners regardless of fee market conditions. This:

- Guarantees a baseline security budget forever
- Makes the long-term inflation rate **decreasing but non-zero** (asymptotically approaches 0% as the supply grows, but never reaches it)
- Removes the moral hazard of a "fee market crisis" decades from now where the network has to choose between underpaying miners and mining empty blocks

Monero pioneered this design. Pirate Chain followed suit. Bitcoin notably did not, and has been having the "what happens after the last halving" debate for over a decade.

## Supply cap interaction with the tail

At 1 CYNC / block tail × 262,800 blocks/year = **262,800 CYNC / year** of tail issuance. The mountain curve's 19 years of pre-tail emission puts cumulative supply at roughly **~248–249 million CYNC** by year 20, leaving about 1 M CYNC of headroom before the 250 M cap.

That headroom is consumed by tail emission over the **decades after year 20** until the cap is reached. The exact year varies depending on the pre-tail integration, but the order of magnitude is "hundreds of years of tail emission". Once the cap is hit, the reward is clamped to zero and miners are compensated by fees only — the same endgame Bitcoin faces, but pushed far enough into the future that the question is about generations from now, not decades from now.

Article I of the Constitution locks the cap absolutely. Nothing — no governance vote, no supermajority, no emergency override — can raise it. The `src/constants.rs` compile-time assertion is the mechanical backstop:

```rust
const _: () = assert!(TOTAL_SUPPLY_TARGET == 250_000_000,
    "UNCONSTITUTIONAL: Article I — Supply cap must be exactly 250,000,000 CYNC");
```

## Coinbase outputs

The coinbase transaction in every block is a single output paying `base_reward(height) + collected_fees - burned_fees` to the miner's stealth address. Even the coinbase uses the privacy machinery — the miner's address is a one-time stealth output, not a reusable transparent address. The view key for the miner's wallet recognizes the output; nobody else can.

The miner's address is published in the block header for the explorer to display, but this is a one-time stealth output derived from the miner's static pubkey plus a per-block transaction secret. It is not a re-identifiable wallet address — every miner can only show the world "I mined this block" if they choose to disclose, never "I am the same miner who mined block N − 5" unless they voluntarily link them off-chain.

### Fee burn

CoinCync has an **activity-scaled fee burn** that activates after year 1, independent of the base reward. A percentage of transaction fees is permanently removed from circulation, accelerating the approach to the supply cap during high-activity periods and dampening it during low-activity periods. The burn rate schedule is in `src/constants.rs::BURN_RATE_ANCHORS`, capped at 50% (`MAX_BURN_RATE = 5000` basis points). The miner receives `MINER_SPLIT_PERCENT = 60` of the non-burned fees.

Fee burn does not create coins, it only destroys them — it cannot violate Article I. The cap is a ceiling, and burn can only push the total further below that ceiling.

## Verifying the curve

The block explorer at [explorer.coincync.network](https://explorer.coincync.network) renders the emission curve on its supply panel. The same curve is queryable via JSON-RPC:

```bash
curl -sX POST https://api.coincync.network/rpc \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_supply_info"}' | jq .
```

Returns something like:

```json
{
  "height":         12345,
  "current_reward": 143000000000000,
  "total_emitted":  "1765035000000000000",
  "emission_phase": "Launch"
}
```

Atomic units: 1 CYNC = 10¹² atomic. `143000000000000` atomic = 143 CYNC.

## What can change about emission

Nothing, by design. The emission curve is locked by [Constitution Article I](../governance/constitution.md#article-i--fixed-supply) and [Article X (Immutability)](../governance/constitution.md#article-x--immutability). Changing the initial reward, the anchor points, the tail, the block time, or the supply cap would require:

- A hard fork (the resulting chain is incompatible with the old chain)
- A deliberate constitutional violation (which is prohibited by Article X and mechanically blocked by the compile-time assertions)
- Every operator on the network to deliberately opt in to a chain that is, by definition, no longer CoinCync

There is **no operator key**, **no admin key**, and **no DAO** that can modify the emission. The numbers are baked into `src/constants.rs` and `src/emission/curve.rs` and into every node binary that anyone has ever built. Changing them requires every operator to deliberately upgrade to a new binary and reach social consensus first — and any binary that tries to ship with altered numbers fails the constitutional `assert!`s at compile time.

## Implementation references

- `src/constants.rs::TOTAL_SUPPLY_TARGET`, `MAX_SUPPLY`, `EMISSION_ANCHORS`, `TAIL_EMISSION`, `TARGET_BLOCK_TIME`
- `src/emission/curve.rs::base_reward` — the mountain-curve linear-interpolation function
- `src/emission/curve.rs::emission_phase` — the Launch/Growth/Maturity/Decline/Tail phase classifier
- `src/emission/supply.rs::SupplyState` — tracks cumulative supply and the cap
- `src/mining/template.rs` — coinbase construction

## Next reading

- [Constitution Article I](../governance/constitution.md#article-i--fixed-supply) — the rule that locks the supply cap
- [Consensus & PoW](./consensus.md) — how blocks are produced and validated
- [Transaction format](./transaction-format.md) — what a coinbase output looks like on the wire
