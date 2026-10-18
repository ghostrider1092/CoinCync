# Fee Experience — the invisible, predictable, honest fee

> **Status:** design note / north star. Documents the **already-implemented**
> consensus fee model and sets the **UX + shielded-routing targets** that make it
> *the best fee experience*, not a novel one. The consensus pieces below are live;
> the UX targets are wallet-side and **deferred** behind the chain-finish feature
> freeze + the security audit. Non-consensus except where explicitly flagged.
>
> Positioning: **best, not first** (see `docs/strategy/utility-thesis.md`). The
> win here is not a cleverer fee *mechanism* — it is the fee the user never has to
> think about, and that the chain gets *right every time*. Apple didn't invent a
> new pricing model; they made paying effortless and predictable. That is the gap
> in crypto fees, and it is an execution gap, which is where we win.

## The one-sentence thesis

**A fee should be invisible by default, predictable to the atom, honest about
what it costs and when a tx will land — and identical whether the payment is
transparent or shielded.**

## What is already implemented (consensus)

All in `src/consensus/fee_market.rs` + `src/consensus/validation.rs`,
constants in `src/constants.rs`. These are live rules, not aspirations.

1. **Byte-priced, not gas-metered.** The required fee is
   `size × MIN_FEE_PER_BYTE` (`MIN_FEE_PER_BYTE = 1000` atomic/byte). There is no
   expressive computation to meter, so the fee is a deterministic function of tx
   size — knowable *before* submit, with no estimation guesswork and no
   "failed-tx-still-charged."
2. **Bounded congestion premium (the key anti-spike property).**
   `congestion_multiplier(congestion_pct)` is a capped step on block fullness
   (`size × 100 / MAX_BLOCK_SIZE`):

   | Block fullness | Floor multiplier |
   |---|---|
   | < 50 % | ×1.0 |
   | 50–75 % | ×1.5 |
   | 75–90 % | ×2.0 |
   | ≥ 90 % | **×3.0 — hard ceiling** |

   The premium **can never exceed ×3**. There is no compounding per-block base
   fee and no bidding auction, so a demand surge cannot run the price away.
3. **Miner / burn split, 0 % dev tax.** `distribute_fee(total, congested)` splits
   every fee (enforced from `FEE_DISTRIBUTION_HEIGHT`; before it, the miner claims
   all, for backward compatibility):

   | State | Miner | Burned | Protocol / dev |
   |---|---|---|---|
   | Normal | **70 %** (`FEE_MINER_NORMAL_PERCENT`) | 30 % | **0 %** |
   | Congested (≥ `CONGESTION_THRESHOLD` = 80 % full) | **50 %** | **50 %** | 0 % |

   The burn gives EIP-1559's deflationary / anti-self-dealing benefit **without**
   its runaway base fee — the share is a fixed fraction of a *bounded* floor. The
   burn share *rises* under congestion, removing a miner's incentive to stuff
   blocks to farm fees. `to_protocol` is hard-wired to 0 (Constitution Article II:
   no dev tax).
4. **A pro-only priority knob.** `fee_multiplier` (wallet-side,
   clamped `[1.0, 100.0]`) lets a user pay above the floor for priority. It is an
   escape hatch, **not** the default interaction.
5. **Standardized fee tiers — built, off by default.** `round_up_to_fee_tier`
   (1–2–5 × 10ᵏ ladder) + `standardized_fee` exist and are tested but are **not**
   on the send path (`docs/design/standardized-fee-tiers.md`). Flipping them on
   (audit-gated) trades a tiny overpay for fee-amount uniformity — a privacy win
   (no per-wallet fee fingerprint) *and* a UX win (fees become a short menu of
   clean round numbers).

## Why this structurally avoids Ethereum's gas/congestion failure

ETH's spikes come from three things stacked: gas metering for arbitrary
computation, a hard per-block gas cap that creates an auction cliff, and a
first-price bidding war. CoinCync has **none of the first or third**, and it
**bounds** the second's effect:

- no gas — fees are bytes, deterministic and predictable per tx;
- no auction — a fixed floor × a **capped** (≤ ×3) multiplier, not a bid;
- the burn is a fixed fraction, not a volatile per-block base fee.

Under extreme sustained demand the fee **plateaus at ×3 and excess txs wait**
(backlog), rather than exploding in price. Congestion manifests as *delay*, not
cost — the deliberate, user-friendly trade.

## The "best" targets (wallet-side UX — deferred, non-consensus)

These are the Apple moves. They are **design targets** to build after the chain
is finished and audited (feature freeze), captured here so the north star is on
record. None of them change consensus.

- **No fee knob by default.** The wallet computes the one correct fee and shows
  **no slider**. This is honest, not a hidden hack: the fee is deterministic and
  the premium is capped, so there is genuinely no decision for the user to make.
- **One human line, and an arrival promise the chain keeps.** Show
  `Network fee: 0.0001 CYNC · arrives in ~2 min`, never gwei/atomic/gas. Because
  the premium is bounded and block cadence is known, the time estimate is a
  promise, not a hope.
- **Graceful congestion.** At ≥ 80 % full, the wallet says *"Network busy — still
  ~X min, same fee,"* because the fee cannot spike. The single most stressful
  moment on ETH becomes a calm status line.
- **Zero privacy-tax friction.** A **shielded** send must feel identical to a
  transparent one — same fee line, same arrival promise. Privacy with no UX
  penalty is the whole "best auditable-privacy" claim, made tangible.
- **Boringly uniform fees.** Wire `standardized_fee` (post-audit) so every wallet
  pays one of a handful of clean values.

## Shielded fee routing (IMPLEMENTED — the mechanism; the amount is wallet policy)

A shielded transfer's fee is **miner-paid**, riding the *same* rail as a
transparent fee. The elegant result is that **no new fee market and no
`total_fees` change were needed**:

- the shielded tx sets `value_balance = +F` — an **unshield of exactly the fee**
  `F` across the veil (amounts/sender/recipient stay hidden; only the fee scalar
  is public, exactly as Monero reveals the fee in the clear);
- the transparent value bridge (`verify_transparent_shielded_balance`) already
  forces `tx.fee == value_balance` for a pure transfer (the `(tx.fee −
  value_balance)·H` term must vanish with empty transparent in/out), so `F` lands
  in `tx.fee`;
- `total_fees` is already `Σ tx.fee`, so it picks `F` up with no change;
  `distribute_fee` splits it 70/30 (or 50/50 congested) and the coinbase claims
  the miner share — **identical path and bounded ≤3× congestion curve as
  transparent**;
- **inflation guard** (`chain::verify_block_spark_v2`): `value_balance == `
  `spend_fee(bundle)`, binding the declared fee to what the libspark bundle
  actually released (`spark_ffi_spend_fee`). So `tx.fee == value_balance ==
  bundle fee`, all the same `F`.

**Miner-paid is required, not optional.** The block-level dynamic-fee floor
(`validation.rs`, `fee too low for congestion`) applies to *every* non-coinbase
tx with **no shielded exemption**, so a `tx.fee = 0` shielded transfer fails
block validation (`0 < size·MIN_FEE_PER_BYTE`) — a "free" shielded transfer was
never mineable. Setting `tx.fee = size·MIN_FEE_PER_BYTE` (× the user's optional
priority multiplier) makes it meet the floor at ×1 and ride the congestion curve
like any transparent tx. The mempool bypass (see the admission note) still admits
the shielded *shape* (empty transparent in/out); the block floor is what the fee
satisfies.

**Status:** mechanism implemented + gated (`sketch-gk-proof + libspark-ffi`),
activation stays `u64::MAX` on testnet/mainnet until the external audit (see
`cip-shielded-txtype.md`, `cip-spark-block-format.md`). The wallet computes the
amount as a size-based fee.

### Supply conservation (verified)

A shielded fee `F` on a pure pool→pool transfer conserves supply — no inflation —
by the same accounting as a transparent fee:

| Quantity | Change | Enforced by |
|---|---|---|
| Emission (`total_supply`) | **+base reward only** | `total_supply += calculate_block_reward(h)` = `base_reward`; fees are never emission |
| Pool value | **−F** | `SparkPoolStore::apply_value_balance(+F)`, with `value_balance == bundle fee` |
| Miner coinbase | **+ miner share** (70 % / 50 %) | `max_coinbase = reward + dist.to_miner`, `total_declared == max_coinbase` |
| Burn (`total_burned`) | **+ burn share** (30 % / 50 %) | `block_fee_burn = Σ tx.fee × burn_pct` (sums the shielded `tx.fee`) |

The supply identity `circulating = emitted − burned` holds: `Δemitted = 0`,
`Δcirculating = −F (pool) + miner_share (new UTXO) = −burn_share`,
`Δburned = +burn_share`. The fee the miner claims is exactly the fee removed from
the pool, pinned to one value `F` by three independent checks (`apply_value_
balance`, the `value_balance == bundle_fee` guard, and the `tx.fee ==
value_balance` bridge). The bridge additionally forces `Σ transparent_outputs ==
identity` whenever `tx.fee == value_balance`, so the current model **cannot**
route an unshield-to-a-user's-transparent-output into the miner fee — it is
confined to the safe (pure-transfer) case by construction.

**Honest caveats (audit-relevant):**

1. **Supply reconciliation doesn't check the crypto.** `total_supply ==
   cumulative_emission` catches accounting-path drift, not a libspark bundle that
   *verifies-but-shouldn't* (a bad balance proof inflating coin values is
   invisible to supply accounting — that's the external audit's job, per
   `cip-security-threat-model.md`). The guard trusts libspark's `input = Σ outputs
   + fee` proof; it binds the *declared* fee to the *bundle's* fee.
2. **Supply-commitment enforcement is gated OFF today** (`enforce_height =
   u64::MAX`) — the burn/emission accounting is computed and reconcilable but not
   yet consensus-rejecting. The general pre-audit posture, not shielded-specific.
3. **Unshield-to-a-transparent-user-output isn't built** (the builders only make
   pool coins). When it is, the fee accounting must *separate* the fee from the
   unshielded value — the current `value_balance == bundle_fee` collapses them,
   which is correct only because the bridge forbids transparent outputs here.
   Flag for that future work.

## The honest limit, and the roadmap

- **Hard 2 MiB block cap.** `congestion_pct = size / MAX_BLOCK_SIZE` assumes a
  fixed cap, so extreme sustained demand becomes a **backlog**, not a spike. That
  is usually the better UX, but it caps throughput at ~2 MiB/block. If throughput
  ever becomes the real constraint, **Monero-style elastic block size** (grow
  above the recent median with a reward penalty) is the upgrade that absorbs
  demand by growing blocks instead of queueing. Bigger consensus change —
  **post-audit roadmap**, not now.
- **Security-budget volatility over time** is a separate axis, addressed by the
  draft `docs/design/cip-fee-reservoir.md` (store fee surplus when quiet, release
  it under load). Complementary to this note, not part of it.

## What we deliberately do NOT build (Apple = removal)

No gas token. No fee auction / first-price bidding UI. No "speed up / cancel"
ritual (that exists only because ETH fees are broken). No mempool fee-market
dashboard shoved at the user. The best fee UX is the one the user never has to
engage with.

## Sequencing

1. **Now:** finish the chain → audit (unchanged; see the feature-freeze posture).
2. **At audit:** this fee model (bounded premium + miner/burn split + 0 dev tax)
   is part of the reviewed design; wire the shielded fee routing above as part of
   shielded economics.
3. **Post-audit:** the wallet UX targets; opt-in `standardized_fee`; evaluate
   elastic block size and the fee reservoir if/when demand warrants.
