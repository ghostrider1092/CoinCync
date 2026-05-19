<!-- markdownlint-disable MD036 -->
# CIP-002 — `cynchub`: Merge-Mined Liquidity Layer

**Status:** Sketch (V1 scope defined; not on the v1.1 or v1.2 release path. Reconsider for v1.3+ once cyncswap is mainnet-stable and budget materializes.)
**Type:** Standards Track (new auxiliary chain, optional client feature)
**Created:** 2026-05-05
**Refined:** 2026-05-18 — V1 scope, simplification pass, bridge-risk model, reuse of `coincync-swap` crate
**Status revert:** 2026-05-18 — briefly promoted to Draft earlier today; reverted to Sketch the same day per the Apple-style release discipline. The design work captured here remains valid as a Sketch; the *commitment* to ship CyncHub is deferred until cyncswap (CIP-001) has been mainnet-stable for ≥12 months with zero principal-loss incidents.
**Layer:** Layer 1.5 — auxiliary PoW chain merge-mined with CoinCync, off the consensus path of CYNC itself

---

## Abstract

**`cynchub` is a coordination layer, not a custody layer.**

CyncHub is a separate proof-of-work blockchain, merge-mined with CoinCync at zero extra cost to miners, whose only job is to host an on-chain order book for trustless CYNC↔BTC trades. Every trade happens through swaps on each asset's native chain — CYNC uses the same adaptor-signature primitive shipped in CIP-001, BTC uses standard P2WSH HTLCs identical to Lightning and Bisq. **CyncHub never holds, signs for, or has keys to user funds.** It publishes orders, witnesses matches, and lets users find each other. The cryptography on Bitcoin and CoinCync settles every trade.

If CyncHub goes offline tomorrow, every locked output remains recoverable on its native chain via the refund path. Miners earn fees by witnessing matches, not by controlling capital. There is no federation, no admin key, no governance token, no bridge contract.

This is the **PoW-secured alternative to the federated bridges that have lost users $2.5B in three years** — Wormhole, Ronin, Nomad, Multichain, Harmony, Poly. The same hashrate that secures CoinCync secures the venue where users can trade out to Bitcoin without a custodian.

---

## V1 Scope (locked)

V1 ships **only**:

- CYNC ↔ BTC trading. Other pairs are V2.
- CLOB (price-time priority) matching. No AMM, no liquidity pools.
- HTLCs / adaptor signatures only. No stablecoin smart contracts.
- Transparent order book. No zk-SNARK privacy. Tor-friendly P2P.
- No commit-reveal MEV protection. Documented limitation in V1; V2 adds it.
- Mandatory reference wallet with watchtower default. No expert mode.

What that gives you: **five transaction types, ~10-12 months of new code, one audit scope**. The full multi-asset / AMM / privacy-orderbook ambition lives in §"V2 Roadmap" — out of scope for this CIP's binding spec.

---

## How V1 Works — User Flow

Alice has 1 CYNC, wants ~0.000025 BTC. Bob has 0.000025 BTC, wants 1 CYNC.

```text
1. Alice's wallet picks a random adaptor secret t, computes T = t·G.
2. Alice's wallet builds a CYNC tx with the spend signature bound to T
   via CLSAG adaptor commitment. To outside observers this looks like
   an ordinary stealth-address CYNC payment.
   → Broadcasts on CYNC chain. Confirms after H+16 finality.
3. Alice's wallet posts an Order tx to CyncHub:
   "Sell 1 CYNC for 0.000025 BTC, my lock = [CYNC txid], T = [...],
    refund_pubkey = [...], expires 1h"
4. Bob (watching CyncHub order book) sees Alice's order, accepts.
5. Bob's wallet builds a Bitcoin P2WSH HTLC using the SAME T:
   "0.000025 BTC, spendable by knowing t such that t·G = T,
    refund to Bob after 12h"
   → Broadcasts on Bitcoin. Confirms after 6 blocks.
6. Bob's wallet posts a counter-Order to CyncHub referencing his BTC lock.
7. A CyncHub miner sees both locks confirmed on their native chains
   (validated via embedded SPV light clients). Includes
   Match(Alice.Order, Bob.Order) in the next CyncHub block.
8. Alice's wallet sees the Match. Uses t to complete the Schnorr
   signature claiming Bob's BTC.
   → Alice now has BTC. The secret t is now extractable from Alice's
     signature on Bitcoin.
9. Bob's wallet extracts t from Alice's BTC claim, uses t to complete
   the CLSAG signature spending Alice's CYNC.
   → Bob now has CYNC.
10. Miner who included Match earns 0.1% in CYNC + 0.1% in BTC.
11. Done. CyncHub never held a satoshi.
```

This is structurally identical to the CIP-001 atomic swap protocol — the **only** addition is the orderbook in step 3/6 that lets Alice and Bob find each other instead of pre-negotiating off-chain.

---

## What Breaks at Each Step (Failure Modes)

| Step | Failure | What happens | User loss |
| --- | --- | --- | --- |
| 2–3 | Alice's CYNC tx never confirms | Order ignored by CyncHub | Tx fee only |
| 4 | Nobody takes Alice's order in 1h | Alice's order expires; CYNC lock refunds at 24h | Tx fees only |
| 5–6 | Bob locks BTC then disappears | Both refund (Bob 12h, Alice 24h) on native chains | Tx fees only |
| 7 | All CyncHub miners offline | Both refund on native chains. **CyncHub being dead does not lose funds.** | Tx fees only |
| 8 | Alice offline before claiming | Watchtower broadcasts pre-signed claim. Worst case: Alice refunds CYNC at 24h — gets her CYNC back, gets no BTC. Trade didn't happen, no loss. | None (refund) |
| 9 | Bob offline after Alice claims | Watchtower extracts t from Bitcoin and broadcasts CYNC claim. **This is the only step where principal could be lost** — fixed by mandatory watchtower default in ref wallet. | None with watchtower |

**Worst case for a user is "trade didn't go through, refund happened, I lost tx fees."** Permanent principal loss requires a bug in the cyncswap (CIP-001) primitive — which is being audited regardless — or a bug in the reference wallet.

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│                         CYNCHUB NODE                             │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  cynchub consensus (RandomX PoW, 60s blocks, merge-mined)  │  │
│  │  Order-book state machine + match logic                    │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────┐  ┌────────────────────────────────┐│
│  │  Bitcoin SPV light client│  │  CYNC SPV light client         ││
│  │  (~50 MB initial sync)   │  │  (~10 MB initial sync)         ││
│  └──────────────────────────┘  └────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
                │                                  │
                ▼                                  ▼
        ┌───────────────┐                ┌─────────────────────┐
        │   Bitcoin     │                │     CoinCync        │
        │   (P2WSH      │                │     (CLSAG +        │
        │   HTLCs)      │                │     adaptor sigs)   │
        └───────────────┘                └─────────────────────┘

   CyncHub WITNESSES locks on each chain via SPV proofs and publishes
   the match. It NEVER holds a key to either side's funds.
```

### Reuse of `coincync-swap` (CIP-001 atomic swap crate)

CyncHub V1 does **not** reimplement either side of the swap. It uses the existing `crates/coincync-swap` workspace as a direct dependency:

| File in `crates/coincync-swap/` | Role in CyncHub V1 |
| --- | --- |
| `cync.rs` | CYNC-side lock construction + RPC. Used as-is. |
| `btc.rs` | Bitcoin-side HTLC construction + RPC. Used as-is. |
| `adaptor.rs` | Adaptor-signature primitives. Used as-is. |
| `strict_dleq.rs` | Cross-curve DLEQ proof. Used as-is. |
| `state.rs` | Swap state-file persistence with HMAC. Wallet-side; used as-is. |
| `coordinator.rs` | Peer-to-peer orchestration. Replaced by CyncHub orderbook. |

**Implication:** the audit that clears `coincync-swap` for CIP-001 mainnet clears the same code for CyncHub. CyncHub adds new code only in: (a) the cynchub chain itself, (b) the orderbook/match logic, (c) Bitcoin SPV light client, (d) watchtower service, (e) wallet integration.

---

## Bridge Risk Model

**CyncHub adds no new custody risk on either side.** The Bitcoin leg uses a standard P2WSH HTLC identical to Lightning, Bisq, and Comit (~10 years of production data). The CYNC leg uses the same adaptor-signature primitive as CIP-001 atomic swaps — the audit that clears CIP-001 for mainnet clears the CYNC leg here. CyncHub itself coordinates orders and witnesses matches; it never holds, signs for, or has keys to user funds.

The only ways for a user to lose principal:

1. **Bug in the cyncswap (CIP-001) primitive** — mitigated by the CIP-001 audit, which is a mainnet blocker regardless.
2. **Bug in the reference wallet** — mitigated by test vectors covering every lock/claim/refund path, and by hardware wallet integration where possible.
3. **User loses their own keys** — universal wallet risk, not bridge-specific.

All other failure modes (CyncHub offline, miner offline, counterparty disappears, network partition, deep reorg, censorship attempt) **refund the user on their asset's home chain** because the refund path does not depend on CyncHub being alive. This is the architectural property that makes the bridge non-custodial: refund is enforced by Bitcoin's `nLockTime` and CYNC's adaptor-refund condition, both honored by their respective native consensus.

Compare to a federated bridge, where principal can be lost via:

- Federation key compromise
- Federation collusion
- Smart-contract reentrancy or upgrade exploit
- Governance attack on the bridge token
- Oracle manipulation

**None of those failure modes exist in this design.** There is no federation, no smart contract holding funds, no governance token, no oracle. That's the whole point of the architecture.

---

## Mechanism — Merge-Mining (Namecoin-Style)

A CYNC miner adds an `OP_RETURN`-equivalent output to their coinbase containing:

```text
[4-byte magic: 0x43484342 ("CHCB")] [32-byte CyncHub block hash]
```

When the CYNC block satisfies CYNC's difficulty, the CyncHub block referenced in the commitment is **also** considered "found." Its PoW proof consists of:

- The CYNC block header (which satisfies CYNC's difficulty by construction)
- The Merkle path from the coinbase commitment to the CYNC block's tx Merkle root
- The CyncHub block itself

CyncHub has its own (lower) difficulty target; CYNC's PoW satisfies CyncHub's automatically since CYNC's target is harder.

**Block time:** 60 seconds (matches CYNC; simplest possible — ≤1 CyncHub block per CYNC block).
**Difficulty retarget:** every 144 blocks (≈2.4 hours).
**No new mining algorithm.** Same RandomX hashrate, same hardware, same miners.

**Reference miner support:** `coincync-rig` includes the CyncHub commitment in coinbase by default. Miners who *don't* include it forfeit CyncHub fee revenue — economic incentive to include it.

---

## Mechanism — Transaction Types

CyncHub V1 has **five** transaction types:

### `LockBtc(amount, T, refund_pubkey, timeout, btc_spv_proof)`

References a Bitcoin P2WSH HTLC the user has already broadcast on Bitcoin. `T` is the adaptor "tweak" public point; whoever learns the corresponding secret `t` can complete the Schnorr signature spending the lock. `btc_spv_proof` is a standard Bitcoin Merkle proof showing the lock tx is included in a Bitcoin block ≥6 confirmations deep.

### `LockCync(amount, T, refund_pubkey, timeout, cync_spv_proof)`

References a CYNC stealth-address tx with CLSAG adaptor binding to the same `T`. `cync_spv_proof` shows the tx is included in a CYNC block ≥H+16 (CYNC's finality depth). To an outside observer scanning the CYNC chain, this lock is indistinguishable from any other CYNC payment.

### `Order(side, amount, price, lock_ref, expiry_block)`

Posts an order to the CyncHub orderbook. `lock_ref` is the txid of the `LockBtc` or `LockCync` (and the chain). The order is automatically backed by collateral via the lock — no separate margin posting.

### `Match(order_a, order_b)`

A CyncHub miner observes two compatible orders (bid price ≥ ask price on the same pair) and includes a match in their block. The match transitions both orders from `Open` to `Matched` in CyncHub state and is the signal both wallets watch for to begin the claim sequence on the native chains.

The matching miner earns:

- `0.1% × amount_btc` from the BTC side (claimable via standard Bitcoin payment to miner's BTC address, encoded in the match)
- `0.1% × amount_cync` from the CYNC side (same)

These fees are paid by Alice and Bob respectively as part of constructing their lock txs (the lock amount is `trade_amount + 0.1%`, the extra 0.1% routes to the matching miner's address on settlement). Minimum match fee: 1000 satoshi-equivalent.

### `Cancel(order_id, owner_sig)`

Order placer cancels an open order. Requires a signature from the lock's refund_pubkey. Cancellation does not refund the underlying lock — that happens on the native chain at the lock's timeout. Cancel just removes the order from the orderbook so no future match can attach to it.

### What's NOT a CyncHub tx

**Refunds happen on the native chain**, not as CyncHub txs. If your lock's timeout expires, your wallet (or watchtower) broadcasts a standard CYNC or Bitcoin tx that takes the refund path. CyncHub doesn't track refunds because it doesn't have to — they're enforced by the underlying chain's consensus.

---

## Order Book Model

Price-time priority CLOB per asset pair. For CYNC/BTC:

- **Bids** (orders to buy CYNC for BTC) sorted by price descending, time ascending.
- **Asks** (orders to sell CYNC for BTC) sorted by price ascending, time ascending.
- A match occurs when the best bid ≥ best ask. The matching miner takes the spread (a small extra fee for them) on top of the 0.1% per-side fee.

**Block size:** 100 KB per CyncHub block. At ~200 bytes per order, this is ~500 orders/block — well above plausible V1 throughput.

**Match latency:** orderbook update + match inclusion happens in the next CyncHub block (60s avg). Plus claim/refund on native chains adds ~6 Bitcoin confirmations (60min) before BTC is spendable.

---

## Fees & Miner Incentives

| What | Amount | Paid to |
| --- | --- | --- |
| Match fee (each side) | 0.1% of trade value, in the traded asset | The matching CyncHub miner |
| Minimum match fee | 1000 sat-equivalent | Same |
| CyncHub block subsidy | **Zero** (no native token to inflate) | N/A |
| CyncHub treasury / devfund | **Zero** — constitutional alignment | N/A |
| Cancel fee | Zero | N/A |

The economic model: a CyncHub miner earns the merge-mining "second income stream" promised in the original sketch — for free with respect to their CYNC mining (same hashrate). At meaningful trade volume, the fee revenue grows independent of the CYNC block subsidy curve.

**Bootstrap caveat:** at V1 launch, trade volume is zero. Miners include CyncHub commitments for free (it costs them ~one hash) but earn no fees until orderbook activity grows. This is acceptable because the marginal cost to miners is genuinely near-zero.

---

## Wallet UX

CyncHub trading folds into `coincync-wallet` as a **"Trade"** tab. One wallet, one install, one set of seed phrases.

The trade screen is **one form, zero parameters**:

```text
┌─────────────────────────────────────────────┐
│  TRADE                                      │
│                                             │
│  Sell  [1.0000 CYNC]                        │
│  For   [0.000025 BTC]                       │
│                                             │
│  Network fee (estimated): ~$0.42            │
│  Refund automatic if no match in 24h.       │
│                                             │
│  [   GO  ]                                  │
└─────────────────────────────────────────────┘
```

Wallet handles everything:

- Adaptor secret generation
- Both lock txs (CYNC + BTC)
- Order placement on CyncHub
- Watchtower handoff (claim + refund pre-signed)
- Status display: `Locked → Waiting → Matched → Claimed → Complete` (or `Refunded`)

**No timeout slider.** No "advanced" mode. No "set custom fee." Hard-coded safe defaults. **That is how you keep users from losing money** — by not letting them set parameters they don't understand.

---

## Watchtower Spec

On lock creation, the wallet pre-signs:

- The **claim tx** for the counterparty's lock (with placeholder for the adaptor secret to be filled in once revealed)
- The **refund tx** for its own lock (with `nLockTime`/timeout already set)

Both txs are handed to ≥1 watchtower service. The user can run their own watchtower (lightweight: ~50 MB, just monitors Bitcoin headers and CYNC headers), or use one of the public reference watchtowers run as part of seed-node software.

Watchtowers:

- Broadcast the claim tx the moment the adaptor secret becomes extractable on the counterparty chain
- Broadcast the refund tx the moment the timeout expires (if claim hasn't completed first)
- Charge a small per-swap fee (e.g., 100 sats) — bundled into the lock; user doesn't see it

**Default config:** ref wallet auto-configures with two public watchtowers + offers easy "run your own" option. Two-watchtower default gives meaningful redundancy without requiring the user to operate infrastructure.

---

## Adding Coins Later (V2+)

V1 protocol is asset-agnostic at the consensus layer — each new asset needs one `Lock<COIN>` tx type and one SPV verifier. Old miners ignore unknown lock types (soft fork). The blast radius of any new-coin bug is limited to people trading that specific pair.

### Easy adds (Bitcoin-script-compatible)

Share Bitcoin's P2WSH HTLC code with near-zero changes:

- **Litecoin** (LTC)
- **Dogecoin** (DOGE)
- **Bitcoin Cash** (BCH)

Estimated effort per asset: 1-2 weeks (mostly RPC client + chain-specific testing).

### Medium adds

- **Lightning Network** — submarine swaps; gives instant settlement on the BTC side. ~1 month.
- **Ethereum (ETH)** — needs an HTLC smart contract on Ethereum side (~200 lines Solidity, well-trodden pattern). One-time contract audit. ~2 months.
- **ERC-20 stablecoins (USDT, USDC)** — same contract template as ETH, plus the **explicit user-disclosed risk that the issuer can freeze addresses**. The bridge can't help with that — document it clearly. ~1 month after ETH.

### Hard adds (defer until V3+)

- **Monero (XMR)** — adaptor signatures already exist (the cyncswap technique); requires careful integration. ~2-3 months.
- **Zcash shielded** — research-grade integration. Indefinite defer.

### V2 Roadmap (informative, not normative)

| Year | Additions |
| --- | --- |
| V1 (post-mainnet 6-12 mo) | CYNC↔BTC only |
| V2 (V1 + ~12 mo stable) | LTC, DOGE, BCH (Bitcoin-script siblings) |
| V2.5 | Lightning submarine swaps for instant BTC settlement |
| V3 | Ethereum + curated stablecoin set, each with documented trust model |
| V4 | AMM mode alongside CLOB; commit-reveal MEV protection; multi-asset matches |
| V?? | Privacy-orderbook research (zk-SNARK orders) if/when primitives mature |

---

## Privacy Properties

### CYNC side (preserved)

- `LockCync` is a normal stealth-address output. The CLSAG signature is adaptor-bound to `T`, but adaptor-binding does not change the on-chain appearance of the tx.
- A CYNC chain observer cannot distinguish a CyncHub lock from any other payment.
- Refund + claim transactions are also normal CYNC outputs.

### CyncHub side (transparent by design)

- CyncHub transactions are not privacy-protected. Order placement, matching, and lock-references are visible.
- This is intentional — CyncHub is a coordination layer, like a stock exchange's matching engine.
- A CyncHub observer sees *that* an order exists for "1 CYNC at $200", but **cannot identify the specific CYNC outputs being locked** because the CYNC-side commitments use stealth addresses.
- Users who want stronger privacy on CyncHub itself can post orders via Tor (the CyncHub P2P protocol must be Tor-friendly by default).

This split is consistent with how Bisq operates: the offer book is transparent, but on-chain settlement preserves Bitcoin's privacy properties.

### Privacy regression (consensual)

A user who participates in a CyncHub trade voluntarily reveals: (a) that they are trading, (b) the amount being traded, (c) approximate timing. This is a **consensual** privacy trade-off, not a protocol-level regression. The wallet warns the user before the first trade.

---

## Constitutional Fit

| Constraint | How cynchub satisfies it |
| --- | --- |
| **Article XII — No Admin Authority** | No multisig, no federation, no admin keys. Mined permissionlessly; miners are replaceable. No address has any power over user funds; refund timeouts handle all failure modes. |
| **Article XIII — No External Trust** | CoinCync consensus is unchanged. CyncHub *imports* CYNC state via SPV proofs (one-way: CyncHub validates CYNC), but CYNC does not import CyncHub state. CYNC consensus has no knowledge of CyncHub. |
| **Article XI — No Algorithmic Capture** | CyncHub fees paid in the assets being traded, not in any new token. No pegged token, no rebase, no reflexive supply mechanism. |
| **Article XIV — No Surveillance Layer** | CYNC-side privacy mathematically preserved (adaptor-binding does not change stealth-address output appearance). CyncHub-side transparency is a design choice for coordination, not a metadata leak attack on CYNC. |
| **Article V — RandomX-only** | CyncHub uses CYNC's PoW. Same algorithm, same hashrate pool, same posture. |
| **Article XVI — Permanent Scarcity** | CYNC emission curve unaffected. CyncHub has no native token to inflate. |

A future maintainer who wanted to "improve" CyncHub by adding a federation, governance token, or fee redirect to a treasury would face the same constitutional discipline as CoinCync proper. **The bridge inherits the discipline.**

---

## Security Considerations (V1-Scoped)

1. **Merge-mining hashrate bifurcation.** Miners who don't include CyncHub commitments forfeit CyncHub fee revenue. Reference miner (`coincync-rig`) includes by default. Risk: low.

2. **Bitcoin-side HTLC correctness.** P2WSH HTLC is a standard pattern (Lightning, Bisq, Comit, ~10 years production). Re-use Bitcoin Core's templates verbatim. Risk: low.

3. **CYNC-side primitive correctness.** Identical to CIP-001 atomic swap. Covered by the CIP-001 audit (mainnet blocker). Risk: tied to CIP-001 audit outcome.

4. **CyncHub consensus bugs (match logic, orderbook state machine, fee distribution).** New code, new attack surface. Mitigation: (a) third-party audit before mainnet, (b) bug bounty (~$100k pool), (c) versioned hard-fork mechanism with rollback window for first 6 months. Risk: this is where audit money actually buys you something.

5. **Front-running / MEV.** Miners control match ordering; they can front-run user orders. **V1 explicitly does not mitigate this** — accepted, documented, fixed in V2 via commit-reveal. Risk: present but bounded (miner can only steal the spread on a match; not user principal).

6. **Order-book griefing.** Malicious orders that lock collateral but never match cost the placer their tx fees but hurt liquidity. Mitigation: short order expiry by default (1h); cancel/expiry refunds the locked collateral via native-chain timeout. Risk: low (it costs the attacker money to attack).

7. **Watchtower compromise.** A malicious watchtower could broadcast a refund prematurely (denying the trade) or fail to broadcast a claim (causing the user to miss the window). Mitigation: redundant watchtowers (≥2 in default config); user can always run their own; pre-signed txs limit watchtower power to "broadcast or not" — they can't forge transactions. Risk: low.

8. **Bitcoin SPV light-client correctness.** Embedded in every CyncHub node. Bug here = CyncHub accepts a fabricated Bitcoin lock proof = match against nonexistent lock. Mitigation: re-use a well-tested Rust SPV library (e.g., `bitcoin-spv` or `bitcoincore-rpc` with proof verification); audit. Risk: medium without an audit, low after.

9. **CYNC SPV light-client correctness.** Same as above, but the CYNC light client is mostly the existing `coincync-node` light-mode code. Risk: low (reused).

10. **Chain-reorg interaction.** CyncHub reorg could un-match an order. Mitigation: 6 CyncHub confirmations before either side claims. Bitcoin reorg deeper than 6 = systemic problem for any Bitcoin app, not bridge-specific. CYNC deep reorg below H+16 = consensus failure (covered by H-16 reorg defense). Risk: low.

11. **Privacy disclosure on participation.** Documented; consensual. Wallet warns user. Risk: not a money-loss vector.

12. **Stablecoin issuer freeze.** N/A in V1 (no stablecoins). Becomes a documented risk in V3 when stablecoins are added.

---

## Implementation Plan

Revised V1 timeline reflecting `coincync-swap` reuse:

| Phase | Scope | Estimated Duration |
| --- | --- | --- |
| **0. Spec promotion** | This document promoted from Draft → Final after community review. Resolve open questions: fee economics tuning, watchtower governance. | 1 month |
| **1. CyncHub chain skeleton** | Genesis block, PoW validation, merge-mining commitment, basic block + header types. No matching logic yet. | 2-3 months |
| **2. Orderbook + match logic** | State machine, match transaction, fee distribution. Tested against `coincync-swap` stubs. | 2 months |
| **3. Bitcoin SPV light client integration** | Embed light client; validate `LockBtc` SPV proofs. Reuse a vetted Rust SPV crate. | 1-2 months |
| **4. CYNC SPV light client integration** | Wire to existing `coincync-node` light-mode code. | 2-4 weeks |
| **5. Watchtower service + reference wallet integration** | Watchtower binary; wallet UI "Trade" tab; pre-sign logic. | 2 months |
| **6. End-to-end testnet** | CYNC testnet + Bitcoin signet, full swap loop, regression tests. | 1-2 months |
| **7. Audit + bug bounty** | Third-party audit of CyncHub consensus + Bitcoin SPV integration. Public bounty round. | 2-3 months |

**Total realistic timeline: 10-12 months of focused work**, gated on:

1. CIP-001 atomic swap shipped + audited (clears the CYNC-side primitive)
2. CYNC mainnet running stable for ≥6 months
3. Audit budget committed (~$100-200k)

Phase 0 can begin now (it's documentation work). Phases 1+ are post-mainnet by definition.

---

## Open Questions (Reduced)

1. **Fee economics tuning.** 0.1% per side is the default proposal. Final value should be benchmarked against post-launch volume; CyncHub fees are protocol-level (need a soft fork to change), so default needs to be defensible at both low and high volume.

2. **Watchtower governance.** How are public reference watchtowers governed? Run by seed-node operators? Permissionless registry on CyncHub itself? Trade-off between decentralization and reliability.

3. **Bitcoin SPV library choice.** Which existing Rust crate to embed (`bitcoin-spv`, `bitcoincore-rpc`, custom). Affects audit scope and maintenance burden.

4. **Bootstrap-period miner subsidy.** Some early-CyncHub schemes propose a temporary block subsidy in CYNC to bootstrap miner participation. **V1 proposal: zero subsidy**, on the theory that merge-mining marginal cost is ~zero. Open to revisit if Phase 0 review surfaces issues.

(The seven Open Questions in the original sketch — AMM, native gas, MEV mitigation, stablecoin trust model, privacy orderbook, per-chain reorg, governance — are all resolved by the V1 scope reductions or deferred to V2+.)

---

## Reference Implementations / Existing Art

- **Namecoin** — merge-mining with Bitcoin since 2011. Reference for the merge-mining commitment scheme.
- **Rootstock (RSK)** — merge-mined Bitcoin sidechain, $30M+ TVL. Reference for hash power inheritance; their bridge is currently federated, used here as a what-not-to-do example.
- **Tari** — merge-mining with Monero. Privacy-coin precedent for the exact pattern proposed.
- **Bisq** — peer-to-peer Bitcoin DEX with transparent offer book + on-chain settlement. Reference for the transparent-offer-book + private-settlement split.
- **Comit / Farcaster** — XMR↔BTC atomic swaps. Reference for the adaptor-signature primitives reused (`coincync-swap`).
- **Lightning Network HTLCs** — production reference for P2WSH HTLC patterns.

---

## Comparison to CIP-001

| | CIP-001 (atomic swaps) | CIP-002 V1 (cynchub) |
| --- | --- | --- |
| **Counterparty discovery** | User finds counterparty themselves (Discord, forum, off-chain) | On-chain order book — automatic |
| **Settlement security** | Adaptor signatures + HTLCs, peer-to-peer | **Same primitives** (literally the same crate), plus CyncHub coordination |
| **Bridge custody** | None (peer-to-peer) | None (HTLCs on native chains; CyncHub holds zero) |
| **Liquidity model** | None (find your own counterparty) | On-chain order book with depth |
| **Time to ship** | In progress; ~3-6 months remaining post-2026-05-18 | 10-12 months post-CIP-001 mainnet |
| **Constitutional posture** | Same | Same |
| **Code base** | `crates/coincync-swap` | New crate `crates/cynchub-*`, depends on `coincync-swap` |

**Complementary, not alternatives.** CIP-001 is the rails — trustless P2P swaps for users who already have a counterparty in mind. CIP-002 V1 is the venue — for users who don't, providing price discovery + depth.

---

## Why This Matters

The privacy-coin space has spent a decade routing around the listing problem with custodial instant-swap services (ChangeNOW, FixedFloat, Exolix). These work, but they're trusted intermediaries that can be subpoenaed, hacked, or coerced. **There is no trust-minimized alternative shipped today.**

CyncHub V1 is the minimum viable design for that alternative. Built right, it would be:

- The first PoW-secured cross-chain liquidity layer
- The first trustless privacy-coin-to-Bitcoin venue with on-chain order book
- A reference implementation other privacy coins could plug into for their own pairs
- A genuinely novel positioning play in a space that's increasingly homogenous

The narrative writes itself: *"PoS bridges keep getting hacked because they centralize trust. We secured ours with hashrate. The same hashrate that secures the privacy coin secures the bridge to the open market. No multisig to compromise. No federation to subpoena. No validator set to bribe. Just the math — and the cryptography that's been shipping in production swap protocols for years."*

---

## Changelog

- **2026-05-05** — Sketch created. Captures design space surfaced during pre-mainnet planning.
- **2026-05-18** — Refined to Draft with V1 scope locked: CYNC↔BTC only, CLOB only, HTLCs/adaptor sigs only, reuse of `coincync-swap` crate for both legs. Added Bridge Risk Model, How V1 Works flow, Watchtower spec, V2 roadmap for multi-asset. Implementation timeline revised from 18-24 mo to 10-12 mo reflecting crate reuse. Five open questions resolved; four remain.

---

*This CIP is a Draft. It commits to the V1 scope (CYNC↔BTC) and the architectural property (CyncHub holds no funds) but leaves fee tuning, watchtower governance, SPV library choice, and bootstrap-period miner subsidy for community review before promotion to Final. Article XV's "Spirit and Construction" applies to any future cynchub-specific protocol changes once the chain ships. V2+ multi-asset roadmap is informative, not binding.*
