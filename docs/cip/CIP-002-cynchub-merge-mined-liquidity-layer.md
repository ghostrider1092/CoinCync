<!-- markdownlint-disable MD036 -->
# CIP-002 — `cynchub`: Merge-Mined Liquidity Layer

**Status:** Sketch (pre-Draft — captures the design space; specifics will be refined before promotion to Draft)
**Type:** Standards Track (new auxiliary chain, optional client feature)
**Created:** 2026-05-05
**Layer:** Layer 1.5 — auxiliary PoW chain merge-mined with CoinCync, off the consensus path of CYNC itself

---

## Abstract

`cynchub` is an auxiliary proof-of-work chain, **merge-mined with CoinCync**, that hosts an on-chain order book for trustless cross-chain trading between CYNC, BTC, and stablecoins (USDT/USDC). The chain has no native token beyond a small fee unit; its sole purpose is to coordinate atomic settlement between assets that live on other chains. Miners on cynchub are the same miners on CoinCync — they get a second income stream from execution fees without splitting their hashrate. Users get price discovery, an order book with depth, and atomic peer-to-peer settlement secured by hash-time-locked contracts (HTLCs). No multisig, no federation, no admin authority, no protocol-level yield.

This is the **PoW-secured alternative to PoS bridges** — closing the listing-independence gap for privacy coins through a venue that no regulator can shut down by serving a subpoena to a federation, because no federation exists.

---

## Motivation

CIP-001 (atomic swaps) gives every CYNC holder a peer-to-peer settlement primitive: trustless CYNC↔BTC trades. But atomic swaps require *finding a counterparty* off-chain. For users who don't already know someone holding the other side of the trade, the experience is bad: post an offer somewhere, wait, hope.

Centralized exchanges solve the price-discovery problem with order books, but they're trusted custodians and they refuse to list mandatory-privacy coins under regulatory pressure. **There is no production system that combines (a) on-chain order book, (b) trustless settlement, (c) PoW-secured coordination, (d) privacy-coin compatibility.** Every existing bridge is PoS-secured by a multisig or bonded validator set, both of which are constitutionally incompatible with CoinCync's posture and have lost users hundreds of millions of dollars to compromise (Wormhole, Ronin, Nomad, Multichain).

`cynchub` fills this gap. The merge-mining foundation gives it Bitcoin-grade security from block 1, no cold-start vulnerability. The HTLC settlement model means no party — including miners — ever takes custody of user funds. The constitutional discipline that protects CoinCync proper extends naturally to cynchub: no admin keys, no governance tokens, no fee redirects.

The narrative that lands publicly: *"Privacy money that doesn't depend on permission to participate. CYNC↔BTC atomic swaps are a constitutional mainnet-launch commitment, not a roadmap item to be deferred. Whether this combination works is what testnet and mainnet are for."*

---

## Status & Implementation

This CIP is a **sketch**. No implementation work has begun. The design captured here defines the problem, the proposed mechanism, and the constitutional/security constraints. Specifics that will be refined before promotion to Draft:

- Exact PoW merge-mining commitment scheme (Namecoin-style auxiliary header vs. Rootstock-style coinbase commitment)
- Order-book data structure on-chain (CLOB vs. AMM vs. hybrid)
- Bitcoin-side HTLC layout (P2WSH vs. Taproot vs. Lightning channels)
- Stablecoin-side integration (Ethereum L1 vs. L2 vs. defer to wrapped variants)
- Fee-unit token economics (minimal native gas vs. fee-paying-in-traded-assets)

**Mainnet launch blocker?** No. cynchub is post-CYNC-mainnet work. The realistic earliest start is 12-18 months after CYNC mainnet ships, after CIP-001 atomic swaps are live and the team has operational maturity.

---

## Components

The system has four moving parts:

```text
┌─────────────────┐         merge-mined          ┌─────────────────┐
│   CoinCync      │  ◀─────────────────────────▶  │   cynchub       │
│   (RandomX PoW, │   same hashrate, two chains   │   (RandomX PoW, │
│   private txs)  │                               │   transparent)  │
└────────┬────────┘                               └────────┬────────┘
         │                                                  │
         │  HTLC commitments                                │  HTLC commitments
         │  (CYNC outputs locked                            │  (BTC + USDT locks
         │   for atomic settlement)                         │   referenced via
         │                                                  │   header proofs)
         ▼                                                  ▼
┌─────────────────┐                               ┌─────────────────┐
│   Bitcoin       │                               │   Ethereum /    │
│   (BTC HTLCs    │                               │   Tron / etc.   │
│   via P2WSH)    │                               │   (USDT/USDC    │
└─────────────────┘                               │   HTLCs)        │
                                                   └─────────────────┘
```

| Component | Role |
|---|---|
| **CoinCync** | The privacy chain. Provides one side of every trade. Privacy preserved at the consensus level. |
| **Bitcoin** | The regulated-fiat anchor. Where USD/EUR liquidity actually lives via instant-swap services and major exchanges. |
| **`cynchub`** | The auxiliary chain. Sequences orders, validates matches, ensures atomic settlement. **Holds no funds.** |
| **Stablecoin chains** | Optional second/third side of multi-leg trades. USDT on Ethereum, USDC on Solana, etc. |
| **Miners** | The CYNC mining set. Merge-mine cynchub for free. Earn block subsidy + execution fees. |

---

## Mechanism — Merge-Mining

A miner produces a single PoW solution that satisfies CYNC's difficulty. If the same block also contains a cynchub Merkle root committed in a known location (typically the coinbase transaction), it counts as a cynchub block too.

**Why this works:** the miner's hashrate is a property of their hardware, not a property of which chain they're "trying" to mine. The same hashrate naturally satisfies both chains' security requirements.

**Why this matters:** a brand-new chain has zero hashrate and is trivially 51%-attacked on day 1. A merge-mined chain inherits its parent's hashrate from block 1. cynchub launches with the full security budget of CoinCync, no cold-start vulnerability.

**Precedents:**
- **Namecoin** — merge-mined with Bitcoin since 2011. The original implementation, ~14 years of production data.
- **Rootstock (RSK)** — merge-mined with Bitcoin since 2018. Currently $30M+ TVL. Actively maintained.
- **Tari** — merge-mined with Monero since 2023. Privacy-coin precedent for the exact pattern we propose.

The mechanism is well-understood. cynchub doesn't need to invent anything here.

---

## Mechanism — On-Chain Order Book

cynchub blocks contain six transaction types:

### 1. `LockCync(amount, htlc_secret_hash, refund_pubkey, timeout_blocks)`

A CYNC user locks their CYNC into an HTLC commitment. The lock can be spent two ways:
- By revealing the secret whose hash is `htlc_secret_hash` (success path)
- By the holder of `refund_pubkey` after `timeout_blocks` (refund path)

The lock is a normal CYNC transaction with the HTLC condition encoded in the output's spend key derivation (similar to Monero's atomic-swap construction). cynchub references this CYNC transaction by including a CYNC block-header proof + the txid.

### 2. `LockBtc(amount, htlc_secret_hash, refund_pubkey, timeout_blocks)`

Same structure, on Bitcoin. The lock is a P2WSH (or future P2TR) HTLC. cynchub references it via Bitcoin SPV proof.

### 3. `LockStable(amount, chain_id, htlc_secret_hash, refund_pubkey, timeout_blocks)`

Stablecoin-side lock. For Ethereum-based stablecoins (USDT, USDC), this requires a small Ethereum-side smart contract that handles the HTLC. cynchub references via Ethereum SPV proof or via a third-party light-client bridge (this is the messiest leg; defer specifics to Draft).

### 4. `Order(side, asset_pair, amount, price, lock_ref, expiry_block)`

Place a buy or sell order. The order references a `lock_ref` (one of the Lock* transactions above), so the order is automatically backed by collateral.

### 5. `Match(order_a, order_b, miner_fee)`

A cynchub miner observes two compatible orders and includes the match in a block. The match transaction reveals the secret(s) in both directions, atomically unlocking both sides' Lock* transactions to their new owners.

### 6. `Cancel(order_id)` / refund timeouts

If an order doesn't match before its expiry block, the user can broadcast a refund transaction on the asset's native chain. The HTLC's refund path activates after the `timeout_blocks` parameter elapses on that asset's chain.

**Critical invariant:** at no point does any cynchub party — including miners — hold custody of user funds. Funds always live in HTLCs on their native chains. cynchub coordinates; cryptography settles.

---

## Mechanism — Concrete User Flow

Alice has 1 CYNC, wants $200 USDT. Bob has $200 USDT, wants 1 CYNC.

```text
Alice                                    cynchub                                 Bob
─────                                    ───────                                 ───
1. Pick secret S, hash to H.
   Lock 1 CYNC on CYNC chain
   with HTLC condition: spendable
   by hash-preimage of H, refund
   to Alice after 24h.
                              ────▶  observes via header watch  ◀────

2. Post Order(side=Sell, pair=CYNC/USDT,
   amount=1, price=$200, lock_ref=...)

                                    Bob has been waiting; sees Alice's order.
                                    Locks $200 USDT with same H, 12h refund timeout.
                              ────────────────────────────────────▶

3.                                    Miner observes both locks confirmed.
                                    Includes Match(Alice.Order, Bob.Order)
                                    in a cynchub block. Match reveals S.

4. See S revealed on cynchub.       ────────────────────────▶  See S revealed.
   Use S to unlock Bob's USDT lock,                            Use S to unlock Alice's
   sending $200 USDT to Alice.                                 CYNC lock, claiming 1 CYNC.

   Alice now has $200 USDT.                                    Bob now has 1 CYNC.

   Miner earns ~0.3% fee from the trade ($0.60 in this example).
   No party held the other's funds at any point.
```

**Timeout asymmetry** is the same as in CIP-001: BTC/USDT side timeouts are *shorter* than CYNC side, so refund safety holds even under network partition.

---

## Privacy Properties

### CYNC side (preserved)

- LockCync uses a one-time stealth address, identical to a normal CYNC payment
- Refund + claim transactions are also normal CYNC outputs
- From outside the swap participants, a CYNC chain observer cannot distinguish a swap from any other transaction
- No cynchub-specific metadata is written to the CYNC chain

### cynchub side (transparent by design)

- cynchub transactions are not privacy-protected. Order placement, matching, and HTLC references are visible.
- This is intentional — cynchub is a coordination layer, like a stock exchange's matching engine.
- A cynchub observer can see *that* an order exists for `1 CYNC` at `$200`, but cannot identify the specific CYNC outputs being locked because the CYNC-side commitments use stealth addresses.
- Users who want stronger privacy on the cynchub layer can post orders via Tor (the cynchub network protocol should be Tor-friendly by default).

This split is consistent with how Bisq operates: the offer book is transparent, but the on-chain settlement preserves Bitcoin's privacy properties.

---

## Constitutional Fit

| Constraint | How cynchub satisfies it |
|---|---|
| **Article XII — No Admin Authority** | No multisig, no federation, no admin keys. The chain is mined permissionlessly. Miners can be replaced by any new entrant with hashrate. No address has any power over user funds; refund timeouts handle all failure modes. |
| **Article XIII — No External Trust** | CoinCync's consensus is unchanged. cynchub *imports* CYNC state via header proofs (one-way: cynchub validates CYNC), but CYNC does not import cynchub state. CYNC consensus has no knowledge of cynchub. |
| **Article XI — No Algorithmic Capture** | cynchub fees are paid in the assets being traded, not in any new token. No pegged token, no rebase, no reflexive supply mechanism. |
| **Article XIV — No Surveillance Layer** | CYNC-side privacy is mathematically preserved. cynchub-side transparency is a design choice for coordination, not a metadata leak attack on CYNC. |
| **Article V — RandomX-only** | cynchub uses CYNC's PoW. Same algorithm, same hashrate pool, same constitutional posture. |
| **Article XVI — Permanent Scarcity** | CYNC's emission curve is unaffected. cynchub fee economy is separate. |

A future maintainer who wanted to "improve" cynchub by adding a federation, a governance token, or a fee redirect to a treasury would hit the same compile-time guards we already have on CoinCync. **The bridge inherits the discipline.**

---

## Security Considerations

1. **Merge-mining hashrate bifurcation.** If miners ever choose to NOT include the cynchub Merkle root in their CYNC blocks, cynchub stalls. Mitigation: include cynchub commitment by default in all reference miner software (`coincync-rig`); make the cost of *not* including it (forgone fees) higher than the cost of including it (one extra hash).

2. **Bitcoin-side HTLC implementation.** P2WSH HTLCs are mature; P2TR HTLCs add efficiency but require BIP-340 deployment. Use whichever is available at implementation time; fall back gracefully.

3. **Stablecoin-side integration.** This is the messiest leg. Ethereum-side smart contract introduces Ethereum-side risk (consensus changes, MEV). Mitigation: support stablecoins via *trusted* bridge variants initially (USDT.t-style wrapped tokens on a privacy-friendly chain), graduate to fully-trustless stablecoin bridging when the underlying chain primitives mature. Document the trust model explicitly per stablecoin variant supported.

4. **Order-book griefing.** Malicious orders that lock collateral but never match (waiting for refund) cost the placer their refund-tx fee but hurt orderbook liquidity. Mitigation: short order expiry by default (1-3 hours); cynchub fee model that rewards *matched* orders, not posted orders.

5. **Front-running and MEV.** Miners control order matching, so they can front-run user orders. Mitigation: commit-reveal scheme for orders (placer commits hash, reveals later — miner can't peek); future research direction.

6. **Chain reorg interaction.** A cynchub reorg could un-match an order after both sides revealed secrets. Mitigation: require N cynchub confirmations before either side claims (similar to Bitcoin's 6-conf rule); document the wait time per asset pair.

7. **Cross-chain header validity.** cynchub validates incoming header proofs from CYNC, BTC, and stablecoin chains. A malicious user could submit an invalid header hoping cynchub miners include their order anyway. Mitigation: cynchub miners run lightweight clients for each supported chain; reject orders referencing invalid headers.

8. **Privacy regression.** A user who locks CYNC into cynchub voluntarily reveals (a) that they're trading, (b) the amount being traded. This is a *consensual* privacy trade-off, not a protocol-level regression. Document clearly so users understand what they're disclosing when they use cynchub.

---

## Implementation Plan

Realistic timeline: 12-24 months of focused work post-CYNC-mainnet, plus security review. This is a Phase 2 product.

| Phase | Scope | Estimated Duration |
|---|---|---|
| **0. Spec refinement** | Promote this CIP from Sketch → Draft. Resolve open questions on PoW commitment scheme, order-book model, fee economics. | 2-3 months |
| **1. cynchub chain skeleton** | Genesis block, PoW validation, merge-mining commitment, basic block structure. No matching logic yet. | 3-4 months |
| **2. CYNC-side HTLC integration** | Lock/refund txs on CYNC chain. cynchub validates CYNC headers. Single-asset HTLC tests. | 2-3 months |
| **3. BTC-side HTLC integration** | P2WSH (and P2TR if available) HTLCs. cynchub validates BTC headers. CYNC↔BTC swaps end-to-end. | 3-4 months |
| **4. On-chain order book** | Match logic, fee distribution, order expiry, refund handling. CLOB-first; AMM as future variant. | 3-4 months |
| **5. Stablecoin-side integration** | USDT/USDC support via Ethereum-side contract or wrapped variant. Trust model documented per stablecoin. | 3-4 months |
| **6. Audit + bug bounty** | Third-party cryptographic + chain-state-machine review. Public bounty round. | 2-3 months |
| **7. Reference miner integration** | `coincync-rig` updated to include cynchub commitment by default. Reference order-book wallet. | 2 months |

**Total realistic timeline: 18-24 months from mainnet.** Aggressive estimate: 12 months. Conservative: 30 months.

---

## Open Questions

1. **Matching algorithm.** CLOB (price-time priority, miners match) vs. AMM (constant-product, no matching needed) vs. hybrid (CLOB for liquid pairs, AMM for the long tail). Each has different miner-economics implications.

2. **Fee unit.** Should cynchub have a tiny native gas token (paid in CYNC?), or should fees be paid in the traded assets? Native gas is simpler implementation; in-asset fees avoid a new economic primitive.

3. **MEV mitigation.** How aggressively to design against miner front-running. Threshold encryption? Commit-reveal? Verifiable delay functions? Each adds latency.

4. **Stablecoin trust model.** Ship trustless from day 1 (slow, hard) vs. ship with documented-trusted bridging (faster, but partial defeat of the constitutional ideal).

5. **Order-book privacy.** Is a transparent on-chain order book OK, or do we need a private one (zk-SNARK-based)? The latter is research-grade; the former matches Bisq's posture.

6. **Cross-chain reorg handling.** What happens if BTC reorgs and the locked output disappears? Confirmation-count requirements per chain need to be calibrated.

7. **Governance for cynchub.** If cynchub itself is constitutionally bound (Article XV "Spirit and Construction"), what does its CIP process look like? Inherits CoinCync's, or has its own?

---

## Reference Implementations / Existing Art

- **Namecoin** — merge-mining with Bitcoin since 2011. Reference for the merge-mining commitment scheme.
- **Rootstock (RSK)** — production merge-mined Bitcoin sidechain with $30M+ TVL. Reference for hash power inheritance + bridge mechanics (their bridge is currently federated, not fully trustless — useful as a what-not-to-do example for our purposes).
- **Tari** — merge-mining with Monero. Privacy-coin precedent for our exact pattern.
- **Drivechains (BIP-300)** — Paul Sztorc's proposal for Bitcoin-miner-secured sidechains. Different mechanism (miners *vote* on peg-out via blind merge-mining), but shares the "miners are the bridge security" ethos.
- **Bisq** — peer-to-peer Bitcoin DEX with transparent offer book + multisig settlement. Reference for the transparent-offer-book + private-settlement split.
- **Comit / Farcaster** — XMR↔BTC atomic swaps. Reference for the HTLC + adaptor signature primitives we'd reuse.

---

## Comparison to CIP-001

| | CIP-001 (atomic swaps) | CIP-002 (cynchub) |
|---|---|---|
| **Counterparty discovery** | User finds it themselves (Discord, forum, off-chain) | On-chain order book — automatic |
| **Settlement security** | Adaptor signatures + HTLCs, peer-to-peer | Same primitives + cynchub coordination |
| **Bridge custody** | None (peer-to-peer) | None (HTLCs on native chains) |
| **Liquidity model** | None (you find your own counterparty) | On-chain order book with depth |
| **Time to ship** | 6-12 months post-skeleton | 18-24 months post-CIP-001 |
| **Constitutional posture** | Same | Same |

**They are complementary, not alternatives.** CIP-001 is the rails — trustless P2P swaps for users who already have a counterparty in mind. CIP-002 is the venue — for users who don't, providing price discovery + depth.

---

## Why This Matters

The privacy-coin space has spent a decade routing around the listing problem with custodial instant-swap services (ChangeNOW, FixedFloat, Exolix). These work, but they're trusted intermediaries that can be subpoenaed, hacked, or coerced. **There is no trust-minimized alternative shipped today.**

cynchub is the design for that alternative. Built right, it would be:

- The first PoW-secured cross-chain liquidity layer
- The first trustless privacy-coin-to-fiat-anchor venue
- A reference implementation other privacy coins (Monero, Pirate, Firo) could plug into
- A genuinely novel positioning play in a space that's increasingly homogenous

The narrative writes itself: *"PoS bridges keep getting hacked because they centralize trust. We secured ours with hashrate. The same hashrate that secures the privacy coin secures the bridge to the open market. No multisig to compromise. No federation to subpoena. No validator set to bribe. Just the math."*

---

## Changelog

- **2026-05-05** — Sketch created. Captures design space surfaced during pre-mainnet planning. Will refine to Draft when implementation budget materializes.

---

*This CIP is a sketch. It has no commitment beyond the design space it captures. Promotion to Draft requires resolving the open questions above and a clear implementation budget. Article XV's "Spirit and Construction" applies to any future cynchub-specific protocol changes once the chain ships.*
