<!-- markdownlint-disable MD036 MD013 -->
# CoinCync Public Roadmap

**Discipline:** one headline feature per release, polished to "really good" before ship. Apple-style — see [docs/decisions/2026-05-18-cyncswap-path.md](decisions/2026-05-18-cyncswap-path.md) for the underlying philosophy. **This document lists only the next three releases.** Anything past v1.3 is research, not roadmap.

**Last updated:** 2026-05-20

---

## Release rules

1. **One headline per release.** Each release has *one* identity. Supporting work happens, but there is one thing the release is about.
2. **Cut ruthlessly before launch.** A feature that isn't ready slips to the next release — it does not ship half-baked.
3. **Quality bar is "would you let your mom use it without supervision?"** Specific shippable-bar criteria per release listed below. Every criterion must be met; no partial-credit shipping.
4. **No new commitments past v1.3.** Anything beyond is in [docs/cip/](cip/) as Sketch or Draft — design work, not commitments. Promotion to a release happens here, when the prior release ships.
5. **Slip the release, never the bar.** If a criterion isn't met by the target month, the release slips. The criteria do not relax to make the date.

---

## v1.0 — Base chain mainnet (testnet live; mainnet next)

**Status:** Testnet shipped and live. Mainnet ship is the next release.
**Date:** Testnet went live 2026-04-30, currently running 5 Vultr-hosted nodes (per `project_vultr_fleet`). Mainnet target: October 1, 2026.

**Headline:** Privacy money chain — mine, send, receive, mainnet-grade. **No cyncswap; no shielded pool.** The base chain ships first, novel cryptographic features ship after each clears its own audit. Same pattern Monero used: chain first (2014), Bulletproofs and CLSAG and other novel crypto later, behind their own audits.

**What v1.0 mainnet contains:**

- 7 privacy innovations (decoy defense, encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead man's switch, auto-churn)
- FROST M-of-N multisig (per CIP-008)
- 6-layer reorg defense (CIP-009) + miner-signed rolling checkpoints (CIP-009.D, feature-gated)
- 46-feature blockchain explorer
- `coincync-node` + `coincync-wallet` reference implementations
- RandomX CPU mining
- Send / receive / history / addresses / mining / multi-sig in the desktop wallet
- Hardened P2P (jitter + size normalisation + constant-rate cover traffic)
- Reproducible Docker builds, multi-maintainer signed-release infrastructure

**What v1.0 mainnet does NOT contain** (intentionally cut, deferred to later releases):

- **Atomic swaps (cyncswap) — v1.1**, after dedicated cyncswap-only audit
- Shielded pool (Orchard / Phase-2) — v1.2 earliest, scope under review
- On-chain orderbook (CyncHub) — v1.3 earliest, conditional
- Stablecoin support — never, by constitutional design
- Federation, governance token, admin authority — never, by constitutional design

**Why the base chain ships without cyncswap:**

Cyncswap is the largest novel-cryptography component in the codebase: Schnorr adaptor signatures (BIP-340 + Ristretto255), strict-binding Noether 2018 cross-curve DLEQ, joint-key CLSAG for the CYNC side, two transports (Noise XX, SOCKS5/Tor). It is the right size for its own focused audit — and a 3-6 month audit on cyncswap would block the base-chain mainnet by 3-6 months for code that the chain itself does not depend on. Decoupling the two lets v1.0 ship to mainnet on schedule and lets the cyncswap audit start from a frozen tag rather than a moving target. See [decisions/2026-05-20-staged-mainnet-and-cyncswap.md](decisions/2026-05-20-staged-mainnet-and-cyncswap.md) for the full rationale.

**Shippable bar for v1.0 mainnet (all must be met before tag):**

| Criterion | Threshold |
| --- | --- |
| Consensus tests | Full suite green on current tip |
| Testnet soak | ≥ 60 days uninterrupted operation of the 5-node fleet with no consensus split |
| Audit | Base-chain audit cleared, report public at `coincync.org/security` |
| Reorg defense | CIP-009 layers 1-3 active in production; CIP-009.D feature-gated and exercised on testnet |
| Reproducible build | Byte-identical binary from Docker on the documented host arch |
| Wallet | Desktop wallet ships base-chain features only (no Trade tab) |
| Genesis ceremony | Mainnet seeds + initial checkpoint set + monitoring live ≥ 7 days pre-genesis |
| Docs | Operator guide + node-runner guide + wallet user guide reviewed by ≥ 3 non-dev users |

If any criterion is not met by the target month, **v1.0 mainnet slips**. The criteria do not relax.

---

## v1.1 — cyncswap (post-mainnet, post-audit)

**Headline:** Trustless CYNC↔BTC atomic swaps with the 6-layer user-safety stack. **Ships after v1.0 mainnet is stable** and cyncswap has cleared its own dedicated audit.
**Target:** 3-6 months after v1.0 mainnet (currently estimated Q1-Q2 2027; specific month locked when the cyncswap audit is scheduled).
**Status:** ~95% implemented (346 tests pass with `--features strict-dleq`), audit prep complete at [docs/cyncswap-audit-prep.md](cyncswap-audit-prep.md). Audit outreach to Cypher Stack / OSTIF / Teserakt pending NLnet grant outcome.

**Why this is the v1.1 headline:**

Once cyncswap ships, every Bitcoin holder is one transaction away from holding CYNC trustlessly. Liquidity stops depending on centralized exchange listings — the listing-independence design that compensates for CYNC's expected CEX delisting trajectory. This is the strategically load-bearing feature of v1.x, and it deserves its own audit cycle separate from the base chain.

**What's in scope:**

- [CIP-001](cip/CIP-001-atomic-swap.md) — the cyncswap protocol itself, adaptor-sig design (per the [path decision](decisions/2026-05-18-cyncswap-path.md))
- [`crates/coincync-swap/`](../crates/coincync-swap/) — the implementation
- The 6-layer user safety stack per [docs/cyncswap-user-safety.md](cyncswap-user-safety.md):
  1. $500 per-swap cap (compile-time const)
  2. Mandatory ≥1 watchtower default
  3. Refund-by-default + type-state pre-flight verification
  4. Wallet-side circuit breakers + signed kill-switch advisory
  5. Triple-backup state (local + paper); cloud deferred to v1.2
  6. Two independent audits + $100k bug bounty + slow-rollout cap ramp
- Wallet "Trade" tab — minimum-viable form (one screen, zero parameters)
- Reference watchtower service (2 dev-team-run instances; community registry deferred to v1.2)
- Bitcoin SPV light-client integration in the wallet (deferred from CyncHub — actually needed in v1.1 for the wallet to verify Bitcoin-side locks without RPC dependency)

**What's explicitly cut from v1.1:**

- Cloud backup leg of the triple-backup → v1.2
- Public watchtower registry → v1.2 (community needs to exist first)
- USD-denomination cap oracle → v1.2 (V1 ships sats-denominated; tuning later)
- Kill-switch advisory feed → v1.2 (V1 ships with the cap + slow-rollout as primary safety)
- Multi-coin pairs (LTC, DOGE, BCH, ETH, USDT) → never in cyncswap; that's CyncHub V2+ scope
- AMM matching → never in cyncswap
- Expert mode / parameter sliders → never in cyncswap
- CyncHub orderbook layer → v1.3 earliest

**Shippable bar (all must be met before ship):**

| Criterion | Threshold |
| --- | --- |
| Tests | 346/346 pass (currently 288/346) |
| Audits | 2 independent firms cleared, full reports public at `coincync.org/security` |
| Real swaps | ≥ 50 end-to-end on testnet by independent users |
| Watchtower | ≥ 30 days stable operation of the 2 reference instances |
| Critical bugs | Zero open |
| Docs | Wallet user guide + recovery guide + safety doc complete + reviewed by ≥ 3 non-dev users |
| Bug bounty | Active + funded ≥ $100k |
| Wallet UX | First-swap-success rate ≥ 95% in user testing (≥ 10 users) |

If any of the 8 above is not met by the target month, **v1.1 slips**. The criteria do not relax.

**Open decisions for v1.1:**

- Cap denomination (USD-via-oracle vs sats) — current proposal: sats for V1
- Bounty pool funding source — dev allocation, crowdfunding, NLnet grant
- CIP-013 (Orchard shielded pool) is now explicitly **not** part of v1.1 — it ships in its own v1.x release after its own audit (same staged pattern). One headline per release.

---

## v1.2 — wallet polish + safety stack v2

**Headline:** Refine the wallet experience based on v1.1 user data; add the remaining safety-stack layers that were cut from v1.1.
**Target:** 3 months after v1.1 ships.
**Status:** Planned. No code yet.

**Why this is the v1.2 headline:**

Apple ships polish releases. iPhone 3GS was "the S is for speed" — same features, refined. v1.2 is coincync's polish release: respond to what v1.1 users actually complain about, add the safety layers we cut to make v1.1 ship on time, and iterate the wallet UX until first-swap-success-rate is ≥ 98%.

**What's in scope:**

- Cloud backup leg of triple-backup (user-chosen provider — Dropbox, iCloud, custom WebDAV)
- Public watchtower registry (community can register; wallet picks 2 by default)
- USD-denomination cap oracle (cap stays at $500 USD-equivalent regardless of BTC price)
- Signed kill-switch advisory feed
- Wallet "Trade" tab v2 — fixes whatever v1.1 users complained about
- Cap ramp eligibility evaluation: $500 → $5,000 if zero incidents in v1.1

**What's explicitly cut from v1.2:**

- CyncHub — still v1.3 earliest
- Multi-coin in cyncswap — never; that's CyncHub V2 scope
- New protocol features of any kind — v1.2 is about refining what ships in v1.1

**Shippable bar:**

| Criterion | Threshold |
| --- | --- |
| v1.1 stability | Zero principal-loss incidents in v1.1 launch period |
| Cloud backup | End-to-end tested, recovery from cloud works without local file |
| Watchtower registry | ≥ 5 community watchtowers operating ≥ 14 days stable |
| Cap oracle | Median of ≥ 3 reputable price feeds; cap-enforcement test passes under price-divergence scenarios |
| Wallet UX | First-swap-success rate ≥ 98% in user testing |
| Docs | v1.1 user feedback addressed in updated guides |

---

## v1.3 — CyncHub V1 (CYNC↔BTC orderbook only)

**Headline:** On-chain order book for trustless CYNC↔BTC trades — users no longer need to find counterparties off-chain.
**Target:** 12 months after v1.1 ships (i.e. ~9 months after v1.2).
**Status:** Sketched at [CIP-002](cip/CIP-002-cynchub-merge-mined-liquidity-layer.md). **Not committed.** Promotion to Draft requires the v1.3 entry-criteria below to be met.

**Why this is the v1.3 headline:**

cyncswap (v1.1) gives users trustless atomic swaps but requires off-chain counterparty discovery. CyncHub adds the orderbook layer — the marketplace where users find each other. CyncHub V1 is intentionally restricted to CYNC↔BTC only (matching v1.1's pair) to keep the audit + implementation surface contained.

**Entry criteria — these must hold before v1.3 promotes from Sketch to Draft:**

1. cyncswap (v1.1) shipped to mainnet
2. cyncswap stable for ≥ 12 months with zero verified principal-loss incidents
3. Cap ramp reached ≥ $25k per-swap (Layer 1 of safety stack, period 3) — implies operational maturity
4. Audit budget for the CyncHub-specific scope (~$60-100k) committed
5. Solo-dev capacity exists for a 10-12 month build (or additional contributors)

**If any entry criterion fails, v1.3 is replaced with a different headline** (e.g. a privacy-innovation polish release, or a multi-region testnet expansion, or v1.3 simply doesn't happen and v1.x effort goes to operations).

**What's in scope (when v1.3 lands):**

- CyncHub L1.5 chain (60s blocks, RandomX merge-mined with CYNC)
- Five-tx-type protocol per [CIP-002 §"Mechanism — Transaction Types"](cip/CIP-002-cynchub-merge-mined-liquidity-layer.md): `LockBtc`, `LockCync`, `Order`, `Match`, `Cancel`
- CLOB matching, price-time priority
- Wallet "Trade" tab — extended with orderbook view (not just point-to-point swap)

**What's explicitly cut from v1.3:**

- Multi-coin pairs (LTC, DOGE, BCH, Lightning, ETH, USDT) — V2+ of CyncHub, separate release decision
- AMM matching — V4 of CyncHub if ever
- Commit-reveal MEV protection — V2 of CyncHub
- Stablecoin support — explicitly never in V1, debated for V3
- zk-SNARK private orderbook — research, no commitment

**Shippable bar (placeholder; full criteria locked when v1.3 promotes from Sketch to Draft):**

Similar 8-criterion gate as v1.1, plus:

- Comit/Farcaster-style alignment work done for the CyncHub layer's novel primitives
- Two independent audits (different firms than v1.1's, ideally, for fresh-eyes review)
- ≥ 100 testnet matches across ≥ 30 days
- Watchtower service handles CyncHub-side observation too

---

## Past v1.3

**Not planned. Not committed. Not promised.**

CIPs in `docs/cip/` marked Sketch represent design space that could become future releases — but only if/when the prior release ships and the entry criteria for the next one are met. Examples include:

- [CIP-003](cip/CIP-003-cut-through-and-aggregation.md) — Cut-through + block aggregation
- [CIP-004](cip/CIP-004-kernel-offsets.md) — Kernel offsets
- [CIP-005](cip/CIP-005-lelantus-spark.md) — Lelantus Spark
- CyncHub V2+ (multi-coin pairs)

None of these are commitments. Treating them as roadmap items is a mistake.

---

## Why this discipline

The privacy-coin space is littered with projects that announced ambitious roadmaps (5-10 features over multiple years) and shipped a fraction of what they promised. The credibility cost is real: outside observers see the long list and discount the whole project.

Apple's discipline — announce only what ships this year — builds credibility because every announced thing actually ships. Coincync targets the same posture.

**The implicit promise of this roadmap: every headline above will ship, in the order above, meeting the shippable bar above. Slippage is acceptable; reduction of the bar is not.**

---

## Changelog

- **2026-05-20** — **Staged mainnet decision locked in.** v1.0 explicitly defined as base-chain mainnet only (no cyncswap, no shielded pool). v1.1 reframed as cyncswap, shipped after the base chain is live on mainnet and cyncswap has cleared its own dedicated audit. Rationale: cyncswap is the largest novel-cryptography surface in the codebase and deserves an independent audit cycle rather than gating the base chain on it. Mirrors Monero's "chain first, novel crypto later" pattern. Decision recorded at [decisions/2026-05-20-staged-mainnet-and-cyncswap.md](decisions/2026-05-20-staged-mainnet-and-cyncswap.md).
- **2026-05-18** — Roadmap created. v1.0 documented as shipped; v1.1 = cyncswap; v1.2 = polish; v1.3 = CyncHub (conditional on entry criteria). CIP-002 (CyncHub) reverted from Draft to Sketch the same day to reflect Apple-style "no commitment past the next 3 releases" discipline.
