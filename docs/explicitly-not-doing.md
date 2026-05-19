<!-- markdownlint-disable MD036 MD013 -->
# What CoinCync Will Not Do

**Privacy money that requires no permission.** That promise is load-bearing for the design discipline below.

This document is the canonical answer to "will you add X?" If X is on this list, the answer is no — and the answer will stay no. Asking again in 6 months will get the same answer. Asking after a fork will get the same answer. The discipline is the product.

If something is *not* on this list, it might be considered for a future release — but check [docs/roadmap.md](roadmap.md) first to see if it's already scoped or sketched.

---

## Categories

1. [Trust-model changes](#trust-model-changes)
2. [Token / economic changes](#token--economic-changes)
3. [Surveillance / compliance integration](#surveillance--compliance-integration)
4. [Trend-chasing features](#trend-chasing-features)
5. [Protocol bloat](#protocol-bloat)
6. [Operational concessions](#operational-concessions)

---

## Trust-model changes

**Will not add: a federation.** Not for the bridge, not for the orderbook, not for the wallet, not for governance. The Constitution's Article XII forbids admin authority over user funds; a federation is the same thing by another name.

**Will not add: a multisig with a project-controlled key.** Same reasoning. Users can run FROST multisigs among themselves (CIP-008) — that's user-controlled and stays user-controlled. Project never holds a key that gates anything user-facing.

**Will not add: an "emergency pause" mechanism that touches user funds.** The kill-switch advisory in the safety stack stops *new* swap activity; it cannot freeze in-flight swaps or move funds. That's the line.

**Will not add: trusted setup ceremonies that aren't already required by the underlying primitive.** Orchard's existing Halo2 setup is acceptable because it's a known property of the construction we're adopting verbatim. Adding new trusted-setup steps is not.

---

## Token / economic changes

**Will not add: a governance token.** No "$CYNC-GOV" or equivalent. Governance is the Constitution + the CIP process, full stop. Article XI forbids algorithmic capture; a governance token is the textbook capture vector.

**Will not add: staking.** Not PoS, not PoW+PoS hybrid, not "stake to vote," not "stake to participate," not any flavor. CoinCync is PoW (RandomX). Period.

**Will not add: a yield mechanism.** No native lending, no native borrowing, no native vaults, no "earn CYNC by holding CYNC." Holding CYNC is the use; there is no second-order economic layer to capture.

**Will not add: a dev fund.** Funding comes from grants ([project_sustainability_grants](../C:/Users/unkno/.claude/projects/c--Users-unkno-OneDrive-coincync-1-0/memory/project_sustainability_grants.md)) and donations, not from protocol fee siphoning. CIP-002 (CyncHub) explicitly routes 100% of match fees to miners, zero to any treasury — and that's not a choice we revisit.

**Will not add: rebasing or inflation-adjustment beyond the published emission curve.** The supply schedule is what it is. No "elastic supply," no "monetary policy committee."

**Will not add: NFTs, name tokens, or any non-fungible primitive.** CYNC fungibility is a constitutional commitment; NFTs are the opposite of fungibility.

---

## Surveillance / compliance integration

**Will not add: KYC integration.** Not in the wallet, not in the node, not as an optional opt-in. Right X of the Constitution is explicit.

**Will not add: address blacklists or allowlists.** Not at the consensus layer, not in the reference wallet, not in any project-controlled component. If a third party publishes a list, that's their business; coincync.org does not host or endorse it.

**Will not add: Travel Rule attestation hooks.** The compliance industry's current preferred lever for tagging crypto txs with off-chain identity data. Not in the protocol, not in the reference wallet.

**Will not add: chain-analysis-friendly metadata.** Per [project_traffic_shaping_status](../C:/Users/unkno/.claude/projects/c--Users-unkno-OneDrive-coincync-1-0/memory/project_traffic_shaping_status.md), all three privacy-traffic layers are active in prod. We will not weaken these to make chain analysis easier.

**Will not add: opt-in transparency mode.** Some privacy coins offer a "view key for auditors" flow. CoinCync has scoped view keys (one of the 7 privacy innovations), which is user-side and bounded. We will not add a coin-side mechanism that lets an auditor see all of a user's transactions globally.

**Will not add: jurisdictional compliance modes.** No "EU mode," no "US mode," no per-country features. The constitution applies uniformly.

---

## Trend-chasing features

**Will not add: smart-contract support.** CoinCync follows Bitcoin's posture — narrow scripting only, no general-purpose VM. CIP-002 (CyncHub) is a separate chain for one specific purpose (orderbook), not a smart-contract platform.

**Will not add: cross-chain bridges beyond what CIP-001 / CIP-002 specify.** cyncswap (CIP-001) is trustless CYNC↔BTC. CyncHub V1 (CIP-002, currently Sketch) is the orderbook layer. There is no "bridge to Ethereum / Solana / Cosmos / Polkadot / etc." planned ever.

**Will not add: ETH-compatible primitives.** Not EVM, not Solidity-callable contracts, not ERC-20-style tokens, not wallet-connect, not anything that exists to ride Ethereum's tail.

**Will not add: DeFi integrations.** Not lending protocols, not perpetual futures, not options markets, not yield-aggregators. CoinCync is money, not a financial-engineering substrate.

**Will not add: DAOs.** No on-chain governance. No "$CYNC holders vote on protocol changes." Governance is the Constitution + the CIP process.

**Will not add: MEV-related features.** Not MEV-Boost, not searcher integration, not priority-fee auctions, not block-builder coordination. Miners include transactions in the order they decide; that's it.

**Will not add: Layer-2 scaling beyond what CIP-002 (CyncHub) covers.** CyncHub is the only L1.5 / L2-adjacent design in scope. No rollups, no state channels (beyond Lightning-style submarine swaps if/when CyncHub V2 adds them), no plasma.

---

## Protocol bloat

**Will not add: a configurable consensus rule.** Consensus rules are constants, not knobs. If a rule changes, it goes through CIP-007's activation policy as a hard fork. Validators do not "vote" on rules; they validate against the rule version they support.

**Will not add: optional privacy modes.** Privacy is on. Privacy is mandatory at the consensus layer. Users do not get to "opt out" of privacy for performance or fee savings.

**Will not add: opt-in transparency for specific transactions.** Same reasoning. The "you can publish a view key for this one tx" flow opens a slippery slope toward de facto opt-out privacy.

**Will not add: fee tiers visible to users.** The wallet picks a sensible fee. Users do not see "economy / standard / priority" sliders. (Per Apple-style principle 3: zero parameters.)

**Will not add: configurable ring sizes.** The ring size is a consensus constant, set by CIP-010 deliberation, not a user choice. (Current value: 16; minimum: 11 → 13 per CIP-010.)

**Will not add: multi-asset native tokens.** CYNC is the only native asset. Other coins live on their own chains and are reachable via cyncswap (CYNC↔BTC) or CyncHub V2+ (multi-coin pairs).

---

## Operational concessions

**Will not host: a centralized wallet service.** Users run wallets on their own devices. No "coincync.org/wallet" web wallet that holds keys.

**Will not host: a custodial swap service.** cyncswap is the trustless option. We do not run a custodial fallback "for users who can't figure out the wallet."

**Will not host: an "official" mining pool.** The reference mining software (`coincync-rig`) supports pool mining; pools are run by third parties. The project does not run one because pool operation creates a centralization pressure point.

**Will not run: cloud mining infrastructure.** Per [feedback_no_cloud_mining](../C:/Users/unkno/.claude/projects/c--Users-unkno-OneDrive-coincync-1-0/memory/feedback_no_cloud_mining.md): home hardware or colocation only. All major hosts ban mining; we will not work around it.

**Will not endorse: third-party services that violate the constitutional posture.** If a third party builds a KYC-gated wallet, the project does not link to it. If a third party runs a custodial mixer, we do not promote it.

---

## What's NOT on this list (yet)

Some things people will ask about that I haven't explicitly addressed:

- **Mobile wallet:** *probably* later, after the desktop wallet is at v1.2 quality. Not actively scoped. If it ships, it follows the same Apple-style principles as the desktop wallet (zero parameters, mandatory watchtower, mandatory privacy default).
- **Hardware wallet integration:** *yes*, this IS in scope per the Apple-style principle 6. Trezor first (reference vendor). Ledger / Coldcard follow if community demand justifies the maintenance burden.
- **Browser extension:** *not planned*. Browser extension wallets are a security model regression (browser sandbox, supply chain risk). Won't say "never" but the bar is high.
- **GUI for the node operator:** *not planned*. Operator-facing tooling is CLI + systemd + standard logs. Adding a GUI for a node is solving the wrong problem.

These four are "open questions" rather than "explicitly not doing" — distinct category.

---

## How this list is amended

Adding something to this list: just edit the file. The list grows naturally as community asks "will you add X?" and the answer is determined.

Removing something from this list: requires a [docs/decisions/](decisions/) record. If we ever decide "yes, we WILL add X after all," that's a strategic reversal that deserves the decision-record treatment — same as the cyncswap-path decision from 2026-05-18.

Until then: the answer is no.

---

## Why this discipline matters

Every crypto project has a feature backlog the size of a small country, driven by the loudest voices in their Discord. Apple's discipline is the opposite — the public list of "won't do" is longer than the public list of "will do," and that's the *whole point*. It frees up engineering attention for the few things you do ship to be really good.

This document is how that discipline becomes a property of the project, not a property of the current maintainer's mood.

---

## Changelog

- **2026-05-18** — Document created as part of the Apple-style discipline shift. Captures the trust-model, economic, surveillance, trend-chasing, protocol-bloat, and operational lines that CoinCync will not cross. Companion to [docs/roadmap.md](roadmap.md) and the [Constitution](../CONSTITUTION.md).
