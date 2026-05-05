<!-- markdownlint-disable MD036 -->
# Constitutional Commentary

**Companion to [CONSTITUTION.md](../CONSTITUTION.md) and [BILL_OF_RIGHTS.md](BILL_OF_RIGHTS.md).**

---

## Status

This document **has no constitutional force**. Nothing recorded here can override, weaken, amend, or reinterpret the Constitution itself. It exists for one reason: to record *why* each article was chosen, what failure modes inspired it, and what historical precedents informed the language — so future maintainers, researchers, and users can understand the reasoning without polluting the operative text.

If this Commentary ever appears to conflict with the Constitution, the Constitution wins. Always. Without exception.

This file may be edited freely as understanding deepens. Edits here do not require any of the gravitas of an amendment to the Constitution itself, because the Constitution itself remains untouched.

---

## On the structure of the documents

The Constitution states *rules*. The Bill of Rights states *user-facing guarantees*. The Commentary states *reasoning*.

This three-layer split prevents two failure modes that have killed other projects' governance documents:

1. **Lawyering loopholes.** Specific rules invite specific exceptions. The more enumerated the rule, the more "is this Z?" arguments it creates. By keeping the Constitution short and principle-level, we narrow the surface for hostile interpretation.
2. **Rationale rot.** When the *reasoning* for a rule lives in the rule itself, updating the reasoning means amending the rule. We don't want that. The Constitution is permanent; the Commentary can evolve as understanding does.

The US Bill of Rights is ten amendments, most one to three sentences long, written in 1791. They apply cleanly to email, GPS data, smartphones, and AI in 2026. That's the durability we're aiming for.

---

## On Article XI — No Algorithmic Capture

**The failure mode.** In May 2022, a stablecoin called UST collapsed from $18 billion to near zero in five days. Its peg was algorithmic — UST was redeemable for $1 worth of LUNA, minted on demand. When demand for UST fell, redemptions printed LUNA into the market, depressing LUNA's price, which required minting more LUNA per UST, which depressed it further. The death spiral was structural to the design and could not be stopped once initiated. A subsidized 19.5% APY product called Anchor had concentrated UST demand into a single yield reflex; when the subsidy faltered, the system unwound catastrophically.

**Why this article exists.** A 100M fixed-cap chain with no peg, no rebase, and no protocol-level yield product cannot algorithmically capture. The only way to introduce that risk is to add a mechanism — a stablecoin module, a rebasing primitive, an algorithmic incentive layer. Article XI forbids the *category*, not specific instances, so future inventions in this category remain forbidden without further amendment.

**What this article does not forbid.** Off-chain or third-party stablecoins denominated in CYNC (which depend on the issuer, not on CoinCync's protocol). Wallets that integrate other chains (which is a wallet UX choice, not a protocol mechanism). User-level smart contracts running on different infrastructure that happen to reference CYNC.

**What this article does forbid.** Any protocol-layer mechanism that mints, burns, redistributes, or subsidizes CYNC outside the Article I emission. Any consensus rule that responds to the price or supply of another asset. Any "treasury" or "stability fund" structure built into the protocol. Any "ve-token" or governance-share mechanism that grants economic advantage from holdings.

---

## On Article XII — No Admin Authority

**The failure mode.** Many tokens shipped with admin keys, pause functions, freeze authority, or upgrade gates as a "safety measure" — and have been compelled to use them under legal pressure (USDC blacklisting addresses), exploited (compromised admin keys draining contracts), or simply abused (founders rugging users). The principle is that any privilege built into a system will eventually be exercised, often against the users it was supposed to protect.

**Why this article exists.** Bitcoin and Monero have no admin keys. They've survived 16 and 11 years respectively without one because they never had one. Once an admin key exists, it becomes a permanent attack surface — legal, technical, and social. The only defense is to never build one.

**What this article does not forbid.** Off-chain governance discussion. Maintainer-signed releases (signing is voluntary attestation, not chain-controlling authority). Multisig wallets used by *individual users* for their own funds. Multi-maintainer commit access on the source repository.

**What this article does forbid.** Any consensus-layer mechanism whose effect depends on a specific key, address, or signer being able to act. Pause functions. Emergency overrides. Upgrade gates that bypass node-operator opt-in. Multisig-controlled minting, freezing, or redirecting of any user's funds.

---

## On Article XIII — No External Trust

**The failure mode.** Cross-chain bridges have been the single largest hack vector in crypto. Wormhole lost $325M (Feb 2022), Ronin lost $625M (Mar 2022), Nomad lost $190M (Aug 2022) — every one because the bridge accepted off-chain or foreign-chain state as authoritative without verifying it could not be forged. The deeper problem: privacy and external-state dependence are mutually destructive. An oracle reveals what a privacy chain is meant to hide.

**Why this article exists.** Sovereignty over local state is what makes a blockchain trustworthy. The moment consensus depends on something the chain cannot prove from its own data, the security model expands to include whatever produced that external data — and that "whatever" is almost always more centralized, more vulnerable, and more political than the chain itself.

**What this article does not forbid.** Off-chain wallets that use price feeds. Block explorers that pull data from third parties. Exchanges that quote CYNC against other assets. None of these touch consensus.

**What this article does forbid.** Any consensus rule that admits external chain state, oracle prices, off-chain attestations, IOU tokens, or wrapped assets into block validity. Any mechanism that makes a transaction's validity depend on data not derivable from the CoinCync chain itself.

---

## On Article XIV — No Surveillance Layer

**The failure mode.** Even when transaction amounts are private, metadata can deanonymize. Bitcoin chain analysis uses coin-age, address clustering, and transaction patterns to identify users. NFTs and soulbound tokens introduce non-fungibility that makes transaction graphs trivially analyzable. Identity attestation systems (proof of personhood, KYC tokens) reintroduce the exact surveillance the privacy stack was built to prevent. The principle: privacy is monotonic — every metadata field weakens it.

**Why this article exists.** Article III established mandatory privacy at the cryptographic primitive level. Article XIV extends that to the metadata layer. Without this article, a future maintainer could argue "we kept ring signatures, so privacy is preserved" while shipping an identity attestation feature that leaks everything ring signatures hide.

**What this article does not forbid.** User-level encrypted memos (those are voluntary, content-private, and tied to a single transaction). Optional view keys (voluntary disclosure, Article VI). Wallet-side address books and labels (those are local-only). Receipts the recipient generates for themselves.

**What this article does forbid.** Any protocol field that distinguishes outputs by age, history, or position. Any non-fungible token primitive. Any name service. Any soulbound or non-transferable class. Any identity attestation system. Any feature that allows a third party to observe metadata that distinguishes one user's CYNC from another's.

---

## On Article XV — Spirit and Construction

**The failure mode.** Constitutional documents fail in two opposite directions: too short and too long. Too short, and every novel situation forces an interpretation question without a guide. Too long, and the document grows brittle and lawyerable.

**Why this article exists.** It establishes a meta-rule for reading every other article: when the text is silent, default-deny. When two articles seem to conflict, the user-protective reading wins. When literal text and underlying intent diverge, *both* must support a change — neither alone is sufficient. This single article does more work than 50 specific prohibitions. It says, in effect: *this document is a floor, not a ceiling, and the burden falls on whoever wants to add to it.*

**The relationship to Article X.** Article X says the Constitution cannot be amended, repealed, or weakened. Article XV says how the Constitution is read. They are compatible: Article X protects the *substance* of the existing articles; Article XV provides the *interpretation* of any silence within them. Future strengthening additions follow Article XV's discipline — they must demonstrably strengthen, not merely "not weaken." Removals, weakenings, and contradictions remain forbidden by Article X.

**The "would the founders be horrified" test.** When a proposed change passes literal review but feels wrong, the right question is: would the people who ratified Block 0 — the users who chose this chain because of its commitments — be horrified by this change? If a diverse panel of original users would say yes, the change is unconstitutional regardless of what the literal text appears to permit. This is fuzzy by design. Loopholes are exploited by people willing to argue text against intent. The spirit test gives the community grounds to reject changes that survive the literal text but betray the original purpose.

---

## On Rights XI–XIII

The Bill of Rights is the user-facing translation of the operator-facing Articles. Each of Rights XI, XII, and XIII corresponds to a Tier-1 protection category from the Articles, restated in plain language about what the user is guaranteed:

- **Right XI (Against Algorithmic Capture)** translates Article XI's prohibition into what it means for the holder: your CYNC is not collateral for a stablecoin you didn't sign up for, nor will it ever be.
- **Right XII (Against Surprise Forks)** translates Articles VIII and XV's hard-fork discipline into what it means for the user: you will never wake up to a chain whose rules changed without you.
- **Right XIII (To Reproducible Software)** translates the supply-chain integrity commitment into what it means for the user: the binary you run can be audited, rebuilt, and verified by anyone.

The split between Constitution and Bill of Rights is intentional: operators read the Constitution, users read the Bill of Rights, and both layers are equally binding. The Bill of Rights is the version a non-technical user can understand. The Constitution is the version a maintainer reviews when evaluating a proposed change.

---

## Why this Commentary lives outside the Constitution

Every paragraph in this file could have been added to the Constitution itself. We didn't, deliberately:

- **Examples become outdated or disputable.** Five years from now, Wormhole and Ronin will be forgotten and someone will ask "what about *new* bridge XYZ?" — and the literal language ("forbidden mechanisms include X, Y, Z") will invite an argument. By keeping Wormhole as historical context here, the Constitution itself remains framed in terms of *categories*, not *instances*.
- **Rationale evolves; rules don't.** Our understanding of why algorithmic stablecoins fail will deepen. Our understanding of which bridge designs were structurally compromised will change. None of that should require amending the Constitution.
- **The "ten-minute readability" test.** The Constitution should be readable in ten minutes by anyone evaluating whether this chain is for them. If we'd inlined this Commentary, it would be 30 minutes. The Constitution stops being a constitution and becomes a treatise.

Keeping the principle in the Constitution and the rationale in the Commentary is the move that lets both documents stay strong over time.

---

*This Commentary is not ratified at any block. It has no consensus weight. It is documentation, not law.*
