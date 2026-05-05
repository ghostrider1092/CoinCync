# CoinCync Bill of Rights

**The Guaranteed Rights of Every CoinCync User**

**Version:** 1.0
**Ratified:** Block 0 (Genesis)
**Network:** CoinCync Mainnet

---

## Preamble

These rights belong to every person who uses CoinCync -- regardless of who they are, where they live, how much CYNC they hold, or what they use it for.

They were not granted by developers. They cannot be revoked by developers. They exist because they are built into the protocol itself wherever mathematically possible, and because this document -- like the Constitution it accompanies -- is permanent.

No governance process, no community vote, no legal order, and no future development team can remove, weaken, suspend, or reinterpret these rights. Any protocol that fails to honor them is not CoinCync.

Some of these rights are enforced by mathematics -- ring signatures, stealth addresses, and Pedersen commitments that make violation of the right computationally impossible. Others are enforced by community commitment and open source code that any person can audit and verify.

Both categories are listed here. Both are equally binding. The distinction between them is noted not to suggest one matters less, but to be honest about the nature of each guarantee -- because honesty is foundational to everything CoinCync is built on.

---

## Right I -- The Right to Financial Privacy

Every person using CoinCync has the right to conduct financial transactions in private. The network shall provide, by default and without exception, the following protections for every transaction:

- **Ring signatures** to conceal the sender among a set of decoys
- **Stealth addresses** to generate one-time destinations that cannot be linked to a public address
- **Pedersen commitments** to conceal transaction amounts from all parties except sender and receiver
- **Bulletproofs** to prove amounts are valid without revealing them

Privacy is not opt-in. There is no transparent mode. There is no reduced-privacy transaction class. Every transaction on CoinCync is private by construction.

**Enforcement:** Protocol-enforced. Mathematical guarantee.

## Right II -- The Right to Verify Supply

Every person has the right to independently verify the total supply of CYNC at any block height without trusting any third party -- not the developers, not the foundation, not any exchange.

The Pedersen commitment accumulator built into the CoinCync protocol allows any person to confirm that no coins were created outside the emission schedule, that no transaction created coins from nothing, and that the total supply matches the expected emission at the current block height.

The supply is not something you are asked to trust. It is something you can prove.

**Enforcement:** Protocol-enforced. Mathematical guarantee.

## Right III -- The Right to Run a Node

No license, permission, fee, identity verification, or approval of any kind shall ever be required to run a CoinCync node. The software shall remain open source and freely available.

No person shall be blocked from participating in the CoinCync network based on:

- Identity or nationality
- Geographic location or jurisdiction
- Political affiliation or beliefs
- Financial status or holdings
- Any other characteristic

Participation in the CoinCync network requires nothing but software and an internet connection.

**Enforcement:** Community-enforced. Open source license and protocol design.

## Right IV -- The Right to Self-Custody

No version of the CoinCync protocol shall ever implement backdoors, key escrow, or any mechanism that allows a third party to access, freeze, seize, or redirect a user's funds without that user's explicit and voluntary consent.

Your keys are your coins. The protocol has no override. There is no account recovery through a central party. There is no emergency freeze mechanism. There is no kill switch.

This right exists because financial self-custody is inseparable from financial privacy. A coin whose funds can be frozen is not a private coin -- it is a monitored one with extra steps.

**Enforcement:** Protocol-enforced. No freeze mechanism exists in the protocol.

## Right V -- The Right to Pseudonymous Participation

No part of the CoinCync network, community, or governance shall require identity verification to participate. Every person may interact with the network, participate in community discussions, submit governance proposals, and contribute to the codebase using a pseudonym.

This right exists because the demand for identity verification is the first step toward financial surveillance. A network that requires you to identify yourself before participating is not a private network.

Contributors who choose to participate publicly under their real names are equally welcome. The right is to choose -- not to be required.

**Enforcement:** Community-enforced. Governance and contribution processes shall never require identity.

## Right VI -- The Right to Exit

Any person may export their wallet, move their funds, and leave the CoinCync network at any time and for any reason. No lockup, vesting schedule, exit fee, or protocol-level restriction shall ever be imposed on withdrawing funds.

This right also extends to the code. Because CoinCync is MIT-licensed, any person may fork the protocol, modify it, and run their own version. The right to exit includes the right to take the technology with you.

A user who cannot leave freely is not a user. They are a captive.

**Enforcement:** Protocol-enforced for funds. Open source license enforces code portability.

## Right VII -- The Right to Audit the Code

The full CoinCync codebase shall remain publicly auditable at all times. No obfuscated, closed-source, or proprietary components shall be introduced into the core protocol.

Every person has the right to:

- Read the full source code of the node, wallet, and all supporting tools
- Compile the software themselves from source
- Verify that compiled binaries match published source code
- Audit the cryptographic primitives independently
- Publish their findings without restriction

Auditability is not a feature. It is what makes all other rights verifiable.

**Enforcement:** Community-enforced. MIT license and public repository.

## Right VIII -- The Right to Participate in Governance

Any CYNC holder may submit governance proposals, participate in protocol discussions, and vote on project-layer decisions regardless of their holdings size, identity, or standing in the community.

No minimum holding threshold shall be set so high as to effectively exclude ordinary users from governance participation. No process shall be designed to favor large holders, early contributors, or any specific class of participant over others.

Governance participation is open to everyone. The protocol belongs to its users -- all of them.

**Enforcement:** Community-enforced. Governance procedures shall guarantee open access.

## Right IX -- The Right to Fee Transparency

Transaction fees shall be calculated deterministically and disclosed to users in full before any transaction is broadcast. No hidden fees, no protocol-level fee extraction to a central party, and no fee mechanisms that advantage any party over another shall ever be implemented.

A user has the right to know exactly what they are paying before they pay it. A network that obscures costs from its users is not serving its users.

Fee changes may be proposed through the CIP process but may never be implemented in a way that directs any portion of fees to developers, foundations, or any centralized entity.

**Enforcement:** Protocol-enforced. Deterministic fee calculation with no central extraction.

## Right X -- The Right Against Censorship

The CoinCync protocol shall never implement transaction blacklists, address blocking, output freezing, or any mechanism that allows the censorship of valid transactions based on origin, destination, amount, or any other characteristic.

A valid transaction -- one that satisfies all cryptographic proofs and consensus rules -- shall always be eligible for inclusion in a block. No miner, node, developer, or governance body shall have the ability to prevent a valid transaction from ever being mined.

This right exists because financial censorship and financial surveillance are two sides of the same coin. A network that can block transactions can control its users. CoinCync shall never control its users.

**Enforcement:** Protocol-enforced. No blacklist or censorship mechanism exists in the protocol.

## Right XI -- The Right Against Algorithmic Capture

Your CYNC will never be tied to a stablecoin's solvency, a yield product's APY, or any external token's price. The protocol's value rests on the chain's own security, scarcity, and privacy -- not on circular tokenomics that depend on continued issuance to redeem. No mechanism may be added that makes your CYNC depend on the continued operation of another system to retain its meaning.

**Enforcement:** Protocol-enforced. Article XI of the Constitution; no mint pathway exists outside the Article I emission.

## Right XII -- The Right Against Surprise Forks

You will never wake to a chain that changed its rules overnight. Protocol changes require a public proposal, a discussion period measured in months, and active opt-in by the node operators you choose to peer with. A fork that fails to reach community consensus is aborted, never forced through.

**Enforcement:** Community-enforced. Article VIII CIP discipline; node-operator adoption is the only valid activation path.

## Right XIII -- The Right to Reproducible Software

The binary you run can be rebuilt from public source by anyone who chooses to verify it. Releases are signed by multiple independent maintainers; no single key can ship software that runs on the network. Supply-chain attacks against the binary distribution are infeasible by construction, not by trust.

**Enforcement:** Build pipeline. Multi-signature release gating. Open-source license guarantees the right to verify.

## Right XIV -- The Right to Permanent Scarcity

A floor of thirty percent of every transaction fee is burned -- removed from circulation forever, captured by no one. This rate rises during network congestion and may never fall below the protocol's stated minimums. Combined with the asymptotic emission cap, this makes CYNC structurally deflationary at any sustained level of network usage. Fees not burned are paid to miners as proof-of-work reward; no fraction of any fee may ever be redirected to a developer fund, foundation, validator pool, or any other party.

**Enforcement:** Protocol-enforced. Article XVI of the Constitution; fee-burn floors are constants with compile-time guards in `src/constants.rs`.

---

## Note on Properties, Not Promises

These Rights describe the protections the CoinCync protocol provides to its users by design. They are properties of the technology, enforced by the code and by the network of node operators who choose to run it. They are not contractual obligations of any developer, foundation, contributor, or other entity. No party warrants that any specific outcome will be achieved by interacting with the network.

Each user of CoinCync assumes responsibility for verifying that the protocol's properties match their needs and for using the network in a manner consistent with applicable laws in their jurisdiction. The MIT license under which all CoinCync code is released expressly disclaims warranty in all jurisdictions where such disclaimers are recognized.

This note does not weaken any Right above. The protections remain real and built into the protocol. It only clarifies the legal nature of the document: technical commitment, not commercial guarantee.

---

## Closing Seal

These rights are final. They are not subject to amendment, revision, or repeal by any person, body, or process -- now or at any point in the future.

They may only be strengthened by technical improvement. They may never be weakened by any means.

Any version of the CoinCync software that removes or weakens any of these rights is not CoinCync. It is a different coin wearing the same name. Users, miners, and node operators are encouraged to identify it as such and reject it.

**Ratified at Block 0. Permanent thereafter.**

---

*Document hash stored on-chain at Block 0 as proof of existence and immutability.*
