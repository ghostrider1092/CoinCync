# The CoinCync Constitution

**The Supreme and Permanent Law of the CoinCync Protocol**

**Version:** 1.0
**Ratified:** Block 0 (Genesis)
**Network:** CoinCync Mainnet

---

## Preamble

This document defines the immutable principles of the CoinCync protocol. These are not guidelines. They are not aspirations. They are hard commitments — promises written into the code that no developer, committee, majority vote, legal order, or act of governance can override.

Any protocol change that violates this Constitution is invalid, regardless of how many people support it, how much proof of work backs it, or who proposes it.

This Constitution was written once. It will not be rewritten. It exists not because we distrust the people building CoinCync today — but because we cannot know who will be building it tomorrow. These principles protect users from every possible future, including futures we cannot predict.

Ten articles follow. Each one is a wall. None of them have doors.

---

## Article I — Fixed Supply

The total supply of CYNC shall never exceed **100,000,000** coins. This limit is asymptotic — the emission curve approaches but never reaches it. It is not subject to amendment, emergency override, governance vote, or any other mechanism.

The emission is determined by one formula: `reward = max(0.6 CYNC, (100M - already_mined) / 2,000,000)`. No eras. No halvings. Every coin mined makes the next one slightly harder to earn. The network itself will reject any block that violates this formula.

A tail emission of 0.6 CYNC per block exists to sustain mining security perpetually. A 30% fee burn offsets this emission — when transaction fees exceed ~2 CYNC per block, the chain becomes deflationary. The 100,000,000 coin cap is the mathematical ceiling; actual circulating supply will stabilize below it.

Anyone can verify the current supply at any time using the Pedersen commitment accumulator built into every node. If the mathematics do not confirm the supply, the chain is invalid. Trust the math, not the announcement.

**Enforcement:** Protocol-enforced. Every node independently validates supply on every block.

## Article II — No Pre-mine, No Developer Tax

Zero coins were created before block 0. Zero coins are or will ever be diverted to developers, foundations, treasuries, or any other entity by protocol design. Every CYNC in existence was mined by someone who contributed proof of work to the network.

The CoinCync protocol shall never introduce:

- A developer fund, foundation treasury, or protocol-level savings account
- A percentage-based fee or tax redirected to any address or entity
- A governance token, staking requirement, or bonding mechanism that grants economic advantage to any party
- Any mechanism that creates coins outside the published emission schedule
- Any retroactive claim on mined supply by founders or contributors

This is not a promise that might be reconsidered if circumstances change. There are no circumstances under which this article can be suspended, amended, or overridden.

**Enforcement:** Protocol-enforced. No dev tax mechanism exists in the codebase. Supply is publicly verifiable.

## Article III — Mandatory Privacy

All transactions on CoinCync are private. There is no transparent mode. There is no opt-in privacy tier. There is no reduced-privacy transaction class. Every transaction, without exception, uses the full privacy stack:

- **Ring signatures** to conceal the sender among a set of cryptographic decoys
- **Stealth addresses** to generate one-time destinations that cannot be linked to any public address
- **Pedersen commitments** to hide transaction amounts from all observers
- **Bulletproofs** to prove that amounts are valid without revealing them

Privacy is not a feature that can be toggled, deprecated, or made optional. It is the default and only state of every coin, every transaction, and every block on CoinCync.

No protocol change shall ever create a class of transactions with weaker privacy guarantees than those described above. Privacy may be strengthened through technical advancement. It may never be weakened.

**Enforcement:** Protocol-enforced. Ring signatures, stealth addresses, and Bulletproofs are required for all transactions.

## Article IV — Auditable Integrity

Despite mandatory privacy, anyone can mathematically verify — without trusting any third party — that:

1. No coins were created outside the emission schedule
2. No transaction created coins from nothing
3. No double-spend has ever occurred on the chain
4. The total supply at any block height matches the expected emission

This is achieved through the Pedersen commitment accumulator — a cryptographic structure embedded in every node that proves supply integrity without revealing individual transaction amounts. Every node validates this accumulator on every block. A block that fails this check is rejected by the entire network.

Privacy and auditability are not in conflict. CoinCync proves both simultaneously. This is the answer to every critic who says privacy coins cannot be trusted. The math is open. Anyone can check it.

**Enforcement:** Protocol-enforced. Pedersen accumulator validated on every block by every node.

## Article V — Open Mining

CoinCync uses **RandomX**, and only RandomX, as its proof-of-work algorithm. RandomX is a CPU-biased, memory-hard, ASIC-resistant algorithm originally designed for Monero. It has been in production on the longest-running CPU-only privacy coin since November 2019 and remains, as of the ratification of this document, the gold standard for permissionless, hardware-accessible mining.

RandomX uses a 256 MB scratchpad and a virtual machine that executes randomly-generated bytecode — both of which favor general-purpose CPUs over fixed-function hardware. An ASIC for RandomX would essentially be a CPU, which offers no economic advantage over commodity consumer hardware. This is what makes mining permissionless in practice and not only in policy.

The following principles are permanent:

- **Single algorithm.** RandomX is the only PoW algorithm. Multi-algorithm rotation schemes are forbidden — they are not security through diversity, they are security through the *weakest* algorithm in the rotation, and they have a documented history of enabling selfish-mining and algorithm-spam attacks on other chains that tried them. The right defense against ASICs is a single strong memory-hard algorithm, not a rotation.
- **No ASIC-friendly algorithms.** Blake3, SHA-256, Equihash, Ethash, and any other algorithm with published ASIC implementations are permanently forbidden. Any deviation — even a single block mined under a different algorithm — produces a chain that is not CoinCync.
- **No Proof of Stake, no hybrid PoS/PoW, no finality gadget.** The CoinCync protocol shall never transition to any consensus mechanism that requires holding coins to validate blocks. PoS rewards the already-wealthy and reintroduces the exact permissioned-finance problems this chain was built to reject.
- **No permission, license, or registration** is required to mine CoinCync.
- **No KYC, identity verification, or whitelist** exists for mining participation.
- **Anyone with consumer hardware** can participate in block production.
- **No minimum stake, bond, or holding** is required to mine.
- **Mining rewards are determined solely by proof of work contributed.**

**Enforcement:** Protocol-enforced. `RANDOMX_ONLY = true` is a compile-time constitutional guard in `src/constants.rs`; any build that tries to flip it fails to compile with `"UNCONSTITUTIONAL: Article V"`. The `randomx` Cargo feature is on by default; building without it makes `compute_pow_hash` return an error at runtime so a PoW-skipping binary cannot silently ship.

**Why RandomX and not multi-algorithm rotation:**

The argument for multi-algorithm rotation is that diversifying across algorithms neutralizes an ASIC advantage in any single one. The argument fails on three grounds:

1. **It reduces security to the weakest algorithm.** A rotation including Blake3 is only ASIC-resistant 2/3 of the time. Every third block is trivially ASIC-mineable, which gives well-resourced adversaries a cheap lever to concentrate hashrate and chain-reorg history.
2. **It expands attack surface.** Per-algorithm difficulty tracking, cross-algorithm reorg rules, and algorithm-specific validation code all add lines to the verifier. Each line is a potential bug. Multi-algorithm privacy coins (Verge, Bitcoin Gold) have a documented history of consensus exploits enabled by exactly this complexity.
3. **The precedent is RandomX alone.** Monero has held ASIC resistance under RandomX-only for five years with no consensus-level exploits and no concentration events attributable to algorithm choice. It is the most thoroughly battle-tested CPU-only design in existence.

RandomX alone is not a compromise. It is the correct choice.

## Article VI — Voluntary Disclosure Only

CoinCync provides view keys that allow users to selectively prove their transaction history when they choose to do so — for tax reporting, personal audits, proof of payment, or any other voluntary purpose.

This disclosure mechanism is governed by three absolute principles:

- **Voluntary** — No person can be required by the protocol to reveal their transactions. Disclosure is always a choice made by the key holder, never a requirement imposed by the network.
- **Selective** — Users can disclose specific transactions or a specific time range without revealing their complete history. The granularity of disclosure belongs to the user.
- **Revocable** — View keys can be rotated. Past keys cannot see transactions generated after rotation. Forward secrecy is preserved by design.

The CoinCync protocol shall never implement:

- Mandatory identity verification of any kind
- Backdoors for any government, regulator, law enforcement agency, or private entity
- Travel rule enforcement at the protocol level
- Mandatory transaction memo fields that associate transactions with identities
- Any mechanism that weakens privacy without the explicit, per-transaction, voluntary consent of the key holder

The right to financial privacy is not contingent on having nothing to hide. It belongs to everyone.

**Enforcement:** Protocol-enforced for privacy. View key mechanism is the only sanctioned disclosure path.

## Article VII — Permissionless Participation

No entity controls who can participate in the CoinCync network. The following rights of participation are absolute and unconditional:

- **Run a node** — anyone may operate a CoinCync node without license, permission, or fee
- **Mine blocks** — anyone may participate in block production
- **Send and receive CYNC** — anyone may transact on the network
- **Read the blockchain** — the chain data is public and accessible to all
- **Build on the protocol** — anyone may create software, services, or tools using CoinCync
- **Fork the code** — the MIT license guarantees the right to take the technology in a new direction

CoinCync is MIT-licensed. The code is open. The network is open. Participation requires nothing but software and an internet connection.

No future version of the protocol may introduce participation requirements based on identity, nationality, financial status, political affiliation, or any other characteristic. The network serves everyone or it serves no one.

**Enforcement:** Protocol-enforced for network access. MIT license enforces code freedom.

## Article VIII — Protocol Governance

CoinCync governance operates on two distinct and separate layers. Both are necessary. Neither can override the other's domain.

### Layer 1 — Protocol Governance

Changes to the CoinCync protocol are proposed through CoinCync Improvement Proposals (CIPs). Any person may submit a CIP regardless of identity, holdings, or standing.

At the protocol level, legitimacy is measured by node operator adoption — not by committee vote, coin weight, or individual authority. A change becomes canonical when a supermajority of active nodes choose to run it. The chain with the most accumulated proof of work is always the valid chain. No committee, council, or individual can force a node to upgrade.

No CIP may violate this Constitution. Proposals to raise the supply cap, remove mandatory privacy, introduce a developer tax, add surveillance capabilities, restrict mining access, or weaken any right in the Bill of Rights are unconstitutional on their face — invalid regardless of support, invalid regardless of who proposes them.

### Layer 2 — Project Governance

The CoinCync project — its codebase, community, communications, and relationships — is governed by the Separation of Powers document. That document establishes three roles: the Protocol Maintainer, the Community Steward, and the Community itself.

These roles have authority over project decisions. They have no authority over the protocol itself. A unanimous resolution of all role holders cannot change a single consensus rule without node operator adoption.

The project layer coordinates human effort around building CoinCync. The protocol layer guarantees that no amount of human coordination can betray the users this project was built to serve. When these layers conflict, the Protocol Layer wins. Always.

### CIP Process

1. Any person may submit a CIP as a public document
2. Minimum 30-day public discussion period before any vote
3. Working implementation required before activation
4. Node operator adoption required for protocol-layer changes
5. Constitutional amendments: not permitted under any circumstances

**Enforcement:** Node adoption is the only vote that matters at the protocol level.

## Article IX — No Surveillance Infrastructure

The CoinCync protocol shall never include any feature whose primary purpose is to enable financial surveillance, network monitoring, or the identification of participants without their consent.

The following are permanently prohibited from the CoinCync protocol:

- Blacklists or address-level transaction blocking of any kind
- Chain analysis hooks or metadata fields that leak identifying information by design
- Mandatory transaction memo fields that associate transactions with identities
- IP address logging in the reference implementation
- Any reporting mechanism that transmits user data to third parties
- Any feature that allows a third party to identify the sender or receiver of a transaction without the voluntary disclosure of a view key

Encrypted peer-to-peer communication and Dandelion++ transaction routing are built into the protocol specifically to prevent network-level surveillance — the identification of transaction originators through network traffic analysis. These protections shall not be weakened.

The distinction between lawful monitoring and surveillance infrastructure is not recognized at the protocol level. The protocol does not know who is asking. It protects everyone equally or it protects no one reliably.

**Enforcement:** Protocol-enforced. No surveillance mechanism exists in the protocol. Dandelion++ and encrypted P2P are mandatory.

## Article X — Immutability

This Constitution is permanent.

It cannot be amended. It cannot be repealed. It cannot be superseded by any governance process, community vote, developer decision, legal order, court ruling, regulatory requirement, or supermajority of any kind. There is no emergency provision. There is no sunset clause. There is no mechanism by which these articles can be weakened, suspended, or removed.

The articles of this Constitution are not starting points for negotiation. They are the final word on what CoinCync is and what it can never become.

Any protocol that violates these articles is not CoinCync — regardless of what its developers call it, regardless of what exchanges list it, regardless of how much hash power backs it, and regardless of how many users it has. A chain that removes mandatory privacy is a different chain. A chain that raises the supply cap is a different chain. A chain that introduces a developer tax is a different chain.

Users, miners, and node operators are encouraged to identify such chains clearly and to continue running the original protocol.

The only legitimate evolution of CoinCync is one that honors every article of this Constitution in full, strengthens the protections it describes, and leaves its foundations untouched.

**Enforcement:** Enforced by every node on the network and by the community's right and responsibility to fork.

---

## Closing Statement

These ten articles were written because code without principles is just software — and software without principles serves whoever controls it.

CoinCync was built to serve its users. Not its developers. Not its investors. Not any government or institution. Its users — every person who runs a node, mines a block, sends a transaction, or simply holds CYNC in a wallet on a device in their pocket.

Financial privacy is not a luxury. It is not a feature for criminals. It is the condition under which free people conduct their lives without accounting for themselves to institutions that did not earn that accounting. It is the difference between a tool that serves you and a tool that reports on you.

CoinCync exists because that difference matters. This Constitution exists to make sure it always will.

*These are not just words. They are compiled into every node, verified by every miner, and enforced by mathematics. No person, committee, or future version of this project can undo what is written here.*

*CoinCync serves its users. No one else.*

---

**Ratified at Block 0. Permanent thereafter.**

---

## Constitutional Foundation — The Fourth Amendment

> *"The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated, and no Warrants shall issue, but upon probable cause, supported by Oath or affirmation, and particularly describing the place to be searched, and the persons or things to be seized."*
>
> — Fourth Amendment to the United States Constitution (1791)

CoinCync recognizes financial records as "papers and effects" protected by this fundamental right. Every technical decision in this protocol — mandatory stealth addresses, ring signatures, Pedersen commitments, Bulletproofs+ range proofs, Dandelion++ propagation, encrypted memos, and uniform decoy selection — is an engineering implementation of this constitutional protection.

Statistical deanonymization of ring signatures, chain analysis of transaction graphs, and network traffic fingerprinting are modern forms of unreasonable search. CoinCync's privacy features are not obstacles to law enforcement — they are the default state of financial privacy that existed before the digital age made mass surveillance trivial.

Users retain the right to voluntarily disclose their financial activity via time-scoped view keys — transparency by consent, not by design flaw.

---

*Companion document: [Bill of Rights](docs/BILL_OF_RIGHTS.md) — the user-facing rights guarantee that complements these operator-facing articles.*
