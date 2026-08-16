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

The articles that follow are the operative law. Each one is a wall. None of them have doors. Future articles may be added only when they strengthen these foundations and never to weaken them, in accordance with Article XV.

---

## Threat Model

This Constitution defines protections against the following adversary classes. Naming them explicitly bounds what "privacy," "sovereignty," and "permissionless" mean in operative terms and prevents future debate over whether a given protection is in scope.

- **Chain analysts** — blockchain forensics firms, surveillance contractors, and entities that correlate on-chain data with off-chain identity. Defended primarily by Articles III, IX, XIV.
- **State-level adversaries** — governments seeking to compel transaction visibility, identify users, freeze funds, or compel protocol changes. Defended by Articles III, VI, IX, XII.
- **Capture by maintainers** — present or future contributors who attempt to introduce backdoors, dev taxes, admin keys, or governance capture. Defended by Articles II, VIII, X, XII, XVIII.
- **Economic capture** — entities attempting to influence consensus through coin holdings, exchange listings, hash-rate concentration, or financial pressure on contributors. Defended by Articles V, VIII, XI.
- **External-system dependencies** — bridges, oracles, wrapped assets, or hybrid protocols that could import trust from systems CoinCync does not control. Defended by Article XIII.
- **Network-level fingerprinting** — observers attempting to identify transaction originators through traffic analysis below the protocol layer. Defended by Article IX (Dandelion++ and encrypted P2P).

Adversary classes explicitly **out of scope** — this Constitution cannot defend against them, and any protocol change premised on defending against them is reaching beyond the scope of these articles:

- **User-side operational-security failures** — lost keys, malware on the user's device, weak passwords, social-engineering of the user. The protocol cannot defend across the user's own threat boundary.
- **Legal compulsion of an individual user** — court orders directing a specific person to disclose their view keys. Article VI provides voluntary disclosure tools; the protocol cannot prevent a user from being legally compelled to invoke them.
- **Network-layer censorship below the protocol** — ISP blocking, DNS censorship, geo-blocking of access. Article VII guarantees permissionless participation at the protocol level; circumvention (Tor, I2P, VPN) is a user-side concern, not a protocol guarantee.

---

## Article I — Fixed Supply

**100,000,000 CYNC is the asymptote of the issuance curve — not a hard cap.** The curve approaches 100,000,000 but never reaches it on its own; the perpetual tail emission (below) then continues, so total *emitted* supply grows past 100,000,000 over the long term. What is immutable is the emission *function itself* — not subject to amendment, emergency override, governance vote, or any other mechanism.

The emission is determined by one formula: `reward = max(0.6 CYNC, (100M - already_mined) / 2,000,000)`. No eras. No halvings. Every coin mined makes the next one slightly harder to earn. The network itself will reject any block that violates this formula.

A tail emission of 0.6 CYNC per block exists to sustain mining security perpetually. A 30% fee burn destroys part of every transaction fee, offsetting the tail; whether net circulating supply stabilizes near, below, or above 100,000,000 depends on long-term fee volume — it is deterministic and fully public either way, never a hidden or discretionary quantity. CoinCync's guarantee is not a fixed coin count; it is a fixed, transparent, verifiable emission schedule.

Anyone can verify the current supply at any time: coinbase issuance is transparent (zero blinding) and consensus-checked to equal the schedule on every block, every transaction is proven to balance, and every ring member references a real prior output — so total supply provably equals the summed deterministic emission. Recompute it independently (from the emission parameters, or the `get_supply_info` / `/api/v1/emission` endpoints) and compare. If the mathematics do not confirm the supply, the chain is invalid. Trust the math, not the announcement.

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

This is achieved not by trusting anyone, but by the structure of the protocol itself: coinbase outputs are transparent (zero blinding factor), so every block's newly minted supply is public and is checked to equal the scheduled emission exactly; every transaction is cryptographically proven to balance (inputs = outputs + fee) via Pedersen commitments and Bulletproofs+ range proofs, so no transaction can create value; and every ring member must reference a real prior on-chain output, so an input cannot be fabricated. Together these make the total supply at any height provably equal to the summed deterministic emission — recomputable by anyone (from the published emission parameters, or the `get_supply_info` / `/api/v1/emission` endpoints) and comparable against what any node reports. Any block violating these rules is rejected by the entire network. (A single-value per-block Pedersen supply-commitment accumulator is a planned enhancement; the guarantees above already prevent hidden inflation without it.)

Privacy and auditability are not in conflict. CoinCync proves both simultaneously. This is the answer to every critic who says privacy coins cannot be trusted. The math is open. Anyone can check it.

**Enforcement:** Protocol-enforced. Every node independently validates, on every block, the transparent coinbase amount, every transaction's balance + range proofs, and ring-member existence.

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
5. Constitutional amendments: permitted only under the narrow security-strengthening path defined in Article XVII; otherwise prohibited

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

This Constitution is permanent in its principles and modifiable only under the narrow security-strengthening path defined in Article XVII. No other amendment, repeal, or suspension mechanism exists. The articles cannot be weakened by any governance process, community vote, developer decision, legal order, court ruling, regulatory requirement, or supermajority of any kind.

The articles of this Constitution are not starting points for negotiation. They are the final word on what CoinCync is and what it can never become.

A protocol that violates these articles is not CoinCync — regardless of what its developers call it, regardless of what exchanges list it, regardless of how much hash power backs it, and regardless of how many users it has. A chain that removes mandatory privacy is a different chain. A chain that raises the supply cap is a different chain. A chain that introduces a developer tax is a different chain.

The only legitimate evolution of CoinCync is one that honors every article of this Constitution in full, strengthens the protections it describes via Article XVII, and leaves the foundations untouched. Users, miners, and node operators are encouraged to identify chains that violate these articles clearly and to continue running the original protocol.

**Enforcement:** Enforced by every node on the network and by the community's right and responsibility to fork.

## Article XI — No Algorithmic Capture

CYNC shall be created only by the Article I emission, and only by miners who present valid proof-of-work. No mechanism shall mint, redistribute, or subsidize CYNC in response to the price of any asset, the supply of any token, the demand for any product, or the holdings of any account. The mining reward is the only reward; the emission curve is the only schedule. Any mechanism that makes CYNC's value depend on the continued operation of another token system is forbidden.

**Enforcement:** Protocol-enforced. No mint pathway exists outside Article I. Compile-time guard `NO_ALGORITHMIC_PEG = true` in `src/constants.rs`.

## Article XII — No Admin Authority

No address, multisig, contract, off-chain entity, or maintainer shall hold protocol-level authority to mint, freeze, seize, redirect, or invalidate any user's funds. No emergency override, pause mechanism, kill switch, or upgrade gate shall ever exist. Protocol changes occur exclusively through the Article VIII CIP process and node-operator opt-in. The protocol has participants and the math; it has no admins.

**Enforcement:** Protocol-enforced. No `admin`, `pauser`, `freezer`, or chain-controlling-multisig concept exists in the codebase. Compile-time guard `NO_ADMIN_KEYS = true` in `src/constants.rs`.

## Article XIII — No External Trust

Consensus shall depend exclusively on state proven within CoinCync itself. No external chain proof, oracle input, wrapped asset, IOU, or off-chain attestation shall ever be admitted into block validity. CoinCync is sovereign over its own state; any mechanism that imports trust from another system, by any name, is forbidden. CYNC is real because the chain says so, and the chain says so without asking anyone else.

**Enforcement:** Protocol-enforced. Validation operates only on locally-derivable state. Compile-time guard `NO_EXTERNAL_BRIDGES = true` in `src/constants.rs`.

## Article XIV — No Surveillance Layer

All CYNC is fungible. No protocol mechanism shall distinguish one CYNC from another by origin, history, age, ownership, or any external attribute. No layer that identifies, classifies, attests to, or labels participants in any transaction shall exist within the protocol, except as required by the Article VI voluntary disclosure mechanism chosen by the user. Privacy and fungibility are inseparable; weakening either weakens both.

**Enforcement:** Protocol-enforced. All outputs are uniform commitments; no metadata layer exists. Compile-time guard `NO_SURVEILLANCE_LAYER = true` in `src/constants.rs`.

## Article XV — Spirit and Construction

This Constitution is read in the most user-protective, privacy-preserving construction available. Where the text is silent, any proposed protocol change must answer "is this consistent with the rights enumerated and the principles established?" — default-deny applies, and the burden falls on the proposer. A protocol change must demonstrate that it strengthens — not merely "does not weaken" — user privacy, self-custody, and chain sovereignty. Where two articles appear to conflict, the article more protective of the user prevails; the literal text and the underlying intent are construed together, and either alone is sufficient grounds to reject a change. This article governs how the Constitution is read; the Constitution itself remains permanent under Article X.

**Enforcement:** Community-enforced. Maintainers, reviewers, and node operators are bound to apply this construction when evaluating any change.

## Article XVI — Permanent Scarcity Through Burn

A floor of thirty percent of every transaction fee shall be permanently destroyed under normal network conditions, with the rate rising during congestion. The burn floors are protocol invariants, not tunable parameters. No mechanism may redirect, reduce, or exempt any portion of the burn to any address, fund, validator, or entity. Fees not burned are paid to miners as proof-of-work reward; no third destination is permitted.

**Enforcement:** Protocol-enforced. Compile-time guards on `FEE_BURN_NORMAL_PERCENT` and `FEE_BURN_CONGESTED_PERCENT` in `src/constants.rs` ensure both the 30% normal-condition floor and the congested-rate-not-below-normal invariant.

## Article XVII — Security Strengthening Exception

A protocol change that strictly strengthens user privacy, self-custody, supply integrity, or chain sovereignty in response to a discovered cryptographic flaw, consensus bug, or security vulnerability is not an amendment within the meaning of Article X — it is maintenance of the protections this Constitution exists to provide. Such a change must measurably strengthen at least one user protection without weakening any other, follow Article VIII CIP discipline, and obtain node-operator consensus through the hard-fork process. The bar is high; the path exists.

**Enforcement:** Community-enforced. Each invocation must show, in the proposing CIP, exactly which protection strengthens and that no other weakens.

## Article XVIII — Interpretive Authority

No maintainer, contributor, foundation, or other entity holds authoritative interpretive power over this Constitution. Where a question of interpretation arises, the answer is settled by node operator consensus through fork-acceptance — the same mechanism that decides any protocol change. The Constitutional Commentary records reasoning but does not bind interpretation; it is documentation, not law.

**Enforcement:** Community-enforced. Node operators may reject any change whose constitutional interpretation they disagree with by refusing to upgrade.

## Article XIX — Properties, Not Promises

This Constitution describes the technical properties of the CoinCync protocol — what the code does, and what it will never do. It is not a contract, warranty, or commercial promise made to any user, holder, or third party. The protocol's properties are enforced by the code and by the network of node operators who choose to run it; no individual or entity warrants any specific outcome from interacting with the network. Any person using CoinCync does so under the MIT license's express disclaimer of warranty.

**Enforcement:** Legal framing. The MIT license under which all CoinCync code is released disclaims warranty in all jurisdictions where such disclaimers are recognized.

---

## Closing Statement

These articles were written because code without principles is just software — and software without principles serves whoever controls it. CoinCync was built to serve its users: every person who runs a node, mines a block, sends a transaction, or holds CYNC in a wallet on a device in their pocket. Financial privacy is the condition under which free people conduct their lives without accounting for themselves to institutions that did not earn that accounting. CoinCync exists because that difference matters, and this Constitution exists to make sure it always will.

*These are not just words. They are compiled into every node, verified by every miner, and enforced by mathematics. No person, committee, or future version of this project can undo what is written here.*

---

**Ratified at Block 0. Permanent thereafter.**

---

*Companion document: [Bill of Rights](docs/BILL_OF_RIGHTS.md) — the user-facing rights guarantee that complements these operator-facing articles.*
