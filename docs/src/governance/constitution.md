# Constitution

**The Supreme and Permanent Law of the CoinCync Protocol**

**Version:** 1.0
**Ratified:** Block 0 (Genesis)
**Network:** CoinCync Mainnet

The authoritative source is [`CONSTITUTION.md`](https://github.com/CyncDevelopment/Cync-Protocol/blob/main/CONSTITUTION.md) at the repository root. This page reproduces it in full and adds, below each article, a **code-enforcement** note pointing at the exact source line where that article is mechanically enforced (where possible). **If this page ever drifts from the repository file, trust the repository file.**

See also the companion [Bill of Rights](./bill-of-rights.md) — the user-facing rights guarantee that complements these operator-facing articles.

---

## Preamble

This document defines the immutable principles of the CoinCync protocol. These are not guidelines. They are not aspirations. They are hard commitments — promises written into the code that no developer, committee, majority vote, legal order, or act of governance can override.

Any protocol change that violates this Constitution is invalid, regardless of how many people support it, how much proof of work backs it, or who proposes it.

This Constitution was written once. It will not be rewritten. It exists not because we distrust the people building CoinCync today — but because we cannot know who will be building it tomorrow. These principles protect users from every possible future, including futures we cannot predict.

Ten articles follow. Each one is a wall. None of them have doors.

---

## Article I — Fixed Supply

The total supply of CYNC shall never exceed **250,000,000** coins. This limit is absolute. It is not subject to amendment, emergency override, governance vote, or any other mechanism.

The emission schedule is defined in code and enforced by every node on the network. No entity — no developer, no foundation, no majority of miners — can create coins beyond this limit. The network itself will reject any block that does.

A tail emission exists to sustain mining security after the primary distribution ends. It is not additional supply. The 250,000,000 coin cap is absolute and includes all tail emission across the full lifetime of the chain. The tail emission rate shall not exceed a level that would cause total supply to approach the cap before the theoretical end of the emission schedule.

Anyone can verify the current supply at any time using the Pedersen commitment accumulator built into every node. If the mathematics do not confirm the supply, the chain is invalid. Trust the math, not the announcement.

**Enforcement:** Protocol-enforced. Every node independently validates supply on every block.

**Code enforcement:** Compile-time assertions in `src/constants.rs`:

```rust
const _: () = assert!(TOTAL_SUPPLY_TARGET == 250_000_000,
    "UNCONSTITUTIONAL: Article I — Supply cap must be exactly 250,000,000 CYNC");
const _: () = assert!(MAX_SUPPLY == 250_000_000u128 * COIN as u128,
    "UNCONSTITUTIONAL: Article I — MAX_SUPPLY atomic-unit value must match 250M cap");
```

Any attempt to ship a binary with a different cap fails the build. See [Emission curve](../protocol/emission.md) for the exact mountain curve that stays below the cap across the chain's lifetime.

---

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

**Code enforcement:** `src/constants.rs`:

```rust
pub const DEV_TAX_PERCENT: u64 = 0;
const _: () = assert!(DEV_TAX_PERCENT == 0,
    "UNCONSTITUTIONAL: Article II — Dev tax must be zero. No fee extraction to developers.");
```

The genesis coinbase is deliberately unspendable — the spend key is the all-zero key, which no one holds.

---

## Article III — Mandatory Privacy

All transactions on CoinCync are private. There is no transparent mode. There is no opt-in privacy tier. There is no reduced-privacy transaction class. Every transaction, without exception, uses the full privacy stack:

- **Ring signatures** to conceal the sender among a set of cryptographic decoys
- **Stealth addresses** to generate one-time destinations that cannot be linked to any public address
- **Pedersen commitments** to hide transaction amounts from all observers
- **Bulletproofs** to prove that amounts are valid without revealing them

Privacy is not a feature that can be toggled, deprecated, or made optional. It is the default and only state of every coin, every transaction, and every block on CoinCync.

No protocol change shall ever create a class of transactions with weaker privacy guarantees than those described above. Privacy may be strengthened through technical advancement. It may never be weakened.

**Enforcement:** Protocol-enforced. Ring signatures, stealth addresses, and Bulletproofs are required for all transactions.

**Code enforcement:** `src/constants.rs` + `src/consensus/privacy_policy.rs`:

```rust
const _: () = assert!(MIN_RING_SIZE >= 11,
    "UNCONSTITUTIONAL: Article III — Minimum ring size must be >= 11 for mandatory privacy");
```

`enforce_privacy_policy` in `src/consensus/privacy_policy.rs` rejects any block containing a transparent transaction, at the consensus-validation layer — before the block is relayed, added to the mempool, or applied to state. See [Privacy model](../protocol/privacy-model.md) for the full implementation.

---

## Article IV — Auditable Integrity

Despite mandatory privacy, anyone can mathematically verify — without trusting any third party — that:

1. No coins were created outside the emission schedule
2. No transaction created coins from nothing
3. No double-spend has ever occurred on the chain
4. The total supply at any block height matches the expected emission

This is achieved through the Pedersen commitment accumulator — a cryptographic structure embedded in every node that proves supply integrity without revealing individual transaction amounts. Every node validates this accumulator on every block. A block that fails this check is rejected by the entire network.

Privacy and auditability are not in conflict. CoinCync proves both simultaneously. This is the answer to every critic who says privacy coins cannot be trusted. The math is open. Anyone can check it.

**Enforcement:** Protocol-enforced. Pedersen accumulator validated on every block by every node.

**Code enforcement:** Bulletproofs+ range proofs ( `bulletproofs` / `tari_bulletproofs_plus` crates) enforce amounts ≥ 0 and ≤ `2^64`, mathematically preventing hidden inflation. The Pedersen commitment math in `src/crypto/` + `src/consensus/validation.rs` is what allows every node to verify total supply without seeing individual amounts.

---

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

**Code enforcement:** `PowAlgorithm` in `src/consensus/pow.rs` is a single-variant enum. `compute_pow_hash` dispatches only to `compute_randomx_hash`. `src/constants.rs` asserts `RANDOMX_ONLY = true` at compile time. Shipping a binary that uses a different algorithm requires deliberately editing three consensus-critical files, which `critical_files.lock` + `build.rs` hash verification catches before the build completes.

**Why RandomX and not multi-algorithm rotation:**

The argument for multi-algorithm rotation is that diversifying across algorithms neutralizes an ASIC advantage in any single one. The argument fails on three grounds:

1. **It reduces security to the weakest algorithm.** A rotation including Blake3 is only ASIC-resistant 2/3 of the time. Every third block is trivially ASIC-mineable, which gives well-resourced adversaries a cheap lever to concentrate hashrate and chain-reorg history.
2. **It expands attack surface.** Per-algorithm difficulty tracking, cross-algorithm reorg rules, and algorithm-specific validation code all add lines to the verifier. Each line is a potential bug. Multi-algorithm privacy coins (Verge, Bitcoin Gold) have a documented history of consensus exploits enabled by exactly this complexity.
3. **The precedent is RandomX alone.** Monero has held ASIC resistance under RandomX-only for five years with no consensus-level exploits and no concentration events attributable to algorithm choice. It is the most thoroughly battle-tested CPU-only design in existence.

RandomX alone is not a compromise. It is the correct choice.

See [Consensus & PoW](../protocol/consensus.md) for the implementation details.

---

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

**Code enforcement:** View keys live in `src/crypto/view_keys.rs`. They are generated by the wallet holder, stored on the user's device, and never transmitted to any party by protocol code. No RPC method, no P2P message, no consensus rule asks for or accepts a view key — disclosure is entirely an out-of-band, user-initiated action outside the network.

---

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

**Code enforcement:** No identity checks exist anywhere in the connection handshake (`src/network/`) or block validation path (`src/consensus/validation.rs`). The node accepts any peer that speaks the P2P protocol and any block that satisfies the cryptographic consensus rules. Running a node requires no account, no registration, no API key, no geographic check.

---

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

**Code enforcement:** BIP9-style fork signaling lives in `src/consensus/fork_signal.rs`. A CIP activates when ≥ `SIGNAL_THRESHOLD` (1814 of 2016 blocks, ≈ 90%) in a `SIGNAL_WINDOW` (2016 blocks) signal its bit. Pending CIPs are listed in `constants.rs`; the table below reflects the current signal-bit assignments.

| CIP | Bit | Name | What it does |
|---|---|---|---|
| CIP-001 | 0 | view-tags | Faster wallet scanning via 1-byte view tags |
| CIP-002 | 1 | ring-size-16 | Increase minimum ring size from 11 → 16 |
| CIP-003 | 2 | fee-market-v2 | Improved fee estimation |
| CIP-004 | 3 | halo2-shielded | Halo2 shielded pool (Zcash Orchard style) |
| CIP-005 | 4 | lelantus-spark | Lelantus Spark large-anonymity-set pool |
| CIP-006 | 5 | mw-cutthrough | MimbleWimble cut-through |

Constitutional invariants are not CIPs and cannot be changed by signaling. A CIP that proposes raising the supply cap, removing mandatory privacy, weakening the ring-size floor, introducing a developer tax, or adding surveillance hooks is unconstitutional on its face — the constitutional guard asserts in `constants.rs` would fail to compile.

---

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

**Code enforcement:** Multiple compile-time guards in `src/constants.rs`:

```rust
pub const ADDRESS_BLACKLIST_ENABLED: bool = false;
const _: () = assert!(!ADDRESS_BLACKLIST_ENABLED,
    "UNCONSTITUTIONAL: Bill of Rights IV & X — No address blacklisting or transaction censorship");

pub const TX_CENSORSHIP_ENABLED: bool = false;
const _: () = assert!(!TX_CENSORSHIP_ENABLED,
    "UNCONSTITUTIONAL: Bill of Rights X — Transaction censorship is permanently prohibited");
```

Dandelion++ stem-and-fluff relay is implemented in `src/network/dandelion.rs`. Encrypted P2P is provided by the Noise framework (`snow` crate) wired into the peer handshake in `src/network/`.

---

## Article X — Immutability

This Constitution is permanent.

It cannot be amended. It cannot be repealed. It cannot be superseded by any governance process, community vote, developer decision, legal order, court ruling, regulatory requirement, or supermajority of any kind. There is no emergency provision. There is no sunset clause. There is no mechanism by which these articles can be weakened, suspended, or removed.

The articles of this Constitution are not starting points for negotiation. They are the final word on what CoinCync is and what it can never become.

Any protocol that violates these articles is not CoinCync — regardless of what its developers call it, regardless of what exchanges list it, regardless of how much hash power backs it, and regardless of how many users it has. A chain that removes mandatory privacy is a different chain. A chain that raises the supply cap is a different chain. A chain that introduces a developer tax is a different chain.

Users, miners, and node operators are encouraged to identify such chains clearly and to continue running the original protocol.

The only legitimate evolution of CoinCync is one that honors every article of this Constitution in full, strengthens the protections it describes, and leaves its foundations untouched.

**Enforcement:** Enforced by every node on the network and by the community's right and responsibility to fork.

**Code enforcement:** Every article above that can be expressed as a compile-time or runtime check is backed by assertions in `src/constants.rs` tagged `"UNCONSTITUTIONAL: Article N"`. Shipping a binary that violates any of them requires deliberately removing the assertion — a change that cannot happen silently because it's in the repository's most-watched file.

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

## What you can do if a constitutional article is violated

Constitutional violations are, by definition, consensus-incompatible: any node enforcing the constitution rejects blocks that violate it. The chain that violates the constitution is not CoinCync — it's a fork.

If a malicious release ever ships that violates a constitutional article, the recovery procedure is:

1. **Don't upgrade.** The old binary is still valid; it just won't follow the malicious chain.
2. **Coordinate via out-of-band channels** to identify the violation and the responsible release.
3. **Fork the project**, rebuild from a known-good commit, and continue under a new release.

The constitution is your defense against your own future maintainers being wrong, captured, or compromised. Treat it accordingly.

## See also

- [`CONSTITUTION.md`](https://github.com/CyncDevelopment/Cync-Protocol/blob/main/CONSTITUTION.md) — the authoritative source at the repository root
- [Bill of Rights](./bill-of-rights.md) — the user-facing rights complement
- [Disclaimer](./disclaimer.md) — what the project does and doesn't promise
- [Emission curve](../protocol/emission.md) — the mountain curve that honors Article I
- [Privacy model](../protocol/privacy-model.md) — the implementation of Article III
- [Consensus & PoW](../protocol/consensus.md) — the implementation status of Article V
