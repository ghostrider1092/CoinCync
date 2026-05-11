<!-- markdownlint-disable MD036 -->
# CoinCync Public Testnet Launch — Announcement Drafts

**Status:** drafts. Soak verdict landed on 2026-05-07 — chain stable across all 5 boxes, GO for launch (see [v1.0.2-testnet-soak-summary.md](v1.0.2-testnet-soak-summary.md)). Canonical source repo lives at `git.coincync.network/coincync/cync-protocol` (self-hosted Forgejo; replaces the now-suspended GitHub mirror).

This file holds three formats for the same announcement:

1. **Long form** — website blog post / launch page hero copy
2. **Discord** — community-channel-friendly version (under embed limits)
3. **Short social** — X / Mastodon / Nostr threads

Pick one or use all three depending on where you're posting. Edit freely; the goal is correctness not pristine drafts.

---

## 1. Long Form — Website / Blog

**Title:** *CoinCync Public Testnet Is Live*

**Subtitle:** *A privacy-first, proof-of-work payments coin. RandomX. CLSAG ring signatures. Stealth addresses. 100M hard cap. 30% fee burn. Zero pre-mine. Zero developer tax.*

---

### What launched

CoinCync's public testnet is live. Anyone can now connect a node, mine blocks with their CPU, send and receive private transactions, run an explorer, or build wallets and infrastructure on top of the network. Testnet coins have zero monetary value — this is a working network for testing, not a market.

The fleet that hosts the public testnet has been running continuously for weeks. Five nodes (three seeds, one explorer, one public API) producing blocks every two minutes on the testnet target. As of this announcement: block height 4275+, network hashrate ~250 H/s, all five nodes synced.

A 72-hour pre-launch soak completed cleanly: 864 sample-points per box across the full window, all five boxes converging at heights `4273-4275`. One operational incident was captured and recovered during the window — a peer wedge on the explorer node — diagnosed, fixed mid-soak, and verified live (no recurrence in the post-fix observation window). The soak data tells a real story rather than a clean-room one.

### What CoinCync is

- **Mandatory privacy.** Every transaction uses ring signatures, stealth addresses, Pedersen commitments, and Bulletproofs+. There is no transparent mode. There is no opt-in privacy tier. There is no reduced-privacy transaction class.
- **CPU mining via RandomX.** No GPU advantage. No ASIC advantage. Anyone with a laptop CPU can mine and meaningfully contribute to network security.
- **Hard cap of 100,000,000 CYNC.** The emission curve is asymptotic and locked at the protocol level. No mechanism exists to raise this.
- **30% of every transaction fee burned permanently.** Captured by no one. Combined with the asymptotic cap, this makes CYNC structurally deflationary at any sustained level of network usage. Fees not burned go to miners as proof-of-work reward — no third destination is permitted.
- **Zero pre-mine. Zero developer tax. Zero foundation.** Every CYNC in existence was mined by someone who contributed proof-of-work to the network. No developer fund, no protocol-level treasury, no governance token.

### Constitutionally bound

CoinCync ships with a Constitution that is not marketing copy. The articles are compile-time enforced where possible — any future change that violates the Articles by silently flipping a constant fails the build with a clear `UNCONSTITUTIONAL: Article X` error. The articles forbid the entire categories of failure that have killed other privacy coins: algorithmic stablecoins, admin keys, cross-chain bridges, surveillance metadata, fee redirects to any party.

A Bill of Rights companions the Constitution and translates the operator-facing articles into user-facing guarantees. Both documents are versioned in the repository, hash-locked against silent edits, and explicitly framed as describing the *technical properties of the protocol* — not as commercial promises that could create implied-warranty liability.

This is the same model Bitcoin's fixed-supply commitment and Monero's permissionless-mining ethos have used for over a decade. We just made it explicit and compile-time-enforced rather than implicit and norm-enforced.

### Why testnet matters

A testnet exists to break things on purpose, in public, with no money at risk. We expect rough edges. We expect bugs. We expect node operators to discover failure modes the soak didn't capture. That's the whole point.

The most valuable thing you can do during testnet:

- **Run a node.** Even a single home node strengthens the testnet's geographic distribution and helps surface the synchronization issues that only show up in real-world network conditions.
- **Mine.** Even a few hours of CPU time. It validates the mining flow, exercises the CLSAG signature path, and gives us real-world hashrate data for difficulty tuning.
- **Send transactions.** The wallet ships with everything needed to send and receive testnet CYNC. Stress-test the privacy primitives by actually using them.
- **Report bugs.** Anything weird, anything slow, anything wrong — file it. Discord `#bugs` for non-security issues; `security@coincync.network` for anything that touches consensus or privacy.

### What testnet is not

- **Not a market.** Testnet coins have zero monetary value and never will. Anyone trading them is wasting their time.
- **Not stable.** Network resets are possible. Protocol parameters may change before mainnet. Wallets and nodes may need to be reinstalled. Don't put real money or trust into testnet operations.
- **Not feature-complete.** Atomic swaps to Bitcoin are committed as a v1.0 mainnet launch blocker — they are not implemented in testnet. The skeleton crate (`coincync-swap`) and design spec (CIP-001) are public; implementation is in progress.

### Mainnet timeline

Mainnet is months out, not weeks. Before it ships:

- A working CYNC↔BTC atomic swap with cryptographic review and a bug bounty round
- A formal third-party audit of the consensus and privacy stack
- Multi-maintainer release infrastructure (M-of-N signing, reproducible builds)
- A meaningful operational track record on testnet

The Constitution's commitments do not depend on audit completion — they are real today. The mainnet timeline depends on getting the audit-and-implementation work right, not fast.

### Get involved

- **Get a wallet + first tCYNC:** [coincync.network](https://coincync.network) — download the desktop wallet, then claim 10 tCYNC from the public faucet at [coincync.network/faucet](https://coincync.network/faucet). One drip per address per hour.
- **Mine:** [coincync.network](https://coincync.network) Get-Started section. RandomX, CPU only, runs on any machine.
- **Run a node:** clone `git.coincync.network/coincync/cync-protocol`, build, point at a seed, sync. Build instructions: [docs.coincync.network/getting-started/build](https://docs.coincync.network/getting-started/build).
- **Read the Constitution:** [docs.coincync.network/governance/constitution](https://docs.coincync.network/governance/constitution) — ten minutes. The articles are short by design.
- **Read the Bill of Rights:** [docs.coincync.network/governance/bill-of-rights](https://docs.coincync.network/governance/bill-of-rights).
- **Discord:** [discord.gg/5tYNSCsqzy](https://discord.gg/5tYNSCsqzy).
- **Block explorer:** [explorer.coincync.network](https://explorer.coincync.network).

CoinCync is what privacy-first money looks like when nobody is selling you anything. Welcome.

---

## 2. Discord — `#announcements` Channel

```
🚀 CoinCync Public Testnet Is Live

Five nodes running. Block height 4275+. ~250 H/s of hashrate.
72h pre-launch soak passed: chain stable, all 5 boxes converged
within ±2 blocks. One known peer-wedge incident, fixed mid-soak.

WHAT YOU CAN DO RIGHT NOW
• Get a wallet + free tCYNC — coincync.network → Download Wallet,
  then coincync.network/faucet for 10 tCYNC (1 drip / hour)
• Mine — RandomX, CPU only, no GPU/ASIC advantage
• Send and receive private transactions — every tx uses ring
  signatures + stealth addresses
• Run an explorer / build a wallet / break things on purpose

WHAT TESTNET IS NOT
• Not a market — testnet CYNC has zero monetary value
• Not stable — resets and parameter changes are possible before mainnet
• Not feature-complete — atomic swaps + audit + signed mainnet release
  ship later

THE 30-SECOND VERSION
• 100M hard cap, asymptotic emission
• 30% of every fee burned permanently — captured by no one
• Zero pre-mine, zero dev tax, zero foundation
• RandomX CPU mining (no GPU/ASIC)
• Mandatory privacy on every tx (no opt-in transparent mode)
• Constitutionally locked — 19 articles + 15 rights, compile-time
  enforced

START HERE
💧 Faucet: coincync.network/faucet
🔧 Mine + wallet: coincync.network
🌐 Explorer: explorer.coincync.network
📜 Constitution: docs.coincync.network/governance/constitution
🛠️  Source: git.coincync.network/coincync/cync-protocol
🐛 Bugs: this channel #bugs (or security@coincync.network for vulns)

This is what privacy-first money looks like when nobody is selling
you anything. Welcome.
```

---

## 3. Short Social — X / Mastodon / Nostr

### Headline post (under 280 chars)

```
CoinCync public testnet is live.

100M hard cap. 30% of every fee burned permanently. Zero pre-mine.
Zero developer tax. RandomX CPU mining. Privacy on every transaction
by default — no opt-in transparent mode.

Constitution + Bill of Rights, compile-time enforced.

discord.gg/5tYNSCsqzy
```

### Thread (5 posts)

**1/**
```
CoinCync public testnet is live.

A privacy-first proof-of-work payments coin. Five nodes running.
72h pre-launch soak passed clean. Anyone can mine, transact, and
break things on purpose.

What's different about this one — thread.
```

**2/**
```
2/ Privacy is not opt-in.

Every transaction uses ring signatures + stealth addresses + Pedersen
commitments + Bulletproofs+. There is no transparent mode. There is
no reduced-privacy class. The privacy stack is the only stack.
```

**3/**
```
3/ Hard supply cap, structural deflation.

100M coin asymptotic cap, locked at the protocol level. 30% of every
transaction fee permanently destroyed — captured by no one. No
developer fund, no foundation, no governance token. Zero pre-mine.
```

**4/**
```
4/ Constitutionally bound.

19 Articles + 15 Rights, compile-time enforced. Any future change
that violates an article fails the build with a labeled
UNCONSTITUTIONAL: Article X error. Stablecoins, admin keys,
bridges, NFTs, fee redirects — categorically forbidden.
```

**5/**
```
5/ Mainnet is months out.

What ships first: working CYNC↔BTC atomic swaps, third-party
audit of the consensus + privacy stack, M-of-N signed releases,
real testnet operational track record.

Until then — testnet. Real network, no real money.
discord.gg/5tYNSCsqzy
```

---

## 4. BitcoinTalk — ANN Thread (Altcoins)

**Forum:** Alternate cryptocurrencies → Announcements (Altcoins) — <https://bitcointalk.org/index.php?board=159.0>

**Subject:**

```
[ANN][CYNC] CoinCync — Privacy PoW | Constitution-Locked | Atomic-Swap Mainnet Blocker
```

**Post body (BBCode):**

```bbcode
[size=14pt][b]CoinCync — Privacy-First Proof-of-Work, Constitutionally Locked[/b][/size]

[size=11pt]Public testnet is live as of [b]2026-05-10[/b]. Mainnet target [b]2026-10-01[/b].
Built solo, MIT-licensed, no premine, no dev tax, no foundation, no token sale.[/size]

[hr]

[b]One-paragraph version[/b]

CoinCync is a privacy-first proof-of-work cryptocurrency in the Monero family. CLSAG-16 ring signatures, Bulletproofs+, stealth addresses, Pedersen commitments, RandomX CPU mining, Dandelion++. What's [i]different[/i] is the structural commitments: a written 19-Article Constitution + 15-Right Bill of Rights, compile-time enforced via SHA-256 file-hash tripwires + 8 tripwire constants in src/constants.rs. Categorically forbidden by the chain itself: algorithmic stablecoins, admin keys, bridges, NFTs, fee redirects, dev taxes. Mainnet ships when CYNC↔BTC atomic swaps work end-to-end (Article XIV).

[hr]

[b]Specifications[/b]
[code]
Network type      : Privacy-by-default, mandatory shielding
Mining algorithm  : RandomX (CPU only — no GPU/ASIC advantage)
Block time target : 120 s
Hard supply cap   : 100,000,000 CYNC (asymptotic)
Atomic units/CYNC : 10^12
Genesis reward    : ~50 CYNC
Tail emission     : 0.6 CYNC/block (perpetual)
Fee burn          : 30% normal | 50% congested
Dev tax           : 0%
Premine           : 0
Foundation        : none
Ring size         : CLSAG-16 (11→16 bootstrap ramp at block 10,000)
Address prefix    : tCYNC (testnet) | CYNC (mainnet)
Genesis hash      : 41f970df6152425a2938725423235c2c40ec52556ecc0fd1422d588652cc56b4
[/code]

[b]Privacy stack[/b]

[list]
[li]CLSAG-16 ring signatures — sender hidden among 16 outputs[/li]
[li]Bulletproofs+ — amount hidden, range-proven[/li]
[li]Stealth addresses — receiver hidden, one-time pubkey per output[/li]
[li]Pedersen commitments — value commitments balance to fee-only[/li]
[li]Dandelion++ — IP/origin hidden during propagation[/li]
[li]FROST hidden multi-sig — multi-sig indistinguishable from single-sig[/li]
[li]Encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead-man's switch, auto-churn — 7 advanced privacy features beyond the Monero baseline[/li]
[/list]

[b]Operational status (live as of post)[/b]

[list]
[li]5-node fleet across 3 continents (US-East / Europe / Asia-Pacific)[/li]
[li]Block height: 4275+[/li]
[li]Network hashrate: ~250 H/s[/li]
[li]Public testnet faucet: 10 tCYNC, 1 drip per address per hour, no signup[/li]
[li]72h pre-launch soak completed 2026-05-07: chain stable across all 5 boxes (864 sample-points each, tip convergence ±2 blocks)[/li]
[/list]

[b]Build from source[/b]

[code]
git clone https://git.coincync.network/coincync/cync-protocol
cd cync-protocol
cargo build --release --features "randomx testnet"
./target/release/coincync-node --network testnet
[/code]

Tested on Linux x86_64, macOS arm64/x86_64, Windows MSVC. Rust 1.75+.

[b]Quick links[/b]

[list]
[li][b]Source code:[/b] [url=https://git.coincync.network/coincync/cync-protocol]git.coincync.network/coincync/cync-protocol[/url][/li]
[li][b]Whitepaper / docs:[/b] [url=https://docs.coincync.network/introduction]docs.coincync.network[/url][/li]
[li][b]Block explorer:[/b] [url=https://explorer.coincync.network]explorer.coincync.network[/url][/li]
[li][b]Faucet (10 tCYNC, free):[/b] [url=https://coincync.network/faucet]coincync.network/faucet[/url][/li]
[li][b]Wallet download:[/b] [url=https://coincync.network/]coincync.network[/url][/li]
[li][b]Constitution:[/b] [url=https://docs.coincync.network/governance/constitution]docs.coincync.network/governance/constitution[/url][/li]
[li][b]Bill of Rights:[/b] [url=https://docs.coincync.network/governance/bill-of-rights]docs.coincync.network/governance/bill-of-rights[/url][/li]
[li][b]CIP-001 — Atomic Swap (mainnet blocker):[/b] [url=https://docs.coincync.network/cip/CIP-001-atomic-swap]CIP-001 spec[/url][/li]
[li][b]Discord:[/b] [url=https://discord.gg/5tYNSCsqzy]discord.gg/5tYNSCsqzy[/url][/li]
[/list]

[b]Mainnet roadmap[/b]

[list]
[li][b]2026-05-10[/b] — Public testnet (today)[/li]
[li][b]2026-05 → 2026-08[/b] — CIP-001 atomic-swap reference implementation, third-party audit kickoff[/li]
[li][b]2026-09[/b] — Mainnet release candidates, multi-maintainer signed-release infra (M-of-N)[/li]
[li][b]2026-10-01[/b] — Mainnet genesis (target)[/li]
[/list]

[b]No-trade ethics[/b]

Testnet coins have zero monetary value and never will. Anyone trading them is wasting their time. Mainnet CYNC has no presale, no IDO, no founders' allocation. Every CYNC in existence is mined by someone who contributed proof-of-work. The first miner gets ~50 CYNC at block 1; that's the entire genesis distribution.

[hr]

[b]Why I posted here[/b]

BitcoinTalk's altcoin ANN section is where serious crypto devs still go for the canonical thread on a project. I want this thread to be the permanent reference link the dev community can come back to as the testnet matures. Happy to answer technical questions in this thread; bug reports go on Discord (#bugs) or security@coincync.network for anything consensus-related.
```

---

## 5. r/CryptoCurrency

**Subreddit:** r/CryptoCurrency
**Flair:** Discussion (NOT News — News flair triggers shilling-detection)

**Title:**

```
CoinCync public testnet is live — privacy-first PoW with a written constitution and atomic-swap commitment
```

**Body (markdown):**

```markdown
CoinCync is a privacy-first proof-of-work cryptocurrency. Built solo, MIT-licensed, no premine, no developer tax, no foundation, no token sale. Public testnet went live today.

I'm posting here because the project has a few structural commitments I haven't seen done together before, and I want technical eyes on it before mainnet.

## What's different

**1. Written Constitution, compile-time enforced.** Most crypto projects have an implicit social contract. CoinCync has a 19-Article Constitution + 15-Right Bill of Rights checked into the repo. Critical files are SHA-256 hash-locked; 8 tripwire constants in `src/constants.rs` mean any future change that silently flips the rules — adding a dev tax, enabling an admin key, redirecting fees — fails the build with a labeled `UNCONSTITUTIONAL: Article X` error.

**2. Atomic-swap-to-BTC as a mainnet-launch blocker.** Article XIV says mainnet doesn't ship until CYNC↔BTC trustless atomic swaps work end-to-end. CIP-001 has the design spec; reference implementation is in progress. The point: every Bitcoin holder will be one transaction away from CYNC, so when CEXes inevitably delist (the privacy-coin pattern), the network has its own on-ramp built in.

**3. FROST hidden multi-sig.** Monero has multisig but observers can detect it from transaction structure. CoinCync uses FROST signature aggregation so a 7-of-10 multisig is indistinguishable on-chain from a normal 1-of-1 signature.

The rest of the privacy stack is the Monero family standard: CLSAG-16 ring signatures, Bulletproofs+ range proofs, stealth addresses, Pedersen commitments, Dandelion++ propagation, RandomX CPU mining.

## Try it in 5 minutes

1. Download the wallet from [coincync.network](https://coincync.network)
2. Click "Faucet" → paste your address → 10 tCYNC arrives in ~30s
3. Send your first private transaction

The faucet is at [coincync.network/faucet](https://coincync.network/faucet), 10 tCYNC per address per hour. No signup. Code is live, no marketing wrapper.

## Status

- 5-node fleet across 3 continents (US-East / Europe / Asia-Pacific)
- Block height 4275+, ~250 H/s network hashrate
- 72h pre-launch soak just completed: chain stable across all 5 boxes, all converged within ±2 blocks
- Mainnet target: 2026-10-01

## Links

- **Source code:** git.coincync.network/coincync/cync-protocol (MIT)
- **Whitepaper / docs:** docs.coincync.network
- **Constitution:** docs.coincync.network/governance/constitution (10 minutes to read; the Articles are short by design)
- **Block explorer:** explorer.coincync.network
- **Discord:** discord.gg/5tYNSCsqzy

## What testnet is NOT

Testnet coins have zero monetary value. This is a working network for testing, not a market. Anyone trading testnet CYNC is wasting their time. There's no presale, no IDO, no roadmap-launch-token-bullshit. Every CYNC in existence will be mined by someone who contributed proof-of-work.

Happy to answer technical questions. Be in the comments for the next 48 hours.
```

---

## 6. r/Monero — Day 2-3 (NOT Day 0)

**Subreddit:** r/Monero
**Strategy note:** post Wednesday or Thursday, after r/CryptoCurrency + BitcoinTalk + HN have ~48h of activity to point at. r/Monero readers want external traction signals before engaging.

**Title:**

```
CoinCync: a privacy PoW chain that uses Monero's primitives, with a written Constitution and atomic-swap-to-BTC as a mainnet-launch blocker
```

**Body (markdown):**

```markdown
I want to be upfront: CoinCync uses Monero's privacy primitives. CLSAG ring signatures, Bulletproofs+, stealth addresses, Pedersen commitments, RandomX, Dandelion++. I'm posting here because Monero is the foundation we built on, and I want this community's eyes on what we did differently — not on what we kept the same.

Public testnet has been running for 48+ hours; soak summary is at the link below. About 250 H/s network hashrate, 5-node bootstrap fleet across NJ, Amsterdam, and Tokyo, faucet drips work, anyone can run a node.

## What's NEW (not the Monero stack)

**1. Written Constitution, compile-time enforced.** A 19-Article Constitution + 15-Right Bill of Rights, with critical files hash-locked and 8 tripwire constants in `src/constants.rs`. Articles forbid the categories of failure that have killed other privacy coins: algorithmic stablecoins, admin keys, bridges, fee redirects, dev taxes, governance tokens. Any future change that violates an Article fails the build with `UNCONSTITUTIONAL: Article X`. Monero does this through social consensus; CoinCync codifies it.

**2. Atomic-swap-to-BTC as the mainnet-launch blocker.** Article XIV: mainnet doesn't ship until CYNC↔BTC trustless atomic swaps work. CIP-001 spec is published. The point is structural: when CEX delistings come (and they will), every Bitcoin holder is one tx away from CYNC. Listing-independence as a protocol commitment, not a hope.

**3. FROST hidden multi-sig.** Monero's existing multisig is detectable from on-chain structure. FROST aggregates signatures so a 7-of-10 multisig is byte-equivalent to a normal 1-of-1 signature. Spends, sends, and recovery flows are indistinguishable. This is genuinely novel work for the Monero-style stack.

## Why CoinCync exists separately rather than as a Monero patch

Monero deliberately doesn't bind itself with constitutional commitments. Its values live in social consensus, which is correct for what Monero is. CoinCync is an experiment in whether *codified* values change the audit math, the credibility math, and the listing-independence math. That's not a critique of Monero — it's a question Monero leaves intentionally untested.

## Specs

- CLSAG-16 (11→16 bootstrap ramp at block 10,000)
- Bulletproofs+, stealth addresses, Pedersen commitments
- RandomX CPU PoW, 120s block time
- 100M asymptotic hard cap, 0.6 CYNC tail emission
- 30% fee burn (50% under congestion), 0% dev tax, 0 premine, no foundation
- 7 additional privacy features beyond the Monero baseline (encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead-man's switch, auto-churn, decoy defense)

## Links

- Source: git.coincync.network/coincync/cync-protocol (MIT)
- Soak summary: docs.coincync.network (search v1.0.2-testnet)
- Faucet: coincync.network/faucet (10 tCYNC, no signup, 30 seconds)
- Constitution: docs.coincync.network/governance/constitution
- CIP-001 (atomic swap spec): docs.coincync.network/cip/CIP-001-atomic-swap
- Discord: discord.gg/5tYNSCsqzy

Critique welcome. Testnet is running for exactly this — to find what doesn't work in real network conditions. Reply or DM if you find something off, especially in the consensus or privacy layers. I'll be in this thread for 48 hours.
```

---

## 7. Hacker News — Show HN

**Title (under 80 chars):**

```
Show HN: CoinCync — privacy PoW with a constitution and atomic-swap mainnet blocker
```

**URL:**

```
https://coincync.network
```

**First comment (post immediately after submission, signed as the author):**

```
Solo dev here. Quick context for why this is on Show HN rather than Show HN: $myproject:

CoinCync is a privacy-first proof-of-work cryptocurrency in the Monero family — CLSAG-16 ring signatures, Bulletproofs+, stealth addresses, RandomX CPU mining. The interesting parts (where I'd appreciate technical eyes) are the structural commitments:

(1) The repo ships with a written Constitution + Bill of Rights that's compile-time enforced — every consensus-critical file is SHA-256 hash-locked, and 8 tripwire constants in `src/constants.rs` mean any future change that silently flips the rules (adding a dev tax, enabling an admin key, redirecting fees) fails the build with `UNCONSTITUTIONAL: Article X`. The articles forbid the categories of failure that have killed other privacy coins.

(2) Mainnet doesn't ship until CYNC↔BTC trustless atomic swaps work end-to-end. CIP-001 has the design (modeled on Comit/Farcaster XMR↔BTC, adaptor signatures over CLSAG so swap txs are indistinguishable from ordinary ones). The point: when CEX delistings come, every Bitcoin holder is one tx away from CYNC. Listing-independence as a protocol commitment, not a hope.

(3) FROST signature aggregation so multi-sig is byte-equivalent to single-sig on-chain. Monero has multisig but observers can detect it from tx structure; this hides it.

The 30-second user flow:
- Download wallet at coincync.network
- Click faucet → paste address → 10 tCYNC arrives
- Send your first private transaction

72h pre-launch soak just finished — chain stable across all 5 boxes, all converged within ±2 blocks. Mainnet target Oct 2026.

No premine, no dev tax, no foundation, no presale, no token sale. MIT licensed. Source at git.coincync.network/coincync/cync-protocol.

Happy to answer anything about the cryptography, the constitution model, or why I'm doing this solo. Tough questions are the most useful ones.
```

---

## 8. lobste.rs

**Submission:**

- **URL:** `https://docs.coincync.network/governance/constitution` (lead with the differentiator, not the homepage)
- **Title:** `CoinCync — privacy-first PoW cryptocurrency with a compile-time-enforced Constitution`
- **Tags:** `cryptocurrencies`, `rust`, `cryptography`

**First comment from author:**

```
Author here. CoinCync is a Rust implementation of a privacy-first PoW cryptocurrency. Submitting the link to the Constitution rather than the homepage because the Constitution is the actually-novel piece — most of the rest of the privacy stack (CLSAG-16, Bulletproofs+, stealth addresses, RandomX) is well-trodden ground from the Monero family. The interesting question is whether *codifying* a privacy coin's values at the protocol level — with file-hash tripwires + compile-time-enforced invariants — changes the audit and credibility math. Other tactical commitments worth noting: atomic-swap-to-BTC as a mainnet-launch blocker (CIP-001), FROST signature aggregation so multi-sig is on-chain-indistinguishable from single-sig, hash-locked critical files protected from silent edits. Working faucet at coincync.network/faucet if you want to send a private transaction in 30 seconds. Solo developer, MIT licensed, no premine, no dev tax, no foundation. Source at git.coincync.network/coincync/cync-protocol. Critique welcome.
```

---

## Posting checklist (Sun 2026-05-10 — 11 AM ET launch)

Run through this 30 minutes before posting. None of these should still be open by the time the announcement goes out.

- [x] IBD wedge bug fixed + deployed to fleet (binary `8328625` on all 5 Vultr boxes — verified live)
- [x] Soak verdict GO (verified 2026-05-07, see [v1.0.2-testnet-soak-summary.md](v1.0.2-testnet-soak-summary.md))
- [x] Faucet endpoint live: `https://api.coincync.network/faucet/health` returns 200
- [x] Hot wallet has tCYNC balance: ~1500 tCYNC after top-up (≈150 drips of buffer)
- [x] Anonymity-set tile on explorer shows real value (~6800)
- [x] Fresh-node IBD smoke-test PASSED on nyc (h=0 → h=429+ progressing, ring=11)
- [x] v1.0.6-testnet shipped: MIN_DIFFICULTY=500 consensus floor (commit `97d09b0`) fixes the launch-day bootstrap runaway. Includes v1.0.5's chain.rs MESS bypass + node.rs InvBlock-during-IBD GetHeaders (commit `d955362`) + configure-fleet-mesh.sh.
- [x] Fleet convergence stress-tested under 4-thread miner load: all 5 boxes converged at h=42, difficulty pinned at 500, tip_age under 60s on every box. Same scenario under v1.0.5 diverged 100+ blocks in 5 minutes.
- [ ] GitHub Release created at v1.0.6-testnet with binaries (manually attach files from `cync-release-v1.0.6-testnet/` or Downloads)
- [ ] CI green for the latest commit
- [ ] Forgejo `git.coincync.network/coincync/cync-protocol` — if NOT yet deployed, swap all references in this doc to `https://github.com/ghostrider1092/Coincync-Testnet-` before posting
- [ ] Block height + hashrate updated to current values (run `curl https://api.coincync.network/rpc/testnet -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | python3 -m json.tool` to grab fresh numbers)
- [ ] Discord invite tested in private browser (not rate-limited)
- [ ] Wallet installer download URL points at v1.0.6-testnet release artifacts (in README + announcement bodies)
- [ ] Local home miner is **set to start on boot** (Sunday windows-sleep is OFF; if your machine reboots overnight, the chain stalls)

## Posting order (Sun 2026-05-10 — adjusted from Mon to Sun)

| Time (ET) | Channel |
| --- | --- |
| 10:30 | Pin the welcome thread on your Discord. Be present in-channel from this point onward. |
| 11:00 | **GO LIVE.** r/CryptoCurrency (Discussion flair) |
| 11:30 | BitcoinTalk ANN |
| 12:00 | Twitter / X thread (5 posts in section 3 above) |
| 15:00 | lobste.rs (with the first-comment context) |
| Tue 11:00 | Hacker News Show HN (give Day-1 traffic time to peak first) |
| Wed 11:00 | r/Monero (they want 48h of external traction signals) |

Hold r/Monero and Hacker News for **Wed 2026-05-13** — they want 48h of activity from the other channels to point at. Posting them on Day 0 is the worst-case timing.

For each platform: be in the comments for at least 6 hours after posting. Reply to every top-level comment within 1 hour for the first 6h. Tough questions are gifts — answer them in detail. Drama-bait is not a gift — answer once technically and move on.
