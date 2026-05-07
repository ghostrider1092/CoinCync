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

- **Get a wallet + first tCYNC:** [coincync.network](https://coincync.network) — download the desktop wallet, then claim 10 tCYNC from the public faucet at [coincync.network/faucet.html](https://coincync.network/faucet.html). One drip per address per hour.
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
  then coincync.network/faucet.html for 10 tCYNC (1 drip / hour)
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
💧 Faucet: coincync.network/faucet.html
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

## Posting Checklist

Before posting any of these:

- [ ] **Confirm the GitHub repo URL** — replace `<repo>` placeholders with the real public URL once the repo is created
- [ ] **Confirm the website domain** — replace `<website>` placeholders with the actual production URL
- [ ] **Confirm the block height + hashrate numbers** — those should be live as of the announcement moment, not stale figures from this draft. Run `bash /tmp/fleet-check.sh` on the explorer for current numbers.
- [ ] **Confirm the soak verdict actually passed** — if it didn't, edit the "soak passed clean" line accordingly or hold the announcement
- [ ] **Confirm the Discord invite is working + not rate-limited** — drop the URL into a private browser to test
- [ ] **Pick one launch day and stick to it** — Tue 2026-05-13 is the safest if soak verdict is clean Wed 2026-05-07
- [ ] **Pre-stage the website + downloads page** — they should be ready to flip to "testnet live" status simultaneously with the announcement post
