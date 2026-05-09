# Discord answer cheat sheet

Copy-paste-ready answers for the questions you'll see in Discord daily during testnet. Each entry has a short form (one-liner reply) and a long form (when someone asks follow-ups). Discord-flavored markdown — paste verbatim, the formatting renders correctly.

Update the height / build / dates before launch week. Numbers in this file are correct as of **2026-05-08**.

---

## Quick navigation

- [What is CoinCync?](#what-is-coincync) · [Is it a Monero fork?](#is-it-a-monero-fork) · [Why does this exist?](#why-does-this-exist)
- [Download / install](#downloads) · [Wallet setup](#wallet-setup) · [Faucet help](#faucet-help)
- [Mining help](#mining-help) · [Pool questions](#pool-questions) · [GPU/ASIC questions](#gpu-asic-questions)
- [Network: nodes, seeds, sync](#network-nodes-seeds-sync) · [Block time / supply / emission](#block-time-supply-emission)
- [Privacy stack](#privacy-stack) · [Regulatory / compliance](#regulatory-compliance)
- [Mainnet / roadmap](#mainnet-roadmap) · [Premine / dev fund / presale](#premine-dev-fund-presale)
- [Audit / security](#audit-security) · [Reproducible builds / binary verify](#reproducible-builds)
- [Common errors](#common-errors) · [How to report a bug](#bug-reporting)
- [Atomic swaps](#atomic-swaps) · [Trading / exchanges](#trading-exchanges)
- [Solo dev / governance](#solo-dev-governance)
- [Hostility / spam / FUD response](#hostility-spam-fud)

---

## What is CoinCync

**Q: What is CoinCync?**
> Privacy-first proof-of-work cryptocurrency. CLSAG-16 ring signatures, Bulletproofs+ range proofs, stealth addresses, RandomX CPU mining, Dandelion++. 100M asymptotic cap, 30% fee burn, zero pre-mine, zero dev tax, zero foundation. Constitutionally locked — 19 Articles + 15 Rights, compile-time enforced. MIT licensed.
>
> Public testnet is live now (height 5675+, 5 nodes across US/EU/Asia). Mainnet target Oct 2026.

**Q: Tell me more about the Constitution thing.**
> The repo ships with a 19-Article Constitution + 15-Right Bill of Rights. Critical files are SHA-256 hash-locked; 8 tripwire constants in `src/constants.rs` mean any future change that silently flips the rules — adding a dev tax, enabling an admin key, redirecting fees — fails the build with `UNCONSTITUTIONAL: Article X`.
>
> Stablecoins, smart-contract VMs, bridges, NFTs, governance tokens, fee redirects — all categorically forbidden. Read it: docs.coincync.network/governance/constitution (10 min, the articles are short)

## Is it a Monero fork

**Q: Is this a Monero fork?**
> No. Independent Rust implementation written from scratch. Uses the same privacy primitives (CLSAG, Bulletproofs+, stealth addresses, RandomX, Dandelion++) because they're battle-tested, but the codebase, consensus rules, emission curve, and Constitution are entirely original. Source at git.coincync.network/coincync/cync-protocol — MIT licensed.

**Q: Why not just use Monero / contribute to Monero?**
> Monero's values live in social consensus, which is correct for what Monero is. CoinCync is an experiment in whether *codifying* a privacy coin's values (constitutional articles, hash-locked critical files, compile-time tripwires) changes the audit and credibility math. Different lane, not a critique.

## Why does this exist

**Q: Why does CoinCync exist when Monero already does this?**
> Two structural commitments Monero deliberately doesn't make: (1) a written Constitution that's compile-time enforced, (2) CYNC↔BTC atomic swaps as a mainnet-launch blocker. The point of the swap commitment: when CEX delistings come — and for any privacy coin they will — every Bitcoin holder is one transaction away from CYNC.

---

## Downloads

**Q: Where do I download the wallet?**
> https://coincync.network — desktop installer for Windows/macOS/Linux. SHA256SUMS.txt published alongside; verify with `sha256sum -c SHA256SUMS.txt`.

**Q: Where's the source code?**
> Canonical: **git.coincync.network/coincync/cync-protocol** (self-hosted Forgejo)
> Public mirror: github.com/ghostrider1092/Coincync-Testnet-
>
> MIT licensed. Build with `cargo build --release --features "randomx testnet"`.

**Q: Is there an Android / iOS wallet?**
> Not yet. Desktop only at testnet. Mobile is post-mainnet.

## Wallet setup

**Q: How do I create a wallet?**
> Download from coincync.network → run installer → "Create New Wallet" → write the 25-word seed phrase **on paper, not in a file**. Lose it = lose your funds, no recovery. Two paper copies in different physical locations is the standard advice.

**Q: How do I restore from seed?**
> Run wallet → "Restore from Seed" → enter your 25 words in order → wait for chain scan to finish (3-15 min depending on history). Don't close the wallet during scan.

**Q: My balance is 0 but I just received coins?**
> Outputs need 10 confirmations (~20 min at 120s blocks) before they're spendable. Check `mempool` vs `confirmed` in the wallet — pending shows in mempool until confirmed.

**Q: I forgot my password.**
> No "forgot password" flow exists — the wallet doesn't phone home. If you have your seed phrase, restore from it (creates a new wallet file with a new password). If you've lost both seed and password: funds are inaccessible, that's the privacy guarantee.

## Faucet help

**Q: Where's the faucet?**
> https://coincync.network/faucet.html — paste your tCYNC address, get 10 tCYNC. Drip rate: 1 per address per hour. No signup. Coins arrive in <2 min on the explorer.

**Q: Faucet didn't send me anything / says I already claimed.**
> Wait an hour from your last drip and try again. The rate-limit is per-address. If your address never claimed and you're still blocked, post the (PARTIAL — first 10 chars) address in #wallet-help with the timestamp you tried.

**Q: How much CYNC does the faucet give?**
> 10 tCYNC, every hour, per address. Testnet only — these coins have ZERO monetary value.

---

## Mining help

**Q: How do I mine?**
> ```
> ./target/release/coincync-miner \
>   --address tCYNC<your_addr> \
>   --threads <num_cores> \
>   --node 127.0.0.1:28081
> ```
> Or use the GUI miner bundled in the desktop installer. Set threads = your physical core count.

**Q: What hashrate should I expect?**
> ~50–500 H/s per core depending on CPU. Modern Ryzen / Intel desktop: 1000–3000 H/s aggregate. Older laptop: 200–800 H/s. RandomX is memory-bound — DDR4-3200 vs DDR4-2400 makes ~10% difference.

**Q: I can't get hugepages working / it's saying "huge pages not enabled".**
> Optional 5–15% speedup. Linux: `echo 1280 | sudo tee /proc/sys/vm/nr_hugepages`. Windows: not exposed at OS level, ignore the warning. The miner works without huge pages.

**Q: How long until I find a block solo?**
> Network hashrate ~250 H/s on testnet. If you contribute 1000 H/s (one decent CPU), you'd hit ~80% of blocks until others catch up. Realistic mainnet expectation will be much harder once hashrate scales; testnet is intentionally low-hashrate to give early miners practice.

**Q: I found a block!**
> Post the height + your hash + which CPU. We'll celebrate in #mining-stats.

## Pool questions

**Q: Where's the pool?**
> No pools yet on testnet. Network hashrate ~250 H/s makes solo mining realistic. Pools may emerge near mainnet — operator-run, community-run, anyone can launch one.

**Q: Will there be a pool I can run?**
> Yes — the JSON-RPC `submit_block` interface is documented and stable. Pool software (a Stratum→RPC proxy) is community work, not maintained by the project. CoinCync ships with no built-in pool advantage; treat all pools as third parties.

## GPU ASIC questions

**Q: Why no GPU mining?**
> RandomX is memory-hard by design. A GPU running RandomX is ~5–20x SLOWER than the same-cost CPU because GPUs lack the L3 cache + branch-predictor architecture RandomX exploits. Not a software lockout — a fundamental algorithmic property.

**Q: When ASIC?**
> Likely never. A RandomX ASIC would essentially be a general-purpose CPU — same memory hierarchy, same branch prediction, same cache. The ASIC manufacturer would be in the CPU business, competing with Intel/AMD. No economic advantage to ship.

**Q: Can I mine on a Raspberry Pi?**
> Pi 4 / 5 yes, but slowly: ~80–150 H/s. Pi 3 and below: probably not enough RAM for the RandomX dataset (needs ~2.5 GB headroom).

---

## Network nodes seeds sync

**Q: How do I run a node?**
> Build from source (see #node-setup pinned message). Run `./target/release/coincync-node --network testnet`. DNS seeds auto-discover: `seed1.coincync.network`, `seed2.coincync.network`, `seed3.coincync.network`.

**Q: My node is at height 0 / not syncing.**
> Check (1) port 28080 outbound is allowed by your firewall, (2) `dig seed1.coincync.network` returns an IP, (3) the seed IPs are reachable from your network with `nc -zv 66.135.23.193 28080`. Post the last 50 lines of node logs in #testnet if still stuck.

**Q: What ports do I need open?**
> **Outbound:** 28080/tcp (P2P). **Inbound:** 28080/tcp if you want others to connect to you (recommended but optional). **Local only:** 28081 (RPC, default 127.0.0.1). Don't expose 28081 publicly without auth.

**Q: How many peers should I have?**
> A healthy node has 8–25 peer connections. <5 sustained means firewall or seed-discovery problems. >50 is unusual; could be a sync-storm bug worth reporting.

**Q: How do I check my node's status?**
> ```
> curl -s -X POST -H 'Content-Type: application/json' \
>   -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
>   http://127.0.0.1:28081 | jq
> ```
> Look for `synced: true`, `peer_count: ≥8`, `tip_age_secs < 300`.

## Block time supply emission

**Q: What's the block time?**
> 120 seconds target. Difficulty retargets every block.

**Q: What's the supply cap?**
> 100,000,000 CYNC asymptotic. Tail emission of 0.6 CYNC per block continues forever (anti-deflation safety). 1 CYNC = 10^12 atomic units.

**Q: Initial block reward?**
> ~50 CYNC at genesis, asymptotic decay. By the time tail kicks in (hundreds of millions of blocks later), the curve is nearly flat at 0.6 CYNC/block.

**Q: What's the fee burn?**
> 30% of every transaction fee is permanently destroyed. Captured by no one. Bumps to 50% under congestion. The remaining 70% goes to miners as part of the block reward.

---

## Privacy stack

**Q: How does the privacy work?**
> Every transaction uses **all** of these by default, no opt-in needed:
> - **Stealth addresses** — receiver hidden via ECDH-derived one-time output keys
> - **CLSAG-16 ring signatures** — sender hidden in a ring of 16 outputs (1 real + 15 decoys)
> - **Pedersen commitments** — amounts hidden, balance still cryptographically verifiable
> - **Bulletproofs+** — range proofs that hidden amounts are non-negative
> - **Dandelion++** — IP/origin hidden during propagation (1–3 hop stem then flood)

**Q: Can I send transparent transactions?**
> No. There is no transparent mode. There is no opt-in privacy tier. The privacy stack is the only stack. This is by design — see CONSTITUTION.md Article VII.

**Q: How can supply be auditable if amounts are hidden?**
> Pedersen commitments are additively homomorphic. Every node verifies that inputs sum equals outputs sum without knowing the actual amounts — `C(in1) + C(in2) = C(out1) + C(out2) + C(fee)`. Combined with Bulletproofs+ proving each output is non-negative, this guarantees no hidden inflation.

**Q: Is there a view key?**
> Yes. **Time-scoped view keys** let you reveal a specific block range to an auditor / exchange / tax authority without exposing your full history. You choose what to reveal and to whom. Compatible with privacy-by-default — disclosure is by consent, not by design flaw.

**Q: Can the network operators see my transactions?**
> No more than anyone else can — the privacy stack is uniform across all participants. Node operators see encrypted bytes on the wire and can correlate timing if they're aggressive about it; Dandelion++ limits this. There's no "operator view" privilege.

## Regulatory compliance

**Q: Is CoinCync legal in <country>?**
> We don't give legal advice. CoinCync is open-source software, MIT-licensed, with no controlling entity. Whether a given user's use of it complies with their jurisdiction's laws is their responsibility. Privacy is a Right (Bill of Rights), not a legal opinion.

**Q: How does CoinCync handle KYC / AML?**
> CoinCync is a protocol, not a service. It doesn't collect identity, doesn't have an account, doesn't have a custodian. Exchanges and other intermediaries that integrate CoinCync handle their own compliance — that's their business, not ours.

**Q: Are you worried about Tornado Cash / sanctions?**
> The Tornado Cash situation involved sanctions on a *smart contract address*. CoinCync has no smart contracts (Article IX forbids them) and no central address controlled by any party. There's nothing to sanction in the same way.

**Q: What if law enforcement asks you to add a backdoor?**
> Article I of the Bill of Rights: "Privacy is not a feature; it is the product." Article II of the Constitution forbids fee redirects to any party including governments. The Constitution is hash-locked at the protocol level — the maintainer can't unilaterally weaken privacy without a build-breaking commit visible in history. Forks are the only path to weaker privacy.

---

## Mainnet roadmap

**Q: When mainnet?**
> Target: **2026-10-01**. Hard launch-blockers before that date:
> - Working CYNC↔BTC trustless atomic swaps (CIP-001)
> - Third-party audit of the consensus + privacy stack
> - Multi-maintainer signed-release infrastructure (M-of-N)
> - Real testnet operational track record

**Q: Why so late?**
> The Constitution's commitments are real today. The mainnet timeline depends on getting the audit + atomic-swap implementation right, not fast. Pre-launching with vulnerabilities or with the listing-independence story unfinished would defeat the point.

**Q: Will testnet coins convert to mainnet?**
> No. Testnet is reset at mainnet launch. Testnet coins have zero monetary value and never will.

## Premine dev fund presale

**Q: How much premine?**
> Zero. Article II forbids it. The first miner takes ~50 CYNC at block 1; that's the entire genesis distribution.

**Q: Is there a developer tax / fee?**
> Zero. 0% dev tax. Article III. 70% of every fee goes to miners; 30% is burned.

**Q: Foundation? Treasury? Governance token?**
> None of those exist or will exist. Articles III, IX, XI forbid them.

**Q: Is there a presale / IDO / ICO?**
> No. There never will be. Anyone offering "early CoinCync tokens" is running a scam — please report in #scam-alerts with screenshots.

---

## Audit security

**Q: Has CoinCync been audited?**
> Not yet. Third-party audit of the consensus + privacy stack is a hard mainnet-launch blocker (see SECURITY.md). Currently: 1093 internal tests in CI, fmt + clippy + cargo audit on every PR, hash-locked critical files.

**Q: Is there a bug bounty?**
> No paid program yet — solo-dev, testnet-stage, no funding to back payouts honorably. Funded program will launch alongside the third-party audit before mainnet. In the meantime: responsible disclosure to security@coincync.network (PGP `2CAA 920F 8B96 1772`) — public credit on disclosure with your consent.

**Q: I found a security vulnerability.**
> **DO NOT** post it publicly. Email **security@coincync.network**. Use PGP if it's anything serious — fingerprint `2CAA 920F 8B96 1772`. We'll respond within 24h, work out a coordinated disclosure timeline, and credit you publicly when the fix lands (with your consent).

## Reproducible builds

**Q: Can I verify the binary I downloaded?**
> Yes. Each release ships `SHA256SUMS.txt`. Run `sha256sum -c SHA256SUMS.txt` to verify integrity.
>
> Full reproducibility (you build from source and the binary matches) is post-launch — Dockerfile-based pinned builder is documented in `docs/operations/REPRODUCIBLE_BUILDS.md` but not yet authored. Coming pre-mainnet.

**Q: How do I build from source?**
> ```
> git clone https://git.coincync.network/coincync/cync-protocol
> cd cync-protocol
> cargo build --release --features "randomx testnet"
> ```
> Tested on Linux x86_64, macOS arm64/x86_64, Windows MSVC. Rust 1.75+.

---

## Common errors

**Q: "INTEGRITY CHECK FAILED — UNCONSTITUTIONAL: Article X"**
> Build-time tripwire fired. A consensus-critical file was modified without updating `critical_files.lock`. If you intentionally changed it: `cargo run --bin update-critical-hashes`. If you didn't: check `git diff <file>` and revert. This guard is the Constitution doing its job — don't try to disable it.

**Q: "Connection refused" on RPC port 28081**
> The node binds RPC to `127.0.0.1:28081` by default. You're either calling from a different machine (need to enable explicitly with auth — see SECURITY.md) or the node isn't running (`systemctl status coincync-node`).

**Q: "Mempool full" on send**
> Network is congested or your fee is too low. Try again in a minute, or bump the fee.

**Q: Wallet says "scanning..." for hours**
> First-time scan over a long history (year+) can take 10–30 min. If it's longer than that, post the wallet log in #wallet-help.

**Q: "Insufficient funds" but my balance shows positive.**
> Outputs need 10 confirmations to be spendable. Confirmed-balance and spendable-balance differ. Wait ~20 min after the receiving block.

## Bug reporting

**Q: I found a bug. Where do I report it?**
> Non-security: open an issue on **github.com/ghostrider1092/Coincync-Testnet-** with the bug-report template (auto-fills environment + repro). The template asks for node version, OS, repro steps, last 200 lines of logs.
>
> Security-sensitive (consensus, privacy, key handling, wallet integrity): email **security@coincync.network**, NOT a public issue. PGP `2CAA 920F 8B96 1772`.

**Q: Can I fix the bug myself and PR?**
> Yes please. Read CONTRIBUTING.md first — it's short. PRs land on `main` via fast-forward / rebase / squash; merge commits are blocked by the ruleset. Tests must pass; signed commits required.

---

## Atomic swaps

**Q: Can I swap CYNC for BTC?**
> Not yet. CYNC↔BTC trustless atomic swaps are a hard mainnet-launch blocker (Article XIV). Design spec is published as **CIP-001** at docs.coincync.network/cip/CIP-001-atomic-swap. Reference implementation is in progress.

**Q: How do the atomic swaps work?**
> Adaptor signatures over CLSAG (CYNC side) + Schnorr/secp256k1 (BTC side), bound by a cross-curve discrete-log-equality proof. Both chains' spend transactions commit to the same secret; redeeming one reveals it, letting the counterparty redeem the other. Either party times out and refunds if the other stalls. No exchange, no escrow.

**Q: Why is atomic swap a launch blocker, not optional?**
> Listing-independence as a protocol commitment, not a hope. CEX delistings come for every privacy coin eventually. Shipping mainnet without an on-ramp leaves users stranded; with the swap, every Bitcoin holder is one transaction away.

## Trading exchanges

**Q: Where can I trade CYNC?**
> Mainnet hasn't launched. Testnet coins have zero monetary value — anyone trying to sell them is wasting your time. Once mainnet ships, exchange listings are third-party decisions; we don't pay for listings, and we expect delistings to happen — that's why atomic swaps are a launch blocker.

**Q: Is there a price?**
> Testnet: zero. Mainnet hasn't launched. There is no presale. Talk of price before mainnet is fiction.

---

## Solo dev governance

**Q: This is one person?**
> Yes. Solo dev shipped the testnet, runs the 5-node fleet, wrote the Constitution + Bill of Rights, MIT-licensed everything. Multi-maintainer M-of-N signed-release infrastructure is a mainnet-launch blocker (Article XV) — by the time mainnet ships, the maintainer count will have grown.

**Q: What if you get hit by a bus?**
> Repo is MIT-licensed and mirrored at git.coincync.network + github + (per-contributor forks). Critical files are hash-locked, so anyone can verify their copy of the source matches mine. The protocol is already running on 5 nodes that don't depend on me to be up. Post-bus: someone forks, picks up where the maintainer left off. The Constitution doesn't depend on the original author being alive.

**Q: How are decisions made?**
> Solo dev makes them currently. Pre-mainnet, this transitions to multi-maintainer with M-of-N for releases. The Constitution itself is functionally immutable — it's hash-locked and any change fails the build with `UNCONSTITUTIONAL: Article X`. So decisions are constrained to the space of changes the Articles allow.

---

## Hostility spam FUD

When someone shows up just to dunk:

**Q: "Just another shitcoin"**
> Cool. Source is MIT, Constitution is hash-locked, no premine, no dev fund, no presale. We're not asking you to buy anything — testnet coins have zero monetary value. If you find something specific that's broken, file an issue.

**Q: "Why isn't this on \[major exchange\]?"**
> Because mainnet hasn't launched. We don't pay for listings; the protocol's listing-independence story is the atomic-swap commitment.

**Q: "Privacy coins are illegal"**
> Privacy coins are open-source software. Legality is jurisdiction-specific and a question for the user's lawyer, not the protocol's. We don't give legal advice.

**Q: "This is just Monero with extra steps"**
> Different stack of structural commitments — written Constitution that's compile-time enforced, atomic-swap-as-launch-blocker, FROST hidden multi-sig (which Monero doesn't have). Same primitives because they're the strongest known tools. We've never claimed to invent ring signatures.

**Q: Repeated trolling / bad-faith engagement**
> Don't engage. Mute, report to mods. CoinCync rules: focus on the protocol, no harassment, no doxing.

---

## Routing — when to redirect to a specific channel

| User's question | Send them to |
|---|---|
| "I have a bug" | #bug-reports (or security@ for vulns) |
| "How do I run a node?" | #node-setup pinned |
| "How do I mine?" | #mining-help pinned |
| "How do I set up the wallet?" | #wallet-help pinned |
| "What's CoinCync?" | #faq pinned |
| "Network down?" | #network-health |
| "When mainnet / what's left?" | #roadmap |
| Anything language-other-than-English | #international |
| Cryptography paper / theory | #papers |
| "I want to propose X" | #ideas → if it gels, #internal-specs (CIP) |
| Confirmed scam | #scam-alerts |

---

## Catchall short-replies

For when you don't have time to type anything custom:

| Reply | When to use |
|---|---|
| "Pinned message in this channel covers this." | Read-the-pins prompt |
| "Testnet coins have zero monetary value — please stop trying to trade them." | Anyone shilling pump-and-dump nonsense |
| "Email security@coincync.network for that, not a public channel." | Security-flavored question |
| "That's in the Constitution — read CONSTITUTION.md, it's 10 minutes." | Governance / commitment questions |
| "Open an issue with the bug-report template." | Bug reports posted in chat |
| "Solo dev, response time best-effort. I'll get to it." | When pinged for fast response |
