# The Crucible

> **Hammer it until it sings.**

*CoinCync Testing Contributors program.*

**The testnet is a real-world adversarial environment. We need real-world adversarial testers running it.**

CoinCync is a privacy-first proof-of-work chain heading to mainnet on 2026-10-01. Unit tests and integration tests catch a lot, but the bugs that surface at *days of real uptime, against multiple actors, on real network conditions* — those only show up when humans run nodes and pay attention. The testnet exists to find them before mainnet does.

**The Crucible** is the recognized track for community members who do that work. A crucible is where you hammer something under pressure until it either breaks or it doesn't — that's the job. Members run the chain, file what they find, and the chain gets stronger.

---

## Why this exists (a worked example)

On 2026-06-02, community operator **barns1253** captured a `WARN broadcast_raw partial delivery sent=4 full=0 closed=1` line repeating in his node logs and posted it to Discord. That single log capture surfaced a real bug — `TrySendError::Closed` cases weren't removing stale peer entries from the broadcast set, so the broadcast loop spun on dead channels for up to 360 seconds until the next maintenance tick.

That fix went out as commit `72f18c6`. Then, while deploying it, a *second* latent bug (eclipse-defense slot leak, `84f40ce`) surfaced. Then a third (a self-connection-loop ban that banned the wrong port, fixed 2026-06-04). Then nginx config drift. Then a hardcoded testnet checkpoint blocking a fresh chain after a wipe. Then a watchdog timer silently reverting an architectural migration. Full post-mortem: [`docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md`](docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md).

None of that was caught by `cargo test`. All of it was caught because someone was running a real node and noticed something off. **That's the work.**

---

## The ranks

The Crucible has two ranks. The first is open — anyone reading this can join today. The second is earned through demonstrated contribution. The progression is borrowed from military cadence because the work is similar in spirit: vigilance, repeatable discipline, signal under fire.

### Recruit (open enrollment)

Anyone running a testnet node, wallet, or miner who wants to be recognized as part of the testing pool.

**How to enroll:**

1. Join Discord at <https://discord.gg/5tYNSCsqzy>
2. Go to channel `#crucible` (if it doesn't exist yet, post in `#general` and a maintainer will create it)
3. Post a one-line intro: what you're testing (node / wallet / miner / docs), what platform (Linux / macOS / Windows / Vultr / hardware), and what you want to focus on
4. A maintainer assigns you the **Crucible Recruit** Discord role within 24h

**What you get:**

- Discord **Crucible Recruit** role (visible to everyone, signal of trust)
- Access to `#crucible` channel for coordination
- Your handle credited in release notes for any bug you report that lands a fix (we list reporter alongside the commit, the way Bitcoin Core does)
- Permission to file `[crucible]` prefixed issues on GitHub without the usual triage delay

**Expectations:**

- Run a current testnet binary at least occasionally (every couple of weeks is fine; we're not measuring uptime)
- When you see something off, **capture the log lines and command context BEFORE filing**. A bug report with `journalctl -u coincync-node --since '1 hour ago' | grep -E 'WARN|ERROR'` attached is worth ten with just "node is slow."
- Don't deliberately attack other Crucible members' nodes or wallets. Adversarial testing of *the protocol* is welcome (see Veteran below); abusing *other participants* is not.

### Veteran (earned, named)

The Veteran rank recognizes Recruits who have moved past "ran into a bug" into "actively hunts bugs and writes them up well." It's invite-based, not application-based — maintainers offer the promotion when criteria are met. Recruits are not penalized for staying Recruits; many of the best testers stay there indefinitely. Veteran is for sustained or high-impact contribution, not a goal everyone needs to chase.

**Criteria (any one of):**

- **3+ verified bug reports** that resulted in shipped fixes
- **1 nontrivial protocol-layer finding** (consensus, P2P, crypto) regardless of count
- **Sustained stress-testing presence** (e.g., running a node continuously for weeks with substantive log analysis and proactive issue reports)

**What you get on top of the Recruit benefits:**

- Discord **Crucible Veteran** role (replaces Recruit)
- Private `#veterans` Discord channel — maintainers + Crucible Veterans only
- **Early-binary access**: pre-release builds shared in private channel ~24-48h before public release, to soak-test before broader rollout
- **Hall of Fame section in this document** (see bottom) with your handle, the bugs/contributions credited to you, and links to the relevant commits or post-mortems
- **Named in release notes** with a "Crucible Veteran" line, not just "reported by"
- **Direct line to maintainers** for non-security findings — file in `#veterans` instead of GitHub for faster turnaround on judgment calls

**No NDA. No token allocation. No "tester bond" or paid track.** The Crucible is volunteer work by people who care about getting privacy money right. The recognition is the recognition. Anyone who asks about compensation gets the same answer every time, and that bright line is part of why volunteers self-select for the right reasons.

---

## What we want tested (four scope tracks)

You don't need to pick one — many of the best Recruits move between them. Listing them so you know what's in scope.

### 1. Network / sync stress

Run a node under unusual conditions and capture what happens. This is the highest-historical-value track — both fixes shipped on 2026-06-04 traced back to this kind of test.

Examples worth doing:

- Run a fresh node behind a residential connection / cellular / weird NAT, watch IBD
- Run multiple nodes on the same `/16` to stress eclipse-defense
- Restart a node mid-IBD and look at recovery behavior
- Run with `--addnode` pointing at offline IPs to check failover
- Capture `WARN`-level log lines that don't obviously map to an existing known issue
- Watch fleet propagation when network conditions get noisy

### 2. Wallet UX + transaction flows

Use the wallet like a real person would. CLI wallet, Tauri wallet, soon mobile.

Examples:

- Send and receive on different OSes (Windows 10/11, macOS, various Linux distros)
- Try CLSAG ring-signature signing at edge ring sizes
- FROST multisig: 2-of-3, 3-of-5, recovery scenarios
- Atomic swap (cyncswap) flows — once those land
- Hardware wallet integration as it becomes available
- Onboarding from scratch with no prior knowledge — what breaks?

### 3. Adversarial / protocol probing

Try to break things. This is closer to bug-bounty territory; **security-impacting findings MUST follow [SECURITY.md](SECURITY.md) responsible disclosure** (email `CyncLabs@proton.me` PGP-encrypted, not a public issue). Non-security adversarial findings (DoS amplification, mempool fingerprinting, peer-scoring bypass) can go through Discord.

Examples:

- Attempt double-spends with various race conditions
- Submit malformed transactions, block headers, P2P messages
- Mempool flooding behavior under fee pressure
- Try to fingerprint stealth-address output discovery
- Stress the RPC layer (rate limits, auth boundaries)
- Look for orphan-flood, peer-scoring, or eclipse-defense bypasses

### 4. Documentation + onboarding feedback

Test the docs by following them as a newcomer. You'd be surprised how much breaks.

Examples:

- Follow [`docs/COMMANDS.md`](docs/COMMANDS.md) verbatim and flag every step that fails or is unclear
- Run through [`docs/SMOKE_TEST.md`](docs/SMOKE_TEST.md) on a fresh box
- Newcomer-perspective issues: "I tried to run a node and got X error, the docs said do Y, here's what actually happened"
- Translations — multi-language docs are welcome (Right V: pseudonymous + global participation)

---

## Filing a bug report (what good looks like)

The single biggest thing that separates high-signal from low-signal reports is **including the actual logs and the exact command sequence**. Maintainers shouldn't have to ask follow-up questions to reproduce.

A good template (use it on the GitHub issue or pin it in your Discord post):

```
**Environment:**
- Binary: <git sha or version, e.g., `coincync-node 1.0.10 / commit 2eaf73a`>
- OS: <Ubuntu 24.04 / macOS 14.5 / Windows 11 / etc.>
- Network: <testnet / regtest>
- Hardware: <vCPU count + RAM + storage type if relevant>

**What I did:**
<exact commands or actions, in order>

**What happened:**
<observed behavior, error messages, screenshots if UI>

**Logs:**
```
<paste relevant log lines — `journalctl -u coincync-node --since 'N min ago'` for nodes,
 or stderr capture for wallet/rig. Trim to the relevant window but include 20-30 lines
 of surrounding context.>
```

**What I expected:**
<what you thought should happen>

**Reproducibility:**
<happens every time / intermittent / one-off>
```

---

## Ground rules

A small set, mostly common sense:

- **Security-impacting findings: PGP email, not GitHub.** See [SECURITY.md](SECURITY.md). Includes anything that could cause loss of funds, chain split, consensus drift, key extraction, or stealth-address deanonymization. If unsure whether it's security-impacting, **default to PGP email**.
- **Don't attack other Crucible members' infrastructure** without their explicit consent. Attack the protocol, not other humans' boxes.
- **Don't synthesize fake bug reports.** Quality > quantity always. We will notice scripted noise and it disqualifies someone from Veteran promotion.
- **Pseudonymous participation is a Right** (Constitution, Right V). Use whatever name you want.
- **Be specific in `#crucible`.** "It's slow" is not a bug report. "tip_age_secs sat at 480 for 12 minutes while peer_count showed 4, here are the log lines" is a bug report.
- **Disagreement is fine, attacks aren't.** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies in all channels.

---

## Hall of Fame — Crucible Veterans

Recognized Crucible Veterans and the work they're known for. Inclusion is by maintainer offer based on demonstrated contribution; updates land via PR alongside the relevant commits.

### barns1253

- **2026-06-02** — captured the `broadcast_raw partial delivery` log pattern that surfaced the closed-channel cleanup bug (commit [`72f18c6`](https://github.com/ghostrider1092/Coincync-Testnet-/commit/72f18c6)). Cascade-fix narrative in [`docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md`](docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md).
- **Inaugural Crucible Veteran.** Set the template for what good log-driven bug reporting looks like.

---

## Questions

- General questions about The Crucible: post in `#crucible` on Discord.
- Wanting to be considered for Veteran promotion: usually you'll be offered it without asking, but if a maintainer hasn't noticed and you think you've met the criteria, DM a maintainer.
- Disputes or grievances: see [MAINTAINERS.md](MAINTAINERS.md) for the recovery + escalation tree.

**Welcome to The Crucible. The testnet is better because real people run it and notice things.**
