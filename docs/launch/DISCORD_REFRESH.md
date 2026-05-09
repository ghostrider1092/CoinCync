# Discord refresh kit — copy-paste into your server

Last updated: 2026-05-08. Live data verified at update time.

This file replaces every piece of stale text in the CoinCync Discord
server. Copy each block into the named target. Numbers come from a
fleet probe done at the time of writing — re-run [scripts/check-soak-status.sh](../../scripts/check-soak-status.sh)
or `curl https://explorer.coincync.network/api/testnet -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}'`
before pasting if the doc is more than a day old.

## Live network state (as of 2026-05-08)

| Field | Value |
|---|---|
| Network | testnet |
| Block height | 5675+ |
| Block time | 120 s target |
| Fleet | 5 nodes (NJ + AMS + Tokyo seeds, Dallas explorer, Frankfurt API) |
| Sync state | All 5 nodes synced, ~±1 block spread |
| Peers per node | 10–19 inbound |
| Build | `28b342099695` (4/5 boxes), `1715693a252d` (api FRA — minor drift, functional) |
| Public testnet launch | 2026-05-11 (Mon) |
| Mainnet target | 2026-10-01 |

---

## 1. Server description (under 200 chars)

```
CoinCync — privacy-first PoW cryptocurrency. Constitutionally locked. CYNC↔BTC atomic swaps. RandomX CPU mining. 100M cap, 30% fee burn. MIT licensed. Public testnet live.
```

---

## 2. Welcome message (`#welcome` / `#rules` / first-channel pin)

```
Welcome to CoinCync — privacy-first proof-of-work, constitutionally locked.

⛓️  TESTNET IS LIVE
   • Block height: 5675+ across 5 nodes (US + EU + Asia)
   • Anyone can run a node, mine, send/receive private tx
   • Testnet coins have ZERO monetary value — ignore anyone trading them

🚀  IN 5 MINUTES
   1. Download wallet → coincync.network
   2. Faucet → coincync.network/faucet (10 tCYNC, 1/hour, no signup)
   3. Send your first private transaction

📜  WHAT MAKES THIS DIFFERENT
   • 19-Article Constitution + 15-Right Bill of Rights, compile-time enforced
   • CYNC↔BTC atomic swaps as a mainnet-LAUNCH BLOCKER (Article XIV)
   • FROST hidden multi-sig — byte-indistinguishable from single-sig on-chain
   • Zero pre-mine, zero dev tax, zero foundation
   • Mandatory privacy on every tx (no opt-in transparent mode)

🔗  LINKS
   • Source: git.coincync.network/coincync/cync-protocol  (MIT)
   • Docs:   docs.coincync.network
   • Explorer: explorer.coincync.network
   • Constitution: docs.coincync.network/governance/constitution

📋  RULES
   • No price talk on testnet — testnet coins have no value, period
   • No referral / mining-pool / shilling links without prior approval
   • Bug reports → #bugs (or security@coincync.network for consensus/privacy bugs)
   • Be patient with the solo dev — answers come, sometimes slowly

This is what privacy-first money looks like when nobody is selling you anything.
```

---

## 3. Channel topics (one-line each, under 1024 chars per Discord limit)

Edit each channel → "Edit Channel" → "Topic":

| Channel | Topic text |
|---|---|
| `#announcements` | Project-level announcements only. Read-only for members. Subscribed via "Follow" so updates land in your server's #news. |
| `#general` | Open chat. Be technical, be patient. No price talk on testnet. Bug reports → #bugs. |
| `#testnet` | Testnet status, height, peer issues, sync help. Live: height 5675+, 5 nodes, all synced. |
| `#node-ops` | Running your own node — sync, peer count, RPC, systemd, builds. seed1/2/3.coincync.network are the public DNS seeds. |
| `#mining` | RandomX CPU mining. Solo or pool. testnet mining target ~250 H/s network. No GPU/ASIC advantage by design. |
| `#wallet-help` | Wallet setup, restore-from-seed, send/receive, address types. tCYNC = testnet, CYNC = mainnet (later). |
| `#bugs` | Public bug reports. Anything weird, slow, or wrong. Consensus/privacy bugs → security@coincync.network instead. |
| `#dev` | Implementation discussion — Rust, cryptography, protocol, CIPs. Read the Constitution before proposing changes. |
| `#research` | Cryptography papers, privacy theory, adversarial analysis. Long-form welcome. |
| `#security` | Public coordination of disclosed vulns post-fix. Embargoed reports → security@coincync.network with PGP. |
| `#faq` | Pinned answers to repeated questions. Read pins before asking. |
| `#status` | Live operational status. Webhook posts incidents. Don't @ me here unless something is on fire. |

---

## 4. Pinned messages — per channel

### Pin in `#announcements`

```
📡  CoinCync Public Testnet — Live Operational Status

Date: 2026-05-08
Height: 5675+
Fleet: 5 nodes (NJ, AMS, Tokyo, Dallas explorer, Frankfurt API)
Sync state: all 5 nodes synced, spread ±1 block
Public testnet launch: 2026-05-11

Recent operational events:
• 2026-05-09 04:00 UTC — Cloudflare 521 incident on explorer (~10 min); zone SSL/TLS mode mismatch, fixed. Origin Cert installed, full-strict TLS now end-to-end.
• 2026-05-04 → 05-07 — 72h pre-launch soak: GO verdict, chain stable across all 5 boxes.
• 2026-05-05 — Explorer peer-wedge (13h max-stall on one box) — diagnosed, fixed mid-soak (commit 28b3420), no recurrence.

Public endpoints (verified reachable now):
• Explorer: https://explorer.coincync.network
• API:      https://api.coincync.network
• Faucet:   https://coincync.network/faucet
• P2P:      seed1/2/3.coincync.network:28080  (TCP-reachable from external)

Latest changes:
• Explorer block-detail page now shows "What it's for" cards on all 11 privacy features
• 6 bug-hunt findings closed (HandshakeAction trap, attestations leak, Bob-Negotiated arc, persist-failure rollback, GetFilterCheckpoints DoS, parent-dir fsync)
• Cloudflare Origin Certs installed on explorer.coincync.network — Full (strict) TLS

Mainnet target: 2026-10-01.
```

### Pin in `#testnet`

```
🛰️  HOW TO JOIN THE PUBLIC TESTNET

1. Build the node from source:
   git clone https://git.coincync.network/coincync/cync-protocol
   cd cync-protocol
   cargo build --release --features "randomx testnet"

2. Run it:
   ./target/release/coincync-node --network testnet

   The node auto-discovers peers via DNS seeds:
     seed1.coincync.network  (66.135.23.193)
     seed2.coincync.network  (140.82.57.168)
     seed3.coincync.network  (207.148.111.76)

3. Watch sync progress (in another terminal):
   curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
     http://127.0.0.1:28081 | jq

   Expect: height climbs to 5675+ over ~10–30 min on a fresh node.

4. (Optional) Mine on the testnet:
   ./target/release/coincync-miner \
     --address tCYNC<your-wallet-address> \
     --threads 4 \
     --node 127.0.0.1:28081

CURRENT STATE
• Block height:  5675+  (advances every ~120s)
• Block time:    120s target
• Network hashrate: low (~250 H/s) — your laptop CPU meaningfully contributes
• All 5 fleet nodes synced; tip-age under 2 min consistently

TROUBLESHOOTING
• Stuck at height 0 → check that port 28080 outbound isn't firewalled
• 0 peers → `dig seed1.coincync.network` to confirm DNS resolves
• Anything else → post here with the last 50 lines of node logs and your `get_info` output
```

### Pin in `#mining`

```
⛏️  MINING ON COINCYNC TESTNET (CPU-ONLY, RandomX)

CoinCync uses RandomX, the same proof-of-work algorithm as Monero.
RandomX is deliberately memory-hard; CPUs are first-class miners
and GPUs / ASICs have no meaningful advantage.

REQUIREMENTS
• 64-bit x86 or ARM CPU
• ~2.5 GB RAM headroom (for the RandomX dataset)
• Linux, macOS, or Windows
• A running coincync-node (see #testnet pinned message)

QUICK START (CLI)
   ./target/release/coincync-miner \
     --address tCYNC<your_addr> \
     --threads <num_cpu_cores> \
     --node 127.0.0.1:28081

GUI MINER (Windows / macOS)
Download from coincync.network — the desktop installer includes a
GUI mining tab with one-click start.

POOL VS SOLO
Testnet hashrate is low (~250 H/s) so SOLO is realistic — you may
hit a block in hours of single-machine CPU time. No public pools yet.

REWARDS
• Block reward: ~50 CYNC at genesis, asymptotic decay
• Tail emission: 0.6 CYNC/block perpetually (anti-deflation safety)
• Fee share: 70% (the other 30% is permanently burned)

WHAT WORKS / WHAT DOESN'T
• ✅ Solo CPU mining via the bundled coincync-miner binary
• ✅ Submit-block via JSON-RPC for custom miners
• ❌ ASIC mining (impossible by design)
• ❌ GPU mining (massively underperforms CPU on RandomX)
• ❌ Stratum public TLS (testnet uses loopback-only stratum currently)

REPORT
If you hit a block, post the height + your hash. We'll celebrate.
```

### Pin in `#wallet-help`

```
💳  WALLET QUICKSTART

DESKTOP (Windows / macOS / Linux)
1. Download from coincync.network
2. Run the installer
3. Choose "Create New Wallet" → write down your 25-word seed phrase
   ON PAPER, NOT IN A FILE. Lose this and you lose your funds.
4. Get tCYNC: faucet at coincync.network/faucet
5. Send / receive normally — every tx is private by default

CLI (advanced)
   ./target/release/coincync-wallet create -p <password>
   ./target/release/coincync-wallet --help  # see all subcommands

ADDRESS TYPES
• tCYNC...   — testnet address (95-character base58)
• CYNC...    — mainnet address (placeholder; mainnet not live yet)
• stCYNC...  — testnet sub-address (one-time, derived from your main)

PRIVACY DEFAULTS
• Every output goes to a fresh stealth address derived from receiver's view+spend keys
• Amounts are hidden via Pedersen commitments + Bulletproofs+ range proofs
• Sender is hidden in a CLSAG-16 ring of decoy outputs
• Origin IP is hidden via Dandelion++ propagation
None of this is opt-in. There is no transparent mode.

LOST SEED PHRASE = LOST FUNDS
The wallet does not phone home. There is no "forgot password" flow.
Write your 25 words on paper and store them somewhere you'll find
them in 5 years. Two paper copies in different physical locations
is the standard advice.

COMMON ERRORS
• "insufficient funds" with positive balance → outputs not yet
  unlocked; wait 10 confirmations (~20 min)
• "no view key" → restoring from seed; let the wallet finish scanning
• Anything else → post here with the wallet log file (NOT your seed)
```

### Pin in `#faq`

```
❓  FREQUENTLY ASKED, ANSWERED ONCE

Q: Is CoinCync a Monero fork?
A: No. CoinCync is an independent Rust implementation that uses the same
   privacy primitives as Monero (CLSAG, Bulletproofs+, stealth addresses,
   RandomX, Dandelion++) because they're battle-tested. Code is independently
   written, MIT-licensed, hash-locked, and constitutionally bound. Not a fork
   of Monero source.

Q: When mainnet?
A: 2026-10-01 target. Hard launch-blockers: working CYNC↔BTC atomic swaps
   (CIP-001), third-party audit, multi-maintainer signed-release infrastructure
   (M-of-N), real testnet operational track record. The Constitution's
   commitments are real today; the launch date depends on getting the
   crypto and audit work right, not fast.

Q: Is there a presale / IDO / token sale?
A: No. There never will be. There is no premine. Article II of the
   Constitution forbids it. Every CYNC in existence will be mined by
   someone who contributed proof-of-work.

Q: Is there a developer fund?
A: No. 0% dev tax, no foundation, no governance token. Article III.

Q: Can I trade testnet CYNC?
A: Technically yes, ethically no, financially never. Testnet coins
   have zero monetary value and are reset-able. Anyone trying to sell
   them is wasting your time.

Q: Does CoinCync support smart contracts?
A: No. Article IX forbids them — Turing-complete on-chain execution
   is incompatible with the privacy stack. CoinCync is a payments coin.

Q: Why solo dev?
A: One person can codify a Constitution. One person can ship MIT-licensed
   code. One person can run a 5-node testnet fleet. The audit + multi-sig
   release infrastructure (Article XV) ramps the maintainer count before
   mainnet — by design.

Q: Why a Constitution?
A: Because privacy coins die from one of two failure modes: regulatory
   capture (changing the rules to comply) or insider corruption (changing
   the rules to steal). Compile-time-enforced articles + hash-locked
   critical files + tripwire constants make both failure modes
   technically impossible without a public, attributable, build-breaking
   commit.

Q: Where do I file bugs?
A: #bugs for non-security issues. security@coincync.network for anything
   touching consensus, privacy, or wallet integrity. PGP welcomed.

Q: Block explorer?
A: explorer.coincync.network — search by height, hash, or address.

Q: How do I verify my download?
A: SHA256SUMS.txt is shipped with each release. Run `sha256sum -c SHA256SUMS.txt`.
   Full Dockerfile-based reproducible build is post-launch (see
   docs/operations/REPRODUCIBLE_BUILDS.md).
```

### Pin in `#status`

```
🟢  COINCYNC TESTNET — STATUS BOARD

Updated by automated webhooks + manual posts. Don't @ here unless something is on fire.

CURRENT (2026-05-08):
   • Network: 🟢 healthy
   • Height: 5675+
   • Fleet sync: 5/5 nodes synced
   • Tip age: < 2 min
   • Public endpoints: explorer, api, faucet, P2P all reachable
   • Build: 28b342099695

OPS RUNBOOKS
   • Cloudflare account loss → see DNS_FAILOVER.md (deSEC backup, 15-min recovery)
   • Origin server outage → multi-region fallback in INCIDENT_RUNBOOKS.md
   • TLS issue → SSL/TLS mode must be Full (strict); Origin Certs at /etc/nginx/ssl/

INCIDENT HISTORY (last 7 days)
   • 2026-05-09 04:00 UTC — explorer Cloudflare 521 — RESOLVED (10 min)
   • 2026-05-05         — explorer peer-wedge — RESOLVED (commit 28b3420)
   • Prior to 05-04     — see soak summary in #announcements pin

EMERGENCY CONTACT
   • Solo dev: response time best-effort, typically <12 h
   • For consensus/privacy emergencies: security@coincync.network
   • For chain-split / suspected attack: post here AND email security@
```

---

## 5. Roles description (Server Settings → Roles)

| Role | Description |
|---|---|
| `Founder` | Solo dev — protocol, infra, releases. Single point of authority until M-of-N maintainer ramp pre-mainnet. |
| `Node Operator` | Self-assigned. Running a public testnet node. Heads-up on consensus issues. |
| `Miner` | Self-assigned. Hashing on testnet. Pinged when difficulty re-tunes. |
| `Wallet Dev` | Self-assigned. Building wallet integrations / clients on top of CoinCync. |
| `Bug Hunter` | Earned. Filed an actionable bug report that landed a fix. Visible in #bugs. |
| `Verified` | Anti-spam: passed a captcha or vouched-for. Required to post links / images. |
| `Bot` | Status / faucet / explorer webhooks. |

---

## 6. Status webhook templates

### Outage start

```
🔴  INCIDENT — ${SERVICE} affected at ${TIME_UTC} UTC

Symptom: ${SYMPTOM}
Impact:  ${IMPACT}
Scope:   ${SCOPE}  (e.g., explorer only / fleet-wide / specific region)

Investigating. Updates every 15 min until resolved.
```

### Outage resolved

```
🟢  RESOLVED — ${SERVICE} restored at ${TIME_UTC} UTC

Root cause: ${ROOT_CAUSE}
Fix:        ${FIX}
Duration:   ${DURATION}

Post-mortem: ${POSTMORTEM_LINK or "filed in INCIDENT_RUNBOOKS.md"}
```

### Recurring health pulse (optional, from cron)

```
🟢  Pulse — ${TIMESTAMP_UTC} UTC

Height:        ${HEIGHT}
Synced nodes:  ${N}/${TOTAL}
Median peers:  ${PEERS}
Tip age:       ${TIP_AGE}s
Build:         ${BUILD_COMMIT}
```

---

## 7. Bot status / presence text

If you have a bot showing presence:

| State | Status text |
|---|---|
| Healthy | `Watching: testnet height 5675+ · 5/5 synced` |
| Pre-launch | `Playing: T-3 days to public launch (2026-05-11)` |
| Incident | `Watching: 🔴 incident on ${SERVICE}` |
| Maintenance | `DND: planned maintenance ${WINDOW}` |

---

## What to delete / replace in your existing Discord

If your current Discord has any of these, OVERWRITE with the corresponding section above:

| If your Discord says... | Replace with |
|---|---|
| "Block height ~4275" or any height under 5000 | The current numbers (5675+) from section 4 pinned in `#announcements` |
| "GitHub mirror" / `github.com/CyncDevelopment` | `git.coincync.network/coincync/cync-protocol` (forgejo) |
| "Atomic swaps in development for testnet" | "Atomic swaps are a MAINNET launch blocker — testnet does not include them. CIP-001 has the design." |
| "Mainnet TBA" or "Mainnet 2027" | "Mainnet target: 2026-10-01" |
| "Premine 1%" / any nonzero premine | "Zero premine. Article II forbids it." |
| "Dev fee 1%" / any nonzero dev tax | "Zero dev tax. Article III forbids it." |
| "RandomX or GPU friendly" | "RandomX, CPU-only by design. GPU/ASIC have no meaningful advantage." |
| References to Spark / Orchard as live | Both are PHASE-2 modules, DISABLED on testnet, optional opt-in for mainnet — see explorer block-detail privacy cards |

---

## Update cadence

- **Status pulse** (#status): every 6 hours via webhook
- **Pinned messages**: re-verify weekly during testnet, monthly during mainnet
- **This file**: regenerate before any major announcement; numbers go stale fast
