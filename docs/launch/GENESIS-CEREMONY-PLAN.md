<!-- markdownlint-disable MD013 MD036 -->
# v1.0 Mainnet Genesis Ceremony — Plan + Checklist

**Target:** 2026-10-01 00:00:00 UTC
**Acceptance criteria** (from [docs/roadmap.md](../roadmap.md)): Mainnet seeds + initial checkpoint set + monitoring live ≥ 7 days pre-genesis. If not met by the target month, **v1.0 mainnet slips.**

This document breaks the genesis ceremony into sub-tasks with owners, timelines, and verification gates. It's operational; no cryptographic content. The crypto questions are answered by the audit (engagement target ~July) and the dormant-vs-active CIP-009.D decision (see [decisions/2026-05-23-cip-009d-production-posture.md](../decisions/2026-05-23-cip-009d-production-posture.md)).

---

## T-minus timeline

```
T-30 days (2026-09-01)   → All infrastructure live. Genesis-block hash candidate frozen.
                            DNS migrated to mainnet endpoints. Monitoring + alerting confirmed.
                            All sub-tasks (1-5) below show ✅.

T-14 days (2026-09-17)   → Rehearsal: chain-fork practice on testnet. Tag v0.99.x-genesis-rehearsal.
                            Bring the rehearsal chain up to a known height, then run the same
                            cut-and-launch procedure that genesis day will use. Confirm
                            monitoring catches the new chain. Verify wallet onboarding.

T-7 days (2026-09-24)    → Final acceptance gate. If anything in §6 below is ❌, slip.
                            "Mainnet seeds + initial checkpoint set + monitoring live ≥ 7 days
                            pre-genesis" — this is the literal date that means.

T-3 days (2026-09-28)    → Communication: pin genesis-day announcement in #announcements,
                            X/Mastodon/Nostr social drafts, BTT OP refresh. Confirm operators.

T-1 day  (2026-09-30)    → Final dry-run of genesis-block-mining at the target height.
                            Operators confirmed in private group chat. Press a hash, watch peers.

T-0      (2026-10-01)    → Genesis block mined at 00:00:00 UTC. Network observed.
                            Within 15 min: first non-genesis block. Within 60 min: ≥5 nodes
                            converged on tip. Within 24h: explorer + faucet (if any) live.

T+24h   (2026-10-02)    → "It's running" post. Open a public retrospective doc.

T+7 days (2026-10-08)    → First incident-or-no-incident retrospective.
```

---

## Sub-tasks (own + execute)

### 1. Mainnet seed nodes

**Goal:** ≥5 mainnet seed nodes online + DNS-resolvable ≥ 7 days pre-genesis, distributed across ≥3 continents.

| Sub-task | Status | Notes |
| --- | --- | --- |
| 1.1 Decide hosting model (VPS / dedicated / hybrid) | TODO | Recommend: 5× Hetzner / OVH / Vultr VPS, $5-10/mo each. ~3 continents represented. |
| 1.2 Pick 5 host candidates with hard public IPs | TODO | Need: 1× North America, 1× South America, 1× Europe, 1× Asia, 1× Oceania. Pinned IPs (no DHCP). |
| 1.3 Procure VPS instances | TODO | Single account is fine. Pay ~$30/mo total. Provision: 4GB RAM, 2 vCPU, 80GB SSD each. |
| 1.4 Install + configure `coincyncd` mainnet binary | TODO | `--network mainnet --listen 0.0.0.0:NN`. Firewall: only the listen port + SSH. |
| 1.5 Generate seed-node identity keys + persist | TODO | Each node's persistent identity key goes into operator-tracked vault. Lose these = lose the node's seed-list slot. |
| 1.6 Test inbound P2P from external IPs | TODO | `nmap` from a separate IP, confirm port open. Try a `coincync-node connect <ip:port>` smoke from a clean box. |
| 1.7 Bake seed-list into mainnet binary (DNS-bootstrapped + IP-fallback) | TODO | `src/network/dns_seeds.rs` already supports this — add the mainnet seed entries. |
| 1.8 Confirm seed-discovery works in fresh mainnet binary | TODO | Spin a 6th node from scratch with only the bin + seed list. Should bootstrap to the other 5 within 60 sec. |

**Owner:** [self] for VPS procurement + config. Volunteer testnet ops for 2-3 of the slots may be willing to host — ask in #dev-updates ~T-45 days.

### 2. Initial checkpoint set (Layer 5)

**Goal:** Hardcoded consensus checkpoints in `src/consensus/checkpoints.rs` (or equivalent) covering genesis + first month of expected blocks (~21 600 blocks at 120s block time = ~30 days).

| Sub-task | Status | Notes |
| --- | --- | --- |
| 2.1 Decide checkpoint cadence | TODO | Recommend: genesis + every 2 880 blocks (≈ every 4 days). Cuts 8 checkpoints in the first month. |
| 2.2 Document the release-process workflow for cutting + signing each checkpoint | TODO | Write `docs/operations/CHECKPOINT-CADENCE.md`. Include: how to fetch the canonical hash, how to sign it (PGP), how to bake into next release. |
| 2.3 Cut genesis-block hash before T-7 days | TODO | Genesis block content is deterministic — see §3 below. Hash known once content is. |
| 2.4 Bake genesis + first checkpoint into v1.0.0 binary | TODO | First non-genesis checkpoint at block 1 (sanity), then per cadence after that. |

**Owner:** [self]. Requires PGP key in vault; if not yet set up, do that first.

### 3. Genesis block content

**Goal:** Genesis block content is deterministic, reproducible, and includes the right embedded data.

| Sub-task | Status | Notes |
| --- | --- | --- |
| 3.1 Pick genesis-block coinbase reward target | TODO | ~50 CYNC per [docs/roadmap.md](../roadmap.md) emission. Recipient address: ?? — discuss. Burn? Charity? Distribute? |
| 3.2 Pick genesis-block memo / OP_RETURN content | TODO | Convention: encode a contemporary headline from a non-cryptocurrency source for unforgeable timestamping. Pick one. |
| 3.3 Pick genesis-block difficulty | TODO | Initial difficulty matters. Too high = no one mines, chain dies. Too low = early reorg risk. Recommend matching final testnet difficulty -50% as safety margin. |
| 3.4 Generate genesis block at T-30 days (frozen) | TODO | Compute the hash. Verify with multiple independent invocations on different machines. Commit the hash to the codebase. |
| 3.5 Embed genesis hash in `src/constants.rs` + critical-files lockfile | TODO | This is consensus-locked. Audit firm must see this commit as final pre-engagement. |

**Owner:** [self]. The choice of memo + coinbase recipient is the project's first public-record choice — pick carefully.

### 4. Mainnet faucet decision

**Goal:** Decide whether mainnet runs a faucet, OR ships with "mine your own" as the entry path.

| Sub-task | Status | Notes |
| --- | --- | --- |
| 4.1 Decide: faucet OR mine-your-own (binary choice) | TODO | See discussion below. |
| 4.2 If faucet: pick funding model (donation pool / dev allocation / paid faucet) | N/A or TODO | Article XII forbids admin authority — faucet operator should be community-funded, not project-controlled. |
| 4.3 If mine-your-own: write a "0 → first CYNC" guide | TODO | Already partially there in the README. Polish + include realistic time estimates ("you mine your first block in ~X minutes on a typical laptop"). |

**Decision discussion:**

- **Pro-faucet:** lowers the barrier to first transaction. New users get something to send/receive without setting up a miner.
- **Anti-faucet:** mainnet token has real value. "Free coins" attracts farmers + complicates Article XII (no admin authority — who runs the faucet?). Testnet faucet was free-as-in-beer; mainnet faucet means *someone is paying for free coins*.
- **Strong recommendation: mine-your-own.** RandomX on a typical laptop should mine the first block within ~10-30 minutes at genesis-day difficulty. That's the same UX as Monero's first weeks. The friction is the feature.

### 5. DNS + monitoring + alerting

**Goal:** Mainnet endpoints DNS-resolvable + monitored ≥ 7 days pre-genesis.

| Sub-task | Status | Notes |
| --- | --- | --- |
| 5.1 DNS: `api.coincync.network/rpc/mainnet` | TODO | Mainnet RPC endpoint. Mirrors the testnet one. SSL via Let's Encrypt + auto-renewal. |
| 5.2 DNS: `seed1.coincync.network` ... `seed5.coincync.network` (A records to seed VPSs) | TODO | Bake into `src/network/dns_seeds.rs`. |
| 5.3 DNS: `explorer.coincync.network` for mainnet | TODO | Spin up the explorer against the mainnet RPC. |
| 5.4 Grafana dashboard for chain tip, peer count, mempool, hashrate | TODO | Already exists for testnet. Clone, point at mainnet. |
| 5.5 Alerting: `chain-tip-stalled > 15min`, `peer-count < 3`, `hashrate-drop > 50%` | TODO | Slack / Discord webhook + a phone-pager fallback. Include the maintainer's PGP-signed public address. |
| 5.6 Status page (`status.coincync.network`) | TODO | Optional but recommended. UptimeRobot-class is fine. |

**Owner:** [self] for DNS + Grafana. The status page can be community.

### 6. T-7 acceptance gate checklist

**Run this on 2026-09-24. If anything is ❌, v1.0 mainnet slips to a target month past October.**

```
[ ] All 5 mainnet seed nodes online + accepting P2P connections + listed in dns_seeds.rs
[ ] Genesis block content frozen + hash committed to src/constants.rs + critical-files lockfile updated
[ ] First month of checkpoints (≥ 8 entries) baked into v1.0.0 binary
[ ] Wallet v2 mainnet build verified on Windows + macOS + Linux
[ ] coincyncd mainnet binary verified: starts, connects to ≥3 of the 5 seeds, sync with itself
[ ] Reproducible Docker build sign-off complete (separate work item)
[ ] DNS resolves: api.coincync.network/rpc/mainnet, seed{1..5}.coincync.network, explorer.coincync.network
[ ] Grafana dashboard live + alerting confirmed firing on simulated incidents
[ ] All audit findings addressed OR documented as known-issue with explicit ship-anyway decision
[ ] CIP-009.D decision signed (dormant or active — see decisions/2026-05-23-cip-009d-production-posture.md)
[ ] Genesis-day operators confirmed in private group chat with their roles
[ ] Final dry-run on testnet at T-14 days passed cleanly
[ ] Mainnet faucet decision communicated publicly (and faucet running if applicable)
[ ] Communications drafts ready (Discord pin, BTT OP refresh, social)
```

---

## Abort criteria

Slip the launch if any of the following on T-7 day:

1. Any seed node is offline + replacement not ready
2. Audit firm has not delivered a final report
3. Any critical audit finding is open (severity High or Critical)
4. CIP-009.D decision still un-signed
5. Reproducible build has not produced byte-identical output across ≥2 machines
6. Wallet v2 has any user-facing crash in the standard onboarding flow on any of 3 OSes
7. Maintainer is unavailable for T-3 through T+7 days (vacation, illness, emergency)

The cost of slipping is real but bounded. The cost of launching with any of (1)-(7) unresolved is unbounded.

---

## What this plan does not include

- **Exchange listings.** Out of scope at v1.0 — focus on the chain working. Exchanges find good chains.
- **Marketing campaigns.** Out of scope — the testnet record speaks for itself.
- **NFT / smart-contract / DEX surfaces.** Not on the v1.0 roadmap. Won't add them under launch pressure.
- **Token-price machinery.** Article XII — no admin authority means no project-controlled liquidity provisioning, no market-maker contracts, no rug-pull vectors.

The genesis ceremony is the technical handoff from "chain in development" to "chain running in production." That's the only goal of this plan. Adoption, liquidity, and price action happen on their own schedule after launch.

---

## Open questions for the maintainer

- Who are 2-3 candidate volunteer testnet operators who'd take a seed-node slot?
- Genesis coinbase recipient: burn / charity / specific address? Public-record choice.
- Genesis memo content: which non-crypto headline gets immortalized?
- Are you willing to be on-call T-3 through T+7?
- Is the maintainer's PGP key already published + verifiable?

These are the choices that turn this plan from a checklist into a real ceremony. None are blockers today; all are blockers by T-30 days.
