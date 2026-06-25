# CoinCync Backlog

**Last updated:** 2026-06-24
**Owner:** ghostrider1092
**Mainnet GA:** 2026-10-01 (hard deadline)
**Testnet v1.0.12 hard fork:** ~2026-07-01 at h=13_000

This is the **single source of truth** for what to work on next. Read top-to-bottom every session. Don't open new work outside this list without adding it here first.

---

## Working agreement

1. **One backlog. One direction at a time.** This file. Items in priority order. No ad-hoc work that isn't here.
2. **Each session starts with `cat docs/BACKLOG.md`.** Pick the top unblocked item. Work it to "done." Then move to the next.
3. **"Done" means:**
   - **Code change:** PR merged + CI green + no `--admin` overrides (unless CI is provably stale)
   - **Deploy:** code on fleet + tip advancing 1+ hr + monitoring green
   - **Docs:** committed to `docs/` (not `out/`, not memory) + linked from this file
   - **Runbook:** committed to `docs/operations/` + step-by-step + tested at least once
4. **Consensus-touching changes need a "consensus change session" framing.** Anything in `src/consensus/`, `src/chain.rs`, activation heights — explicit session, not slipped into other work.
5. **No silent ad-hoc SSH changes.** Anything done on fleet hosts: capture in `scripts/` or `docs/operations/` before/after.
6. **One human reviewer + AI is not enough for v1.0.12 fork.** Get a second pair of eyes on consensus changes before July 1.
7. **Memory files = AI-internal cache, not source of truth.** This BACKLOG is the source of truth.

---

## 🔥 P0 — blockers for v1.0.12 testnet fork (~2026-07-01)

| # | Item | Owner | Done when |
|---|---|---|---|
| 1 | seed1↔miner gossip broken — fix peering | operator+AI | seed1 reports miner in active peer list, tip advances within 5 min of miner producing |
| 2 | Cron sync workaround as bridge (deployed; install-script grep bug) | AI | cron fires every 10 min, /var/log/chaindata-sync.log shows clean runs |
| 3 | seed1 RAM upgrade or db-cache config — currently 3.8 GB, OOM-prone | operator (Vultr console) | seed1 stable 24 hr no OOM + no swap above 20% utilization |
| 4 | Discord announcement to community miners (template ready) | operator | post by 2026-06-26 in #announcements, #mining, #testnet |
| 5 | Cut `v1.0.12-rc1` GitHub Release + reproducible-build verification | operator | release page has binary + sha256 + repro-verify by independent party |
| 6 | Staggered fleet upgrade (no-bulk-restart rule) | operator | all 5 fleet nodes on v1.0.12-rc1, peer_count≥3, tip_age<300s between each |
| 7 | Activation watch at h=13_000 | operator+AI | all 5 fleet nodes same tip post-activation, mining continues |

**P0 done = July 1 fork activates cleanly + public RPC stays fresh through activation.**

---

## ⏰ P1 — pre-mainnet (2026-10-01)

| # | Item | Owner | Done when |
|---|---|---|---|
| 8 | Monitoring + alerting: Grafana dashboard reading Prometheus :28082; Discord webhook on `is_synced=false OR tip_age>600s` | operator | alert fires within 5 min of test partition |
| 9 | Fleet config as code: `scripts/fleet-config.json` is single source, units regenerated, CI verifies units match | AI | edit JSON → run sync script → all 5 hosts converge; no hand-edited systemd units |
| 10 | Remove `95.179.165.225` (nginx-only api) from every node's `--addnode` list — wasted dial budget | AI | grep across fleet shows zero refs to 95.179.165.225 in node addnode args |
| 11 | Remove self-IP from each node's `--addnode` list — wasted dial budget | AI | no node's addnode list contains its own external IP |
| 12 | Per-failure-mode runbooks in `docs/operations/`: chain stall, OOM, peer partition, miner down, fork rollback | AI | one .md per failure mode, each ≤1 page, each tested in dry-run |
| 13 | Fleet box right-sizing to 8 GB+ all nodes | operator (Vultr) | all 5 hosts ≥8 GB RAM verified via `free -h` |
| 14 | Mainnet-specific config + IP allocation (separate from testnet fleet) | operator | mainnet seeds provisioned, MAINNET_SEED_NODES populated, mainnet bech32 HRP `cync` verified |
| 15 | Mainnet code freeze + final binary | operator+AI | git tag `v1.0.12.x-mainnet`, reproducible binary on release page |
| 16 | Mainnet genesis ceremony + launch coordination | operator | genesis block mined, 5 mainnet seeds live, Discord announcement, explorer live |

**P1 done = mainnet launches Oct 1 with monitored, organized fleet.**

---

## 🛠 P2 — post-mainnet (v1.0.12.x point releases, Aug-Sep 2026)

| # | Item | Owner | Done when |
|---|---|---|---|
| 17 | Item 10f from audit marathon: per-peer pending_headers cap (~180 LOC structural) | AI | PR merged + 4-wk soak on testnet no incidents |
| 18 | Item 10g from audit marathon: per-outbound nonce tracking (~256 LOC, supersedes #96) | AI | PR merged 4-8 wks after #96 lands on fleet, no handshake regressions |
| 19 | halo2_gadgets 0.3→0.5 + orchard →0.14 + audit crates/orchard-side; re-enable yank check | AI | crypto-reviewed PR merged, `.cargo/audit.toml` `[yanked] enabled = true` restored |
| 20 | Schema versioning verification: all 11 persisted Borsh structs use the v1 stamp; migration tests | AI | PR with migration test suite green |

---

## 🔧 P3 — v1.0.13 next testnet fork (late 2026)

| # | Item | Owner |
|---|---|---|
| 21 | Fork-choice tiebreak (zebrad lowest-hash pattern) ~200 LOC | AI |
| 22 | MTP-in-ASERT (Verge 2018 defense) | AI |
| 23 | Merkle RFC 6962 leaf/node tags (CVE-2012-2459) | AI |
| 24 | Graduated ring ramp 5→7→11→16 | AI |
| 25 | BIP-9 validator wiring completion | AI |
| 26 | Crypto-adjacent dep bumps: tari_bulletproofs_plus 0.4→0.5 (#56), rand 0.8→0.10 (#50), rocksdb 0.22→0.24 (#54), secrecy 0.8→0.10 (#48), plus #51 | AI |

---

## 💼 P4 — v1.1 cyncswap (Q1-Q2 2027)

| # | Item |
|---|---|
| 27 | NLnet grant decision (~Sept 2026) — funded = external audit budget |
| 28 | Atomic swap impl in `crates/coincync-swap` |
| 29 | External audit (NLnet or self-funded) |
| 30 | v1.1 testnet fork for cyncswap consensus rules |
| 31 | v1.1 mainnet release |

---

## 🌀 Phase 2 (>2027)

- Halo2 shielded pool (CIP-004)
- Lelantus Spark pool (CIP-005)
- MimbleWimble cut-through (CIP-003)
- FROST multisig (CIP-008/012)

---

## ✅ Shipped this week (2026-06-23 → 2026-06-24)

- **PRs #90-101 (12-PR audit-prep marathon)** merged: utxos atomic cleanup, scanner ghost-balance, wallet C1 height fix, mempool DoS bounds, addr-book DoS bounds, ban-GC, **eclipse-attack defense**, **CVE-2015-3641 unroutable filter**, compact-block validation, Inv dedup, RPC saturating math, RPC hex caps
- **PR #102 + tag v1.0.12-rc1** merged: testnet hard-fork activation at h=13_000
- **PR #103** merged: CI unblock (halo2_gadgets yank-skip + quinn-proto 0.11.15 for RUSTSEC-2026-0185)
- **Chain partition 2026-06-22 resolved** on public RPC (manual chaindata-tarball transfer; gossip still broken — see P0 #1)
- **`docs/operations/v1.0.12-hard-fork-rollout.md`** committed (operator runbook)
- **`docs/operations/v1.0.12-discord-announcement.md`** committed (post drafts)
- **`scripts/chaindata-sync-miner-to-seed1.sh` + `install-incoming-chaindata.sh`** written (cron workaround for gossip; install-script grep bug — see P0 #2)

---

## ⛔ Hard rules / never do

1. **Never restart all 5 fleet nodes within 10 min.** Caused 2 partitions previously. Always wait peer_count≥3 AND tip_age<300s between hosts.
2. **Never wipe chaindata on a 3.8 GB box.** Fresh IBD OOMs. Use chaindata-tarball recovery instead.
3. **Never hand-edit `/etc/systemd/system/coincync-node.service`.** The unit says use `scripts/fleet-config.json` + `scripts/sync-fleet-config.sh`.
4. **Never stop `coincync-node` on the miner without explicitly restarting `coincync-rig` after.** Systemd dep kills the rig.
5. **Never `git commit`/`git push` without explicit per-change authorization from operator.** "Continue" on a plan does NOT include push.
6. **Never `gh pr merge --admin` past failing checks without provable evidence the checks are stale.** Today's bulk merge with --admin was justified by CI failures being pre-#103; document that reasoning when reused.
7. **Never bypass `cargo audit` policy** (`.cargo/audit.toml`) for RUSTSEC vulns. Yanks are fine to skip (already configured); CVEs require a real dep bump.
8. **Never assume `api.coincync.network` is a coincync-node.** It's nginx-only (95.179.165.225). The real fleet IPs are seed1/2/3, explorer, and the miner.
9. **Never paste credentials in chat.** If a real token appears in conversation, revoke it and redirect to `gh auth login --with-token` stdin.

---

## 📚 Reference

- `docs/operations/v1.0.12-hard-fork-rollout.md` — fork rollout playbook
- `docs/operations/v1.0.12-discord-announcement.md` — community comms drafts
- `scripts/fleet-config.json` — fleet single source of truth (should be — see P1 #9)
- `scripts/chaindata-sync-miner-to-seed1.sh` — cron workaround
- `src/testnet.rs` — testnet seed IPs (currently authoritative for seed list)
- `src/network/dns_seeds.rs` — DNS-resolvable seed names
- `CHANGELOG.md` — historical changes

---

## 📈 How to use this file

**Session opening:**
```bash
git pull origin main
cat docs/BACKLOG.md  # scan P0 + P1
```

Pick the top P0 unblocked. Work it. When "done" per the criteria above, move it to "Shipped" section and commit this file with the update.

**Session closing:** commit any backlog changes. New items go in P-level matching their urgency. If new item displaces a P0, justify it inline.

**Never let this file get stale.** If you didn't update it this session, the session didn't add organized value.
