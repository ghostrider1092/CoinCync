# 2026-06-06 — Fleet recovery after sync.rs hotfix

## Summary

The testnet fleet wedged after deploying the previous day's sync.rs
phantom-target hotfix (commit `35332d8`). Three independent bugs
stacked on top of each other, and each one masked the others until
diagnosed in order. End state: 5-node fleet clean, chain advancing,
peer tables rewritten, two follow-up commits on `main`.

## Timeline (all times UTC)

| Time | Event |
| --- | --- |
| 2026-06-05 | Sync hotfix `35332d8` deployed to fleet (Vultr seed1, seed2, explorer-Dallas). Binary SHA `0d276145…`. |
| 2026-06-05 evening | Fleet wedges. seed1 stuck at h=49, can't advance. Logs show `Hardcoded checkpoint mismatch at height 50`. Operator pauses, picks 5-option recovery menu before logging off. |
| 2026-06-06 ~16:00 UTC | Recovery begins. **Bug #1 found:** `src/testnet.rs` on `main` still has the 280 pre-2026-06-04-wipe checkpoint entries. The v1.0.11 branch had cleared them but main never got the patch. The hotfix binary inherited the stale table. Build #2: clear checkpoints, refresh `critical_files.lock`, rebuild. New SHA `f458108b…`. |
| 2026-06-06 ~17:00 UTC | Deploy script run. **Bug #2 manifests:** the wipe targeted `/var/lib/coincync/chaindata` but RocksDB actually lives at `/var/lib/coincync/testnet/`. The wipe was a no-op. Nodes restarted with the same chaindata that wedged them. |
| 2026-06-06 ~17:30 UTC | Correct path identified; re-wipe `/var/lib/coincync/testnet`. Fleet boots fresh at h=0. seed1+seed2 active. |
| 2026-06-06 ~18:00 UTC | seed1+seed2 IBD slowly, status stays `syncing`, chain advances 0→508. **Bug #3 found:** the Dallas explorer box at `207.148.6.50` was missed — the SSH config `ric` alias pointed at a DigitalOcean box, not the live Vultr explorer. It still ran the pre-2026-06-04 chaindata advertising the dead chain to peers. |
| 2026-06-06 ~19:00 UTC | Holdout explorer wiped + redeployed. Fleet converged on the post-wipe chain. |
| 2026-06-06 afternoon | While auditing config, **discovered the bigger root cause**: `bootstrap.rs::TESTNET_NODES`, `dns_seeds.rs::MAINNET_FALLBACK`, `mainnet.rs::MAINNET_SEED_NODES`, the wallet seed list, nginx routes, prometheus scrape targets, docker-compose `--addnode` flags, and several scripts all referenced 10 IPs that no longer exist (4 decommissioned DO + 6 boxes that were never actually in the live fleet). Every node restart wasted its first ~30s dialing graveyard. Plausible contributor to the IBD stalls. |
| 2026-06-06 late | 17-file scrub committed (`c893b6c`). All hardcoded peer tables now point at the live 5-node Vultr fleet. Two commits pushed to origin/main. |

## Root causes

### #1 — testnet.rs cleanup never merged to main

The 2026-06-04 cascade-recovery work cleared the checkpoint table
in `src/testnet.rs`, but the commit landed on
`v1.0.11-canonical-clsag` rather than `main`. The sync-hotfix
binary was built from `main`, which still had 280 stale checkpoints
including the one at h=50 that matched the *pre*-wipe chain, not
the current chain.

**Fix:** commit `ef21132` on main re-clears the table with a
justification comment.

### #2 — chaindata path mismatch in the deploy script

The deploy script wiped `/var/lib/coincync/chaindata` but the
actual RocksDB data dir is `/var/lib/coincync/testnet/` (the
network-name subdirectory is automatic from
`NodeConfig::data_dir`). The wipe deleted a non-existent path
without error and the nodes restarted with the same broken
chaindata.

**Fix:** the corrected path is documented in this incident. Any
future operational script that wipes chaindata must reference the
`<data_dir>/<network>/` layout, NOT a `chaindata/` subdirectory.

### #3 — graveyard peer tables across the codebase

10 dead IPs were embedded in 17 files. Most of those tables are
referenced at node boot or wallet startup. Even the v1.0.10
binaries wasted bootstrap time dialing them; the May/June IBD
slowness reports were probably partially attributable to this.

| IP | Label | Why dead |
| --- | --- | --- |
| `165.245.161.62` | RIC | DigitalOcean droplet, decommissioned |
| `143.110.218.99` | TOR | DigitalOcean droplet, decommissioned |
| `165.245.140.113` | ATL | DigitalOcean droplet, decommissioned |
| `64.227.49.44` | SFO | DigitalOcean droplet, decommissioned |
| `138.68.172.80` | LON | Never in live fleet |
| `45.55.32.13` | NYC/NYC3 | Only NYC node is `seed1 = 66.135.23.193` |
| `192.34.59.42` | NYC1 | Never in live fleet |
| `46.101.138.120` | FRA | Operator's Frankfurt is `api = 95.179.165.225` |
| `164.92.153.24` | AMS | Operator's Amsterdam is `seed2 = 140.82.57.168` |
| `170.64.142.146` | SYD | Never in live fleet |

The live fleet:

| Box | IP | Role |
| --- | --- | --- |
| seed1 | `66.135.23.193` | New York |
| seed2 | `140.82.57.168` | Amsterdam |
| seed3 | `207.148.111.76` | Tokyo |
| explorer | `207.148.6.50` | Dallas |
| api | `95.179.165.225` | Frankfurt |

**Fix:** commit `c893b6c` rewrites every hardcoded peer / seed /
mirror / route / scrape / addnode table across 17 files to the
live 5-node fleet only. Decommission comments preserved as
historical record.

## Follow-up

- [ ] **`mirrors.json` docs+landing backend IPs are nulled.** When a canonical
  docs / landing host is re-established, set them.
- [ ] **DigitalOcean droplets confirmed decommissioned** per operator; SSH
  config aliases (`ric`/`toronto`/`atl`/`sfo`) removed. Other dead aliases
  (`nyc`/`lon`/`syd`/`nyc1`/`fra`/`ams`) still in `~/.ssh/config` — operator
  to remove or repurpose.
- [ ] **Operational runbook update:** add a "post-wipe holdout check" step.
  After any coordinated wipe, query every box's chain height; mismatch
  ⇒ a box was missed.
- [ ] **Deploy-script unit test:** add a test that `wipe` targets exist
  before deleting (`stat` the directory, alert if absent).
- [ ] **Peer-table provenance:** any future commit that touches a hardcoded
  peer table must include a comment with the date verified and the
  source (operator panel, DNS, etc.). Tables drift quietly otherwise.

## Status at close

- Fleet: seed1 + seed2 + explorer-Dallas active on new binary `f458108b…`,
  chain advancing.
- seed3 + api still inactive (chaindata not relevant for this incident).
- Mining: chain advanced ~140 blocks over the afternoon despite operator's
  local rig being off — community / external miner is contributing.
- Two unverified-but-cryptographically-signed commits on origin/main.
  Signing-key registration on GitHub is pending operator action.
