# Sync-Recovery Consolidation

**Status:** design / proposal (2026-10-10)
**Scope:** testnet only; any behavioral change lands **gated**, nothing is ripped out on the live net.

## Problem

Over 2026-06 → 2026-10 we accreted **four** independent stall-recovery layers.
They were each added to fix a specific live incident, in isolation, and they now
**overlap**: three of them trigger off the *same* signal — "block height frozen
while the node is behind its sync target for ~300s" — and fire in a cascade. The
live self-heal demo captured exactly this: a soft self-heal `WARN` at 300s
immediately followed by an `EMERGENCY-TIER-3` `ERROR` on the same tick, on the
same wedge.

That is not inherently wrong (soft-before-hard is a sane ordering), but it is
**undocumented and uncoordinated**: no single place states which layer owns which
failure mode, the thresholds were picked independently and happen to collide, and
the newest layer (in-process self-heal, #274) now duplicates most of what the
external systemd watchdog does. This doc maps ownership and proposes a staged,
gated consolidation.

## The four layers

| # | Layer | Where | Trigger | Action | Scope | Reversible? |
|---|-------|-------|---------|--------|-------|-------------|
| 1 | `recover_stuck_downloads` | `src/network/sync.rs:1826` | download-scheduler orphans: hashes in `downloading` with no matching `pending_requests` entry | re-queue orphaned hashes to the front of `pending_headers`, drop `Synced`→`Blocks` | in-process, per-tick | soft (pure scheduler bookkeeping) |
| 2 | Tier-1/2/3 stall escalation | `src/network/node/sync_driver.rs` §4 | consecutive no-progress tick firings (`stall_count`, `tier2/3_fires_since_progress`) | rotate peer selection, re-request; Tier-3 backoff pauses 30s after `N_T3_BEFORE_BACKOFF` | in-process, tick loop | soft (request rotation) |
| 3 | EMERGENCY-TIER-3 deep reset | `src/network/node/sync_driver.rs` §1/§3 | height not advanced for `EMERGENCY_T3_NO_PROGRESS_SECS` (~300s) **despite** `is_stalled()==false`; "behind" judged by `max(target_height, live peer heights)` | clear address tried-list, drop expired orphans, reset headers-request timeout, force `SyncState::Headers`; re-fire throttled to `EMERGENCY_T3_REPEAT_SECS` | in-process, tick loop | medium (drops tried-list + orphans; no restart) |
| 4a | In-process self-heal | `src/network/node/maintenance.rs` (`run_self_heal_tick`, #274) | `!is_synced` **and** a peer >`SELF_HEAL_HEIGHT_SLACK` ahead **and** no height progress `SELF_HEAL_STALL_SECS`=300 **and** outside `SELF_HEAL_MIN_GAP`=600 | `retain_connected_peers` (purge phantom peer-heights) + `expire_stale_work_claims` + `arm_near_tip_catchup` | in-process, 60s tick | **soft** (no peer drops, no restart, no new plumbing) |
| 4b | External sync watchdog | `deploy/fleet/coincync-sync-watchdog.{sh,service,timer}` | height frozen `STALL_SECS`=300 while behind target **or** isolated (0 peers → false-synced); outside `MIN_RESTART_GAP`=600 | `systemctl restart coincync-node` (re-seeds scheduler via fresh `--addnode` dial) | **systemd, fleet hosts only** | hard (process restart) |

## Failure-mode → owner map

- **Download scheduler orphans** (hashes stuck in `downloading`, no in-flight
  request) → **#1 `recover_stuck_downloads`**. Narrow, cheap, correct. Keep as-is.
- **Transient peer-selection churn** (a peer went quiet, need to rotate) →
  **#2 Tier-1/2/3**. Keep as-is.
- **Phantom peer-height / stale work-claim wedge** (a departed peer's stale
  height pins `best_known_height` so `is_synced()` is false forever; see
  [phantom-IBD-target bug]) → **#4a self-heal** (soft purge). This is the common
  live wedge and the softest fix owns it.
- **Orphan-fetch cascade** (engine internally busy, `is_stalled()==false`, zero
  real progress — the 2026-06-02 coincync-lon 22h stall) → **#3 EMERGENCY-TIER-3**
  deep reset. Only this layer clears the tried-list + orphan set in-process.
- **Hard wedge nothing in-process can clear** (scheduler spinning
  "Recovered N stuck downloads" every 0.5s without advancing — the 2026-10-10
  fresh-relay stall; or an isolated 0-peer false-synced node) → **#4b watchdog**
  restart, as a genuine last resort.

## The redundancy

Layers **#3, #4a, #4b all key off the same ~300s "frozen-while-behind" signal**
with the same 600s rate-limit (#4a/#4b). They differ only in how hard they hit:

```
#4a self-heal  → soft:  purge phantom heights, expire claims, re-arm catchup   (every node)
#3 EMERGENCY-T3 → medium: clear tried-list + orphans, reset headers, force Headers (every node)
#4b watchdog   → hard:  restart the process                                     (fleet only)
```

#4a was explicitly written to **internalize** #4b ("internalizes
coincync-sync-watchdog.sh as a SOFT in-process recovery, so every node self-heals
— no watchdog, no restart"). It does so for the *common* wedge, but it cannot
cover the two cases that genuinely need a restart: (a) a hard scheduler spin that
survives a soft re-arm, and (b) an isolated 0-peer node that reports false-synced
(the self-heal's own `!is_synced` gate never trips there, so #4a no-ops — only
#4b's peer-aware gate catches it).

So: **#4a does not fully subsume #4b yet.** It subsumes the *routine* trigger and
leaves #4b as the backstop — but today both fire at the same threshold, so the
watchdog still restarts nodes the self-heal could have fixed soft.

## Proposal (staged, gated)

**Goal:** one documented ladder — soft in-process first, hard restart only as
true last resort — without a flag day on the live fleet.

### Stage 1 — document + de-collide thresholds (no code risk)
- Land this doc as the single source of truth for the ladder.
- Make the watchdog genuinely *last-resort* by **raising its `STALL_SECS` above
  the self-heal's**, so self-heal (300s) + EMERGENCY-TIER-3 get first crack and
  the watchdog only restarts if the chain is *still* frozen well after both have
  tried. This is a one-line env change in the timer unit
  (`STALL_SECS=900`), fully reversible, no binary change. Keep `MIN_RESTART_GAP`.

### Stage 2 — make the watchdog self-heal-aware (gated)
- Export a `self_heal_fires_total` + `last_self_heal_unix` counter on
  `get_info` (metrics already has the gauge pattern from #273).
- Gate the watchdog restart on **"height frozen AND ≥N self-heal fires since last
  progress"** — i.e. only restart once the soft path has demonstrably tried and
  failed. Behind an env flag (`COINCYNC_WATCHDOG_REQUIRE_SELFHEAL=1`), default
  off, so we can enable it per-host and watch before fleet-wide.

### Stage 3 — teach self-heal the isolated-node case (gated)
- The one failure #4b catches that #4a structurally cannot is the isolated 0-peer
  false-synced node. Add a self-heal sub-case: if `peer_count==0` for
  `SELF_HEAL_STALL_SECS`, re-run bootstrap/`--addnode` dial in-process (we already
  have re-bootstrap-on-isolation in the mesh layer; wire self-heal to trigger it).
  Gated (`COINCYNC_SELFHEAL_ISOLATION=1`, default off). Once this is proven live,
  #4b's remaining unique capability is only the hard process restart for a wedge
  that survives *everything* in-process — at which point the watchdog can drop to
  a very high `STALL_SECS` (e.g. 1800s) and exist purely as a crash-loop backstop
  alongside systemd `Restart=on-failure`.

### What we do NOT do
- We do **not** delete the watchdog. A soft in-process layer can never cover
  "the process itself is wedged in a way only a restart clears." #4b stays as the
  floor of the ladder, just demoted to true last-resort.
- We do **not** touch #1 or #2 — they own distinct, narrow failure modes and are
  not part of the 300s-signal redundancy.
- We do **not** change any of this unilaterally on the live net: Stages 2/3 land
  gated-off and are enabled per-host with observation first (same discipline as
  shielded / Warren / difficulty-damping).

## Test / rollout notes
- Stage 1 is config-only (timer env) + docs — deploy via `safe-deploy.sh`,
  verify `self_heal_fires` stays 0 on the synced fleet (correct no-op) and the
  watchdog restart count drops.
- Stages 2/3 each need a unit test for the new gate predicate (pure function,
  like `self_heal_decision`) before the gated path ships, and a single-host
  soak with the flag on before any fleet-wide enable.

## References
- `src/network/node/sync_driver.rs` §1–§5 audit map (tier taxonomy + threats + tests)
- `src/network/sync.rs:1826` `recover_stuck_downloads`
- `src/network/node/maintenance.rs` `run_self_heal_tick` / `self_heal_decision` / `self_heal_recover` (#274)
- `deploy/fleet/coincync-sync-watchdog.sh`
- phantom-IBD-target bug (the wedge #4a soft-owns); smoothness-program Tier-A notes
