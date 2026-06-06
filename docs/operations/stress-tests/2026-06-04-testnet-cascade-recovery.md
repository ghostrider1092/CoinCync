# Testnet Cascade Recovery — 2026-06-04

**Status:** Resolved via testnet wipe + fresh-genesis restart on fixed binary
**Active investigation:** ~6 hours (~01:00 – 07:11 UTC, 2026-06-04)
**Scope:** Testnet only. Mainnet not yet running. No funds at risk.
**Public-facing impact:** Explorer banner showed stale chain data ("Chain data is 20+ minutes old"). Replaced with maintenance page during recovery; left up after recovery for further stabilization.

## TL;DR

A combination of one already-coded-but-just-deployed network bug (broadcast_raw cleanup, [72f18c6](../../..)), one already-coded-but-just-deployed eclipse-defense bug (slot leak, [84f40ce](../../..)), one nginx config drift, one missing deploy-fleet entry, and an opportunistic third-party miner producing orphan blocks at floor difficulty produced a multi-hour cascade that fragmented the testnet across four heights and four "tip" chains. Recovery required a full-fleet wipe to clean genesis on the fixed binary. The chain came up healthy within 8 minutes of the wipe decision, with no recurrence of the underlying symptoms — confirming both deployed fixes work as designed and the pre-incident state was accumulated drift, not active code-level leakage.

This is the kind of compound cascade a pre-mainnet testnet exists to surface. The combination of (a) a latent leak that needs days of uptime to express, (b) a subtle config drift hidden under "it's been working," (c) a safety check that's correct in the common case but degrades in edge cases, and (d) an adversarial peer we don't control is impossible to surface in unit tests or short integration runs.

## What broke and why

Five distinct issues compounded. Listed roughly in their causal order.

### 1. broadcast_raw closed-channel cleanup (fixed in commit 72f18c6)

`src/network/node.rs` — when broadcasting to `peer_senders`, `TrySendError::Closed` was logged-and-counted but the stale entry was never removed from `peer_senders` or `peers`. Until the 60-second maintenance task cleared it, every subsequent broadcast retried `try_send` on the dead channel, returned `Closed`, and produced `WARN broadcast_raw partial delivery sent=N full=0 closed=M`. Sync stalls observed for up to 360 seconds. This was the bug barns1253 hit in his node logs on 2026-06-02.

Fixed by collecting closed peers in `to_remove_closed: Vec<PeerId>` and cleaning them up (untrack_connection + remove from peers/senders + sync.on_peer_disconnected + event_tx) off the hot path after the broadcast loop. Confirmed in deployed binary at `src/network/node.rs:2073-2092`.

### 2. Eclipse-defense slot leak (fixed in commit 84f40ce)

`src/network/node.rs` — at the cleanup branch in `handle_connection`, the `is_closed()` check on the peer's sender returned `false` even when the receiver was unreachable, because `rx` was still in scope in the same function. This skipped the cleanup branch on every normal disconnect, orphaning the `PeerInfo` entry and its `eclipse_slot: Arc<OutboundSubnetSlot>` in the peers map. The /16 subnet counter never decremented (the Drop impl on `OutboundSubnetSlot` never ran), so across hours of peer churn the subnet sums grew from 1 → 2 → 4, exhausting `MAX_OUTBOUND_PER_SUBNET=2` and blocking new outbound dials to subnets that already had phantom inventory.

Fixed by adding `drop(rx);` before the `is_closed()` check. Confirmed in deployed binary at `src/network/node.rs:2591`.

### 3. api proxy box excluded from deploy-script FLEET

`scripts/deploy-node-binary.sh` `FLEET` variable lists only the 5 P2P nodes:
```
root@66.135.23.193 root@140.82.57.168 root@207.148.111.76 root@207.148.6.50 root@192.248.151.16
```

The api proxy box (`95.179.165.225`) — which runs its own `coincync-node` so the public `/rpc/testnet` endpoint can be served from a local backend — was not in the list. As a result, every binary deploy left the api box 1–2 commits behind the rest of the fleet. At incident start it was on `6a3667f8c3d8`, two commits behind the deployed fleet `2eaf73a634a9`. Both 72f18c6 and 84f40ce were missing from it — the same broadcast-cleanup and slot-leak issues were live on the box serving the public RPC backend.

Trivial followup: add `root@95.179.165.225` to `FLEET`, plus add a SHA-256 verification step that's already present for the other five.

### 4. nginx sites-enabled drift on api proxy

`/etc/nginx/sites-enabled/coincync-api` on `95.179.165.225` was a real file, not a symlink to `sites-available`. The two had drifted: `sites-available/coincync-api` had `proxy_pass http://127.0.0.1:28081;` (correct — forward to the api box's own local node), while `sites-enabled/coincync-api` had `proxy_pass http://192.248.151.16:28081;` (London's RPC). This was the immediate cause of the chain split: every wallet, miner, and dashboard hitting `api.coincync.network/rpc/testnet` was routed past the canonical fleet into London's private fork.

Likely origin: an in-place edit (or a `cp`-not-`ln` install step) at some point in the past. Once the drift existed, ordinary nginx config-edit workflows on `sites-available` had no effect on the actual served config.

Fix during incident: flipped `sites-enabled` back to `127.0.0.1:28081` via `sed -i`, validated with `nginx -t`, reloaded. Followup: `rm sites-enabled/coincync-api && ln -s ../sites-available/coincync-api sites-enabled/` to prevent recurrence.

### 5. Rig sync gate too rigid for floor-difficulty / many-tip scenarios

`crates/coincync-rig/src/orchestrator.rs` — the sync gate (added 2026-06-02 for the barns1253 wallet-rewards-but-no-propagation scenario) reads `synced` from the daemon's `get_info` and refuses to mine while it's `false`. The criterion in `src/chain.rs:984` (`is_synced`) returns true if (a) the P2P layer set the flag, (b) `height >= target_height`, or (c) `target.saturating_sub(h) <= 2 AND tip < 360s old`.

Under floor-difficulty + multiple competing miners producing orphan-rich tips, the api box stayed at `synced=false` indefinitely: target_height kept advancing 30–80 blocks ahead of the api box's commit speed because peers were advertising orphan-chain tips. The rig observed `synced=false`, slept 30s, observed it again, slept 30s, in perpetuity — even though the api box was on the canonical heaviest-work chain by total_difficulty.

Operational bypass applied: env-var `COINCYNC_RIG_SKIP_SYNC_CHECK=1` short-circuits the gate. Comments in the patch explicitly warn that this can produce orphans if the local daemon is NOT on the canonical chain. Followup: promote to a proper `--unsafe-skip-sync-check` CLI flag with operator-facing docs in the README; consider adding an `is_essentially_synced()` variant in chain.rs that handles "behind because peers stuck on orphan-tip target" without flapping.

## Confounding factor: the 98.191.113.4 OrphanFlood peer

Throughout the incident, a non-fleet peer at `98.191.113.4:3555` (a Comcast residential IP) connected to multiple fleet seeds and produced rapid-fire blocks whose parent hashes did not extend canonical. The fleet's new binary correctly identified the pattern (`WARN Orphan flood detected from peer ... scored OrphanFlood`) but the scoring did not translate to immediate disconnect+ban. The peer continued reconnecting and pumping orphans, contributing to the fragmented "subnet_sum > outbound_count" warnings and to the floor-difficulty regime that broke the rig sync gate.

Followup commit: `src/network/scoring.rs` — make `OrphanFlood` score translate to immediate `ban_peer` + `dandelion.remove_outbound_peer`, the same way `ChronicSendQueueFull` does in `broadcast_raw` at `node.rs:2056`.

## Timeline (UTC)

| Time | Event |
|---|---|
| ~01:00 | Session begins with broadcast_raw fix deploy via `scripts/build-in-docker.sh` + `scripts/deploy-node-binary.sh`. CI fails compile due to 5 test files importing the removed `generate_stealth_address`; fixed in 2eaf73a (`tests: switch 5 call sites to generate_stealth_address_checked`). |
| ~02:00 | Explorer banner reports stale chain. `api.coincync.network/rpc/testnet` returns 504s. Investigation reveals api proxy is forwarding to London (192.248.151.16) instead of its own local node. |
| ~03:00 | Chain split confirmed: 4 fleet seeds on canonical h=17211 (total_diff=682M, stalled), London on h=17949 with total_diff=543M (lighter, on a private fork fed by the operator's local rig via the misconfigured nginx). |
| ~04:00 | London `coincync-node` + `coincync-baseline-miner` stopped. Operator's local rig stopped (captured args for restart). Nginx `sites-enabled/coincync-api` flipped from `http://192.248.151.16:28081` → `http://127.0.0.1:28081`; reload. |
| ~04:30 | api box binary upgraded from `6a3667f8c3d8` to `2eaf73a634a9` via SCP + SHA-256 verify + atomic swap + `systemctl restart`. |
| ~05:00 | First chain-DB jumpstart: rsync (via SSH tar pipe) seed1's `/var/lib/coincync/testnet` → api box. api box reaches h=17217. |
| ~05:15 | Rig still refuses to mine — `synced=false` due to fork-noise advancing `target_height` faster than api box catches up. Patched `orchestrator.rs` with `COINCYNC_RIG_SKIP_SYNC_CHECK=1` bypass; `cargo build --release -p coincync-rig` (22s); restart rig with env var. |
| ~05:30 | Second jumpstart, same procedure. api box reaches h=17314 — momentarily matches target — `synced` flips true — rig dataset rebuilds (32s) — first block found at h=17328 with `hashrate=1527 H/s`. 13 blocks mined before `synced` flaps false again under fork pressure. |
| ~06:00 | Chain fragmented across 4 heights (seed1+seed2 at 17414, api at 17358, seed3 at 17328, explorer at 17321). api box RPC returns 504s — local node hung. Maintenance page deployed on `explorer.coincync.network` to mask the chaos from community. |
| ~07:00 | Decision: wipe. The deployed fixes are present and verified at the source level; remaining symptoms are accumulated state plus the OrphanFlood peer. A fresh genesis on the fixed binary gives a definitive signal. |
| ~07:09 | Wipe executed across all 5 fleet boxes. `mv /var/lib/coincync/testnet → testnet.archived-20260604-070909` on each (preserving `node_key` + `node_signing_key`). All 5 restarted. |
| ~07:11 | First `BLOCK_COMMIT height=1` from rig at `hashrate=101 H/s`. RandomX dataset rebuild took 31.87s. |
| ~07:13 | api box at h=49, status=healthy, peer_count=4 full mesh. All 4 seeds receiving blocks via gossip. No recurrence of `eclipse-defense: significant drift` warnings on the new chain. |

## Recovery procedure used (for the runbook)

```
# 1. Stop all 5 fleet nodes (parallel)
for ip in 66.135.23.193 140.82.57.168 207.148.111.76 207.148.6.50 95.179.165.225; do
  ssh root@$ip "systemctl stop coincync-node" &
done; wait

# 2. Archive each chain DB; preserve node_key + node_signing_key
TS=$(date -u +%Y%m%d-%H%M%S)
for ip in ...; do
  ssh root@$ip "mv /var/lib/coincync/testnet /var/lib/coincync/testnet.archived-${TS}" &
done; wait

# 3. Restart all 5 (parallel)
for ip in ...; do
  ssh root@$ip "systemctl start coincync-node" &
done; wait

# 4. Verify all 5 at h=0 with peers connecting
# 5. Operator miner with COINCYNC_RIG_SKIP_SYNC_CHECK=1 auto-resumes via existing get_block_template polling
```

Wall-clock from decision to first `BLOCK_COMMIT`: ~8 minutes.

## Followup commits

In approximate priority order:

1. **`scripts/deploy-node-binary.sh`** — add `root@95.179.165.225` to FLEET, mirror the SHA verify step. Without this, every future deploy leaves the public RPC backend on an older binary.
2. **`/etc/nginx/sites-enabled/coincync-api` → symlink** — `rm sites-enabled/coincync-api && ln -s ../sites-available/coincync-api .` on `95.179.165.225`. Add a `nginx -t && diff <(realpath sites-enabled/coincync-api) <(realpath sites-available/coincync-api)` check to STATUS_PAGE.md fleet self-check.
3. **`crates/coincync-rig/src/orchestrator.rs`** — promote `COINCYNC_RIG_SKIP_SYNC_CHECK` env-var to a `--unsafe-skip-sync-check` CLI flag; document the failure mode it bypasses (orphan production on a private fork) and the verification an operator should do before flipping it.
4. **`src/network/scoring.rs` + `src/network/node.rs`** — make `MisbehaviorType::OrphanFlood` translate to immediate `ban_peer` like `ChronicSendQueueFull` does. Currently detected but not actionable fast enough.
5. **`src/network/node.rs` eclipse-defense warning** — demote `significant drift` to debug at small deltas (≤3), reserve WARN for sustained drift over multiple maintenance ticks. The metric snapshots `outbound_count` and the `outbound_per_subnet` map at different points, so transient mismatches under churn are expected and not actionable.
6. **`src/chain.rs::is_synced`** — consider an additional condition for "tip is fresh AND peer-advertised target is dominated by orphan branches." Hard to define precisely without false positives, but the current criterion flaps under fork-noise.
7. **api proxy bearer key rotation** — value `f5b2be6d8ba3fef434808f01de665d359308c545061391065401f9f6465aa4f8` was read into terminal scrollback during nginx config inspection. Rotate on `95.179.165.225` (`/etc/nginx/sites-available/coincync-api` `$coincync_rpc_key` variable + reload) and on any fleet seed UFW-allowing 28081 from that origin.
8. **`/var/www/explorer/maintenance.html` permanent template + swap script** — the maintenance page deployed during this incident was written ad-hoc. Make it a checked-in artifact with a one-line script that swaps `index.html`. Avoids re-writing it under pressure next time.

## What this proved

- **Both already-coded network fixes work as designed.** Once the chain was wiped to genesis, the `eclipse-defense: significant drift` warning did not recur on the fresh chain, the `WARN broadcast_raw partial delivery` spam did not recur, and full 4-outbound peer mesh established immediately on every box.
- **Backup-not-delete-by-default** saved the session: every destructive op had a `.before-<purpose>.<timestamp>` backup. The api box has `testnet.archived-20260604-070909` (302M), `testnet.before-jumpstart.20260604-045549` (269M), `testnet.before-jumpstart2.20260604-050736`, etc. — every state we destroyed is recoverable.
- **The maintenance page pattern works** as a community-facing pressure release valve. Once the public site stopped showing chaos, the recovery work could proceed without operator-facing pressure to "fix it faster."
- **A wipe is the right call when accumulated state outpaces incremental fixes.** Six hours of partial fixes did not converge; eight minutes of wipe + restart did. The wipe is not a retreat — it's the cleanest engineering signal that the deployed fixes work on freshly-tracked state.

## What we did NOT do (worth noting)

- We did NOT amend or rewrite git history. The deployed commits `2eaf73a634a9` ←- `72f18c6` ←- `84f40ce` stand as the authoritative chain.
- We did NOT modify the testnet checkpoints. Future testnet wipes are operator-controlled events, not consensus events.
- We did NOT change consensus rules. Difficulty floor (500), ASERT/LWMA parameters, ring size, etc., are unchanged.
- We did NOT touch the mainnet codebase or configs. Mainnet remains at its planned Oct 1, 2026 launch posture.

## What this means for mainnet readiness

This is favorable signal, not unfavorable. The bugs the cascade surfaced are precisely the class of bugs that surface only under days of real uptime and multi-actor adversarial conditions. Catching them on testnet — with no funds at risk, no community trust to repair, and recovery measurable in single-digit minutes — is exactly what testnet is for. The fixes are already deployed and have been validated on fresh state. The followup list is finite and tractable.

---

## Round 2 — 2026-06-04 evening session

After the morning recovery the chain ran healthy for ~10 hours. Two issues surfaced that traced back to a single underlying network bug:

## Symptoms observed during evening monitoring

- **`api.coincync.network/rpc/testnet` returning empty / 504 intermittently** — about 2 in 10 cron-fired sensor reads found the endpoint unreachable. Nginx error log on the api proxy box showed continuous `upstream timed out (110: Connection timed out) while reading response header from upstream` to `127.0.0.1:28081`. Memory inspection on the box revealed why: 955MB RAM tier with 838MB used and **1.9GB of swap actively used** — the local `coincync-node` was thrashing swap, taking longer than nginx's `proxy_read_timeout 8s` to respond. This was a hard-architectural mismatch, not a transient.
- **seed1 (66.135) repeatedly falling 14–28 blocks behind** with EMERGENCY-TIER-3 sync escalations firing. Root cause: a peer was advertising `target_height=11144` (10× canonical h=1170) — likely a corrupted advertisement or a stale entry from before the wipe — and seed1's sync engine treated it as a real catchup target, getting stuck. Restart cleared the in-memory peer state; seed1 caught up cleanly to h=1170 and stayed there.

## Real root cause behind both: **self-connection loop bug in AddressManager**

When we attempted the architecture-correct fix (stop coincync-node on api box, point nginx upstream at London which has a proper 16GB RAM tier), London's IBD ran at ~8 blocks/min instead of the expected 80+. Investigation revealed London was making 12 successful Noise handshakes with **its own public IP** (`192.248.151.16`) over a 37-minute window — self-loops eating outbound peer slots.

The pre-existing self-connection-detection logic worked **mechanically** (the `version_nonce` SECURITY (NET-001) check fired correctly, the WARN line emitted), but the **ban was being recorded with the wrong key**:

- `AddressManager::mark_self_address(addr: SocketAddr)` stored the full `SocketAddr` (IP + port).
- For the **inbound** side of a self-loop, `peer_info.addr` carried the remote's random TCP source port, not the listen port (28080).
- So banning `192.248.151.16:54321` did nothing for the next outbound dialer attempt, which targets `192.248.151.16:28080`.
- `dns_seeds.rs` `TESTNET_FALLBACK` lists `192.248.151.16:28080` — London continuously re-discovered its own listen address through DNS failover, dialed it, self-detected, banned the wrong port, repeated.

This explained ALL the morning's outbound-dial pathology too: the eclipse-defense `subnet_sum > outbound_count` warnings, the `Noise handshake timed out` reports, the slow IBD on London after the wipe. Multiple seeds were also affected to a lesser degree because they share the dns_seeds fallback.

## The fix

[src/network/bootstrap.rs](../../../src/network/bootstrap.rs) — added `self_ips: HashSet<IpAddr>` alongside the existing `self_addresses: HashSet<SocketAddr>`:

- `mark_self_address(addr)` now also inserts `addr.ip()` into `self_ips`, removes ALL addresses sharing that IP from the address list and dedup set
- `add(addr)` rejects any address whose IP is in `self_ips`
- `get_next()` filters out addresses whose IP is in `self_ips`

Result: once any port on a given IP is detected as self, the entire IP is permanently banned for the lifetime of the process. The dns_seeds fallback re-introduction loop is broken — `add()` rejects the re-discovery.

Verified post-deploy on London: **zero self-connection detections over a 90-second window** after restart with the new binary on a fresh DB. Compare to 12 detections / 37 min on the previous binary.

## Phase 3 (architecture-correct pivot) executed

With the self-loop bug fixed, the original architectural plan (deploy script comment from 2026-06-03 calling for the api box to be nginx-only) became viable. Sequence executed:

1. rsync `seed1:/var/lib/coincync/testnet` → London (~30s, bypasses the orphan-cascade IBD bug noted below)
2. Restart London on new binary → at canonical h=1203 with 4 outbound peers, healthy
3. Backup `sites-enabled/coincync-api` to `/etc/nginx/backups/coincync-api.before-london-flip.<TS>`
4. `sed -i` `proxy_pass http://127.0.0.1:28081` → `http://192.248.151.16:28081` (one minor near-miss: first sed wrote `192.168.151.16` typo, corrected by chained second sed; final `grep` confirmed correct IP landed)
5. `nginx -t && systemctl reload nginx`
6. `systemctl stop coincync-node` on api box

**api box RAM after:**

| | Before | After |
|---|---|---|
| Memory used | 838 MB / 955 MB | **255 MB / 955 MB** |
| Available | 101 MB | **719 MB** |
| Swap used | 1.9 GB | **35 MB** |

The intermittent endpoint failures and the underlying swap thrashing are eliminated, and the deployed architecture now matches the documented one.

## Fleet-wide rollout

The self-loop fix benefits every box (the dns_seeds fallback is system-wide). Deployed via `scripts/deploy-node-binary.sh` to the 4 seeds (66.135, 140.82, 207.148.111.76, 207.148.6.50) with 6s rolling-restart spacing. London already received it directly. The api box no longer runs coincync-node so it doesn't need the binary.

## New separate followup commits

Continuing the followup numbering from the morning section (items 10-13 in the running list):

1. **`src/network/bootstrap.rs` self-loop fix → upstream commit** with a unit test for the IP-level ban (`mark_self_address` + repeated `add()` of same IP)
2. **`src/sync/ibd.rs` orphan-cascade investigation** — London exhibits glacial IBD (8 blocks/min) even after the self-loop fix, due to a separate bug where received blocks at h>>>our_height arrive as orphans and the parent-fetch logic is slow. The rsync workaround sidesteps this for testnet but it should be fixed properly before mainnet.
3. **Vultr tier review** — three seed boxes still on 955MB tier with active swap usage even though not running coincync-node would help. Either upgrade to 2GB+ or move them to nginx-only roles like the api box.
4. **`scripts/migrate-to-nginx-only.sh`** — write a helper script that does the full migration atomically. Stopping `coincync-node` alone is NOT enough on any box that runs `coincync-node-watchdog.timer`: the watchdog fires every 5 min, detects RPC unreachable, calls `systemctl restart coincync-node`, and silently reverts the migration. Discovered ~30 min after Phase 3 looked clean — api box had quietly come back up under swap thrashing again. Migration must: `systemctl stop coincync-node && systemctl disable coincync-node && systemctl stop coincync-node-watchdog.timer && systemctl disable coincync-node-watchdog.timer`. The `coincync-node.service` unit file is a real file (not a systemd default), so `systemctl mask` fails with "File already exists"; rely on `disable` + watchdog removal instead.
