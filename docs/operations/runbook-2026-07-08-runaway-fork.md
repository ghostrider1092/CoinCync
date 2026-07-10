# Runbook — 2026-07-08 runaway-fork recovery + prevention deploy

**Incident:** After the h10042 freeze was cleared by deploying v1.0.12, miner
**randomx2** (45.32.79.234) briefly lost mesh sync at restart, its difficulty
collapsed, and it mined a **low-work private fork** (10042 → 10551+) that the
rest of the fleet (group A, canonical/heavier, stuck at 10042) correctly
rejects. All 8 nodes are on v1.0.12. The fork does **not** self-heal while
randomx2 keeps extending it.

Fixes landed in the tree (uncommitted) that PREVENT recurrence — see the bottom
section. This runbook is the operational sequence to (1) end the live fork and
(2) roll out the prevention.

---

## Step 1 — End the live fork (do this first)

Stop randomx2's miner and restart its node so it drops the fork and
re-evaluates against the heavier canonical chain:

```bash
ssh -i ~/.ssh/coincync_fleet root@45.32.79.234 \
  'systemctl stop coincync-rig && systemctl restart coincync-node'
```

Verify randomx2 converges DOWN onto the canonical chain (height should drop
from ~10551 toward group A's height, then track it):

```bash
# randomx2 node height (local RPC)
ssh -i ~/.ssh/coincync_fleet root@45.32.79.234 \
  "curl -s --max-time 6 -X POST http://127.0.0.1:28081 \
   -H content-type:application/json \
   -d '{\"jsonrpc\":\"2.0\",\"method\":\"get_info\",\"params\":[],\"id\":1}' \
   | grep -oE '\"height\":[0-9]+'"
```

Do NOT restart `coincync-rig` on randomx2 yet — leave the miner off until the
whole fleet agrees on one height (Step 4). A miner on the canonical chain is
fine; a miner racing ahead again is what we're avoiding.

## Step 2 — Build the fixed binary

The prevention fixes are in `coincync-rig` + the node. Build the Linux binary
via the normal reproducible path (WSL / Linux builder), from `c:\dev\coincync`
(GitHub main), never OneDrive/sandbox:

```bash
# in WSL, repo root
CARGO_TARGET_DIR=$HOME/.cync-target cargo build --release --bin coincync-node
cp $HOME/.cync-target/release/coincync-node out/coincync-node
```

(Bump `Cargo.toml` `version` past 1.0.12 before tagging any release so
`check-update` reports correctly — see the release checklist. For a same-day
hotfix deploy of uncommitted code you may keep 1.0.12; the deploy version-gate
treats equal versions as "not a downgrade" and allows it.)

## Step 3 — Re-render units (adds `--external-ip`) + deploy

The unit renderer now emits `--external-ip <own_ip>` per node. Re-render and
push the units, then deploy the binary **one host at a time** (never
`redeploy-fleet.sh` — it wipes the chain DB):

```bash
# roll the new units out (adds --external-ip to every node)
bash scripts/sync-fleet-config.sh

# deploy the binary, one host at a time; seeds last as anchors
for n in randomx relay1 relay2 explorer randomx2 seed1 seed2 seed3; do
  bash scripts/deploy-node-binary.sh --only "$n"
done
```

The deploy now refuses to install a binary OLDER than the one running (the
2026-07-08 trigger). For an intentional rollback only: `ALLOW_DOWNGRADE=1`.

## Step 4 — Verify

- **Convergence:** every node's `get_info` height tracks one tip that advances
  steadily. No node stuck hundreds of blocks behind.
- **No self-dials:** `journalctl -u coincync-node | grep -c "Self-connection"`
  should stop growing (each node now marks its own `--external-ip` as self).
- **Mine-gate works:** if a miner ever gets far ahead of peers again it logs
  `fork-divergence: local height … runs >25 blocks ahead of best peer …` and
  refuses to mine instead of building a fork. Then restart `coincync-rig` on
  the miners once the fleet is converged.

---

## Prevention that shipped (why this won't recur)

| Layer | Change | Where |
|---|---|---|
| Miner | Fork-divergence gate: refuse to mine when local tip runs >25 blocks ahead of the best peer (blocks not being adopted = private fork). | `coincync-rig/orchestrator.rs`, `chain.rs::peer_advertised_height`, `node_api.rs` get_info |
| Deploy | Version-downgrade guard: refuse a binary older than the running one (`ALLOW_DOWNGRADE=1` to override). | `scripts/deploy-node-binary.sh` |
| Mesh | `--external-ip` marks own IP as self so gossip can't cause self-dials; `AddressManager::add()` refuses to re-admit a self-address. | `bin/node.rs`, `network/node.rs`, `network/bootstrap.rs`, `scripts/render-systemd-unit.sh` |
| Consensus (deferred) | Difficulty-drop clamp so an isolated miner can't crater difficulty. Needs a coordinated fork — proposal only. | `docs/security/difficulty-runaway-fork-proposal.md` |

Recommended follow-ups (not yet done): make `is_synced()` work-aware (touches
core sync — separate reviewed change); deploy the `coincync-tick` heartbeat
sidecar (~60s stall detection vs the 6.5h this incident took to notice).
