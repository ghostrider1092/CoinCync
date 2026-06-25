# Chaindata-sync cron deploy guide

**Workaround for:** seed1 ↔ miner gossip broken (2026-06-23). Keeps public
RPC fresh by periodic chaindata snapshots from miner to seed1.

**Remove this once peering is fixed.**

## Files in this PR

- [`scripts/chaindata-sync-miner-to-seed1.sh`](chaindata-sync-miner-to-seed1.sh) — runs on miner, pushes to seed1
- [`scripts/install-incoming-chaindata.sh`](install-incoming-chaindata.sh) — runs on seed1, atomically installs

## Deploy steps

### 1. Deploy fleet SSH key to miner

The miner needs a key authorized on seed1. Either reuse the same
operator key the rest of the fleet management uses, or generate a
miner-specific key.

```bash
# On operator workstation
scp -i ~/.ssh/coincync_fleet ~/.ssh/coincync_fleet root@173.199.93.21:/root/.ssh/coincync_fleet
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'chmod 600 /root/.ssh/coincync_fleet'
```

### 2. Install scripts on the two hosts

```bash
# Miner
scp -i ~/.ssh/coincync_fleet scripts/chaindata-sync-miner-to-seed1.sh root@173.199.93.21:/usr/local/bin/
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'chmod +x /usr/local/bin/chaindata-sync-miner-to-seed1.sh'

# seed1
scp -i ~/.ssh/coincync_fleet scripts/install-incoming-chaindata.sh root@66.135.23.193:/usr/local/bin/
ssh -i ~/.ssh/coincync_fleet root@66.135.23.193 'chmod +x /usr/local/bin/install-incoming-chaindata.sh'
```

### 3. Test once manually before scheduling

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'bash /usr/local/bin/chaindata-sync-miner-to-seed1.sh'
```

Verify:
- Both nodes stayed active
- coincync-rig restarted
- Public RPC at api.coincync.network reports a recent tip

### 4. Schedule via cron

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21
echo "*/10 * * * * root /usr/local/bin/chaindata-sync-miner-to-seed1.sh >> /var/log/chaindata-sync.log 2>&1" > /etc/cron.d/chaindata-sync
chmod 644 /etc/cron.d/chaindata-sync
```

### 5. Verify cron firing

```bash
# After 10 min:
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'tail -50 /var/log/chaindata-sync.log'
```

## Operational notes

- Each run: ~1s miner downtime, ~10s seed1 downtime
- Tarball grows with chain — currently 6 MB, will hit ~50 MB by mainnet at ~200k blocks
- Mining stops for the tar window (~1s). Acceptable loss.
- coincync-rig systemd dep means stopping coincync-node kills the rig. The
  sync script explicitly restarts the rig after node restart. Don't remove
  that line without verifying the dep was fixed.

## Removing post-fix

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'rm /etc/cron.d/chaindata-sync /usr/local/bin/chaindata-sync-miner-to-seed1.sh'
ssh -i ~/.ssh/coincync_fleet root@66.135.23.193 'rm /usr/local/bin/install-incoming-chaindata.sh'
```

## Background: why this is needed

See `out/PROJECT_STATUS.md` "Chain partition 2026-06-22" section and
the eventual `project_chain_partition_2026_06_22` memory entry. TL;DR:

1. 2026-06-22 03:52: orphan-flood scoring banned the miner on seed1
2. Miner kept mining alone on its own valid chain (more PoW)
3. seed1 stuck on a dead chain, public RPC showed h=4170 for 18+ hours
4. 2026-06-24 02:46: manual chaindata transfer recovered seed1
5. But seed1 ↔ miner gossip is STILL broken (suspected eclipse-defense
   + nginx-only api in addnode + self-IP-in-addnode). Needs focused
   peering debug session.
6. This cron is the bridge keeping public RPC fresh until then.
