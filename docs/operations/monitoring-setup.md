# Monitoring + alerting setup (Grafana Cloud free tier)

**Why this exists:** today's chain partition went undetected for 18 hours because nobody was watching `is_synced`. With this setup, any partition / OOM / stalled tip pings `#alerts` within 5 minutes.

**Cost:** $0/mo (Grafana Cloud free tier: 10K active series, 14-day retention, sufficient for a 5-node fleet).

**Time to set up:** ~30 minutes operator time + 5 min × 5 hosts script runs.

---

## Architecture

```
┌────────────────────┐
│ Each fleet host:   │
│  - coincync-node   │ → :28082/metrics (Prometheus format)
│  - node_exporter   │ → :9100/metrics  (system metrics)
│  - vmagent         │ → scrapes both, remote_writes to Grafana Cloud
└────────────────────┘
           │
           ▼  HTTPS push
┌─────────────────────────────┐
│ Grafana Cloud (free tier)   │
│  - Hosted Prometheus        │
│  - Dashboard                │
│  - Alert rules              │
│  - Discord webhook contact  │
└─────────────────────────────┘
           │
           ▼  on threshold breach
   ┌──────────────┐
   │ #alerts      │
   │ Discord      │
   └──────────────┘
```

---

## Step 1: Grafana Cloud signup (5 min)

1. Go to https://grafana.com/auth/sign-up
2. Pick **Forever Free** plan
3. Create a stack — pick a region near your fleet (e.g. `prod-us-west` for Vultr SFO; `prod-eu-west` for AMS)
4. Wait ~2 min for stack provisioning

## Step 2: Get remote_write credentials (3 min)

In your stack:
1. Left nav → **Connections** → **Add new connection**
2. Search for "Hosted Prometheus metrics" → click → **Send Metrics**
3. Copy these three values into `/etc/coincync/grafana-cloud.env` on EACH fleet host (one file, deploy to all):

```bash
# /etc/coincync/grafana-cloud.env  (chmod 600, owned root:root)
GRAFANA_CLOUD_REMOTE_WRITE_URL=https://prometheus-prod-XX.grafana.net/api/prom/push
GRAFANA_CLOUD_INSTANCE_ID=1234567
GRAFANA_CLOUD_API_TOKEN=glc_eyJv...
```

**Token scope:** the token MUST have `metrics:write` only. Do NOT use an account-wide token.

## Step 3: Install agent on each fleet host (5 min × 5 = 25 min)

Run `scripts/install-grafana-cloud-agent.sh` on each:

```bash
# Repeat for seed1, seed2, seed3, explorer, randomx (skip api — nginx-only)
scp -i ~/.ssh/coincync_fleet scripts/install-grafana-cloud-agent.sh root@<host>:/tmp/
scp -i ~/.ssh/coincync_fleet /local/grafana-cloud.env root@<host>:/etc/coincync/grafana-cloud.env

ssh -i ~/.ssh/coincync_fleet root@<host> '
  chmod 600 /etc/coincync/grafana-cloud.env
  chown root:root /etc/coincync/grafana-cloud.env
  chmod +x /tmp/install-grafana-cloud-agent.sh
  /tmp/install-grafana-cloud-agent.sh
'
```

The script auto-derives the host label from `hostname -s`. Override with `COINCYNC_FLEET_HOSTNAME=seed1` in the env file if hostname doesn't match the fleet-config role.

**Verify in Grafana Cloud:**
- Left nav → **Explore** → pick "grafanacloud-...-prom"
- Query: `up{host="seed1"}` — should return `1`
- Query: `coincync_node_height` — should show all 5 hosts with their current height

## Step 4: Import dashboard (2 min)

1. Left nav → **Dashboards** → **New** → **Import**
2. Upload `docs/operations/grafana-coincync-dashboard.json` (in this repo)
3. Pick your Prometheus data source
4. Click **Import**

The dashboard shows:
- Per-host: height, peer_count, tip_age_secs, mempool_size, is_synced
- Per-host system: memory used %, CPU 5-min load, disk free
- Per-host: coincync-node uptime, restart count last 24h

## Step 5: Configure Discord webhook (5 min)

In Discord:
1. Pick `#alerts` channel (create if needed)
2. Edit channel → **Integrations** → **Webhooks** → **New Webhook**
3. Name: "Grafana Cloud Alerts"
4. Copy webhook URL

In Grafana Cloud:
1. Left nav → **Alerting** → **Contact points** → **Add contact point**
2. Name: `discord-alerts`
3. Type: **Discord**
4. URL: paste webhook URL
5. Save

## Step 6: Provision alert rules (5 min)

Either:
- **A.** Import `docs/operations/grafana-coincync-alerts.yaml` via Grafana's "Alert rules → Import" (Grafana Cloud supports YAML provisioning)
- **B.** Create them manually via the UI per the spec in that file

The 4 rules:

| Rule | Threshold | Severity |
|---|---|---|
| `tip_age_secs > 600` for 5 min | testnet block-time 120s, so 5+ blocks late = real stall | warning |
| `peer_count < 3` for 5 min | mesh degraded | warning |
| `is_synced == 0` for 10 min | node lost sync entirely | critical |
| `node_memory_MemAvailable_bytes < 500_000_000` for 5 min | OOM risk | critical |

Default contact point: `discord-alerts`.

## Step 7: Test (5 min)

1. SSH to seed1 → `systemctl stop coincync-node`
2. Wait ~6 min
3. Discord should ping with: tip_age > 600s + is_synced=0 alerts
4. SSH seed1 → `systemctl start coincync-node`
5. Wait ~6 min — alerts resolve, Discord posts "OK"

If the test fires correctly, monitoring is live.

---

## What this catches (post-deploy)

| Today's incident | Detection time before | After |
|---|---|---|
| Chain partition 2026-06-22 | 18 hours (manual discovery) | **5 min** (tip_age alert) |
| seed1 OOM-cycle | 2-3 cycles before noticed | **5 min** (memory alert) |
| Miner stops mining | hours (chain stalls visibly) | **5 min** (tip_age alert) |
| Single peer disconnect | never noticed | **10 min** (peer_count<3 alert) |

## What this does NOT catch (still needs human attention)

- **Slow-burn issues:** memory leak over days, disk filling at 1% per day. Add longer-window alerts later (`predict_linear` queries).
- **Bad blocks accepted:** consensus bug producing chain that doesn't reorg. Requires deeper logic (compare tip hashes across nodes — Grafana doesn't help here).
- **Bandwidth saturation:** node_exporter exports network bytes; you'd need to add a panel + alert manually.

## When to upgrade from free tier

The free tier covers:
- 10K active series (current fleet uses ~500-1000 series)
- 14-day retention
- 50 GB logs/mo

You'll bump against limits when:
- Fleet grows past ~20 nodes
- You want 30-90 day retention for trend analysis
- You add detailed RandomX miner-specific metrics

Paid tier starts at $19/mo for the next step up. For v1.0 testnet + mainnet, free tier is plenty.
