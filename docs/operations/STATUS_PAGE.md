# Status page design

`https://status.coincync.network` is the canonical answer to "is
the network working right now?" Without it, every user with a
problem assumes the worst and fills the Discord `#help` channel
with "is the chain down?"

This doc specifies what the page shows, where the data comes from,
how it's hosted, and how it gets updated during incidents.

## What the page shows

A single landing page with:

### Section 1 — Top banner

One of three states, color-coded:

- **All systems operational** (green) — fleet healthy, no
  incidents.
- **Partial degradation** (yellow) — at least one fleet box is
  unhealthy, OR an active incident is being investigated.
- **Major incident** (red) — chain stalled, fleet down, or
  consensus failure.

The banner color is computed from the data below (see "Health
score").

### Section 2 — Per-service uptime grid

Each row a service; each column a day; each cell colored
green/yellow/red.

Services tracked:

- **Mainnet RPC** (post-launch)
- **Testnet RPC** (`api.coincync.network/api/`)
- **Explorer** (`explorer.coincync.network`)
- **Faucet** (`faucet.coincync.network`)
- **Seed1** (`seed1.coincync.network:28080`)
- **Seed2** (`seed2.coincync.network:28080`)
- **Seed3** (`seed3.coincync.network:28080`)
- **Forgejo** (`git.coincync.network`)
- **Discord webhook** (post-incident, the on-call channel)

Default view: last 30 days. Click a cell for the day's incident
detail.

### Section 3 — Real-time chain health

A small panel showing:

- **Current chain height** (1.0 testnet)
- **Last block age** ("12s ago")
- **Average block time** (last 100 blocks)
- **Network hashrate** (last 100 blocks)
- **Connected nodes** (sum across fleet boxes)
- **Mempool depth** (txs waiting)

Refreshed every 10 seconds.

### Section 4 — Active and recent incidents

A timeline of incidents, most recent first. Each incident has:

- Title (e.g., "Explorer peer-wedge")
- Start time
- Resolved time (if resolved)
- Status (investigating / identified / monitoring / resolved)
- Updates posted as the incident progresses

When there are no active incidents, the section says so explicitly.
"No active incidents" is a state, not an absence of state.

### Section 5 — Upcoming planned changes

Hard-fork activations, scheduled maintenance windows, planned
fleet rolls. With:

- Date / height
- Description
- What users need to do (usually "upgrade your wallet by X")

This is the user-visible copy of the activation announcements
from CIP-007.

### Section 6 — Subscriptions

A simple form to subscribe to incident notifications via:

- Email
- Discord webhook (paste your webhook URL; we POST to it)
- RSS feed
- Atom feed

No account required. No tracking. The subscription store is just
a list of webhooks / emails per channel.

## Health score

The per-service status is computed from a per-minute health probe:

```python
# Pseudo-code; real impl is the status-probe binary.
def probe(service):
    if not http_reachable(service.url):
        return "red"  # service is down
    if probe_latency_p99(service, last_5_min) > service.latency_threshold:
        return "yellow"  # service is slow
    if service is RPC:
        info = http_get(service.url + "/get_info")
        if info.synced is False:
            return "yellow"  # synced flag is false
        if info.peers < 2:
            return "yellow"  # poor connectivity
        if info.tip_age_secs > 600:
            return "red"  # tip is >10 min old, chain may have stalled
    return "green"
```

The "synced" / "peers" / "tip_age_secs" fields exist in
`get_info` per the existing `src/rpc/server.rs` health-score
logic.

### Health score (the BIG one)

The top banner aggregates per-service health:

```
green  if every fleet RPC is green AND chain tip is fresh
yellow if any service is yellow OR one fleet box is red
red    if >1 fleet box is red OR the chain tip is >10 min old
```

This is the user-facing one-line answer to "is the network
working right now?"

## Where the data comes from

The status page is **not** a manual-update wiki page. Each metric
has an automated source:

| Metric | Source |
|---|---|
| Per-service reachability | A status-probe daemon running at the api box, hitting each service every 60s |
| Chain height | Latest `get_info` response from the api box |
| Block age | `tip_age_secs` from `get_info` |
| Hashrate | Last 100 blocks of `get_block_template` data |
| Mempool depth | `get_mempool_info.count` |
| Active incidents | A separate "incidents" file (JSON) that the operator updates manually during incidents |
| Upcoming changes | Pulled from `docs/cip/` + `docs/launch/` (committed to repo) |

The "operator updates manually" part is just the on-call writing
to a JSON file in the same repo. No separate database. No CMS.
The status page itself is static HTML + small JS that fetches
the live JSON.

## Hosting

The status page **must NOT** be on the same infrastructure as
the services it monitors. If the api box is down, the status
page must still tell users so.

Recommended:

- **Hosting:** GitHub Pages, Cloudflare Pages, or a cheap VPS
  outside the main fleet.
- **DNS:** Cloudflare (project's existing provider).
- **Updates:** the status-probe daemon pushes a JSON snapshot
  every 60s to the static-page hosting via GitHub Pages
  (commits to a `status-data` branch) or a Cloudflare Workers
  KV write.

Cost: ~$0/mo for GitHub Pages hosting; ~$5/mo for a cheap VPS.

## Implementation plan

### Phase 1 (pre-launch — NOW)

- Create `status.coincync.network` DNS record.
- Set up GitHub Pages or equivalent hosting.
- Author the static HTML/CSS/JS for the landing page.
- Author the status-probe daemon (Rust binary, lives in
  `crates/coincync-status-probe`).
- Wire the daemon's output to the page.

### Phase 2 (within a week of public testnet launch)

- Add subscription store + email/Discord-webhook notification.
- Add the incidents-file flow: write a CLI like
  `status-cli incident create --title="<x>" --severity=major`
  that updates the JSON. Operator uses this during incidents.
- Add the "operator on duty" link (just a Discord ping for now).

### Phase 3 (post-launch)

- Add historical incident archive (post-mortem links).
- Add public incident-response SLA commitments.
- Migrate to a real status-page tool if maintenance burden warrants
  (Statuspage.io, Atlassian Statuspage, or self-hosted Cachet).
  At ~$25/mo Statuspage is the easy answer; $0 with the simple
  page is the budget answer.

## What this replaces

Right now, when something is wrong, users:

1. Notice their wallet doesn't sync.
2. Open Discord.
3. Ask "is the network down?"
4. Wait for a maintainer to respond.
5. Eventually find out the api box is being redeployed.

With a status page, step 1 → 2 changes to step 1 → "check
status.coincync.network." 80% of the inbound questions go away.
The remaining 20% are real bugs the maintainer should know
about anyway.

## Anti-patterns to avoid

- **Don't make the status page show your private monitoring
  data.** Operators have detailed Grafana dashboards; users get a
  simplified summary. Mixing the two confuses both audiences.
- **Don't post fake green when something is degraded.** Trust
  is earned in drips and lost in buckets. If the page shows
  green when the network is broken, users learn to ignore it
  and you have no on-channel signal during the next real
  incident.
- **Don't auto-resolve incidents.** "Incident resolved at HH:MM"
  is an operator statement; let the operator make it. An
  auto-resolve based on health-probe thresholds will close
  incidents the moment a probe blip hits, even if the underlying
  issue continues.
- **Don't put the status page on the same DNS as the API.**
  If `coincync.network` DNS goes down, the status page should
  still resolve. Use a different domain (or at least a
  different DNS provider).

## Pointers

- `https://www.statuspage.io/` — the canonical reference for
  what a status page can be
- `https://upptime.js.org/` — open-source status page template
  that runs on GitHub Pages; the project may use this directly
- `crates/coincync-status-probe/` — the Rust daemon (to be
  authored)
- `docs/operations/INCIDENT_RUNBOOKS.md` — what to do during an
  incident the status page reports
