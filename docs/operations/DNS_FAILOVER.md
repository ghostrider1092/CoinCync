# DNS failover runbook

**Status:** Drafted 2026-05-08; setup not yet executed.
**Trigger:** any Cloudflare account incident — suspension, lockout,
billing dispute, regional block, MITM compromise.
**Time to recover post-trigger:** ~15 minutes if pre-staged per this
runbook; ~hours if you discover the runbook during the incident.

---

## Why this matters

The CoinCync project's user-facing surface — `coincync.network`,
`api.coincync.network`, `explorer.coincync.network`,
`docs.coincync.network`, `git.coincync.network`, the future
`updates.coincync.network` — currently resolves through a single
Cloudflare zone. If Cloudflare suspends the account (the project's
operator has a documented history of GitHub account suspensions; the
same risk applies to any single SaaS account), every user-facing URL
breaks at the same time:

- The web faucet stops accepting drip requests.
- Block explorer goes down.
- Wallet auto-update checks fail.
- The launch-day announcement links go dead, and the project looks
  abandoned to anyone clicking them.

Every minute of downtime on launch week costs trust.

---

## Architecture (current)

```
                            user
                              │
                              ▼
                  Cloudflare DNS (acct: $primary)
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
       Vultr api box     Vultr explorer    Cloudflare Pages
      (95.179.165.225)  (207.148.6.50)    (coincync-landing)
       coincync-node     coincync-node
       coincync-faucet   coincync-explorer
```

Single point of failure: the Cloudflare zone.

---

## Architecture (post-failover-ready)

```
                            user
                              │
                              ▼
              ┌───── primary registrar (Cloudflare) ─────┐
              │     CNAME records for the zone           │
              ▼                                          ▼
    secondary registrar (Hetzner DNS or deSEC)     Cloudflare Pages
    same A/AAAA records as Cloudflare              ↓
    nameservers ready to swap in via               (coincync-landing)
    domain registrar control panel                 + duplicate on Pages
                              │                       at neocities.org
                              ▼                       (free fallback)
              Vultr api box / explorer
              (origin servers; same IPs in both DNS providers)
```

Two changes: (a) DNS records mirrored at a second provider, (b) the
domain registrar (where the actual `.network` registration lives) is
ready to switch nameservers in one operation.

---

## Pre-stage steps (do this before launch, not during incident)

### Step 1 — pick a secondary DNS provider

Recommended: **deSEC** (free, EU-based, no account required for
email-only signup, has been reliable in similar incidents historically).
Alternatives: Hetzner DNS (free, requires Hetzner account), AWS Route
53 (paid but enterprise-grade), Cloudflare itself with a separate
account (defeats the purpose if Cloudflare's the one that suspended you).

### Step 2 — replicate every DNS record

Pull every record from the current Cloudflare zone:

```bash
# From any machine with curl + Cloudflare API token (project's
# existing token, not a new one):
ZONE_ID="<your_cf_zone_id>"
TOKEN="<your_cf_api_token>"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?per_page=100" \
  | jq '.result[] | {name, type, content, ttl, proxied}'
```

Save the output as `dns-snapshot-YYYYMMDD.json` and commit it to
the repo at `deploy/dns-snapshot.json` (it's not secret).

Manually add each non-proxied record (A, AAAA, CNAME, MX, TXT) at
the secondary provider. Cloudflare-proxied records (orange cloud)
become bare A records pointing at the origin IP at the secondary —
during failover you lose Cloudflare's DDoS protection until you can
re-orange-cloud. Document this trade-off; it's a known cost.

### Step 3 — register the secondary nameservers at the registrar

Most domains use NS records at the registrar to point to a single
provider's nameservers (e.g., `marlowe.ns.cloudflare.com`). The
secondary provider gives you a different set (`ns1.desec.io`,
`ns2.desec.org`, `ns3.desec.net`).

You do NOT add both to the registrar's NS list at the same time —
that would split queries between providers and cause cache
inconsistency. Instead:

1. Identify your registrar (where the `.network` domain is
   registered — probably Namecheap, Cloudflare Registrar, or
   similar). Confirm you have account access.
2. **Document the swap procedure**: which menu, which button, which
   nameservers to enter. Some registrars let you save NS sets as
   profiles for one-click switching; if so, save both sets now.
3. **Test the secondary provider's records BEFORE you need them**.
   Use `dig` against the provider's nameservers directly:
   ```bash
   dig @ns1.desec.io coincync.network A
   dig @ns1.desec.io api.coincync.network A
   ```
   Both should return the correct IPs without going through the
   registrar.

### Step 4 — pin the runbook somewhere offline

Print a copy. Save it to a non-Cloudflare-dependent location (paper,
USB stick, separate cloud provider). If the trigger event includes
loss of access to the project's email or document hosting, you'll
need this to be readable from a phone with cellular data.

---

## Failover procedure (during incident)

Total time budget: 15 minutes from "I notice the trigger" to
"users are back online."

### Step F1 — confirm the trigger (60 seconds)

Don't reflexively swap nameservers if the issue is something else.
Verify Cloudflare is the actual problem:

```bash
# From a machine NOT going through Cloudflare:
dig @8.8.8.8 coincync.network A
# Expected during incident: NXDOMAIN, SERVFAIL, or REFUSED.
```

If it returns a real IP, the issue is downstream of DNS — check the
origin server, not nameservers.

### Step F2 — log into the registrar (2 minutes)

Use the offline-stored credentials. If the registrar account is also
locked, the failover stops here and becomes a multi-day registration-
recovery process; that's a much longer runbook.

### Step F3 — swap nameservers (1 minute)

In the registrar control panel:

1. Find the NS records for `coincync.network`.
2. Replace the Cloudflare entries (`*.ns.cloudflare.com`) with the
   secondary provider's (`ns1.desec.io`, `ns2.desec.org`,
   `ns3.desec.net`).
3. Save.

The change takes effect at the registry layer in seconds. End-user
DNS resolution depends on cached values everywhere; the actual
propagation is governed by the TTLs on the existing NS records (often
24-48 hours at the registrar level — but most resolvers re-fetch
NS records aggressively when the SOA changes).

### Step F4 — verify resolution from the new provider (5 minutes)

```bash
# Targeted dig at the new nameservers:
dig @ns1.desec.io coincync.network A
dig @ns1.desec.io api.coincync.network A
dig @ns1.desec.io explorer.coincync.network A

# Then from a few resolvers globally:
dig @8.8.8.8 coincync.network A           # Google
dig @1.1.1.1 coincync.network A           # Cloudflare's public DNS (independent of zone)
dig @9.9.9.9 coincync.network A           # Quad9
```

The third group will lag for cached records. Don't panic during the
first 10-30 minutes; keep refreshing.

### Step F5 — announce the outage and recovery (5 minutes)

Post to `#testnet-status` Discord channel (or the channel-of-record
for status updates). Even if the URL hasn't propagated yet, telling
the community what happened and what you're doing buys patience.
Template:

```
## Status: DNS provider switch in progress

CoinCync's primary DNS was disrupted at HH:MM UTC (cause: <Cloudflare
suspension / outage / lockout>). We've swapped nameservers to our
backup provider; resolution should normalize over the next 30-60
minutes as caches refresh. The CHAIN itself is unaffected — fleet
nodes and the wallet binary are not DNS-dependent for peer
discovery (DNS seeds resolve through the OS resolver, which gets
the new IPs once it picks up the new NS).

What's affected:
- web faucet at coincync.network (DOWN until DNS catches up)
- block explorer (DOWN)
- docs (DOWN)

What's unaffected:
- testnet chain itself
- wallets that already have peer IPs cached
- nodes connected to the fleet via direct IP

ETA on full recovery: ~30 min for most users, ~2h worst case.
```

### Step F6 — re-add Cloudflare's protection at the secondary (post-recovery)

The secondary provider doesn't proxy/CDN by default — your origin
IPs are now exposed. Acceptable for an emergency; should be patched
within 24h:

- Either add Cloudflare proxying via a NEW Cloudflare account
- Or install bunny.net / Fastly / a Cloudflare-alternative CDN
  in front of the origins
- Or accept the bare-IP exposure as a known temporary cost

---

## DNS records inventory (current, as of 2026-05-08)

These are the records that need to be replicated at the secondary
provider. Source-of-truth: `deploy/dns-snapshot.json` (committed).

| Record | Type | Target | Purpose |
|---|---|---|---|
| `coincync.network` | A | (Cloudflare Pages IP) | Landing site |
| `www.coincync.network` | CNAME | `coincync.network` | www alias |
| `api.coincync.network` | A | `95.179.165.225` | RPC + faucet (Vultr Frankfurt) |
| `explorer.coincync.network` | A | `207.148.6.50` | Explorer (Vultr Dallas) |
| `docs.coincync.network` | CNAME | (Cloudflare Pages) | mdbook docs |
| `git.coincync.network` | A | (TBD — Forgejo box) | Self-hosted Forgejo (post-launch) |
| `seed1.coincync.network` | A | `66.135.23.193` | DNS seed peer (NJ) |
| `seed2.coincync.network` | A | `140.82.57.168` | DNS seed peer (AMS) |
| `seed3.coincync.network` | A | `207.148.111.76` | DNS seed peer (Tokyo) |

**Critical:** the `seedN.coincync.network` records are what
DNS-seed-discovery in `coincync-node` queries on startup. If the DNS
zone is fully unresolvable, NEW node startups (cold installs) can't
find peers. Existing nodes are fine — they cache peer IPs after
first successful sync. So the failover priority is: get DNS back up
SO new operators can start nodes; existing nodes don't break.

---

## What this runbook does NOT solve

- **Origin-server outages.** If `95.179.165.225` (the api box) goes
  down, this runbook is the wrong tool. That needs a multi-region
  origin failover, which is a separate (larger) project.
- **Coordinated registrar + DNS failure.** If Cloudflare locks the
  account AND the `.network` registrar locks the registration, you
  need to recover the registration before this runbook helps. Lead
  time to recover a domain through ICANN dispute resolution: weeks
  to months. Mitigation: don't use the same email or payment method
  for registrar and DNS provider.
- **Cloudflare Pages content (landing site, docs).** The DNS swap
  redirects users to the right A record, but if Cloudflare Pages
  itself is the suspended service, the IP behind those records is
  also down. Mitigation: mirror the landing site at a second host
  (Netlify, GitHub Pages, neocities.org) and the secondary DNS
  provider can A-record to that mirror.

## Cost

- deSEC: free.
- Hetzner DNS: free (requires Hetzner account, ~€5/mo cloud server
  to associate but the DNS is free even on a tiny server).
- Cloudflare alternative account: free (just don't use the same
  email/payment as primary).
- Time: 1-2 hours initial setup, 0 ongoing if records are stable.

## Rotation cadence

This runbook is good as long as:

- The IP addresses in the records inventory are current.
- The secondary provider is still receiving update pushes.
- The registrar account is still accessible.

Pull `deploy/dns-snapshot.json` against the live Cloudflare zone
quarterly. If it differs from what's at the secondary, propagate
the changes. Test the failover end-to-end annually by literally
swapping nameservers for 5 minutes and verifying the secondary
provider answers correctly.

---

## What you need to do before launch

The minimum viable version of this for the 2026-05-11 testnet
launch:

1. ☐ Pick a secondary provider and create an account (deSEC
   recommended). Email + password, no payment.
2. ☐ Run the DNS-snapshot dump in Step 2; commit to repo.
3. ☐ Manually create matching records at the secondary (paste from
   snapshot).
4. ☐ Verify with `dig @<secondary-ns>` that the records work.
5. ☐ Document the registrar's NS-swap menu path on this file under
   "Pre-stage Step 3."
6. ☐ Print a copy and store offline.

Time investment: ~90 minutes one-time. Saves you a multi-hour
incident if Cloudflare ever tries to remove your account.
