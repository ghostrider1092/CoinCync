# Federation & DDoS mitigation

The defensive posture for CoinCync's public infrastructure. The TL;DR is **distribute, don't centralize**. The longer reading explains why every "obvious" answer (Cloudflare, edge CDN, scrubbing service) is actively wrong for a privacy coin.

## Threat model

Privacy coins face DDoS for very different reasons than e-commerce sites:

### 1. Market manipulation / short-selling

Someone shorting CYNC wants the public explorer down during a coordinated FUD campaign. *"Blockchain is broken, the explorer is offline"* headlines move price. Taking the explorer offline for 6 hours during a Twitter storm manufactures the appearance of technical failure at exactly the moment when speculators are looking for confirmation bias. **The DDoS is advertising.**

### 2. Compliance pressure

Governments hostile to privacy coins (US Treasury OFAC, China, Korea, India) have documented motivation to disrupt privacy-coin infrastructure. The Tornado Cash precedent in August 2022 is the clearest case: a privacy tool whose frontend was hosted **behind Cloudflare** got its Cloudflare account terminated within days of the US Treasury sanctions announcement. The attack wasn't a botnet flood — it was a letter.

A regulator who wants a privacy coin off the public internet doesn't attack your servers; they send Cloudflare a letter, and Cloudflare complies within hours. **Using Cloudflare makes your operational survival a function of someone else's legal calculus.** This is why "just put it behind Cloudflare" is structurally wrong for a privacy coin no matter how technically convenient it is.

### 3. Traffic-analysis piggybacking

Adversaries flood the explorer specifically to manipulate the statistical signature of legit queries. Two variants:

- **Cover traffic**: produce noise that looks like a wallet scanner so when a real wallet scanner queries, it doesn't stand out.
- **Differential analysis**: force the rate-limit logic to throttle specific IPs into predictable timing patterns, giving the attacker a clock to correlate against on-chain activity.

Cloudflare's edge caching makes this *worse* by homogenizing response timing across geographic regions.

### 4. Chainalysis-style scraping

This is the actual sustained baseline traffic. Chain-forensics firms (Chainalysis, TRM Labs, Elliptic, CipherTrace) scrape public block explorers at industrial rates because they need the data for pattern analysis. It's not technically a DDoS — it's legitimate-looking HTTP traffic — but:

- It eats your bandwidth budget
- It slows the explorer for real users
- It builds a dataset the scraper uses to deanonymize users
- Rate-limiting them hits real users first, because forensics firms use rotating residential proxies and rotating IPs that Cloudflare can't distinguish from real users

**The rate limit you put in Caddy is primarily defending against this**, not against botnet floods. That's actually the dominant defensive use case on a privacy coin.

### 5. Targeted user attacks

If an attacker knows a specific user (whistleblower, journalist, dissident) checks their CoinCync balance via the explorer at a specific time, taking the explorer down during that window is an attack on **that user specifically**. Small surface-area attacks that look like minor downtime spikes.

### 6. Compliance harassment

Paperwork floods aimed at your hosting stack: rapid-fire takedown requests against your hosting provider (DigitalOcean), domain registrar, DNS provider, or any third party in the chain. DigitalOcean has complied with takedowns. Cloudflare has de-platformed customers. **The defense is distribution** — the more places your infrastructure lives, the more paperwork a regulator has to file, the more chances one of them says no.

## Why Cloudflare (and most CDNs) are wrong

Five structural reasons:

1. **Cloudflare MITMs every request.** It terminates TLS at its edge, decrypts every request, inspects it, then re-encrypts to your origin. Even in "Full (strict)" mode, Cloudflare is a designed-in MITM. For a privacy coin, that means a US corporation logs `(visitor_ip, queried_address, timestamp)` tuples for every explorer lookup. The cryptographic privacy you built into CLSAG, Bulletproofs, and stealth addresses is defeated at the network layer.

2. **Cloudflare blocks Tor users** via captcha challenges that make many sites unreachable through Tor Browser. The users who most need privacy are the ones routing through Tor — and they're the ones Cloudflare treats as suspicious.

3. **Cloudflare is a compliance chokepoint** (the Tornado Cash precedent above).

4. **Cloudflare centralizes outage risk.** A Cloudflare-wide outage (June 2024, July 2019) takes down everyone behind it simultaneously. A privacy coin whose explorer AND API both depend on Cloudflare goes fully dark on those days.

5. **The threat Cloudflare solves isn't the threat a privacy coin actually faces.** Cloudflare is excellent against drive-by botnet floods. The real threats are the six categories above, none of which Cloudflare meaningfully addresses.

## The correct defensive posture

Five layers, in rough order of effort:

### Layer 1 — aggressive own-edge rate limiting

The Caddyfiles in `deploy/explorer/` and `deploy/api/` already do this:

- `explorer.coincync.network`: **60 req/min/IP**
- `api.coincync.network`: **30 req/min/IP**

The primary purpose of these limits is **not** botnet defense — it's making **Chainalysis-style scraping expensive**. Scrapers will still get data, but at a rate that degrades their deanonymization tooling.

### Layer 2 — federation instead of centralization

Run multiple independent hosts. When `explorer.coincync.network` is at capacity, the right answer is **not** "add a CDN" — it's "run a second host."

Bitcoin's explorer ecosystem is the model:

- `blockstream.info`
- `mempool.space`
- `blockchain.info`

Three parallel independent deployments. A user who doesn't trust one picks another. A DDoS that takes one down leaves the others up. A takedown against one doesn't affect the others. **There is no single point a regulator can lean on.**

For CoinCync, the federation plan looks like:

```text
explorer.coincync.network    →  RIC      (primary)
explorer2.coincync.network   →  <new>    (second host you control)
explorer3.coincync.network   →  <community-run>
```

A first-time visitor lands on `explorer.coincync.network`. If it's slow or down, the page shows a "try a different mirror" link to the alternatives. Each mirror is independently operated; the operator just runs the same Caddy stack from `deploy/explorer/` with a different `CADDY_HOSTNAME` env var.

The DDoS resistance comes from **there being nowhere to aim**, not from a single scrubber in front.

#### Mirror discovery

The mirror list is published as a small static JSON file at `https://docs.coincync.network/mirrors.json` (or a dedicated `mirrors.coincync.network` if you want it on its own host):

```json
{
  "explorer": [
    { "url": "https://explorer.coincync.network",  "host": "RIC",      "operator": "official" },
    { "url": "https://explorer2.coincync.network", "host": "<region>", "operator": "<community>" }
  ],
  "api": [
    { "url": "https://api.coincync.network",       "host": "Toronto",  "operator": "official" }
  ]
}
```

The explorer application fetches this on load and offers a "switch mirror" affordance in the UI. A failed RPC fetch on the primary auto-falls-back to the next mirror in the list.

This file is the only thing CoinCync centralizes — and it's static, cacheable, replicable, and the failure mode is graceful (a stale mirrors list still works because the URLs in it are stable).

### Layer 3 — accept occasional downtime

Privacy coin explorers don't need five-9s uptime. If an attacker takes the explorer offline for an hour, users run their own node and verify directly. **The node is the source of truth; the explorer is a convenience.** Don't spend operational complexity on availability you don't need — spend it on the privacy guarantees you do need.

### Layer 4 — privacy-respecting CDN if traffic genuinely demands it

If traffic ever grows past what federation can handle (tens of thousands of concurrent users), there are two CDNs whose privacy posture is meaningfully better than Cloudflare's:

- **BunnyCDN** — European, GDPR-friendly, explicit "we don't mine customer data" policy. Cheap.
- **Fastly** — more expensive; used by Wikipedia, GitHub, Stripe, Mozilla. Strong privacy posture, no data resale.

Both are strictly better than Cloudflare for a privacy coin. Still not as good as no CDN at all, but if you genuinely need edge presence for performance, start with one of these. Almost certainly you'll never need to.

### Layer 5 — Tor hidden service availability

Publish an `.onion` mirror alongside the clearnet site for users whose threat model demands strong anonymity. Additive, not replacement. ~20 minutes of setup. See [Tor hidden services](./tor.md) for the runbook.

## TL;DR

| Threat | Wrong answer | Right answer |
| --- | --- | --- |
| Botnet DDoS | Cloudflare | Caddy rate limit + federation |
| Chainalysis scraping | Cloudflare | **Caddy rate limit (primary purpose)** |
| Traffic-analysis piggybacking | Cloudflare (makes it worse) | Federation + `.onion` availability |
| Regulator takedown | Cloudflare (single chokepoint) | Federation across jurisdictions |
| Short-seller narrative DDoS | Cloudflare | Federation + accept occasional downtime |
| Targeted user attack | Cloudflare | `.onion` availability for that user |

**Never route privacy-coin public traffic through a third party whose business model involves inspecting the traffic.** Your users' threat model says "nobody should see my queries." Cloudflare's business model says "we see everything to add value." Those are incompatible premises.

## See also

- [Tor hidden services](./tor.md) — the `.onion` mirror runbook
- [Block explorer](./explorer.md) — the deployment recipe (federation-ready)
- [Public RPC API](./api-host.md) — the parallel API deployment
