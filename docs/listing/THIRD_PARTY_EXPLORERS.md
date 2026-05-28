# Third-Party Explorer & Aggregator Strategy

Anti-scam classifiers weight **independent third-party attestation**
much higher than first-party infrastructure, no matter how polished
the first-party explorer is. CoinCync already has a strong in-house
explorer at https://explorer.coincync.network — additional in-house
explorer features are the lowest-leverage move in the space.

This document is the prioritized playbook for getting CoinCync onto
explorers and data services CoinCync does **not** operate.

## Order of leverage

```
1. Blockchair listing           (1 week of email,        very high signal)
2. Community-operated mirror    (1 month relationship,   high signal)
3. Aggregator submissions       (1 day each,             medium signal)
4. More in-house explorer feats (months of dev,          low scam-signal value)
```

Work top-to-bottom. Don't skip ahead to (4) because it's the most
fun — it's the least leveraged of the four.

---

## 1. Blockchair listing — primary objective

**Why this is the highest-leverage move:** Blockchair is the
multi-chain explorer that wallet integrations, scam classifiers,
and "is this real?" reviewers check first for non-EVM chains. They
already index Monero, Zcash, Dash, Bitcoin Cash, and other privacy
coins — the technical pattern is well-established, so the
engineering work on their side is low.

A "Supported on Blockchair" listing is the privacy-coin equivalent
of an Etherscan token page: third-party-operated, independently
verifiable, and the venue that downstream services trust.

### Action

- **Contact:** https://blockchair.com/contact (subject:
  "Privacy-coin integration request — CoinCync")
- **Send them:**
  - Link to the public source repository
  - Link to https://api.coincync.network (public RPC + REST)
  - Link to https://explorer.coincync.network (reference explorer)
  - [docs/listing/PROJECT_FACTS.md](PROJECT_FACTS.md) (canonical facts)
  - [CONSTITUTION.md](../../CONSTITUTION.md) (no-premine, no-dev-tax proof)
  - Genesis date and block-time confirmation
  - Confirmation that the project is open source and the chain is
    mineable today (testnet now, mainnet 2026-10-01)
- **Timeline expectation:** 2–8 weeks from first email to live page,
  most of it on Blockchair's queue, not yours.
- **Cost:** zero, except operator time.

### Done criteria

- [ ] CoinCync appears on https://blockchair.com (top of page or
      under "More chains")
- [ ] At least block height + tip hash + tx count visible
- [ ] Their data matches https://explorer.coincync.network within a
      sensible lag (≤ 10 min)

---

## 2. Community-operated explorer mirror — secondary objective

**Why this matters:** Two independent operators running explorer
codebases that agree on chain state is the strongest possible
"this chain is real and stable" signal short of a tier-1 CEX
listing. xmrchain.net vs the Monero core explorers is the model.

### Action

- Identify one or two technically-capable community members. (The
  Discord regulars are the natural pool. The community member with
  the 35 H/s mining issue from earlier in v1.0.9 prep is exactly
  the kind of person — engaged, running their own infrastructure.)
- Offer them:
  - The explorer source (already public in [src/explorer/](../../src/explorer/))
  - A one-page operator runbook (port assignments, RPC config,
    nginx template — derive from [scripts/deploy-explorer-nginx.ps1](../../scripts/deploy-explorer-nginx.ps1))
  - DNS subdomain forwarding if they want one (e.g.,
    `community-explorer.coincync.network` CNAME to their host)
- Do **not** pay them — paid operators are not independent
  operators, and that defeats the entire signal.

### Done criteria

- [ ] At least one community-operated explorer live on a
      different IP / different ASN / different host than the
      five-node project fleet
- [ ] Discoverable from coincync.network (link from the
      footer or a "community resources" page)
- [ ] Has been online for at least 30 days with self-reported
      uptime

---

## 3. Aggregator submissions — medium-effort, medium-signal

**Why these matter:** Aggregators are not explorers — they're the
data-services tier that scam classifiers cross-reference. Each one
appearing in a CoinCync search is a separate "third-party confirmed"
signal.

Submit to all of these in one operator afternoon:

| Service | URL | What they want | Effort |
|---|---|---|---|
| Cryptocompare | https://www.cryptocompare.com/coins/list-coin/ | Coin info form (overlaps with CoinGecko fields) | 30 min |
| Messari | https://messari.io/onboarding | Coin profile + tokenomics doc | 60 min |
| Coinpaprika | https://coinpaprika.com/about/contact/ | Email with PROJECT_FACTS link | 15 min |
| CryptoCompare CCData | https://data.ccdata.io/ | API integration request | 30 min |
| CoinCodex | https://coincodex.com/page/contact/ | Listing form | 30 min |
| Live Coin Watch | https://www.livecoinwatch.com/contact | Listing email | 15 min |
| Mosca (scam tracker) | https://mosca.io | Submit *not* as a coin — submit as a project so they have you on file with positive metadata before any scam report can claim the slot | 30 min |

### Action

- Submit each one. Use the long-form description from
  [SUBMISSION_KIT.md §1](SUBMISSION_KIT.md) verbatim — consistent
  description across services is itself a credibility signal.
- Maintain a tracker (suggest: `docs/listing/SUBMISSION_TRACKER.md`)
  of submission date / response / live-date per service. Use it
  to follow up on ones that go quiet after 4 weeks.

### Done criteria

- [ ] At least 5 of the 7 services above show CoinCync in their
      coin/asset search before mainnet launch day
- [ ] The remaining 2 have outstanding submissions with response
      acknowledgments

---

## 4. More in-house explorer features — only after 1-3 are underway

**Why this is the lowest-leverage move:** Adding features to your
own explorer does not change scam classification. The features
*do* help users, mining operators, and bug-bounty researchers, so
they're worth doing — but **not as a substitute** for items 1-3.

Privacy-coin constraints mean many Etherscan features are
structurally impossible on CoinCync:

- ✗ Per-address balance page (amounts are Pedersen-hidden)
- ✗ Token contract source (no programmable contracts)
- ✗ Token-holder analytics (recipients are stealth-addressed)
- ✗ Token-transfer list (no token layer)

These DO apply and are good incremental work:

- Deeper search (block-hash prefix, tx-hash prefix, height range)
- CSV export for public blockchain data (block headers, fee burn,
  difficulty series)
- Public REST + JSON-RPC docs page with copy-paste curl examples
- Rate-limited public API tier with documented quotas
- Charts for genuinely-public stats: hashrate, difficulty, block
  count, circulating supply, fee burn, anonymity-set growth (the
  5 privacy-stat pages shipped 2026-05-23 are the foundation here)

### Order within (4)

Do them in this order — each builds on the previous:

1. Public REST + JSON-RPC docs page (one-day task; the
   [openapi.rs](../../src/rpc/openapi.rs) descriptions already
   carry most of the content)
2. CSV export buttons on existing chart pages
3. Search improvements (prefix matching, height ranges)
4. Rate-limited public API tier (requires auth layer; this is the
   "weeks of work" item)

---

## Anti-pattern: do not do these

- **Do not pay for "premium listing" placements.** Aggregator paid
  tiers are themselves a scam-signal pattern in some classifiers
  (they cluster with pump-and-dump projects). Free organic listing
  only.
- **Do not submit to obscure scanner-only sites** with no review
  process. Volume of listings on shady sites is worse than absence.
- **Do not run multiple in-house explorers under different
  domains** trying to look like multiple operators. Classifiers
  ASN-cluster these and flag the pattern as misrepresentation.

---

## Reporting

After mainnet, maintain a single "Where to find CoinCync" page on
coincync.network that lists every third-party scanner, aggregator,
and explorer that indexes the chain. This is what wallets,
exchanges, and journalists will cite. Update it when items 1-3
above complete.

---

**Last updated:** 2026-05-26
**Related:** [PROJECT_FACTS.md](PROJECT_FACTS.md), [SUBMISSION_KIT.md](SUBMISSION_KIT.md)
