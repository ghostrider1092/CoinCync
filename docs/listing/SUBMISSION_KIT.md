# CoinCync — Listing Submission Kit

Pre-drafted, ready-to-paste content for the two listing services that
matter most to anti-scam classification (CoinGecko and CoinMarketCap),
plus the operational checklist for tag-cut week.

**Why pre-draft this?** Slow / incomplete listing-form responses are
themselves a scam signal — reviewers see "we'll get back to you" and
move the application to the bottom of the queue. A complete packet
submitted on day 1 of public mainnet shifts you from "unknown
project" to "audited, doxxed, transparent" before market makers
ever look.

All fact-fields below pull from [PROJECT_FACTS.md](PROJECT_FACTS.md).
Keep that as the source of truth; do not edit numbers here directly.

---

## 1. CoinGecko submission

**Form URL:** https://www.coingecko.com/en/coins/new
**Estimated review time:** 1–3 weeks (faster if packet is complete)

### Required fields

| Field | Value |
|---|---|
| Project name | CoinCync |
| Symbol / ticker | CYNC |
| Genesis date | 2026-10-01 (UTC) |
| Project category | Privacy Coin, Proof of Work |
| Hash algorithm | RandomX |
| Block time | 120 seconds |
| Block reward (initial) | 50 CYNC, asymptotic curve |
| Max supply | 100,000,000 CYNC (asymptotic, never reached) |
| Total supply at genesis | 0 CYNC (no premine) |
| Premine | None — compile-time enforced (Article II) |
| ICO / IDO / private sale | None |
| Team allocation | None |
| Foundation reserve | None |
| Website (primary) | https://coincync.network |
| Source repository | (fill in public github URL) |
| License | (fill — MIT / Apache-2.0 / etc) |
| Block explorer URL | https://explorer.coincync.network |
| Public RPC endpoint | https://api.coincync.network/rpc/mainnet (post-launch) |
| Whitepaper / docs | https://coincync.network/docs (or repo `docs/` URL) |
| Audit report | (link once published) |
| Discord / community URL | (fill) |
| Twitter / X | (fill, if any) |
| Reddit | (fill, if any) |
| Public contact email | (fill — recommend `contact@coincync.network`) |

### Long-form description (paste into "Project Description")

> CoinCync is a privacy-preserving proof-of-work cryptocurrency
> launched in 2026 with a fair-launch distribution and constitutional
> guarantees enforced at compile time.
>
> **Privacy by default.** Every transaction uses CLSAG ring signatures
> (minimum ring size 11), Pedersen-committed amounts hidden with
> Bulletproofs+ range proofs, and one-time stealth addresses. Privacy
> is mandatory at the consensus level, not opt-in.
>
> **Fair launch.** No premine, no developer tax, no foundation
> reserve, no token sale of any kind. The codebase enforces a 0%
> developer tax with a compile-time assertion (Article II) — any
> build that violates this fails to compile.
>
> **Capped supply.** 100,000,000 CYNC asymptotic cap, approached but
> never reached, plus a 0.6 CYNC/block tail emission. 30% of all
> transaction fees are burned. No halvings.
>
> **Smooth emission.** Block reward decays smoothly with circulating
> supply rather than via discrete halving events, eliminating the
> economic shocks that have historically destabilized halvening-based
> chains.
>
> **Public audit posture.** [link to audit report once published].
> Pre-audit verification: 27 fuzz targets, reproducible builds, signed
> binaries, critical-files SHA-256 lockfile that fails the build on
> any consensus-file tampering.
>
> CoinCync is open source under [license]. There is no operating
> company — the protocol is maintained by the contributors listed
> in MAINTAINERS.md and operated by the global community of node
> runners and miners.

### Tokenomics image / chart

CoinGecko likes a single chart showing the emission curve. Generate one from
`src/emission/curve.rs` after launch — Python script suggestion:

```python
# block_height vs cumulative_supply over the first 10 years
# x-axis: block_height (each block = 120s)
# y-axis: total supply in CYNC
# Use EMISSION_DIVISOR = 2_000_000, TAIL_EMISSION = 0.6 CYNC
```

Save as `docs/listing/emission-curve.png` and attach to the form.

---

## 2. CoinMarketCap submission

**Form URL:** https://support.coinmarketcap.com/hc/en-us/articles/360043659351 → "Self-Reporting Dashboard"
**Estimated review time:** 1–4 weeks
**Key differentiator vs CoinGecko:** CMC requires a "self-reported
circulating supply API endpoint" that they can poll. See §3 below.

### Required fields

Same as CoinGecko §1 plus:

| Field | Value |
|---|---|
| Self-reported circulating supply URL | https://api.coincync.network/api/v1/mainnet/supply/circulating (see §3) |
| Self-reported max supply URL | https://api.coincync.network/api/v1/mainnet/supply/max (returns 100000000) |
| Proof of address ownership | Sign a CMC-provided challenge with the website's domain DNS, or with a Twitter pinned tweet |
| Liquidity / first listing | (CMC requires at least one CEX or DEX market; this is a launch-week dependency) |

### Long-form description

Use the same text as the CoinGecko description above. CMC accepts
markdown.

### CMC categories to check

- [x] Privacy
- [x] Proof of Work
- [x] Mineable
- [x] Layer 1
- [ ] Smart Contracts (CoinCync is intentionally non-programmable)

---

## 3. Self-reported supply endpoint (CMC requirement)

CMC and several exchanges require a publicly-pollable endpoint that
returns the current circulating supply as a plain number with no
JSON wrapping. Two endpoints are shipped on the REST API:

| Route | Returns | Format |
|---|---|---|
| `GET /api/v1/supply/circulating` | current circulating supply | `12345.678901` (6 decimals) |
| `GET /api/v1/supply/max` | supply target | `100000000` |

**Public URLs (post nginx-deployment):**

- https://api.coincync.network/api/v1/mainnet/supply/circulating
- https://api.coincync.network/api/v1/mainnet/supply/max
- (testnet variants: `/api/v1/testnet/supply/...`)

**Implementation:** [src/rpc/rest.rs](../../src/rpc/rest.rs)
(handlers `get_supply_circulating` and `get_supply_max`). Uses
integer arithmetic — the f64 cast that appeared in earlier drafts
loses precision above 2^53. Uses `crate::constants::COIN` and
`crate::constants::TOTAL_SUPPLY_TARGET` so any constitutional change
flows through automatically.

**Known precision ceiling:** the JSON-RPC `total_emitted` field is
serialized as u64, which caps representable supply at ~18.4M CYNC.
That covers all of pre-2030+ at current emission rates. Switching
to u128 serialization is a separate v1.x follow-up if and when
circulating supply approaches the u64 ceiling.

**Deployment dependency:** the production nginx must proxy
`/api/v1/(testnet|mainnet)/(.*)` to the daemon's REST port and
**preserve the `/api/v1/` prefix**. The current production proxy
returns 404 on these paths — `scripts/deploy-explorer-nginx.ps1`
needs a re-deploy / rewrite-rule audit before CMC's polling can
succeed.

---

## 4. Tag-cut week launch checklist

Submit listings on **day 1** of public mainnet, not week 4. The
pre-drafted packet above is what makes this realistic.

- [ ] **T-7 days:** PROJECT_FACTS.md `(set this)` placeholders all filled
- [ ] **T-7 days:** audit report URL fixed (or "in progress" with firm name)
- [ ] **T-3 days:** emission-curve chart generated and saved to `docs/listing/`
- [ ] **T-3 days:** self-reported supply endpoint deployed and live on testnet
- [ ] **T-1 day:** verify `https://api.coincync.network/v1/testnet/supply` returns a sensible number
- [ ] **T+0 (mainnet launch):** supply endpoint live for `/v1/mainnet/`
- [ ] **T+0:** submit CoinGecko form
- [ ] **T+0:** submit CMC form
- [ ] **T+0:** submit Cryptowatch.cc, Mosca, and CryptoCompare (lower-tier but boost classifier scores)
- [ ] **T+3 days:** follow up on each submission with any clarifications

---

## 5. Anti-scam evidence packet

Bundle these into a single zip and link from PROJECT_FACTS.md §5
before submitting listings. Reviewers love a single download.

| File | Purpose |
|---|---|
| CONSTITUTION.md | binding rules incl. no premine, no dev tax |
| critical_files.lock | SHA-256s of consensus files — reviewer can verify build hasn't tampered |
| SHA256SUMS (signed) | binary integrity for the launched release |
| SECURITY.md | responsible disclosure process |
| MAINTAINERS.md + governance/bus-factor.md | who maintains, who has keys |
| docs/audit-submission.md + audit firm report | external attestation |
| sha256(release-binary).txt + signing key fingerprint | reproducibility proof |
| docs/THREAT_MODEL.md | shows the project has thought about adversaries |
| docs/explicitly-not-doing.md | bounds the attack surface intentionally |

Name the zip `coincync-listing-evidence-<release-tag>.zip` and host
it at a stable URL on `coincync.network/listing/`.

---

**Last updated:** 2026-05-26
**Owner:** maintainer cutting the tag (see MAINTAINERS.md)
