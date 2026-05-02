# Block explorer

How to run the public block explorer at `https://explorer.coincync.network`. Lives in [`/deploy/explorer/`](https://github.com/CoinCync/Coincync-Testnet-/tree/main/deploy/explorer).

## Architecture (one-line)

A single Caddy reverse proxy on port 443, fronting a localhost-bound `coincync-node` jsonrpsee server, with the embedded block explorer HTML served from `GET /` and `POST /api/{testnet,mainnet}` proxying to the cyncd RPC.

The explorer UI loads chain data **only** through that JSON-RPC surface (same-origin `/api/testnet` or `/api/mainnet`). On the **Blocks** page it walks the full canonical height range using batched `get_block_range` (100 heights per request, server-capped) so the table can list every block the upstream node stores, without thousands of per-height round trips.

Recent UX hardening keeps the CoinCync visual style while making chain views more operator-friendly:
- blocks/mempool/network/health/iron pages show explicit source + freshness badges,
- the blocks table supports newest reset + height jump + progressive backfill,
- duplicate low-signal widgets were removed from high-traffic pages to prioritize chain state.

```text
    public 443/tcp ── Caddy ── 127.0.0.1:28081 (cyncd testnet RPC)
                        │   └─ 127.0.0.1:19081 (cyncd mainnet RPC, post-launch)
                        ├─── /var/www/explorer/index.html (embedded HTML)
                        └─── /static/vendor/* (vendored CDN assets)
```

## Files

| File | Purpose |
|---|---|
| `Caddyfile` | TLS termination, security headers, rate limit, RPC proxies |
| `docker-compose.yml` | Caddy 2.8-alpine, host networking, persistent ACME volumes |
| `README.md` | Operator runbook, DDoS-mitigation discussion |
| `fetch-vendor.sh` | Downloads chart.js / d3 / globe.gl / topojson / world-atlas / three-globe textures + Google Fonts. TOFU SHA-256 pinning. |
| `patch-vendor.sh` | Rewrites `src/explorer/index.html` to use `/static/vendor/` paths instead of external CDN URLs. |
| `static/vendor/` | Vendored CDN assets after `fetch-vendor.sh` runs. Committed to git for reproducibility. |
| `static/vendor/checksums.txt` | SHA-256 of every vendored file. Verified on every `fetch-vendor.sh` run. |

## First-time deploy

On the explorer host (currently LON):

```bash
# 1. Pre-flight: confirm cyncd is bound to localhost only
ss -tlnp | grep -E ':(28081|19081) '
# Expect: 127.0.0.1:28081 (testnet RPC). Mainnet RPC appears post-launch.
# DO NOT see 0.0.0.0 — that defeats the entire Caddy security model.

# 2. Pre-flight: confirm 80/443 are clear and DNS resolves
ss -tlnp | grep -E ':(80|443) '   # expect nothing
dig +short explorer.coincync.network
# Expect: the IP of the current explorer host (see operator inventory)

# 3. Open public ports in DigitalOcean firewall: 80/tcp and 443/tcp.
#    DO NOT also open 28081 (the whole point is that only Caddy is public).

# 4. Pull and deploy
cd /opt/coincync
git pull --ff-only
cd deploy/explorer

# 4a. (Recommended) vendor the CDN dependencies
./fetch-vendor.sh
# Reviews + commits checksums.txt
git add static/vendor && git commit -m "explorer: vendor CDN deps"

# Then patch index.html to use the vendored paths
./patch-vendor.sh
git add ../../src/explorer/index.html && git commit -m "explorer: use vendored assets"

# Re-run lib tests to confirm the CDN-enumeration test still passes
cargo test --lib -p coincync explorer

# 4b. Start Caddy
docker compose up -d
docker compose logs -f caddy   # watch the ACME handshake
```

First request to `https://explorer.coincync.network/` triggers Let's Encrypt cert provisioning (~5 seconds). Subsequent requests are instant.

## Verification

```bash
curl -I https://explorer.coincync.network/
# expect: HTTP/2 200, content-type: text/html, cache-control: public, max-age=300, must-revalidate

curl -sX POST https://explorer.coincync.network/api/testnet \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq .

# Mainnet pre-launch returns 502 (no upstream). Post-launch returns chain data.
curl -sX POST https://explorer.coincync.network/api/mainnet \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' -w '\n%{http_code}\n'
```

## Updating the explorer HTML

The HTML is bind-mounted live from `src/explorer/index.html`. To update:

```bash
cd /opt/coincync
git pull --ff-only       # pulls any changes to src/explorer/index.html
# Caddy doesn't need to restart. The HTML cache is 5 minutes, so worldwide
# rollout completes in ≤ 5 minutes.
```

To force-refresh immediately, `docker compose restart caddy`.

## Production keep/remove checklist

Use this as the default trim for the public explorer. The goal is a safer, lower-noise operator surface.

### Keep (public-by-default)

- `home` (summary, latest blocks, chain status)
- `blocks`, `block`, `tx`, `mempool` (core explorer flow)
- `network`, `health` (operational observability)
- `supply`, `burn` (tokenomics transparency)
- `privacy`, `about`, `constitution`, `changelog` (project/legal context)
- `docs`, `api`, `search`, `faucet` (user support and read-only API docs)

### Dev-only or remove from public nav

- `wallet` (browser key generation risk, even with warnings)
- `apilive` (encourages ad-hoc probing from browsers)
- `txbuilder` (implies browser tx construction workflow)
- `multisig` (advanced flow better documented in wallet/CLI docs)
- `balancelookup`, `richlist` (privacy/targeting metadata amplification)
- `webhooks`, `livestream` (non-essential attack surface and data churn)
- `status`, `miningtutorial`, `governance` (better hosted in docs pages, not top nav)

### Runtime control now in `index.html`

The explorer now defaults to **production mode**, which hides the dev-only pages above.

- Public deployment behavior: pages are hidden and direct navigation falls back to `home`
- Local dev override: run on `localhost` or `127.0.0.1` with `?dev_explorer=1`
- External dependency override: remote assets/fetches are disabled by default and only enabled on `localhost` with `?allow_external_deps=1`

Example:

```text
http://localhost:19082/?dev_explorer=1
```

## Security model

The explorer host is a **trust boundary**. Every public-facing HTTP request lands on Caddy, which enforces:

- **TLS** via Let's Encrypt (auto-provisioned, auto-renewed)
- **HSTS** preload (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`)
- **CSP** (`default-src 'self'` target posture; temporary external origins must stay explicitly documented and minimized)
- **Rate limit** of 60 req/min per source IP (whose primary purpose is making industrial-rate scraping by chain-forensics firms expensive — see [Federation & DDoS](./federation-and-ddos.md))
- **Body size cap** of 64 KB per request (mirrors the `rest.rs` proxy's cap)
- **Method allowlist** enforced by the upstream `rest.rs` proxy when the explorer's JS calls `/api/v1/...`
- **No third-party MITM** (no Cloudflare, no CDN, no edge cache that sees decrypted traffic)

The cyncd node itself is NOT exposed publicly. Caddy proxies allowlisted requests to it on localhost. Any attacker who finds a vulnerability in jsonrpsee can still only hit it through Caddy's allowlisted method set, with the rate limit applied.

## What this stack deliberately does NOT do

- **Cloudflare in front** — see [Federation & DDoS](./federation-and-ddos.md). The whole reason to NOT use a CDN is structural to the privacy-coin threat model.
- **Per-user authentication** — every endpoint is read-only and rate-limited. Authentication on a write-capable wallet endpoint lands in P1.
- **Transaction submission** — `submit_block` and `send_raw_transaction` are blocked from the public REST proxy by `RPC_ALLOWED_METHODS`. Wallets that need to submit transactions submit to their own local node, not to the public explorer.
- **Tx-by-hash lookup** — `get_transaction` returns a labelled `NotImplemented` because the chain doesn't yet have a `txid → (block_height, tx_index)` index. Lands in P1.
- **Asset queries** — permanently `NotImplemented`. CoinCync 1.0 stripped the confidential-asset layer.

## Adding a `.onion` mirror

See [Tor hidden services](./tor.md). The same Caddy stack can additionally serve the explorer over an `.onion` for users whose threat model demands strong anonymity. ~20 minutes of setup, additive to the clearnet site.

## See also

- [Federation & DDoS](./federation-and-ddos.md) — why this is one host and not behind a CDN
- [Public RPC API](./api-host.md) — the parallel deployment for the API subdomain
- [Tor hidden services](./tor.md) — adding `.onion` availability
- The `deploy/explorer/README.md` source file — has the same content as this page plus operator-runbook details
