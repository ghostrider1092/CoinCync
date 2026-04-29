# CoinCync Explorer Deployment (nginx-only)

Public explorer: `https://explorer.coincync.network`

This deployment path is intentionally **nginx-only**. Caddy artifacts were removed to avoid split-brain operations and port conflicts.

## What this directory contains

- `install-nginx-explorer.sh` — installs/updates nginx vhost for explorer, enables `/api/testnet`, `/api/mainnet`, and `/health/*` routes with bearer auth forwarding, validates config, reloads nginx.
- `fetch-vendor.sh` — downloads/pins third-party frontend assets into `static/vendor`.
- `patch-vendor.sh` — rewrites explorer HTML CDN URLs to `/static/vendor/...` paths.
- `static/vendor/` — vendored JS/fonts/textures used by the explorer frontend.

## Production deploy

Run on the explorer host (RIC):

```bash
cd /opt/coincync
git pull --ff-only
sudo bash deploy/explorer/install-nginx-explorer.sh '<COINCYNC_RPC_API_KEY>'

# Optional: force explorer to read from a canonical node
# (recommended for "single source of truth" operation).
# Example points explorer testnet API at one designated upstream:
EXPLORER_TESTNET_RPC_UPSTREAM='10.0.0.42:28081' \
sudo bash deploy/explorer/install-nginx-explorer.sh '<COINCYNC_RPC_API_KEY>'
```

### One-command deploy helper

For routine explorer updates (when nginx wiring is already configured), use:

```bash
cd /opt/coincync
bash deploy/explorer/deploy-explorer.sh
```

Optional overrides:

```bash
BRANCH=main REPO_DIR=/opt/coincync NODE_SERVICE=coincync-node \
bash deploy/explorer/deploy-explorer.sh
```

### Explorer wiring model (top-explorer style)

CoinCync explorer follows the Etherscan/Esplora posture:

- Browser calls same-origin `/api/*` only.
- No browser-side direct node fallback.
- nginx chooses the canonical upstream node(s).
- If upstream is unhealthy, explorer fails closed instead of silently mixing sources.

Block history on the **Blocks** tab is filled with batched `get_block_range` JSON-RPC calls (100 blocks per request) against that same `/api/testnet` upstream, so the explorer can enumerate the full chain the node holds while keeping round trips bounded.

The UI now surfaces source/freshness badges on chain-critical pages. If operators change upstream wiring, those badges should be validated after deploy (expect `/api/testnet` for chain pages and `/health/*` for fleet probes).

## Verify routes

```bash
# Main explorer API
curl -sS -X POST https://explorer.coincync.network/api/testnet \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq .

# Node-health fan-out (example: SFO)
curl -sS -X POST https://explorer.coincync.network/health/sfo \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq .
```

If `/health/*` returns 502, check upstream node RPC reachability and auth key consistency across nodes.

## Updating explorer frontend

`src/explorer/index.html` is the source of truth. After pulling latest code on the host, nginx serves updated content immediately from `/var/www/explorer` path configured in the installer output.

## Vendored assets workflow

```bash
cd /opt/coincync/deploy/explorer
./fetch-vendor.sh
./patch-vendor.sh
```

Commit `static/vendor/` updates and the patched explorer HTML together.
