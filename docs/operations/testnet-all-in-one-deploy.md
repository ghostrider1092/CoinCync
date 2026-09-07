# Testnet all-in-one deployment (single Hetzner box)

How to bring up the full CoinCync **testnet** — the seed node **and** all public
sites (landing, docs, explorer, api, faucet) — on one Hetzner box.

**Target:** `cync-node-hel1` — Hetzner CPX22 (2 vCPU / ~4 GB / 80 GB),
Falkenstein DE, public IP `2.28.1.75`, Debian 12.

All web services run behind nginx on this box and reverse-proxy to the node's
**loopback** RPC (`127.0.0.1:28081`). Nothing but P2P (28080) and HTTPS (443)
is exposed. As the fleet grows, split roles onto more boxes — the same
scripts support that; here everything is co-located.

> Substitute your own domain if it isn't `coincync.network`. Run everything as
> root (or with `sudo`). Commands assume the repo is checked out at
> `/opt/coincync` on the box.

---

## 0. Prerequisites

- DNS control for `coincync.network` (testnet). You will point records at
  `2.28.1.75`.
- **Hetzner Cloud Firewall** (and/or `ufw`) allowing inbound:
  - `28080/tcp` — P2P (public)
  - `80/tcp`, `443/tcp` — HTTP/HTTPS (nginx; 80 is for certbot + redirect)
  - `22/tcp` — SSH
  - **Do NOT** expose `28081` (RPC), `28083` (REST), or `9091` (metrics).
- Packages on the box: `nginx`, `certbot python3-certbot-nginx`, `git`, `curl`,
  `ufw`.

```bash
sudo apt-get update && sudo apt-get install -y nginx certbot python3-certbot-nginx git curl ufw
sudo git clone https://github.com/ghostrider1092/CoinCync.git /opt/coincync
```

---

## 1. Get the node binaries onto the box

Use the reproducible **testnet** release binaries (the Docker build path — a
`*-testnet` tag now produces correct testnet-consensus Linux binaries). Either
download from the GitHub Release for the `v2.0.0-testnet` tag, or build them and
`scp` them up:

```bash
# On a build host with Docker:
bash scripts/build-in-docker.sh --testnet --out ./out
# Verify, then copy node + wallet + faucet-relevant bins to the box:
scp out/coincync-node out/coincync-wallet root@2.28.1.75:/usr/local/bin/
```

Confirm it's a testnet binary (must print the testnet genesis):

```bash
/usr/local/bin/coincync-node print-genesis-hash
# Genesis hash: d2240feaa1f5aa29f25f4c9f3b6948368a9a3607443d637660637d28a00d82da
```

---

## 2. Install and start the seed node

```bash
cd /opt/coincync
sudo bash deploy/ops/install-testnet-node.sh --open-ufw
```

This creates the `coincync` system user + `/var/lib/coincync`, installs the
hardened `coincync-node.service` (`--network testnet`, P2P `0.0.0.0:28080`, RPC
`127.0.0.1:28081`), opens `28080/tcp` in `ufw`, and starts the node. Watch it
sync:

```bash
journalctl -u coincync-node -f
```

---

## 3. RPC API key (shared by node + nginx)

RPC binds loopback, so this is defense-in-depth, but the site installers expect
a key. Generate one, store it for the node, and load it via `EnvironmentFile`:

```bash
KEY=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 43)
sudo install -d -m 0750 -o root -g coincync /etc/coincync
printf 'COINCYNC_RPC_API_KEY=%s\n' "$KEY" | sudo tee /etc/coincync/coincync.env >/dev/null
sudo chmod 0640 /etc/coincync/coincync.env && sudo chown root:coincync /etc/coincync/coincync.env
# Load it into the node unit:
sudo sed -i '/^\[Service\]/a EnvironmentFile=/etc/coincync/coincync.env' /etc/systemd/system/coincync-node.service
sudo systemctl daemon-reload && sudo systemctl restart coincync-node
echo "RPC key: $KEY"   # you'll pass this to the explorer installer in step 6
```

---

## 4. DNS records

Point these A records at `2.28.1.75`:

| Record | Purpose |
|--------|---------|
| `seed1.coincync.network` | P2P DNS seed (bootstrap) |
| `coincync.network`, `www` | landing |
| `docs.coincync.network` | docs |
| `explorer.coincync.network` | block explorer |
| `api.coincync.network` | public API + faucet |

`seed1` is the one that makes `verify-community-bootstrap.sh` pass. Add
`seed2`/`seed3` when you provision more boxes (see
[`fleet-config.md`](./fleet-config.md)).

---

## 5. TLS certificates (Let's Encrypt)

The on-host nginx installers expect certs at
`/etc/letsencrypt/live/<domain>/`. Issue them once DNS resolves:

```bash
sudo certbot certonly --nginx -d coincync.network -d www.coincync.network -d docs.coincync.network
sudo certbot certonly --nginx -d explorer.coincync.network
sudo certbot certonly --nginx -d api.coincync.network
```

---

## 6. Bring up the sites

All from `/opt/coincync`. Each installer writes an nginx vhost that proxies to
the loopback node.

**Landing + docs:**
```bash
# Populate /var/www/landing and /var/www/docs with your static builds first, then:
sudo bash deploy/landing/install-nginx-landing.sh
```

**Explorer:** assemble the first-party assets, deploy to the docroot, then the
vhost (pass the RPC key from step 3):
```bash
bash scripts/assemble-explorer.sh
sudo bash deploy/explorer/deploy-explorer.sh
sudo bash deploy/explorer/install-nginx-explorer.sh "$KEY"
```
The explorer's node-status/globe now shows the single `hel1` node and its
`/health/hel1` route resolves to the local node.

**API (+ faucet route):**
```bash
sudo bash deploy/api/install-nginx-api.sh api.coincync.network
```

Reload and sanity-check nginx after the vhosts are in:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## 7. Faucet

Stage the binaries where `install-faucet.sh` expects them, then install and
**fund the hot wallet**:

```bash
sudo cp /usr/local/bin/coincync-wallet /tmp/coincync-wallet
scp out/coincync-faucet root@2.28.1.75:/tmp/coincync-faucet   # from your build host
cd /opt/coincync && sudo bash scripts/install-faucet.sh
# It prints the hot-wallet address — mine/send testnet CYNC to it before use.
```

The faucet listens on `127.0.0.1:8082`; the api vhost exposes `/faucet`,
`/faucet/stats`, `/faucet/health`. Publish the registry entry with
`scripts/publish-faucet-registry.sh` (see
[`runbook-faucet-registry.md`](./runbook-faucet-registry.md)).

---

## 8. Verify

```bash
# Bootstrap health (DNS seeds resolve + seed accepts P2P):
bash deploy/ops/verify-community-bootstrap.sh          # expect result=OK

# Node is syncing:
curl -s -X POST http://127.0.0.1:28081 -H 'content-type: application/json' \
  -H "Authorization: Bearer $KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | head

# Sites answer over HTTPS:
curl -sSI https://coincync.network | head -1
curl -sSI https://explorer.coincync.network | head -1
curl -sS -X POST https://explorer.coincync.network/health/hel1 \
  -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | head
curl -sS https://api.coincync.network/faucet/health | head
```

---

## Cutting an existing seed over to the September reset

If the box is **already running an older binary on the pre-reset chain** (e.g.
`CoinCync/1.0.12` at some height N — check with `get_peers` / the node's
`user_agent`), it is on a **different genesis** than the current code
(`d2240fea`, the 2026-09-04 reset). New-code nodes cannot sync it — you must
reset the box onto the new genesis. **This discards the old chain** (a
throwaway pre-reset testnet):

```bash
sudo systemctl stop coincync-node
# Discard the old-chain data (back it up first only if you truly want it):
sudo rm -rf /var/lib/coincync/testnet
# Install the new testnet binary (from the v2.0.0-testnet release or scp'd build):
sudo install -m0755 coincync-node /usr/local/bin/coincync-node
sudo systemctl start coincync-node
# Confirm it re-inited at the reset genesis, height 0:
/usr/local/bin/coincync-node print-genesis-hash
# → d2240feaa1f5aa29f25f4c9f3b6948368a9a3607443d637660637d28a00d82da
```

The seed is now on the fresh chain at height 0. It will stay at 0 until a
**miner** (next section) produces blocks — that's expected.

## Making the testnet alive: block production (NOT on this box)

The Hetzner box is a **seed** — it relays blocks and serves the sites, but it
does **not** mine, so it never produces a block on its own. A testnet is only
"alive" (height climbing, faucet fundable, transactions confirming) while a
**miner** is running somewhere and peered to this seed. Keep the miner **off**
the public box (dedicate its cycles to the node + nginx); run it on a separate
machine — e.g. your home/dev box, which can stay behind NAT and never needs a
public IP.

On the **miner machine** (not the Hetzner box):

```bash
# 1. A local testnet node that dials the Hetzner seed (outbound only — no
#    inbound/public exposure needed):
coincync-node --network testnet --data-dir ~/.coincync \
  --rpc-bind 127.0.0.1:28081 --addnode 2.28.1.75:28080

# 2. A wallet + payout address (once):
coincync-wallet create            # save the seed phrase
coincync-wallet address           # copy the tCYNC... address

# 3. Mine to it (RandomX CPU). --threads 0 auto-detects cores:
coincync-rig run-solo --network testnet \
  --node http://127.0.0.1:28081 --address tCYNC<your-address> --threads 0
```

Blocks found on the miner propagate over that peer link to the Hetzner seed,
which gossips them to the rest of the network — so `explorer.coincync.network`
starts climbing and the chain is live. **Fund the faucet** (step 7) by sending
mined testnet CYNC from this wallet to the faucet's printed hot-wallet address.

> One miner + one seed is a valid *minimal* live testnet, but it stalls if the
> miner goes offline. Add a second miner and/or seed for resilience once the
> basics are proven.

## Scaling past one box

When you add Hetzner seeds: provision the box, run step 2 on it, add its IP to
`scripts/fleet-config.json` **and** `TESTNET_SEED_NODES`/`TESTNET_FALLBACK`
(the `testnet_fallback_matches_fleet_config` test enforces this), add a
`/health/<id>` nginx route + a matching row in the explorer node arrays
(`src/explorer/app/{01-core,07-map,08-globe-network}.js`), register its DNS
seed record, and run `scripts/sync-fleet-config.sh`. Full procedure in
[`fleet-config.md`](./fleet-config.md).
