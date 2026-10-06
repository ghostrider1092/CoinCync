# Two-box testnet deployment

A split where the **shared** box does the low/bursty-CPU work (node + tick sidecar)
and the **dedicated** box does nothing but RandomX (the rig). This keeps the miner
off shared/burstable CPU (no steal, no abuse flags) and keeps the node's public
surface small.

```
        Internet / testnet mesh
                  │  P2P 28080 (public)
        ┌─────────┴──────────┐
        │  SHARED box        │   coincync-node  (validate/relay/RPC)
        │  <SHARED_IP>       │   coincync-tick  (health + colony, loopback)
        └─────────┬──────────┘
                  │  RPC 28081  (firewalled to the rig IP + Bearer auth)
        ┌─────────┴──────────┐
        │  DEDICATED box     │   coincync-rig   (RandomX, full-mem, all cores)
        │  62.238.121.186    │   NO keys — payout address only
        └────────────────────┘
```

## Hard rules

- **No spend keys on either box.** The rig only ever holds the *payout address*
  (receive-only). Your wallet/private keys stay on your own machine.
- **Testnet only** for now. Every binary MUST be built with `--features testnet`
  — consensus network is compile-time, so a default (mainnet) build will silently
  disagree with the testnet chain.
- **Node RPC is never open to the world.** It's Bearer-authenticated *and*
  firewalled to the rig's IP. The node refuses a non-loopback RPC bind without a
  key, so the auth can't be forgotten.

## What's here

```
shared-node/
  coincync-node.service     node systemd unit
  coincync-tick.service     tick sidecar unit (health + maintainer /colony)
  coincync-tick.toml        tick adapter config (reads the local node)
  node.env.example          secrets template (RPC API key)
  firewall.sh               ufw rules (public P2P, rig-only RPC)
rig/
  coincync-rig.service      rig systemd unit (RandomX, full-mem)
  rig.env.example           secrets template (RPC API key)
  firewall.sh               ufw rules (SSH only; /metrics stays loopback)
```

Placeholders to replace everywhere: `<SHARED_IP>` (the shared box's public IP,
once provisioned). The rig IP `62.238.121.186`, the seed `2.29.34.197:28080`, and
the payout address are already filled in.

## One-time: generate the shared secret

Pick ONE random API key and put the SAME value on both boxes.

```bash
openssl rand -hex 32          # copy this value
```

- Shared box: put it in `/etc/coincync/node.env` as `COINCYNC_RPC_API_KEY=...`
  AND write the bare value to `/etc/coincync/rpc.key` (the tick reads that file).
- Rig box: put it in `/etc/coincync/rig.env` as `COINCYNC_RPC_API_KEY=...`.

The maintainer token that gates the tick's `/colony` endpoint is a *separate*
secret — generate another `openssl rand -hex 32` and write it to
`/etc/coincync/maintainer.token` on the shared box.

## Deploy — shared box (node + tick)

```bash
# 0. build a testnet node + tick binary and copy them to /usr/local/bin
#    (build on a matching Linux host):  cargo build --release --features testnet \
#      --bin coincync-node --bin coincync-tick
sudo useradd --system --home /var/lib/coincync --create-home coincync
sudo mkdir -p /etc/coincync && sudo chmod 750 /etc/coincync
sudo install -m640 node.env.example /etc/coincync/node.env       # then edit in the key
sudo install -m640 coincync-tick.toml /etc/coincync/coincync-tick.toml
# create /etc/coincync/rpc.key (bare key) and /etc/coincync/maintainer.token, chmod 600
sudo chown -R root:coincync /etc/coincync && sudo chmod 640 /etc/coincync/*
sudo install -m644 coincync-node.service coincync-tick.service /etc/systemd/system/
sudo bash firewall.sh                     # EDIT <SHARED_IP>/SSH source first
sudo systemctl daemon-reload
sudo systemctl enable --now coincync-node
# wait until it's synced to the tip, THEN start the tick:
sudo systemctl enable --now coincync-tick
```

## Deploy — dedicated rig box (62.238.121.186)

```bash
# build a testnet rig binary and copy it to /usr/local/bin
#   cargo build --release --features testnet --bin coincync-rig   (in tools? no —
#   coincync-rig is in the main workspace; build from the repo root)
sudo useradd --system --no-create-home coincync
sudo mkdir -p /etc/coincync && sudo chmod 750 /etc/coincync
sudo install -m640 rig.env.example /etc/coincync/rig.env         # edit in the key
sudo chown -R root:coincync /etc/coincync && sudo chmod 640 /etc/coincync/*
sudo install -m644 coincync-rig.service /etc/systemd/system/
sudo bash firewall.sh
sudo systemctl daemon-reload
sudo systemctl enable --now coincync-rig
```

## Verify

```bash
# on the rig box — is it authenticating and hashing?
journalctl -u coincync-rig -f          # look for "daemon ok" then rising hashrate
curl -s localhost:9109/metrics | grep current_hashrate_hps

# on the shared box — node synced, tick publishing?
curl -s -X POST localhost:28081 -H 'content-type: application/json' \
  -H "Authorization: Bearer $(cat /etc/coincync/rpc.key)" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}'
curl -s -H "Authorization: Bearer $(cat /etc/coincync/maintainer.token)" \
  localhost:9200/colony        # 200 + JSON; 401 without the token
```

## Full-memory RandomX (the whole point of the dedicated box)

The rig unit does **not** set `COINCYNC_RANDOMX_LIGHT_MODE`, so it uses full-mem
mode (~2.3 GB dataset) — many times the hashrate of light mode. Ensure the box
has **≥4 GB RAM**. Optional big speed-up: reserve hugepages before start —

```bash
echo 1280 | sudo tee /proc/sys/vm/nr_hugepages     # ~2.5 GB in 2 MB pages
```

(make it persistent in `/etc/sysctl.d/` if it helps on your CPU).
