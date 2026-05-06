# Run a testnet node

You can either download a pre-built binary or build from source ([Build from source](./build.md)).

## Download a pre-built binary

|Platform|URL|
|---|---|
|Linux x86_64|<https://coincync.network/release/v1.0.1-testnet/coincync-node-linux-x86_64>|
|Windows x86_64|<https://coincync.network/release/v1.0.1-testnet/coincync-node-windows-x86_64.exe>|

```bash
# Linux example
curl -L -o coincync-node \
  https://coincync.network/release/v1.0.1-testnet/coincync-node-linux-x86_64
chmod +x coincync-node
./coincync-node --network testnet --data-dir ~/.coincync
```

> **Where to run a node, where NOT to mine:** running a `coincync-node` (P2P relay,
> RPC, no PoW computation) on a cloud VPS is fine. **Mining is different** —
> DigitalOcean, Cloudflare, AWS, GCP, and most major hosting providers
> explicitly prohibit cryptocurrency mining in their TOS and will terminate
> accounts that compute PoW. Run `coincync-miner` / `coincync-tui-miner` on
> personal hardware (your laptop, desktop, or a server you physically own).
> RandomX is CPU-only by design specifically so home machines can secure the
> chain — that's the architecture, not a workaround.

## Quick start

```bash
./coincync-node --network testnet --data-dir ~/.coincync
```

That's it. The node will:

1. Open (or create) a RocksDB database under `~/.coincync/testnet/`
2. Initialize the genesis block if the database is empty (and verify its hash against the hardcoded constant in `src/testnet.rs`)
3. Start the P2P listener on `0.0.0.0:28080`
4. Start the JSON-RPC server on `127.0.0.1:28081`
5. Connect to the public testnet seed nodes and begin syncing

Stop the node with `Ctrl-C`. Restart it later — chain state is on disk; it picks up where it left off.

## What success looks like

The first ~30 seconds of log output should look something like this:

```text
INFO  CoinCync 1.0 node starting
INFO  Network:  Testnet
INFO  Data dir: "~/.coincync"
INFO  Opening database at "~/.coincync/testnet"
INFO  Chain tip: height=0, hash=41f970df
INFO  Starting P2P listener on 0.0.0.0:28080
INFO  Starting RPC server on 127.0.0.1:28081
INFO  RPC server bound, methods: get_info, get_blockchain_info, ...
INFO  Connected to seed1.coincync.network:28080
INFO  Sync started — target height 12345
INFO  Node is running. Ctrl-C to stop.
```

If you see `CRITICAL: Genesis hash mismatch!` instead, your build is corrupt or you modified `src/testnet.rs` without recomputing the hash. Don't ignore that error — it means the binary you built will fork off the live testnet on the very first block.

## Talk to the running node

In a second terminal:

```bash
# How's the chain tip?
curl -sX POST http://127.0.0.1:28081 \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq .

# Block at a specific height
curl -sX POST http://127.0.0.1:28081 \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_block_by_height","params":[100]}' | jq .

# Mempool stats
curl -sX POST http://127.0.0.1:28081 \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_mempool_info"}' | jq .
```

The full method inventory is in [JSON-RPC reference](../api/json-rpc.md).

## Common CLI flags

| Flag | Default | What it does |
|---|---|---|
| `--network <testnet\|mainnet\|regtest>` | `testnet` | Which network to join |
| `--data-dir <path>` | `~/.coincync` | Where chain + wallet state lives |
| `--p2p-bind <addr>` | `0.0.0.0:28080` (testnet) | P2P listen address. Set to `0.0.0.0:port` to accept inbound |
| `--rpc-bind <addr>` | `127.0.0.1:28081` (testnet) | JSON-RPC listen address. **Always keep this on `127.0.0.1`** in production unless you've put a Caddy reverse proxy in front (see [Deploying a node](../operations/deployment.md)) |
| `--rest-bind <addr>` | none | Optional axum REST API. Defaults to `127.0.0.1:<rpc_port + 2>` if `--explorer` is passed |
| `--explorer` | off | Mounts the embedded block explorer at `GET /` on the REST port. **Local development only.** Production uses [`/deploy/explorer/`](../operations/explorer.md) |
| `--addnode <ip:port>` | (seed list) | Force-add a peer at startup. Useful for isolated test networks |
| `--no-peers` | off | Disable all peer discovery. Used for `regtest` and isolated tests |
| `--log-level <trace\|debug\|info\|warn\|error>` | `info` | Tracing-subscriber filter |

## Networks

| Network | P2P port | RPC port | Genesis | Status |
|---|---|---|---|---|
| `testnet` | 28080 | 28081 | March 6, 2026 | **live** |
| `mainnet` | 19080 | 19081 | October 1, 2026 | pre-launch |
| `regtest` | (any) | (any) | local-only | for isolated dev |

## Try the local explorer

If you want to see the block explorer alongside your node, pass `--explorer`:

```bash
./target/release/coincync-node --network testnet --explorer
```

Then visit `http://127.0.0.1:28083/` in your browser. Localhost-only by default — nobody on the LAN or the public internet can see it. This is for **local development only**; for a public block explorer use the standalone Caddy stack in [`/deploy/explorer/`](../operations/explorer.md).

## Operating a public seed (operators)

If you run infrastructure that should accept inbound peers: open **TCP 28080** in your **cloud** firewall (not only the host), install `coincync-node` under systemd, and verify DNS/TCP health. Broader deployment notes are in [Deploying a node](../operations/deployment.md). In the source tree, scripts live under `deploy/ops/` ([README](https://github.com/CyncDevelopment/Cync-Protocol/blob/main/deploy/ops/README.md)): `install-testnet-node.sh`, `verify-community-bootstrap.sh`, plus [`scripts/verify-community-join-readiness.ps1`](https://github.com/CyncDevelopment/Cync-Protocol/blob/main/scripts/verify-community-join-readiness.ps1) on Windows.

## Next steps

- [Create a wallet](./create-a-wallet.md) — generate a seed phrase, derive an address, receive testnet CYNC from the faucet
- [Deploying a node](../operations/deployment.md) — systemd unit, docker compose, firewall rules, monitoring
- [JSON-RPC reference](../api/json-rpc.md) — every method the node exposes, with sample requests
