# Mine CYNC from your PC

CoinCync uses **RandomX** — a CPU-only proof-of-work designed so that
anyone with a regular computer can secure the network. No GPUs, no
ASICs, no warehouse. The chain is more decentralized when more home
machines mine; that's the whole point of the algorithm.

## You will need

- Any modern computer (Windows, Linux, or macOS)
- A CoinCync wallet address starting with `tCYNC...` to receive rewards
  ([create a wallet](./create-a-wallet.md) if you don't have one)
- A few minutes

You do **not** need a GPU, special hardware, or any kind of exchange
account.

## Quick start

All testnet binaries are published as a single GitHub release at
[`v1.0.2-testnet`](https://github.com/Coincync/Coincync-Testnet-/releases/tag/v1.0.2-testnet)
along with `SHA256SUMS.txt`. Verify after download with
`sha256sum -c SHA256SUMS.txt`.

### Windows

Download the node binary:

|Binary|URL|
|---|---|
|coincync-node|<https://github.com/Coincync/Coincync-Testnet-/releases/download/v1.0.2-testnet/coincync-node.exe>|
|coincync-rig (miner)|<https://github.com/Coincync/Coincync-Testnet-/releases/download/v1.0.2-testnet/coincync-rig.exe>|

Open PowerShell in the folder where you saved them and run:

```powershell
# Start a node (leave this window running)
.\coincync-node.exe --network testnet

# In a second window, start mining (replace tCYNC… with your address)
.\coincync-rig.exe run-solo --node http://127.0.0.1:28081 `
    --address tCYNC3Z6jt428m... --threads 4 --tui
```

The `--tui` flag opens a live ratatui dashboard (stats bar +
scrolling log). Press `q` or `Esc` to quit.

### Linux

```bash
BASE=https://github.com/Coincync/Coincync-Testnet-/releases/download/v1.0.2-testnet
curl -L -O $BASE/coincync-node-linux-x86_64
curl -L -O $BASE/coincync-rig-linux-x86_64
curl -L -O $BASE/SHA256SUMS.txt
chmod +x coincync-node-linux-x86_64 coincync-rig-linux-x86_64

# (optional) verify
sha256sum -c SHA256SUMS.txt 2>/dev/null | grep -E "node|rig"

./coincync-node-linux-x86_64 --network testnet &
./coincync-rig-linux-x86_64 run-solo --node http://127.0.0.1:28081 \
    --address tCYNC3Z6jt428m... --threads 4 --tui
```

### macOS

The macOS-native build is not yet published; build from source for
Apple Silicon (see [Build from source](./build.md)). Reproducible
build environment is documented in
`docs/operations/REPRODUCIBLE_BUILDS.md`.

## What success looks like

The miner prints scrolling tracing-style output:

```
2026-05-02T19:00:01Z  INFO  miner: ✓ BLOCK FOUND at height 753!
2026-05-02T19:00:03Z  INFO  chain h=753 tip_age=2s diff=302 peers=8 synced=true
2026-05-02T19:00:18Z  INFO  miner: ✓ BLOCK FOUND at height 754!
```

Each `BLOCK FOUND` line means your machine just produced a block. The
mining reward (currently **~50 CYNC** per block) goes to the address
you passed in `--address`.

## Where NOT to run a miner

**Most cloud and dedicated-server providers prohibit mining**, including
DigitalOcean, AWS, GCP, Azure, Cloudflare, Hetzner, OVH, and Vultr.
Trying to mine on those services will get your account suspended.

The right places to run a CoinCync miner are:

- Your home computer
- A spare machine you own (mini-PC, Pi 5, old laptop)
- A box you've put in colocation (you own the hardware, the provider
  only rents space and bandwidth)

This is fine — RandomX is designed to run efficiently on the kind of
CPU you already have. A modest desktop will mine just as well as a
purpose-built rig.

## How much will I earn?

Testnet CYNC has no monetary value. Treat mining rewards as a way to
verify your wallet works, send transactions, and stress-test the
network. **Mainnet launch** is targeted for October 2026; testnet
mining is preparation, not income.

## Stopping the miner

Press `Ctrl+C` in the miner window. The node keeps running until you
stop it the same way. Restart either at any time — your chain state
and wallet are saved on disk and pick up where they left off.

## What if I'm the only miner?

If everyone running CoinCync stops mining, the chain stops producing
blocks. The chain doesn't break — it just sits at the current tip
until someone resumes. This makes mining inherently a community
activity. **The more home miners, the more resilient the network.**
That's exactly the architecture we want.
