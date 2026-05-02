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

### Windows

Download two binaries from `coincync.network`:

|Binary|URL|
|---|---|
|coincync-node|<https://coincync.network/release/v1.0.1-testnet/coincync-node-windows-x86_64.exe>|
|coincync-tui-miner|<https://coincync.network/release/v1.0.1-testnet/coincync-tui-miner-windows-x86_64.exe>|

Open PowerShell in the folder where you saved them and run:

```powershell
# Start a node (one-time, leave running)
.\coincync-node-windows-x86_64.exe --network testnet

# In a second window, start mining (replace tCYNC… with your address)
.\coincync-tui-miner-windows-x86_64.exe --testnet --address tCYNC3Z6jt428m... --threads 4 --log
```

### Linux

```bash
curl -L -O https://coincync.network/release/v1.0.1-testnet/coincync-node-linux-x86_64
curl -L -O https://coincync.network/release/v1.0.1-testnet/coincync-tui-miner-linux-x86_64
chmod +x coincync-node-linux-x86_64 coincync-tui-miner-linux-x86_64

./coincync-node-linux-x86_64 --network testnet &
./coincync-tui-miner-linux-x86_64 --testnet --address tCYNC3Z6jt428m... --threads 4 --log
```

### macOS

Same as Linux. The macOS-native build is not yet published; build from
source for Apple Silicon (see [Build from source](./build.md)).

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
