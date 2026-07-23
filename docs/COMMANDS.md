<!-- markdownlint-disable MD036 MD013 -->
# CoinCync Command Reference

Every CLI binary CoinCync ships, with the subcommands and the practical recipes for each. Copy-paste friendly. For developer-side commands (build, test, deploy), see [`DEVELOPER.md`](DEVELOPER.md).

---

## Which binary do I want?

| Binary | What it does | When to reach for it |
| --- | --- | --- |
| `coincync-node` | Full node daemon — validates, propagates, serves RPC | Run a node, host an explorer, expose RPC |
| `coincync-wallet` | Wallet CLI — keys, addresses, send/receive, multi-sig | Hold or move CYNC, sign transactions |
| `coincync-rig` | CPU miner | Mine CYNC against a daemon |
| `cyncswap` | CYNC↔BTC atomic swap (**skeleton — not yet functional**) | Browse the protocol surface; see `CIP-001` |

---

## `coincync-node` — Full Node Daemon

```text
Usage: coincync-node [OPTIONS] [COMMAND]

Commands:
  start               Start the node (default if no command is given)
  print-genesis-hash  Print the genesis block hash and exit
  status              Show node status

Common options:
  --data-dir <DIR>      Data directory  [default: ~/.coincync]
  --network <NET>       mainnet / testnet / regtest  [default: testnet]
  --log-level <LEVEL>   info / debug / trace  [default: info]
  --p2p-bind <ADDR>     P2P listen override
  --rpc-bind <ADDR>     RPC listen override
  --addnode <ADDR>      Force-connect a peer at startup
  --no-peers            No automatic peer discovery (for isolated tests)
  --explorer            Mount the embedded block explorer (LOCAL DEV ONLY)
  --rest-bind <ADDR>    REST + explorer bind, default 127.0.0.1:<rpc+2>
```

### Recipes

**Run a testnet node, default everything:**

```bash
coincync-node start
```

**Run a node bound to a public IP for relay duty:**

```bash
coincync-node start \
  --rpc-bind 127.0.0.1:28081 \
  --p2p-bind 0.0.0.0:28080 \
  --network testnet
```

**Run a regtest node for local CI / smoke testing:**

```bash
coincync-node start \
  --network regtest \
  --no-peers \
  --data-dir /tmp/coincync-regtest
```

**Print the genesis hash (for verifying you're on the right chain):**

```bash
coincync-node print-genesis-hash --network testnet
```

**Quick status check on a running daemon:**

```bash
coincync-node status
```

---

## `coincync-wallet` — Wallet CLI

```text
Usage: coincync-wallet [OPTIONS] <COMMAND>

Commands:
  create              Create a new wallet with a fresh seed phrase
  restore             Restore a wallet from a 24-word seed phrase
  open                Open an existing wallet (checks password)
  info                Wallet status + chain info from the node
  address             Show spend + view public keys for receiving
  balance             Local-snapshot balance (no resync)
  show-seed           Print the master seed (requires password)
  scan                Scan blocks from the node for owned outputs
  privacy-stats       Shielded-pool / Spark / MW stats
  send                Build + submit a privacy transaction
  multisig-gen        Generate M-of-N FROST key shares
  multisig-info       Show multi-sig key-share info
  multisig-round1     FROST round 1: nonces + commitments
  multisig-round2     FROST round 2: signature share
  multisig-aggregate  Combine signature shares into final sig
  multisig-send       Threshold-signed privacy transaction
  set-recovery        Configure dead man's switch recovery address
  check-recovery      Check recovery status of UTXOs
  auto-churn          Random self-sends to poison the tx graph

Common options:
  --wallet <PATH>       Wallet file  [default: ~/.coincync/wallets/default.wallet]
  --network <NET>       mainnet / testnet / regtest
  --node <URL>          Node RPC URL  [default: http://127.0.0.1:28081]
  --log-level <LEVEL>   debug / info / warn  [default: warn]
```

### Recipes

**Create a fresh wallet on testnet:**

```bash
coincync-wallet --network testnet \
  --wallet ~/.coincync/wallets/me.wallet \
  create
```

**Show your address (the thing you give other people to send you CYNC):**

```bash
coincync-wallet --wallet ~/.coincync/wallets/me.wallet address
```

Outputs three values you'll see referenced elsewhere:

```text
Address:       tCYNC...   (bech32m, share this)
Spend public:  <64 hex>   (used in send --to-spend)
View public:   <64 hex>   (used in send --to-view)
```

**Sync the wallet against the chain:**

```bash
coincync-wallet --wallet ~/.coincync/wallets/me.wallet \
  --node https://api.coincync.network/rpc/testnet \
  scan
```

**Send 0.001 CYNC (1,000,000,000 atomic units) to someone:**

```bash
coincync-wallet --wallet ~/.coincync/wallets/me.wallet \
  --node https://api.coincync.network/rpc/testnet \
  send \
  --to-spend <recipient-spend-pubkey-64hex> \
  --to-view  <recipient-view-pubkey-64hex> \
  --amount 1000000000
```

> 1 CYNC = 10¹² atomic units (one trillion). 0.001 CYNC = 10⁹ atomic.

**Restore a wallet from a 24-word seed:**

```bash
coincync-wallet --network testnet \
  --wallet ~/.coincync/wallets/restored.wallet \
  restore
```

(You'll be prompted for the seed phrase + a new password.)

**Set up a dead man's switch (auto-recovery if wallet goes silent):**

```bash
coincync-wallet --wallet ~/.coincync/wallets/me.wallet \
  set-recovery \
  --address <backup-spend-pubkey-64hex> \
  --timeout 50000
```

**Multi-sig (M-of-N FROST) flow — three signers, threshold 2:**

```bash
# Round 0: each signer generates their share
coincync-wallet multisig-gen --threshold 2 --total 3 --output-dir ./shares/

# Round 1: each signer produces nonces + commitment
coincync-wallet multisig-round1 \
  --share-file ./shares/share-0.json \
  --output ./round1-0.json

# Round 2: each signer produces a signature share, given everyone's commitments
coincync-wallet multisig-round2 \
  --share-file ./shares/share-0.json \
  --nonce-file ./round1-0-secret.json \
  --commitments ./round1-0.json ./round1-1.json ./round1-2.json \
  --message <tx-hash-hex> \
  --output ./sig-share-0.json

# Aggregate + submit
coincync-wallet multisig-aggregate \
  --shares ./sig-share-0.json ./sig-share-1.json \
  --output ./final-sig.json

coincync-wallet --node <RPC> multisig-send ...
```

---

## `coincync-rig` — CPU Miner

```text
Usage: coincync-rig [COMMAND]

Commands:
  selftest    One-shot hash check — smallest end-to-end test
  verify      Hash a specific (anchor, tx_root, height, nonce) tuple
              and check against a target. Best debugging tool when
              a share is rejected.
  bench       Benchmark mode — hash as fast as possible for N seconds
              and print H/s. Use this to compare against xmrig.
  info        Connect to a daemon and print height/tip/peers.
              Reachability check, does NOT mine.
  run-solo    Solo mining loop. Multi-thread, auto-reconnect, optional
              Prometheus /metrics, optional ratatui --tui dashboard.
  run-config  Same as run-solo but reads from a TOML config file.
```

### Recipes

**Verify your CPU + RandomX wiring works (10 seconds, no mining):**

```bash
coincync-rig selftest
```

**Benchmark your hashrate — gives you the H/s number for capacity planning:**

```bash
coincync-rig bench --threads 4 --duration 30
```

Typical output (consumer laptop):

```text
4 threads, 30 seconds:
  hashes:     1,832,400
  hashrate:   61,080 H/s
```

**Check connectivity to a node, no mining:**

```bash
coincync-rig info --node https://api.coincync.network/rpc/testnet
```

**Solo mine against the public testnet, 4 threads, with the premium TUI dashboard:**

```bash
coincync-rig run-solo \
  --node https://api.coincync.network/rpc/testnet \
  --address tCYNC... \
  --threads 4 \
  --network testnet \
  --tui
```

**Same, but headless with Prometheus metrics on port 9100:**

```bash
coincync-rig run-solo \
  --node https://api.coincync.network/rpc/testnet \
  --address tCYNC... \
  --threads 4 \
  --network testnet \
  --metrics-port 9100
```

**Verify a specific hash (debugging a rejected share):**

```bash
coincync-rig verify \
  --anchor <32-byte-hex> \
  --tx-root <32-byte-hex> \
  --height 2700 \
  --nonce 0x12345678 \
  --target <target-hex>
```

### TUI keyboard shortcuts (during `--tui`)

| Key | Action |
| --- | --- |
| `q` / `Esc` | Quit (prints session summary first) |
| `t` | Cycle theme (Brass / Dark / Midnight / Forge / Vault / Mono / Paper / Cream / Contrast) |
| `p` | Pause / resume mining |
| `l` | Toggle log pane |
| `?` / `h` | Help modal |
| `c` | Snapshot dashboard to `%TEMP%\coincync-rig-<unix>.txt` |

---

## `cyncswap` — Atomic Swap (Skeleton, Not Functional Yet)

This binary is the skeleton CLI for the eventual CYNC↔BTC atomic swap. **Every subcommand currently prints a "skeleton mode, not yet implemented" notice and exits 2.** The protocol design is in [`docs/cip/CIP-001-atomic-swap.md`](cip/CIP-001-atomic-swap.md); this section documents the surface that the eventual implementation will fill in.

```text
Usage: cyncswap <COMMAND>

Commands:
  alice           Initialize a swap as Alice (sells CYNC, buys BTC)
  bob             Initialize a swap as Bob (sells BTC, buys CYNC)
  status          Show status of an active swap
  cancel          Cancel + walk through the refund path
  design-version  Print the CIP-001 revision this skeleton tracks
```

### Verifying the skeleton is wired correctly

```bash
cyncswap design-version
```

Expected output:

```text
CIP-001 (atomic-swap) — skeleton revision
Implementation status: NONE. See docs/cip/CIP-001-atomic-swap.md for the design spec.
```

When working swaps ship (mainnet launch blocker), this section will replace the "skeleton" notice with real recipes.

---

## Internal Tools

These ship in the repo but most users will never need them.

### `update-critical-hashes` — Refresh the Lockfile

After an *intentional* change to a consensus-critical file (`CONSTITUTION.md`, `BILL_OF_RIGHTS.md`, `src/constants.rs`, `src/consensus/*`, `src/emission/curve.rs`, `src/testnet.rs`), the build will fail with `UNCONSTITUTIONAL: Article X` errors until the lockfile is refreshed. Run:

```bash
COINCYNC_REGEN_LOCK=1 cargo run --locked --release --bin update-critical-hashes
```

Commit the updated `critical_files.lock` alongside your code change. **Never refresh without reviewing the file change.**

### `bootstrap_manifest_tool`

Generates the bootstrap manifest used by new nodes during fast-IBD. Internal tool for the operator who is rolling up a new mainnet bootstrap snapshot.

### `stratum_ban_tool`

Inspects + manages the Stratum-side ban list. Only relevant once a CoinCync mining pool exists; not load-bearing for solo mining.

---

## Quick Cross-Reference: "How do I…?"

| Goal | Command |
| --- | --- |
| Send 1 CYNC to someone | `coincync-wallet ... send --amount 1000000000000 --to-spend ... --to-view ...` |
| Mine to my own wallet | `coincync-wallet ... address` then `coincync-rig run-solo --address tCYNC... --tui` |
| Check chain tip | `coincync-rig info --node <URL>` (fastest); or `coincync-wallet info` |
| Run a node + explorer locally | `coincync-node start --explorer` |
| Verify a specific share | `coincync-rig verify --anchor ... --tx-root ... --height ... --nonce ...` |
| Set up multi-sig spending | `coincync-wallet multisig-gen --threshold 2 --total 3 --output-dir ./shares/` |
| Restore wallet from seed | `coincync-wallet --network testnet ... restore` (interactive) |
| Test full send-receive path | `pwsh scripts/smoke-test-tx.ps1` |
| Refresh constitutional hashes | `COINCYNC_REGEN_LOCK=1 cargo run --locked --release --bin update-critical-hashes` |

---

## Network Defaults

| Setting | Mainnet | Testnet | Regtest |
| --- | ---: | ---: | ---: |
| P2P port | 19080 | 28080 | 18080 |
| RPC port | 19081 | 28081 | 18081 |
| Address HRP | `cync` | `tcync` | `rcync` |
| Block target | 120 s | 120 s | (no target) |
| Atomic units / CYNC | 10¹² | 10¹² | 10¹² |

The atomic-units constant matters every time you specify `--amount`. **0.001 CYNC = 1_000_000_000 atomic units.** Off-by-thousand errors are the most common send-amount mistake.
