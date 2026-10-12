<!-- markdownlint-disable MD013 -->
# CoinCync — Miner Quickstart

Copy-paste commands to build the miner, make a wallet, and start solo-mining the
**testnet**. For the full CLI reference (every binary + subcommand) see
[`docs/COMMANDS.md`](docs/COMMANDS.md).

> **Running from Windows?** The binaries build and run under WSL. If your prompt
> is `PS C:\...>` (PowerShell), prefix each command with `wsl -e bash -lc '…'`.
> If your prompt is already a Linux shell (e.g. `you@host:~$`), run the commands
> **as-is** — do *not* add the `wsl -e bash -lc` wrapper (inside WSL that hits a
> different `wsl` binary and fails with "Unknown command: -e").

---

## 1. Build the tools (one time)

From the repo root:

```bash
# The miner. RandomX is baked in; the only feature to pass is `testnet`.
cargo build --release -p coincync-rig --features testnet

# The wallet (keys/addresses/balance). This one DOES take the randomx feature.
cargo build --release --bin coincync-wallet --features "randomx testnet"
```

Binaries land in `target/release/coincync-rig` and `target/release/coincync-wallet`.

---

## 2. Make a wallet + get your address

**Run this yourself** — it generates a secret 24-word seed and sets a password.
Never let anyone (or any tool/log) capture the seed; write it down offline.

```bash
./target/release/coincync-wallet --network testnet create
```

It prints your `tCYNC…` payout address. Re-show it anytime:

```bash
./target/release/coincync-wallet --network testnet address
```

**Validate an address before you mine to it** (a truncated/typo'd address means
every block reward is lost — the decoder catches it):

```bash
./target/release/coincync-wallet --network testnet address-info <tCYNC-address>
```

A good address prints `Type: Standard` + spend/view pubkeys. A bad one errors
(e.g. `invalid address: too short`).

---

## 3. Start mining

Point `--node` at a daemon's JSON-RPC. Options, fastest first:

- Your own local node: `http://127.0.0.1:28081`
- An SSH tunnel to a fleet node: `ssh -N -L 28081:127.0.0.1:28081 root@<seed-ip>`, then use `http://127.0.0.1:28081`
- Public endpoint: `https://api.coincync.network/rpc/testnet`

**Full-speed solo mining (recommended):**

```bash
./target/release/coincync-rig run-solo \
  --node http://127.0.0.1:28081 \
  --address <YOUR_tCYNC_ADDRESS> \
  --network testnet \
  --threads 8
```

At startup it builds the ~2 GB RandomX **full dataset** (~1–2 min, needs ~2.5 GB
free RAM), then hashes at full rate. Add `--tui` for the live dashboard, or leave
it off for plain scrolling heartbeat/hashrate log lines.

> ### ⚠️ Do NOT set `COINCYNC_RANDOMX_LIGHT_MODE=1` for mining
> Light mode (256 MB cache) is the **validating-node** mode — it's ~10× slower to
> hash. It only makes sense if you're RAM-constrained. For mining, leave it unset
> so the rig uses the full 2 GB dataset. (If you ever see the rig refuse to start
> because the var is set, unset it and ensure ~2.5 GB free RAM.)

---

## 4. Check your mined balance

Once blocks land to your address, scan + check the wallet against the node:

```bash
./target/release/coincync-wallet --network testnet --node http://127.0.0.1:28081 scan
./target/release/coincync-wallet --network testnet info
```

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Unknown command: -e` / "Wsman Shell" help text | You're already inside WSL — drop the `wsl -e bash -lc '…'` wrapper. |
| `invalid address: too short` | Address is truncated/mistyped — re-copy the full `tCYNC…` string; validate with `address-info`. |
| Hashrate far lower than `bench` | `COINCYNC_RANDOMX_LIGHT_MODE` is set — unset it to get full-dataset speed. |
| Rig can't reach the node | The RPC/tunnel isn't up. Test with `coincync-rig info --node <URL>`. |
| Rig dies mid-run (native JIT crash) | Known sporadic RandomX crash — run under a supervisor that relaunches (`scripts/mine-supervised.ps1` on Windows; `Restart=always` systemd unit on Linux). |

**Benchmark your box first** (no mining, just raw H/s):

```bash
./target/release/coincync-rig bench --threads 8 --duration 30
```

---

## Network defaults (testnet)

| Setting | Value |
| --- | --- |
| P2P port | 28080 |
| RPC port | 28081 |
| Address prefix | `tcync` |
| Atomic units / CYNC | 10¹² (0.001 CYNC = 1_000_000_000) |
