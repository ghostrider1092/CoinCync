# Mine CYNC in 5 minutes (no GPU, no rig, no farm)

CoinCync uses **RandomX** — the same CPU-only proof-of-work Monero
uses. Any modern laptop can mine it. No GPU, no rig, no warehouse.

This guide gets you from zero to mining testnet CYNC on your own
laptop in five minutes flat. For the full version with options,
solo-node setup, performance tuning, etc., see
[mining-on-your-pc.md](./mining-on-your-pc.md).

---

## Windows — paste these three commands

Open PowerShell (Start menu → type `powershell` → Enter), then:

```powershell
# 1. Download the miner + wallet (~30 sec)
$base = 'https://github.com/Coincync/Coincync-Testnet-/releases/latest/download'
Invoke-WebRequest -Uri "$base/coincync-rig.exe"    -OutFile coincync-rig.exe
Invoke-WebRequest -Uri "$base/coincync-wallet.exe" -OutFile coincync-wallet.exe

# 2. Create a wallet (you'll set a password; remember it)
.\coincync-wallet.exe --network testnet --wallet testnet.bin create

# 3. Start mining (point at the public testnet RPC; no API key needed)
$addr = (.\coincync-wallet.exe --network testnet --wallet testnet.bin address | Select-String '^Address:').ToString().Split()[-1]
.\coincync-rig.exe run-solo --node https://api.coincync.network/rpc/testnet --address $addr --network testnet --tui
```

The `--tui` flag opens a live dashboard. Press `q` to quit.

> Verified against `v1.0.9-testnet-pre-audit` (the current `latest`
> release). The `/releases/latest/download/...` URLs are GitHub's
> tag-redirect — they automatically resolve to the most recent
> release without doc updates per tag.

---

## Linux / macOS — build from source (10-15 min)

Native Linux / macOS binaries aren't currently shipped on the GitHub
release page (Windows `.exe` + installer only as of `v1.0.9-testnet-pre-audit`).
For now, build locally — you only need this once.

```bash
# Prereqs: rustup (rustc 1.88+) and a C toolchain
# Ubuntu / Debian:  sudo apt-get install build-essential pkg-config libssl-dev
# macOS:            xcode-select --install

git clone https://github.com/Coincync/Coincync-Testnet- coincync
cd coincync
cargo build --release --bin coincync-rig --bin coincync-wallet

# 1. Create a wallet
./target/release/coincync-wallet --network testnet --wallet testnet.bin create

# 2. Get your address
ADDR=$(./target/release/coincync-wallet --network testnet --wallet testnet.bin address | awk '/^Address:/{print $2}')

# 3. Mine
./target/release/coincync-rig run-solo --node https://api.coincync.network/rpc/testnet --address "$ADDR" --network testnet --tui
```

---

## WSL Ubuntu — use the Windows binaries

WSL users can run the `.exe` files directly from `/mnt/c/Users/...`
without building from source. Open WSL, navigate to the folder where
you saved the Windows downloads, and run them via `./coincync-rig.exe`
exactly as in the Windows section. No extra setup.

---

## What you should see within 60 seconds

```text
H/s: 2,847    Threads: 8    Tip: 11500 / 11500 ✓
Best share: 0x000007ab...    Templates polled: 3
```

If the H/s number is non-zero and "Tip" advances every ~2 minutes,
**you are mining**. Block rewards arrive to your wallet automatically
when you find one. On a typical laptop expect one testnet block reward
every few hours to days depending on testnet difficulty and how many
other miners are active.

Check your balance any time:

```powershell
.\coincync-wallet.exe --network testnet --wallet testnet.bin info
```

---

## Troubleshooting in 3 lines

|If you see|Do this|
|---|---|
|`H/s: 0`|Your CPU doesn't support AES-NI (very old box). Try `coincync-rig.exe selftest` to confirm.|
|`could not reach daemon`|Public RPC is up — check your firewall isn't blocking outbound 443.|
|`RandomX initialization failed`|Add the rig binary to Windows Defender exclusions (RandomX uses JIT, which AV scanners panic about).|

---

## What this is NOT

- **Not real money** — this is testnet CYNC. Has no value. Mainnet launches 2026-10-01.
- **Not pool mining** — this is solo mining against the public testnet RPC. A real pool ships with v1.1.
- **Not a get-rich quick** — testnet mining proves the chain works and earns you a place in the genesis announcement, nothing more.

What it IS: a 5-minute way to confirm CoinCync's privacy POW actually
runs on your hardware, plus a way to support the network before
mainnet. Solo mining also means any block you find is yours alone —
no pool fee, no proportional split.

---

## What's next

- Pre-mainnet miners get an early-supporter shoutout in the launch announcement. Join the Discord and post your H/s — that's the only signup.
- For long-running setups (systemd, Prometheus, dashboard), see [mining-on-your-pc.md](./mining-on-your-pc.md).
- For running a full node (helps the network even more than just mining), see [run-a-node.md](./run-a-node.md).
