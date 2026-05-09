# Troubleshooting

A reference for the errors a new CoinCync user is most likely to hit.
Organized by where the error shows up — wallet, node, miner, faucet,
build, network. Each entry: what the error looks like, what it means,
and the smallest action that fixes it.

If your problem isn't here, check `#wallet-help` / `#bug-reports` /
`#node-setup` on Discord (<https://discord.gg/5tYNSCsqzy>) before
opening a GitHub issue.

---

## Wallet

### "Invalid secret key: decryption failed - wrong password or corrupted data"

You typed the wrong password. The wallet file at
`~/.coincync/wallets/default.wallet` (or wherever) IS readable, the
file format is intact — only the password unwrap failed.

**Fix options:**

1. Try other passwords you might have used.
2. Restore from your 25-word seed phrase to a new wallet file with a
   new password:

   ```bash
   coincync-wallet --wallet ~/.coincync/wallets/restored.wallet restore
   ```

3. If you've lost both seed and password — funds in that wallet are
   inaccessible. That's the privacy guarantee. There is no recovery.

### "insufficient funds" but my balance shows positive

Outputs need **10 confirmations** (~20 minutes at 120 s blocks) before
they're spendable. Confirmed-balance and spendable-balance are
different. Wait one block-time and retry.

### Balance is 0 after restore from seed

Your scan window may be too small. The wallet's `scan` defaults to
1000 blocks per call, starting from the wallet's last-scanned-height.
If you have any history, run with `--max-blocks 50000` (or higher)
to walk to the chain tip in one go:

```bash
coincync-wallet --wallet path/to.wallet --node https://api.coincync.network/rpc/testnet \
  scan --password '...' --max-blocks 50000
```

If the balance is still 0 after a full-tip scan, the seed you
restored from never had any CYNC. Check whether you mixed up seed
phrases.

### "Cannot find 2 UTXOs whose sum covers N atomic"

CoinCync transactions use a uniform 2-input / 2-output shape so all
on-chain transactions look the same. To send `N`, the wallet has to
find **two** inputs whose total ≥ `N + fee`. If your largest pair
sums to less than that, you can't send `N` in a single tx.

The error reports the actual maximum-per-tx for your wallet:

```
... largest pair sums to 139514723508750 atomic. Either send no more
than 139514673508750 atomic per tx, or run `auto-churn` to redistribute
UTXO sizes into a larger one.
```

**Fix:** either send a smaller amount, or run
`coincync-wallet auto-churn` overnight to consolidate small UTXOs
into larger ones.

### "no view key" while restoring

The wallet hasn't finished scanning yet. Let it run; the view key
populates as scan progresses. Don't close the window during scan.

### Wallet says "scanning..." for hours

First-time scan over a long history can take 10–30 min legitimately.
If it's been >1 hour with no progress:

1. Check the node you're scanning against is synced:
   `curl ... | grep is_synced`
2. Restart the wallet — it picks up from the last-scanned-height.
3. If still stuck, post the wallet log file (NOT your seed) in
   `#wallet-help`.

---

## Node

### "Connection refused" on RPC port 28081

The node binds RPC to `127.0.0.1:28081` by default — only loopback
clients can reach it. If you're calling from another machine, you
need to either:

1. SSH-tunnel to the node:
   `ssh -L 28081:localhost:28081 user@nodebox`
2. Bind RPC to the public interface (with auth!) — see
   `docs/operations/...` for the security posture.

### Node stuck at height 0 / not syncing

Three things to check, in order:

1. **Outbound port 28080**:
   `nc -zv 66.135.23.193 28080` should connect.
2. **DNS seed resolution**:
   `dig seed1.coincync.network` returns a valid A record.
3. **Peer count**: in the node's `get_info`, `peer_count` should be
   ≥ 1 within a minute of startup. Zero peers means firewalls or
   seed-discovery problems.

### Node logs show "rpc error: 401 Unauthorized"

The node's RPC requires Bearer auth (defense in depth). Pass the
key in the `Authorization` header, OR call the node through the
nginx route on the api box (which adds the header server-side):
`https://api.coincync.network/rpc/testnet`.

Wallet/miner CLIs don't yet support `--rpc-key`; route through
the public nginx endpoint until that lands.

### "tip_age_secs" is climbing — chain stalled?

At low testnet hashrate (~250 H/s), block time variance is high.
Stalls of 20–30 minutes are within normal range. If `tip_age` exceeds
60 minutes, the chain is genuinely under-mined — fire up your CPU
miner to contribute hashrate.

---

## Miner

### "RandomX VM creation failed"

Your CPU is missing one of the RandomX-required instruction set
extensions. RandomX runs fastest on x86-64-v3 (AVX2, FMA, BMI2). On
older / virtualized CPUs, the JIT or AES path may not be available.

The miner falls back to portable code automatically, but throughput
drops 5–10×. Check with:

```bash
coincync-rig selftest
```

If that fails, run with `--threads 1` first to isolate which thread
is dying.

### "huge pages not enabled"

Optional 5–15 % speedup. Linux:

```bash
echo 1280 | sudo tee /proc/sys/vm/nr_hugepages
```

Windows: not exposed at OS level — ignore the warning. The miner
works without huge pages.

### Hashrate is 50 % of expected

Common causes:

- Another process pegging the CPU (check `htop` / Task Manager).
- Mining on more threads than physical cores (don't count
  hyper-threads — RandomX is L3-bound and physical cores compete
  for cache).
- Power-saving mode capping CPU frequency (set the OS to
  Performance / Maximum).
- DDR4-2400 vs DDR4-3200 RAM is a real ~10 % gap.

### "rpc error: ... in block submission" after solving a block

Several possible causes:

1. The chain advanced under you while you were searching the
   nonce. Rare; the miner refreshes templates every 60 s.
2. Wrong network — make sure both miner and node are on
   `--network testnet` (or both on mainnet).
3. Node is syncing, not at tip. Check `is_synced=true` first.

---

## Faucet

### Faucet returns 503 Service Unavailable

The faucet's hot wallet is dry (or its UTXOs are locked behind
confirmation thresholds). Operator action — top up via
`scripts/fund-faucet.ps1`. If you're a user, just retry in 20 min
and post in `#faucet-help` if it persists.

### "address rate-limited; try again in Xs"

Rate-limit working as designed: 1 drip per address per hour. Use
a different address, or wait the printed `retry_after_secs`.

### "ip rate-limited; try again in Xs"

Same per-IP limit. Stricter than per-address. Common cause: NAT'd
office network where multiple users share an outbound IP. Switch
network or wait.

### Faucet sends 10 CYNC but the explorer shows 0

The drip tx is in mempool but hasn't landed in a block yet. Wait
1–2 minutes (one block-time at 120 s target), then refresh.

---

## Build / install

### "INTEGRITY CHECK FAILED — UNCONSTITUTIONAL: Article X"

The build-time integrity check fired. A consensus-critical file's
SHA-256 doesn't match `critical_files.lock`. This guard is
intentional — it prevents silent edits to consensus / Constitution /
key crypto code without an attributable commit.

If you intentionally changed the file:

```bash
cargo run --bin update-critical-hashes
```

Then commit `critical_files.lock` alongside the change. Reviewers
see the lockfile diff and ask "why".

If you didn't intend to change anything: `git diff <file>` and
revert. Possibly a CRLF-vs-LF line-ending corruption — see
[gitattributes](#crlf-vs-lf-line-endings) below.

### "the term '.\scripts\fund-faucet.ps1' is not recognized"

You're not in the project root. `cd` to where the project lives:

```powershell
cd "C:\Users\unkno\OneDrive\coincync 1.0"
```

### CRLF vs LF line endings

The repo uses LF endings. Git on Windows may convert to CRLF on
checkout, which can break:

- `critical_files.lock` hash matching (recompute uses LF-normalized
  bytes).
- shell scripts (CRLF-tainted scripts fail to execute on Linux
  fleet boxes).

If commits show whole files re-indented for no reason, your
`core.autocrlf` is converting. Fix:

```powershell
git config --global core.autocrlf false
git config --global core.eol lf
```

### Cargo build fails on RocksDB

Likely missing `clang` or `libclang`. Linux: `apt-get install
clang libclang-dev cmake`. macOS: `brew install llvm cmake`.
Windows: install Visual Studio 2022 with C++ Desktop workload, or
use the reproducible Docker build:
`./scripts/build-in-docker.sh`.

---

## Network

### Wallet auto-update never triggers

The wallet polls `https://releases.coincync.network/wallet/latest.json`.
Verify the URL resolves and returns valid JSON:

```bash
curl -I https://releases.coincync.network/wallet/latest.json
```

Should return `200 OK content-type: application/json`. If it 404s
or returns HTML, the auto-update endpoint is misconfigured — file
in `#bug-reports`.

### "connection reset" hitting an endpoint

Most often a Cloudflare-level block. Try the same URL with a
different IP (mobile hotspot, VPN). If only your IP is blocked,
contact `security@coincync.network` — we'll add an exception.

### `git.coincync.network` redirects to GitHub

That's expected, pre-launch. The Forgejo instance isn't deployed
yet; redirects keep all the existing references in the announcement
working. Post-launch, the redirect will be replaced with the real
Forgejo (and `git.coincync.network` will be the canonical source).

---

## Where to file what

| What | Where |
|---|---|
| Bug in the protocol / wallet / node | <https://github.com/ghostrider1092/Coincync-Testnet-/issues> with the bug-report template |
| Security vulnerability (consensus, privacy, key handling) | `security@coincync.network` (PGP `2CAA 920F 8B96 1772`) — DO NOT file publicly |
| "Just a question" | Discord `#faq` (read pins first) |
| Reproducibility check failure | Open an issue with both your `sha256sum` and the published hash |
| Operational problem (network down, faucet broken) | Discord `#network-health` channel |
