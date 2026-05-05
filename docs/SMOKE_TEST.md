<!-- markdownlint-disable MD036 -->
# Smoke Test — End-to-End Transaction Flow

**What it proves:** the user-facing transaction path actually works on the public testnet — wallet creation, mining to your own address, scanning for owned outputs, building a privacy transaction, broadcasting it, and verifying receipt on the recipient side.

**What it doesn't prove:** load-handling, adversarial cases, edge cases on extreme amounts, multi-sig flows. Those are separate test suites.

---

## Why this exists

The 72-hour pre-launch soak only samples RPC health: tip age, peer count, error rate. It tells us nothing about whether a *user* can actually send and receive coins. If something is broken between the wallet's transaction builder and the daemon's mempool, the soak runs clean while users hit a wall.

The smoke test closes that gap. One automated run produces a clear PASS / FAIL on the user-facing path that matters most.

---

## What the test does

```text
[1/7] create wallet A (sender) and wallet B (recipient)
[2/7] read addresses + (spend, view) public keys for each
[3/7] spawn coincync-rig pointed at wallet A's address
       wait until A receives a confirmed block reward
[4/7] stop the rig
[5/7] build + broadcast a small privacy transaction A → B
[6/7] scan wallet B until it sees the received amount
[7/7] report PASS or FAIL with diagnostic info
```

Default amount sent: 100,000,000 atomic units (0.0001 CYNC). Tiny on purpose — the test only proves the path works, not that we can move large amounts.

---

## How to run

### Windows (PowerShell)

```powershell
pwsh scripts\smoke-test-tx.ps1
```

Defaults to the public testnet API at `https://api.coincync.network/rpc/testnet`. Takes 3–10 minutes depending on how quickly your rig finds a block.

### Custom node

```powershell
pwsh scripts\smoke-test-tx.ps1 -Node http://127.0.0.1:28081
```

### Slower hardware (longer wait)

```powershell
pwsh scripts\smoke-test-tx.ps1 -FundTimeoutMinutes 20 -ConfirmTimeoutMinutes 10
```

### Keep wallet artifacts for debugging

```powershell
pwsh scripts\smoke-test-tx.ps1 -KeepArtifacts
```

---

## When to run

**Pre-launch hard requirement:** at least one PASS within 24 hours of the public testnet announcement going live.

**Recommended cadence post-launch:**

- Before each binary release (Windows + macOS bundles)
- After any change to `coincync-wallet`, `coincync-node` RPC, or transaction builder code
- Once per week as a steady-state check

The script is idempotent — it creates fresh wallets each run and cleans them up on success. Failed runs leave the wallets in `%TEMP%\coincync-smoketest-<timestamp>\` so you can post-mortem.

---

## Interpreting failures

| Stage | What it means | First place to look |
|-------|---------------|---------------------|
| **wallet create failed** | Binary not built or password handling regressed | `cargo build --release` first; check wallet.rs `cmd_create` |
| **address read failed** | Wallet binary's `address` output format changed | Check the regex against current wallet output |
| **funding timeout** | Mining isn't reaching A's address, OR network too slow | Check rig log in temp dir; verify A's address renders on explorer |
| **send failed** | Transaction build / broadcast broke | Run wallet `send` manually with same args; capture full error |
| **receive timeout** | Tx didn't propagate, OR scan path broken | Check the explorer for the txid; if visible there but not in B's scan, the issue is wallet-side |

A FAIL at stage 5 (send) is the highest-priority signal — it means the user-facing send path is broken, which is a launch-blocker. A FAIL at stage 6 (receive verify) with the tx visible on the explorer means the *recipient scan path* is broken, also a launch-blocker.

---

## What's deliberately not tested

- **Multi-sig (FROST) flows.** Tested separately; the wallet ships `multisig-gen` / `multisig-round1` / `multisig-round2` subcommands.
- **Restoration from seed phrase.** Tested separately via `wallet restore` integration tests.
- **Encrypted memos, scoped view keys, dead-man's switch.** Each has its own test surface.
- **Mempool stress.** Single-tx test, not load-handling.
- **Network partition recovery.** Soak's job, not the smoke test's.

This script is the user-path smoke test. Other test suites cover other surfaces.

---

## Provenance

- Script: [`scripts/smoke-test-tx.ps1`](../scripts/smoke-test-tx.ps1)
- Wallet binary: [`src/bin/wallet.rs`](../src/bin/wallet.rs)
- Rig binary: [`crates/coincync-rig/`](../crates/coincync-rig/)
- Public testnet API: [`api.coincync.network/rpc/testnet`](https://api.coincync.network/rpc/testnet)
