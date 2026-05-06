<!-- markdownlint-disable MD036 MD013 -->
# CoinCync Developer Guide

Build, test, lint, deploy, troubleshoot. Every command someone working on the codebase will reach for, in one place. For end-user CLI commands (`coincync-wallet send …`, `coincync-rig run-solo …`), see [`COMMANDS.md`](COMMANDS.md).

---

## Setup (first time)

### Prerequisites

- **Rust toolchain** — stable channel, edition 2021. `rustup default stable`.
- **C compiler** — for the RandomX FFI. Linux: `gcc`. Windows: MSVC build tools (comes with VS Build Tools or Rust's `x86_64-pc-windows-msvc` target). macOS: Xcode CLT.
- **Git** + a working SSH or HTTPS clone path.
- **Optional but useful:**
  - WSL Ubuntu (for cross-compiling Linux binaries from Windows — see [`Cross-compile to Linux`](#cross-compile-to-linux-via-wsl))
  - `jq` (used by some scripts)
  - PowerShell 7 (`pwsh`) for the Windows-side scripts

### First clone

```bash
git clone <repo-url>
cd coincync
cargo build --release
```

The first release build pulls every dep, compiles RandomX C code, and runs the constitutional integrity check on `critical_files.lock`. Expect 5-15 minutes on first build, depending on hardware. Subsequent rebuilds are seconds.

If the build fails with `UNCONSTITUTIONAL: Article X`, see [`Critical-files lockfile`](#critical-files-lockfile).

---

## Build

### Default — release everything in the workspace

```bash
cargo build --release --workspace
```

### Just the daemon

```bash
cargo build --release --bin coincync-node
```

### Just the rig (CPU miner)

```bash
cargo build --release -p coincync-rig
```

### Just the wallet CLI

```bash
cargo build --release --bin coincync-wallet
```

### With consensus features enabled

The `randomx` feature is on by default. If you ever explicitly disable it, the rig and node return runtime errors when asked to compute a PoW hash — never silently mine garbage.

```bash
cargo build --release --features "randomx testnet"
```

### Debug build (slower runtime, faster compile, includes assertions)

```bash
cargo build
```

Use debug builds for iterating on logic. Use release for anything you'll actually run against the network.

### Pre-launch / release mode (LTO + symbols stripped)

The default `--release` profile already enables LTO and strips. The CI release pipeline runs:

```bash
cargo build --release --workspace --locked
```

`--locked` ensures the exact `Cargo.lock` versions ship — no surprise dep upgrades between developer machines.

---

## Test

### Whole workspace

```bash
cargo test --release --workspace
```

The release flag is important — many tests exercise RandomX, and debug-mode RandomX is unusably slow. Expect the full suite to take 5-15 minutes.

### Specific crate

```bash
cargo test --release -p coincync-rig
cargo test --release -p coincync-swap
cargo test --release -p bridge
```

### Library tests only (skip integration / binary tests)

```bash
cargo test --release --lib
```

### Specific test by name

```bash
cargo test --release nonce_range_split   # matches any test containing the substring
```

### Smoke test — end-to-end transaction path

This is the user-facing test. Creates two wallets, mines to A, sends to B, verifies receipt.

```pwsh
pwsh scripts\smoke-test-tx.ps1
```

Takes 3-10 minutes. See [`SMOKE_TEST.md`](SMOKE_TEST.md) for the full description and configuration options.

### With test output streaming (for debugging hangs)

```bash
cargo test --release -- --nocapture --test-threads=1
```

---

## Lint + Format

### Format (always run before commit)

```bash
cargo fmt --all
```

### Lint with clippy (all targets, all warnings as errors)

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

We treat clippy warnings as errors in CI. If a warning is genuinely wrong for your case, suppress it locally with `#[allow(clippy::lint_name)]` and a comment explaining why — never blanket `--allow`.

### Cargo check (faster than build, type-checks only)

```bash
cargo check --workspace --all-targets
```

Useful when iterating on signatures.

---

## Critical-files lockfile

`critical_files.lock` SHA-256-locks the Constitution, Bill of Rights, consensus modules, and `src/constants.rs`. Any unintentional edit fails the build with a clear error. Any *intentional* edit requires a refresh.

### Build fails with `UNCONSTITUTIONAL: Article X`

You touched a locked file. Check what changed:

```bash
git diff CONSTITUTION.md docs/BILL_OF_RIGHTS.md src/constants.rs src/consensus/ src/emission/curve.rs src/testnet.rs
```

If the change is intentional and reviewed, refresh the lockfile:

```bash
cargo run --bin update-critical-hashes --release
```

Commit the updated `critical_files.lock` alongside your code change. **Never refresh without reading the diff first.** A bad refresh launders an accidental consensus rule change into the chain.

### Adding a new file to the lockfile

Update both lock-step lists:

- `build.rs::CRITICAL_FILES`
- `src/bin/update_critical_hashes.rs::CRITICAL_FILES`

Then re-run `cargo run --bin update-critical-hashes --release` to compute the initial hash.

---

## Cross-compile to Linux (via WSL)

Fleet boxes are Linux x86_64. To produce a Linux binary from a Windows dev machine without leaving Windows:

```pwsh
wsl -d Ubuntu -e bash -lc 'cd "/mnt/c/Users/<you>/<repo>" && cargo build --release --bin coincync-node --features "randomx testnet"'
```

Output binary: `target/release/coincync-node` (no `.exe` extension). Confirm it's an ELF:

```bash
file target/release/coincync-node
# expected: ELF 64-bit LSB pie executable, x86-64, …
```

The first WSL build is slow (8 minutes); subsequent rebuilds use the same target dir and are fast.

---

## Deploy to fleet

### Roll a new node binary across all 5 boxes

The intentional way (no chain DB wipe):

```pwsh
$key  = "$env:USERPROFILE\.ssh\coincync_fleet"
$bin  = "C:\Users\unkno\OneDrive\coincync 1.0\target\release\coincync-node"
$hosts = @(
  @{ n='seed1';    ip='66.135.23.193'  },
  @{ n='seed2';    ip='140.82.57.168'  },
  @{ n='seed3';    ip='207.148.111.76' },
  @{ n='explorer'; ip='207.148.6.50'   },
  @{ n='api';      ip='95.179.165.225' }
)

foreach ($h in $hosts) {
  Write-Output "── $($h.n) ──"
  scp -q -i $key -o StrictHostKeyChecking=no $bin "root@$($h.ip):/tmp/coincync-node-new"
  scp -q -i $key -o StrictHostKeyChecking=no "$env:TEMP\rollout-node.sh" "root@$($h.ip):/tmp/rollout-node.sh"
  ssh -i $key -o StrictHostKeyChecking=no root@$($h.ip) `
    "chmod 0755 /tmp/coincync-node-new /tmp/rollout-node.sh && bash /tmp/rollout-node.sh"
  Start-Sleep -Seconds 5
}
```

The `rollout-node.sh` script does: stop service → swap binary (keeping `.bak`) → start → poll RPC.

### **Do NOT use** `deploy/ops/redeploy-fleet.sh` for non-consensus changes

That script wipes the chain DB and rebuilds. It's only correct for hard-fork rollouts. For binary-only updates, use the rollout pattern above.

### Verify post-rollout

```pwsh
ssh -i $key -o StrictHostKeyChecking=no root@207.148.6.50 'bash /tmp/fleet-check.sh'
```

Expected: all 5 boxes at the same height, fresh tip age, peer count > 8.

### Restart api-box's miner if a daemon rollout knocked it offline

The `coincync-rig.service` on the api box has `Requires=coincync-node.service` but no `Restart=`. So when the daemon restarts, the rig stops and *does not* auto-restart. Manually:

```pwsh
ssh -i $key -o StrictHostKeyChecking=no root@95.179.165.225 'systemctl start coincync-rig.service'
```

---

## Inspect the soak

Real-time fleet health:

```pwsh
ssh -i "$env:USERPROFILE\.ssh\coincync_fleet" -o StrictHostKeyChecking=no root@207.148.6.50 'bash /tmp/fleet-check.sh'
```

Soak progress on a specific box:

```pwsh
ssh -i "$env:USERPROFILE\.ssh\coincync_fleet" -o StrictHostKeyChecking=no root@<ip> 'bash /tmp/sk1.sh'
```

Watch the latest soak log live:

```pwsh
ssh -i "$env:USERPROFILE\.ssh\coincync_fleet" -o StrictHostKeyChecking=no root@<ip> 'tail -f /var/lib/coincync/soak/*.jsonl'
```

---

## Local node setup (for iterating on protocol code)

```bash
# 1. Clean data dir for a fresh chain
rm -rf /tmp/coincync-local

# 2. Run a regtest node, no peer discovery
target/release/coincync-node start \
  --network regtest \
  --no-peers \
  --data-dir /tmp/coincync-local \
  --rpc-bind 127.0.0.1:18081 \
  --p2p-bind 127.0.0.1:18080

# 3. In another terminal: mine to your own address
target/release/coincync-wallet --network regtest --wallet /tmp/me.wallet create
ADDR=$(target/release/coincync-wallet --network regtest --wallet /tmp/me.wallet address | grep '^Address:' | awk '{print $2}')

target/release/coincync-rig run-solo \
  --node http://127.0.0.1:18081 \
  --address $ADDR \
  --network regtest \
  --threads 1
```

You'll have your own private chain with money, ready to break.

---

## Common workflows

### "I want to add a new RPC method"

1. Define the handler in `src/rpc/server.rs` (or split out into `src/rpc/<module>.rs` if it's a clean group).
2. Wire it into the JSON-RPC dispatch table.
3. Add an integration test in `tests/`.
4. Update the API docs in `docs/API.md`.
5. `cargo test --release --workspace`.

No CIP needed for read-only RPC additions. CIP needed if it changes consensus-relevant behavior.

### "I want to fix a bug in the consensus / privacy stack"

1. Open the relevant module under `src/consensus/` or `src/crypto/`.
2. Add a regression test that fails without the fix.
3. Implement the fix.
4. If the file is in `critical_files.lock`, run `cargo run --bin update-critical-hashes --release` after the fix is reviewed.
5. Reference Article XVII (Security Strengthening Exception) in the PR description if the fix is security-driven.

### "I want to add a wallet feature"

1. Decide if it's a new subcommand on `coincync-wallet` or a flag on an existing one.
2. Add the clap definition in `src/bin/wallet.rs`.
3. Implement in a new function `cmd_<name>` in the same file.
4. Update `COMMANDS.md` with a recipe.
5. Smoke-test path manually if it touches send/receive: `pwsh scripts/smoke-test-tx.ps1`.

### "I want to add a TUI feature to the rig"

The rig TUI lives in `crates/coincync-rig/src/tui.rs`. The render function `draw()` dispatches into `draw_header`, `draw_hero`, etc. To add a new widget:

1. Add the data source to `crates/coincync-rig/src/metrics.rs` (atomic counter, ring buffer, etc.).
2. Plumb the data update into `crates/coincync-rig/src/orchestrator.rs` if it's mining-loop-driven.
3. Write a `draw_<name>` function in `tui.rs`.
4. Add a `Constraint::Length(N)` to the layout in `draw()` and dispatch in the right order.
5. Build, kill running rig, relaunch.

The rig's premium-redesign commit (`d2d318f`) is the reference for how widgets should look + feel.

### "I want to add an Article to the Constitution"

Don't, unless it strictly *strengthens* a user protection. The bar is in Article XV. If you do:

1. Append the new article in principle language (≤4 sentences) — see existing articles for voice.
2. Add a Commentary section in `docs/CONSTITUTIONAL_COMMENTARY.md` explaining the failure mode it forecloses.
3. Add a tripwire constant in `src/constants.rs` if applicable.
4. Refresh `critical_files.lock` (`cargo run --bin update-critical-hashes --release`).
5. Commit with a clear "constitution: …" prefix.

---

## Troubleshooting

### Build is slow or appears stuck

First release build is genuinely 5-15 minutes (compiles RandomX C code + 200+ Rust deps). Watch progress: it should print `Compiling <crate>` lines every few seconds. If it hasn't printed anything in 60+ seconds, it might be stuck on `pasta_curves` or `tari_bulletproofs_plus` — try `cargo clean -p <name>` and rebuild.

### `cargo test` runs forever

Almost always: you're running with `--no-default-features` or in debug mode, and the RandomX-using tests are software-emulating. Switch to `--release` and the suite drops from 30+ minutes to 5-10.

### Tests fail with `connection refused` to localhost

You have a test that needs a running daemon. Either run `coincync-node start --network regtest --data-dir /tmp/cync-test` in another terminal, or skip integration tests with `cargo test --release --lib`.

### Rig hangs on `Creating RandomX VM` for >5 seconds

First-launch cache build is normal. If it's >30 seconds, your CPU may not support AVX2; check `cat /proc/cpuinfo | grep avx2` (Linux) or `Get-CimInstance Win32_Processor` (Windows). RandomX without AVX2 falls back to a slower path.

### Fleet box build vs local build hash mismatch

You're building on Windows + the fleet is Linux. Cross-compile via WSL (see [`Cross-compile to Linux`](#cross-compile-to-linux-via-wsl)). Windows + Linux builds are not byte-identical even with `--locked`.

---

## File map

```text
.
├── CONSTITUTION.md                      # Operative constitutional law
├── CONTRIBUTING.md                      # PR + style + conduct
├── critical_files.lock                  # SHA-256 lock on consensus files
├── Cargo.toml                           # Workspace manifest
├── build.rs                             # Constitutional integrity check
├── crates/
│   ├── bridge/                          # Bytes-only Tari↔Orchard isolation
│   ├── coincync-rig/                    # CPU miner + TUI
│   └── coincync-swap/                   # CYNC↔BTC atomic swap (skeleton)
├── deploy/
│   ├── explorer/                        # Caddy + nginx for explorer.coincync.network
│   └── ops/                             # Hard-fork rollout scripts
├── docs/
│   ├── BILL_OF_RIGHTS.md                # User-facing rights
│   ├── CODE_OF_CONDUCT.md
│   ├── COMMANDS.md                      # CLI reference (this file's neighbor)
│   ├── CONSTITUTIONAL_COMMENTARY.md     # Rationale (no constitutional force)
│   ├── DEVELOPER.md                     # ← you are here
│   ├── SMOKE_TEST.md                    # End-to-end test runbook
│   ├── cip/                             # CoinCync Improvement Proposals
│   └── launch/                          # Pre-launch announcement drafts
├── scripts/
│   ├── coincync-soak.sh                 # On-box soak sampler
│   ├── deploy-soak.ps1                  # Deploy soak across fleet
│   ├── smoke-test-tx.ps1                # End-to-end tx test (Windows)
│   └── …                                # Many more — see scripts/README.md
└── src/
    ├── bin/                             # Binary entry points
    ├── consensus/                       # Lockfile-protected consensus rules
    ├── crypto/                          # Cryptographic primitives
    ├── emission/                        # Lockfile-protected emission curve
    ├── network/                         # P2P, Dandelion++, framing
    ├── rpc/                             # JSON-RPC server
    └── wallet/                          # Wallet logic shared by CLI + Tauri
```

---

## See also

- [`COMMANDS.md`](COMMANDS.md) — end-user CLI reference (recipes for `coincync-wallet send …` etc.)
- [`SMOKE_TEST.md`](SMOKE_TEST.md) — end-to-end transaction-path test
- [`CONSTITUTION.md`](../CONSTITUTION.md) — the operative law
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — what we welcome / what we won't accept
- [`cip/`](cip/) — CoinCync Improvement Proposals (CIP-001 = atomic swaps)
