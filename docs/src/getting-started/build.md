# Build from source

CoinCync is written in Rust. Pre-built Linux and Windows binaries are available — see the download table at the top of [Run a testnet node](./run-a-node.md). Building from source is for users on other platforms, those who want to verify reproducibility, or contributors patching the code. The build is reproducible: same commit + same Rust version → byte-identical output.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Rust toolchain | **1.75 or newer** | Edition 2021, rust-version pinned in `Cargo.toml` |
| `cmake`, `clang`, `pkg-config`, `libssl-dev` | any recent | for building `librocksdb-sys` (the storage layer) |
| `git` | any | source checkout |
| `cargo` | bundled with Rust | build orchestration |

Install on Debian / Ubuntu:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt update
sudo apt install -y cmake clang libclang-dev build-essential pkg-config libssl-dev git curl
```

Install on macOS:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
brew install cmake llvm git
```

Windows: use [WSL2](https://learn.microsoft.com/windows/wsl/install) running Ubuntu, then follow the Linux instructions. Native Windows (MSVC) builds also work, with one known test-suite quirk described in [Run the test suite](#run-the-test-suite) below.

## Clone and build

```bash
git clone https://git.coincync.network/coincync/cync-protocol.git
cd Coincync-Testnet-
cargo build --release --features "randomx testnet"
```

First build takes 5–15 minutes depending on the machine because RocksDB and several Rust crypto crates compile from source. Subsequent builds are incremental (seconds).

The five binaries land under `target/release/`:

| Binary | Purpose |
|---|---|
| `coincync-node` | the full node daemon (P2P + RPC + chain) |
| `coincync-wallet` | command-line wallet (create, list, send) |
| `coincync-miner` | standalone solo miner (talks to a node via RPC) |
| `coincync-tui-miner` | terminal UI for monitoring the miner |
| `coincync-tui-operator` | terminal UI for monitoring node health |

## Feature flags

The build accepts compile-time features. The defaults are sensible for a testnet node; you only need to override them in unusual cases.

| Feature | Default | Effect |
|---|---|---|
| `randomx` | **on** | Enables the RandomX PoW backend. **Required** — running without it makes `compute_pow_hash` panic at runtime. There is no non-RandomX fallback; the panic is by design so you can't accidentally ship a PoW-skipping node. |
| `testnet` | off | Selects testnet network magic, ports, and genesis. Enable when you want a node that talks to the public testnet seed nodes. |
| `mainnet` | off | Selects mainnet network magic, ports, and genesis. Enable after the October 1, 2026 mainnet launch. |
| `metrics` | off | Exports Prometheus metrics on a separate HTTP port. Recommended for production hosts. |
| `test-utilities` | off | Exposes a few `Mempool::add_skip_crypto`-style helpers used only by integration tests. **Never enable in production builds.** |

## Verify the build

```bash
./target/release/coincync-node --help
./target/release/coincync-node print-genesis-hash
# Should print the expected genesis hash; if it doesn't match the
# hardcoded constant in src/testnet.rs / src/mainnet.rs, the build
# is corrupt or the source is modified.
```

## Run the test suite

```bash
cargo test --lib -p coincync
# Expect ~520+ tests passing, 0 failed, 0 ignored.
```

For the full suite including the integration tests in `tests/*.rs`:

```bash
cargo test -p coincync
```

### Windows: the `librocksdb_sys` rlib race

If you're on native Windows (MSVC), `cargo test -p coincync` will sometimes fail partway through with an error like:

```text
error: crate `librocksdb_sys` required to be available in rlib format,
       but was not found in this form
```

cascading into a bunch of `could not compile coincync (test "…")` failures. Individual tests (`cargo test --lib -p coincync`, `cargo test --test wallet_roundtrip -p coincync`) work fine, and Linux / macOS are unaffected.

**Root cause:** parallel-link race on a static-archive read. `cargo test -p coincync` builds ~12 integration-test binaries, each of which statically links `librocksdb_sys` (~80 MB). With the default build parallelism (= CPU count), several of those final link steps fire simultaneously, and each rustc invocation opens the same `liblibrocksdb_sys-<hash>.rlib` as a static archive to pull symbols out of. On Windows, the file-sharing semantics for static-archive reads are strict enough that a second reader occasionally observes a partial / wrong-magic view of the archive and errors out.

This was previously blamed on OneDrive sync interference. That was wrong — relocating `CARGO_TARGET_DIR` to `%LOCALAPPDATA%` (completely outside any sync daemon) does **not** fix the race. The real cause is Windows + parallel static-archive reads.

**The fix: serialize the build with `--jobs 1`.** `cargo test -p coincync --jobs 1` builds one target at a time. Dependency compilation is slower end-to-end (~5 min vs ~2 min), but test execution itself is still parallel under the Rust harness — `--jobs` affects the build, not the runner. The rlib race cannot happen because there is only ever one reader at a time.

**Fix A — use `scripts/windows-test.sh` (recommended).** The script sets `--jobs 1` automatically on Windows and also relocates `CARGO_TARGET_DIR` out of OneDrive (IO-cost win, not correctness):

```bash
./scripts/windows-test.sh                         # full suite
./scripts/windows-test.sh --lib                    # library tests only
./scripts/windows-test.sh --test wallet_roundtrip  # one integration test
```

It's a no-op on Linux / macOS — no target relocation and no `--jobs 1` forced. If you ever need to opt out of serial build on Windows (you shouldn't), set `COINCYNC_SERIAL_BUILD=0` in the environment.

**Fix B — run the raw cargo command yourself:**

```bash
cargo test -p coincync --jobs 1
```

Works anywhere; slower than parallel but reliable.

**Fix C — run integration tests one at a time.** Cargo only links one test binary per invocation, so there's no concurrent access to the same rlib:

```bash
cargo test --lib -p coincync                      # fastest path, always safe
cargo test -p coincync --test wallet_roundtrip
cargo test -p coincync --test transaction_lifecycle
# ... and so on
```

This is what `scripts/windows-test.sh` falls back to if you pass it explicit `--test <name>` arguments.

### Why relocating off OneDrive is still a good idea

Even though the parallel-link race is not OneDrive-specific, keeping `target/` out of OneDrive / Dropbox / iCloud is still worth doing for two separate reasons: (1) fewer IO round trips because the sync daemon doesn't index multi-GB artifact trees, and (2) faster incremental rebuilds because no file-lock contention with the sync agent. `scripts/windows-test.sh` does this for you automatically. If you want it for every cargo invocation (not just tests), set the env var in your shell profile:

```bash
# PowerShell profile ($PROFILE):
[Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR', "$env:LOCALAPPDATA\coincync-target", 'User')

# Git Bash profile (~/.bashrc):
export CARGO_TARGET_DIR="$LOCALAPPDATA/coincync-target"
```

Rust-analyzer, VS Code, and IntelliJ Rust all honor `CARGO_TARGET_DIR`.

## Where to put the binaries on a real host

Production deployment ships the binaries to `/usr/local/bin/` and runs them under systemd. See [Deploying a node](../operations/deployment.md) for the full runbook. For local development just leave them in `target/release/`.
