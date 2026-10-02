# CoinCync Beta — trying the shielded (Lelantus-Spark) feature

The **beta** is a disposable, isolated test network for opt-in users to try the
shielded transaction feature **before** its external audit. It is **not** testnet
and **not** mainnet:

- Its own network magic (`BETA_MAGIC`) and its own genesis — a separate chain.
- **Shielded activates at beta block height 5**, with a deliberately **low
  initial difficulty** so blocks mine in seconds and activation is reached almost
  immediately.
- **Testnet and mainnet are unaffected** — on both, shielded stays permanently
  disabled (`u64::MAX`) until the audit clears. Nothing here changes that.

> ⚠️ **Disposable + unaudited.** The beta chain may be wiped and relaunched at any
> time, and the shielded crypto is **not yet audited**. Beta coins have **no
> value**. Do not reuse beta wallets/keys anywhere else.

## 1. Run a beta node (no shielded — default build)

A normal build runs a beta node, but the shielded engine is **fail-closed**
(`StubBackend`): the node follows the beta chain only until the first block that
carries a shielded transaction (activation is at height 5). From there it rejects
every such block and stops syncing, so a default build is **not** usable as a
long-running beta node or seed once shielded is in use. Fine for a quick look at the
network; build §2 for anything else.

```bash
cargo build --release --features testnet       # 'testnet' pulls in RandomX; beta reuses it
./target/release/coincync-node --network beta
```

(Use `./coincync-node --network beta --help` for the P2P/RPC ports and flags.
To reach the beta network, `--addnode <BETA_SEED_HOST:PORT>` — the beta seed
address is announced with each beta launch — or run your own local beta nodes.)

## 2. Build WITH shielded enabled (to actually try shielded)

Shielded only works when the binary is compiled with the shielded engine. Use the
**validated feature set** (the same combination the 24h in-block soak and the
shielded test suite run under):

```bash
cargo build --release --features "testnet,sketch-gk-proof,libspark-ffi"
```

`libspark-ffi` builds the vendored Firo **libspark** engine, which pulls a **C++
toolchain + OpenSSL**, so this build has extra prerequisites:

- **LLVM/libclang** — set `LIBCLANG_PATH` to your LLVM `bin` (e.g. on Windows
  `C:/Program Files/LLVM/bin`).
- **OpenSSL** — on Windows set `SPARK_OPENSSL_DIR` to an OpenSSL install with
  `include/` and `lib/` (the project uses a vcpkg `x64-windows-static-md` build).
  On Linux/macOS the build finds `libcrypto` through `pkg-config` (install
  `libssl-dev` / `openssl-devel` / `brew install openssl@3`); `SPARK_OPENSSL_DIR`
  is only an override there.
- A C++17 compiler (MSVC on Windows; clang/gcc elsewhere).

See `docs/design/cip-shielded-libspark-ffi.md` for the full build/toolchain
rationale. Without `libspark-ffi`, `backend()` stays the fail-closed stub and
shielded transactions are rejected even though the beta network has activated
them — so the feature flags are **required**, not optional, to exercise shielded.

```bash
# example (Windows / Git Bash)
export LIBCLANG_PATH="C:/Program Files/LLVM/bin"
export SPARK_OPENSSL_DIR="C:/path/to/openssl-static-md"
cargo build --release --features "testnet,sketch-gk-proof,libspark-ffi"
```

### Linux build (Debian/Ubuntu)

```bash
# 1. Toolchain: Rust, a C++ compiler, clang/libclang (for the FFI bindings),
#    pkg-config and OpenSSL development files.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # if cargo isn't installed
sudo apt-get update
sudo apt-get install -y build-essential clang libclang-dev pkg-config libssl-dev cmake

# 2. Point the RandomX bindings at libclang. OpenSSL needs no variable:
#    build.rs asks pkg-config for libcrypto.
export LIBCLANG_PATH="$(llvm-config --libdir 2>/dev/null || echo /usr/lib/llvm-*/lib)"

# 3. Build.
cargo build --release --features "testnet,sketch-gk-proof,libspark-ffi"
```

On RHEL/Fedora the package names are `clang clang-devel openssl-devel pkgconf`.
If pkg-config cannot see your OpenSSL (custom prefix), set `SPARK_OPENSSL_DIR` to
a prefix laid out as `<prefix>/include/openssl/*.h` + `<prefix>/lib/libcrypto.*`
(Debian's `lib/<triplet>/` subdirectory is searched as well).

### macOS build

```bash
brew install cmake openssl@3 pkg-config
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"   # optional: build.rs also knows the Homebrew prefix
export LIBCLANG_PATH="/Library/Developer/CommandLineTools/usr/lib"
cargo build --release --features "testnet,sketch-gk-proof,libspark-ffi"
```

## 3. Mine the beta so shielded activates

The beta's low initial difficulty means a single miner reaches height 5 (shielded
activation) in seconds:

```bash
# generate a payout wallet, then mine solo against your local beta node
./coincync-rig run-solo --node http://127.0.0.1:<beta-rpc-port> \
  --address <your-beta-address> --threads 0
```

Note the rig's **≥3-peer** mining gate still applies on a real mesh; for a tiny
beta you may run a couple of nodes, or use the node's own `--mine` for a
single-box beta.

## 4. Try a shielded transaction

With a shielded-enabled build (§2) on a beta node past height 5, the shielded
wallet subcommands work (`shielded-address`, `shielded-send`, `shielded-balance`;
see `docs/COMMANDS.md`). Report anything you hit in Discord `#beta`.

## What to report

Anything that looks wrong: a shielded tx that should verify but is rejected (or
vice-versa), a node that halts, a reorg that strands pool state, or a mismatch
between what a sender sent and what a recipient scans. Include your beta node logs
and, if a shielded op failed, the command you ran. These reports feed directly
into the pre-audit hardening.
