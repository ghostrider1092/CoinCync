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
(`StubBackend`): the node follows the beta chain, but any shielded transaction is
rejected. Fine if you just want to run a node / mine.

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
- **A static OpenSSL prefix** — set `SPARK_OPENSSL_DIR` to an OpenSSL install with
  `include/` and `lib/` (the project uses a vcpkg `x64-windows-static-md` build).
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

> **⚠️ Shielded on Linux is not buildable yet.** The `libspark-ffi` build
> (`crates/spark-connector/build.rs`) is currently **Windows/MSVC-only** — it
> unconditionally sets `WIN32`/`NOMINMAX` and links Windows system libs
> (`advapi32`, `crypt32`, …) with MSVC OpenSSL naming, so `cargo build
> --features "...,libspark-ffi"` **fails on Linux** until `build.rs` is ported to
> be cross-platform (tracked separately). A plain `cargo build --release
> --features testnet` *does* build on Linux and runs a beta node, but with the
> fail-closed stub it can't validate shielded txs — so it is **not** a usable beta
> seed once shielded activates. For now, a shielded-capable node (incl. the seed)
> must be **built on Windows**. The steps below are the Linux prerequisites for
> once the port lands.

```bash
# 1. Toolchain: Rust, a C++ compiler, clang/libclang (for the FFI bindings),
#    and OpenSSL development files.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # if cargo isn't installed
sudo apt-get update
sudo apt-get install -y build-essential clang libclang-dev pkg-config libssl-dev

# 2. Point the build at libclang and an OpenSSL prefix (include/ + lib/).
#    libssl-dev installs OpenSSL under /usr, which works as the prefix:
export LIBCLANG_PATH="$(llvm-config --libdir 2>/dev/null || echo /usr/lib/llvm-*/lib)"
export SPARK_OPENSSL_DIR=/usr          # /usr/include/openssl + /usr/lib/.../libcrypto

# 3. Build.
cargo build --release --features "testnet,sketch-gk-proof,libspark-ffi"
```

If the linker can't find `libcrypto` under `/usr` on your distro (some put it in
`/usr/lib/x86_64-linux-gnu`), install a static OpenSSL into a dedicated prefix and
point `SPARK_OPENSSL_DIR` there instead — the layout the build expects is
`<prefix>/include/openssl/*.h` and `<prefix>/lib/libcrypto.*`. On RHEL/Fedora the
package names are `clang clang-devel openssl-devel`.

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

Not possible yet on this tag, see issue #172. With a shielded-enabled build on a
beta node past height 5, `shielded-address` and `shielded-balance` talk to the
node, and `shielded-send` builds and verifies a real libspark spend bundle, but
it then prints

    NOTE: not submitted - live shielded submission awaits activation and a shielded submission RPC.

and nothing reaches the chain. There is also no shield-in (mint) command, so the
on-chain pool is empty and `shielded-balance` reports no notes. The only complete
shielded flow today is `--demo`, which runs against an in-process regtest pool and
needs no node. Please do not report "shielded-send did nothing" as a new bug.

What you can test on beta today: node sync, mining, peer behaviour across the
shielded activation height (5), and the transparent wallet flow. The wallet does
not accept `--network beta` yet; use
`coincync-wallet --network testnet --node http://127.0.0.1:38081 ...` (beta uses
testnet's address format and the node does not check the wallet's network label).
Report anything you hit in Discord `#beta`.

## What to report

Anything that looks wrong: a shielded tx that should verify but is rejected (or
vice-versa), a node that halts, a reorg that strands pool state, or a mismatch
between what a sender sent and what a recipient scans. Include your beta node logs
and, if a shielded op failed, the command you ran. These reports feed directly
into the pre-audit hardening.
