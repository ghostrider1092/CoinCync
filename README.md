# CoinCync

Copyright (c) 2025-2026, The CoinCync Project

**Privacy money that requires no permission.** A fair-launch, RandomX
CPU-mined cryptocurrency with mandatory privacy at the consensus layer, an
auditable asymptotic supply, and a hash-locked constitution that even its authors
cannot quietly change.

## Table of Contents

- [Development resources](#development-resources)
- [Vulnerability response](#vulnerability-response)
- [Research and design](#research-and-design)
- [Announcements](#announcements)
- [Introduction](#introduction)
- [About this project](#about-this-project)
- [Supporting the project](#supporting-the-project)
- [License](#license)
- [Contributing](#contributing)
- [Scheduled software/network upgrades](#scheduled-softwarenetwork-upgrades)
- [Release staging schedule and protocol](#release-staging-schedule-and-protocol)
- [Compiling CoinCync from source](#compiling-coincync-from-source)
  - [Dependencies](#dependencies)
  - [Reproducible builds](#reproducible-builds)
- [Installing CoinCync from a release](#installing-coincync-from-a-release)
- [Running coincync-node](#running-coincync-node)
- [Running a miner](#running-a-miner)
- [Using Tor](#using-tor)
- [Storage and sync](#storage-and-sync)
- [Debugging](#debugging)
- [Known issues](#known-issues)

## Development resources

- Web: [coincync.network](https://coincync.network)
- Explorer: [explorer.coincync.network](https://explorer.coincync.network)
- Live chain (JSON-RPC): [api.coincync.network/rpc/testnet](https://api.coincync.network/rpc/testnet)
- Discord: [join](https://discord.gg/5tYNSCsqzy) — the primary place for development discussion and coordination
- Security: `CyncLabs@proton.me`

CoinCync is developed openly. Because it is a small, security-critical project,
the Discord `#dev` channel is the best way to stay current on best practices and
in-flight protocol work before integrating against the network — the same
reasoning Monero applies to its `#monero-dev` channel. `#dev` is about CoinCync
protocol development; for help *using* CoinCync, use the general channels.

## Vulnerability response

CoinCync follows a responsible-disclosure process documented in
[SECURITY.md](SECURITY.md). Report vulnerabilities privately to
`CyncLabs@proton.me` — please do not open a public issue for a security bug.

The codebase is fuzzed with `cargo-fuzz` and checked under the Miri interpreter
for undefined behavior on suitable pure-Rust components. The disclosure SLA
(24-hour first response) is in [MAINTAINERS.md](MAINTAINERS.md).

## Research and design

Protocol changes go through the **CoinCync Improvement Proposal (CIP)** process
(see [CONTRIBUTING.md](CONTRIBUTING.md#cip-process--for-protocol-changes)).
Design documents, threat models, and privacy analyses live under [docs/](docs/):

- [docs/architecture/PRIVACY.md](docs/architecture/PRIVACY.md) — the privacy model
- [docs/PRIVACY_FEATURES.md](docs/PRIVACY_FEATURES.md) — per-feature detail with file:line citations
- [docs/security/reorg-defense.md](docs/security/reorg-defense.md) — reorg + finality defenses
- [docs/cip/](docs/cip/) — improvement proposals
- [CONSTITUTION.md](CONSTITUTION.md) and [docs/BILL_OF_RIGHTS.md](docs/BILL_OF_RIGHTS.md) — the hash-locked guarantees

Outside researchers are welcome; reach out on Discord `#research` before
duplicating known work.

## Announcements

Critical announcements (releases, network upgrades, security advisories) are
posted in Discord and attached to GitHub releases. Node and miner operators
should watch releases and upgrade when a network upgrade is scheduled.

## Introduction

CoinCync is a private, permissionless, fairly launched proof-of-work
cryptocurrency. You are your own bank, you control your funds, and your
transactions are private by default — no one can trace them unless you choose to
disclose.

**Privacy.** Privacy is mandatory and enforced at the consensus layer, not an
opt-in wallet setting. It is built as *Concentric Privacy* — independent, layered
defenses across the transaction, linkability, network, and operational surfaces —
so that no single break exposes the whole. CLSAG ring signatures (ring size 16),
Bulletproofs+ confidential amounts, stealth addresses, and view tags hide sender,
amount, and recipient on-chain.

**Security.** Every transaction is secured by a distributed proof-of-work
consensus network. Wallets are protected by an encrypted seed; a leaked wallet
file is useless without the passphrase.

**Untraceability.** Ring signatures give each spend a set of decoys drawn from an
age-matched distribution, so a real spend is statistically indistinguishable from
its ring members.

**Decentralization.** CoinCync mines with **RandomX**, so validation and mining
run on ordinary consumer CPUs — no ASICs, no specialized hardware. Anyone can run
the node software, validate the chain, and mine on equal terms.

**Constitutional guarantees.** The [Constitution](CONSTITUTION.md) forbids
premine, dev tax, founder allocation, admin authority, surveillance hooks, and
external-chain trust — and it is **hash-locked into the build**, so these
guarantees cannot be quietly changed later. Supply approaches an asymptote of
100,000,000 CYNC on an auditable curve; a perpetual 0.6 CYNC/block tail emission
continues past it.

## About this project

This is the reference implementation of CoinCync, written in Rust. It is open
source and free to use under the terms in [LICENSE](LICENSE). Anyone may build an
alternative implementation that is compatible with the protocol and network.

As with most development projects, the `main` branch on the repository is the
staging area for the latest changes. Changes are developed in feature branches,
submitted as pull requests, and reviewed before merging. For production use,
prefer a tagged release over `main` for stability.

Contributions are welcome — see [Contributing](#contributing) below.

## Supporting the project

CoinCync takes **no dev tax, has no premine, and holds no founder allocation** —
these are constitutional and hash-locked, so there is no insider stake and users
are never anyone's exit liquidity. The project is sustained instead by:

- **Public-interest grants** (e.g. NLnet / NGI0) that fund audits and development.
- **Voluntary community crowdfunding** on a transparent, per-initiative basis.
- **Founders and contributors mining on equal terms**, like everyone else.

The most valuable thing you can contribute is not money: **run a node, run a
miner, review pull requests, or operate an independent seed.** A network with
many independent operators is worth more than any donation.

## License

See [LICENSE](LICENSE).

## Contributing

If you'd like to help, see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
Small, self-contained fixes can be submitted directly as pull requests to `main`.
Protocol-affecting changes must go through the [CIP process](docs/cip/). Note
that `main` is protected: all changes land via reviewed pull requests.

## Scheduled software/network upgrades

CoinCync uses scheduled hard-fork network upgrades to introduce consensus
changes. Operators should run current versions and upgrade before a scheduled
upgrade height. Consensus-critical files are protected by a SHA-256 lockfile, so
consensus changes are explicit and reviewable.

Dates use YYYY-MM-DD. "Minimum" is the version that follows the new consensus
rules. The table below reflects the **testnet** schedule; the mainnet schedule is
finalized before genesis.

| Network | Height | Date | Change | Minimum version |
|---|---|---|---|---|
| Testnet | 13,000 | — | Hard-fork rules activation | v1.0.12 |
| Testnet | 50,000 | — | CIP-011 rolling soft-finality (behind `rolling-finality`) | TBD |
| Mainnet | genesis | 2026-10-01 (target) | Genesis; full ruleset from block 0 | TBD |

Values marked TBD/— are not finalized as of this revision.

## Release staging schedule and protocol

Approximately before a scheduled network upgrade, a release branch is cut from
`main` with the new version tag. Bug-fix PRs target both `main` and the release
branch; large features and optimizations target `main` only. The release version
in `Cargo.toml` is bumped to match the tag before tagging.

## Compiling CoinCync from source

CoinCync is a Rust workspace built with Cargo.

### Dependencies

| Dependency | Min. version | Purpose |
|---|---|---|
| Rust toolchain (rustc + cargo) | 1.88.0 | build |
| A C/C++ toolchain (gcc/clang) | any | compiles the RandomX backend |
| CMake | 3.10 | RandomX build |
| Git | any | source checkout |

Install the Rust toolchain via [rustup](https://rustup.rs), then the platform C
toolchain (`build-essential cmake` on Debian/Ubuntu; `base-devel cmake` on Arch;
`gcc gcc-c++ cmake` on Fedora; Xcode command-line tools + `cmake` on macOS).

**Clone and build:**

```bash
git clone https://github.com/Coincync-sys/Coincync-Testnet-.git coincync
cd coincync
cargo build --release --features randomx
```

The resulting binaries are in `target/release/`:

- `coincync-node` — full node
- `coincync-wallet` — CLI wallet
- `coincync-rig` — CPU miner

**Run the tests:**

```bash
cargo test --workspace
```

RandomX needs ~2 GB of RAM resident for its dataset; allow ~2 GB per parallel
build thread when using `cargo build -j<N>`.

### Reproducible builds

Production Linux binaries are produced by a reproducible Docker build so anyone
can independently reproduce the release artifacts from a recorded revision. See
`Dockerfile` and the build scripts under `scripts/` / `deploy/`.

## Installing CoinCync from a release

Prebuilt Linux x86_64 binaries are attached to each release (node, wallet, and
miner). Download, make executable, and place on your `PATH`:

```bash
wget <release-url>/coincync-node
chmod +x coincync-node
./coincync-node --network testnet
```

Always prefer a tagged release over a source build of `main` for production use.

## Running coincync-node

Run a node on the public testnet (binds `0.0.0.0:28080` P2P, `127.0.0.1:28081`
RPC). Default bootstrap uses the DNS seeds `seed1/2/3.coincync.network`:

```bash
./coincync-node --network testnet
```

Verify it is syncing (from another shell, ~60s later):

```bash
curl -s http://127.0.0.1:28081/rpc/testnet \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}'
# Expect: peer_count >= 3, height climbing toward the current tip
```

If DNS is blocked on your network, the binary falls back to hardcoded seed IPs
automatically; you can also pass them explicitly:

```bash
./coincync-node --network testnet \
  --addnode 66.135.23.193:28080 \
  --addnode 140.82.57.168:28080 \
  --addnode 45.32.251.6:28080 \
  --addnode 207.148.6.50:28080 \
  --addnode 173.199.93.21:28080
```

`--addnode` accepts either `IP:port` or a `hostname:port`; hostname resolution is
refused under `--proxy`/`--tor` to avoid a DNS leak.

To run detached, use `--detach` (and `--log-file`). List all options with
`./coincync-node --help`.

## Running a miner

The most useful thing you can do for the network is run a miner. Same setup as a
node, plus the `coincync-rig` binary.

**Hardware:** 4 GB RAM minimum (RandomX dataset needs ~2 GB resident), 2 CPU
cores recommended. A $5–10/mo VPS or a spare home machine works.

```bash
# 1. Generate a payout wallet
./coincync-wallet --wallet ~/.coincync/wallets/miner.wallet create --password YOUR_PASSWORD
./coincync-wallet --wallet ~/.coincync/wallets/miner.wallet address --password YOUR_PASSWORD
# Save the tCYNC... (testnet) address — block rewards land there.

# 2. Point the rig at your local node + payout address
./coincync-rig run-solo \
  --node http://127.0.0.1:28081 \
  --address tCYNC_YOUR_ADDRESS_HERE \
  --threads 0   # 0 = auto-detect CPU count
```

`coincync-rig` logs `BLOCK FOUND, submitting` when it solves a block. Say hi in
Discord `#mining` once you're up so operators can prioritize your node.

## Using Tor

CoinCync supports routing peer-to-peer traffic over a SOCKS proxy / Tor. Start
the node with `--proxy <ip:port>` (and `--tor` for onion routing). Under a proxy,
`--addnode` will not perform plaintext DNS resolution, and the node avoids
leaking your interest in specific peers or transactions. See the network privacy
docs for the full Dandelion++ + Noise-XX + cover-traffic model.

## Storage and sync

CoinCync is a young chain, so full history is small. Fresh nodes sync from the
seeds and cross-check node-local rolling checkpoints for long-range-attack
defense; the hardcoded consensus-checkpoint table is populated post-launch
(currently empty). Light-wallet sync downloads compact block digests and scans locally, so
the node never answers "does this specific output exist" — a surveillance-
resistance property (there is deliberately no balance-lookup RPC).

## Debugging

First, ensure you are running the latest build from the repository.

- Set `RUST_BACKTRACE=1` (or `full`) for a backtrace on panic.
- Increase log verbosity with `--log-level` / `RUST_LOG`.
- For a running systemd service, inspect logs with `journalctl -u coincync-node`.
- For crashes, run under `gdb --args ./coincync-node ...` and `bt`, or enable
  core dumps with `ulimit -c unlimited`.
- Build with debug assertions for extra checks: `cargo build` (debug profile).

## Known issues

CoinCync is **early-stage infrastructure software on public testnet.** Honest
current state:

- **Single-miner network.** Today most testnet hashrate is on one operator's
  box; every maintenance restart produces a visible chain stall. This is the
  biggest pre-mainnet issue and the reason we actively recruit community miners.
- **Provider concentration.** Fleet nodes are hosted across regions of a single
  cloud provider; we mitigate by inviting independent operators on other
  providers.
- **Phase-2 modules feature-gated.** Shielded modules (Orchard / Lelantus Spark /
  MimbleWimble kernels) and rolling soft-finality ship behind feature flags,
  off by default until a future activation.
- **Atomic swaps in progress.** CYNC↔BTC atomic-swap machinery is shipped; the
  real adaptor-signature crypto is pending its audit window.
- **Wallet UX** is mid-refactor; some flows are still utilitarian.

Use at your own risk. Testnet coins have no value; mainnet is not yet live.
