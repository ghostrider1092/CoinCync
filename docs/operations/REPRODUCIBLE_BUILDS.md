# Reproducible builds

A reproducible build is one where, given the same source tree, every
builder produces a byte-identical binary. This is the technical basis
for the trust statement "the binary you downloaded came from the
public source you can read." Without it, a compromised release-signing
machine could ship a back-doored binary indistinguishable from clean.

This document describes how CoinCync's build is reproducible, how to
verify a release binary against the source, and what to do if a
mismatch shows up.

## Why we care

The Constitution (Article XV) and Bill of Rights (Right XIII) commit
the project to verifiable supply-chain provenance. "Trust me bro" is
not a security model; "build it yourself, byte-for-byte the same as
mine" is.

For privacy-coin users specifically: a malicious release binary
could log view keys, reuse stealth-randomness predictably, or weaken
the wallet's RNG in ways that don't show up in code review. Repro
builds cut that whole class of attack: the auditable artifact is
the SOURCE TREE, not a binary nobody can inspect.

## Current state

The project's release profile (`Cargo.toml::profile.release`) is
already configured for reproducibility:

```toml
[profile.release]
opt-level     = 3
lto           = "thin"
codegen-units = 1
panic         = "abort"
strip         = true
```

`codegen-units = 1` is the most important knob here — multi-codegen
parallelism is non-deterministic. With one codegen unit, the
optimizer always sees the whole crate at once and produces the same
output.

What's NOT yet in place:

1. **A documented build environment.** Reproducibility requires the
   builder to have the same Rust toolchain version, the same target
   triple, the same dependency lockfile, and the same system
   libraries. Without pinning, two clean checkouts of the same
   commit produce different binaries.
2. **A verifier script.** A mechanical "compare binary X to source
   tree at commit Y" check.
3. **Published expected hashes.** A signed manifest of
   `release.tar.gz -> sha256` values per commit.

This doc plus `scripts/verify-build.sh` close those gaps.

## Build environment

The reproducible build is performed inside a Rust slim-bookworm image,
pinned to the same toolchain version as the workspace's `rust-toolchain.toml`
(currently **1.88.0**). The Dockerfile parameterises this via
`ARG RUST_VERSION=1.88.0`; override with `--build-arg RUST_VERSION=...`
or the wrapper script's `--rust` flag.

The 1.88.0 floor is dictated by transitive deps (`cpufeatures 0.3.0` needs
edition2024 = 1.85+; `time 0.3.47` / `time-core` / `time-macros` need 1.88+).
The workspace's stated `rust-version = "1.75"` in `Cargo.toml` is a
source-level promise (our own code stays compatible with 1.75), not a
guarantee any given Cargo.lock resolution compiles on 1.75. See
`docker/builder.Dockerfile`'s header comment for the full reasoning.

### Authoritative source

See [`docker/builder.Dockerfile`](../../docker/builder.Dockerfile) — that
file is the source of truth. The snippet below is illustrative only and
may lag the real Dockerfile after dep bumps.

```dockerfile
ARG RUST_VERSION=1.88.0
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libclang-dev clang cmake make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# SOURCE_DATE_EPOCH is set at build time from the committer date of HEAD
# so two checkouts of the same commit get the same value. The wrapper
# script (scripts/build-in-docker.sh) computes and passes it.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN cargo build --release --workspace --locked
```

### How to build reproducibly

```bash
# Inside the cloned repo, at the commit you want to verify:
docker build -f docker/builder.Dockerfile -t coincync-build:HEAD .
docker run --rm -v "$(pwd)/out:/out" coincync-build:HEAD \
    sh -c 'cp target/release/coincync-* /out/'

# The /out/ directory now contains the build artifacts.
sha256sum out/coincync-*
```

Two clean clones of the same commit, run through this Docker image,
must produce IDENTICAL sha256 sums. If they don't, the reproducibility
contract is broken; file an issue.

## Verifier script

Run `scripts/verify-build.sh <release-version>` to:

1. Download the released binaries from the official release server.
2. Build the same commit locally inside the reproducibility Docker
   image.
3. Diff the two artifacts.
4. Print PASS / FAIL.

See the script for the exact mechanism. Total time on a 4-core box:
~10 minutes (most of it is the Docker build).

## Published manifest

Each release ships a manifest at
`https://releases.coincync.network/<version>/MANIFEST.txt`:

```
# CoinCync release manifest
# Version: 1.0.0
# Commit:  <full-sha>
# Builder: coincync/builder@sha256:<digest>
# Built:   2026-05-08T03:00:00Z

a1b2c3d4...  coincync-node-1.0.0-x86_64-linux-gnu.tar.gz
e5f6g7h8...  coincync-wallet-1.0.0-x86_64-linux-gnu.tar.gz
i9j0k1l2...  coincync-rig-1.0.0-x86_64-linux-gnu.tar.gz
m3n4o5p6...  coincync-node-1.0.0-x86_64-windows-msvc.zip
...
```

The manifest is signed with the release key (`releases@coincync.network`,
PGP fingerprint published in the project's `SECURITY.md`). The
signature file is `MANIFEST.txt.asc` alongside.

Verification:

```bash
# Download manifest + signature.
curl -O https://releases.coincync.network/1.0.0/MANIFEST.txt
curl -O https://releases.coincync.network/1.0.0/MANIFEST.txt.asc

# Verify signature.
gpg --verify MANIFEST.txt.asc MANIFEST.txt

# If verification passes, every binary listed has a known-good hash.
sha256sum -c MANIFEST.txt
```

## When a mismatch happens

A reproducibility mismatch means one of three things:

1. **The build environment isn't truly pinned.** Some piece of
   non-determinism leaks through (timestamps, build paths, locale,
   parallelism, etc.). Fix the Dockerfile.
2. **The release was built by a compromised builder.** Or someone
   slipped a non-reviewed change into the release pipeline.
3. **The published binary is fake.** Someone is hosting a malicious
   binary at a URL that looks like the official one.

For case 1: file an issue, identify the source of variation, fix.

For case 2 or 3: this is an emergency. Notify operators via the
status page, Discord, and `security@coincync.network`. Pull the bad
release from official channels. Investigate.

The verifier script's PASS/FAIL output is what makes case 2 vs 3
distinguishable: if YOUR build matches the source-tree commit and
the released binary doesn't, the released binary is the problem.

## What's NOT verified by repro

Repro builds prove "this binary was compiled from this source." They
do NOT prove:

- The source itself is correct (that's audits + tests + review)
- The toolchain is trustworthy (we use upstream Rust; "trusting trust"
  is a deeper problem)
- The hardware running the build is uncompromised (a rootkit can
  intercept the build; pinning the Docker image hash mitigates this
  somewhat — same image hash = same compiled output, even on a
  compromised host)

Repro is a building block, not the whole supply-chain story. For the
deeper layers, see the security audit policy and the
`docs/THREAT_MODEL.md` analysis of compiler / toolchain trust.

## Status

| Component | State |
|---|---|
| `profile.release` configured for determinism | ✅ shipped |
| Dockerfile builder image (`docker/builder.Dockerfile`) | ✅ shipped |
| Wrapper script (`scripts/build-in-docker.sh`) | ✅ shipped |
| `.dockerignore` keeping the build context lean | ✅ shipped |
| `scripts/verify-build.sh` | ✅ shipped (testnet) |
| Published manifest format | ✅ shipped (this doc) |
| End-to-end Docker build verified working | ✅ verified 2026-05-24 — fresh build on `a7f0a6d` produced all 5 binaries (`coincync-node`, `coincync-wallet`, `coincync-rig`, `coord`, `coord-cli`); `sha256sum -c SHA256SUMS` passed for all 5 inside the container. |
| Host-side artifact extraction on Windows | ✅ fixed 2026-05-24 — wrapper script now sets `MSYS_NO_PATHCONV=1` to prevent Git Bash from translating the container-side `/out` mount path |
| Two-builder byte-identical comparison | ⏳ requires a second machine — single-machine reproducibility verified, cross-machine pending |
| First repro-verified release | ⏳ blocks on release process — pre-mainnet |
| OSS-Fuzz / cosign / sigstore integration | ⏳ post-launch |

What this means today:

- Anyone can run `./scripts/build-in-docker.sh` from a fresh clone.
  Two clean clones of the same git commit produce byte-identical
  binaries on the same host CPU architecture. Cross-arch builds
  (x86_64 vs arm64) are NOT byte-identical — that's a separate
  promise we don't make.
- The published v1.0.2-testnet binaries were NOT built through
  this Dockerfile; they were a one-shot from the dev box. So
  `sha256sum` of `out/coincync-wallet` from `build-in-docker.sh`
  will not match the published `release/v1.0.1-testnet/coincync-wallet*`
  binaries. This will start matching when the v1.0.3 release is
  cut through the Dockerfile.
- The mainnet release process (Article XV / multi-maintainer M-of-N)
  will use this Dockerfile and publish a signed manifest of
  `(commit, dockerfile-digest, binary-sha256)`. That's the gate
  this section's "first repro-verified release" row is waiting on.

## Pointers

- `Cargo.toml` — `profile.release` settings (codegen-units=1,
  lto=thin, panic=abort, strip=true)
- `docker/builder.Dockerfile` — the pinned build environment
- `scripts/build-in-docker.sh` — wrapper that runs the Dockerfile
  and extracts artifacts to `./out/`
- `scripts/verify-build.sh` — the (in-progress) verifier
- `.dockerignore` — what's NOT in the build context
- `releases@coincync.network` — release-signing PGP identity
- Reproducible Builds project: <https://reproducible-builds.org/> —
  the canonical reference for the field
