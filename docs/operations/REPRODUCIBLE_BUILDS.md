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

The reproducible build is performed inside a fixed Docker image:
`coincync/builder:1.0.0`. Pinning to an image hash means the
toolchain, system libs, and build tools are byte-identical
across every builder.

### `Dockerfile` (in repo at `docker/builder.Dockerfile`):

```dockerfile
FROM rust:1.75.0-slim-bookworm@sha256:<digest>

# System libraries pinned to versions in Debian Bookworm.
RUN apt-get update && apt-get install -y \
    pkg-config=1.8.1-1 \
    libssl-dev=3.0.x-x \
    cmake=3.25.1-1 \
    clang=1:14.0-55.7~deb12u1 \
    lld=1:14.0-55.7~deb12u1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# SOURCE_DATE_EPOCH controls timestamps in the binary. Set from the
# committer date of HEAD so two checkouts of the same commit get the
# same value.
ENV SOURCE_DATE_EPOCH=1714838400

# Build.
RUN cargo build --release --workspace --locked

# Strip absolute paths from debug info that survives `strip = true`.
# (The release profile already strips, but this is a belt-and-
# suspenders pass for the rare debug strings that linger.)
RUN find target/release -maxdepth 1 -type f -executable \
    | xargs -I{} sh -c 'objcopy --strip-all {} || true'
```

The pinned digest in `FROM rust:1.75.0-slim-bookworm@sha256:<...>`
is the linchpin. When the Rust team publishes a new patch release,
the digest changes; we explicitly do NOT auto-update — every change
to the build environment is a deliberate commit, reviewed.

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
| Dockerfile builder image | ⏳ to author (PR welcome) |
| `scripts/verify-build.sh` | ✅ shipped (this PR) |
| Published manifest format | ✅ shipped (this doc) |
| First repro-verified release | ⏳ blocks on Dockerfile + release process |
| OSS-Fuzz / cosign / sigstore integration | ⏳ post-launch |

The Dockerfile + the first verified release are the remaining gates
before this is a guarantee, not a plan. ETA: pre-mainnet (October
2026), with intermediate releases through testnet.

## Pointers

- `Cargo.toml` — `profile.release` settings
- `scripts/verify-build.sh` — the verifier
- `docker/builder.Dockerfile` — the pinned build environment
  (to be authored)
- `releases@coincync.network` — release-signing PGP identity
- Reproducible Builds project: <https://reproducible-builds.org/> —
  the canonical reference for the field
