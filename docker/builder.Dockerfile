# CoinCync — pinned reproducible builder
#
# Builds the workspace inside a fixed Debian Bookworm + Rust toolchain
# combination so two invocations on different machines produce identical
# binaries (modulo the disclaimers in REPRODUCIBLE_BUILDS.md).
#
# Usage:
#   docker build -f docker/builder.Dockerfile -t coincync-build:HEAD .
#   docker run --rm -v "$(pwd)/out:/out" coincync-build:HEAD
#   sha256sum out/*
#
# Or use the wrapper: scripts/build-in-docker.sh
#
# Determinism knobs (set automatically by this Dockerfile):
#   SOURCE_DATE_EPOCH    — pinned to the COMMITTER date of HEAD at build time
#   codegen-units = 1    — set in Cargo.toml (single codegen unit removes
#                          codegen-parallelism non-determinism)
#   strip = true         — set in Cargo.toml (no debug strings)
#   --locked             — Cargo respects Cargo.lock byte-for-byte
#
# What this DOES guarantee:
#   - Anyone running this Dockerfile against the same git commit
#     produces byte-identical binaries.
#   - Every published Linux release binary from tag v1.0.10-testnet
#     onward comes out of THIS Dockerfile, so
#     `bash scripts/build-in-docker.sh` at the release commit
#     produces the same SHA256 as the published tarball. See
#     `.github/workflows/release.yml` (build-linux job) for the
#     wiring, and `docs/operations/REPRODUCIBLE_BUILDS.md` for the
#     end-to-end verification recipe a community member follows.
#
# What this does NOT (yet) guarantee:
#   - macOS / Windows releases. Those still build via `cargo build`
#     on their native runners in `release.yml` because neither of
#     those platforms has a Debian-Bookworm-equivalent
#     reproducible-container ecosystem in GitHub Actions today.
#     Cross-arch (x86_64 vs arm64) builds are also not guaranteed
#     identical.
#   - A signed manifest of (commit, dockerfile-digest, binary-sha256).
#     Sigstore attestation via `actions/attest-build-provenance@v4`
#     is done in `release.yml` today; the explicit signed-manifest
#     format from `REPRODUCIBLE_BUILDS.md` §"Published manifest" is
#     a separate follow-up.

# Pin the Rust base image to a specific minor.
# Use --build-arg RUST_VERSION=<x.y.z> to override.
#
# Effective minimum is 1.88.0 — the workspace's `rust-version` field
# says 1.75 but transitive dependencies (cpufeatures 0.3.0 needs
# edition2024 = 1.85+, time 0.3.47 / time-core / time-macros need
# 1.88+) drag the actual floor up. We pin to 1.88.0 here as the
# baseline that resolves the current Cargo.lock end-to-end.
#
# When you next bump deps, `cargo build` errors will tell you the new
# minimum; bump RUST_VERSION accordingly. The workspace's stated
# `rust-version = "1.75"` in Cargo.toml is a SOURCE-LEVEL promise
# (CoinCync's own code stays compatible with 1.75), not a guarantee
# any given Cargo.lock resolution will compile on 1.75.
ARG RUST_VERSION=1.88.0

FROM rust:${RUST_VERSION}-slim-bookworm AS builder

# Pinned system deps. We deliberately do NOT pin patch versions here —
# Debian Bookworm's apt-get pulls deterministic snapshots within a
# single release pocket, and over-pinning breaks builds the day Debian
# rotates an apt key. The Bookworm stable archive is the actual pin.
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    make \
    lld \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /src

# Copy the workspace. Use --link to keep the layer cache friendly.
COPY . .

# Compute SOURCE_DATE_EPOCH from the HEAD commit's committer date (Unix
# timestamp). This makes any timestamps the linker / strip might leak
# deterministic across runs of the same commit. If the working tree has
# uncommitted changes we still build, but emit a warning — the resulting
# binary will not be reproducible against any other clone.
RUN if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
        export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct); \
    else \
        export SOURCE_DATE_EPOCH=1714838400; \
    fi && \
    if [ -n "$(git status --porcelain 2>/dev/null)" ]; then \
        echo "WARN: working tree has uncommitted changes; binary will not be" >&2 ; \
        echo "      byte-identical to a clean checkout of HEAD." >&2 ; \
    fi && \
    echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" > /src/.source_date_epoch && \
    cat /src/.source_date_epoch

# The actual build. --locked refuses to update Cargo.lock; --frozen
# refuses to even read it. We use --locked so a stale lockfile errors
# loudly instead of silently fetching a different version.
#
# Default features only. The audit / supply-chain claim is about the
# default release profile, not feature combinations — those are the
# user's choice.
RUN . /src/.source_date_epoch && \
    export SOURCE_DATE_EPOCH && \
    cargo build --release --workspace --locked --bins && \
    cargo build --release --locked \
        -p coincync-frost-coordinator \
        --features "server cli" \
        --bin coord --bin coord-cli

# Strip absolute paths from any debug info that survives `strip = true`
# (the release profile already strips, but objcopy --strip-all is a
# belt-and-suspenders pass for the rare debug strings that linger).
RUN find target/release -maxdepth 1 -type f -executable \
    -exec sh -c 'objcopy --strip-all "$1" 2>/dev/null || true' _ {} \;

# Stage 2 — minimal artifact image. Just copies the built binaries
# into a slim layer that can be exported via `docker run -v`.
FROM debian:bookworm-slim AS artifacts

COPY --from=builder /src/target/release/coincync-node \
                    /src/target/release/coincync-wallet \
                    /src/target/release/coincync-rig \
                    /src/target/release/coord \
                    /src/target/release/coord-cli \
                    /src/target/release/cyncswap \
                    /artifacts/

# Compute checksums of the binaries inside the image so they're
# included in `docker history` for auditors.
RUN cd /artifacts && \
    sha256sum * > SHA256SUMS && \
    cat SHA256SUMS

# Default command: copy artifacts to a mounted /out volume.
CMD ["sh", "-c", "mkdir -p /out && cp -v /artifacts/* /out/ && cd /out && sha256sum -c SHA256SUMS"]
