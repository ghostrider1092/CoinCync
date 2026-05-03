# ── Stage 1: Build ────────────────────────────────────────────
FROM rust:1.75-slim AS builder

RUN apt-get update && apt-get install -y \
    cmake \
    clang \
    libclang-dev \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies by copying Cargo files first
COPY Cargo.toml Cargo.lock build.rs ./
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/bin/node.rs && \
    echo 'fn main() {}' > src/bin/wallet.rs && \
    echo 'pub fn main() {}' > src/lib.rs && \
    cargo build --release --features "testnet" 2>/dev/null || true && \
    rm -rf src/

# Build the real source
COPY . .
ARG NETWORK=testnet
RUN cargo build --release --features "${NETWORK}"

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    libgcc-s1 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=builder /build/target/release/coincync-node   /usr/local/bin/
COPY --from=builder /build/target/release/coincync-wallet /usr/local/bin/
COPY --from=builder /build/target/release/coincync-miner  /usr/local/bin/

# Create data directory
RUN useradd -r -s /bin/false coincync && \
    mkdir -p /data && \
    chown coincync:coincync /data

USER coincync
VOLUME ["/data"]

# P2P, RPC, Metrics
EXPOSE 28333 28332 9091

ENTRYPOINT ["coincync-node"]
CMD ["--data-dir", "/data", "--network", "testnet", "--p2p-bind", "0.0.0.0:28333", "--rpc-bind", "0.0.0.0:28332", "--metrics-bind", "0.0.0.0:9091"]

# ── Stage 3: Export binaries without running ──────────────────
FROM scratch AS export
COPY --from=builder /build/target/release/coincync-node   .
COPY --from=builder /build/target/release/coincync-wallet .
COPY --from=builder /build/target/release/coincync-miner  .
