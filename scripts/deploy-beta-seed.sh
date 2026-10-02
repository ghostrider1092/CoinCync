#!/usr/bin/env bash
# Deploy a CoinCync BETA-channel seed node, co-located on an existing box (e.g.
# the testnet seed). Builds the beta-channel binary WITH the shielded engine,
# installs it as /usr/local/bin/coincync-node-beta, and sets up the
# coincync-beta-seed systemd service (separate user/data-dir/ports from testnet).
#
# Run from a `beta-channel` checkout, as root (or via sudo), on the Linux box:
#   git fetch origin && git checkout beta-channel && git pull
#   sudo SPARK_OPENSSL_DIR=/opt/openssl-static-md BETA_PAYOUT=<addr> \
#        bash scripts/deploy-beta-seed.sh
#
# Env:
#   SPARK_OPENSSL_DIR   (optional) OpenSSL prefix override for the libspark link;
#                       by default build.rs finds libcrypto via pkg-config.
#   BETA_PAYOUT         (optional) beta payout address → the seed also mines.
#   BETA_MINE_THREADS   (optional, default 2) mining threads when BETA_PAYOUT set.
#   RANDOMX_LIGHT       (optional) set to 1 for low-memory RandomX (~256 MB vs ~2 GB).
set -euo pipefail

# OpenSSL for the libspark link is found via pkg-config (libssl-dev). Only
# export an override if the caller set one (e.g. a dedicated static build).
if [ -n "${SPARK_OPENSSL_DIR:-}" ]; then
  export SPARK_OPENSSL_DIR
fi
BETA_PAYOUT="${BETA_PAYOUT:-}"
BETA_MINE_THREADS="${BETA_MINE_THREADS:-2}"
RANDOMX_LIGHT="${RANDOMX_LIGHT:-0}"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

echo "==> Installing build prerequisites (clang/libclang + OpenSSL dev) …"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y build-essential clang libclang-dev pkg-config libssl-dev cmake
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y gcc gcc-c++ clang clang-devel openssl-devel pkgconfig cmake
else
  echo "    (unknown package manager — ensure a C++ toolchain, clang/libclang, and OpenSSL dev headers are present)"
fi
export LIBCLANG_PATH="${LIBCLANG_PATH:-$(llvm-config --libdir 2>/dev/null || echo /usr/lib)}"

echo "==> Building beta node (features: testnet,sketch-gk-proof,libspark-ffi) …"
echo "    NOTE: this is a full libspark (C++) build — CPU/memory-heavy. On a box"
echo "    that also runs the live testnet node, expect a load spike during the build."
cargo build --release --features "testnet,sketch-gk-proof,libspark-ffi" --bin coincync-node

echo "==> Installing binary → /usr/local/bin/coincync-node-beta"
install -m 0755 target/release/coincync-node /usr/local/bin/coincync-node-beta

echo "==> Creating service user + data dir"
id -u coincync-beta >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin coincync-beta
install -d -o coincync-beta -g coincync-beta /var/lib/coincync-beta

echo "==> Writing /etc/coincync/beta.env"
install -d /etc/coincync
if [ -n "$BETA_PAYOUT" ]; then
  mine_args="--mine $BETA_PAYOUT --mine-threads $BETA_MINE_THREADS"
else
  mine_args=""
  echo "    (no BETA_PAYOUT → seed validates/relays only; set BETA_PAYOUT to also mine)"
fi
{
  echo "BETA_MINE_ARGS=$mine_args"
  [ "$RANDOMX_LIGHT" = "1" ] && echo "COINCYNC_RANDOMX_LIGHT_MODE=1"
} > /etc/coincync/beta.env
chmod 0644 /etc/coincync/beta.env

echo "==> Installing + starting systemd service"
install -m 0644 scripts/coincync-beta-seed.service /etc/systemd/system/coincync-beta-seed.service
systemctl daemon-reload
systemctl enable --now coincync-beta-seed.service

echo "==> Done. Open the P2P port so testers can reach it:"
echo "    sudo ufw allow 29080/tcp    # (or your firewall equivalent)"
echo "    Testers then: --addnode <this-box-public-ip>:29080"
echo "==> Logs: journalctl -u coincync-beta-seed -f"
