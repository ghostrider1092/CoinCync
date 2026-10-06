#!/usr/bin/env bash
# 24-hour shielded (Spark) in-block consensus soak.
#
# Drives mint -> transfer(to a 2nd wallet) -> self-spend -> double-spend-reject
# -> reorg cycles through the REAL block hooks with live libspark proofs,
# asserting after every op: pool_value >= 0, no consensus halt, double-spend
# rejected, reorg restores an empty pool, and that a transfer's recipient (and
# only the recipient) recovers the output coin. Panics with the reproducing
# seed on any anomaly (src/chain.rs::soak_shielded_in_block_consensus).
#
# Usage:  scripts/soak-24h-shielded.sh [SECONDS]      (default 86400 = 24h)
#         SHIELDED_SOAK_SEED=<n> scripts/soak-24h-shielded.sh 3600
#
# Run it from a dedicated terminal (Git Bash). It builds --release first (the
# only step that needs OpenSSL for linking), then runs the self-contained
# binary. Output is redirected DIRECTLY to a timestamped log — no tee/pipe,
# which previously produced an empty release-build log.
set -euo pipefail

# This is a Windows MSVC build (libspark C++ + MSVC linker). It MUST run under
# Git Bash (MINGW64), NOT WSL/Linux bash — under WSL the paths and toolchain are
# wrong. On Windows `bash` often resolves to C:\Windows\System32\bash.exe (WSL);
# invoke Git Bash explicitly instead.
case "$(uname -s)" in
  MINGW*|MSYS*) : ;;
  *)
    echo "ERROR: this must run under Git Bash (MINGW64), not '$(uname -s)' (likely WSL)." >&2
    echo "Run it from a Git Bash terminal, or from PowerShell invoke Git Bash directly:" >&2
    echo '  & "C:\Program Files\Git\bin\bash.exe" scripts/soak-24h-shielded.sh' >&2
    exit 1
    ;;
esac

cd "$(dirname "$0")/.."

# --- Build/link environment (edit paths here if your toolchain differs) ------
export LIBCLANG_PATH="${LIBCLANG_PATH:-C:/Program Files/LLVM/bin}"
export PATH="/c/Program Files/LLVM/bin:$PATH"
# RandomX light mode: this soak does not mine, so it is harmless here.
export COINCYNC_RANDOMX_LIGHT_MODE=1
# Static OpenSSL prefix for the libspark C++ link. Copied out of the session
# scratchpad to a STABLE location so this works in any future session.
export SPARK_OPENSSL_DIR="${SPARK_OPENSSL_DIR:-C:/Users/unkno/dev/spark-openssl-static-md}"

SECS="${1:-86400}"
export SHIELDED_SOAK_SECS="$SECS"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="soak-shielded-${STAMP}.log"

if [ ! -f "$SPARK_OPENSSL_DIR/lib/libcrypto.lib" ]; then
  echo "ERROR: libcrypto.lib not found under SPARK_OPENSSL_DIR=$SPARK_OPENSSL_DIR" >&2
  echo "Point SPARK_OPENSSL_DIR at your vcpkg x64-windows-static-md prefix." >&2
  exit 1
fi

echo "Building --release soak binary (features: testnet sketch-gk-proof libspark-ffi)…"
cargo build --release --locked --lib \
  --features "testnet sketch-gk-proof libspark-ffi" 2>&1 | tail -3

echo "Starting shielded soak for ${SECS}s → ${LOG}"
echo "  (tail -f ${LOG} to watch; a clean finish prints 'SHIELDED SOAK OK: <n> … cycles')"
# --lib avoids compiling integration-test targets (a pre-existing librocksdb_sys
# rlib error on this toolchain). Direct redirect — do NOT pipe through tee.
cargo test --release --locked --lib \
  --features "testnet sketch-gk-proof libspark-ffi" \
  soak_shielded_in_block_consensus -- --ignored --nocapture > "$LOG" 2>&1

echo "Soak finished. Result:"
grep -iE "SHIELDED SOAK|test result|ANOMALY|panicked" "$LOG" | tail -5
