#!/usr/bin/env bash
# Probe the WSL environment for the toolchain we need to run the
# CoinCync test suite on Linux.

# Prepend the user's cargo bin dir so we pick up rustup's rust without
# relying on a login shell having sourced ~/.cargo/env.
export PATH="$HOME/.cargo/bin:$PATH"

echo "--- uname ---"
uname -a

echo "--- rust ---"
cargo --version 2>&1 || echo "cargo: MISSING"
rustc --version 2>&1 || echo "rustc: MISSING"

echo "--- build deps ---"
for tool in cmake gcc clang pkg-config; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf '  %-12s %s\n' "$tool" "$(command -v "$tool")"
    else
        printf '  %-12s %s\n' "$tool" "MISSING"
    fi
done

echo "--- libclang ---"
dpkg -l libclang-dev 2>/dev/null | tail -1 || echo "libclang-dev: NOT INSTALLED"
ls /usr/lib/llvm-* 2>/dev/null | head -3 || echo "(no /usr/lib/llvm-*)"

echo "--- libssl-dev ---"
dpkg -l libssl-dev 2>/dev/null | tail -1 || echo "libssl-dev: NOT INSTALLED"

echo "--- build-essential ---"
dpkg -l build-essential 2>/dev/null | tail -1 || echo "build-essential: NOT INSTALLED"
