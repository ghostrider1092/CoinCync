#!/usr/bin/env bash
# scripts/fuzz-wsl-setup.sh
#
# One-shot setup of cargo-fuzz inside Ubuntu/WSL (or any Debian-derived
# Linux). Installs the prerequisites and prints next-step commands.
#
# WHY WSL: cargo-fuzz on Windows needs the LLVM compiler-rt ASAN runtime
# (`clang_rt.asan_*.lib`), which isn't bundled with MSVC Build Tools.
# Linux ships ASAN out of the box. Same fuzz harness, full coverage,
# zero Windows-link errors.
#
# USAGE (run this from inside WSL Ubuntu, NOT from Windows PowerShell):
#
#   1. Open WSL:  wsl -d Ubuntu
#   2. Clone:     git clone https://github.com/<you>/coincync.git ~/coincync
#                 (or rsync from your Windows-side checkout — see note below)
#   3. cd ~/coincync && bash scripts/fuzz-wsl-setup.sh
#   4. Pick a fuzz target and run (this script prints the command).
#
# NOTE on path performance: clone into the WSL filesystem (~/...) NOT
# /mnt/c/...  — the /mnt/c/ bridge is 10× slower for any I/O-heavy
# operation, which a cargo build very much is.

set -euo pipefail

cyan()  { printf "\033[0;36m%s\033[0m\n" "$*"; }
green() { printf "\033[0;32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[0;33m%s\033[0m\n" "$*"; }
red()   { printf "\033[0;31m%s\033[0m\n" "$*"; }

# ── sanity: are we in Linux? ────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
  red "This script must run from Linux / WSL. Detected: $(uname -s)"
  red "On Windows: open WSL first (\`wsl -d Ubuntu\`) then re-run."
  exit 1
fi

# ── sanity: are we in the repo? ─────────────────────────────────────
if [[ ! -d "fuzz/fuzz_targets" ]]; then
  red "Run from the coincync repo root (fuzz/fuzz_targets/ not found)."
  exit 1
fi

# ── sanity: path performance warning ────────────────────────────────
if [[ "$(pwd)" == /mnt/c/* ]] || [[ "$(pwd)" == /mnt/d/* ]]; then
  yellow "WARN: you're under /mnt/c/ which is 10× slower for I/O."
  yellow "Move the checkout into the WSL filesystem (e.g. ~/coincync) for"
  yellow "a usable cargo-fuzz iteration loop. Continuing anyway."
fi

cyan "==> 1/4  apt prereqs"
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev \
                            curl git cmake

cyan "==> 2/4  rust + cargo-fuzz"
if ! command -v rustup >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
       --default-toolchain stable
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi
rustup install nightly
rustup component add rust-src --toolchain nightly
if ! command -v cargo-fuzz >/dev/null; then
  cargo install --locked cargo-fuzz
fi

cyan "==> 3/4  verify build (compile only, no run)"
# A cold build the first time can take 5-15 minutes for this dep tree.
# We do it now so the actual fuzz commands launch instantly.
cd fuzz
cargo +nightly fuzz build fuzz_p2p_message
cd ..

cyan "==> 4/4  ready"
green "cargo-fuzz is installed and the harness compiles."
echo
echo "Next: run one of these (CTRL-C to stop)."
echo
echo "  # 60-second smoke (good to confirm everything works)"
echo "  cargo +nightly fuzz run fuzz_p2p_message -- -max_total_time=60"
echo
echo "  # 1-hour overnight pass (real bugs start to surface here)"
echo "  cargo +nightly fuzz run fuzz_p2p_message -- -max_total_time=3600"
echo
echo "  # Other targets:"
for t in fuzz_block fuzz_clsag fuzz_stealth fuzz_transaction; do
  echo "    cargo +nightly fuzz run $t -- -max_total_time=3600"
done
echo
echo "  # Seed corpus dirs (drop known-valid inputs here):"
echo "    audit-suite/corpus/{wire-frames,rpc-bodies,state-file-json,...}/"
echo
echo "  # Crash artifacts land at:"
echo "    fuzz/artifacts/<target>/crash-*"
echo "  Promote each triaged crash to audit-suite/regression-corpus/cves.json."
