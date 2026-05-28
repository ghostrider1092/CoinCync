#!/usr/bin/env bash
# kani-check.sh — run the full Kani proof suite on the CoinCync codebase.
#
# Kani (https://github.com/model-checking/kani) is AWS's bounded model
# checker for Rust. It proves properties about pure-function code by
# symbolic execution / SAT solving rather than fuzzing — where cargo-fuzz
# tries random inputs, kani provably enumerates ALL inputs within bounds.
#
# Kani is Linux-only; from Windows, run inside WSL Ubuntu:
#
#     wsl -- bash /mnt/c/dev/coincync/scripts/kani-check.sh
#
# First-time setup:
#
#     cargo install --locked kani-verifier
#     cargo kani setup
#
# Setup downloads ~1 GB of CBMC + internal Rust toolchain. It is a one-time
# operation; subsequent runs use the cached toolchain.
#
# Proof harnesses are gated behind #[cfg(kani)] so they have no impact on
# the normal release binary. The cfg(kani) marker is registered in
# build.rs so non-kani builds don't warn about unexpected cfg.

set -uo pipefail

cd "$(dirname "$0")/.."

echo "===================================================================="
echo "  Kani proof suite — CoinCync"
echo "===================================================================="
echo "  started: $(date -u +%FT%TZ)"
echo

# Verify kani is installed before launching.
if ! command -v cargo-kani >/dev/null 2>&1; then
    echo "ERROR: cargo-kani not found in PATH." >&2
    echo "       Install with: cargo install --locked kani-verifier" >&2
    echo "       Then run:     cargo kani setup" >&2
    exit 127
fi

# Each kani run compiles the library against kani's bundled nightly,
# then CBMCs each #[kani::proof] harness. Default solver is CaDiCaL;
# minisat is also bundled. --output-format terse keeps the log readable.
#
# The proof modules live at:
#   src/kani_proofs.rs                 (constants helpers)
#   src/emission/kani_proofs.rs        (emission curve)
#
# Add new modules behind cfg(kani) in src/<area>/kani_proofs.rs and
# wire from the parent mod via `#[cfg(kani)] mod kani_proofs;`.

START=$(date +%s)
cargo kani --output-format terse
RC=$?
END=$(date +%s)

echo
echo "===================================================================="
echo "  Done in $((END - START))s. Exit: $RC"
echo "===================================================================="
exit $RC
