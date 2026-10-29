#!/usr/bin/env bash
# scripts/cyncswap-audit-smoke.sh
#
# The script the audit firm runs after `git clone` to verify the
# perimeter state matches what docs/cyncswap-audit-prep.md claims.
# Pure-read; never mutates anything. Exits non-zero on any drift.
#
# Usage (auditor side):
#   bash scripts/cyncswap-audit-smoke.sh
#   # …or with explicit feature-flag pinning for both modes…
#   FAST_ONLY=1   bash scripts/cyncswap-audit-smoke.sh   # skips the DLEQ v2 stage
#   STRICT_ONLY=1 bash scripts/cyncswap-audit-smoke.sh   # skips default run
#
# Exit codes:
#   0  — every check matches docs/cyncswap-audit-prep.md
#   2  — environment / toolchain / sanity problem (auditor side)
#   3  — test-suite counts drifted from the doc
#   4  — reproducibility vectors don't regenerate identically (RNG drift)
#   5  — property tests didn't run (likely a feature-flag misuse)
#
# Wall-clock: ~5 min on a warm cargo cache, ~15 min cold. The v2
# cross-curve DLEQ suite is the slowest part (each case is a full
# 252-bit proof); FAST_ONLY=1 skips its dedicated stage.

set -u  # don't `-e` — we want to keep going so the auditor sees every drift

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || { echo "fatal: cannot cd to repo root" >&2; exit 2; }

# ─── 0. Pretty-print helpers ─────────────────────────────────────
red()    { printf "\033[0;31m%s\033[0m\n" "$*"; }
green()  { printf "\033[0;32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[0;33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n"   "$*"; }

# `cargo test` prints one `test result:` line per test binary (lib, each
# integration test, doc-tests). Sum the passed counts over all of them;
# the last line, or the first match in the last few lines, is usually the
# doc-test summary ("0 passed") and under-reports the suite.
sum_passed() {
    grep -E "^test result: " | grep -oE "[0-9]+ passed" \
        | awk '{ total += $1 } END { print total + 0 }'
}

bold "═══════════════════════════════════════════════════════════════"
bold " cyncswap audit smoke test"
bold "═══════════════════════════════════════════════════════════════"
echo " commit:    $(git rev-parse --short HEAD 2>/dev/null || echo '(not a git repo)')"
echo " branch:    $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
echo " host:      $(uname -mrs 2>/dev/null || echo '?')"
echo " rustc:     $(rustc --version 2>/dev/null || echo 'rustc NOT FOUND')"
echo " cargo:     $(cargo --version 2>/dev/null || echo 'cargo NOT FOUND')"
echo

EXIT=0

# ─── 1. Toolchain sanity ─────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
    red "fatal: cargo not on PATH"
    exit 2
fi
if ! command -v rustc >/dev/null 2>&1; then
    red "fatal: rustc not on PATH"
    exit 2
fi

# ─── 2. Build clean + run default-feature tests ──────────────────
if [ "${STRICT_ONLY:-}" != "1" ]; then
    bold "─── default-feature build + test ──────────────────────────────"
    echo "Running: cargo test -p coincync-swap --quiet"
    DEFAULT_OUT=$(cargo test -p coincync-swap --quiet 2>&1)
    DEFAULT_STATUS=$?
    echo "$DEFAULT_OUT" | grep -E "^test result: "
    # audit-prep §10 expects 192+ tests under default features (with
    # the post-2026-05-20 +24 mutation-testing tests, the count is 216+).
    if [ "$DEFAULT_STATUS" -eq 0 ]; then
        DEFAULT_COUNT=$(echo "$DEFAULT_OUT" | sum_passed)
        if [ "$DEFAULT_COUNT" -lt 192 ]; then
            red "  ✗ default-feature test count $DEFAULT_COUNT < 192 (audit-prep §10 floor)"
            EXIT=3
        else
            green "  ✓ default-feature: $DEFAULT_COUNT tests passed (≥ 192 floor)"
        fi
    else
        red "  ✗ default-feature test suite FAILED — re-run with full output"
        EXIT=3
    fi
    echo
fi

# ─── 3. Cross-curve DLEQ (v2) suite ──────────────────────────────
# The v1 `strict-dleq` feature is gone; v2 is always compiled. This
# stage isolates its unit tests (soundness and encoding adversaries)
# so a regression there is reported on its own line.
if [ "${FAST_ONLY:-}" != "1" ]; then
    bold "─── cross-curve DLEQ v2 tests ─────────────────────────────────"
    echo "Running: cargo test -p coincync-swap --lib cross_curve_dleq --quiet"
    DLEQ_OUT=$(cargo test -p coincync-swap --lib cross_curve_dleq --quiet 2>&1)
    DLEQ_STATUS=$?
    echo "$DLEQ_OUT" | grep -E "^test result: "
    DLEQ_COUNT=$(echo "$DLEQ_OUT" | sum_passed)
    if [ "$DLEQ_STATUS" -eq 0 ] && [ "$DLEQ_COUNT" -gt 0 ]; then
        green "  ✓ cross-curve DLEQ v2: $DLEQ_COUNT tests passed"
    else
        red "  ✗ cross-curve DLEQ v2 test suite FAILED or ran no tests"
        EXIT=3
    fi
    echo
fi

# ─── 4. Reproducibility vectors regenerate identically ───────────
bold "─── reproducibility vector regeneration ──────────────────────"
VECTORS_DIR="crates/coincync-swap/test-vectors/reproducibility"
if [ -d "$VECTORS_DIR" ]; then
    BEFORE_HASH=$(find "$VECTORS_DIR" -name "*.json" -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | awk '{print $1}')
    echo "Pre-regen   hash: $BEFORE_HASH"
    cargo run -p coincync-swap --example gen_reproducibility_vectors --quiet 2>&1 | tail -3
    AFTER_HASH=$(find "$VECTORS_DIR" -name "*.json" -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | awk '{print $1}')
    echo "Post-regen  hash: $AFTER_HASH"
    if [ "$BEFORE_HASH" = "$AFTER_HASH" ]; then
        green "  ✓ vectors regenerated bit-identically — no RNG drift"
    else
        red "  ✗ vectors regenerated to different bytes — RNG drift or non-determinism"
        echo "    diff:"
        git diff --stat "$VECTORS_DIR" 2>&1 | sed 's/^/    /'
        EXIT=4
    fi
else
    yellow "  ! $VECTORS_DIR not present — skipping vector check"
fi
echo

# ─── 5. Property tests are actually being run ────────────────────
bold "─── property tests exercised ──────────────────────────────────"
# Select the property-test binaries with `--test`. A bare
# `property_invariants` argument is a test-NAME filter, and no test
# function is named that, so it ran zero property tests.
PROP_OUT=$(cargo test -p coincync-swap --quiet \
    --test property_invariants \
    --test property_invariants_cync \
    --test state_machine_invariants 2>&1)
PROP_STATUS=$?
echo "$PROP_OUT" | grep -E "^test result: "
PROP_COUNT=$(echo "$PROP_OUT" | sum_passed)
if [ "$PROP_STATUS" -eq 0 ] && [ "$PROP_COUNT" -gt 0 ]; then
    green "  ✓ property tests ran: $PROP_COUNT passed"
else
    red "  ✗ property tests failed or did not run"
    EXIT=5
fi
echo

# ─── 6. Cargo.lock present + non-empty ───────────────────────────
bold "─── Cargo.lock dependency integrity ──────────────────────────"
if [ -f Cargo.lock ]; then
    LOCK_HASH=$(sha256sum Cargo.lock | awk '{print $1}')
    echo "  Cargo.lock sha256: $LOCK_HASH"
    echo "  Out-of-band, the operator should provide the expected hash"
    echo "  per docs/cyncswap-audit-prep.md §9. Compare manually."
else
    red "  ✗ Cargo.lock missing — auditor cannot verify dependency tree"
    EXIT=2
fi
echo

# ─── 7. Final verdict ────────────────────────────────────────────
bold "═══════════════════════════════════════════════════════════════"
if [ "$EXIT" -eq 0 ]; then
    green " AUDIT SMOKE: PASS"
    green " Perimeter matches docs/cyncswap-audit-prep.md."
else
    red " AUDIT SMOKE: FAIL (exit $EXIT)"
    red " See above for which check drifted from the doc."
fi
bold "═══════════════════════════════════════════════════════════════"

exit $EXIT
