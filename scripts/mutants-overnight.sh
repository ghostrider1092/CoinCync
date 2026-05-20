#!/usr/bin/env bash
# scripts/mutants-overnight.sh
#
# Mutation-testing pass across the four crypto-critical cyncswap files
# (strict_dleq, adaptor, cync, btc — per docs/cyncswap-audit-prep.md §5).
#
# cargo-mutants flips operators / constants / returns / match arms and
# re-runs the test suite per mutation; MISSED = tests still pass (bad,
# means a test gap), CAUGHT = tests fail (good).
#
# This runs against the .cargo/mutants.toml config, so the scope is
# fixed — running with different args is intentionally not supported.
# Per-file summary lands in mutants-overnight-report.txt.
#
# Usage:
#   nohup bash scripts/mutants-overnight.sh > ~/mutants-overnight.log 2>&1 &
#   tail -f ~/mutants-overnight.log
#
# Output:
#   mutants.out/                      cargo-mutants result tree
#   mutants.out/outcomes.json         per-mutant verdicts (machine-readable)
#   mutants.out/missed.txt            list of mutants the suite did NOT catch
#   mutants.out/caught.txt            list of mutants the suite DID catch
#   ~/mutants-overnight-report.txt    final per-file summary table
#
# Expected runtime: 4-8 hours on a warm cache. The four scoped files
# total ~7,200 LOC; cargo-mutants typically generates 1 mutant per
# 15-25 lines, so expect 300-500 mutants × baseline test time.

set -u  # don't `-e` — we want the summary even if cargo-mutants exits non-zero

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || { echo "fatal: cannot cd to repo root" >&2; exit 2; }

REPORT="$HOME/mutants-overnight-report.txt"
RESULTS="mutants.out"   # cargo-mutants writes here by default

# ─── 0. Sanity ────────────────────────────────────────────────────

if ! command -v cargo-mutants >/dev/null 2>&1 && ! cargo mutants --version >/dev/null 2>&1; then
    echo "fatal: cargo-mutants not installed. Install with: cargo install cargo-mutants --locked" >&2
    exit 2
fi

START_TIME=$(date +%s)
echo "═══════════════════════════════════════════════════════════════"
echo " cargo-mutants overnight run"
echo " started: $(date -Iseconds)"
echo " commit:  $(git rev-parse --short HEAD)"
echo " branch:  $(git rev-parse --abbrev-ref HEAD)"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. Baseline check ───────────────────────────────────────────
# cargo-mutants does this internally with --baseline=run (the default),
# but doing it explicitly first surfaces compile/test failures faster
# and with cleaner error output.

echo
echo "[1/2] Verifying baseline: cargo test -p coincync-swap --features strict-dleq"
if ! cargo test -p coincync-swap --features strict-dleq --quiet 2>&1 | tail -5; then
    echo "fatal: baseline tests failed; not running mutants" >&2
    exit 3
fi

# ─── 2. Run mutants ──────────────────────────────────────────────

echo
echo "[2/2] Running cargo mutants -p coincync-swap"
echo "      scope: .cargo/mutants.toml examine_globs"
echo "      output: ./$RESULTS/"
echo

# --no-shuffle: deterministic ordering — easier to compare runs.
# Exit code: 0 = all mutants caught; 1 = at least one MISSED; 2+ = error.
cargo mutants \
    -p coincync-swap \
    --no-shuffle 2>&1
MUTANTS_EXIT=$?

# ─── 3. Per-file summary ─────────────────────────────────────────

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ELAPSED_HR=$((ELAPSED / 3600))
ELAPSED_MIN=$(((ELAPSED % 3600) / 60))

{
    echo "═══════════════════════════════════════════════════════════════"
    echo " cargo-mutants overnight report"
    echo " ended:    $(date -Iseconds)"
    echo " elapsed:  ${ELAPSED_HR}h ${ELAPSED_MIN}m"
    echo " commit:   $(git rev-parse --short HEAD)"
    echo " exit:     $MUTANTS_EXIT  (0=all caught, 1=at least one missed)"
    echo "═══════════════════════════════════════════════════════════════"
    echo

    if [ -f "$RESULTS/missed.txt" ] && [ -f "$RESULTS/caught.txt" ]; then
        MISSED=$(wc -l < "$RESULTS/missed.txt" | tr -d ' ')
        CAUGHT=$(wc -l < "$RESULTS/caught.txt" | tr -d ' ')
        TIMEOUT=$([ -f "$RESULTS/timeout.txt" ] && wc -l < "$RESULTS/timeout.txt" | tr -d ' ' || echo 0)
        UNVIABLE=$([ -f "$RESULTS/unviable.txt" ] && wc -l < "$RESULTS/unviable.txt" | tr -d ' ' || echo 0)
        TOTAL=$((MISSED + CAUGHT + TIMEOUT + UNVIABLE))

        echo "TOTALS:"
        printf "  caught:    %4d   ✓\n" "$CAUGHT"
        printf "  missed:    %4d   %s\n" "$MISSED" "$([ "$MISSED" -gt 0 ] && echo "✗ — investigate" || echo "")"
        printf "  timeout:   %4d\n" "$TIMEOUT"
        printf "  unviable:  %4d   (wouldn't compile — expected)\n" "$UNVIABLE"
        printf "  total:     %4d\n" "$TOTAL"
        echo

        if [ "$TOTAL" -gt 0 ] && [ $((MISSED + CAUGHT)) -gt 0 ]; then
            SCORE=$(awk -v c="$CAUGHT" -v m="$MISSED" 'BEGIN { printf "%.1f", c * 100 / (c + m) }')
            echo "MUTATION SCORE: ${SCORE}%   (caught / (caught + missed))"
            echo
        fi

        echo "PER-FILE BREAKDOWN (top of missed.txt):"
        echo "──────────────────────────────────────────────────────────────"
        if [ "$MISSED" -gt 0 ]; then
            awk -F: '{ print $1 }' "$RESULTS/missed.txt" | sort | uniq -c | sort -rn | head -20
        else
            echo "  (no missed mutants — every mutation caught by the test suite)"
        fi
        echo
        echo "Full machine-readable report:  $RESULTS/outcomes.json"
        echo "Missed mutants:                $RESULTS/missed.txt"
    else
        echo "warning: $RESULTS/missed.txt and/or caught.txt not found — cargo-mutants may have errored before completing"
        echo "check the cargo-mutants stderr above"
    fi
} | tee "$REPORT"

exit $MUTANTS_EXIT
