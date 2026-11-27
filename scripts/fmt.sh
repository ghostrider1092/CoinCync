#!/usr/bin/env bash
#
# Format (or --check) the CoinCync workspace while keeping the lock-protected
# consensus core BYTE-STABLE. Use this instead of `cargo fmt --all`.
#
# Why a wrapper? rustfmt's own `ignore` option is nightly-only — on the pinned
# stable toolchain (rust-toolchain.toml) it is silently dropped and
# `cargo fmt --all` reformats the locked consensus core, moving
# critical_files.lock hashes and handing the audit firm cosmetic churn. And raw
# `rustfmt <file>` recurses `mod` declarations from a crate root back into the
# locked files, so a file-list exclusion does not work either. So we let cargo fmt
# format the workspace (it resolves per-crate editions and the module tree) and
# then restore the lock-protected files from HEAD. The audited core is reformatted
# only as a separate, deliberate, reviewed act (docs/design/modernization-roadmap.md,
# Tier-1c).
#
# Usage:
#   scripts/fmt.sh            # format in place, leaving the locked core untouched
#   scripts/fmt.sh --check    # CI gate: fail if any NON-locked file is unformatted
#
# --check formats to compare, so it requires a clean working tree and restores it
# afterwards. cargo fmt --check's own exit code is unreliable here, which is why
# the gate is built on `git diff` instead.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

mode=write
[ "${1:-}" = "--check" ] && mode=check

restore_locked() {
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    git checkout -- "$f" 2>/dev/null || true
  done < <(grep -E '\.rs=' critical_files.lock | sed 's/=.*//' | tr -d '\r' | sort -u)
}

if [ "$mode" = check ]; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "fmt.sh --check: working tree must be clean (it formats in place to compare)." >&2
    echo "Commit or stash your changes first." >&2
    exit 2
  fi
  cargo fmt --all
  restore_locked
  if git diff --quiet; then
    echo "format check: clean (lock-protected consensus core excluded)."
    exit 0
  fi
  echo "format check FAILED — these non-locked files are not rustfmt-clean:" >&2
  git diff --name-only >&2
  echo "Run scripts/fmt.sh to fix." >&2
  git checkout -- . # safe: the tree was clean before this ran
  exit 1
fi

cargo fmt --all
restored=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  git checkout -- "$f" 2>/dev/null && restored=$((restored + 1))
done < <(grep -E '\.rs=' critical_files.lock | sed 's/=.*//' | tr -d '\r' | sort -u)
echo "formatted the workspace; restored $restored lock-protected consensus file(s) to keep them byte-stable."
