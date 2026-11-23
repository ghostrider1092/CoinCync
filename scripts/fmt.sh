#!/usr/bin/env bash
#
# Format the CoinCync workspace while keeping the lock-protected consensus core
# byte-stable. Use this instead of `cargo fmt --all`.
#
# Why a wrapper? rustfmt's own `ignore` option is nightly-only — on the pinned
# stable toolchain (rust-toolchain.toml) it is silently dropped and
# `cargo fmt --all` reformats the locked consensus core, moving
# critical_files.lock hashes and handing the audit firm cosmetic churn. So we let
# cargo fmt format the workspace (it correctly resolves per-crate editions) and
# then restore the lock-protected files from HEAD. The audited core is reformatted
# only as a separate, deliberate, reviewed act (docs/design/modernization-roadmap.md,
# Tier-1c) — never incidentally.
#
# Usage: scripts/fmt.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

cargo fmt --all

# Restore every lock-protected *.rs file (the audited consensus core).
restored=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  git checkout -- "$f" 2>/dev/null && restored=$((restored + 1))
done < <(grep -E '\.rs=' critical_files.lock | sed 's/=.*//' | tr -d '\r' | sort -u)

echo "formatted the workspace; restored $restored lock-protected consensus file(s) to keep them byte-stable."
