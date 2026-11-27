#!/usr/bin/env bash
#
# Cast-lint RATCHET gate for the CoinCync workspace.
#
# Every source surface that has been swept for lossy integer casts carries a
# file-level
#
#     #![deny(
#         clippy::cast_possible_truncation,
#         clippy::cast_sign_loss,
#         clippy::cast_lossless
#     )]
#
# The workspace baseline (Cargo.toml `[lints.clippy]`) sets `clippy::all = allow`
# but promotes these three cast lints to `warn`. So a PLAIN `cargo clippy` emits a
# WARNING for every remaining cast (including the not-yet-swept locked core) yet
# still EXITS 0 — warnings do not fail the exit code. A file's own
# `#![deny(clippy::cast_*)]` escalates those three to hard ERRORS within that file,
# so plain clippy exits non-zero EXACTLY when an already-swept (deny'd) file gains
# a new truncating / sign-losing / needless-lossless cast. That is the ratchet; the
# remaining warn-level backlog does NOT fail this gate. This script runs that plain
# clippy and additionally guards the `#![deny]` blocks themselves from removal.
#
# It deliberately does NOT touch the lock-protected consensus/emission core
# (critical_files.lock): those files carry no `#![deny]` yet and their casts are
# cleaned only inside a planned, reviewed, fingerprint-moving release — never by a
# lint sweep. So this gate neither requires nor expects them to be clean.
#
# Usage:
#   scripts/clippy-ratchet.sh          # CI gate (and a fine local pre-push check)
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Minimum number of file-level cast-deny blocks expected under src/. This is a
# FLOOR: it must never decrease. Raise it (in the same commit) whenever a new
# surface is swept and gains its `#![deny]` block. A drop means a ratchet was
# removed or weakened — which is exactly what this guard exists to catch.
BASELINE=89

sig='^    clippy::cast_possible_truncation,$'
count=$(grep -rE "$sig" src/ | wc -l | tr -d ' ')
if [ "$count" -lt "$BASELINE" ]; then
  echo "clippy-ratchet: FAIL — cast-deny blocks dropped to $count (floor $BASELINE)." >&2
  echo "A file-level #![deny(clippy::cast_*)] ratchet was removed or weakened." >&2
  echo "If that was deliberate, lower BASELINE in scripts/clippy-ratchet.sh in the SAME commit." >&2
  exit 1
fi

echo "clippy-ratchet: $count cast-deny'd files under src/ (floor $BASELINE). Running clippy…"

# PLAIN clippy — no `-D warnings`. Only the per-file #![deny(clippy::cast_*)]
# blocks promote a cast lint to an error, so a non-zero exit means a new lossy
# cast landed in an already-swept file. The broad warn-level backlog does NOT
# fail this gate (that is the separate, still-informational clippy job).
if cargo clippy --workspace --all-targets --features "randomx testnet"; then
  echo "clippy-ratchet: PASS — no new lossy casts in the $count ratcheted surfaces."
else
  echo "clippy-ratchet: FAIL — a ratcheted file has a lossy integer cast (see clippy output above)." >&2
  echo "Replace the \`as\` with a checked conversion (try_from / From) or, if the" >&2
  echo "truncation is intentional and bounded, a documented #[allow(...)] at the site." >&2
  exit 1
fi
