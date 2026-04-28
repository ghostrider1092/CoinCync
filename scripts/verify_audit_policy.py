#!/usr/bin/env python3
"""
Verify Cargo audit policy is narrowly scoped.

This guardrail ensures we only allow the explicitly accepted advisory and
do not silently broaden ignore rules over time.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT_TOML = ROOT / ".cargo" / "audit.toml"
ALLOWED_IDS = {"RUSTSEC-2023-0089"}


def parse_ignored_ids(content: str) -> set[str]:
    # Parse all string literals that look like advisory IDs.
    # Keep this strict to reduce accidental policy drift.
    return set(re.findall(r'"(RUSTSEC-\d{4}-\d{4})"', content))


def main() -> int:
    if not AUDIT_TOML.exists():
        print(f"Missing audit policy file: {AUDIT_TOML}", file=sys.stderr)
        return 1

    content = AUDIT_TOML.read_text(encoding="utf-8")
    ids = parse_ignored_ids(content)

    if ids != ALLOWED_IDS:
        print("Audit policy violation:", file=sys.stderr)
        print(f" - expected ignored IDs: {sorted(ALLOWED_IDS)}", file=sys.stderr)
        print(f" - actual ignored IDs:   {sorted(ids)}", file=sys.stderr)
        return 1

    print(f"Audit policy verification passed: {sorted(ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
