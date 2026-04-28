#!/usr/bin/env python3
"""
Verify policy coverage for docs/BEST_PRACTICES_BY_FILE.md.

This script enforces that security-critical path groups are not downgraded
to `standard-review` or `asset-review`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "docs" / "BEST_PRACTICES_BY_FILE.md"

LINE_RE = re.compile(
    r"^\| `(?P<file>[^`]+)` \| (?P<profile>[^|]+) \| (?P<controls>[^|]+) \| (?P<baseline>[^|]+) \| `(?P<status>[^`]+)` \|$"
)


def required_status(path: str) -> str | None:
    if path.startswith("src/consensus/") or path in {
        "src/constants.rs",
        "src/consensus/difficulty.rs",
        "src/consensus/pow.rs",
        "critical_files.lock",
    }:
        return "priority-review"

    if path.startswith(("src/rpc/", "src/network/", "src/wallet/", "scripts/", "deploy/")):
        return "security-review"

    if path == "src/bin/node.rs":
        return "security-review"

    if path.startswith(("tests/", "fuzz/")):
        return "assurance-review"

    return None


def required_profile(path: str) -> str | None:
    if path.startswith(("src/consensus/", "src/constants.rs", "src/emission/")):
        return "Consensus-Critical"

    if path.startswith(("src/network/", "tests/network_", "tests/p2p_", "tests/adversarial")):
        return "P2P-Critical"

    if path.startswith(("src/rpc/", "tools/rpc-lib/", "docs/src/api/")):
        return "RPC-Surface"

    if path.startswith(("src/wallet/", "src/bin/wallet.rs", "coincync-wallet/", "miner-gui/")):
        return "Wallet-Key-Material"

    if path.startswith(("scripts/", "deploy/")):
        return "Ops-Automation"

    if path.startswith(("tests/", "fuzz/")):
        return "Assurance"

    return None


def parse_report() -> list[tuple[str, str, str]]:
    if not REPORT_PATH.exists():
        raise FileNotFoundError(f"missing report: {REPORT_PATH}")

    rows: list[tuple[str, str, str]] = []
    for line in REPORT_PATH.read_text(encoding="utf-8").splitlines():
        match = LINE_RE.match(line.strip())
        if match:
            rows.append(
                (
                    match.group("file"),
                    match.group("profile").strip(),
                    match.group("status").strip(),
                )
            )
    return rows


def main() -> int:
    rows = parse_report()
    if not rows:
        print("No table rows parsed from report; format may be invalid.", file=sys.stderr)
        return 2

    violations: list[str] = []
    for path, profile, status in rows:
        required_prof = required_profile(path)
        if required_prof is not None and profile != required_prof:
            violations.append(f"{path}: expected profile `{required_prof}`, got `{profile}`")

        required = required_status(path)
        if required is not None and status != required:
            violations.append(f"{path}: expected `{required}`, got `{status}`")

    if violations:
        print("Best-practices policy violations:", file=sys.stderr)
        for item in violations:
            print(f" - {item}", file=sys.stderr)
        return 1

    print(f"Policy verification passed for {len(rows)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
