#!/usr/bin/env python3
"""
Generate a per-file blockchain best-practices report for this repository.

Output: docs/BEST_PRACTICES_BY_FILE.md
"""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = ROOT / "docs" / "BEST_PRACTICES_BY_FILE.md"


def git_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def profile_for(path: str) -> tuple[str, str, str]:
    if path.startswith(("src/consensus/", "src/constants.rs", "src/emission/")):
        return (
            "Consensus-Critical",
            "Deterministic only; consensus vectors required; protected by critical hash lock.",
            "Bitcoin Core, Ethereum client test-vector discipline",
        )
    if path.startswith(("src/network/", "tests/network_", "tests/p2p_", "tests/adversarial")):
        return (
            "P2P-Critical",
            "Strict input validation; per-peer quotas; relay only verified objects.",
            "Bitcoin Core p2p hardening, Monero Dandelion++ style privacy routing",
        )
    if path.startswith(("src/rpc/", "tools/rpc-lib/", "docs/src/api/")):
        return (
            "RPC-Surface",
            "Loopback by default; authenticated remote access; bounded expensive methods.",
            "Geth/Nethermind auth-gated admin RPC and method limits",
        )
    if path.startswith(("src/wallet/", "src/bin/wallet.rs", "coincync-wallet/", "miner-gui/")):
        return (
            "Wallet-Key-Material",
            "No secret logging; encrypted at rest; zeroize sensitive buffers where applicable.",
            "Monero wallet key hygiene, Bitcoin wallet seed handling",
        )
    if path.startswith(("scripts/", "deploy/")):
        return (
            "Ops-Automation",
            "No hardcoded secrets; localhost-first binds; explicit fail-fast behavior.",
            "Production node ops playbooks (Bitcoin/Ethereum validators)",
        )
    if path.startswith(("tests/", "fuzz/")):
        return (
            "Assurance",
            "Cover edge cases and adversarial inputs; keep deterministic fixtures.",
            "libFuzzer/AFL practice in major clients, consensus differential testing",
        )
    if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".woff2", ".svg", ".min.js", ".json")):
        return (
            "Static-Asset",
            "Pin integrity/checksums for vendored assets; avoid embedding executable trust silently.",
            "Supply-chain integrity baselines used in major wallets/explorers",
        )
    if path.endswith((".md", ".txt")):
        return (
            "Documentation",
            "Keep operational/security guidance consistent with real runtime defaults.",
            "Bitcoin/Monero operator-doc alignment with runtime defaults",
        )
    return (
        "General-Code",
        "Validate all external inputs; bound resources; fail closed for security-sensitive paths.",
        "General secure software guidance used by mature client teams",
    )


def control_status(path: str) -> str:
    # Lightweight status markers so this report is useful immediately and can be refined manually.
    if path.startswith("src/consensus/") or path in {
        "src/constants.rs",
        "src/emission/mod.rs",
        "src/consensus/difficulty.rs",
        "src/consensus/pow.rs",
        "critical_files.lock",
    }:
        return "priority-review"
    if path.startswith(("src/rpc/", "src/network/", "src/wallet/", "src/bin/node.rs", "scripts/", "deploy/")):
        return "security-review"
    if path.startswith(("tests/", "fuzz/")):
        return "assurance-review"
    if path.endswith((".woff2", ".jpg", ".jpeg", ".png", ".svg")):
        return "asset-review"
    return "standard-review"


def render(files: list[str]) -> str:
    header = [
        "# BEST PRACTICES BY FILE",
        "",
        "This report is auto-generated to provide top-level blockchain/privacy/security best-practice coverage for every tracked file.",
        "",
        "## Status Legend",
        "",
        "- `priority-review`: consensus-critical or chain-validity-sensitive code.",
        "- `security-review`: network/RPC/wallet/ops security-sensitive surfaces.",
        "- `assurance-review`: tests/fuzz that should defend core invariants.",
        "- `asset-review`: static/vendor assets that require provenance/integrity checks.",
        "- `standard-review`: all remaining files.",
        "",
        "## Feature Baseline (from major chains)",
        "",
        "- **Consensus/Validation**: deterministic state transitions, strict canonical serialization, consensus vectors, backward-compatible upgrades.",
        "- **PoW/Mining**: anti-DoS header validation, bounded template construction, timestamp/difficulty sanity checks, robust orphan/reorg handling.",
        "- **Privacy**: enforce minimum anonymity set/ring policy, avoid metadata leaks in logs/RPC, relay obfuscation strategy for tx propagation.",
        "- **P2P Networking**: per-peer scoring and bans, bounded decode/queues, handshake/version gating, eclipse-resistance guardrails.",
        "- **Mempool/Fees**: deterministic ordering, replacement policy consistency, size/CPU quotas, eviction policy tested under adversarial load.",
        "- **RPC/Interfaces**: auth by default off-loopback, strict allowlists for public surfaces, capped expensive scans, stable schema/versioning.",
        "- **Wallet/Keys**: seed/key material never logged, encrypted persistence, explicit key lifecycle and memory cleanup.",
        "- **Storage/DB**: crash-safe commits, corruption detection/recovery paths, pruning invariants, schema migration discipline.",
        "- **Release/Supply Chain**: locked deps, reproducible builds where possible, vulnerability scanning, signed/reviewed release process.",
        "",
        "## Per-File Recommendations",
        "",
        "| File | Profile | Recommended controls | Industry baseline | Status |",
        "|---|---|---|---|---|",
    ]

    body = []
    for path in files:
        profile, controls, baseline = profile_for(path)
        status = control_status(path)
        body.append(f"| `{path}` | {profile} | {controls} | {baseline} | `{status}` |")
    body.append("")
    body.append(
        "_Regenerate with `python scripts/generate_best_practices_report.py` after file moves/additions._"
    )
    return "\n".join(header + body)


def main() -> None:
    files = git_files()
    report = render(files)
    OUT_PATH.write_text(report, encoding="utf-8")
    print(f"Wrote {OUT_PATH.relative_to(ROOT)} for {len(files)} files.")


if __name__ == "__main__":
    main()
