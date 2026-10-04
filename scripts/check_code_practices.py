#!/usr/bin/env python3
"""
check_code_practices.py — find where CoinCync code departs from "the right way".

Run one command; it reads the source, tests each file against a set of project
rules (determinism, panic-safety, hygiene), and tells you — in plain English,
located by file, line and the enclosing section (fn/impl/mod) — what is wrong
and how it is supposed to be done instead.

This is the content-level upgrade to the best-practices tooling: the existing
scripts classify files by PATH (review tiers) or check fixed substrings; this
one actually analyses code and explains findings.

Usage:
  python scripts/check_code_practices.py                 # check src/ (default)
  python scripts/check_code_practices.py src/consensus   # a subtree or file
  python scripts/check_code_practices.py --errors-only    # only error severity
  python scripts/check_code_practices.py --rule DET-FLOAT # one rule
  python scripts/check_code_practices.py --summary        # counts only
  python scripts/check_code_practices.py --strict         # exit 1 if any error
  python scripts/check_code_practices.py --json           # machine-readable

Exit code is 0 unless --strict is given and an error-severity finding exists,
so it is safe to run informally and still usable as a CI gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]

# ── Severity ────────────────────────────────────────────────────────────────
ERROR, WARN, INFO = "error", "warn", "info"
SEV_ORDER = {ERROR: 0, WARN: 1, INFO: 2}


@dataclass
class Rule:
    id: str
    severity: str
    pattern: re.Pattern
    problem: str          # plain-English: what is wrong
    right_way: str        # plain-English: how it should be done
    where: str            # "code" (ignore comments) or "comment" (only comments)
    include: tuple[str, ...] = ()   # path prefixes it applies to (() = all under root scope)
    exclude: tuple[str, ...] = ()   # path prefixes to skip
    skip_tests: bool = True          # ignore matches inside #[cfg(test)] / mod tests
    # If set and found within `window` lines of the match, the finding is
    # considered satisfied and suppressed (e.g. an error IS coded → a CYNC_ is near).
    satisfied_by: Optional[re.Pattern] = None
    window: int = 3

    def applies_to(self, rel: str) -> bool:
        if self.include and not rel.startswith(self.include):
            return False
        if self.exclude and rel.startswith(self.exclude):
            return False
        return True


# ── The rules — "the right way", encoded ─────────────────────────────────────
RULES: list[Rule] = [
    Rule(
        "DET-FLOAT", ERROR, re.compile(r"\b(f64|f32)\b"),
        "Floating-point in consensus/emission code. f64/f32 is NOT deterministic "
        "across CPU architectures, so two nodes can compute different results and "
        "fork the chain (hazard H-1).",
        "Use integer-only math (u128 fixed-point). See src/consensus/difficulty.rs "
        "for the fixed-point pattern.",
        where="code", include=("src/consensus/", "src/emission/"),
    ),
    Rule(
        "DET-CLOCK", WARN, re.compile(r"\b(SystemTime::now|Instant::now)\s*\("),
        "Reads the wall/monotonic clock directly. This bypasses the clock seam, so "
        "the code can't be driven deterministically in simulation/tests (enabler E1).",
        "Use crate::clock (unix_now() / mono_now()) so the clock can be overridden.",
        where="code", include=("src/",),
        exclude=("src/clock.rs", "src/bin/", "src/explorer/"),
    ),
    Rule(
        "DET-RNG", WARN, re.compile(r"\b(thread_rng\s*\(|OsRng|rand::random\s*\()"),
        "Pulls entropy from a non-seeded RNG. In consensus/mining/sim paths this "
        "breaks deterministic, reproducible runs (enabler E3).",
        "Use the seeded RNG seam so a run can be replayed from a seed.",
        where="code", include=("src/consensus/", "src/mining/", "src/network/"),
    ),
    Rule(
        "PANIC-CONSENSUS", WARN,
        re.compile(r"(\.unwrap\s*\(\)|\.expect\s*\(|\bpanic!\s*\(|\bunreachable!\s*\(|\btodo!\s*\(|\bunimplemented!\s*\()"),
        "A panic path in consensus code. A crafted block/tx that reaches it crashes "
        "the node (a remote DoS) instead of being rejected.",
        "Return an Error (reject the input) rather than unwrap/expect/panic.",
        where="code", include=("src/consensus/",),
    ),
    Rule(
        "CAST-TRUNCATE", WARN, re.compile(r"\bas\s+(u8|u16|u32|i8|i16|i32)\b"),
        "A narrowing integer cast on the consensus path. `as` truncates SILENTLY, "
        "so a value that doesn't fit produces a wrong consensus number with no "
        "error (an inflation / divergence risk).",
        "Use a checked conversion (u32::try_from(x)? / x.try_into()) and handle the "
        "overflow; if the value provably fits, mark it `// check-allow: CAST-TRUNCATE`.",
        where="code", include=("src/consensus/",),
    ),
    Rule(
        "ERROR-UNCODED", INFO,
        re.compile(r"Error::(InvalidTransaction|PowValidation|InvalidTxVersion|InvalidSignature|DuplicateKeyImage)\s*\("),
        "A consensus rejection with no coded diagnostic (CYNC_*) nearby. It won't "
        "appear in the flight recorder or the coincync-diag registry, so operators "
        "can't track or explain why a block/tx was rejected.",
        "Pair it with a coded diagnostic (add_error_coded(CYNC_...) / "
        "flight_recorder::record(CYNC_..., ...)), or reference the CYNC_ code nearby.",
        where="code", include=("src/consensus/",),
        satisfied_by=re.compile(r"CYNC_"), window=4,
    ),
    Rule(
        "HYGIENE-PRINT", WARN,
        re.compile(r"\b(println!|eprintln!|dbg!)\s*\("),
        "Ad-hoc stdout/stderr printing (or a leftover dbg!) in library code.",
        "Use the `tracing` macros (info!/warn!/debug!) so output is structured and "
        "level-controlled. (println! is fine in bins/examples/tests.)",
        where="code", include=("src/",),
        exclude=("src/bin/", "src/explorer/", "src/cli/", "src/build_info.rs"),
    ),
    Rule(
        "HYGIENE-MARKER", INFO,
        re.compile(r"\b(TODO|FIXME|XXX|HACK)\b"),
        "An unfinished-work marker.",
        "Resolve it, or file an issue and reference it, before shipping.",
        where="comment", include=("src/",), skip_tests=False,
    ),
    Rule(
        "ALLOW-LINT", INFO, re.compile(r"#\[allow\("),
        "A suppressed compiler/clippy lint — a warning someone chose to silence.",
        "Confirm the suppression is still justified; prefer fixing the underlying "
        "cause, and scope the allow as narrowly as possible.",
        where="code", include=("src/",),
    ),
    Rule(
        "UNSAFE", WARN, re.compile(r"\bunsafe\s+(?:fn\b|impl\b|\{)"),
        "An `unsafe` block/fn/impl — the compiler's memory-safety guarantees are off "
        "here.",
        "Make sure a SAFETY comment documents the invariant that makes it sound; "
        "prefer a safe alternative if one exists.",
        where="code", include=("src/",),
    ),
]


# ── Section tracking (plain-English "what section") ──────────────────────────
FN_RE = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?(?:async\s+|const\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*fn\s+(\w+)")
IMPL_RE = re.compile(r"^\s*impl(?:<[^>]*>)?\s+(.+?)(?:\s+where\b.*)?\s*\{")
MOD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)")
TEST_RE = re.compile(r"#\[cfg\(test\)\]|^\s*mod\s+tests\b")
# Intentional, reviewed exception: `// check-allow: RULE-ID[, RULE-ID]` (or `all`)
# on the flagged line or the line directly above it.
ALLOW_RE = re.compile(r"check-allow:\s*([A-Za-z0-9_,\- ]+)")


def allowed(rule_id: str, *lines: str) -> bool:
    for line in lines:
        m = ALLOW_RE.search(line)
        if m:
            ids = {t.strip().upper() for t in m.group(1).split(",")}
            if "ALL" in ids or rule_id in ids:
                return True
    return False


@dataclass
class Finding:
    file: str
    line: int
    rule: Rule
    section: str
    snippet: str


def split_code_comment(line: str, in_block: bool) -> tuple[str, str, bool]:
    """Return (code_part, comment_part, in_block_after). Heuristic: good enough
    for line scanning — does not fully parse string literals."""
    if in_block:
        end = line.find("*/")
        if end == -1:
            return "", line, True
        return "", line[: end + 2], False  # rest after */ is rare; treat as comment
    # not currently in a block comment
    block_start = line.find("/*")
    line_start = line.find("//")
    if block_start != -1 and (line_start == -1 or block_start < line_start):
        code = line[:block_start]
        rest = line[block_start:]
        closed = rest.find("*/")
        if closed == -1:
            return code, rest, True
        return code, rest, False
    if line_start != -1:
        return line[:line_start], line[line_start:], False
    return line, "", False


def scan_file(path: Path, rel: str, active: list[Rule]) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    return scan_text(text, rel, active)


def scan_text(text: str, rel: str, active: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    section = "(top level)"
    in_block = False
    in_tests = False
    lines = text.splitlines()
    for i, raw in enumerate(lines, start=1):
        prev = lines[i - 2] if i >= 2 else ""
        if TEST_RE.search(raw):
            in_tests = True
        # Update the enclosing-section label.
        if (m := FN_RE.match(raw)):
            section = f"fn {m.group(3)}"
        elif (m := IMPL_RE.match(raw)):
            section = f"impl {m.group(1).strip()}"
        elif (m := MOD_RE.match(raw)):
            section = f"mod {m.group(1)}"

        code_part, comment_part, in_block = split_code_comment(raw, in_block)

        for rule in active:
            if not rule.applies_to(rel):
                continue
            if rule.skip_tests and in_tests:
                continue
            haystack = comment_part if rule.where == "comment" else code_part
            if haystack and rule.pattern.search(haystack):
                if allowed(rule.id, raw, prev):
                    continue
                if rule.satisfied_by is not None:
                    lo = max(0, i - 1 - rule.window)
                    hi = min(len(lines), i + rule.window)
                    if rule.satisfied_by.search("\n".join(lines[lo:hi])):
                        continue
                findings.append(
                    Finding(rel, i, rule, section, raw.strip()[:160])
                )
    return findings


SELFTEST = """\
pub fn estimate() -> f64 { 0.0 }
let t = SystemTime::now();
let x = foo.unwrap();
let r = thread_rng();
let ok = bar.unwrap(); // check-allow: PANIC-CONSENSUS
// TODO: tidy this
#[allow(dead_code)]
unsafe { touch() }
let n = big as u32;
return Err(Error::InvalidTransaction("bad".into()));
let a = 1;
let b = 2;
let c = 3;
let d = 4;
let e = 5;
// CYNC_CONS_001
return Err(Error::PowValidation("x".into()));
"""


def selftest() -> int:
    """Scan an inline fixture as if it were a consensus file and assert the
    rules fire (and that suppression works). Returns 0 on pass, 1 on fail."""
    got = {(f.rule.id, f.line) for f in scan_text(SELFTEST, "src/consensus/fixture.rs", RULES)}
    expect_present = [
        ("DET-FLOAT", 1), ("DET-CLOCK", 2), ("PANIC-CONSENSUS", 3),
        ("DET-RNG", 4), ("HYGIENE-MARKER", 6), ("ALLOW-LINT", 7), ("UNSAFE", 8),
        ("CAST-TRUNCATE", 9), ("ERROR-UNCODED", 10),
    ]
    missing = [e for e in expect_present if e not in got]
    # Line 5's unwrap is suppressed by the inline check-allow; line 17's error is
    # satisfied by the CYNC_CONS_001 on line 16 (within the 4-line window).
    leaked = [
        (r, ln) for (r, ln) in got
        if (r == "PANIC-CONSENSUS" and ln == 5) or (r == "ERROR-UNCODED" and ln == 17)
    ]
    ok = not missing and not leaked
    if ok:
        print("selftest: PASS")
        return 0
    if missing:
        print(f"selftest: FAIL — missing {missing}", file=sys.stderr)
    if leaked:
        print(f"selftest: FAIL — suppression leaked {leaked}", file=sys.stderr)
    return 1


def iter_sources(targets: list[Path]) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for target in targets:
        if target.is_file():
            if target.suffix == ".rs":
                out.append((target, target.relative_to(ROOT).as_posix()))
        else:
            for p in sorted(target.rglob("*.rs")):
                rel = p.relative_to(ROOT).as_posix()
                if "/target/" in f"/{rel}":
                    continue
                out.append((p, rel))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["src"], help="files/dirs to check (default: src)")
    ap.add_argument("--errors-only", action="store_true", help="only error-severity findings")
    ap.add_argument("--rule", action="append", default=[], help="limit to rule id(s)")
    ap.add_argument("--summary", action="store_true", help="print only the summary")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any error-severity finding")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--selftest", action="store_true", help="run the built-in rule self-test and exit")
    args = ap.parse_args()

    # Windows consoles default to cp1252 and choke on non-ASCII; never crash on it.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if args.selftest:
        return selftest()

    active = RULES
    if args.rule:
        wanted = {r.upper() for r in args.rule}
        active = [r for r in RULES if r.id in wanted]
        if not active:
            print(f"No such rule(s): {', '.join(args.rule)}", file=sys.stderr)
            print(f"Known rules: {', '.join(r.id for r in RULES)}", file=sys.stderr)
            return 2

    targets = [(ROOT / p).resolve() for p in args.paths]
    sources = iter_sources(targets)

    findings: list[Finding] = []
    for path, rel in sources:
        findings.extend(scan_file(path, rel, active))

    if args.errors_only:
        findings = [f for f in findings if f.rule.severity == ERROR]

    findings.sort(key=lambda f: (f.file, f.line))

    if args.json:
        print(json.dumps([
            {"file": f.file, "line": f.line, "rule": f.rule.id,
             "severity": f.rule.severity, "section": f.section,
             "problem": f.rule.problem, "right_way": f.rule.right_way,
             "code": f.snippet}
            for f in findings
        ], indent=2))
        return strict_exit(args, findings)

    if not args.summary:
        current = None
        for f in findings:
            if f.file != current:
                current = f.file
                print(f"\n{f.file}")
            tag = {"error": "ERROR", "warn": "warn ", "info": "info "}[f.rule.severity]
            print(f"  line {f.line:<5} [{tag}] {f.rule.id:<16} in {f.section}")
            print(f"      Problem:   {f.rule.problem}")
            print(f"      Right way: {f.rule.right_way}")
            print(f"      Code:      {f.snippet}")

    # ── Summary ──
    by_sev: dict[str, int] = {ERROR: 0, WARN: 0, INFO: 0}
    by_rule: dict[str, int] = {}
    files_hit = set()
    for f in findings:
        by_sev[f.rule.severity] += 1
        by_rule[f.rule.id] = by_rule.get(f.rule.id, 0) + 1
        files_hit.add(f.file)
    print("\n" + "-" * 60)
    print(f"Scanned {len(sources)} file(s); {len(findings)} finding(s) in {len(files_hit)} file(s).")
    print(f"  errors: {by_sev[ERROR]}   warnings: {by_sev[WARN]}   info: {by_sev[INFO]}")
    if by_rule:
        print("  by rule: " + ", ".join(f"{k}={v}" for k, v in sorted(by_rule.items())))
    return strict_exit(args, findings)


def strict_exit(args, findings: list[Finding]) -> int:
    if args.strict and any(f.rule.severity == ERROR for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
