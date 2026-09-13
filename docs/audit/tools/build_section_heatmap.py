#!/usr/bin/env python3
"""
Section coverage — a small, portable audit tool.

The problem it solves: on a large blockchain codebase it is hard to answer
"where is this behaviour proven, and is that proof passing right now?" This tool
makes the codebase self-describing:

  * Every source file carries a `## Audit map` doc-comment: each `§N` section
    states the INVARIANT it guarantees, the THREAT/incident it defends, and the
    TESTS that prove it. That convention is the single source of truth.
  * This tool PARSES those maps, then either
      - `--query <thing>`: finds the matching section(s) — by file, §N, section
        name, a test fn, or an incident tag (C-2, 1d27d3c8, H1, …) — RUNS just
        those tests, and colors the answer green/red so you see instantly
        whether the thing you care about is covered and passing; or
      - (no query): prints the whole-codebase colored section report; and
      - `--out-html`: an optional heatmap.

Any Rust project can adopt it: write the `## Audit map` convention and point the
build command at your test runner (see `run_cargo_for`).

Examples:
  python build_section_heatmap.py --query distribute_fee     # find + run + color
  python build_section_heatmap.py --query C-2                 # by incident tag
  python build_section_heatmap.py --test-log lib_test.log     # full report
"""
from __future__ import annotations
import argparse, json, re, sys, html, os, subprocess
from pathlib import Path

# ── audit-map parsing ────────────────────────────────────────────────────────
BACKTICK_RE = re.compile(r"`([^`]+)`")
TAG_RE = re.compile(
    r"\b(CVE-\d{4}-\d+|[A-Z]-?\d{1,3}(?:-[A-Z0-9]+)*|[A-Z]{1,4}-[A-Z0-9]{2,}"
    r"|#\d+|[0-9a-f]{8}|S\d+|R-\d+|H\d\b|C-\d)\b"
)
ADVERSARIAL_RE = re.compile(
    r"reject|tamper|malicious|overflow|underflow|invalid|forge|double_?spend"
    r"|attack|adversar|fails?|rejects?|does_not|must_not|_bad_|_wrong_|poison"
    r"|evict|inflation|out_of_range|non_canonical|identity|exhaust|flood",
    re.I,
)

def strip_doc(line: str) -> str:
    s = line.strip()
    for p in ("//!", "///", "//"):
        if s.startswith(p):
            return s[len(p):].strip()
    return s

def parse_audit_map(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    in_map, buf = False, []
    for ln in text:
        d = strip_doc(ln)
        if not in_map:
            if re.match(r"#+\s*Audit map", d):
                in_map = True
            continue
        if not (ln.strip().startswith("//!") or ln.strip().startswith("///")):
            break
        if re.match(r"#\s+\S", d):
            break
        buf.append(d)
    if not in_map or not buf:
        return []
    blob = "\n".join(buf)
    chunks = re.split(r"\n?\s*-\s*\*{0,2}\u00a7\s*", blob)
    sections = []
    for ch in chunks:
        ch = ch.strip()
        if not ch or not ch[0].isdigit():
            continue
        num = re.match(r"(\d+)", ch).group(1)
        anchor = re.search(r"(INVARIANT:|THREAT:|TESTS:)", ch)
        if not anchor:
            continue
        title, body = ch[:anchor.start()], ch[anchor.start():]
        nm = BACKTICK_RE.search(title)
        name = nm.group(1) if nm else re.sub(r"[`*\u2014\u2013-]+", " ", title).strip()[:64]
        inv = re.search(r"INVARIANT:\s*(.*?)(?:THREAT:|TESTS:|$)", body, re.S)
        threat = re.search(r"THREAT:\s*(.*?)(?:TESTS:|$)", body, re.S)
        tests_txt = re.search(r"TESTS:\s*(.*)$", body, re.S)
        test_fns, gap = [], False
        if tests_txt:
            tt = tests_txt.group(1)
            gap = "(gap" in tt
            for bt in BACKTICK_RE.findall(tt):
                fn = bt.split("::")[-1].strip()
                if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", fn):
                    test_fns.append(fn)
        tag_src = (threat.group(1) if threat else "") + " " + (inv.group(1) if inv else "")
        tags = sorted(set(t for t in TAG_RE.findall(tag_src) if t not in ("1", "2")))
        adversarial = bool(threat) or any(ADVERSARIAL_RE.search(f) for f in test_fns)
        sections.append({
            "num": int(num), "name": name,
            "invariant": re.sub(r"\s+", " ", inv.group(1)).strip() if inv else "",
            "threat": re.sub(r"\s+", " ", threat.group(1)).strip() if threat else "",
            "tags": tags, "tests": test_fns, "gap": gap, "adversarial": adversarial,
        })
    sections.sort(key=lambda s: s["num"])
    return sections

# ── test-result parsing ──────────────────────────────────────────────────────
RESULT_RE = re.compile(r"^test\s+([\w:]+)\s+\.\.\.\s+(ok|FAILED|ignored)", re.M)

def parse_test_text(text):
    res, rank = {}, {"ignored": 0, "ok": 1, "FAILED": 2}
    for m in RESULT_RE.finditer(text):
        fn, st = m.group(1).split("::")[-1], m.group(2)
        if fn not in res or rank[st] > rank[res[fn]]:
            res[fn] = st
    return res

def parse_test_log(log_path: Path):
    if not log_path or not log_path.exists():
        return {}
    return parse_test_text(log_path.read_text(encoding="utf-8", errors="replace"))

# ── colorizer ────────────────────────────────────────────────────────────────
CRITICAL_DIRS = ("consensus", "storage", "db", "emission", "crypto")
CRITICAL_FILES = ("chain.rs",)
GATED_HINT = re.compile(r"sketch-|dormant|gated|deferred|Phase 2|feature-gated", re.I)

def is_critical(relpath: str) -> bool:
    parts = relpath.replace("\\", "/").split("/")
    if any(relpath.endswith(f) for f in CRITICAL_FILES):
        return True
    return len(parts) > 1 and parts[1] in CRITICAL_DIRS

def colorize(section, results):
    tests = section["tests"]
    statuses = [results.get(t) for t in tests]
    if any(s == "FAILED" for s in statuses):
        return "red"
    if not tests or section["gap"]:
        return "grey" if GATED_HINT.search(section["threat"] + section["invariant"]) else "yellow"
    if any(s is None for s in statuses):
        return "yellow"
    if all(s == "ignored" for s in statuses):
        return "grey"
    if section.get("proven") or any("kani" in t for t in tests):
        return "blue"  # backed by a Kani proof or a property (proptest) test
    return "green" if section["adversarial"] else "yellow"

# ── terminal (ANSI) render ───────────────────────────────────────────────────
ANSI = {"green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m",
        "blue": "\033[34m", "grey": "\033[90m"}
DOT = {c: "\u25cf" for c in ANSI}
RST, BOLD, DIM, CRIT = "\033[0m", "\033[1m", "\033[2m", "\033[38;5;209m"
COLOR = {
    "green":  ("covered + passing",      "#1f9d55", "#34d399"),
    "yellow": ("incomplete / happy-only", "#c98a00", "#fbbf24"),
    "red":    ("failing (bug)",          "#d64545", "#f87171"),
    "blue":   ("formally verified",      "#2b6cb0", "#60a5fa"),
    "grey":   ("gated / deferred",       "#6b7280", "#9ca3af"),
}
ORDER = ["red", "yellow", "green", "blue", "grey"]
VERDICT_WORD = {"green": "COVERED", "yellow": "INCOMPLETE", "red": "FAILING",
                "blue": "PROVEN", "grey": "GATED"}
INCIDENTS = {}  # tag -> post-mortem doc path (populated in main)

def find_line(path, *patterns):
    try:
        for i, ln in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if any(pat in ln for pat in patterns):
                return i
    except Exception:
        pass
    return None

def render_terminal(files, results, use_color=True):
    def col(c, s): return f"{ANSI[c]}{s}{RST}" if use_color else s
    def b(s): return f"{BOLD}{s}{RST}" if use_color else s
    total = sum(len(f["sections"]) for f in files)
    tally = {c: 0 for c in COLOR}
    crit_ng = 0
    for f in files:
        for s in f["sections"]:
            tally[s["color"]] += 1
            if f["critical"] and s["color"] in ("red", "yellow"):
                crit_ng += 1
    n_fail = sum(1 for v in results.values() if v == "FAILED")
    out = ["", b("  Section coverage \u2014 live test status") + f"   ({total} sections \u00b7 {len(files)} files)"]
    out.append("  " + "  ".join(col(c, DOT[c]) + " " + COLOR[c][0] for c in ORDER))
    out.append(f"  {col('green', str(tally['green'])+' green')}   {col('yellow', str(tally['yellow'])+' incomplete')}   "
               f"{col('red', str(tally['red'])+' FAILING')}   {col('grey', str(tally['grey'])+' gated')}   "
               + (f"{CRIT if use_color else ''}{crit_ng} consensus-critical not green{RST if use_color else ''}"))
    if total:
        bar = "".join(col(c, "\u2588" * round(56 * tally[c] / total)) for c in ORDER) if use_color \
              else "".join(DOT[c] * round(56 * tally[c] / total) for c in ORDER)
        out += ["  " + bar, ""]
    subs = {}
    for f in files:
        subs.setdefault(f["subsystem"], []).append(f)
    for sub in sorted(subs):
        out.append("  " + b(sub.upper()))
        for f in sorted(subs[sub], key=lambda x: (not x["critical"], x["path"])):
            swatch = "".join(col(s["color"], DOT[s["color"]]) for s in f["sections"])
            mark = (CRIT + "\u258c" + RST) if (use_color and f["critical"]) else (" " if not f["critical"] else "|")
            out.append(f"  {mark} {f['path']:<34} {swatch}")
            for s in f["sections"]:
                if s["color"] == "green":
                    continue
                why = ("TEST FAILING" if s["color"] == "red" else
                       "gated / opt-in only" if s["color"] == "grey" else
                       "no test mapped" if not s["tests"] else
                       "gap marked" if s["gap"] else
                       "happy-path only (no adversarial test)" if not s["adversarial"] else
                       "a mapped test not in this run")
                out.append(f"       {col(s['color'], DOT[s['color']])} \u00a7{s['num']} {s['name'][:30]:<30} "
                           f"{DIM if use_color else ''}{why}{RST if use_color else ''}")
        out.append("")
    out.append(f"  {n_fail} test(s) failing. Green = passing AND adversarial. "
               f"Query one: --query <file|\u00a7N|test|tag>")
    out.append("")
    return "\n".join(out)

# ── per-section query + live run ─────────────────────────────────────────────
def match_sections(files, query):
    q = query.lower().strip().lstrip("\u00a7")
    hits = []
    for f in files:
        base = f["path"].split("/")[-1]
        for s in f["sections"]:
            if any(q == tag.lower() for tag in s["tags"]):
                hits.append((f, s))
                continue
            keys = [f["path"].lower(), base.lower(), f"{base.lower()}:{s['num']}",
                    f"\u00a7{s['num']}", str(s["num"]) if q.isdigit() else "",
                    s["name"].lower()] + [t.lower() for t in s["tests"]]
            if any(q == k or (len(q) >= 3 and q in k) for k in keys if k):
                hits.append((f, s))
    return hits

def run_cargo_for(test_fns, spark=False):
    if not test_fns:
        return {}
    env = dict(os.environ)
    env.setdefault("LIBCLANG_PATH", "C:/Program Files/LLVM/bin")
    env.setdefault("COINCYNC_RANDOMX_LIGHT_MODE", "1")
    env.setdefault("RUST_MIN_STACK", "268435456")
    llvm = "C:/Program Files/LLVM/bin"
    if llvm not in env.get("PATH", ""):
        env["PATH"] = llvm + os.pathsep + env.get("PATH", "")
    feats = "testnet sketch-lelantus-spark" if spark else "testnet"
    cmd = ["cargo", "test", "--lib", "--features", feats, "--", "--include-ignored", *sorted(set(test_fns))]
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=1800)
        return parse_test_text(p.stdout + "\n" + p.stderr)
    except Exception as e:
        sys.stderr.write(f"cargo run failed: {e}\n")
        return {}

def render_query(hits, results, use_color):
    def col(c, s): return f"{ANSI[c]}{s}{RST}" if use_color else s
    def b(s): return f"{BOLD}{s}{RST}" if use_color else s
    def dim(s): return f"{DIM}{s}{RST}" if use_color else s
    if not hits:
        return ("  no section matched. Try a file name, a \u00a7N, a test fn, a section\n"
                "  name, or an incident tag (e.g. C-2, 1d27d3c8, H1).\n")
    out = [""]
    for f, s in hits:
        color = colorize(s, results)
        passed = sum(1 for t in s["tests"] if results.get(t) == "ok")
        total = len(s["tests"])
        adv = "adversarial \u2713" if s["adversarial"] else "no adversarial test"
        sline = code_line(f, s)
        loc = f"{f['path']}:{sline}" if sline else f["path"]
        crit = (CRIT + "\u258c" + RST + " ") if (use_color and f["critical"]) else ""
        tags = ("  " + " ".join(col('yellow', tg) for tg in s['tags'])) if s['tags'] else ""
        out.append("  " + crit + col(color, b(f"[{VERDICT_WORD[color]}]")) + f" {b(f['path'])} \u00a7{s['num']} {s['name']}")
        out.append("     " + dim(f"\u21b3 {loc}") + "   " + col(color, f"{passed}/{total} passing") + dim(f" \u00b7 {adv}") + tags)
        links = list(dict.fromkeys(INCIDENTS[t] for t in s["tags"] if t in INCIDENTS))
        if links:
            out.append("     " + dim("incident: " + "  ".join(links)))
        if s["invariant"]:
            out.append("     " + dim("INVARIANT:") + f" {s['invariant']}")
        if s["threat"]:
            out.append("     " + dim("THREAT:") + f"    {s['threat']}")
        if s["tests"]:
            for t in s["tests"]:
                st = results.get(t)
                tline = find_line(f["path"], f"fn {t}(", f"fn {t}<", f"fn {t} ")
                where = dim(f"  {f['path']}:{tline}") if tline else dim("  (tests/*.rs \u2014 integration/e2e)")
                if st == "ok":
                    out.append("       " + col("green", f"\u2713 {t}") + col("green", " PASS") + where)
                elif st == "FAILED":
                    out.append("       " + col("red", f"\u2717 {t}") + col("red", " FAIL") + where)
                elif st == "ignored":
                    out.append("       " + col("grey", f"\u25e6 {t}") + col("grey", " ignored (opt-in / real-PoW)") + where)
                else:
                    out.append("       " + col("yellow", f"? {t}") + col("yellow", " not run here") + where)
        else:
            out.append("     " + col("yellow", "no test mapped \u2014 coverage gap"))
        out.append("")
    return "\n".join(out)

# ── HTML heatmap (optional) ──────────────────────────────────────────────────
def render_html(files, results):
    tally = {c: 0 for c in COLOR}
    for f in files:
        for s in f["sections"]:
            tally[s["color"]] += 1
    rows = []
    for f in sorted(files, key=lambda x: (x["subsystem"], not x["critical"], x["path"])):
        sw = "".join(f'<i class="d {s["color"]}"></i>' for s in f["sections"])
        rows.append(f'<div class="f{" crit" if f["critical"] else ""}"><b>{html.escape(f["path"])}</b> {sw}</div>')
    legend = " ".join(f'<span><i class="d {c}"></i>{html.escape(COLOR[c][0])}</span>' for c in ORDER)
    css = ".d{display:inline-block;width:12px;height:12px;border-radius:2px;margin:1px}"
    for c, (_, lt, _dk) in COLOR.items():
        css += f".d.{c}{{background:{lt}}}"
    return (f"<title>Section Coverage</title><style>body{{font:14px system-ui;margin:24px}}"
            f".f{{padding:6px 0}}.crit{{border-left:3px solid #b4472a;padding-left:8px}}{css}</style>"
            f"<h2>Section coverage \u2014 {tally['green']} green \u00b7 {tally['yellow']} incomplete \u00b7 {tally['red']} failing</h2>"
            f"<p>{legend}</p>" + "\n".join(rows))

# ── lint / gaps / CI ratchet ─────────────────────────────────────────────────
PUBFN_RE = re.compile(r"^\s*pub(?:\s*\([^)]*\))?\s+(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+(\w+)", re.M)

def public_fns(path):
    txt = Path(path).read_text(encoding="utf-8", errors="replace")
    # ignore the test module — we only care that PRODUCTION fns are audited
    cut = txt.find("#[cfg(test)]")
    if cut != -1:
        txt = txt[:cut]
    return [m.group(1) for m in PUBFN_RE.finditer(txt)]

def unmapped_fns(f):
    claimed = " ".join(s["name"].lower() for s in f["sections"])
    return [fn for fn in public_fns(f["path"])
            if fn.lower() not in claimed and not fn.startswith("_")]

def render_lint(files, use_color):
    def col(c, s): return f"{ANSI[c]}{s}{RST}" if use_color else s
    def b(s): return f"{BOLD}{s}{RST}" if use_color else s
    out = ["", b("  Unmapped public functions") +
           "  (production pub fns no § section claims — unaudited surface)"]
    total = 0
    for f in sorted(files, key=lambda x: (not x["critical"], x["path"])):
        miss = unmapped_fns(f)
        if not miss:
            continue
        total += len(miss)
        mark = (CRIT + "▌" + RST) if (use_color and f["critical"]) else " "
        out.append(f"  {mark} {b(f['path'])}  {col('yellow', str(len(miss))+' unmapped')}")
        out.append("       " + col("yellow", ", ".join(miss)))
    out.append("")
    out.append(f"  {total} unmapped public fn(s) across {len(files)} audited files.")
    out.append("")
    return "\n".join(out)

def render_gaps(files, use_color):
    def col(c, s): return f"{ANSI[c]}{s}{RST}" if use_color else s
    def b(s): return f"{BOLD}{s}{RST}" if use_color else s
    def dim(s): return f"{DIM}{s}{RST}" if use_color else s
    rank = {"red": 0, "yellow": 1, "grey": 2}
    gaps = [(f, s) for f in files for s in f["sections"] if s["color"] in rank]
    gaps.sort(key=lambda fs: (rank[fs[1]["color"]], not fs[0]["critical"], fs[0]["path"], fs[1]["num"]))
    out = ["", b("  Coverage gaps") + "  (fix these to reach green — critical + failing first)"]
    for f, s in gaps:
        why = ("TEST FAILING" if s["color"] == "red" else "gated/opt-in" if s["color"] == "grey"
               else "no test" if not s["tests"] else "gap marked" if s["gap"]
               else "no adversarial test" if not s["adversarial"] else "a mapped test not in run")
        mark = (CRIT + "▌" + RST + " ") if (use_color and f["critical"]) else "  "
        sline = find_line(f["path"], f"§{s['num']}")
        loc = f"{f['path']}:{sline}" if sline else f["path"]
        out.append(f"  {mark}{col(s['color'], DOT[s['color']])} {f['path']} §{s['num']} "
                   f"{s['name'][:28]:<28} {dim(why)}  {dim(loc)}")
    out.append(f"\n  {len(gaps)} gap(s). Query one to run it: --query <file>:§N\n")
    return "\n".join(out)

def run_check(files, strict=False):
    """CI ratchet. Default: nonzero exit only on a RED section (a mapped test is
    FAILING) — safe to adopt today. `--strict` ALSO fails on any consensus-
    critical section that isn't green/blue, for teams ratcheting toward 100%."""
    reds, crit_weak = [], []
    for f in files:
        for s in f["sections"]:
            if s["color"] == "red":
                reds.append((f, s))
            elif f["critical"] and s["color"] not in ("green", "blue"):
                crit_weak.append((f, s))
    for f, s in reds:
        print(f"  FAIL  {f['path']} §{s['num']} {s['name']} — a mapped test is FAILING")
    if strict:
        for f, s in crit_weak:
            print(f"  WEAK  {f['path']} §{s['num']} {s['name']} — consensus-critical, not green")
    bad = reds or (strict and crit_weak)
    print(f"\n  check{'(strict)' if strict else ''}: {'FAIL' if bad else 'PASS'} "
          f"({len(reds)} failing, {len(crit_weak)} critical-not-green"
          f"{'' if strict else ' [warn-only]'})")
    return 1 if bad else 0

# ── smarter adversarial detection (inspect test bodies, not just names) ───────
ADV_BODY_RE = re.compile(
    r"is_err\(\)|expect_err|unwrap_err|should_panic|#\[should_panic|assert!\(\s*!"
    r"|matches!\([^)]*Err|\.err\(\)|panic!|assert_err|InvalidTransaction|reject")
_FN_HEAD_RE = re.compile(r"\bfn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^{;]*?\)\s*(?:->[^{;]+)?\{")

def build_adversarial_index(roots=("src", "tests")):
    """Set of fn names whose BODY contains an adversarial assertion (is_err /
    should_panic / assert!(! / rejects …). Makes 🟢 trustworthy: a section is
    only adversarial if a mapped test actually asserts a failure path."""
    idx = set()
    for root in roots:
        rp = Path(root)
        if not rp.exists():
            continue
        for p in rp.rglob("*.rs"):
            txt = p.read_text(encoding="utf-8", errors="replace")
            for m in _FN_HEAD_RE.finditer(txt):
                name, i, depth = m.group(1), m.end() - 1, 0
                while i < len(txt):
                    c = txt[i]
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                if ADV_BODY_RE.search(txt[m.end():i]):
                    idx.add(name)
    return idx

# ── changed-since-baseline (re-review) ───────────────────────────────────────
def changed_files_since(ref):
    try:
        out = subprocess.run(["git", "diff", "--name-only", ref, "--", "src"],
                             capture_output=True, text=True, timeout=30).stdout
        return set(l.strip().replace("\\", "/") for l in out.splitlines() if l.strip())
    except Exception as e:
        sys.stderr.write(f"git diff failed: {e}\n")
        return set()

def render_since(files, changed, use_color):
    def col(c, s): return f"{ANSI[c]}{s}{RST}" if use_color else s
    def b(s): return f"{BOLD}{s}{RST}" if use_color else s
    hits = [f for f in files if f["path"] in changed]
    out = ["", b("  Sections to re-review") + f"  (code changed since baseline — {len(hits)} files)"]
    if not hits:
        out.append("  nothing changed under audited files.\n")
        return "\n".join(out)
    for f in sorted(hits, key=lambda x: (not x["critical"], x["path"])):
        mark = (CRIT + "▌" + RST) if (use_color and f["critical"]) else " "
        out.append(f"  {mark} {b(f['path'])}  — {len(f['sections'])} section(s): "
                   + ", ".join(f"§{s['num']} {s['name'][:20]}" for s in f["sections"]))
    out.append("")
    return "\n".join(out)

# ── property / Kani "proven" tier (🔵) ───────────────────────────────────────
_KANI_RE = re.compile(r"#\[kani::proof\][^\n]*\n\s*(?:pub\s+)?fn\s+(\w+)")

def build_proven_index(roots=("src", "tests")):
    """fn names that carry a Kani proof or live inside a `proptest!{ }` block."""
    idx = set()
    for root in roots:
        rp = Path(root)
        if not rp.exists():
            continue
        for p in rp.rglob("*.rs"):
            txt = p.read_text(encoding="utf-8", errors="replace")
            idx.update(_KANI_RE.findall(txt))
            for m in re.finditer(r"proptest!\s*\{", txt):
                i, depth = m.end() - 1, 0
                while i < len(txt):
                    if txt[i] == "{":
                        depth += 1
                    elif txt[i] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                idx.update(re.findall(r"\bfn\s+(\w+)", txt[m.end():i]))
    return idx

# ── incident → post-mortem doc links ─────────────────────────────────────────
def build_incident_index(roots=("docs/operations/incidents",)):
    """tag token -> doc path, from incident post-mortems ONLY (filename + first
    lines). Deliberately excludes docs/audit/* so the tool's own docs (which list
    tags as examples) don't masquerade as post-mortems."""
    idx = {}
    for root in roots:
        rp = Path(root)
        if not rp.exists():
            continue
        for p in sorted(rp.rglob("*.md")):
            head = p.name + "\n" + "\n".join(
                p.read_text(encoding="utf-8", errors="replace").splitlines()[:15])
            for tag in set(TAG_RE.findall(head)):
                idx.setdefault(tag, str(p).replace("\\", "/"))
    return idx

# ── code-anchor: the section's line in the CODE (fn def), not the doc header ──
def code_line(f, s):
    # prefer a `// §N` banner, then the fn definition, then the doc-map line
    ln = find_line(f["path"], f"// §{s['num']} ", f"// §{s['num']}\t", f"===== §{s['num']}")
    if ln:
        return ln
    nm = s["name"].split()[0].strip("`")
    ln = find_line(f["path"], f"fn {nm}(", f"fn {nm}<", f"fn {nm} ", f"struct {nm}", f"impl {nm}")
    if ln:
        return ln
    return find_line(f["path"], f"§{s['num']}")

# ── coverage trend ───────────────────────────────────────────────────────────
def record_trend(files, hist_path="docs/audit/.coverage-history.json"):
    import datetime
    tally = {c: 0 for c in COLOR}
    for f in files:
        for s in f["sections"]:
            tally[s["color"]] += 1
    hp = Path(hist_path)
    hist = json.loads(hp.read_text(encoding="utf-8")) if hp.exists() else []
    prev = hist[-1]["tally"] if hist else None
    hist.append({"at": datetime.datetime.now().isoformat(timespec="seconds"),
                 "total": sum(tally.values()), "tally": tally})
    hp.write_text(json.dumps(hist[-200:], indent=2), encoding="utf-8")
    return prev, tally

# ── auditor handoff bundle ───────────────────────────────────────────────────
def make_bundle(out_zip, test_log):
    import zipfile
    want = ["docs/audit/sections.json", "docs/audit/findings.md", "docs/audit/AUDIT.md",
            "critical_files.lock", "docs/audit/tools/build_section_heatmap.py",
            "docs/audit/tools/README.md", test_log]
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for w in want:
            if w and Path(w).exists():
                z.write(w, Path(w).name if "/" not in w or w.endswith(".log") else w)
    return out_zip

# ── declared-invariant manifest (the invariants! pipeline) ───────────────────
def load_invariant_manifest(path="docs/audit/invariants.json"):
    """Ingest invariants declared once via the `invariants!` macro (exported to
    invariants.json) as a synthetic audited 'file', so `declare once` also feeds
    the coverage view — test + monitor + section from a single declaration."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    secs = []
    for i, e in enumerate(data, 1):
        secs.append({
            "num": i, "name": e.get("id", f"inv{i}"),
            "invariant": e.get("statement", ""), "threat": "",
            "tags": e.get("tags", []), "tests": [e.get("test", "")],
            "gap": False, "adversarial": True,  # a declared invariant IS an assertion
        })
    return {"path": "invariants (declared pipeline)", "subsystem": "invariants",
            "critical": True, "sections": secs}

# ── main ─────────────────────────────────────────────────────────────────────
def subsystem_of(rel):
    parts = rel.replace("\\", "/").split("/")
    return parts[1] if len(parts) > 1 else "root"

def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="src")
    ap.add_argument("--test-log", default="")
    ap.add_argument("--out-json", default="docs/audit/sections.json")
    ap.add_argument("--out-html", default="")
    ap.add_argument("--query", default="")
    ap.add_argument("--no-run", action="store_true")
    ap.add_argument("--spark", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--lint", action="store_true",
                    help="list production pub fns that no section claims (unaudited surface)")
    ap.add_argument("--gaps", action="store_true",
                    help="list every not-green section, critical + failing first (the to-do)")
    ap.add_argument("--check", action="store_true",
                    help="CI ratchet: exit nonzero on any FAILING (red) section")
    ap.add_argument("--strict", action="store_true",
                    help="with --check, ALSO fail on any consensus-critical section not green")
    ap.add_argument("--since", default="",
                    help="list sections whose CODE changed since this git ref (re-review)")
    ap.add_argument("--bundle", default="",
                    help="write an auditor handoff zip (sections.json + findings + log + manifest)")
    ap.add_argument("--trend", action="store_true",
                    help="on the full report, record + show the coverage delta since last run")
    a = ap.parse_args()

    files = []
    for p in sorted(Path(a.src).rglob("*.rs")):
        secs = parse_audit_map(p)
        if not secs:
            continue
        rel = str(p).replace("\\", "/")
        files.append({"path": rel, "subsystem": subsystem_of(rel),
                      "critical": is_critical(rel), "sections": secs})

    # Invariants declared once via the `invariants!` macro also become sections.
    inv_file = load_invariant_manifest()
    if inv_file:
        files.append(inv_file)

    # Smarter adversarial: a section is adversarial if a MAPPED TEST BODY asserts
    # a failure path (not just the name heuristic) — makes green trustworthy.
    adv_idx = build_adversarial_index()
    proven_idx = build_proven_index()
    global INCIDENTS
    INCIDENTS = build_incident_index()
    for f in files:
        for s in f["sections"]:
            s["adversarial"] = s["adversarial"] or any(t in adv_idx for t in s["tests"])
            s["proven"] = any(t in proven_idx for t in s["tests"])

    use_color = not a.no_color

    if a.bundle:
        z = make_bundle(a.bundle, a.test_log)
        print(f"wrote auditor bundle: {z}")
        return

    if a.since:
        sys.stdout.write(render_since(files, changed_files_since(a.since), use_color))
        return

    if a.lint:
        sys.stdout.write(render_lint(files, use_color))
        return

    # gaps / check color from a test log
    if a.gaps or a.check:
        results = parse_test_log(Path(a.test_log)) if a.test_log else {}
        for f in files:
            for s in f["sections"]:
                s["color"] = colorize(s, results)
        if a.gaps:
            sys.stdout.write(render_gaps(files, use_color))
        if a.check:
            sys.exit(run_check(files, strict=a.strict))
        return

    if a.query:
        hits = match_sections(files, a.query)
        test_fns = sorted({t for _, s in hits for t in s["tests"]})
        if a.no_run:
            results = parse_test_log(Path(a.test_log)) if a.test_log else {}
        else:
            sys.stderr.write(f"running {len(test_fns)} test(s) for {len(hits)} matched section(s)\u2026\n")
            results = run_cargo_for(test_fns, spark=a.spark)
        sys.stdout.write(render_query(hits, results, use_color))
        return

    results = parse_test_log(Path(a.test_log)) if a.test_log else {}
    for f in files:
        for s in f["sections"]:
            s["color"] = colorize(s, results)
    Path(a.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out_json).write_text(json.dumps(files, indent=2), encoding="utf-8")
    if a.out_html:
        Path(a.out_html).write_text(render_html(files, results), encoding="utf-8")
    sys.stdout.write(render_terminal(files, results, use_color=use_color))
    if a.trend:
        prev, now = record_trend(files)
        if prev:
            delta = ", ".join(f"{c} {now[c]-prev[c]:+d}" for c in ORDER if now[c] != prev[c])
            sys.stdout.write(f"  trend since last run: {delta or 'no change'}\n\n")

if __name__ == "__main__":
    main()
