# Per-Section Test-Coverage Dashboard — design (deferred: build AFTER the bug fixes)

User's idea (2026-09-12): make the codebase trivially reviewable/auditable by
dividing each file into small labelled sections, mapping tests to sections, and
showing a **color-coded status heatmap** driven by an actual test run.

## Requirements (verbatim intent)
1. **Each source file → at least 6 simple sections.** Simplicity is the point —
   small, digestible chunks with plain, easy-to-read section headers.
2. **Each file has a coverage map** (section → the tests that pin it), plus a
   central map doc across the whole codebase (`docs/audit/code-to-test-map.md`).
3. **Section banners in code and test module mirror each other**, in the same
   order, so a reviewer reads one section of logic and its tests together.
4. **Color-coded status when the tests are run:**
   - 🟢 green  = section fully covered AND all its tests pass
   - 🟡 yellow = coverage incomplete (missing/partial tests for the section)
   - 🔴 red    = a test for the section FAILS (a bug)
   - extensible: e.g. 🔵 blue = formally verified (kani), ⚪ grey = gated/deferred
5. Delivered so "if they run the test it highlights the sections" — i.e. a
   rendered view, ideally an **interactive HTML heatmap** (an Artifact the user
   and auditors can open), regenerated from a real `cargo test` run.

## Build sketch (when we get to it)
- Define sections per file via `// ===== §N: TITLE =====` banners (code + tests).
- A machine-readable map: `section_id -> [test fn names]` + `coverage_status`
  (complete / partial) — could live in `code-to-test-map.md` front-matter or a
  small JSON the dashboard reads.
- Runner: `cargo test --lib --features testnet -- -Z unstable-options --format json`
  (or parse the human output) → per-test pass/fail.
- Colorizer: for each section, RED if any mapped test failed; else YELLOW if the
  map marks it partial/missing; else GREEN. Blue/grey from static annotations.
- Render: an HTML Artifact — one panel per file, sections as colored blocks with
  the test list and pass/fail counts; filter by subsystem; totals at top.

## Enhancement ideas (target ~99%; keep the DEFAULT view simple)

Layer these on top of the green/yellow/red core — simple by default, powerful on
drill-in.

A. Richer status:
- **Adversarial-ratio gate**: a section is 🟢 only if it has ADVERSARIAL tests,
  not just happy-path (1206 passing tests caught 0 of 38 bugs — happy-path green
  is worthless). All-passing but happy-path-only ⇒ 🟡.
- **Criticality border** (separate from status color): thick red border =
  consensus-critical (can fork the chain / move funds); grey = utility. Scan for
  "critical + not-green" first.
- **Coverage number** per section (covered/total behaviors), so 🟡 says HOW
  incomplete; the yellow sections become the to-do list to 100%.

B. Audit-native:
- **One plain-English INVARIANT per section header** (e.g. `distribute_fee:
  miner+burn+protocol == total, always`) — the claim next to the proving test.
- **Incident/CVE tags** per section (ASERT S1 testnet-wipe, merkle CVE-2012-2459,
  ring-size determinism 1d27d3c8, R-2 genesis binding, …).
- **🔵 formally-verified tier** for sections with Kani proofs (`kani_proofs.rs`).
- **Changed-since-baseline tint**: sections whose bytes changed since the
  hash-lock / last audit commit = "re-review"; ties into `critical_files.lock`.

C. Ratchet (so 99% can't slip):
- **Single source of truth = `sections.json`** (section → line range → tests →
  invariant → tags → status); code banners AND dashboard read it, so no drift.
- **CI lint fails the build** if a public fn is in no section, or a
  consensus-critical section has no adversarial test.
- **Reproducible + shippable**: generate from one `cargo test --format json` run;
  attach the heatmap to the release beside the SHA-256 build manifest.

Two-audience view: top level = subsystem tiles (🟢/🟡/🔴) for a 5-second glance;
click → file → section → the actual test + its assertion. Simple on top, deep
underneath.

## Status
DEFERRED until the H3–H9 (and medium/low) bug fixes are done, so it captures the
final code state. The `fee_market.rs` test module has a Level-1 preview
(coverage-map header + a §1 banner) — redo it to ≥6 sections in the real pass.

See also [[coincync-test-coverage-marathon]].
