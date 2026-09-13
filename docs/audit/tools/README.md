# Section coverage — find where a behaviour is proven, and if it's passing

A small, portable audit tool. It answers the question every blockchain team hits:
**"where is this behaviour proven, and is that proof green right now?"** — in the
terminal, from the code, no web dashboard.

## How it works

Each source file carries a `## Audit map` doc-comment (the single source of
truth). Every `§N` section states, in the code where you already read:

- the **INVARIANT** it guarantees,
- the **THREAT / incident** it defends (tagged: `C-2`, `1d27d3c8`, `H1`, `A8-DIST-01`, …),
- the **TESTS** that prove it (real fn names; gaps marked `(gap — …)`).

`build_section_heatmap.py` parses those maps and runs the tests you ask about.

## Commands

Let `T=docs/audit/tools/build_section_heatmap.py`. First capture a test log once
(reused by the fast, no-run modes):

```bash
cargo test --lib --features testnet 2>&1 | tee lib_test.log
```

**Look up + run + color one thing** — by section name, `§N`, a test fn, or an
incident tag. Runs just those tests and turns the letters green/red:
```bash
python $T --query distribute_fee            # by section / area name
python $T --query C-2                        # by incident tag (reverse lookup)
python $T --query validation.rs:5            # a specific file's §5
python $T --query fee_distribution_is_valid_rejects_bad_sum   # test → its section+invariant
python $T --query H2 --no-run --test-log lib_test.log         # instant, from cached log
```
Each answer shows the verdict (`[COVERED]`/`[INCOMPLETE]`/`[FAILING]`),
`passing/total`, incident tags, and a clickable `file:line` for the section **and
every test**.

**Find where bugs hide / gate the codebase:**
```bash
python $T --lint                             # pub fns no §section claims (unaudited surface)
python $T --gaps  --test-log lib_test.log    # every not-green section, critical+failing first
python $T --check --test-log lib_test.log    # CI ratchet: exit≠0 on red or critical-not-green
python $T --since HEAD~1                      # sections whose CODE moved → re-review
```

**Whole-codebase colored report:**
```bash
python $T --test-log lib_test.log            # subsystem → file → §section swatches
python $T --test-log lib_test.log --out-html audit.html   # optional HTML (off by default)
```

Add `--no-color` for plain text (CI logs), `--spark` to include the
feature-gated Spark tests in a query. Green requires passing AND *adversarial*
coverage (a mapped test whose body actually asserts a failure path), so a green
section is trustworthy.

### Colors (why a section is what it is)
- 🟢 **green** — every mapped test passes **and** the section has adversarial
  coverage. (Happy-path-only stays yellow on purpose: in the 2026 bug hunt ~1200
  passing happy-path tests caught 0 of 38 bugs.)
- 🟡 **yellow** — incomplete: a mapped test is missing/not-run, a `(gap —)` marker,
  or no adversarial test.
- 🔴 **red** — a mapped test is FAILING (a live bug).
- 🔵 **blue** — formally verified (Kani proof).
- ⚪ **grey** — gated / opt-in (feature-gated or real-PoW `#[ignore]` only).

## Invariant → everything pipeline

Declare a consensus invariant **once** in `tests/invariant_pipeline.rs`:

```rust
invariants! {
    supply_conservation, "total_supply + burned == Σ reward over the canonical chain", ["C-2"], chk_supply_conservation;
}
```

and get three things that can't drift apart:
1. a **derived unit test** (`#[test] fn supply_conservation`),
2. a **`CATALOG` entry** the `simkit` multi-node harness registers as a live
   runtime **monitor** (checked after every delivery round), and
3. a **`docs/audit/invariants.json`** manifest this tool auto-loads, so the
   invariant shows up as an audited section (`--query supply_conservation`).

One source of truth for "what must always be true" → test + monitor + audit view.

## Companion test harnesses (`tests/common/simkit.rs`)
- **`simkit`** — deterministic multi-node harness (virtual clock, partition/heal,
  equivocation, state-diff `first_divergence`, pluggable invariant monitors).
  Run its mining scenarios instantly with the **`test-fast-pow`** feature:
  `cargo test --features "testnet test-fast-pow" --test simkit_demo -- --ignored`.
- **`consensus_fuzz`** — malformed-block corpus; every node must agree on rejection.
- **`param_calibration`** — drives real ASERT + emission; catches unit/sign (S1) and supply-cap bugs at CI time.

## Adopting it in another chain

1. Add a `## Audit map` block to each file, using the format in
   `src/consensus/fee_market.rs` (§N · INVARIANT · THREAT · TESTS).
2. Point `run_cargo_for()` at your build/test command and features, and adjust
   `CRITICAL_DIRS` for your consensus-critical paths.

That's it — the parser, colorizer, query, and report are generic.
