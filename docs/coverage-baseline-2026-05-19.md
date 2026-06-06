<!-- markdownlint-disable MD036 MD013 -->
# Coverage Baseline — coincync-swap @ 2026-05-19

**Tool:** `cargo llvm-cov v0.8.7`
**Run from:** clean Windows tree, `C:\dev\coincync`
**Command:** `cargo llvm-cov --package coincync-swap --summary-only`
**Includes:** unit tests + integration tests + property tests + external_vectors harness (all 151 named tests).

## Library coverage (the load-bearing surface)

| File | Region % | Line % | Function % | Notes |
| --- | --- | --- | --- | --- |
| `adaptor.rs` | **93.27%** | **96.22%** | 93.55% | Property-tested (4 properties × 256 cases) + 12 reproducibility vectors |
| `state.rs` | 94.65% | 96.60% | 96.77% | HMAC + persistence well-covered |
| `protocol.rs` | 91.30% | 87.65% | 93.94% | State-machine property-tested (6 properties × 256 sequences) |
| `btc.rs` | 88.81% | 91.14% | 81.71% | RPC + tx-construction integration tests |
| `coordinator.rs` | 87.53% | 87.95% | 60.00% | Many fn variants; line coverage strong |
| `cync.rs` | **77.86%** | **76.32%** | 61.29% | **Coverage gap** — target for Friday's CYNC-side property tests |
| `error.rs` | 100% | 100% | 100% | Trivially full |
| `lib.rs` | 87.50% | 87.50% | 100% | Status sentinel |

## Binary coverage (lower priority)

| File | Coverage | Why |
| --- | --- | --- |
| `bin/cyncswap.rs` | **0.00%** | CLI binary — no integration tests exercise it yet. Adding tests here is a separate effort from library-side testing; could be CI-driven smoke tests calling `cyncswap` with subcommand args. |

## Total

| Dimension | Value |
| --- | --- |
| Regions | 11,782 — 68.04% covered |
| Lines | 7,245 — 66.02% covered |
| Functions | 657 — 53.73% covered |

The headline number is pulled down by the CLI binary (which contributes ~25% of total regions but is 0% covered). **Library-only effective coverage is ~85-90%**, which is strong.

## What this tells us for Friday's work

The Friday plan was "consensus-layer property tests in main `coincync` crate." This baseline suggests a refined order:

1. **Highest-leverage in coincync-swap:** add property tests targeting `cync.rs` (77% → 90%+ target). The state-machine and BTC sides are already strong; the CYNC side has gaps.
2. **Then move to main `coincync`:** once swap-side coverage is uniform, the next biggest leverage is consensus-layer properties (block validation, difficulty, fee market) — that's the original Friday plan.
3. **CLI testing is separate:** the `cyncswap.rs` binary at 0% is a known gap but needs different tooling (`assert_cmd` or similar CLI-test crate). Defer to next week.

## Trend tracking

When this run is re-done after Friday's work, the diff against this file should show:

- `cync.rs` jumping from ~78% → ~90%+
- Total library coverage from ~85% → ~92%+
- Function coverage especially: from 53.73% total → ~75%+ (because the property tests will exercise more code paths per function)

## Reproducing this measurement

```sh
cargo install cargo-llvm-cov --locked   # one-time
cargo llvm-cov --package coincync-swap --summary-only
```

For HTML report (drill into per-line coverage):

```sh
cargo llvm-cov --package coincync-swap --html
# Output: target/llvm-cov/html/index.html
```

For the whole workspace:

```sh
cargo llvm-cov --workspace --summary-only
```

## Why coverage isn't the whole story

A high coverage number doesn't prove correctness — it proves the lines were executed at least once. Combined with property tests (which exercise random inputs), the combination is meaningful: coverage says "the lines run," property tests say "the lines produce correct outputs on every input we threw at them."

Coverage gaps are honest signals — "we don't even run this line in tests." Friday's work fills the gaps.
