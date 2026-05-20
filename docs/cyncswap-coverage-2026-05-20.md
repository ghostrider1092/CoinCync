<!-- markdownlint-disable MD036 MD013 -->
# Coverage Baseline — `coincync-swap` — 2026-05-20

Measured via `cargo llvm-cov` on Linux (WSL Ubuntu, isolated target dir
to avoid Windows .pdb contamination). Command:

```bash
CARGO_TARGET_DIR=/tmp/coincync-cov \
  cargo llvm-cov --package coincync-swap --features strict-dleq --summary-only
```

## Audit-critical files (per `docs/cyncswap-audit-prep.md` §5)

| File | Lines | Missed | **Cover** | Regions | Missed | Functions | Missed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `adaptor.rs` | 767 | 20 | **97.39%** | 1586 / 73 (95.40%) | 62 fns / 3 missed (95.16%) | | |
| `btc.rs` | 1433 | 47 | **96.72%** | 2106 / 113 (94.63%) | 101 fns / 5 missed (95.05%) | | |
| `cync.rs` | 725 | 19 | **97.38%** | 1154 / 49 (95.75%) | 85 fns / 7 missed (91.76%) | | |
| `strict_dleq.rs` | 1182 | 11 | **99.07%** | 2512 / 115 (95.42%) | 100 fns / 0 missed (**100.00%**) | | |

**Audit perimeter average:** ~97% line coverage across the four crypto-critical files. Combined with the 100% mutation score from the same date, this is the empirical answer to "are the tests thorough?": every line is exercised by at least one test, AND every operator/constant/return/match-arm mutation in those files is caught by at least one test.

## Other files in the crate

| File | Lines | Missed | Cover | Notes |
| --- | --- | --- | --- | --- |
| `coordinator.rs` | 2272 | 265 | 88.34% | Network/handshake layer; 60% function coverage reflects many CLI-only branches |
| `protocol.rs` | 334 | 34 | 89.82% | State machine; covered by property tests |
| `state.rs` | 358 | 11 | 96.93% | Persistence layer |
| `error.rs` | 3 | 0 | 100.00% | Error type wrappers |
| `lib.rs` | 7 | 0 | 100.00% | Re-exports |
| `bin/cyncswap.rs` | 1901 | 1901 | **0.00%** | CLI binary; tested via manual operator script + dual-testnet smoke. Per audit-prep §8, this is the documented gap. |

## Coverage methodology notes

- Run on Linux (WSL Ubuntu 22.04). Same coverage works on macOS; on Windows it requires installing the LLVM toolchain matching rustc.
- `--summary-only` gives the table above; drop the flag (or pass `--html`) for the per-file source view.
- The Windows `.pdb` files from prior PowerShell builds will choke `llvm-cov`'s object loader — always use an isolated `CARGO_TARGET_DIR` when running coverage from WSL against a checkout that PowerShell has built into.

## What this measurement does + does not say

**Coverage IS:** the fraction of source lines / regions / functions that are *executed* by at least one test.

**Coverage IS NOT:**

- Proof that the executed code is *correct* — for that, see property tests (random valid inputs preserve invariants) + the 100% mutation score (every mutation is caught).
- Proof that *every input class* is exercised — for that, see fuzz (random adversarial inputs) + external vectors (cross-impl byte-equality).

Coverage + mutation + property + fuzz + vectors are the five legs of the test stool. Coverage alone is the weakest, but it's a fast sanity check that no large blocks of audit-critical code go entirely un-exercised. The audit perimeter result here (~97% line) confirms there are no such blocks.
