# Code-practices checker

`scripts/check_code_practices.py` reads the CoinCync source and reports — in
plain English, located by **file, line, and enclosing section (fn/impl/mod)** —
where code departs from the project's "right way", and how it is supposed to be
done instead.

This is the content-level upgrade to the best-practices tooling: the older
scripts classify files by *path* (review tiers) or check fixed substrings; this
one analyses code and explains each finding.

## Run it

```bash
python scripts/check_code_practices.py                 # check src/ (default)
python scripts/check_code_practices.py src/consensus   # a subtree or single file
python scripts/check_code_practices.py --errors-only    # only error-severity
python scripts/check_code_practices.py --rule DET-FLOAT # one rule
python scripts/check_code_practices.py --summary        # counts only
python scripts/check_code_practices.py --json           # machine-readable
python scripts/check_code_practices.py --selftest       # verify the rules
python scripts/check_code_practices.py --strict         # exit 1 on any error
```

Exit code is `0` unless `--strict` is given and an error-severity finding
exists, so it is safe to run informally and still usable as a CI gate.

## What it checks ("the right way")

| Rule | Sev | Scope | What it means |
|------|-----|-------|---------------|
| `DET-FLOAT` | error | `src/consensus/`, `src/emission/` | No `f64`/`f32` — floats are non-deterministic across CPUs and can fork the chain (H-1). Use u128 fixed-point. |
| `DET-CLOCK` | warn | `src/` (not `clock.rs`/bins) | No direct `SystemTime::now()`/`Instant::now()` — use the clock seam (E1) so runs are deterministic. |
| `DET-RNG` | warn | consensus/mining/network | No `thread_rng()`/`OsRng` — use the seeded RNG seam (E3) so runs replay from a seed. |
| `PANIC-CONSENSUS` | warn | `src/consensus/` | No `unwrap`/`expect`/`panic!`/`todo!` on the consensus path — a crafted input would crash the node; return an `Error`. |
| `CAST-TRUNCATE` | warn | `src/consensus/` | No narrowing `as u8/u16/u32/i8/i16/i32` — `as` truncates silently; use `try_from`/`try_into` and handle overflow. |
| `ERROR-UNCODED` | info | `src/consensus/` | A consensus rejection (`InvalidTransaction`/`PowValidation`/…) with no `CYNC_*` code within 4 lines — it won't show in the flight recorder / `coincync-diag`. |
| `HYGIENE-PRINT` | warn | `src/` lib (not bins/cli/explorer) | No `println!`/`eprintln!`/`dbg!` in library code — use `tracing`. |
| `HYGIENE-MARKER` | info | `src/` | Flags `TODO`/`FIXME`/`XXX`/`HACK`. |
| `ALLOW-LINT` | info | `src/` | Flags `#[allow(...)]` suppressions to re-justify. |
| `UNSAFE` | warn | `src/` | Flags `unsafe` blocks/fns/impls to confirm a SAFETY rationale. |

Test code (`#[cfg(test)]` / `mod tests`) is exempt from the code rules.

## Suppressing a reviewed, intentional case

Add an inline marker on the flagged line or the line directly above it:

```rust
// check-allow: DET-FLOAT
pub fn estimate_hashrate(..) -> f64 { .. }   // informational, not consensus
```

Use `check-allow: all` to suppress every rule on that line. Prefer fixing the
cause; suppress only genuinely-correct exceptions, and leave the reason nearby.

## Adding a rule

Append a `Rule(...)` to `RULES` in the script: an id, a severity, a regex, a
plain-English `problem` and `right_way`, whether it matches `code` or `comment`,
and the `include`/`exclude` path scopes. Then extend `--selftest`'s fixture so
the new rule is covered.
