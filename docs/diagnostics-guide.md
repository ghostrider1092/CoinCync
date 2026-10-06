# CoinCync Diagnostics — a statement for maintainers

## Why this exists

CoinCync is now large enough that the slowest part of fixing a bug is **finding
it** and **understanding what rule it broke**. A node logs `BlockStatus::Invalid`,
a soak panics with a seed, a reorg leaves a scary one-line warning — and then
someone greps 200k lines trying to reconstruct which invariant failed and where.
That cost grows with the tree. It also makes the codebase harder for new
maintainers and auditors to reason about.

We're fixing that the way the Rust compiler did for *compile* errors: **every
runtime and consensus failure gets a stable code and an `--explain`.** When
something breaks, you don't search — you read.

## What it is

A single catalog (`src/diagnostics.rs`, `CATALOG`) where each failure class has a
stable code `CYNC-<DOMAIN>-<NNN>` and a fixed set of fields: the invariant it
guards, the code location that enforces it, the spec/CIP that defines it, and
fix guidance. When a failure actually happens, the code emits a `Report` that
adds the live context and renders compiler-style:

```
error[CYNC-STOR-001]: reorg could not roll back a Phase-2 store (state stranded)
  --> height 142, spark store
   = invariant : every disconnected block's Phase-2 state rewinds in lock-step with the UTXO set
   = expected  : 0 elements after rewind
   = got       : 3 element(s) stranded above the new tip
   = where     : src/chain.rs::rewind_phase2_stores (+ src/storage/phase2.rs)
   = spec      : src/storage/phase2.rs (Phase2Store lock-step contract)
   = help      : …must not activate until rewind checkpoints are restart-durable…
```

That one block is **find** (`where`), **understand** (`invariant` / `expected` /
`got` / `help`), and **fix + reproduce** — no grep.

## What this means for you, day to day

**Debugging.** See a code in a log, a panic, or a failed test? Run:

```
coincync-diag explain CYNC-STOR-001     # the full catalog entry
coincync-diag list                      # every code, one line each
```

It points you straight at the subsystem, the rule, and the spec. You navigate
the codebase *by the failure you observed*, not by familiarity with the tree.

**Writing a new check.** When you add a consensus check, an invariant, or a
reject path, give it a diagnostic instead of a bare string:

1. Add a `Diagnostic` to `CATALOG` with the next free code in its domain, a clear
   invariant, the `where`, the spec link, and real `help`.
2. Add a `CYNC_<DOMAIN>_<NNN>` const and emit it:
   `tracing::error!("\n{}", Report::new(CYNC_STOR_001).at(…).expected(…).got(…));`
3. If your check has a test or soak, have the failure print the `Report` (and a
   reproduce handle — a seed, a block hash).

**The rules (so it never rots):**

- **Codes are stable and append-only.** Never renumber or reuse a code — people,
  logs, and docs reference them. Retire one by marking it, never by recycling it.
- **One source of truth.** The catalog drives the runtime message, `explain`, and
  the generated `DIAGNOSTICS.md`. Don't duplicate the text anywhere else.
- **Reference the const, not the string.** Emit `CYNC_STOR_001`, never
  `"CYNC-STOR-001"`, so a typo is a compile error and `grep CYNC_` finds every
  emission site.
- **CI guards it** (next slice): a code emitted in the tree but missing from the
  catalog fails the build, so the catalog stays complete as we grow.

## Where it's going

This is maintainer infrastructure first, but it's also a differentiator. Most
chains surface failures as opaque reject reasons and panics. A first-class,
documented, stable **diagnostic-code system for consensus and runtime failures**
— explainable, located, reproducible — is something the crypto space doesn't
really have. It makes CoinCync faster to maintain, easier to audit (the catalog
is a map of every safety property and where it's enforced), and more legible to
everyone who touches it. We extend it one check at a time; every code we add
makes the next bug cheaper to find.

— Start with `coincync-diag list`, and add a code the next time you write a check.
