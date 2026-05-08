# Workspace split — migration checklist

**Status:** Plan, not executed. ~2 days of focused refactor.
**Goal:** split the monolithic `coincync` crate (1,500+ files,
492 lib tests, 3-min full-build cycle) into independent
workspace crates so test+compile times drop linearly with the
crate boundary.

---

## Why this matters

Current state:

- One `coincync` crate at the workspace root.
- 499 unit tests in a single test binary.
- Full-build time: ~1-3 minutes after a touch.
- Touching `src/wallet/balance.rs` recompiles every test in the
  whole project.

Splitting into per-domain crates:

```
coincync-primitives/    (Hash, Amount, KeyImage, PublicKey, ...)
coincync-crypto/        (CLSAG, BP+, stealth, view tags, ...)
coincync-consensus/     (validation, PoW, difficulty, emission, ...)
coincync-wallet/        (balance, send, scan, persistence, multisig, ...)
coincync-network/       (P2P, Dandelion++, Noise_XX, peer scoring, ...)
coincync-rpc/           (JSON-RPC server, REST proxy, allowlist, ...)
coincync-mempool/       (admit, ordering, eviction, ...)
coincync/               (the integrating crate; thin)
```

After: touching `coincync-wallet` recompiles `coincync-wallet`
+ `coincync` (the integrator). `coincync-network` etc. don't
rebuild. Estimated rebuild time: 30-60 sec for typical changes.

---

## Pre-conditions

- ☐ All current tests passing (verify with `cargo test
  --release --workspace` — currently 499 lib + integration; all
  green as of commit `491a796`).
- ☐ No in-flight branches with significant `src/` edits — this
  refactor will conflict with everything.
- ☐ Read this checklist end-to-end before starting; the order
  matters.

---

## Order (least-coupled first)

The dependency graph dictates the order. Going least-coupled
to most-coupled means each step's dependencies are already
crates by the time you hit them, so import paths only have
to change once per file.

1. `coincync-primitives` (depends on nothing internal)
2. `coincync-crypto` (depends only on primitives)
3. `coincync-consensus` (depends on primitives + crypto)
4. `coincync-mempool` (depends on consensus + transaction types)
5. `coincync-network` (depends on consensus + mempool + crypto)
6. `coincync-wallet` (depends on consensus + crypto + primitives)
7. `coincync-rpc` (depends on most of the above)
8. `coincync` (the integrator) — re-exports for backward compat

---

## Step-by-step (per crate)

For each crate in the order above, do this loop:

### Step A — create the workspace member

```bash
mkdir -p crates/coincync-<NAME>/src
```

Copy a `Cargo.toml` template from one of the existing workspace
members (`crates/coincync-faucet/Cargo.toml` is a good model):

```toml
[package]
name = "coincync-<NAME>"
version = "1.0.0"
edition = "2021"

[dependencies]
# ...whatever the source files import that's external...
serde = { workspace = true }
borsh = { workspace = true }

# Internal:
coincync-primitives = { path = "../coincync-primitives" }
# etc.
```

Add the new crate to the workspace `Cargo.toml`:

```toml
[workspace]
members  = [".", "crates/bridge", "crates/coincync-rig",
            "crates/coincync-swap", "crates/coincync-faucet",
            "crates/coincync-<NAME>"]   # NEW
```

### Step B — move files

```bash
git mv src/<MODULE>/ crates/coincync-<NAME>/src/
```

Use `git mv` (not `mv`) so the move is captured as a rename
in the diff, preserving history.

### Step C — fix imports inside the moved files

In every moved file, replace:
- `crate::primitives::Hash` → `coincync_primitives::Hash`
- `crate::crypto::CLSAG` → `coincync_crypto::CLSAG`
- etc.

Faster than hand-editing: use sed across the moved tree:

```bash
find crates/coincync-<NAME>/src -name '*.rs' -exec \
  sed -i 's|crate::primitives::|coincync_primitives::|g' {} \;
```

Do this for each external module the files use.

### Step D — fix imports OUTSIDE the moved files

The OLD path `crate::<MODULE>::*` is now gone from the main
crate. Every file that used to reach into the moved module
must now use the new crate name.

Easiest: in `src/lib.rs`, add re-exports for backward compat:

```rust
// Backward-compat re-exports — until callers migrate.
pub use coincync_<NAME> as <module>;
```

Then existing `use crate::<module>::Foo` paths still work via
the re-export. Land the split, THEN clean up callers in a
follow-up commit.

### Step E — verify

```bash
cargo build --release --workspace
cargo test --release --workspace
```

Both must pass before moving to the next crate. If either
fails, fix BEFORE starting the next step.

### Step F — commit

```bash
git commit -m "split: extract coincync-<NAME> from main crate"
```

One commit per crate. Each one must compile + pass tests on
its own. This makes bisecting any future regression
straightforward.

---

## Specific gotchas

### Test files

`tests/` at the workspace root holds integration tests against
the main `coincync` crate. After the split, some of those tests
exercise things that now live in sub-crates. Three options:

1. **Keep them at the root** — the integration tests use the
   re-exports added in Step D, so they keep working unchanged.
2. **Move to per-crate tests** — `tests/` per crate. Cleaner
   but more upfront work. Defer until after the split lands.
3. **Hybrid** — root `tests/` for cross-crate integration
   (e.g., wallet+network end-to-end), per-crate `tests/` for
   per-domain integration. This is where the project will
   likely end up.

### `feature` flags

The current crate has `[features] randomx`, `testnet`, etc.
After the split, features apply per-crate. Check which crate
each feature is meaningful for and move the `[features]`
table to the right `Cargo.toml`. Likely candidates:

- `randomx` → `coincync-consensus` (it gates the PoW verifier).
- `testnet` → root `coincync` (affects activation heights,
  network magic, etc. — cross-cutting; keeps it in the
  integrator).

### `bin/` targets

The main crate has bin targets in `src/bin/`:
- `coincync-node`
- `coincync-wallet`
- `update-critical-hashes`

Decide: do these stay in the root crate (which becomes a thin
integrator + bins) or move to their own crate? Recommendation:
keep them in the root crate. The integrator owns the bins.

### `critical_files.lock`

The lockfile pins file paths like `src/constants.rs`. After
split, these become `crates/coincync-consensus/src/constants.rs`
or wherever the file ends up. The lockfile and `build.rs` need
updates. Plan: update both atomically with the moves.

### `coincync-wallet/` (the Tauri desktop app)

There is also a `coincync-wallet/` directory at the workspace
root that's the Tauri/React desktop app — it is EXCLUDED from
the workspace via `Cargo.toml`'s `exclude = ["coincync-wallet/src-tauri"]`.
Don't confuse this with the new `crates/coincync-wallet/` from
the split. To avoid the name clash, name the split crate
something else: `crates/coincync-wallet-core` or
`crates/coincync-wallet-lib`. The desktop app keeps its existing
name.

---

## Estimated effort

- Step A-F per crate: 1.5-2 hours each.
- 7 crates × 2 hours = ~14 hours.
- Plus: time fighting compiler errors at boundaries,
  rebuilding the lockfile, validating the bins still work,
  CI catches.

Realistic total: **2 working days**, possibly 3 if there are
non-trivial cyclic deps surfaced (which there shouldn't be —
the order above is acyclic — but the compiler always finds
something).

## When NOT to do this refactor

- **Right before launch.** This is a refactor; it adds risk
  with zero user-visible benefit. Do it AFTER the testnet is
  stable and AFTER any pending hotfixes have shipped.
- **In one massive commit.** Land it as 7 commits per the
  procedure above. Bisecting a regression in a 14-hour mega-
  commit is genuinely awful.
- **While anyone else is working on `src/`.** Conflicts will be
  miserable. Either solo this when no other branches are live,
  or coordinate.

## How to validate the split actually paid off

After landing all 7 splits:

```bash
# Touch one file in coincync-wallet:
touch crates/coincync-wallet-core/src/balance.rs

# Time the rebuild:
time cargo build --release --workspace
```

Expect: ~30-60 seconds for typical wallet edits, vs the current
~3 minutes. If it's still ~3 minutes, the dependency graph
isn't actually decoupled — something is pulling in too much.
Investigate which crate is rebuilding when it shouldn't.

If the rebuild time doesn't drop meaningfully, the refactor
wasn't worth it. Document that finding and roll back; don't
preserve a slow-AND-complicated build.
