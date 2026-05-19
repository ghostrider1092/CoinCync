<!-- markdownlint-disable MD036 MD013 -->
# Property-Based Testing Discipline

**Privacy money that requires no permission** rests on cryptographic invariants. Property tests are how we prove — automatically, on every commit — that those invariants actually hold. Fuzz proves the code doesn't crash. Property tests prove the code is *correct*.

**Status:** Active practice. Started 2026-05-18 with `crates/coincync-swap/tests/property_invariants.rs`. Extended through the rest of the week per the [v1.1 prep tracker](v1.1-prep.md).

---

## What property testing is

A property test:

1. Generates **hundreds of random valid inputs**
2. Runs an operation on each one
3. Asserts a **property** (an invariant) about the result

Example: *"For every valid (signing key, adaptor secret, message), the cycle create_pre_sig → decrypt → recover returns the original adaptor secret byte-for-byte."*

If the property holds on 256 random inputs, the probability it holds on input #257 is extremely high. Multiply by every commit running it in CI, and you've cheaply proven the math is sound for the entire input space — without writing a thousand individual unit tests.

---

## The complementary stack

| Tool | Catches | Misses |
| --- | --- | --- |
| **Unit tests** | Specific known cases | Anything the test author didn't think of |
| **Fuzz** (libFuzzer + ASAN) | Panics, memory bugs, crashes on adversarial input | Logic bugs (wrong-but-not-crashing answers) |
| **External vendor vectors** | Divergence from a reference implementation | Anything the reference also gets wrong |
| **Property tests** | Logic bugs (invariant violations) | Bugs not expressible as invariants (UX, ergonomics) |
| **Audit** | What humans see when reading code | What humans miss when reading code |

Each catches a class the others miss. The audit is irreplaceable but expensive; the others are cheap and reduce audit scope.

---

## What makes a good property

A property is good if:

1. **It's true.** If your test fails on the first run, either the property is wrong or your impl is buggy. Both are useful.
2. **It catches the right class of bug.** "Roundtrip equality" catches encoding bugs but not protocol-state bugs. State-machine properties catch protocol-state bugs but not crypto-primitive bugs. Pick the right shape for the threat.
3. **It's cheap to evaluate.** Each property runs 256 cases by default. If one property takes 10 seconds, 256 cases is 40 minutes. Aim for sub-second-per-case operations.
4. **It survives refactoring.** A property tied to internal implementation details breaks every time you reorganize code. Bind to *behavior*, not structure.
5. **Its failure mode is debuggable.** proptest shrinks failing inputs to a minimal counterexample. Write properties such that the minimal counterexample tells you what's wrong (a 32-byte secret showing a specific bit pattern is more useful than a million-byte payload).

Examples of well-shaped properties (already in the repo):

- `btc_adaptor_roundtrip` — encoding-preserving (catches byte-order, encoding, and arithmetic bugs)
- `btc_adaptor_binding` — security-property (catches the principal-loss-class bug)
- `cync_adaptor_roundtrip` — symmetric to BTC side
- `dleq_roundtrip` — protocol-essential (catches "honestly-built proofs fail to verify")

---

## When to add a new property

Add a property when:

1. **You ship a new cryptographic primitive.** Every primitive needs at least a roundtrip property and at least one negative property (wrong inputs are rejected).
2. **You ship a new state-machine.** Properties like "no reachable state has Alice and Bob both holding the same funds" are how you catch atomicity bugs.
3. **You receive an audit finding.** Convert it to a property test so the fix can't regress.
4. **You receive a bug report.** Same — convert "Alice's wallet did X when it should have done Y" into a property and the bug becomes auto-recurring-defended-against.
5. **You're about to refactor something risky.** Properties before refactor = safety net during refactor.

---

## When NOT to use property testing

Property testing is the wrong tool for:

1. **UI / UX bugs.** Properties don't help with "the button is in the wrong place" or "the error message is confusing."
2. **Network / IO logic.** Properties run in-process. Use integration tests for network behavior.
3. **Single-case regression tests.** If a specific input caused a bug, a 5-line `#[test]` is clearer than a property. Add the property as well if it covers the class of bug, but don't drop the specific case.
4. **Performance.** Properties run in tests; production performance needs benchmarks.

---

## Where property tests live in this repo

| Crate | File | Status | Owner |
| --- | --- | --- | --- |
| `coincync-swap` | [tests/property_invariants.rs](../crates/coincync-swap/tests/property_invariants.rs) | **Active** (4 crypto properties) | Project lead |
| `coincync-swap` | [tests/state_machine_invariants.rs](../crates/coincync-swap/tests/state_machine_invariants.rs) | **Active** (6 state-machine properties) | Project lead |
| `coincync` (main) | *not yet* | Planned for Friday (consensus-level properties: difficulty, block validation, fee market) | Project lead |
| `cynchub` | *not yet* | Skeleton crate; properties when implementation lands | Future |
| `coincync-rolling-finality` | *not yet* | Audit-cleared; properties would be defense-in-depth | Future |

---

## How to run property tests

```sh
# Run all property tests for a crate, release mode (much faster)
cargo test -p coincync-swap --test property_invariants --release

# Run just one property
cargo test -p coincync-swap --test property_invariants --release btc_adaptor_binding

# Crank up the case count (default 256)
PROPTEST_CASES=10000 cargo test -p coincync-swap --test property_invariants --release

# Re-run only a failing case after a fix
# (proptest auto-saves failing cases in proptest-regressions/*.txt)
cargo test -p coincync-swap --test property_invariants -- --include-ignored
```

---

## Triaging a property failure

When a property fails, proptest minimizes the input to a small counterexample. Steps:

1. **Read the failure message.** It includes the exact input and the assertion that fired.
2. **Reproduce locally.** Copy the input into a one-off unit test (`#[test]`) so you can debug it without proptest's machinery.
3. **Decide: bug or property error?** If the math says the property should hold but the code says otherwise → code bug. If the math itself was wrong → property bug; fix the property.
4. **Fix the bug or the property.** Either way, commit + push so CI re-runs.
5. **Keep the regression case.** proptest auto-saves the minimal counterexample in `proptest-regressions/`. Commit that file — it becomes a permanent test case for this specific input.

---

## Budget per property

| Operation cost | Default 256 cases | At 10,000 cases |
| --- | --- | --- |
| Pure scalar arithmetic | <1 ms total | <40 ms |
| One Schnorr sig + verify | ~100 ms total | ~4 sec |
| One full atomic-swap protocol round | ~1 sec total | ~40 sec |
| One block validation | ~1 sec total | ~40 sec |

Tonight's `tests/property_invariants.rs` runs all 4 properties (1,024 cases) in 0.09 sec. Budget for CI: keep the *whole property-test suite* under 10 sec on release mode, so it stays cheap to run on every commit.

---

## Relationship to the audit posture

This file is part of the [Farcaster/Comit alignment plan](cyncswap-farcaster-comit-alignment.md). Property tests sit alongside the external vector harness and the fuzz suite as the three pre-audit assurance layers:

1. **Fuzz** — no input crashes the code (proven over 8+ hours nightly)
2. **External vectors** — outputs match Comit + Farcaster reference impls (planned; harness scaffolded)
3. **Properties** — invariants hold on every valid input (this file)

Together these turn the audit from "review a new design" into "verify a few specific suspected issues against an already-validated implementation." The cost reduction is real (~50% per the alignment doc) and the residual risk is correspondingly lower.

---

## Changelog

- **2026-05-18** — Document created. First active property test file lives in `crates/coincync-swap/tests/property_invariants.rs` with 4 properties: BTC roundtrip, BTC binding, CYNC roundtrip, DLEQ roundtrip. All pass on 256-case default.
