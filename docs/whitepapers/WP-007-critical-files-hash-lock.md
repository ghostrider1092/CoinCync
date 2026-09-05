# WP-007 · Consensus Integrity by Build Gate
### The critical-files hash lock

**Status:** Shipped · **Layer:** Build / Process · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Most consensus failures are not attacks. They are edits.

A linter reformats a constant. A refactor "simplifies" a comparison in the
difficulty calculation. An IDE rewrites line endings. A well-meaning contributor
tidies the emission curve. Each of these produces a binary that disagrees with the
network about which blocks are valid — and none of them look dangerous in a diff.

The problem is that consensus-critical code is **indistinguishable from ordinary
code** to every tool that touches it. Nothing in the file says "changing this
splits the chain."

CoinCync's answer is a build gate: a small set of files whose bytes are pinned by
hash, so that any change — intentional or not — **fails the build** until a human
deliberately re-locks it.

---

## 2. Threat addressed

| Failure | Assumption it needs | What we removed |
|---|---|---|
| **Accidental consensus edit** — lint, refactor, formatter, or merge artifact | Consensus files can be edited like any others | Any byte change fails the build |
| **Silent constitutional drift** — the governing documents diverge from the code that implements them | Docs are not consensus | `CONSTITUTION.md` and `BILL_OF_RIGHTS.md` are locked alongside the code |
| **Cross-platform hash mismatch** — CRLF vs LF makes the gate fail for Windows contributors | Byte-identity is portable | Line endings normalised (CRLF → LF) before hashing |
| **Missing-lock bypass** — delete the lockfile and the check disappears | An absent gate is an open gate | A missing lockfile is a **hard build failure**, not a skip |
| **Drift between the checker and the refresher** | Two file lists stay in sync by discipline | Both lists documented as lock-step; a mismatch breaks the build |

---

## 3. Design

### 3.1 What is locked

Eight files, each carrying a SHA-256 of its normalised bytes in
`critical_files.lock`:

| File | Why |
|---|---|
| `src/constants.rs` | Ring size, supply cap, intervals, caps — the parameters |
| `src/consensus/difficulty.rs` | The retarget rule (WP-001) |
| `src/consensus/pow.rs` | Anchor derivation and RandomX binding (WP-004) |
| `src/consensus/validation.rs` | Block and transaction validity |
| `src/emission/curve.rs` | The issuance schedule (WP-003) |
| `src/testnet.rs` | Testnet genesis and parameters |
| `CONSTITUTION.md` | The governing document |
| `docs/BILL_OF_RIGHTS.md` | The declared user rights |

Including the two **documents** is a deliberate statement. The Constitution's 0%
dev tax and the Bill of Rights' privacy articles are the reason specific code in
the locked set looks the way it does. Locking the prose alongside the
implementation means the justification cannot be quietly edited to match a change
in behaviour — the direction of drift that matters most.

### 3.2 How the gate runs

`build.rs` runs before every compilation: it hashes each listed file, normalises
CRLF to LF, and compares against the lockfile. A mismatch fails the build with a
message naming the file and the remedy.

Because it is a **build script**, the gate cannot be skipped by running a
different command. `cargo build`, `cargo test`, `cargo run`, and CI all pass
through it. There is no configuration to disable it.

### 3.3 The deliberate re-lock

Consensus files *do* legitimately change. The escape hatch is explicit and
single-purpose:

```
COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes
```

`COINCYNC_REGEN_LOCK` must be **exactly `1`** — any other value panics rather
than being interpreted loosely, so a stray `0` or `false` cannot half-enable the
bypass. When set, the missing-lock and mismatch checks relax to warnings, purely
so the updater binary can build in order to regenerate the file it depends on.
Every other build treats both conditions as hard failures.

The regenerated lockfile is committed **alongside** the change, which is the
property that makes the mechanism useful in review: a consensus change is never a
one-file diff. It always shows up as `critical_files.lock` moving, which is
impossible to miss and impossible to do by accident.

### 3.4 Missing lock = hard failure

If `critical_files.lock` is absent, the build fails. It does not warn and
continue.

This is the difference between a gate and a suggestion. A check that silently
passes when its reference data is missing protects nothing — deleting one file
disables it, and a build that produced no consensus binary would look identical to
one that did. The lockfile's absence is treated as evidence the gate cannot run,
which is exactly when it must not be assumed to have passed.

### 3.5 Normalisation, and why it is in scope

Hashes are computed over bytes with CRLF normalised to LF, so Windows and Linux
contributors produce identical values. Without this the gate would fail for
platform reasons unrelated to consensus — and a gate that cries wolf gets
disabled. **Making a security control usable is part of making it effective.**

---

## 4. Security analysis

**What holds.** No consensus-critical file changes without a deliberate,
reviewable, two-file commit. Accidental edits — formatters, lints, merges, line
endings — fail immediately and loudly at the point of change rather than in
production.

**What this does not protect against.**

- **It is not tamper-proof.** Anyone who can edit the source can also run the
  re-lock command. The gate raises accidents into deliberate acts; it does not
  stop a determined author. Against a hostile committer, the defense is code
  review and reproducible builds (WP-026), not this.
- **`src/mainnet.rs` is NOT locked.** Mainnet genesis and initial difficulty can
  currently be edited without tripping the gate, while `src/testnet.rs` cannot.
  This is a real asymmetry in the wrong direction and is recorded here as an open
  item rather than presented as intentional.
- **Only listed files are protected.** Consensus-relevant logic that migrates
  into an unlisted file — a new helper module, a moved function — leaves the
  protected set silently. The list needs review whenever consensus code is
  refactored across file boundaries.
- **The gate checks bytes, not meaning.** A re-lock with a bad change is as
  accepted as a re-lock with a good one. It creates a review checkpoint; it does
  not perform the review.
- **Two lists must stay in sync.** `build.rs` and
  `src/bin/update_critical_hashes.rs` each carry the file list. They are
  documented as lock-step, but the coupling is convention, not compilation.
- **Operational friction is real.** Re-locking requires building the updater, and
  on Windows the workflow has needed elevation in practice. Friction is the
  intended cost; it is still a cost.

---

## 5. Implementation

| Component | Location |
|---|---|
| Build-time gate, normalisation, missing-lock failure | `build.rs` |
| Pinned hashes | `critical_files.lock` |
| Deliberate re-lock tool | `src/bin/update_critical_hashes.rs` |
| Locked consensus sources | `src/constants.rs`, `src/consensus/{difficulty,pow,validation}.rs`, `src/emission/curve.rs`, `src/testnet.rs` |
| Locked governing documents | `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md` |

**In practice.** The gate has fired on real changes during development — the ASERT
startup grace in `difficulty.rs` and the proof-of-work-skip removal in
`validation.rs` both required an explicit re-lock, which is the mechanism working
as designed.

---

## 6. Known limits

- `src/mainnet.rs` is unlocked (§4) — the most significant gap.
- Protects listed files only; refactors can move logic out of scope.
- Bypassable by anyone who can commit.
- Checker and refresher file lists are coupled by convention.
- No enforcement that a re-lock was accompanied by review.

---

## 7. References

- Reproducible-builds practice — the complementary control for "the binary
  matches the source" (WP-026); this paper covers "the source matches what was
  agreed."
- Internal: [WP-001 Difficulty](WP-001-difficulty-stability.md),
  [WP-003 Emission](WP-003-emission.md),
  [WP-004 PoW binding](WP-004-pow-binding.md),
  [WP-026 Reproducible builds](WP-026-reproducible-builds.md),
  `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md`.
