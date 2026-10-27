# PR carving checklist — feat/live-chaos-harness → main

Carve the review branch into **6 curated PRs** as a **contiguous stack in history
order** (CIP-011 = the bridge). This supersedes the earlier 5-PR cherry-pick plan,
which was wrong: Beta is **not** independent of the bridge, Beta **does** touch a
locked file, and that plan dropped the beta-genesis commit. See "Why a stack, not
cherry-picks" below.

## Why a stack, not cherry-picks (the dependency facts)

Verified against the trees on 2026-10-26:

- `regtest_bridge_enabled(network)` is introduced by the **bridge** commit
  `d9bb83ef` — it is **absent on `origin/main`**. So `a801b91d`'s "enable the
  shielded bridge on Beta" (`Regtest` → `Regtest | Beta`) hard-depends on the
  bridge. **Beta cannot sit on `main` alone.**
- `NetworkType::Beta` is introduced by `42f53834`; `a801b91d` adds the remaining
  exhaustive-match arms (`config.rs`, `fingerprint.rs`, `node.rs`) that the
  cherry-picks "didn't reach". Without `a801b91d` the **Beta build does not
  compile** on this branch. And `a801b91d` edits locked `validation.rs` + the
  lock → **the Beta PR is LOCKED**, not lock-free.
- `SWEEP 61386523` and `UNSHIELD ce61a562` both edit locked `validation.rs`; in
  history they land *after* `a801b91d`. A cherry-pick plan that pulled them in
  front of Beta would fight `validation.rs`/lock conflicts. A **contiguous stack
  never reorders them**, so that risk is gone.

Because the branch history is already a valid, compiled, signed sequence, each PR
is just a **range boundary** on it — no cherry-pick, no conflict, authorship and
signatures preserved. The only new commit is the post-soak ACTIVATION knob.

## Rules (standing)

Signed commits only (`git commit` signs; never `-c commit.gpgsign=false`);
squash-only merges; **open ≠ merge** — a LOCKED PR merges only after **2-of-N**
owner sign-off (@ghostrider1092 / @junbyjun1238 / @0x4D-5A, 2 of 3). Carve git via
Windows Git Bash (not inside WSL). Each carved branch MUST build + pass its slice
before the PR is marked ready (focused-PR gotcha: a branch missing a companion
test breaks main's gate — grep `src/` AND `tests/`). Do not run the gated build
while a chaos soak holds the binaries.

## The stack (contiguous ranges, oldest→newest)

```
origin/main
  └─#1 BREAKERS      23238d98..1f28d765   (3 commits)   no lock
      └─#2 HARNESS   111bbdc9..5f734e95   (4 commits)   no lock (test-only)
          └─#3 CIP-011 BRIDGE  d9bb83ef..e9070f8e  (2)  LOCKED  validation.rs+lock
              └─#4 BETA NET     42f53834..a801b91d (9)  LOCKED  validation.rs+lock
                  └─#5 SWEEP+UNSHIELD  61386523..ce61a562 (2) LOCKED validation.rs+lock
                      └─#6 ACTIVATION+CI+DOCS  715266b1..HEAD + post-soak knob  LOCKED constants.rs+lock
```

Branch = `git branch <name> <tip-sha>` at each boundary (no cherry-pick). Base
each PR on its parent branch; squash-merge bottom-up, re-targeting each child to
`main` as its parent merges (stacked-PR gotcha: re-landing the tip carries
ancestors).

---

## PR #1 — Circuit-breaker suite + fuse box  (no lock)
- `git branch cip/circuit-breakers 1f28d765`  (tip of BREAKERS)
- Base: `origin/main`. Range: `23238d98 c62bc794 1f28d765`.
- Verify: `cargo test --release --lib --features "randomx testnet fuse block-integrity-breaker supply-breaker shielded-breaker"`
- Body: `scratchpad/pr1-breakers.md`

## PR #2 — Chaos/soak harness (TEST-ONLY, no lock)  [on #1]
- `git branch cip/chaos-harness 5f734e95`  (tip of HARNESS)
- Base: `cip/circuit-breakers`. Range: `111bbdc9 4895ccf9 af9b8094 5f734e95`.
- Verify: builds with the full chaos set incl. `regtest-chaos` + `test-fast-pow`
  (harness build) — NOT a correctness gate.
- Body: `scratchpad/pr2-harness.md`

## PR #3 — CIP-011: Option-B shielded bridge  (LOCKED → 2-of-N)  [on #2]
- `git branch cip-011/shielded-bridge e9070f8e`  (tip of BRIDGE)
- Base: `cip/chaos-harness`. Range: `d9bb83ef e9070f8e`.
- Verify: GATED suite `2400/0`, NO test-fast-pow:
  `SPARK_OPENSSL_DIR=/usr cargo test --release --lib --features "testnet fuse block-integrity-breaker supply-breaker shielded-breaker regtest-chaos sketch-gk-proof libspark-ffi"`
- `cargo check` runs build.rs integrity → `critical_files.lock` must match.
- **2-of-N** on `validation.rs` + lock. Mark "DO NOT MERGE until 2-of-N".
- Body: `scratchpad/pr3-cip011-bridge.md`

## PR #4 — Beta staging network  (LOCKED → 2-of-N)  [on #3]
- `git branch cip/beta-network a801b91d`  (tip of BETA; **includes `e71b29f0`
  beta-genesis** — do not drop it)
- Base: `cip-011/shielded-bridge`. Range: `42f53834 e71b29f0 c488d061 93975299
  2a851d33 37b8b069 1671130b 4eba9fb1 a801b91d`.
- Depends on #3: `a801b91d` enables `regtest_bridge_enabled` for Beta and adds the
  exhaustive-match arms (doc this in the PR body). Touches locked `validation.rs`.
- Verify: `cargo build --release --features "randomx testnet"` (beta boots under
  the standard set) AND the gated suite green (same features as #3).
- **2-of-N** on `validation.rs` + lock.
- Body: `scratchpad/pr4-beta.md`

## PR #5 — Audit sweep + Wallet-1 + unshield/stealth  (LOCKED → 2-of-N)  [on #4]
- `git branch cip-011/sweep-unshield ce61a562`  (tip of UNSHIELD)
- Base: `cip/beta-network`. Range: `61386523 ce61a562`.
- The 16-bug audit sweep + Wallet-1 key-epoch + unshield-to-transparent + harness
  stealth fix. Touches locked `validation.rs`.
- Verify: GATED suite `2400/0` (same features as #3).
- **2-of-N** on `validation.rs` + lock + the signoff doc.
- Body: `scratchpad/pr5-sweep-unshield.md`

## PR #6 — Testnet activation knob + CI gate + audit docs  (LOCKED → 2-of-N)  [on #5]
- `git branch cip/shielded-activation <post-soak knob commit>`  (created post-soak)
- Base: `cip-011/sweep-unshield`. Range: `715266b1 69ef7174 e8b9ef3d 0a256eb7
  16b234fd` + the **post-soak `constants.rs` knob commit** (placeholder `u64::MAX`;
  needs lock regen — created after the soak frees the binaries).
- Verify: gated `2400/0` (same features as #3) incl.
  `shielded_activation_mainnet_permanently_off_testnet_is_dedicated_knob`.
- **2-of-N** on `constants.rs` + lock.
- Body: `scratchpad/pr6-activation.md`

---

## Merge order
- Mergeable first (no lock, review-only): **#1, #2**.
- LOCKED, merge bottom-up after 2-of-N, re-targeting each child to `main` as its
  parent merges (squash-only): **#3 → #4 → #5 → #6**.
- Nothing merges to protected `main` without signed commits + green CI
  (`integration-tests` all-shards, `shielded-gate`, `critical-lock`) + 2-of-N on
  every LOCKED PR.

## Note
The whole branch is already exposed for review as **draft PR #342** with the
auditor entry point (`docs/audit/audit-pack-2026-10-26-shielded-bridge.md`). This
6-PR stack is the *merge* path; #342 stays the *review* vehicle until the stack
lands.
