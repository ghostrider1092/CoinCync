# PR carving checklist — feat/live-chaos-harness → main

Carve the 24-commit review branch into 5 curated PRs (CIP-011 = the bridge).
Order below is the dependency order. #1, #2, #3 are independent/low-risk (no
locked files). #4, #5 touch LOCKED consensus files → **2-of-N before merge**.
#4→#5 are **stacked** (the sweep edits bridge code), so base each on the prior.

Rules (standing): signed commits only (`git commit` signs; never
`-c commit.gpgsign=false`); squash-only merges; **open ≠ merge** — merge #4/#5
only after 2-of-N. Carve git via Windows Git Bash (not inside WSL). Each carved
branch MUST build + pass its slice before the PR is marked ready (focused-PR
gotcha: a branch missing a companion test breaks main's gate — grep `src/` AND
`tests/`).

Commit groups (from the review branch, oldest→newest within each group):

- **BREAKERS**: 23238d98, c62bc794, 1f28d765
- **HARNESS** (test-only): 111bbdc9, 4895ccf9, af9b8094, 5f734e95
- **BRIDGE**: d9bb83ef, e9070f8e
- **BETA**: 42f53834, c488d061, 93975299, 2a851d33, 37b8b069, 1671130b, 4eba9fb1, a801b91d
- **SWEEP**: 61386523  (audit sweep + Wallet-1; LOCKED validation.rs)
- **UNSHIELD**: ce61a562  (LOCKED validation.rs)
- **CI/DOCS**: 715266b1, 69ef7174, e8b9ef3d, 0a256eb7
- **ACTIVATION**: (post-soak) constants.rs knob commit (LOCKED constants.rs)

---

## PR #1 — Circuit-breaker suite + fuse box  (independent, no lock)
- Branch: `cip/circuit-breakers` off `origin/main`
- `git checkout -b cip/circuit-breakers origin/main`
- `git cherry-pick 23238d98 c62bc794 1f28d765`
- Verify: `cargo test --release --lib --features "randomx testnet fuse block-integrity-breaker supply-breaker shielded-breaker"`
- `git push origin cip/circuit-breakers` (+ mirror) ; `gh pr create --base main --title "CIP: safety circuit-breaker suite + fuse box (observe-only, gated OFF)" --body-file <desc>`

## PR #2 — Beta network  (independent, no lock)
- Branch: `cip/beta-network` off `origin/main`
- `git cherry-pick 42f53834 c488d061 93975299 2a851d33 37b8b069 1671130b 4eba9fb1 a801b91d`
- Verify: `cargo build --release --features "randomx testnet"` + `cargo test --release --lib --features "randomx testnet"`
- push + `gh pr create --base main --title "feat: isolated Beta test network"`

## PR #3 — Chaos/soak harness (TEST-ONLY, no lock)  [stacks on #1]
- Branch: `cip/chaos-harness` off `cip/circuit-breakers` (needs the breakers)
- `git cherry-pick 111bbdc9 4895ccf9 af9b8094 5f734e95`
- Verify: builds with the full chaos set incl. `regtest-chaos` + `test-fast-pow` (harness build) — NOT a correctness gate
- push + `gh pr create --base cip/circuit-breakers` (re-target to main after #1 merges)

## PR #4 — CIP-011: Option-B shielded bridge  (LOCKED → 2-of-N)  [stacks on #3]
- Branch: `cip-011/shielded-bridge` off `cip/chaos-harness`
- `git cherry-pick d9bb83ef e9070f8e 61386523 ce61a562`
- Verify: GATED suite `2400/0`, NO test-fast-pow:
  `SPARK_OPENSSL_DIR=/usr cargo test --release --lib --features "testnet fuse block-integrity-breaker supply-breaker shielded-breaker regtest-chaos sketch-gk-proof libspark-ffi"`
- Confirm `critical_files.lock` matches (`cargo check` runs build.rs integrity).
- **2-of-N** on validation.rs + lock (signoff doc). Mark PR "DO NOT MERGE until 2-of-N".
- push + `gh pr create --base cip/chaos-harness --title "CIP-011: Option-B transparent<->shielded bridge (gated OFF, pre-audit)"`

## PR #5 — Testnet activation + CI gate + audit docs  (LOCKED → 2-of-N)  [stacks on #4]
- Branch: `cip/shielded-activation` off `cip-011/shielded-bridge`
- Bring in CI/DOCS: `git cherry-pick 715266b1 69ef7174 e8b9ef3d 0a256eb7`
- Bring in ACTIVATION: the post-soak `constants.rs` knob commit (placeholder u64::MAX)
  — this commit is created post-soak (needs lock regen); until then PR #5 is DRAFT.
- Verify: gated `2400/0` (same features as #4) incl.
  `shielded_activation_mainnet_permanently_off_testnet_is_dedicated_knob`.
- **2-of-N** on constants.rs + lock.
- push + `gh pr create --base cip-011/shielded-bridge --title "feat: testnet shielded-activation knob + CI gate + audit docs (held)"`

---

## Independent vs stacked (merge order)
- Independent, mergeable in any order once reviewed: **#1, #2**.
- Stack (merge bottom-up, re-target each child to main as its parent merges;
  squash-only; per the stacked-PR gotcha, re-landing the TIP carries ancestors):
  **#1 → #3 → #4 → #5**.
- Nothing merges to the protected org `main` without signed commits + green CI
  (`integration-tests` all-shards, `shielded-gate`, `critical-lock`) + 2-of-N on
  #4/#5.
