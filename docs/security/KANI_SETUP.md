# Kani — bounded model checking for CoinCync

[Kani](https://github.com/model-checking/kani) is AWS's bounded model
checker for Rust. It proves properties about pure-function code by
symbolic execution and SAT solving — where `cargo fuzz` tries random
inputs, kani provably enumerates ALL inputs within bounds.

CoinCync uses kani to prove monetary-policy invariants (emission
floor / ceiling, supply-cap arithmetic) and consensus-helper
correctness (hard-fork activation switch) on every input, not just
the hand-picked examples in unit tests. This is part of the audit-prep
posture documented in [docs/audit-submission.md](../audit-submission.md).

---

## Why kani in addition to fuzz + unit tests

|Tool|Strengths|Limits|
|---|---|---|
|`#[test]` examples|Cheap, fast, document intent|Only the cases you remember to write|
|`cargo fuzz`|Random exploration, finds shallow bugs in millions of trials|No guarantees — may miss bugs in a corner the RNG never visits|
|`cargo kani`|**Proves** the property for all inputs in scope|Only tractable for pure functions with bounded reasoning; cryptographic primitives are usually out of reach|

The three are complementary. Kani's value is *certainty* for the
narrow set of consensus invariants that decide whether two nodes
agree on the validity of the same block.

---

## Install (one-time)

Kani is Linux-only. From Windows, run inside WSL Ubuntu:

```bash
cargo install --locked kani-verifier
cargo kani setup
```

`setup` downloads:

- CBMC (the C bounded model checker that kani lowers to)
- An internal pinned Rust nightly (kani 0.67.0 ships nightly-2025-11-21)
- ~1 GB total on first install

The internal toolchain is isolated from the project's pinned 1.88.0 —
kani uses its own rustc, so the host toolchain doesn't need to match.

---

## Running the suite

```bash
# From WSL:
wsl -- bash /mnt/c/dev/coincync/scripts/kani-check.sh

# Or interactively from inside WSL:
cd /mnt/c/dev/coincync
./scripts/kani-check.sh
```

Run a single harness:

```bash
cargo kani --harness emission::kani_proofs::proof_reward_floor_is_tail
```

To enumerate the available harnesses, grep the proof modules:

```bash
grep -rn "#\[kani::proof\]" src/
```

(Older kani versions had `--list`; 0.67+ dropped it. The grep above is
equivalent and works on any version.)

Each proof typically discharges in under a minute for the pure-u128
arithmetic harnesses. Expect 30s – 5min total for the current suite.

---

## How proofs are organized

Proof harnesses live in **sibling files** to the code under test, not
inline in the locked consensus files. The reason: `src/constants.rs`,
`src/consensus/*.rs`, `src/emission/curve.rs` are protected by
`critical_files.lock` (build.rs verifies the SHA-256 on every build).
Inline proofs would force a lockfile refresh on every proof change.

Current proof files:

|File|Proves|
|---|---|
|[src/kani_proofs.rs](../../src/kani_proofs.rs)|`min_output_age_at_height` binary-switch correctness, post-fork branch, activity-bonus bounds|
|[src/emission/kani_proofs.rs](../../src/emission/kani_proofs.rs)|`base_reward_from_supply` floor (≥ tail), ceiling (≤ genesis), cap-equals-tail boundary, overflow safety|

Each module is gated behind `#[cfg(kani)]` and wired from the parent
module via `#[cfg(kani)] mod kani_proofs;`. Normal `cargo build` never
sees the proof code — zero release-binary impact.

The `cfg(kani)` marker is registered in `build.rs` so non-kani builds
don't warn about unexpected configuration.

---

## Adding a new proof

1. Identify a pure function whose properties matter for consensus or
   wallet correctness. Good candidates: arithmetic helpers, bounded
   state machines, lookup tables. Bad candidates: anything with
   network I/O, file system, dynamic dispatch, large recursion, or
   cryptographic primitive internals (CBMC chokes on them).

2. Decide which file to place proofs in:
   - If the parent file is in `critical_files.lock`: create a sibling
     `kani_proofs.rs` in the same directory (e.g.,
     `src/wallet/kani_proofs.rs`).
   - If the parent file is NOT locked: you may inline proofs at the
     bottom of the file behind `#[cfg(kani)]`.

3. Add the module declaration behind `#[cfg(kani)]` in the parent
   `mod.rs` or `lib.rs`. Match the existing pattern in
   `src/emission/mod.rs:14-17`.

4. Write the proof harness using `#[kani::proof]`:

   ```rust
   #[kani::proof]
   fn proof_my_invariant() {
       let x: u64 = kani::any();
       kani::assume(x < SOME_BOUND);  // optional input restriction
       let result = my_function(x);
       assert!(result.is_valid());
   }
   ```

5. Run `./scripts/kani-check.sh` from WSL to validate.

6. Document the proof's *property* (not just what code it touches) in
   the doc-comment. A reviewer should be able to read the comment and
   understand which consensus invariant would break if the proof
   failed.

---

## Common gotchas

- **Loops kill performance**: CBMC unwinds loops symbolically. Even
  a `for i in 0..100` will balloon proof time. Use `kani::any()` to
  abstract over the loop variable when possible.
- **`Vec<T>` is bounded** by kani's default `--default-unwind`. Pass
  `--unwind <N>` to extend, or use fixed-size arrays.
- **`std::collections::HashMap`** uses random hashing that breaks
  determinism. Use `BTreeMap` in proofs if you need a map.
- **External crates** (cryptographic libraries especially) are often
  intractable. Stub them with `#[cfg(kani)]` replacements if you must.
- **Saturating arithmetic** is kani's friend. Wrapping arithmetic
  generates many more cases. Prefer `saturating_*` operations in
  consensus code anyway.

---

## What's currently proved

As of 2026-05-28, 15 proof harnesses across three modules (full suite runs in ~156s):

**Emission curve** (4 proofs):

- Reward never drops below `TAIL_EMISSION` for any u128 supply input
- Reward never exceeds the genesis reward (50 CYNC)
- Reward at the exact supply cap equals `TAIL_EMISSION`
- No panic or overflow on any u128 input, including above-cap values

**Constants helpers** (3 proofs):

- `min_output_age_at_height` returns one of exactly two values
- Post-fork branch reached at and above the activation height
- `activity_bonus_rate` bounded in [100, 1000] bps for all inputs

**Consensus helpers — fee market + difficulty** (7 proofs):

- `congestion_multiplier` returns one of exactly {100, 150, 200, 300}
- `congestion_multiplier` is monotonically non-decreasing in congestion
- `calculate_fee` never panics for any (tx_size, congestion) pair
- `calculate_fee(0, _)` returns zero (boundary case)
- `distribute_fee`: `to_miner + burned + to_protocol == total` for all inputs (Article II conservation)
- `distribute_fee`: `to_protocol == 0` always (Constitution Article II)
- `max_target()` maps to difficulty 1 (difficulty-scale anchor)

---

## What kani does NOT cover (and why)

- **Privacy crypto** (CLSAG, Bulletproofs+, Pedersen) — these use
  curve25519-dalek and tari_bulletproofs_plus, both of which include
  inline assembly and large constant-time bit-twiddling that CBMC
  doesn't reduce well. Out of scope for kani; in scope for the
  Cypher Stack or OSTIF-paired audit.
- **Wallet KDF / AEAD** — Argon2id state is too large for CBMC to
  unroll. The wallet v4 file format will be reviewed by the audit
  firm, not by kani.
- **P2P / networking** — I/O effects outside kani's reasoning model.
- **Database / storage** — heap-allocated structures, lifetime
  reasoning issues.
- **Difficulty adjustment** — depends on a slice of arbitrary length
  (`&[DifficultyBlock]`). Kani can handle small bounded slices; the
  full adjustment math is a follow-up if a useful bounded property
  surfaces.

---

## CI integration (follow-up)

Not yet wired into GitHub Actions. Adding kani to CI requires:

1. A Linux runner with kani's bundled CBMC available (kani has an
   official GitHub Action: `model-checking/kani-github-action`).
2. A budget for ~10 min of proof time per push (current suite).
3. A policy decision on whether kani failures block merge or
   block release (recommend: block release only, since proof flakes
   are possible).

Track as a v1.0.11 or v1.1 line item depending on how much new
proof code accumulates.

---

**Last updated:** 2026-05-26
**Maintainer responsibility:** anyone modifying a function with a
kani proof should re-run `./scripts/kani-check.sh` before pushing.
