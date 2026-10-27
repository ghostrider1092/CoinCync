# Audit pack — Option-B shielded bridge (2026-10-26)

Entry point for an external reviewer of the shielded work on
`feat/live-chaos-harness`. This is the map: what to read, in what order, how to
build + run the gated surface yourself, and the honest scope (what is gated,
test-only, and pre-audit). Nothing here is on `main` — this is a review branch.

## 0. Scope & honest status (read first)

- The shielded pool (Lelantus-Spark) + the Option-B transparent↔shielded
  **bridge** (shield-in / shielded-send / unshield) is **gated and pre-audit**.
  In a production build it compiles to a no-op: `regtest_bridge_enabled()` is a
  compile-time `false`, and shielded activation is `u64::MAX` on testnet AND
  mainnet. Production binaries are byte-identical with the bridge code present.
- The bridge is exercised only on **regtest** and the isolated **Beta** net,
  behind the `sketch-gk-proof` + `libspark-ffi` features. This branch is the
  engine the audit is being asked to review; it lands on `main` as **CIP-011**,
  curated, not as a whole-branch merge.
- **Mainnet shielded = permanently off** until this audit + governance. That
  invariant is asserted in code (see §2) and must not be weakened.

## 1. The cross-veil value model (the crux)

The one thing to get right: no value is created or destroyed crossing the veil.

- `src/consensus/spark_payload.rs` — `verify_transparent_shielded_balance`: the
  bridge equation `Σ pseudo_in == Σ out + (tx.fee − value_balance)·H`. This is
  the single public-value binding.
- `src/chain.rs` — `verify_block_spark_v2`: binds `value_balance == spend_fee`
  of the libspark bundle (the cross-veil inflation guard), the mint-XOR-spend
  rule, and the pool-underflow guard (`simulated_pool` can't go negative =
  can't unshield more than the pool holds).
- `src/crypto/spark_balance.rs` — the signed `value_balance` arithmetic
  (positive = unshield out, negative = shield-in) with proptest coverage.
- Property test: the value bridge accepts a tx **iff** it conserves — search
  tests for the conservation proptest (commit `e9070f8e`).

## 2. Admission / activation gating (where "shielded off" is enforced)

- `src/consensus/validation.rs`:
  - `require_pure_shielded_shape` — production shielded txs carry NO transparent
    side (Option A). Relaxed ONLY under `regtest_bridge_enabled`.
  - `regtest_bridge_enabled` — the single switch; `const false` in production.
  - `validate_transaction` bridge arm — runs transparent RingCT on a bridge tx's
    transparent side, split by direction: shield-in (transparent inputs →
    ring sigs + range proofs); unshield (no inputs, value-revealing zero-blinding
    outputs → curve-point check only). Mirrored in the mempool structural gate.
- `src/constants.rs`:
  - `shielded_activation_height(network)` — regtest/beta finite (gated), testnet
    = `SHIELDED_TESTNET_ACTIVATION_HEIGHT` (currently `u64::MAX` placeholder),
    mainnet = `SHIELDED_TX_ACTIVATION_HEIGHT` (`u64::MAX`, unconditional).
  - Invariant test: `shielded_activation_mainnet_permanently_off_testnet_is_dedicated_knob`
    — mainnet is permanently off and decoupled from the testnet knob.
- `critical_files.lock` + `build.rs` — the consensus-critical files are
  hash-locked; a change without a lock regen fails the build. Changes to them
  require 2-of-N owner sign-off (see §5).

## 3. How to build + run the gated surface yourself

The gated shielded suite (what the maintainer runs at 2400/0):

```
# Linux (ubuntu): system OpenSSL works for libspark.
export SPARK_OPENSSL_DIR=/usr        # or a prefix containing include/ + lib/
export COINCYNC_RANDOMX_LIGHT_MODE=1
cargo test --release --lib \
  --features "testnet fuse block-integrity-breaker supply-breaker \
              shielded-breaker regtest-chaos sketch-gk-proof libspark-ffi"
# NOTE: NEVER add `test-fast-pow` to a correctness build — it skips real PoW and
# breaks the checkpoint test. `test-fast-pow` is for the live chaos NODE only.
```

- CI that gates this surface: `.github/workflows/shielded-gate.yml` (gated unit
  suite + the real-crypto subaddress/pipeline integration test + a gated
  `cargo check` that also enforces the lock).
- libspark portability (Linux/macOS build recipe):
  `docs/design/cip-shielded-libspark-portability.md`.

## 4. Live behavior & resilience evidence

- **Chaos/soak harness** (TEST-ONLY): `scripts/live-user-chaos.sh`. An 8h armed
  chaos soak on regtest (RELEASE build + `test-fast-pow`) exercises transparent
  sends, subaddress (stealth) receives, shielded round-trips, unshield pool
  exits, and injects faults into all 7 breakers. Reference run: 0 panics, 7/7
  breaker coverage (100%), breakers trip → fail-closed → recover, shielded triad
  end-to-end.
- **Safety breakers / fuse box**: `src/fuse.rs`. Observe-only by design (detect +
  record, never act); the Observe→Enforcing arm switch is a reviewed governance
  constant (default `u64::MAX` = off). Consensus-surface breakers stay
  detection-only until coordinated post-audit activation.

## 5. Governance / change-control artifacts

- `docs/AUDIT_READINESS.md` — the canonical readiness state (§5 is the
  ships/complete/protected matrix).
- `docs/audit/signoff-2026-10-26-audit-sweep-locked-files.md` — the 2-of-N
  sign-off record for the locked `validation.rs` + `constants.rs` changes
  (audit sweep + unshield + testnet-activation prep). Lists the exact locked
  hunks and the reviewer checklist.
- `docs/audit/quality-remediation-2026-10-26.md` — the four quality risks
  classified bug/milestone/process, with status.
- `docs/design/cip-shielded-testnet-activation.md` — the coordinated testnet
  activation runbook (no height set; the preconditions + fork-avoidance).

## 6. What the internal review already found (full disclosure)

A 6-agent review + verification sweep (2026-10-26) found and fixed **16 bugs** of
one class — Option-A assumptions ("a shielded tx has no transparent side") that
broke once the Option-B bridge went live — plus the decoy-#2 root cause (wallet
digest vs node `batch_from_block` ordinal divergence) and a per-UTXO key-epoch
spend bug (Wallet-1). All are in commit `61386523`; the unshield port + stealth
fix in `ce61a562`. These are disclosed so the audit can both verify the fixes and
probe for siblings of the same class. The honest residuals (gated surface, the
testnet-activation milestone, habit of tracing invariants before landing bridge
code) are in the quality-remediation doc.

---

_Reviewer access: this is the `feat/live-chaos-harness` review branch, 22 commits
ahead of `origin/main`, not merged. The commit series (breakers → chaos harness →
bridge → Beta → audit sweep → unshield/stealth → CI/docs) is itself a readable
narrative of how the surface was built and hardened._
