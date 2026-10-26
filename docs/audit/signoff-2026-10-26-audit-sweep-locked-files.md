# 2-of-N sign-off — audit-sweep (feat/live-chaos-harness) locked-file changes

Status: **PENDING** — HELD, must NOT merge/push until 2-of-N sign-off is recorded below
AND the maintainer explicitly authorizes the push.

## Why this record
The 2026-10-26 audit sweep + Wallet-1 + the unshield-to-transparent port modified two
**hash-locked** critical files. Per `.github/CODEOWNERS`, `/src/consensus/` and
`/critical_files.lock` require review from the code owners; this change needs
**2 of 3**: `@ghostrider1092`, `@junbyjun1238`, `@0x4D-5A`.

Non-locked files in the batch (wallet spend paths, mempool, storage/utxos,
chain apply/reorg, spark-connector, rpc, transaction builder, wallet scanner,
the unshield wallet command, and the TEST-ONLY chaos harness) are governed by the
normal `*` owner but are listed here for completeness because they are
consensus-adjacent.

**SCOPE UPDATE (2026-10-26, unshield port):** this record originally covered the
audit sweep + Wallet-1. It now ALSO covers the unshield-to-transparent port, which
re-touched the SAME locked `validation.rs` — see the two unshield items under
"Locked files changed" below. The validation.rs lock hash advanced accordingly.
Reviewers: you are signing off on the COMBINED locked diff (sweep + unshield).

## Locked files changed (the 2-of-N subjects)
1. `src/consensus/validation.rs`
   - lock hash: `ae1168971422dacedd731c72e1d440a46828432d14d9d0e75ea38ed5fb1f8000`
     → `470aa3fead0b9f39eb491836e1cc1a94d14aa1c100a7dc981b604b757a90e2d4` (audit sweep)
     → `f31dd9dab9ea11454943229ce6869a837991f7ad41085136ee8795cc6082bdea` (unshield port)
   - changes (all bridge-gated / production byte-identical where `regtest_bridge_enabled`
     is const false):
     - **Consensus-1** — v1 `ShieldedPayload` forced pure-shielded + `value_balance == 0`
       on ALL networks (v1 has no cross-veil conservation layer; closes an unbacked-mint hole).
     - **transparent RingCT for bridge txs** — `validate_transaction` now runs ring-sig /
       range / ring-member / no-double-spend / curve-point checks on a bridge tx's
       transparent side, CONTEXTUAL-ONLY (block/reorg), skipping the transparent balance
       proof (bridge binding replaces it) and the anti-fingerprint shape checks.
     - **Consensus-3** — mempool structural gate requires a range proof for a shielded tx
       that HAS transparent outputs — originally `!tx.outputs.is_empty()`; see Unshield-2.
     - **Unshield-1 (bridge-arm direction split)** — the `validate_transaction` bridge arm now
       branches on direction. SHIELD-IN (`!tx.inputs.is_empty()`) keeps the full transparent
       authentication (no-double-spend / ring-members / ring-size / ring-size-cap / ring-sigs /
       range proofs on its confidential change). UNSHIELD (`tx.inputs.is_empty()` with revealed
       transparent outputs) runs ONLY `check_output_curve_points` — its outputs are value-
       revealing (public amount, ZERO blinding, coinbase-shaped), so no ring sigs or range
       proofs apply; the output value is bound to exactly what left the pool by
       `verify_transparent_shielded_balance` + the `value_balance == spend_fee` guard in
       `verify_block_spark_v2`. (Before: the arm ran ring/range on BOTH directions, so an
       unshield's revealed output was wrongly rejected as "missing range proof".)
     - **Unshield-2 (mempool structural gate)** — the Consensus-3 range-proof predicate changed
       from `(!is_shielded || !tx.outputs.is_empty())` to
       `(!is_shielded || (!tx.inputs.is_empty() && !tx.outputs.is_empty()))`, so a range proof is
       required only for a shield-in (transparent inputs AND a confidential change output), not
       for an unshield (no transparent inputs; revealed outputs). Matches the block arm exactly
       to avoid mempool-vs-block drift.
2. `critical_files.lock`
   - regenerated for the `validation.rs` hash above (no other locked file changed; git-diff of
     the lock shows ONLY the `validation.rs` line).

## Non-locked files in the unshield port (normal `*` owner, consensus-adjacent)
- `src/transaction/builder.rs` + `src/transaction/mod.rs` — `build_revealed_output`: a
  value-revealing (zero-blinding, public-amount, coinbase-shaped) transparent output builder,
  `#[cfg(feature = "libspark-ffi")]`. Mirrors the coinbase output shape so the recipient's
  scanner recovers it on the zero-blinding path.
- `src/wallet/scanner.rs` — `is_revealed` widening at BOTH scan paths: coinbase OR a shielded
  tx with empty transparent inputs (= unshield). Byte-identical for coinbase and shield-in;
  only newly treats an unshield's transparent output as revealed (mask 0).
- `src/mempool.rs` — `verify_crypto_for_admission` now range-proofs a bridge tx's transparent
  outputs only when it also has transparent INPUTS (shield-in), exempting unshield. Mirrors
  Unshield-1/-2.
- `src/bin/wallet_support/legacy.rs` — the `shielded-unshield` wallet command (2-pass
  size-based miner fee, full fee breakdown, opt-in UNSHIELD DISCLOSURE), adapted to this
  branch's 5-arg `build_spend_over_set` (single pool-change output; bundle fee = `leaving`).
- `scripts/live-user-chaos.sh` — TEST-ONLY: `act_unshield` (shield-in → unshield → verify the
  pool shrank), wired into SMOKE + a 150s main-loop cadence; also the stealth fix (`act_stealth`
  via raw subaddress keys + `--subaddress`) and a configurable node-readiness window.

## Reviewer checklist (each signer confirms)
- [ ] Reviewed the full `validation.rs` diff; the five changes (Consensus-1/-3, transparent
      RingCT for bridge txs, Unshield-1 bridge-arm split, Unshield-2 mempool gate) match the
      descriptions above.
- [ ] Confirmed the three range-proof gates (block arm Unshield-1, mempool structural gate
      Unshield-2, `mempool.rs` admission) are mutually consistent: a range proof is required
      iff the tx is non-shielded OR a shield-in (has transparent inputs AND outputs).
- [ ] Confirmed production (no `sketch-gk-proof`) behavior is byte-identical
      (`regtest_bridge_enabled` is const false; bridge arms are unreachable).
- [ ] Confirmed the regenerated `critical_files.lock` hash matches a local rebuild
      (`f31dd9da…6082bdea`), and git-diff shows ONLY the `validation.rs` line changed.
- [ ] Gated unit suite green (2400/0, no `test-fast-pow`).
- [ ] Unshield exercised end-to-end on regtest (harness `act_unshield`: node accepts the
      unshield tx, it mines, the shielded pool shrinks by `amount + miner_fee`).

## Sign-off (2 of 3 required) — fill in on actual review; do NOT pre-fill
- [ ] @ghostrider1092 — reviewed, approved — <date> <commit sha>
- [ ] @junbyjun1238 — reviewed, approved — <date> <commit sha>
- [ ] @0x4D-5A — reviewed, approved — <date> <commit sha>

NOTE: No approvals are recorded by tooling. Each box is checked only by the named
owner after an actual review. Until 2 are checked, this change stays HELD.
