# 2-of-N sign-off — audit-sweep (feat/live-chaos-harness) locked-file changes

Status: **PENDING** — HELD, must NOT merge/push until 2-of-N sign-off is recorded below
AND the maintainer explicitly authorizes the push.

## Why this record
The 2026-10-26 audit sweep + Wallet-1 (29 files, +709/-131) modified two
**hash-locked** critical files. Per `.github/CODEOWNERS`, `/src/consensus/` and
`/critical_files.lock` require review from the code owners; this change needs
**2 of 3**: `@ghostrider1092`, `@junbyjun1238`, `@0x4D-5A`.

Non-locked files in the batch (wallet spend paths, mempool, storage/utxos,
chain apply/reorg, spark-connector, rpc) are governed by the normal `*` owner
but are listed here for completeness because they are consensus-adjacent.

## Locked files changed (the 2-of-N subjects)
1. `src/consensus/validation.rs`
   - lock hash: `ae1168971422dacedd731c72e1d440a46828432d14d9d0e75ea38ed5fb1f8000`
     → `470aa3fead0b9f39eb491836e1cc1a94d14aa1c100a7dc981b604b757a90e2d4`
   - changes (all bridge-gated / production byte-identical where `regtest_bridge_enabled`
     is const false):
     - **Consensus-1** — v1 `ShieldedPayload` forced pure-shielded + `value_balance == 0`
       on ALL networks (v1 has no cross-veil conservation layer; closes an unbacked-mint hole).
     - **transparent RingCT for bridge txs** — `validate_transaction` now runs ring-sig /
       range / ring-member / no-double-spend / curve-point checks on a bridge tx's
       transparent side, CONTEXTUAL-ONLY (block/reorg), skipping the transparent balance
       proof (bridge binding replaces it) and the anti-fingerprint shape checks.
     - **Consensus-3** — mempool structural gate requires a range proof for a shielded tx
       that HAS transparent outputs (`!tx.outputs.is_empty()`).
2. `critical_files.lock`
   - regenerated for the `validation.rs` hash above (no other locked file changed).

## Reviewer checklist (each signer confirms)
- [ ] Reviewed the full `validation.rs` diff; the three changes match the descriptions above.
- [ ] Confirmed production (no `sketch-gk-proof`) behavior is byte-identical
      (`regtest_bridge_enabled` is const false; bridge arms are unreachable).
- [ ] Confirmed the regenerated `critical_files.lock` hash matches a local rebuild.
- [ ] Gated unit suite green (2400/0, no `test-fast-pow`).

## Sign-off (2 of 3 required) — fill in on actual review; do NOT pre-fill
- [ ] @ghostrider1092 — reviewed, approved — <date> <commit sha>
- [ ] @junbyjun1238 — reviewed, approved — <date> <commit sha>
- [ ] @0x4D-5A — reviewed, approved — <date> <commit sha>

NOTE: No approvals are recorded by tooling. Each box is checked only by the named
owner after an actual review. Until 2 are checked, this change stays HELD.
