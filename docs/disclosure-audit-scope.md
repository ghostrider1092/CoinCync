# Disclosure / Compliance Suite — Audit Scope

> Audit-scoping note for the selective-disclosure + proof-of-reserves utility
> ("auditable privacy"). The suite is **built and tested** (disclosure +
> compliance tests, incl. adversarial, anchoring, and a live decoy-sampler →
> build → anchor regression) but **gated** behind
> `sketch-gk-proof` and **unaudited**. It must be in the audit scope alongside
> the shielded (Spark) engine — it rides the same Groth-Kohlweiss primitive.

## What this is
CoinCync's utility (see `docs/strategy/utility-thesis.md`) is **auditable
privacy** — private by default, provable on demand. This suite is the engine:

- **Balance proof** — a UTXO's amount ≥ threshold, without revealing it.
- **Ownership proof** — control of a specific output.
- **Sum proof** — a set of outputs sums to a value.
- **Source proof** — where funds came from.
- **Unlinkable proof-of-solvency** (single + multi) — holds ≥ X across hidden
  outputs **without revealing which** (the differentiating "first": Monero's
  reserve proof is *linkable*; this is not — see the thesis).
- **Scoped view keys** — time-bounded read-only disclosure (e.g. a tax year).
- **Org-signed audit packages** — an org signs a package; an auditor verifies it
  against a node, which **anchors every proof to real chain state** and returns a
  verdict + reconciliation + report.

CLI: `coincync-wallet disclose {balance, verify-balance, ownership,
verify-ownership, solvency [--unlinkable-solvency], scoped-view-key, scan-scoped,
verify-audit-package}` (`src/bin/wallet_support/legacy.rs`).
Crypto: `src/crypto/disclosure.rs`; anchoring/packages: `src/compliance.rs`.

## Crypto the auditor must review
- **Groth-Kohlweiss one-of-many** (`src/crypto/groth_kohlweiss.rs`) — the
  unlinkable-solvency membership proof **and** the Spark spend proof both use it.
  **Auditing it once covers both; this is the critical shared primitive.**
- Pedersen commitments + Bulletproofs+ range proofs (the balance/threshold leg).
- Schnorr proofs (ownership; blinding-difference openings).
- Fiat-Shamir domain separation across all proof types
  (tested: `test_proofs_domain_separated`).

## Soundness points to scrutinize
1. **Anchoring is load-bearing.** A disclosure proof is only a trust decision
   once every anonymity-set member / referenced output is confirmed to be a
   **real on-chain commitment at the stated height**. On its own it is a statement
   about a caller-supplied set. `verify-audit-package` and the `--anchor*` flags
   are the anchored layer — confirm it is complete and non-bypassable. The
   prover-side decoy source is bound to the **same** anchor lookup (see point 5),
   so the set a prover assembles and the set an auditor anchors cannot drift.
2. **Unlinkable solvency hides *which*, not current-unspent.** It proves "≥ K
   hidden outputs held ≥ threshold **at height H**", NOT "currently unspent" —
   proving current-unspent would require revealing a key image / nullifier, which
   would break unlinkability. Deliberate tradeoff (Monero's reserve proof is
   current-unspent but linkable).
3. **Multi-output double-count guard.** The K anonymity sets must be pairwise
   disjoint; with the per-member one-of-many this forces K **distinct** real
   outputs. Confirm the disjointness check is enforced
   (tested: `multi_unlinkable_solvency_anchors_every_member`).
4. **Value bounds.** Confirm thresholds / `value_balance` are sanely bounded and
   the range proofs prevent negative/overflow (incl. the `i64::MIN`/`unsigned_abs`
   edge).
5. **Decoy selection offers only anchorable, non-treasury outputs.**
   `collect_anchorable_solvency_decoys` (`src/chain/compliance_view.rs`) is the
   prover's decoy source; it emits an output only if it resolves through the SAME
   `NodeChainView::anchor` lookup the auditor uses, with a matching commitment,
   excludes the prover's own treasury, de-duplicates, and returns fewer (never
   pads) when the chain lacks enough distinct outputs. This closed a real defect:
   `init_genesis` persists the genesis coinbase's output but never `index_tx`'s
   it, so `get_tx_location` could not resolve it while `get_block_by_height`
   could enumerate it — the old sampler could hand a prover a genesis/reorg-stale
   output that then failed anchoring (draw-dependent `anchored_valid:false`), or
   return the treasury itself (shrinking the distinct set below the anonymity
   size). Confirm the sampler and the auditor's anchor path cannot diverge, and
   that `init_genesis` indexing the genesis coinbase (a reasonable follow-up) is
   not relied on by the sampler gate.
6. **Non-gk builds fail closed with a clear reason.** A node built without
   `sketch-gk-proof` has no struct members for the gk-only solvency fields, so
   serde drops them on deserialize and the signature recomputes over a different
   payload (a misleading `signature_valid:false`). `unsupported_audit_fields`
   (`src/compliance.rs`) detects this from the raw request and the
   `verify-audit-package` RPC returns an explicit "rebuild with sketch-gk-proof"
   error instead. Confirm a non-gk node never *accepts* such a package.

## Test coverage (current)
Disclosure + compliance tests pass, including: adversarial
(`unlinkable_solvency_adversarial_attacks`), fail-closed
(`unlinkable_solvency_proves_hidden_output_over_threshold_and_is_fail_closed`),
anchoring (`multi_unlinkable_solvency_anchors_every_member`), and tamper/wrong
cases for every proof type.

**Live sampler loop — the coverage gap, now closed.** The suite above was all
in-process with hand-built anonymity sets and never exercised the real decoy
*draw → set assembly → anchor* loop — which is exactly how the draw-dependent
`anchored_valid:false` / "too few distinct decoys" defect slipped past it. It is
now guarded by `unlinkable_solvency_live_decoy_draw_builds_and_anchors_every_time`
(`src/chain.rs`): 24 iterations of the real
`collect_anchorable_solvency_decoys → build → verify_anchored` loop over a chain
seeded with an unindexed genesis-like coinbase **and** a reorg-stale tx,
asserting the package is accepted every time (and that the treasury /
non-anchorable outputs are never drawn). The non-gk fail-closed path is covered
by `non_gk_build_reports_uninterpretable_package_explicitly`. Both landed with
the anchorable-decoy + non-gk-reject fixes and were live-verified end-to-end
(20/20 build → verify on a deliberately small chain — the pre-fix failure case).

## Status / honest caveats
- **Gated** behind `sketch-gk-proof`; **not activated**; **unaudited**.
- The utility is real and tested but **NOT claimable until the GK primitive + this
  suite clear audit** — the same audit as the shielded pool covers both.
- Pre-audit tense: "designed to", not "does".
