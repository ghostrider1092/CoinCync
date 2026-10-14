<!-- markdownlint-disable MD036 -->
# CIP-011 — Validated Transparent Bridge for the Shielded (Spark) Pool

**Status:** Draft (pre-activation requirement — issue #314)
**Type:** Standards Track (consensus change, hard fork)
**Created:** 2026-10-13
**Layer:** Consensus + Mempool + Wallet
**Depends on:** CIP-005 (Lelantus Spark), the v2 libspark engine (`cip-shielded-libspark-ffi.md`)

---

> ## ⚠️ Status (read first)
>
> The shielded engine is **gated OFF on every network** (`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`). Nothing in this CIP is live or exploitable today. This document specifies the work that **MUST land, pass two-of-N maintainer review, and be re-soaked BEFORE shielded can ever be activated** on a path that moves value across the transparent↔shielded veil.
>
> The interim fail-closed state is **Option A (#315):** a block-admitted shielded tx must be *pure-shielded* — empty transparent inputs/outputs and `value_balance == 0`. Option A is the default and remains enforced until Option B (this CIP) is validated and audited. Option B is **additive**: it re-enables on-chain shield-in / unshield; it never weakens Option A's guarantee for pure-shielded txs.

---

## 1. Motivation

An internal pre-audit adversarial review (finding **F4**, issue #314) identified a soundness hole on the transparent side of a shielded transaction.

A shielded tx early-returns from `validate_transaction` (`src/consensus/validation.rs:1600`) into `check_shielded_tx`, **before** the transparent-side checks that every normal tx receives:

- `check_tx_ring_signatures` (CLSAG — proves input ownership)
- `check_tx_ring_members` + `check_tx_no_double_spend` (ring members exist / are unspent)
- `check_tx_range_proofs` → `verify_output_range_proofs` (outputs commit to a value in `[0, 2^64)`)
- `check_tx_balance_proof` (pseudo-output commitments bind the real inputs)

The stateful block gate `chain.rs::verify_block_spark_v2` then feeds the tx's `inputs[].pseudo_output_commitment` and `outputs[].commitment` into the Pedersen value bridge `verify_transparent_shielded_balance` (`spark_payload.rs:241`). That bridge is a commitment **balance** check only:

```
Σ pseudo_outputs  ==  Σ outputs + (fee − value_balance)·H
```

It proves the transparent commitments *sum* consistently with the public `value_balance`, but it does **not** prove that any individual output commits to a non-negative, in-range value, nor that any input is owned and unspent. Range proofs on the outputs are exactly what stop a wrapped / out-of-range value from satisfying the balance equation while minting value across the veil; CLSAG + the UTXO check are what stop value entering the bridge from inputs the spender neither owns nor has left unspent.

The hole is **symmetric** (per the #314 follow-up): outputs lack range proofs, and inputs lack ring/UTXO validation. Both sides reach the bridge unvalidated.

## 2. Scope

Option B re-enables, under full validation:

- **Shield-in** (value entering the pool): `value_balance < 0`, transparent ring-signed inputs fund the mint, authenticated mint bundle proves the minted coins' value.
- **Unshield** (value leaving the pool): `value_balance > 0`, transparent outputs receive the unshielded value, the Spark spend bundle proves pool-side conservation.
- **Transparent change** on either side.

Out of scope: the shielded-side crypto (inherited from the audited libspark bundle); Option A's pure-shielded path (unchanged).

**Phased delivery.** Option B lands in increments, each fully validated + soaked before the next: **phase 1 = shield-in** (`value_balance < 0`; fund the pool — nothing else matters until value can enter), **phase 2 = unshield** (`value_balance > 0`). Each phase enables only its own direction at the policy slot (§3.5); the other direction stays rejected (fail-closed) until its phase lands. Activation (off `u64::MAX`) still gates the whole engine regardless of phase.

## 3. Specification

### 3.1 The invariant

A shielded tx with a transparent side (`!inputs.is_empty() || !outputs.is_empty() || value_balance != 0`) is accepted **only if all four hold**:

1. **Transparent outputs are range-proven.** Every `tx.outputs[i]` carries a valid range proof over `outputs[i].commitment` (`verify_output_range_proofs`). This is the check currently relaxed for shielded — Option B un-relaxes it for the transparent output set.
2. **Transparent inputs are owned and unspent.** Every `tx.inputs[i]` passes CLSAG (`check_tx_ring_signatures`), ring-member validity (`check_tx_ring_members`), no-double-spend against the live UTXO set (`check_tx_no_double_spend`), the ring-size cap/uniqueness checks, and the pseudo-output binding (`check_tx_balance_proof`) — i.e. the identical transparent-input validation a normal tx receives.
3. **The value bridge balances.** `verify_transparent_shielded_balance(pseudo_outputs, output_commitments, fee, value_balance)` holds (unchanged).
4. **The shielded side conserves.** The libspark spend/mint bundle verifies against the node-authoritative cover set (#258), and for a shield-in the authenticated mint value equals `−value_balance` (`verify_mint_shield_in`).

Only when (1)+(2) gate the commitments is (3)'s balance equation meaningful, and only with (4) does the shielded side conserve. Order matters: **(1) and (2) run before (3)**.

### 3.2 Where each check runs (the stateless/stateful split)

Checks (1) output range proofs and the structural parts of (2) (CLSAG, ring-size cap) are **stateless** and belong in `check_shielded_tx`. The **contextual** parts of (2) — ring-member existence and no-double-spend — need the UTXO set and therefore run in the stateful block gate `verify_block_spark_v2` (which already holds chain state and the `SparkPoolStore`), alongside (3) and (4). This mirrors how `validate_transaction` splits `contextual` vs non-contextual checks today, and keeps the authoritative gate the one that rejects the whole block on any fault.

Concretely, Option B replaces the blanket early-return at `validation.rs:1600` with: *dispatch to `check_shielded_tx`, which runs the shielded verify AND the stateless transparent-side checks on the transparent portion* — it no longer silently skips range proofs and CLSAG for a shielded tx that carries a transparent side.

### 3.3 Mempool / block consistency (relay-DoS)

The same transparent-side validation MUST be applied at **mempool admission** (`mempool.rs`, module `shielded_mempool_admission_172`), not only at the block gate. Today the mempool admits a shielded tx on a lighter check; once Option B activates, a shielded tx with an unvalidated transparent side that the block gate would reject must also be rejected at admission, or it becomes a relay-amplification DoS vector (the same mempool-vs-block drift the comment at `validation.rs:1606` already warns about for transparent outputs). This is a hard requirement of Option B, not a follow-up.

### 3.4 Activation

`SHIELDED_TX_ACTIVATION_HEIGHT` stays `u64::MAX`. Option B does not itself flip activation. Activation is a separate, later governance step (CIP-007 policy) that may only proceed after Option B has landed, been reviewed two-of-N, and been re-soaked (§5). Until then Option A (pure-shielded) is the enforced behaviour.

### 3.5 Connector architecture (the translation seam)

Option B is wired as a **connector + fail-closed policy slot**, the same shape as `shielded_connector` (the single libspark swap point) and the project's other seams — not as validation scattered through the tuned consensus functions. This keeps the intricate bridge logic in its own reviewable module, out of the locked consensus heart, with a fail-safe default.

- A **`ShieldInPolicy` slot defaults to `Disabled`** — reject every shield-in, identical to Option A (#315, pure-shielded). The real bridge runs only when the slot is `Enabled` **and** shielded is activated; both are gated, and neither holds on any current network.
- The connector performs only the **cross-world translation**. libspark already carries the shielded-side code (mint value proof, spend proof, coin range proofs); the transparent side is CoinCync-native (ristretto CLSAG/UTXO — a different curve and model that libspark cannot validate). The connector ties them together through the **cleartext `value_balance` turnstile** — no cross-curve ZK (see `cip-shielded-libspark-ffi.md`). It adds **no new crypto**: it orchestrates `verify_transparent_shielded_balance` (transparent commitments ↔ `value_balance`) and the libspark `verify_mint_shield_in` + `verify_spark_payload` (`value_balance` ↔ authenticated shielded coins).
- Because the connector cannot run CoinCync's transparent-input checks itself (they need the chain's UTXO/ring state), the **caller validates the transparent side first** — in consensus, where that state lives — then calls the connector only for the translation. The caller's call *is* its attestation that CLSAG / no-double-spend / range proofs ran.
- The consensus seam is **one call** in `verify_block_spark_v2`: pure-shielded (`value_balance == 0`) unchanged; shield-in (`value_balance < 0`) → run the transparent validators, then the connector; unshield (`value_balance > 0`) → rejected in phase 1. Mirrored at mempool admission per §3.3.

## 4. Rationale

- **Reuse, don't re-implement.** Option B calls the *existing, audited* transparent validators (`check_tx_*`) on the transparent portion rather than writing shielded-specific variants — minimising new consensus surface and keeping one code path for "is this transparent input/output valid."
- **Additive over Option A.** Keeping Option A as the default and making Option B an explicitly-gated, separately-reviewed addition means the fail-closed state is never regressed by in-progress bridge work.
- **Symmetry.** Both the input and output sides are closed together; a half-fix (outputs only) leaves the input hole open.

## 5. Test cases (adversarial — all must pass before activation)

Reject:

1. **Wrapped / out-of-range output value** that satisfies the balance equation but has no valid range proof → rejected at (1).
2. **Unowned transparent input** (CLSAG fails) → rejected at (2).
3. **Double-spent transparent input** (already in the UTXO spent set) → rejected at (2).
4. **Identity / malformed commitment** on either side → rejected (bridge already rejects identity pseudo-outputs; range proofs reject degenerate outputs).
5. A tx the **block gate rejects but the mempool would admit** → must now also be rejected at admission (§3.3).

Accept:

6. Honest **shield-in** (ring-signed inputs + authenticated mint, `value_balance < 0`, transparent change range-proven).
7. Honest **unshield** (Spark spend + range-proven transparent outputs, `value_balance > 0`).

Plus: the production-param in-block soak (`soak-24h-shielded.sh`) re-run to a clean 24h **with the transparent bridge exercised** (mint → shield-in → transfer → unshield → reorg), not only pure-shielded cycles.

## 6. Security considerations

- The bridge equation is only sound once (1)+(2) constrain its inputs; this CIP's whole point is that ordering. A future refactor that reorders or short-circuits the transparent checks ahead of the bridge re-opens F4 — the tests in §5 (#1, #2) are the regression guard.
- Range-proof verification on the transparent outputs is CPU-bound; the existing `verify_output_range_proofs` cache (`proof_cache_key`) applies, and the DoS ring-size cap (`check_tx_ring_size_cap`, #260) already bounds CLSAG cost. No new unbounded work.
- `value_balance` magnitude is bounded by the pool value (the cumulative `simulated_pool` check in `verify_block_spark_v2` rejects an unshield larger than the pool holds); the bridge's `unsigned_abs()` is safe across the i64 range.

## 7. References

- Issue #314 (F4 tracking — Option B pre-activation requirement); #315 (Option A, pure-shielded interim).
- `docs/shielded-audit-submission.md` §8 (must-fix-before-activation).
- CIP-005 (Lelantus Spark), `cip-shielded-libspark-ffi.md` (v2 engine), #258 (node-authoritative cover set).
- Code: `src/consensus/validation.rs` (`check_shielded_tx`, `check_tx_*`), `src/chain.rs` (`verify_block_spark_v2`), `src/consensus/spark_payload.rs` (`verify_transparent_shielded_balance`, `verify_mint_shield_in`).
