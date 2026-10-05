# CIP-Shielded — a shielded (Lelantus-Spark) transaction type

**Status:** DRAFT / skeleton implemented (fail-closed, permanently disabled).
**Scope:** testnet-only design; mainnet parked pending audit. This is the
consensus-format work the originality audit said would actually move the needle
(privacy ideas built but not live in blocks).

## Goal

Add a real privacy transaction kind that is validated in-block: a shielded
spend that proves membership in the Spark accumulator with a serial-tag
double-spend guard, instead of a CLSAG ring over transparent UTXOs. This is a
**wire hard fork** (a new `TxType` borsh discriminant) and touches hash-locked
consensus files, so it lands in careful, reviewed, gated increments.

## Increment 1 (this change): the fail-closed skeleton

Establish the wire type, the activation gate, and every consensus dispatch/apply
point — all fail-closed and disabled — so the real verifier plugs into marked
slots without pulling unaudited crypto into a live perimeter.

- **Wire type:** `TxType::Shielded` (borsh discriminant `3`). Round-trips;
  out-of-range discriminant (`4`) still rejected. `Transaction::is_shielded()`.
- **Activation gate:** `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` (permanently
  disabled) + `shielded_tx_active_at_height()`. Setting a finite height later is
  the coordinated hard fork.
- **Validation dispatch:** `validate_transaction_for_network_ctx` branches on
  `is_shielded()` immediately after the coinbase early-return, routing to
  `check_shielded_tx` and **skipping** the ring/range/balance checks (which
  assume the transparent CLSAG model). `check_shielded_tx` is **double
  fail-closed**: rejects below activation, and rejects even post-activation
  until the real verifier is wired (so an activation height can never precede a
  working, audited verifier).
- **Privacy policy:** shielded is exempt from the transparent §4 ring-input
  requirement (it would otherwise be rejected for having no ring inputs); its
  privacy is enforced by the shielded verifier. This is the branch the existing
  `TODO (Phase 2)` in `privacy_policy.rs` anticipated.
- **Apply path:** `UtxoSet::batch_from_block` skips shielded txs — they never
  enter the transparent UTXO set. (Unreachable today since shielded is rejected
  in validation, but keeps the transparent path correct by construction.)
- **Hash-lock:** `constants.rs` + `validation.rs` regenerated in
  `critical_files.lock` (the only two locked files touched).

## Not in Increment 1 (the real mountains, next)

- **The real Spark verifier + accumulator apply.** Today `lelantus_spark.rs` is
  a `sketch-*`-gated, unaudited **O(n) Schnorr stand-in**, not the log-size
  Groth-Kohlweiss proof. Wiring the stand-in into consensus would be the
  easy-but-wrong path; Increment 2 confronts the real proof (or stages it behind
  the gate with the stand-in clearly marked non-production).
- **Spark note output model** (vs the transparent `TxOutput`), serial-tag store,
  accumulator root into `spark_set_root` (the header field already exists,
  hashed + PoW-bound, currently zero).
- **Reorg rewind** of the accumulator/serial store (the `checkpoint_phase2_stores`
  / `rewind_phase2_stores` scaffolding in `chain.rs`, inert while stores are
  `None`) — must be proven before any activation.
- **CLSAG↔Spark balance across a mixed tx**, fee handling, block-apply e2e on
  regtest, and a real regression net (there are currently **no** tests for a
  non-ring tx type through validation/apply).

## Invariant

At every step until a coordinated, audited activation: **no shielded tx can
enter a block on any build.** The skeleton exists to be tested and reviewed, not
to be live.
