# Test Results — Privacy Hardening & Connector (2026-08-22)

Real results for the work described in
`docs/operations/CHANGES-2026-08-22-privacy-hardening.md`. Two parts: the
automated test suites, and a live regtest run on a real node with real RandomX
proof-of-work and real RingCT transactions (no mocks).

Build under test: `coincync 2.0.0`, commit `cfb979a1` (working tree, uncommitted).

---

## 1. Automated test suites

| Suite | Command | Result |
|---|---|---|
| Full library suite (default build) | `cargo test --lib` | **1150 passed, 0 failed**, 7 ignored (39.7s) |
| Lelantus Spark (fix + attack) | `cargo test --lib --features sketch-lelantus-spark lelantus_spark` | **14 passed** |
| MimbleWimble cut-through (fix + attack) | `cargo test --lib mw_cutthrough` | **11 passed** |
| Full-pipeline real crypto (incl. subaddress E2E) | `cargo test --test full_pipeline_real_crypto` | **14 passed** |
| Privacy connector (default) | `cargo test --lib privacy_connector` | **11 passed** |
| Privacy connector (+ Spark spoke) | `cargo test --lib --features sketch-lelantus-spark privacy_connector` | **12 passed** |

Highlighted assertions (attacks that MUST fail, and do):

- `double_spend_forged_serial_tag_is_rejected` — Spark forged serial tag rejected.
- `verify_kernel_set_rejects_hidden_value_inflation` — MW canceling `±v·H`
  inflation rejected.
- `real_crypto_subaddress_output_spendable_e2e` — a subaddress-received output is
  built, CLSAG-signed, and accepted by the full mempool validator.
- `connect_spark_spend_detects_double_spend`, `connect_shielded_note_and_nullifier_double_spend`
  — connector rejects double-spends via the nullifier/serial-tag sets.
- `inert_on_mainnet_without_audit`, `value_converter_is_disabled_until_audited`,
  `kill_switch_refuses_everything` — connector safety interlocks hold.

---

## 2. Live regtest run (real node, real PoW, real RingCT)

Isolated regtest node (`--network regtest --no-peers`), built with the reduced
coinbase-maturity testnet profile so a spend chain can be reached quickly. This
did NOT touch any production node.

### Node + proof-of-work

- Genesis initialized, RocksDB opened, P2P + RPC + REST started.
- **RandomX dataset built (full-mem, `FLAG_HARD_AES | FLAG_FULL_MEM | FLAG_JIT |
  FLAG_SECURE | FLAG_ARGON2_*`)** — the `FLAG_SECURE` (W^X) Windows fix is active;
  mined 150+ real blocks with zero crashes.
- Live difficulty adjustment observed (ASERT reacting; see Findings).

### RPC (the endpoints the wallet/GUI use)

- `get_info` — real height/network/version/build.
- `get_mempool_info` — real mempool size/bytes (feeds the wallet fee estimate).
- **`get_privacy_features`** (new) — returns the connector's honest registry:
  5 active, 1 disabled, 4 gated-inert, `connector_audited: false`. The connector
  is wired into the live node.
- `get_privacy_stats` — Phase-2 store roots/sizes (all 0; schemes gated).

### Wallet lifecycle + receive

- `create` → wallet + 24-word seed; `address` → real stealth address + pubkeys.
- `scan` → detected **148 coinbase outputs**, balance **7,399 CYNC**, UTXOs
  persisted. Coinbase maturity enforced.

### Real privacy transactions

| # | Action | Tx | Result |
|---|---|---|---|
| 1 | Send 10 CYNC to self (2-in/2-out RingCT, real decoys + range proofs) | `990526aa…` | accepted by mempool → **mined** → rescanned/received ✅ |
| 2 | Create subaddress `0/1` (mainnet gate now lifted) | — | address + distinct view key produced ✅ |
| 3 | Send 5 CYNC to subaddress `0/1` (`--subaddress`) | `87b3d290…` | accepted → **mined** → subaddress output **credited** (the CLI `scan` registers the wallet's subaddress keys) ✅ |
| 4 | Send 52 CYNC to self (another 2-in/2-out RingCT send) | `d6bf2de7…` | accepted → **mined at height 157** ✅ |
| 5 | `utxos` command (added this session) — decisive per-UTXO inspection | — | shows the 5-CYNC output tagged **subaddress `0/1`, `spent: no`** ✅ |

**Subaddress receive is decisively verified:** the new `utxos` command lists a
5-CYNC output tagged `subaddress 0/1` (from tx `87b3d290`), confirming the
scanner detected and credited a subaddress-received output on a live chain.

**Subaddress *spend* was NOT exercised in this live run — and the `utxos`
command is how we know.** We initially expected the 52-CYNC send (#4) to draw the
5-CYNC subaddress UTXO into its inputs via minimal-excess coin selection, but the
`utxos` output shows that UTXO is still **unspent** — coin selection chose other
inputs, and the CLI has no coin-control to force a specific one. So the live run
proves subaddress *receipt*, not subaddress *spend*. The definitive proof that a
subaddress-offset key produces a valid spend remains the deterministic
`real_crypto_subaddress_output_spendable_e2e` test (build → CLSAG-sign → full
mempool validation). This correction is itself a result: the `utxos` tooling
turned an inference into a checked fact and caught an overclaim.

---

## 3. Findings

1. **W^X RandomX confirmed on Windows** — 150+ blocks mined, `FLAG_SECURE`
   active, zero native crashes. Validates the rig-crash fix.
2. **Regtest difficulty oscillation is real** — on a fresh small chain the
   near-instant early blocks drive ASERT difficulty up sharply (observed spikes
   to ~190k–720k), which then slows mining. Regtest has no fixed-low-difficulty
   / instant-mine mode; this is a dev-tooling gap worth closing (Bitcoin/Monero
   regtest offer difficulty-1 + a generate RPC).
3. The wallet `balance` subcommand prints a stale "UTXOs not persisted" note,
   though `scan` does persist them and reports the real balance — cosmetic.

---

## 4. Honest scope

- The experimental privacy schemes (Spark, MW cut-through, shielded pool,
  dead-man's-switch sweep) were **not** activated in live consensus. They are
  built, fixed, and tested, and are **gated off pending external cryptographic
  audit** — reported truthfully by `get_privacy_features` as `gated-inert`. They
  were additionally exercised live as real code via
  `examples/spark_mw_live_demo.rs` (both attack scenarios rejected).
- All work in this report is in the working tree pending commit.

---

## Update — subaddress *spend* now decisively verified live

The gap above (subaddress spend not exercised in the first live run) is closed.
Using the new `regtest-fast` dev mode (fixed low difficulty → fast, non-
oscillating mining; see `docs/operations/regtest-fast-mode.md`), a second live
run completed the full loop on a real node:

1. Received a 5-CYNC output to subaddress `0/1` — confirmed via `wallet utxos`
   (`5.000000 … 0/1 … spent: no`, tx `c66005fe…`).
2. Sent a follow-up transaction; minimal-excess coin selection drew that 5-CYNC
   subaddress UTXO into the inputs. The tx was accepted and **mined**.
3. `wallet utxos --include-spent` then shows that exact output as
   **`spent: yes`** (tx `c66005fe…`, subaddress `0/1`).

Because the block validator accepted the spend, the subaddress UTXO's
offset-derived (`x_i = x + m`) key produced a valid, block-confirmed CLSAG spend
on a live chain — the decisive live confirmation, matching the deterministic
`real_crypto_subaddress_output_spendable_e2e` test.

