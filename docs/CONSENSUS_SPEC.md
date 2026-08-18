# CoinCync Consensus Specification

**Status:** Living document, v1 (2026-08-17). **Network target:** mainnet 2026-10-01.

This document specifies the consensus rules a CoinCync node enforces: what makes
a block valid, what makes a transaction valid, how the emission schedule is
computed, how the canonical chain is selected, and the determinism contract that
every accumulated consensus value must satisfy. It is written to be checked
**against the code** — every rule cites the exact enforcement site.

> **The code is ground truth.** Where this document and the source disagree, the
> source wins and this document is the bug. Rules below are as of branch `main`
> and cite `file:line`; line numbers drift, so treat the cited function/constant
> name as authoritative and the number as a hint.

**Consensus-critical surface (hash-locked).** These eight files are integrity-
locked by `critical_files.lock` (SHA-256 over LF-normalized bytes; the build
fails on any mismatch). Changing consensus behavior means changing one of these:

- `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md` (governance text)
- `src/constants.rs` — all consensus constants
- `src/consensus/difficulty.rs` — ASERT difficulty
- `src/consensus/pow.rs` — RandomX proof-of-work
- `src/consensus/validation.rs` — block + transaction validity
- `src/emission/curve.rs` — emission curve
- `src/testnet.rs` — testnet genesis/params

Two drivers do the work: **block** validation is
`consensus::validation::validate_block_with_checkpoint_for_network`
(`validation.rs`); **transaction** validation is
`validate_transaction_for_network` (`validation.rs`). Note that **exact
difficulty and median-time-past are enforced in `chain.rs::add_block`, not in
`validation.rs`** (validation.rs carries only a loose difficulty sanity gate) —
see §5.

---

## 1. Consensus constants

Exact values from `src/constants.rs` (unless noted). ⚠️ marks a divergence or
dormant item detailed in §8.

| Constant | Value | Notes |
|---|---|---|
| `TARGET_BLOCK_TIME` | 120 s | ASERT + emission are built on this |
| `BLOCKS_PER_YEAR` | 262,800 | `= 365·24·3600 / 120` |
| `COIN` | 1_000_000_000_000 (10¹²) | atomic units per CYNC |
| `MAX_SUPPLY` | 100,000,000 · COIN (10²⁰) | the **asymptote**, not a hard cap |
| `TOTAL_SUPPLY_TARGET` | 100,000,000 | whole CYNC (asymptote) |
| `EMISSION_DIVISOR` | 2,000,000 | curve denominator |
| `TAIL_EMISSION` | 600_000_000_000 (0.6 CYNC) | perpetual reward floor |
| `MIN_DIFFICULTY` | 500 | consensus floor (`difficulty.rs`) |
| `ASERT_HALFLIFE` | 3600 s | difficulty responsiveness |
| `DIFFICULTY_SHORT/LONG_WINDOW` | 8 / 144 | dual-window ASERT |
| `MAX_BLOCK_SIZE` | 2 MiB | serialized block cap |
| `MAX_TXS_PER_BLOCK` | 5000 | |
| `MAX_TX_INPUTS` / `MAX_TX_OUTPUTS` | 256 / 16 | |
| `RING_SIZE` | 16 | mature ring size |
| `BOOTSTRAP_MIN_RING_SIZE` | 11 | ring size below height 10,000 |
| `MAX_RING_SIZE` | 32 | |
| `STRICT_RING_MEMBER_HEIGHT` | 100 | below it, an unknown ring member is warned-and-allowed |
| `MIN_OUTPUT_AGE` / `_POST_FORK` | 10 / 100 | coinbase maturity (blocks) |
| `MIN_OUTPUT_AGE_HARDFORK_HEIGHT` | `u64::MAX` testnet / 0 mainnet | mainnet uses 100 from genesis |
| `MIN_OUTPUT_AMOUNT` | 1,000,000 | dust floor (0.000001 CYNC) |
| `MIN_FEE_PER_BYTE` | 1000 | |
| `FEE_BURN_NORMAL_PERCENT` / `_CONGESTED` | 30 / 50 | burn share; miner gets 70 / 50 |
| `FEE_DISTRIBUTION_HEIGHT` | 525 testnet / 0 mainnet | fee-split activation |
| `DEV_TAX_PERCENT` | 0 | constitutional |
| `CHECKPOINT_INTERVAL` | 144 | auto-checkpoint cadence |
| `HARD_FORK_V1_0_12_HEIGHT` | 13,000 (testnet); mainnet always-on | see §7 |
| `V2_TX_ACTIVATION_HEIGHT` | 50,000 | tx version 2 |
| `BULLETPROOFS_PLUS_HEIGHT` / `UNIFORM_TX_SHAPE_HEIGHT` | 0 / 0 | active from genesis |
| `STANDARD_INPUT_COUNT` / `_OUTPUT_COUNT` | 2 / 2 | uniform tx shape |
| `MAX_TIMESTAMP_DRIFT` | 600 s | future-block bound |
| `REORG_UNCONDITIONAL_DEPTH` | 10 (`chain.rs`) | MESS Tier 1 |
| `MESS_EXPONENT_DIVISOR` | 20 (`chain.rs`) | MESS Tier 2 |
| `BOOTSTRAP_MESS_HEIGHT` | 1000 (`chain.rs`) | |
| `max_reorg_depth_for` | Mainnet 100 / Testnet·Regtest 1000 (`chain.rs`) | MESS Tier 3 hard cap |
| Network magic | mainnet `43 59 4E 43` ("CYNC") / testnet `74 43 59 4E` / regtest `72 43 59 4E` | |
| P2P / RPC ports | mainnet 19080/19081 · testnet 28080/28081 · regtest 18080/18081 | |
| Address HRP | `cync` / `tcync` / `rcync` | |

---

## 2. Emission schedule

**Curve** (`emission/curve.rs::base_reward_from_supply`):

```
reward(mined) = max( TAIL_EMISSION,  (100_000_000·COIN − mined) / EMISSION_DIVISOR )
```

- Genesis (height 0) reward = **50 CYNC** (`(100M·COIN)/2,000,000`); test-locked.
- Reward is proportional to the remaining distance to the 100M asymptote, so it
  decays geometrically (Monero-style): 50 → 25 (at 50M) → 12.5 (at 75M) → … until
  it would drop below the **0.6 CYNC tail floor**, at ~98.8M mined, after which
  every block pays exactly 0.6 CYNC forever.
- **100M is an asymptote, not a hard cap.** The perpetual 0.6/block tail means
  total *emitted* supply crosses and grows past 100M indefinitely. There is no
  `supply ≤ MAX_SUPPLY` rejection — the guarantee is a fixed, transparent
  emission *function*, not a coin-count ceiling.

**On-chain enforcement is height-parameterized.** Block validation checks the
coinbase against `calculate_block_reward(height)` =
`base_reward_from_supply(estimate_supply_at_height(height))`
(`emission/mod.rs`, `curve.rs`). `estimate_supply_at_height` numerically
integrates the curve with adaptive step sizes, so the reward is a deterministic
pure function of **height** — miner and validator compute the same value, and it
is reorg-history-independent (see §6). It approximates, but is not, the exact
per-block cumulative supply.

**Fee burn / split** (`consensus/fee_market.rs::distribute_fee`): at/after
`FEE_DISTRIBUTION_HEIGHT`, each transaction fee is split — **30% burned / 70% to
miner** normally, **50% / 50%** under congestion (`CONGESTION_THRESHOLD = 80%`
block fullness). 0% to any developer/protocol fund. Burns destroy coins (they
push net supply below the gross-emission curve); net supply is deflationary only
when burned fees exceed the 0.6/block tail (fees > ~2 CYNC/block), otherwise
net-inflationary via the tail.

---

## 3. Block validity

Enforced by `validate_block_with_checkpoint_for_network` and the checks it calls
(all `validation.rs` unless noted). Genesis (height 0) is exempt from PoW,
magic, and timestamp checks. Under the compile-time `insecure-fast-sync` feature
(default **off**; CI rejects release artifacts built with it) crypto may be
skipped for blocks below a checkpoint — production builds verify fully.

1. **Network magic** — `header.network_magic` equals this node's network magic
   (`check_block_network_magic`).
2. **Consensus checkpoint** — if a hardcoded `(height, hash)` exists, the block
   hash must match (`expected_checkpoint_hash`, `constants.rs`). *The
   `CONSENSUS_CHECKPOINTS` table is currently empty (dormant).*
3. **Header** — `version ≥ block_version_at_height(h)`; `height == prev+1`;
   `prev_hash == prev.hash()`; `timestamp > prev.timestamp`; `checkpoint_vote`
   height (if present) `< block.height`.
4. **Future timestamp** — reject if `timestamp > now + MAX_TIMESTAMP_DRIFT`
   (600 s); a local clock error is a non-fatal error, not a rejection.
5. **Proof of work** — recompute the anchor `mixed_hash` from
   `(prev_hash, height, timestamp)`; it must equal the claimed anchor; the
   algorithm must match; the RandomX hash over `(anchor, nonce, tx_root, height)`
   must meet `header.target` (byte-wise big-endian ≤). (`pow.rs::verify_pow`.)
   *The sequential-pad iteration count is 1 — this is RandomX, not a VDF.*
6. **Difficulty sanity (loose)** — `validate_difficulty_target`: target ≤
   max, ≠ 0, and within a coarse inter-block ratio. **The exact ASERT target is
   enforced in `chain.rs` (§5), not here.**
7. **Size / weight / count** — serialized size ≤ `MAX_BLOCK_SIZE`; block weight
   `Σ(tx_size + ring_members·256) ≤ 4·MAX_BLOCK_SIZE`; tx count ≤
   `MAX_TXS_PER_BLOCK`.
8. **Coinbase structure** — ≥1 tx; `transactions[0]` is the coinbase; exactly one
   coinbase (multiple rejected); coinbase output count ≤ 16.
9. **Merkle root** — `merkle_root(tx_hashes)` (RFC-6962 domain separation, leaf
   `0x00` / node `0x01`, CVE-2012-2459-safe) equals `header.tx_root`.
10. **Privacy policy** — every non-coinbase tx: commitment decompresses to a
    non-identity Ristretto point; stealth address is a valid non-identity point;
    ≥1 input (`privacy_policy.rs`). Confidential + stealth are mandatory.
11. **Coinbase amount** — each coinbase output commitment equals
    `commit(declared_amount, 0)` (zero blinding — transparent issuance); each
    on-curve, non-identity; `Σ declared == calculate_block_reward(height) +
    miner_fee_share`, with `checked_add` (overflow → reject). "Max coinbase" =
    reward + `distribute_fee(fees, congested).to_miner` at/after
    `FEE_DISTRIBUTION_HEIGHT`, else reward + full fees. Reward is bounded to
    `[TAIL_EMISSION, reward(0)]`. If >1 output, reward ≥ `MIN_OUTPUT_AMOUNT ×
    output_count`.
12. **No duplicate tx hashes** in the block.
13. **No duplicate key images** across all txs in the block (Phase-1 double-spend
    guard).
14. **v1.0.12 output rules** (when active, §7) — no two outputs in the block
    share a stealth address; coinbase/output `encrypted_amount` exactly 8 bytes;
    `encrypted_memo ≤ MAX_OUTPUT_MEMO_SIZE`.
15. **Per-tx congestion fee** — each non-coinbase `tx.fee ≥ size ·
    MIN_FEE_PER_BYTE · multiplier/100` (multiplier 1.0/1.5/2.0/3.0 at 50/75/90%
    fullness, `fee_market.rs`).
16. **Per-tx crypto** — every non-coinbase tx passes §4, validated in parallel.

---

## 4. Transaction validity (non-coinbase)

Enforced by `validate_transaction_for_network` (`validation.rs`), in order. A
coinbase early-returns after the version check.

1. **Version** — `1 ≤ version ≤ MAX_TX_VERSION (2)`; version ≥ 2 rejected below
   `V2_TX_ACTIVATION_HEIGHT (50,000)`.
2. **I/O counts** — inputs and outputs non-empty; inputs ≤ 256; outputs ≤ 16;
   legacy ratio inputs ≤ 32× outputs and vice-versa.
3. **Uniform tx shape** (from `UNIFORM_TX_SHAPE_HEIGHT = 0`, i.e. genesis) —
   Transfer/Churn must have exactly **2 inputs**; **2 outputs** for CYNC (3 for
   an asset tx); Churn exactly 2 outputs.
4. **Output field caps** (v1.0.12) — `encrypted_amount` exactly 8 bytes;
   `encrypted_memo ≤ 256`.
5. **Double-spend** — no duplicate key image within the tx; no key image already
   present in the UTXO set.
6. **Ring member existence + commitment** — each ring member's stealth address is
   found in the live UTXO set **or** the permanent `output_index`, and
   `member.commitment` equals the on-chain commitment. **Below
   `STRICT_RING_MEMBER_HEIGHT (100)`, a ring member not found on-chain is logged
   and allowed** (bootstrap relaxation — see §8 and the genesis-bootstrap
   runbook).
7. **Ring member coinbase maturity** — a coinbase ring member must satisfy
   `current_height − output_height ≥ min_output_age_at_height(current_height)`
   (10 pre-fork / 100 post; mainnet 100 from genesis).
8. **Ring member time-lock** — a ring member carrying `lock_height` must be
   unlocked (`current_height ≥ lock_height`).
9. **Ring size** — `input.ring_members.len() == effective_ring_size(height,
   available)`, where `available` is the output-availability metric (see §6):
   under v1.0.12, `total_outputs_ever − reorg_disconnects_total`; otherwise the
   live `output_count()`. `effective_ring_size` targets 11 below height 10,000
   and 16 at/above, adapting downward on a young chain (min 2).
10. **Ring member uniqueness** — no duplicate public key within an input's ring.
11. **CLSAG ring signatures** — every input's CLSAG verifies over
    `tx.signing_hash()` (parallel, `SeqCst` fail-flag).
12. **Range proofs** — non-empty; commitments on-curve; **Bulletproofs+**
    verification (BP+ active from genesis, `BULLETPROOFS_PLUS_HEIGHT = 0`).
13. **Pedersen balance** — `Σ pseudo_output_commitments == Σ output_commitments +
    commit(fee, 0)`; an identity pseudo-output is rejected.

*Mempool admission* (`validate_transaction_basic`) additionally enforces
min/max tx size, a per-byte minimum fee, ring ≥ 11, and per-output dust
(`MIN_OUTPUT_AMOUNT`). These are relay-policy, **not** block consensus.

---

## 5. Chain selection, reorg, and finality

All in `chain.rs::add_block`.

- **Exact difficulty (ASERT).** `block.target` must bit-equal
  `calculate_difficulty(window, height)` (`difficulty.rs`) — a dual-window
  (8/144) integer ASERT with `ASERT_HALFLIFE = 3600` and a `MIN_DIFFICULTY = 500`
  floor. Fork/reorg blocks use a fork-aware window.
- **Median-time-past.** For height ≥ 11, `timestamp` must exceed the median of
  the 11 ancestor timestamps, walked via `prev_hash` along the block's **own
  lineage** (`median_time_past_of_lineage`) — not the active chain, so a fork
  block is judged against its own history.
- **Fork choice.** The canonical chain is the one with the greatest cumulative
  `total_difficulty` (Nakamoto). Ties (equal work) are broken by the
  **lexicographically smaller tip hash**.
- **`total_difficulty` definition.** `1 (genesis base) + Σ
  calculate_difficulty_from_target(target)` over the canonical chain, where
  `dft(target) = u128::MAX / target[0..16]_BE`. All three code paths (extend,
  fork-walk `calculate_fork_cumulative_work`, and `recompute_total_difficulty`)
  agree on the genesis base of 1, and the value **self-heals** by recomputation
  on load — making it a pure function of canonical content (§6).
- **Reorg acceptability (MESS).** `evaluate_reorg_acceptability`: Tier 1 (depth ≤
  `REORG_UNCONDITIONAL_DEPTH = 10`) accepts strictly-more-work; Tier 2 (11 …
  `max_reorg_depth`) requires `fork_work > honest_work · 2^((depth−10)/20)`
  (exponentially harder with depth); Tier 3 (> `max_reorg_depth`) is a hard
  reject. `max_reorg_depth` is **100 on mainnet** (1000 on testnet/regtest).
  Tier 2 is skipped below `BOOTSTRAP_MESS_HEIGHT = 1000`.
- **Checkpoint height floor.** A reorg whose fork point is below `last_checkpoint`
  (the height of the most recent auto-checkpoint, recorded every
  `CHECKPOINT_INTERVAL = 144` blocks) is rejected; `rollback` refuses to go below
  it. This is the deterministic finality mechanism (a *height*, a pure function
  of tip height). *The former self-recorded checkpoint-**hash** gate was removed
  as path-dependent — see §6/§8.*
- **Reorg-tip re-validation (REORG-TIP-VALIDATE).** After disconnecting the main
  chain to the fork point and re-validating + applying each fork block against
  the rebuilding UTXO set, the triggering tip block is **re-validated against the
  reorged UTXO state** before being applied. This closes a post-reorg
  double-spend/inflation path (a tip re-spending a key image a fork block already
  consumed). Any failure routes through the proven full-rollback path, restoring
  the honest chain.

---

## 6. Determinism contract

**Every accumulated or persisted value that feeds a consensus verdict MUST be a
pure function of the canonical chain content — never of a node's reorg history.**
Violations let two honest nodes on the same tip disagree and fork. This project
has fixed three bugs of exactly this shape; the contract below is now enforced
and, where noted, guarded by tests.

| Value | Contract | Status |
|---|---|---|
| `total_difficulty` | `1 + Σ dft(target)` over the canonical chain; identical genesis base in all paths; self-heals on load | **Order-independent** (fixed; E2E + self-heal) |
| `total_outputs_ever` | monotonic, **never** decremented (even on reorg) → path-dependent *on its own* | Raw counter — **must not** feed consensus alone |
| `reorg_disconnects_total` | paired; `total_outputs_ever − reorg_disconnects_total` = canonical-outputs-ever | **Order-independent**; this is the v1.0.12 ring-size `available` (property-tested, `tests/property_invariants_determinism.rs`) |
| `output_count()` (live UTXO) | path-dependent / pruning-sensitive | Used only *pre*-v1.0.12 ring-size (the split risk the fork closes) |
| recorded checkpoint **hash** | was path-dependent (first-seen block at a height, not reverted on reorg) | **Removed** as a consensus gate; only the checkpoint **height** floor remains |
| `total_supply` | gross `Σ emission(height)` (deterministic by height; burns not subtracted) | Order-independent; telemetry |
| `output_index` | permanent per-stealth records; removed on reorg-disconnect; unaffected by pruning | Order-independent (canonical) |
| Phase-2 header roots (`spark_set_root`, `mw_kernel_root`) | zero pre-activation; stores `None` | Dormant; inert |

**Rule of thumb for future work:** never feed a raw monotonic counter, a live
`HashMap` iteration order, wall-clock time, or a first-seen/self-recorded value
into a consensus decision. Derive from the canonical chain, or from a value that
provably reverts on disconnect.

---

## 7. Activation heights & hard forks

- **v1.0.12 rules** (`v1_0_12_rules_active`): **always on for Mainnet and
  Regtest**; on Testnet from `HARD_FORK_V1_0_12_HEIGHT = 13,000`. Turns on:
  exact-8-byte `encrypted_amount`; `encrypted_memo` cap; in-tx, cross-tx-in-block,
  and cross-tx-on-chain duplicate-stealth rejection; and the
  `total_outputs_ever − reorg_disconnects_total` ring-size availability metric.
  *On mainnet these apply from genesis, so early-block behavior matches the
  mature chain — see the genesis-bootstrap runbook for the blocks 1–99
  ring-member relaxation (§8).*
- **Bulletproofs+ / uniform tx shape** (`= 0`): active from genesis.
- **Tx version 2** (`V2_TX_ACTIVATION_HEIGHT = 50,000`).
- **Coinbase maturity 10 → 100** (`MIN_OUTPUT_AGE_HARDFORK_HEIGHT`): mainnet uses
  100 from genesis; testnet is pinned at 10 (`u64::MAX` hard-fork height).

---

## 8. Known divergences, relaxations & dormant features

Honest notes for auditors — none is a live consensus bug, but each is a place
where the code differs from a naive reading:

1. **Bootstrap ring-member relaxation.** Below `STRICT_RING_MEMBER_HEIGHT = 100`,
   a ring member absent from the UTXO set and output-index is *warned and
   allowed* with no commitment check — a mint-from-nothing window on blocks
   1–99. Closed **operationally** by the genesis-bootstrap runbook (self-mine ≥
   100 blocks with `--no-peers` before opening the network), not in code.
2. **Height-parameterized reward.** The coinbase reward is
   `calculate_block_reward(height)` (an adaptive-step estimate of supply-at-
   height), not the exact per-block cumulative supply. Deterministic and
   fork-safe; the exact `base_reward_from_supply` is used for templates/display.
3. **Dead/divergent consensus constants removed (2026-08-17).**
   `MINER_SPLIT_PERCENT` (unused; the fee split uses the
   `FEE_MINER/BURN_NORMAL/CONGESTED_PERCENT` 70/30 · 50/50 constants),
   `RANDOMX_KEY_INTERVAL` (dead duplicate of `consensus::pow::RANDOMX_KEY_EPOCH`),
   and `MAX_FUTURE_TIMESTAMP` (unused; the future-block check uses
   `MAX_TIMESTAMP_DRIFT`) were deleted from `constants.rs`, and `MTP_WINDOW` is
   now wired into the MTP walk (previously a hardcoded `11`).
4. **`total_burned` is not accumulated** into a persisted chain counter; burns
   are computed per-fee in `distribute_fee` but not summed into chain state.
   `total_supply` therefore tracks *gross* emission.
5. **`min_target()`** (`difficulty.rs`) is defined and re-exported but not read
   by block validation. Cosmetic.
6. **Dormant / feature-gated (inert in production):** rolling-finality
   (`#[cfg(feature="rolling-finality")]` + a `None` adapter), Phase-2 Spark & MW
   stores (`None` → rewind inert; header roots zero), the CIP-007 activation
   registry (empty), `CONSENSUS_CHECKPOINTS` (empty), and `insecure-fast-sync`
   (compile-time, default off; CI rejects release artifacts built with it).

---

## 9. Test-coverage map

| Rule area | Guarding tests |
|---|---|
| Reorg-tip re-validation (§5) | `tests/reorg_double_spend_e2e.rs` (real-PoW E2E, `#[ignore]`) — verified to fail without the fix |
| Ring-size availability determinism (§6) | `tests/property_invariants_determinism.rs` (400 random reorg histories) + the `utxos.rs` unit regression — both verified to fail against the raw counter |
| `total_difficulty` determinism (§6) | recompute-on-load self-heal + the reorg E2E; the historical divergence is fixed |
| Difficulty/ASERT (§5) | `tests/property_invariants_difficulty.rs` + `difficulty.rs` unit tests |
| Emission curve (§2) | `curve.rs` unit tests (genesis 50 CYNC, tail floor, monotonicity) |
| CLSAG / BP+ / balance (§4) | `tests/full_pipeline_real_crypto.rs`, `crypto_properties.rs`, historical-attack suites |
| Reorg policy / MESS (§5) | `tests/tier14_reorg_defense.rs` |
| P2P hostile input | framing/dispatch caps (audited clean) |

**Gaps / follow-ups:** a dedicated Chain-level reorg-fuzz for `total_difficulty`
(needs a real-PoW mining harness), and an external professional audit — the one
form of assurance self-review cannot substitute.

---

*This spec is derived from a full read of the consensus-critical code on branch
`main`. Corrections that reconcile it to the source are always in order.*
