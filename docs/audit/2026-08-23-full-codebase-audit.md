# Full-codebase correctness audit vs. Bitcoin / Monero — 2026-08-23

Baseline: `main` @ `cfb979a1`. Method: 9 domain reviewers read the real code and
compared it to Bitcoin/Monero norms; **every high-severity finding below was then
re-verified by hand against the actual code** (subagent audits run ~50% false
positive on file:line specifics, so nothing here is relayed unverified). Findings
are tagged with verification status:

- **[VERIFIED]** — I read the cited code and confirmed the claim this session.
- **[REVIEWER]** — reported by a reviewer, consistent with the code I saw, not yet
  independently line-verified end-to-end.

Cross-references to the open PRs (#47–#54) are noted where a finding is already
being fixed.

---

## CRITICAL (2) — both are key-image binding; both live on `main`; NOT fixed by any open PR

### C-1 — CLSAG aggregation coefficients omit the commitment key image `D` → key-image malleability → double-spend  **[VERIFIED (omission); analytic exploit]**
`src/crypto/clsag.rs:138-152`, verify at `:~420`.
`mu_p = H(ring, I, pseudo_output, message)` and `mu_c = H("CLSAG_agg_1" || mu_p)` — **neither depends on `D`** (`commitment_image`). Verification uses `J = mu_p·I + mu_c·D` with both `I` and `D` attacker-supplied. In Monero **both** coefficients hash the full transcript *including `D`*; that inclusion is exactly what makes `D` (and thus the key image `I`) non-malleable. Because they don't here, an output owner can pick an arbitrary `I'`, solve `D' = mu_c⁻¹·(agg·Hp − mu_p·I')` in closed form (no circularity, since `mu_p/mu_c` don't depend on `D'`), run the normal signing loop, and produce a verifying signature whose key image is unrelated to `x·Hp(P)`. Fresh `I'` each spend ⇒ unlimited double-spend / inflation.
Fix: derive `mu_p` and `mu_c` as two independent, domain-separated hashes over the full transcript **including `D`** (the Monero construction).

### C-2 — Consensus/mempool never bind `input.key_image` to `signature.key_image`  **[VERIFIED]**
`src/transaction/types.rs` (TxInput has both fields), double-spend uses `input.key_image` (`validation.rs:1555,1560,2400`), ring verify uses `input.signature` (`validation.rs:2036`, `verify_ring_signature` never touches `input.key_image`). The only binding check (`input.signature.key_image == input.key_image`) is in `src/transaction/validator.rs:118`, inside `pub fn validate_transaction(tx, height)` — which is called **only by its own unit tests** (`validator.rs:193/200/207`). The live paths call `consensus::validate_transaction` / `validate_transaction_for_network` / `verify_ring_signature`, none of which bind the two. A grep for `signature.key_image` across `consensus/`, `mempool.rs`, `chain.rs` returns nothing.
Exploit: sign honestly (`signature.key_image = x·Hp`), set `input.key_image` to any fresh valid point; double-spend detection stores the fresh point, so the same output spends unlimited times.
Fix: enforce `input.key_image == input.signature.key_image` on the block AND mempool path (promote validator.rs:118), or delete the redundant field and use the signature's key image everywhere.

> C-1 and C-2 compound: both must be fixed. C-2 makes the stored key image attacker-chosen; C-1 makes the *signature's* key image attacker-chosen. Together they are the single most important outcome of this audit — a privacy coin's core anti-double-spend invariant. Recommend a written PoC test for each before and after the fix.

---

## HIGH (4)

### H-1 — Difficulty retarget over-corrects: uses the TIP target as base with a full-window exponent  **[VERIFIED rigorously]**
`src/consensus/difficulty.rs:113-129` (base = `tip_target`), `:167-251` (`apply_asert`; `anchor.target` never read; exponent = `(t_tip − t_anchor) − W·ideal`).
The retarget is `new = tip_target · 2^(windowed_error/halflife)` — a *relative* (tip) base with an *absolute-style windowed* exponent. A single slow/fast block stays in the sliding window for ~W blocks and its solvetime deviation is re-applied on the tip each of those blocks, compounding to `2^(W·Δ/halflife)` before it ages out, then snapping back = ringing. Canonical aserti3-2d bases on the *anchor* block's target (no compounding); WTEMA uses a single-block exponent. This is a genuine, previously-unidentified root cause of the difficulty oscillation seen in production — the existing `docs/design/difficulty-oscillation-analysis.md` attributes the sawtooth to Poisson-variance railing the ±clamp and does **not** identify this. Any fix is a consensus hard fork (the doc already recommends simulate-then-height-gate). Not fund-malleable, so HIGH not CRITICAL.

### H-2 — Fee-market: per-tx congestion fee is a BLOCK-VALIDITY rule the builders don't apply → cheap chain-halt  **[VERIFIED (validator rule); REVIEWER (full exploit chain)]**
`src/consensus/validation.rs:585-637` makes every non-coinbase tx's fee `≥ tx_size · MIN_FEE_PER_BYTE · congestion_multiplier(block_size)/100` a **hard block-validity** rule (an add_error → block invalid) — a deviation from Bitcoin, where fee adequacy is relay/mining policy, never validity. The block builders pack fee-sorted txs to ~`MAX_BLOCK_SIZE` and **never apply this floor** during selection, and the mempool admission floor is scaled to `MAX_MEMPOOL_BYTES` (300 MB), ~150× the block scale. So ~1 MB of *valid* minimum-fee txs is admitted at ×1, packed into a ≥50%-full block that requires ×1.5+, and the miner's own node rejects the block it just mined — repeatedly, until the txs expire (~9.6 h), at near-zero attacker cost. Distinct from Jun #41 (the fee *distribution* half, fixed in PR #47). Fix: apply the same congestion floor in the builder's selection loop (iteratively), or demote the per-tx congestion fee from validity to policy (Bitcoin posture).

### H-3 — Reorg "finality floor" caps reorg depth at `tip_height % 144` and bans the honest peer  **[VERIFIED (code path); REVIEWER (ban amplifier)]**
`src/chain.rs:2603-2617`. `finality_floor = tip − (tip % CHECKPOINT_INTERVAL)`; any reorg with `fork_point < finality_floor` is rejected as `BlockStatus::Invalid`. Effective max reorg depth ranges 0–143 (zero when the tip is on a 144-boundary), far shorter than the MESS tiers advertise — a routine 5-deep reorg crossing a boundary is permanently rejected, stranding the node on the minority branch. The rejection reason doesn't match a non-ban matcher in `scoring.rs`, so the honest peer serving the winning chain is banned, deepening the partition. Same class as the 2026-05-10 launch break. Fix: base the floor on `tip − CHECKPOINT_INTERVAL` so a full window is always reorg-able, and don't ban on this reason.

### H-4 — Light-sync (SPV) cannot detect coinbase outputs  **[REVIEWER; consistent with code I've seen]**
`src/wallet/lightsync.rs`. `OutputDigest`/`BlockDigest` carry no coinbase flag and scan every output as a normal ECDH output, but coinbase amounts are plaintext + zero-blinding + a public-data view tag — so the view-tag gate skips them, and even past it the amount/commitment recompute fails. A solo miner on light sync sees zero reward balance. SPV-only (full scanner handles coinbase correctly); functional, not consensus. Fix: carry an `is_coinbase` flag in the digest and mirror the full scanner's coinbase path.

---

## MEDIUM (6)

- **M-1 [REVIEWER]** Inbound eviction has an absolute `REPUTATION_PROTECT_FLOOR` (80) vs default reputation 100, so a quiet inbound flooder is never an eviction candidate → all honest inbound rejected (eclipse). `network/eviction.rs:133`, `peer.rs:136`. Fix: rely on relative per-axis protection, drop the absolute floor.
- **M-2 [REVIEWER]** Fork blocks are validated against the *main-chain* UTXO set at ingestion, so a fork that spends fork-internal outputs can't assemble (rejected + peer scored) even though the reorg path would handle it. `chain.rs:1964-2003`.
- **M-3 [VERIFIED, already fixed in PR #50]** `primitives/address.rs` still hard-disables mainnet subaddresses with a comment claiming they're unspendable — but the per-subaddress offset `m_i` IS applied on both spend paths (W-1 fixed). PR #50 lifts the gate + corrects the comment.
- **M-4 [REVIEWER]** Future-timestamp cap uses the raw local system clock, not network-adjusted (median-of-peers) time — liveness/partition hazard under clock skew. `validation.rs:1066-1085`. (The 600s bound itself is tighter than Bitcoin's 7200s = good.)
- **M-5 [REVIEWER]** Wallet decoy picker maps the (correct Monero) gamma sample to nearest block height with uniform ordinal, not weighted by per-height output count — statistical deanonymization edge. `wallet/decoy_selection/sampling.rs`. Known approximation (documented).
- **M-6 [REVIEWER]** Light-sync uses the view tag as a hard filter (the full scanner deliberately removed this) → any tx_public_key corruption silently loses the output. `lightsync.rs`.

---

## LOW / INFO (condensed; all [REVIEWER] unless noted)

- **[VERIFIED] `total_burned` truncates u128→u64 on disk** (`chain.rs:279` u128; persist casts `as u64` at 1079/1812/2348/3515; `db/state.rs:36` u64). Telemetry only, never feeds consensus; same class already fixed for `total_supply`.
- **[VERIFIED, fixed in PR #48] Merkle CVE-2012-2459 comment misattributed** (`hash.rs`): the real defense is the duplicate-tx-hash check, not RFC-6962 domain separation. PR #48 documents this.
- Dead coinbase "no inputs" check (`validation.rs:317-320`, always-false condition) — coinbase inputs are ignored downstream so no exploit; still a logic bug.
- Height-1 exact-difficulty bootstrap gap (only the ~32× sanity gate applies to block 1).
- Bulletproofs: verification-cache key omits `current_height` (harmless — BP+ active from genesis); ring-sig cache hit is a timing oracle (privacy, LOW); `H` NUMS-generator provenance not reproducible in-code (verifiability gap); dead exported batch verifiers return `true` on empty input (not wired to consensus).
- Mempool: `FeePercentiles` mixes scaled/unscaled units → wrong wallet fee estimates; RBF is feerate-bump-only (no BIP125 absolute-fee/incremental-relay rules — low impact, self-conflict only); valid txs crypto-verified twice at admission (CPU); `load_from_disk` re-admits without re-validating vs current chain.
- Stealth: one-time-key scalar rides the generic `hash_to_scalar` domain (no collision reachable); memo AEAD key not index-bound (mitigated by random nonce); `Address::from_bytes_checked` accepts the identity point on the string path (Borsh path rejects it) — self-sabotage only.
- CLSAG: effective ring size can drop to 2 during bootstrap (<10k, intentional); a second unused decoy assembler relaxes the age floor with only a warning.
- P2P: DB-persist `panic!` sites turn transient disk errors into aborts (`panic=abort`) — deliberate halt-vs-diverge, availability trade-off.

---

## What is CORRECT (valuable negatives — most of the crypto/consensus is strong)

- **No inflation via coinbase**: each coinbase output checked against `commit(declared, 0)` individually (closes blinding-cancellation), identity/off-curve rejected, sum via `checked_add`, exact `reward+fees` required. **[VERIFIED-adjacent]**
- **Emission**: u128 throughout, monotonic, tail floor, overflow-free across the full height range, reorg-symmetric supply accounting (same tip ⇒ same supply), u64→u128 overflow fix complete on disk with borsh migration.
- **Range proofs + balance**: every output range-proven (BP+, [0,2^64)) in the live path; Pedersen balance `Σpseudo == Σout + fee·H` enforced; identity pseudo-outputs rejected; independent generators; dead batch/cache traps not wired into consensus; fast-sync crypto-skip compile-gated OFF.
- **CLSAG surrounding hardening** (despite C-1/C-2): canonical scalar/point decode at the wire (rejects non-canonical/identity/torsion — Ristretto), full message binding, ring-member on-chain commitment match (closes forged-commitment inflation), ring size + uniqueness enforced, constant-time compare.
- **Stealth/ECDH**: symmetric `r·A == a·R`, domain-separated + index-bound shared secrets, correct subaddress math with the spendability offset, ghost-balance defense (commitment recompute) on all credit paths, ChaCha20-Poly1305 memos with per-encryption random nonce.
- **Validation**: full block validation actually invoked on connect; any-invalid-tx rejects the whole block; merkle root always recomputed; exactly-one-coinbase-first; coinbase maturity enforced at spend for real inputs AND ring decoys (mainnet 100); cross-network magic rejected; strict-monotonic + MTP-of-11 timestamps (blocks timewarp).
- **Fork choice / reorg**: most-cumulative-work with deterministic smaller-hash tiebreak; `total_difficulty` path-independent with self-heal on load; reorg atomic with full rollback on failure and post-reorg tip re-validation (closes a real double-spend vector); cycle/bounds guards on all chain walks.
- **P2P**: header sync fully verifies PoW + MTP + ASERT + checkpoints; message framing caps size before allocation; MissingParent/orphan not scored; IBD validates as it goes (no assume-valid in production).
- **Mempool**: atomic admission (simulate-evict-before-mutate), lowest-feerate-first eviction, resource bounds, reorg re-validation, full crypto at admission. Internal safety is often stricter than Bitcoin.
- **PoW**: sound anchor binding (prev_hash/height/timestamp/tx_root/nonce), no grind/precompute shortcut, correct big-endian `hash ≤ target`, solid integer safety, exact-ASERT target enforced bit-for-bit on both acceptance paths.

---

## Recommended priority

1. **C-1 + C-2** (key-image binding) — pre-mainnet blockers; write PoC tests, fix both, re-audit CLSAG.
2. **H-2** (fee-market chain-halt) — pre-mainnet blocker; align builder or demote the rule.
3. **H-3** (finality-floor reorg cap + honest-peer ban) — pre-mainnet consensus/liveness.
4. **H-1** (difficulty over-correction) — design + simulate + height-gated hard fork (already the doc's plan; feed it this root cause).
5. **H-4 / M-1 / M-2** (SPV coinbase, eclipse eviction, fork assembly) — before public launch.
6. MEDIUM/LOW as capacity allows; M-3 and merkle-comment already in PRs #50/#48.

Every consensus-critical fix (C-1/C-2/H-1/H-2/H-3) touches hash-locked files and must be height-gated + re-locked + testnet-first.
