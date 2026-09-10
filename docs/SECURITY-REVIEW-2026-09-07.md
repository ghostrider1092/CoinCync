# CoinCync security review — 2026-09-07

**Scope:** prioritized attack-surface review of the CoinCync codebase (~187K LOC)
ahead of the final testnet. Five domains reviewed in parallel — network/P2P,
JSON-RPC, consensus/validation, cryptography, wallet/keys — each reading the
actual code and reporting only confirmed, concrete findings. The HIGH finding
was independently re-verified against source (see §1).

**This is not a substitute for the engaged professional audit.** It covers the
reachable, high-signal surface and gives the auditors a head start. Feed this
list to them.

**Headline:** one HIGH (consensus, launch-blocking), no CRITICALs; the rest are
MEDIUM/LOW DoS, hygiene, and defense-in-depth. The privacy-critical custom
crypto (CLSAG, key-image binding, Bulletproofs+ dispatch, stealth ECDH) and the
inflation/double-spend paths were **verified sound**.

---

## Severity summary

| # | Severity | Area | Issue |
|---|----------|------|-------|
| 1 | **HIGH** | consensus | PoW does not commit to the full header → block-hash malleability + tie-break grinding |
| 2 | MEDIUM | rpc | Unauthenticated, unthrottled `/api/v1/transaction/submit` drives full crypto verification |
| 3 | MEDIUM | network | Half-open inbound connections bypass `MAX_INBOUND` + memory budget |
| 4 | MEDIUM | rpc | `verify_keyimage_uniqueness` blocks a tokio worker + chain-sized `HashSet` |
| 5 | MEDIUM | wallet | `SparkScanKey` secret scalar never zeroized |
| 6 | LOW/MED | crypto | Disclosure Schnorr verifiers accept the identity point |
| 7 | LOW | wallet | Unbounded `ct_len` allocation in v4 wallet loader (~4 GB OOM) |
| 8 | LOW | wallet | Windows ACL fallback grants `Users` group full control when `USERNAME` unset |
| 9 | LOW | wallet | Coinbase amount trusted without commitment check in light sync |
| 10 | LOW | rpc | Several `verify_*`/`full_chain_audit` handlers off the blocking pool (bounded 128) |
| 11 | LOW | rpc | App-layer RPC rate limiter effectively off by default on a public bind |
| 12 | LOW | rpc | `api_key` ignored when `auth_enabled=false` on loopback |
| 13 | LOW | consensus | `supply_commitment` documented but never validated |
| 14 | INFO | crypto | `thread_rng` (CSPRNG) for churn timing — align with `OsRng` discipline |

Feature-gated (OFF by default) — **fix before enabling:** `SparkNote` leaks its
secret serial via `Debug`/`Serialize` and isn't zeroized (`sketch-lelantus-spark`);
`kernel_offset` verify lacks point hygiene (`sketch-kernel-offsets`);
`lightwallet.rs` `is_output_for_keys()` always returns `true` (dead code, no route
wires it — fix before any light-wallet P1 wiring).

---

## 1 — HIGH: PoW does not commit to the full block header

**`src/consensus/pow.rs:255-283` (`compute_pow_hash`), `:1259-1313` (`verify_pow`),
`:219-252` (`compute_full_anchor`); `src/consensus/header.rs:47-87` (`hash()`);
tie-break at `src/chain.rs:2444-2452`.** Independently re-verified.

The difficulty check runs against `RandomX(anchor.mixed_hash || nonce || tx_root)`,
where `anchor` binds only `(prev_hash, height, timestamp)`. `verify_pow` checks
`pow_hash.meets_difficulty(target)` and **never hashes `header.hash()`**. So these
header fields — which *are* in `header.hash()` (block identity) — are **not bound
by PoW**: `version`, `miner_pubkey`, `supply_commitment`, `checkpoint_vote`,
`spark_set_root`, `mw_kernel_root`. (`target` is separately pinned to the ASERT
value in `chain.rs`; `algorithm` is checked; `network_magic` is checked first —
those three are safe.)

The `header.rs:50-53` comment claims all fields are bound "to prevent block
malleability where a miner could modify omitted fields after finding a valid PoW
hash." **That guarantee is false** — including a field in `header.hash()` does not
bind it to the PoW, because the target comparison uses the anchor-based
`pow_hash`, not `header.hash()`.

**Consequence:**
- One PoW solution yields **unlimited distinct valid `block.hash()` values** (same
  work, same txs) → equivocation and orphan/fork-pool + block-cache pollution
  (DoS amplification) with zero extra RandomX work.
- The equal-work fork tie-break (`chain.rs:2449`) prefers the lexicographically
  smallest `block.hash()`. An attacker can **grind the unbound fields** (cheap
  header hashing, not RandomX) to force honest nodes to reorg to *their* variant
  of the honest miner's block — overriding the real miner's `miner_pubkey` /
  `checkpoint_vote` / `supply_commitment` on essentially every block.
- Latent, higher-impact once feature-gated subsystems activate: rolling-finality
  vote forgery/stripping via unbound `checkpoint_vote`; unbound Phase-2 accumulator
  roots (`spark_set_root`/`mw_kernel_root`) become a forgery surface.

**Fix:** make the PoW preimage commit to the full header — feed `header.hash()`
(or a canonical hash over all consensus fields) into the RandomX input instead of
only `anchor || nonce || tx_root`, or fold the remaining header fields into the
anchor seed. Then the `header.rs` anti-malleability comment becomes true.

**Note on timing:** this changes the PoW preimage, i.e. it resets the chain. Far
cheaper to land it in the final testnet than to discover it after mainnet. Route
the exact construction through the auditors.

---

## 2 — MEDIUM: unauthenticated, unthrottled tx submit (REST)

**`src/rpc/rest.rs:915-934` → `send_raw_transaction` (`src/rpc/server.rs:1339`).**
Every other expensive REST endpoint calls `enforce_fixed_window_limit` +
`enforce_ip_fixed_window_limit`; this one calls **neither**. Each request drives
full CLSAG + Bulletproofs+ verification + key-image DB walk under `block_in_place`,
so an anonymous client can flood expensive validation on the public api node.
Minor: the size guard allows 2 MB while the error says "max 1MB".
**Fix:** add the same fixed-window + per-IP limiters; correct the size/message mismatch.

## 3 — MEDIUM: half-open inbound connection DoS

**`src/network/node/peer_manager.rs:142-144` (+ `connection.rs:422`, `noise.rs:384`).**
`MAX_INBOUND` (64) counts only peers that finished the Noise handshake; in-handshake
connections are invisible to it (only the per-IP cap of 2 applies). Each accepted
connection spawns a task and eagerly allocates a 64 KiB buffer **not** charged to
the `ConnectionTracker` budget. An IP-diverse attacker (~1000 IPs → ~2000 concurrent
handshakes → ~128 MiB uncounted + 2000 tasks, refreshing every 15 s) bypasses both
`MAX_INBOUND` and the memory budget.
**Fix:** a `tokio::Semaphore` acquired at accept (before spawn), sized `MAX_INBOUND
+ slack`; optionally charge the handshake buffer to the connection budget.

## 4 — MEDIUM: `verify_keyimage_uniqueness` ties up a worker

**`src/rpc/server.rs:2252-2287`.** Plain async handler (not `register_blocking_method`)
that scans up to 25k blocks and builds a chain-sized `HashSet<String>` — holds a
tokio worker for the whole scan.
**Fix:** `register_blocking_method` (or `block_in_place`) + lower/paginate the 25k cap.

## 5 — MEDIUM: `SparkScanKey` never zeroized

**`src/wallet/keys.rs:473-474`.** `SparkScanKey(pub Scalar)` has no
`ZeroizeOnDrop`/`Drop`, unlike every sibling secret key (`SpendKey`,
`IncomingViewingKey`, … all wiped per the R-80 fixes). It's a secret (detects all
incoming Spark coins) that persists in freed heap after drop. `Serialize`/
`Deserialize` also means it can reach disk — confirm it is only persisted inside
the encrypted wallet blob.
**Fix:** add `zeroize::Zeroize, zeroize::ZeroizeOnDrop` (or a manual `Drop`).

## 6 — LOW/MEDIUM: identity-point gap in disclosure Schnorr verifiers

**`src/crypto/disclosure.rs:207,366,751/753`.** The balance/ownership/source
compliance-disclosure proofs decode peer-supplied nonce points with raw
`decompress()` / `PublicPoint::from_bytes`, which accept the identity element —
`peer_scalars.rs:91-105` flags this as unclosed. Defense-in-depth gap (no forgery
path constructed; the Fiat-Shamir challenge binds `R`), and these are disclosure
proofs, not consensus.
**Fix:** route through `PeerPoint::decode_non_identity`, matching the scalar-side
`PeerScalar` migration already applied to `schnorr_s`.

## 7 — LOW: unbounded `ct_len` allocation in v4 wallet loader

**`src/wallet/persistence.rs:1352-1354`.** `ct_len` (u32 from the file) is used in
`vec![0u8; ct_len]` with no bound; the v3 loader caps the analogous field at 100 MB.
A crafted/corrupt v4 wallet can force a ~4 GB allocation on open.
**Fix:** bound `ct_len` (must fit the remaining prelude, or the same 100 MB ceiling).

## 8 — LOW: Windows ACL fallback grants `Users`

**`src/wallet/persistence.rs:224-225`.** `USERNAME` unset (service/CI/container) →
`icacls /grant:r Users:F` after `/inheritance:r`, leaving the encrypted wallet +
sidecars readable/writable by all local users.
**Fix:** on empty `USERNAME`, deny/skip loudly rather than granting `Users:F`;
better, resolve the current user SID.

## 9 — LOW: coinbase amount trusted without commitment check (light sync)

**`src/wallet/lightsync.rs:630-671`; same omission in `scanner.rs:640-697`.** The
coinbase digest path returns the plaintext amount with zero blinding and no
`commit(amount, 0) == output.commitment` recompute (the non-coinbase paths do
verify). Impact is a ghost/unspendable balance, not fund loss, and requires a
light-sync server presenting an output the wallet owns.
**Fix:** verify the zero-blinding coinbase commitment for parity.

## 10-14 — LOW / INFO

- **10** `verify_signatures_in_range` / `verify_range_proofs_in_range` /
  `verify_commitment_balance_in_range` / `full_chain_audit` /
  `check_zero_commitments_in_range` (`server.rs:2291-2462`) run heavy crypto off
  the blocking pool — bounded to a 128-block span, so worker-hold is bounded. Move
  to the blocking pool.
- **11** The app-layer RPC rate limiter whitelists `127.0.0.1`, and without
  `COINCYNC_RPC_XFF_PROXY_ACK=1` every request resolves to `127.0.0.1` → no
  throttling by default on a public bind (bearer auth still required, so only an
  authed/compromised-key caller is un-throttled). Documented as a "safe default"
  but it silently negates a claimed mitigation.
- **12** `api_key` set with `auth_enabled=false` on a loopback bind → no auth
  applied. Warn when a key is set but unenforced.
- **13** `header.supply_commitment` is documented as committing to emitted supply
  (`calculate_supply_commitment` exists) but no consensus check compares them; every
  producer sets it to zero. Enforce it or mark it reserved. (Also unbound by PoW per §1.)
- **14** `src/wallet/churn.rs:129,144` use `thread_rng` (a CSPRNG — not a key/nonce
  weakness) for churn timing/amount; the project's discipline is `OsRng` for
  privacy-critical randomness. Align.

---

## Verified sound (no issue — high-scrutiny areas)

- **No inflation / double-spend path.** Coinbase `commit(declared,0)` equality +
  exact `total_declared == max_coinbase` with `checked_add`; fees Pedersen-bound;
  in-tx + in-block + global UTXO key-image checks; `input.key_image` bound to
  `signature.key_image` before the cache; key-image set replayed from genesis at
  startup.
- **CLSAG** sign/verify correct; key-image malleability closed by binding the
  commitment image into both aggregation coefficients (with a forgery regression
  test); verifier rejects identity key-image/commitment-image/ring members;
  `ct_eq` final compare; canonical `PeerScalar` decode; aggregate secret zeroized.
- **Ring-sig verification cache** keys on `(message, sig_bytes)` and the signing
  hash is length-framed + domain-separated — cannot be poisoned across statements.
- **Bulletproofs+** delegates to `tari_bulletproofs_plus`; height-gated dispatch
  fails closed; commitments decoded checked.
- **Determinism:** integer u128 ASERT, integer fee/congestion math, hash-lex fork
  tie-break, pure-function emission — no float or platform-dependent consensus.
  RandomX fast/light asserted bit-identical.
- **P2P:** framer enforces per-message byte caps before deserialization; borsh 1.6.1
  caps pre-allocation; every handler validates after decode; sync nonces single-use
  and peer/generation-bound (no eclipse); peer height/difficulty rejected-not-clamped;
  Dandelion++ uses `OsRng`.
- **Wallet at rest:** XChaCha20-Poly1305 + Argon2id with stored+validated KDF params;
  redacted `Debug` on secret types; seed/key stack-copy zeroization; ghost-balance
  commitment-recompute in full + (non-coinbase) light scanners; curve-point-validated
  address decode; atomic sidecar writes with permission hardening; constant-time
  HMAC-before-AEAD.
- **RPC auth:** bearer middleware sound; no auth-bypass to state-mutating methods;
  hex-length + range caps (audit 128, batch 100, locators 256, journal 4096);
  saturating/checked overflow math; `get_outputs_by_locators` correctly capped.

---

## Recommendation

1. **Before the final testnet:** fix **§1** (bind the full header into PoW) — it
   resets the chain, so it's far cheaper now than post-mainnet. Route the exact
   construction through the auditors.
2. **Before any public exposure:** fix **§2** and **§3** (the reachable DoS vectors)
   and **§5** (secret zeroization).
3. **Opportunistic:** §4, §6-§14.
4. **Gate-keep:** the three feature-gated items must be closed before their
   `sketch-*` / light-wallet features are ever enabled.
5. Hand this entire list to the engaged security auditors — it is a starting map,
   not a clearance.

---

## Remediation status (applied 2026-09-07)

All findings except §1 were fixed and verified. Affected test suites all pass:
disclosure 26, crypto 150, wallet 193, rpc 56, network 287, consensus 74.

| # | Status | What changed |
|---|--------|--------------|
| 1 | **DEFERRED — design below** | Chain-resetting PoW change; needs auditor sign-off before it lands |
| 2 | ✅ fixed | `rest.rs`: global + per-IP fixed-window limiter (5/s) on tx submit; size cap 2MB→1MB |
| 3 | ✅ fixed | `peer_manager.rs`: `Semaphore(MAX_INBOUND + 32)` acquired at accept, held for the connection's life — bounds in-handshake connections |
| 4 | ✅ fixed | `verify_keyimage_uniqueness` → `register_blocking_method` |
| 5 | ✅ fixed | `SparkScanKey`: `Drop` zeroizes the secret scalar |
| 6 | ✅ fixed | `disclosure.rs`: 4 Schnorr nonce points now reject identity (`PeerPoint::decode_non_identity` / `is_identity`) |
| 7 | ✅ fixed | v4 wallet loader: `ct_len` capped at 100 MiB before alloc |
| 8 | ✅ fixed | Windows ACL: resolve current user via `whoami`; never fall back to `Users`; fail-closed |
| 9 | ✅ fixed | coinbase zero-blinding commitment verified in light sync + full scanner |
| 10 | ✅ fixed | 5 `verify_*`/`full_chain_audit` handlers → `register_blocking_method` |
| 11 | ✅ fixed | startup warning when the per-IP RPC limiter is inert on a public bind |
| 12 | ✅ fixed | loud warning when `api_key` is set but unenforced |
| 13 | ⚠️ doc-marked reserved | field documented as reserved/unenforced; full enforcement bundled with §1 |
| 14 | ✅ fixed | `churn.rs`: `thread_rng` → `OsRng` |
| gated: SparkNote | ✅ fixed | `Debug` redacted, secrets zeroized on drop (canonical-decode noted for activation) |
| gated: kernel_offset | ✅ fixed | `verify_against` rejects identity excess/R |
| gated: lightwallet | ✅ contract fixed | `is_output_for_keys` documented as a candidate filter, not an ownership gate; must be renamed + rate-limited before wiring |

---

## §1 — PoW header-binding: implementation design (for review before landing)

**Goal:** bind every consensus header field into the PoW so a valid solution
can't be re-used with mutated `version` / `miner_pubkey` / `supply_commitment` /
`checkpoint_vote` / `spark_set_root` / `mw_kernel_root`.

**Chosen approach — fold the unbound fields into the anchor** (less hot-path
disruption than feeding `header.hash()` into every per-nonce RandomX input; the
anchor is computed once per block, not per nonce, so the batch hasher's
`anchor ‖ nonce ‖ tx_root` input shape is unchanged):

1. Add `header_pow_binding(header) -> Hash` = domain-separated `hash_concat` over
   the currently-unbound fields (`version`, `miner_pubkey`, `supply_commitment`,
   `checkpoint_vote`, `spark_set_root`, `mw_kernel_root`). Do **not** include
   `nonce`/`anchor`/`tx_root`/`target` (already bound / would create circularity).
2. `compute_full_anchor(prev_hash, height, timestamp, binding)` folds `binding`
   into its `seed`, and the `SEQ_PAD_CACHE` key gains `binding`.
3. `verify_pow` computes `binding` from the header it validates and passes it to
   `compute_full_anchor` (its anchor-mismatch check then enforces the binding).
4. Update every `compute_full_anchor` / `compute_pow_hash` / `verify_pow` /
   `compute_pow_hash_batch` caller (block_builder, stratum ×4, pool, pow_cache,
   dispatch/headers, rpc, tick_adapter) to compute + thread `binding`.
5. **Then** §13 becomes enforceable: add `header.supply_commitment ==
   calculate_supply_commitment(height)` to block validation.

**Regression test (must accompany):** take a valid block; mutate `miner_pubkey`
(and `checkpoint_vote`) while keeping nonce/tx_root; assert `verify_pow` now
**fails**. Also assert single-shot == batch == verify PoW are bit-identical
(existing `hash_batch_matches_single` extended).

**Rollout:** this changes the PoW preimage → genesis reset. Land it in the final
testnet genesis, not after mainnet. Run the exact `header_pow_binding` byte
layout past the auditors first.

