# CoinCync — Privacy Hardening & Connector (2026-08-22)

A development log of the privacy-layer soundness work, the new privacy
connector, and the wallet/UX wiring completed on 2026-08-22. Written for the
community so there is a single, honest record of what changed, what is live,
what is gated pending external review, and what is deliberately disabled.

**Guiding principle:** CoinCync does not ship half-finished features silently.
Every item below is labeled with its real status. Cryptography that has not had
external review is **gated off and clearly marked** — it is built and tested,
but it does not guard real funds until it is audited.

---

## 1. Security fixes (verified)

### 1.1 Lelantus Spark — serial-tag double-spend (H-1) — FIXED
- **Root cause:** the spend ring signature proved only knowledge of the coin
  secret against base `H` (`P = s·H`); the serial tag `T = s·G` was hashed into
  the Fiat-Shamir transcript but never *proven* to share the same `s`. A coin
  owner could therefore attach an arbitrary tag `T' ≠ s·G` on each spend, so the
  double-spend detector (which keys on the tag) never saw a collision.
- **Fix:** a dual-base Chaum-Pedersen binding — a companion commitment
  `L'_i = z_i·G + c_i·T` is now hashed alongside `L_i = z_i·H + c_i·P_i` at every
  step, forcing one secret `s` to satisfy both `P = s·H` and `T = s·G`.
- **Verification:** completeness at ring sizes n=1/2/3/5 plus a regression test
  that the exact forged-tag attack is now rejected. 14 tests pass under the
  `sketch-lelantus-spark` feature. *(Feature gated off — see §4.)*

### 1.2 MimbleWimble cut-through — kernel inflation — FIXED
- **Root cause:** kernel-set verification checked only the aggregate balance
  (`Σ excess == Σ fee·H`). Two kernels carrying canceling `+v·H` / `−v·H`
  components balance in aggregate while each hides value creation.
- **Fix:** a per-kernel Schnorr signature over base `G` proving `excess − fee·H`
  is a pure blinding `x·G` with no hidden value. Any residual `H` component is
  unsignable, so inflation is rejected per kernel.
- **Verification:** 11 tests including unsigned-kernel rejection, hidden-value
  inflation rejection, and signature round-trip. Runs in the default build.

### 1.3 Subaddress spend (W-1 / W-B) — VERIFIED + mainnet gate lifted
- Subaddress-received outputs are spendable: the spend path applies the
  per-subaddress offset `x_i = x + m` (scanner records the `(account, index)`;
  the send path threads the same key). Proven end-to-end by a receive → spend →
  full-mempool-validate test (`real_crypto_subaddress_output_spendable_e2e`).
- The prior "disabled on mainnet — funds unspendable" gate is now **removed** at
  all three sites (address parse boundary, send path, generation), and the
  now-false "permanently unspendable" messages were corrected.

### 1.4 Reorg / chain-state hardening — FIXED
- **F1 (HIGH):** a failed reorg restored blocks in memory but never restored the
  on-disk `output_index`, which the disconnect removes immediately — leaving a
  ring-member validation partition after cache eviction. Now restored on both
  rollback paths.
- **F2:** the success-path tip apply lacked the Phase-2 store checkpoint every
  other apply site performs; added.
- **F3:** `rollback_to_height` never decremented `total_difficulty`; added.

### 1.5 Transaction hashing — fail-closed
- `Transaction::hash()` / `size()` previously fell back to a *different* value on
  a (practically impossible) serialization error — a consensus footgun (two
  nodes could disagree on a txid). Now they fail closed rather than diverge.

### 1.6 Merkle construction — documentation corrected
- The merkle root duplicates odd nodes (classic CVE-2012-2459 malleability
  shape). It is contained today by downstream duplicate-key-image / single-
  coinbase checks. The prior comment wrongly claimed the construction *prevented*
  the issue; it now accurately describes the containment and flags a root fix as
  a hard-fork decision to make before the mainnet genesis is finalized.
  *(Construction unchanged — owner decision.)*

---

## 2. New: the privacy connector

A single guarded boundary (`src/crypto/privacy_connector.rs`) between the
experimental / dormant privacy schemes and the RingCT chain. One hub, one set of
safety interlocks, a spoke per scheme — instead of scattered hooks across the
consensus code.

**Safety interlocks (fail-closed, inert by default):**
- **Kill switch** — instantly refuses every operation.
- **Mainnet audit interlock** — `CONNECTOR_AUDITED = false` ships false; the
  connector is inert on mainnet until the hand-rolled ZK passes external audit.
- **Activation height** — `None` means permanently inert; activation is a
  scheduled, reviewed event.
- **Feature-compiled check** and a **per-block rate limit**.

**Spokes:** MW cut-through kernels, shielded note-commitment pool, Lelantus
Spark spends, and the dead-man's-switch recovery sweep — each with its
double-spend defense (excess signature / nullifier set / serial tag / timeout).
A cross-scheme **value converter** exists but is hard-disabled behind the audit
flag; it enforces value conservation so the anti-inflation property is in place
for the day it is activated.

**Observability:** a read-only registry (`privacy_feature_registry`) reports the
status of *every* privacy feature. It is exposed over RPC as
**`get_privacy_features`** so anyone can query exactly what is active, gated, or
disabled. It reports state only — it has no power to disable the live features.

---

## 3. Wallet / UX wiring

Five previously-registered-but-unused wallet commands are now surfaced in the
desktop wallet (coincync-wallet-v2):
- network-aware currency unit (tCYNC on testnet, CYNC on mainnet)
- live fee estimate from the node
- recipient-address validation
- lock-wallet-now
- update check

---

## 4. Honest status of the privacy surface

| Feature | Status | Notes |
|---|---|---|
| RingCT / CLSAG confidential transfers | **Active** | Core privacy |
| Stealth addresses + subaddresses | **Active** | Subaddress spend verified this session |
| Decoy (ring) selection | **Active** | Live in the send path |
| Encrypted memos | **Active** | ECDH-encrypted per output |
| Scoped view keys | **Active** | Per-epoch disclosure |
| Auto-churn | **Active** | Opt-in |
| Traffic shaping | **Active** | Jitter + size-norm + cover packets |
| Lelantus Spark | **Gated (inert)** | Fixed + tested; awaits external audit |
| MimbleWimble cut-through | **Gated (inert)** | Fixed + tested; awaits external audit |
| Shielded pool | **Gated (inert)** | State scaffold; awaits proof system + audit |
| Dead-man's-switch sweep | **Gated (inert)** | Authorization path gated in the connector |
| Deniable wallets | **Disabled** | Prior impl leaked artifacts; pending structural rewrite + audit |

The gated schemes are **not** part of the mainnet consensus transaction format;
they will only activate via a scheduled hard fork **after** external
cryptographic review.

---

## 5. What is intentionally NOT done (and why)

- **We did not activate the experimental schemes in live consensus.** They carry
  hand-rolled zero-knowledge constructions that must be reviewed by external
  cryptographers first. Shipping them active would be exactly the kind of
  unfinished feature CoinCync refuses to release.
- **We did not change the merkle construction.** That is a hard fork; it is an
  owner decision to make before the mainnet genesis hash is frozen.

---

*All changes in this log are in the working tree pending commit. Test results
for this work are recorded in `docs/testing/2026-08-22-privacy-hardening-results.md`.*
