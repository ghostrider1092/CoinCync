# CIP-Shielded — Note Addressing, Detection & Recovery (the wallet layer)

Status: **DESIGN / draft** (not implemented). Companion to `cip-shielded-txtype.md`,
`cip-shielded-proof.md`, `cip-shielded-anonset.md`. Unblocks B5 (wallet shielded
transactions). **Privacy-critical — must be finalized against the Lelantus-Spark
paper and externally audited before implementation lands unGated.**

## Problem — two coin models, no wallet link

The codebase has two shielded-coin schemes that never converged:

1. **Wallet-facing (exists):** `SpendKey → SparkSpendKey → SparkScanKey →
   SparkAddress { diversifier[11], pk = scan_secret·G }` (`wallet/keys.rs`) +
   `SparkNote` (`crypto/lelantus_spark.rs`) + `SparkStore`. The spend proof here
   was the unaudited O(n) Schnorr stand-in.
2. **Flagship (this work):** the log-size `groth_kohlweiss` **bound coin**
   `C = v·Gv + s·H + r·K` + `ShieldedStore` + `shielded_pipeline` +
   `build_shielded_payload`. The CIP-Shielded proof replaced the O(n) proof — but
   on a **new coin model and store**, not by adapting `SparkNote`/`SparkScanKey`.

**The gap:** a bound coin's opening `(value v, serial s, blinding r)` is not
derived from any recipient key, so the wallet's `SparkScanKey` **cannot detect or
recover** a bound coin. B5 needs that link. This CIP defines it, making the bound
coin **canonical** and reusing the existing `SparkScanKey` chain (retiring the old
`SparkNote`/O(n) path) instead of adding a third scheme.

## Address — one gap to close first

`SparkAddress` today carries a **single** point `pk = scan_secret·G`. That is
enough to *detect* but not to *separate detection from spend*: anyone who can
derive the opening from the scan-side shared secret could also spend. Proper
Spark separation needs the address to carry **two** points (diversified):

- `Q_scan = scan_secret·G`  — the incoming-view / detection key (current `pk`).
- `Q_spend = spend_pub`     — a spend-authority public key (NEW; derived from
  `SparkSpendKey`), so the *spendable* part of a coin binds to the spend secret.

**Action:** extend `SparkAddress` to `{ diversifier, q_scan, q_spend }` (bech32m
payload grows; version the HRP/format). `SparkScanKey` detects + recovers value;
only the holder of `SparkSpendKey` can produce the spend witness / nullifier.

## Note creation (sender → recipient address `(d, Q_scan, Q_spend)`)

Per output:
1. Ephemeral scalar `e ← CSPRNG`; **tx public** `R = e·G` (published with the note).
2. Shared secret `ss = e·Q_scan` (ECDH; recipient recomputes `ss = scan_secret·R`).
3. Derive from `ss` (domain-separated SHA3):
   - coin blinding `r  = H(ss ‖ "COINCYNC_NOTE_r")`,
   - value blinding `b = H(ss ‖ "COINCYNC_NOTE_b")` (for the balance `V = v·Gv + b·K`),
   - amount pad     `k = H(ss ‖ "COINCYNC_NOTE_amt")`; `enc_value = v ⊕ k` (v as LE u64).
4. **Serial (spend-bound):** `s = H(ss ‖ "COINCYNC_NOTE_s" ‖ Q_spend)`. The tree
   coin is `C = v·Gv + s·H + r·K`. The **nullifier** is derived so it requires the
   spend secret — `nf = H("COINCYNC_SPARK_NULLIFIER_v1" ‖ s ‖ spend_secret·H(s))`
   (exact binding TBD with the paper); the scanner can compute `s` but **not** the
   nullifier / spend witness without `SparkSpendKey`.
5. Published note = `(C, R, enc_value [, memo])`; `C` is appended to `ShieldedStore`.
   The value commitment `V` for balance is built at *spend* time from `(v, b)`.

## Scan (recipient, `SparkScanKey`)

For each new tree coin's published note `(C, R, enc_value)`:
1. `ss = scan_secret·R`; derive `r, b, k` as above; `v = enc_value ⊕ k`.
2. Recompute `C' = v·Gv + s·H + r·K` with `s = H(ss ‖ "…_s" ‖ Q_spend)`; **owned iff
   `C' == C`** (constant-time). This is the trial-decryption, mirroring the
   transparent stealth scan in `wallet/lightsync.rs` (`compute_shared_secret` +
   `decrypt_amount`).
3. On a match, store the recovered `(value v, serial s, blinding r)` + the coin's
   `bucket_index`/`member_index` (leaf position) as a spendable `SpendNote`.

The **scan key alone recovers value (for balance display) but cannot spend** — the
nullifier and spend witness need `SparkSpendKey`. Retire the standalone O(n)
`SparkNote` path once this lands.

## Spend (wallet send path — B5)

1. Select owned `SpendNote`s covering `amount + fee`.
2. Resolve each note's bucket via `resolve_bucket`.
3. Create `NewNote`s for recipient(s) + change (each addressed as above).
4. Call `shielded_pipeline::gk::build_shielded_payload(...)` → `ShieldedPayload`.
5. Wrap in a `TxType::Shielded` transaction; submit.

## Security / correctness gates (must hold; audit these)

- **Scan ≠ spend.** Deriving the opening from `ss` must NOT grant spend — the
  nullifier/witness binds `SparkSpendKey`. Requires `Q_spend` in the address.
  *(This is the fund-loss / view-key-steals-funds class; the most important gate.)*
- **Nullifier uniqueness & determinism** per coin (double-spend safety) —
  consistent with `SparkSpendProofV3::nullifier`.
- **Amount privacy:** `enc_value` reveals nothing without `ss`; consider a MAC /
  detection tag to avoid trial-decrypt false positives and to bind `enc_value`.
- **Unlinkability:** diversifiers give distinct-looking addresses under one scan
  key (as `to_spark_address(diversifier)` already intends).
- **Domain separation** on every `H(ss ‖ …)`.

## Open questions

1. Exact nullifier ↔ spend-secret binding (pin to the paper).
2. Detection-tag design (avoid O(notes) full trial-recompute; e.g. a short view tag).
3. Address/bech32 format + version bump for the two-point address.
4. How `s` (public function of `ss`) interacts with the GK spend (the spend proves
   knowledge of `(m=s, r)`; confirm scan-derivable `s` doesn't weaken soundness —
   it shouldn't, since spending still needs `r`, but state it).
5. Migration: subsume `SparkNote`/`SparkStore`; keep `SparkScanKey`/address.

## Implementation plan (post-design-signoff, all gated `sketch-gk-proof`)

1. Extend `SparkAddress` → `{diversifier, q_scan, q_spend}` + bech32 version.
2. `crypto/spark_note.rs`: `create_note(address, value, rng) -> (coin C, R, enc, opening)`
   and `scan_note(scan_key, C, R, enc) -> Option<RecoveredNote>` + tests
   (create→scan round-trip; wrong key rejects; scan-only cannot spend).
3. Wallet: a shielded note store (owned `SpendNote`s) + hook `scan_note` into the
   block scan (`background_sync`/`lightsync`).
4. Wallet `shielded-send` command → selects notes → `build_shielded_payload` → submit.
5. regtest e2e (mint → scan → spend) → external audit → activation.
