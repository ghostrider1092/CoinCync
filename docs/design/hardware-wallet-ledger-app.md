# CoinCync Ledger App — Design & Milestone

Status: **draft / scoping** · Owner: TBD · Target: post-mainnet · Relates to: host-side PR "Hardware-wallet foundation (slices 1–3)"

This document scopes the **on-device app** required to make CoinCync hardware-wallet support real. The host side (the `TxSigner` seam, the `hardware` feature, the APDU transport, and the read-only device ops) already lands incrementally in the main repo. This app is the **other half** and lives in its **own repository** (embedded Rust/C on the Ledger SDK); it is the large, security-critical part.

Nothing in this document is consensus code. It defines a device protocol and its security model.

---

## 1. Why a device app is unavoidable

CoinCync is a Monero/Firo-family privacy coin: ed25519/Ristretto keys, CLSAG ring signatures, RingCT, stealth addresses, subaddresses, view keys. The spend authority is a scalar `b` (the epoch spend secret). For a hardware wallet the invariant is absolute:

> **The spend secret `b` never leaves the device.** Everything that consumes `b` — one-time-secret derivation, key images, CLSAG responses — must execute on-device.

A generic "sign this hash" device is insufficient, because CLSAG is not a single signature over a hash: it derives a key image, aggregates coefficients over the whole ring, and walks a challenge chain (see §4). The device must run that algorithm itself.

## 2. On-device vs host split

Grounded in the current host code:

| Operation | Where | Host reference |
|---|---|---|
| Seed → spend/view key derivation | **device** | `WalletKeys::derive_epoch` (HMAC-SHA256, domains `COINCYNC_SPEND_v2` / `COINCYNC_VIEW_v2`), `src/wallet/wallet_keys.rs` |
| One-time secret `x = H(a·R‖idx) + b (+ m)` | **device** (secret half) | `compute_one_time_secret`, `src/crypto/stealth.rs` |
| Key image `I = x·Hp(x·G)` | **device** | `KeyImage::from_secret`, `src/crypto/curve.rs` |
| CLSAG response `s_real = α − c·(µ_p·x + µ_c·z)` + `α` generation | **device** | `clsag_sign`, `src/crypto/clsag.rs` |
| Subaddress secret offset `m` | **device** | `subaddress_scalar`, `src/crypto/stealth.rs` |
| View key `a` (for scanning) | **host** (released by device after confirm) | `src/crypto/view_keys.rs` |
| Ring / decoy selection, pseudo-output blinding split, `blinding_diff` | **host** | `src/transaction/builder.rs` (amount-side, not spend authority) |
| Range proofs, `signing_hash` construction | **host** | `Transaction::compute_signing_hash` |
| Address display, recipient/amount confirmation | **device screen** | — |

This is the standard Monero-family split: the **host scans** with the view key; the **device signs** with the spend key. It keeps the device's job bounded (no full-chain scan on-device) while preserving the spend-key invariant.

## 3. Key derivation must match the software wallet exactly

A wallet must be movable between the software keystore and the device (same seed → same addresses → same funds). Therefore the device MUST reproduce the host derivation **bit-for-bit**:

1. BIP39 seed → master, path `m/44'/<coin>'/<account>'` (mirror `DerivationPath` in `src/wallet/wallet_keys.rs`).
2. Epoch keys via the **exact** HMAC-SHA256 domain separation (`COINCYNC_SPEND_v2`, `COINCYNC_VIEW_v2`) used by `WalletKeys::derive_epoch`.
3. `spend_public = b·G`, `view_public = a·G` on Ristretto.
4. Subaddress offset `m = subaddress_scalar(a, account, index)`, `D_i = m·G + B`, `C_i = a·D_i`.

**Cross-check gate (CI):** for a fixed test seed, every device output (`account_pubkeys`, `subaddress_pubkeys`, key images, CLSAG signatures) MUST equal the `SoftwareSigner`'s output. This is the single most important correctness test — it prevents the fund-losing "device derives different addresses" class of bug.

## 4. The CLSAG-on-device state machine (the hard part)

`clsag_sign` (`src/crypto/clsag.rs`) is a single closed loop that (1) derives the key image and the auxiliary point `D`, (2) computes the aggregate coefficients `µ_p, µ_c` over the **whole ring**, (3) walks the challenge chain `c_{i+1} = H(…, c_i, …)`, and (4) closes with the real response. A Ledger device cannot hold the full ring + message in one APDU, and the aggregate coefficients require the entire ring before any response can be emitted. So the device flow is a resumable state machine:

- **CLSAG_INIT** (`0x10`): host sends `signing_hash`, `tx_public_key R`, `output_index`, subaddress index, `ring_size`, `pseudo_output`, `blinding_diff`. Device derives `x` (§2), computes `I = x·Hp(x·G)` and `D`, generates the per-signature nonce `α`, hashes the fixed prefix, and returns `key_image, D`.
- **CLSAG_UPDATE** (`0x12`) × ring_size: host streams ring members (public key + commitment) one or a few per APDU. Device accumulates the running hashes needed for `µ_p, µ_c` and the challenge chain, and computes the fake responses for non-real indices as it goes.
- **CLSAG_FINAL** (`0x14`): device closes the chain, computes `s_real = α − c·(µ_p·x + µ_c·z)`, and returns `c1` + the response vector. Host assembles the `ClsagSignature` (`src/crypto/clsag.rs`) exactly as `SoftwareSigner` would.

**Constraints to design against:** Ledger Nano S has ~4–10 KB of app RAM; ring size and the streaming granularity must fit. `α` must be held across INIT→FINAL and wiped on abort. The device must bind every emitted signature to the recipients confirmed on-screen (§6) so a compromised host cannot swap outputs after approval.

## 5. APDU protocol (CLA `0xE0`)

Mirrors `src/wallet/hardware.rs::ins` (host side already defines these constants):

| INS | Command | Host → device | Device → host |
|---|---|---|---|
| `0x00` | GET_APP_CONFIG | — | version `(major,minor,patch)` |
| `0x02` | GET_PUBLIC_KEYS | account (LE u32) | `spend_public ‖ view_public` (64 B) |
| `0x04` | GET_VIEW_KEY | — (on-device confirm) | `view_secret` (32 B) |
| `0x06` | GET_SUBADDRESS | account, index (LE u32×2) | `D_i ‖ C_i` (64 B) |
| `0x08` | GEN_KEY_IMAGE | `R`, output_index, subaddr | `I` (32 B) |
| `0x10` | CLSAG_INIT | see §4 | `key_image ‖ D` |
| `0x12` | CLSAG_UPDATE | next ring member(s) | ack |
| `0x14` | CLSAG_FINAL | — | `c1 ‖ responses[]` |
| `0x1A` | SIGN_TX_CONFIRM | recipients + amounts | user-approval flag |

Short-form APDUs (`CLA INS P1 P2 Lc DATA`, ≤255 B data) with host-side chunking, matching `Apdu::serialize` in the host crate.

## 6. Security model

- **PIN + secure element**: keys live in the Ledger secure element; derivation runs in the app.
- **On-screen confirmation**: before CLSAG_FINAL, the device displays every recipient address + amount + fee (from SIGN_TX_CONFIRM) and requires physical approval. The signature is bound to the approved set — a host that alters outputs after approval produces an invalid signature.
- **View-key release is explicit**: GET_VIEW_KEY shows a warning and requires confirmation (releasing `a` enables host-side scanning, which is a privacy—not spend—trade-off).
- **No spend-key export path exists** in the app. Ever.
- **Blind-signing disabled by default**: refuse to sign a transaction whose outputs weren't displayed.

## 7. Testing & CI

- **Speculos emulator**: run the app headless in CI; drive it with `ledger-transport-zemu` from a Rust integration test.
- **Golden cross-check** (§3): device vs `SoftwareSigner` for a shared seed — pubkeys, subaddress keys, key images, and full CLSAG signatures must match and `clsag_verify` must accept the device signature.
- **Adversarial**: malformed APDUs, oversized rings, aborted state machine (α must be wiped), output-swap-after-approval must fail.

## 8. Milestones

App repo:
1. Skeleton + GET_APP_CONFIG + GET_PUBLIC_KEYS; Speculos CI; golden pubkey cross-check.
2. Derivation parity (epoch domains, subaddresses) + GET_SUBADDRESS + GET_VIEW_KEY confirm flow.
3. GEN_KEY_IMAGE + golden key-image cross-check.
4. CLSAG state machine (INIT/UPDATE/FINAL) + golden signature cross-check + `clsag_verify` acceptance.
5. SIGN_TX_CONFIRM UX + output binding + blind-sign refusal.
6. Trezor variant (different model/SDK; same protocol semantics) — scope separately.

Host repo (consumes the app — these are the deferred slices 4–6 from the foundation PR):
- Slice 4: implement `HardwareSigner::key_image` + `sign_clsag_input` against GEN_KEY_IMAGE / CLSAG_*.
- Slice 5: move one-time-secret derivation behind the signer (stop deriving `x` host-side for hardware).
- Slice 6: wallet UX — connect/attest, `SignerBackend` enum, watch-only host scanning, send confirmation.
- Add the real `ledger-transport-hid` adapter behind the `hardware` feature + Speculos integration test.

## 9. Open questions / risks

- **RAM footprint** of the CLSAG state machine on Nano S — may cap ring size or force finer UPDATE chunking; measure early.
- **Trezor** has a different app model and no comparable Monero-app precedent; treat as a separate, later track.
- **Multi-input transactions**: each input runs its own INIT→FINAL; confirm the per-input α lifecycle and total signing time are acceptable UX.
- **Address/amount display** for stealth outputs: the device shows the recipient's *public address*, not the on-chain stealth address; ensure the host passes enough to reconstruct/display it trustworthily.
