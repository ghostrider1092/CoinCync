<!-- markdownlint-disable MD036 -->
# CIP-001 — CYNC↔BTC Atomic Swap

**Status:** Draft
**Type:** Standards Track (non-consensus, optional client feature)
**Created:** 2026-05-04
**Layer:** Application (off-chain coordination + on-chain primitives reused without modification)
**Design path locked:** [docs/decisions/2026-05-18-cyncswap-path.md](../decisions/2026-05-18-cyncswap-path.md) — adaptor-sig + DLEQ design retained; hash-locked stealth alternative explicitly rejected. Ship with the user-safety stack at [docs/cyncswap-user-safety.md](../cyncswap-user-safety.md) ($500 per-swap cap V1, mandatory watchtower, dual audit). Audit alignment per [docs/cyncswap-farcaster-comit-alignment.md](../cyncswap-farcaster-comit-alignment.md).

---

## Abstract

A trustless atomic swap protocol allowing direct exchange of CYNC for BTC (and vice versa) without any third-party custodian, exchange, or bridge. The protocol is modeled on the well-studied Comit / Farcaster XMR↔BTC swap design, which has been in production since 2021. CYNC's ring-signature scheme is structurally similar enough to Monero's that the cryptographic techniques transfer directly.

The protocol uses **adaptor signatures** rather than HTLCs on the privacy chain, so a CYNC-side observer cannot distinguish swap transactions from ordinary CYNC transactions. The Bitcoin side is a standard P2WPKH/P2TR transaction with adaptor-signed witnesses. Both chains see normal-looking transactions; only the swap participants know they are linked.

---

## Motivation

CoinCync's Constitution forbids the compliance features (transaction blacklists, address filters, Travel Rule attestation hooks) that major US/EU exchanges demand for listing — see Articles VI, IX, XIV, and Right X. CYNC will end up in roughly Monero's listing position: present on rest-of-world and privacy-friendly exchanges, delisted from major US/EU CEXes over time as regulatory pressure tightens.

Atomic swaps compensate. Once CYNC↔BTC swaps work end-to-end, every Bitcoin holder is one transaction away from holding CYNC trustlessly, and major-CEX listings stop being load-bearing for liquidity. This is the listing-independence design that Monero's community pioneered and that CoinCync inherits.

This CIP defines the protocol so an implementation can begin with a clear specification, against which auditors can verify correctness and competing implementations can interoperate.

---

## Status & Implementation

**Substantial portions are now implemented (last updated 2026-05-17).** What's real today in `crates/coincync-swap/`:

| Component | Status | Module | Tests |
| --- | --- | --- | --- |
| Schnorr adaptor sigs (BTC, secp256k1) — create/verify/decrypt/extract | ✅ shipped | `adaptor.rs` | 5 tests; BIP-340 parity-correct path via `create_pre_sig_bip340` |
| Schnorr adaptor sigs (CYNC, Ristretto255) — create/verify/decrypt/extract | ✅ shipped | `adaptor.rs` | 5 tests; no parity dance (Ristretto is prime-order) |
| Cross-curve DLEQ proof (v2) — joint bit decomposition, one Fiat-Shamir challenge | ✅ implemented, pending audit | `cross_curve_dleq.rs` | completeness, encoding, tamper, substituted-statement, mixed-bit and per-curve-secret forgeries, nonce-independence regression |
| `AdaptorSecret` byte-order discipline (secp BE / Ristretto LE) | ✅ shipped | `adaptor.rs::AdaptorSecret` | encoding tag + transparent accessors |
| `AdaptorSecret` constant-time comparison | ✅ shipped | `subtle::ConstantTimeEq` backing `PartialEq` | side-channel-safe |
| BTC RPC client (broadcast + watch + block count) | ✅ shipped | `btc.rs::{BtcChain, BitcoinCoreRpc, MockBtcChain}` | async trait; mock for tests |
| BTC tx construction — lock (with optional script-tree refund branch) | ✅ shipped | `btc.rs::build_lock_tx` | 10 tests; key-path + script-path; dust + overflow + network-mismatch rejection |
| BTC tx construction — claim (key-path spend, tweaked-output-key) | ✅ shipped | `btc.rs::build_claim_tx` | full BIP-340 verification at construction time |
| BTC tx construction — refund (script-path spend, CSV-locked) | ✅ shipped | `btc.rs::build_refund_tx` | 3-element witness, BIP-68 sequence |
| Sighash split for adaptor pre-signing | ✅ shipped | `btc.rs::claim_sighash` / `refund_sighash` | BIP-341 key-path + script-path |
| CYNC RPC client (broadcast + watch + block count) | ✅ shipped | `cync.rs::{CyncChain, CyncNodeRpc, MockCyncChain}` | targets `coincync-node` v1.0.8 RPC surface |
| CYNC swap key-derivation (recipient pubkey + spender secret) | ✅ shipped | `cync.rs::derive_swap_*` | round-trips through real CYNC stealth scheme |
| End-to-end happy-path protocol composition | ✅ shipped | `tests/swap_happy_path_e2e.rs` | walks Alice + Bob through full 17-step flow against mock chains |
| Coordinator state machine + persistence | ✅ shipped | `coordinator.rs` + `state.rs` | 10 integration tests in `tests/integration_full_flow.rs` |
| v1 cross-curve proofs ("fast" dual-response, "strict" per-curve bits) | ❌ removed | — | fast leaked `t` from one proof; strict did not bind the curves — see §"Why the v1 proofs were removed" |
| CLSAG ring-binding for the CYNC adaptor | ⏳ deferred | — | requires modifying audited `coincync::crypto::clsag` |
| BTC tx construction — `bitcoin` crate integration | ✅ shipped | uses real `bitcoin 0.32` types | |
| `cync::build_lock_tx` (full tx construction) | ⏳ wallet's job | — | CYNC tx construction is too wallet-entangled (decoys, blinding, CLSAG ring composition) to live in this crate; the swap-specific glue (key-derivation helpers above) is sufficient |
| Dual-testnet smoke (bitcoind regtest + coincync-node testnet) | ⏳ operational | — | needs running daemons; not a code slice |

**Test totals:** 129 unit + integration tests pass across the swap crate; the end-to-end test exercises every primitive in one Alice/Bob walkthrough.

**Mainnet launch blocker:** working CYNC↔BTC swaps must ship before v1.0 mainnet, per `project_atomic_swap_mainnet_blocker.md`. Public testnet ships without it. The cryptographic primitives are now all in place — what remains is operational integration (wallet UI, dual-testnet smoke, audit) rather than fundamental construction.

---

## Roles

The two parties in any single swap:

- **Alice** — sells CYNC, buys BTC. Locks her CYNC first.
- **Bob** — sells BTC, buys CYNC. Locks his BTC after observing Alice's CYNC lock confirmed.

The roles are asymmetric. Alice locks first because the BTC side has shorter timelocks (necessary so that Alice can refund if Bob disappears, before Bob can refund). The asymmetry is structural and cannot be removed without breaking refund safety.

---

## State Machine

```text
                    Negotiated
                        │
                        │  Alice broadcasts CYNC lock
                        ▼
                  AliceLocked ─────────── timeout ──→ Refunded (Alice)
                        │
                        │  Bob observes confirmations, broadcasts BTC lock
                        ▼
                   BobLocked ─────────── timeout ──→ Refunded (both)
                        │
                        │  Alice claims BTC, revealing the secret
                        ▼
                SecretRevealed
                        │
                        │  Bob extracts secret from Alice's claim, claims CYNC
                        ▼
                   Completed
```

Two terminal states: `Completed` (both sides claimed) and `Refunded` (timeouts elapsed; both sides recovered original funds). A failed swap loses no money — that's the entire point of "atomic".

---

## Cryptographic Primitives

### Adaptor signatures (BTC, Schnorr / BIP-340)

Single-signer Schnorr adaptor over secp256k1, following the construction in Aumayr et al. *Generalized Channels from Limited Blockchain Scripts and Adaptor Signatures* (Asiacrypt 2021) and what `secp256k1-zkp` ships. Given keypair `(x, X = x·G)`, message `m`, adaptor `(t, T = t·G)`:

1. **Pre-sig:** pick nonce `r`, set `R = r·G`. Compute `s_pre = r + e·x  (mod n)` where `e = H_BIP340/challenge(R+T || X_x || m)`. Publish `(R, s_pre)` alongside `T` (the adaptor point, communicated out-of-band).
2. **Verify pre-sig:** check `s_pre·G == R + e·X`.
3. **Decrypt:** given `s_pre` and adaptor secret `t`, compute `s = s_pre + t`. The final BIP-340 signature is `((R+T)_x, s)` — broadcasts as a normal Schnorr witness on a Taproot output.
4. **Extract:** given pre-sig `s_pre` and the on-chain final-sig scalar `s`, recover `t = s - s_pre  (mod n)`.

**BIP-340 parity handling.** Bitcoin consensus enforces even-y for the encoded signer pubkey and the on-chain nonce-commitment `R+T`. The `create_pre_sig_bip340` entry point handles both via (1) `d' = n - d` if `X.y` is odd, and (2) deterministic nonce derivation with `counter`-based retry until `R+T` has even y. Tested against `secp.verify_schnorr` to confirm the resulting 64-byte signature accepts under Bitcoin's consensus verifier.

### Adaptor signatures (CYNC, Ristretto255)

Symmetric to the BTC half but on the prime-order Ristretto255 group, which removes the parity dance entirely. Same `create / verify / decrypt / extract` API; uses SHA-512 + `Scalar::from_hash` for the challenge with domain-separation tag `"CoinCync/SwapAdaptor/CyncChallenge-v1"`.

CLSAG ring-binding (folding the adaptor into the CLSAG c-value so the *act of spending* reveals `t` on the CYNC chain) is deferred — see Status table. The shipped scheme reveals `t` via the BTC-side `recover_secret_from_btc_sig`. That `t` opens the CYNC lock (`bob_spend + t`) only because the cross-curve DLEQ proved, before any funds moved, that `T_btc` and `T_cync` share one secret. Nothing downstream re-checks it.

### Cross-curve discrete-log equality proof (v2)

Both adaptors must be bound to the same scalar `t`, but `t` lives on two different curves (`secp256k1` for Bitcoin, `Ristretto255` for CYNC). The proof is `crates/coincync-swap/src/cross_curve_dleq.rs`: a single Sigma protocol, made non-interactive with ONE Fiat-Shamir challenge, following the composition of `sigma_fun`'s `dl_secp256k1_ed25519_eq` (adapted from Edwards to Ristretto points). It proves knowledge of one integer `0 < t < 2^252` with `T_btc = t·G_btc` and `T_cync = t·G_cync`.

```text
Setup (fixed, derived by every verifier):
  H_btc  = NUMS point on secp256k1   (try-and-increment, domain "CoinCync/Swap/CrossCurveDLEQ-v2/H_btc")
  H_cync = NUMS point on Ristretto   (uniform map of SHA-512, domain ".../H_cync")
  W_i    = 2^i · H  on each curve, i = 0..252     (2^252 < n and 2^252 < ℓ)

Statement digest:
  S = SHA256("CoinCync/Swap/CrossCurveDLEQ-v2/statement" || len(ctx) || ctx || T_btc || T_cync)
  ctx = session context (network, swap id, agreed parameters); verifier supplies its own.

Prover (bits b_0..b_251 of t):
  For each i, independently per curve:
    r_btc_i uniform mod n, r_cync_i uniform mod ℓ
    C_btc_i  = r_btc_i  · G_btc  + b_i · W_btc_i
    C_cync_i = r_cync_i · G_cync + b_i · W_cync_i
  R_btc = Σ r_btc_i (mod n), R_cync = Σ r_cync_i (mod ℓ)      (published)
  U = Σ C_i − R · G = t · H                                  (on each curve)

  Sigma protocol, one challenge e (248-bit integer, same value on both curves):
    Per bit, OR of two ANDs, each branch sharing ONE challenge across the curves:
      branch 0: C_btc_i       = x·G_btc  AND  C_cync_i       = y·G_cync
      branch 1: C_btc_i − W_i = x·G_btc  AND  C_cync_i − W_i = y·G_cync
      challenges e0 XOR e1 = e; responses (s0_btc, s0_cync, s1_btc, s1_cync)
    Per curve, Chaum-Pedersen with an independent nonce:
      log_G(T) = log_H(U)                    (response z_btc mod n, z_cync mod ℓ)
  e = SHA256(domain || version || S || H_btc || H_cync || R || all C_i || all announcements)[..31]

Verifier:
  Rebuild every announcement from (e0, responses, e), recompute e, compare in constant time.
```

**Why this binds the curves.** Two accepting transcripts with different `e` differ in at least one branch challenge per bit. That branch opens `C_btc_i` and `C_cync_i` to the *same* bit. A mixed pair (BTC=0, CYNC=1) has no branch that can be opened on both curves, so it would need both branch challenges fixed in advance (probability 2^-248). The common bits give one integer `t < 2^252` on both curves. The link proof then forces `T = t·G` on each curve, unless the prover knows `log_G(H)`.

**Why it leaks nothing.** No nonce, blinding, or response is shared between curves. Each response is reduced only modulo its own curve's order, from a fresh uniform nonce. Both OR branches are computed with the same operations and selected in constant time. Secret scalars multiply non-generator secp256k1 points only through libsecp256k1's ECDH ladder (`ecmult_const`). `PublicKey::mul_tweak` uses variable-time `ecmult` and is never given secret scalars. Publishing `R` reveals `U = t·H`, which tells an observer no more than `T = t·G` already does (DDH).

**Wire format (v2, fixed 56,608 bytes).** `version (=2) ‖ e (31) ‖ R_btc (32, BE) ‖ R_cync (32, LE) ‖ 252 × [C_btc (33) ‖ C_cync (32) ‖ e0 (31) ‖ s0_btc ‖ s0_cync ‖ s1_btc ‖ s1_cync (4 × 32)] ‖ z_btc (32) ‖ z_cync (32)`. Decoding rejects every other length or version, noncanonical scalars, invalid points, and an identity `C_cync`. The CLI's `prove-dleq` prints `{"version":2,"proof":"<hex>"}`, and `verify-dleq` takes the keys and `--context` from the verifier's own side of the negotiation.

### Why the v1 proofs were removed

v1 had two proofs, and both are deleted, not feature-gated.

- **The "fast" proof leaked `t`.** It used one integer nonce `k < ℓ` for both curves, with `s_btc = k + c·t mod n` and `s_cync = k + c·t mod ℓ`. These are two congruences in two ~252-bit unknowns against a combined modulus `n·ℓ ≈ 2^508`. CRT plus a 2-D lattice reduction recovers `(k, t)` from a single proof: 100/100 trials, at most two candidates, each checked against `T`. Anyone who saw the proof could take the CYNC lock without locking BTC.
- **The "strict" proof proved no equality.** Its per-bit OR proofs ran independently per curve, each with its own challenge, and its linear-combination checks ran per curve too. Nothing tied the BTC bit to the CYNC bit, so `t_btc ≠ t_cync` verified. It also embedded the fast proof as a "floor", so it leaked `t` as well.
- **The "operational binding" argument was backwards.** A mismatched `t` does not leave Alice "with nothing valuable". Alice claims the BTC by revealing `t_btc`; Bob's CYNC key `bob + t_btc` then fails to open the lock. Bob loses his BTC. The proof is the only thing that prevents this; the adaptors are not a backstop.

**Alternative considered:** Chase–Orrù–Perrin–Zaverucha (ePrint 2022/1593): a Pedersen commitment plus a Bulletproofs range proof plus an integer-response Sigma protocol. It gives proofs of a few KB but needs rejection sampling and a new range-proof integration in this crate. The bit-decomposition proof matches a construction with production history (sigma_fun / COMIT) and keeps the arithmetic simple to audit. Revisit if bandwidth matters.

---

### `AdaptorSecret` byte-order discipline

secp256k1 and Ristretto255 disagree on scalar serialization (big-endian vs little-endian). The same scalar value has different byte representations. `AdaptorSecret` carries an `Encoding` tag and exposes `secp256k1_bytes()` / `ristretto_bytes()` accessors that transparently reverse if needed. Constructors `from_secp256k1_bytes` / `from_ristretto_bytes` declare caller intent + run the appropriate canonicality check. Equality (`PartialEq` + `subtle::ConstantTimeEq`) compares by *value*, normalizing to one encoding internally — so a secret recovered from a BTC adaptor (`Secp256k1BigEndian`) compares equal to the original (`RistrettoLittleEndian`) when they represent the same number.

### Refund signatures

The BTC refund uses Taproot script-path spending. The lock tx has a single-leaf script tree:

```text
<csv_blocks> OP_CSV OP_DROP <bob_xonly_pubkey> OP_CHECKSIG
```

After `csv_blocks` (BIP-68 blocks-relative form), Bob can spend via the script path with a Schnorr signature under his refund key. The lock's internal key remains Alice's adaptor-bound spending key (for the happy-path key-path claim). When the script tree is present, Bitcoin consensus enforces the *tweaked output key* `Q = K + tweak·G` where `tweak = TaggedHash("TapTweak", K.x || merkle_root)`; the `tweaked_claim_secret` helper does this arithmetic for the signer side, and `build_claim_tx`'s verifier uses the same `TaprootBuilder` path the lock used so the tweaked key is bit-for-bit consistent.

CYNC refund is currently outside this crate's scope — the swap protocol's CYNC-side refund relies on standard CYNC timelock outputs constructed by the wallet's transaction builder, with the recipient derived via the swap key-derivation helpers in `cync.rs`.

---

## Protocol Phases

### 1. Negotiation (off-chain)

1. Alice publishes (out-of-band: a forum post, a peer-discovery service, a direct contact) her offer: amount of CYNC, desired BTC amount, listen endpoint, swap ID.
2. Bob connects to Alice's endpoint with the swap ID.
3. Both parties exchange:
   - secp256k1 public keys (BTC side)
   - Ed25519 public keys (CYNC side)
   - Cross-curve DL-equality proof binding the adaptor pairs
   - Pre-signed refund transactions for each chain
4. Both parties verify the cross-curve proof. **Mandatory abort if verification fails.**

### 2. Alice locks CYNC

1. Alice constructs a CYNC transaction whose output is a stealth address spendable by Bob's pub key + the adaptor secret (success path) or by Alice's refund key after `cync_timeout_blocks` (refund path).
2. Alice broadcasts to the CoinCync network.
3. Bob's coordinator watches for the txid + N confirmations (typically 10).

### 3. Bob locks BTC

1. After seeing Alice's lock confirmed, Bob constructs a Bitcoin P2WPKH transaction whose unlock condition is Alice's adaptor-decrypted signature (success) or Bob's refund signature after `btc_timeout_blocks` (refund).
2. Bob broadcasts to the Bitcoin network.
3. Alice's coordinator watches for the txid + N confirmations (typically 6).

### 4. Alice claims BTC

1. Alice combines the secret she chose during negotiation with the adaptor she shared, producing a complete Bitcoin signature.
2. Alice broadcasts the BTC claim transaction.

### 5. Bob extracts secret and claims CYNC

1. Bob's coordinator watches the BTC chain. When Alice's claim is observed, Bob extracts the underlying secret from `(adaptor_sig, final_sig)` via the recovery operation.
2. Bob uses the recovered secret to sign the spend of Alice's CYNC lock output, transferring the CYNC to Bob.

The swap is now `Completed`. Both parties have what they wanted; no third party touched the funds.

### Refund paths

If at any non-terminal stage a counterparty disappears:

- After `cync_timeout_blocks` without progress past `AliceLocked`, Alice broadcasts her refund transaction; the CYNC lock returns to her.
- After `btc_timeout_blocks` without progress past `BobLocked`, Bob broadcasts his refund transaction; the BTC lock returns to him.

The asymmetric timeout requirement (`btc_timeout_blocks < cync_timeout_blocks`) ensures Alice can always refund if Bob never broadcasts, and Bob can always refund if Alice never claims.

---

## Timeout Safety

The single most subtle design constraint:

```text
btc_timeout_blocks < cync_timeout_blocks
```

with sufficient margin that the typical block-time difference between the two chains can't invert the order. CYNC targets 120s, Bitcoin targets 600s — so a CYNC timeout of 720 blocks (~24 hr) and a BTC timeout of 144 blocks (~24 hr) is approximately equivalent in wall time, with margin for variance.

Getting this wrong loses funds. Implementation must include exhaustive test cases for timeout-edge scenarios.

---

## Security Considerations

1. **Adaptor implementation correctness.** Adaptor signatures are subtle; existing Monero / Comit implementations have been reviewed by multiple cryptography auditors. We adopt their constructions verbatim where possible, never reimplement primitives.
2. **Cross-curve proof correctness.** The DL-equality proof must be bulletproof against malleability. Use the proof from the Farcaster project's reference implementation.
3. **Replay protection.** Refund signatures bind to specific UTXOs and timeouts; they cannot be replayed against future swaps.
4. **Privacy.** The CYNC-side transactions look like ordinary CYNC transactions — same ring-signature shape, same stealth-address structure, same Pedersen commitment for amounts. Chain analysis cannot identify swap activity from CYNC-side data alone.
5. **No on-chain swap markers.** The protocol reveals nothing on the BTC side that distinguishes a swap from a normal payment, beyond what an HTLC would reveal anyway. Future "Schnorr-only" deployments make this even stronger.
6. **Network-level privacy.** Coordination must run over Tor (or equivalent) to prevent network observers from correlating swap participants. Plain TCP+Noise is acceptable for testnet; Tor onion service is the production default. **Operator guide:** [`docs/cyncswap-transport-setup.md`](../cyncswap-transport-setup.md) — covers all three shipped transports (plain TCP / Noise XX / Noise XX over Tor SOCKS5) with key-generation, torrc HiddenService config, and fingerprint-exchange best practices.
7. **Refund-griefing.** A malicious counterparty who locks then disappears costs the victim only the BTC/CYNC fee for the refund transaction — no principal is at risk. The refund cost is the only griefing vector and is bounded.

---

## Implementation Plan

What's shipped (refreshed 2026-05-17):

1. ✅ **Cryptographic primitives** — BTC + CYNC adaptors, v2 cross-curve DLEQ, byte-order discipline, constant-time comparison. All real, end-to-end tested.
2. ✅ **BTC lock + claim + refund tx construction** — `build_lock_tx` (optional script-tree refund), `build_claim_tx` (full BIP-340 verification), `build_refund_tx` (script-path spend with BIP-68 sequence).
3. ✅ **BTC RPC + CYNC RPC** — async traits + Bitcoin Core JSON-RPC impl + `coincync-node` JSON-RPC impl + in-memory mocks for unit tests.
4. ✅ **CYNC swap key-derivation** — `derive_swap_recipient_spend_pub` + `derive_swap_spender_secret` + round-trip through real stealth scheme. Wallet drives full CYNC tx construction with these helpers wired into its existing builder.
5. ✅ **Coordinator session + state persistence** — already shipped in `coordinator.rs` + `state.rs` with 10 integration tests.
6. ✅ **End-to-end protocol composition test** — `tests/swap_happy_path_e2e.rs` walks the 17-step Alice/Bob flow against mock chains.

Also shipped (continuing the same numbering as the list above):

- ✅ **CLI `cyncswap`** — 32 subcommands total: 24 cryptographic-primitive wrappers + 6 state-machine orchestration handlers (`lock-cync`, `lock-btc`, `claim-btc`, `claim-cync`, `refund-btc`, `refund-cync`) + 2 housekeeping (`status`, `cancel`). All 6 orchestration commands follow the same posture: load state → role-check → state-check → hex-validate → broadcast → apply-transition → save. Broadcast-first-then-save means no on-chain side effect on pre-broadcast failure.
- ✅ **Refund-path e2e test** — `tests/swap_happy_path_e2e.rs::refund_path_bob_recovers_btc_via_csv_branch` exercises the BIP-341 script-path spend through Bob's CSV refund branch, including the adversarial sub-test that confirms `build_refund_tx` is key-binding (rejects sigs under any key other than `refund_branch.bob_pubkey`).
- ✅ **CYNC swap-recipient helper** — `cync::compute_swap_lock_recipient(...) → SwapLockRecipient` bundles the wallet-ready (spend_pubkey, view_pubkey, amount, lock_height) for the lock output. The wallet drops the bundle straight into its existing `TransactionBuilder::add_output(...)` without coincync-swap needing a `coincync` lib dep (avoids the heavy compile-graph reverse-direction).
- ✅ **Dual-testnet smoke harness** — `scripts/cyncswap-dual-testnet-smoke.sh` operator-driven script with three scenarios (`happy` / `refund-btc` / `refund-cync`) walking the 6 orchestration commands + 8 cryptographic-primitive subcommands against a live `bitcoind regtest` + `coincync-node` testnet pair. Pauses at each wallet-signing step for the operator to paste signed-tx hex; cryptographic steps (adaptor pre-sigs, decrypt, recover, DLEQ) run automatically.

What's still ahead:

1. ⏳ **Wallet integration** — embed the swap into the Tauri wallet UI as a first-class flow, consuming the swap key-derivation helpers + `SwapLockRecipient` bundle on the CYNC side.
2. ✅ **Cross-curve DLEQ v2** — `crates/coincync-swap/src/cross_curve_dleq.rs` replaces both v1 proofs (removed: the fast proof leaked `t`, the strict proof did not bind the curves). Always compiled; no feature flag; single proof path in the CLI, tests and benchmarks. Remaining: ⏳ independent cryptographic review of the composition and of the Edwards→Ristretto adaptation.
3. ⏳ **CLSAG ring-binding** — fold the adaptor into the CLSAG c-value so the CYNC spend reveals `t` cryptographically rather than relying on the BTC-side reveal. Touches audited `coincync::crypto::clsag` code; treat as consensus-adjacent.
4. ⏳ **Coordinator transport** — `coordinator::{listen, connect, handshake}` still return `NotImplemented`. The message-level `HandshakeSession` state machine is complete; what's missing is the TCP+Noise (and later Tor) wrapper.
5. ⏳ **Audit + testnet exercise + bug bounty round** — before mainnet launch.

The primary cryptographic-construction risk is now behind us; what's left is integration, UX, and a dual-testnet shakeout. The earlier 3-6-month estimate was for the construction work — the remaining items are weeks of focused engineering plus the audit window.

---

## Pre-Coordination With Liquidity Providers

To shorten time-to-liquidity at mainnet launch:

- **Haveno** (XMR-DEX fork) — adding CYNC support is a relatively small extension once CIP-001 is implemented. Reach out 60 days before mainnet.
- **ChangeNOW / FixedFloat / SimpleSwap / Exolix** — instant-swap services that already integrate Monero. They tend to integrate quickly given a working swap protocol + RPC daemon.
- **THORChain / Maya Protocol** — discussion of privacy-coin support is ongoing in those communities. Lower priority but worth tracking.

---

## Reference Implementations (Existing Art We Build From)

- **Comit project** — XMR↔BTC reference implementation in Rust. Active since 2021. Source: `https://github.com/comit-network/xmr-btc-swap`. License: GPL-3.0; we cannot copy code directly (license incompatibility with our MIT) but the design is freely usable.
- **Farcaster project** — research-grade specification of the protocol, including formal proofs. Source: `farcaster-project.github.io`.
- **MoneroOcean / Cake Wallet** — production wallets with swap UX we can study for the user-facing flow.

---

## Open Questions

1. ~~**Schnorr-only or ECDSA-fallback?**~~ **Resolved 2026-05-17:** Schnorr-only. Implementation targets BIP-340; the Taproot-key-path claim transaction uses Schnorr witnesses exclusively. ECDSA fallback was punted — Bitcoin Core has shipped Taproot since 2021 and the audit window is shorter without ECDSA's parity-handling cases.
2. **Timeout values.** The 24-hour wall-time symmetry above is a starting point; production values should be informed by miner-extractable-value and network-stability research. Open until the testnet exercise produces real data.
3. ~~**Coordinator transport.**~~ **Resolved 2026-05-17 (late evening):** Plain TCP + Noise XX over TCP + Noise XX over Tor (SOCKS5 dial) — three composable transports, operator picks per use case. All three shipped in `crates/coincync-swap/src/coordinator.rs` with loopback integration tests for each. See [`docs/cyncswap-transport-setup.md`](../cyncswap-transport-setup.md) for the operator-facing setup guide. libp2p was rejected as overkill — adds many MB of deps + heavy abstraction for what's effectively a 2-party point-to-point handshake.
4. **Wallet UX.** Do we ship the swap as a separate `cyncswap` binary, embed it in the Tauri wallet, or both? Recommend both — separate binary for power users + scripts, embedded UI for retail.
5. ~~**Strict-binding DLEQ before audit?**~~ **Resolved 2026-10-03:** not optional. The adaptors do not enforce same-secret binding (a mismatched `t` costs Bob his BTC), and the v1 fast proof leaked `t`. v2 is the only cross-curve proof.

---

## Changelog

- **2026-05-04** — Draft created alongside `crates/coincync-swap/` skeleton.
- **2026-05-17** — Major refresh. Status table reflects ~70% of cryptographic + chain-integration construction shipped: Schnorr adaptors (BTC + CYNC), dual-response cross-curve DLEQ, AdaptorSecret byte-order discipline + constant-time comparison, full BTC tx construction (lock with optional script-tree refund, claim with full BIP-340 verification, refund with BIP-68 sequence), BTC + CYNC RPC clients with mock impls, CYNC swap key-derivation, 17-step end-to-end protocol composition test. Cryptographic Primitives section rewritten with construction details suitable for cryptographic review. Implementation Plan split into ✅ shipped / ⏳ ahead. Open Question 1 (Schnorr vs ECDSA) resolved as Schnorr-only.
- **2026-05-17 (afternoon)** — Mainnet-blocker push slice. Shipped: all 6 CLI state-machine orchestration handlers (`lock-cync`, `lock-btc`, `claim-btc`, `claim-cync`, `refund-btc`, `refund-cync`), refund-path e2e composition test with key-binding adversarial check, `SwapLockRecipient` wallet-bridge helper, dual-testnet smoke harness script (`scripts/cyncswap-dual-testnet-smoke.sh`). Added §"Pre-audit hardening: strict-binding cross-curve DLEQ (Noether 2018)" with full construction spec, wire format (`CrossCurveDlProofStrict`), Cargo-feature plan, and ~81 KB proof-size budget — implementation deferred until the audit team's preference is confirmed. **Test count: 130 swap-crate tests pass, 0 failures, 0 warnings.**
- **2026-05-17 (evening)** — **Strict-binding cross-curve DLEQ implementation complete** (modulo Cargo feature-gating). New module `crates/coincync-swap/src/strict_dleq.rs` (~1100 LOC + 58 unit tests) implements the full Noether 2018 construction stack: NUMS generators `H_btc`/`H_cync` via try-and-increment + hash-to-curve, Pedersen commitments on both curves, 252-bit strict decomposition (`STRICT_BIT_COUNT`), per-bit Chaum-Pedersen OR-proofs (`BitProofPair`), linear-combination opening checks (`Σ 2^i · C_i ?= T + R · H` on both curves), and the orchestrating `prove_cross_curve_strict` / `verify_cross_curve_strict` entrypoints wrapping the existing dual-response Schoenmakers proof as a fast-soundness floor. PRF expansion from a single seed (`OsRng`-friendly API) derives all 2017 per-bit scalars deterministically. Round-trip works on real adaptor secrets; tamper rejection verified at every layer (fast floor, OR-proof, R-sum, wrong-T, truncated-bits-vec); deterministic under fixed seed for test bisectability. The construction is now ready to be Cargo-feature-gated (`strict-dleq`) and audit-reviewed; updating Implementation Plan item #2 from "deferred" to "shipped behind feature flag" pending the gating slice.
- **2026-05-18** — **External strict-DLEQ test vectors shipped.** [crates/coincync-swap/test-vectors/strict-dleq-vectors.json](../../crates/coincync-swap/test-vectors/strict-dleq-vectors.json) — 3 vectors covering small / middle-of-range / near-bit-251-boundary secrets. Each vector: `(secret_le_hex, seed_hex) → (T_btc_hex, T_cync_hex, fast_proof_canonical_hex, strict_proof_canonical_sha256_hex, strict_proof_canonical_len_bytes=81085)`. Validated by [tests/strict_dleq_vectors.rs](../../crates/coincync-swap/tests/strict_dleq_vectors.rs) golden-file regression test (4 tests added: golden compare, round-trip-per-vector, canonical-determinism, fast-proof canonical layout). Closes the audit-prep doc's §8 "test-vector file deferred until requested" gap. New `canonical_bytes()` methods shipped on `CrossCurveDlProof` (129 bytes), `BitProofPair` (321 bytes), and `CrossCurveDlProofStrict` (80,929 bytes + SHA-256 helper) — these are the stable wire forms any independent implementation re-derives + byte-compares against.
- **2026-05-17 (late evening)** — **Cargo `strict-dleq` feature gate shipped.** Module `strict_dleq` is now `#[cfg(feature = "strict-dleq")]`-gated with `default = []` in `crates/coincync-swap/Cargo.toml`. Default builds compile out the ~1100 LOC strict-DLEQ module entirely (121 unit tests); `--features strict-dleq` enables it (179 unit tests). Integration + e2e tests (10 + 3) are feature-agnostic and pass in both modes. No new deps. Implementation Plan item #2 fully resolved; remaining strict-DLEQ work is operational (~30 LOC protocol-layer wire upgrade to switch variants at runtime, gated by audit-team selection).
- **2026-10-03** — **Cross-curve DLEQ v2; v1 proofs removed.** The v1 fast proof shared one nonce across curves and leaked `t` from a single proof (CRT + 2-D lattice). The v1 strict proof's per-curve bit proofs never tied the curves together, so `t_btc ≠ t_cync` verified. Both are deleted along with the `strict-dleq` feature, their vectors and their benchmark. Added `cross_curve_dleq.rs`: joint per-bit OR-of-AND proofs and per-curve link proofs under one Fiat-Shamir challenge, a session-context-bound statement, and a fixed 56,608-byte v2 encoding. CLI `prove-dleq` / `verify-dleq` changed: no `--nonce`, a required `--context`, and a single versioned proof blob. Earlier entries describe the removed v1 design.
- **2026-05-17 (overnight)** — **Coordinator transport COMPLETE across three composable layers.** `Coordinator::{listen, connect}` shipped real plain-TCP backends; `listen_noise` / `connect_noise` shipped Noise XX mutual-auth over TCP via the `snow` crate (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, with transparent chunking for the >65 KiB strict-DLEQ proof); `connect_via_socks5` / `connect_noise_via_socks5` shipped SOCKS5 CONNECT dial for Tor hidden-service support (hand-rolled RFC 1928 no-auth subset, ATYP=DOMAINNAME for `.onion` compat). 7 new integration tests including full-handshake loopbacks for plain TCP, Noise XX, SOCKS5-tunneled plain TCP, and SOCKS5-tunneled Noise XX (the production-grade combo). Open Question 3 resolved as "all three transports shipped, operator picks per use case." Operator guide added at [`docs/cyncswap-transport-setup.md`](../cyncswap-transport-setup.md). Remaining: ⏳ accept-then-validate DoS hardening on the listener side (documented as a known issue in the operator guide).

---

*This CIP is informational until the implementation phases above are complete and audited. The Constitution's Article XV "Spirit and Construction" applies: any change to the protocol described here must demonstrably strengthen at least one user protection without weakening any other.*
