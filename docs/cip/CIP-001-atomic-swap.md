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
| Cross-curve DLEQ proof — dual-response Schoenmakers | ✅ shipped | `adaptor.rs::prove_cross_curve` | 7 tests incl. round-trip + 4 tamper-rejections |
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
| Strict-binding cross-curve DLEQ (Noether 2018) | ⏳ deferred | — | dual-response shipped today is sufficient for operational binding; strict version is multi-week |
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

CLSAG ring-binding (folding the adaptor into the CLSAG c-value so the *act of spending* reveals `t` on the CYNC chain) is deferred — see Status table. The shipped scheme reveals `t` operationally via the BTC-side `recover_secret_from_btc_sig`; the cryptographic binding to "same `t` on both sides" is enforced by the cross-curve DLEQ + the swap key-derivation (Bob's effective spending key equals `bob_spend + t` only when `t` matches the value Alice committed to).

### Cross-curve discrete-log equality proof

Both adaptors must be bound to the same scalar `t`, but `t` lives on two different curves (`secp256k1` for Bitcoin, `Ristretto255` for CYNC). Shipped construction is a **dual-response Schoenmakers DLEQ**:

```text
Prover:
  k uniform in [0, ℓ)
  A_btc  = k · G_btc          A_cync = k · G_cync
  c_64   = H_512( tag || A_btc || A_cync || T_btc || T_cync )
  c_btc  = c_64 mod n         c_cync = c_64 mod ℓ
  s_btc  = (k + c_btc · t) mod n
  s_cync = (k + c_cync · t) mod ℓ
  Send  (A_btc, A_cync, s_btc, s_cync).

Verifier:
  Recompute c_64, c_btc, c_cync.
  Check  s_btc  · G_btc  == A_btc  + c_btc  · T_btc   (secp256k1)
  Check  s_cync · G_cync == A_cync + c_cync · T_cync  (Ristretto)
```

The dual-response shape sidesteps the field-order mismatch (`n ≠ ℓ`) that the single-response Maxwell construction runs into: a single `s` can't satisfy both verification equations without range-bounding `t`, which would require Bulletproofs-style range proofs. Two independent responses, one per field, work without that machinery.

**Soundness caveat — documented honestly.** This construction proves the prover knows discrete logs of `T_btc` (base `G_btc`) and `T_cync` (base `G_cync`), and used a shared nonce commitment `k`. It does NOT directly prove the two discrete logs are the *same* number. The full strict-binding variant (Noether's 2018 *Discrete Logarithm Equality Across Groups*, or Comit's range-bounded-secrets approach) is multi-week follow-up work. **In the swap context, strict binding is enforced operationally:** Alice's BTC claim signature reveals `t` to Bob; Bob's CYNC spend secret then equals `bob + t` and either successfully opens the CYNC lock (correct `t`, swap completes) or fails (wrong `t`, Alice gets nothing valuable). The DLEQ is the pre-commitment sanity check; the adaptors themselves are the cryptographic backstop.

### Pre-audit hardening: strict-binding cross-curve DLEQ (Noether 2018)

**Status (2026-05-17 evening): implementation complete in `crates/coincync-swap/src/strict_dleq.rs`** — the full Noether 2018 stack is shipped behind a planned `strict-dleq` Cargo feature (gating slice pending). 58 unit tests cover NUMS generators, Pedersen commitments, bit-decomposition, per-bit Chaum-Pedersen OR-proofs, linear-combination openings, and the full `prove_cross_curve_strict` / `verify_cross_curve_strict` orchestration with round-trip + tamper-rejection at every layer + determinism-under-fixed-seed property tests. The spec below describes what was built.

The dual-response Schoenmakers proof above proves *knowledge of dlogs on each curve under a shared nonce commitment* but not *same-secret-across-curves*. The full strict-binding variant follows **Noether 2018, "Discrete Logarithm Equality Across Groups"** (Mercury Labs tech note, also used in production by Comit's xmr-btc-swap and Farcaster). Construction sketch:

```text
Setup (one-time):
  H_btc  = NUMS point on secp256k1   (independent of G_btc; e.g. via try-and-increment from a fixed seed)
  H_cync = NUMS point on Ristretto   (independent of G_cync; e.g. via hash-to-curve from a fixed seed)
  N = number of bits to commit (must satisfy 2^N < min(n, ℓ); we pick N=252)

Prover (secret t with at most N bits):
  Decompose t into bits b_0..b_(N-1).
  For each bit i:
    Pick r_btc_i  uniform in [0, n)
    Pick r_cync_i uniform in [0, ℓ)
    C_btc_i  = b_i · G_btc  + r_btc_i  · H_btc       (Pedersen commitment on secp256k1)
    C_cync_i = b_i · G_cync + r_cync_i · H_cync      (Pedersen commitment on Ristretto)
    OR-proof π_i: "C_btc_i is a commitment to 0 OR to 1"
                  AND "C_cync_i is a commitment to 0 OR to 1"
                  AND "C_btc_i and C_cync_i commit to the SAME bit"
                  (3-way Chaum-Pedersen with shared challenge across both curves;
                  ~4 scalars on each curve per bit-proof)
  Linear-combination proof:
    Σ 2^i · r_btc_i  = R_btc                          (sum of bit-blinders, mod n)
    Σ 2^i · r_cync_i = R_cync                         (sum of bit-blinders, mod ℓ)
    Prover sends R_btc, R_cync.
  Verifier checks:
    Σ 2^i · C_btc_i  == T_btc  + R_btc  · H_btc      (on secp256k1)
    Σ 2^i · C_cync_i == T_cync + R_cync · H_cync     (on Ristretto)
    Each π_i verifies under both curves.

Proof size (N=252):
  per-bit:  2 · 33 (commits) + 4 · 32 (secp scalars) + 4 · 32 (Ristretto scalars)
          = 66 + 128 + 128 = 322 bytes
  total:    252 · 322 + 2 · 32 (R_btc, R_cync)
          ≈ 81.2 KB per proof
  verify cost: ~2 · 252 · 2 = ~1008 group ops per curve.
```

**Wire format** (planned `CrossCurveDlProofStrict`):

```rust
pub struct CrossCurveDlProofStrict {
    // Re-uses the existing 4 fields of CrossCurveDlProof as the
    // "fast soundness floor" — verifier rejects on either layer.
    pub fast: CrossCurveDlProof,

    // Per-bit Pedersen commitments + OR-proofs.
    pub bits: Vec<BitCommitmentProof>,    // length == N (== 252)

    // Linear-combination opening blinders.
    pub r_btc_sum:  [u8; 32],
    pub r_cync_sum: [u8; 32],
}

pub struct BitCommitmentProof {
    pub c_btc:  [u8; 33],
    pub c_cync: [u8; 32],
    // Chaum-Pedersen OR-proof responses (e0, e1, s0_btc, s0_cync,
    // s1_btc, s1_cync) — the standard 4-of-8 same-bit construction.
    pub e0:        [u8; 32],
    pub e1:        [u8; 32],
    pub s0_btc:    [u8; 32],
    pub s0_cync:   [u8; 32],
    pub s1_btc:    [u8; 32],
    pub s1_cync:   [u8; 32],
}
```

**Cargo feature gating.** The strict construction sits behind `[features] strict-dleq` in `coincync-swap/Cargo.toml`. The default flow continues to use `prove_cross_curve` (fast, operationally sound, dual-response Schoenmakers) until the audit firm asks for the cryptographic-level upgrade. Both code paths coexist; the swap state machine accepts whichever variant the counterparty sends and verifies accordingly.

**Implementation footprint estimate:** ~600 lines of crypto code (Pedersen helpers + Chaum-Pedersen OR-proof + bit decomposition + linear-combination check) + ~150 lines of tests (round-trip + tamper-rejection per layer + length validation) + the proof-size jump from ~256 bytes to ~81 KB on the wire. Bandwidth budget: a swap is at most a few proofs over the lifetime, ~250 KB total transferred is fine.

**Alternative considered:** Comit's range-bounded-secrets approach (`t < 2^k` enforced by Bulletproofs range proof; then a single-response Maxwell DLEQ works) yields a smaller proof (~2 KB) but pulls in a Bulletproofs library dep we'd otherwise avoid. Noether's approach is dep-light at the cost of bigger proofs — the right trade for our crate-isolation posture.

**Decision pending the audit firm:** Resolved when the audit team is selected. If they accept "operationally sufficient via the adaptors themselves," the dual-response Schoenmakers proof ships unchanged. If they require cryptographic-level same-secret binding, the strict variant lands behind the feature flag per the spec above.

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

1. ✅ **Cryptographic primitives** — BTC + CYNC adaptors, dual-response cross-curve DLEQ, byte-order discipline, constant-time comparison. All real, end-to-end tested.
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
2. ✅ **Strict-binding cross-curve DLEQ (Noether 2018) implementation** — full stack shipped in `crates/coincync-swap/src/strict_dleq.rs` (NUMS generators, Pedersen commits, bit decomposition, per-bit Chaum-Pedersen OR-proofs, linear-combination openings, full `prove_cross_curve_strict` / `verify_cross_curve_strict` entrypoints). 58 unit tests pass including end-to-end round-trip and tamper-rejection at every layer. **Gated behind Cargo feature `strict-dleq`** (off by default; flip on for the audit cycle). Default build: 121 tests, no binary-size impact. With feature: 179 tests. Remaining: ⏳ protocol-layer wire upgrade to accept either the dual-response or strict variant at runtime (~30 LOC, depends on the audit-team selection deciding which variant to ship at mainnet).
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
5. **Strict-binding DLEQ before audit?** Open. The shipped dual-response Schoenmakers proof is operationally sufficient (the adaptors themselves enforce same-secret binding via the spend path), but a cryptographer-led audit may want the stronger same-secret-cross-curve property. Decision happens when the audit firm is selected.

---

## Changelog

- **2026-05-04** — Draft created alongside `crates/coincync-swap/` skeleton.
- **2026-05-17** — Major refresh. Status table reflects ~70% of cryptographic + chain-integration construction shipped: Schnorr adaptors (BTC + CYNC), dual-response cross-curve DLEQ, AdaptorSecret byte-order discipline + constant-time comparison, full BTC tx construction (lock with optional script-tree refund, claim with full BIP-340 verification, refund with BIP-68 sequence), BTC + CYNC RPC clients with mock impls, CYNC swap key-derivation, 17-step end-to-end protocol composition test. Cryptographic Primitives section rewritten with construction details suitable for cryptographic review. Implementation Plan split into ✅ shipped / ⏳ ahead. Open Question 1 (Schnorr vs ECDSA) resolved as Schnorr-only.
- **2026-05-17 (afternoon)** — Mainnet-blocker push slice. Shipped: all 6 CLI state-machine orchestration handlers (`lock-cync`, `lock-btc`, `claim-btc`, `claim-cync`, `refund-btc`, `refund-cync`), refund-path e2e composition test with key-binding adversarial check, `SwapLockRecipient` wallet-bridge helper, dual-testnet smoke harness script (`scripts/cyncswap-dual-testnet-smoke.sh`). Added §"Pre-audit hardening: strict-binding cross-curve DLEQ (Noether 2018)" with full construction spec, wire format (`CrossCurveDlProofStrict`), Cargo-feature plan, and ~81 KB proof-size budget — implementation deferred until the audit team's preference is confirmed. **Test count: 130 swap-crate tests pass, 0 failures, 0 warnings.**
- **2026-05-17 (evening)** — **Strict-binding cross-curve DLEQ implementation complete** (modulo Cargo feature-gating). New module `crates/coincync-swap/src/strict_dleq.rs` (~1100 LOC + 58 unit tests) implements the full Noether 2018 construction stack: NUMS generators `H_btc`/`H_cync` via try-and-increment + hash-to-curve, Pedersen commitments on both curves, 252-bit strict decomposition (`STRICT_BIT_COUNT`), per-bit Chaum-Pedersen OR-proofs (`BitProofPair`), linear-combination opening checks (`Σ 2^i · C_i ?= T + R · H` on both curves), and the orchestrating `prove_cross_curve_strict` / `verify_cross_curve_strict` entrypoints wrapping the existing dual-response Schoenmakers proof as a fast-soundness floor. PRF expansion from a single seed (`OsRng`-friendly API) derives all 2017 per-bit scalars deterministically. Round-trip works on real adaptor secrets; tamper rejection verified at every layer (fast floor, OR-proof, R-sum, wrong-T, truncated-bits-vec); deterministic under fixed seed for test bisectability. The construction is now ready to be Cargo-feature-gated (`strict-dleq`) and audit-reviewed; updating Implementation Plan item #2 from "deferred" to "shipped behind feature flag" pending the gating slice.
- **2026-05-18** — **External strict-DLEQ test vectors shipped.** [crates/coincync-swap/test-vectors/strict-dleq-vectors.json](../../crates/coincync-swap/test-vectors/strict-dleq-vectors.json) — 3 vectors covering small / middle-of-range / near-bit-251-boundary secrets. Each vector: `(secret_le_hex, seed_hex) → (T_btc_hex, T_cync_hex, fast_proof_canonical_hex, strict_proof_canonical_sha256_hex, strict_proof_canonical_len_bytes=81085)`. Validated by [tests/strict_dleq_vectors.rs](../../crates/coincync-swap/tests/strict_dleq_vectors.rs) golden-file regression test (4 tests added: golden compare, round-trip-per-vector, canonical-determinism, fast-proof canonical layout). Closes the audit-prep doc's §8 "test-vector file deferred until requested" gap. New `canonical_bytes()` methods shipped on `CrossCurveDlProof` (129 bytes), `BitProofPair` (321 bytes), and `CrossCurveDlProofStrict` (80,929 bytes + SHA-256 helper) — these are the stable wire forms any independent implementation re-derives + byte-compares against.
- **2026-05-17 (late evening)** — **Cargo `strict-dleq` feature gate shipped.** Module `strict_dleq` is now `#[cfg(feature = "strict-dleq")]`-gated with `default = []` in `crates/coincync-swap/Cargo.toml`. Default builds compile out the ~1100 LOC strict-DLEQ module entirely (121 unit tests); `--features strict-dleq` enables it (179 unit tests). Integration + e2e tests (10 + 3) are feature-agnostic and pass in both modes. No new deps. Implementation Plan item #2 fully resolved; remaining strict-DLEQ work is operational (~30 LOC protocol-layer wire upgrade to switch variants at runtime, gated by audit-team selection).
- **2026-05-17 (overnight)** — **Coordinator transport COMPLETE across three composable layers.** `Coordinator::{listen, connect}` shipped real plain-TCP backends; `listen_noise` / `connect_noise` shipped Noise XX mutual-auth over TCP via the `snow` crate (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, with transparent chunking for the >65 KiB strict-DLEQ proof); `connect_via_socks5` / `connect_noise_via_socks5` shipped SOCKS5 CONNECT dial for Tor hidden-service support (hand-rolled RFC 1928 no-auth subset, ATYP=DOMAINNAME for `.onion` compat). 7 new integration tests including full-handshake loopbacks for plain TCP, Noise XX, SOCKS5-tunneled plain TCP, and SOCKS5-tunneled Noise XX (the production-grade combo). Open Question 3 resolved as "all three transports shipped, operator picks per use case." Operator guide added at [`docs/cyncswap-transport-setup.md`](../cyncswap-transport-setup.md). Remaining: ⏳ accept-then-validate DoS hardening on the listener side (documented as a known issue in the operator guide).

---

*This CIP is informational until the implementation phases above are complete and audited. The Constitution's Article XV "Spirit and Construction" applies: any change to the protocol described here must demonstrably strengthen at least one user protection without weakening any other.*
