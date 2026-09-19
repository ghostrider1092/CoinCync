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

The protocol uses **adaptor signatures** rather than HTLCs on the privacy chain, so a CYNC-side observer cannot distinguish swap transactions from ordinary CYNC transactions. The Bitcoin lock is a P2TR output with dedicated 2-of-2 success and CSV-refund leaves whose adaptor-bound signatures reveal the missing CYNC share.

---

## Motivation

CoinCync's Constitution forbids the compliance features (transaction blacklists, address filters, Travel Rule attestation hooks) that major US/EU exchanges demand for listing — see Articles VI, IX, XIV, and Right X. CYNC will end up in roughly Monero's listing position: present on rest-of-world and privacy-friendly exchanges, delisted from major US/EU CEXes over time as regulatory pressure tightens.

Atomic swaps compensate. Once CYNC↔BTC swaps work end-to-end, every Bitcoin holder is one transaction away from holding CYNC trustlessly, and major-CEX listings stop being load-bearing for liquidity. This is the listing-independence design that Monero's community pioneered and that CoinCync inherits.

This CIP defines the protocol so an implementation can begin with a clear specification, against which auditors can verify correctness and competing implementations can interoperate.

---

## Status & Implementation

**Substantial portions are now implemented (last updated 2026-08-24).** What's real today in `crates/coincync-swap/`:

| Component | Status | Module | Tests |
| --- | --- | --- | --- |
| Schnorr adaptor sigs (BTC, secp256k1) — create/verify/decrypt/extract | ✅ shipped | `adaptor.rs` | 5 tests; BIP-340 parity-correct path via `create_pre_sig_bip340` |
| Schnorr adaptor sigs (CYNC, Ristretto255) — create/verify/decrypt/extract | ✅ shipped | `adaptor.rs` | 5 tests; no parity dance (Ristretto is prime-order) |
| Cross-curve DLEQ proof — dual-response Schoenmakers | ✅ shipped | `adaptor.rs::prove_cross_curve` | 7 tests incl. round-trip + 4 tamper-rejections |
| `AdaptorSecret` byte-order discipline (secp BE / Ristretto LE) | ✅ shipped | `adaptor.rs::AdaptorSecret` | encoding tag + transparent accessors |
| `AdaptorSecret` constant-time comparison | ✅ shipped | `subtle::ConstantTimeEq` backing `PartialEq` | side-channel-safe |
| BTC RPC client (broadcast + watch + block count) | ✅ shipped | `btc.rs::{BtcChain, BitcoinCoreRpc, MockBtcChain}` | async trait; mock for tests |
| Legacy BTC construction primitives | ✅ diagnostic only | `btc.rs::build_{lock,claim,refund}_tx` | retained for compatibility and primitive tests; not accepted by the production safety gate |
| BTC-first two-path safety contract | ✅ shipped | `safety.rs` | no key path; exact 2-of-2 success/refund templates, signatures, CSV, and share reveals verified |
| CYNC RPC client (broadcast + watch + block count) | ✅ shipped | `cync.rs::{CyncChain, CyncNodeRpc, MockCyncChain}` | targets `coincync-node` v1.0.8 RPC surface |
| CYNC swap key-derivation (recipient pubkey + spender secret) | ✅ shipped | `cync.rs::derive_swap_*` | round-trips through real CYNC stealth scheme |
| End-to-end happy-path protocol composition | ✅ shipped | `tests/swap_happy_path_e2e.rs` | walks Alice + Bob through full 17-step flow against mock chains |
| Coordinator state machine + persistence | ✅ shipped | `coordinator.rs` + `state.rs` | 10 integration tests in `tests/integration_full_flow.rs` |
| Strict-binding cross-curve DLEQ (Noether 2018) | ✅ shipped and mandatory | `strict_dleq.rs`, `safety.rs` | canonical decoder + pre-CYNC-lock verification gate |
| CLSAG ring-binding for the CYNC adaptor | ⏳ deferred | — | requires modifying audited `coincync::crypto::clsag` |
| BTC tx construction — `bitcoin` crate integration | ✅ shipped | uses real `bitcoin 0.32` types | |
| `cync::build_lock_tx` (full tx construction) | ⏳ wallet's job | — | CYNC tx construction is too wallet-entangled (decoys, blinding, CLSAG ring composition) to live in this crate; the swap-specific glue (key-derivation helpers above) is sufficient |
| Dual-testnet smoke (bitcoind regtest + coincync-node testnet) | ⏳ operational | — | needs running daemons; not a code slice |

**Test status:** 231 library tests plus the swap integration/property suites cover the primitives, BTC-first state ordering, persistence migration, both safe Bitcoin paths, and evidence tampering.

**Mainnet launch blocker:** working CYNC↔BTC swaps must ship before v1.0 mainnet, per `project_atomic_swap_mainnet_blocker.md`. Public testnet ships without it. The cryptographic primitives are now all in place — what remains is operational integration (wallet UI, dual-testnet smoke, audit) rather than fundamental construction.

---

## Roles

The two parties in any single swap:

- **Alice** — sells CYNC, buys BTC. Locks CYNC only after Bob's BTC contract is confirmed and fully verified.
- **Bob** — sells BTC, buys CYNC. Creates the first on-chain lock.

The roles are asymmetric. Bitcoin locks first because a CYNC joint-key output has no native timeout branch. Alice therefore never risks CYNC until the Bitcoin output, both spend templates, both adaptor pre-signatures, and both strict cross-curve share bindings have passed the pre-lock gate.

---

## State Machine

```text
                    Negotiated
                        │
                        │  Bob broadcasts verified BTC lock
                        ▼
                    BobLocked ─────────── timeout ──→ Refunded (Bob)
                        │
                        │  Alice verifies both paths, broadcasts CYNC lock
                        ▼
                  AliceLocked ─── BTC refund ──→ BtcRefunded ──→ Refunded (Alice)
                        │
                        │  Alice claims BTC, revealing the secret
                        ▼
                SecretRevealed
                        │
                        │  Bob extracts secret from Alice's claim, claims CYNC
                        ▼
                   Completed
```

The on-chain terminal states are `Completed` and `Refunded`; `Aborted` is available only from `Negotiated`, before Bitcoin moves on-chain. Once Bitcoin is locked, a local abort cannot hide the outstanding refund obligation.

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

The compact dual-response proof remains available as a fast rejection floor, but it is not accepted by the fund-locking safety gate on its own. The gate requires the strict Noether proof for each party so the Bitcoin adaptor point and CYNC spend share are cryptographically bound to the same scalar before either contract can authorize a CYNC lock.

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

**Wire format** (`CrossCurveDlProofStrict`):

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

**Cargo feature gating.** `strict-dleq` remains a named feature for build control but is enabled by default. Disabling it removes the production safety module and therefore cannot produce the capability required by `Swap::apply_pre_cync_lock`.

**Implementation footprint estimate:** ~600 lines of crypto code (Pedersen helpers + Chaum-Pedersen OR-proof + bit decomposition + linear-combination check) + ~150 lines of tests (round-trip + tamper-rejection per layer + length validation) + the proof-size jump from ~256 bytes to ~81 KB on the wire. Bandwidth budget: a swap is at most a few proofs over the lifetime, ~250 KB total transferred is fine.

**Alternative considered:** Comit's range-bounded-secrets approach (`t < 2^k` enforced by Bulletproofs range proof; then a single-response Maxwell DLEQ works) yields a smaller proof (~2 KB) but pulls in a Bulletproofs library dep we'd otherwise avoid. Noether's approach is dep-light at the cost of bigger proofs — the right trade for our crate-isolation posture.

**Decision:** strict same-secret binding is mandatory for the pre-CYNC-lock gate; the compact proof is retained only as the strict proof's fast floor.

---

### `AdaptorSecret` byte-order discipline

secp256k1 and Ristretto255 disagree on scalar serialization (big-endian vs little-endian). The same scalar value has different byte representations. `AdaptorSecret` carries an `Encoding` tag and exposes `secp256k1_bytes()` / `ristretto_bytes()` accessors that transparently reverse if needed. Constructors `from_secp256k1_bytes` / `from_ristretto_bytes` declare caller intent + run the appropriate canonicality check. Equality (`PartialEq` + `subtle::ConstantTimeEq`) compares by *value*, normalizing to one encoding internally — so a secret recovered from a BTC adaptor (`Secp256k1BigEndian`) compares equal to the original (`RistrettoLittleEndian`) when they represent the same number.

### Refund signatures

The BTC lock has no key-path spend. A deterministically derived NUMS internal key commits to two Tapscript leaves:

```text
success: <alice_claim> OP_CHECKSIG <bob_claim> OP_CHECKSIGADD 2 OP_NUMEQUAL
refund:  <csv> OP_CSV OP_DROP <alice_refund> OP_CHECKSIG <bob_refund> OP_CHECKSIGADD 2 OP_NUMEQUAL
```

On success Alice signs normally and Bob's signature is adapted to Alice's CYNC share. On refund Bob signs normally and Alice's signature is adapted to Bob's CYNC share. The second signature on each leaf prevents either signer from bypassing the adaptor path, while the unknown-discrete-log internal key removes the key-path escape entirely. Final claim/refund signatures are re-verified against their exact script-path sighash before the revealed share can advance protocol state.

CYNC has no alternate-key timelock output. Its lock is an ordinary output owned by the joint spend key `S_a + S_b`. A successful Bitcoin claim reveals Alice's share to Bob; a Bitcoin refund reveals Bob's share to Alice. The older single-key helpers in `btc.rs` do not enforce this invariant and are excluded from the state-machine-aware lock, claim, and refund commands.

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

### 2. Bob locks BTC

1. Bob constructs the key-path-disabled P2TR lock with the negotiated 2-of-2 success and CSV-refund leaves.
2. Bob binds both exact spend templates to their adaptor pre-signatures and strict cross-curve share proofs, then broadcasts the verified lock.
3. Alice's coordinator watches for the exact txid, output, amount, and confirmation depth (typically 6).

### 3. Alice verifies safety and locks CYNC

1. Alice independently verifies the Bitcoin lock, both exact spend destinations and fees, both strict share proofs, and both adaptor pre-signatures.
2. Only a successful verification capability may authorize the wallet to construct the ordinary CYNC transaction to joint spend key `S_a + S_b` and the shared view key.
3. Alice broadcasts to the CoinCync network; Bob watches for the expected output and confirmation depth (typically 10).

### 4. Alice claims BTC

1. Alice combines the secret she chose during negotiation with the adaptor she shared, producing a complete Bitcoin signature.
2. Alice broadcasts the BTC claim transaction.

### 5. Bob extracts secret and claims CYNC

1. Bob's coordinator watches the BTC chain. When Alice's claim is observed, Bob extracts the underlying secret from `(adaptor_sig, final_sig)` via the recovery operation.
2. Bob uses the recovered secret to sign the spend of Alice's CYNC lock output, transferring the CYNC to Bob.

The swap is now `Completed`. Both parties have what they wanted; no third party touched the funds.

### Refund paths

If at any non-terminal stage a counterparty disappears:

- After `btc_timeout_blocks` without an Alice claim, Bob broadcasts the pre-agreed Bitcoin refund. That final signature must reveal Bob's CYNC share, allowing Alice to sweep the joint CYNC output.
- If Bob disappears before locking Bitcoin, Alice has not locked CYNC and can abort without an on-chain recovery.

`cync_timeout_blocks` is a coordination deadline expressed in CYNC block-time units, not an on-chain CYNC timelock. It provides scheduling margin around the Bitcoin refund race but grants no spending authority by itself.

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
2. ✅ **BTC lock + claim + refund tx construction** — `safety.rs` builds the mandatory no-key-path two-leaf contract and verifies exact 2-of-2 claim/refund spends; older single-key helpers remain diagnostic only.
3. ✅ **BTC RPC + CYNC RPC** — async traits + Bitcoin Core JSON-RPC impl + `coincync-node` JSON-RPC impl + in-memory mocks for unit tests.
4. ✅ **CYNC joint-key derivation** — `combine_spend_public_shares` + `combine_spend_secret_shares` + round-trip through the real stealth scheme. Identity and zero-share combinations are rejected.
5. ✅ **Coordinator session + state persistence** — already shipped in `coordinator.rs` + `state.rs` with 10 integration tests.
6. ✅ **End-to-end protocol composition test** — `tests/swap_happy_path_e2e.rs` walks the 17-step Alice/Bob flow against mock chains.

Also shipped (continuing the same numbering as the list above):

- ✅ **CLI `cyncswap`** — 32 subcommands total: 24 cryptographic-primitive wrappers + 6 state-machine orchestration handlers (`lock-cync`, `lock-btc`, `claim-btc`, `claim-cync`, `refund-btc`, `refund-cync`) + 2 housekeeping (`status`, `cancel`). All 6 orchestration commands follow the same posture: load state → role-check → state-check → hex-validate → broadcast → apply-transition → save. Broadcast-first-then-save means no on-chain side effect on pre-broadcast failure.
- ✅ **Refund-path e2e test** — `tests/swap_happy_path_e2e.rs::refund_path_bob_recovers_btc_via_csv_branch` exercises the BIP-341 script-path spend through Bob's CSV refund branch, including the adversarial sub-test that confirms `build_refund_tx` is key-binding (rejects sigs under any key other than `refund_branch.bob_pubkey`).
- ✅ **CYNC swap-recipient helper** — `cync::compute_swap_lock_recipient(...) → SwapLockRecipient` bundles the joint spend key, validated shared view key, and amount. It never applies a CYNC `lock_height`.
- ✅ **Wallet transaction bridge** — the opt-in root `cyncswap` feature converts the bundle into the normal `SpendCoordinator` pipeline and reconstructs a temporary joint `KeyEpoch` after a Bitcoin adaptor reveals the missing share. Lock and sweep construction therefore reuse ordinary decoy selection, CLSAG signing, and serialization.
- ✅ **Dual-testnet smoke harness** — `scripts/cyncswap-dual-testnet-smoke.sh` operator-driven script with three scenarios (`happy` / `refund-btc` / `refund-cync`) walking the 6 orchestration commands + 8 cryptographic-primitive subcommands against a live `bitcoind regtest` + `coincync-node` testnet pair. Pauses at each wallet-signing step for the operator to paste signed-tx hex; cryptographic steps (adaptor pre-sigs, decrypt, recover, DLEQ) run automatically.

What's still ahead:

1. ✅ **Protocol safety gate + wallet orchestration** — BTC-first ordering, no-key-path two-leaf 2-of-2 contract, strict proof verification for both shares, exact claim/refund adaptor binding, final-signature share recovery, CLI evidence checks, and wallet capability gating are implemented.
2. ✅ **Strict-binding cross-curve DLEQ (Noether 2018) implementation** — full stack shipped in `crates/coincync-swap/src/strict_dleq.rs`, including canonical encode/decode and mandatory use by the fund-locking safety gate.
3. ✅ **Ordinary CLSAG joint-key spend** — no CLSAG adaptor or consensus change is required; Bitcoin adaptor signatures reveal the missing CYNC share.
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

1. ~~**Schnorr-only or ECDSA-fallback?**~~ **Resolved 2026-05-17:** Schnorr-only. Both Taproot script paths use BIP-340 witnesses exclusively. ECDSA fallback was punted — Bitcoin Core has shipped Taproot since 2021 and the audit window is shorter without ECDSA's parity-handling cases.
2. **Timeout values.** The 24-hour wall-time symmetry above is a starting point; production values should be informed by miner-extractable-value and network-stability research. Open until the testnet exercise produces real data.
3. ~~**Coordinator transport.**~~ **Resolved 2026-05-17 (late evening):** Plain TCP + Noise XX over TCP + Noise XX over Tor (SOCKS5 dial) — three composable transports, operator picks per use case. All three shipped in `crates/coincync-swap/src/coordinator.rs` with loopback integration tests for each. See [`docs/cyncswap-transport-setup.md`](../cyncswap-transport-setup.md) for the operator-facing setup guide. libp2p was rejected as overkill — adds many MB of deps + heavy abstraction for what's effectively a 2-party point-to-point handshake.
4. **Wallet UX.** Do we ship the swap as a separate `cyncswap` binary, embed it in the Tauri wallet, or both? Recommend both — separate binary for power users + scripts, embedded UI for retail.
5. ~~**Strict-binding DLEQ before audit?**~~ **Resolved 2026-08-24:** required by default for every pre-CYNC-lock safety verification.

---

## Changelog

- **2026-08-24** — Switched the fund-locking protocol to BTC-first. Added a key-path-disabled two-leaf Taproot contract whose success and CSV refund leaves are both 2-of-2; bound Bob's success signature to Alice's CYNC share and Alice's refund signature to Bob's share; made strict DLEQ default; added canonical proof decoding, exact lock/template/adaptor verification, final-signature share-recovery capabilities, CLI gates, and wallet capability requirements. Direct state transitions can no longer bypass CYNC-lock or share-reveal verification.
- **2026-05-04** — Draft created alongside `crates/coincync-swap/` skeleton.
- **2026-05-17** — Major refresh. Status table reflects ~70% of cryptographic + chain-integration construction shipped: Schnorr adaptors (BTC + CYNC), dual-response cross-curve DLEQ, AdaptorSecret byte-order discipline + constant-time comparison, full BTC tx construction (lock with optional script-tree refund, claim with full BIP-340 verification, refund with BIP-68 sequence), BTC + CYNC RPC clients with mock impls, CYNC swap key-derivation, 17-step end-to-end protocol composition test. Cryptographic Primitives section rewritten with construction details suitable for cryptographic review. Implementation Plan split into ✅ shipped / ⏳ ahead. Open Question 1 (Schnorr vs ECDSA) resolved as Schnorr-only.
- **2026-05-17 (afternoon)** — Mainnet-blocker push slice. Shipped: all 6 CLI state-machine orchestration handlers (`lock-cync`, `lock-btc`, `claim-btc`, `claim-cync`, `refund-btc`, `refund-cync`), refund-path e2e composition test with key-binding adversarial check, `SwapLockRecipient` wallet-bridge helper, dual-testnet smoke harness script (`scripts/cyncswap-dual-testnet-smoke.sh`). Added §"Pre-audit hardening: strict-binding cross-curve DLEQ (Noether 2018)" with full construction spec, wire format (`CrossCurveDlProofStrict`), Cargo-feature plan, and ~81 KB proof-size budget — implementation deferred until the audit team's preference is confirmed. **Test count: 130 swap-crate tests pass, 0 failures, 0 warnings.**
- **2026-05-17 (evening)** — **Strict-binding cross-curve DLEQ implementation complete** (modulo Cargo feature-gating). New module `crates/coincync-swap/src/strict_dleq.rs` (~1100 LOC + 58 unit tests) implements the full Noether 2018 construction stack: NUMS generators `H_btc`/`H_cync` via try-and-increment + hash-to-curve, Pedersen commitments on both curves, 252-bit strict decomposition (`STRICT_BIT_COUNT`), per-bit Chaum-Pedersen OR-proofs (`BitProofPair`), linear-combination opening checks (`Σ 2^i · C_i ?= T + R · H` on both curves), and the orchestrating `prove_cross_curve_strict` / `verify_cross_curve_strict` entrypoints wrapping the existing dual-response Schoenmakers proof as a fast-soundness floor. PRF expansion from a single seed (`OsRng`-friendly API) derives all 2017 per-bit scalars deterministically. Round-trip works on real adaptor secrets; tamper rejection verified at every layer (fast floor, OR-proof, R-sum, wrong-T, truncated-bits-vec); deterministic under fixed seed for test bisectability. The construction is now ready to be Cargo-feature-gated (`strict-dleq`) and audit-reviewed; updating Implementation Plan item #2 from "deferred" to "shipped behind feature flag" pending the gating slice.
- **2026-05-18** — **External strict-DLEQ test vectors shipped.** [crates/coincync-swap/test-vectors/strict-dleq-vectors.json](../../crates/coincync-swap/test-vectors/strict-dleq-vectors.json) — 3 vectors covering small / middle-of-range / near-bit-251-boundary secrets. Each vector: `(secret_le_hex, seed_hex) → (T_btc_hex, T_cync_hex, fast_proof_canonical_hex, strict_proof_canonical_sha256_hex, strict_proof_canonical_len_bytes=81085)`. Validated by [tests/strict_dleq_vectors.rs](../../crates/coincync-swap/tests/strict_dleq_vectors.rs) golden-file regression test (4 tests added: golden compare, round-trip-per-vector, canonical-determinism, fast-proof canonical layout). Closes the audit-prep doc's §8 "test-vector file deferred until requested" gap. New `canonical_bytes()` methods shipped on `CrossCurveDlProof` (129 bytes), `BitProofPair` (321 bytes), and `CrossCurveDlProofStrict` (80,929 bytes + SHA-256 helper) — these are the stable wire forms any independent implementation re-derives + byte-compares against.
- **2026-05-17 (late evening)** — **Cargo `strict-dleq` feature gate shipped.** Module `strict_dleq` is now `#[cfg(feature = "strict-dleq")]`-gated with `default = []` in `crates/coincync-swap/Cargo.toml`. Default builds compile out the ~1100 LOC strict-DLEQ module entirely (121 unit tests); `--features strict-dleq` enables it (179 unit tests). Integration + e2e tests (10 + 3) are feature-agnostic and pass in both modes. No new deps. Implementation Plan item #2 fully resolved; remaining strict-DLEQ work is operational (~30 LOC protocol-layer wire upgrade to switch variants at runtime, gated by audit-team selection).
- **2026-05-17 (overnight)** — **Coordinator transport COMPLETE across three composable layers.** `Coordinator::{listen, connect}` shipped real plain-TCP backends; `listen_noise` / `connect_noise` shipped Noise XX mutual-auth over TCP via the `snow` crate (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, with transparent chunking for the >65 KiB strict-DLEQ proof); `connect_via_socks5` / `connect_noise_via_socks5` shipped SOCKS5 CONNECT dial for Tor hidden-service support (hand-rolled RFC 1928 no-auth subset, ATYP=DOMAINNAME for `.onion` compat). 7 new integration tests including full-handshake loopbacks for plain TCP, Noise XX, SOCKS5-tunneled plain TCP, and SOCKS5-tunneled Noise XX (the production-grade combo). Open Question 3 resolved as "all three transports shipped, operator picks per use case." Operator guide added at [`docs/cyncswap-transport-setup.md`](../cyncswap-transport-setup.md). Remaining: ⏳ accept-then-validate DoS hardening on the listener side (documented as a known issue in the operator guide).

---

*This CIP is informational until the implementation phases above are complete and audited. The Constitution's Article XV "Spirit and Construction" applies: any change to the protocol described here must demonstrably strengthen at least one user protection without weakening any other.*
