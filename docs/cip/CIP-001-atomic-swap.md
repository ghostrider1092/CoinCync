<!-- markdownlint-disable MD036 -->
# CIP-001 — CYNC↔BTC Atomic Swap

**Status:** Draft
**Type:** Standards Track (non-consensus, optional client feature)
**Created:** 2026-05-04
**Layer:** Application (off-chain coordination + on-chain primitives reused without modification)

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

This CIP is currently a **design draft**. The `crates/coincync-swap/` crate exists as a skeleton with stable type signatures and CLI surface. No protocol step is implemented; every operation returns `Error::NotImplemented`. This skeleton-first approach lets downstream code (wallet UI, integration tests, documentation) be written against stable types while the cryptographic protocol is built in stages.

**Mainnet launch blocker:** working CYNC↔BTC swaps must ship before v1.0 mainnet, per `project_atomic_swap_mainnet_blocker.md`. Public testnet ships without it.

---

## Roles

The two parties in any single swap:

- **Alice** — sells CYNC, buys BTC. Locks her CYNC first.
- **Bob** — sells BTC, buys CYNC. Locks his BTC after observing Alice's CYNC lock confirmed.

The roles are asymmetric. Alice locks first because the BTC side has shorter timelocks (necessary so that Alice can refund if Bob disappears, before Bob can refund). The asymmetry is structural and cannot be removed without breaking refund safety.

---

## State Machine

```
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

### Adaptor signatures

An adaptor signature is a signature missing a known piece of data. Given the missing data ("the secret"), the adaptor decrypts into a complete signature. Conversely, given the complete signature *and* the original adaptor, anyone can recover the secret.

Both chains use this primitive:

- **Bitcoin** — Schnorr (BIP-340) or ECDSA adaptor signatures over secp256k1. We prefer Schnorr where available; ECDSA fallback is well-studied for legacy environments.
- **CoinCync** — Adaptor signatures over the CLSAG ring-signature scheme on Ed25519. The CLSAG construction is designed to admit adaptor variants; the technique is identical to Monero's implementation in the Comit project.

### Cross-curve discrete-log equality proof

Both adaptors must be bound to the *same* underlying secret, but the secret lives on two different elliptic curves (secp256k1 for Bitcoin, Ed25519 for CYNC). A cross-curve DL-equality proof lets each party verify that the adaptors are linked without revealing the secret. This proof is exchanged during the negotiation phase, before either side commits an on-chain transaction.

### Refund signatures

Each party pre-signs a refund transaction during the negotiation phase that becomes valid only after the chain-side timeout. This is what makes "Refunded" a safe terminal state — the refund signatures are unchangeable artifacts of the negotiation, not actions that require the counterparty's cooperation.

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

```
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
6. **Network-level privacy.** Coordination must run over Tor (or equivalent) to prevent network observers from correlating swap participants. Plain TCP+Noise is acceptable for testnet; Tor onion service is the production default.
7. **Refund-griefing.** A malicious counterparty who locks then disappears costs the victim only the BTC/CYNC fee for the refund transaction — no principal is at risk. The refund cost is the only griefing vector and is bounded.

---

## Implementation Plan

The implementation phases the skeleton is structured to support, in approximate order:

1. **Cryptographic primitives** — adaptor signatures (BTC + CYNC sides), cross-curve DL proof. Smallest, riskiest, needs cryptographic review.
2. **Refund-tx construction** — BTC + CYNC refund transactions with proper timelocks. Pre-signed during negotiation.
3. **Lock-tx construction** — the two on-chain transactions Alice and Bob each broadcast.
4. **Coordinator session** — peer-to-peer message exchange for negotiation. Plain TCP+Noise first, Tor second.
5. **State persistence** — the on-disk swap state file the CLI loads/saves.
6. **CLI `cyncswap`** — the user-facing binary that ties it all together.
7. **Wallet integration** — embed the swap into the Tauri wallet UI as a first-class flow.
8. **Audit + testnet exercise + bug bounty round** — before mainnet launch.

Realistic timeline: 3-6 months of focused work, plus audit. This belongs entirely after public testnet launch and before mainnet launch.

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

1. **Schnorr-only or ECDSA-fallback?** Schnorr (BIP-340) is the right primitive but legacy clients may need ECDSA. Decide based on Bitcoin Core support window at implementation time.
2. **Timeout values.** The 24-hour wall-time symmetry above is a starting point; production values should be informed by miner-extractable-value and network-stability research.
3. **Coordinator transport.** Plain TCP+Noise vs. Tor onion service vs. libp2p. Decide before implementation begins.
4. **Wallet UX.** Do we ship the swap as a separate `cyncswap` binary, embed it in the Tauri wallet, or both? Recommend both — separate binary for power users + scripts, embedded UI for retail.

---

## Changelog

- **2026-05-04** — Draft created alongside `crates/coincync-swap/` skeleton.

---

*This CIP is informational until the implementation phases above are complete and audited. The Constitution's Article XV "Spirit and Construction" applies: any change to the protocol described here must demonstrably strengthen at least one user protection without weakening any other.*
