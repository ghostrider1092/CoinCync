# CIP-014 — Payment URI scheme + `coincync-pay` merchant tooling

**Status:** Draft (v2.0+ track, NOT a v1.0 blocker)
**Created:** 2026-05-28
**Replaces:** none
**Depends on:** v1.0 base chain mainnet (CIP-XXX hard-fork activation)

---

## Motivation

CoinCync is positioned as a **privacy** chain, not a **payments** chain. Those are different products. As of v1.0:

- Block time is 120s — payments are 2-4 minutes to first confirmation, ~20 minutes to 10-conf finality.
- No wallet → wallet URI scheme — recipients have to share an address out-of-band (Discord DM, QR code app, copy-paste).
- No merchant tooling — no invoice generation, no payment-status webhooks, no point-of-sale integration.
- No second layer — no Lightning-analog for sub-second payments.

This CIP scopes the **minimum viable payments surface**: a wallet URI scheme + a merchant-facing HTTP service. Neither competes with Lightning on speed, but both close the gap between "CoinCync exists on testnet" and "you can actually pay someone with it" by making the basic payment flow as friction-free as Bitcoin's `bitcoin:` URI was in 2010.

**Explicitly NOT in scope of this CIP:**

- Payment channels / Lightning-analog (separate CIP, v3+)
- Atomic swaps for cross-chain payment (covered by CIP-001 cyncswap, v1.1)
- Custodial payment processors (anti-Constitution Article XII)

## Constraints — what payments-on-privacy looks like

The privacy primitives that make CoinCync good for privacy are the same primitives that make it slow for payments:

| Step | Cost | Why |
|---|---|---|
|Tx build (wallet side)|~1-3s|Ring sig + range proof + stealth address derivation|
|Tx serialize + submit|~100ms|Wire format is ~2-5 KB per tx vs ~250 B for a transparent BTC tx|
|Mempool relay (Dandelion++)|~30-60s for stem→fluff|Privacy IS the cost — fluff happens later by design|
|First block inclusion|~120s average|PoW block time|
|10-conf finality|~20 min|Probabilistic — depends on the recipient's risk tolerance|

A payment URI + merchant tooling doesn't change any of these. What it changes is the OPERATOR experience: zero-friction sender flow, deterministic receiver flow, machine-readable invoice state.

## Spec — Payment URI scheme

Drop-in replacement for the `bitcoin:` URI pattern. Wallets that handle the scheme can launch from a QR scan, deep link, or browser click.

```
coincync:<address>[?<key>=<value>[&<key>=<value>]*]
```

### Required

- `<address>` — A valid recipient address (`tCYNC...` testnet or `cync...` mainnet).

### Optional query parameters

| Key | Type | Meaning |
|---|---|---|
|`amount`|decimal CYNC|Pre-filled send amount (e.g., `?amount=1.5`). Wallet MUST display this prominently; user MUST confirm before signing.|
|`memo`|URL-encoded string ≤256 bytes|Encrypted memo to attach to the tx (uses the existing `encrypted_memo` field per `src/crypto/memo.rs`). Wallets MUST show the memo to the user before signing. NOT visible on-chain to anyone except the recipient.|
|`label`|URL-encoded string|Display name for this payee. Stored locally in the wallet's address book; not transmitted.|
|`expires`|unix timestamp|If set and now > expires, wallet MUST refuse to construct the tx and display "invoice expired."|
|`view_token`|hex string|Optional one-time view key the sender shares with the merchant to prove payment. See "Merchant flow" below.|

### Example URIs

```
# Simple payment, no amount
coincync:tCYNC1abc...xyz

# Pre-filled amount
coincync:tCYNC1abc...xyz?amount=0.5

# Full invoice with memo + expiry + view-token for merchant verification
coincync:tCYNC1abc...xyz?amount=10.0&memo=Invoice%20%23472&expires=1717372800&view_token=a1b2c3...
```

### Backward compatibility

The `coincync:` scheme has no prior deployment. v1.0 wallets MUST register the handler at install time (Windows: `HKCU\Software\Classes\coincync\shell\open\command`; macOS: `LSHandlerURLScheme`; Linux: `.desktop` mimetype). Unknown query parameters MUST be ignored by senders (forward compatibility for v2+ additions).

## Spec — `coincync-pay` merchant service

A standalone HTTP service the merchant runs (self-hosted, no project-controlled instance). Acts as an invoice generator + payment-confirmation webhook.

### Architecture

```
Merchant backend
      |
      |  POST /invoices  { amount, memo, expires_in_secs, callback_url }
      v
+--------------+              +--------------+
| coincync-pay |---reads----->| coincync-node|
|   (HTTP)     |  RPC poll    |  (loopback)  |
+--------------+              +--------------+
      |
      |  On payment seen:
      |  POST callback_url
      |  { invoice_id, txid, confirmations }
      v
Merchant webhook handler
```

### Why merchant-self-hosted

Constitution Article XII forbids the project from running custodial / payment-processor infra. `coincync-pay` is a CLI binary the merchant installs themselves on a box that runs a CoinCync node. The project ships the binary; the merchant runs it.

Same model as BTCPay Server for Bitcoin.

### HTTP endpoints (v1)

| Verb | Path | Purpose |
|---|---|---|
|POST|`/invoices`|Create a new invoice. Returns `{invoice_id, payment_uri, expires_at}`.|
|GET|`/invoices/{id}`|Poll an invoice. Returns `{status: pending | seen | confirmed | expired, txid?, confirmations?}`.|
|POST|`/invoices/{id}/webhook`|(Internal — fires `callback_url` registered at creation when state changes.)|
|GET|`/health`|Liveness probe.|

### Invoice state machine

```
pending  ──tx seen in mempool──>  seen  ──1+ conf──>  confirmed
   │                                                       │
   ├──expires_at passed──> expired                          │
                                                            ├──reorg-deeper-than-cap──> reverted
```

Merchants choose their confidence threshold:

- **0-conf**: accept on `seen` (mempool admission). Same risk model as on-chain transparent chains accepting 0-conf for low-value purchases.
- **1-conf**: accept on `confirmed` with `confirmations >= 1`. ~120s.
- **10-conf**: accept on `confirmations >= 10`. ~20 min, considered final.

### View-token flow (for merchant proof)

The `view_token` URI parameter is a one-time view key the sender derives + shares with the merchant. The merchant can verify "this specific output reached me" without holding a persistent view key for the recipient. Implementation: derives from the recipient's view key + invoice ID via HKDF; scoped per-invoice.

This solves the long-standing privacy-chain merchant problem of "how do I prove a payment without permanently leaking my entire transaction history."

## Implementation roadmap

| Phase | Scope | Effort |
|---|---|---|
|**Phase 1**: URI scheme handler|`coincync:` scheme registered by wallet v2 (Tauri). Wallet recognizes the URI, pre-fills the send form.|1-2 weeks|
|**Phase 2**: Invoice format + `coincync-pay` daemon|HTTP service skeleton: `/invoices` create/poll, callback firing. SQLite for invoice state.|3-4 weeks|
|**Phase 3**: View-token derivation + merchant verification|HKDF scope from recipient view key. Merchant verification CLI.|2-3 weeks|
|**Phase 4**: QR-code generation + mobile wallet|Mobile wallet (separate effort) handles `coincync:` URIs from camera scan.|2-3 months|

**Total to ship Phase 1-3:** ~6-9 weeks. **v2.0 timeline.** Not in v1.0 or v1.1.

## Out of scope (explicit non-goals)

- **No custodial payment processor.** Article XII.
- **No KYC.** Article IX.
- **No automatic fiat conversion.** Outside the protocol's scope; merchants integrate with their own exchange/banking flow.
- **No payment channels.** Separate CIP for v3+ (Lightning-analog for sub-second payments).

## Why this is realistic vs aspirational

Each phase reuses primitives that already exist in the v1.0 codebase:

| `coincync-pay` need | v1.0 primitive |
|---|---|
|URI parse + handler|Standard OS-level URL scheme registration (~50 lines per platform)|
|Tx detection|Existing `wallet/scanner.rs` view-key chain scanning|
|Confirmation count|`get_block_count` RPC + tx's block height|
|View-token derivation|HKDF over `view_keys.rs` scoped key|
|Encrypted memo carry|Existing `memo.rs` ChaCha20-Poly1305 + ECDH key derivation|

Nothing in this CIP requires new consensus primitives. The protocol stays unchanged; this is all wallet + merchant tooling on top.

## Strategic narrative

CoinCync is not the FASTEST payment chain. It's the **most private chain you can actually use to pay someone in 2-4 minutes**. That's a narrower position than "best payments" but it's a defensible one — no competing privacy chain has merchant-grade invoicing + URI scheme + view-token verification today. Monero merchant tooling is fragmented (MoneroPay, monerod-rpc-based bespoke setups); Zcash has shielded-pool issues with merchant verification. CoinCync can lead in this specific niche.

This CIP scopes the work to get there. Implementation gates on mainnet stability (≥3 months post-launch) and is explicitly v2.0+ — it does NOT compete for v1.0 audit-prep or v1.1 cyncswap resources.

---

**Last updated:** 2026-05-28
**Author:** Sebastian (ghostrider1092)
**Review status:** draft, not yet circulated for community comment
