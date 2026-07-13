# CIP-018 — Private Light-Wallet Fast-Sync

**Status:** Draft (deferred — not scheduled)
**Type:** Standards Track (wire protocol + wallet)
**Created:** 2026-07-10

## Abstract

Give the wallet a fast-sync path that is **simultaneously** low-bandwidth,
**spend-safe**, and **zero-leak private** — by extending the existing
`get_output_digests` light-sync protocol so each `BlockDigest` also carries the
block's **spent key images**. This closes the one gap that today forces a
false choice between losing spend-detection (a funds bug) or leaking the
wallet's key images to the node (a privacy regression).

## Status / why deferred

**This is not scheduled.** The CLI wallet's current **full-block scan is
correct, spend-safe, and maximally private** (it scans locally and leaks
nothing), and there is no live pain: the network is single-operator with a
small chain, so a full scan is fast enough. This CIP is the *right* design for
when there are many users syncing large chains — it is captured now so it is
shovel-ready then, not built speculatively against a need that does not yet
exist.

## Motivation

The node already ships a private light-sync protocol
(`src/wallet/lightsync.rs` + the `get_output_digests` RPC / `GetOutputDigests`
P2P message): the server returns compact per-block **output digests**
(~138 B/output, ~50–100× less bandwidth than full blocks), and the wallet
scans them locally with a **view-tag pre-filter** (rejects 255/256 outputs
before any ECDH). Its privacy property is strong: *the server learns only the
height range, never which outputs the wallet cares about.*

But a wallet scan does two things, and digests only enable one:

1. **Receive-detection** — find the wallet's incoming outputs. ✅ digests do this.
2. **Spend-detection** — mark the wallet's UTXOs spent when they appear as
   transaction **inputs**. ❌ `BlockDigest` strips all input data, so digests
   carry no key images.

Missing (2) reintroduces the "spent UTXO stays available forever → duplicate
key-image at spend time" bug — the class that stalled the testnet at
h4885→4887 (2026-05-07). So digest-only sync is unsafe for funds.

### Why the obvious workaround is rejected

The node exposes `is_nullifier_spent` (a point query). A digest wallet could
call it per-UTXO to detect spends. **Rejected:** that tells the node *"is MY
output spent?"* for each of the wallet's key images, which lets the node link
the wallet's UTXOs — destroying the very zero-leak property that makes
light-sync private. On a privacy coin (Constitution Article III) that is a
regression, not a detail.

### The trade table this CIP resolves

| Spend-detection | Bandwidth | Spend-safe | Zero-leak privacy |
|---|---|---|---|
| Full blocks (today) | high | ✅ | ✅ |
| Digests + `is_nullifier_spent`/UTXO | low | ✅ | ❌ leaks key images |
| Digests only | low | ❌ misses spends | ✅ |
| **Digests + spent-key-images (this CIP)** | **low** | **✅** | **✅** |

## Specification

### Wire change: `BlockDigest` gains spent key images

```rust
// src/wallet/lightsync.rs
pub struct BlockDigest {
    pub height: u64,
    pub hash: Hash,
    pub prev_hash: Hash,          // already present — enables reorg chain-verify
    pub timestamp: u64,
    pub output_count: u16,
    pub outputs: Vec<OutputDigest>,
    pub spent_key_images: Vec<Hash>,   // NEW: every input key image in the block
}
```

Key images are **already public** (they appear in `tx.inputs[i].key_image` in
every full block), so publishing them in the digest leaks nothing beyond what a
full block already reveals — and, crucially, the wallet matches them **locally**
against its own UTXO set, so the server still never learns which are the
wallet's. Size impact is modest (~32 B per input).

### Node side

- `BlockDigest::from_block` populates `spent_key_images` from the block's tx
  inputs.
- `get_output_digests` handler (`src/rpc/server.rs`) and the
  `GetOutputDigests` P2P handler need no logic change beyond the struct.

**Compatibility:** no consumer uses `get_output_digests` today (the CLI wallet
does not wire light-sync), so the format can be extended freely now. If a
consumer ever ships first, gate the new field behind a capability bit
(Firework `CAP_*`).

### Wallet side

The digest scan loop mirrors the full-block loop (`cmd_scan` in
`src/bin/wallet.rs`):

1. **Reorg**: chain-verify `BlockDigest.prev_hash` against the scanner journal
   (same `find_fork_point` + rewind recovery already implemented).
2. **Receives**: `LightWalletSync::scan_digests_parallel(&digests)` →
   `add_utxo` for each `DecryptedOutput`.
3. **Spends**: for each `ki` in `digest.spent_key_images`, if it is one of the
   wallet's UTXOs, `mark_spent_by_key_image(ki)` + journal it for reorg rewind
   — the exact spend-detection the full-block path does, now without inputs.

Ship it behind a `--light` flag (or auto-detect a light-sync-capable node),
with the full-block scan retained as the default/fallback until light-sync has
soaked.

## Backward compatibility

Purely additive to an unused protocol surface. No consensus impact. No change
to how funds are validated — only how the wallet *discovers* its own receives
and spends.

## Test plan

- Digest scan finds the **same** outputs + spends as the full-block scan over
  the same range (parity test).
- Reorg mid-digest-batch rewinds receives **and** restores spends correctly.
- A spent key image in `spent_key_images` that is *not* the wallet's is ignored
  (no false spend).

## References

- `src/wallet/lightsync.rs` — existing digest protocol + `LightWalletSync`
- `docs/security/LIGHTSYNC_AUDIT.md` — privacy analysis (server learns only the range)
- Full-block scan + spend-detection: `cmd_scan` in `src/bin/wallet.rs`
- Constitution Article III — mandatory privacy (why the `is_nullifier_spent` shortcut is rejected)
