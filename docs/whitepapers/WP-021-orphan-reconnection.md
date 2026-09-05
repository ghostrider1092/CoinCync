# WP-021 · Orphan Reconnection and Sync Generations
### Making out-of-order block delivery a non-event

**Status:** Shipped · **Layer:** Network · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Blocks do not arrive in order. A node hears a new tip from one peer before it has
the parent from another; a reorg delivers a branch backwards; gossip races
initial sync. Every chain must therefore hold blocks whose parent is unknown —
*orphans* — and reconnect them once the gap fills.

The naive approach (drop the orphan, ask again later) has a specific and severe
failure mode: **peers do not spontaneously re-send block bodies.** A node that
discards an orphan and requests it again may simply never be offered it, because
from the peer's perspective it already delivered that block. The chain then
stalls, not because of an attack, but because the node threw away the only copy
it was going to get.

This paper documents the orphan pool, and a failure we shipped: a pool that
stored orphans correctly and never replayed them.

---

## 2. Threat addressed

| Failure | Assumption it needs | What we removed |
|---|---|---|
| **Orphan-fetch loop** — node re-requests a block peers won't re-send, spinning without progress | Peers will re-deliver bodies on demand | Store the orphan *body*, not just its hash, so replay needs no network round-trip |
| **Sync stall on out-of-order/reorg delivery** | Storing a block for later is the same as replaying it | An explicit accept-hook that drains and re-injects orphans when their parent connects |
| **Orphan-pool flooding** | Any peer may queue unbounded orphans | Per-peer orphan caps, a global pool bound with oldest-first eviction, and a TTL |
| **Stale sync replies** — a slow peer answers a question the node has moved past | A response matches the request that is currently outstanding | Generation nonces: replies carrying a stale nonce are rejected |
| **Punishing honest orphan senders** | The peer supplying the parent is the peer that sent the orphan | Orphan accounting credits the *origin* peer recorded on the pooled block |

---

## 3. Design

### 3.1 Bodies in the pool, not hashes

When a block arrives whose parent is unknown, the node stores the **full block
body** keyed by hash, indexed by parent hash, together with the origin peer and a
receive timestamp. It simultaneously requests the *parent* — never the orphan
itself, which would restart the loop described above.

Storing bodies is the load-bearing choice. It means reconnection is a local
operation: when the gap fills, the node already has everything it needs.

### 3.2 The accept hook

When a block connects to the chain, the node asks the orphan pool for the direct
children waiting on that block's hash, removes them from the pool, and re-injects
each through the **normal block-receipt path** — full validation, connection, and
relay. Each re-injected child that connects fires the same hook for *its*
children, so a buried branch unwinds forward in cascade.

Re-injection rather than a bespoke apply path is deliberate: orphans get exactly
the same validation as any other block, with no second code path to drift out of
sync (the failure pattern of WP-100 §4.4).

### 3.3 Bounded, attributed, expiring

- **Per-peer cap** on outstanding orphans, so one peer cannot monopolise the pool.
- **Global cap** with oldest-first eviction.
- **TTL** sweep for orphans whose parent never arrives.
- **Origin attribution**: the peer that *sent* the orphan is recorded on the entry
  and credited when it resolves. Crediting the peer that later supplied the parent
  — the intuitive but wrong choice — left honest orphan senders permanently pinned
  at their cap even after every orphan they sent had reconciled.

### 3.4 Generation nonces

Header and block requests carry a generation nonce. When the node's view advances,
the generation changes and replies to superseded requests are rejected rather than
applied. This prevents a slow or malicious peer from answering a stale question
and dragging the sync cursor backwards.

### 3.5 Peer selection for gap-filling

Block-span requests target peers strictly ahead of the local height, so a peer
stuck at the same height cannot be handed a gap it cannot fill — the fix for a
real wedge in which a same-height peer answered with empty responses and sync
halted (WP-100 §6.5).

---

## 4. Security analysis

**The failure this paper exists for.** The pool above was implemented, documented
in detail — including its own prior bug-fix history — and **the drain had no
production caller.** Orphans were stored and never replayed. The block was also
excluded from re-download precisely *because* it was pooled, so out-of-order and
reorg delivery stalled until the 30-minute TTL released it. The chain self-healed,
which is exactly why it survived review: intermittent multi-minute stalls under
reorg pressure look like network flakiness.

Two transferable lessons:

1. **A doc-comment describing a mechanism is not evidence the mechanism runs.**
   The comment asserted the drain executed on parent-connect. It did not. Wiring
   deserves a test that fails when the wire is cut.
2. **Self-healing masks defects.** A bug whose symptom is "slow sometimes" is
   harder to find than one that crashes, and is not less serious.

**Validation.** Sync suite 31/31, including
`catch_up_stall_side_block_delivers_orphan_descendant` (a side block must be
delivered *with* its pooled descendants so the heavier branch can assemble) and a
deep-reorg orphan-cap regression. Live: a fresh node synced to a mining peer's tip
in lockstep, and a node holding a 203-block competing fork reconnected and
converged on the heavier chain with no stall.

**What this does not protect against.**

- **A peer that never supplies the parent.** The pool bounds the wait (TTL) but
  cannot conjure a missing block; recovery then depends on finding another peer.
- **Deliberate orphan flooding** is bounded by the caps, not eliminated —
  an attacker can still consume their share of the pool.
- **Eclipse.** If every peer is the attacker, orphan handling is irrelevant; that
  is WP-022's subject.

---

## 5. Implementation

| Component | Location |
|---|---|
| Orphan pool, caps, TTL, origin attribution | `src/network/sync.rs` |
| `take_orphans_of(parent)` — the drain | `src/network/sync.rs` |
| `notify_block_accepted` — the accept hook / re-injection | `src/network/node.rs` |
| Hook wiring on block accept | `src/bin/node.rs` |
| Orphan request path (fetch parent, pool body) | `src/network/node.rs`, `src/bin/node.rs` |
| Generation nonces, peer-height selection | `src/network/sync.rs`, `src/network/node/sync_driver.rs` |

**Failure record.** WP-100 §6.1 (drain unwired) and §6.5 (orphan-fetch loop,
multi-peer IBD wedge, reorg self-deadlock, framer cancel-safety).

---

## 6. Known limits

- Direct children are drained per accept, with deeper descendants unwinding via
  the cascade. This is correct but relies on each child connecting; a child that
  fails validation stops its own subtree (as it should).
- Pool caps are policy numbers, not derived limits.
- The re-injection path re-relays connected orphans to peers, which is harmless
  but not free.
- Equal-height heavier forks are not block-fetched by span requests (peer
  selection is height-based); single side blocks still arrive by gossip. Noted as
  an open observation rather than a fixed defect.

---

## 7. References

- Bitcoin Core orphan-handling and `getdata` semantics — the prior art for why
  bodies must be retained.
- Internal: [WP-005 Reorg defense](WP-005-layered-reorg-defense.md),
  [WP-022 Peer eviction](WP-022-relative-peer-eviction.md),
  [WP-100 §6](WP-100-solved-issues-ledger.md).
