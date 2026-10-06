# Address manager new/tried table (eclipse resistance)

**Status:** implemented (non-consensus, P2P); part of batch-2 Wave 2.

## Problem
The `AddressManager` had no Bitcoin-style new/tried distinction: its existing
`tried` set is a per-cycle *failed*-skip set, not a "proven-good" table. So a
flood of attacker-controlled untried gossip addresses ("new") could crowd
proven-reachable peers out of the dialer — an address-book eclipse.

## Design
- A `good` table = addresses we have successfully connected to at least once
  (populated in `mark_success`, kept a subset of the book, pruned on
  eviction/purge/self).
- `get_next` now dials **manual → anchors → GOOD → new**: proven peers are
  always tried before never-connected gossip, so untried flooding cannot starve
  them. Activates only when `good` is non-empty, so existing priority ordering
  (manual→anchors→book) is unchanged on a fresh node.
- `select_feeler_candidate()` returns an unproven (not-good/tried/self/manual/
  anchor) address for a feeler probe (see below).
- Tests: good-preferred-over-new, flood-cannot-starve-a-good-peer, feeler picks
  an unproven address; the existing priority-order test still passes.

## Feeler dialer (deferred)
A proper feeler is a slot-independent handshake-and-drop connection that
promotes an unproven address to `good` even when all outbound slots are full. A
TCP-only probe would wrongly promote non-nodes, and normal dialing already
validates the book whenever a slot is free, so the selection primitive ships now
and the dialer (connection-lifecycle work) is deferred to avoid rushing the live
P2P path.

## Testnet-safe
P2P peer-selection only; no consensus/genesis/hash-locked change.
