# node-internal inbound block-relay scoring → eclipse-safe eviction

> Status: **DESIGN (Phase 0)** — no code. The **node-internal** counterpart
> to the sidecar's [colony forager](colony.md): the node scores its own
> **inbound** peers by block-relay quality and uses it as a bounded,
> eclipse-safe eviction-protection axis.

## Why this exists (and why it isn't the sidecar forager)

The colony forager in `coincync-tick` scores **fleet** peers over RPC — which
are **outbound / operator-configured** and therefore already unevictable.
Two facts make it the wrong tool for eviction:

1. `eviction.rs` only evicts **inbound** peers (`filter(|p| !p.outbound)`).
2. Inbound P2P peers expose no RPC, so the sidecar **cannot score them**.

The signal that matters for eviction — "which of my *inbound* peers relay
blocks well" — has to be measured **inside the node**, which already sees
every block arrival. This also makes it **un-poisonable by a compromised
sidecar**: the node measures relay quality itself; nothing external feeds it.

There is also a plain gap: `eviction.rs` today protects by age, activity,
and reputation, but **has no block-relay axis** — Bitcoin Core's eviction
protects "8 by block-relay-only-time." This design closes that gap the
CoinCync way.

## The signal: node-internal inbound relay score (ACO, un-poisonable)

Same Ant-Colony-Optimization idea as the sidecar forager, but inside the
node and over **inbound** peers:

- When a peer delivers a block the node **had not yet seen** (a genuine
  first-relay), credit that peer's relay score. Evaporate every window so
  the score tracks *current* relay usefulness, not ancient history.
- Integer, deterministic, per-inbound-peer. Stored on `PeerInfo` (or a
  side-map keyed by `PeerId`), updated in the existing block-receive path
  (`on_block_received_from`).
- **Public signal only.** Block arrival is public; this observes *which peer
  delivered a public block first* — never a transaction, never contents
  (Prime Invariant, same as the colony). Blocks reveal no sender.

## Integration with eviction (the eclipse-safe part)

Add a **bounded block-relay protection axis** to `select_inbound_to_evict`,
exactly parallel to the existing age/activity/reputation axes:

- Protect the top `PROTECT_PER_AXIS` (4) inbound peers by relay score.
- This runs **before** the netgroup step, like the other axes.
- **The netgroup-concentration eviction step is UNCHANGED.** That step — pick
  the most-saturated netgroup, evict its youngest — *is* the eclipse defense,
  and this design does not touch it. Relay protection only removes up to 4
  provably-good relayers from the candidate pool, symmetric with the three
  existing bounded axes.

### Why protecting good relayers is eclipse-safe (unlike an RPC hint)

The earlier idea — an RPC that lets the sidecar mark peers "preferred" — was
rejected because a **poisoned** sidecar could protect an attacker's peers for
free. This design has no such hole:

- The score is **earned, not asserted.** To gain relay protection a peer must
  *actually deliver blocks first* — i.e., be a genuinely useful relay. An
  attacker who earns it is **helping the network propagate blocks**, which is
  the opposite of an attack. This is precisely why Bitcoin Core protects
  block relayers.
- It is **bounded** (≤ 4 peers), symmetric with the existing axes.
- The **netgroup defense still dominates**: a flood from one /16 stays the
  most-concentrated group and still loses its excess peers; protecting 4
  relayers cannot prevent eviction of a real flood (there are more than 4).
- Nothing external can inject scores — no RPC, no sidecar authority.

## Consensus / privacy / DoS posture

`CONSENSUS IMPACT: none` — eviction is a local peer-management policy; it
never validates, orders, or selects blocks. `FORK RISK: none`.
`PRIVACY IMPACT: none` — observes public block-relay timing, never a
transaction (P3.5/P4.1 untouched; Dandelion untouched). `DOS SURFACE:`
unchanged — the score is O(peers), integer, updated on an event the node
already handles. `CRYPTO REVIEW NEEDED: no`.

## Relationship to the colony

This is the **inbound, node-internal** sibling of the sidecar's **outbound,
RPC-based** forager. Same ACO metaphor; two vantage points:

| | sidecar forager (colony) | this (node-internal) |
|---|---|---|
| Peers | outbound / fleet (RPC-reachable) | inbound (P2P) |
| Location | `coincync-tick` sidecar | inside `coincync-node` |
| Use | ops observability / advise | eviction protection |
| Poisonable? | externally (bounded, advisory) | no — node measures it |

Together they give CoinCync ACO-style relay awareness on **both** sides of
its connections, each wired where it's safe.

## Phased plan

- **Phase 0 — this doc.**
- **Phase 1 — measure.** Track the per-inbound-peer relay score in the
  block-receive path; expose it in `get_peer_info` / logs. **Does not touch
  eviction.** Pure measurement; zero behavior change — safe to ship and
  observe on the fleet first.
- **Phase 2 — protect.** Add the bounded relay protection axis to
  `select_inbound_to_evict`, with the adversarial test below, only after
  Phase 1 data confirms the score behaves.

## Testing (mandatory before Phase 2 ships)

- **Adversarial eclipse test:** an attacker floods a /16 with inbound peers;
  even if some earn relay score, `select_inbound_to_evict` **still evicts
  from the attacker's /16** (netgroup defense intact). This is the load-
  bearing test — it proves the new axis can't be used to eclipse.
- Unit tests: relay-score deposit/evaporate; top-N protection is bounded;
  a genuinely-good relayer is protected when its netgroup isn't flooded.
- Determinism: integer score, stable ordering.

## Forking hazards

- **Hazard 1 — letting relay protection override netgroup selection.** If a
  fork moves the protection *after*/*into* the netgroup step, or lets it
  drop the concentrated group, it re-opens eclipse. *Guard:* protection is a
  pre-step bounded axis; the netgroup step is untouched; the adversarial
  test fails loudly if a flood survives.
- **Hazard 2 — scoring on transactions instead of blocks.** Crediting relay
  on *transaction* delivery would leak tx-origin timing. *Guard:* the score
  is updated only in the block-receive path; no transaction event feeds it;
  a test asserts the input is block arrivals only.
- **Hazard 3 — unbounded protection.** *Guard:* capped at `PROTECT_PER_AXIS`,
  same as every other axis.

## Non-goals

- **Not** a change to netgroup/eclipse selection — that stays exactly as is.
- **Not** an external/RPC peer-preference hook (rejected: poisonable).
- **Not** transaction-aware in any way.

## References

- [colony](colony.md) — the sidecar forager this complements; the ACO idea.
- Bitcoin Core `SelectNodeToEvict` — block-relay-time protection axis (the
  prior art this brings to CoinCync's `eviction.rs`).
- CoinCync AI Development Rules — B.3 (never weaken a defense), D.3
  (eclipse/Sybil), P3.5/P4.1 (tx-propagation privacy).
