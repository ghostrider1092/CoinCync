# stick-insect — protocol camouflage

> Status: **BUILT (pure policy core)** — caste of the
> [biomimetic suite](biomimetic.md). Code: `src/colony/stick_insect.rs`. Privacy caste.
>
> One-line: snap every node's **wire fingerprint** — user-agent, message sizes —
> to a canonical form: it normalizes the user-agent and rounds message sizes into
> fixed buckets so nodes are harder to fingerprint on the wire.
> Uniformity is anonymity.

## The problem: a distinctive fingerprint is a handle

A stick insect survives by looking exactly like every other twig. On the wire,
a node that advertises a distinctive build string, an unusual padding, or a
unique size distribution is trivially re-identifiable across sessions and
networks. Cryptography hides message *contents*; it does nothing about the
*shape* of the traffic — the banner a node presents and the exact byte-lengths
it emits.

## The mechanism: one canonical profile

- **Canonical user-agent.** [`normalize_user_agent`] discards whatever a peer
  claims and returns one shared constant ([`CANONICAL_USER_AGENT`] = `/coincync/`,
  version-less and build-less). A *random* UA is itself a fingerprint (the
  randomness leaks); an *empty* UA is a fingerprint (few do it); one shared
  constant is the only choice that makes nodes mutually indistinguishable.
- **Size-bucket padding.** [`padded_len`] rounds a payload length **up** to the
  next rung of a fixed ladder ([`SIZE_BUCKETS`] = 256 … 65 536 bytes), so the
  observed size reveals only which bucket it fell in, not the exact byte count.
  It is idempotent, never shrinks the payload (including an overflow-safe guard
  for pathological near-`usize::MAX` lengths), and pads even a 0-length frame so
  "empty" is not itself a signal.

## Boundary

This is the canonical *policy* — "what does the camouflaged fingerprint look
like." It sends nothing. The live wire-size normalization already runs in
`network::traffic_shaping`; stick-insect's `padded_len` expresses the same idea
as a pure, testable ladder so the policy has one audited definition.

## Status

- **Pure core:** built, `src/colony/stick_insect.rs`, 7 unit tests (UA
  canonicalisation, cross-node identical fingerprint, snap-up, idempotence,
  empty-padded, oversize multiple-of-top, overflow safety).
- **Wiring:** displayed by `coincync-tick --castes-observe` (logs the canonical
  UA + a sample padded size). Wiring it as the source of truth for the handshake
  banner is a later phase.
