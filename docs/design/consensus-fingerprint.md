# Consensus-rules fingerprint in the handshake

**Status:** implemented (network-additive, advisory; no consensus impact)
**Idea family:** "small hidden things" — the dam's monitoring wire that warns of
a crack before the wall moves.

## Problem

`PROTOCOL_VERSION` gates wire compatibility, and the stored genesis gates chain
identity — but neither catches two nodes that share a genesis and protocol yet
carry **different consensus rules** (e.g. disagree on a scheduled hard-fork
height like `MIN_OUTPUT_AGE_HARDFORK_HEIGHT`, or a new checkpoint). Such nodes
peer happily and then **silently diverge at the activation height**. Nothing
surfaced that divergence in advance.

## Design

A node advertises a 32-byte **consensus fingerprint** to peers that support it,
so a mismatch is visible immediately — long before the fork it predicts.

- **`consensus::fingerprint`** — `consensus_fingerprint(NetworkType) -> Hash`,
  a domain-separated digest over the runtime-resolved consensus **parameters**:
  network magic, genesis hash, and the hard-fork schedule
  (`fee_distribution_height`, `min_output_age_hardfork_height`,
  `rolling_finality_enable/enforce_height`, `consensus_checkpoints`). Split into
  a pure `fingerprint_from_parts` so its sensitivity to each field is unit-tested.

  **Parameters, not source hashes.** A chain-compatible bugfix (e.g. the C1
  fork-validation fix, which edited `validation.rs` but kept every block valid)
  must NOT change the fingerprint, or every rolling upgrade would look divergent.
  Hashing the rule parameters flips the fingerprint exactly when block validity
  at a height would change, and not otherwise.

- **Wire (capability-gated, forward-compatible).** A new Flare capability bit
  `CAP_CONSENSUS_FINGERPRINT` and a new `ConsensusFingerprint` message
  (`MessageType = 52`). A node sends the message **only** to peers that
  advertised the bit — so nodes predating this feature never receive an unknown
  message type (which they'd reject). This mirrors the existing `CAP_CHAINWORK` /
  `ChainWork` pattern exactly. A peer that never advertises the bit simply never
  participates; nothing breaks.

- **Advisory handling.** `handle_consensus_fingerprint` records the peer's
  fingerprint on `PeerInfo.consensus_fingerprint` and logs a WARN on mismatch.
  It **never disconnects** — a staged consensus upgrade (some nodes on the new
  rules, some not, all still compatible until the activation height) must not be
  partitioned by the detector meant to make it safer. Oversized/malformed
  payloads are dropped silently.

- **Observability.** The local fingerprint is exposed in `get_info`
  (`consensus_fingerprint`, hex), so operators can compare it across the fleet
  the same way they compare tips with `get_peer_info` — a mismatch across nodes
  that *should* be identical is an early upgrade-coordination alarm.

## Why it's testnet-safe / no consensus impact

No block validation, serialization, genesis, or hash-locked file changes. The
fingerprint is computed from existing parameters; the new message is additive
and capability-gated; handling is advisory. Default behavior for peers without
the capability is unchanged.

## Portability (help other chains)

"Advertise a digest of your consensus rules and flag divergence at the
handshake, advisorily" is a small, generic upgrade-safety primitive. Most chains
rely solely on a protocol-version integer, which cannot distinguish two builds
that disagree only on a future fork height. A parameter-based fingerprint,
capability-gated so it never breaks older peers, gives every chain early warning
of an un-coordinated consensus split.
