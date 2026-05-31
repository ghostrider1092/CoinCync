# CIP-015 — Warp sync via UTXO-set state snapshots

**Status:** Sketch (v2.0+ track, NOT a v1.0 or v1.1 blocker)
**Created:** 2026-05-31
**Replaces:** none
**Depends on:** v1.0 base chain mainnet stability (≥6 months in
production), CIP-007 hard-fork activation policy

---

## Abstract

Today a new CoinCync node must download and validate every block from
genesis to chain tip to reach a usable state. At current testnet
parameters (120s block time, 14k blocks) this takes 1-2 hours of pure
CPU time on a healthy box. Post-mainnet, after years of accumulated
history, this number becomes a multi-day proposition — a hard wall
between "I want to try CoinCync" and "I'm running a node."

This CIP proposes **warp sync**: a new-node startup mode that
downloads a recent state snapshot (UTXO commitment set + key-image
set), verifies it against block-header-committed Merkle roots, and
begins full validation from the snapshot height forward. New nodes
reach a usable state in **minutes regardless of chain length**.

The trust model is **trustless under honest-majority PoW**: the snapshot
is bound to a specific block's header. If you trust the header chain
(which you do, by PoW validation), you trust the snapshot. There is
no separate signing committee, no off-chain attestations, no
operator-signed manifests.

This is the replacement for today's stopgap chaindata-tarball
bootstrap (see
[docs/src/operations/bootstrap-from-snapshot.md](../src/operations/bootstrap-from-snapshot.md)),
which depends on operator-published checkpoints and post-hoc binary
verification.

---

## Motivation

### Onboarding friction is a chain's most measurable failure mode

CoinCync's positioning is privacy + transparent PoW. We compete with
Monero (privacy + PoW) on the privacy story and with everyone else on
the operator-onboarding story. Monero's bootstrap from genesis takes
~1 day on a modern box; that is the bar we need to beat, not match.

A 2026-05-31 community report (operator `barns1253`) hit a 1-2 hour
sync wait on a 14k-block testnet — and that's BEFORE meaningful chain
history accumulates. Without warp sync, the sync wait grows linearly
with chain age, and the new-operator onboarding window collapses
correspondingly.

### Checkpoint-based bootstrap is a stopgap, not a destination

The current chaindata-tarball bootstrap (see operator doc) gets the
job done for testnet but depends on:

1. Operator publishes a tarball + SHA256 + (height, hash) attestation.
2. New operator trusts the published SHA256 wasn't tampered with by
   the publisher.
3. New operator's binary re-validates the chain head against ~80
   hardcoded checkpoints. **Once the snapshot height is BELOW the
   highest hardcoded checkpoint, this defense exists. Once a snapshot
   is published ABOVE the highest hardcoded checkpoint, the defense
   degrades to "trust the maintainer."**

Hardcoded checkpoints can't grow indefinitely (the binary's checkpoint
set is fixed at compile time). Without warp sync, we're forever in a
"publish a new binary every N blocks just to extend the trust anchor"
loop. That's not a path to mainnet maturity.

### Privacy chains need warp sync MORE than transparent chains

For transparent chains like Bitcoin, the UTXO set is publicly
queryable from any full node. Snapshot validation is just "ask 5
peers what the UTXO set is at height N, compare." A privacy chain
can't do this — UTXOs are commitments, not addresses, and you can't
ask "what's the UTXO set" without exposing observation patterns. We
need a cryptographic commitment scheme baked into block headers.
This CIP designs that scheme.

---

## Specification

### State commitment

At every block header, commit two Merkle roots:

```
StateCommitment {
  utxo_commitment_root:  [u8; 32]  // Merkle root over ordered UTXO commitments
  key_image_root:        [u8; 32]  // Merkle root over ordered spent key-images
}
```

The header serialization changes from current `BlockHeader {...}` to:

```
BlockHeader {
  version:          u32,
  parent_hash:      Hash,
  merkle_root:      Hash,
  timestamp:        u64,
  difficulty:       u64,
  nonce:            u32,
  // -- new in CIP-015 activation block --
  state_commitment: StateCommitment,
}
```

This is a **consensus-level hard fork**. It must go through CIP-007
Mode A activation policy. Pre-activation blocks have the old header
shape; post-activation blocks have the new shape. Pre-activation
blocks have no `state_commitment` field, and warp-sync snapshots
cannot exist below the activation height.

### Merkle tree shape

Both trees use:

- **Hash function:** Blake3 (matches the rest of the v1.0 codebase;
  consistent with `src/crypto/hash.rs`).
- **Domain separation:** Leaf hashes prefixed with `0x00`; internal
  node hashes prefixed with `0x01`. Defends against second-preimage
  attacks where an internal node hash could be interpreted as a leaf.
- **Ordering:** UTXOs sorted by `(creation_block_height, creation_tx_index, output_index)`.
  Key-images sorted by their 32-byte canonical encoding. Deterministic
  ordering is required for cross-node snapshot byte-equality.
- **Tree shape:** Standard binary Merkle, with odd-leaf-duplication
  (the Bitcoin convention). RFC 6962 was considered + rejected as
  unnecessary complexity for this use case.

### Snapshot format

A warp-sync snapshot is a sequence of typed chunks:

```
SnapshotV1 {
  header:               SnapshotHeader,
  utxo_commitments:     Vec<UtxoCommitment>,         // ordered per above
  key_images:           Vec<KeyImage>,                // ordered per above
  utxo_merkle_proof:    MerkleProofOptional,          // optional: present for streaming verify
  ki_merkle_proof:      MerkleProofOptional,
  trailer:              SnapshotTrailer,              // sha256 over preceding content
}
```

Where:

- `SnapshotHeader` includes the snapshot's tip block hash, height,
  and Blake3 hash of `BlockHeader` at that height. These let the
  verifier confirm "this snapshot corresponds to this block."
- `MerkleProofOptional` is provided when serving a partial snapshot
  (streaming verification mode). For initial implementation, snapshots
  are monolithic and proofs are computed locally.
- `SnapshotTrailer` includes a single sha256 over the preceding
  bytes, defending against in-flight corruption distinct from the
  cryptographic Merkle verification (which defends against malice).

### Sync procedure for a new node

1. **Bootstrap peer discovery** — same as today: DNS seeds + addnode
   list + DHT.
2. **Header chain download** — request all block headers from genesis
   to tip. Headers are small (~200 bytes each); 100k headers = ~20 MB.
   Verify PoW + ASERT difficulty + parent linkage for every header.
   This is cheap (~seconds).
3. **Header chain validation** — verify the header chain extends from
   the genesis hardcoded in the binary AND that the longest chain has
   sufficient cumulative work to dominate any alternative chain by
   the CIP-009 reorg-defense threshold. Reject chains below this
   threshold as suspect.
4. **Snapshot offer/request** — ask peers `which_snapshots_do_you_have`
   (new P2P message). Peer responds with snapshot heights it can
   serve. New node picks a snapshot near tip but at least
   `FINALITY_CONFIRMATIONS` behind (default 50 — see "Reorg
   interaction" below).
5. **Snapshot download** — stream the snapshot from one or more
   peers. Verify the trailer sha256 as bytes arrive.
6. **Snapshot Merkle verification** — compute Blake3 Merkle roots
   over the received UTXO commitments + key-images. Compare against
   the `state_commitment` field IN THE BLOCK HEADER you already
   validated in step 3. **If they match, the snapshot is bound to
   the chain. No separate trust source needed.**
7. **State application** — write the UTXO set + key-image set into
   RocksDB. Mark chain state as "synced to snapshot height N".
8. **Forward sync** — request and apply blocks from snapshot height
   + 1 forward. Full validation (RandomX PoW, ring sigs, range
   proofs) applies to these blocks.
9. **Steady state** — node is now a full-validation node from
   snapshot height forward, with state inherited at snapshot height.

### What warp-synced nodes can and cannot do

A warp-synced node:

- **CAN** validate all blocks from the snapshot height forward at
  full consensus rigor.
- **CAN** serve blocks, headers, and snapshots to other warp-sync
  peers (snapshots only from heights they actually have data for —
  the snapshot they imported, plus snapshots they generate later).
- **CAN** detect and reject double-spend attempts on the post-snapshot
  chain (because their key-image set is complete from snapshot height).
- **CAN** participate in mining (their tip is current).
- **CANNOT** serve full historical block bodies for heights below the
  snapshot. They didn't download them. Archive nodes (full sync from
  genesis) still exist for this role.
- **CANNOT** retroactively detect a pre-snapshot rule violation. They
  are trusting that the snapshot's chain head reflects honest-majority
  PoW. If 51% of historical PoW was malicious, a warp-synced node
  couldn't detect it post-hoc.

The 51%-attack tradeoff is real but already implicit in PoW: even a
genesis-syncing node accepts the longest-chain rule. Warp sync makes
this tradeoff slightly more pronounced (shorter validated history)
but in the same direction.

### P2P protocol additions

Three new message types, all backward-compatible (peers that don't
understand them simply ignore — old nodes won't have warp sync but
will still serve blocks normally):

```
SnapshotInventoryReq  { from: VersionPrefix }
SnapshotInventoryResp { snapshots: Vec<SnapshotMeta> }
   // SnapshotMeta { height: u64, tip_hash: Hash, size_bytes: u64 }

SnapshotChunkReq      { snapshot_height: u64, chunk_index: u32 }
SnapshotChunkResp     { snapshot_height: u64, chunk_index: u32, data: Vec<u8>, is_last: bool }

SnapshotProofReq      { snapshot_height: u64 }  // for streaming verify mode (future)
SnapshotProofResp     { snapshot_height: u64, proofs: ... }
```

Snapshot chunks default to 4 MB to balance memory pressure during
transfer against round-trip overhead. Chunk size is negotiable.

### Snapshot generation

Snapshots are generated by full-sync nodes at fixed cadence:

- **Cadence:** every 10,000 blocks (~14 days at 120s block time).
- **Retention:** keep the 3 most recent snapshots locally, prune older.
- **Generation cost:** must complete in <60 seconds on a mainnet-spec
  box (16 GB RAM, NVMe). For a 1 GB UTXO set, this is dominated by
  serialization, not computation.
- **Concurrency:** generation runs in a background thread with no
  impact on block validation latency.

### Pre-activation behavior

Before the CIP-015 activation height:

- Block headers do NOT include `state_commitment`. Snapshots cannot
  be cryptographically bound to header content for these heights.
- The today-stopgap chaindata-tarball bootstrap (operator-published,
  binary-checkpoint-verified) remains the only fast-bootstrap option
  for pre-activation chain data.

After the activation height:

- New blocks include `state_commitment` in their header.
- Snapshots taken at heights ≥ activation height are cryptographically
  bound and can be warp-synced trustlessly.
- The chaindata-tarball bootstrap is formally deprecated and removed
  one release after warp sync ships.

---

## Reorg interaction

A snapshot at height N becomes invalid if the chain reorgs to a
chain whose ancestor at height N is different. Mitigations:

1. **Snapshots are taken at heights well below tip.** Default
   `FINALITY_CONFIRMATIONS` is 50 (≈100 minutes at 120s blocks). The
   probability of a reorg this deep is negligible under honest-
   majority PoW.
2. **Warp-synced nodes still observe forward sync.** If the chain
   reorgs to a different ancestor of the snapshot height, the warp-
   synced node's tip diverges from network consensus. Standard reorg
   detection applies; the node re-warp-syncs from a fresher snapshot
   if it falls behind significantly.
3. **CIP-009 reorg defense applies above the snapshot.** Once the
   warp-synced node has built up `MAX_REORG_DEPTH` confirmations of
   its own validation above the snapshot, it can reject deeper
   reorgs by policy.

---

## Security considerations

### Trust surface

Warp sync's trust surface is:

1. **The honest majority assumption inherent in PoW.** Same as full
   sync from genesis. Warp sync does not weaken this; it relies on it
   for header-chain validation.
2. **Blake3's collision resistance.** Standard assumption; consistent
   with the rest of the v1.0 codebase.
3. **The CIP-015 activation having occurred via CIP-007 Mode A**
   (or Mode B, depending on roadmap decision). Pre-activation
   snapshots cannot be cryptographically verified.

What warp sync does NOT trust:

- The peer serving the snapshot. They cannot lie — the Merkle root
  in the block header is the verifier.
- The maintainer or any single operator. There are no operator-
  signed manifests; the snapshot is bound to the chain by consensus
  data.
- Any centralized infrastructure. Snapshots come from peers, not
  CDNs.

### Potential failure modes

1. **State commitment computation bug.** If the activation block has
   a bug in computing `state_commitment`, every block thereafter is
   on a divergent chain from any correct implementation. Mitigation:
   activation rehearsal CIP (sibling CIP-015-A) following the
   CIP-010/CIP-011/CIP-012 pattern.
2. **Snapshot generation determinism bug.** If two correctly
   functioning nodes produce different snapshots for the same
   height, warp sync fails for honest snapshots. Mitigation: byte-
   level snapshot equality test in CI (two CI runs must produce
   identical snapshots; deterministic-ordering invariant is
   property-tested).
3. **Privacy leak via snapshot observation timing.** An adversary
   observing P2P snapshot requests could learn which UTXOs are being
   downloaded as a set. Mitigation: snapshots transfer the COMPLETE
   commitment set (not a queried subset), so observation reveals only
   "this peer is warp-syncing," which is already public information.

### Audit scope

Warp sync is a separate audit-firm engagement from the base v1.0
audit. We don't get to add it to the v1.0 contract; the protocol
surface area is large enough that auditors need dedicated review
budget. Sequence:

1. v1.0 audit completes (Q3 2026 target).
2. CIP-015 implementation lands in `main` behind `--enable-warp-sync`
   feature flag.
3. Separate audit firm reviews warp sync surface (Q1 2027 target).
4. Activation rehearsal (CIP-015-A) on testnet (Q1-Q2 2027).
5. Mainnet activation in v2.0 release.

---

## Out of scope (explicit non-goals)

- **Snapshots for the CIP-013 Orchard shielded pool.** Orchard's
  state is fundamentally different (note commitment tree + nullifier
  set instead of UTXO + key-image set). A separate CIP will design
  Orchard warp sync after CIP-013 is shipped and stable.
- **Snapshots for cyncswap (CIP-001) state.** Cyncswap has its own
  state file (HMAC'd) and recovery procedure separate from the chain
  state. Out of scope here.
- **Compressed snapshots / dictionary-based delta updates.** v1
  snapshots are uncompressed binary; compression is a v2 optimization.
- **Snapshot streaming verification (verify-while-download).** v1
  requires the whole snapshot before verification; v2 may add
  proof-of-inclusion streaming.
- **Light-client mode.** A node that only verifies headers + a small
  subset of UTXOs of interest is a separate design (SPV-analog for
  privacy chains). Out of scope.

---

## Implementation roadmap

| Phase | Scope | Effort | Target |
|---|---|---|---|
| **Phase 0**: This CIP | Public design doc, 60-day comment window per CONTRIBUTING.md | already done | 2026-05-31 → 2026-08 |
| **Phase 1**: State commitment activation rehearsal | CIP-015-A — testnet rehearsal of the header-format change. Required before mainnet activation per CIP-007 Mode A | 2-3 weeks design + 3-4 weeks testnet run | 2026-Q3 |
| **Phase 2**: Snapshot generation + local consumption | Snapshot serialization + Merkle root computation + import-locally test. No P2P. | 4-6 weeks | 2026-Q4 |
| **Phase 3**: P2P protocol additions | New message types, snapshot transfer over existing network stack | 3-4 weeks | 2027-Q1 |
| **Phase 4**: Audit | Independent audit firm review (separate engagement from v1.0 audit) | 6-10 weeks | 2027-Q1 |
| **Phase 5**: Mainnet activation | CIP-007 Mode A activation; v2.0 release | activation window | 2027-Q2 |

**Total: ~9-12 months from CIP draft to mainnet activation.**

This timeline is aggressive but achievable IF v1.0 mainnet stays on
schedule (2026-10-01) and IF cyncswap (CIP-001, v1.1) ships in Q4
2026 / Q1 2027 without consuming all engineering capacity. If either
slips, warp sync slips with them.

---

## Strategic narrative

Three positioning points warp sync gives CoinCync that no privacy
chain currently has:

1. **"Run a privacy-coin node in under 5 minutes."** Monero, Zcash,
   Beam — all require multi-hour or multi-day sync from genesis.
   Warp sync reduces this to header download + snapshot import. A
   measurable, demoable improvement.

2. **"Trustless bootstrap without centralized snapshots."** Other
   chains' "fast sync" modes either require trusting a maintainer-
   signed checkpoint (Beam) or require a separate trust source
   (Zcash's checkpoints in the binary). Warp sync makes the snapshot
   verification cryptographic and chain-bound.

3. **"Privacy doesn't require infrastructure trust."** The CoinCync
   constitutional positioning is that no operator, no exchange, no
   maintainer is in your trust loop. Warp sync extends this to the
   bootstrap path, which today still requires trusting the publisher
   of the chaindata tarball.

This is the kind of feature that doesn't matter on day 1 of mainnet
(operators sync from genesis fine when the chain is small) but
becomes existential by year 2-3 (multi-day genesis sync is the death
of grassroots node adoption). Shipping it in v2.0 puts CoinCync
ahead of the curve rather than behind it.

---

**Last updated:** 2026-05-31
**Author:** Sebastian (ghostrider1092)
**Review status:** Sketch — open for public comment per CIP process,
60-day minimum window before any promotion to Draft.
**Discord discussion:** `#cip-discussion` channel.
