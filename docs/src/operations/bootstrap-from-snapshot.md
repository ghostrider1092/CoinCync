# Bootstrap a new node from a chaindata snapshot

**TL;DR:** start the node with `--fast-sync` on a fresh data dir. It
fetches a **signed** chaindata snapshot, verifies it, and imports it
before initial sync — so you resume near the chain tip in seconds
instead of RandomX-verifying every block from genesis.

This is a **stopgap** until trustless warp sync ships per
[CIP-015](../../cip/CIP-015-warp-sync-utxo-snapshot.md) in v2.0. If you
want zero trust, sync from genesis instead — see
[run-a-node.md](../getting-started/run-a-node.md).

## When to use this

**Use fast-sync if:**

- You're a new community member who wants to start mining or running a
  node without waiting for initial sync.
- You're recovering a node after data loss and don't want to re-sync
  from genesis.
- You're spinning up a test node and don't need historical verification.

**Do NOT use fast-sync if:**

- You want trustless validation of the chain from genesis to tip. Sync
  normally instead.
- You're operating an exchange or any infrastructure that holds user
  funds. Always sync from genesis.

## What trust you're placing

The snapshot is a packed copy of an already-synced chain database. Your
binary defends the import three ways:

1. **Signature (fail-closed).** The snapshot manifest must be signed by a
   trusted signer baked into this binary, or fast-sync refuses it and
   falls back to full sync from genesis.
2. **Hardcoded checkpoints.** The imported chain head is re-checked
   against the binary's hardcoded `(height, hash)` checkpoints (see
   `src/testnet.rs`) plus a snapshot re-anchor point. A tampered or
   wrong-fork snapshot fails here and the node refuses to extend it.
3. **Integrity hash.** A blake3 hash over the database catches corruption
   or tampering in transit.

This is **trust-minimized**, not **trustless** — the snapshot's contents
still come from whoever produced it, bounded by the checks above. If you
don't trust that, sync from genesis. CIP-015 warp sync (v2.0) removes
this trust by verifying snapshots against block-header-committed state
roots instead of post-hoc checkpoint matching.

## Fast path — `--fast-sync` (recommended)

On a **fresh data dir**, add `--fast-sync`:

```bash
coincync-node --network testnet --fast-sync \
  --addnode 2.29.34.197:28080
```

That's the whole procedure. The node:

1. Reads the signed snapshot pointer. Default for testnet:
   `https://github.com/ghostrider1092/CoinCync/releases/download/bootstrap-snapshots/snapshot-latest-testnet.json`
   (override with the `COINCYNC_FAST_SYNC_POINTER_URL` env var).
2. Downloads the snapshot tarball the pointer names.
3. Verifies the signature (fail-closed), the hardcoded checkpoints, and
   the blake3 integrity hash.
4. Imports it, then syncs the remaining blocks from the seed.

Any fetch, download, or verification error **falls back to a full sync
from genesis** — fast-sync never leaves you on an unverified chain. It
only runs on a fresh data dir; a node that already has chain data syncs
normally and ignores the flag.

## Manual path — `snapshot-import`

If you already have a snapshot directory (from `snapshot-export`, or one
an operator handed you), import it directly. **Stop the node first.**

```bash
sudo systemctl stop coincync-node        # or: pkill -x coincync-node

coincync-node snapshot-import --input /path/to/snapshot
```

The snapshot directory contains `db/` and `manifest.json`.
`snapshot-import` verifies the snapshot's network + genesis hash (it
refuses a wrong-chain snapshot) and the blake3 integrity hash, backs up
any existing chaindata to a reversible `.pre-snapshot-<timestamp>`
sibling, then installs the snapshot. Restart the node afterward.

## Producing a snapshot (operators)

Fleet operators generate the published snapshot with the node itself —
there is no separate script:

```bash
# Node stopped. Exports a consistent copy of the chain DB.
coincync-node snapshot-export --out /path/to/out

# Optionally sign the manifest — REQUIRED for others' --fast-sync to accept it:
COINCYNC_SNAPSHOT_SIGN_SEED_HEX=<64-char-hex> \
  coincync-node snapshot-export --out /path/to/out
```

Sign **offline** — the signing seed must never live on an
internet-facing node. Publish the exported directory (packed as
`snapshot.tar`) and update the `snapshot-latest-testnet.json` pointer on
the release so `--fast-sync` clients pick it up.

## FAQ

**Q: How often are new snapshots published?**
A: Ad-hoc during the testnet phase. The `--fast-sync` pointer always
resolves to the latest published snapshot, so you don't track versions
by hand.

**Q: What's in the snapshot besides the chain?**
A: Just the chain database. It does NOT include wallet files, peer ban
lists, RPC tokens, or operator config — those stay yours.

**Q: Can I use a snapshot from a different binary version?**
A: Same-major-version-or-newer only; RocksDB column-family definitions
can change across releases. The manifest records the version it was made
with. If in doubt, sync from genesis.

**Q: When will this be replaced by warp sync?**
A: v2.0. See [CIP-015](../../cip/CIP-015-warp-sync-utxo-snapshot.md).

## Related

- [run-a-node.md](../getting-started/run-a-node.md) — normal
  (sync-from-genesis) install flow.
- [CIP-015](../../cip/CIP-015-warp-sync-utxo-snapshot.md) — trustless
  warp sync design (the future replacement for this procedure).
