# Signed peer-snapshot consumer — operator guide

Companion runbook to `signed-peer-snapshots.md` (producer side).
This document covers the **node-side** wiring: how the fresh-node
cold-start bootstrap picks up the signed snapshot, what env vars
control it, and how it integrates with the existing bootstrap paths.

Producer: `scripts/publish-peer-snapshot.sh` (delivered in PR #136).
Consumer: `src/network/peer_snapshot.rs` (this PR).

## Trust model summary

Trust is in the **maintainer's Ed25519 signature over the snapshot
bytes**, domain-separated with the namespace
`coincync-peer-snapshot-v1`. An attacker who controls one IPFS
gateway cannot forge that signature; a signature over another
coincync-signed artifact (release tag, checkpoint) cannot be
replayed here because of the domain-separator.

**The consumer is off by default.** Bootstrap uses IPFS snapshots
only when the operator explicitly sets the maintainer public key
via env var (see below). A binary shipped without operator config
falls straight through to DNS seeds → hardcoded seed list, exactly
as it did pre-this-PR.

## Bootstrap order

Cold-start peer discovery, in order:

1. **`--addnode` from CLI** — operator-supplied peers
2. **Signed local manifest** (existing —
   `COINCYNC_BOOTSTRAP_SIGNED_MANIFEST` env var points at a local
   file with an accompanying `.sig`)
3. **DNS seeds** (existing — `TESTNET_DNS_SEEDS` / `MAINNET_DNS_SEEDS`)
4. **NEW: Signed IPFS peer snapshot** (this PR) — only if the env
   vars below are set AND paths 1-3 haven't yielded any peers
5. **Hardcoded seed list** (existing — `TESTNET_NODES` /
   `MAINNET_NODES` baked into the binary)

The IPFS snapshot lives between DNS and hardcoded because a fresh
maintainer-signed snapshot reflects current fleet IPs, whereas the
hardcoded list may be months stale after fleet-IP churn.

## Env vars

| Var | Purpose | Required? |
|---|---|---|
| `COINCYNC_PEER_SNAPSHOT_PUBKEY` | Maintainer Ed25519 public key, 32 bytes as hex. Enables the snapshot fallback. | Yes (opt-in) |
| `COINCYNC_PEER_SNAPSHOT_POINTER_URL` | Well-known URL for the current snapshot pointer, e.g. `https://coincync.network/bootstrap/latest-testnet.json` | Yes |
| `COINCYNC_PEER_SNAPSHOT_LAST_TS` | Unix seconds of the last snapshot this node accepted. Replay defence — new snapshot must be newer. Fresh installs omit this. | No |
| `COINCYNC_BOOTSTRAP_MANIFEST_ONLY` | If `1`, skip DNS + snapshot + hardcoded, use ONLY the signed local manifest. | No (existing) |
| `COINCYNC_BOOTSTRAP_DISABLE_DNS` | If `1`, skip DNS seed resolution. Also disables the snapshot fallback. | No (existing) |

Example systemd drop-in (`/etc/systemd/system/coincync-node.service.d/peer-snapshot.conf`):

```ini
[Service]
Environment=COINCYNC_PEER_SNAPSHOT_PUBKEY=6a2f3b1c... [32-byte hex]
Environment=COINCYNC_PEER_SNAPSHOT_POINTER_URL=https://coincync.network/bootstrap/latest-testnet.json
```

Reload + restart:

```bash
systemctl daemon-reload
systemctl restart coincync-node
```

## Verification pipeline

For each cold-start snapshot fetch, in order:

1. HTTP GET the pointer URL. Parse as `SnapshotPointer` JSON.
2. Try each configured IPFS gateway in order
   (`cloudflare-ipfs.com` → `ipfs.io` → `dweb.link`) fetching:
   - `{gateway}/ipfs/{snapshot_cid}` → snapshot bytes (≤ 128 KB)
   - `{gateway}/ipfs/{signature_cid}` → raw 64-byte Ed25519 signature
3. Reject if signature is not exactly 64 bytes.
4. Compute `signed_payload = "coincync-peer-snapshot-v1" || snapshot_bytes`
5. Ed25519 verify `signature` against maintainer pubkey over
   `signed_payload`. Reject on mismatch.
6. Parse `signed_payload_after_ns` as `SignedPeerSnapshot` JSON.
7. Reject if `snapshot.network` != our network.
8. Reject if `snapshot.unix_ts > now + 300` (clock-skew defence).
9. Reject if `snapshot.unix_ts <= last_seen_snapshot_ts`
   (replay defence).
10. Reject if `snapshot.peers` is empty.
11. Extract `addr` strings, parse as `SocketAddr`, drop unparseable
    entries. Return the list.

Any failure at any step means the fallback returns Err; the caller
falls through to hardcoded seeds.

## Producer wire-format v2 (REQUIRED for this consumer)

The v1 producer script (`scripts/publish-peer-snapshot.sh` on PR
#136) uses `ssh-keygen -Y sign` which produces a PEM-armored
signature envelope. **This consumer expects RAW 64-byte Ed25519
signature bytes** on the IPFS-served `.sig` object.

The producer needs a small follow-up update to output raw bytes
instead of the PEM envelope. Options:

- **Option A** (simpler): sign with a small Rust CLI helper that
  wraps `ed25519_dalek::SigningKey::sign` and writes 64 raw bytes.
  Adds a build target `coincync-sign-snapshot`.
- **Option B** (compat with existing key management): extract the
  signature from ssh-keygen's PEM envelope in bash — strip the
  `-----BEGIN SSH SIGNATURE-----` armor, base64-decode, walk the
  SSH signature wire format (openssh's serialized structure), pull
  out the 64-byte Ed25519 body.

Option A is cleaner and self-contained. Option B keeps the
existing operator SSH key workflow. Both leave the consumer's wire
contract intact (`.sig` file is 64 raw bytes).

## Failure modes and behavior

| Failure | Consumer behavior |
|---|---|
| `PUBKEY` env var unset | Skip snapshot fallback silently (opt-in gate) |
| `POINTER_URL` env var unset | Skip snapshot fallback silently |
| Pointer URL 404/DNS-fail | Log warn, fall through to hardcoded |
| Pointer JSON malformed | Log warn, fall through |
| All IPFS gateways fail | Log warn with per-gateway reasons, fall through |
| Snapshot > 128 KB | Reject with `SnapshotTooLarge`, fall through |
| Signature != 64 bytes | Reject with `SignatureInvalidLength`, fall through |
| Signature invalid | Reject with `SignatureVerifyFailed`, fall through |
| Network mismatch | Reject with `NetworkMismatch`, fall through |
| Snapshot ts in future | Reject with `ClockSkew`, fall through |
| Snapshot ts stale (replay) | Reject with `StaleSnapshot`, fall through |
| Zero peers in snapshot | Reject with `NoPeersInSnapshot`, fall through |
| Every path fails | Node starts with zero bootstrap peers; must wait for `--addnode` or manual peer injection |

Every failure logs a specific reason at `warn!` level so operators
can triage; no failure silently degrades to a WORSE state than what
the pre-this-PR bootstrap would have done.

## Testing

12 unit tests in `src/network/peer_snapshot.rs`:

- signature over namespaced payload verifies with the correct key
- signature rejects the wrong key
- signature rejects a tampered payload
- **domain-separation rejects a signature made under a different namespace**
  (blocks cross-context replay: a release-tag signature can NOT be
  replayed here)
- signature rejects wrong-length input (63 or 65 bytes)
- env-var loader returns None when unset
- env-var loader rejects wrong-length hex, non-hex
- env-var loader accepts valid 32-byte hex
- snapshot rejects network mismatch
- snapshot rejects replayed stale timestamp
- snapshot rejects far-future timestamp
- snapshot accepts matching network + fresh timestamp

Full suite: 752/752 lib tests pass (was 740, +12 new). No changes
to test count in other modules.

## What this PR does not deliver

- **Producer wire-format v2 script update**: separate small follow-up
  to modify `scripts/publish-peer-snapshot.sh` to emit raw Ed25519
  signature bytes.
- **Well-known-URL hosting**: operator sets up
  `https://coincync.network/bootstrap/latest-testnet.json` (behind
  Cloudflare) as a separate infra step. Not code.
- **IPFS pinning account**: Pinata token is operator's external step
  (already covered in producer runbook).
- **Persistent `last_seen_ts`**: currently read from
  `COINCYNC_PEER_SNAPSHOT_LAST_TS` env var. A future refinement can
  persist this in `<data_dir>/peer_snapshot_state.json` so operator
  doesn't have to manage it manually. Deferred.
- **Onion-mode**: gateway URLs are clearnet HTTPS. Tor-mode nodes
  would need `.onion` IPFS gateways added to `IPFS_GATEWAYS`.
  Deferred.
- **Signature rotation**: maintainer key rotation belongs in a
  release-process addition. v1 is fixed-key.
