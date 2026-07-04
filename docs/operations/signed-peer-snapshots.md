# Signed peer snapshots — bootstrap resilience

## What this document is

Fort-Knox roadmap Item 6: eliminate the "all DNS seeds gone, hardcoded
seeds unreachable" bootstrap failure mode by publishing a weekly
maintainer-signed peer list to IPFS. A new node with zero peers can
pull the signed list from any IPFS gateway, verify the signature
offline against a maintainer public key baked into the binary, and
bootstrap without any specific seed being reachable.

This PR delivers the **producer** side (`scripts/publish-peer-snapshot.sh`).
The **consumer** side (node-side code that fetches + verifies + uses
the snapshot on cold-start) is a separate follow-up PR — bigger scope
because it needs signature verification, cache management, and
fallback ordering integration with the existing `bootstrap.rs`.

## Threat model this closes

**Failure that would have been catastrophic**: an attacker (or an
accidental config break) takes down the entire `coincync.network` DNS
zone AND all hardcoded seed addresses in the binary go stale AND
Cloudflare drops the CDN edge. A fresh node has zero peer addresses
and no way to discover the mesh.

**With signed snapshots**: the fresh node's bootstrap fall-through
tries:

1. DNS seeds (`bootstrap.rs::dns_seeds` — existing)
2. Hardcoded seed list (existing)
3. **NEW**: pull signed peer snapshot from IPFS via any of the
   configured gateways, verify signature, use as peer address book

Bootstrap now depends on **at least one working IPFS gateway**
(Cloudflare, ipfs.io, dweb.link, Pinata's public gateway, or a
self-hosted node) plus the ability to verify one Ed25519 signature.
Both are independently robust.

## Why IPFS

- **Content-addressed**: the CID IS the file's hash. Any gateway that
  serves the right CID cannot lie about content — the consumer
  `sha256sum`'s and it either matches or the file is discarded.
- **Multi-gateway**: dozens of gateways serve the same CID. No single
  gateway is load-bearing.
- **Pin-cheap**: Pinata's free tier + web3.storage both accept few-KB
  blobs at zero recurring cost. Multi-gateway pinning gives us the
  redundancy we want without renting infrastructure.
- **NOT consensus-critical**: this is a bootstrap-time aid. The chain
  itself doesn't ratify these snapshots. If the snapshot is malicious
  or stale, the WORST case is the node tries to dial some old peers
  that don't answer — same class as any other stale peer entry, no
  privacy or safety impact.

## Why sign

The trust is in the **signature**, not the delivery channel. An
attacker who controls one IPFS gateway can serve any CID, but cannot
forge a valid signature under the maintainer's key. The consumer
enforces:

```
signature_valid(maintainer_pubkey, snapshot_bytes) == true
&& snapshot.unix_ts > last_seen_snapshot_ts   # replay defence
&& snapshot.network == expected_network       # scope check
```

The maintainer public key is baked into the binary. Rotation happens
via a coordinated release (same procedure as other pinned constants);
out of scope for this PR.

## What's in a snapshot

Canonical JSON structure — signed with the `coincync-sign-snapshot`
CLI over `b"coincync-peer-snapshot-v1" || snapshot_bytes` (raw
64-byte Ed25519 output — see wire-format v2 note below):

```json
{
  "schema_version": 1,
  "network": "testnet",
  "unix_ts": 1751618400,
  "chain_tip_height": 9342,
  "chain_tip_hash": "...",
  "peers": [
    { "addr": "216.128.156.239:28080", "last_seen": 1751618000 },
    { "addr": "140.82.57.168:28080",   "last_seen": 1751617980 },
    ...
  ]
}
```

Fields:
- `schema_version` — bumped on incompatible layout changes
- `network` — testnet | mainnet
- `unix_ts` — when the snapshot was CAPTURED
- `chain_tip_height` + `chain_tip_hash` — the source's chain state at
  capture time; consumer uses this as a soft freshness check
- `peers` — the routable public address list

The producer filters peers to routable-public addresses (drops
loopback, RFC1918 private, CGNAT, docs, benchmark, link-local, v6
unique-local, IPv6 link-local, IPv6 docs) using the same predicate
class the node enforces on gossip. Consumers may re-filter for their
own paranoia; producer filter is defence-in-depth.

## Producer operational flow

Weekly cron (or manual trigger for a fresh cutover):

One-time setup: generate a rotating Ed25519 signing seed and record
the corresponding public key on every consumer node.

```bash
# 1. Generate a fresh 32-byte seed as 64 hex chars
export SIGN_SEED_HEX=$(head -c 32 /dev/urandom | xxd -p -c 64)

# 2. Print the public key — paste into COINCYNC_PEER_SNAPSHOT_PUBKEY
#    on every consumer node's systemd env drop-in
cargo run --release --bin coincync-sign-snapshot -- pubkey $SIGN_SEED_HEX
```

Weekly cron (or manual trigger for a fresh cutover):

```bash
# From a maintainer workstation
export SIGN_SEED_HEX="<64 hex chars from above>"
bash scripts/publish-peer-snapshot.sh
```

The script:

1. SSHs to a designated healthy fleet host (default `relay1` — a
   loopback-RPC host; public-bind hosts redact `addr` under the
   P7-R1/R2 metadata-minimization audit fix) and calls `get_info` +
   `get_peers` via the local RPC
2. Filters the peer list to routable public addresses AND outbound
   peers only (inbound peers' `addr` is their ephemeral outbound
   socket, not a dial-able listen address)
3. Refuses to publish if the source sees fewer than 3 peers — a
   degenerate snapshot would poison future bootstrapping worse than a
   stale one
4. Signs the canonical JSON with `coincync-sign-snapshot` over
   `b"coincync-peer-snapshot-v1" || snapshot_bytes`. Output is
   64 raw bytes; no envelope, no armor.
5. Uploads snapshot + signature to a local IPFS daemon (Kubo default
   API `/ip4/127.0.0.1/tcp/5001`)
6. If `PINATA_TOKEN` is set, additionally pins on Pinata for gateway
   redundancy
7. Writes a `latest-<network>.json` pointer file recording the current
   CID — this is what gets published at the well-known URL

### Wire-format v2 note (2026-07-04)

Earlier draft of this document referenced `ssh-keygen -Y sign` for
the signature step. That approach produces a PEM-armored SSH
signature envelope; the consumer at `src/network/peer_snapshot.rs`
expects raw 64-byte Ed25519 bytes.

Switched to `coincync-sign-snapshot` (built from `src/bin/sign_snapshot.rs`)
which is a small Rust CLI that:

- Reads a 32-byte Ed25519 seed as 64 hex chars (via `SIGN_SEED_HEX`
  env var so it never appears in process argv)
- Signs with the namespace `b"coincync-peer-snapshot-v1"` prefixed
  to the snapshot bytes — same domain-separator the consumer verifies
- Writes exactly 64 raw bytes to the output file

The seed is a rotating operational key, separate from the SSH
release-signing key. Store it wherever you keep other Ed25519 seeds
(systemd credential store, password manager, sops-encrypted file).

Dry-run mode skips signing + upload:

```bash
bash scripts/publish-peer-snapshot.sh --dry-run
```

Alternative source host:

```bash
bash scripts/publish-peer-snapshot.sh --host relay1
```

## Well-known URL

The producer generates a `latest-testnet.json` pointer:

```json
{
  "schema_version": 1,
  "unix_ts": 1751618400,
  "snapshot_cid": "bafybeigd...",
  "signature_cid": "bafybeif7...",
  "source_host": "seed1",
  "chain_tip_height": 9342,
  "peer_count": 47
}
```

Publish this at `https://coincync.network/bootstrap/latest-testnet.json`
(behind Cloudflare, cache TTL 1 hour). A fresh node fetches this URL,
extracts `snapshot_cid`, then pulls the snapshot itself from IPFS.

Multi-registrar / secondary-DNS work (Fort-Knox item elsewhere) covers
the case where `coincync.network` itself is unreachable.

## Consumer flow (follow-up PR — NOT this one)

Fresh node with zero peers:

```rust
async fn bootstrap_fallback_signed_snapshot(...) -> Result<Vec<PeerAddress>> {
    // 1. Try well-known URL for the latest CID
    let latest = fetch_latest_pointer("https://coincync.network/bootstrap/latest-testnet.json").await?;

    // 2. Try each configured IPFS gateway to fetch the snapshot bytes
    for gateway in ["cloudflare-ipfs.com", "ipfs.io", "dweb.link", ...] {
        let bytes = fetch_ipfs(gateway, &latest.snapshot_cid).await?;
        let sig = fetch_ipfs(gateway, &latest.signature_cid).await?;

        // 3. Verify signature against the maintainer public key baked
        //    into the binary
        if verify_ssh_signature(MAINTAINER_PUBKEY, &bytes, &sig) {
            let snapshot: SignedPeerSnapshot = serde_json::from_slice(&bytes)?;

            // 4. Sanity + replay defence
            if snapshot.network != our_network { continue; }
            if snapshot.unix_ts > SystemTime::now() { continue; }
            if snapshot.unix_ts < last_seen_snapshot_ts { continue; }

            return Ok(snapshot.peers.into_iter().map(PeerAddress::new).collect());
        }
    }
    Err(BootstrapError::NoGatewayReachable)
}
```

Called only after DNS seeds + hardcoded seeds have all failed. Not
part of THIS PR.

## What this PR does not close

- **Consumer code**: separate PR (adds `bootstrap.rs` fallback,
  signature verification, cache).
- **Maintainer key rotation**: needs a design + release-process
  addition. For v1.0 the key is fixed.
- **Adversarial gateway**: attacker who controls every IPFS gateway
  simultaneously could refuse to serve, but cannot forge. Failure mode
  is "bootstrap falls back to hardcoded list", same as today.
- **Empty gateways scenario**: if every gateway loses the pin
  simultaneously (extremely unlikely with 3+ redundant pinning
  services), consumer would need to fall through to hardcoded list.
- **Non-Kubo IPFS clients**: script assumes a local Kubo daemon at
  `/ip4/127.0.0.1/tcp/5001`. Adapting to other IPFS clients (e.g.
  js-ipfs, iroh) is trivial but not done here.

## Testing

Dry-run against a live source host:

```bash
bash scripts/publish-peer-snapshot.sh --host seed1 --dry-run
```

Should produce `out/peer-snapshots/peer-snapshot-testnet-<ts>.json`
with 5-50 peers, non-empty. Inspect with `jq . <snap>` for shape.
