# Runbook: signed peer-snapshot bootstrap ceremony (first-time setup)

**Scope**: the one-time ceremony to enable Fort-Knox Item 6 (signed peer snapshots) on the fleet. After this ceremony completes, a fresh coincync node with zero DNS + hardcoded seeds reachable can still bootstrap by pulling a signed peer list from IPFS.

**This runbook is for the OPERATOR only** — the maintainer holding the Ed25519 signing key. Ed25519 keys are non-recoverable if lost; every step involving the seed must be done offline or on an operator-controlled workstation, never on a shared machine and never pasted into chat.

**Before this ceremony**: PR #136 (producer + `coincync-sign-snapshot` CLI) and PR #137 (consumer) must be merged and deployed to the fleet. Verify with:

```bash
git log --oneline origin/main | grep -E '#136|#137'
# Both must appear.
```

Also verify the deployed fleet binary contains PR #137's consumer code:

```bash
IP=$(jq -r '.nodes.relay1.ip' scripts/fleet-config.json)
ssh -i ~/.ssh/coincync_fleet root@${IP} 'coincync-node --version'
# Version must be >= the version containing #137.
```

## Standing rules that apply

- **`[[feedback_credential_hygiene]]`** — never paste the Ed25519 seed into chat. Type it directly at the terminal, or read it from a file the operator generated locally.
- **The ceremony is idempotent for the pubkey rollout, one-shot for the seed generation**. If you re-run seed generation, you're rotating the key — which means every previous signed snapshot becomes invalid until the fleet is reconfigured with the new pubkey. Rotation is a separate procedure.

## Prerequisite verification

### 1. Confirm the CLI ships with the deployed binary

The `coincync-sign-snapshot` CLI is a separate `[[bin]]` in `Cargo.toml` (verified line 44-45). It builds alongside `coincync-node` in the release workflow:

```bash
# On the maintainer workstation (WSL Ubuntu):
wsl -d Ubuntu -- bash -lc "cd /mnt/c/dev/coincync && cargo build --release --bin coincync-sign-snapshot"
wsl -d Ubuntu -- bash -lc "/mnt/c/dev/coincync/target/release/coincync-sign-snapshot --help"
```

Expected: `sign` and `pubkey` subcommands are documented.

### 2. Confirm the producer script is present

```bash
ls /c/dev/coincync/scripts/publish-peer-snapshot.sh
# Must exist.
```

### 3. Confirm IPFS is available (locally OR via a hosted pin service)

**Option A (self-hosted IPFS via Kubo)** — recommended:

```bash
# Verify IPFS daemon is reachable
curl -s http://127.0.0.1:5001/api/v0/id --request POST | jq '.ID'
# Non-empty output = daemon reachable.
```

If not running: `ipfs daemon &` (Kubo installed via `apt install ipfs-kubo` or `brew install ipfs`).

**Option B (Pinata-only)** — acceptable but single-vendor risk:

```bash
[ -n "$PINATA_TOKEN" ] && echo "Pinata token present" || echo "Pinata token missing"
```

Use a Pinata JWT with `pinList,pinFileToIPFS` scopes (not the API-key/secret pair — deprecated).

**Preferred**: both. Local IPFS + Pinata pin gives dual redundancy.

## Ceremony steps

### Step 1 — generate the maintainer Ed25519 seed

Do this on the operator workstation ONLY, offline if possible. The seed is 32 bytes (64 hex chars).

```bash
# Cryptographically-safe random 32 bytes → 64 hex chars.
# Redirect to a file with 0600 perms so the seed never lands in shell history.
SEED_DIR="$HOME/.coincync-maintainer-seed"
mkdir -p "$SEED_DIR"
chmod 0700 "$SEED_DIR"
umask 0077
head -c 32 /dev/urandom | xxd -p -c 64 > "$SEED_DIR/testnet-seed.hex"
chmod 0400 "$SEED_DIR/testnet-seed.hex"

# Verify the file:
wc -c "$SEED_DIR/testnet-seed.hex"
# Expected: 65 (64 hex chars + newline)

ls -la "$SEED_DIR/testnet-seed.hex"
# Expected: -r-------- (0400) — read-only for owner, no one else
```

**IMMEDIATELY BACK UP THIS FILE OUT-OF-BAND.** Copy to:
1. An encrypted USB drive stored in a physically-secure location
2. A GPG-encrypted archive uploaded to your personal backup (not any coincync-owned infra)
3. An air-gapped hardware token if you have one

The seed is **not recoverable** if lost. Losing it means every future signed snapshot is orphaned; the fleet keeps trusting the old pubkey until a coordinated re-key.

### Step 2 — derive and record the public key

```bash
export COINCYNC_SIGN_SEED_HEX=$(cat "$HOME/.coincync-maintainer-seed/testnet-seed.hex")
PUBKEY=$(/mnt/c/dev/coincync/target/release/coincync-sign-snapshot pubkey "$COINCYNC_SIGN_SEED_HEX")
echo "COINCYNC_PEER_SNAPSHOT_PUBKEY=$PUBKEY"
```

Expected output: a 64-char hex string (32 bytes = 64 hex chars).

**Record this value in three places (all public, none secret)**:

1. `docs/operations/signed-peer-snapshots.md` — under a `## Current maintainer public key` section (add if not present)
2. A GitHub-visible `MAINTAINERS.md`-style file so the community can independently verify snapshots offline
3. The fleet systemd env drop-in (Step 3)

The pubkey is **public information**. Publishing it widely is the whole point — every consumer verifies against it.

### Step 3 — deploy the pubkey to fleet systemd drop-in

Create a systemd drop-in that sets the env var on every fleet host:

```bash
cat > /tmp/coincync-peer-snapshot-pubkey.conf <<EOF
[Service]
Environment=COINCYNC_PEER_SNAPSHOT_PUBKEY=$PUBKEY
EOF

for HOST in relay1 relay2 seed1 seed2 seed3 randomx randomx2 explorer; do
  IP=$(jq -r ".nodes.\"$HOST\".ip" /c/dev/coincync/scripts/fleet-config.json)
  echo "── $HOST ($IP) ──"
  ssh -i ~/.ssh/coincync_fleet root@${IP} \
    'mkdir -p /etc/systemd/system/coincync-node.service.d/'
  scp -i ~/.ssh/coincync_fleet /tmp/coincync-peer-snapshot-pubkey.conf \
    root@${IP}:/etc/systemd/system/coincync-node.service.d/peer-snapshot-pubkey.conf
  ssh -i ~/.ssh/coincync_fleet root@${IP} \
    'systemctl daemon-reload'
done

# Clean up the temp file — pubkey is public but hygiene matters
rm /tmp/coincync-peer-snapshot-pubkey.conf
```

**Do NOT restart the fleet nodes yet.** The env var will be picked up on the next scheduled restart (typically the next deploy window). Restarting solely to activate a pubkey is not worth the mesh-gate cost.

### Step 4 — publish the first signed snapshot

From the maintainer workstation (SIGN_SEED_HEX still exported):

```bash
cd /c/dev/coincync

# Dry-run first to confirm the source host reports enough peers
COINCYNC_SIGN_SEED_HEX="$COINCYNC_SIGN_SEED_HEX" \
  DRY_RUN=1 bash scripts/publish-peer-snapshot.sh

# If dry-run reports >= 3 outbound peers and no errors, publish for real:
COINCYNC_SIGN_SEED_HEX="$COINCYNC_SIGN_SEED_HEX" \
  bash scripts/publish-peer-snapshot.sh
```

Expected output:
- The JSON snapshot
- A 64-byte Ed25519 signature (verified against the derived pubkey inline)
- A CID (starts with `bafk` for CIDv1 or `Qm` for CIDv0)
- If `PINATA_TOKEN` set: a Pinata pin confirmation

**Record the CID.** This CID is what the well-known pointer URL will resolve to.

### Step 5 — populate the well-known pointer URL

The consumer (PR #137, `src/network/peer_snapshot.rs`) fetches from a well-known URL that resolves to the latest snapshot CID. The URL scheme is configured via `COINCYNC_PEER_SNAPSHOT_POINTER_URL` (default is likely a coincync.network sub-path).

Check the code for the exact default:

```bash
grep -n "POINTER_URL\|pointer_url" /c/dev/coincync/src/network/peer_snapshot.rs | head
```

The pointer file at that URL should serve JSON like:

```json
{
  "schema_version": 1,
  "cid": "bafk...THE_CID_FROM_STEP_4...",
  "updated_at": "2026-07-04T21:00:00Z"
}
```

Deploy the pointer file to your web infrastructure (Cloudflare Pages, S3+CDN, a coincync.network sub-domain served by nginx, etc.). This is **not** something the fleet controls — it's operator-managed static hosting.

### Step 6 — verify consumer end-to-end

On ONE fleet host that has already been restarted with the new env var (or restart it now if this is convenient):

```bash
IP=$(jq -r '.nodes.relay1.ip' /c/dev/coincync/scripts/fleet-config.json)
ssh -i ~/.ssh/coincync_fleet root@${IP} \
  "journalctl -u coincync-node --since '10 min ago' | grep -Ei 'peer[_-]snapshot|fetch_verified' | tail -20"
```

Expected: log lines indicating the consumer fetched the CID, verified the signature against the maintainer pubkey, and used the peer list.

If the verification fails, the log line will say why (wrong network, expired snapshot, signature mismatch). Fix the specific issue.

### Step 7 — set up the weekly cron

Once the manual publish works end-to-end, schedule it. On the maintainer workstation (NOT a fleet host):

```bash
# Example: publish every Sunday at 12:00 UTC
crontab -l 2>/dev/null | grep -v publish-peer-snapshot > /tmp/cron.new
cat >> /tmp/cron.new <<EOF
# Coincync signed peer snapshot — every Sunday 12:00 UTC
0 12 * * 0 COINCYNC_SIGN_SEED_HEX=\$(cat \$HOME/.coincync-maintainer-seed/testnet-seed.hex) bash /path/to/coincync/scripts/publish-peer-snapshot.sh
EOF
crontab /tmp/cron.new
rm /tmp/cron.new
```

**Do NOT run the publish cron on a fleet host.** The seed must not leave the operator workstation.

### Step 8 — publish the pubkey publicly

Commit the maintainer pubkey to the repo so anyone can independently verify a snapshot:

```bash
cd /c/dev/coincync

# Edit docs/operations/signed-peer-snapshots.md — add:
#   ## Current maintainer public key
#   
#   Testnet: <PUBKEY>
#   
#   Published: 2026-07-04
#   Rotation policy: none currently (pre-mainnet); manual key rotation
#   only via coordinated re-release.

git add docs/operations/signed-peer-snapshots.md
git commit -m "docs(peer-snapshot): publish current maintainer pubkey"
git push
```

Do NOT commit the seed. Only the pubkey.

## Rotation procedure (out of scope for first-time ceremony)

If the maintainer seed is lost, compromised, or the operator changes:

1. Generate a NEW seed (Step 1)
2. Derive the NEW pubkey (Step 2)
3. Deploy the NEW pubkey to fleet (Step 3)
4. **Restart all fleet nodes** to activate the new pubkey (mesh gate required)
5. Publish the FIRST snapshot under the new seed (Step 4-5)
6. Commit the new pubkey to the repo (Step 8), documenting the rotation

Rotation IS disruptive — plan for a maintenance window. Community members with cached snapshots signed under the old key must re-sync from the new pointer URL. Their nodes will simply reject old snapshots (signature verification fails against the new pubkey) and fall through to other bootstrap mechanisms.

## Failure modes and recovery

| Failure | Symptom | Recovery |
|---|---|---|
| Seed file corrupted / deleted | `pubkey` subcommand errors, or produces a different pubkey than fleet has | Rotate (see above). Do NOT ship binaries built with a partial-key state. |
| IPFS local daemon down at publish time | `publish-peer-snapshot.sh` errors on `curl 127.0.0.1:5001` | Restart Kubo. Publish again. Use Pinata-only fallback (`SKIP_LOCAL_IPFS=1`) if daemon is genuinely broken. |
| Pinata quota exhausted | Pinata pin fails with 429 | Continue with local IPFS + rely on public gateways for pinning. Optionally, top up Pinata (free tier is 1 GB — snapshots are ~KB each, so quota is only an issue if this ceremony is happening for the 100,000th time). |
| Consumer rejects signature | Fleet log: `peer_snapshot: signature verification failed` | Verify the fleet's env-var pubkey MATCHES the pubkey derived from the seed used at publish time. Off-by-one env drop-in is the usual cause. |
| Snapshot fetched from IPFS gateway hangs | Fleet log: `peer_snapshot fetch timeout` on all gateways | Cache is stale AND all gateways are down. Fall back to hardcoded seed list is automatic. Investigate upstream IPFS network status. |
| Pointer URL 404s | Consumer log: `pointer fetch failed` | Static-hosting misconfiguration — fix the URL. Consumer falls through to hardcoded seeds meanwhile. |

## Cross-references

- [`docs/operations/signed-peer-snapshots.md`](signed-peer-snapshots.md) — producer-side design + threat model
- [`docs/operations/signed-peer-snapshots-consumer.md`](signed-peer-snapshots-consumer.md) — consumer-side details
- [`scripts/publish-peer-snapshot.sh`](../../scripts/publish-peer-snapshot.sh) — the actual publish script
- [`src/bin/sign_snapshot.rs`](../../src/bin/sign_snapshot.rs) — CLI source
- [`src/network/peer_snapshot.rs`](../../src/network/peer_snapshot.rs) — consumer implementation
