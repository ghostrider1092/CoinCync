# Runbook: signed faucet registry (Fort-Knox item 2)

**Scope**: publish the current faucet directory to IPFS as a signed JSON blob so wallets can discover live faucets even when the compiled-in canonical entry (`faucet.coincync.network`) is down or the operator has added community-run instances the wallet doesn't know about at compile time.

**Related PRs** (both must be merged before this runbook applies):
- `feat/fk-2-3-signed-registry-infrastructure` — generic signed-registry infra (`src/network/signed_registry.rs`)
- `feat/fk-2-faucet-registry-wiring` — this runbook + `faucet_registry.rs` consumer + producer script

## Threat model this closes

**Failure this addresses**: `faucet.coincync.network` becomes unreachable (Cloudflare edge outage, DNS zone hijack, deliberate takedown). Users can't claim testnet CYNC. Community members can't test wallet flows.

**With the signed faucet registry**: wallet queries the registry at startup, picks an available faucet from the returned list (fleet-run OR community-run), and lets the user click through. If one entry is down, others likely work — federated redundancy without an operational load balancer.

## Trust model

Trust is in the **maintainer signature**, not the URLs themselves.

- Signature namespace: `coincync-faucet-registry-v1` (distinct from `coincync-peer-snapshot-v1` — cross-service replay defence enforced by `signed_registry` module)
- Same Ed25519 seed as the peer-snapshot ceremony (`~/.coincync-maintainer-seed/testnet-seed.hex`) — single maintainer key, single ceremony to rotate
- If a community faucet in the registry misbehaves, remove it from the input JSON and republish — users get the fix within one publish cycle

Users who want stricter posture skip the registry and hit `faucet.coincync.network` directly. This module is additive.

## Prerequisites (verify BEFORE first publish)

### 1. Maintainer key ceremony complete

Same Ed25519 seed as the peer-snapshot ceremony (see [`runbook-bootstrap-ceremony.md`](runbook-bootstrap-ceremony.md)). Verify:

```bash
[ -r "$HOME/.coincync-maintainer-seed/testnet-seed.hex" ] \
  && wc -c "$HOME/.coincync-maintainer-seed/testnet-seed.hex" \
  && echo "OK: seed file present and readable"
```

Expected: file exists, `65` bytes (64 hex chars + newline), mode `0400`.

### 2. IPFS reachable

Either local Kubo daemon or a Pinata JWT:

```bash
curl -sf -X POST http://127.0.0.1:5001/api/v0/id | jq -r '.ID'
# OR
[ -n "$PINATA_TOKEN" ] && echo "Pinata JWT present"
```

### 3. The extended `coincync-sign-snapshot` binary is built

The producer script needs the CLI's `COINCYNC_SIGN_NAMESPACE_HEX` env-var support (shipped in the same PR as this runbook). Verify:

```bash
cargo build --release --bin coincync-sign-snapshot
./target/release/coincync-sign-snapshot sign --help 2>&1 | head -3
```

If a prior release of the CLI is on your PATH without namespace support, the producer script will silently sign with the wrong (peer-snapshot) namespace and the consumer will reject the payload. **Always run the just-built binary from this repo's `target/release/`, not a pre-existing system install.**

### 4. Curated input file at `deploy/faucet-registry/<network>.json`

A starter file is committed (see `deploy/faucet-registry/testnet.json`). Before your first publish, verify the entries reflect **live faucets** — a stale registry pointing at dead URLs is worse UX than none.

Edit checklist per entry:
- `name`: short-name label for UI display
- `url`: full HTTPS URL of the `/faucet` POST endpoint
- `operator`: `"fleet"` for fleet-run, `"community"` for anyone else
- `description`: free-form; sanitized before wallet display
- `drip_amount_atomic`: how many atomic units the faucet drips per claim (10 CYNC = 10 000 000 000 000)
- `network`: must match the outer `network` field
- `last_seen`: the timestamp when YOU last verified the URL responded. Update whenever you re-verify.

## Publish ceremony (per-update)

Do this whenever you need to add / remove a faucet or refresh `last_seen` fields. Recommended cadence: **weekly**, aligned with the peer-snapshot cadence so both use the same maintenance window.

### Step 1 — verify prerequisites (all four above)

### Step 2 — edit the curated JSON

Add / remove entries in `deploy/faucet-registry/testnet.json`. Commit the edit as its own git commit BEFORE publishing, so the registry contents match the repo's tracked history:

```bash
git add deploy/faucet-registry/testnet.json
git commit -m "faucet-registry: add community-alice for 2026-07-04 publish"
```

### Step 3 — dry-run

```bash
bash scripts/publish-faucet-registry.sh --network testnet --dry-run
```

Verify:
- No parse errors
- `entries: N` matches the number you expect
- Canonical JSON written to `out/faucet-registry-testnet-<ts>.json`

### Step 4 — publish

Set the signing seed from your offline seed store:

```bash
export COINCYNC_SIGN_SEED_HEX="$(cat "$HOME/.coincync-maintainer-seed/testnet-seed.hex")"
```

**With local Kubo**:

```bash
bash scripts/publish-faucet-registry.sh --network testnet
```

**With Pinata pin as well** (recommended for redundancy):

```bash
PINATA_TOKEN="$YOUR_JWT" bash scripts/publish-faucet-registry.sh --network testnet
```

Script emits:
- `registry CID`: the payload's IPFS CID
- `signature CID`: the raw 64-byte signature's IPFS CID
- `sha256`: hash of the canonical JSON, for cross-verification
- Pointer file at `out/faucet-registry-latest-testnet.json`

### Step 5 — verify the pin

```bash
CID=<registry CID from step 4>
curl -sI "https://cloudflare-ipfs.com/ipfs/$CID" | grep -E 'HTTP|content-length'
curl -sI "https://ipfs.io/ipfs/$CID" | grep -E 'HTTP|content-length'
```

Both should return HTTP 200 within 30-60 seconds of publish. If either 404s after 2 minutes, the pin didn't propagate — re-publish OR wait longer.

### Step 6 — publish the pointer to the well-known URL

The consumer fetches the pointer JSON from a stable URL. Deploy `out/faucet-registry-latest-testnet.json` to:

`https://coincync.network/faucet-registry/latest-testnet.json`

Exact path depends on your static-hosting setup (Cloudflare Pages, S3+CDN, nginx alias). The consumer's default URL is compiled into the wallet; changing the URL requires a new wallet release.

Example nginx alias:

```
location /faucet-registry/latest-testnet.json {
    alias /var/www/coincync/faucet-registry/latest-testnet.json;
    add_header Cache-Control "public, max-age=300";
    add_header Access-Control-Allow-Origin *;
}
```

Deploy example (if fleet uses same box as explorer):

```bash
scp -i ~/.ssh/coincync_fleet \
    out/faucet-registry-latest-testnet.json \
    root@<explorer-host>:/var/www/coincync/faucet-registry/latest-testnet.json
```

### Step 7 — smoke test end-to-end

From a fresh wallet build (or a browser fetching the well-known URL):

```bash
curl -s https://coincync.network/faucet-registry/latest-testnet.json | jq
# Should be the pointer JSON: schema_version, unix_ts, payload_cid, signature_cid, ...
```

Then fetch + verify the payload manually to double-check the signature works before pushing an announcement:

```bash
CID=$(curl -s https://coincync.network/faucet-registry/latest-testnet.json | jq -r .payload_cid)
SIG=$(curl -s https://coincync.network/faucet-registry/latest-testnet.json | jq -r .signature_cid)
curl -s "https://cloudflare-ipfs.com/ipfs/$CID" > /tmp/payload.json
curl -s "https://cloudflare-ipfs.com/ipfs/$SIG" > /tmp/signature.bin
# Verify with `openssl` or a wallet build in verify-only mode.
```

Confirm the payload's entry list matches what you just published.

### Step 8 — announce (optional but recommended)

If the update added a new community faucet, post to Discord so users know:

> New community faucet added to the testnet registry: `<name>` operated by `<who>`. Wallets auto-discover on next start. Direct URL: `<url>`.

## Rotation cadence

- **Weekly**: publish an updated registry to refresh `last_seen` fields and prune stale entries
- **Ad-hoc**: whenever you add or remove a faucet
- **On maintainer key rotation**: republish immediately so consumers switch to the new signature under the new key

Old CIDs remain reachable on IPFS forever. Consumers accept only the CID currently advertised at the pointer URL.

## Failure modes and recovery

| Failure | Symptom | Recovery |
|---|---|---|
| `coincync-sign-snapshot` on PATH lacks namespace support | Consumer rejects: `signature verification failed` | Rebuild from the current commit (`cargo build --release --bin coincync-sign-snapshot`) and re-invoke via `./target/release/coincync-sign-snapshot`, NOT the system-installed binary |
| Input JSON schema drift | Producer rejects with schema/field validation error | Fix the input JSON per the schema in `deploy/faucet-registry/testnet.json`'s comments |
| Kubo down | Producer exits early with `local IPFS unreachable` | Start `ipfs daemon &`, or fall back to Pinata-only with `PINATA_TOKEN=... bash scripts/publish-faucet-registry.sh` |
| Pinata token expired | Pinata pin fails with 401 | Rotate the JWT in Pinata dashboard; re-run |
| Gateway serves 404 for the CID | Consumer log: `pointer fetch: HTTP 404` | Wait 60s for propagation; if still 404 after 2 min, verify `ipfs pin ls | grep $CID` shows the pin |
| Local CID differs from Pinata CID | Producer WARN in output | Content-addressed CIDs should match. Investigate (usually a hidden character difference in the input JSON). Use the local Kubo CID; Pinata is redundancy. |
| Consumer wallet is old and doesn't know about the pointer URL | User sees only the compiled-in canonical faucet | Publish a wallet update; older wallets keep working with the compiled-in entry. |

## Cross-references

- [`src/network/faucet_registry.rs`](../../src/network/faucet_registry.rs) — consumer wire types + entry-point function
- [`src/network/signed_registry.rs`](../../src/network/signed_registry.rs) — generic fetch-verify-parse path
- [`scripts/publish-faucet-registry.sh`](../../scripts/publish-faucet-registry.sh) — this ceremony's producer script
- [`src/bin/sign_snapshot.rs`](../../src/bin/sign_snapshot.rs) — signing CLI (with the namespace-override env var)
- [`deploy/faucet-registry/testnet.json`](../../deploy/faucet-registry/testnet.json) — curated input file
- [`docs/operations/runbook-bootstrap-ceremony.md`](runbook-bootstrap-ceremony.md) — Ed25519 seed generation (shared with peer-snapshot ceremony)
