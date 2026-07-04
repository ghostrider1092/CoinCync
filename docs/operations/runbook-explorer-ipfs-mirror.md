# Runbook: Explorer IPFS mirror (Fort-Knox Item 4)

**Scope**: publish an IPFS pin of the coincync explorer so users can browse the chain even if `explorer.coincync.network` becomes unreachable. Community members visit any IPFS gateway URL and get a functioning explorer that talks to `api.coincync.network` (or their own node).

**Prerequisite**: the frontend at `src/explorer/index.html` must contain `_computeApiBase()` (Fort-Knox Item 4 code). Publishing to IPFS without this fix produces a broken mirror that 404s on every RPC call.

## Threat model this closes

**Failure this addresses**: `explorer.coincync.network` becomes unreachable — DNS zone compromised, Cloudflare edge outage, the origin server pulled offline, all at once. Users currently have no fallback to inspect a transaction, verify a block hash, or check the chain height.

**With IPFS mirror**: the community can hit any of dozens of public IPFS gateways using a CID:

- `https://cloudflare-ipfs.com/ipfs/<cid>/`
- `https://ipfs.io/ipfs/<cid>/`
- `https://dweb.link/ipfs/<cid>/`
- `https://gateway.pinata.cloud/ipfs/<cid>/`

Any of them serves the SAME bytes (content-addressed — the CID IS the SHA of the content), and the frontend's `_computeApiBase()` transparently routes API calls to `api.coincync.network`.

## What this does NOT protect against

- **API compromise**: an IPFS-served frontend that talks to `api.coincync.network` still trusts our API for the DATA. If the API returns lies, the mirror faithfully displays them. Full trust-minimization requires users to point the mirror at their own coincync-node via `?api=http://your-node:28081` or `localStorage.setItem('cync-api-base', ...)`.
- **Content freshness**: an IPFS CID is immutable. Every deploy requires publishing a new CID. Users bookmarking an old CID see that snapshot forever (this is arguably a feature — audit-trail immutability).

## Prerequisites (verify BEFORE first publish)

### 1. CORS on `api.coincync.network`

The IPFS-served frontend makes cross-origin fetches to `api.coincync.network`. Verify the API's nginx config allows this:

```bash
curl -sI \
  -H "Origin: https://cloudflare-ipfs.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS \
  https://api.coincync.network/api/testnet | grep -i "access-control"
```

Expected: `access-control-allow-origin: *` (or an allowlist explicitly containing `https://cloudflare-ipfs.com`, `https://ipfs.io`, `https://dweb.link`, `https://gateway.pinata.cloud`).

If CORS is not enabled, the mirror will silently fail on any browser. **Fix nginx before publishing.**

The nginx snippet (add to the api box's coincync-node reverse-proxy location block):

```nginx
add_header 'Access-Control-Allow-Origin' '*' always;
add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;
if ($request_method = 'OPTIONS') {
    add_header 'Access-Control-Allow-Origin' '*';
    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
    add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization';
    add_header 'Access-Control-Max-Age' 1728000;
    add_header 'Content-Length' 0;
    add_header 'Content-Type' 'text/plain charset=UTF-8';
    return 204;
}
```

Reload nginx (`nginx -s reload`) and re-test.

### 2. IPFS pinning path

**Recommended (both)**:
- Local Kubo daemon on the maintainer workstation (`ipfs daemon` running at `127.0.0.1:5001`)
- Pinata JWT with `pinFileToIPFS` scope in `$PINATA_TOKEN`

Kubo gives immediate propagation to the public IPFS network; Pinata gives paid-tier gateway redundancy. Publishing to both is belt-and-suspenders.

**Minimum acceptable**: either Kubo OR Pinata. The script errors out if neither is configured.

### 3. Well-known pointer URL infrastructure

The pointer file (`out/explorer-latest.json`) is small JSON that maps to the current CID. It needs to be served at a stable URL so the community can discover the current mirror:

- Recommended: `https://explorer.coincync.network/.well-known/mirror.json` (self-referential — if explorer is up, so is the pointer)
- Alternative: `https://api.coincync.network/.well-known/explorer-mirror.json`
- Alternative: any static-hosting URL you control (Cloudflare Pages, S3+CDN, GitHub Pages)

The URL itself is public and doesn't need to be signed — an attacker who serves a fake pointer directs users to a different CID, but the CID's content is content-addressed and can't be forged.

## Publish ceremony (per-deploy)

Do this whenever the explorer frontend changes AND the change has been through PR review + merge.

### Step 1 — verify prerequisites

```bash
# CORS still enabled
curl -sI -H "Origin: https://ipfs.io" -X OPTIONS \
  https://api.coincync.network/api/testnet | grep -i access-control-allow-origin

# Fort-Knox 4 code still in the frontend
grep -c "_computeApiBase" /c/dev/coincync/src/explorer/index.html
# Must be >= 1

# IPFS reachable
curl -sf -X POST http://127.0.0.1:5001/api/v0/id | jq -r '.ID'
# Non-empty output = reachable

# Or: Pinata token loaded
[ -n "$PINATA_TOKEN" ] && echo "Pinata token present"
```

### Step 2 — dry-run publish

```bash
cd /c/dev/coincync
bash scripts/publish-explorer-ipfs.sh --dry-run
```

Inspect the `out/explorer-static/` output. Verify:
- `index.html` is present
- `assets/`, `static/` present with expected content
- No `serve.py` or `__pycache__` (excluded by the script)
- `BUILD_INFO.txt` records the current commit
- `README.md` present

If the dry-run looks clean:

### Step 3 — publish for real

```bash
# Both paths (recommended):
PINATA_TOKEN="$YOUR_JWT" bash scripts/publish-explorer-ipfs.sh

# Local IPFS only:
bash scripts/publish-explorer-ipfs.sh

# Pinata only:
SKIP_LOCAL_IPFS=1 PINATA_TOKEN="$YOUR_JWT" bash scripts/publish-explorer-ipfs.sh
```

Record the CID from stdout. The script also writes `out/explorer-latest.json` with the full pointer payload.

### Step 4 — verify the pin

```bash
CID=<from step 3>
curl -sI "https://cloudflare-ipfs.com/ipfs/$CID/index.html" | grep -E 'HTTP|content-length'
# Expected: HTTP/2 200 and a content-length > 300000 (index.html is ~330KB)

curl -sI "https://ipfs.io/ipfs/$CID/index.html" | grep -E 'HTTP|content-length'
# Same
```

Both gateways should serve the file. If one 404s, the pin hasn't propagated yet — wait 30-60 seconds and retry. If both 404 after 2 minutes, the publish failed silently.

### Step 5 — smoke-test in a browser

Open `https://cloudflare-ipfs.com/ipfs/<cid>/` in a fresh incognito window. Verify:

- The page loads with styles applied
- The block list starts populating within 5 seconds
- Network tab shows requests going to `api.coincync.network` (NOT to the gateway)
- Bottom-left status shows the current chain height
- Console has no CORS errors

If any of these fail, the CORS or `_computeApiBase()` chain is broken. Do NOT publish the pointer until this is clean.

### Step 6 — publish the pointer

Deploy `out/explorer-latest.json` to the pointer URL you chose. Example for `explorer.coincync.network/.well-known/mirror.json`:

```bash
scp -i ~/.ssh/coincync_fleet \
  /c/dev/coincync/out/explorer-latest.json \
  root@<explorer-host-ip>:/var/www/explorer/.well-known/mirror.json

# Or via the deploy script if you have one that handles static files:
bash scripts/deploy-explorer-static.sh out/explorer-latest.json
```

### Step 7 — announce

- Add the CID to the current release notes (`docs/announcements/` or the current GitHub Release body)
- Discord announcement: "Explorer IPFS mirror updated. New CID: `<cid>`. Access at any of: cloudflare-ipfs.com, ipfs.io, dweb.link, gateway.pinata.cloud (/ipfs/CID/)."
- Optional: bump a version tag in the pointer JSON so the community can distinguish updates

## Rotation (when the explorer changes)

Every explorer update needs a new publish. The pointer URL always resolves to the CURRENT CID. Old CIDs remain valid on IPFS forever — anyone who bookmarked them still gets the old snapshot (this is a feature; audit-immutable snapshots).

**Cadence**: publish on every merged explorer change that lands in `src/explorer/`. Weekly at minimum.

## Recovery (if primary explorer is down)

1. Get the current CID from the well-known pointer URL:
   ```bash
   curl -s https://explorer.coincync.network/.well-known/mirror.json | jq -r .cid
   ```
   If the primary is down and the pointer is co-hosted, use the last-known CID from a Discord announcement or GitHub Release body.

2. Direct users at:
   ```
   https://cloudflare-ipfs.com/ipfs/<cid>/
   https://ipfs.io/ipfs/<cid>/
   https://dweb.link/ipfs/<cid>/
   ```

3. If `api.coincync.network` is ALSO down, users need to point at their own coincync-node:
   ```
   https://cloudflare-ipfs.com/ipfs/<cid>/?api=http://<their-node>:28081
   ```

## Failure modes and recovery

| Failure | Symptom | Recovery |
|---|---|---|
| CORS not enabled on `api.coincync.network` | Browser console shows `Access to fetch ... blocked by CORS policy` on the IPFS mirror | Deploy the nginx snippet in step 1 and `nginx -s reload` |
| Frontend missing `_computeApiBase` | Every fetch on the IPFS mirror is a `/api/testnet` 404 | Merge the Fort-Knox item 4 PR before publishing |
| Kubo down at publish time | Script exits with "not reachable" | `ipfs daemon` on the maintainer workstation, or use `SKIP_LOCAL_IPFS=1 PINATA_TOKEN=...` |
| Pinata JWT expired | Script logs `WARN: Pinata pin failed` and proceeds with local-only CID | Rotate the JWT in Pinata dashboard; re-run |
| Gateway serves 404 for the CID | `curl -sI ipfs.io/ipfs/<cid>/index.html` returns 404 | Wait 60s for propagation; if still 404, verify the CID is pinned via `ipfs pin ls | grep <cid>` |
| Different local vs Pinata CID | Script logs a WARN | Kubo directory-add vs. Pinata tarball-upload produce different CIDs. Kubo's CID is canonical; Pinata is redundancy. Use the Kubo CID in the pointer. |

## Cross-references

- [`src/explorer/index.html`](../../src/explorer/index.html) — `_computeApiBase()` at ~line 2170
- [`scripts/publish-explorer-ipfs.sh`](../../scripts/publish-explorer-ipfs.sh) — the publish script
- [`docs/operations/signed-peer-snapshots.md`](signed-peer-snapshots.md) — Fort-Knox Item 6 (similar IPFS-based bootstrap pattern)
- [Reproducible Builds — Explorer](REPRODUCIBLE_BUILDS.md) — future work: byte-identical explorer builds
