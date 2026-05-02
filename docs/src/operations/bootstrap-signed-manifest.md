# Signed Bootstrap Manifest

Use a signed seed manifest when you want bootstrap peers to come from an authenticated operator-controlled list instead of unsigned DNS/hardcoded seeds.

## Why this exists

- DNS seeds are useful, but they are still a trust surface.
- A signed manifest lets you pin bootstrap peers to what your operators explicitly approved.
- Signature verification happens in-node before peers are accepted.

CoinCync verifies signatures over:

- `b"coincync/bootstrap-manifest/v1" + manifest_bytes`

with an Ed25519 public key you provide at runtime.

## Manifest format

JSON file:

```json
{
  "peers": [
    "1.2.3.4:28333",
    "5.6.7.8:28333"
  ]
}
```

## Tooling

CoinCync ships a first-party helper binary:

- `bootstrap_manifest_tool`

### 1) Generate signing keypair

```bash
cargo run --bin bootstrap_manifest_tool -- \
  keygen \
  --secret-out ./bootstrap_signing.key \
  --public-out ./bootstrap_signing.pub
```

- `bootstrap_signing.key`: raw 32-byte secret key (keep private)
- `bootstrap_signing.pub`: hex public key (safe to distribute)

### 2) Create manifest

```bash
cargo run --bin bootstrap_manifest_tool -- \
  create \
  --out ./bootstrap_seeds.json \
  --peer seed1.coincync.network:28333 \
  --peer seed2.coincync.network:28333 \
  --peer seed3.coincync.network:28333
```

### 3) Sign manifest

```bash
cargo run --bin bootstrap_manifest_tool -- \
  sign \
  --manifest ./bootstrap_seeds.json \
  --secret-key ./bootstrap_signing.key \
  --sig-out ./bootstrap_seeds.json.sig
```

### 4) Verify locally (recommended)

```bash
cargo run --bin bootstrap_manifest_tool -- \
  verify \
  --manifest ./bootstrap_seeds.json \
  --public-key ./bootstrap_signing.pub \
  --signature ./bootstrap_seeds.json.sig
```

Expected output:

```text
Signature OK
```

## Node runtime configuration

Set these environment variables for `coincync-node`:

- `COINCYNC_BOOTSTRAP_SIGNED_MANIFEST=/path/bootstrap_seeds.json`
- `COINCYNC_BOOTSTRAP_SIGNING_PUBKEY=<32-byte-hex-public-key>`
- Optional: `COINCYNC_BOOTSTRAP_SIGNED_MANIFEST_SIG=/path/bootstrap_seeds.json.sig`
  - default if omitted: `<manifest>.sig`

Additional bootstrap hardening knobs:

- `COINCYNC_BOOTSTRAP_MANIFEST_ONLY=1`
  - Use signed manifest peers only (skip DNS and hardcoded fallback)
- `COINCYNC_BOOTSTRAP_DISABLE_DNS=1`
  - Skip DNS seeds even when not in manifest-only mode
- `COINCYNC_BOOTSTRAP_SEED_ALLOWLIST=ip:port,ip:port,...`
  - Filter final candidate peers to explicit allowlist

## Example (systemd environment file)

```ini
COINCYNC_BOOTSTRAP_SIGNED_MANIFEST=/etc/coincync/bootstrap_seeds.json
COINCYNC_BOOTSTRAP_SIGNING_PUBKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
COINCYNC_BOOTSTRAP_SIGNED_MANIFEST_SIG=/etc/coincync/bootstrap_seeds.json.sig
COINCYNC_BOOTSTRAP_MANIFEST_ONLY=1
```

## systemd preflight (recommended)

Use a preflight check so the service fails before startup when manifest or
signature config is broken.

Script:

- `scripts/preflight_bootstrap_manifest.py`

Example unit override:

```ini
[Service]
EnvironmentFile=/etc/coincync/bootstrap.env
ExecStartPre=/usr/bin/python3 /opt/coincync/scripts/preflight_bootstrap_manifest.py
```

Template environment file:

- `deploy/bootstrap.env.example`

This verifies:

- required env vars are present
- manifest and signature files exist
- Ed25519 signature is valid for the manifest (same domain-separated scheme as node bootstrap verification)

## Operational guidance

- Keep signing keys offline if possible.
- Rotate signing keys with an overlap window (ship new pubkey + new manifest before removing old).
- Treat manifest publication like release artifacts: change review, checksum, signature verification.
- Log and alert on bootstrap candidate count dropping unexpectedly (empty manifest, signature mismatch, etc.).

## Troubleshooting

### Symptom: `loaded 0 signed manifest peers`

Common causes:

- Manifest path is wrong (`COINCYNC_BOOTSTRAP_SIGNED_MANIFEST`).
- Manifest JSON is malformed.
- `peers` list is empty.
- Entries are not valid `ip:port` socket addresses.

Check quickly:

```bash
ls -l /path/bootstrap_seeds.json
python -m json.tool /path/bootstrap_seeds.json
```

### Symptom: `Bootstrap manifest signature verification failed`

Common causes:

- Signature file does not match manifest bytes.
- Wrong `COINCYNC_BOOTSTRAP_SIGNING_PUBKEY`.
- Signed a different file than the one deployed.
- Wrong signature file path (`COINCYNC_BOOTSTRAP_SIGNED_MANIFEST_SIG`).

Verify end-to-end:

```bash
cargo run --bin bootstrap_manifest_tool -- \
  verify \
  --manifest /path/bootstrap_seeds.json \
  --public-key /path/bootstrap_signing.pub \
  --signature /path/bootstrap_seeds.json.sig
```

### Symptom: node starts but still uses DNS/hardcoded peers

You likely forgot strict mode.

Use:

```ini
COINCYNC_BOOTSTRAP_MANIFEST_ONLY=1
```

Optional extra hardening:

```ini
COINCYNC_BOOTSTRAP_DISABLE_DNS=1
```

### Symptom: no peers after enabling manifest-only

Likely causes:

- Manifest signature/key mismatch (manifest ignored).
- Manifest peer list unreachable from this host.
- Firewall blocks outbound P2P.

Checks:

```bash
ss -tlnp | rg 28080
journalctl -u coincync-node -n 200 --no-pager
```

Look for bootstrap log lines about manifest load count and signature verification.
