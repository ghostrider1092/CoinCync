# Bootstrap a new node from a chaindata snapshot

**TL;DR:** Download a tarball, verify its SHA256, untar to your data
dir, start the node. You'll be at the chain tip in ~30 seconds instead
of waiting 1-2 hours for initial sync.

This is a **stopgap** until trustless warp sync ships per
[CIP-015](../../cip/CIP-015-warp-sync-utxo-snapshot.md) in v2.0. If
you want zero trust, sync from genesis instead — see
[run-a-node.md](../getting-started/run-a-node.md).

## When to use this

**Use snapshot bootstrap if:**

- You're a new community member who wants to start mining or running
  a node without waiting for initial sync.
- You're recovering a node after data loss and don't want to re-sync
  from genesis.
- You're spinning up a test node and don't care about historical
  verification.

**Do NOT use snapshot bootstrap if:**

- You want trustless validation of the chain from genesis to tip.
  Sync normally instead.
- You're operating an exchange or any infrastructure that holds user
  funds. Always sync from genesis.
- The snapshot is more than 14 days old — too much chain progress
  since the snapshot; you'd still have a long catch-up to do.

## What trust you're placing

The snapshot is a packed copy of someone else's already-synced
RocksDB. When you untar it, you're trusting:

1. **The tarball wasn't tampered with in transit.** Defended by the
   SHA256 you'll verify against the manifest.
2. **The fleet node that produced the snapshot wasn't malicious.**
   Defended by your binary's hardcoded checkpoints (see
   `src/testnet.rs`) — when you start the node, it re-checks the
   imported chain head against ~80 hardcoded (height, hash) pairs.
   A tampered snapshot would fail at the first checkpoint above the
   snapshot's tip height, and your node would refuse to extend that
   chain.

This is **trust-minimized**, not **trustless**. The mainnet binary
ships with the same checkpoint defense, but the snapshot itself comes
from us. If you don't trust us, sync from genesis.

CIP-015 warp sync (v2.0) removes this trust — snapshots will be
verified against block-header-committed state roots instead of
post-hoc checkpoint matching.

## Procedure

### 1. Get the snapshot URL + expected SHA256

Check the Discord `#announcements` channel or the GitHub release page
for the latest bootstrap pack. You're looking for three files:

```
coincync-chaindata-testnet-h<N>.tar.gz       # the data
coincync-chaindata-testnet-h<N>.manifest.json # height + hash + sha256
coincync-chaindata-testnet-h<N>.sha256        # just the sha256 line
```

Where `<N>` is the snapshot's tip height (e.g. `h14800`).

### 2. Download all three files

```bash
mkdir -p ~/coincync-bootstrap
cd ~/coincync-bootstrap

BASE="coincync-chaindata-testnet-h14800"
RELEASE="https://github.com/Coincync/Coincync-Testnet-/releases/download/v1.0.9.1-testnet"

wget "$RELEASE/${BASE}.tar.gz"
wget "$RELEASE/${BASE}.manifest.json"
wget "$RELEASE/${BASE}.sha256"
```

### 3. Verify SHA256

```bash
sha256sum -c "${BASE}.sha256"
# Expected output:  coincync-chaindata-testnet-h14800.tar.gz: OK
```

**If you see `FAILED`, STOP.** The tarball is corrupt or has been
tampered with. Do not import it. Re-download or report to the
maintainer.

### 4. Stop your node (if running)

```bash
sudo systemctl stop coincync-node            # if installed as a service
# OR
pkill -x coincync-node                       # if running manually
```

### 5. Back up your existing data dir

```bash
# Default data dir locations:
#   Linux:   ~/.coincync/testnet
#   Windows: %APPDATA%\coincync\testnet
#   macOS:   ~/Library/Application Support/coincync/testnet

mv ~/.coincync/testnet ~/.coincync/testnet.backup-$(date +%F)
```

This is a defensive step: if the bootstrap fails for any reason, you
can restore your old chain by moving the backup back. Once the
imported chain successfully extends past the snapshot tip and you've
seen "applied block at height N" for several N > snapshot tip, the
backup is safe to delete.

### 6. Untar the snapshot

```bash
mkdir -p ~/.coincync
cd ~/.coincync
tar -xzf ~/coincync-bootstrap/${BASE}.tar.gz
# Tarball contains a `testnet/` directory, so this creates ~/.coincync/testnet
ls testnet/   # should show CURRENT, MANIFEST-*, LOG, *.sst, *.log, etc.
```

### 7. Start the node

```bash
coincync-node --network testnet \
  --addnode 66.135.23.193:28080 \
  --addnode 140.82.57.168:28080 \
  --addnode 207.148.111.76:28080 \
  --addnode 207.148.6.50:28080 \
  --addnode 95.179.165.225:28080 \
  --addnode 192.248.151.16:28080
```

(The `--addnode` flags are the standard fleet seeds — same list as in
[run-a-node.md](../getting-started/run-a-node.md). Drop them after
first sync if you want.)

### 8. Verify success

Watch the log. You should see:

```
INFO  Loaded chain database at height 14800
INFO  Tip hash: <matches manifest>
INFO  Verifying against hardcoded checkpoints...
INFO  Checkpoint match at height 14000 ✓
INFO  Connected to peer 66.135.23.193:28080
INFO  Sync started — target height 14823
INFO  Applied block at height 14801
INFO  Applied block at height 14802
...
```

The "Checkpoint match" line is the critical safety check. If you see
`Checkpoint MISMATCH at height N`, the snapshot was tampered with and
your node correctly refused to extend it. Delete the imported data
dir, restore your backup, and report to the maintainer.

Once you see "Applied block at height N" for several N above the
snapshot tip, you're fully bootstrapped and on the live chain.

## Procedure (Windows)

Same steps, PowerShell syntax for the file operations:

```powershell
# 1-3: download + verify
$base = "coincync-chaindata-testnet-h14800"
$release = "https://github.com/Coincync/Coincync-Testnet-/releases/download/v1.0.9.1-testnet"
$dest = "$env:USERPROFILE\coincync-bootstrap"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Set-Location $dest
Invoke-WebRequest -Uri "$release/${base}.tar.gz" -OutFile "${base}.tar.gz"
Invoke-WebRequest -Uri "$release/${base}.manifest.json" -OutFile "${base}.manifest.json"
Invoke-WebRequest -Uri "$release/${base}.sha256" -OutFile "${base}.sha256"

# 3: SHA256 verify
$expected = (Get-Content "${base}.sha256").Split(' ')[0].ToLower()
$actual = (Get-FileHash "${base}.tar.gz" -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { throw "SHA256 mismatch — STOP" }
Write-Host "SHA256 OK"

# 4: stop node (if running)
Get-Process coincync-node -ErrorAction SilentlyContinue | Stop-Process

# 5-6: backup + untar
$dataParent = "$env:APPDATA\coincync"
$dataDir = "$dataParent\testnet"
$backup = "$dataDir.backup-$(Get-Date -Format 'yyyy-MM-dd')"
if (Test-Path $dataDir) { Move-Item $dataDir $backup }
New-Item -ItemType Directory -Force -Path $dataParent | Out-Null
Set-Location $dataParent
tar -xzf "$dest\${base}.tar.gz"

# 7: start node (with fleet seeds — same list as Linux)
coincync-node --network testnet `
  --addnode 66.135.23.193:28080 `
  --addnode 140.82.57.168:28080 `
  --addnode 207.148.111.76:28080 `
  --addnode 207.148.6.50:28080 `
  --addnode 95.179.165.225:28080 `
  --addnode 192.248.151.16:28080
```

## FAQ

**Q: How often will new snapshots be published?**
A: Currently ad-hoc, generally weekly during the testnet phase. We'll
formalize a cadence (probably every 2,000 blocks, or weekly,
whichever comes first) before mainnet.

**Q: Can I use a snapshot from a different binary version?**
A: Same-major-version-or-newer ONLY. RocksDB column-family
definitions sometimes change across releases. The manifest lists the
binary version the snapshot was made with; your binary must be
that version or newer. If in doubt, sync from genesis.

**Q: What's in the snapshot besides the chain?**
A: Just the chain database (`~/.coincync/testnet/`). It does NOT
include any wallet files, peer ban list, RPC tokens, or operator
config. Those stay yours.

**Q: Why not just provide a block-by-block download from a CDN?**
A: Because that's still O(chain length) work to import and verify.
The tarball approach lets RocksDB skip rebuilding its index files
and you go straight to a usable database state.

**Q: When will this be replaced by warp sync?**
A: v2.0 (probably Q2 2027). See [CIP-015](../../cip/CIP-015-warp-sync-utxo-snapshot.md).

## Related

- [run-a-node.md](../getting-started/run-a-node.md) — normal
  (sync-from-genesis) install flow.
- [CIP-015](../../cip/CIP-015-warp-sync-utxo-snapshot.md) — trustless
  warp sync design (the future replacement for this procedure).
- [scripts/create-chaindata-snapshot.sh](../../../scripts/create-chaindata-snapshot.sh)
  — the script fleet operators use to generate these snapshots.
