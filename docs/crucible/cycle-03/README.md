# Crucible Cycle 03 — 2026-06-13

**Status:** in progress.
**Operator:** ghostrider1092 (local, US Pacific) + barns1253 (remote, France).
**Build under test:** `v1.0.11-testnet` — first public release with
cryptographically verified commits + cross-platform binaries (released
2026-06-12). Tag: https://github.com/ghostrider1092/Coincync-Testnet-/releases/tag/v1.0.11-testnet
**Mesh shape:** barns1253 dials the public 3-node fleet via DNS seeds
(`seed{1,2,3}.coincync.network`). First Crucible cycle against the
**live public testnet**, not an isolated mesh.

## Goal

Validate v1.0.11 as a real-world release:

  1. **Download path** — GitHub release link + SHA256 verification
     works from a fresh user's perspective.
  2. **Auto-discovery** — DNS seeds auto-resolve, bootstrap works
     without any `--addnode` flags.
  3. **Initial Block Download** — sync from h=0 to current tip
     (~h=5,156+) completes without manual intervention.
  4. **Wallet + send** — wallet operates against the live chain;
     a tx submitted from barns reaches a fleet box.
  5. **Long-running stability** — node remains connected + tip-advancing
     for the duration of the test.

## Difference from Cycles 01 + 02

  | | Cycle 01 | Cycle 02 | **Cycle 03** |
  |---|---|---|---|
  | Network shape | barns alone | 2-node mesh (operator ↔ barns) | **3-fleet + barns (4 nodes)** |
  | Mesh discovery | DNS seeds | manual `--addnode` | **DNS seeds (live)** |
  | Build under test | v1.0.10 | v1.0.11-fleet HEAD pre-release | **v1.0.11-testnet release** |
  | First public release | no | no | **yes** |

## Pre-cycle baseline

Live fleet state at test start:

  | Box | IP | Role | Status |
  |---|---|---|---|
  | seed1 | 66.135.23.193 (New York) | seed + p2p | active, v1.0.11 |
  | seed2 | 140.82.57.168 (Amsterdam) | seed + p2p | active, v1.0.11 |
  | explorer | 207.148.6.50 (Dallas) | explorer + p2p | active, v1.0.11 |

Chain height: ~5,156 (passed v1.0.12's ring-ramp boundary h=5,000
overnight; v1.0.11 fleet does not enforce ramp so blocks accepted
normally — real-world confirmation that v1.0.12 is a coordinated
hard fork).

## Test sequence

  1. **barns downloads** from the GitHub release page.
     Expected: SHA256 matches `89a60738fba1699360888cd6085434dc40e6baada52357f5a5e6c1fd312726cd`
     (Windows zip).

  2. **barns extracts + verifies signature** on the commit history.
     Expected: GitHub shows "Verified ✓" on every commit in the
     release tag's history.

  3. **barns starts node**:
     `coincync-node --network testnet start`
     Expected: DNS seeds resolve → peer connections to all 3 fleet
     boxes → IBD begins from h=0.

  4. **IBD completion** to chain tip (~5,156+).
     Expected: completes in 20-40 minutes (depends on barns' link).

  5. **barns creates wallet**:
     `coincync-wallet --network testnet --wallet my.wallet create`
     Expected: 24-word seed printed, wallet file written.

  6. **barns submits a tx**:
     Send some testnet CYNC to operator's address or self-send.
     Expected: mempool admission OK, tx mines into a block, recipient
     scan sees it.

## What we're explicitly watching for

  - Any **Cycle 01 finding regression** — silent mempool eviction,
    `--no-peers` dropping addnode, GetHeaders flood, Ctrl+C hang.
  - Any **Cycle 02 finding manifestation** — peer flap (~75s
    disconnect cycle since v1.0.11 doesn't have keepalive),
    EMERGENCY-TIER-3 firing during IBD.
  - Any **NEW findings** that show up only against a real public
    deployment vs the isolated meshes of prior cycles.

## Operator monitoring stack

Active while test runs:

  - `journalctl -u coincync-node -f` on seed1, seed2, explorer
    (tail follows captured to background tasks)
  - `curl api.coincync.network/rpc/testnet` for chain state polling
  - GitHub release page download counter

## Cycle results

(Filled in as findings + verifications surface during the test.)

  - Finding NN — [finding-NN-short-title.md](finding-NN-short-title.md)
    (use the template at `finding-TEMPLATE.md`)
  - Verification NN — [verification-NN-...](verification-NN-...)
    (use the template at `verification-TEMPLATE.md`)
