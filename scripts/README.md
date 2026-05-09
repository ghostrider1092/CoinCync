# scripts/

Operational and development scripts grouped by purpose. The
filenames are descriptive — this README catalogs them so an
operator can find the right one for a task without `ls`-ing
the whole directory.

Conventions:

- `*.sh` — POSIX (Linux / WSL / macOS); fleet operations
- `*.ps1` — PowerShell (Windows host); operator-side
  controlplane scripts
- `*.py` — Python; one-off tools and config-generation
- `*.service`, `*.timer` — systemd units; deploy alongside
  the matching `.sh` script

## Fleet provisioning + deployment

Bootstrapping a new fleet box, deploying binaries, configuring
nginx + TLS:

| Script | What it does |
| --- | --- |
| `provision-vultr-fleet.ps1` | Spin up a fresh Vultr VPS with the project's standard config. |
| `setup_node.sh` | Initial node setup on a fresh Linux host. |
| `swap-binary-and-verify.ps1` | Replace a node's binary in place + verify the new version is healthy. |
| `deploy-coincync-rig-to-api.ps1` | Deploy the mining rig binary to the api box. |
| `deploy-api-nginx.ps1` | Configure nginx as the public-facing reverse proxy on the api box. |
| `deploy-explorer-nginx.ps1` | Same for the explorer box. |
| `add-origin-tls.sh`, `install-origin-cert.ps1` | Origin-cert setup for TLS termination behind Cloudflare. |
| `deploy-rpc-key-and-verify.ps1` | Distribute the RPC API key to a fleet box + smoke-test. |

## Faucet operations

Faucet drips, refilling, smoke-testing the public testnet faucet:

| Script | What it does |
| --- | --- |
| `install-faucet.sh` | Install the faucet daemon + its systemd unit on the api box. |
| `deploy-faucet.ps1` | Deploy the faucet binary from the operator's host. |
| `faucet.py` | Manual drip CLI (operator side). |
| `fund-faucet.ps1` | Top up the faucet's hot wallet from the operator's reserve. |
| `smoke-test-faucet.ps1` | Verify a fresh drip lands in a recipient wallet end-to-end. |

## Health monitoring + soak

Long-running checks that watch fleet health and feed the Discord
alert channel:

| Script | What it does |
| --- | --- |
| `coincync-selfcheck.sh` + `.service` + `.timer` | Per-box health check (synced, peer count, tip age). Emits Discord webhook on failure. |
| `coincync-soak.sh` + `.service` | The 72-hour pre-launch soak runner. |
| `run-72h-soak.ps1`, `watch-72h-soak.ps1` | Operator-side wrappers to start + monitor the soak. |
| `soak-final-summary.sh`, `soak_summary.py` | Generate the post-soak report. |
| `check-soak-status.sh`, `check-fleet-peers.sh` | Quick spot-checks during a running soak. |
| `coincync-weekly-review.sh` + `.service` + `.timer` | Weekly summary of fleet activity to Discord. |
| `deploy-selfcheck.ps1`, `deploy-soak.ps1`, `deploy-weekly-review.ps1` | Push the corresponding scripts + units to fleet boxes. |
| `deploy-node-health-dashboard.ps1` | Stand up the health dashboard (wraps the Prometheus scrape). |

## Continuous fuzzing

Self-hosted continuous fuzzing infra (see
`docs/operations/CONTINUOUS_FUZZING.md`):

| Script | What it does |
| --- | --- |
| `coincync-fuzz.sh` + `.service` | The 24/7 cargo-fuzz loop. Rotates through every fuzz target. Discord webhook on crash. |

## Tests + smoke checks

Adversarial scripts that run live against the fleet:

| Script | What it does |
| --- | --- |
| `smoke-test-tx.ps1` | Full tx happy-path: build, broadcast, observe on-chain. |
| `attack_test.sh` | Adversarial input fuzzing against a running node. |
| `flood_mempool.sh` | Mempool-flooding load test. |
| `test_partition_merge.sh` | Partition the fleet, then merge — verify state converges. |
| `test_propagation_timing.sh` | Block / tx propagation latency between fleet boxes. |
| `test_reorg.sh` | Force a reorg to verify the node handles it correctly. |
| `test-tx-propagation.ps1` | Same as `test_propagation_timing.sh` but operator-side. |
| `integration-fresh-node-sync.sh` | Wipe a fleet box and verify it can re-sync from scratch. |
| `debug-fresh-node-sync.sh` | Manual investigation tool when fresh sync gets stuck. |
| `diagnose-seed1-peering.sh` | Diagnose seed1's peering health when it falls behind. |
| `nudge-api.sh` | Force the api box to re-sync if it's drifted. |

## Privacy + audit verification

Scripts that exercise the privacy guarantees on real chain
state:

| Script | What it does |
| --- | --- |
| `verify-privacy.ps1` | Spot-check that all 22 privacy invariants hold on a recent tx. Height-aware (Ring-11 bootstrap vs Ring-16 post-10000). |
| `verify-strict-mode.ps1` | Run the full strict-privacy validation pass. |
| `verify_audit_policy.py` | Check that the codebase complies with the audit checklist. |
| `verify_best_practices_policy.py`, `generate_best_practices_report.py` | Generate the best-practices conformance report. |
| `check_insecure_defaults.py` | Static scan for insecure default values in config files. |
| `preflight_bootstrap_manifest.py` | Pre-launch manifest check. |

## Build + release

Reproducible-build verification, release packaging,
checkpoint refresh:

| Script | What it does |
| --- | --- |
| `verify-build.sh` | Verify a release binary matches its source-tree commit (per `docs/operations/REPRODUCIBLE_BUILDS.md`). |
| `publish.ps1` | Build + sign + upload a release. |
| `build-docs-pages.ps1` | Build the docs site for `docs.coincync.network`. |
| `releases-index.html` | Auto-generated release-listing page. |
| `verify-pages-deploy.ps1` | Verify a docs-site deploy landed correctly. |
| `refresh-checkpoints.sh` | Pull current chain head + append to the consensus-checkpoint table. |

## DNS + TLS + alerting

Cloudflare DNS snapshots, TLS rotation, Discord webhook
plumbing:

| Script | What it does |
| --- | --- |
| `dns-snapshot.sh` | Dump current Cloudflare DNS records to a JSON file (per `docs/operations/DNS_FAILOVER.md`). |
| `post-to-discord.ps1` | Post arbitrary content to the project Discord webhook. |

## Wallet + miscellaneous

| Script | What it does |
| --- | --- |
| `regenerate-tauri-icons.py` | Regenerate the Tauri wallet's icon set from the source PNG. |
| `verify-community-join-readiness.ps1` | Pre-flight check that a community node can join the public testnet. |
| `snap-explorer-api.ps1` | Snapshot of the explorer's API state for diff'ing across releases. |
| `devserver.py` | Local dev server for working on the explorer / docs site. |
| `wsl-check.sh`, `windows-test.sh` | Platform-specific developer-environment checks. |

## How to add a new script

1. Pick a descriptive lowercase-with-dashes filename.
2. First line is the shebang; line 2 is a brief comment
   explaining what the script does.
3. Add an entry to the appropriate table above. If no table
   fits, add a new section.
4. If the script is operational (gets deployed to a fleet
   box), accompany it with a systemd unit + a `deploy-*.ps1`
   wrapper if the deployment shape isn't already covered by
   an existing wrapper.
5. Set executable bit (`chmod +x`) for `*.sh`.
