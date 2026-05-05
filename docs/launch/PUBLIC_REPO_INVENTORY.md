<!-- markdownlint-disable MD036 MD013 -->
# Public Repo Inventory — Pre-Push Audit

**Status:** ready to push *after* the two cleanup items below are addressed. This document is the authoritative list of what lands on GitHub when the public repo is created.

**Total tracked files:** 611
**Tag to push:** `v1.0.2-testnet`
**Suggested repo name:** `coincync` (canonical) or `coincync-1.0`

---

## 🔴 Two cleanup items before first push

These should be fixed *and committed* before `git push origin main` ever runs:

### 1. Hardcoded bearer in `scripts/run-72h-soak.ps1` (line 2)

```powershell
$headers=@{ Authorization='Bearer 6430f9425dcd29549017499686852edb504f20ba1ee8a97c8a14eff8a62f0a48' }
```

Even if this is the public testnet RPC bearer, hardcoding it sets a precedent future scripts will copy. Fix: read from `$env:COINCYNC_RPC_API_KEY` like every other ops script.

### 2. Fleet IPs inline in `docs/DEVELOPER.md`

The "Roll a new node binary across all 5 boxes" snippet inlines the actual fleet IPs. They're public seeds (also in `src/testnet.rs`), but framing them in DEVELOPER.md as "the production servers in the rollout" maps the operational topology. Replace with `<seed1-ip>` placeholders + a pointer to `src/testnet.rs` for the canonical list.

---

## 🟢 Top-level inventory

| Dir / file | Files | What it is |
| --- | ---: | --- |
| `src/` | 243 | Rust source — node, consensus, crypto, RPC, network, wallet, explorer page |
| `coincync-wallet/` | 87 | Tauri wallet (React + Rust, sidecars excluded) |
| `website/` | 58 | Marketing site (HTML + assets + wallpapers) |
| `tests/` | 53 | Integration + adversarial test suites (14 tiers) |
| `deploy/` | 52 | Caddy / nginx configs for explorer + landing + API |
| `docs/` | 38 | Bill of Rights, Commentary, COMMANDS, DEVELOPER, CIPs, mdbook source |
| `crates/` | 24 | `bridge`, `coincync-rig` (miner), `coincync-swap` (skeleton), `orchard-side` |
| `scripts/` | 21 | Public ops scripts (smoke-test, soak, fleet-check, faucet) |
| `fuzz/` | 7 | Fuzz harness (cargo-fuzz targets) |
| `.github/` | 7 | CI workflows (release, integration-tests, critical-lock, hardening, etc.) |
| `tools/` | 5 | RPC client lib, vanity-gen, paper-wallet generator |
| `release/` | 3 | Sample config + systemd unit + README (binaries ship via Releases) |
| Top-level | 13 | `CONSTITUTION.md`, `LICENSE`, `README.md`, `Cargo.toml`, etc. |

**Total: 611 files.**

---

## Detail by directory

### `src/` — 243 files

```text
  94  src/explorer/        # static HTML/JS/CSS for the embedded explorer
  30  src/network/         # P2P, Dandelion++, framing, sync, peer mgmt
  18  src/crypto/          # CLSAG, stealth, Pedersen, Bulletproofs+, view keys
  16  src/wallet/          # wallet logic (shared by CLI + Tauri)
  12  src/rpc/             # JSON-RPC server, lightwallet, node_api
  11  src/db/              # rocksdb-backed chain + UTXO storage
  10  src/consensus/       # validation, difficulty, PoW — LOCKFILE-PROTECTED
   8  src/storage/         # checkpoint, peer-store, persistence
   7  src/mining/          # mining-side helpers (used by node + miner)
   7  src/cli/             # shared CLI argument parsing
   5  src/transaction/     # tx types + serialization
   5  src/primitives/      # core types (Hash, Address, Amount)
   5  src/bin/             # binary entry points (node, wallet, tools)
   3  src/emission/        # emission curve — LOCKFILE-PROTECTED
   ~   src/<flat files>    # constants.rs, chain.rs, lib.rs, mempool.rs, etc.
```

**Lockfile-protected (will fail build if touched without intentional refresh):**
- `src/testnet.rs`
- `src/constants.rs`
- `src/consensus/difficulty.rs`
- `src/consensus/pow.rs`
- `src/consensus/validation.rs`
- `src/emission/curve.rs`

### `crates/` — 24 files (4 workspace members)

```text
  11  crates/coincync-rig/   # CPU miner with premium TUI dashboard
   9  crates/coincync-swap/  # CYNC↔BTC atomic swap (skeleton; CIP-001)
   2  crates/orchard-side/   # Halo2 wrapper (workspace-excluded; pending upstream)
   2  crates/bridge/         # Bytes-only Tari↔Orchard isolation crate
```

### `docs/` — 38 files

```text
  24  docs/src/              # mdbook source (rendered via build.sh)
   1  docs/theme/            # mdbook theme overrides
   1  docs/launch/           # ← this file + TESTNET_LAUNCH_ANNOUNCEMENT.md
   1  docs/cip/              # CIP-001 (atomic swap)
   ~   docs/<flat files>     # API.md, BILL_OF_RIGHTS.md, COMMANDS.md,
                             # CONSTITUTIONAL_COMMENTARY.md, DEVELOPER.md,
                             # SMOKE_TEST.md, CODE_OF_CONDUCT.md, DISCLAIMER.md,
                             # P2POOL_INTEGRATION.md, book.toml, build.sh
```

### `scripts/` — 21 files (curated; ops-internal scripts gitignored)

```text
  smoke-test-tx.ps1                Windows smoke test runner (end-to-end tx)
  run-72h-soak.ps1                 ⚠ contains hardcoded bearer (FIX BEFORE PUSH)
  watch-72h-soak.ps1               Live tail of soak progress
  releases-index.html              Public downloads page
  faucet.py                        Testnet faucet (when deployed)
  devserver.py                     Local explorer dev server
  setup_node.sh                    One-shot node setup
  coincync-verify-chain.sh         Chain integrity verifier
  attack_test.sh / flood_mempool.sh / test_*.sh    Adversarial tests
  verify_best_practices_policy.py / verify_audit_policy.py
  verify-community-join-readiness.ps1
  preflight_bootstrap_manifest.py
  generate_best_practices_report.py
  check_insecure_defaults.py
  windows-test.sh / wsl-check.sh
```

### `tests/` — 53 files (the proof we ship with the code)

```text
  11  tests/historical_attacks/    # Monero 2017, BTC overflow, etc. — replays
   8  tests/extended_tiers/        # extra adversarial tiers
  ~   tests/tier{1..14}_*.rs       # main 14-tier security regression suite
  ~   tests/<flat>                 # rate_limiter, p2p_adversarial, ic_crypto,
                                   # full_pipeline_real_crypto, etc.
```

### `deploy/` — 52 files

```text
  38  deploy/explorer/             # Caddy + nginx + systemd for explorer.coincync.network
   4  deploy/ops/                  # PUBLIC ops scripts only — private ones gitignored
   3  deploy/landing/              # landing page (currently dormant)
   2  deploy/monitoring/           # Prometheus / alerting templates
   2  deploy/api/                  # api.coincync.network nginx config
   1  deploy/docker-compose.yml
   1  deploy/coincync-node.service
   1  deploy/bootstrap.env.example
```

### `coincync-wallet/` — 87 files (Tauri shell)

```text
  src/                Preact + Vite frontend
  src-tauri/          Rust backend, *minus* target/, *minus* sidecar binaries
  public/fonts/       Webfont assets
  scripts/            Build helpers
  package.json + lockfile, Tauri configs, README, BUILD.md
```

Excluded: `node_modules/`, `dist/`, `src-tauri/target/`, `src-tauri/resources/binaries/*`.

### `website/` — 58 files (marketing site, deployed to coincync.network)

```text
  index.html          Main landing page (with theme switcher, mark-rolodex,
                      countdown, "Built on" primitives grid, etc.)
  brand.html          Brand assets / press kit
  faucet.html         Testnet faucet UI
  banner.svg          Site banner
  assets/             Logo + 12 wallpapers (landscape + portrait variants)
```

### `.github/` — 7 files (CI workflows)

```text
  .github/workflows/release.yml                Triggers on tag — builds signed bundles
  .github/workflows/integration-tests.yml      Full test suite on PR
  .github/workflows/critical-lock.yml          Constitutional integrity check
  .github/workflows/hardening-baseline.yml     Security regression suite
  .github/workflows/build-wallet.yml           Tauri wallet build
  .github/workflows/community-bootstrap.yml    Bootstrap manifest CI
  .github/workflows/best-practices-policy.yml  Doc coverage / lint policy
```

### Top-level files (13)

```text
  CONSTITUTION.md                Operative constitutional law (lockfile-protected)
  CONTRIBUTING.md                What we welcome / what we won't accept
  README.md                      Project overview
  LICENSE                        MIT
  CHANGELOG.md                   Release notes
  WALLET_INTEGRATION.md          Wallet / explorer integration notes
  Cargo.toml                     Workspace manifest
  Cargo.lock                     Pinned dep versions (committed for reproducibility)
  build.rs                       Constitutional integrity check at build time
  critical_files.lock            SHA-256 lockfile for consensus + Constitution
  Dockerfile                     Container build (used by deploy/)
  .gitignore                     Excludes ops/private/runtime files
  .cargo/audit.toml              Cargo-audit policy
```

---

## ⛔ What's NOT going to GitHub (gitignored)

The `.gitignore` is comprehensive (156 lines). High-confidence exclusions:

### Build + runtime artifacts

- `/target/` (all Rust build output)
- `*.exe`, `*.dll`, `*.so`, `*.dylib`, `*.pdb`
- `*.tar.gz`, `*.zip`, `*.tgz`
- `release/**/coincync-{node,miner,wallet,tui-miner,tui-operator}-*` (binaries via GitHub Releases)
- `release/**/SHA256SUMS.txt`
- `coincync-wallet/node_modules/`, `coincync-wallet/dist/`, `coincync-wallet/.vite/`
- `coincync-wallet/src-tauri/target/`, `coincync-wallet/src-tauri/resources/binaries/*`
- `*.log`, `nul`

### IDE / editor / tooling state

- `.idea/`, `.vscode/`, `.claude/`, `.cursor/`
- `*.swp`, `.DS_Store`
- `.cargo/config.toml` (machine-specific)

### Local data + backups

- `/data/`, `/node_data/`, `/db/`
- `/backups/`, `/logs/`, `/tmp-deploy-fix/`, `/tmp-testnet-snapshot/`
- `/Screenshot*.png`
- `/fuzz/target/`

### Internal ops scripts (private infra)

- `deploy/ops/coincync-miner-watchdog.*`
- `deploy/ops/fix-node-port-conflict.sh`
- `deploy/ops/miner-deep-log-check.sh`
- `deploy/ops/miner-liveness-check.sh`
- `deploy/ops/miner-log-check.sh`
- `deploy/ops/node-info-check.sh`
- `deploy/ops/read-diag.sh`
- `deploy/ops/template-check.sh`
- `scripts/fetch_testnet_rpc_key.sh`
- `scripts/lib/coincync_rpc_auth.sh`
- `scripts/setup_atl_miner.sh`
- `scripts/discord_*.py`
- `scripts/deploy.sh`, `scripts/deploy_all.sh`, `scripts/fix_systemd.sh`
- `scripts/recover_stale_nodes.sh`, `scripts/check_nodes.sh`
- `scripts/daily-health-check.sh`
- `scripts/wipe_and_restart.sh`, `scripts/wipe_chain.sh`

### Atomic-swap private artifacts

- `swap_*.json`
- `swap_*_SECRET.json`

### Internal-only docs

- `docs/BLOCKCHAIN_FEATURE_BEST_PRACTICES.md`
- `docs/HARDENING_ROADMAP.md`
- `docs/AGGRESSIVE_TESTING.md`
- `docs/BEST_PRACTICES_BY_FILE.md`
- `docs/*_REPORT.md`
- `docs/book/`, `docs/pages/` (mdbook output, regenerated by CI)

### Jarvis / assistant code (entire surface, explicitly excluded)

```
.gitignore comment: "NEVER push to github"

  /OpenJarvis/
  /coincync-jarvis-bridge/
  /future-update/
  /coincync-wallet/jarvis.html
  /coincync-wallet/src/main-jarvis.jsx
  /coincync-wallet/src/JarvisStandaloneApp.jsx
  /coincync-wallet/src/pages/Jarvis.jsx
  /coincync-wallet/src/components/Jarvis*.jsx
  /coincync-wallet/src/utils/jarvis*.js
  /coincync-wallet/src/utils/jarvis*.test.js
  /coincync-wallet/src/utils/agentNamePolicy.js
  /coincync-wallet/scripts/dev-jarvis.ps1
  /coincync-wallet/scripts/dev-jarvis.sh
```

---

## 🟡 Tracked files with public-but-mappable info

These are NOT secrets, but they map operational topology. Flagged for awareness, not for redaction:

### Fleet IPs in `src/testnet.rs` and `src/explorer/index.html`

```
  66.135.23.193     seed1   (New Jersey)
  140.82.57.168     seed2   (Amsterdam)
  207.148.111.76    seed3   (Tokyo)
  207.148.6.50      explorer (Dallas)
  95.179.165.225    api     (Frankfurt)
```

These are seed nodes and explorer hosts. Anyone running a node *needs* to know these IPs to bootstrap. Public by design.

### Public testnet RPC endpoint

```
  https://api.coincync.network/rpc/testnet    (Cloudflare-fronted, bearer auto-injected)
```

Public access by design.

### Constitutional bearer pattern

The bearer token strings appear as variables (`COINCYNC_RPC_API_KEY`) in many scripts. The variable references are fine; only the one hardcoded literal in `run-72h-soak.ps1` needs to be redacted.

---

## ✅ Pre-Push Checklist

Run through these in order before `git push origin main`:

- [ ] **Fix #1:** Replace hardcoded bearer in `scripts/run-72h-soak.ps1` with env-var read
- [ ] **Fix #2:** Replace fleet IPs in `docs/DEVELOPER.md` rollout snippet with placeholders
- [ ] **Commit both fixes** with a clear `pre-push: redact ...` commit message
- [ ] **Audit recent commits** for sensitive content in commit messages (memory paths, etc.) — `git log --oneline | head -50`
- [ ] **Verify gitignore coverage:** `git status -s | head` shows nothing surprising
- [ ] **Run smoke test** locally: `pwsh scripts/smoke-test-tx.ps1` → PASS
- [ ] **Verify build clean** on a fresh clone: `cargo build --release --workspace`
- [ ] **Verify tests pass** on a fresh clone: `cargo test --release --workspace`
- [ ] **Soak verdict** received and documented (Wed 2026-05-07)
- [ ] **Decide repo name** — recommend `coincync` (matches the brand)
- [ ] **Decide repo description** — one-liner for the GitHub heading. Suggested: *"Privacy-first proof-of-work payments coin. RandomX. CLSAG. Hard-capped supply. 30% fee burn. Constitutionally bound."*
- [ ] **Create the GitHub repo** (public, no template, no README — we have one)
- [ ] **Push:** `git remote add origin <url>` → `git push -u origin main` → `git push --tags`
- [ ] **Verify Actions tab** runs `release.yml` for `v1.0.2-testnet` → produces signed Windows + macOS bundles
- [ ] **Update website + Discord links** to point at the new repo URL
- [ ] **Post launch announcement** (drafts in `docs/launch/TESTNET_LAUNCH_ANNOUNCEMENT.md`)

---

## What this list is for

This document exists so that the moment of "create the public repo" isn't a leap of faith. Every file that goes public has been reviewed against this inventory; everything that stays local has an explicit `.gitignore` rule and a stated reason. If you're reading this *after* the first push: this is the historical baseline of what was made public on day 1, useful for any future "wait, when did X become public?" question.

Generated alongside the pre-launch readiness review on 2026-05-04. Last refreshed: see git log.
