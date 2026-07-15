# Changelog

All notable changes to CoinCync are recorded here.

## 2026-05-18 — Apple-style discipline shift (docs only, no code changes to production)

Internal organizational change to release + roadmap discipline. No protocol changes, no consensus changes, no behavior changes.

- **Locked one-sentence promise:** "Privacy money that requires no permission." Used in README, doc index, security policy, contributing guide, wallet integration guide. See [README](README.md) header.
- **Public roadmap discipline:** new [docs/roadmap.md](docs/roadmap.md) — only v1.1, v1.2, v1.3 are documented as release commitments. Anything past v1.3 is research, not roadmap.
- **CIP register reorganized** ([docs/cip/README.md](docs/cip/README.md)) into 3 sections: Currently shipping toward v1.1 / Active design / Sketch (research).
- **CIP-002 (CyncHub) reverted to Sketch** — earlier same-day promotion to Draft was rolled back under Apple-style "no commitment past the next 3 releases" discipline. CyncHub V1 design captured for future reconsideration (v1.3+ conditional).
- **Cyncswap design path locked** in [docs/decisions/2026-05-18-cyncswap-path.md](docs/decisions/2026-05-18-cyncswap-path.md): adaptor-signature + DLEQ design retained, hash-locked-stealth alternative explicitly rejected.
- **6-layer user-safety stack** specified in [docs/cyncswap-user-safety.md](docs/cyncswap-user-safety.md): $500 V1 per-swap cap, mandatory watchtower default, refund-by-default architecture, circuit breakers + kill-switch advisory, triple-backup state + recovery, dual audit + bug bounty + slow rollout.
- **Audit-alignment plan** in [docs/cyncswap-farcaster-comit-alignment.md](docs/cyncswap-farcaster-comit-alignment.md): 5-step plan to align cyncswap with Comit + Farcaster prior art, cutting audit cost ~50%.
- **Canonical doc home:** new [docs/INDEX.md](docs/INDEX.md). Anything not linked from there is internal.
- **Refusal list:** new [docs/explicitly-not-doing.md](docs/explicitly-not-doing.md) — 30+ features CoinCync will not add, organized into 6 categories. The discipline is the product.
- **CyncHub skeleton crate** scaffolded at [crates/cynchub/](crates/cynchub/) — Sketch status, 15/15 stub tests pass; not on any committed release. Code lives so future-V1.3 work has a starting place if/when the entry criteria are met.
- **Cyncswap external-vector harness** scaffolded at [crates/coincync-swap/tests/external_vectors.rs](crates/coincync-swap/tests/external_vectors.rs) — Comit + Farcaster vendor vector dirs created; vectors not yet imported (Step 1 of alignment plan).
- **docs/BLOCKCHAIN_ROADMAP.md repositioned** as the technical update log + cross-CIP sequencing notes (not the authoritative roadmap — docs/roadmap.md is).

## How to read this changelog

Entries are grouped by category so you can scan for just the kind of
change you care about:

- **Added** — new features and capabilities.
- **Changed** — changes to how existing features behave.
- **Optimized** — performance and resource-use improvements with no
  behaviour change.
- **Fixed** — bug fixes.
- **Security** — vulnerability fixes and dependency security patches.
- **Deprecated** / **Removed** — features on the way out, or gone.

Each entry carries the commit hash(es) so you can trace it to source.
This category structure begins with the May 12–13, 2026 entry below;
earlier entries use the prior topical structure and are kept verbatim
for the historical record.

The format follows the "Keep a Changelog" convention
(<https://keepachangelog.com>), with one CoinCync-specific addition —
the **Optimized** category — because performance work on a
proof-of-work privacy chain is frequent enough to deserve its own
scan target, separate from behavioural **Changed** entries.

## Unreleased — post-launch hardening (May 12–15, 2026) — v1.0.8

Nine commits over May 12–13 plus four slice commits on May 15 covering
the first phases of the post-launch fix campaign agreed after the
v1.0.7-testnet release. No consensus break in this batch — block
validation rules and transaction format are unchanged. (The
`MIN_OUTPUT_AGE` 10 → 100 hard fork is deferred to v1.0.9 with a
coordinated activation height; see `out/v1.0.9-plan.md`.)

### Added

- **Prometheus `/metrics` endpoint — real metrics replace the 1.0
  trim's noop stubs** (`2a8af30`) — `src/metrics.rs` now registers a
  real `prometheus::Registry` with four histograms covering the hot
  paths flagged by the `benches/crypto_hot_paths.rs` baselines:
  block-receive-to-tip, tx-admit-to-mempool, peer-handshake
  (Noise XX + Version exchange), and RandomX-hash. The six existing
  Dandelion++
  counters (`epoch_rotations_total`, `current_epoch_mode`,
  `embargo_fluffs_total`, `stem_relays_total`,
  `fluff_broadcasts_total`, `stempool_size`) are preserved unchanged
  — no caller code touched.
- **Metrics scrape endpoint on `RPC_PORT + 1`** (`2a8af30`) —
  `coincync-node` now spawns an `axum` HTTP server bound to
  `127.0.0.1` at one port above the JSON-RPC port (e.g. RPC 28081 →
  metrics 28082) that responds to `GET /metrics` with the standard
  Prometheus text exposition format. Localhost-only by design; if you
  want remote scraping, front it with a reverse proxy that adds auth.
- **`PEER_HANDSHAKE` histogram** (`11e6b8e`) —
  `PeerInfo::connected_at: Instant` is captured at peer insertion and
  observed when `Verack` lands. Catches slow handshakes
  (hostile-but-slow peers, congested networks) at the histogram
  bucket boundaries 10ms / 50ms / 100ms / 250ms / … / 10s.
- **Constant-rate cover-traffic broadcast loop activated**
  (`11e6b8e`) — `P2PNode::start` spawns `run_padding_loop_broadcast`
  so the default config (`TrafficShaperConfig::default` has
  `padding_enabled = true`) emits padding to all connected peers.
  This is the 4th-Amendment defence layer that prevents a passive
  observer on the network path from telling an idle node from one
  actively relaying transactions. The jitter + size-normalisation
  components were already shipping; this finishes the third leg.
- **FROST coordinator in the reproducible Docker builder**
  (`11e6b8e`) — `docker/builder.Dockerfile` now builds `coord` +
  `coord-cli`, the threshold-signature coordinator that backs the
  M-of-N multi-sig wallet path, alongside `coincync-node` inside the
  reproducible builder image. Required `--features "server cli"` per
  the coordinator crate's `required-features` declaration.
- **Storage-side reorg checkpoint/rewind for the three Phase-2 trees**
  (`ef4f48c`) — `ShieldedStore`, `SparkStore`, and `KernelStore` each
  gain `checkpoint_at_height` and `rewind` methods backed by a parallel
  checkpoint stack (interp-B contract: checkpoint taken BEFORE the
  block's appends, rewind restores to the popped checkpoint). The
  shielded tree gates its parallel-stack push on the `BridgeTree`'s
  `tree.checkpoint()` return value so the stacks stay in sync. A new
  `compute_root` helper makes root computation consistent across the
  `new()`, `open_with_db`, and `add_*` paths. `MAX_REORG_CHECKPOINTS`
  raised 100 → 1000 to cover the testnet `max_reorg_depth = 1000`.
  Stores remain `None` at chain construction — dormant in production,
  this is the prerequisite for future Phase-2 activation. 42 new tests:
  cap-boundary, multi-cycle persistence, high-volume stress
  (4000+ coins), hand-rolled LCG fuzzers, and concurrent read/write.
- **`checkpoint_phase2_stores` / `rewind_phase2_stores` helpers in
  `chain.rs`** (`ef4f48c`) — call into each of the three optional
  stores when present, no-op otherwise. Wired into 5 reorg-relevant
  call sites: accept after `height_to_hash.insert` (BEFORE the
  DB-persist break point — a placement fix found via audit), DB-error
  rollback, and the reorg disconnect / connect arcs. Integration test
  `phase2_stores_rewind_together_through_helpers` exercises the cycle.
- **CIP-011 rolling-finality machinery (feature-gated, default OFF)**
  (`ef4f48c`) — `src/consensus/rolling_finality.rs` ships a
  `RollingFinality` adapter wrapping the existing `FinalityTracker` +
  `Ed25519Verifier` from the `coincync-rolling-finality` workspace
  crate. `Blockchain` gains a `rolling_finality: Option<RollingFinality>`
  field, an `on_accepted_block` notify call, and a reorg-rule check
  that refuses a reorg below the soft-final tip when the feature is on
  and past the enforce height. Four height constants in `constants.rs`:
  testnet enables at 50,000 and enforces at 75,000; mainnet enables at
  25,000 and enforces at 50,000. 8 unit tests pass. Flipping the
  cargo feature on at the enable height is a future testnet-only
  operation.
- **`RANDOMX_HASH` histogram observation site** (`24b22b7`) —
  `src/consensus/pow.rs` wraps the `compute_pow_hash` call in
  `crate::metrics::RANDOMX_HASH.start_timer()` so RandomX hash latency
  shows up at `/metrics`. Closes the last unobserved hot-path histogram
  in the four-set shipped this campaign.
- **Wallet + node opt-in update check (Monero posture)** (`12edf66`) —
  user-invoked only, no automatic poll. `coincync-node check-update`
  CLI subcommand mirrors the wallet's `check_for_update` Tauri command:
  both query `/releases/latest` first and fall back to
  `/releases?per_page=1` when the "Latest"-badged endpoint 404s (every
  CoinCync release is currently flagged prerelease). The wallet adds
  an "Updates" section to Settings → General with a toggle defaulting
  to OFF, a `window.confirm()` privacy warning that fires only on
  opt-in, and a "Check now" manual button for one-off checks without
  enabling the auto-poll. Startup auto-check in `App.jsx` runs at most
  once per session via a `useRef` guard, gated on `appState ===
  "unlocked"`, backend availability, and `loadSettings().checkUpdates
  === true`. Errors are silent (`console.warn` only) — a wallet launch
  should not raise a popup just because GitHub blipped.

### Changed

- **`MessageType::Padding = 99` replaces the `PADDING_MAGIC` hack**
  (`11e6b8e`) — retires the unreachable `PADDING_MAGIC = 0xDEADBEEF`
  hack that conflicted with the framer magic and never reached
  message processing in practice. Cover packets now flow through the
  framer like any other message and are silently discarded in
  `process_message` after the type-byte parse.
- **Block and transaction processing routed through async
  `spawn_blocking` wrappers** (`2a8af30`) — triage of the `2026-05-12
  16:18 UTC` 13-minute API-box stall found block-validation and
  mempool-admit running synchronously on tokio worker threads,
  holding `parking_lot` write locks across multi-second crypto-verify
  passes. Layer 1 (commit `5c98bae`, pre-campaign) was a defensive
  `worker_threads = 4` floor; this is the structural fix. Six new
  `Blockchain::*_async` methods (`add_block_async`,
  `process_block_async`, `get_block_async`, `get_chain_state_async`,
  `tip_height_async`, `tip_async`) and the matching
  `SharedMempool::{add_with_chain_async, get_block_transactions_async}`
  use `self: Arc<Self>` + `spawn_blocking` to route PoW recheck,
  ring-signature verify, range-proof verify, and RocksDB writes off
  the worker pool. The `BlockReceived` and `TransactionReceived`
  handlers in `src/bin/node.rs` were migrated to the async wrappers,
  replacing inline `spawn_blocking + panic-handling` boilerplate;
  `JoinError` now maps to `Error::Internal(...)` and is caught by the
  existing `Err(e)` arm. Resolves the documented 2026-05-12 stall.

### Security

Eighteen dependabot alerts closed: 1 critical, 6 high, 9 medium, 2
low. Production attack surface fully cleared.

- **`openssl 0.10.77 → 0.10.79`** in the Tauri wallet (`38c0c4c`) —
  closes a Nov-2026 batch of 5 high-severity advisories in the
  rust-openssl bindings (CVE-2026-41676 derive buffer overflow,
  CVE-2026-41678 AES key-wrap bounds, CVE-2026-41681 digest_final OOB
  write, CVE-2026-41898 PSK/cookie trampoline length, CVE-2026-42327
  X509Ref OCSP UB) plus 1 medium (AES key-wrap heap overflow) and 1
  low (PEM password callback OOB). Pulled in via `reqwest →
  hyper-tls → native-tls`. Patch-level bump, semver-compatible, no
  Cargo.toml edits.
- **`fuzz/Cargo.lock` refreshed** (`44d147b`) — closes CVE-2021-38195
  (libsecp256k1 0.3.5 overflow, critical — the package is gone from
  the dep graph entirely post-refresh) and GHSA-82j2-j2ch-gfr8
  (rustls-webpki DoS via panic on malformed CRL BIT STRING, high —
  bumped 0.103.12 → 0.103.13). The fuzz lockfile had drifted far
  enough that `cargo tree` couldn't run without a relock; this is
  pure catch-up churn for the dev-only fuzz harness, no production
  binary impact.
- **Unused `jsonwebtoken` dep removed** (`ccbed53`, `f249bd6`) —
  closes CVE-2026-25537 (type confusion → authorization bypass) in
  both production and fuzz lockfiles. The crate was declared in
  `Cargo.toml`'s RPC-extras block but had zero call sites anywhere in
  `src/`, `benches/`, or `bin/` — a leftover placeholder for a
  planned auth-on-RPC feature that never landed. Removing it dropped
  94 lockfile lines (47 production + 47 fuzz: jsonwebtoken plus its
  older ring 0.16 transitive chain).
- **Unused `vitest` devDep removed** (`02d0bbc`) — the wallet
  declared `vitest: ^2.1.9` plus a `test: vitest run` script, but no
  test files exist anywhere in `coincync-wallet/src/`. Likely
  Vite-React scaffolding leftover. Removing it dropped 1829 lines
  from `package-lock.json` (vitest + @vitest/mocker + vite-node and
  their nested vite 5.4.21 + esbuild 0.21.5 copies). Reduces
  dev-attack surface; closes 3 dev-tool alert chains.

**Remaining after this batch — 7 dependabot alerts, all dev-only or
stale:** 4 npm vite alerts targeting vite 7.x/8.x (the lock has vite
4.5.14 and 5.4.21, neither in the alerts' vulnerable ranges — stale,
should auto-close on the next rescan); 1 esbuild medium (real,
transitive of vite 4.5, `npm run dev` only — never in the shipped
wallet binary; closing requires a breaking vite 4 → 7 major bump); 1
glib medium in the Tauri wallet Cargo.lock (requires a Tauri major
upgrade); 1 rand low (alert lists `== 0.10.0` but neither lockfile
has rand 0.10.0 — stale).

## Unreleased — launch readiness (May 8–9, 2026)

A second pre-launch session of 27 commits, complementary to the
multi-phase code expansion below. Focus: surface area + operations,
not protocol code. Goal: every public path a Monday-2026-05-11
visitor will hit responds correctly with current data.

### Explorer block-detail enrichment

- **5 new privacy-feature cards** (eb35986) — FROST M-of-N
  multi-sig (CIP-008), CYNC↔BTC atomic swap (CIP-001),
  light-wallet SPV, rolling soft-finality (CIP-009.D),
  multi-node Dandelion++ verification. Each card carries an
  animated 280×160 SVG visualisation matching the existing
  CLSAG / Pedersen / Bulletproofs+ style.
- **"What it's for" explainers** (3c62d97) on all 11
  block-detail privacy cards. Plain-language paragraphs answer
  "why does this exist" so a non-cryptographer skimming a block
  page learns the mechanism without clicking through to docs.

### Bug-hunt second pass — 7 fixes

Found via aggressive review of the new code introduced in the
prior session. None were exploitable in production paths but
each could surface under load or persistence-failure conditions.

- **swap/HandshakeAction** (62ae62a) — replaced
  `Send(Message::Abort{placeholder})` at three "caller must
  invoke X next" sites with a new `WaitForCaller { next_call }`
  variant. A naive transport that piped `Send` payloads to the
  wire would have transmitted the placeholder Abort and killed
  the handshake.
- **finality/attestations** (8442ffb) — `record_block` now
  prunes attestation entries below `chain_tip - stale_horizon`
  via `BTreeMap::split_off`. Was an unbounded growth path.
- **swap/Bob-Negotiated arc** (0448cdd) — added
  `Transition::ObserveAliceLocked` so Bob's chain watcher can
  advance Negotiated → AliceLocked through `apply()` instead of
  poking `bob_swap.state` directly.
- **swap/persist-rollback** (6ec5c8d) — `cancel_cmd` switched to
  clone-then-commit so a failed `store.save` doesn't leave
  in-memory state ahead of disk.
- **network/GetFilterCheckpoints** (cff56f8) — capped at
  `MAX_CHECKPOINTS=1000` per request. The handler did
  per-iteration disk reads + filter recomputation with no upper
  bound; any peer could amplify a single request into
  O(chain_height) work.
- **persistence/parent-dir fsync** (833c838) — both
  `SwapStore::save` and `SessionStore::save` now fsync the
  parent directory after `rename`. Without it, a crash after
  rename(2) but before the dentry is flushed could lose the
  rename even though the data file is durable.
- **tests/MutexGuard-across-await** (22b8d7f) — `env_lock` in
  `tests/rpc_endpoints.rs` switched from `std::sync::Mutex` to
  `tokio::sync::Mutex`. Holding a std MutexGuard across `.await`
  is unsound (guard is `!Send`); the test was getting away with
  it but only by accident.

### Constitution

- **Fourth-Amendment foundation appendix removed** (9559b8c).
  CoinCync is jurisdiction-neutral; anchoring the privacy stack
  to a US-specific 1791 legal text narrowed the audience without
  adding cryptographic substance. The 19 Articles + 15 Rights
  stand on their own. `critical_files.lock` updated to the new
  hash; `cargo check` green.

### Discord — full-server refresh

- **Discord refresh kit** (41f8f4e) — `docs/launch/DISCORD_REFRESH.md`,
  copy-paste-ready text for every Discord surface (server desc,
  41 channel topics, 8 pinned messages, role descriptions,
  status webhook templates).
- **Bot tooling shipped** (50d6a57, b2da99c) —
  `scripts/discord-refresh.py` (single-script bot driver with
  no external deps) and `scripts/discord-cleanup.py`
  (companion that unpins + optionally deletes stale pins).
  Both stdlib-only Python; bot token via `DISCORD_BOT_TOKEN`
  env var, never committed.
- **Live execution** — server description updated, 41 channel
  topics set, 8 pinned messages posted in the major channels
  (#announcements / #node-setup / #mining-help / #testnet /
  #mining-general / #wallet-help / #faq / #network-health),
  7 stale pins unpinned + their messages deleted from history.
- **Answer cheatsheets** (9c1af7a, bc8b7c3) — two reference
  docs for launch-day support: `DISCORD_ANSWER_CHEATSHEET.md`
  for in-server questions, and `REPLY_CHEATSHEETS.md` with
  per-venue tone (Twitter / Reddit / BitcoinTalk / HN / lobste.rs).

### Website

- **Bug-bounty payout cards removed** (2145416). The
  $5K-$50K-by-tier marketing was unfunded; replaced with a
  responsible-disclosure note that says plainly we don't have a
  paid program yet, will launch one alongside the third-party
  audit before mainnet. Original 4-card markup preserved in
  the HTML comment marker `FUNDING-GATED`.
- **Faucet link rewrites /faucet.html → /faucet** (adf803d).
  The `.html` variant 308-redirects with a broken `Location`
  header; PowerShell IWR can't follow it and some browsers /
  SDKs choke. Sweep across website, explorer, the launch
  announcement, both Discord cheatsheets, and `release/README.md`.
- **Docs link rewrites .html → no-extension** (cb85c39). Same
  308-redirect pattern on docs.coincync.network. 8 homepage
  links rewritten.

### GitHub repository

- **Public mirror published** at
  `github.com/Coincync/Coincync-Testnet-`. 669 files
  pushed; 27 session commits visible in main.
- **Branch + tag rulesets imported** (11eed02) —
  `release/github/main-protection-ruleset.json` (block
  deletion, block force-push, require linear history, require
  signed commits, require PR before merge with 0-reviewer
  for solo work) and `release/github/tag-protection-ruleset.json`
  (block creation/deletion/update of `refs/tags/v*` for any
  account except Admin). Both bypass for `actor_id: 5`
  (Admin role) so the maintainer can override in an emergency.
- **Community files** (a7ca952, 0125dee) —
  `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 with
  project-specific additions: pseudonymity is a Right per
  Right V; no price talk on testnet channels; no coordinated
  brigading). Plus `.github/ISSUE_TEMPLATE/` (bug_report,
  feature_request, config.yml that disables blank issues and
  routes security to `security@coincync.network`) and
  `.github/PULL_REQUEST_TEMPLATE.md` and `.github/dependabot.yml`
  (cargo + Tauri Rust + Tauri JS + GH Actions, weekly).
- **SSH commit signing wired up locally** with `id_ed25519`
  registered as a Signing Key on GitHub. Test commits
  verified locally via `gpg.ssh.allowedSignersFile`. The
  rulesets enforce signed commits on `main`; admin bypass
  active until propagation.

### Cloudflare / DNS / serving

- **Origin TLS to Full (strict)** — Cloudflare Origin Certs
  installed at `/etc/nginx/ssl/origin{,.network}.crt` on the
  explorer box. Two certs (one per zone) because each was
  generated for a single zone and the dashboard's hostname
  auto-append produced bogus SANs when crossing zones. nginx
  selects via SNI. Plan: regenerate a single clean cert later.
- **deploy-explorer-nginx.ps1 hardened** (abd05b1, 196031d,
  09b6ec4) — IPv6 `listen [::]:80` and IPv6
  `listen [::]:443 ssl`, cert precheck (fails fast if certs are
  missing rather than half-installing a config nginx can't
  load), and `/health/*` proxy routes baked into the canonical
  config (the dashboard was breaking after every redeploy
  because the separate-script-patches were getting wiped).
- **`releases.coincync.network` set up** — DNS A record →
  `207.148.6.50`, nginx server block on the origin serving
  `wallet/latest.json` with CORS open. Auto-update chain
  verified end-to-end: wallet poll → DNS → nginx → JSON →
  GitHub Releases v1.0.2-testnet → SHA-256 verify of the
  Windows installer matches the hash baked into the manifest.
- **`git.coincync.network` redirect set up** — DNS A record
  added; nginx 301 with path preservation
  (`/coincync/cync-protocol/blob/main/build.rs` →
  `github.com/.../blob/main/build.rs`). Lets the
  ~25 references in launch materials and `book.toml`
  resolve cleanly without sweeping every file. Replaceable
  with a real Forgejo install later.

### Faucet — operational fix + funding

- **Wallet RPC auth path fixed** (4f140cd) —
  `FAUCET_NODE_RPC` rewritten to point at the local nginx
  `/rpc/testnet` route, which adds the Bearer header
  server-side. The wallet CLI has no `--rpc-key` flag, so
  direct calls to port 28081 returned 401 Unauthorized after
  RPC auth was hardened, which made every drip silently exit 1.
  Knock-on effect: with the wallet unable to talk to the node,
  its auto-scan never refreshed UTXOs from chain, so even after
  fixing auth the wallet had a stale UTXO set and refused to
  build a privacy-uniform 2-in tx. Both layers cleared during
  pre-launch verification.
- **Wallet topped up + faucet drip verified** end-to-end. After
  fleet-wide hashrate boost (api + 3 seeds) advanced the chain
  259 blocks, 18 mining payouts confirmed at the faucet. Real
  drip POST returned `{"success":true,"tx_hash":"d2074b0a..."}`.
  Rate-limit verified: second drip to the same address returned
  429 with `retry_after_secs: 3535`.

### Pre-launch test sweep

Six items from the launch-blocker punch list, all closed:

- **A1** wallet flow on a clean machine: ✓
- **A2** faucet drip end-to-end: ✓ (1147 CYNC across 21 UTXOs,
  ~114 drips of capacity)
- **A3** miner-onboarding stranger walkthrough: ✓
- **A4** explorer load test: ✓ (5444 RPS sustained, p99 22 ms,
  zero errors)
- **A5** SHA256SUMS hosted on Pages + GitHub Releases: ✓
- **A6** auto-update chain end-to-end: ✓

### Stats

- 35+ commits; ~5000 lines added, ~80 lines removed
- 1098 workspace tests; 0 regressions; cargo audit reports
  0 vulnerabilities across 742 dependency crates
- All 12+ public launch URLs return 200; mining-onboarding URLs
  now point at the GitHub Releases v1.0.2-testnet assets that
  actually exist (8 assets after operator drag-uploaded
  `coincync-rig.exe` + `coincync-tui-miner.exe`)
- 5 fleet nodes synced
- Two cron-driven monitors live (faucet balance every 15 min on
  api box; fleet health every 5 min on explorer); both alert via
  Discord webhook on threshold violation
- Reproducible-build Dockerfile + wrapper script + .dockerignore
  shipped at `docker/builder.Dockerfile` and `scripts/build-in-docker.sh`
- Public status page deployed at <https://coincync.network/status>
- Troubleshooting documentation page added at
  <https://docs.coincync.network/troubleshooting>
- Pre-launch checklist at `docs/launch/MONDAY_PRELAUNCH.md`

---

## Unreleased — pre-mainnet workspace expansion (May 8, 2026)

This window spans 23 commits between `v1.0.2-testnet` and the
public testnet launch on 2026-05-11. The work is structured into
three multi-phase tracks plus operational-readiness docs and
launch-prep polish. Nothing here is consensus-affecting; all
additions live in feature-gated workspace crates or in `docs/`.

### Three multi-phase code tracks

Each track follows the same shape: a pure state-machine library
(phase 1), then real cryptography or codec (phase 2), then
persistence (phase 3), then runtime / integration (phase 4+),
each layer feature-gated and independently testable. The pattern
keeps the audit perimeter minimal — the state machine ships to
auditors as ~500 LOC of pure logic; the wire / I/O layers are
add-ons.

#### FROST coordinator (CIP-008) — `crates/coincync-frost-coordinator`

- **Phase 1** (286cc40) — pure session state machine: `Session`,
  `Transition`, terminal-stickiness invariant. 11 tests
  (8 unit + 3 proptest).
- **Phase 2** (9e9729b) — invitation-token authentication via
  HMAC-SHA256 over (session_id || pubkey || expiry), feature
  `invitations`. Constant-time MAC compare via `subtle`.
  14 tests.
- **Phase 3** (1e20b8e) — JSON-file session persistence with
  atomic temp-file-and-rename writes, feature `persistence`.
  Schema-versioned with loud-failure on mismatch. 13 tests.
- **Phase 4** (b2f23ac) — WSS server bin `coord` wraps the
  in-process state machine in a real network transport. JSON
  request/response, per-session pub/sub broadcasts, persistence
  on every accepted transition, graceful SIGINT shutdown,
  MAX_CONNECTIONS=1000, MAX_MESSAGE_BYTES=16 KiB.
  Feature `server` (composes `invitations` + `persistence` +
  tokio + tokio-tungstenite). 7 bin tests.
- **Phase 4.5** (bf9fc06) — operator CLI `coord-cli`. Sync,
  no async runtime. Subcommands: `gen-secret`,
  `create-session`, `mint-invitation`, `list`, `inspect`,
  `force-abort`, `gc-terminal`. Feature `cli`. 6 bin tests.
- **Phase 5** (0e94dea) — full-flow integration test composing
  state + invitations + persistence through realistic 2-of-3
  signing flow + adversarial cases (cross-session token
  rejection, expired tokens, unattached-participant rejection,
  double-submit rejection, terminal-stickiness through reload,
  crash recovery). 8 integration tests.
- Side fix: `ParticipantId` now serializes as 64-char hex string
  so it works as a JSON map key (was failing
  `BTreeMap<ParticipantId, _>` round-trip).
- Operations spec: **CIP-012** (18e00c7) — deployment
  rehearsal, two-instance mainnet plan, six failure-mode
  runbooks.

**Total: 59 FROST tests across 4 binaries + lib + integration.**

#### Rolling soft-finality (CIP-009.D) — `crates/coincync-rolling-finality`

- **Phase 1** (05c4c74) — `FinalityTracker` state machine,
  `ActiveMinerSet` rolling window, monotonic soft-final tip,
  2/3 Byzantine threshold semantics, `MIN_QUORUM=5` gate.
  Property-tested across: terminal-state stickiness, threshold
  exact-fire, dual-fork tolerance. 19 tests
  (5 active_set + 11 finality + 3 proptest).
- **Phase 2** (7292682) — feature `ed25519` adds real
  `Ed25519Verifier` via `ed25519-dalek`; feature `wire-codec`
  adds borsh-serialized on-chain attestation format with magic
  prefix `b"CIP9"` + version byte. 17 tests
  (8 verifier + 9 codec).
- **Integration test** (421016e) — full composition with REAL
  ed25519 signing throughout (unlike FROST/swap which use
  opaque bytes; rolling-finality's security depends on the
  verifier hooking up to the codec correctly).
  11 integration tests.
- Spec: **CIP-009.D** (e394811) — design (replaces rejected
  MESS, layered with shipped Path B). **CIP-011** (67dcd0c) —
  two-phase activation rehearsal (ENABLE → ENFORCE) with five
  recovery scenarios.

**Total: 47 rolling-finality tests.** Phase 3 (`validate_block`
hook) is queued; touches integrity-locked consensus files and
needs CIP-007 Mode A activation.

#### Atomic swap (CIP-001) — `crates/coincync-swap`

- **Protocol state machine** (6f8c5e7) — `Swap`, `Transition`,
  `SwapParameters`. Asymmetric role gating (Alice / Bob),
  refund-path safety, terminal-stickiness, **timeout-safety
  invariant** (`btc_timeout_secs * 6/5 < cync_timeout_secs`)
  enforced at construction time. 17 tests.
- **Handshake state machine** (1caf02c) — `coordinator.rs`
  upgraded from `NotImplemented` stub to a fully-functional
  message-protocol layer. `Message` enum (Hello / HelloAck /
  Accept / AdaptorMaterial / Ready / Abort), `Phase` state,
  `HandshakeAction` (Send / Done / VerifyAdaptorMaterial /
  Aborted). 12 tests.
- **State persistence** (0377a41) — `SwapStore` mirroring
  FROST's `SessionStore`. Atomic temp-file-and-rename, schema
  versioning, idempotent delete, parent-directory creation.
  13 tests.
- **CLI integration** (5fdb7e6) — `cyncswap` binary upgraded
  from skeleton-mode to real load/save flow. `alice` /
  `bob` / `status` / `cancel` actually persist; `lock-cync` /
  `lock-btc` / `claim-btc` / `claim-cync` exit non-zero with
  clear "phase 3 implements this" notice.
- **Integration test** (c98e898) — full composition through
  every layer plus adversarial cases (refund safety from
  every lock state, crash recovery, terminal stickiness
  through reload, unsafe-timeout rejection at both layers).
  10 integration tests.

**Total: 52 atomic-swap tests.** Phase 3 (real adaptor sigs +
cross-curve DL proof + Tor/Noise transport) is queued for the
multi-week dedicated audit window.

### Operational-readiness pack (9f110ae)

Five docs, 1768 lines, no code:

- `SECURITY.md` — public security disclosure policy with
  90-day coordinated-disclosure window, safe-harbor language,
  pre-launch testnet hosts marked in-scope.
- `docs/cip/CIP-010-testnet-hardfork-rehearsal.md` — concrete
  activation playbook for the `BOOTSTRAP_MIN_RING_SIZE` 11→13
  bump, exercising CIP-007 Mode A end-to-end before mainnet.
- `docs/operations/REPRODUCIBLE_BUILDS.md` and
  `scripts/verify-build.sh` — pinned-Docker build environment
  and verifier script with PGP-signed manifest format.
- `docs/operations/INCIDENT_RUNBOOKS.md` — 9 runbooks
  captured from the actual testnet bring-up (chain stalled,
  fleet box behind, "have 0" UX panic, faucet recipients
  can't spend, Discord webhook silent, mempool full,
  explorer stale, integrity check, bulletproofs+ build
  errors).
- `docs/operations/STATUS_PAGE.md` — design for
  `status.coincync.network` with 3-state health banner,
  per-service uptime grid, real-time chain health, incident
  timeline.

### Launch-prep polish

- **Lightsync handler unparked** (95af7aa) — `GetOutputDigests`
  network handler + `get_output_digests` JSON-RPC handler.
  Light-wallet SPV path now actually works against running
  testnet nodes (was `log-and-drop` before). Closes Gap 1 + 4
  from `LIGHTSYNC_AUDIT.md`. Privacy posture is strictly
  stronger than BIP-157 (server learns only height range,
  never the wallet's address set).
- **Multi-node Dandelion++ harness** (32d7a9e) —
  `tests/dandelion_multi_node.rs` covers the *graph*
  behaviour where stem-and-fluff propagation lives. 6 tests:
  stem fan-out is exactly one (privacy invariant),
  stem-then-fluff completes, stem-loop detection triggers
  immediate fluff, fluff-epoch broadcasts immediately,
  embargo timeout fail-safes, diffusion confirmation clears
  stempool.
- **KNOWN_ISSUES.md sync** (6ff3b36) — moved bugs #4, #5,
  #7, ops #2 from OPEN to FIXED-in-`fd5a444`. The doc was
  stale.
- **CoinCync 2.0 → 1.0 sweep** (f5a53f3) — 22 doc-comment
  headers, 1 OpenAPI title, 1 explorer testnet-guide
  paragraph, 1 generated-config-template header. Three files
  deliberately kept (`.gitignore`, `src/metrics.rs`,
  `src/mining/miner.rs`) because their text contrasts the
  prior 2.0 version with the current codebase. Critical-
  file `constants.rs` hash refreshed.
- **disclosure.rs doc fix** (e341773) — single-line stale
  "2.0" reference; committed separately to keep the larger
  rename sweep auditable.

### Pre-launch sanity sweep (no commit, validation only)

Confirmed the FIXED-in-`9b83772` items still hold post-session:
`NoUtxoPairCovers` error type, O(n²) UTXO pair sweep,
`mark_spent_by_key_image` in `cmd_scan`, 2-pass mempool
shadow-eviction with `EvictReason::DoubleSpend`. OPEN items
still as documented: `BOOTSTRAP_MIN_RING_SIZE=11` (planned
hard fork), faucet drip-pair fee fingerprint (testnet-only
operational tradeoff). Full lib test suite (501 tests) +
multi-crate workspace build all clean.

### Roll-up

- 23 commits
- ~190 new tests across 11 modules
- 6 new feature gates: `ed25519`, `wire-codec`,
  `invitations`, `persistence`, `server`, `cli`
- 4 new binaries / first-time-functional binaries:
  `coord` (FROST WSS server), `coord-cli` (FROST operator
  CLI), `cyncswap` (now wired with persistence; was
  skeleton), `verify-build.sh` (reproducible build
  verifier)
- 5 new spec / runbook / policy docs
- 3 new CIPs: CIP-009.D (rolling finality protocol),
  CIP-010 (ring-bump testnet rehearsal),
  CIP-011 (rolling-finality activation rehearsal),
  CIP-012 (FROST coordinator deployment rehearsal)

### Outstanding work, queued for dedicated future sessions

These were intentionally NOT taken on in this window because
they each need multi-week focus + audit:

- **CIP-009.D phase 3** — wire `FinalityTracker` into
  `validate_block` behind a feature flag. Touches integrity-
  locked consensus files; requires `critical_files.lock`
  refresh and a real activation height per CIP-011.
- **Atomic swap phase 3** — adaptor signature primitives
  (BTC + CYNC sides), cross-curve DL-equality proof, BTC
  HTLC + CYNC tx construction, Tor / Noise transport. Per
  CIP-001 the timeline is 3-6 months focused work plus
  external audit.
- **FROST phase 6** — real `frost_ed25519` integration tests
  against the running coord, Prometheus metrics endpoint,
  per-IP rate limiting, connection idle timeouts, per-session
  invitation secrets.

### User-facing decision deck queued

- Approve / defer / reject **CIP-009.D + CIP-011** (rolling
  finality + activation playbook).
- Approve / defer / reject **CIP-010** (ring-bump testnet
  rehearsal).
- Approve / defer / reject **CIP-012** (FROST coordinator
  deployment).
- Schedule + budget **external cryptographic audit**
  (~$60-120k or focused single-firm review at $15-30k).
- Resolve uncommitted edit to
  `docs/launch/v1.0.2-testnet-soak-summary.md` (GO/NO-GO
  decision section deleted in working tree).

---

## v1.0.2-testnet (May 5, 2026)

### Public Repo + Fleet Migration

**Network:**
- 3-seed minimal-bootstrap fleet across 3 continents: New Jersey (US-East), Amsterdam (Europe), Tokyo (Asia-Pacific). Resolves via `seed1/2/3.coincync.network`.
- Migrated from DigitalOcean (locked-out 2026-05-02) to Vultr. Smaller fleet that exactly matches the DNS-seeded hostname set.
- Per-peer consecutive-empty-Blocks ban (threshold 5, duration 1h) — fixes the recurring IBD wedge pathology where one bad peer could stall sync indefinitely.

**Privacy stack (already in v1.0.0, restated for the public-repo cut):**
- CLSAG-16 ring signatures (11→16 bootstrap ramp at block 10,000) · Bulletproofs+ range proofs · stealth addresses · Pedersen commitments · Dandelion++ propagation · FROST hidden multi-sig · 7 advanced privacy features (decoy defense, encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead-man's switch, auto-churn).

**Governance & process:**
- 19-article Constitution + 15-right Bill of Rights, locked at compile time via critical-files SHA-256 hashes and 8 tripwire constants.
- CIP process documented: CIP-001 (CYNC↔BTC atomic swap, mainnet blocker) and CIP-002 (cynchub merge-mined liquidity layer) published as drafts.
- Public CIP register at `explorer.coincync.network/?p=proposals`.

**Public surfaces:**
- Source code public at <https://git.coincync.network/coincync/cync-protocol>
- Docs site rebranded to match the rest of CoinCync (Fraunces / IBM Plex / JetBrains Mono / gold accent on warm-dark).
- Landing site overhauled: removed competitive "Compare" section, added Get-Started two-path split (users vs developers), added 7-phase roadmap, updated faucet flow.
- Explorer: constitutional-status panel, live fee-burn counter, mempool fee histogram, globe block-propagation visualization, /api /soak /broadcast /leaderboard /privacymetrics /proposals pages.

## v1.0.0-testnet (April 21, 2026)

### Public Testnet Launch

**Chain:**
- New genesis: `41f970df6152425a2938725423235c2c40ec52556ecc0fd1422d588652cc56b4`
- Genesis message: "CoinCync Public Testnet - April 2026 - Trust the Math"
- 10-node curated bootstrap fleet across NA / EU / Oceania (DigitalOcean), 3 miners (LON, SFO, SYD)
  &mdash; later replaced by the 3-seed Vultr fleet documented under v1.0.2-testnet below
- Fast sync with 5 checkpoints (heights 100-500)

**Security Fixes:**
- C-8: Privacy policy bypass in skip_crypto path (Critical)
- C-9: Zero key image structural validation (High)
- H-15: Peer scorer validated flag (High)
- H-16: MESS hybrid reorg defense — 3-tier (High)
- H-18: Invalid key image curve-point validation (High)
- H-19: Invalid stealth address / commitment validation (High)

**Testing:**
- 947 automated tests, 0 failures
- 24 historical attack reproductions
- 17 MESS reorg defense tests
- 13 full-pipeline real-crypto tests
- 5-level chain verification script (Bitcoin Core verifychain style)
- 6 verification RPC endpoints

**Wallet GUI:**
- Local-first node connection (falls back to remote)
- Mining address auto-fills from wallet
- Miner output visible in terminal
- No hardcoded passwords
- Real fee estimates from mempool

**Infrastructure:**
- systemd auto-restart on all nodes
- nginx failover proxy for explorer
- Stale-data warning banner
- deploy.sh + wipe_and_restart.sh operational scripts
- Release binaries (Linux x86_64 + Windows x64)
- Faucet (10 CYNC per request)

**Documentation:**
- Consensus specification
- Security fixes documentation
- Getting started guide
- Node operator guide
- Mining guide
- Wallet guide
- Privacy model
- Chain verification guide
- Deploy runbook
- Audit scope document

### Previous (pre-public)

- Initial testnet with 6 nodes
- 806 tests
- 7 privacy innovations (decoy defense, encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead man's switch, auto-churn)
- FROST multi-sig
- Explorer with 9 themes + wallpaper picker
- Brass/gold brand redesign
