# CoinCync Roadmap

> Single source of truth for release planning. Read this if you want to know what's coming next, what's coming later, and what's deliberately out of scope until then.

**Last updated:** 2026-06-06
**Mainnet target:** 2026-10-01 00:00:00 UTC

This document covers the planned release sequence from the current testnet state through mainnet GA and into the post-mainnet point releases. Plans are subject to change as the project learns from the testnet, the [Crucible](CRUCIBLE.md) community testing program, and external review. Material changes land here via PR with rationale in the commit message.

---

## Where we are right now (2026-06-06)

| Item | State |
| --- | --- |
| Latest shipped testnet release | v1.0.10 (in fleet) |
| Tagged but not yet pushed | v1.0.11-canonical-clsag (in Crucible Cycle 01 testing) |
| In local development | v1.0.12 (consensus parameter refresh, scratch-chain validated) |
| Mainnet GA | 2026-10-01 00:00:00 UTC |
| Community testing program | [The Crucible](CRUCIBLE.md) — Cycle 01 active |
| Funding application | NLnet Commons Fund (cyncswap track) — first-round review |

---

## How to read this document

**Version cadence:**

- **v1.0.X** — pre-mainnet testnet point releases, each a focused theme. Consensus-breaking changes batched per release, never sneaked in.
- **v1.0.0 (mainnet GA)** — frozen consensus as of v1.0.16; tagged on 2026-10-01 launch.
- **v1.0.X post-GA** — bug fixes and non-consensus refinements only. No consensus changes without a CIP.
- **v1.1.X** — first major post-mainnet feature train. Currently scoped to atomic swaps (cyncswap).
- **v1.2.X** — second major train. Currently scoped to the Orchard shielded pool.
- **v2.0** — protocol-scale architectural changes. Currently scoped to warp sync (CIP-015 sketch).

**Status legend:**

- ✅ **Shipped** — code is in a published release
- 🟢 **In development** — code is being written or reviewed
- 🟡 **Planned** — scope is committed but work hasn't started
- 🔵 **Tentative** — likely to happen but timing/scope flexible
- ⚪ **Speculative** — listed for transparency, no commitment

---

## Pre-mainnet — v1.0.X testnet releases

### ✅ v1.0.0 — v1.0.10 (history)

The testnet history up to the current production state. Highlights:

- v1.0.6 / v1.0.7 / v1.0.8 — early functional milestones, wallet GUI installer first shipped in v1.0.8 (the most-downloaded asset to date by a wide margin)
- v1.0.9 — pre-audit checkpoint with full binary set
- v1.0.9.1 — chaindata-snapshot distribution introduced
- v1.0.10 — current fleet binary; reorg handling complete, 59 tests + 2,304 proptest cases all green; full testnet wipe to genesis on 2026-06-04

For exact tags and changelogs see [GitHub Releases](https://github.com/ghostrider1092/Coincync-Testnet-/releases).

### ✅ v1.0.11 — canonical CLSAG ring signatures

**Theme:** consensus-correctness fix to ring signatures.
**Status:** local branch + tag (`v1.0.11-canonical-clsag`), in Crucible Cycle 01 community validation.

CLSAG aggregate-coefficient formula now matches the canonical Monero CLSAG specification (Goodell, Noether, Blue 2020, eprint 2019/654):

- Both μ_p and μ_c are independent random-oracle outputs over the full input set including the commitment image D
- The pre-existing variant had no known concrete attack but didn't satisfy the forking-lemma → DL unforgeability reduction
- Net effect: the security argument now reduces cleanly to the published proof

Plus an audit-batch of non-consensus cleanups:

- SLIP-0044 `coin_type` migrated off the NEO collision (888 → 19166 provisional, pending upstream registration PR)
- Mempool persistence wired across restarts
- Per-IP connection tracker cleanup hook actually wired into the maintenance loop
- Per-peer message rate-limit table corrected (GetAddr / Addr were silently uncapped due to enum-discriminant drift)
- Several stale `#[allow(dead_code)]` markers and orphan duplicates removed
- London (192.248.151.16) removed from source after the orphan-chain incident; full post-mortem will live in `docs/operations/incidents/`

Decision docs: [`docs/decisions/2026-06-05-asert-halflife-rationale.md`](docs/decisions/2026-06-05-asert-halflife-rationale.md), [`docs/decisions/2026-06-05-coin-type-migration.md`](docs/decisions/2026-06-05-coin-type-migration.md).

### 🟢 v1.0.12 — ring ramp + MIN_OUTPUT_AGE activation

**Theme:** consensus parameter refresh.
**Status:** local development complete (scratch chain validated + in-vivo boundary test passed); awaiting Cycle 01 result before next-cycle bundle.
**Target:** late June 2026.

Two batched parameter changes:

1. **Ring-size ramp** — replaces the previous single hard cutover at h=10,000 (ring 11 → ring 16) with a graduated 11 → 13 → 16 ramp at h=5,000 and h=10,000. Final ring 16 still activates at the same h=10,000; the change adds an intermediate stop. Smoother growth curve, no available-output cliff, additional test surface.
2. **`MIN_OUTPUT_AGE` 10 → 100 activation** — `MIN_OUTPUT_AGE_HARDFORK_HEIGHT` set to 5,000 on testnet (was the `u64::MAX` placeholder since v1.0.10). Aligned with the ring 11→13 step so testnet operators see one upgrade event, not two. Closes the deep-reorg double-spend window from ~20 minutes at 10 blocks to ~3.3 hours at 100 blocks of >50% hashpower.

Mainnet activation heights unchanged (genesis-active).

Decision doc: [`docs/decisions/2026-06-06-ring-ramp-and-output-age.md`](docs/decisions/2026-06-06-ring-ramp-and-output-age.md).

### 🟡 v1.0.13 — architecture & operational polish

**Theme:** non-consensus cleanup surfaced by recent operations.
**Target:** early-to-mid July 2026.

- **Crucible cycle automation** — script that takes a tag, builds the bundle, generates SHA256s, drafts the README + Discord post template. Every cycle currently manual; this is a force multiplier as more Veterans join.
- **Health-monitor + tip-age alert** — Prometheus exporter on each fleet box + paging on `tip_age_secs > 600`. The 6-hour fleet stall on 2026-06-05/06 went unnoticed because no automated alarm.
- **Single-TOML fleet inventory** — one `fleet.toml` at repo root that every script reads. Eliminates the "London missed the wipe" failure class structurally, not just operationally.
- **Rig CLI ergonomics** — auto-append `/rpc/<network>` when the daemon URL is missing the path. The same stumble from 2026-06-05.
- **Two failing fuzz targets** triaged and fixed (per 2026-05-24 snapshot backlog).
- Other small tech-debt items.

### 🟡 v1.0.14 — desktop wallet MVP + IBD speedups

**Theme:** user experience + new-node onboarding.
**Target:** late July / early August 2026.

**Desktop wallet (Tauri-based `coincync-wallet-v2`)** — MVP scope only:

- Wallet create + 24-word seed restore
- Receive (address display + QR code)
- Send (recipient + amount + fee preview + confirm)
- Balance display + scan against the chain
- Transaction history
- Basic settings (data directory, RPC endpoint)

Out of MVP scope (deferred to v1.0.15 or later): multisig UI, subaddress UI, dead-man's-switch UI, theming, advanced settings, hardware wallet integration.

Slotted here for adoption-readiness time. Shipping the wallet in v1.0.14 (~late July) gives the community ~10 weeks of real-world testing before mainnet GA on 2026-10-01. Shipping later compresses that window in a way that hurts mainnet user experience.

**IBD speedups** (parallel track, different code paths from the wallet):

- Public bootstrap chaindata snapshot at a stable URL with SHA256 + verification flow
- AssumeValid mechanism (per the 2026-05-31 hybrid sync-speedup plan, Track 2)
- DNS-seed resilience — A+AAAA records, second DNS provider, `/.well-known/coincync-seeds.json` HTTPS-based fallback
- `coincync-node ibd-status` diagnostic that explains in plain English what's happening, peers found, blocks per minute, ETA

### 🟡 v1.0.15 — crypto formal-review responses + wallet polish

**Theme:** lock in external review of the consensus crypto, expand the wallet beyond MVP.
**Target:** mid-to-late August 2026.

**Crypto review responses** (consensus may shift slightly based on reviewer feedback):

- CLSAG canonical-match formal review confirmation (or revisions)
- MESS variant decision — keep the current exponential-by-depth path, or adopt the canonical ECIP-1100 cubic-by-time formula, or replace with a different reorg-resistance scheme
- ASERT halflife review — the current 3,600s value vs. the BCH-canonical 2 × target_block_time, with the threat-model derivation in [`docs/decisions/2026-06-05-asert-halflife-rationale.md`](docs/decisions/2026-06-05-asert-halflife-rationale.md) as the input
- **Test-vector library** — known-good CLSAG signatures, Bulletproofs+ range proofs, stealth addresses with their derivation inputs and expected outputs, locked in JSON files at `tests/vectors/`. Gives external reviewers and re-implementers ground truth without rebuilding the wallet.
- **Differential fuzz harness** — fuzz our CLSAG sign/verify against a reference implementation (Monero CLSAG or independent Rust). Catches the exact divergence class we surfaced manually during v1.0.11 work.
- **Threat model document** — explicit table: who can attack what, with what budget, for what payoff.

**Wallet expansion** (slides from v1.0.14 MVP):

- Subaddress UI
- Multi-signature UI (FROST flows)
- Dead-man's-switch recovery UI
- Theming + visual polish
- UX bug-bash from v1.0.14 real-world usage

### 🟡 v1.0.16 — mainnet release candidate

**Theme:** locks everything. No consensus changes after this until v1.1.
**Target:** mid-to-late September 2026.

- **SLIP-0044 PR** merge confirmed upstream (coin_type 19166 official; fresh pick if 19166 is taken when we re-verify)
- **All activation heights** set to final mainnet values
- **Multi-maintainer signed-release infrastructure** — M-of-N FROST coordinator hardened; bus-factor inventory populated per the `project_governance_busfactor` memory (T-30 deadline 2026-09-01)
- **Genesis ceremony rehearsal** — full procedural dry-run with timing
- **Disaster-recovery runbook** — one section per failure mode (fleet down, chaindata corrupted, key-image DB wedge, peer mesh fractured, etc.) with exact commands
- **Status page** (status.coincync.network) — real-time chain state, fleet health, last block, current difficulty, automatically updated
- **Reproducible-build verification** — Docker build hash matches across ≥3 independent builders, manifest published
- **Extended Crucible cycle** — 1-2 weeks instead of 15 minutes. Veterans run the binary against real workloads. Final go/no-go signal before flipping mainnet.

---

## ⭐ Mainnet GA — 2026-10-01 00:00:00 UTC

Genesis block message: *"CoinCync Mainnet Genesis — Privacy You Can Audit — October 2026"*.

What ships in v1.0 base chain at mainnet GA:

- CPU-only RandomX proof-of-work
- CLSAG-16 ring signatures (with the v1.0.12 ramp 11 → 13 → 16 from genesis)
- Bulletproofs+ range proofs
- Stealth addresses with view-key derivation
- Dandelion++ transaction propagation
- Pedersen commitment supply audit
- MIN_OUTPUT_AGE 100-block maturity from genesis
- Time-scoped view keys for selective disclosure
- M-of-N multisig (FROST-based)
- Dead-man's-switch recovery (time-locked sweep)
- Compact block filters for light wallets
- CIP-009 reorg defense (per-DB Merkle checkpoints + Tier 3 hard cap)
- Desktop wallet (Tauri-based) shipped from v1.0.14, polished through v1.0.16

What deliberately does NOT ship in v1.0:

- Atomic swaps (cyncswap) — separate audit, separate release (v1.1)
- Orchard shielded pool — separate audit, separate release (v1.2)
- Hardware wallet integration — v1.0.x point release post-GA
- Mobile wallet beta — v1.0.x point release post-GA
- Light-wallet protocol v2 (DHT block filter replacement, M-13) — v1.x

This staging mirrors Monero's: chain first, novel crypto later, each behind its own audit.

---

## Post-mainnet — v1.0.X stability releases

### 🔵 v1.0.16.1 through v1.0.X — post-GA stability

**Theme:** bug fixes and non-consensus refinements only.
**Target:** rolling, as needed during the first 60-90 days post-GA.

- Wallet UX bug fixes surfaced by mainnet usage
- Node operational refinements (logs, diagnostics, configuration ergonomics)
- Documentation corrections
- Crucible-discovered non-consensus issues
- Hardware wallet integration land (v1.0.X.Y)
- Mobile wallet beta land (v1.0.X.Y)

Hard rule for this phase: **no consensus changes without a CIP**. If a consensus change becomes necessary (security finding, etc.), it goes through the CIP process and lands in v1.1 or whichever feature train is next, not as a stealth patch.

---

## v1.1.X — atomic swaps (cyncswap)

### 🟡 v1.1.0 — cyncswap launch

**Theme:** trustless CYNC ↔ BTC atomic swaps with the 6-layer user-safety stack.
**Target:** Q1-Q2 2027 (~3-6 months post-mainnet).

Substantial code is already written today — 346 tests pass with strict DLEQ, mutation score 100% on audit-critical files, ~97% line coverage on the audit perimeter, libFuzzer + AddressSanitizer overnight runs clean across 27 fuzz targets. The release is gated on:

1. v1.0 mainnet running cleanly for ~30-60 days
2. Dedicated cyncswap audit by an external firm (potentially funded by [NLnet Commons Fund](https://nlnet.nl/commonsfund/) — application 2026-06-1a4 in review)
3. The desktop wallet's Trade tab implementation
4. Cross-chain integration testing against actual Bitcoin testnet/mainnet
5. Documentation: user-facing swap guide, threat model for cross-chain UX

What v1.1.0 means for users: every Bitcoin holder is one transaction away from holding CYNC trustlessly — no centralized exchange, no federation, no custodial bridge.

### 🔵 v1.1.X — cyncswap polish

Post-v1.1.0 point releases for swap UX refinements, additional supported counterpart assets (if any), routing optimizations.

---

## v1.2.X — Orchard shielded pool

### 🔵 v1.2.0 — Orchard launch

**Theme:** transparent-to-shielded value migration, opt-in advanced privacy.
**Target:** TBD, post-cyncswap, ~2027-2028 depending on audit cadence.

The Orchard shielded pool is the second of the two "novel cryptography" tracks deliberately deferred from v1.0. Ships with:

- Its own dedicated external audit
- Its own Crucible cycle
- Documentation update covering shielded vs. transparent flow
- Wallet integration in coincync-wallet-v2 (Shielded tab unhides)

Detailed design lives in [`docs/cip/CIP-013-phase-2-orchard-shielded-pool.md`](docs/cip/CIP-013-phase-2-orchard-shielded-pool.md). The cryptography itself (commitment scheme, nullifiers, action descriptions) is implemented at the storage layer today but disabled at the application layer until this release.

---

## v1.X.Y — other features in the queue

These are committed-but-unscheduled features that will land in v1.X point releases as time and resources allow. Order and exact slotting flexible.

### 🔵 Hardware wallet integration
**Probable slot:** v1.0.X point release post-mainnet
Target Ledger, Trezor, and any others with viable Rust SDK + screen-confirm flow for sends.

### 🔵 Mobile wallet beta
**Probable slot:** v1.0.X point release post-mainnet
Initially read-only / receive-only on mobile, send and full management on desktop. Light-wallet protocol (Tier 1) is the foundation already shipping in v1.0.

### 🔵 DHT replacement — light-wallet privacy upgrade (M-13)
**Probable slot:** v1.0.X or v1.1.X
Current Tier 2 DHT key-image queries leak per-query privacy. Documented limitation; replacement with BIP158-style block filters is the planned fix. Substantial architectural work, slots when wallet team has bandwidth.

### ⚪ ORYN connection
**Status:** speculative — separate project per `project_oryn_genesis` memory, started 2026-05-26 at `c:\dev\oryn\` as a transparent PoW L1 with its own design. Connection to CoinCync (if any) — atomic swap, federated peg, something else entirely — undecided until ORYN reaches its own milestones.

---

## v2.0 — warp sync

### ⚪ v2.0.0 — protocol-scale architectural release

**Theme:** order-of-magnitude IBD improvement via warp sync.
**Target:** post-2027, no committed timeline.

Per the 2026-05-31 hybrid sync-speedup plan, this is Track 3: warp sync sketched as CIP-015. v1.0.14's AssumeValid mechanism (Track 2) is an interim that helps but doesn't fundamentally change IBD complexity. Warp sync does.

A "v2.0" version bump signals protocol-scale change — wallets and nodes need explicit upgrade, may include other architectural changes batched in (state trie restructure, kernel-store rework, etc.).

---

## Cross-cutting tracks (not slotted into a single release)

These run in parallel to the version-by-version sequence.

### Community building — The Crucible

[The Crucible](CRUCIBLE.md) launched 2026-06-05. The pre-mainnet build-out:

- **Target by mainnet:** 5+ active Recruits, 2-3 Veterans
- **Current state:** 1 inaugural Veteran (barns1253), Cycle 01 active on v1.0.11

Crucible cadence aims for one cycle per testnet release (v1.0.13, v1.0.14, v1.0.15, v1.0.16 each get a cycle, plus the extended pre-GA cycle in v1.0.16).

### Documentation gaps to close before mainnet

- [`docs/API.md`](docs/API.md) — completeness audit, every RPC method covered with request/response shape examples
- User-facing wallet guide — newcomer's "send your first transaction" walkthrough
- Light-wallet / SPV protocol documentation (Tier 1 / Tier 2 protocol exists in code, needs external-facing docs)
- Node-operator threat model — jurisdictional, network, ISP, hardware-failure considerations
- Standalone "no token sale, no premine" statement — the Constitution implies it; a standalone 1-pager makes it citation-friendly for regulators, journalists, exchange compliance teams

### Outside-the-codebase commitments

- **SLIP-0044 PR filed as soon as v1.0.12 ships** (don't wait for v1.0.16) — SatoshiLabs PR merges take weeks to months
- **Tagged-release CI** — push a tag → Docker build → SHA256SUMS published → GitHub Release auto-populated
- **License and contribution clarity** — MIT-licensed code; no-CLA policy; public-domain or MIT contributions accepted
- **Reproducible-build community verification** — multiple independent builders publishing matching SHA256SUMS for each release
- **Regular Discord status updates** after every Crucible cycle so the community sees rigor

### Tooling backlog (slot where bandwidth allows)

- Chain stress harness — Byzantine peer simulator + network partition simulator. Lets reproducible reproduction of failure classes Crucible catches organically.
- RPC compat test suite — hits every documented method, asserts response shape against fixtures. Catches accidental API breakage during refactors.
- Wallet migration test suite — v1.0.13 wallet → v1.0.14 wallet → ... → v1.0.16 wallet sweep test. Ensures no version-upgrade key/data loss.

---

## How priorities can change

This document is the current best plan. Real life will change things. The most likely sources of plan revision:

- **External crypto review findings** (v1.0.15 input) may change CLSAG, MESS, or ASERT specifics. Decision docs in `docs/decisions/` will record what shifted and why.
- **NLnet Commons Fund decision** (~Sept 2026) — if funded, the cyncswap audit gets external budget and the v1.1 timeline may compress; if not, the staged-mainnet plan continues as-is.
- **Crucible cycle findings** — the Crucible exists precisely to surface things that change plans. If a Veteran flags a real bug in v1.0.14, v1.0.15 absorbs the fix.
- **Community feedback** — issues, discussions, Discord conversations all feed back into prioritization. Particularly weight is given to feedback from people running real nodes (not just commentary).
- **Hardware partner availability** for hardware-wallet integration may shift that work earlier or later.

When plans change, this document gets a PR. The commit message explains what changed and why. No silent edits.

---

## See also

- [CRUCIBLE.md](CRUCIBLE.md) — community testing program details
- [CONSTITUTION.md](CONSTITUTION.md) — what cannot change, ever
- [`docs/BILL_OF_RIGHTS.md`](docs/BILL_OF_RIGHTS.md) — user rights protected by consensus
- [`docs/decisions/`](docs/decisions/) — architectural decision records
- [GitHub Releases](https://github.com/ghostrider1092/Coincync-Testnet-/releases) — shipped binaries with download counts
- [`MAINTAINERS.md`](MAINTAINERS.md) — bus-factor inventory and recovery tree

---

*Privacy-first proof-of-work cryptocurrency. Mine, send, receive, multi-sig. The full 7-feature privacy stack. CIP-009 reorg defense active.*

*Mainnet October 1, 2026.*
