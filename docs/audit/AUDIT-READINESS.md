# CoinCync / Cynstra — External Audit Readiness Package

**Purpose.** A single day-one entry point for an external security auditor. It
states the audit scope, maps the launch-critical surface to the code and the
per-subsystem design docs, records the resolution status of every known
launch-blocker (with commit receipts), and gives exact commands to reproduce the
build and run the test suites.

**Target.** v1 mainnet ("Cynstra"), planned 2026-10-01. Fair-launch, CPU-only
RandomX PoW privacy chain (Monero-lineage RingCT/CLSAG + Bulletproofs+ + stealth
addresses; 0% dev tax; zero premine).

**Branch under audit.** `fix/base-audit-2026-09-05` (worktree `cc-integrate`).
Confirm `git rev-parse HEAD` with the maintainer before starting.

---

## 1. Scope

### In scope (launch-critical)
| Domain | Entry files | Design doc |
|---|---|---|
| Consensus: PoW binding | `src/consensus/pow.rs` | WP-004 |
| Consensus: difficulty | `src/consensus/difficulty.rs` | WP-001 |
| Consensus: reorg / fork choice | `src/chain.rs`, `src/consensus/finality.rs` | WP-005, WP-006, WP-008 |
| Consensus: block validation | `src/consensus/validation.rs` | — |
| Emission / supply | `src/emission/`, `supply_commitment` | WP-002, WP-003 |
| Crypto: RingCT/CLSAG, BP+ | `src/crypto/` | WP-009, WP-011 |
| Crypto: stealth, view tags, memos | `src/crypto/`, `src/wallet/` | WP-013, WP-014, WP-016 |
| Decoy selection | `src/wallet/`, allocation | WP-010 |
| P2P: eviction / eclipse | `src/network/eviction.rs`, `connection_tracker.rs`, `bootstrap.rs` | WP-022 |
| P2P: Dandelion++ | `src/network/` | WP-020 |
| Mining: stratum / share-replay | `src/mining/stratum.rs` | WP-023 |
| Wallet: light sync, disclosure | `src/wallet/lightsync.rs`, `scanner.rs` | WP-017, WP-013 |
| Supply-chain / build integrity | `docker/`, `build.rs`, `critical_files.lock` | WP-007, WP-026 |

### Explicitly OUT of scope for v1
- **Atomic swap (`crates/coincync-swap` / `cyncswap`)** — deferred post-launch.
  The node binary has **no dependency** on it and it is **not built or shipped**
  in the v1 release (see §4). Its unaudited crypto composition is the reason for
  the deferral; audit it when it returns, not now.
- **`crates/cynchub`** — CIP-002 skeleton (merge-mined liquidity layer), not a
  launch component.
- **`coincync-wallet-v2` Tauri app** — separate build-debt track, not launch.

---

## 2. Threat model & prior audits

- `docs/THREAT_MODEL.md` and `docs/whitepapers/WP-101-threat-model-index.md` —
  the authoritative threat model and its index into the WP series.
- `docs/whitepapers/WP-100-solved-issues-ledger.md` — every historically-found
  consensus/security issue, its failure mode, the fix, and the receipt commit.
  **Read this first** to avoid re-deriving already-closed findings.
- Prior internal audits (for context; not all findings survived verification):
  - `docs/audit/2026-06-30-expert-audit-response.md` (in-tree).
  - The 2026-08-24 full-repo deep-dive and 2026-08-30 crypto-cluster briefing are
    **provided to the auditor privately** on engagement — they contain detailed
    vulnerability analysis and are deliberately not published to the public tree.

---

## 3. Launch-blocker resolution status (verified 2026-09-05)

| Blocker | Status | Receipt |
|---|---|---|
| Deep rollback skipped DB-only blocks (junbyjun1238) | **Fixed** | `852d07cf`; test `rollback_to_height_disconnects_db_only_blocks_past_the_cache` (chain.rs) |
| Reorg-vs-extend / reorg-vs-reorg concurrency corruption | **Fixed** | `f0645f04`: `apply_lock: parking_lot::Mutex<()>` held across all of `add_block` / `rollback_to_height` / `restore_state` (chain.rs). `begin_state_update` is a mempool-signal counter, NOT the serializer. |
| Native-stratum share-replay | **Fixed** | Server-owned `JobNonceLedger` keyed by canonical job; stale-job rejected before ledger mutation; dedup on nonce; both native + legacy submit paths; tests in `stratum.rs`. WP-023. |
| Address-flood / eclipse | **Fixed** | Address-book netgroup quota (bootstrap.rs, 125/·/16); outbound per-/16 cap `MAX_OUTBOUND_PER_SUBNET=2` enforced in the dial path (peer_manager.rs → `try_track_outbound_subnet_owned`); eclipse-safe eviction targets the concentrated netgroup (eviction.rs). WP-022. |
| Reorg finality floor could be zero | **Fixed** | `f16b2c9e` (#56); WP-100 §3.4. |
| Cumulative-work path-dependence divergence | **Fixed** | `recompute_total_difficulty`; WP-100 §3.5. |
| Equal-work tiebreak was grindable (`block.hash()`) | **Fixed** | Tiebreak now on the PoW hash (`fork_wins_equal_work_tiebreak`, chain.rs). Raised the selfish-mining threshold off ~0. |
| RandomX genesis env-var fallback (WP-004 §4 footgun) | **Fixed** | `randomx_key_for_height` fails closed (aborts) in production instead of guessing genesis from `COINCYNC_NETWORK`. |

### Owner-action items (not code; must land before/at launch)
- **C-1 blocks 1–99 inflation window** — mitigation is a **post-launch operational
  checkpoint** shipped in the first release. The mechanism (`CONSENSUS_CHECKPOINTS`
  + `expected_checkpoint_hash` + validator path) is built and testnet-exercised;
  the mainnet table is necessarily empty pre-launch (the blocks are not yet mined).
- **Seed fleet + DNS seeds** — infrastructure.
- **External audit engagement** — this package exists to make that fast.

---

## 4. Atomic-swap deferral — proof it is out of v1

- `Cargo.toml` (root, package `.`): **no** `coincync-swap` dependency.
- `src/**`: **no** `coincync_swap` import; swap is unreachable from the node.
- `docker/builder.Dockerfile`: `cyncswap` removed from the artifacts export.
- `.github/workflows/release.yml`: `cyncswap` not built (Windows/macOS) and not
  packaged/checksummed on any platform.
- `release/README.md`: documents the deferral for users.

The crate remains in the workspace for future development but is never
distributed in a v1 artifact.

---

## 5. Reproduce the build (supply-chain claim: default release profile)

```bash
# Deterministic Linux release binaries + SHA256SUMS in ./out
bash ./scripts/build-in-docker.sh --out "$PWD/out"
sha256sum -c out/SHA256SUMS
```

Consensus-critical files are hash-locked (`build.rs` + `critical_files.lock`, WP-007):
any edit to a locked file fails the build until a deliberate re-lock via
`COINCYNC_REGEN_LOCK=1 cargo run --release --features "randomx testnet" --bin update-critical-hashes`.
Locked set includes `pow.rs`, `difficulty.rs`, `validation.rs`, `emission/curve.rs`,
`constants.rs`, `mainnet.rs`, `testnet.rs`, `CONSTITUTION.md`, `BILL_OF_RIGHTS.md`.

---

## 6. Run the tests

```bash
# Library unit tests (fast; ~1207 tests). Release profile avoids a debug-only
# bulletproofs trait-recursion overflow.
cargo test --release --features "randomx testnet" --lib

# Integration / consensus suites (real RandomX PoW — slow; several minutes each).
# Some heavy reorg/sim/chaos cases are #[ignore]d by default; run with --ignored.
cargo test --release --features "randomx testnet" --test reorg_double_spend_e2e -- --ignored
cargo test --release --features "randomx testnet" --test sim_l3_consensus     -- --ignored
cargo test --release --features "randomx testnet" --test chaos_partition_l6   -- --include-ignored
```

Verified 2026-09-05 on this branch: lib 1207 passed / 0 failed; reorg E2E 6/6;
sim L3 2/2; chaos-partition 1/1.

---

## 7. Suggested audit sequence

1. WP-100 solved-issues ledger (avoid re-deriving closed findings).
2. Consensus determinism: `advance_supply_totals`, `fork_wins_equal_work_tiebreak`,
   `apply_lock` scope in `chain.rs` — the invariants a divergence would break.
3. Crypto composition: CLSAG + BP+ + stealth (the double-spend and privacy core).
4. Emission/supply: `supply_commitment` single-sourcing (WP-006 §4.4 pattern).
5. P2P: eclipse/eviction/Dandelion++ under adversarial peers.
6. Wallet: light-sync disclosure + decoy selection privacy leaks.
