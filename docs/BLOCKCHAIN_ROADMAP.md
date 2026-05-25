# Blockchain — Update Log + Technical Context

> **Note (2026-05-20, staged-mainnet decision):** This document is the **technical update log + cross-CIP sequencing notes**, not the authoritative roadmap. For public release commitments see [docs/roadmap.md](roadmap.md) — that is the source of truth for *what ships when*. **As of 2026-05-20, atomic swaps (cyncswap) are no longer a v1.0 mainnet blocker**; they ship in v1.1 after a dedicated cyncswap-only audit. See [decisions/2026-05-20-staged-mainnet-and-cyncswap.md](decisions/2026-05-20-staged-mainnet-and-cyncswap.md) for rationale. This document captures the historical update log and forward-looking technical context that doesn't fit neatly into per-CIP files.

The protocol, consensus, P2P, and wallet layers of CoinCync. Companion to the [CIP register](cip/README.md) — the CIP register is the spec source-of-truth for any one design; this document captures the cross-cutting technical narrative.

Effort labels: **S** (under half a day), **M** (half a day to two
days), **L** (two to five days), **XL** (more than a week).

---

## Most recently shipped — v1.0.9-testnet-pre-audit

The v1.0.9 release is tagged and binaries are published at <https://github.com/ghostrider1092/Coincync-Testnet-/releases/tag/v1.0.9-testnet-pre-audit>. Non-consensus, audit-prep-focused cut. **No protocol break** — operators upgrade at their own pace. Headline content:

- **Reorg-handling track complete** — 9 wallet tasks shipped end-to-end (BlockApplyDiff detection journal, `scan_block_with_result` returning `Scanned`|`ReorgDetected`, `rewind_to_height` with `RewindOutcome`, `find_fork_point` MVP RPC, orchestrator recovery paths A (scan-detected) + B (periodic 30s tip-poll), Tauri `WalletStateEvent` for the wallet UI, in-app reorg banner). **59 unit + integration tests + 9 proptest properties × 256 cases = 2,304 generated cases, all green.**
- **Wallet v2 polish** — history page empty-state icon, dashboard `tCYNC` consistency + Swap v1.1 chip, reactive Send review pane (was hardcoded zeros + dash), Receive copy button wired, `alert()` → toast across multiple flows, reorg banner CSS using the real design tokens.
- **Explorer 5 new privacy-stat pages** — `/?p=anonset`, `/?p=reorghistory`, `/?p=compare` (features showcase), `/?p=mininglive`, `/?p=feemarket`. Plus a footer-position bug fix that was rendering the footer mid-page on ~16 prior pages.
- **Multisig typed-error migration complete** — `multisig_{info,round1,round2,aggregate,send}` ported `Result<T, String>` → `Result<T, WalletError>` per the recipe. Closes the v1.0 typed-error track at 14/35 commands (swap_* defers to v1.1; 12 get_* return data not Result).
- **Decision records signed** — CIP-009.D production posture (Option A: dormant at genesis), reorg-handling v1.0 scope (Option B: finish for v1.0), genesis-defaults worksheet (5 defaults adopted including coinbase = burn, initial difficulty 0.5×, CIP-009.D dormant).
- **`rust-toolchain.toml`** pinned to 1.88.0 — workspace floor, matches the Dockerfile pin. Closes the SIMD/HRTB compile issues that affected Rust 1.92.

Detailed work since the v1.0.9 tag continues on `main` and is queued for **v1.0.10** (see "Near-term" section below).

---

## Earlier — v1.0.8 (May 12–15, 2026 batch)

Cleanup release, no consensus break. Operators upgrade at their own
pace. Six commits on top of the v1.0.7 base.

### Observability

- **Real Prometheus `/metrics` endpoint** (`2a8af30`) — four hot-path
  histograms (block-receive-to-tip, tx-admit-to-mempool, peer-handshake,
  RandomX-hash). Localhost-only on `RPC_PORT + 1`. Replaces the 1.0-trim
  noop stubs.
- **`RANDOMX_HASH` histogram observation** (`24b22b7`, this session) —
  wraps `compute_pow_hash` with `start_timer()`. Closes the last
  unobserved hot-path histogram.

### Privacy stack

- **Constant-rate cover traffic** (`11e6b8e`) — `MessageType::Padding = 99`
  retires the `PADDING_MAGIC` hack; cover packets now flow through the
  framer like any other message. Third leg of jitter + size-norm + cover
  packets is now complete.
- **FROST coordinator in reproducible Docker builder** (`11e6b8e`) —
  `coord` + `coord-cli` built alongside `coincync-node`.

### Runtime

- **`spawn_blocking` for block + mempool admit** (`5c98bae` + `0d8e0c4`
  + `2a8af30`) — six new `Blockchain::*_async` methods route PoW
  recheck, ring-sig verify, range-proof verify, and RocksDB writes off
  the tokio worker pool. Layer 2 fix for the 2026-05-12 13-minute stall.

### Consensus prep

- **CIP-011 rolling-finality machinery** (`ef4f48c`, this session) —
  feature-gated `rolling-finality` (default OFF). `RollingFinality`
  adapter wraps `FinalityTracker` + `Ed25519Verifier`. Four height
  constants in `constants.rs`: testnet enables at 50,000 / enforces at
  75,000; mainnet 25,000 / 50,000.
- **Phase-2 storage reorg checkpoint/rewind** (`ef4f48c`, this session) —
  `ShieldedStore`, `SparkStore`, `KernelStore` each gain
  `checkpoint_at_height` + `rewind` + parallel checkpoint stack. 42 new
  tests. Stores remain `None` at chain construction — dormant in
  production, this is the storage prerequisite for future activation.

### Wallet

- **Opt-in update check (Monero posture)** (`12edf66`, this session) —
  user-invoked only, no automatic poll. Both `coincync-node check-update`
  CLI and wallet `check_for_update` Tauri command. Default OFF with an
  explicit privacy warning on opt-in.

### Documentation

- **`docs/PRIVACY_FEATURES.md`** + **`docs/security/reorg-defense.md`**
  + **`docs/atomic-swap-clsag-adaptor-design.md`** (`52d99f2`, this
  session) — new-dev onboarding, six-layer reorg-defence threat model,
  CLSAG adaptor design correction.

### Security

- **18 dependabot alerts closed** — 1 critical, 6 high, 9 medium, 2 low.
  Highlights: `openssl 0.10.77 → 0.10.79` closing five CVEs; unused
  `jsonwebtoken` removed closing CVE-2026-25537; fuzz lockfile
  refreshed closing `libsecp256k1` overflow.

### Carried forward to v1.0.10

- **`MIN_OUTPUT_AGE` 10 → 100** — consensus hard fork, deferred from
  v1.0.8 (and skipped over v1.0.9-testnet-pre-audit since that was a
  non-consensus audit-prep cut) so it gets a real soak window. Code
  preserved at [out/v1.0.9-slice1.patch](../out/v1.0.9-slice1.patch)
  with applier instructions at
  [out/v1.0.9-slice1-instructions.md](../out/v1.0.9-slice1-instructions.md)
  — filenames retain the original `v1.0.9` slug as historical
  artifacts from when this was first staged; the contents apply
  unchanged to the v1.0.10 release.

---

## Near-term — v1.0.10 (target: 3rd week of June 2026)

The first consensus break since launch. Coordinated upgrade required.
v1.0.9-testnet-pre-audit (now shipped) was deliberately non-consensus
so the hard-fork content got its own dedicated release window with no
unrelated soak risk.

1. **`MIN_OUTPUT_AGE` 10 → 100 hard fork** — **M** (~1 week incl.
   soak). Pre-flight: pick activation height (current tip + 5,000
   block buffer = ~7 days at 120s), post to Discord
   `#announcements`, add activation guard in
   `src/wallet/history.rs` and any consensus call site, sandbox-soak
   ≥5 days. Full checklist in
   [out/v1.0.9-plan.md](../out/v1.0.9-plan.md) (filename retains the
   original `v1.0.9` slug as a historical artifact; contents apply
   unchanged to v1.0.10).
2. **CIP-010 ring-bump rehearsal** — **M**. Bump `BOOTSTRAP_MIN_RING_SIZE`
   11→13 as a planned CIP-007 Mode A exercise. Validates the
   activation policy works end-to-end before relying on it for the real
   hard forks. Can ride alongside the MIN_OUTPUT_AGE flip or be its own
   release.
3. **CIP-012 FROST coord production deploy** — **S** (operational,
   half-day). Scripts drafted this session
   ([scripts/deploy-coord.ps1](../scripts/deploy-coord.ps1) +
   nginx /coord/ block in [scripts/deploy-api-nginx.ps1](../scripts/deploy-api-nginx.ps1)).
   Not yet run.
4. **`spawn_blocking` audit final pass** — **L**. Sweep
   `src/rpc/server.rs` get-handlers + remaining sync RocksDB callers
   outside `chain.rs` and `mempool.rs`. Phase 2 #9 from the
   post-launch campaign.

## v1.1.x — mainnet-prep window

5. **CIP-009.D / CIP-011 rolling-finality testnet activation** — **L**.
   Flip the `rolling-finality` cargo feature on for testnet builds at
   height 50,000 (ENABLE) and observe through 75,000 (ENFORCE). Five
   recovery scenarios documented in CIP-011 — pick which one to
   rehearse before mainnet.
6. **H-16 reorg-defense formal decision** — **M** (research +
   writeup). MESS vs. hybrid vs. hard cap. Threat model framework
   exists at [docs/security/reorg-defense.md](security/reorg-defense.md);
   the choice between the three is still open. Audit-blocking but not
   testnet-blocking.
7. **Multi-sig wallet GUI (FROST participant UI)** — **L**. FROST
   coordinator exists; the desktop wallet does not yet have UI for
   participating in a coord session (attach, submit round-1, submit
   round-2, observe state). Without this the M-of-N path requires
   manual JSON crafting.
8. **Atomic swap clear-signing CIP** — **M**. Wallet-side display
   contract for swap messages so users don't blind-sign hex. ERC-7730
   posture. Sub-item of CIP-001 but worth its own CIP for the wallet UX
   contract.
9. **SOCKS5 UDP-ASSOCIATE DNS** — **S-M**. Flagged in
   `src/network/bootstrap.rs` as the missing piece for full Tor-mode
   DNS privacy. The peer-routing side of Tor support already exists
   (`onion_only` + `proxy_active` flags); this closes the DNS leak.

## v1.0 mainnet blockers — must ship before tag

> **Updated 2026-05-20:** Atomic swap (CIP-001) and Phase-2 activation (Orchard) have been **moved out of v1.0 mainnet blockers** and into their own staged releases (v1.1 and a separate v1.x, respectively). They are each the largest novel-cryptography surface in the codebase and deserve their own dedicated audit cycles rather than gating the base chain. See [decisions/2026-05-20-staged-mainnet-and-cyncswap.md](decisions/2026-05-20-staged-mainnet-and-cyncswap.md). The remaining v1.0 mainnet blockers are:

10. **Base-chain security audit** — **XL** (3-6 months). NLnet-funded.
    Scope: consensus, P2P, wallet, mining, reorg defense. **Cyncswap
    and Orchard are NOT in v1.0 audit scope** (they ship in their own
    releases behind their own audits). Outreach to Cypher Stack / OSTIF
    / Teserakt drafted in
    `C:\Users\unkno\grants\nlnet-2026-06-coincync-application.md`; not
    sent. Audit firm picks the commit + works from there.
11. **Mainnet genesis ceremony** — **M**. Operational only: mainnet
    seed nodes, initial checkpoint set, mainnet faucet decision (or
    "mine your own"), DNS, monitoring.
12. **CIP-009.D rolling-finality production posture** — **M**.
    Feature-gated machinery shipped in v1.0.8. Decide whether v1.0
    mainnet enables CIP-009.D from genesis (with checkpoint signers
    elected) or ships it dormant and activates via CIP-007 later.
    Either is defensible; pick one before tag.
13. **Reproducible Docker build sign-off** — **S**. Confirm byte-identical
    output on the documented host arch, document the verifier workflow,
    publish the SHA-256 set with the v1.0 release notes.
14. **Wallet v2 ships base-chain only** — **M**. Trade tab hidden behind
    a build flag for v1.0 (unhides in v1.1). Send, receive, history,
    addresses, mining, multi-sig all wired against live mainnet RPC.

## v1.1 — cyncswap (post-mainnet, post-audit)

15. **CIP-001 atomic swap real crypto** — **substantially complete**.
    What's now shipped: state machine + handshake + persistence;
    Schnorr adaptor sigs (BTC BIP-340 parity-correct + CYNC
    Ristretto255); dual-response cross-curve DLEQ + strict-binding
    Noether 2018 variant (gated by Cargo feature `strict-dleq`); BTC
    + CYNC RPC clients with mock impls; BTC lock/claim/refund tx
    construction (BIP-341 script-path); CYNC swap key-derivation +
    `SwapLockRecipient` wallet-bridge helper; coordinator transport
    (Plain TCP + Noise XX + SOCKS5/Tor dial, all with DoS-hardened
    filtered-listen variants); 6 CLI orchestration handlers
    (`lock-cync`, `lock-btc`, `claim-btc`, `claim-cync`, `refund-btc`,
    `refund-cync`); operator-driven dual-testnet smoke harness
    ([scripts/cyncswap-dual-testnet-smoke.sh](../scripts/cyncswap-dual-testnet-smoke.sh));
    operator transport-setup guide ([docs/cyncswap-transport-setup.md](cyncswap-transport-setup.md)).
    **346 tests pass with `--features strict-dleq`; 288 in default
    builds.** Mutation score 100% on audit-critical files. Audit prep
    complete at [docs/cyncswap-audit-prep.md](cyncswap-audit-prep.md).
    What's left: **(a)** wallet Trade tab; **(b)** optional CLSAG
    ring-binding for the CYNC-side adaptor (touches audited consensus,
    separate planning); **(c)** **dedicated cyncswap audit** —
    kickoff target ~30 days after v1.0 mainnet ships.
16. **Cyncswap audit** — **L-XL**. Scope: adaptor signatures (both
    curves), cross-curve DLEQ + Noether strict-binding variant, BTC
    script paths, coordinator transport, refund timing. Separate from
    the base-chain audit. Estimate Q1-Q2 2027.

## v1.x — Phase-2 activation (Orchard shielded pool)

17. **Phase-2 activation (Orchard shielded pool)** — **XL** (months).
    Storage-side rewind shipped (`ef4f48c`, dormant). Cryptographic
    primitives layer shipped in `crates/orchard-side/` — 86 tests pass:
    commitment, note, nullifier, value-commit + RedPallas binding sig,
    full spend-key hierarchy, action-circuit skeleton with Halo2 IPA
    prove/verify wiring + 8-row public-input scaffolding. **Halo2 Action
    circuit constraint roadmap: Step 1 ✅ (column scaffolding for the
    chip set), Steps 2-8 ⏳** (ECC chip + Sinsemilla + Merkle + Poseidon,
    plus lookups + ranges + public-input equality + audit pass). Step 2
    is blocked on a dep-version decision: orchard 0.12 needs
    halo2_gadgets 0.4 but we're on 0.3; either bump our pin (low-risk
    upgrade) or implement local `FixedPoints` (heavier, dep-free) —
    documented in [crates/orchard-side/src/action.rs](../crates/orchard-side/src/action.rs)
    `ConstraintRoadmap`. Activation also requires: (a) construct
    `ShieldedStore` at chain init, (b) wire block-apply-time append
    calls, (c) hard-fork height, (d) transaction-format hard fork
    (current tx format is ring-only), (e) wallet support for shielded
    send/receive. The single biggest piece of work left, dominated by
    Steps 2-8 of the constraint roadmap (estimated multi-month per
    reference `orchard` crate's ~3000 LOC `synthesize` body).
12. **Security audit** — **XL** (3-6 months). NLnet-funded. Outreach
    to Cypher Stack / OSTIF / Teserakt drafted in
    `C:\Users\unkno\grants\nlnet-2026-06-coincync-application.md`; not
    sent. **Audit-prep checklist for `cyncswap`** (the largest
    cryptographic component to be reviewed) shipped 2026-05-18 at
    [docs/cyncswap-audit-prep.md](cyncswap-audit-prep.md) — scope,
    cryptographic-module map, primary review targets, test-vector
    inventory, license-boundary statement, and build-reproducibility
    commands. Audit firm picks the commit + works from there.
13. **Mainnet genesis ceremony** — **M**. Operational only: mainnet
    seed nodes, initial checkpoint set, mainnet faucet decision (or
    "mine your own"), DNS, monitoring.

## Post-mainnet — Sketch CIPs

These are placeholders behind `sketch-*` feature flags in workspace
`Cargo.toml`. Not part of the production audit perimeter. Revisit
post-mainnet.

14. **CIP-002 CyncHub merge-mined liquidity layer** — **XL**.
    Auxiliary PoW chain for atomic order book. Miners coordinate;
    HTLCs settle. The PoW alternative to PoS bridges. **18-24 months
    post-mainnet.**
15. **CIP-003 Cut-through and aggregation** — **L**. MimbleWimble
    cut-through. Requires Phase-2 active first.
16. **CIP-004 Kernel offsets** — **L**. Storage code skeleton exists
    in [src/storage/kernels.rs](../src/storage/kernels.rs); activation
    requires Phase-2 hard fork.
17. **CIP-005 Lelantus Spark integration** — **L**. Storage skeleton
    shipped this session ([src/storage/spark.rs](../src/storage/spark.rs),
    dormant). Activation pairs with Phase-2.

## Acknowledged gaps not yet captured as CIPs

These should probably be filed as draft CIPs at some point.

18. **Hardware wallet support** (Ledger / Trezor) — **L-XL**. No
    `device-*` crate exists. Architecturally needs a signing-device
    abstraction layer in the wallet.
19. **Watchtowers for atomic swap timeout enforcement** — **L**.
    Needed if HW-wallet users want offline swap protection. Depends
    on hardware-wallet integration.
20. **Post-quantum P2P transport** — **XL**, long-term. Replace
    Noise XX with PQ-hybrid eventually. ML-KEM-768 + X25519 hybrid is
    the obvious starting point.
21. **Wallet recovery / encrypted seed export tooling** — **M**.
    Partial in the Tauri wallet; needs a structured export format and
    cross-wallet portability spec.
22. **Multi-language wallet (i18n)** — **L**. The Tauri wallet is
    English-only. Discord membership skews international; this
    matters for adoption.

---

## Explicitly rejected — by Constitution or design

So they don't keep being re-suggested.

- **Optional transparency / KYC paths** — **REJECTED by Articles III,
  IX, XI.** No opt-out from privacy. CoinCync is jurisdiction-neutral.
- **Address balance lookup RPC** — **REJECTED by Article IX** + the
  documented "No RPC exists to query an address balance" commitment.
- **Admin keys / pause / freeze functionality** — **REJECTED by
  Article XII.** Same posture as Monero.
- **Smart contracts as a feature** — **OUT OF SCOPE.** CoinCync is a
  privacy money chain. Smart contracts complicate the privacy model and
  are an attack surface the design intentionally rejects.
- **Custodial bridges** — **REJECTED.** Atomic swaps (CIP-001) replace
  this need. No multisig federation between chains.
- **Pre-rendered "rich list by value"** — explicitly avoided. Amounts
  are hidden by Pedersen commitments; a value-sorted list would either
  be meaningless or require linking that the cryptography intentionally
  erases.
- **Mandatory KYC for mining pool participation** — **REJECTED.** No
  permission layer on mining.
- **Algorithmic stablecoin / asset issuance** — **REJECTED.** Single
  asset (CYNC). Asset infrastructure exists at the protocol level
  (Article I) but issuance is closed.

---

## Sequencing notes — what depends on what

```
                 v1.0.9 cut          ──►  v1.0.10 cut         ──►  v1.1.x mainnet-prep
                 (testnet-pre-audit)      (MIN_OUTPUT_AGE         (rolling-finality test
                                           hard fork)              + ring rehearsal)
                       │                       │
                       │                       │
                       ▼                       ▼
                 FROST coord deploy      H-16 decision
                 (operational)           (research, audit-blocking)
                       │
                       ▼
                 Multi-sig wallet GUI
                 (depends on coord live)
                                                                       │
                                                                       ▼
                                                                Mainnet blockers
                                                                ┌────────────────┐
                                                                │ Atomic swaps   │
                                                                │ Phase-2 active │
                                                                │ Security audit │
                                                                │ Mainnet genesis│
                                                                └────────────────┘
                                                                       │
                                                                       ▼
                                                              MAINNET LAUNCH
                                                                       │
                                                                       ▼
                                                            Post-mainnet sketches
                                                            (CIP-002/003/004/005)
                                                            HW wallets, i18n, PQ
```

The two critical-path items for mainnet are **atomic swaps** and
**Phase-2 activation** — each is independently multi-month. They can
run in parallel since atomic swaps don't touch the transaction format
and Phase-2 doesn't touch the swap state machine.

The audit window needs to start during the back half of those two
workstreams, not after. Otherwise the audit blocks mainnet by 3-6
additional months after the code is feature-complete.

---

## Privacy invariants for blockchain code

Every protocol change must satisfy these. If a design needs to violate
any, it's the wrong design.

- **No opt-out from privacy.** Mandatory ring sigs, mandatory
  commitments, mandatory bulletproofs. Article III.
- **No address-balance disclosure.** No RPC, no on-chain query path,
  no "view all transactions for address X" surface. Article IX.
- **Activation hooks (CIP-007).** Every consensus rule change goes
  through the activation registry. No silent flag flips.
- **Feature gates default to OFF.** Anything not yet activated lives
  behind a cargo feature, off by default. Compile-time tripwire.
- **No external chain trust.** Article XIII. The chain validates
  itself; no oracle, no external-data dependency.
- **Locked files have hashes.** Consensus-critical files are listed
  in `critical_files.lock`; build fails if a hash drifts. Changing
  any of them requires explicit lockfile roll + review.
- **Reproducible builds.** `scripts/build-in-docker.sh` produces
  byte-identical binaries on the same host CPU architecture. Audit
  trust starts here.

## Adding a new consensus rule

The CIP-007 + CIP-010-style rehearsal pattern is the established
process:

1. Draft a CIP at `docs/cip/CIP-NNN-short-name.md` using the
   structure in [docs/cip/README.md](cip/README.md). Discuss publicly
   for at least 60 days before final.
2. Working reference implementation behind a `cargo` feature flag,
   default OFF. Tests pass with the feature both on and off.
3. Separate activation-rehearsal CIP per the CIP-010 / CIP-011 / CIP-012
   pattern. Specifies the deployment process for the
   already-approved CIP.
4. Pick activation heights in `src/constants.rs` (split testnet /
   mainnet via `#[cfg(feature = "testnet")]`). Add to the activation
   registry per CIP-007.
5. Coordinate the upgrade window: post activation height to Discord
   `#announcements` ≥7 days ahead, soak the new binary on a sandbox
   node against live testnet ≥5 days, deploy to fleet, monitor
   through the activation block, document outcome.

The current "MIN_OUTPUT_AGE 10 → 100" hard fork (v1.0.10) is the
first real exercise of this pattern. CIP-010 (the ring-bump
rehearsal) is queued as a deliberate second rehearsal so the
process is exercised twice before atomic swaps or Phase-2 ride it.
