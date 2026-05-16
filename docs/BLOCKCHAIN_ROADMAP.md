# Blockchain — Update Log + Roadmap

The protocol, consensus, P2P, and wallet layers of CoinCync. This is
the forward-looking companion to the [CIP register](cip/README.md) —
the CIP register is the spec source-of-truth for any one design, this
roadmap is how the work sequences across releases.

Effort labels: **S** (under half a day), **M** (half a day to two
days), **L** (two to five days), **XL** (more than a week).

---

## Recently shipped — v1.0.8 (May 12–15, 2026 batch)

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

### Carried forward to v1.0.9

- **`MIN_OUTPUT_AGE` 10 → 100** — consensus hard fork, deferred from
  v1.0.8 specifically so it gets a real soak window. Code preserved at
  [out/v1.0.9-slice1.patch](../out/v1.0.9-slice1.patch) with applier
  instructions at [out/v1.0.9-slice1-instructions.md](../out/v1.0.9-slice1-instructions.md).

---

## Near-term — v1.0.9 (target: 3rd week of June 2026)

The first consensus break since launch. Coordinated upgrade required.

1. **`MIN_OUTPUT_AGE` 10 → 100 hard fork** — **M** (~1 week incl.
   soak). Pre-flight: pick activation height (current tip + 5,000
   block buffer = ~7 days at 120s), post to Discord
   `#announcements`, add activation guard in
   `src/wallet/history.rs` and any consensus call site, sandbox-soak
   ≥5 days. Full checklist in
   [out/v1.0.9-plan.md](../out/v1.0.9-plan.md).
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

## Mainnet blockers — must ship before tag

10. **CIP-001 atomic swap real crypto** — **XL** (multi-month). State
    machine + handshake + persistence shipped in `crates/coincync-swap`;
    Schnorr adaptor sigs (musig2-style), BTC RPC client + tx broadcast/
    monitor, CYNC RPC integration, dual-testnet smoke (BTC testnet +
    CYNC testnet) all pending. NLnet-funded. **The constitutional
    commitment** — see [[project_atomic_swap_mainnet_blocker]].
11. **Phase-2 activation (Orchard shielded pool)** — **XL** (months).
    Storage-side rewind shipped this session (`ef4f48c`, dormant).
    Activation requires (a) construct `ShieldedStore` at chain init,
    (b) wire block-apply-time append calls, (c) hard-fork height, (d)
    **Halo2 circuit** — `crates/orchard-side/src/` is currently empty,
    (e) transaction-format hard fork (current tx format is ring-only),
    (f) wallet support for shielded send/receive. The single biggest
    piece of work left.
12. **Security audit** — **XL** (3-6 months). NLnet-funded. Outreach
    to Cypher Stack / OSTIF / Teserakt drafted in
    `C:\Users\unkno\grants\nlnet-2026-06-coincync-application.md`; not
    sent.
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
                 v1.0.8 cut  ────────►  v1.0.9 cut  ────────►  v1.1.x mainnet-prep
                 (this batch)           (MIN_OUTPUT_AGE)        (rolling-finality test
                                                                 + ring rehearsal)
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

The current "MIN_OUTPUT_AGE 10 → 100" hard fork (v1.0.9) is the
first real exercise of this pattern. CIP-010 (the ring-bump
rehearsal) is queued as a deliberate second rehearsal so the
process is exercised twice before atomic swaps or Phase-2 ride it.
