# CIP register

CoinCync Improvement Proposals — the design specs for any
non-trivial protocol or operational change. CIPs that affect
consensus rules go through CIP-007's activation policy; non-
consensus CIPs (deployment plans, operational runbooks) go
through normal code review.

**Release commitments live in [docs/roadmap.md](../roadmap.md), not here.**
This register documents the *design state* of each CIP.
Whether a CIP ships in v1.1, v1.2, v1.3, or later is decided
in the roadmap, not by the CIP's own status field. A CIP at
Draft status with full implementation may still not be on the
next release if it doesn't fit Apple-style one-headline-per-
release discipline.

## Status legend

- **Sketch** — design space captured; **not on any release path**.
  Revisit if/when budget + scope alignment materializes. Treat
  as research, not commitment.
- **Draft** — under discussion; design may change. Eligibility
  for a release is decided in the roadmap.
- **Approved** — accepted; implementation in progress or queued
  for a specific release per the roadmap.
- **Shipped** — implementation merged on `main` behind a feature
  flag or as the default.
- **Activated** — consensus rule live on testnet or mainnet.
- **Deferred** — postponed without rejection; revisit at a
  future decision point.
- **Rejected** — explicitly refused.

## Currently shipping toward v1.1 (mainnet)

Headline: **cyncswap end-to-end with the 6-layer user-safety stack**. See [docs/roadmap.md](../roadmap.md) for the full release scope and shippable bar.

| CIP | Status | Title |
| --- | --- | --- |
| [CIP-001](CIP-001-atomic-swap.md) | Draft (mainnet blocker — v1.1 headline) | CYNC↔BTC atomic swap. Adaptor-signature design **locked** per [docs/decisions/2026-05-18-cyncswap-path.md](../decisions/2026-05-18-cyncswap-path.md). 70% of cryptographic construction shipped (288/346 tests pass). Remaining: wallet integration, the 58 failing tests, dual-testnet smoke, two independent audits. Safety stack at [docs/cyncswap-user-safety.md](../cyncswap-user-safety.md). |
| [CIP-007](CIP-007-hard-fork-activation-policy.md) | Approved | Hard-fork activation policy (Mode A static-height + Mode B BIP8-style signaling). Process scaffolding for any consensus-change CIP. |
| [CIP-009](CIP-009-reorg-defense-decision.md) | Path B Shipped, Path A Rejected | Reorg defense decision. Path B (hardcoded checkpoints) shipped at `45e621d`. Path A (MESS) rejected as too risky. |
| [CIP-009.D](CIP-009-D-miner-signed-rolling-checkpoints.md) | Shipped (feature-gated, default OFF) | Miner-signed rolling checkpoints. Library + `validate_block` integration shipped at `ef4f48c` behind the `rolling-finality` cargo feature. Activation tracked by CIP-011. |
| [CIP-013](CIP-013-phase-2-orchard-shielded-pool.md) | Draft (mainnet-blocker status under review — see roadmap) | Phase 2 Orchard shielded pool. Non-circuit cryptographic primitive set complete (86 tests pass). Halo2 Action circuit is the remaining multi-month work. **Whether this ships with v1.1 mainnet or as a separate v1.x release is an open decision per the roadmap.** |

## Active design (Draft, not yet on a committed release)

| CIP | Status | Title |
| --- | --- | --- |
| [CIP-008](CIP-008-frost-coordinator.md) | Draft (implementation shipped; activation pending) | FROST M-of-N signing coordinator. State machine, invitations, persistence, WSS server, operator CLI all shipped (`crates/coincync-frost-coordinator`). Integration tests pass. |
| [CIP-010](CIP-010-testnet-hardfork-rehearsal.md) | Draft | Testnet hard-fork rehearsal — `BOOTSTRAP_MIN_RING_SIZE` 11→13 bump as a planned CIP-007 Mode A exercise. |
| [CIP-011](CIP-011-rolling-finality-activation.md) | Draft (code prereq shipped) | Rolling-finality activation rehearsal — two-phase ENABLE → ENFORCE playbook for CIP-009.D's mainnet activation. |
| [CIP-012](CIP-012-frost-coordinator-deployment.md) | Draft (deploy scaffolding ready) | FROST coordinator deployment rehearsal. Single-instance pre-mainnet, two-instance multi-region mainnet. |
| [CIP-017](CIP-017-ring-size-increase.md) | Draft | Ring-size increase above 16 (phased 16→24→32) as coordinated CIP-007 Mode B hard forks. Constitutionally sanctioned (Art. III strengthening clause). Benchmarked CLSAG cost; target pending batch-verify + fleet-hardware measurement. Distinct from the 11→13 bootstrap-floor bump (CIP-010). |
| [CIP-018](CIP-018-private-light-wallet-fast-sync.md) | Draft (deferred) | Private light-wallet fast-sync: extend `get_output_digests` `BlockDigest` with per-block spent key images so digest sync is low-bandwidth AND spend-safe AND zero-leak private. Deferred — the current full-block scan is correct/private/fast enough for now; captured as the right design for when many users sync large chains. |

## Sketch — research, not roadmap

These are design-space captures *only*. They are explicitly **not** on any committed release. Behind feature flags (`sketch-*` in the workspace `Cargo.toml`) when prototype code exists. Promotion to Draft requires explicit roadmap inclusion.

| CIP | Status | Title |
| --- | --- | --- |
| [CIP-002](CIP-002-cynchub-merge-mined-liquidity-layer.md) | Sketch | `cynchub` merge-mined liquidity layer. V1 design captured 2026-05-18 (briefly promoted to Draft same day, reverted to Sketch under Apple-style discipline). Earliest reconsideration: v1.3+, after cyncswap is mainnet-stable ≥12 months with zero principal-loss incidents. |
| [CIP-003](CIP-003-cut-through-and-aggregation.md) | Sketch | Cut-through + block aggregation. Post-mainnet research. |
| [CIP-004](CIP-004-kernel-offsets.md) | Sketch | Kernel offsets. Post-mainnet research. |
| [CIP-005](CIP-005-lelantus-spark.md) | Sketch | Lelantus Spark integration. Post-mainnet research. |
| [CIP-015](CIP-015-warp-sync-utxo-snapshot.md) | Sketch | Warp sync via UTXO-set state snapshots. v2.0 destination, replaces today's stopgap chaindata-tarball bootstrap. Trustless under honest-majority PoW. |
| [CIP-016](CIP-016-randomx-xmrig-parity.md) | Sketch | RandomX hashrate parity with xmrig. v2.0+ research. coincync-rig currently ~5-25% of xmrig per-thread depending on CPU tier. Phase 2 (per-thread VMs) already shipped 2026-05-25 — remaining gap is xmrig's micro-optimizations (JIT variants, prefetch, hugepages). Bounded difficulty, unbounded calendar risk; research track only. |

## How to read a CIP

Each CIP includes:

- **Status** banner — the source of truth for whether to
  treat the CIP as a design under discussion vs. a shipped
  rule. **Status does NOT imply a release commitment** —
  that's the roadmap's job.
- **Abstract** — one-paragraph summary
- **Motivation** — why we're considering it
- **Specification** — the actual rule / protocol
- **Security considerations** — what could go wrong
- **Out of scope** — what this CIP explicitly does NOT
  cover (so it doesn't get used as a hook for unrelated
  changes)

Activation-rehearsal CIPs (CIP-010, CIP-011, CIP-012) follow
a different shape: they SPECIFY a deployment process for
a previously-approved CIP rather than introducing new
protocol rules.

## How to propose a new CIP

1. Pick the next available number (none are skipped — the
   gap between CIP-005 and CIP-007 is intentional, reserving
   006 for a separate work item).
2. Open a new file at `docs/cip/CIP-NNN-short-name.md` using
   the structure above. **Mark it `Status: Sketch` by default.**
3. Discuss publicly (Discord `#cip-discussion` plus the file
   itself) for **at least 60 days** before promoting to Draft.
4. Promotion to Draft requires explicit roadmap inclusion —
   the CIP becomes a commitment only when it lands in
   [docs/roadmap.md](../roadmap.md) for a specific release.
5. For consensus-rule CIPs: a working reference implementation
   behind a feature flag, plus a separate activation-rehearsal
   CIP per the CIP-010 / CIP-011 / CIP-012 pattern.
6. For non-consensus CIPs: a working reference implementation
   on a feature branch, plus the regular code-review process.

## See also

- [docs/roadmap.md](../roadmap.md) — public release commitments
  (v1.1, v1.2, v1.3 only). The source of truth for *what
  ships when*.
- [docs/BLOCKCHAIN_ROADMAP.md](../BLOCKCHAIN_ROADMAP.md) —
  cross-CIP sequencing notes and forward-looking technical
  context (historical document; superseded by docs/roadmap.md
  for release commitments).
- [docs/decisions/](../decisions/) — irreversible-ish design
  decisions recorded one per file, with rationale + revisit
  conditions.

## License

CIPs are part of the CoinCync project and shipped under the
project's MIT license. Use them freely as reference for your
own privacy-coin or PoW-coin design.
