# CIP register

CoinCync Improvement Proposals — the design specs for any
non-trivial protocol or operational change. CIPs that affect
consensus rules go through CIP-007's activation policy; non-
consensus CIPs (deployment plans, operational runbooks) go
through normal code review.

## Status legend

- **Draft** — under discussion; design may change
- **Approved** — accepted; implementation in progress or queued
- **Shipped** — implementation merged on `main`
- **Activated** — consensus rule live on testnet or mainnet
- **Deferred** — postponed without rejection; revisit at a
  future decision point
- **Rejected** — explicitly refused

## Index

### Process / governance

| CIP | Status | Title |
| --- | --- | --- |
| [CIP-007](CIP-007-hard-fork-activation-policy.md) | Approved | Hard-fork activation policy (Mode A static-height + Mode B BIP8-style signaling) |

### Consensus rules

| CIP | Status | Title |
| --- | --- | --- |
| [CIP-009](CIP-009-reorg-defense-decision.md) | Path B Shipped, Path A Rejected | Reorg defense — decision document. Path B (hardcoded checkpoints) shipped at commit `45e621d`. Path A (MESS) rejected as too risky. Successor: CIP-009.D. |
| [CIP-009.D](CIP-009-D-miner-signed-rolling-checkpoints.md) | Shipped (feature-gated, default OFF) | Miner-signed rolling checkpoints — replaces MESS with discrete, auditable, time-warp-immune soft-finality. Layered on top of Path B. Library shipped (`crates/coincync-rolling-finality`); `validate_block` reorg-rule integration shipped at commit `ef4f48c` behind the `rolling-finality` cargo feature. Activation heights in `src/constants.rs`: testnet enable 50,000 / enforce 75,000; mainnet 25,000 / 50,000. Flipping the feature on is a future testnet operation tracked by CIP-011. |
| [CIP-010](CIP-010-testnet-hardfork-rehearsal.md) | Draft | Testnet hard-fork rehearsal — `BOOTSTRAP_MIN_RING_SIZE` 11→13 bump as a planned CIP-007 Mode A exercise before mainnet. |
| [CIP-011](CIP-011-rolling-finality-activation.md) | Draft (code prerequisite shipped) | Rolling-finality activation rehearsal — two-phase (ENABLE → ENFORCE) playbook with five recovery scenarios. The implementation plan for CIP-009.D's mainnet activation. Code prerequisite (CIP-009.D feature-gated integration) shipped at `ef4f48c`; next step is the testnet rehearsal at height 50,000. |

### Application-layer protocols

| CIP | Status | Title |
| --- | --- | --- |
| [CIP-001](CIP-001-atomic-swap.md) | Draft (mainnet blocker) | CYNC↔BTC atomic swap. Adaptor-signature-based, modeled on Comit / Farcaster XMR↔BTC. State machine + handshake + persistence shipped (`crates/coincync-swap`); real adaptor sigs queued for the audit window. |
| [CIP-002](CIP-002-cynchub-merge-mined-liquidity-layer.md) | Draft | CyncHub merge-mined liquidity layer. |
| [CIP-008](CIP-008-frost-coordinator.md) | Draft | FROST M-of-N signing coordinator. State machine, invitations, persistence, WSS server, operator CLI all shipped (`crates/coincync-frost-coordinator`). Integration tests pass. |
| [CIP-012](CIP-012-frost-coordinator-deployment.md) | Draft (deploy scaffolding ready) | FROST coordinator deployment rehearsal — single-instance pre-mainnet, two-instance multi-region mainnet. The operations plan for CIP-008. Deploy scaffolding drafted 2026-05-15: `scripts/coincync-coord.{service,env.example}`, `scripts/install-coord.sh`, `scripts/deploy-coord.ps1`, `scripts/coincync-coord-smoketest.sh`, plus nginx `/coord/` WSS termination in `scripts/deploy-api-nginx.ps1`. Default target: api host (95.179.165.225). Next step is to run `scripts/deploy-coord.ps1` for the single-instance phase. |

### Sketch / future-track

These are placeholders behind feature flags
(`sketch-*` in the workspace `Cargo.toml`). Not part of the
production audit perimeter; revisit post-mainnet.

| CIP | Status | Title |
| --- | --- | --- |
| [CIP-003](CIP-003-cut-through-and-aggregation.md) | Sketch | Cut-through + block aggregation. |
| [CIP-004](CIP-004-kernel-offsets.md) | Sketch | Kernel offsets. |
| [CIP-005](CIP-005-lelantus-spark.md) | Sketch | Lelantus Spark integration. |

## How to read a CIP

Each CIP includes:

- **Status** banner — the source of truth for whether to
  treat the CIP as a design under discussion vs. a shipped
  rule
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

## Open decisions for the operator

The following are filed but awaiting a project-level
approve / defer / reject:

- **CIP-009.D** + **CIP-011** — rolling soft-finality
  activation timeline. Code now shipped feature-gated; what
  remains is the decision to flip the cargo feature on for a
  testnet build, pick the activation cohort, and execute the
  CIP-011 ENABLE → ENFORCE rehearsal at heights 50,000 / 75,000.
- **CIP-010** — ring-bump testnet rehearsal. Queued as
  deliberate second exercise of CIP-007 Mode A after the
  v1.0.9 `MIN_OUTPUT_AGE` hard fork is the first.
- **CIP-012** — FROST coordinator deployment. Deploy
  scaffolding ready; awaiting decision to run.

## See also

- [docs/BLOCKCHAIN_ROADMAP.md](../BLOCKCHAIN_ROADMAP.md) —
  cross-CIP sequencing and forward-looking roadmap. This
  register is the per-CIP source of truth; the roadmap is how
  they sequence across releases.

See each CIP's "Decision" section for the specific options.

## How to propose a new CIP

1. Pick the next available number (none are skipped — the
   gap between CIP-005 and CIP-007 is intentional, reserving
   006 for a separate work item).
2. Open a draft at `docs/cip/CIP-NNN-short-name.md` using the
   structure above.
3. Discuss publicly (Discord `#cip-discussion` plus the file
   itself) for **at least 60 days** before final.
4. For consensus-rule CIPs: a working reference
   implementation behind a feature flag, plus a separate
   activation-rehearsal CIP per the CIP-010 / CIP-011 / CIP-012
   pattern.
5. For non-consensus CIPs: a working reference implementation
   on a feature branch, plus the regular code-review process.

## License

CIPs are part of the CoinCync project and shipped under the
project's MIT license. Use them freely as reference for your
own privacy-coin or PoW-coin design.
