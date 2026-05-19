<!-- markdownlint-disable MD036 MD013 -->
# Deprecation Schedule

**Privacy money that requires no permission.** That promise outlives any single feature. Some code that ships in v1.x will not ship in v1.y — and that's not a regression, it's discipline. This document tracks what's queued for removal and when.

**Discipline (Apple-style Principle 10):** every release *removes* something, not just adds. iOS removed the 3.5mm jack, the home button, USB-A. Slimming, refining, simplifying. CoinCync follows the same posture.

---

## How this document works

1. Code, config, flags, file formats, RPC methods, or CLI flags that should eventually be removed are listed below with: target release, reason, N-1 warning policy, removal owner.
2. A "deprecation warning" lands at least one release before removal. Users running the deprecated thing see a clear notice with the migration path.
3. Removal happens in the release listed under **Target removal release**. By that point, the warning has been visible for at least one full release cycle.
4. After removal, the entry stays here under §"Removed" with the commit SHA, so anyone debugging a forgotten dependency can find what happened.

---

## Currently queued for deprecation

*(none yet — this section gets populated as v1.1 prep identifies cleanup candidates)*

| Item | Type | Target removal release | Reason | Warning policy | Owner |
| --- | --- | --- | --- | --- | --- |
| _example pending_ | _CLI flag_ | _v1.2_ | _superseded by configuration file_ | _warning printed in v1.1 when used_ | _project lead_ |

To add to this table: append a row, then verify the corresponding code path has (a) a deprecation warning in the *current* release, (b) an actual removal scheduled in the target release, (c) documentation updated to reflect the new way.

---

## Candidate items to evaluate before v1.1

These are flags / features / code paths I'd audit before v1.1 ships, with the question *"is this still load-bearing?"* If yes, keep. If not, queue for removal in v1.2.

| Candidate | Where | Question to answer |
| --- | --- | --- |
| `rolling-finality` cargo feature | `Cargo.toml` `[features]` | Was added off-by-default for safe rollout. Will v1.1 ship with this on by default? If yes, the feature flag itself can be retired (the code becomes always-on, not feature-gated). |
| `sketch-cut-through`, `sketch-block-aggregation`, `sketch-kernel-offsets`, `sketch-lelantus-spark` cargo features | `Cargo.toml` `[features]` | These gate post-mainnet phase-2 research code. They're harmless behind-flag, but the gated modules add audit-perimeter ambiguity ("is this code shipped or not?"). Audit before v1.1: either commit to keeping them as research-flags OR move the code out of `src/` into a `research/` subtree. |
| `metrics` cargo feature | `Cargo.toml` `[features]` | If metrics ship by default in v1.1 (as the operational story suggests), the feature flag becomes vestigial. |
| `testnet` / `mainnet` cargo features | `Cargo.toml` `[features]` | Both currently equivalent (both gate `randomx`). If they stay equivalent at v1.1 mainnet ship, collapse to one. |
| `test-vdf` / `test-utilities` cargo features | `Cargo.toml` `[features]` | Diagnostic knobs. Audit whether the gated test code is exercised by anyone outside dev — if no, fold into `#[cfg(test)]`. |
| `bridge` workspace crate | `crates/bridge/` | Predates the `coincync-swap` crate (which is the actual CIP-001 bridge work). Audit whether anything still depends on it; if not, remove. |
| Old wallet file format | (if any exists from pre-v1.0) | If v1.0.x changed the wallet file format, the migration path for the older format probably has a clean deprecation window now. |
| `docs/BLOCKCHAIN_ROADMAP.md` | `docs/` | Repositioned 2026-05-18 as technical-context (not authoritative roadmap). If `docs/roadmap.md` is the canonical surface, evaluate whether BLOCKCHAIN_ROADMAP.md should be archived to `docs/archive/` after v1.1 ships. |
| `tmp-deploy-fix/` directory | repo root | Per the name, this is a transient deploy artifact. Confirm it can be removed; if yes, do it before v1.1. |

These are **candidates**, not commitments. The point is to make the audit happen, not to pre-commit to removal.

---

## Removed

*(empty for now; this section gets entries as removals ship)*

| Item | Removed in | Commit SHA | Removal date |
| --- | --- | --- | --- |
| _example_ | _v1.2_ | _abc1234_ | _2026-12-01_ |

---

## What this discipline buys you

1. **No accumulating cruft.** Every Rust codebase that ships for years grows feature flags, deprecated CLI flags, vestigial config keys, dead-code-paths-behind-conditionals. CoinCync's posture: the codebase *shrinks* across releases, not just grows.
2. **Clear migration story for users.** A flag that disappears without warning breaks workflows. A flag with an N-1 deprecation warning gives users time to migrate.
3. **Smaller audit surface over time.** Removing dead code shrinks what auditors review, which makes audits cheaper and faster.
4. **Honest signaling to outside observers.** A project that *only* adds is in startup-mode. A project that adds *and removes* is in product-maintenance mode. CoinCync should be in product-maintenance mode by v1.2+.

---

## Not on this schedule (and why)

- **Consensus rules.** A consensus rule cannot be deprecated through this schedule — it requires a [CIP-007](cip/CIP-007-hard-fork-activation-policy.md) hard fork. Consensus changes are in [docs/roadmap.md](roadmap.md) and the CIP register, not here.
- **API stability.** RPC method signatures and on-disk file formats follow a stronger stability commitment than this schedule provides. Breaking changes to those are infrequent, announced via release notes well in advance (typically N-2 or N-3 releases of warning, not N-1).
- **The Constitution.** Articles cannot be deprecated. Period. Article XVIII (or the relevant amendment article) is the only mechanism for any change to constitutional text, and "deprecation" is not how that works.
- **Cyncswap and CyncHub primitives.** Once these ship to mainnet, the cryptographic primitives they use are not replaceable through this schedule. Replacement would be a CIP-007 hard fork process (for consensus-touching parts) or a wallet major-version event (for client-side parts).

---

## How this relates to other docs

- [docs/roadmap.md](roadmap.md) — what's *added* in each release. The deprecation schedule is the symmetric companion: what's *removed* in each release.
- [docs/explicitly-not-doing.md](explicitly-not-doing.md) — what's never added. Doesn't intersect with this doc; deprecation is about removing things that *were* added.
- [docs/cip/README.md](cip/README.md) — CIPs go through their own status lifecycle (Sketch → Draft → Approved → Shipped → Activated). CIPs that are explicitly *rejected* are documented in the relevant CIP file, not here.

---

## Changelog

- **2026-05-18** — Document created as the Apple-style Principle 10 scaffold. Queue is intentionally empty at creation time — first entries land as v1.1 prep audit identifies cleanup candidates. Candidate-to-evaluate list seeded from a scan of `Cargo.toml` features + the repository tree at the time of creation.
