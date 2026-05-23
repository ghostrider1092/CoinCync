<!-- markdownlint-disable MD036 MD034 MD040 -->
# GitHub Release — 2026-05-22

**Suggested tag:** `v1.0.9-testnet-pre-audit`
**Title:** `v1.0.9 — Pre-audit hardening + wallet v2 redesign`
**Target branch:** `main`
**Mark as:** Pre-release (this is a milestone snapshot, not a binary cut)

---

## Release body (paste into GitHub Releases UI, or use the `gh` command below)

```markdown
## Highlights

- **Staged-mainnet decision locked in.** v1.0 mainnet ships the base chain alone on **October 1, 2026**. Cyncswap (CYNC↔BTC atomic swaps) ships as v1.1 after its own dedicated audit clears, target Q1–Q2 2027.
- **23 pre-audit hardening fixes** across the v1.0 audit perimeter. 585/585 library tests green.
- **Wallet v2 rebuild** (`coincync-wallet-v2/`) — Apple-aesthetic Tauri redesign with full reactive push-event wiring, typed errors, complete first-launch onboarding, working settings, zero mock data.
- **Fuzz overnight #3** — 24h budget, 27 libFuzzer + ASAN targets, 26 clean, 1 slow-input flagged (DoS-class, queued).
- **Post-release update (fuzz #4, 2026-05-23):** A subsequent 24h fuzz pass surfaced a real panic-on-malformed-input DoS in `wallet/persistence.rs::KdfParams::validate()` — missing RFC 9106 §3.1 cross-constraint check (`m_cost ≥ 8 × p_cost`). Fixed in `6e06b6f`; Argon2 upper caps additionally tightened in `69c27dc`. Both shipped to `main` pre-audit. Overnight #5 launched against patched code to confirm clean baseline. Working fuzz pipeline catching real bugs is a stronger pre-audit signal than "all clean."

---

## Why staged mainnet

Cyncswap is the largest novel-cryptography surface in the codebase: Schnorr adaptor signatures over two curves, strict-binding cross-curve DLEQ (Noether 2018), joint-key CLSAG, two transports (Noise XX, SOCKS5/Tor). Bundling it into the base-chain audit would add 3–6 months to the mainnet window for code the chain itself does not depend on.

Same staging Monero used: chain first, novel privacy crypto later, each behind its own audit.

Article XV (constitutional commitment to atomic-swap support) unchanged — v1.0 ships the chain, v1.1 ships the swaps.

Full rationale: [`docs/decisions/2026-05-20-staged-mainnet-and-cyncswap.md`](../decisions/2026-05-20-staged-mainnet-and-cyncswap.md)

---

## Pre-audit hardening — what shipped

23 fixes across ~165 source files in the v1.0 audit perimeter. By class:

- **Availability** — `parking_lot::RwLock` swap closes 4 panic-on-poison sites in `consensus/rolling_finality.rs`. `RUST_LOG` parse-error no longer panics before tracing init.
- **DoS hygiene** — WS handler in `rpc/rest.rs` now has 5-min idle timeout, per-IP cap of 5, XFF gated behind `COINCYNC_TRUST_PROXY_HEADERS=1`. Noise XX frame cap dropped 65 535 → 8 192. `lightwallet.rs` `max_blocks` returns explicit error on over-cap instead of silently clamping.
- **DB corruption error propagation** — 6 sites of silent `try_into().unwrap_or([0u8; 8])` converted to `DatabaseError` propagation (`db/blocks.rs`, `db/keys.rs`, `db/state.rs`, `db/filters.rs`).
- **Operator visibility** — `dns_seeds.rs`, `noise.rs`, rig auto-detect + daemon client now surface failures via `tracing::warn` instead of dropping them.
- **Posture** — rig `/metrics` default-bind dropped from `0.0.0.0` to `127.0.0.1` with new `--metrics-bind` flag. `wallet/background_sync.rs` `record_error(msg)` now actually stores the message.
- **Consensus refactor** — `consensus/validation.rs:846` target comparison rewritten to use `target_to_u128` for consistency. Behavior-preserving but defends against any future `max_target` lowering. Required `critical_files.lock` re-hash.

Full disposition list: [`docs/v1.0-base-chain-hardening-punchlist.md`](../v1.0-base-chain-hardening-punchlist.md)
Audit-prep doc for the firm: [`docs/v1.0-mainnet-audit-prep.md`](../v1.0-mainnet-audit-prep.md)

---

## Wallet v2 redesign

[`coincync-wallet-v2/`](../../coincync-wallet-v2/) — fresh Tauri 1.6 desktop wallet on the v1 Rust backend.

- **Three push-event channels Rust → JS** (`chain_state`, `wallet_state`, `mining_stats`) + `tx_received` / `block_found`. Zero per-component polling.
- **Typed errors** on the 8 most-touched commands (`WalletError` enum serialized as `{ code, ... }` so JS pattern-matches on the variant code, not message text).
- **First-launch onboarding** — Create new wallet (password → 24-word seed → dashboard) or Restore from seed phrase. Auto-scan after unlock / create / restore.
- **Settings page** — 4 themes (dark / gold / midnight / paper), reduce-motion, font-weight, auto-lock, require-pw-on-send, default fee tier. All persisted to localStorage. Backend-required rows badged "SOON".
- **Mining end-to-end against the real chain** — Prometheus `/metrics` scrape every 3s, `block_found` push event + auto-rescan when a coinbase lands. Backend refuses to mine on empty / placeholder addresses.
- **No mock data** — every screen renders real state with illustrated empty states.
- **Brand mark consistency** — favicon, splash, unlock, sidebar, Tauri taskbar / dock icons all rebuilt from the canonical face mark.

---

## What's next

1. Roll the dashboard's design treatment across the other 10 wallet screens
2. Tighten the remaining 25 typed-error migrations
3. Base-chain audit scheduling (NLnet outreach to Cypher Stack / OSTIF / Teserakt; engagement target ~July)
4. Genesis ceremony prep — mainnet seed nodes, initial checkpoint set, monitoring, DNS
5. CIP-009.D production-posture decision (dormant vs active at v1.0 genesis)

---

## Commits in this release

- `28946fb` docs: 2026-05-22 milestone announcement
- `72704ad` wallet-v2: full rebuild — Tauri wrapper, reactive wiring, onboarding, settings, no-mock-data
- `a9775ad` docs: v1.0 mainnet audit prep + hardening punch list + design notes
- `a48fa83` roadmap: lock in staged-mainnet decision (v1.0 base chain only, v1.1 cyncswap)
- `12523c0` hardening: pre-audit base-chain pass (23 fixes + lockfile re-hash)

---

## Full announcement

Long-form announcement (with Discord + short-social drafts) at [`docs/launch/MILESTONE-2026-05-22.md`](MILESTONE-2026-05-22.md).
```

---

## How to publish

Tag the release and push the tag, then create the release. Run from the repo root:

```powershell
# 1. Create + push the annotated tag
git tag -a v1.0.9-testnet-pre-audit -m "Pre-audit hardening + wallet v2 redesign" 28946fb
git push origin v1.0.9-testnet-pre-audit

# 2. Create the release from the body file (mark prerelease)
gh release create v1.0.9-testnet-pre-audit `
  --title "v1.0.9 — Pre-audit hardening + wallet v2 redesign" `
  --notes-file docs/launch/GITHUB-RELEASE-2026-05-22.md `
  --prerelease
```

Alternatively, paste the body into https://github.com/ghostrider1092/Coincync-Testnet-/releases/new via the UI.

---

## Notes for the operator

- The `--notes-file` flag will include the entire markdown file including the framing at the top. If you want only the inner release body, copy the fenced block contents into a separate file first, or paste into the UI.
- The repo's branch-protection rules allow tag pushes (only PR-required for branch refs), so the tag push should succeed without bypass.
- Repo has 8 open Dependabot alerts visible to release viewers. Decide whether to triage before publishing.
