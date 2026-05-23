<!-- markdownlint-disable MD036 MD040 -->
# CoinCync — Milestone Update 2026-05-22

**Status:** draft. Three formats: long form (website / blog hero copy), Discord (community channel, under embed limits), short social (X / Mastodon / Nostr).

This update covers the work done between the 2026-04-30 testnet launch and 2026-05-22, focused on three milestones:

1. **Staged-mainnet decision** — v1.0 ships the base chain alone on October 1, 2026; cyncswap atomic-swaps ship as v1.1 after their own dedicated audit
2. **Pre-audit hardening pass** — 23 real fixes shipped across the v1.0 audit perimeter, 585/585 lib tests green
3. **Wallet v2 redesign** — Apple-aesthetic rebuild with reactive push-event wiring, full onboarding flow, working settings, no-mock-data everywhere

---

## 1. Long Form — Website / Blog

**Title:** *Staged mainnet locked in: base chain ships October 1, cyncswap ships after its own audit*

**Subtitle:** *A staging decision, an audit-prep pass, and a wallet rebuild — what's actually shipping for v1.0 and why.*

---

### The staged-mainnet decision

CoinCync v1.0 mainnet now has a definitive scope: the base chain alone. October 1, 2026. Mine, send, receive, multi-sig FROST, the full seven-feature privacy stack (decoy defense, encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead man's switch, auto-churn), six-layer reorg defense (CIP-009), Bulletproofs+ range proofs, CLSAG ring signatures, RandomX CPU PoW. The thing privacy-money users have been waiting for since the testnet went live.

**What's *not* in v1.0:**

- **Cyncswap** (CIP-001 atomic swap protocol — CYNC↔BTC) ships as v1.1, after its own dedicated audit clears. Target Q1–Q2 2027, kickoff ~30 days post-mainnet
- **Orchard shielded pool** (CIP-013 Phase-2 activation) ships in its own later v1.x release, post its own audit

This is a deliberate change from the prior framing that bundled atomic-swap support into the mainnet launch. The reasoning is in the decision record at [`docs/decisions/2026-05-20-staged-mainnet-and-cyncswap.md`](../decisions/2026-05-20-staged-mainnet-and-cyncswap.md). The short version:

- **Cyncswap is the largest novel-cryptography surface in the codebase.** Schnorr adaptor signatures over BIP-340 secp256k1 + Ristretto255, strict-binding cross-curve DLEQ (Noether 2018), joint-key CLSAG construction for the CYNC side, two transports (Noise XX, SOCKS5/Tor). It's audit-ready in isolation today (346 tests pass with `--features strict-dleq`, 100% mutation score on audit-critical files, ~97% line coverage, multiple clean 24-hour fuzz runs), but its audit perimeter is large enough that bundling it into the base-chain audit would add 3–6 months to the mainnet window for code the chain itself does not depend on.
- **Monero used the same staging.** Launched in 2014 with ring signatures and stealth addresses. Bulletproofs (2018), CLSAG (2020), and other novel primitives shipped later, each behind its own audit. The chain established itself first, then the privacy stack hardened around it. CoinCync follows the same posture.
- **Audit firms produce cleaner reports on one perimeter at a time.** A base-chain-only audit is sharper than a bundled audit. The audit firm reviews one cryptographic surface, scoped against its own threat model, with clearer findings.
- **Risk isolation.** If the cyncswap audit surfaces something serious, it does not block the base chain. Users on mainnet keep using the chain; the swap layer ships when fixed.
- **The constitutional commitment doesn't change.** Article XV still requires atomic-swap support. It just requires it on the chain, not on the genesis block.

The public roadmap at [`docs/roadmap.md`](../roadmap.md) reflects this. So does the live site at [coincync.org](https://coincync.org) — the roadmap section was redeployed earlier this week.

### Pre-audit hardening pass

A focused review pass across the ~165 source files in the v1.0 audit perimeter. The goal: close low-hanging audit findings before the audit firm starts, so its report is shorter and tighter. Full disposition list at [`docs/v1.0-base-chain-hardening-punchlist.md`](../v1.0-base-chain-hardening-punchlist.md). Companion audit-prep doc for the firm itself at [`docs/v1.0-mainnet-audit-prep.md`](../v1.0-mainnet-audit-prep.md).

**Twenty-three fixes shipped**, grouped by class:

- **Availability** — `parking_lot::RwLock` swap in `consensus/rolling_finality.rs` closes 4 panic-on-poison sites with one dep swap. `RUST_LOG` parse-error no longer panics before tracing init (chained fallback to `info` with stderr warn).
- **DoS hygiene** — WebSocket handler in `rpc/rest.rs` now has a 5-minute idle timeout, per-IP cap of 5 connections alongside the global 128, and treats protocol errors as connection-close. X-Forwarded-For / X-Real-IP headers are gated behind a `COINCYNC_TRUST_PROXY_HEADERS=1` env var (default off — direct clients can't spoof past per-IP rate limits). Noise XX handshake frame cap dropped from 65 535 to 8 192 (the previous check was dead code given `u16::from_be_bytes`). The `max_blocks` parameter on `lightwallet.rs` now returns an explicit error on over-cap instead of silently clamping.
- **DB corruption error propagation** — six sites of the same pattern (`try_into().unwrap_or([0u8; 8])` silently coercing malformed keys to 0): `db/blocks.rs`, `db/keys.rs` (×2), `db/state.rs` (×2), `db/filters.rs`. All now propagate `DatabaseError` with the actual malformed-key length so the operator sees the issue instead of getting a phantom "everything is at height 0" reading.
- **Operator visibility** — `dns_seeds.rs` now logs per-entry fallback parse failures, `noise.rs` surfaces `chmod` / `icacls` failures via `tracing::warn`, the rig's auto-detect of available threads logs the error reason on fallback to 1 thread, the rig's daemon client warns when `base_url` is `http://` for a non-localhost host (bearer token would cross the wire in plaintext).
- **Posture** — rig's `/metrics` endpoint default bind dropped from `0.0.0.0` to `127.0.0.1` with a new `--metrics-bind` flag and loud warn on any public bind. `wallet/background_sync.rs` `record_error(msg)` now actually stores the message and surfaces it via `progress().last_error` (was named `_msg` and dropped on the floor).
- **Consensus-layer behavior-preserving refactor** — `consensus/validation.rs:846` bytewise target comparison rewritten to use `target_to_u128` for consistency with the adjustment-ratio check at line 862. Mathematically equivalent today (`max_target = [0xFF; 32]` makes the bytewise check dead code), but defends against any future `max_target` lowering. Required a `critical_files.lock` re-hash.

585 of 585 library tests pass with all fixes applied. Agent-claimed findings had a ~37% false-positive rate (in line with the codebase's standing expectation), so each H-severity claim was verified against the actual source before fixing.

**Fuzz overnight #3** ran the full 24-hour budget across all 27 libFuzzer + AddressSanitizer targets. 26 clean, one slow-input flagged in `fuzz_wallet_persistence` (DoS-class, not memory-unsafety — queued as audit-prep follow-up).

**Update — fuzz overnight #4 (2026-05-23):** ran the same 27-target / 24-hour budget against the post-v1.0.9 main branch. **Surfaced a real panic-on-malformed-input DoS** in `wallet/persistence.rs::KdfParams::validate()` — the function bounded Argon2 m_cost, t_cost, and p_cost individually but missed the RFC 9106 §3.1 cross-constraint `m_cost ≥ 8 × p_cost`. A crafted wallet header with `m_cost=8 + p_cost=16` passed validate(), reached `Argon2::Params::new()`, and triggered `MemoryTooLittle` → `.expect()` panic. Closed in commit `6e06b6f`. Argon2 upper caps also tightened in `69c27dc` (1 GiB → 512 MiB, 100 iter → 32, 16 lanes → 8) to close 3 related slow-units that exploited the previous "future-proof" bounds. Both fixes shipped pre-audit; fuzz overnight #5 launched against the patched code to confirm a clean baseline before the audit firm engages. Read: the fuzz pipeline is working as intended — catches real bugs pre-audit, fixes them, re-validates. That's a stronger audit-prep posture than "26 clean" would have been.

### Wallet v2 redesign

[`coincync-wallet-v2/`](../../coincync-wallet-v2/) is a fresh Tauri 1.6 desktop wallet, built from scratch on the v1 Rust backend with an Apple-aesthetic frontend. The redesign happens because the v1 wallet was scaffolded fast enough to ship the testnet, and v1.0 mainnet deserves something polished.

**What landed in this session:**

- **Three reactive push-event channels from Rust → JS** — `chain_state` (2-second background poll on `get_info`), `wallet_state` (emitted on unlock / lock / scan / send), `mining_stats` (emitted on start / stop / 3-second monitor tick). Plus `tx_received` and `block_found` for distinct "something arrived" notifications. The JS subscribes once at boot and updates reactively; zero per-component `setInterval` polling anywhere.
- **Typed errors on the 8 most-touched commands** — `WalletError` enum serialized as `{ code: "AUTH_INVALID_PASSWORD", wait_secs: 30, ... }` so the JS pattern-matches on the variant code instead of substring-matching error-message text. Variants carry structured detail (`AuthRateLimited { wait_secs }`, `InvalidAddress { reason }`, etc.). Migration recipe documented for the remaining 25 commands.
- **Full first-launch onboarding flow** — boot detects whether a wallet file exists; if not, routes to "Set up your wallet" with two cards: Create new wallet (password → 24-word seed display with mandatory acknowledgement → dashboard) or Restore from seed phrase (12/24-word input + new password → dashboard). After any unlock / create / restore, an auto-scan kicks off so the balance and transaction list populate without a manual sync click.
- **Working settings page** — color scheme (four themes: dark / gold / midnight / paper light-mode), reduce-motion toggle, font-weight selector, auto-lock minutes, require-password-on-send, default fee tier. All preferences persist to localStorage. Theme applied before the splash renders so there's no flash on first paint. Backend-required rows (change password, view seed, network switching, BTC RPC, Tor proxy, ring size, devtools) are explicitly badged "SOON" with a violet pill so users see the future-work.
- **Mining wired end-to-end against the real chain** — Start spawns the `coincync-rig` subprocess with `--metrics-port 28091` (loopback). A monitor thread scrapes the Prometheus `/metrics` endpoint every 3 seconds for live hashrate and blocks-found counters. When a block is actually found, a `block_found` push event fires a gold-glowing toast and auto-triggers `scan_wallet` so the coinbase reward lands in the displayed balance. Backend refuses to mine if the wallet is locked, if the address is empty, or if the address matches the development placeholder string.
- **No mock data anywhere user-facing** — state defaults are zero / empty across the board. Dashboard activities, history rows, address book, receive screen, mining stats all render from real state with illustrated empty states when empty ("Receive your first CYNC" with a CTA pill, "No saved addresses yet," "Unlock your wallet to start mining"). The browser-preview mode still has canned responses for design demos, but they never fire in the Tauri-launched wallet that real users see.
- **Brand mark consistency** — the favicon, the splash logo, the unlock-screen logo, the sidebar mark, and the Tauri window / taskbar / dock icons all now render the canonical CoinCync face (gold ring with an open right-side mouth and two gold dots inside). Multi-platform icon set (`icon.ico`, `icon.icns`, multi-resolution PNGs) regenerated from a 1024×1024 source.

### Audit-prep documentation

The audit firm gets a wayfinding layer separate from the spec:

- [`docs/v1.0-mainnet-audit-prep.md`](../v1.0-mainnet-audit-prep.md) — the base-chain audit-prep doc. 12 sections. Scope (~73 000 LOC across `src/` + the four v1.0 supporting crates), license + IP boundary, cryptographic primitives map (16 primitives), 14 prioritized review targets (RandomX FFI safety first), conceptual clarifications, test-vector inventory, knowingly-missing items, build + test reproducibility commands.
- [`docs/cyncswap-audit-prep.md`](../cyncswap-audit-prep.md) — the cyncswap audit-prep doc (separate engagement, separate firm encouraged for fresh-eyes review)
- [`docs/security/wallet-file-v4-design.md`](../security/wallet-file-v4-design.md) — design doc for the wallet file v4 format (HMAC-over-(header‖nonce‖ct) with HKDF-derived independent MAC key). Closes the header-tampering timing channel. Unscheduled future-work — not for v1.0 ship.
- [`docs/wallet-v2-in-process-library-design.md`](../wallet-v2-in-process-library-design.md) — design for replacing the CLI-subprocess pattern in the wallet with a direct in-process library link. Unscheduled future-work / v1.0.x polish window.
- [`docs/wallet-v2-design-research.md`](../wallet-v2-design-research.md) — clean-room trail from the Rainbow (GPL-3.0) study during the wallet redesign. Records what design patterns were observed at the idea level only — no values, no curves, no hex codes, no source copied. Audit-defensible posture.

### What's next

In rough order:

1. **Roll the dashboard's design treatment across the other 10 wallet screens** (send, receive, swap, history, settings, addresses, mining, multi-sig, unlock, splash). Incremental, no schedule pressure.
2. **Tighten the remaining 25 typed-error migrations** in the wallet. Mechanical work; ~5–15 minutes per command following the documented recipe.
3. **Base-chain audit scheduling.** NLnet outreach to Cypher Stack / OSTIF / Teserakt; engagement target ~July.
4. **Genesis ceremony prep** — mainnet seed nodes, initial checkpoint set, monitoring, DNS, the operational mechanics of the October 1 launch.
5. **CIP-009.D production-posture decision** — does v1.0 mainnet ship the rolling-finality machinery dormant (feature-gated, off by default) or active (with checkpoint signers elected)? Either is defensible; pick one before tag.

### How to follow / contribute

- **Source:** [github.com/ghostrider1092/Coincync-Testnet-](https://github.com/ghostrider1092/Coincync-Testnet-)
- **Live testnet:** mainnet target is October 1, 2026; testnet is live now at [explorer.coincync.network](https://explorer.coincync.network)
- **Discord:** community + dev-updates channels for technical discussion
- **Roadmap:** [`docs/roadmap.md`](../roadmap.md) is the source of truth for what ships when. v1.0 → v1.3 is the committed window; anything past v1.3 is research, not roadmap.

This update is intentionally detailed because the audit firm and serious contributors need the substance, and casual readers should still come away with the headline: **base chain ships October 1, 2026; cyncswap ships in v1.1 after its own audit; the work is on schedule.**

---

## 2. Discord — community channel

```
🛡️ **CoinCync milestone update — 2026-05-22**

Three things landed since the testnet went live:

**1. Staged-mainnet decision locked in.**
v1.0 mainnet ships the base chain alone on October 1, 2026 — mining,
send / receive, multi-sig, the 7-feature privacy stack, 6-layer reorg
defense. Cyncswap (CYNC ↔ BTC atomic swaps) ships as v1.1 after its
own dedicated audit clears, target Q1–Q2 2027. Same chain-first /
novel-crypto-later staging Monero used. The audit firm reviews one
cryptographic perimeter at a time, the base-chain ship doesn't block
on cyncswap findings, and the cyncswap audit kicks off from a frozen
commit ~30 days post-mainnet.

Full rationale: `docs/decisions/2026-05-20-staged-mainnet-and-cyncswap.md`
Roadmap: `docs/roadmap.md` (also live at coincync.org)

**2. Pre-audit hardening pass shipped.**
23 real fixes across the v1.0 audit perimeter (~165 source files
reviewed). Highlights:
• `parking_lot::RwLock` swap closes 4 panic-on-poison sites in
  rolling_finality.rs
• WS DoS hygiene — 5-min idle timeout, per-IP cap, XFF gating
• Noise handshake frame cap 65 535 → 8 192
• 6 sites of silent DB-corruption fallback converted to error propagation
• Metrics endpoint default-bind to loopback with new --metrics-bind flag
• validation.rs target-comparison refactor + critical_files.lock re-hash

585/585 lib tests green throughout. Punch list:
`docs/v1.0-base-chain-hardening-punchlist.md`. Audit-prep doc ready for
the firm at `docs/v1.0-mainnet-audit-prep.md`.

**3. Wallet v2 rebuild taking shape.**
Apple-aesthetic Tauri redesign with full reactive wiring (3 push-event
channels Rust → JS, no per-component polling), typed errors, complete
first-launch onboarding flow (Create new wallet / Restore from seed),
working settings page with 4 selectable color themes + 5 persisted
preferences, mining wired end-to-end with /metrics-scraped live hashrate
+ block-found auto-rescan, zero mock data anywhere user-facing.

`coincync-wallet-v2/` in the repo.

**Fuzz overnight #3:** 24h budget, 27 targets, ASAN. 26 clean, 1
slow-input flagged in fuzz_wallet_persistence (DoS-class, queued).

**Next**: dashboard polish across the other 10 wallet screens, base-chain
audit scheduling, genesis ceremony prep. October 1, 2026 still on track.
```

---

## 3. Short Social — X / Mastodon / Nostr thread

```
🛡️ CoinCync milestone update.

v1.0 mainnet now scoped as base chain alone — October 1, 2026.
Cyncswap (atomic swaps) ships as v1.1 after its own audit
clears, target Q1–Q2 2027.

Same chain-first / novel-crypto-later staging Monero used.

[🧵]
```

```
2/ Why staged:

— Cyncswap = largest novel-crypto surface in the codebase
  (Schnorr adaptors × 2 curves, cross-curve DLEQ, joint-key
  CLSAG, Noise+Tor)
— A separate audit reviews one cryptographic perimeter cleanly
— Base-chain ship doesn't block on cyncswap audit findings
— Risk isolation: cyncswap issues don't ground the chain
```

```
3/ Pre-audit hardening pass shipped today: 23 real fixes
across the v1.0 audit perimeter (~165 source files reviewed).

585/585 lib tests green. 24h fuzz overnight: 27 targets, 26
clean, 1 slow-input flagged (DoS class, queued).

Punch list + audit-prep doc public in repo.
```

```
4/ Wallet v2 redesign progress:

— Reactive event-driven UI (Rust → JS push events, no polling)
— Full first-launch onboarding (create / restore from seed)
— Working settings page, 4 color themes, persisted prefs
— Mining wired end-to-end with live hashrate + block-found
  auto-rescan
— Zero mock data — every screen renders real state
```

```
5/ Article XV (constitutional commitment to atomic-swap support)
unchanged. v1.0 ships the chain. v1.1 ships the swaps.

Next 6 months: base-chain audit, genesis ceremony prep,
mainnet seed nodes, October 1 launch.

Source: github.com/ghostrider1092/Coincync-Testnet-
Roadmap: coincync.org
```

---

## 4. Open commitments embedded in this update

For the operator running the announcement, items in this post that imply a future obligation:

- **October 1, 2026** — v1.0 base-chain mainnet launch
- **~30 days post-mainnet** — cyncswap audit kickoff
- **Q1–Q2 2027** — cyncswap audit clearance + v1.1 ship
- **Audit firm** — Cypher Stack / OSTIF / Teserakt outreach (NLnet-funded). Names should be confirmed before public mention if not already secured
- **Article XV unchanged** — implies the constitution stays as written; any future amendment is a separate CIP

If any of these are softer than the wording suggests, edit the drafts before posting.

---

## 5. Changelog

- **2026-05-22** — Document created. Captures the 2026-05-21 hardening session, the 2026-05-20 staged-mainnet decision, and the wallet v2 redesign work that landed in the same window.
