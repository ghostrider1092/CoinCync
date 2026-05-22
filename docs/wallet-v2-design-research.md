<!-- markdownlint-disable MD036 MD013 -->
# Wallet v2 — design-research notes (Rainbow, Phantom)

**Created:** 2026-05-21
**Purpose:** clean-room trail. Records what we observed from public references at the **idea** level only, so an audit firm has a defensible answer to "where did your wallet design language come from?"

**What this document is NOT:**

- Not a copy of Rainbow's source code (Rainbow is GPL-3.0; CoinCync is MIT — direct copying would be a license violation)
- Not a record of specific color hex values, animation curves, font metrics, or component file structures observed in any reference codebase
- Not a derivative work of any other wallet

**What this document IS:**

- A high-level summary of design patterns that are commonplace in modern crypto wallet UX
- A record of the ideas we drew on for the v2 wallet's design language
- The audit-firm-facing answer to "did you copy from Rainbow / Phantom / Cake / etc.?" — *we studied the user-facing patterns; we implemented from those patterns; no source code was lifted*

---

## 1. References consulted

| Reference | License | What was studied |
| --- | --- | --- |
| Rainbow (rainbow-me/rainbow) | GPL-3.0 | Three design-system files: `typography/typography.ts`, `layout/space.ts`, `layout/shapes.ts`. Read for general pattern language; no values, curves, or hex codes lifted. The clone at `c:\dev\rainbow-reference` is reference-only and is **not** in the CoinCync workspace. |
| Phantom | Closed-source | App Store screenshots, public marketing site, the running app's observable behavior. No source available; no source studied. |
| Cake Wallet | (Public-source variant exists; not studied for v1.0) | Mentioned in passing as the privacy-coin UX benchmark; no source read. |
| Apple Human Interface Guidelines | Public spec | Spring-physics, hit-target sizing, focus-ring posture |
| Material Design 3 | Public spec | Elevation tokens, motion duration scales |

---

## 2. Patterns observed (idea-level only)

### 2.1 Typography

- **Rounded typefaces feel warmer than standard sans-serif** in wallet contexts. Several public references use rounded variants (SF Pro Rounded on iOS, system-font equivalents on Android). The general pattern: a rounded face for body + numbers, a serif or display face for hero moments.
- **Capsize-style typography trimming** is increasingly common — trimming ascender/descender whitespace so display sizes feel tighter to their visual centerline. Implemented in CSS via `text-box-trim: cap` (modern browsers) or manual line-height tuning.
- **Distinct weight ranges for headings vs. text.** Headings get heavy/bold/black weights only; body text spans the full range. This keeps hierarchy clean.

Our v2 wallet uses Fraunces (serif display) + Inter (body) + JetBrains Mono (technical surfaces). Already differentiated — the choice ahead is whether to also adopt a rounded variant somewhere (e.g., a rounded face for primary CTAs).

### 2.2 Spacing scale

- **Token names that preserve the pixel value** (e.g., "16px" as the token name itself) trade off semantic naming for at-a-glance value recall. Our v2 uses semantic naming (`--sp-4` = 16px). Both valid; our convention is more abstract.
- **The scale doesn't have to be strictly mathematical.** Common practice: 4, 8, 12, 16, 20, 24, 32, 40, 48, 64, 80 — with deliberate gaps where visual rhythm calls for them, not strict doubling.
- **Audit-deprecation discipline.** Some references mark certain spacing tokens as `(Deprecated)` once they're identified as non-conforming. We don't need this yet; worth keeping in mind as the wallet matures.

### 2.3 Shape language

- **Squircle (superellipse) corners feel softer than circular-arc rounded corners.** iOS uses squircles natively for app icons and many UI surfaces. The perceptual difference is subtle but real — squircles avoid the visual "kink" where the straight edge meets the curve.
- **Platform-aware corner smoothing** — iOS squircles, Android material-style rounded rectangles. Cross-platform wallets choose between consistency (one corner style everywhere) and native-feel (per-platform).
- **In CSS, full squircle is hard** — `border-radius` produces circular-arc corners. Approximations exist (`clip-path: path(...)` with a precomputed squircle SVG, or libraries like `figma-squircle` to generate the path). For v1.0, sticking with `border-radius` is fine; squircles are a polish item.

### 2.4 Color philosophy

- **Brand-led, neutral-backed.** Strong primary brand color (Rainbow's purple/pink, Phantom's purple) lives mostly on hero surfaces. Vast majority of the UI is neutral grays + tints.
- **Color-coded semantics that the user learns once.** Inbound transactions are one color, outbound another, pending a third. Consistent across every screen.
- **Accent gradients used sparingly.** Hero balances, primary CTAs, brand moments — yes. Body text, secondary UI — no.

Our v2 uses gold as the primary brand color. Today's session added violet + pink as secondary warmth accents (in `tokens.css`). Not loud; available for state changes and empty states.

### 2.5 Motion patterns

- **Spring physics on every tap.** The user's finger lands → the surface scales down slightly → on release the scale springs back with overshoot. Read as tactile, alive.
- **Layered easing curves.** Standard ease for hover, snappy ease for active, spring-with-overshoot for release. Three different curves on one element, but each tied to a different state.
- **Sub-100ms perceived latency.** Show the response BEFORE the work completes. Pulse the button into its "loading" state instantly; let the network confirmation lag behind.

The v2 wallet now has `--ease-bounce` (stronger overshoot than `--ease-spring`) for the tap-release moment. Applied to action cards today.

### 2.6 Empty states

- **Empty wallets are a beginning, not a void.** First-receive screens are illustrated, conversational, and warm. The empty transaction list says "Receive your first ___" not "No transactions yet."
- **Soft animations on empty-state art.** Breathing rings, gentle pulses — gives the empty state presence without being distracting.

The v2 wallet's dashboard now has an illustrated empty state for the activity list (`.activity-empty*` in `dashboard.css`), with a breathing violet+gold glow ring and a primary CTA pill that routes to the receive screen.

### 2.7 Conversational microcopy

- **Talk to the user, not at them.** "Send" / "Receive" labels are fine; the subcopy underneath benefits from sentence-style writing.
- **Avoid jargon on the first surface.** Save terms like "stealth address," "ring size," "view key" for settings or technical surfaces; the dashboard talks in human language.

The v2 wallet's action-card subcopy was rewritten today:

- "Outgoing transaction" → "Pay anyone, anywhere"
- "Get paid · stealth address" → "Show this to get paid"
- "Earn block rewards" → "Earn while you sleep"

---

## 3. What we are NOT taking

To preserve the clean-room argument explicitly:

- **No animation curves copied.** The `cubic-bezier` values in our `tokens.css` are either standard Apple curves (commonplace in documentation) or curves we chose at the keyboard.
- **No color hex values copied.** Our gold + violet + pink palette was chosen for CoinCync's brand independently.
- **No type-scale values copied.** Our `--fs-*` tokens were set to fit the wallet's hero-balance + body-text + technical-surface contexts, not borrowed.
- **No component file structures copied.** Our wallet is vanilla JS + per-feature CSS files; the references are React Native + TypeScript design-system trees. Architecturally incompatible.
- **No copyrightable expression of any kind.** Every line of CSS and JS in `coincync-wallet-v2/web/` was written here.

---

## 4. Recommended next steps for the v2 wallet

Based on the patterns above, the highest-leverage moves for the remaining 10 screens:

1. **Spring-physics tap feedback** — apply the same `--ease-bounce` + scale-0.97 pattern used on dashboard action cards to every button, list row, and CTA.
2. **Hero-confident type at the top of every screen** — display weight + tight letter-spacing + soft halo for the primary number/title.
3. **Illustrated empty states everywhere** — send-with-no-contacts, history-with-no-txs, multi-sig-with-no-sessions, etc. Each one is a small piece of soft-CSS-illustrated art + conversational copy + a primary CTA pill.
4. **Conversational subcopy pass** across the remaining screens.
5. **Sub-100ms tap acknowledgment** — pre-render screens, never show a spinner under 300 ms, animate the *intent* to load before the load itself.

Estimated effort: ~2 hours per screen at the same quality bar as the dashboard PoC. 10 screens → ~20 hours total, easily a 2-3 day focused push.

---

## 5. Audit-firm-facing posture

If the v1.0 audit firm asks "where did the wallet design language come from?" — the honest answer is:

> "The v2 wallet design draws on commonplace patterns in modern crypto-wallet UX — spring-physics tap feedback, display-size hero typography, illustrated empty states, conversational microcopy, color-coded transaction semantics. These patterns are documented in public design systems (Apple HIG, Material Design 3) and observable in every modern wallet's running app. The implementation is clean-room CSS + vanilla JS, written for CoinCync. No source code was copied from any reference codebase; the GPL-3.0 Rainbow repo was studied at the pattern level only (this document records what was observed), and the closed-source Phantom wallet was only studied through its running app's observable behavior."

That answer is defensible because:

- The patterns named (spring physics, hero type, etc.) are commonplace, not Rainbow-specific
- No values, curves, structures, or code were transferred
- This document records the boundary in writing, contemporaneously with the work

---

## 6. Changelog

- **2026-05-21** — Document created during the v2 wallet dashboard PoC session. Records the design-research trail for the audit firm and for future implementers who want to know "why does the wallet look the way it does." Reference clone of Rainbow at `c:\dev\rainbow-reference` is workspace-external and is intended to be deleted once the v2 wallet is shipped.
