# Explorer — Update Log + Roadmap

The public block explorer lives at [explorer.coincync.network](https://explorer.coincync.network)
and is served from the static asset bundle in [src/explorer/](../../src/explorer/).
This document tracks what shipped, what's queued, and what was deliberately rejected.

It's a living roadmap, not a release contract. Items move between
sections as scope and time allow. Effort labels: **S** (under half a
day), **M** (half a day to two days), **L** (two to five days),
**XL** (more than a week).

---

## Recently shipped — 2026-05-23 session (privacy-stats expansion)

Five new pages shipped in a single push after a comparison sweep against
`monerospace.org` (the mempool.space fork retargeted at Monero). Each
exists to surface a CoinCync-specific privacy property that no other
chain's explorer can match. All five share consistent panel styling
and Chart.js bar histograms where applicable.

- **Anonymity-set depth viewer** (`page-anonset`) — driven by
  `get_anonymity_set` RPC with a client-side synthesised-distribution
  fallback when the RPC isn't exposed. Shows decoy-age histogram across
  configurable block ranges (50/100/250/500), plus four stat tiles
  (inputs sampled, decoy pool size, median age, privacy-health score
  computed as inverse-skew of the histogram). Roadmap item #1 of the
  Near-term list. **DONE**.
- **Reorg history page** (`page-reorghistory`) — driven by
  `get_chain_events` filtered to reorg events. Renders the six-layer
  reorg-defense status (L1-3 MESS hybrid, L4 per-node checkpoints, L5
  hardcoded checkpoints, L6 dormant per the 2026-05-23 CIP-009.D
  decision, wallet-side bounded rewind) plus a table of detected reorgs.
  Roadmap item #6. **DONE**.
- **Privacy comparison table** (`page-compare`) — pure content. Four
  side-by-side tables (cryptographic primitives, network privacy, reorg
  defense depth, economic posture) vs Monero / Zcash / Bitcoin / Litecoin
  MWEB. Roadmap Medium-term #5. **DONE**.
- **Mining-live tile** (`page-mininglive`) — `get_mining_live` for the
  hashrate / median / difficulty stats; `get_block_range` for the last
  50 inter-block intervals rendered as a histogram. 10s polling while
  the page is active; clears the interval on navigation away. Roadmap
  Near-term #9. **DONE**.
- **Fee estimator** (`page-feemarket`) — derived purely from
  `get_mempool_transactions`. Recommends Slow / Normal / Fast / Flash
  fees from the 25th / 50th / 75th / 95th percentile of current backlog
  fee_per_byte. Roadmap Near-term #5. **DONE**.

All five linked from both the desktop nav bar (after Supply) and the
mobile menu (under a "Privacy stats" heading). PAGES + PUBLIC_EXPLORER_PAGES
arrays updated; `go()` router has per-page entry hooks.

---

## Recently shipped — v1.0.8 (2026-05-15 session)

### v1.0.8 Network Status panel — NEW

One consolidated 4-tile panel at the top of the home page, refreshing
every 15 seconds while home is the active page.

- **Finality tile** — driven by `get_finality_info` + static CIP-011
  activation heights. Shows chain tip, last checkpoint (every 5 blocks),
  max reorg depth, and distance-to-CIP-011-enable. Transitions through
  three states automatically: *N blocks to enable* → *enabled, awaiting
  enforce* → *enforced* as the chain crosses 50,000 / 75,000 on testnet.
- **Phase-2 storage tile** — driven by `get_shielded_anchor` +
  `get_spark_anchor`. Shows tree sizes and a `REWIND READY` badge while
  sizes are 0 (current state — storage-side rewind machinery wired but
  trees not yet appended to). Flips to `ACTIVE` when the Phase-2 hard
  fork lands and trees start filling.
- **Health tile** — driven by `get_health`. Status badge
  (HEALTHY/DEGRADED), peer count, sync flag. Deep-links to the existing
  fleet health page.
- **Operations tile** — driven by `get_metrics`. Mempool depth, total
  txs, total blocks, "Updated Xs ago" freshness indicator.

Plus a collapsible "What's new in 1.0.8" callout for users who want the
release summary without clicking through to GitHub.

### Stale-prose sweep

- Lines 9359 / 9363 / 9480: "validate_block integration queued
  post-launch" rewritten to "shipped behind `rolling-finality` feature
  flag" with the actual activation heights inline.
- Line 613 testnet banner: "Phase-2 modules disabled" → "Phase-2 stores
  dormant (reorg-rewind machinery wired, trees not yet appended to)".
  Honest about what's done vs. what's pending.
- Version refs bumped from `v1.0.0` / `v1.0.1` to `v1.0.8` in three
  spots (Version label, footer credit, Changelog doc-card).
- Dead `_blockSound = new AudioContext ? null : null` placeholder
  removed (ternary always evaluated to `null`).

### Carried forward

- `<div>` tag imbalance of 2 extra closes — pre-existing, browsers
  auto-recover, real-world impact nil. Documented for future cleanup
  if anyone ever does a structural HTML audit pass.

---

## Near-term — uses existing RPC methods

Estimated 1-2 sprints if pulled together. These all use RPC methods
the node already serves but the explorer doesn't call.

1. **Anonymity-set depth viewer** — `get_anonymity_set`. Show
   per-address ring decoy distribution as a small histogram. Educational
   value high; reinforces "everyone's transactions look the same."
   **M**, high educational value.
2. **Decoy policy visualizer** — `get_decoys`. Interactive demo of the
   V1 target-age distribution and eligible-chain boundaries. **M**.
3. **Real fleet health page** — replace the current `health` tab
   implementation with one driven by `get_health` against each fleet
   node. The RPC method exists; the health page currently fans out to
   per-node `/health/seedN` proxies which is more brittle. **M**.
4. **Mempool age histogram** — extend the mempool tab with a histogram
   of how long pending txs have been waiting. Uses
   `get_mempool_transactions` (already called); just needs a chart. **S**.
5. **Fee estimator widget** — recommend a fee for "next block" vs
   "within 10 blocks" based on mempool pressure. Derives from mempool
   data; no new RPC. **S**.
6. **Reorg history page** — list reorgs that have happened (when, fork
   point, depth). Even if reorgs are rare, the page builds confidence
   that defensive logic is being exercised. Needs `get_chain_events`
   (already called for the supply page) filtered to reorg events. **M**.
7. **CIP browser with search** — the current Proposals page lists CIPs
   as static cards. Add a search box and tag filter. Cards already
   carry status badges; just need a filter UI. **S**.
8. **Sync-status detail** — `get_sync_status` (currently not called)
   exposes per-stage sync progress. Surface on the network tab. **S**.
9. **Mining-live tile** — `get_mining_live` exposes real-time hashrate
   estimate. Add to the mining tab. **S**.
10. **Block-template inspector** — `get_block_template` for the
    pool-config page. Shows what miners are working on. **M**, dev-facing.

## Medium-term — moderate code, may need new endpoints

1. **FROST coord status tile** — depends on `scripts/deploy-coord.ps1`
   actually running. WSS probe against `wss://api.coincync.network/coord/`
   + active-session count from the coord's own `/metrics` endpoint
   (already shipped per CIP-012). **S** once the coord is deployed;
   currently blocked on deploy.
2. **Real-time WebSocket subscription** — replace the 15s `get_metrics`
   poll with a server-side subscription model. Requires a new RPC method
   like `subscribe_chain_events` on the node side. **L** including the
   server-side work. Cuts explorer-to-node load by ~95% under normal
   browsing.
3. **Block-propagation latency distribution** — needs the node to expose
   per-peer "block first seen" timestamps. Useful for diagnosing slow
   peers and operator hardware bottlenecks. **L**.
4. **Geographic peer distribution overlay** — the globe page renders
   3D constellations but doesn't actually use real peer IP → geo
   mapping. Enhancement: pull peer IPs from `get_peers` and resolve via
   a privacy-respecting GeoIP DB (MaxMind GeoLite2 country-level,
   self-hosted, no per-request leak). **M**.
5. **Comparison-table page** — privacy properties side-by-side: CoinCync
   vs Monero vs Zcash vs Bitcoin vs Litecoin MWEB. Educational for
   newcomers; helps Discord moderators answer "why CoinCync over X?"
   without retyping. Pure content. **M**.
6. **Interactive ring-signature visualizer** — animated walkthrough of
   how a CLSAG signature picks 10 decoys + the real signer. Pairs with
   the existing FROST diagram (line 1470 area). **L**, high educational
   value.
7. **Wallet integration deep-links** — `coincync://` URI scheme
   handlers for "open in wallet" buttons. Needs cooperation from the
   Tauri wallet's URI registration. **M**.
8. **Audit history page** — when the first audit lands (NLnet-funded,
   targeting late-2026), explorer needs a page that lists audit reports,
   what was tested, findings, remediations. Drafting it ahead of the
   first audit so the structure is ready. **M**.

## Long-term — depends on Phase-2 / atomic swaps / mainnet

1. **Shielded pool explorer** — when the Phase-2 hard fork activates
   shielded transactions, add a tab that browses anchored Orchard
   blocks, nullifier ranges (publicly visible since they're keys),
   total shielded value, anchor history. **XL**.
2. **Spark coin browser** — same for Lelantus Spark. Browsing
   serial-number commitments and value-tag distribution. **L**.
3. **Kernel-aggregation viewer** — MimbleWimble kernels and cut-through
   stats once Phase-2 lands. **L**.
4. **Rolling-finality attestation viewer** — when CIP-011 enables on
   testnet (height 50,000), surface per-block attestations,
   active-signer set, soft-final tip distance. Requires a new
   `get_rolling_finality_info` RPC method on the node (currently
   doesn't exist — the feature is feature-gated and not RPC-exposed
   yet). **L**, depends on node-side RPC + activation.
5. **CYNC↔BTC swap explorer** — list of in-flight and completed atomic
   swaps. Adaptor-signature state visualization. **XL**, depends on
   atomic-swap implementation (NLnet-funded, multi-month).
6. **Mainnet countdown → mainnet live** — the homepage already has a
   mainnet countdown hardcoded against `src/mainnet.rs`. When mainnet
   launches, the countdown becomes "mainnet live for N days, M blocks";
   the explorer's network-toggle changes from "testnet only" to dual
   testnet+mainnet routes. **M** for the transition; trivial after.

## Performance / scale — parallel to feature work

1. **Lazy-load per-page modules** — the 9804-line monolith parses on
   every page load even if the user only ever visits home. Split into
   one module per `PAGES[]` entry; load on demand inside `go(id)`.
   **L**. Cuts first-paint to under 1s on slow connections.
2. **Asset compression** — the file is ~470 KB uncompressed (~120 KB
   gzipped). Most of the weight is the inline `<style>` and `<script>`
   blocks. Audit for dead CSS / unreachable JS branches. **M**.
3. **Service worker** — offline-friendly browsing for previously-viewed
   blocks. Privacy implications: a service worker can fingerprint via
   resource caching, but cache scoped to static assets only is safe.
   **M**.
4. **Immutable-block HTTP caching** — blocks below `tip - max_reorg_depth`
   never change. Add `Cache-Control: public, max-age=31536000, immutable`
   on the nginx side for those routes. Cuts explorer RPC load
   ~70% for users who browse historical blocks. **S**, nginx-only.
5. **CDN-fronted static assets** — Cloudflare already fronts the
   domain; ensure HTML + JS + fonts are cacheable at the edge with
   sensible TTLs. **S**.

## Developer-facing

1. **API playground** — interactive RPC tester on a `/api` page.
   Currently the API page has documentation; an interactive form that
   lets devs run RPC calls in-browser would be more useful. **M**.
2. **TypeScript types generator** — auto-generate `.d.ts` files for
   every RPC method from the server-side handler signatures. Publish
   to npm as `@coincync/types`. **L**.
3. **SDK download page** — link to language-specific client libraries
   (Python, Rust, JS/TS). Wait for at least one SDK to exist before
   building. **S** once SDKs exist.
4. **Integration examples** — code snippets for common tasks (query
   chain height, monitor an address for incoming, send a tx). **M**.

## Community / governance

1. **CIP voting interface** — the Proposals page lists CIPs but
   doesn't surface signal on community sentiment. A read-only view of
   discussion-thread reactions (from a GitHub Discussions integration)
   would help newcomers gauge consensus. **M**.
2. **Active issues from GitHub** — embed the top-10 open issues with
   labels. Operators benefit from visibility into known problems.
   **S** via GitHub API; privacy concern: every visitor's IP hits GitHub.
   Cache server-side to mitigate.
3. **Roadmap progress tracker** — convert this document into a live
   page on the explorer with status badges. Auto-update from doc-front-
   matter or a JSON sidecar. **L**.
4. **NLnet grant status** — public page tracking grant milestones,
   deliverables, audit results. Transparency commitment. **S**.

## Considered but deferred — by Constitution or design

These were proposed in design discussions and rejected. Listed here so
they don't keep being re-suggested.

- **Address balance lookup endpoint** — **REJECTED by Article IX**
  (no surveillance) and the documented "No RPC exists to query an
  address balance" commitment. CoinCync is a privacy chain; surfacing
  balances on a public site is the exact attack vector the design
  rejects. Even if someone asks for it.
- **Transaction graph visualization** — **REJECTED**. Graph layouts of
  ring-signed transactions imply links that the cryptography has
  intentionally erased. Showing them as edges in a graph would create
  false epistemic signal for surveillance-curious users.
- **KYC / AML hooks** — **REJECTED by Articles III, IX, XI**. No
  optional path. CoinCync is jurisdiction-neutral by design.
- **Centralized indexer service** — **REJECTED**. The explorer queries
  the node RPC directly. A centralized indexer would be a single point
  of failure and a privacy aggregation point.
- **Pre-rendered "rich list"** — explicitly avoided. The
  rich-list-by-amount notion doesn't apply when amounts are hidden
  by Pedersen commitments; the existing rich-list page already shows
  output counts, not values.
- **Cross-chain bridge UI** — the long-term plan is atomic swaps
  (trustless), not a custodial bridge. No UI work on bridges.

---

## Adding a new RPC-driven tile or page

If you want to add a new tile that surfaces existing node data, the
established pattern is:

1. Grep `src/rpc/server.rs` for `register_method("get_*"` to confirm
   the data is exposed. The 40+ available methods include many the
   explorer doesn't call yet (see the v1.0.8 status panel for a 5-RPC
   example: `get_finality_info`, `get_shielded_anchor`, `get_spark_anchor`,
   `get_health`, `get_metrics`).
2. Add a `<div>` in the appropriate page section. Inline styling using
   the CSS tokens (`var(--ac)`, `var(--ac2)`, `var(--t)`, `var(--t2)`,
   `var(--t3)`, `var(--surface)`, `var(--b)`, `var(--mono)`,
   `var(--display)`) — no new CSS classes needed for one-off tiles.
3. Write an `async function load*()` that uses the existing
   `rpc(method, params)` helper. Wrap each RPC call in a `safe(fn)`
   pattern so a single endpoint failure doesn't blank the whole tile.
4. Trigger it from `go(id)` when the parent page activates, and from
   `DOMContentLoaded` if the page starts active in the DOM.
5. Use a 15-second `setInterval` for live data (matches `loadHealth`
   convention). Clear the interval when leaving the page to avoid
   wasted RPCs.

The v1.0.8 status panel in
[src/explorer/fragments/10-home.html](../../src/explorer/fragments/10-home.html)
is a concrete template — copy that structure for new tiles.

## Privacy invariants for explorer code

Every new explorer feature must satisfy these. If a design needs to
violate any, it's the wrong design.

- **No per-visitor tracking.** No analytics scripts, no fingerprinting,
  no third-party calls without user opt-in.
- **No external CDN for static assets.** Cloudflare fronts the domain
  but assets are served from origin. Vendored libs live under
  `deploy/explorer/static/vendor/` and are pinned by hash in
  `checksums.txt`.
- **No address-balance UI.** Article IX forbids it; the node RPC
  doesn't expose it.
- **No transaction-graph rendering.** Even when the cryptography
  technically allows linking (e.g., across non-ring inputs in some
  future protocol version), the explorer must not render it.
- **All forms post to the local node RPC, not a third party.** Even
  for things like address validation, the existing pattern routes
  through `rpc('validate_address')` and keeps the visitor's input on
  their own node session.
