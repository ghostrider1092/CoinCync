# Changelog

## v1.0.2-testnet (May 5, 2026)

### Public Repo + Fleet Migration

**Network:**
- 3-seed minimal-bootstrap fleet across 3 continents: New Jersey (US-East), Amsterdam (Europe), Tokyo (Asia-Pacific). Resolves via `seed1/2/3.coincync.network`.
- Migrated from DigitalOcean (locked-out 2026-05-02) to Vultr. Smaller fleet that exactly matches the DNS-seeded hostname set.
- Per-peer consecutive-empty-Blocks ban (threshold 5, duration 1h) — fixes the recurring IBD wedge pathology where one bad peer could stall sync indefinitely.

**Privacy stack (already in v1.0.0, restated for the public-repo cut):**
- CLSAG-16 ring signatures (11→16 bootstrap ramp at block 10,000) · Bulletproofs+ range proofs · stealth addresses · Pedersen commitments · Dandelion++ propagation · FROST hidden multi-sig · 7 advanced privacy features (decoy defense, encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead-man's switch, auto-churn).

**Governance & process:**
- 19-article Constitution + 15-right Bill of Rights, locked at compile time via critical-files SHA-256 hashes and 8 tripwire constants.
- CIP process documented: CIP-001 (CYNC↔BTC atomic swap, mainnet blocker) and CIP-002 (cynchub merge-mined liquidity layer) published as drafts.
- Public CIP register at `explorer.coincync.network/?p=proposals`.

**Public surfaces:**
- Source code public at <https://git.coincync.network/coincync/cync-protocol>
- Docs site rebranded to match the rest of CoinCync (Fraunces / IBM Plex / JetBrains Mono / gold accent on warm-dark).
- Landing site overhauled: removed competitive "Compare" section, added Get-Started two-path split (users vs developers), added 7-phase roadmap, updated faucet flow.
- Explorer: constitutional-status panel, live fee-burn counter, mempool fee histogram, globe block-propagation visualization, /api /soak /broadcast /leaderboard /privacymetrics /proposals pages.

## v1.0.0-testnet (April 21, 2026)

### Public Testnet Launch

**Chain:**
- New genesis: `41f970df6152425a2938725423235c2c40ec52556ecc0fd1422d588652cc56b4`
- Genesis message: "CoinCync Public Testnet - April 2026 - Trust the Math"
- 10-node curated bootstrap fleet across NA / EU / Oceania (DigitalOcean), 3 miners (LON, SFO, SYD)
  &mdash; later replaced by the 3-seed Vultr fleet documented under v1.0.2-testnet below
- Fast sync with 5 checkpoints (heights 100-500)

**Security Fixes:**
- C-8: Privacy policy bypass in skip_crypto path (Critical)
- C-9: Zero key image structural validation (High)
- H-15: Peer scorer validated flag (High)
- H-16: MESS hybrid reorg defense — 3-tier (High)
- H-18: Invalid key image curve-point validation (High)
- H-19: Invalid stealth address / commitment validation (High)

**Testing:**
- 947 automated tests, 0 failures
- 24 historical attack reproductions
- 17 MESS reorg defense tests
- 13 full-pipeline real-crypto tests
- 5-level chain verification script (Bitcoin Core verifychain style)
- 6 verification RPC endpoints

**Wallet GUI:**
- Local-first node connection (falls back to remote)
- Mining address auto-fills from wallet
- Miner output visible in terminal
- No hardcoded passwords
- Real fee estimates from mempool

**Infrastructure:**
- systemd auto-restart on all nodes
- nginx failover proxy for explorer
- Stale-data warning banner
- deploy.sh + wipe_and_restart.sh operational scripts
- Release binaries (Linux x86_64 + Windows x64)
- Faucet (10 CYNC per request)

**Documentation:**
- Consensus specification
- Security fixes documentation
- Getting started guide
- Node operator guide
- Mining guide
- Wallet guide
- Privacy model
- Chain verification guide
- Deploy runbook
- Audit scope document

### Previous (pre-public)

- Initial testnet with 6 nodes
- 806 tests
- 7 privacy innovations (decoy defense, encrypted memos, scoped view keys, deniable wallets, traffic shaping, dead man's switch, auto-churn)
- FROST multi-sig
- Explorer with 9 themes + wallpaper picker
- Brass/gold brand redesign
