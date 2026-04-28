# Changelog

## v1.0.0-testnet (April 21, 2026)

### Public Testnet Launch

**Chain:**
- New genesis: `41f970df6152425a2938725423235c2c40ec52556ecc0fd1422d588652cc56b4`
- Genesis message: "CoinCync Public Testnet - April 2026 - Trust the Math"
- 10 nodes across 6 continents, 3 miners (LON, SFO, SYD)
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
