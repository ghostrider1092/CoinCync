# CoinCync — Bitcointalk ANN draft

> Modeled on the classic Monero ANN structure. **Testnet-framed and honest:**
> mainnet is a *target* (March 2027), shielded is *activating on testnet*, no
> fabricated numbers or infra. **NO audit language anywhere** (legal: public audit
> references are a liability — per counsel). `[CONFIRM]` = fill/verify before
> posting (URLs, live heights). Format is light BBCode for Bitcointalk; tune to
> taste.

---

[b]CoinCync (CYNC) — a mandatory-privacy, CPU-mined proof-of-work coin[/b]
[i]Monero-school privacy, extended with a modern shielded pool. Testnet live now; mainnet targeted March 2027.[/i]

››› [Source code][CONFIRM: repo URL] • [Testnet builds][CONFIRM: releases URL] • [Website][CONFIRM: coincync.network] • [Docs][CONFIRM: docs URL] ‹‹‹

[b]What CoinCync is[/b]
CoinCync is a privacy-focused cryptocurrency in the CryptoNote/Monero lineage: every transaction is private by default — no transparent-by-default mode to leak metadata. It is not based on Bitcoin's code. Sender ambiguity comes from CLSAG ring signatures, recipients are hidden with one-time stealth addresses, and amounts are hidden with Pedersen commitments and Bulletproofs+ range proofs. On top of that Monero-school base, CoinCync is bringing up a Lelantus-Spark shielded pool (accumulator-based, anonymity set = the whole pool) — activating now on the public testnet.

The project's stance is deliberately modest: where it reuses proven cryptography, it says so and inherits that scrutiny; where its own additions are younger, it says that too. The goal is to be a rigorously built, honest privacy chain — not to be first.

[b]Status (be clear about this)[/b]
• Testnet is LIVE and mineable today.
• The Lelantus-Spark shielded pool activates on testnet at block [b]29,000[/b] (a coordinated fork, ~[CONFIRM: N] blocks out). Until then the chain is ring-private (CLSAG), not shielded-pool-private — we don't call it "fully shielded" before activation.
• Mainnet is a [b]target of March 2027[/b] — still in active development and testing, not a commitment. Testnet coins have no value — the point is to run the real privacy code under real activity and find bugs before they get expensive.

[b]Features[/b]
• Private by default (mandatory at the consensus level — not opt-in)
• Strong sender privacy — CLSAG ring signatures (ring size 16; ramps 11→16 during early bootstrap)
• Unlinkable transactions — one-time stealth addresses
• Hidden amounts — Pedersen commitments + Bulletproofs+ range proofs
• Shielded pool (activating on testnet) — Lelantus-Spark accumulator, anonymity set = the whole pool
• Egalitarian mining — RandomX, CPU-friendly, ASIC-resistant by design
• Fair launch — no premine, no developer tax, no foundation, no token sale (all compile-time enforced)
• Smooth emission — reward decays continuously with supply, no halving shocks

[b]Academic and theory[/b]
CoinCync's privacy is built on peer-reviewed constructions, credited to their authors rather than reinvented:
• CryptoNote — ring signatures + one-time keys (the Monero lineage)
• CLSAG — compact linkable ring signatures (Goodell, Noether, et al.)
• Bulletproofs+ — short range proofs for confidential amounts
• Lelantus-Spark — the shielded-pool construction (Aram Jivanyan, Aaron Feickert)
• RandomX — CPU-biased proof-of-work
Our own work is layered on top of these as additive, reviewed extensions — see the project's whitepapers (Concentric Privacy; Extending Spark).

[b]Specifications[/b]
• PoW algorithm: RandomX (CPU)
• Ticker: CYNC — 12 decimals (atomic unit = 1e-12 CYNC)
• Block time: 120 seconds (target)
• Difficulty: ASERT-DAA, retargets every block (3600s halflife)
• Supply: ~100,000,000 CYNC issuance-curve asymptote (NOT a hard cap) + perpetual 0.6 CYNC/block tail emission → total crosses ~100M long-term and rises slowly forever
• Initial block reward: 50 CYNC, smooth asymptotic decay (no halvings)
• Fee burn: 30% of transaction fees burned per block
• Max block size: 2 MiB; max 5,000 txs/block

[b]Fair launch[/b]
Mining only, from genesis block 0. No ICO, no IDO, no airdrop, no private sale, no team or investor allocation. The 0% developer tax is enforced by a compile-time assertion — a build with a non-zero dev tax does not compile. Solo- and pool-mineable (P2Pool-compatible).

[b]Source and verification[/b]
• Language: Rust (toolchain pinned)
• Reproducible builds; SSH-signed commits + signed checksums
• Critical consensus files guarded by a SHA-256 lockfile enforced at build time (tampering fails the build)
• Fuzz suite + extensive property tests
• No operating company — a decentralized protocol maintained by its contributors
• Repository: [CONFIRM: public repo URL]

[b]Blockchain explorer[/b]
• [CONFIRM: explorer URL] — first-party block explorer (currently being redeployed; link will be live shortly)
We also welcome independent community-operated explorers — two operators agreeing on chain state is the strongest "this chain is real" signal.

[b]Connect to the testnet[/b]
• Seed node: [CONFIRM: 2.29.34.197 — verify still the published seed]
• Build the node from source, run with the testnet flag, point at the seed, and it syncs from genesis. CPU mining is built into the node binary.

[b]Contact[/b]
• Security: CyncLabs@proton.me
• [CONFIRM: community links — Discord/forum/etc, if any]

[b]Disclaimer[/b]
CoinCync is provided as-is, is non-custodial, and is testnet-only today. Nothing here is financial, legal, or tax advice. Mainnet is a target, not a commitment, and depends on continued development and testing.
