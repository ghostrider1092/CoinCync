# Glossary

Terms used throughout the CoinCync documentation. Defined to be approximately consistent with how Monero, Zcash, and Pirate Chain use them, with footnotes where CoinCync diverges.

---

**Anchor.**  A deterministic chain-history value mixed into the proof-of-work preimage so PoW solutions can't be precomputed against a hypothetical future chain. Computed by `compute_full_anchor(prev_hash, height, timestamp)`.

**Anonymity set.**  The total population of unspent outputs that could plausibly be the real input of a given ring signature. CoinCync's anonymity set is the entire UTXO pool minus already-spent outputs. Larger = better privacy.

**Atomic units.**  The smallest indivisible unit of CYNC. 1 CYNC = 10^12 atomic units. All on-chain amounts are stored as atomic units; user-facing displays convert to CYNC.

**BIP9 signaling.**  A miner-driven soft-fork activation mechanism originally from Bitcoin. Miners signal readiness for a CoinCync Improvement Proposal (CIP) by setting a bit in their coinbase. Once `SIGNAL_THRESHOLD` (1814 of 2016 blocks ≈ 90%) signal in a `SIGNAL_WINDOW` (2016 blocks), the fork locks in and activates at the start of the next window.

**Blinding factor.**  The random scalar `b` in a Pedersen commitment `C = a·G + b·H`. Without `b`, the commitment to amount `a` would be deterministic and an attacker could brute-force it. The blinding makes commitments hiding.

**Block reward.**  The amount of CYNC paid out as the coinbase output of a new block. Computed from the [emission curve](./protocol/emission.md) — a smooth **geometric decay** (Monero-style, supply-proportional): `reward = max(TAIL_EMISSION, (100M·COIN − mined) / 2,000,000)`. It starts at **50 CYNC/block** at genesis, decays continuously as cumulative supply grows (25 CYNC at 50M mined, 12.5 CYNC at 75M), and floors at the **0.6 CYNC/block tail** once supply passes ~98.8M. 100,000,000 CYNC is the curve's **asymptote (soft target), not a hard cap** — the perpetual tail carries total emitted supply past 100M over the long term. Locked by [Constitution Article I](./governance/constitution.md#article-i--transparent-emission-no-hidden-inflation).

**Bulletproofs+.**  A range-proof scheme that proves a committed amount falls in `[0, 2^64)` without revealing it. CoinCync uses Bulletproofs+ (the 2022 improvement on the original Bulletproofs), which is ~96 bytes shorter and ~10% faster to verify.

**Caddy.**  The reverse-proxy / TLS-terminator used in front of every public CoinCync HTTP service (explorer, API, landing). Auto-provisions Let's Encrypt certs, enforces rate limits, applies security headers. Lives in `deploy/explorer/`, `deploy/api/`, and `deploy/landing/`.

**CIP.**  CoinCync Improvement Proposal. An optional protocol change activated via BIP9 signaling. Listed in `src/consensus/fork_signal.rs::DEPLOYMENTS`. Does not include constitutional invariants — those cannot be CIP'd.

**CLSAG.**  Concise Linkable Spontaneous Anonymous Group signature. The ring signature scheme CoinCync uses for transaction inputs. Provides sender anonymity (you know "one of these N signed" but not which) plus linkability (the same input can't be spent twice without producing the same key image).

**Commitment.**  See **Pedersen commitment**.

**Confidential transaction.**  A transaction where amounts are hidden behind Pedersen commitments and proven valid via range proofs. Every CoinCync transaction is confidential — there is no transparent variant.

**Constitution.**  The set of invariants that will never be broken by the CoinCync maintainers. Documented in [Constitution](./governance/constitution.md) and the repository-root `CONSTITUTION.md`.

**CYNC.**  The native asset of CoinCync. Singular and plural — "1 CYNC", "100 CYNC".

**Decoy.**  A ring member that is NOT the real input. Selected from the chain's anonymity set by the wallet's decoy selector (`src/crypto/ring_selection.rs`) using an age-weighted distribution that matches Monero's current best practice.

**Domain separator.**  A unique tag prefix on a hash preimage that prevents two hashes computed with different tags from colliding. CoinCync uses domain separators on every protocol hash (`coincync/header/v1`, `coincync/tx-sign/v1`, etc.). See [Privacy model → Hash domain separation](./protocol/privacy-model.md#hash-domain-separation).

**Dust output.**  A UTXO with an amount so small that the fee to spend it exceeds the value. CoinCync's mempool policy doesn't formally define a dust threshold; in practice, amounts below ~1000 atomic units are uneconomic to spend.

**Effective ring size.**  The actual ring size used at a given height, possibly clamped above the constitutional minimum if the anonymity set isn't large enough yet. Computed by `effective_ring_size(height, available_outputs)` in `src/constants.rs`.

**Federation.**  Running multiple independent hosts of the same service (explorer, API) under different hostnames (`explorer.coincync.network`, `explorer2.coincync.network`, ...) so the system has no single point a regulator or DDoS can lean on. The CoinCync alternative to putting everything behind a CDN. See [Federation & DDoS](./operations/federation-and-ddos.md).

**Genesis block.**  Block 0 — the hardcoded first block of the chain. The genesis hash is a constant in `src/testnet.rs::TESTNET_GENESIS_HASH` and `src/mainnet.rs::MAINNET_GENESIS_HASH`. `init_genesis()` verifies the computed hash matches the constant; a mismatch is a fatal error.

**Hashrate.**  The rate at which a miner computes PoW hashes, measured in hashes per second (H/s). RandomX hashrates are typically in the kH/s to MH/s range on commodity CPUs.

**HSM.**  Hardware security module. CoinCync does not natively integrate with HSMs in 1.0; wallet keys are stored as encrypted files. HSM support is a future research item.

**IBD.**  Initial Block Download. The process of a fresh node downloading and verifying every block from genesis to the current chain tip. On a synced testnet that's ~12k blocks; the IBD takes ~10 minutes on commodity hardware.

**Key image.**  The cryptographic value `I = x · H_p(x · G)` derived from the spend key `x` of a CLSAG ring input. Published with the signature so the network can detect double-spends without learning which output was spent. Same key image twice = double-spend = block rejected.

**LWMA.**  Linearly Weighted Moving Average. The difficulty-adjustment algorithm CoinCync uses (same as Monero). Responsive to short-term hashrate changes, resistant to time-warp attacks. Implementation: `src/consensus/difficulty.rs::calculate_difficulty`.

**Mempool.**  The pool of pending (unconfirmed) transactions held in memory by every node. New blocks are built from mempool contents. The mempool runs the same crypto verifiers consensus does — there is no fast path that bypasses verification.

**MimbleWimble cut-through (MW cut-through).**  Phase 2 chain-compression technique where historical transaction graphs collapse, leaving only unspent commitments. Compresses the chain and eliminates traceable transaction history. Activates via CIP-006.

**Mnemonic phrase.**  A 24-word BIP39 phrase that encodes the wallet's master seed. The only way to recover a wallet if the encrypted file is lost. Memorize, paper-back, or both. Never digital, never online.

**Nullifier.**  See **key image**. (Different name in Zcash; the concept is the same.)

**Pedersen commitment.**  An additively homomorphic commitment scheme. `C = a·G + b·H` commits to amount `a` with blinding `b`. Two commitments add: `C(a) + C(b) = C(a+b)`. CoinCync uses Pedersen commitments for amounts so the network can verify the balance equation `sum(inputs) = sum(outputs) + fee` without learning any individual amount.

**PoW.**  Proof of work. CoinCync uses **RandomX, and only RandomX**, by [Constitution Article V](./governance/constitution.md#article-v--open-mining). Single memory-hard CPU-biased algorithm, same as Monero. No rotation, no hybrid, no PoS transition path. See [Consensus & PoW](./protocol/consensus.md) for the rationale on why single-algorithm is stronger than multi-algo rotation.

**Privacy policy.**  The consensus rule that rejects transparent transactions at the consensus layer (not just the mempool). Implemented in `src/consensus/privacy_policy.rs::enforce_privacy_policy`. Even a maliciously-crafted block trying to include a transparent transaction is rejected by `validate_block`.

**RandomX.**  A CPU-friendly, ASIC-resistant, memory-hard proof-of-work algorithm designed for Monero, used as-is by CoinCync as one of the three rotating PoW algorithms per [Article V](./governance/constitution.md#article-v--open-mining). Uses a 256 MB scratchpad and a virtual machine that interprets randomly-generated bytecode — both of which favor general-purpose CPUs over fixed-function hardware.

**Range proof.**  A zero-knowledge proof that a committed amount falls in a given range without revealing the amount. CoinCync uses Bulletproofs+ for the `[0, 2^64)` range that's standard for currency amounts.

**Reorg.**  Chain reorganization. When a node sees a competing fork that has more total work than its current tip, it rolls back blocks on the old tip and applies blocks from the new chain. Implementation: `src/chain.rs::add_block`.

**Ring signature.**  See **CLSAG**.

**Seed phrase.**  See **mnemonic phrase**.

**Selective disclosure.**  Sharing your view key with an exchange or auditor so they can verify your incoming and outgoing payments without being able to spend funds. The view key is read-only; the spend key remains private.

**Signing hash.**  The cryptographic hash that the CLSAG ring signature is computed over. Constructed by `Transaction::compute_signing_hash` — the single source of truth for the preimage. Both the wallet's signer and the consensus verifier funnel through this helper. See [Transaction format → signing hash](./protocol/transaction-format.md#the-signing-hash).

**Spend key.**  The secret key that authorizes spending an output. Derived from the wallet's master seed. Never share this. Loss of this key = loss of access to funds.

**Stealth address.**  A receiver-side address scheme where every payment to the same `(spend_pub, view_pub)` pair generates a fresh, unlinkable one-time output public key. Only the recipient (with their view key) can recognize that an output is theirs.

**Tail emission.**  A constant block reward floor that takes over once the geometric-decay curve would fall below it, providing a permanent baseline mining incentive. CoinCync's tail is **0.6 CYNC/block, in perpetuity** (`TAIL_EMISSION = 600_000_000_000` atomic) — it kicks in once cumulative supply passes ~98.8M CYNC, not at any fixed date or height. Because the tail never stops, total emitted supply crosses and grows past the 100M asymptote forever; 100M is a soft target, not a cap. See [Emission curve → 100M is an asymptote, not a hard cap](./protocol/emission.md#100m-is-an-asymptote-not-a-hard-cap).

**Target block time.**  The intended interval between blocks. **120 seconds (2 minutes)** for CoinCync. The LWMA difficulty adjustment keeps actual intervals close to this target.

**Testnet.**  A live but valueless network used for development, testing, and staging. CoinCync's testnet has the same code as mainnet but a different network magic, a different genesis, and a faucet that gives free CYNC away.

**Tor hidden service.**  A way of publishing an HTTP service inside the Tor network so visitors reach it without going through a Tor exit node. CoinCync supports `.onion` mirrors for the explorer and API alongside the clearnet sites. See [Tor hidden services](./operations/tor.md).

**UTXO.**  Unspent transaction output. The fundamental unit of state in a CoinCync wallet — every UTXO is an output that the wallet's view key recognizes and that hasn't been spent. The wallet's balance is the sum of unspent UTXOs.

**View key.**  A scalar that lets a holder scan the chain for outputs to a specific address WITHOUT being able to spend them. Enables selective disclosure: show your view key to your accountant, prove a transaction is yours to a regulator, etc., all without giving up spending authority.

**View tag.**  A 1-byte filter on every output that lets a wallet reject 255/256 outputs without doing a full ECDH computation — speeds up scanning by ~250×. Optional; activated via CIP-001.
