# Reply cheat sheets — per-venue launch-day responses

Companion to DISCORD_ANSWER_CHEATSHEET.md. Different platforms have different
audiences, different tones, and different ways to lose. This file gives you
pre-written replies for each launch-day venue so you can keep up with
comment volume on Mon 2026-05-11 without writing each response from scratch.

**Update before launch:** search for height `5675+`, build `28b342099695`,
date `2026-05-08` and refresh to current values.

---

## Tone reference (why answers differ across venues)

| Venue | Audience | Tone that lands | Tone that fails |
|---|---|---|---|
| **Twitter / X** | Crypto-twitter generalists, attention-span ~3s | Short, punchy, link-heavy. One concrete thing per reply | Long thoughtful prose, defensiveness |
| **r/CryptoCurrency** | Mostly speculators + some devs. Skeptical of altcoins | Acknowledging the pattern (we know "another privacy coin" is the prior), then the specific differentiator | Hyping, "moon" language, dismissing concerns |
| **r/Monero** | Hardcore privacy-coin community. Technically excellent. Wary of forks | Respectful of Monero, clear about what's *new* (not what's similar), invite critique | Anything that reads as Monero competition or critique |
| **BitcoinTalk ANN** | Old-school crypto devs, evaluating projects for years. Mining specs matter | Technical depth, exact numbers, reproducible build path, no marketing | "Innovative", "revolutionary", missing genesis hash / timing details |
| **Hacker News** | Programmers, contrarian by default. Will pick at solo-dev claims | Engineering substance, honest about limitations, code as evidence | Vague claims, refusing to engage on hard questions |
| **lobste.rs** | Smaller HN, more programming-focused, less crypto-friendly | Treat it as a Rust + cryptography submission, NOT a coin pitch | Anything that smells like financial promotion |

---

# Twitter / X reply cheatsheet

## Replies to common reactions

**Reaction:** "another privacy coin? lol"
> Source is MIT, no premine, no dev tax, no presale, no foundation. Public testnet running 5 nodes, height 5675+. We're not asking you to buy anything — testnet coins have zero value. Pick any specific concern and I'll respond.

**Reaction:** "scam"
> Open-source on git.coincync.network. Constitution + Bill of Rights compile-time enforced — any change that flips the rules fails the build. Specific allegation?

**Reaction:** "rugpull incoming"
> 0% premine, 0% dev tax, no presale, no IDO. Article II of the Constitution forbids them — hash-locked at the protocol level. Show me the rug-able surface.

**Reaction:** "this is just Monero"
> Same primitives (CLSAG, Bulletproofs+, RandomX) — those are the strongest known tools, of course we use them. What's *new*: written Constitution that's compile-time enforced, atomic-swap-to-BTC as a mainnet-launch blocker, FROST hidden multi-sig.

**Reaction:** "looks scammy" / "logo is sus" / "website looks like AI"
> Fair. It's a solo dev who can write privacy crypto better than landing pages. Here's the source: git.coincync.network/coincync/cync-protocol — judge the protocol, not the marketing.

**Reaction:** "where can i buy it"
> Mainnet hasn't launched. Testnet coins have ZERO monetary value. Anyone selling them right now is wasting your time. Mainnet target Oct 2026.

**Reaction:** "$ELON LISTED THIS MAY 2026 PUMP" / shilling spam
> Ignore. Don't reply. Block + mute.

**Reaction:** "is the discord active"
> discord.gg/5tYNSCsqzy — yes, daily activity in #testnet, #mining-general, #wallet-help.

**Reaction:** "🚀🚀🚀 to the moon!!"
> Don't engage. Like the tweet, don't reply.

**Reaction:** Genuinely technical question (e.g., "how do you hide multisig with FROST?")
> FROST aggregates the signature shares into one combined Schnorr signature that's byte-equivalent to a single-sig. On-chain, a 7-of-10 multisig output looks identical to a normal 1-of-1. Spec: docs.coincync.network/cip/CIP-008-frost-multisig — happy to go deeper here if you have specific questions.

## Twitter / X don't-do

- Don't reply to every "this is a shitcoin" comment. Engagement = oxygen.
- Don't get into long threads. Make your point in 1-2 replies, stop.
- Don't use "literally" or "based" unironically. Don't post celebration GIFs.
- Don't say "we're gonna be huge". The protocol either works or doesn't; the price isn't a goal.

---

# Reddit reply cheatsheet

## r/CryptoCurrency (post on launch day)

**Reaction:** "another privacy coin"
> Fair prior. The thing that's new isn't the privacy stack (it's CLSAG + Bulletproofs+ + RandomX, same as Monero — those are the strongest known tools). The thing that's new is structural: a written Constitution that's compile-time enforced, atomic-swap-to-BTC as the mainnet-launch blocker, and FROST hidden multi-sig. Genuine technical questions welcome here, I'll be in this thread.

**Reaction:** "where's the team page / how do I know you're real"
> Solo dev. Pseudonymous (Right V in the Bill of Rights — pseudonymity is a Right, not a flaw). Source is MIT-licensed, hash-locked, with 1093 internal tests + cargo audit on every PR. Trust the source, not the team page. "Hit by a bus" plan: anyone can fork, the testnet runs on 5 nodes that don't depend on me.

**Reaction:** "what's the tokenomics"
> 100M asymptotic cap. 0.6 CYNC tail emission perpetually. 30% of every transaction fee permanently destroyed (50% under congestion). 0% pre-mine, 0% dev tax, no foundation, no governance token. The first miner gets ~50 CYNC at block 1; that's the entire genesis distribution.

**Reaction:** "when will it be on Coinbase / Binance"
> We don't pay for listings. We expect delistings — that's why CYNC↔BTC trustless atomic swaps are a hard mainnet-launch blocker. Listing-independence as a protocol commitment, not a hope. Article XIV, CIP-001 has the spec.

**Reaction:** "is this safe" / "audited?"
> Honest answer: third-party audit is a hard mainnet-launch blocker, not yet done. Currently 1093 internal tests, fmt + clippy + cargo audit on every PR, hash-locked critical files. Mainnet target Oct 2026 — no audit, no mainnet. Testnet runs *now* with no real money at risk; that's the entire point of testnet.

**Reaction:** "why no GPU mining" / "why CPU mining"
> RandomX is memory-hard by design. A GPU running RandomX is 5-20× SLOWER than the same-cost CPU because GPUs lack the L3 cache + branch-predictor hardware RandomX exploits. Not a software lockout — fundamental algorithmic property. Anyone with a laptop CPU can meaningfully mine.

**Reaction:** "give me the steel-man for why I should care"
> If you don't already have a privacy-coin position, you probably don't need one. CoinCync exists because (a) Monero's existing values live in social consensus, which is correct for what Monero is, but (b) some people want those values *codified* with cryptographic enforcement. Different niche, not a competitor. If neither (a) nor (b) means anything to you — feel free to ignore this one.

## r/Monero (post Wed 05-13, NOT day-0)

**Reaction:** "fork bad"
> Hear you. Not a fork — independent Rust implementation written from scratch. Uses Monero primitives (CLSAG, Bulletproofs+, RandomX, Dandelion++) because they're battle-tested. Codebase, consensus rules, emission curve, Constitution are all original. Source MIT-licensed at git.coincync.network.

**Reaction:** "Monero already does this"
> True for the privacy primitives. Two structural differences:
> (1) Compile-time-enforced Constitution. Articles forbidding the categories of failure that have historically killed privacy coins are SHA-256 hash-locked + tripwire'd in src/constants.rs. Any rule-flip fails the build with `UNCONSTITUTIONAL: Article X`. Monero deliberately doesn't do this — its values live in social consensus, which is correct for what Monero is.
> (2) FROST hidden multi-sig. Monero's existing multi-sig is detectable from on-chain structure; FROST aggregates the shares into a combined Schnorr that's byte-equivalent to single-sig. Genuinely novel for the Monero-style stack.

**Reaction:** "this is going to compete for hashrate"
> Possibly, in the long run. Honestly, both networks are better off if there's more total privacy-coin hashrate in the world — the diversity of Monero+CoinCync makes it harder to attack either. We're not optimizing for taking your hashrate; we're trying to make a chain we'd want to use, with structural commitments Monero deliberately doesn't make.

**Reaction:** "split the community"
> Different niche. We're not asking Monero users to switch. People building on Monero today should keep building on Monero. The constitutional-codification model attracts a different audience; if it doesn't appeal to you, ignore it. No critique of Monero is intended.

**Reaction:** "show me the actual differences in code"
> Three concrete spots:
> - `crates/coincync-frost-coordinator/` — FROST hidden multisig, RFC 9591
> - `crates/coincync-swap/` — CYNC↔BTC atomic swap protocol (CIP-001)
> - `src/constants.rs` — 8 tripwire constants enforcing Articles
> Plus our entire Rust impl is from-scratch — different node, different wallet, different RPC layer.

**Reaction:** Aggressive critique of the cryptography
> Engage technically. Always assume the questioner is right until proven otherwise. r/Monero has people who've been doing this longer than I have. "That's a fair point — let me look at it" is a better reply than defending.

## Reddit don't-do

- Don't downvote disagreement. It looks petty and kills your visibility.
- Don't link-spam. ONE link per comment max, rest in the original post.
- Don't reply to every comment. Pick the substantive ones, ignore drive-bys.
- Don't say "FUD". Don't use "shill" pejoratively. Don't say "dyor" — explain instead.

---

# BitcoinTalk ANN reply cheatsheet

The ANN thread on BitcoinTalk's altcoin board is the long-tail reference link. Posts there get screenshotted years later. Tone: technical, exact, no marketing language.

**Q: "Genesis block hash?"**
> Testnet genesis: `41f970df6152425a2938725423235c2c40ec52556ecc0fd1422d588652cc56b4`. Mainnet genesis is computed at mainnet launch — message will be "CoinCync Mainnet Genesis - Privacy You Can Audit - October 2026".

**Q: "Block time / supply schedule?"**
> 120s block time. 100M asymptotic hard cap. Emission curve: ~50 CYNC at genesis decaying asymptotically; 0.6 CYNC tail emission per block perpetually. 1 CYNC = 10^12 atomic units. Source-of-truth: src/emission/curve.rs (hash-locked).

**Q: "Difficulty algorithm?"**
> LWMA-3 over a 720-block window (~1 day). Source: src/consensus/difficulty.rs. Tuned for 120s target with ±10% drift tolerance. Bootstrap difficulty floor of 60000 prevents the easy-block problem at low hashrate.

**Q: "What hash function?"**
> RandomX for proof-of-work (CPU-only by design). BLAKE3 for general-purpose hashing (block hash, tx hash). Ed25519 + Schnorr for signatures. CLSAG-16 for ring signatures.

**Q: "Wallet format?"**
> 25-word seed phrase, BIP39-style but project-specific wordlist. Argon2id KDF for password → key derivation. XChaCha20-Poly1305 for wallet-file encryption. View key + spend key separation per Monero-family convention.

**Q: "Address format?"**
> 95-character base58. Mainnet prefix `CYNC`, testnet `tCYNC`, sub-address `stCYNC`. Includes 4-byte checksum.

**Q: "How does the atomic swap work?"**
> CIP-001 has the spec. Adaptor signatures over CLSAG (CYNC) + Schnorr/secp256k1 (BTC), bound by a cross-curve discrete-log-equality proof. Both chains' spend transactions commit to the same secret; redeeming one reveals it. Either party times out and refunds. Modeled on Comit/Farcaster XMR↔BTC.

**Q: "Pool support?"**
> JSON-RPC `submit_block` interface is documented and stable. No Stratum support yet; that's community work for pool-operators to build. Pre-mainnet: solo mining.

**Q: "Is the build deterministic?"**
> `profile.release` configured for determinism: `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`. Full Dockerfile-pinned reproducible-build infrastructure is post-launch (documented in docs/operations/REPRODUCIBLE_BUILDS.md but not yet authored). Pre-mainnet.

**Q: "What's the protocol versioning story?"**
> Hard forks are coordinated via static-height activation (Mode A) for known-date events, or BIP8-style version-bit activation (Mode B) for community-proposed changes. Spec: CIP-007.

## BitcoinTalk don't-do

- Don't post the ANN, then disappear. Be in the thread for the first week.
- Don't use the "🚀" emoji. Don't bold every other word. Plain text reads better here.
- Don't promise prices, exchange listings, or partnerships. None of those are within the protocol's scope.

---

# Hacker News reply cheatsheet (Show HN thread)

HN audience: programmers, default-skeptical, will pick at any vague claim. Engineering substance wins.

**Q: "Why Rust? Couldn't you have used $other_language?"**
> Memory safety + zero-cost abstractions matter for code that handles user keys and validates consensus. Rust's borrow checker eliminates an entire class of vulns (use-after-free, data races) that have hit other crypto projects. Plus the cryptographic crate ecosystem (curve25519-dalek, frost-ed25519, k256) is mature and well-audited. C++ would have been the default; Rust is the right call now.

**Q: "Solo dev for a privacy coin? That's terrifying."**
> Fair criticism. Mitigations:
> (1) Multi-maintainer M-of-N signed releases is a hard mainnet-launch blocker (Article XV).
> (2) Critical files (CONSTITUTION, consensus code, crypto) are SHA-256 hash-locked; any change is auditable in `critical_files.lock` history.
> (3) MIT-licensed and mirrored at github + git.coincync.network — anyone can fork.
> (4) Testnet exists exactly to find the bugs my solo eyes missed.
> Solo-dev today; not solo-dev at mainnet by design.

**Q: "What's the threat model for the privacy stack?"**
> See docs/THREAT_MODEL.md. Tl;dr: chain analysts with full chain-history access + ability to operate seed nodes + correlate timing. Mitigations: ring signatures (sender), stealth addresses (receiver), Bulletproofs+ (amount), Pedersen commitments (homomorphic balance verify), Dandelion++ (origin IP), traffic shaping (timing). NOT in scope: SIGINT-level adversary tapping every link to/from a user's machine.

**Q: "Why a Constitution?"**
> Privacy coins die from one of two failure modes: (a) regulatory capture (changing the rules to comply), (b) insider corruption (changing the rules to steal). Compile-time-enforced Articles + hash-locked critical files + tripwire constants make both technically infeasible without a public, attributable, build-breaking commit visible in git history. The Constitution doesn't replace governance; it removes the option of silent governance.

**Q: "compile_error! tripwires sound clever but they're trivially patched out by an attacker."**
> Correct. The point isn't to stop a malicious maintainer — it's to make the change *attributable*. A patch that removes `UNCONSTITUTIONAL: Article X` shows up in the diff, in the commit hash, in the release-binary's hash. Reproducible builds + signed releases + multi-maintainer M-of-N close the gap further. The Constitution is a "make corruption visible" mechanism, not a "make corruption impossible" mechanism.

**Q: "What stops you from launching mainnet without doing the atomic swap?"**
> The Article XIV commitment + the public CIP-001 with progress visible. If we launch mainnet without working swaps, anyone reading can verify and call it out. Reputation cost. We're already publishing operational track record (72h soak summary, fleet health dashboard, incident logs); skipping a stated launch-blocker would be observable.

**Q: "How is this not Monero++"**
> The privacy primitives ARE Monero's — that's deliberate, those are the strongest known tools. Three things that aren't Monero: (1) compile-time-enforced Constitution, (2) atomic-swap-to-BTC as launch-blocker, (3) FROST hidden multi-sig. Different niche. If you'd rather use Monero, please do.

**Q: "I see a `#[cfg(test)]` block in your CLSAG code that disables ring-signature verification. Is that a backdoor?"**
> No, but it's a fair question. That's the unit-test fixture path, NOT the runtime path. `cfg(test)` only compiles in `cargo test`; release binaries don't include it. You can verify by running `cargo build --release` and checking the resulting binary doesn't contain that symbol. If you find a `cfg(test)` path that ACTUALLY runs in release, that's a real bug — file it.

**Q: "Why not use existing privacy-coin code? Why rewrite?"**
> Two reasons: (1) we wanted to write the constitutional-tripwire system into the build at the source level — that's hard to bolt on after the fact; (2) Rust + memory safety + the modern crypto crate ecosystem felt worth the cost of starting fresh. Tradeoff: more bugs we have to find ourselves vs. fewer inherited bugs.

## HN don't-do

- Don't say "we built", "we shipped", "our team" — it's solo dev, just say "I".
- Don't refuse to engage with hard questions. "I don't know yet" is acceptable; silence is not.
- Don't claim novelty for things that aren't novel (CLSAG, Bulletproofs+, RandomX). Acknowledge the prior art.
- Don't moderate the thread. HN's voting handles it. Replying to "this is a scam" with rebuttals is fine; flagging it is bad form.

---

# lobste.rs reply cheatsheet

lobste.rs: smaller HN, Rust + cryptography focus, less crypto-friendly but more programming-friendly. Post the link to the **Constitution** (not the homepage) to lead with the differentiator.

**Q: "Why is this on lobste.rs"**
> Submitted because the constitutional-tripwire system is a programming-language idea (compile-time-enforced invariants over a long-lived codebase) that happens to be applied to a privacy coin. The crypto context is secondary; the tag is `cryptocurrencies` because that's the host project.

**Q: "Compile-time check? doesn't `cargo build` just succeed if you change the hash?"**
> Yes — that's what makes it visible. The check fires in build.rs and reads `critical_files.lock`. Updating a hash is a deliberate commit (`COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes`) that any reviewer sees. It's not "make corruption impossible" — it's "make corruption attributable."

**Q: "Show me the build.rs"**
> https://git.coincync.network/coincync/cync-protocol/blob/main/build.rs — `CRITICAL_FILES` is at the top, the SHA-256 verification loop runs on every cargo invocation. ~150 lines total.

**Q: "Reproducible builds?"**
> `[profile.release]` configured for determinism (codegen-units=1, lto=thin, panic=abort, strip=true). Full Dockerfile-pinned builder is post-launch — documented in docs/operations/REPRODUCIBLE_BUILDS.md, ETA pre-mainnet. Currently SHA256SUMS.txt for binary integrity.

**Q: "What's novel here from a Rust perspective?"**
> Honest answer: nothing about the Rust *itself* is novel — it's idiomatic, uses standard crates, no clever macros. The novel piece is the build-time integrity check applied to a long-lived consensus codebase, which is a pattern I haven't seen elsewhere. Worth a discussion if you have a counter-example.

## lobste.rs don't-do

- Don't pitch the coin. Pitch the engineering.
- Don't reply with marketing language. The audience reads it as a flag.

---

# When to disengage (every venue)

Engagement triggers spam. Some reply patterns are net-negative — recognize and skip:

- "It's a scam" with no specifics → skip
- "🚀🚀🚀" or any emoji-only reply → skip
- Personal insults / accusations of fraud → don't dignify
- "Where is the elon musk endorsement" → block, don't reply
- Anyone trying to get you to DM about "investment" → block + report
- Coordinated FUD raid (3+ accounts saying the same thing in 5 min) → mods + block, don't dignify

**Rule of thumb:** if a reply requires you to defend yourself rather than explain the protocol, you're in the wrong conversation. Disengage.

---

# Posting-day operational checklist

| Task | Time |
|---|---|
| Pin announcement in #announcements (already auto-done by your refresh script) | 09:30 ET |
| Post r/CryptoCurrency thread (Discussion flair) | 10:00 ET |
| Post BitcoinTalk ANN | 10:30 ET |
| Post X/Mastodon thread (5 posts in TESTNET_LAUNCH_ANNOUNCEMENT.md §3) | 11:00 ET |
| Post lobste.rs (Constitution URL, NOT homepage) | 14:00 ET |
| **Reply to every top-level comment within 1 hour for the first 6h on every venue** | 10:00–18:00 ET |
| Wed 05-13: Post r/Monero (after 48h of activity to reference) | 10:00 ET |
| Wed 05-13: Post HN Show HN (same window) | 10:00 ET |
