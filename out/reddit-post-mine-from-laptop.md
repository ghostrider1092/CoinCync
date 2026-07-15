<!-- markdownlint-disable MD034 -->
<!-- Bare URLs are intentional throughout this file. The content is
     designed to be pasted into Reddit and Discord, where bare URLs
     auto-link and `<url>` / `[text](url)` post as literal markdown
     characters. See the header note below. -->

# Reddit / Discord post: "Minable from your laptop right now"

Primary template is **Variant 1** below — adapted from a post that
already converted to 1,600+ views in 15 days on r/CPUMining, with
the following fixes:

- Release tag corrected to `v1.0.9-testnet-pre-audit`
- Linux binary path replaced with build-from-source (native Linux
  binaries aren't shipped yet for this release)
- "Atomic swaps at mainnet" claim removed (cyncswap is v1.1)
- **"Monero-family" / "Monero clone" framing removed.** CoinCync uses
  RandomX (same proof-of-work algorithm Monero uses) and the
  Monero-school privacy primitive family (CLSAG, Bulletproofs+,
  stealth addresses). The hardware-compat hook is real and worth
  keeping. But positioning as "Monero-family" makes you derivative
  by association — different design, different supply policy,
  different governance model, different roadmap. Lead with what
  CoinCync IS, not what it's adjacent to.

Bare URLs are intentional throughout (Reddit and Discord auto-link
them). Don't wrap them in `<>` or `[text](url)` — that posts literal
markdown to most clients.

Don't paste the same text into multiple subs (Reddit auto-detects
cross-posts; varied angles read as genuine).

---

## Variant 1: r/CPUMining — proven template, updated

**Title:** New privacy POW chain on testnet — RandomX, CPU-mineable from any laptop right now

**Body:**

CoinCync went live on testnet a few months ago and is heading for
mainnet on October 1, 2026. It's a privacy proof-of-work chain that
runs on the RandomX algorithm — so any CPU rig you already have
pointed at any RandomX coin will mine it with the same hardware,
same hashrate ballpark, zero new setup.

Testnet coins have no monetary value. This is for hardware testing,
dialing in your rig before mainnet, or contributing hashrate while
the launch warms up.

## Specs that matter to miners

- **Algorithm:** RandomX (CPU-only, ASIC-resistant)
- **Block time:** 120 seconds
- **Block reward (testnet, now):** ~50 CYNC, declining asymptotically
- **Tail floor:** 0.6 CYNC/block forever
- **Min difficulty:** 500 (consensus floor)
- **Supply cap:** 100M asymptotic + tail emission + 30% fee burn
- **Pool support:** solo only right now (community pools welcome)
- **Network hashrate at this hour:** small — your laptop's contribution will matter

## How to mine in 3 commands

### Windows (proven, works today)

Open PowerShell, paste:

```powershell
$base = 'https://github.com/Coincync/Coincync-Testnet-/releases/latest/download'
Invoke-WebRequest -Uri "$base/coincync-rig.exe"    -OutFile coincync-rig.exe
Invoke-WebRequest -Uri "$base/coincync-wallet.exe" -OutFile coincync-wallet.exe
.\coincync-wallet.exe --network testnet --wallet testnet.bin create
$addr = (.\coincync-wallet.exe --network testnet --wallet testnet.bin address | Select-String '^Address:').ToString().Split()[-1]
.\coincync-rig.exe run-solo --node https://api.coincync.network/rpc/testnet --address $addr --network testnet --tui
```

`--tui` opens a live dashboard with H/s, threads, current tip. Press `q` to quit.

### Linux / macOS

Native binaries aren't on the release page yet (`v1.0.9-testnet-pre-audit`
shipped Windows .exe only). Build from source — 10-15 min, you only
need this once:

```bash
git clone https://github.com/Coincync/Coincync-Testnet- coincync
cd coincync
cargo build --release --bin coincync-rig --bin coincync-wallet
./target/release/coincync-wallet --network testnet --wallet testnet.bin create
ADDR=$(./target/release/coincync-wallet --network testnet --wallet testnet.bin address | awk '/^Address:/{print $2}')
./target/release/coincync-rig run-solo --node https://api.coincync.network/rpc/testnet --address "$ADDR" --network testnet --tui
```

WSL Ubuntu users — just run the Windows .exe files via `./coincync-rig.exe`
from inside WSL. No build step needed.

## Hashrate expectations

Standard RandomX hashrate ranges (same as any RandomX coin):

- Modern desktop CPU (Ryzen 5/7, 8-16 threads): ~3-8 KH/s
- Laptop (4-8 threads): ~500 H/s - 2 KH/s
- VPS / server (limited cores): hundreds of H/s
- Raspberry Pi: ~50-100 H/s

## What CoinCync is (the short version)

**Monetary policy and launch:**

- Hard 100M asymptotic supply cap with smooth decay — no halvings, no economic shocks every 4 years. 0.6 CYNC/block tail emission forever, 30% fee burn at the protocol level.
- Zero premine, zero dev tax. Every block reward goes to the miner. Article II of the project Constitution is compile-time asserted in the source — any build that violates it fails to compile.
- Fair launch — no ICO, no IDO, no team allocation, no foundation reserve. Mining starts from block 0 at the public mainnet genesis (Oct 1, 2026).
- Constitutional commitments bound to the binary by compile-time assertions in `src/constants.rs`. Reviewers can verify by grepping the source.

**Privacy stack — all of this is mandatory at the consensus layer, not opt-in. Highlighting the bits other privacy chains don't have:**

*Cryptographic layer:*

- **Uniform decoy selection** — deliberately NOT gamma-distributed. Defeats the output-age statistical deanonymization that hit other privacy chains historically.
- **CLSAG ring signatures** — ring size 16, minimum 11 during bootstrap (< 10k blocks).

*Network layer:*

- **Dandelion++** — stem/fluff tx relay with per-epoch fixed relay peers, Poisson delays, exponential embargo timers. Breaks "tx-submission IP → originator" linkage.
- **Traffic shaping** — constant-rate cover packets + packet-size normalization to TLS frame sizes. An idle node is indistinguishable from an active one on the wire.

*Consensus enforcement:*

- **Mandatory privacy at consensus** — rejects transparent transactions. Every non-coinbase tx MUST have hidden amounts, hidden recipients, and ≥1 privacy-preserving input. No transparent escape hatch.

*Wallet layer:*

- **Deniable wallets** — two-password plausible deniability. Decoy and real data in one size-padded file; loading tries the password against both regions.
- **Dead man's switch** — time-locked recovery metadata in the tx extra field. After 24 h – 2 y a recovery address can sweep without the owner's spend key. Validated at consensus.

Full feature table — Bulletproofs+, stealth addresses, scoped view keys, encrypted memos, selective disclosure, CLSAG multisig, Noise XX P2P, auto-churn, subaddresses, etc. — at https://github.com/Coincync/Coincync-Testnet-/blob/main/docs/PRIVACY_FEATURES.md

**What's on the roadmap (NOT in v1.0):**

- v1.1: **cyncswap** — trustless CYNC↔BTC atomic swaps via CLSAG adaptor signatures. Lets you exit/enter without a custodian.
- v1.2: **Orchard shielded pool** — optional zk-SNARK-based shielded pool (Halo 2 proofs).

## Why bother mining testnet

You won't get any USD value from testnet coins, but you:

1. Test your hardware against the actual network before mainnet (when it counts)
2. Help the network find bugs while there's no money at risk
3. Get an address with a long mining history before mainnet, which some people care about for clean-distribution reasons
4. Pre-mainnet miners get an early-supporter acknowledgement in the mainnet launch announcement

If you join the Discord (https://discord.gg/5tYNSCsqzy), there's a #miners channel where people are comparing rigs and configurations.

Source: https://github.com/Coincync/Coincync-Testnet-
Block explorer: https://explorer.coincync.network

---

## Variant 2: r/MoneroMining — adjacent audience, no derivative framing

**Title:** Privacy POW chain heading to mainnet Oct 1 — RandomX, testnet CPU-mineable right now

**Body:**

CoinCync is a privacy proof-of-work chain on testnet now, mainnet
2026-10-01. Different project, different design, different team —
not a fork, not a clone. But it does use RandomX, so any CPU rig
already mining a RandomX coin will mine CoinCync testnet with the
same hardware and same hashrate ballpark. Posting here because the
audience that knows RandomX is the audience that can actually use
this on day one.

Design differences worth knowing:

- Hard 100M asymptotic supply cap (vs. Monero's unbounded with
  tail-only)
- Smooth asymptotic decay, no halving events
- Mandatory privacy enforced at the consensus layer with compile-time
  assertions in the source code (Article III of the project
  Constitution)
- Zero premine, zero dev tax (Article II, also compile-time asserted)
- Roadmap: base chain v1.0 in October, atomic-swap layer (cyncswap)
  in v1.1 after its own audit, optional shielded pool later

If you have a few cores you don't mind donating to a testnet,
pre-mainnet miners get acknowledged in the launch announcement.
Setup is the same Windows / Linux commands as the post in
r/CPUMining; full quickstart at:
https://github.com/Coincync/Coincync-Testnet-/blob/main/docs/src/getting-started/mine-in-5-minutes.md

Skeptical questions welcome.

Discord: https://discord.gg/5tYNSCsqzy
Source: https://github.com/Coincync/Coincync-Testnet-

---

## Variant 3: r/CryptoCurrency Daily Discussion

Format as a COMMENT in the daily thread, NOT a post (cc has strict
post moderation; promotion-shaped posts get removed).

**Body:**

For anyone interested in privacy POW: CoinCync testnet is currently
CPU-mineable from any laptop. Mainnet 2026-10-01. Fair launch — no
premine, no dev tax, no team allocation (Article II of the project
Constitution is compile-time asserted in the source). Pre-mainnet
miners get an early-supporter acknowledgement, nothing else.

Privacy stack: CLSAG ring sigs, Pedersen commitments, Bulletproofs+
range proofs, stealth addresses. PoW: RandomX (CPU-only).

Mining quickstart (3 PowerShell commands):
https://github.com/Coincync/Coincync-Testnet-/blob/main/docs/src/getting-started/mine-in-5-minutes.md

Source: https://github.com/Coincync/Coincync-Testnet-
Explorer: https://explorer.coincync.network
Discord: https://discord.gg/5tYNSCsqzy

---

## Variant 4: CoinCync Discord #announcements

@everyone — only use this ping for milestones (mainnet, security, listing).

**Body:**

🟢 **Testnet mining is now a 3-command setup.**

If anyone in the community can't currently mine testnet because the
docs assume Cargo familiarity, that's fixed. New quickstart:

https://github.com/Coincync/Coincync-Testnet-/blob/main/docs/src/getting-started/mine-in-5-minutes.md

Three copy-paste PowerShell commands. No build step on Windows. Uses
the public RPC at api.coincync.network — no local node required.

Pre-mainnet miners are getting acknowledged in the mainnet launch
announcement (Oct 1, 2026). Post your hashrate in #miners when you
have it running — we're tracking distinct miners as a community-
engagement metric for exchange listing applications.

---

## Posting checklist (per submission)

- [ ] Variant 1 is the proven copy — post that FIRST to r/CPUMining
- [ ] If posting on a Friday in your timezone, wait until Sunday evening / Monday morning UTC for best Reddit engagement
- [ ] Don't crosspost via Reddit's built-in crosspost button — that triggers cc anti-cross-promo. Manually re-write per the variants above.
- [ ] If a post gets removed by a mod, DON'T resubmit. Reach out to the mod first asking what the issue was. Resubmitting after removal puts you on a shadowban watchlist.
- [ ] Track click-throughs via Cloudflare analytics for `coincync.network` — that's the real conversion metric.
- [ ] Save the post + comment count + view count as a screenshot for the listing-application packet (organic community-engagement proof).
- [ ] After ~7 days, update PROJECT_FACTS.md with the new view + click-through total as a citable engagement metric.

---

**Last updated:** 2026-05-26
**Proven base:** Variant 1 (1,600+ views in 15 days on r/CPUMining, pre-Monero-framing-removal)
