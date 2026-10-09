# CoinCync — Complete Overview

> **Privacy money that requires no permission.** A fair‑launch, RandomX
> CPU‑mined cryptocurrency with mandatory privacy at the consensus layer, an
> auditable asymptotic supply, and a hash‑locked constitution that even its
> authors cannot quietly change.

This is the single‑page tour of *everything* CoinCync is and does. For hands‑on
build/run steps see [`README.md`](../README.md); for the formal specifications
see the CIPs in [`docs/cip/`](cip/) and the design notes in
[`docs/design/`](design/); the canonical whitepaper is
[`docs/whitepaper/CoinCync-Whitepaper.md`](whitepaper/CoinCync-Whitepaper.md).

> **Status legend:** ✅ live on testnet · 🔒 built but gated/disabled pre‑audit ·
> 🧪 experimental / soak‑only · 📐 designed (CIP/spec) · 🅿️ parked. Mainnet is
> parked pending an external security audit; the shielded pool is gated OFF on
> every production network until then.

---

## 1. What CoinCync is

CoinCync is a from‑scratch cryptocurrency in **Rust**. It takes Monero's proven
transparent privacy model (ring signatures + confidential amounts + stealth
addresses), mines with **RandomX** so ordinary CPUs stay competitive, and builds
toward stronger privacy and scaling: a **Lelantus‑Spark shielded pool** and
**Mimblewimble‑style cut‑through**.

| Pillar | Meaning |
|---|---|
| **Mandatory privacy** | Every ordinary payment hides sender, receiver and amount at consensus. |
| **Fair launch** | No premine, no founder reward; RandomX keeps issuance CPU‑distributed. |
| **Auditable supply** | Smooth emission to a **100,000,000 CYNC** cap + a perpetual tail; supply is independently recomputable and optionally header‑committed. |
| **Hash‑locked constitution** | Economic/rights invariants in `CONSTITUTION.md` / `BILL_OF_RIGHTS.md` are hashed into `critical_files.lock`; the build refuses to compile if a consensus file changes without an explicit re‑bless. |
| **Permissionless** | P2P, Tor‑friendly, no gatekeepers. |

**Unit & ticker:** **CYNC**; 1 CYNC = 10¹² atomic units. **Block time** 120 s.
**Ring size** 16 (bootstrap floor 11, max 32).

---

## 2. Monetary policy & economics ✅

- **Max supply** 100,000,000 CYNC (asymptotic); **tail** 0.6 CYNC/block forever.
- **Emission curve** `max(tail, remaining/divisor)` — smooth decay then flat tail
  (`docs/src/protocol/emission.md`, `emission/curve.rs`).
- **Live supply reconciliation** — `cumulative_emission(h)` re‑derives expected
  supply and the node checks it against `total_supply` on every connect/
  disconnect/reorg.
- **Supply‑commitment enforcement** 📐🔒 — bind cumulative supply into the block
  header so an over‑issuing chain can't produce a valid header (CIP, activation‑
  gated).
- **Fee model**: **standardized fee tiers** (privacy — uniform fees so fee amount
  doesn't fingerprint a wallet) and a 📐 **fee reservoir** ("water battery") that
  charges fee surplus at low congestion and discharges at peak to smooth the
  security budget, issuance‑neutral by construction.

---

## 3. Consensus ✅

- **PoW: RandomX** — CPU‑optimised, ASIC‑resistant; per‑epoch dataset with a
  **self‑check** that rejects a corrupt dataset (light vs full‑mem modes).
- **Difficulty** — ASERT‑style retarget to the 120 s target; closed‑loop
  replay‑tested; separate non‑consensus **difficulty/interval telemetry**;
  oscillation analysis for low‑hashrate chains.
- **Reorg defence** — bounded reorg depth, checkpoints, **miner‑signed rolling
  checkpoints** (CIP‑009‑D, soft finality) and optional **rolling‑finality**
  enforcement (CIP‑011) via a dedicated attestation service.
- **Consensus fingerprint** — advertised in the handshake so a rules mismatch is
  detected, not silently followed.
- **Hash‑locked consensus files** — `constants.rs`, `testnet.rs`,
  `consensus/{difficulty,pow,validation}.rs`, `emission/curve.rs`, the
  constitution texts; compile‑time economic asserts (100M cap, tail).
- **Coded diagnostics** — consensus‑critical failures emit stable codes
  (`coincync-dbg explain CYNC‑…`).

---

## 4. Privacy tier 1 — transparent base layer ✅

Every ordinary payment conceals all three sensitive facts:

- **Sender** — **CLSAG ring signatures** over decoy rings (default 16). Decoy
  selection is **empirical/histogram‑tracking** (matches the real spend‑age
  distribution), with a **ring self‑audit lint**. Ring‑size increase above 16 is
  specced in CIP‑017.
- **Amount** — **Bulletproofs(+)** range proofs over Pedersen commitments;
  batch‑verified.
- **Receiver** — **stealth (one‑time) addresses**, plus **integrated addresses**
  (encrypted payment IDs) and **subaddresses** for account separation.

---

## 5. Privacy tier 2 — Lelantus‑Spark shielded pool 🔒 (built, gated OFF, pre‑audit)

Replaces the 16‑member ring with a **pool‑sized anonymity set** and
logarithmic‑size membership proofs; publishes a nullifier to stop double‑spends
without revealing the spent coin (CIP‑005, `cip-shielded-*.md`).

- **Engine** — vendored **libspark** (Firo's Lelantus‑Spark C++), isolated behind
  the `spark-connector` crate + FFI (`SparkBackend`); pinned to an audited
  upstream commit with a provenance manifest (`cip-shielded-libspark-ffi.md`).
- **TxType::Shielded** — `ShieldedPayload` carries shield‑in mints, shielded
  spends/outputs, a signed **value‑balance** for crossing the veil, and the spend
  proofs (`cip-shielded-txtype.md`, `cip-spark-block-format.md`).
- **Spend proof** — one‑out‑of‑many membership (Grootle/Groth‑Kohlweiss) + a
  Dodis‑Yampolskiy **linking tag** nullifier + range + balance
  (`cip-shielded-proof.md`, `cip-shielded-spend-composition.md`,
  `cip-triptych-ki-binding.md`).
- **Anonymity‑set determinism contract** — every node derives the same cover set
  (`cip-shielded-anonset.md`); production target Firo‑class (n=8, m=5 ⇒ 32768).
- **Consensus frame** — fail‑closed mempool admission, block‑level verify, a
  reorg‑durable pool accumulator, nullifier double‑spend rejection, and a
  **pool‑value turnstile** (no inflation across the veil).
- **Wallet** — shielded addresses, note scan via **incoming view key**
  (watch‑only), balance, send/transfer, self‑spend (`cip-shielded-notes.md`).
- **Validated** — 24h in‑block consensus soak (0 anomalies) + FFI verify soak.
- **Safety** — activation `u64::MAX` on testnet/mainnet (permanently off);
  activatable only on regtest/beta in a gated build. **Off everywhere real until
  external audit.**

---

## 6. Scaling & aggregation — Mimblewimble‑style 📐

- **Cut‑through & aggregation** (CIP‑003) — collapse spent intermediate outputs so
  the chain stores net state, not every historical output.
- **Kernel offsets** (CIP‑004) — Mimblewimble transaction kernels; a KernelStore
  participates in the Phase‑2 accumulator set and bridges to the Spark pool
  (MW‑Pedersen ↔ Spark value bridge).

---

## 7. Merge mining & liquidity 📐🅿️

- **Governed merge‑mining / AuxPoW** (`auxpow` crate, `auxpow-governed-merge-
  mining.md`) — allow CoinCync to be merge‑mined with a **hashrate governor** so
  borrowed hashrate is bounded/governed rather than unconditional.
- **CynchHub** (CIP‑002, `cynchub` crate) — a post‑mainnet merge‑mined liquidity
  layer (skeleton; re‑joins the workspace when implementation starts).

---

## 8. Treasury & solvency proofs 📐🧪

- **Unlinkable treasury solvency** (`cip-unlinkable-solvency.md`) and
  **unlinkable *unspent* solvency** (`cip-unlinkable-unspent.md`) — prove the
  treasury holds/retains funds without doxxing the specific outputs.
- **Treasury‑protection suite** 🧪 — custody attestation, sealed audit packages,
  watch‑only monitoring, allow‑lists, velocity limits, hygiene checks.

---

## 9. Networks ✅

| Network | Purpose | Shielded |
|---|---|---|
| **Mainnet** | The real chain — **parked** until audit. | off (`u64::MAX`) |
| **Testnet** | Live public test chain (seed `2.29.34.197:28080`). | off (`u64::MAX`) |
| **Regtest** | Local, deterministic; soak harnesses. | activatable (gated) |
| **Beta** | **Isolated public** net (own genesis + magic) where *gated, unaudited* features switch **on** at finite heights for opt‑in testing. Can't peer with / split testnet or mainnet. | activates (gated) |

---

## 10. Networking & propagation

- **Noise‑encrypted P2P**, borsh‑framed messages, headers‑first multi‑peer IBD,
  work‑aware fetch. ✅
- **Eclipse resistance** — addrman new/tried tables (`addrman-new-tried.md`),
  per‑/16 caps, per‑address backoff, **runtime mesh‑floor + anchor durability**.
  ✅
- **Honest health** — `fork_stuck` fires only when *both* behind **and** stalled.
  ✅
- **Dandelion++** stem/fluff relay via the upgradeable **Baffle** privacy
  connector (adaptive stem timing) on the connector catalog ("Manifold"). ✅
- **Near‑tip block propagation** (CIP‑019) 📐 — compact/near‑tip relay to fix
  chronic lag and single‑miner stalls.
- **Constant‑rate origination pacing** (CIP‑020) 📐 — close the traffic‑shaper
  timing side‑channel by pacing tx origination.
- **Tor hidden services** + **federation / DDoS** operations guidance. ✅

---

## 11. Sync & bootstrap

- **Warp sync via UTXO‑set snapshots** (CIP‑015) 📐 — fast initial sync from a
  state snapshot instead of full replay.
- **Private light‑wallet fast‑sync** (CIP‑018) 📐 — let light wallets sync without
  leaking which outputs they care about.
- **Bootstrap from snapshot** + a **signed bootstrap manifest** for trust‑minimised
  snapshot distribution. ✅
- **Self‑preflight boot guard** (`self-preflight-boot-guard.md`) — the node
  self‑checks its own consensus wiring at boot before joining. ✅

---

## 12. Wallet ✅ / 🔒

- Transparent send/receive (rings + range proofs), **standardized fee tiers**.
- **Integrated addresses** + **subaddresses**.
- **FROST M‑of‑N threshold multisig** send (CIP‑008/012) with a dedicated
  **FROST coordinator** service — reconstruct the group key from shares, sign
  CLSAG, submit, zeroise.
- **Shielded CLI** 🔒 (gated): `shielded-address`, `shielded-send`,
  `shielded-balance`, `shielded-view-key` (watch‑only).
- **Payment URIs + `coincync-pay`** merchant tooling (CIP‑014) 📐.
- Encrypted wallet files with crash‑safe spent‑output reservation/reload.

---

## 13. Mining ✅

- **In‑node solo miner** (`coincync-node --mine <address>`).
- **`coincync-rig`** — standalone **XMRig‑style** miner with a live `--tui`
  dashboard, targeting **xmrig parity** (CIP‑016); enforces a **mesh floor**
  (won't solo‑mine until synced with a healthy peer set).
- RandomX light vs full‑mem; per‑epoch dataset + self‑check.

---

## 14. RPC, API & observability ✅

- **JSON‑RPC 2.0** + **REST** API (`get_info`, `get_mining_live`,
  `send_raw_transaction`, cover‑set/decoy queries, …); read‑only RPC proxy.
- **`get_vitals`** chain‑vitals schema (`chain-vitals-schema.md`).
- **Prometheus `/metrics`**, explorer REST endpoints.
- **Colony** 🧪 — a two‑tier operator security dashboard (public educational view
  + a maintainer‑gated live security tab, Bearer‑auth, fails closed).

---

## 15. Tooling — binaries & crates

**Binaries:** `coincync-node` (full node) · `coincync-wallet` (reference wallet).

| Crate | Role |
|---|---|
| `spark-connector` | Shielded engine: `SparkBackend` trait + vendored libspark FFI |
| `coincync-rig` | Standalone XMRig‑style miner (`--tui`) |
| `coincync-frost-coordinator` | FROST threshold‑signing coordinator (CIP‑008/012) |
| `coincync-rolling-finality` | Rolling‑finality attestation service (CIP‑011) |
| `coincync-swap` | Cross‑chain **atomic swaps** (CIP‑001) |
| `coincync-faucet` | Testnet faucet |
| `coincync-dbg` | Diagnostics / coded‑error explainer |
| `auxpow` | Governed merge‑mining / AuxPoW |
| `cynchub` | CIP‑002 merge‑mined liquidity layer (skeleton) |
| `bridge` | Bridge/relay tooling |
| `orchard-side`, `tick` | Supporting components |

**`cytop`** — a from‑scratch **btop‑architecture** Rust monitor (separate branch):
host (CPU/mem/disks/net/GPU) + node (chain/mining/peers, live node‑log activity
feed, estimated mining earnings), a theme engine that parses btop `.theme` files,
mouse support, and a config file.

---

## 16. Cross‑chain 📐

- **Atomic swaps** (CIP‑001, `coincync-swap`) — trustless cross‑chain swaps.
- **Cross‑chain on‑ramp** (`cip-crosschain-onramp.md`) — a one‑way private
  turnstile peg‑in *into* the Spark shielded pool (anti‑sprawl, trust ladder
  federated→bonded→light‑client), post‑audit.

---

## 17. Governance & the constitution ✅

- **`CONSTITUTION.md`** + **`BILL_OF_RIGHTS.md`** — inviolable rules, hash‑locked.
- **Hard‑fork activation policy** (CIP‑007) and **testnet hard‑fork rehearsal**
  (CIP‑010) — rule changes are deliberate, rehearsed, and public.
- The numbered **CIPs** are the per‑feature specifications.

---

## 18. Security program ✅

- **Testnet‑only until audit**; mainnet parked; shielded gated OFF everywhere
  real.
- **Hash‑locked heart**, **fail‑closed defaults**, **far‑future activation
  gates**.
- **Correctness program** (`correctness-program.md`) — clock/RNG/transport
  determinism enablers + staged hardening.
- **Wave‑1 hardening** (`wave1-hardening.md`) — version fingerprint, graceful
  shutdown, boot canary, mempool health.
- **Threat model** (`cip-security-threat-model.md`) — what the guards catch and
  what they don't.
- **Underground / privacy‑manifold** 🧪🅿️ — a uniform‑face transaction envelope
  research track (`underground-depth-anonymity.md`,
  `privacy-manifold-uniform-face.md`).
- Multi‑regime green test suite (default / shielded‑gated / FFI) before consensus
  changes land.

---

## 19. CIP index

| CIP | Title | Status |
|---|---|---|
| 001 | Atomic swaps | 📐 |
| 002 | CynchHub merge‑mined liquidity layer | 📐🅿️ |
| 003 | Cut‑through & aggregation | 📐 |
| 004 | Kernel offsets (Mimblewimble kernels) | 📐 |
| 005 | Lelantus‑Spark shielded pool | 🔒 |
| 007 | Hard‑fork activation policy | ✅ |
| 008 | FROST coordinator | ✅ |
| 009‑D | Miner‑signed rolling checkpoints | ✅ |
| 009 | Reorg‑defence decision | ✅ |
| 010 | Testnet hard‑fork rehearsal | ✅ |
| 011 | Rolling‑finality activation | 🔒 |
| 012 | FROST coordinator deployment | ✅ |
| 014 | Payment URI + `coincync-pay` | 📐 |
| 015 | Warp sync via UTXO snapshots | 📐 |
| 016 | RandomX hashrate parity with xmrig | ✅ |
| 017 | Ring‑size increase above 16 | 📐 |
| 018 | Private light‑wallet fast‑sync | 📐 |
| 019 | Near‑tip block propagation | 📐 |
| 020 | Constant‑rate origination pacing | 📐 |

---

## 20. Roadmap

1. **Finish shielded → external audit** (production anon‑set params, then propose
   activation). The single highest‑value track.
2. **Beta‑channel live exercise** of the gated shielded path (mint → send →
   spend, live over P2P).
3. **Mainnet launch** after audit.
4. **Cross‑chain on‑ramp** into the pool, then the CIP backlog (cut‑through,
   merge‑mined liquidity, warp‑sync, near‑tip propagation, light‑wallet fast‑sync,
   ring‑size increase, payment URIs, origination pacing).

---

## 21. Where to look next

- Build & run: [`README.md`](../README.md)
- Whitepaper: [`docs/whitepaper/CoinCync-Whitepaper.md`](whitepaper/CoinCync-Whitepaper.md)
- Specs: [`docs/cip/`](cip/) · Design notes: [`docs/design/`](design/)
- Docs site (mdBook): [`docs/src/`](src/) · Rules: [`CONSTITUTION.md`](../CONSTITUTION.md)

---

*CoinCync is pre‑release software under active development. The shielded layer is
unaudited and disabled on all real networks until an external audit is complete.
Nothing here is financial advice.*
