# CoinCync: Permissionless Privacy Money with Mandatory Confidentiality and a Hash‑Locked Constitution

**A fair‑launch, RandomX CPU‑mined cryptocurrency with consensus‑level privacy,
an auditable asymptotic supply, and a dual‑tier confidentiality architecture.**

*Version 0.1 (draft) — pre‑mainnet, testnet‑only. The shielded layer described in
§6 is implemented and soak‑tested but disabled on all production networks pending
an external security audit.*

---

## Abstract

CoinCync is a proof‑of‑work cryptocurrency that makes financial privacy the
default rather than an opt‑in. Its transparent base layer adopts the Monero
model — CLSAG ring signatures, Bulletproofs(+) confidential amounts, and stealth
addresses — so that sender, receiver and amount are hidden on every ordinary
payment. On top of this, CoinCync is building a second confidentiality tier: a
**Lelantus‑Spark** shielded pool that replaces a fixed‑size decoy ring with a
pool‑sized anonymity set and logarithmic‑size membership proofs, eliminating the
remaining ring‑bounded linkability. Issuance is a fair launch — no premine, no
founder reward — mined with **RandomX** to keep ordinary CPUs competitive, and
converges to a **100,000,000 CYNC** cap with a small perpetual tail that keeps
security funded forever. A distinguishing design choice is a **hash‑locked
constitution**: the economic and rights invariants of the system are committed
into the build itself, so the chain's heart cannot be changed silently — only
through an explicit, reviewable, coordinated hard fork. This paper describes the
consensus, monetary policy, both privacy tiers, the network model, governance,
and the staged security posture under which privacy features are kept
fail‑closed and disabled until independently audited.

---

## 1. Introduction

Two problems recur in privacy cryptocurrencies. First, privacy is often optional,
which fragments the anonymity set and marks the private users. Second, the rules
that matter most — supply, privacy guarantees — can in practice be changed by the
few people who control the reference implementation. CoinCync addresses both:
privacy is **mandatory** at the consensus layer, and the inviolable rules are
**hash‑locked** into the software so a change cannot pass unnoticed.

CoinCync does not try to be novel for novelty's sake. It reuses the most
battle‑tested privacy constructions available (Monero's transparent stack;
Firo's Lelantus‑Spark for the shielded pool) and concentrates its original work
on *integration discipline*: a single audited shielded engine, a fail‑closed
activation model, deterministic consensus, and a constitution the authors
themselves cannot quietly rewrite.

### 1.1 Design goals

1. **Mandatory confidentiality** — hide sender, receiver, amount by default.
2. **Fair, CPU‑friendly issuance** — RandomX PoW, no premine.
3. **Auditable, bounded supply** — a recomputable emission schedule to a fixed
   cap plus a perpetual tail.
4. **Tamper‑evident consensus** — a hash‑locked constitution and consensus
   fingerprinting.
5. **Conservative security staging** — unaudited privacy stays off, fail‑closed,
   behind far‑future activation gates, until external review.

### 1.2 Units

The ticker is **CYNC**. One CYNC is 10¹² atomic units.

---

## 2. Consensus

### 2.1 Proof of Work: RandomX

CoinCync mines with **RandomX**, the ASIC‑resistant, CPU‑optimised PoW. Each
difficulty epoch derives a RandomX key and dataset; nodes validate in a
light (cache‑only) mode and miners use a full‑memory dataset. A **dataset
self‑check** verifies a freshly built dataset against a light‑mode reference
before it is used, and a runtime recheck drops a dataset that mis‑verifies the
node's own block, so a corrupt dataset cannot silently waste work or accept bad
blocks.

### 2.2 Difficulty

The retarget is an ASERT‑style absolutely‑scheduled algorithm tracking a
**120‑second** block interval. It is a pure function, replay‑tested as a
closed‑loop control system: given a hashrate model it converges back to the
target spacing across step changes in hashrate, with no windowing or seam.
Non‑consensus block‑interval telemetry is kept in a separate module so the
hash‑locked retarget code is never touched for observability.

### 2.3 Finality and reorg defence

Block acceptance is bounded by a maximum reorg depth and by canonical
checkpoints. Beyond that, CoinCync provides **miner‑signed rolling checkpoints**
(soft finality: a supermajority of recent miners attest to a tip, and reorgs
below the attested floor are refused) and an optional, activation‑gated
**rolling‑finality** enforcement rule. Nodes advertise a **consensus
fingerprint** in the handshake so a peer running divergent rules is detected
rather than silently followed.

### 2.4 The hash‑locked constitution

The consensus‑critical files — `constants.rs`, the testnet parameters, the
difficulty, PoW and validation modules, the emission curve, and the
`CONSTITUTION.md` / `BILL_OF_RIGHTS.md` texts — are hashed into
`critical_files.lock`. The build **refuses to compile** if any of them changes
without an explicit, recorded regeneration of the lock. Economic invariants
(e.g. the 100M cap, the tail value) are additionally asserted at compile time
against the constitution. The effect is that the heart of the chain cannot drift
silently: every consensus change is visible in review and requires a deliberate,
coordinated act.

---

## 3. Monetary policy

- **Cap:** 100,000,000 CYNC (asymptotic).
- **Tail:** 0.6 CYNC per block, perpetual.
- **Schedule:** each block's reward is
  `max(TAIL, remaining_supply / divisor)` — a smooth decay toward the cap, then
  the flat tail, so there is no cliff and security is always rewarded.
- **Block time:** 120 s.

Supply is independently verifiable: `cumulative_emission(h)` recomputes the
expected total from the schedule, and the node reconciles it against the running
`total_supply` on every connect, disconnect and reorg — turning a once test‑only
invariant into a live guard. An activation‑gated **supply‑commitment** rule can
additionally bind the cumulative supply into the block header, so a chain that
over‑issued could not produce a valid header.

---

## 4. Transaction model

CoinCync transactions are UTXO‑based. The wire format carries a transaction type
(`TxType`): the ordinary **transparent** type, a coinbase, and a gated
**shielded** type (§6). Unknown types are rejected at decode (borsh discriminant
checking), and the validator's type dispatch is exhaustively checked by the
compiler, so a new type can never be silently admitted.

---

## 5. Privacy tier 1 — the transparent base layer

Every ordinary CoinCync payment already conceals the three sensitive facts:

- **Sender anonymity — CLSAG ring signatures.** A spend is signed over a ring of
  one real and many decoy outputs; the verifier learns that *some* ring member
  signed, not which. The default ring size is **16** (bootstrap floor 11, maximum
  32). Decoys are selected by an age‑ and distribution‑aware policy, with a
  self‑audit that checks the realised ring distribution.
- **Amount confidentiality — Bulletproofs(+).** Output amounts are Pedersen
  commitments; a Bulletproofs+ range proof shows each is in range without
  revealing it, and balance is proved homomorphically. Proofs are batch‑verified.
- **Receiver unlinkability — stealth addresses.** Each payment is sent to a fresh
  one‑time address derived via Diffie‑Hellman from the recipient's public
  address, so on‑chain outputs cannot be linked to a published address.
  **Integrated addresses** (encrypted payment IDs) and **subaddresses** support
  exchange deposits and account separation without extra linkage.

This tier is live on testnet today.

---

## 6. Privacy tier 2 — the Lelantus‑Spark shielded pool

### 6.1 Motivation

Ring signatures bound the anonymity set to the ring size (16). A shielded pool
removes that bound: a spend proves membership in the **entire pool** with a
proof whose size is logarithmic in the pool, and publishes a **nullifier** that
makes a second spend of the same coin detectable without revealing which coin was
spent. CoinCync adopts **Lelantus‑Spark** (the construction deployed by Firo) for
this tier.

### 6.2 Construction

A shielded coin commits to a value and secrets; spending it:

1. proves **one‑out‑of‑many** membership in the pool's commitment set
   (Grootle/Groth‑Kohlweiss‑style, logarithmic size) over a hidden index;
2. binds a **Dodis‑Yampolskiy‑style linking tag** (the nullifier) to the coin's
   serial and the spender's key, published to prevent double‑spends while keeping
   the spent index hidden;
3. carries **range proofs** on the value commitments and a **balance proof** so
   that value is conserved, including a signed **value‑balance** term that
   accounts for value crossing between the transparent and shielded sides
   (shield‑in is negative, unshield positive, pure‑shielded zero).

CoinCync's production engine is the vendored **libspark** (Firo's audited
Lelantus‑Spark C++), isolated behind a dedicated `spark-connector` crate and a
narrow FFI (`SparkBackend`: create output, build spend, verify spend, identify).
The vendored source is pinned to a specific upstream commit with a recorded,
byte‑verifiable provenance manifest. A separate native Rust implementation of the
underlying one‑out‑of‑many primitives is retained, gated, as a differential
oracle and research record — it is **not** the production path.

### 6.3 Consensus integration

The shielded type threads through the full stack, each stage fail‑closed:
stateless mempool admission (`check_shielded_tx`), stateful block‑level
verification against the pool accumulator (`verify_block_spark_v2` /
`verify_block_shielded_spends`), nullifier double‑spend rejection, a
reorg‑durable pool accumulator with restart‑persistent checkpoints, and a
pool‑value **turnstile** that rejects any block which would make the shielded
pool value negative — i.e. no inflation can cross the veil.

### 6.4 Wallet

The wallet derives shielded addresses, scans the pool for owned notes using an
**incoming view key** (watch‑only: it can see balances but cannot spend), reports
balance, and builds shielded sends/transfers and self‑spends.

### 6.5 Validation status

The shielded path has passed a **24‑hour in‑block consensus soak** (hundreds of
thousands of mint/transfer/spend/reorg cycles with real libspark proofs, zero
anomalies) and a separate FFI verify soak.

### 6.6 Safety gating (critical)

On **testnet and mainnet** the shielded activation height is `u64::MAX` —
permanently disabled. A normal production binary is byte‑identical with shielded
off on every network; the feature can only be switched on in a special
feature‑gated build, and only on the isolated **regtest** and **beta** networks.
**The shielded tier remains disabled on every real network until an external
audit is complete.**

---

## 7. Network‑level privacy

Transaction‑origin privacy is protected with **Dandelion++** (a stem phase that
relays a new transaction along a single anonymity path before fluffing it to the
whole network). CoinCync implements this through an upgradeable **privacy
connector** ("Baffle") with size‑aware adaptive stem timing, registered on a
connector catalog so the policy can be improved without touching the core relay.
The node is Tor‑friendly and uses eclipse‑resistant peer management (per‑subnet
caps, per‑address exponential backoff, re‑bootstrap on isolation, a runtime mesh
floor).

---

## 8. Networks

CoinCync defines four networks: **mainnet** (parked pending audit), **testnet**
(the live public test chain), **regtest** (local/deterministic), and **beta** —
an isolated *public* network, with its own genesis and magic bytes, where gated
and still‑unaudited consensus features (such as shielded) are switched **on** at
finite heights for opt‑in user testing. Beta mirrors testnet's schedule but can
never peer with or split testnet/mainnet, giving new features real runtime
exposure (live mempool → mining → P2P relay → re‑verify) on a disposable network
before any mainnet proposal.

---

## 9. Governance

Rule changes are deliberate and public. The inviolable rules live in
`CONSTITUTION.md` (hash‑locked). A **hard‑fork activation policy** (CIP‑007) and a
**testnet hard‑fork rehearsal** process (CIP‑010) govern how and when rules
change. The broader design space is captured as numbered **CoinCync Improvement
Proposals (CIPs)** and design notes, each of which functions as the technical
specification — effectively the per‑component whitepaper — for its feature.

---

## 10. Security posture

CoinCync's security philosophy is *conservative staging*:

- **Testnet‑only until audit;** mainnet parked; shielded gated off everywhere
  real.
- **Hash‑locked heart;** consensus files cannot change without a reviewable
  re‑bless.
- **Fail‑closed defaults;** new/unaudited verifiers reject rather than accept,
  behind far‑future activation gates.
- **Determinism program;** clock/RNG/transport determinism enablers plus staged
  correctness features and a treasury‑protection suite (custody attestation,
  sealed audit packages, watch‑only monitoring, allow‑lists, velocity limits).
- **Multi‑regime testing;** the full suite is run green across the default,
  shielded‑gated and FFI builds before consensus changes land.

---

## 11. Roadmap

1. Finish the shielded pool with production (Firo‑class) anonymity‑set parameters
   and submit it for **external audit** — the single highest‑priority track.
2. Exercise the gated shielded path end‑to‑end on the **beta** channel.
3. Launch **mainnet** once the audit clears.
4. Deliver the CIP backlog: cross‑chain on‑ramp into the shielded pool,
   merge‑mined liquidity (CIP‑002), warp‑sync snapshots (CIP‑015), near‑tip
   compact‑block propagation (CIP‑019), private light‑wallet fast sync (CIP‑018),
   ring‑size increase (CIP‑017), payment URIs (CIP‑014), and more.

---

## 12. Conclusion

CoinCync combines well‑reviewed privacy cryptography with unusual integration
discipline: one audited shielded engine, mandatory base‑layer privacy, a fair
RandomX launch, a bounded‑but‑perpetually‑secured supply, and a constitution that
is committed into the software so it cannot be quietly rewritten. The shielded
tier — the system's most ambitious component — is built and soak‑tested, and is
held disabled and fail‑closed on every real network until it has passed
independent audit. Privacy should require no one's permission; CoinCync is an
attempt to make that true by construction.

---

## References & further reading

- **Constitution:** `CONSTITUTION.md`
- **Operational README:** `README.md`
- **Full overview:** `docs/COINCYNC_OVERVIEW.md`
- **CIPs (per‑feature specifications):** `docs/cip/CIP-001 … CIP-020`
- **Design notes:** `docs/design/` — in particular the shielded set
  (`cip-shielded-*.md`), the block format (`cip-spark-block-format.md`), the
  anonymity‑set analysis (`cip-shielded-anonset.md`), the libspark FFI
  (`cip-shielded-libspark-ffi.md`), the threat model
  (`cip-security-threat-model.md`), and the correctness program
  (`correctness-program.md`).

*Lelantus‑Spark is the construction of Aram Jivanyan et al. as implemented by the
Firo project; CoinCync vendors and binds to that implementation rather than
reimplementing it. RandomX is the work of the Monero project. CoinCync's
transparent privacy stack follows the Monero/CLSAG/Bulletproofs+ lineage.*
