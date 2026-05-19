<!-- markdownlint-disable MD013 MD033 -->
# CoinCync — Privacy Features Map

**Privacy money that requires no permission.** The features below are how that promise is implemented at the consensus, network, and wallet layers. Anything that would weaken the promise is on the [explicitly-not-doing](explicitly-not-doing.md) list.

**Purpose:** new-developer onboarding reference. Every privacy feature in the
codebase, where it lives, what it does, and its **honest implementation
status**. Read this alongside [`THREAT_MODEL.md`](THREAT_MODEL.md) (which
adversary each feature defeats) and [`src/protocol/privacy-model.md`](src/protocol/privacy-model.md)
(the protocol-level model).

**Network status:** CoinCync is on **public testnet**. Mainnet is targeted for
later 2026. "Live" below means *live on testnet and in the default node/wallet
build* — it does not mean a mainnet deployment exists yet.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ **Live** | Implemented and active in the default build (testnet). |
| 🔒 **Feature-gated** | Implemented but compiled only behind an opt-in Cargo feature; off by default. |
| ⚠️ **Inert** | Real implementation in-tree, but not wired into the running chain (e.g. constructed as `Option::None`). Activates at Phase 2. |
| 📐 **Design-only** | A CIP / design doc exists; implementation is partial or absent. |
| ❌ **Not implemented** | Acknowledged gap. |

---

## 1. Active privacy stack (Phase 1) — live on testnet

### 1.1 Cryptographic primitives — `src/crypto/`

| Feature | File | What it does | Status |
|---|---|---|---|
| **CLSAG ring signatures** | `clsag.rs` | Hides *which* ring member spent an output. Ring 16 (Ring 11 during bootstrap, height < 10 000). Key images prevent double-spends. | ✅ Live |
| **Bulletproofs+ range proofs** | `bulletproofs.rs` | Hides output *amounts* via Pedersen commitments `C = v·H + r·G` + a proof the value is in `[0, 2^64)`. Standard Bulletproofs + the BP+ variant. | ✅ Live |
| **Stealth addresses** | `stealth.rs` | ECDH-derived one-time output keys — every output goes to a unique address. Includes subaddresses, audit keys, batch scanning. | ✅ Live |
| **Scoped view keys** | `view_keys.rs` | Forward-secret view keys scoped by epoch / time-range / amount-cap / single-use (`ViewKeyScope`). Key bytes zeroized on drop, excluded from serialization. | ✅ Live |
| **Encrypted memos** | `memo.rs` | ChaCha20-Poly1305 memos on outputs; ECDH key derivation; ≤256 bytes, enforced at consensus. | ✅ Live |
| **Decoy selection** | `ring_selection.rs` | **Uniform** random decoy picking (deliberately *not* gamma-distributed — defeats output-age statistical deanonymization). | ✅ Live |
| **Selective disclosure** | `disclosure.rs` | Non-interactive Fiat-Shamir proofs for voluntary compliance (prove balance ≥ X, ownership, source) without revealing the rest. | ✅ Live |
| **Batch verification** | `batch_verify.rs`, `parallel_proofs.rs` | Parallel batch-verify of CLSAG / Bulletproofs — block-validation performance, not a privacy feature itself but part of the crypto path. | ✅ Live |
| **CLSAG multisig** | `clsag_multisig.rs` | Multi-party CLSAG signing (pairs with the FROST coordinator work). | ✅ Live |

### 1.2 Network-layer privacy — `src/network/`

| Feature | File | What it does | Status |
|---|---|---|---|
| **Dandelion++** | `dandelion.rs` | Stem/fluff transaction relay — stem phase hops through fixed per-epoch relay peers with Poisson delays + exponential embargo timers before fluff broadcast. Breaks "tx-submission IP → originator" linkage. | ✅ Live |
| **Traffic shaping** | `traffic_shaping.rs` | Three layers: constant-rate cover packets (`MessageType::Padding`), packet-size normalization to standard TLS frame sizes, and outbound timing jitter. Makes an idle node indistinguishable from an active one to a network observer. | ✅ Live |
| **Noise XX encryption** | `noise.rs` | Authenticated + encrypted P2P links — no plaintext peer traffic. | ✅ Live |
| **Peer scoring / Sybil defense** | `scoring.rs` | Scores and bans peers exhibiting isolation/stall patterns — protects the stem-phase relay relationships Dandelion++ depends on. | ✅ Live |

### 1.3 Consensus-level enforcement — `src/consensus/`

| Feature | File | What it does | Status |
|---|---|---|---|
| **Mandatory privacy** | `privacy_policy.rs` | Consensus rule: rejects transparent transactions. Every non-coinbase tx must have hidden amounts (non-zero Pedersen commitments), hidden recipients (stealth/Spark addresses, never raw pubkeys), and ≥1 privacy-preserving input. No transparent escape hatch. | ✅ Live |
| **Ring-size rules** | `constants.rs` + `validation.rs` | `RING_SIZE = 16`, `BOOTSTRAP_MIN_RING_SIZE = 11` (height < `BOOTSTRAP_CUTOVER_HEIGHT = 10 000`), `MAX_RING_SIZE = 32`. Enforced per-input in block validation. | ✅ Live |

### 1.4 Wallet-level privacy — `src/wallet/`, `src/transaction/`

| Feature | File | What it does | Status |
|---|---|---|---|
| **Auto-churn** | `wallet/churn.rs` | Wallet self-sends at Poisson-distributed intervals — fresh stealth address, full ring + decoys + range proof each time. Config-driven, **disabled by default**. | ✅ Live (opt-in) |
| **Deniable wallets** | `wallet/persistence.rs` | Two-password plausible deniability — decoy + real data in one size-padded file (`[len][decoy][real]`); loading tries the password against both regions. | ✅ Live |
| **Dead man's switch** | `transaction/recovery.rs` | Time-locked recovery metadata in the tx extra field (TLV, 42 B/output). After `timeout_blocks` (24 h – 2 y) a recovery address can sweep without the owner's spend key. Validated at consensus. | ✅ Live |
| **Wallet scanner** | `wallet/scanner.rs` | View-key chain scanning — ECDH stealth-address matching + commitment verification + subaddress derivation. | ✅ Live |
| **Subaddresses** | `wallet/subaddress.rs`, `crypto/stealth.rs` | Unlinkable receive addresses from one key set — outputs across subaddresses don't correlate. | ✅ Live |

### 1.5 The "7 privacy innovations" — quick index

A project shorthand; all seven are ✅ Live on testnet. They are not separate
subsystems — they map onto the tables above:

1. **Decoy defense** → `crypto/ring_selection.rs` (uniform selection)
2. **Encrypted memos** → `crypto/memo.rs`
3. **Scoped view keys** → `crypto/view_keys.rs`
4. **Deniable wallets** → `wallet/persistence.rs`
5. **Traffic shaping** → `network/traffic_shaping.rs`
6. **Dead man's switch** → `transaction/recovery.rs`
7. **Auto-churn** → `wallet/churn.rs`

---

## 2. Phase 2 — partial; the activation path is *not* just "wire it up"

Verified state. The cryptographic primitives are **partially** in-tree —
Lelantus Spark (`lelantus_spark.rs`, 917 lines), kernel offsets, and MW
cut-through are real implementations. **But the shielded half is a green
field**: `crates/orchard-side/src/` is an empty directory (no `Cargo.toml`, no
`lib.rs`) — the Halo2 shielded action circuit doesn't exist in this repo yet.
And the `Transaction` type is ring-only — it has no fields or variants that
can represent a shielded note, a Spark coin, or an MW kernel. Activating Phase
2 therefore needs (a) writing the Halo2 circuit, (b) a hard-forking
`Transaction`-format extension, (c) consensus-validation updates in the
locked files `privacy_policy.rs` / `validation.rs`, *and* (d) the chain wiring
to populate the stores — in that order. Per `fork_signal.rs:66`'s "M-5 FIX:
Phase 2 features disabled until external audit complete," the activation
framework deliberately holds this back behind an audit window.

The rest of this section lists what *does* exist in-tree today and how it's
held inert — useful for a new dev surveying the code, **not** a "ready to
flip on" inventory.

| Feature | File | Status | Activation path |
|---|---|---|---|
| **Lelantus Spark** | `crypto/lelantus_spark.rs` | 🔒 Feature-gated (`sketch-lelantus-spark`, off by default). One-out-of-many proofs over a ~16 384-coin anonymity set (~1000× CLSAG-16). | CIP-005 |
| **MimbleWimble cut-through** | `crypto/mw_cutthrough.rs` | ⚠️ Inert — real code, but wired as `None` in `chain.rs` (no kernel appends happen). Prunes spent outputs after `MW_CUTTHROUGH_DEPTH` blocks, keeping only kernels. | CIP-003 |
| **Kernel offsets** | `crypto/kernel_offset.rs` | 🔒 Feature-gated (`sketch-kernel-offsets`, off by default). Blinding-factor unlinkability layer — real implementation (`KernelOffset::generate` / `aggregate` / `verify_against`, `AggregateOffset`), **not a stub**; simply not compiled into the default build. | CIP-004 (depends on CIP-003) |
| **ShieldedStore** | `storage/shielded.rs` | ⚠️ Inert — full BridgeTree commitment tree (depth 32) + nullifier set + reorg checkpoint/rewind. Constructed as `Option::None` in chain state. | Phase 2 (Halo2 action circuit) |
| **SparkStore** | `storage/spark.rs` | ⚠️ Inert — Lelantus Spark coin accumulator + spent-serial set + reorg checkpoint/rewind. `Option::None` in chain state. | CIP-005 |
| **KernelStore** | `storage/kernels.rs` | ⚠️ Inert — MimbleWimble kernel store surviving cut-through + reorg checkpoint/rewind. `Option::None` in chain state. | CIP-003 |

> **Reorg note for the Phase-2 stores:** all three carry a checkpoint/rewind
> stack so they roll back in lock-step with the UTXO set on a chain reorg
> (post-launch campaign item #2 / CIP-009.D Interp-B). That wiring is in
> `chain.rs` but inert while the stores are `None`.

---

## 3. Acknowledged gaps

| Gap | Status | Notes |
|---|---|---|
| **Tor / onion routing** | ❌ Not implemented | No SOCKS/Tor transport in `src/network/`. `THREAT_MODEL.md §2.2` names the "active cut-route adversary" as a non-defense and states the fix is "Tor or a similar anonymizing transport beneath CoinCync's P2P." Intended as a wallet default for mainnet. |

---

## 4. Where to read more

- **[`docs/THREAT_MODEL.md`](THREAT_MODEL.md)** — adversary classes (chain-only, network-observing, chain+network, coercion) and which feature defeats which. Start here for the *why*.
- **[`docs/src/protocol/privacy-model.md`](src/protocol/privacy-model.md)** — the protocol-level privacy model.
- **CIPs covering the Phase-2 features** (`docs/cip/`):
  - **CIP-003** — Cut-Through & Block Aggregation (MimbleWimble compaction).
  - **CIP-004** — Kernel Offsets (blinding-factor unlinkability; depends on CIP-003).
  - **CIP-005** — Lelantus Spark (large anonymity set).
  - **CIP-007** — Hard-Fork Activation Policy (the ~95%-miner-signaling process all Phase-2 activations go through).
- **`critical_files.lock`** — `privacy_policy.rs`, `constants.rs`, and other consensus-critical files are integrity-locked; changing them is a deliberate consensus action.

---

## 5. One-paragraph orientation for the new dev

The **active** privacy stack is Phase 1: ring signatures + confidential amounts
+ stealth addresses + the network layer (Dandelion++, traffic shaping, Noise),
all enforced as *mandatory* at the consensus layer — there is no transparent
transaction type, by design. The **7 "innovations"** are wallet- and
crypto-level features layered on top, all live on testnet. **Phase 2** (Spark,
cut-through, kernel offsets, the three privacy stores) is real code sitting
in-tree but switched off — it activates through the CIP hard-fork process, not
by default. The one honest gap is Tor support. When in doubt about whether
something runs, check: is it behind a `sketch-*` Cargo feature, or constructed
as `Option::None` in `chain.rs`? If yes to either — it's Phase 2, not live.

---

*Document status: onboarding reference, maintained by hand. If you touch a
privacy feature, update the relevant row. Last mapped: 2026-05.*
