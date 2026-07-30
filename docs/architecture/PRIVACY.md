# CoinCync Privacy — Maintainer Reference

This is the deep-dive companion to [`docs/PRIVACY_FEATURES.md`](../PRIVACY_FEATURES.md)
(the new-contributor map) and [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md)
(the adversary catalogue). It exists for the person who has to **modify,
review, or audit** the privacy code without breaking it.

It assumes you know what a ring signature is, that range proofs exist, and
that "stealth address" isn't a marketing term. It does not re-derive any
crypto.

It does, however, name **every place where a one-line change can
silently destroy user privacy or split consensus**, drawn from real bugs
shipped + caught + fixed in the last two weeks.

---

## Contents

1. [The promises](#the-promises)
2. [Architectural invariants](#architectural-invariants)
3. [Layer 1 — Cryptographic primitives](#layer-1--cryptographic-primitives)
4. [Layer 2 — Transaction privacy](#layer-2--transaction-privacy)
5. [Layer 3 — Network privacy](#layer-3--network-privacy)
6. [Layer 4 — Advanced shielded pools](#layer-4--advanced-shielded-pools)
7. [Layer 5 — Operational privacy](#layer-5--operational-privacy)
8. [The "two validators" rule](#the-two-validators-rule)
9. [Mandatory enforcement](#mandatory-enforcement)
10. [Audit-time invariants](#audit-time-invariants)
11. [Common bug classes](#common-bug-classes-with-real-examples)
12. [Maintenance checklists](#maintenance-checklists)

---

## The promises

CoinCync makes three privacy promises **that cannot be backed out without
violating the Constitution** ([`CONSTITUTION.md`](../../CONSTITUTION.md)
Article III; [`docs/BILL_OF_RIGHTS.md`](../BILL_OF_RIGHTS.md) Articles I,
II, IV):

| Promise | What it means at the wire | Enforced where |
| --- | --- | --- |
| **Sender ambiguity** | The on-chain record never identifies which UTXO funded a tx; every input is one of 11+ structurally indistinguishable candidates | CLSAG ring signatures, `src/crypto/clsag.rs` |
| **Amount confidentiality** | The on-chain record never reveals tx amounts. Outputs are Pedersen commitments + range-proven via Bulletproofs+ | `src/crypto/bulletproofs.rs`, `src/transaction.rs` |
| **Recipient ambiguity** | One-time stealth addresses; the recipient's long-lived public address never appears on-chain | `src/crypto/stealth.rs`, `src/wallet/scan.rs` |

These are **mandatory privacy** — there is no transparent-tx escape hatch.
`src/constants.rs` enforces this:

```rust
pub const MANDATORY_CONFIDENTIAL: bool = true;
pub const MANDATORY_STEALTH: bool = true;
```

Code review rule: any patch that flips either to `false`, or that gates
either behind a config flag at consensus level, is by definition
unconstitutional. Reject without review.

---

## Architectural invariants

These are the load-bearing facts. Most bugs in this codebase happen when
one of these is forgotten.

### Invariant 1 — every tx-validating code path runs the **same** validator

The system has two structural validation entry points:

- **Block validation** — `consensus::validate_block` calls
  `consensus::validate_transaction` for every tx in a block
- **Mempool admission** — `mempool::add_with_chain` runs at
  `send_raw_transaction` RPC time

Both **must** call `consensus::validate_transaction(tx, &utxos,
current_height)`. If they diverge, the same tx can be accepted by mempool,
then rejected when it tries to mine — the "silent eviction" failure mode.

This invariant was violated in v1.0.10 and earlier (see [Bug Class B](#bug-class-b--validator-divergence)).
The post-`7358775` codebase restores it; **do not undo this**.

Specifically, **never re-introduce** a "fast path" check that runs
`validate_transaction_basic` (the contextless one) without also running
the full `validate_transaction`. The `_basic` variant is for shape +
universal-required checks; it deliberately misses every height-gated
rule.

### Invariant 2 — every privacy primitive is **mandatory** at consensus

Range proof missing → reject (line 1748 of `src/consensus/validation.rs`).
Stealth address all-zero → reject (`src/consensus/privacy_policy.rs::check_tx_privacy`).
Commitment all-zero → same. Ring size below `BOOTSTRAP_MIN_RING_SIZE` →
reject (line 1740). These are non-negotiable.

Code review rule: a check that returns early with "skip this for
coinbase" or "skip this for asset type X" is suspect. The coinbase
exemption exists in exactly two places (range proof, balance proof —
coinbase amount is public by design) and is gated behind
`tx.is_coinbase()`. Any other "skip" needs a defensive comment + a
constitutional review.

### Invariant 3 — anonymity sets only work if **all txs look the same**

`UNIFORM_TX_SHAPE_HEIGHT = 0` (currently `BULLETPROOFS_PLUS_HEIGHT`)
means: **from genesis**, every Transfer/Churn tx must be
`STANDARD_INPUT_COUNT × STANDARD_OUTPUT_COUNT` (2-in/2-out) or
`STANDARD_INPUT_COUNT × (STANDARD_OUTPUT_COUNT + 1)` (asset tx, 2-in/3-out).
Anything else dilutes the anonymity set into a fingerprintable subset.

The wallet enforces this via `select_utxos_uniform` and the rejection
in `create_privacy_transaction_with_options` (`src/wallet/send.rs:247-254`).
The validator enforces it via `consensus::validate_transaction`
(line 1094-1124).

Code review rule: a wallet path that lets the user "save bytes by going
2-in/1-out" is unconstitutional unless it's behind a hard fork at a new
activation height. Same for the validator.

### Invariant 4 — **the chain is what the validator says, not what the wallet thinks**

The wallet may build a tx the user wants, but consensus is the authority.
Any wallet code that asserts "the validator will accept this" — *test
that assertion against the actual validator in CI*, not against the
wallet's own checks. The two paths drift; this codebase has shipped at
least one such drift (Crucible Finding #1, this week).

---

## Layer 1 — Cryptographic primitives

### 1.1 CLSAG ring signatures — `src/crypto/clsag.rs`

**What it does.** Proves "I own the secret key for one of these N public
keys" without revealing which one, and pins each spend to a unique key
image `I = x · H_p(P)` so the same key can't sign twice (double-spend
detection without identity reveal).

**Spec.** Goodell, Noether, Blue 2020 (IACR eprint 2019/654). The
**canonical** form — as of `v1.0.11-canonical-clsag` (`589ba64`). The
previous form was close but not exact; commit `589ba64` aligned the
aggregate coefficients with the reference.

**Aggregate coefficients (load-bearing — get these wrong, every
signature fails to verify):**

```text
μ_p = H_s("CLSAG_agg_0" || {P_i} || {C_i} || I || D || C' || msg)
μ_c = H_s("CLSAG_agg_1" || {P_i} || {C_i} || I || D || C' || msg)
```

Both are independent random-oracle outputs over the **full** input set:
ring public keys, commitments, key image, commitment image,
pseudo-output, message. The independence (distinct domain prefix +
identical data binding) is what lets the forking-lemma proof of
unforgeability go through.

**Maintenance rules.**

1. **Never** change the domain-separation strings. `"CLSAG_agg_0"` and
   `"CLSAG_agg_1"` are part of consensus; flipping a byte breaks every
   existing signature.
2. **Never** drop an item from the agg-hash input set. Each one binds the
   signature to a specific context; omitting one creates a malleability
   window.
3. **Never** use a non-canonical curve operation (e.g., variable-time
   point multiplication on secret scalars). The implementation uses
   constant-time Ristretto throughout; preserve that.
4. Adding a new commitment binding (e.g., for a new asset type) needs
   either a new domain prefix (and a hard fork) or a structural argument
   that the existing binding suffices.

**Where the bugs lurk.**

- Key image identity-point checks (`I != identity`). Without this, a
  zero-scalar signer can forge any tx. Defensive layer at line ~115 of
  `clsag.rs`.
- Commitment image identity-point check (same reason, separate input).
- Ring deduplication: two ring members with identical public keys halve
  the effective anonymity set silently. Wallet must dedupe in
  `select_ring_decoys`; validator currently doesn't enforce this
  (open question for v1.0.13 review).

**Critical file.** Yes (`critical_files.lock`). Any change → must update
the lock hash via `COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes` **with a
review comment explaining why**.

### 1.2 Bulletproofs+ range proofs — `src/crypto/bulletproofs.rs`

**What it does.** Proves an amount `v` is in `[0, 2^64)` without
revealing it. Without this, an attacker could "spend" 2^64 - ε CYNC out
of an output that actually holds 1 CYNC, inflating supply.

**Spec.** Bulletproofs+ (Chung-Han-Wong 2020). Active from
`BULLETPROOFS_PLUS_HEIGHT = 0` — i.e., from genesis. The dependency is
`tari_bulletproofs_plus = "0.4"`, pinned with the
`rust-toolchain.toml`-pinned 1.88.0 because 1.92+ breaks tari's SIMD path
(see `rust-toolchain.toml` for the trail).

**Maintenance rules.**

1. **Never** make a range proof optional. The constitutional check at
   `validate_transaction_basic:1748` enforces non-empty range proofs for
   non-coinbase txs.
2. **Never** accept a tx whose claimed amount exceeds `2^64 - 1`
   atomic units. Above this the addition in balance verification wraps
   silently.
3. When upgrading the bulletproofs crate, **rebuild every existing test
   vector** — the range-proof byte layout is consensus-relevant.
   Mismatched serialization = silent fork.

**Critical file.** Yes. Don't touch without an audit-grade review.

### 1.3 Stealth addresses — `src/crypto/stealth.rs`

**What it does.** Recipients publish a long-lived `(spend_pub, view_pub)`
pair. Senders derive a fresh **one-time** public key for each output
using ECDH; the on-chain record only contains the one-time key. An
on-chain observer cannot link two outputs as going to the same
recipient.

**Wire shape.** Each output carries:

- `stealth_address: [u8; 32]` — the one-time pubkey
- `commitment: [u8; 32]` — the Pedersen commitment to the amount
- `view_tag: u8` — 1-byte hint for fast scan filtering (false-positive
  rate ≈ 1/256)
- (encrypted_amount + encrypted_memo, in `encrypted_data`)

**Maintenance rules.**

1. **Never** allow `stealth_address == [0; 32]`. That's the "transparent
   address" attack vector; rejected at
   `privacy_policy::check_tx_privacy`.
2. The `view_tag` is a **performance** feature, not a privacy one. It's
   public; don't add code that conditions on it for privacy reasons.
3. Wallet scan path (`src/wallet/scan.rs`) must check the view_tag
   **before** doing the expensive ECDH/derivation. Otherwise the wallet
   leaks timing signal to anyone observing its CPU.

### 1.4 Pedersen commitments + balance proofs

**What it does.** Each output's amount lives inside a commitment `C =
v·G + r·H` where `r` is a per-output blinding factor. The tx is balanced
when `Σ inputs - Σ outputs = 0·G + (Σr_in - Σr_out)·H`. Verifier sees a
random-looking point, can check it's a multiple of `H`, can't read `v`.

**Implementation.** `src/transaction.rs` (`verify_balance_proof`).

**Maintenance rule.** Same as range proofs — the balance proof is
non-skippable except for coinbase. The coinbase exemption is explicit
and intentional (coinbase amount = block reward, public by design).
Don't add other exemptions.

---

## Layer 2 — Transaction privacy

### 2.1 Ring decoy selection — `src/wallet/send.rs::select_ring_decoys`

**What it does.** When the wallet spends, it picks `ring_size - 1`
decoys from the chain's UTXO history to mix with the real input. The
on-chain record can't distinguish real from decoy.

**Spec.** CoinCync V1 uses a log-gamma bootstrap profile with shape=19.28
and scale=1/1.61. `storage::UtxoSet::select_decoys` conditions samples on
the eligible canonical-chain age window and maps them to target block
heights. `crypto::RingSelector` only assembles the already-shaped pool
uniformly. This height mapping is not claimed to reproduce Monero's
cumulative-output-index picker or an empirical CoinCync spend-age fit.

**Constants.**

| Name | Value | Means |
| --- | --- | --- |
| `BOOTSTRAP_MIN_RING_SIZE` | 11 | Hard minimum — constitutional |
| `MID_RING_SIZE` | 13 | Intermediate during ring ramp (v1.0.12+) |
| `DEFAULT_RING_SIZE` | 16 | Mature chain target |
| `RING_SIZE_RAMP_TO_MID_HEIGHT` | 5_000 | When 11 → 13 |
| `RING_SIZE_RAMP_TO_FULL_HEIGHT` | 10_000 | When 13 → 16 |

The ramp exists because young chains don't have enough mature outputs
for ring 16; a hard 11 → 16 cutover would brick early txs.

**Maintenance rules — these are the rules people forget:**

1. **Decoys must be mature.** A coinbase output that is younger than
   `min_output_age_at_height(current_height)` cannot legally appear in
   a ring; the validator at `validation.rs:1186` rejects. The wallet
   must request decoys with a non-zero `min_age` filter
   (`bin/wallet.rs::send_command`, fixed in `7358775`). Failing this is
   exactly Crucible Finding #1.
2. **Dedupe by public key, not by index.** Multiple raw decoys can share
   the same stealth pubkey (e.g., old coinbase outputs from before
   address rotation); raw dedup leaves the real anonymity set far
   smaller than the ring size suggests. See `dedup_seen` at line ~260
   of `send.rs`.
3. **The minimum ring size on a mature chain is hard-coded to 11**
   ([Article III](../../CONSTITUTION.md)). The `effective_ring_size`
   adaptation only kicks in below `RING_SIZE_RAMP_TO_FULL_HEIGHT`. A
   wallet that requests ring=10 must be rejected by the validator.

### 2.2 Coinbase maturity

**What it does.** Coinbase outputs (block rewards) cannot be spent or
used as ring decoys until they age. Prevents:

- Selfish-mining-style attacks where a miner spends their own reward
  before the network has even seen the block
- Privacy degradation from a ring containing a "very fresh" coinbase
  (almost certainly the miner who mined the parent block — identifies
  the spender)

**Constants.**

```rust
pub const MIN_OUTPUT_AGE: u64 = 10;          // pre-fork
pub const MIN_OUTPUT_AGE_POST_FORK: u64 = 100; // post-fork
pub const MIN_OUTPUT_AGE_HARDFORK_HEIGHT: u64 = u64::MAX; // mainnet default
pub const MIN_OUTPUT_AGE_HARDFORK_HEIGHT: u64 = 0;        // testnet override
```

Note the dual definition — the cfg block in `constants.rs` selects one
or the other based on the `testnet` feature. The hardfork height is
`u64::MAX` on mainnet (not yet scheduled) and 0 on testnet (active from
genesis).

**Maintenance rule.** When you eventually schedule the mainnet
activation, **change ONLY** the mainnet `MIN_OUTPUT_AGE_HARDFORK_HEIGHT`
constant. Do not touch the function `min_output_age_at_height` — it's
already height-keyed correctly.

### 2.3 Uniform transaction shape

**What it does.** Every Transfer/Churn tx has exactly the same input
count and one of two output counts. The on-chain observer can't
fingerprint your wallet by tx shape.

**Constants.** `STANDARD_INPUT_COUNT = 2`, `STANDARD_OUTPUT_COUNT = 2`
(CYNC) or `+1` (asset). `UNIFORM_TX_SHAPE_HEIGHT = 0` —
**active from genesis**.

**Maintenance rules.**

1. The wallet must use `select_utxos_uniform` (not the older
   `select_utxos`) when `uniform` is true. Earlier today (Crucible
   Cycle 01) one of the wrappers nearly slipped through with the wrong
   path; the test fixture should pin this.
2. The validator at `validation.rs:1094-1124` enforces this on every
   block. Don't add a "skip this for special tx X" exemption — the only
   exemption is the dual shape (2-in/2-out for CYNC, 2-in/3-out for
   asset). Both are uniform within their own anonymity sets.

### 2.4 Encrypted memos + per-encryption nonce

**What it does.** Optional encrypted memo on the first recipient output,
recoverable by the recipient's view key. Plaintext capped at 256 bytes
(consensus rule).

**Maintenance rule.** **Every** memo encryption MUST use a fresh random
nonce. A nonce-reuse vulnerability was closed in `79b2625` (May 2026).
Don't reintroduce. The `RNG_NONCE_REUSE_PREVENTION` check in
`crypto::memo` is the test gate; if you change the construction, that
test must still pass.

### 2.5 Tx version gating

**What it does.** `tx.version == 0` is rejected unconditionally (FIX #39).
`tx.version > MAX_TX_VERSION` is rejected unconditionally. `tx.version
>= 2` is rejected if `current_height < V2_TX_ACTIVATION_HEIGHT = 50_000`.

**Maintenance rule.** This is the **forward-compat gate**. When v1.1
introduces a new tx version, bump `MAX_TX_VERSION` in lockstep with the
activation height. A node running pre-bump code will reject the new tx
version cleanly (a flag-day fork), which is the correct behavior.

---

## Layer 3 — Network privacy

### 3.1 Dandelion++ — `src/network/dandelion/`

**What it does.** Each locally-originated tx goes through a **stem
phase** (forwarded over a single random path) before the **fluff phase**
(global gossip). Defeats supernode IP-deanonymization attacks.

**Implementation.** Stem embargo timer in `bin/node.rs`; fluff fallback
when the embargo expires or no stem hop is available. Log lines look
like:

```
STEM: Local tx <hash> entering Dandelion++ (embargo in 55s)
FLUFF: No relay peer for tx <hash> — fail-safe broadcast
```

The "No relay peer" + "fail-safe broadcast" path triggers when there
are < 3 outbound peers (the privacy degradation threshold).

**Maintenance rules.**

1. The **stem embargo must be randomized per tx** (5-60s currently).
   Constant-time stems leak the originator via cross-correlation.
2. The 3-peer threshold is **privacy-critical**. A user running with
   `peer_count < 3` is told `Dandelion++ has only N outbound peer(s) —
   privacy degraded`. Don't suppress this warning.
3. Fluff phase must use the **same broadcast envelope** regardless of
   whether the tx was originally stemmed locally or received from a
   stem peer. Otherwise a network observer can distinguish your txs
   from forwarded ones.

### 3.2 Tor / SOCKS5 proxy — `bin/node.rs`, `src/network/socks_dns.rs`

**What it does.** All P2P + DNS seed lookups can be routed through a
SOCKS5 proxy (typically Tor at `127.0.0.1:9050`). DNS queries go via
**DNS-over-TCP through the proxy** (default resolver `1.1.1.1:53`); the
OS resolver never sees seed hostnames.

**Flags.**

- `--proxy HOST:PORT` — generic
- `--tor` — shortcut for `127.0.0.1:9050`
- `--onion-only` — refuse clearnet peers entirely; implies `--tor` if no
  proxy set

**Maintenance rule.** The DNS leak — using the OS resolver while the
peer connection is through Tor — is the canonical Tor-misuse failure
mode. **Never** add a "fast path" that bypasses
`resolve_seeds_with_proxy` when a proxy is configured.

### 3.3 Eclipse defense — `src/network/peer/`

**What it does.** Limits how many outbound connections can land in a
single `/16` IPv4 subnet (and `/64` IPv6). An attacker controlling one
subnet can't monopolize the node's view of the network.

**Visible in logs as:** `eclipse-defense: outbound_per_subnet ...`

**Maintenance rule.** The subnet keying is a **privacy and security
control**, not just a connectivity stat. If you change the bucketing
(e.g., relax to `/24`), an attacker who controls one cloud provider can
cheaply eclipse a node. Don't.

### 3.4 No-peers isolated mode — `--no-peers`

**What it does.** Disables auto-discovery (DNS seeds + hardcoded
fallbacks). Used for isolated 2-node testing.

**Maintenance rule — recent bug.** As of Crucible Finding #2 (this
week), `--no-peers` must still permit `--addnode` peers. The previous
code set `max_outbound = 0` which silently killed outbound dialing even
to manually-added peers. Fixed by capping at
`extra_peers.len().max(1)`. Don't undo this — it broke the only path
for cross-CGNAT testing.

---

## Layer 4 — Advanced shielded pools

These are the next-gen privacy primitives, partially live on testnet
and slated for full activation in later releases.

### 4.1 Spark accumulator — `src/spark/`

**What it does.** A Pedersen-style accumulator over output commitments.
Spends from Spark don't reveal which output was consumed (much stronger
than ring signatures: anonymity set = entire pool, not 11-16 decoys).

**Wire shape.** Spark txs have a separate output type carrying:

- An accumulator membership proof
- A serial number (linkability anchor, plays the role of key image)
- A range proof on the spent amount

**Implementation status.** Live on testnet. Node startup log shows
`Spark accumulator loaded (N coins)` — the pool is real, but the count
is low because Spark txs are wallet-opt-in and most users still use
ring CLSAG.

**Maintenance rule.** Spark accumulator state is **append-only**.
Removing an entry requires a full hard fork (the accumulator root is in
the block header). Don't add "prune old Spark entries" code without
that.

### 4.2 Mimblewimble kernels — `src/mw/`

**What it does.** MW outputs aggregate at block time (cut-through):
many txs in a block collapse to net inputs/outputs/kernels, dramatically
shrinking the on-chain footprint and providing perfect linkability
unlinking within a block.

**Visible in logs as:** `Kernel store loaded`.

**Implementation status.** Live but conservative; cut-through is run on
candidate blocks before validation, savings reported in
`cut_through_stats()`.

**Maintenance rule.** Kernel validation is **layered separately** from
CLSAG validation. Don't try to "unify the validators" — the math is
fundamentally different (MW kernels validate Schnorr signatures on the
excess; CLSAG validates ring signatures on inputs). The block validator
runs both; never short-circuit one based on the other passing.

### 4.3 Shielded tree (Zcash-Sapling-style)

**Implementation status.** Inert in v1.0.x — the tree exists in code
but `MANDATORY_CONFIDENTIAL` rules don't yet permit shielded-only txs.
Phase 2 activation lands in a future release.

**Maintenance rule.** Don't wire it into the active consensus path
without (a) a hard fork, (b) cryptographic review, (c) the
constitutional commentary update.

---

## Layer 5 — Operational privacy

### 5.1 Auto-churn — `src/wallet/churn.rs`

**What it does.** Background loop that does random self-sends at random
intervals (typically once per 6-72 hours per UTXO). Poisons transaction
graph analysis: by the time an external observer sees a "send" tx, the
ring almost certainly contains the wallet's own decoys.

**Wallet flag.** `auto-churn` subcommand.

**Maintenance rule.** Churn timing must be **random** and **per-utxo**,
not a fixed schedule. Deterministic timing is a fingerprint; the same
attack as constant-time Dandelion stems.

### 5.2 Dead-man's switch recovery — `src/wallet/recovery.rs`

**What it does.** A wallet can attach a recovery pubkey + timeout to a
tx. If the original key doesn't sign for N blocks, the recovery key can
sweep the output.

**Privacy consideration.** The recovery metadata is **public** in
`tx.extra`. This is a deliberate UX trade — it lets a recovery wallet
detect expiry without having to scan with the original view key. Users
opting in are aware their tx is tagged.

### 5.3 Mempool privacy policy — `src/consensus/privacy_policy.rs`

**What it does.** Catches "transparent" txs at mempool admission. Run on
*every* tx before crypto verification. Reject anything that:

- Has any output with `stealth_address == [0; 32]`
- Has any output with `commitment == [0; 32]`
- Has any input without a ring (ring size 0)

These are Category B checks per the C-8 audit fix: they run **always**,
they're cheap, and skipping them was a real vulnerability previously.

---

## The "two validators" rule

Today's Crucible Finding #1 surfaced a real version of this anti-pattern.
It deserves its own section because every privacy bug we've shipped has
some flavor of this.

### The anti-pattern

The system has multiple entry points for "is this tx valid?":

- `validate_transaction_basic(tx)` — universal shape checks
- `verify_crypto_for_admission(tx, h)` — crypto only
- `validate_transaction(tx, &utxos, h)` — **the** validator
- `validate_block(block)` — calls `validate_transaction` per-tx
- `shadow_evict_invalid` — calls `validate_transaction` per-tx in mempool

If anything except `validate_transaction` is used as the gatekeeper
for accepting state-changing operations (admission, broadcast), the
**other** code paths can find a defect the gatekeeper missed.

### How it goes wrong

The `mempool::add_with_chain` path was:

```rust
// pre-fix:
for ki in tx.key_images() {
    if chain.is_spent(&ki) { return Err(...); }
}
self.add(tx)  // → preflight (basic) + verify_crypto + admit
```

Three checks, none of which call the full validator. Coinbase maturity,
ring member existence, lock heights, V2 activation, uniform shape — all
silently skipped. `shadow_evict_invalid` later ran the full validator
and dropped them.

User experience: `OK: tx accepted by mempool` → ~60s later, balance
never changed, no error.

### The fix

```rust
// post-fix:
chain.validate_transaction(&tx)?;   // full validator
self.add(tx)
```

### The rule

**Any code path that admits a tx to mempool or includes it in a block
candidate MUST call `consensus::validate_transaction` with the current
chain state.** No exceptions. If you need a "fast-path" for performance,
the fast path validates the same predicate as the slow path; profile,
don't shortcut.

---

## Mandatory enforcement

These run on **every** non-coinbase tx, at **every** check site, with
no opt-out at any level:

| Rule | Site | Severity |
| --- | --- | --- |
| `ring_members.len() >= BOOTSTRAP_MIN_RING_SIZE` | `validate_transaction_basic:1739` | UNCONSTITUTIONAL — reject |
| `!range_proof.is_empty()` | `validate_transaction_basic:1748` | UNCONSTITUTIONAL — reject |
| `stealth_address != [0; 32]` | `privacy_policy::check_tx_privacy` | UNCONSTITUTIONAL — reject |
| `commitment != [0; 32]` | `privacy_policy::check_tx_privacy` | UNCONSTITUTIONAL — reject |
| `tx.version >= 1 && tx.version <= MAX_TX_VERSION` | `validate_transaction_basic:1694` | Future-fork safety — reject |
| Range proof verifies | `verify_output_range_proofs` | Inflation defense — reject |
| Balance proof verifies | `verify_balance_proof` | Inflation defense — reject |
| Every input's CLSAG verifies | `verify_ring_signature` | Forgery defense — reject |
| In-tx duplicate key images | `validate_transaction:1141` | DoS — reject |
| Cross-tx duplicate key images | `validate_transaction:1148` | Double-spend — reject |
| Ring members exist in UTXO | `validate_transaction:1160` | Forgery defense — reject |
| Coinbase maturity on every ring member | `validate_transaction:1186` | Privacy + selfish-mining defense |
| Uniform input/output count | `validate_transaction:1094` | Anonymity-set defense |

A maintainer modifying any of these needs a constitutional review.
There's a checklist in `docs/operations/INCIDENT_RUNBOOKS.md` for
"how to change consensus rules safely".

---

## Audit-time invariants

If you are preparing for an external audit (next one: post-v1.0.15
crypto review), these are the documented invariants the auditor will
check:

1. CLSAG aggregate coefficients match Goodell-Noether-Blue 2020
2. Range proof construction matches Bulletproofs+ spec (Chung et al.)
3. Stealth address derivation matches the Monero one-time-key scheme
4. Pedersen commitment generator `H` is a verifiable hash-to-curve, not
   an arbitrary point (otherwise H = k·G for unknown k is a trapdoor)
5. RNG sources for nonces are `OsRng`, never `thread_rng` (the latter is
   seeded from `OsRng` but is reused across threads — privacy signal)
6. Ring decoy selection passes the fixed-seed conditioned-distribution,
   minimum-age, sparse/locked, and reorg fixtures
7. The mempool ADD path and the SHADOW-EVICT path run identical
   validators (Invariant 1)
8. The wallet selection path enforces uniform shape when
   `current_height >= UNIFORM_TX_SHAPE_HEIGHT`
9. `MANDATORY_CONFIDENTIAL` + `MANDATORY_STEALTH` are `true` and not
   feature-gated
10. The critical-files lock file (`critical_files.lock`) covers every
    file an auditor would call "consensus-critical" and the build
    actually enforces it

If any of these can be silently changed by a single PR, the audit
report will flag it as a process gap.

---

## Common bug classes (with real examples)

### Bug class A — wallet builds invalid tx that node accepts and later rejects

**Example.** Crucible Finding #1 (this week): wallet picks decoys
including immature coinbase outputs. Mempool ADD accepts (no maturity
check at the crypto-only verification path). Block validation runs the
full check and rejects. shadow_evict drops the tx silently ~60s later.

**Defense pattern.** Wallet construction must mirror validator
constraints. The CI must include a fixture that exercises "build a tx
that would pass the wallet but fail the validator" and confirm both
paths reject identically.

### Bug class B — validator divergence

**Example.** Same Finding #1: `mempool::add_with_chain` ran a
key-image-only check; `mempool::shadow_evict_invalid` ran the full
validator. Their disagreement was the "silent eviction" failure mode.

**Defense pattern.** Any new validator entry point MUST call the
canonical one. Audit grep target:
`grep -rE 'fn (validate|check|verify)_' src/consensus/`. Any function
that *doesn't* terminate at `validate_transaction` and that is *called*
from a state-changing path needs justification.

### Bug class C — feature flag accidentally disables a privacy check

**Example.** `add_skip_crypto` (May 2026) used to be a `pub fn` without
a `#[cfg(test)]` gate. Confirmed via repo-wide grep that no production
code called it — but the absence of the gate meant a future caller
(human or LLM) could silently bypass ring-sig + range-proof + balance
verification.

**Defense pattern.** Test-only helpers MUST have:
`#[cfg(any(test, feature = "test-utilities"))]` AND `#[doc(hidden)]`.
The build profile (release without test-utilities) must not link them.

### Bug class D — "fast path" for performance accidentally weakens privacy

**Example.** The `revalidate_on_reorg` function was removed in
`2026-06-03` because it ran a key-image-only check, weaker than the
real reorg path (`restore_orphaned` + `shadow_evict_invalid`). A
future caller reaching for the name by accident would silently get
the weaker check.

**Defense pattern.** When two functions check similar predicates but
one is weaker, **delete the weaker one** if no production caller uses
it. Don't leave it as a footgun.

### Bug class E — timing side-channel leaks signer identity

**Example.** Wallet scan that does ECDH for every output (without view
tag pre-filter) takes O(N) work per block; a network observer measuring
the wallet's CPU during sync infers wallet activity.

**Defense pattern.** Privacy-critical paths must be **constant-time per
output**, or **scale identically regardless of wallet state**. The view
tag is the canonical mitigation; use it.

---

## Maintenance checklists

### Code review checklist (privacy-touching PRs)

Before approving any PR that touches `src/crypto/`, `src/wallet/send.rs`,
`src/wallet/scan.rs`, `src/mempool.rs`, `src/consensus/validation.rs`,
or `src/consensus/privacy_policy.rs`:

- [ ] No mandatory-privacy constant has been changed
- [ ] No critical-file hash has been updated **without** a justifying
      review comment
- [ ] Any new validation function ends in `validate_transaction`, not
      a shortcut
- [ ] Any new wallet builder calls `select_ring_decoys` with the
      current chain's `min_age`, not 0
- [ ] Any new RNG use is `OsRng`, not `thread_rng`
- [ ] Any new state-changing RPC route runs the full validator at
      admission
- [ ] No new wallet path uses `select_utxos` instead of
      `select_utxos_uniform` when `uniform` is active
- [ ] New tests cover the post-fix path AND the pre-fix-regression
      path

### Release-prep checklist (consensus changes)

Before tagging a release that includes consensus changes:

- [ ] Activation height set in the dedicated constant (NOT inline)
- [ ] Pre-activation behavior tested at h = activation - 1
- [ ] Post-activation behavior tested at h = activation + 1
- [ ] Old-binary-against-new-block rejection tested
      (consensus-break detection)
- [ ] Critical-files lock refreshed with explicit reviewer signoff
- [ ] Threat model document updated if the change touches an
      adversary that was previously covered
- [ ] Constitutional commentary updated if the change touches a
      mandatory-privacy rule

### Audit-prep checklist (every ~6 months / per audit cycle)

- [ ] All `unsafe` blocks reviewed
- [ ] Critical-files lock covers everything the auditor will call
      consensus-critical
- [ ] No `#[cfg(test)]` helper has leaked into the production-build
      symbol table (verified by `nm` on a release binary)
- [ ] All Crucible cycle findings since the last audit are documented
      under `docs/crucible/cycle-N/`
- [ ] All historical incident docs are linked from the audit handover
- [ ] `THREAT_MODEL.md` is up to date with the current network shape

---

## Cross-references

- [`CONSTITUTION.md`](../../CONSTITUTION.md) — the non-negotiables
- [`docs/BILL_OF_RIGHTS.md`](../BILL_OF_RIGHTS.md) — user-facing
  privacy guarantees
- [`docs/PRIVACY_FEATURES.md`](../PRIVACY_FEATURES.md) — onboarding
  map (status legend, where things live)
- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — adversary catalogue
- [`docs/CONSTITUTIONAL_COMMENTARY.md`](../CONSTITUTIONAL_COMMENTARY.md)
  — case-by-case constitutional analyses
- [`docs/operations/INCIDENT_RUNBOOKS.md`](../operations/INCIDENT_RUNBOOKS.md)
  — what to do when a privacy bug fires in prod
- [`docs/crucible/cycle-01/`](../crucible/cycle-01/) — most recent
  Crucible findings (Finding #1: silent mempool eviction; Finding #2:
  `--no-peers` kills `--addnode`)
- [`critical_files.lock`](../../critical_files.lock) — files where any
  change requires lockfile refresh + reviewer signoff
- [`rust-toolchain.toml`](../../rust-toolchain.toml) — pinned
  toolchain version + why (tari_bulletproofs_plus 0.4 SIMD
  compatibility)
