# WP-100 · Solved-Issues Ledger
### Every failure we found, and the assumption it died on

**Status:** Living document · **Layer:** All · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Most chains publish what they built. Far fewer publish what they broke, found,
and removed. That record is the more useful artifact: a feature list is a claim,
but a defect ledger is evidence — it shows the defenses were derived from real
failures rather than imagined ones.

This ledger follows one discipline: **never bank an attack without its
inversion.** Each entry states the failure, the assumption it depended on, and
the design change that deleted that assumption. Where a fix is a one-line guard,
we say so; where it changed a rule, we link the analysis.

Nothing here is theoretical. Every entry was either found by adversarial review
of our own code, surfaced by an external auditor, or caught by a live test on a
running chain.

---

## 2. How to read an entry

> **Failure** — what went wrong.
> **Assumption** — the belief the failure needed in order to be possible.
> **Removal** — the change that made the assumption false.
> **Receipts** — implementation, test, or live result.

Severity uses the audit convention: **CRITICAL** (inflation / consensus split /
fund loss), **HIGH** (halt, stall, or a defence gate bypassed), **MEDIUM**
(degradation, incorrect accounting, honest-peer harm), **LOW** (resource or
hygiene).

---

## 3. Consensus & validation

### 3.1 Unbound key image — silent double-spend (CRITICAL)
**Failure.** A transaction input carried a key image *and* its ring signature
carried a key image, but nothing required them to be equal. An attacker could
keep an honest, fully-valid signature and vary `input.key_image`, spending the
same output repeatedly under fresh images — undetectable inflation.
**Assumption.** That two copies of the same value in a signed structure are
necessarily the same value.
**Removal.** `verify_ring_signature` now rejects any input where
`input.key_image != signature.key_image`, checked *before* the ring-signature
cache is consulted (so a cached "valid" verdict can never be reused for a
different image). Enforced on both the mempool and block-validation paths.
**Receipts.** `src/consensus/validation.rs`; regression test
`real_crypto_unbound_key_image_rejected` exercises it through real `Mempool::add`
with genuine crypto; verified live on a running chain.

### 3.2 Proof-of-work silently skipped below checkpoints (HIGH)
**Failure.** The PoW gate had three arms: skip when fast-sync is *enabled*, warn
when fast-sync is *requested but unavailable*, else verify. In a normal
production build the middle arm was reachable for every block at
`height <= last_checkpoint` — it logged "full verification will run" and then
returned **without calling `verify_pow`**. PoW was not checked. An attacker could
mass-produce invalid-PoW fork blocks essentially free and have a node store them.
**Assumption.** That a branch which *reports* verification performs it — and that
"requested" and "enabled" are the same condition.
**Removal.** The skip is now gated solely on fast-sync actually being enabled;
the warning is informational and control always falls through to `verify_pow`.
**Receipts.** `src/consensus/validation.rs` (commit `5adc4072`, merged in #86).
Bounded, not a split: reorg-apply re-validates with `checkpoint_height = None`
and the finality floor rejects sub-checkpoint fork points — but a defence gate
must hold on its own.

### 3.3 Deep rollback skipped DB-only blocks (HIGH)
**Failure.** `rollback_to_height` — the deep-partition recovery path — read block
hashes and bodies only from the in-memory caches, which evict everything below
`tip-200`. A rollback reaching past that window silently skipped the UTXO,
supply, burn, cumulative-work, and phase-2 disconnect for every DB-only block
*while still moving the tip down*, leaving persisted supply and total work
over-counted.
**Assumption.** That the blocks being disconnected are always still cached —
in the one function whose entire purpose is going deeper than the cache.
**Removal.** The disconnect loop now resolves hash and body through a cache→DB
cascade (mirroring the tip update, which already had one) and fails loudly if a
body is missing from both, rather than under-disconnecting silently.
**Receipts.** `src/chain.rs` (commit `db9af263`); regression test
`rollback_to_height_disconnects_db_only_blocks_past_the_cache` stages
fee-carrying blocks in the DB only and asserts supply, burn, and work all
revert. Reported by external auditor **junbyjun1238**.

### 3.4 Reorg finality floor could be zero (HIGH)
**Failure.** The floor was computed as `tip - (tip % interval)`, making the
maximum reorg depth `tip % interval` — which is **zero** when the tip sits
exactly on a checkpoint boundary. A routine shallow reorg that happened to cross
a boundary was permanently rejected, stranding the node on a minority branch.
The rejection also returned `Invalid`, which banned the honest peer serving the
heavier chain.
**Assumption.** That a floor anchored to the last boundary always leaves a usable
reorg window.
**Removal.** The floor is `tip.saturating_sub(interval)` — always a full window —
and over-deep forks return `ReorgTooDeep` rather than `Invalid`, so the honest
peer is not punished for a policy outcome.
**Receipts.** `src/chain.rs` (merged in #56 → main `f16b2c9e`); 22 reorg tests.

### 3.5 Cumulative-work divergence — false "work behind" (CRITICAL, historical)
**Failure.** Nodes on an *identical tip* held different `total_difficulty`
because the value was path-dependent on each node's reorg history. Follower
miners then vetoed their own chain as "behind" and refused to mine.
**Assumption.** That accumulated work can be tracked incrementally without a
canonical definition independent of the path taken to the tip.
**Removal.** Total work is defined as a pure function of the chain: a uniform
genesis base of 1 across all three producers (extend, fork-walk, recompute), plus
a recompute-and-self-heal on load that reconverges a drifted stored value.
**Receipts.** `src/chain.rs`; independently re-verified during the 2026-09 base
audit as still correct.

### 3.6 Supply underflow silently clamped (CRITICAL-class, historical)
**Failure.** Disconnect paths used `saturating_sub` on total supply, so an
underflow — which can only mean corrupted state — was silently clamped to zero
and every downstream supply read became wrong.
**Assumption.** That clamping is a safe default for an arithmetic result that
should be impossible.
**Removal.** `checked_sub` with an explicit halt: the node panics with a
diagnostic rather than continuing on corrupt state, preserving the on-disk chain
for a clean restart. Applied uniformly at every connect/disconnect site.
**Receipts.** `src/chain.rs`.

### 3.7 Aggregate supply u64 overflow — chain halt (CRITICAL, historical)
**Failure.** Aggregate supply accumulated in `u64` and would overflow at roughly
height 407,828 (~18.4M CYNC), halting the chain.
**Assumption.** That a 64-bit accumulator is sufficient for a running total whose
per-block increments are themselves near-64-bit.
**Removal.** Widened to `u128` with a Borsh legacy migration and saturating RPC
surfaces. Not a hard fork: `supply_commitment` is a zero placeholder.
**Receipts.** External finding (**junbyjun1238**); embargoed fix branch.

---

## 4. Difficulty & emission

### 4.1 Startup overshoot and stall (HIGH)
**Failure.** A fresh chain whose initial difficulty was far below the miner's
real capability solved early blocks far under target; ASERT ramped difficulty
into a large overshoot and the chain stalled. Observed live: difficulty climbed
4,800 → 1,592,310 (~330×) and the node reported `stalled` with no block for
50+ minutes.
**Assumption.** That the difficulty controller alone can absorb an arbitrary
mismatch between genesis difficulty and actual launch hashrate.
**Removal.** Genesis calibration: initial difficulty is set to
`launch_hashrate × target_block_time`, so genesis-era blocks land near target and
there is nothing large to correct. **Notably, we did *not* retune ASERT** — an
offline simulator showed the obvious parameter fixes (tighter clamp, reweighted
or widened windows, median input) *fail to reduce overshoot and several
destabilise it*. The per-step clamp is a no-op here because it never binds during
a smooth ramp.
**Receipts.** `src/testnet.rs`, `src/mainnet.rs` (commit `e8a25882`);
[difficulty-oscillation-analysis §7](../design/difficulty-oscillation-analysis.md);
simulators `difficulty_sim.py`, `difficulty_sim2.py`.

### 4.2 Stale genesis timestamp defeats calibration (HIGH)
**Failure.** With calibration in place, difficulty *still* collapsed — to the
`MIN_DIFFICULTY` floor — for roughly the first long-window of blocks. Cause: the
genesis timestamp was 135 days older than the first mined block, and ASERT
anchors on genesis during that window, so the chain appeared catastrophically
slow.
**Assumption.** That a genesis timestamp is a label rather than an input to the
difficulty controller.
**Removal.** Genesis timestamp set to the chain's actual start.
**Receipts.** `src/testnet.rs` (commit `d32d7da2`); caught by live soak, not by
tests — the failure only appears on a chain whose genesis is genuinely old.

### 4.3 Residual dip: genesis as an ASERT anchor (HIGH)
**Failure.** Even with a fresh timestamp, *any* gap between genesis and first
block re-introduced the floor dip, because the genesis block remained a valid
window anchor. Calibration alone was fragile.
**Assumption.** That the genesis timestamp — a fixed constant, not a mining
observation — is a legitimate reference for measuring block production rate.
**Removal.** **Startup grace:** `get_anchor` advances past the genesis block
(height 0) to the first *mined* block, so every `time_error` is computed over
real inter-block timestamps and the genesis timestamp never feeds a retarget.
Deterministic (all nodes see identical heights), and it differs from prior
behaviour only while genesis is inside the window — mature difficulty is
unchanged.
**Receipts.** `src/consensus/difficulty.rs` (commit `25a73464`); simulator
`difficulty_sim3.py` scored three candidate graces — this one removes the dip for
genesis gaps from 2 minutes to 135 days with ~17-block convergence and beat
warmup-hold; test `startup_grace_ignores_a_stale_genesis_timestamp` (30-day-stale
genesis); confirmed live — difficulty held and climbed instead of collapsing.

### 4.4 Difficulty rule diverged between block and header validation (HIGH)
**Failure.** Header validation computed the expected target with plain ASERT
while the miner and block validator routed through the network-aware rule. On
regtest the two disagreed, every peer header was rejected with "difficulty target
mismatch", and nodes could not sync from each other at all.
**Assumption.** That a consensus rule implemented twice stays in agreement.
**Removal.** `Chain::expected_next_target` is now the single source of the
expected-target rule, used by the miner, block validation, fork validation, and
header validation alike.
**Receipts.** `src/chain.rs`, `src/network/node/dispatch/headers.rs` (commit
`102b0fb8`, merged in #86). **Found by live test, not review** — two nodes simply
would not sync.

---

## 5. Privacy

### 5.1 Genesis placeholder as a ring decoy — intermittent send failure (HIGH)
**Failure.** The genesis coinbase is a placeholder whose public key and
commitment are all-zero — the identity point. It lives in the canonical output
set like any other output, so the decoy sampler could draw it into a ring. The
CLSAG verifier correctly rejects identity ring members, so the transaction failed
with "ring signature verification failed" for that input — intermittently, and
*worst on a young chain* where the eligible decoy pool is small and genesis is a
large fraction of it.
**Assumption.** That every output in the canonical set is a usable ring member.
**Removal.** The decoy allocator excludes identity-point candidates, mirroring
the verifier's own guard, so such an output is never placed in a ring.
**Receipts.** `src/wallet/decoy_selection/allocation.rs` (commit `ca33e8d3`);
test `allocation_excludes_identity_point_decoys`; verified live — 20 consecutive
sends on a fresh small-pool chain with zero failures, where the bug previously
reproduced.
**Why it mattered.** This is a launch-window bug: it bites hardest in the first
weeks of a chain's life, exactly when early adopters are forming their opinion.

### 5.2 Spark proof leaks the real ring position (HIGH — contained)
**Failure.** In the dual-base Spark proof, the prover binds `real_index` into the
seed challenge and the verifier searches candidate positions until one matches —
so any observer with the public inputs can run the same search and de-anonymise
the real input.
**Assumption.** That a value bound into a challenge is hidden by the challenge.
**Removal.** *Not yet removed.* The construction must be replaced before the
feature can be activated. Contained today: the module is behind a non-default
feature flag with zero callers in any transaction path, so it is not reachable in
a production build.
**Receipts.** `src/crypto/lelantus_spark.rs`; gated at `src/crypto/mod.rs`.
Reported by **junbyjun1238**; verified and left disabled. **This is an open
item, stated plainly rather than buried.**

### 5.3 Light-sync could not see mining rewards (HIGH)
**Failure.** Coinbase outputs carry a plaintext amount, a zero-blinding
commitment, and a public-data view tag. The light-sync scanner applied the normal
path — view-tag gate, ECDH amount decrypt, commitment recompute — all of which
fail on a coinbase. A solo miner on light sync saw a zero reward balance.
**Assumption.** That every output is detectable by the same procedure.
**Removal.** Coinbase outputs are flagged in the block digest and detected via a
dedicated path (direct/ECDH ownership, plaintext amount, zero blinding),
mirroring the full scanner.
**Receipts.** `src/wallet/lightsync.rs` (merged in #85 → main `d51f18bb`); test
`scan_digest_detects_coinbase_plaintext_amount`. Reported by **junbyjun1238**.

### 5.4 Subaddress funds unspendable (CRITICAL — gated off)
**Failure.** Outputs sent to a subaddress can be *detected* but not *spent*: the
spend-side one-time-secret and key-image derivation omit the per-subaddress
offset. Funds received there would be permanently lost.
**Assumption.** That detection and spending derive the same key material.
**Removal.** *Not yet removed.* Subaddresses are disabled on mainnet by an
explicit launch gate; kept enabled on testnet/regtest so the fix can be developed
against a real receive→spend round-trip test.
**Receipts.** `src/bin/wallet_support/legacy.rs` (mainnet gate). **Open item.**

---

## 6. Network, sync & mining

### 6.1 Orphan reconnection was never wired (HIGH)
**Failure.** On receiving a block whose parent is unknown, the node stashed the
orphan body and requested the parent — but nothing ever replayed the orphan once
the parent connected. The forward drain existed only inside a function with no
production caller. The stashed block was also excluded from re-download, so
out-of-order and reorg delivery stalled until a 30-minute TTL released it.
**Assumption.** That storing a block for later replay is the same as replaying
it — the code comments asserted the drain ran; it did not.
**Removal.** `ChainSync::take_orphans_of(parent)` drains the direct orphan
children of a just-connected block, and a `notify_block_accepted` hook re-emits
each through the normal receive path, cascading to their own children.
**Receipts.** `src/network/sync.rs`, `src/network/node.rs`, `src/bin/node.rs`
(commit `1c8e353c`, merged in #86); sync suite 31/31 including
`catch_up_stall_side_block_delivers_orphan_descendant`.
**Lesson recorded.** A doc-comment describing a mechanism is not evidence the
mechanism runs. This one was described in detail — including its own bug-fix
history — while being inert.

### 6.2 Absolute reputation floor enabled eclipse (MEDIUM)
**Failure.** Peers above a fixed reputation threshold were exempt from eviction.
Since the default reputation *is* the maximum, a quiet inbound flood produced an
empty eviction candidate set, so every new honest inbound connection was
rejected — precisely the eclipse the function exists to prevent.
**Assumption.** That "well-behaved" can be measured absolutely rather than
relative to the current peer set.
**Removal.** Protection is now purely *relative* — per-axis top-N, as Bitcoin
Core does — so a uniform flood always yields an eviction candidate.
**Receipts.** `src/network/eviction.rs` (merged in #58 → main `74b19f3e`); test
renamed to assert the inverse: an all-high-reputation flood *must* remain
evictable.

### 6.3 Share replay — payout theft (HIGH, historical)
**Failure.** Stratum share deduplication was per-worker and keyed on
client-supplied job IDs, which the client could rotate to clear the set. The same
nonce could be credited repeatedly, or resubmitted across worker connections,
because extranonce fields are not part of the PoW.
**Assumption.** That client-supplied identifiers can key server-side
anti-replay state.
**Removal.** A single server-owned ledger keyed on the *server's* canonical job,
shared across all connections; stale client job IDs are rejected *before* the
ledger is touched; the ledger clears only on server job rotation.
**Receipts.** `src/mining/stratum.rs`. Follow-up (#35): the legacy path also
credited share *statistics* before the post-hash job re-check, so a job rotation
during hashing could credit a stale share — now downgraded to `Stale` before any
accounting (`downgrade_stale_share`, unit-tested).

### 6.4 Metrics endpoint: false-empty series and scrape DoS (MEDIUM)
**Failure.** A failed refresh left the previous values published (presence flags
were never cleared), so `/metrics` served stale data as if current; and the
listener performed a blocking read with no timeout on a serial handler, so one
client that connected and sent nothing stalled every later scrape.
**Assumption.** That a metric, once present, remains meaningful; and that a
scrape client will always speak.
**Removal.** Absent-publishers clear the presence flags on refresh failure so the
series is *omitted* rather than stale; read/write timeouts bound any single
client. (Contained: this is a non-default sidecar.)
**Receipts.** `src/bin/coincync-tick.rs`; test
`absent_publishers_clear_present_flags_so_stale_series_are_omitted`.

### 6.5 Historical sync and liveness defects
Recorded compactly; each was found live and fixed:

| Failure | Assumption removed |
|---|---|
| **Reorg self-deadlock** — commit guard held a write lock, then re-took a read lock; non-reentrant lock froze *every* reorg | That a lock held across a call is safe if the callee "only reads" |
| **Multi-peer IBD wedge** — block spans split across all peers ignoring peer height; a stuck same-height peer answered empty and wedged sync | That any connected peer can serve any block |
| **Orphan-fetch loop** — hashes-only orphan propagation forced gossip to re-deliver 200 block bodies it would never volunteer | That peers re-send bodies on request without prompting |
| **Framer cancel-safety** — a streaming read used a local buffer inside `select!`; cancellation dropped partial bytes | That a cancelled future leaves no partial state |
| **Message-type misread** — five sites bypassed the canonical encoder; the peer loop misread a payload byte as the message type and dropped peers mid-IBD | That parallel encoders stay consistent |
| **`is_synced` height heuristic** — a height-based sync test let an isolated miner pass its own mine-gate and build a runaway low-work fork | That height is a proxy for chain agreement |

---

## 7. Process defects (the ones that cause the others)

**Consensus files edited without ceremony.** Consensus-critical files are
hash-locked by a build gate: any edit fails the build until the lock is
deliberately regenerated. This turns "I changed a consensus rule" from an
invisible diff into a required, reviewable step. See WP-007.

**Findings verified before they are fixed.** Automated review of this codebase
produced roughly a 50% false-positive rate on file/line specifics. Every finding
in this ledger was re-read against the actual code before any change was made —
and several plausible-sounding reports were dismissed on inspection, including a
decoy-sampling "bug" that did not exist and a congestion mismatch that was not
present. Fixing an imaginary bug in consensus code is itself a defect.

**Tests must fail before they pass.** Each regression test above was reasoned
through against the pre-fix code to confirm it would have caught the bug.

**The live chain finds what review does not.** Two entries here — the stale
genesis timestamp (§4.2) and the difficulty rule divergence (§4.4) — were
invisible to unit tests and code review, and appeared within minutes of running
real nodes. Adversarial live testing is not a formality.

---

## 8. Known limits of this ledger

- It records what we **found**. It is not a claim that nothing remains.
- Two entries (§5.2 Spark, §5.4 subaddress spend) are **open**, contained by
  feature gates rather than fixed. They are listed because a ledger that omits
  live problems is marketing.
- Cryptographic soundness of the primitives is inherited, not asserted by us; an
  external cryptographic audit remains a launch requirement.
- Several fixes are recent. Recency is not maturity.

---

## 9. References

- Eyal & Sirer, *Majority is not Enough: Bitcoin Mining is Vulnerable* (2013)
- Heilman et al., *Eclipse Attacks on Bitcoin's Peer-to-Peer Network* (2015)
- Bojja Venkatakrishnan et al., *Dandelion++* (2018)
- Möser et al., *An Empirical Analysis of Traceability in the Monero Blockchain* (2018)
- CryptoNote key-image flaw; Zcash counterfeiting disclosure (2019)
- Ethereum Classic 51% attack post-mortems (2019–2020)
- Internal: [difficulty-oscillation-analysis](../design/difficulty-oscillation-analysis.md),
  [reorg-defense](../security/reorg-defense.md)
