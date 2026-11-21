# Bobtail Multi-Sample PoW — Specification (draft)

**Status:** draft spec, derived from `bobtail-multisample-pow.md` (the analysis
and the Phase-A/B/C results it cites). This is a **consensus hard fork**: it
changes block validity and the block format, so it activates at a single
coordinated height, feeds the consensus fingerprint, and ships **post-audit**.
It is implemented as an **additive, height-gated module running Observe→Enforce**;
the hash-locked RandomX core (`src/consensus/pow.rs`) is **not edited**. This
draft is to be refined and audited, not implemented as-is.

Prereqs settled in the analysis: conversion constant (§10.1), reward split
(§11), security/finality (§12), gossip bound (§13) of the analysis doc.

## 1. Parameters

| name | value | notes |
|------|-------|-------|
| `K` | **20** (95%-in-band knee) | samples/block; block-time CV ≈ 0.26, ~95% of blocks in 60–180 s |
| `C_SHARE` | 3 | share safety factor → E[shares]/block = 3K = 60 |
| `tau = T·(K+1)/2` | derived | k-mean block threshold from the ASERT target `T` |
| `tau_share = 3·K·T` | derived (≈5.7× `tau`) | gossip threshold; couples to the retarget, no separate knob |

`K` was finalized by full cost accounting (`scratchpad/finalize_k.py`): smoothness
vs gossip, shielded-coinbase chain growth, and proving. The shielded-coinbase
output count *saturates* (~6–7/block even at k=32, since one large miner holds
several of the K slots), so chain growth is sublinear in K and modest (~1.4 GB/yr
at K=20; ~4.7 KB gossip/block; ~39 ms proving). Gains flatten past K=20, so 20 is
the knee. K=16 (CV 0.28, ~90% in-band) is a lighter power-of-two alternative.
| `BOBTAIL_ACTIVATION_HEIGHT` | TBD | flag-day; `u64::MAX` until scheduled |
| `BOBTAIL_OBSERVE_HEIGHT` | TBD < activation | start computing (not enforcing) |

`K`, `C_SHARE`, and the activation heights are genesis/fork parameters, fixed
once per network. RandomX, `TARGET_BLOCK_TIME = 120`, and the dual-anchor ASERT
retarget are unchanged.

## 2. Hash function — unchanged

RandomX stays the PoW hash, byte-identical. A **sample** is one RandomX output:
```
h_i = RandomX( prev_hash || miner_pubkey || nonce_i )
```
A miner grinds `nonce_i` exactly as today; the only change is that it reports its
low samples rather than stopping at the first below a single target. The input
binds `prev_hash` (so samples are tied to one parent) and `miner_pubkey` (so a
sample is non-transferable — it names its owner, who will be paid).

## 3. Proof-share (gossip unit)

```
ShareProof {
  miner_pubkey : [u8; 32]   // owner (and reward recipient commitment)
  nonce        : u64
}                            // h = RandomX(prev_hash || miner_pubkey || nonce), recomputed by verifiers
```
A node gossips a ShareProof when `h < tau_share`. Verifiers recompute `h`;
invalid or duplicate shares are dropped. `prev_hash` is implicit (the current
tip); shares for a stale parent are discarded. Wire cost: ~`C_SHARE`·K shares per
block (§13), ~2–5 KB/block, hashrate-independent, flood-deduped. Per-peer rate
cap reuses the existing mesh limiter; spam is work-bounded (every share is a
RandomX solution below `tau_share`).

## 4. Block format

The block header's single `nonce` is replaced by an ordered set of `K` shares
plus the proposer's body binding. Everything else in the header
(`prev_hash`, `tx_root`, `timestamp`, `target`, `algorithm`) is unchanged.

```
BobtailHeader {
  prev_hash, tx_root, timestamp, target, algorithm   // as today
  shares : [ShareProof; K]   // the K lowest, ascending by h
}
```
- `shares[0]` is the **minimum** → its `miner_pubkey` is the **proposer**, who
  chose `tx_root` (the block body).
- The block hash commits to the full header including all `K` shares, so the set
  is non-malleable once published.

## 5. Block validity (consensus)

A block is valid iff all hold:
1. each `shares[i]` recomputes to `h_i = RandomX(prev_hash || miner_pubkey_i || nonce_i)`;
2. the `(miner_pubkey_i, nonce_i)` are **distinct** (no sample reused);
3. `shares` are sorted ascending by `h_i`;
4. **`mean(h_0 … h_{K-1}) ≤ tau`**, where `tau = T·(K+1)/2` and `T` is the ASERT
   target for this height (§7);
5. **canonical set (anti-grinding):** the `K` shares are the `K` *lowest* in the
   validator's gossiped share pool for this parent — a block is rejected if the
   validator holds a gossiped share with `h < h_{K-1}` that was not included.
   Partial-view tolerance: a share counts against this rule only if it was
   gossiped before the block's `timestamp` minus a small grace (impl item §13.3);
6. the body (`tx_root`) is valid under all existing rules, coinbase obeys §8;
7. `timestamp` obeys the existing strictly-increasing / median-time rules.

Rules 4 **and 5** are the new conditions, and rule 5 is **load-bearing** (§6):
without it the proposer's freedom to pick *which* `K` shares to include lets a
10 %-hashrate proposer steer the single-output lottery to itself ~83 % of the time
*and* pad its own slots under the equal split. Rule 5 forces the set, nulling both.

## 6. Proposer selection & grinding resistance

The proposer is fixed as `shares[0]`'s owner — the single global minimum, which
is uniform over hashers (so proposal rate = hashrate share; §10.2). Because
`shares[0]` is the minimum of real RandomX work, a proposer cannot cheaply
re-grind to replace it. The tx-set binding (`tx_root`) is chosen by the proposer
only; other share owners contribute PoW tickets over `prev_hash` and need never
see the tx set, so shares found before the body existed still bind correctly.

### 6.1 The grinding vector: set selection

The attack is **not** on the proposer slot (that is one global minimum — re-mining
it costs a full block). It is on **which `K` shares fill the block**. The k-mean
bar `mean ≤ tau` does *not* pin a unique set: because the mean divides by `K`,
swapping the largest included share for a slightly higher collected one barely
moves the mean, so many valid sets coexist. `scratchpad/grinding_sim.py` measures
this directly (K=20, `E[shares]=3K`, normalized `tau_share=1`):

- the `K`-lowest mean sits ≈ at `tau` (the bar is tight), **yet** multiple valid
  sets are reachable by single swaps in ~52 % of blocks — the freedom is real,
  not marginal;
- a proposer can pick the set, and *each distinct set is a distinct outcome* for
  any set-dependent reward rule. Modelled against the fallback lottery
  `idx = H(shares) mod K`, a proposer with **10 %** of hashrate steers the winner
  to one of its own slots **~83 %** of the time (vs its fair 10 %); at 30 % it is
  near-certain. (The sim's own closing comment — "almost no slack to grind" — is
  **wrong**; the measured freedom disproves it. Recorded here so the error is not
  silently inherited.)

Crucially this is **not** lottery-specific. The same set freedom breaks the
**equal split** too: the proposer selects the valid set that contains the most of
*its own* shares, padding its `reward/K` slot count above its fair share. Any
reward rule that reads the chosen set is grindable by set selection.

### 6.2 The fix: canonical `K`-lowest set (validity rule §5.5)

The cure removes the freedom at its root: a block's `K` shares **must be the
globally `K`-lowest** in the gossiped share pool, not merely *some* `K` with
`mean ≤ tau`. A validator rejects a block that omits a share it holds which is
**canonically lower** than the block's greatest included share (§5.5). "Lower"
is the full canonical total order — hash, then owner pubkey, then nonce — *not*
hash alone: two shares that tie on hash still have a strict deterministic order,
so a proposer cannot swap between equal-hash shares to steer the proposer slot or
lottery winner. (A hash-only `h < h_{K-1}` check would leave exactly that gap.)
With the set forced:

- **equal split:** the proposer cannot swap in extra own-shares — the set is not
  its to choose — so its slot count is exactly what it legitimately mined. Fair.
- **lottery fallback:** `idx = H(shares) mod K` is now a function of a fixed set,
  so it is fixed. The proposer cannot resample it without changing the set, which
  the rule forbids. Fair (`win-prob = fair`, `d = 0` in the sim).

### 6.3 Residual vectors, all EV-negative

1. **Own-share withholding.** A miner can decline to gossip one of its own low
   shares so the canonical set legitimately excludes it. But a withheld share is a
   *forfeited* reward slot (and, if it was the minimum, a forfeited proposal). It
   buys no new set — only a worse one — so it is strictly EV-losing (consistent
   with the no-advantage withholding result, §10.2). It cannot be used to *add*
   own-slots (that needs omitting *others'* lower shares, which §5.5 catches).
2. **Re-mining the set.** To legitimately change the canonical set the attacker
   must produce a *new* share below the current `h_{K-1}` — i.e. do fresh
   sub-`tau_share` RandomX work — for at most a one-slot shift and a `1/K` lottery
   re-roll. That is full share-work spent to chase a fractional reward: dominated
   by spending the same work mining honestly.
3. **Partial-view races.** Two validators may hold different pools near the
   `K`-th share at block time. This is the only non-trivial residual and is an
   **implementation** question, not a design hole: resolved by a gossip-inclusion
   deadline / small grace window (a share counts against §5.5 only if gossiped
   before `timestamp − grace`), tuned in the Observe phase (§13.3). It bounds
   disagreement, it does not reopen steering — the attacker still cannot *choose*
   a non-canonical set, only exploit timing at the single boundary slot.

**Conclusion.** Under §5.5 both reward mechanisms are grind-proof: set selection
is eliminated (`d = 0`), and every residual costs more work than it returns.
Without §5.5 the design is grindable (10 % → 83 % lottery capture; equal-split
slot-padding), which is why §5.5 is a validity rule, not an optimization.

## 7. Difficulty retarget — reuse ASERT unchanged

`src/consensus/difficulty.rs` computes `T` exactly as today (dual-anchor ASERT,
same windows/weights/clamp — the ASERT-parameter question is settled, see the
oscillation analysis). The acceptance rule applies `tau = T·(K+1)/2` to the
k-mean. This preserves expected hashes/block (hence difficulty and the 51 % bound)
— validated in §10.1. `tau_share` is derived from `T` so E[shares] = `C_SHARE`·K.

## 8. Reward / coinbase rule

Per §11: the block reward (unchanged emission total) is split **equally across
the K share owners**, paid as **shielded coinbase outputs into the Spark pool**.

**Amounts are PUBLIC, not hidden** (corrects §13.2's earlier framing). Hiding
coinbase amounts would make total issuance unauditable and break the "no hidden
inflation" guarantee (`chain supply`/`chain emission`). So each output commits to
the *rule-determined* amount `reward/K · count_i`, which anyone can compute. The
privacy is elsewhere: each output goes to a one-time **stealth address**
(unlinkable to the miner) and joins the **Spark pool**, so *who* was paid is
hidden and the *later spend* is pool-private. Who/when private; how-much public —
which is the correct posture for coinbase.

**Verification** (cheap; uses the Pedersen commitments Spark already has, which
are additively homomorphic):
1. the coinbase has the right output count, each to a declared stealth key;
2. each output's commitment `C_i` opens to the public amount `reward/K · count_i`;
3. `Σ C_i = reward·G + R·H` — sums to exactly the block reward, emission-neutral,
   checkable homomorphically (no inflation);
4. each output is a well-formed Spark coin.

**Output grouping** — a sub-choice: **dedup** (one output per distinct owner,
`reward/K · count_i`; ~6–7 outputs, ~1.4 GB/yr, but an output's amount leaks that
owner's slot-count as *unlinkable* metadata) vs **uniform** (K separate `reward/K`
outputs, all identical, zero metadata, ~4 GB/yr). Recommend **dedup** (the
metadata is tiny and tied to an unlinkable stealth key); uniform is the
maximal-privacy option. **Fallback** (if chain size binds): a single shielded
output to the grinding-resistant lottery winner `idx = H(shares) mod K`. All in
this module; emission policy untouched.

## 9. Fork choice

Cumulative work is unchanged in form: a Bobtail block contributes the difficulty
it cleared (`work(T)` for its `tau`), and chain selection remains
most-cumulative-work. No change to reorg depth, checkpoints, or finality
machinery beyond the (improved, §12.2) time-to-finality distribution.

## 10. Rollout — Observe → Enforce

1. **Observe** (`BOBTAIL_OBSERVE_HEIGHT …`): every node computes the share pool,
   the k-mean, and what a Bobtail block *would* be, and exposes it via a
   read-only diagnostic (`CYNC-POW-00x`), but blocks are still validated by the
   single-hash rule. This runs the new path in shadow on the live chain with zero
   consensus risk — the fuse-box posture.
2. **Arm review**: confirm Observe parity (the shadow k-mean tracks the retarget,
   shares propagate, no divergence) across the fleet + community nodes.
3. **Enforce** (`BOBTAIL_ACTIVATION_HEIGHT`): one reviewed switch flips validity
   to rule §5.4. Fingerprint changes here (intended). Coordinated flag-day, like
   the h29000 shielded activation; testnet first, then mainnet post-audit.

## 11. Module layout (no core edits)

- `src/consensus/pow.rs` — **unchanged** (RandomX).
- `src/consensus/difficulty.rs` — **unchanged** (`T` via ASERT).
- new `src/consensus/bobtail/` — share verification, k-mean acceptance, block
  format, proposer/tx binding, coinbase-split check, Observe gauge; all behind
  the activation-height gate.
- `src/network/` — proof-share gossip message + relay (additive; CAP bit so pre-
  activation peers are unaffected, like the addrv2 cap).
- `critical_files.lock` — regenerated for the new module; `pow.rs` line unchanged.

## 12. Security (reference)

- Honest-majority 51 % bound: preserved (§10.1, exact match to Nakamoto).
- Selfish mining / d-conf double-spend: variance-independent → unchanged (§12.1).
- Time-based finality: improved; `P(<3 confs in 12 min)` 6.3 % → 0 % (§12.2).
- Share withholding: no proposer advantage (§10.2). Share spam: work-bounded (§13).

## 12a. Share-informed hashrate (smoothness prototype)

Shares arrive ~`C_SHARE·K` (≈60×) more often than blocks, so the share stream is a
~60× denser hashrate signal. `consensus::bobtail::hashrate` (Observe-only, gated)
estimates hashrate from shares — `Σ work(tau_share) / elapsed`, the standard
"shares × share-difficulty / time" estimator — with ~60× more samples, so its
noise (std ∝ 1/√N) is ~√60 ≈ 7.7× lower and it reacts ~60× faster than a
block-interval estimate. The Observe share handler records each admitted batch
into a sliding window (`ShareHashrate`) and logs the estimate. This **measures**
the signal with real data now; feeding it into the ASERT retarget for a smoother,
lower-lag difficulty is a gated, post-audit step (it would touch `difficulty.rs`,
so it stays a connector/measurement until then). `consensus::bobtail::shadow`
turns the estimate into a **shadow difficulty** (`hashrate · TARGET_BLOCK_TIME`)
and compares it side by side with the live ASERT difficulty (`DifficultyShadow`:
ratio + the `√N` noise advantage); the Observe handler logs the comparison each
tick. A Monte-Carlo demo (`tests/bobtail_observe_e2e.rs`) confirms the share-based
estimate's CV is ~√60 ≈ 7.7× tighter than a block-interval one. Pure + unit-tested.

The retarget **rule** is also fully built, as a connector + gated policy-slot
(`consensus::bobtail::retarget`): `retarget_blend` weighted-averages the ASERT
target with the share-informed shadow target in the 256-bit domain, and
`effective_next_target(height, asert, hashrate)` is the slot the validator would
consult — returning the ASERT target **unchanged** until `bobtail_enforce_active_at`
(blend held at `0/4` while gated), so wiring it into a call site is byte-identical.
This keeps the hash-locked `difficulty.rs` / `validation.rs` untouched. The **one
remaining change** to make the retarget live is the locked-core call site adopting
this slot — a single coordinated post-audit fork edit (review + lock regen +
fingerprint change), exactly like the Enforce height (§10). It is deliberately a
gate, not a loose end: everything up to it (the rule, the shadow comparison, the
telemetry) is wired and tested; only the locked validator's adoption is deferred.

## 13. Open before implementation

1. ~~`tau_share` calibration~~ — **done**: `tau_share = 3·K·T` (≈5.7× `tau`),
   couples to the retarget; derived in §1.
2. Shielded-coinbase mechanics — **design settled (§8)**: amounts PUBLIC
   (emission-auditable), recipients shielded stealth into the Spark pool,
   split verified by the homomorphic commitment sum = reward; dedup grouping
   (~6–7 outputs, ~1.4 GB/yr). *Remaining:* measure real proving cost on the
   Spark FFI (needs a build) and confirm the commitment-sum check against the
   live `sketch-gk-proof + libspark-ffi` path.
3. ~~Grinding-resistance proof for the lottery fallback’s `H(shares) mod K`~~ —
   **done (§6)**: set selection, not slot selection, is the vector, and it breaks
   *both* the lottery and the equal split (sim: 10 % hashrate → ~83 % lottery
   capture). Nulled by the **canonical `K`-lowest** validity rule (§5.5, `d=0`);
   residuals (own-share withholding, re-mining) are EV-negative. *Remaining impl
   item:* the partial-view gossip-inclusion deadline / grace window (§6.3.3),
   to be tuned empirically in the Observe phase.
4. ~~`K` final value~~ — **done**: K=20 (the 95%-in-band knee), by full cost
   accounting; K=16 is the lighter power-of-two alternative.
5. Full Phase-C selfish-mining write-up beyond the depth/finality split (done)
   — model any mempool-level share games.
6. Reference implementation — **in progress** (`src/consensus/bobtail/`, Cargo
   feature `bobtail`, off by default; production builds byte-identical with it
   off, no hash-locked file touched). *Slice 1 (done):* the pure consensus math —
   the work-preserving k-mean bar (`kmean::k_mean_meets_target`, exact 512-bit
   integer form `2·Σh ≤ T·K·(K+1)`), the canonical K-lowest set + the §5.5/§6
   anti-grinding predicate (`shares::canonical_k_lowest` / `omits_lower_share`),
   the emission-exact equal split and the set-bound lottery (`shares::equal_split`
   / `lottery_index`), a composite validity predicate (`block_shares_valid`), the
   pool-flood bound (`retain_lowest` / `max_pool_size`, keep only the lowest
   `4·C_SHARE·K`), the read-only `observe()` gauge, and the detection-only Observe
   telemetry (`health::BobtailHealth` — distinct owners, slot concentration,
   bar-fill margin — plus `view_divergence`, the partial-view split early-warning
   that counts a block's canonically-lower omitted shares and its shares unseen
   locally) — all unit-tested. The omission check compares over the full canonical
   total order (hash, pubkey, nonce), closing the equal-hash swap. The proof-share
   gossip pool is built too (`gossip::SharePool`): parent-bound, with admission
   control (verify PoW `< tau_share` — `kmean::tau_share_target` — before relay),
   dedup, wrong-parent drop, flood cap, and tip-change clearing, plus the
   `ProofShareBatch` wire type and the `CAP_BOBTAIL_SHARES` Flare bit. The
   **inbound dispatch is wired** too (all gated, Observe-only, no hash-locked file
   touched): a `cfg`-gated `MessageType::ProofShares = 53` (+ `TryFrom` / `max_size`
   arms — a non-`bobtail` build rejects discriminant 53 as unknown), the
   `CAP_BOBTAIL_SHARES` bit OR'd into `firework::local_capabilities`, a
   `Message::proof_shares` constructor, and a `dispatch::bobtail_shares` handler
   that decodes a batch, admits it into a process-local tip-bound `SharePool`
   (fail-closed until `BOBTAIL_OBSERVE_HEIGHT`), and floods the admitted shares to
   the other peers. The share hash uses the existing public `compute_pow_hash`
   (interim §2 definition; touches no hash-locked file). The **miner send-side is
   wired** too (gated): `bobtail::collect_shares` grinds a bounded nonce budget for
   the node's pubkey against the tip and returns the samples below `tau_share`;
   the node mining task (`src/bin/node.rs`) runs this each round when Observe is
   active and gossips them via a new `broadcast_proof_shares` on the p2p handle.
   A share is its own grind (`RandomX(prev‖pubkey‖nonce)`), not a block-PoW
   byproduct, since the share hash is `tx_root`-independent. The **`CYNC-POW` diagnostics bus
   is wired** too: catalog entries `CYNC-POW-004` (slot concentration) and
   `CYNC-POW-005` (partial-view divergence), a `bobtail::diagnostics` module that
   turns `observe()` / `view_divergence` into catalog-backed `Report`s on
   threshold crossings, and a throttled (once/min) concentration emission from the
   Observe share handler. *Remaining:* the domain-separated share preimage
   (replaces the interim hash at the Enforce fork) and the `view_divergence`
   emission at Enforce (needs a block carrying a share set), then the adversarial
   testnet soak, before any Enforce height is chosen.
