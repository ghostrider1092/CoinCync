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
5. the body (`tx_root` and its transactions) is valid under all existing rules,
   and the coinbase obeys §8;
6. `timestamp` obeys the existing strictly-increasing / median-time rules.

Rule 4 is the *only* new PoW condition. Rules 1–3 bind the samples; 5–6 are
unchanged. No node may accept a block failing rule 4 at or after activation.

## 6. Proposer selection & grinding resistance

The proposer is fixed as `shares[0]`'s owner — the single global minimum, which
is uniform over hashers (so proposal rate = hashrate share; §10.2). Because
`shares[0]` is the minimum of real RandomX work, a proposer cannot cheaply
re-grind to replace it. The tx-set binding (`tx_root`) is chosen by the proposer
only; other share owners contribute PoW tickets over `prev_hash` and need never
see the tx set, so shares found before the body existed still bind correctly.

## 7. Difficulty retarget — reuse ASERT unchanged

`src/consensus/difficulty.rs` computes `T` exactly as today (dual-anchor ASERT,
same windows/weights/clamp — the ASERT-parameter question is settled, see the
oscillation analysis). The acceptance rule applies `tau = T·(K+1)/2` to the
k-mean. This preserves expected hashes/block (hence difficulty and the 51 % bound)
— validated in §10.1. `tau_share` is derived from `T` so E[shares] = `C_SHARE`·K.

## 8. Reward / coinbase rule

Per §11: the block reward (unchanged emission total) is split **equally across
the K share owners**, paid as **shielded coinbase outputs into the Spark pool**
(one per owner, deduplicated so an owner holding several of the K gets one output
for the sum). Shielded payouts leak no miner linkage and grow the anonymity set.
The coinbase must mint exactly `reward/K · (count_i)` to each distinct owner;
validators check the split against the K shares. **Fallback** (if chain size
binds): a single shielded output to the grinding-resistant lottery winner
`idx = H(shares) mod K`. Both live in this module; emission policy is untouched.

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

## 13. Open before implementation

1. ~~`tau_share` calibration~~ — **done**: `tau_share = 3·K·T` (≈5.7× `tau`),
   couples to the retarget; derived in §1.
2. Shielded-coinbase mechanics: ~6–7 small shielded mints per block on the Spark
   path (count saturates sublinearly in K). Chain growth ~1.4 GB/yr, proving
   ~39 ms/block with the batched GK prover (first-order estimates from
   `finalize_k.py`) — still to confirm the split is verifiable without revealing
   amounts, and to measure real proving on the Spark FFI.
3. Grinding-resistance proof for the lottery fallback’s `H(shares) mod K`.
4. ~~`K` final value~~ — **done**: K=20 (the 95%-in-band knee), by full cost
   accounting; K=16 is the lighter power-of-two alternative.
5. Full Phase-C selfish-mining write-up beyond the depth/finality split (done)
   — model any mempool-level share games.
6. Reference implementation in the Observe module, then the adversarial testnet
   soak, before any Enforce height is chosen.
