# Mempool relay policy review — 2026-05-25

> **Scope.** Focused one-pass review of `src/mempool.rs` admission +
> eviction policy ahead of the audit-firm engagement. Question being
> asked: *"What does our mempool accept that production mempools
> (Bitcoin Core, monerod) wouldn't?"* and the inverse: *"What
> production-grade defenses are we missing?"*
>
> **Outcome.** No v1.0.10 blockers. One real gap (per-peer bad-tx
> scoring) flagged for v1.0.11. Several intentional deviations from
> Bitcoin's model that are correct for a privacy chain — documented
> here so the audit firm sees the reasoning instead of having to ask.

---

## Defenses in place (verified against `src/mempool.rs` HEAD)

| Layer | Check | Location |
|---|---|---|
| 1 | Coinbase rejection from mempool | `preflight_check` line 421-426 |
| 2 | Structural validation (`validate_transaction_basic`) | line 429 |
| 3 | Privacy policy check (zero stealth/commitment reject) | line 437 |
| 4 | Range-proof verification (Bulletproofs+) | `verify_crypto_for_admission` line 451 |
| 5 | Balance proof verification | line 456 |
| 6 | CLSAG ring-signature verification per input | line 461-466 |
| 7 | Tx size cap (`MAX_TX_SIZE`) | line 477 |
| 8 | Dynamic fee escalation by mempool fullness (1× / 2× / 4× / 8×) | line 482-498 |
| 9 | Double-spend detection (mempool key-image set) | line 504-510 |
| 10 | RBF with 25% fee bump + cross-multiply (no rounding bypass) | line 517-525 |
| 11 | Bounded eviction loop (`MAX_EVICTION_ATTEMPTS = 100`) | line 549-562 |
| 12 | `MempoolFull` rejection when eviction can't free space | line 558-560 |
| 13 | Lowest-fee-per-byte eviction via `by_fee` BTreeMap | `evict_lowest_fee` line 923-932 |
| 14 | TTL expiry (288 blocks ≈ 9.6h at 120s blocks) on every `set_height` | `expire_old_transactions` line 271-301 |
| 15 | Audit log for every Added / Rejected / Removed event | `audit()` line 304+ |
| 16 | Shadow-evict on chain advance (v1.0.11 added 2026-05-25) | `shadow_evict_invalid` |

That's a Bitcoin-Core-grade admission funnel for the consensus
relevant rules. Crypto-verify-before-admit is actually STRONGER than
Bitcoin Core, which defers signature verify to block-validation-time
to keep relay cheap. CoinCync front-loads it because the privacy
crypto (CLSAG + bulletproofs) is more expensive per tx, and we'd
rather burn CPU on admission than have the miner template repeatedly
include + reject the same poison tx.

---

## Intentional deviations from Bitcoin's mempool model

These are choices, not gaps. The audit firm will likely ask about
each — pre-staged rationale below.

### 1. No mempool persistence across restarts

**Bitcoin Core:** saves mempool to `mempool.dat` on shutdown,
reloads on startup so unmined txs survive a node restart.

**CoinCync:** intentionally does not. Reasons:

- **Privacy implication.** A persisted mempool is a forensic
  artifact. If a node is seized or the disk is imaged, the
  attacker recovers transactions that were never mined — possibly
  exposing tx-graph relationships that the privacy crypto was
  supposed to hide. A clean-on-restart mempool denies that
  forensic surface.
- **Churn cost.** Privacy txs are mostly individual end-user
  spends, not the long-chain RBF-bidding pattern Bitcoin sees.
  Losing the mempool on restart costs each user one re-broadcast,
  not a multi-hop ancestor chain.
- **Restart-as-DoS-mitigation.** If a flood attack fills the
  mempool, operators can restart to clear it without losing
  legitimate user value (re-broadcasts are cheap).

### 2. No ancestor / descendant package limits

**Bitcoin Core:** enforces max 25 ancestors, max 101 KB ancestor
package, max 25 descendants per parent, max 101 KB descendant
package.

**CoinCync:** does not. The chain has no public UTXO graph
(stealth addressing makes it structurally invisible to the
mempool), so "ancestor" isn't a meaningful concept the relay layer
can enforce. Each tx is admitted in isolation; the only inter-tx
relationship the mempool sees is "shared key image" (caught by
the RBF / double-spend rule).

### 3. No min-relay-fee separate from min-block-fee

**Bitcoin Core:** distinguishes `min_relay_fee_rate` (will accept
into mempool / forward to peers) from the effective min-block fee
(what's actually included in templates). The split exists to
support strategies like "relay free txs, mine only paying ones."

**CoinCync:** unified. `MIN_FEE_PER_BYTE` + the dynamic fullness
multiplier is the single gate at both relay-admit and template-
include time. Simpler; matches the privacy chain's "if it's worth
relaying, it's worth mining" framing.

### 4. Block-based TTL instead of wallclock TTL

**Bitcoin Core:** mempool entries expire after 14 days of
wallclock time (`-mempoolexpiry`).

**CoinCync:** expires after 288 BLOCKS (≈ 9.6h at 120s blocks).

The block-based form means: if the chain stalls (no blocks for
hours), txs don't expire either. That's correct behavior because
nothing's being mined anyway and operator visibility into the
stall is the operational signal that needs attention. A wallclock-
based expiry during a chain stall would silently delete user value
that has nowhere to land yet.

---

## Real gaps (flag for v1.0.11)

### Gap 1 — No per-peer bad-tx scoring

**The issue.** A peer that floods us with format-valid-but-
crypto-invalid txs burns ~5ms each in `verify_crypto_for_admission`
(CLSAG ring sig verify dominates). At 10 MB/s ingress (the
per-connection bandwidth cap in `src/network/peer.rs:267`) the
attacker can sustain ~4000 tx/s. We'd burn ~20 sec CPU/sec
verifying their garbage — saturating one core per attacker
connection.

The framing layer rate-limits BYTES, not BAD-MESSAGES. Each crypto
rejection emits an `AuditEvent::TxRejected` to the local audit log
but does NOT increment any per-peer counter, so the attacker
can keep coming back for free.

**Bitcoin Core's defense:** every rejected message increments the
peer's `nMisbehavior` score. Threshold (DEFAULT_BANSCORE_THRESHOLD
= 100) triggers disconnect + 24h ban.

**Recommended fix (v1.0.11):**

1. Add `peer_misbehavior_score: HashMap<PeerId, u32>` to the
   network layer.
2. On every mempool rejection, increment the originating peer's
   score by a category-weighted amount:
     - InvalidCrypto / InvalidStructure → +50 (close to instant ban)
     - DuplicateKeyImage (RBF too low) → +5 (noisy retry, slow ban)
     - MempoolFull / FeeTooLow → 0 (not the peer's fault)
3. Threshold ≥ 100 → disconnect + 24h ban.
4. Score decays at 1/hour so honest mistakes age out.

Size: ~half-day to implement + ~half-day for tests. Audit-firm
priority M (not consensus-critical, but the kind of DoS surface
they'll cite).

### Gap 2 — No tx-graph mempool depth limit

The mempool currently has a SIZE cap (bytes) and a TTL (288
blocks). It does NOT cap the number of distinct txs. If an
attacker submits 100,000 tiny txs each just over the dynamic-fee
threshold, they fit in the size cap but each one costs ~5ms to
crypto-verify — total ~8 minutes of CPU per fill-attempt.

The dynamic fee escalation (1× → 8× as the mempool fills) is the
soft defense against this. It DOES help — by the time the mempool
hits 75%+ fullness, an attacker needs 8× the base fee to keep
submitting. At realistic testnet conditions today, this is
adequate.

For mainnet with potential adversarial load, consider adding
`MEMPOOL_MAX_TX_COUNT = 5000` as a hard cap separate from the
byte cap.

Size: trivial (one constant + one check). Audit-firm priority L.

### Gap 3 — Mempool admission does not check coinbase maturity

`preflight_check` runs structural + privacy checks but does NOT
verify the input coinbase outputs are mature enough to spend per
`min_output_age_at_height(current_height)`. That check happens
in `consensus/validation.rs` at block-validation time, and the
v1.0.11 admission-side `shadow_evict_invalid` re-validates on
every chain advance — so a tx that becomes mature-then-immature
across a reorg or hard-fork-activation gets evicted.

But: at INITIAL admission, an attacker can submit a tx spending an
input coinbase that's only 1 block old. It admits cleanly (passes
ring-sig + bulletproof + balance), sits in mempool, gets evicted
on the first `shadow_evict_invalid` call (cheap), but consumed
admission CPU.

Recommended fix (v1.0.11): add the maturity check to
`preflight_check` so the rejection happens before crypto-verify
not after.

Size: ~30 min + tests. Audit-firm priority L (defense-in-depth
against a low-cost attack — `shadow_evict_invalid` already
catches it on every chain advance).

---

## Out of scope for this review

- **Package relay** (Bitcoin v25 CPFP for parent + child mempool
  admission). Privacy chain has no parent-child relationship the
  mempool sees; not applicable.
- **Cluster mempool** (Bitcoin v28+). Same reasoning — privacy
  txs don't form clusters the mempool can detect.
- **BIP-125 RBF opt-in/opt-out signaling.** We unconditionally
  allow RBF with the 25% bump. Bitcoin has the BIP-125 sequence-
  number convention for opt-in. Privacy chain doesn't expose
  sequence numbers at this layer; unconditional RBF is the
  cleaner model.

---

## Audit firm pre-staged answer

If the firm flags the mempool surface, the answer is:

> Mempool admission runs 16 checks before accepting a tx, including
> full CLSAG + bulletproofs + balance crypto verify. RBF, dynamic
> fee escalation, lowest-fee eviction, TTL expiry, and shadow-evict
> on chain advance are all in place. The three remaining gaps —
> per-peer bad-tx scoring, hard tx-count cap, and admission-time
> coinbase-maturity check — are flagged in
> `docs/security/mempool-relay-policy-review-2026-05-25.md` with
> sizing + rationale, scheduled for v1.0.11.

---

**Reviewer:** session of 2026-05-25, base-chain queue items 8-12.
**Next review trigger:** any change to `preflight_check`,
`admit_after_checks`, `expire_old_transactions`,
`shadow_evict_invalid`, or the constants `MAX_TX_SIZE`,
`MIN_FEE_PER_BYTE`.
