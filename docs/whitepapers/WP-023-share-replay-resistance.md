# WP-023 · Share-Replay Resistance
### The server-owned per-canonical-job nonce ledger

**Status:** Shipped · **Layer:** Mining · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

A mining pool pays for work it cannot directly verify was *new*. A miner submits a
share — a nonce meeting a reduced difficulty target — and the pool credits it. If
the pool can be made to credit the **same nonce twice**, the attacker is paid twice
for work done once, and every honest miner in the pool is diluted proportionally.

Share replay is theft, and unlike most attacks on a chain it does not target
consensus at all. It targets the accounting layer, where the money is actually
distributed.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Cross-connection replay** — submit the same nonce from a second worker | Per-worker dedup is sufficient because workers are distinct | Server-owned ledger shared across **all** connections |
| **Extranonce laundering** — vary the extranonce so the share "differs" | The extranonce is part of the proof of work | It is not: CoinCync PoW is `H(anchor, nonce, tx_root, height)` — so the nonce alone identifies the work |
| **Job-id toggling** — flip to a stale `job_id` to wipe the dedup set, then replay | The client's `job_id` identifies the job | Ledger is keyed by the **server-chosen canonical** job |
| **Nonce-width mismatch** — a legacy 32-bit nonce evades a 64-bit set, or vice versa | Nonce representations are interchangeable | Ledger keys on `u64`; the legacy path widens its `u32` |
| **Verification DoS** — force expensive PoW recomputation with junk resubmissions | Replay checks happen after verification | Replayed nonces are rejected **before** any PoW is recomputed |
| **Stale-job credit** — a share for a rotated job counted as current | Job rotation is instantaneous | Explicit rotation check; results downgraded to stale |

---

## 3. Design

### 3.1 The invariant

> Deduplication MUST be owned by the **server** and keyed by the **current
> canonical job** — never by per-worker state, and never by a client-supplied
> `job_id`.

Both halves of that sentence were learned from a broken design.

### 3.2 Why per-worker dedup fails

The intuitive implementation gives each worker connection its own set of seen
nonces. It fails because **the extranonce fields are not part of CoinCync's proof
of work.**

CoinCync's PoW is `H(anchor, nonce, tx_root, height)`. In pool protocols the
extranonce normally partitions the search space so two workers never test the same
input — which is precisely what makes per-worker dedup sound *in those protocols*.
Here it is not, because the extranonce does not enter the hash. A nonce valid for
one worker is valid, unchanged, for every worker on the same job.

So an attacker opens a second connection, replays the identical nonce, and is
credited again. Each connection's set is empty of the other's history, and each
one is individually correct.

**The general lesson:** a deduplication key must cover exactly the fields the
*verified artifact* depends on. Key on anything narrower and the same artifact
appears under two keys. Key on identity (worker, connection, session) when the
artifact does not depend on identity, and you have not deduplicated at all.

### 3.3 Why client-supplied job ids fail

The second broken design keys the set by `job_id` and clears it when the job
changes — reasonable, since nonces are only meaningful for one job.

The flaw is trusting the *client's* `job_id`. A miner submits under a stale id,
the server observes an id change, **clears the accepted-nonce set**, and the miner
replays everything it already submitted. The attacker controls the reset.

The fix is that the ledger tracks the **server-chosen canonical** job id and
resets only when the *server* rotates the job. A client-supplied id is treated as
what it is: a claim to be checked, never a control signal.

### 3.4 `JobNonceLedger`

```rust
struct JobNonceLedger {
    job_id: String,                  // the canonical, server-chosen job
    nonces: HashSet<u64>,            // nonces already credited under it
}
```

Held as a single `Arc<RwLock<…>>` shared across every worker connection. It holds
accepted nonces for exactly one canonical job and resets when that job rotates.

Nonces key on `u64` to cover the native path's 64-bit nonce; the legacy path
widens its `u32` into the same space, so one representation cannot slip past a set
built for the other.

### 3.5 Reject before recompute

A replayed nonce is rejected **before any PoW is recomputed**. This is a security
property as much as a performance one: verification is the expensive operation, so
a check that runs after it lets an attacker impose cost by submitting duplicates.
Cheap checks belong first.

### 3.6 Job rotation and stale shares

`canonical_job_unchanged` compares the submission's job against the server's
current canonical job. A share whose job has rotated mid-flight is **downgraded to
stale** rather than credited as current — extracted as the pure helper
`downgrade_stale_share(result, job_still_current)` so the decision is unit-testable
apart from the async submission path.

---

## 4. Security analysis

**What holds.** The same nonce cannot be credited twice for one canonical job,
regardless of how many connections the attacker opens, what extranonce they use,
what `job_id` they claim, or which nonce width their client speaks.

**Validation.** Regression tests cover the specific attacks rather than the happy
path:

| Test | Attack it pins |
|---|---|
| Worker B replays worker A's nonce for the same job → duplicate | Cross-connection replay (§3.2) |
| `claim_resets_on_canonical_job_rotation` | Reset happens on **server** rotation only |
| `canonical_job_unchanged_detects_rotation` | Stale-job detection |
| `downgrade_stale_share_treats_rotated_job_results_as_stale` | Stale downgrade logic |

**What this does not protect against.**

- **Replay across job rotations.** The ledger holds one canonical job. A nonce
  valid for a *different* job is a different artifact and legitimately credited —
  but it also means the ledger provides no protection if job rotation can be
  induced cheaply by an attacker. Rotation is server-driven, which bounds this.
- **Memory growth within a long-lived job.** The set grows with accepted shares
  until rotation. Bounded in practice by rotation frequency, not by an explicit
  cap.
- **Withholding attacks.** A miner who finds a *block* and submits only the share
  is not addressed here; share dedup is orthogonal to block withholding.
- **Pool-side trust generally.** This protects the pool's accounting from one
  specific miner attack. It says nothing about whether the pool pays honestly —
  that is the miner's risk, and the argument for solo mining.
- **The wider mining surface.** Rig read-line bounds, builder/validator congestion
  sizing, fork-divergence mine gating, and nonce-search coverage are separate
  fixes in the same subsystem, not covered by this mechanism.

---

## 5. Implementation

| Component | Location |
|---|---|
| `JobNonceLedger`, `nonce_dedup` shared handle | `src/mining/stratum.rs` |
| `canonical_job_unchanged` | `src/mining/stratum.rs` |
| `downgrade_stale_share` pure helper | `src/mining/stratum.rs` |
| Native and legacy submission paths | `src/mining/stratum.rs` |

---

## 6. Known limits

- No explicit size cap on the accepted-nonce set within one job.
- Protection is per-canonical-job by construction.
- Does not address block withholding or pool honesty.
- No adversarial load test against a real pool deployment.

---

## 7. References

- Stratum protocol and its extranonce semantics — the source of the assumption
  §3.2 shows does not transfer.
- Rosenfeld (2011), *Analysis of Bitcoin Pooled Mining Reward Systems* — pool
  accounting attacks, including share manipulation.
- Internal: [WP-004 PoW binding](WP-004-pow-binding.md) — the hash definition that
  makes the extranonce irrelevant here,
  [WP-006 §4.4](WP-006-cumulative-work-determinism.md),
  [WP-100](WP-100-solved-issues-ledger.md).
