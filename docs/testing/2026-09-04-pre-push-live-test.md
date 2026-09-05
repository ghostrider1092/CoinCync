# Live test — 2026-09-04, before pushing `fix/base-audit-2026-09-05`

Regtest, two nodes, release binaries built from the branch head. Run because this
session changed consensus in four places and a green unit suite is not evidence
that a daemon runs.

**Headline: three rounds, 30 checks. The live run found FOUR defects that 1184
passing unit tests did not — one that stopped the node booting, one that made a
documented audit path impossible, one where the CLI told users the opposite of
the truth about an irreversible key disclosure, and one silent consensus-rule
mismatch. Plus one unfixed finding (memo padding) that needs an owner decision.**

---

## Bugs found

### 1. Node would not boot — duplicate RPC method

```
ERROR node start failed: RPC error: Method: get_finality_info was already registered
```

`get_finality_info` already existed as an explorer endpoint. jsonrpsee rejects a
second registration at startup, so the finality-hints work (`50d8aaf3`) made the
daemon **unbootable**. Nothing in the unit suite constructs the RPC module, so
nothing caught it.

Merged into one method (`a72778dd`). The pre-existing version was also lying to
the explorer: it hardcoded `checkpoint_interval: 5` and derived `last_checkpoint`
from `height % 5` when the real `CHECKPOINT_INTERVAL` is **144**, then asserted
that blocks below that fabricated checkpoint "cannot be reverted by any amount of
hashpower". Legacy field names kept for the explorer, values corrected.

### 2. The documented supply-audit path could not be completed

WP-002 tells an auditor to recompute the commitment and compare it against the
block header — and **no RPC exposed `supply_commitment` on a block**. The claim
was unverifiable without deserializing the raw block blob. Added to the shared
block payload (`a72778dd`).

---

## What passed

| # | Check | Result |
|---|---|---|
| 1 | Node boots, Cynstra branding wired | `CoinCync Regtest node starting (coincync 2.0.0)` / `Network: CoinCync Regtest (regtest)` |
| 2 | **Mining with genesis-active supply commitments** | **549 consecutive blocks, every one `Accepted`** |
| 3 | RandomX `FLAG_SECURE` (Windows W^X, WP-004 §3.4) | Active: `FLAG_HARD_AES \| FLAG_FULL_MEM \| FLAG_JIT \| FLAG_SECURE \| …` |
| 4 | Restart / reload from disk | Reloaded at 549, continued to 577 |
| 5 | Two-node P2P sync | Both height 972, **identical tip** `1fee876459d44fc7` |
| 6 | Independent supply audit (Python + blake3, no CoinCync code) | RPC == header == recomputed; genesis = 32 zero bytes; inflated figure correctly FAILS |
| 7 | MESS deep-reorg rejection | ~84-block fork with 1 block of extra work correctly **refused** — nodes stayed split |
| 8 | **Shallow reorg + supply check on the reorg path** | `REORG_COMMIT height=66 reorg_depth=4`, both nodes converged to `a8b0531e78153b59` |
| 9 | Equal-work tiebreak (PoW hash) fired live | `Fork at height 66 has more work (26881 > 26881), performing reorg` |
| 10 | **Supply state identical after a reorg** | The node that reorged and the node that did not produced byte-identical commitments |
| 11 | `get_finality_info` truthfulness | `checkpoint_interval=144`, MESS reported **suspended** at height 80, 6-confirmation payment labelled "unconditional" |
| 12 | Dust-quarantine CLI | `quarantine list` shows threshold; `accept` refuses unknown outputs with a pointer |

**Check 2 is the one that mattered most.** The miner fills
`header.supply_commitment` from the template's parent totals and the validator
recomputes it independently on connect. A disagreement of one atomic unit would
have meant block 1 was rejected and the chain never left height 0.

**Check 10 is the strongest.** Node 2 disconnected 4 blocks and re-applied 20,
node 1 did neither, and both then produced the same commitment — cumulative
supply is a function of the chain, not of reorg history. That is the WP-006
property demonstrated rather than argued.

**Check 8 exercised the second connect path.** A block reaches the chain through
two independent loops; the reorg loop re-applied 20 blocks and ran the supply
check on each. Had that check been wrong there, the reorg would have aborted.

---

## Round 2 — the money path (RingCT send)

Run after the above, on the same branch. This was the gap the first round left
open, and it is the path that moves money.

| # | Check | Result |
|---|---|---|
| 13 | Wallet scan detects mined coinbase (stealth addresses) | 689 outputs / 47 598 CYNC |
| 14 | **RingCT/CLSAG send, uniform shape** | `Inputs: 2  Outputs: 2`, 3395 bytes, fee 7 160 000 atomic — accepted |
| 15 | Transaction mined into a block | Confirmed, `block 8ed4e16b…` |
| 16 | Recipient detects the payment by stealth scan | w2 found its outputs unaided |
| 17 | **Spend of RECEIVED funds (not coinbase)** | w2 → w1, `Inputs: 2 Outputs: 2`, accepted and mined |
| 18 | Balances reconcile | w2: 110 received − 25 sent − 0.00000716 fee = **84.9999 CYNC** ✓ |

**Check 17 is the one that matters.** WP-016 §4.1 makes the point that "receive
works" is half a feature and the dangerous half, because it is the half that
takes custody. A wallet that can detect a payment but not spend it looks healthy
and loses money. Detect → spend → change round-trips correctly for main
addresses. (Subaddresses remain gated off mainnet for exactly the failure this
check rules out for the main path — see WP-016.)

### Two observations, neither a defect

- **Decoy pool floor.** A send on a very young chain fails with
  `Insufficient decoy outputs: 76 available, 126 needed`. Correct behaviour — the
  ring cannot be built from a pool that small — but the error is the first thing
  a new-chain operator will hit, and 126 candidates for one 2-input send is a
  steeper floor than `BOOTSTRAP_MIN_RING_SIZE = 11` suggests. Worth a friendlier
  message.
- **Benign warning on a peerless node.** `P2P transaction rejected by mempool:
  Duplicate key image`, emitted when Dandelion++'s fail-safe fluff re-offers a
  locally-submitted tx that `send_raw_transaction` already admitted. Harmless —
  the tx is already in the mempool and does get mined — but it reads like a
  failure in the log.

---

## Round 3 — memos, disclosure, quarantine, subaddress gate, light-sync, stratum, mainnet params

| # | Check | Result |
|---|---|---|
| 19 | **Encrypted memo round-trip** (WP-014) | `"invoice-4471 rent september"` decrypted by recipient only; 27 plaintext → 55 wire bytes (27 + 28 overhead) |
| 20 | **Dust quarantine end-to-end** (WP-018) | 5 000 000-atomic output auto-quarantined on receipt; listed; **refused** without confirmation; released on `accept`; flag persisted |
| 21 | Disclosure — balance proof | 2 631-byte proof that a UTXO ≥ 1 CYNC, without revealing 54.99 CYNC |
| 22 | Disclosure — **unanchored** verify warns | `⚠ NOT ANCHORED TO CHAIN: this does not prove the commitment corresponds to any real on-chain output` |
| 23 | Disclosure — **anchored** verify | `ANCHORED + VALID — range proof holds AND the commitment is on chain` |
| 24 | Disclosure — **anchor mismatch rejected** | Wrong output → `ANCHOR MISMATCH: the range proof is well-formed but its commitment does NOT match` |
| 25 | Disclosure — verifier-privacy warning (WP-013 §3.4) | `⚠ PRIVACY: … That node now knows you care about this output` |
| 26 | Subaddress **mainnet gate** (W-1) | Refused: "funds received at a subaddress would be permanently unspendable" |
| 27 | Light-sync digests (WP-017) | 21 blocks for a 21-block range; digest carries `is_coinbase` (the H-4 fix) and `view_tag` |
| 28 | Light-sync range cap | 500-block request clamped to 100 |
| 29 | Stratum pool server | `Starting Stratum pool on 127.0.0.1:23333 (block_production=true)` |
| 30 | Mainnet genesis parameters | `c9eb73ab…fe07635c` — matches `MAINNET_GENESIS_HASH` byte for byte |

**Check 24 is the one worth dwelling on.** The three-valued `AnchorVerdict` from
WP-013 §3.5 is doing real work: it distinguishes "the math is fine but this is
not the output you named" from "the proof is broken". A boolean would have
merged them, and an auditor needs to tell a mistake from an attempt.

---

## Round 3 bugs found

### 3. `scoped-view-key` told the user the opposite of the truth — FIXED (`3d463489`)

The CLI printed:

> "It lets the holder see every output your wallet received in this height range
> — **and nothing outside it**."

That is false, and it was proven live: exporting two scoped keys with ranges
`1180..1200` and `1..50` produced the **byte-identical** `view_secret`. The
height range is metadata in a JSON blob; the key material is the wallet's full
view secret. `from_height`/`to_height` are honoured by our own scanner
(`disclose scan-scoped`) and by nothing else.

The source was already honest — `wallet/key_epoch.rs` says "The key material is
the same — the scope is enforced by the wallet scanner", and WP-013 §3.6
documents it. **The CLI contradicted its own source and told the user the
opposite.**

This is the most user-dangerous shape of defect in the whole session. Sharing a
view key is a deliberate, irreversible act taken on the strength of exactly that
sentence. A user disclosing "a tax year" to an accountant was in fact disclosing
everything, forever, and had been told they were not.

Warning rewritten to state what the key does, that it cannot be revoked, and to
point at the disclosure *proofs* as the primitive that actually binds against an
adversarial recipient. No behaviour change — the export was always the full
secret.

### 4. Compile-time feature vs `--network` mismatch — GUARDED (`257a452a`)

`MIN_OUTPUT_AGE_HARDFORK_HEIGHT` is selected by `#[cfg(feature = "testnet")]`,
and `min_output_age_at_height(height)` takes **no network parameter**. So a
binary built `--features testnet` and started `--network mainnet` silently
enforces testnet maturity (10 blocks instead of 100) and would disagree with
correctly-built peers about which spends are valid — a chain split with no
symptom until it happens. `FEE_DISTRIBUTION_HEIGHT`, `CONSENSUS_CHECKPOINTS` and
the `ROLLING_FINALITY_*` heights are gated the same way.

This is the F31 SEV-A shape that already bit this project (the 2026-07-04
partition trap). F31 was fixed for `max_reorg_depth` by reading the runtime
network; these constants were left compile-time and unguarded.

The official release build (`--features "${NETWORK}"`) never produces a
mismatch, so this only fires on a hand-built binary — which is exactly the case
nothing else catches. Now a fail-closed startup check naming the rebuild command.

---

## Round 4 — memo padding (the round-3 finding, now fixed and verified)

Resolved by the project's own design charter, which lists under *mandatory
uniformity*: "fixed ring size, uniform fees, **padded sizes**." Padding was not
an open design question — it was a stated commitment the code did not meet.

Implementing it surfaced a **second** defect in the same forty lines:
`MAX_MEMO_SIZE` was a hardcoded 256 while consensus caps the *encrypted* field
at 256, so a maximum-size memo encrypted to 284 and the network refused it. The
documented maximum memo was unusable. Verified live: a 240-byte memo drew
`encrypted_memo too large: 268 bytes (max 256)`; 228 was the real limit. A
builder that accepts what the verifier rejects is the WP-009 §2.3 rule-asymmetry
class — the **third** instance in this project, after the decoy sampler and the
difficulty target.

| # | Check | Result |
|---|---|---|
| 31 | Memo length no longer observable | Memos of **2, 27 and 200** bytes all produce exactly **256** on-chain bytes |
| 32 | Padded memos decrypt correctly | `"hi"`, `"invoice-4471 rent september"`, and a 228-byte memo all round-trip |
| 33 | **Legacy memos still readable** | Pre-fix 55-byte memos still decrypt — padded plaintext is always exactly the padded size, so any other length is unambiguously legacy |
| 34 | Builder cap matches consensus | Max-size memo now encrypts to exactly the consensus cap; over-cap refused by the wallet, not the network |
| 35 | Presence leak still present (expected) | Per-output sizes read `[256, 0]` — the change output carries no memo |

The fix derives the padded size from `MAX_OUTPUT_MEMO_SIZE` with a compile-time
assertion, so the asymmetry is **unrepresentable** rather than merely fixed. Two
pre-existing tests had been *pinning the bug in place* by asserting
`encrypted.len() == nonce + memo.len() + tag` — i.e. requiring the wire size to
reveal the memo length.

Three documents that claimed padding already happened were corrected
(`8adfb5de`), including the hash-locked `constants.rs`, which required a
deliberate re-lock — the WP-007 gate working as intended on a comment-only edit.

**Still open:** memo *presence* leaks (256 bytes vs an empty field). Closing it
needs a fixed-size memo field on every output — a consensus rule with a real
per-transaction size cost, and a separate decision.

## Round 5 — stratum share submission and the WP-023 replay defense

The remaining money-adjacent gap: the pool payout accounting, where WP-023's
per-canonical-job nonce ledger lives, was untested outside unit tests. Ran the
real `coincync-rig run-pool` client against the node's built-in `--stratum` pool.

| # | Check | Result |
|---|---|---|
| 36 | Miner logs in, receives jobs | `pool: logged in ... as live-test-worker`, `new job 00000001 (height 1)` |
| 37 | Shares accepted, blocks produced server-side | **83 blocks** mined via stratum; `stratum: block from worker 1 submitted — Accepted` |
| 38 | **WP-023 cross-connection nonce replay REJECTED** | conn A submits nonce N → `low difficulty share`; conn B (separate login) replays N → `duplicate share` |
| 39 | Ledger records at claim time, before PoW | An arbitrary (invalid) nonce still cannot be replayed — the ledger caught it without RandomX ever running on the replay |
| 40 | Valid work still accepted (ledger not over-rejecting) | The same run that rejects replays produced 83 real blocks |

**Check 38 is the one this round exists for.** The defense WP-023 documents is
that the nonce ledger is *server-owned*, not per-connection: if it were
per-worker, a second connection replaying the same nonce would be re-credited
(paid twice for one unit of work, diluting every honest miner). Two separate
logins, same nonce, same canonical job — the second is rejected as `duplicate`
before `verify()` recomputes any PoW. Test script kept at
`docs/testing/wp023-stratum-replay-test.py` (raw TCP, ~90 lines, no CoinCync
dependency).

The ledger records the nonce at *claim* time, before the PoW check, so the replay
is caught even for a nonce that would fail verification — which is why an
arbitrary test nonce suffices and no RandomX is needed to demonstrate the
defense.

### One observation, not a defect

Under regtest's trivial difficulty the rig submits far faster than the
`MIN_SUBMIT_INTERVAL_MS = 200` cadence throttle, so the client log fills with
`{"code":-1,"message":"throttled"}` warnings. Harmless — shares still get
through between throttle windows and blocks are produced — but on a real network
this cadence is per-worker and legitimate; it only looks alarming because
regtest difficulty makes every hash a share.

## Round 6 — mainnet-parameter chain

Everything before this ran on regtest/testnet. This round built **real mainnet
binaries** (`--features randomx`, no `testnet`) and exercised mainnet consensus.

### What a mainnet binary does, confirmed live

| # | Check | Result |
|---|---|---|
| 41 | Mainnet binary boots on `--network mainnet` (the guard from 257a452a passes for the correct build) | `Cynstra node starting (coincync 2.0.0)` / `Network: Cynstra (mainnet)` |
| 42 | **Cynstra branding live on a real mainnet binary** | first observation of the mainnet display name on an actual mainnet node |
| 43 | Genesis hash matches `MAINNET_GENESIS_HASH` | `c9eb73ab…fe07635c` |
| 44 | Mainnet address prefix | `CYNC…` (99 chars), not `tCYNC` |

### A mainnet chain cannot be mined before Oct 1 2026 — by design, proven

The mainnet genesis is timestamped **1790812800 (Oct 1 2026)**. Today is Sept 5.
`check_header_future_timestamp` (validation.rs:1103) exempts genesis but caps
every later block at `local_clock + MAX_TIMESTAMP_DRIFT` (600 s). The miner sets
block 1's timestamp to `max(now, genesis+1)` = Oct 1, which is ~26 days past the
drift window, so block 1 can never be accepted today.

Confirmed by a **controlled experiment**: a real-genesis mainnet miner sat at
height 0 indefinitely; changing *only* the genesis timestamp to ~2 h ago (nothing
else) made the same binary mine immediately. The future-dated genesis is the sole
blocker — you cannot mine mainnet before its launch date, which is correct.

The genesis-integrity guard also fired correctly during this: altering the
genesis produced `Genesis hash mismatch! Computed d39d548e… but expected
c9eb73ab…`, catching the change at startup.

### Mainnet consensus rules, on a test-genesis chain

With a near-now test genesis (all other mainnet params intact — magic, difficulty
64000, ring schedule, emission, maturity, fee-burn height):

| # | Check | Result |
|---|---|---|
| 45 | Mines valid blocks under mainnet consensus | height climbed, difficulty settling ~32k→converging toward the 120 s target |
| 46 | **Independent supply audit passes under mainnet params** | RPC == header == blake3-recomputed; genesis zero; inflated figure fails |
| 47 | Emission schedule | `emission_phase: Distribution`, per-block reward matches the curve |

### Not driven — and why, stated plainly

- **100-block maturity (vs testnet's 10).** `MIN_OUTPUT_AGE_POST_FORK = 100` is
  the active constant on a mainnet build (unit-tested, and now protected by the
  feature/network startup guard). Driving a real spend of a 100-deep output at
  mainnet difficulty needs ~130 blocks × ~120 s ≈ 4 h — impractical this session.
  The maturity *gate mechanism* is the same code verified on testnet at 10 blocks.
- **Fee-burn from genesis (`FEE_DISTRIBUTION_HEIGHT = 0`).** Every block mined
  here was coinbase-only, so `total_burned` stayed 0 correctly (no fees to burn).
  Exercising a non-zero burn flowing into the supply commitment needs a
  fee-paying transaction, which needs a mature output — the same 4 h wall. The
  burn split itself is unit-tested (`block_fee_burn_matches_validator_burn_split`)
  and the supply-commitment path is verified in rounds 1–2.

### Cleanup

The test genesis was a throwaway local edit to the **unlocked** `src/mainnet.rs`
(timestamp + hash), never committed. Reverted from backup; `git diff` on
`mainnet.rs` is empty, `test_mainnet_genesis_hash_consistency` passes, and the
standard testnet working binaries were rebuilt.

## Round 7 — the colony castes, live

After building the act-phase spine (honeybee quorum + guards), every caste was
exercised against a live node via `examples/colony_live.rs` — the real decision
cores, on real public RPC signals, with the detection castes' output run through
the spine. It only reads and prints; no node behavior changes.

| # | Check | Result |
|---|---|---|
| 48 | Every caste core runs on live signals | spider/sensor/forager/army_ant/centipede/locust/cicada/firefly/mantis/stick_insect all produced output from a live 2-node chain |
| 49 | **A live single-signal detection does NOT act** | spider fired `EclipsePressure` (1 inbound peer, 100% one netgroup); honeybee: *"no threat reached quorum confidence (nothing would act)"* |
| 50 | Corroborated threat reaches confidence | synthetic 5-source / 3-dimension Partition → confidence **100** |
| 51 | Guard allows a floor-safe response | `army_ant-bridge` keeping 6 netgroups → `Ok` |
| 52 | **Guard denies a floor-breaking response** | `peer-rotate` dropping to 2 netgroups → `WouldBreakDiversityFloor { floor: 4 }` |
| 53 | Kill switch overrides everything | engaged → `Err(KillSwitch)` even on a confidence-100 action |

**Check 49 is the whole point.** The colony's own defenses are the obvious attack
surface — forge a detection, steer a response. On live data, a genuine caste
detection (`spider` seeing eclipse-shaped topology) could not by itself move the
colony, because the quorum refuses one source on one dimension. The
"not-an-attack-surface" property is demonstrated, not just asserted.

The harness is kept in the repo (`cargo run --example colony_live -- <rpc-url>`)
so the whole pipeline can be re-run against any node.

## Superseded — the original round-3 write-up of this finding

**Memos are not padded.** WP-014 §3.4 and WP-011 §3.3 both state that honest
wallets pad memos to the 256-byte cap, sourced from the claim in
`constants.rs:207`:

> "Honest wallets pad memos up to this cap via the MAX_MEMO_SIZE = 256 +
> MEMO_OVERHEAD constants"

No wallet code does this. `transaction/builder.rs:570` calls
`encrypt_memo(memo_bytes, …)` with the raw plaintext, and outputs without a memo
get an empty field. Live: a 27-byte memo produced 55 wire bytes; an unmemo'd
output produces 0.

So both memo **presence** and memo **length** are directly observable on chain,
which partitions the anonymity set exactly as WP-011 §1 warns — the users who
attach memos are identifiable as memo users, and length leaks content class.

Not fixed here because it is a **wire-format decision, not a bug fix**:

- Padding the plaintext to the cap needs a length-preserving encoding (e.g. a
  2-byte length prefix), which changes the encrypted-memo format. Safe
  pre-launch, but it is a format change.
- It only fixes *length*. Presence still leaks (0 bytes vs 284). Closing that
  needs every output to carry a fixed-size memo field — a consensus uniformity
  rule with a real size cost on every transaction.

Recommendation: pad to the cap now (cheap, pre-launch, removes the length leak),
and treat "every output carries a memo-sized field" as a separate consensus
decision. Either way the three documents claiming padding already happens must be
corrected — that is not optional, since two of them are whitepapers.

---

## Still not covered after round 3

- **Tor transport** — no Tor daemon available in this environment; only flag
  parsing could be checked, which is not worth calling a test.
- **Subaddress receive→spend on regtest** — the mainnet gate was verified; the
  underlying W-1 unspendability was not re-demonstrated, since it is a known and
  documented defect and the gate is what protects users.
- **Stratum share submission** — DONE in round 5 (WP-023 replay defense verified
  live).
- **Mainnet chain run** — genesis parameters verified; no mainnet chain was
  built or mined.

## Process notes

**Two false alarms, both mine, both from checking the wrong thing.**

1. I reported a transaction as "never mined" after finding the mempool empty and
   `tx_count=1` in recent blocks. The tx was submitted at height 290; I inspected
   blocks near 867 — roughly 570 blocks past where it landed. It had been mined
   almost immediately. Regtest produces ~3 blocks/second, so a transaction is
   essentially never observable in the mempool.
2. My confirmation wait loop polled `get_transaction` until the response
   contained `"height"`. That field is not in the response shape, so the loop
   could never terminate regardless of chain state.

Both produced confident, wrong conclusions from real output. The lesson is the
same one as the reorg fixture below: **verify the instrument before trusting a
negative result.** An absence of evidence from a check you have not validated is
evidence about the check.

**Fixture hygiene.** An early attempt at the reorg test was invalidated by my own sloppiness: repeated
restarts left stale heights and leftover peer state, so heights I sampled did not
match what the nodes had actually reached, and the "divergence" I started
investigating was an artifact. The clean run cloned the chain directory at a
known height to guarantee an identical fork base. **A test whose setup you cannot
fully account for produces evidence you cannot use** — the correct response was
to discard it and rebuild the fixture, not to reason harder about the output.
