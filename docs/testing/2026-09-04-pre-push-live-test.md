# Live test — 2026-09-04, before pushing `fix/base-audit-2026-09-05`

Regtest, two nodes, release binaries built from the branch head. Run because this
session changed consensus in four places and a green unit suite is not evidence
that a daemon runs.

**Headline: the live run found two bugs that 1184 passing unit tests did not,
one of which stopped the node from starting at all.**

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

## Not covered

Stated plainly rather than implied by omission:

- **Dust quarantine end-to-end** — the CLI was exercised, but no output was
  actually quarantined and released, because regtest coinbase rewards are far
  above the threshold.
- No stratum/pool test, no Tor transport test, no light-wallet sync test.
- No subaddress send (gated off mainnet; W-1).
- Regtest only. No mainnet-parameter run.

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
