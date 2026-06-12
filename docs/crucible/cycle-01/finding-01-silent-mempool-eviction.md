# Crucible Cycle 01 — Finding #1: Silent mempool eviction on send

**Status:** Fixed
**Severity:** High (UX-blocking — every privacy send on a fresh chain failed silently)
**Discovered:** 2026-06-07
**Fixed in:** `v1.0.11-fleet-2026-06-06` commit `7358775`
**Tester:** barns1253 (independently surfaced); operator confirmed + root-caused
**Time-to-fix:** ~3 hours from first repro to verified end-to-end working

## TL;DR

A privacy `send` would print `OK: tx accepted by mempool`, then ~60 seconds
later the node would silently drop the tx in `shadow_evict_invalid`. Neither
sender nor recipient saw any balance change, and no error was surfaced to
the user. Caused by two combined bugs in the wallet + mempool that took the
"accept" and "revalidate" paths down different code branches; the wallet
also picked decoys that the consensus validator was guaranteed to reject.

## Symptom

```
$ coincync-wallet send --to-spend ... --to-view ... --amount 10000000000 -p ...
Built tx:
  Hash:    fbec87df...
  Inputs:  2
  Outputs: 2
Submitting to http://127.0.0.1:28081...
  OK: tx accepted by mempool.

$ # ~60 seconds later, node log shows:
2026-06-07T18:27:55.851706Z  INFO shadow-evict: dropping 1 mempool tx(s) ...

$ coincync-wallet scan ...    # recipient
Found outputs:  0
Balance total:  0 CYNC

$ coincync-wallet scan ...    # sender
Balance total:  <unchanged>
```

No error returned. User retries — same result.

## Discovery path

1. **Operator's first send (2026-06-06 evening):** built tx via old-version
   wallet on local v1.0.11 node — accepted, then evicted. Mentioned to me as
   "First Tx is OK but no balance change". Diagnosed initially (incorrectly)
   as a coinbase-maturity wallet bug.
2. **Crucible bundle prepped for barns:** rebuilt with version-matching
   wallet, did a fresh send/receive test as smoke check before shipping
   the bundle.
3. **Send still failed identically** with the version-matched wallet.
   Eviction reproduced on 4 separate sends across 2 wallets and 2
   recipients.
4. **Debug logging:** restarted node with `--log-level debug` to surface
   the per-tx eviction reason that `shadow_evict_invalid` logs at debug
   level (`shadow-evict <hash>: <reason>`).
5. **Reason captured:**
   ```
   Invalid transaction: Input 0 ring member 1 references immature
   coinbase output (height 729, age 63 < required 100)
   ```
6. **Source dive** confirmed two contributing bugs (below).

## Reproduction

100% deterministic on any fresh chain with the unfixed binaries:

1. Run `coincync-node` (v1.0.11 unfixed) with `--no-peers`
2. Start `coincync-rig` against it, let it mine to ~h=200+ (so the wallet
   has multiple mature-ish coinbase UTXOs to spend)
3. Build any standard 2-in/2-out privacy `send` via `coincync-wallet`
   (unfixed)
4. Watch the node log — within ~60s, `shadow-evict: dropping 1 mempool tx(s)`
5. Recipient balance never changes; sender balance never changes

## Root causes

### Bug A — `select_ring_decoys` did not filter decoys by coinbase maturity

`bin/wallet.rs::send_command` calls the `get_decoys` RPC like so:

```rust
// Before fix:
let decoys_json = rpc_call(node, "get_decoys",
    serde_json::json!([ring_size * 8, 0])).await?;
//                              ^^^^^^^^^^^^^^^^^^^ count, min_age
```

The second parameter is the node-side filter `min_age` — outputs younger
than `min_age` are excluded from the returned decoy pool. The wallet passed
`0` — no filter. The returned pool included every coinbase output on the
chain, including newly-mined ones with age < `min_output_age_at_height(h)`
(10 pre-fork, 100 after `MIN_OUTPUT_AGE_HARDFORK_HEIGHT`).

`consensus/validation.rs::validate_transaction` (line ~1186) rejects any
ring containing a coinbase with `age < required`. So if the wallet picked
even one decoy that was a recent coinbase, the entire tx was guaranteed
to fail block validation — but only at validation time, never at mempool
admission time (see Bug B).

**Probability of hitting it:** very high on fresh chains where most
outputs are coinbase. Low but nonzero on mature chains.

### Bug B — Mempool `add_with_chain` skipped the height-gated validator

`mempool.rs::add_with_chain` (the entry point called by `send_raw_transaction`
RPC) ran only a per-key-image `chain.is_spent(&ki)` check before delegating
to `mempool::add`. `mempool::add` itself runs:

- `preflight_check` → `validate_transaction_basic(tx)` — contextless,
  height-less, no UTXO state
- `verify_crypto_for_admission(&tx, chain_height)` — range proofs, balance
  proof, ring signatures
- `admit_after_checks` — size/fee/RBF

None of these check height-gated consensus rules: coinbase maturity, ring
member existence in UTXO, lock heights, V2 activation, or uniform-shape
(STANDARD_INPUT_COUNT).

Meanwhile `mempool.rs::shadow_evict_invalid`, called after every block
apply, runs the **full** `chain.validate_transaction(&tx)` against current
chain state — and catches every rule the ADD path skipped.

Net effect: any tx tripping any height-gated rule was accepted at submission
(no user-visible error), then evicted ~one block later.

**This is a general architectural flaw, not specific to coinbase maturity.**
The same divergence would silently drop:

- Pre-activation V2 txs after `V2_TX_ACTIVATION_HEIGHT`
- Non-uniform-shape Transfer txs post-`UNIFORM_TX_SHAPE_HEIGHT`
- Txs whose ring members reference outputs not (yet) in UTXO
- Txs spending outputs with active lock heights
- Txs with in-tx duplicate key images that pass the per-key-image chain
  check but fail intra-tx dedup

## Fix

Two changes, both surgical, committed together as `7358775`.

### Fix A — wallet passes proper `min_age` to `get_decoys`

```rust
// After fix (src/bin/wallet.rs):
let min_decoy_age = coincync::constants::min_output_age_at_height(current_height);
let decoys_json = rpc_call(node, "get_decoys",
    serde_json::json!([ring_size * 8, min_decoy_age])).await?;
```

The node-side `get_decoys` implementation already supported the `min_age`
filter; only the wallet was passing `0`.

### Fix B — `add_with_chain` calls the full validator at admission

```rust
// After fix (src/mempool.rs):
pub fn add_with_chain(
    &self,
    tx: Transaction,
    chain: &crate::chain::SharedBlockchain,
) -> Result<Hash> {
    chain.validate_transaction(&tx)?;   // FULL validator, same as shadow_evict
    self.write_lock().add(tx)
}
```

Admission and revalidation now use the same code path. The previous
per-key-image check is subsumed by `validate_transaction`
(`utxos.contains_key_image` at validation.rs:1148).

Failure modes shift from "silent eviction" to "immediate rejection with
the same error the validator would have given a block" — exactly what the
user needs to debug their own tx.

## Verification

End-to-end test on the local v1.0.11 node with the fixed binaries:

| Step | Pre-fix | Post-fix |
| --- | --- | --- |
| Submit tx via `coincync-wallet send` | `OK: accepted` | `OK: accepted` |
| 60 seconds later | `shadow-evict: dropping 1 mempool tx(s)` | tx mined into block |
| Recipient `scan` | balance: 0 | balance: 0.01 CYNC ✓ |
| `get_transaction <hash>` | "transaction not found in index" | full tx record + block_height |

Reproducer: tx `fbec87df...` mined into block 835 at h=835. Recipient
(fresh v1.0.11-built wallet) saw the output on first scan.

## Impact on shipped versions

- **v1.0.10 and earlier:** affected. Wallet code is the same call to
  `get_decoys` with `min_age=0`; mempool `add_with_chain` is the same
  weak-check pattern. Not surfaced earlier because:
  - Pre-2026-06-04 testnet wipe, the chain had enough mature coinbase +
    received outputs that wallet decoy selection happened to pick mature
    ones often enough to be ignored as "occasional flakes"
  - The "tx silently disappears" failure mode is hard to attribute without
    debug logs
- **v1.0.11 (canonical CLSAG branch):** affected until commit `7358775`
- **v1.0.11-fleet-2026-06-06 from `7358775` onward:** fixed

Anyone running an earlier binary on a fresh chain (e.g. day 1 of mainnet)
will hit this on their first send. **This must be in the v1.0.11 release
notes.**

## What Crucible got right

- A single external tester hitting "send doesn't work" within the first
  hour of receiving a binary surfaced a class-of-bug that internal
  testing had missed for the entire v1.0.10 lifecycle.
- The combination of "operator does the same test in parallel" + "operator
  has source access + debug logging" + "tester has independent repro env"
  turned a 60-second silent failure into a 3-hour fix.
- The bug class (accept-path vs revalidate-path divergence) is the kind
  of architectural drift that integration tests rarely catch because they
  typically use one path or the other, not both in sequence.

## What Crucible should improve

- **A test fixture that always reproduces.** A regression test on a fresh
  regtest chain that sends within the first 100 blocks would have caught
  Bug A. A separate test that compares add-path and revalidate-path
  validators on a corpus of generated txs would catch Bug B.
- **Per-tx eviction reasons at INFO level, not DEBUG.** The current
  `shadow_evict_invalid` logs the count at INFO and the per-tx reason at
  DEBUG. Reasons should be INFO so production logs surface them without
  re-running with `--log-level debug`.
- **The mempool RPC's success response should be qualified.** Returning
  `accepted: true` from `send_raw_transaction` when the tx might still
  be evicted on the next block is misleading. Either run the full
  validator before returning success (this PR's approach), or change the
  response shape to communicate "accepted-pending-revalidation".

## Follow-up tasks

- [ ] Add the regression test described above to the v1.0.13 ops-polish
      tracking
- [ ] Bump the eviction-reason log level INFO in a separate PR (small,
      cosmetic)
- [ ] Audit other "two validators" cases in the codebase (`validate_block`
      vs `validate_transaction`, mempool `add` vs `shadow_evict_invalid`)
      for similar drift
- [ ] Release-notes entry for v1.0.11 noting the fix is required for
      day-1-of-mainnet UX
