# Decoy-Selection Policy

**Status:** Authoritative policy
**Scope:** CLSAG ring-member selection for CoinCync wallets
**Policy version:** [`DECOY_LOCATOR_POLICY_VERSION`](../../src/decoy.rs)

> This document is the single source of truth for decoy selection. Wallets,
> tests, tooling, and other documentation must follow the code boundaries and
> failure rules below. Concrete constants remain authoritative in code.

---

## 1. Policy in one paragraph

The wallet, not the serving node, chooses decoys. It first selects the real
inputs, samples canonical output locators locally with the configured log-gamma
age profile, mixes every real locator into one shuffled fixed-size covered
lookup, and resolves that locator set against a snapshot-bound RPC response. The
wallet validates the entire response and assigns decoys without reuse across the
transaction. A stale snapshot, malformed response, missing locator, or
insufficient eligible pool aborts the spend without retry or legacy fallback.

---

## 2. Ownership boundaries

| Concern | Authoritative code | Responsibility |
|---|---|---|
| Canonical locator and RPC types | [`src/decoy.rs`](../../src/decoy.rs) | Defines `(height, ordinal)`, snapshot metadata, and resolved-output records. |
| Canonical output catalog | [`storage::UtxoSet`](../../src/storage/utxos.rs) | Stores per-height output order and resolves locators. It does not choose decoys. |
| Snapshot binding | [`chain::Blockchain`](../../src/chain.rs) | Produces the current distribution snapshot and rejects a locator lookup if the snapshot block is no longer canonical. |
| Public RPC methods | [`src/rpc/server.rs`](../../src/rpc/server.rs) | Exposes `get_decoy_distribution` and `get_outputs_by_locators`. |
| Age shaping and covered lookup | [`wallet::decoy_selection`](../../src/wallet/decoy_selection.rs) | Owns gamma sampling, minimum-age conditioning, request construction, response validation, and transaction-wide allocation. |
| Input/fee preparation and final signing | [`wallet::send`](../../src/wallet/send.rs) | Selects inputs before lookup, then consumes already allocated rings without reselecting inputs or resampling a shared pool. |
| Ring size and maturity floor | [`src/constants.rs`](../../src/constants.rs) | Supplies consensus-coupled ring size and `min_output_age_at_height`. |

The node supplies deterministic public chain data only. It must not supply
wallet-specific randomness or a preselected candidate pool.

---

## 3. Canonical output locators

An output locator is:

```text
(height: u64, ordinal: u32)
```

For a canonical block, `ordinal` is the position of the output's
`(transaction_hash, transaction_output_index)` key after those keys are sorted
lexicographically. The order is therefore independent of hash-map insertion or
iteration order.

A locator is valid only while the block at `height` remains canonical. A reorg
that replaces that block invalidates the old locator even when the replacement
block contains the same number of outputs.

The node keeps a canonical all-output locator catalog. Entries remain available
after an output is spent because spent outputs are still valid ring members;
they are removed when the creating block is disconnected by a reorg. Wallets
store the locator on each owned UTXO. Older sidecars deserialize the field as
missing, but a selected UTXO without a locator cannot be spent: the user must run
a full rescan so canonical locators are reconstructed without revealing owned
outputs through a separate lookup.

---

## 4. RPC contracts

### `get_decoy_distribution`

Returns a snapshot containing:

- `snapshot_height`;
- the canonical `snapshot_hash` at that height;
- `policy_version`;
- strictly increasing non-empty `(height, output_count)` buckets through the
  snapshot height.

The response contains counts only. It does not choose outputs.

### `get_outputs_by_locators`

Accepts:

```text
[snapshot_height, snapshot_hash, policy_version, locators]
```

The locator list must be duplicate-free and contains at most 256 entries. The
node verifies that the supplied snapshot block is still canonical, resolves
all locators or none, preserves request order, and returns the same snapshot
metadata with each output's public key, commitment, creation height, coinbase
flag, and optional lock height.

Ordinary extension above the snapshot does not invalidate it. Replacement of
the snapshot block does.

`get_decoys` is deprecated and absent from the public REST allowlist. Wallets
and explorer tooling must not fall back to it.

---

## 5. Wallet selection flow

1. Obtain one distribution snapshot.
2. Compute the transaction height as `snapshot_height + 1`, then derive the
   consensus ring size and minimum output age for that height.
3. Prepare the transaction. Input selection, amount checks, and fee estimation
   happen before any locator lookup. Every selected real UTXO must already carry
   a canonical locator.
4. Sample candidate locators locally using the wallet-owned log-gamma policy.
   Exclude every real locator and sample without replacement.
5. Add every real locator, fill the request to
   [`COVERED_LOOKUP_SIZE`](../../src/wallet/decoy_selection.rs), and shuffle the
   complete list.
6. Make exactly one `get_outputs_by_locators` call for the send attempt.
7. Verify policy version, snapshot height and hash, response cardinality,
   locator validity, request order, and each real output's public key and
   commitment.
8. Remove real outputs from the candidate set. Exclude outputs that are too
   young or still locked at the transaction height, and deduplicate public keys.
9. Shuffle the eligible candidates and allocate `ring_size - 1` decoys per
   input without reuse anywhere else in the transaction. Choose each real
   position independently and uniformly.
10. Build and sign from the prepared inputs and allocated rings. The build step
    must not reselect inputs or choose different decoys.

Every final ring member, including every real member, is therefore contained in
the node-observed covered request. The old candidate-set subtraction attack has
no outside-the-request real member to identify.

---

## 6. Gamma age policy

The wallet module is the single source of truth for:

- [`DECOY_GAMMA_SHAPE`](../../src/wallet/decoy_selection.rs);
- [`DECOY_GAMMA_SCALE`](../../src/wallet/decoy_selection.rs);
- bounded age resampling;
- conversion from sampled seconds to blocks using
  [`TARGET_BLOCK_TIME`](../../src/constants.rs);
- nearest non-empty-height selection;
- fixed covered-request size.

A sampled age is measured at the transaction height (`snapshot_height + 1`),
not at the snapshot block itself. This keeps wallet eligibility aligned with
`min_output_age_at_height(current_height)` and avoids rejecting the newest output
that has just reached the age floor.

The policy starts from the public log-gamma fit used as CoinCync's bootstrap
profile. It is not claimed to be an empirical fit to CoinCync spends. Changing
its parameters or mapping requires a versioned policy rollout and independent
distribution review.

---

## 7. Eligibility and uniqueness

A resolved output may be used as a decoy only when all of the following hold at
the transaction height:

1. its age meets `min_output_age_at_height`;
2. its optional `lock_height` has passed;
3. its locator is not one of the transaction's real locators;
4. its public key is not a real input key and has not already been selected;
5. it came from the single validated covered response.

Decoys are unique across all inputs in one transaction, not merely within each
ring. Consensus still independently verifies ring-member existence, maturity,
locks, signatures, and commitments.

---

## 8. Fail-closed behavior

The wallet aborts without a second covered lookup when any of these occur:

- unsupported locator policy version;
- malformed or non-monotonic distribution buckets;
- duplicate or out-of-range real locator;
- too many inputs for the fixed covered request;
- stale snapshot hash;
- partial, reordered, or metadata-mismatched response;
- a real locator resolving to a different public key or commitment;
- too few eligible unique candidates.

There is no uniform-selection fallback, partial-response reuse, silent input
reselection, retry with the same real locators, or `get_decoys` fallback.
Repeated covered requests would make request-intersection analysis possible, so
a failed send attempt discards the snapshot and candidate set.

---

## 9. Reorganizations and storage semantics

A normal chain extension leaves a snapshot valid. A reorg that replaces its
anchor block makes resolution fail before the wallet accepts output data. The
wallet synchronizes and the user retries with a fresh snapshot.

Wallet rewind removes owned outputs from disconnected blocks; replacement scans
compute new locators. Outputs below the fork retain their locators because the
canonical prefix is unchanged.

`UtxoSet::apply_batch` is sequential in memory while readers are excluded by the
chain write lock. It is not a transactional, panic-rollback boundary. Documentation
and reviews must not describe it as atomically recoverable across a panic.

---

## 10. Residual privacy limits

The resolving node sees a timestamped 128-output superset and may correlate it
with a later transaction. The design removes the deterministic set-difference
leak; it does not provide private information retrieval. Statistical spend-age
heuristics inherent to ring signatures also remain. Running a local node and
using privacy-preserving network transport are still preferable.

---

## 11. Conformance checklist

A decoy-selection change must preserve all of the following:

- wallet-owned randomness and gamma sampling;
- one snapshot-bound covered lookup containing every real locator;
- exact response validation with no fallback;
- transaction-wide decoy uniqueness;
- minimum-age evaluation at `snapshot_height + 1`;
- deterministic canonical locator ordering and reorg removal;
- focused tests for distribution conditioning, locator bounds, stale/malformed
  responses, and multi-input uniqueness;
- removal of stale `get_decoys` callers and documentation in the same change.
