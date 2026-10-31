# CIP-draft: Rung-2 UTXO state-root commitment (trustless light-sync foundation)

Status: **connector built, inert.** The mechanism lives in
`src/state_root_connector.rs` (feature `state-root-commit`), declared from
`lib.rs` so it does not modify the hash-locked `consensus/mod.rs`, as a
fail-closed, default-OFF policy slot. It touches **none** of the hash-locked
consensus core (`validation.rs`, `header.rs`, `constants.rs`) and changes
nothing on the live chain. Activation (real enforcement) is a separate,
audited, planned fork — **not** performed yet.

## Motivation

The light-sync trust ladder:

1. hardcoded checkpoints — trust the binary,
2. operator-signed tip — trust a key,
3. **Rung 1** miner-voted checkpoints — trust honest-majority + a liveness bet,
4. **Rung 2 (this)** committed state root — trust *block validity itself*.

(A Rung-3 "zk validity proof" was evaluated and **removed** — it could not be
completed on available hardware; Rung 2 is the trustless path CoinCync uses.)

Rung 2 is the trustless foundation: if the chain commits to its UTXO-set state
root as an **enforced** consensus value, then a light client trusts the state by
trusting that the block is valid at all — no key, no committee, no vote, no
liveness assumption. Every full node already rejects an invalid block; Rung 2
makes "wrong state root" one of the invalidity conditions. Rung 3 later binds its
succinct proof to this same root, so Rung 2 is also the clean base for the zk
light client.

## The committed value

The **canonical UTXO-set commitment** the node already computes —
`Blockchain::utxo_commitment_at_tip()` (→ `UtxoSet::commitment_hash()`), a
deterministic, order-independent hash of the transparent output catalog + spent
key-image set — taken at the block's resulting tip. Two honest nodes on the same
tip compute the same value.

Performance note: `commitment_hash()` hashes the whole set. For per-block cost an
**incremental accumulator** is preferable (the `zk_stf` spike models an LtHash
that updates in O(touched outputs)); adopting one is an implementation detail of
activation, not a change to what is committed. The shielded pool carries its own
commitments and stays outside this transparent root.

## The connector (what is built now)

A pure, total policy slot — no chain-state access, so it cannot perturb the
locked validation path:

- `StateRootPolicy` = `Observe` (default; compute+compare, **never reject**) or
  `Enforce { activation_height }` (defaults to `NEVER = u64::MAX`).
- `check(policy, height, committed, actual) -> StateRootCheck` ∈ {`Inactive`,
  `Match`, `Mismatch`, `Missing`}; `rejects()` is true only for `Mismatch`/
  `Missing`, and only when enforcing at/after activation. **Fail-closed:** a
  missing commitment under enforcement is a rejection, never a pass.
- **Carriage = coinbase `extra` TLV** (`embed_in_extra`/`extract_from_extra`,
  tag `0x53`), so populating the root needs **no block-header format change and
  forks nothing**.

Tested: Observe never rejects; below activation inert; match/mismatch/missing
behave; the TLV round-trips, skips foreign entries, and rejects truncated input.

## Activation plan (a later, audited fork — NOT done here)

1. Miners populate the coinbase-extra state-root TLV (soft, additive — old nodes
   ignore it; no fork from population alone).
2. After a maturity window, set `Enforce { activation_height = H }` at a chosen
   fork height `H` and wire the **single** `check(...)` call into the block
   connect path, rejecting on `rejects()`.
3. `H` is far enough out that the miner set is populating roots well before
   enforcement (same ENABLE→ENFORCE gap pattern as CIP-011 rolling finality).
4. Optionally promote the commitment from coinbase extra to a first-class,
   PoW-bound header field at the fork (cleaner long-term; a true format change,
   hence only at the fork).

This activation is **post-audit** and consensus-gated — never applied
unilaterally to the live testnet.

## Security model

Before activation: nothing changes; `Observe` is consensus-neutral. After
activation: the state root is enforced by **every full node**, so its authority
is block validity — no trusted party at all. A light client (or a Rung-3 proof)
that reads the committed root inherits that guarantee. The only assumption is the
one already securing the chain (honest-majority PoW produces valid blocks).

## Scope boundary

This CIP/connector deliberately does **not**: edit `validation.rs`/`header.rs`/
`constants.rs`, enforce anything on the live chain, change block hashes, or set a
real activation height. Those are the activation step, gated behind audit and a
planned fork.
