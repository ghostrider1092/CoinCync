# Runbook: mainnet genesis bootstrap — self-mine the first ≥100 blocks

**Status: MANDATORY launch step. Do this BEFORE opening the mainnet P2P network to the public.**

## Why (the security window this closes)

Consensus finding **C-1** (pre-mainnet audit 2026-08-16): below
`STRICT_RING_MEMBER_HEIGHT` (= **100**), transaction validation *skips* the
check that a ring member exists on-chain. This is a deliberate "bootstrap gap"
— a brand-new chain has too few outputs to form full decoy rings, so early
honest spends are allowed to reference not-yet-existent ring members.

The side effect: on blocks **1–99**, an attacker can fabricate **all** ring
members of a transaction with an arbitrary hidden-amount commitment. Because
the input value in RingCT is pinned to reality *only* by a ring member's
on-chain commitment, skipping that check lets the attacker **mint coins from
nothing** (CLSAG, range proofs, and the balance proof all still verify). The
minted outputs become permanent, spendable value once the chain passes
height 100.

`mainnet.rs` checkpoints only genesis and `CONSENSUS_CHECKPOINTS` is empty at
launch, so nothing else protects blocks 1–99. The window is only reachable if a
public miner or a public tx can land in those blocks — i.e. only if the network
is open before height 100.

## The fix (operational — no consensus-code change needed)

Mine the first **≥ 100 blocks yourself, on an isolated network, before any
external peer can connect.** By the time the public joins, the strict
ring-member check is already active for every new block, and no attacker
transaction ever entered blocks 1–99.

### Procedure

1. **Bring up the genesis node with peering disabled.**
   ```
   coincync-node --network mainnet --data-dir <mainnet-data> --no-peers \
     --p2p-bind 127.0.0.1:<port> --rpc-bind 127.0.0.1:<rpc>
   ```
   `--no-peers` guarantees no inbound/outbound connections during bootstrap.
   Do **not** publish the peer-snapshot / DNS seeds yet.

2. **Mine to at least height 110** (100 + a safety margin) to your own wallet:
   ```
   coincync-rig run-solo --node http://127.0.0.1:<rpc> --address <CYNC-addr> \
     --network mainnet --threads <n>
   ```
   Watch height via `get_info` until `height >= 110`, then stop the rig.

3. **Verify the guard is now closed** before opening up:
   ```
   curl -s -X POST http://127.0.0.1:<rpc> -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":{}}' \
     | grep -oE '"height":[0-9]+'
   # height must be >= 100 (STRICT_RING_MEMBER_HEIGHT)
   ```

4. **Only now** open the network: publish DNS seeds / the signed peer snapshot
   (see `runbook-bootstrap-ceremony.md`), set `--external-ip`, and drop
   `--no-peers`. External peers now sync a chain whose blocks 1–99 were mined
   solely by you.

### Optional belt-and-suspenders (needs a hash-lock re-lock)

Hard-code the observed block-1..100 hashes into `CONSENSUS_CHECKPOINTS`
(`constants.rs`) so any node rejects a tampered variant of the bootstrap
range even in an eclipse scenario. This edits a hash-locked file, so it
requires the `update-critical-hashes` re-lock (elevation). The self-mine step
above already closes the window; treat the checkpoint as defense-in-depth.

## Do NOT instead set `STRICT_RING_MEMBER_HEIGHT = 0`

Turning the strict check on from block 1 re-introduces the original problem it
was added to avoid: early honest wallets can't form valid decoy rings when too
few outputs exist yet, so early legitimate spends would fail. It also edits a
hash-locked constant. The operational self-mine is the correct fix.

## Sign-off checklist

- [ ] Genesis node started with `--no-peers`, DNS seeds unpublished.
- [ ] Chain mined to height ≥ 110 by the launch operator only.
- [ ] `get_info` confirms height ≥ 100 before opening.
- [ ] (optional) blocks 1–100 checkpointed in `constants.rs` + re-locked.
- [ ] Peer snapshot / DNS seeds published, `--no-peers` removed — network opened.
