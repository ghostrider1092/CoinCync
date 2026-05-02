# P2Pool Integration — design memo

**Status:** post-mainnet milestone (NOT for the May 2026 testnet launch).
**Estimated effort:** 6–8 weeks of focused engineering + 2 weeks private-testnet validation.
**Owner:** TBD.
**Last reviewed:** 2026-05-02.

## Why

Every PoW chain that ships without a decentralized pool option goes
through a centralized-pool era it later regrets — pool operators
accumulate hashrate, miners hand them custody of rewards, the chain
becomes a 3-pool oligopoly. Monero spent years there before sech1
shipped P2Pool, which fixed it cleanly: a sidechain that merge-mines,
pays directly via coinbase, and has no pool admin.

Shipping P2Pool-equivalent on day-one of CoinCync mainnet would skip
the centralized era entirely. The cost is real — it's not "fork the
repo" easy — but it's the right architectural bet.

## Reference

- Source: <https://github.com/SChernykh/p2pool>
- License: MIT
- Language: C++17, ~15K LOC
- Dependencies: libuv, libcurl, libzmq, RandomX, monero-project's
  cryptonote utility headers
- Author: SChernykh ("sech1")

## CoinCync compatibility audit (2026-05-02)

| Requirement | CoinCync status | Action |
|---|---|---|
| RandomX PoW | ✅ ready | none |
| `get_block_template` RPC | ✅ ready | [src/rpc/server.rs:690](../src/rpc/server.rs#L690) |
| Stealth addresses (Ristretto255) | ✅ ready | derivation scheme is Monero-compatible enough |
| Address format (`tCYNC.../CYNC...`) | ✅ ready | well-defined prefix |
| **Coinbase output count** | 🔴 **HARD BLOCKER** | [src/consensus/validation.rs:369](../src/consensus/validation.rs#L369): `max_outputs = 16`. P2Pool needs ~50–200+ recipients in one coinbase. **Consensus rule change.** |
| ZMQ pub/sub for new-block events | 🟡 missing | Either add ZMQ to `coincync-node` or adapt P2Pool to poll the JSON-RPC `get_info` for tip changes |
| Coinbase tx with arbitrary recipient list | 🟡 partial | Output construction is fine; just blocked by the count limit above |
| Difficulty algorithm tunable for sidechain | ✅ ready | [src/consensus/difficulty.rs](../src/consensus/difficulty.rs) is parameterized |

## The 16-output cap is the show-stopper

[src/consensus/validation.rs:369–376](../src/consensus/validation.rs#L369):

```rust
let max_outputs = 16;
if coinbase.outputs.len() > max_outputs {
    result.add_error(format!(
        "Coinbase has too many outputs: {} (max {})",
        coinbase.outputs.len(),
        max_outputs
    ));
}
```

Why this matters: P2Pool's PPLNS window is 2160 blocks (~6 hours). A
typical share-block has 50–200 active miners depending on hashrate
distribution. When a P2Pool block also meets mainchain difficulty, the
mainchain coinbase pays everyone in the window — that's a coinbase
with one output per active miner. We currently cap that at 16.

The cap exists for a reason — coinbase outputs become permanent UTXOs;
unbounded outputs are a chain-bloat vector. But 16 is too low for
P2Pool to function. Reasonable revised cap: **256 outputs per
coinbase**, with the existing dust-protection check
([validation.rs:381](../src/consensus/validation.rs#L381)) keeping
miners honest about reward per output.

This is a consensus rule change. It must:

1. Be activated at a planned future height, not retroactively.
2. Pair with documentation of the new max in
   [src/constants.rs](../src/constants.rs) and the spec doc.
3. Pass the existing `test_coinbase_validation` test suite plus a new
   test that exercises 256-output coinbase acceptance.
4. Be in the binary BEFORE the activation height — every node needs
   to apply the new rule simultaneously. Consensus splits otherwise.

## Implementation plan

### Phase 0 — pre-work (1 week)

- Raise coinbase `max_outputs` from 16 to 256 with an activation
  height (probably mainnet-launch height, since we have time).
- Add ZMQ pub/sub to `coincync-node`: publish `block-new` topic on
  every accepted block, payload = block hash + height. New crate
  dependency: `zeromq` or `tmq`.
- Document the new RPC + ZMQ contract.

### Phase 1 — fork sech1's P2Pool (2 weeks)

Fork into `coincync-pool` repo. Mechanical changes:

- Chain identity: replace Monero genesis hash, network magic, port
  numbers in `src/p2p_server.cpp` and `src/sidechain.cpp`.
- RPC binding: point at our `get_block_template` and our new ZMQ
  topic instead of monerod's.
- Coin parameters: block reward formula, decimal places (we use 12),
  address prefix in `src/params.cpp`.
- Difficulty: target 120s parent-chain blocks, ~10s sidechain blocks.

### Phase 2 — cryptographic adapter (2 weeks)

P2Pool relies on Monero's specific deterministic key-derivation for
proving share ownership. Our Ristretto255 stealth addresses need an
adapter:

- Reimplement P2Pool's `wallet/address` against our
  [src/wallet/address.rs](../src/wallet/address.rs).
- The PPLNS payout calculation in `src/sidechain.cpp` needs to use
  our reward formula and atomic units.
- Share difficulty fraction: probably 1/10000 of mainchain difficulty
  initially, tunable based on observed hashrate.

### Phase 3 — private testnet validation (2 weeks)

- Spin up a dedicated CoinCync regtest with our `coincync-node`s and
  3+ instances of the forked `coincync-pool`.
- Verify share-block production, sidechain consensus, payout math,
  uncle-block handling.
- Property-test against malicious miner scenarios: under-paying,
  share-stealing, fake share-difficulty.
- Test mainnet "first P2Pool block payout" specifically — that one
  block carries the entire 6-hour window's reward distribution.

### Phase 4 — mainnet rollout (ongoing)

- Ship `coincync-pool` binary alongside the wallet.
- Document running it ("attach to your existing CoinCync node, point
  miner at port X").
- Operate one bootstrap P2Pool node ourselves; let community add
  more as they come online.

## What we are NOT doing

- **Not** porting P2Pool before mainnet launch. Testnet ships May 2026
  with solo + traditional pool support only.
- **Not** building our own decentralized pool from scratch — sech1's
  design is well-tested and licensed permissively. Reinventing it is
  hubris.
- **Not** running a centralized pool ourselves to bridge the gap. If
  the community wants a centralized pool while P2Pool ships, they can
  run one — but CoinCync the project doesn't operate one. Same posture
  as Monero core team.

## Open questions

- Do we want to support merge-mining BETWEEN testnet and mainnet
  P2Pool sidechains, or are they fully separate? (Probably separate;
  testnet sidechain has no economic value.)
- Share-difficulty floor: too low and miners spam shares; too high
  and small miners get nothing. P2Pool's 1/10000 is a starting point;
  watch for share frequency in private testnet.
- ZMQ vs RPC polling: ZMQ adds a new public-facing port and dep;
  polling adds latency. Lean toward ZMQ if we're going to support
  external pool software anyway.

## References

- Monero P2P architecture: `src/p2p/net_node.inl`
- 2025 Monero topology study (~14 super-nodes, 82% of connections):
  ResearchGate
- P2Pool design rationale: <https://github.com/SChernykh/p2pool/blob/master/docs/PROTOCOL.md>
- Bitcoin original P2Pool (orphan-prone, what sech1 improved on):
  <https://github.com/p2pool/p2pool>
