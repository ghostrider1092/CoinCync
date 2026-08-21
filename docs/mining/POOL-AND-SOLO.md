# CoinCync Mining: Solo, Self-Hosted Pool, and the Pool Protocol

CoinCync is fair-launch, CPU-only RandomX. Mining is **permissionless**: anyone
can mine solo, and anyone can run a pool for others — the software ships the
whole stack (node-side pool server, a reference client, and the wire protocol).
**No blessed pool, no operator you have to trust, no dev tax on rewards.**

This document is the reference for every mining option and the pool protocol, so
third parties can run pools or write their own miners/pools against CoinCync.

> **Why CoinCync has its own protocol (not xmrig/Monero stratum):** CoinCync's
> PoW folds the nonce through a blake3 pre-hash —
> `RandomX(seed, blake3(anchor ‖ nonce_le ‖ tx_root))` — whereas Monero/xmrig
> patch the nonce directly into a RandomX blob. So an unmodified xmrig cannot
> mine CoinCync; the protocol below is CoinCync-native.

---

## 1. Solo mining — three ways

All three pay **your** address and share rewards with no one.

### a) All-in-one (simplest)
One process = a node that mines to your address.
```
coincync-node --network mainnet --mine <YOUR_ADDRESS> --mine-threads 8
```
The node only ever holds your **public** address (no secret-key custody); you
scan and spend the coinbase later with your wallet. It mines only when synced,
when it has no peers, or on regtest — so it never builds a private fork.

### b) Separate miner + node
```
coincync-node --network mainnet
coincync-rig run-solo --node http://127.0.0.1:19081 --address <YOUR_ADDRESS> --threads 8
```
Use this when you want the miner as its own process (restart / move / scale it
independently of the node).

### c) Self-hosted "solo pool" (aggregate several of *your* machines)
Run your own node with the built-in pool paying **your** address, and point one
or more mining boxes at it:
```
# your node — coinbase → your address:
coincync-node --network mainnet --stratum 127.0.0.1:3333 --stratum-address <YOUR_ADDRESS>

# each mining box (thin client — no full node needed on these):
coincync-rig run-pool --pool <your-node-ip>:3333
```
Every block any box finds pays your `--stratum-address`. No operator, no
reward-splitting — you are the only miner. **Best for 1–5 of your own machines on
a trusted LAN.**

---

## 2. Running a pool for others

The node's `--stratum` server + the protocol below are all a third party needs
to run a pool. The operator sets `--stratum-address` to the **pool's** address;
the coinbase of every block the pool finds is paid there, and the operator
distributes to miners off the pool's share record (see §4).

```
coincync-node --network mainnet --stratum 0.0.0.0:3333 --stratum-address <POOL_ADDRESS>
```

> **Public exposure is gated.** A non-loopback `--stratum` bind requires the
> Stratum exposure acknowledgements (`COINCYNC_STRATUM_PUBLIC_BIND_ACK=1`, a
> `COINCYNC_STRATUM_PASSWORD`, and TLS or a `..._TLS_PROXY_ACK=1` behind
> nginx). Terminate TLS at a reverse proxy for internet-facing pools.

**State of the reference pool (be honest with your miners):**

| Capability | Status |
|---|---|
| Block production (build coinbase → pool address, submit, broadcast) | ✅ done, consensus-correct |
| CoinCync-native `login`/`job`/`submit`/`keepalived` protocol | ✅ done |
| Fork-safe, mempool-synced submission | ✅ done |
| Pool-wide **share difficulty** (job carries a share target below the block target) | ✅ done (`share_difficulty`, default 1000) |
| Per-miner **share accounting** for reward-splitting | ✅ done (difficulty-weighted, `StratumServer::share_tally()`) |
| Per-worker **adaptive vardiff** (per-connection target that tracks its hashrate) | ⛔ not yet (single pool-wide share target) |
| Extranonce partitioning (avoid overlap at large scale) | ⛔ not yet |
| Client auto-reconnect | ⛔ not yet (supervise the client) |

So today the reference pool measures each miner's contribution (weighted shares
per `login`) and pays the pool's own address on every block — enough to run a
**small reward-splitting public pool** where all miners have comparable hashrate.
The gap for a *large* public pool is **per-worker adaptive vardiff** (so a fast
farm and a laptop each submit at a steady rate against a target sized to them)
and extranonce partitioning (roadmap, §5). `src/mining/pool.rs` is the unwired
reference for that vardiff + PPLNS-window layer.

---

## 3. The CoinCync stratum protocol

Newline-delimited JSON-RPC over one TCP connection (optionally TLS). Four methods.

### `login`
```json
→ {"id":1,"method":"login","params":{"login":"<worker>","pass":"<optional>","agent":"...","algo":["cync/rx"]}}
← {"id":1,"jsonrpc":"2.0","result":{"id":"<session>","job":{...},"status":"OK"},"error":null}
```
Authenticates (optional shared password) and returns the current job.

### `job` (pushed by the server on a new tip)
```json
← {"jsonrpc":"2.0","method":"job","params":{
     "job_id":"...", "algo":"cync/rx",
     "anchor":"<64-hex>", "tx_root":"<64-hex>",
     "seed_hash":"<64-hex>", "target":"<64-hex>", "height":N }}
```
The miner computes, for a varying u64 `nonce`:
`RandomX(seed_hash, blake3(anchor ‖ nonce_le ‖ tx_root))` — identical to the
node's `compute_pow_hash(anchor, nonce, tx_root, height)` — and wins when the
result meets `target`. (`seed_hash` is the RandomX VM key for `height`; a client
that calls `compute_pow_hash` can ignore it, since that re-derives it.)

### `submit`
```json
→ {"id":2,"method":"submit","params":{"id":"<session>","job_id":"...","nonce":"<hex-u64>"}}
← {"id":2,"jsonrpc":"2.0","result":{"status":"OK"},"error":null}
```
On a nonce meeting the block target, the server assembles the stored candidate,
submits it to the chain, and broadcasts it.

### `keepalived`
```json
→ {"id":3,"method":"keepalived","params":{"id":"<session>"}}
← {"id":3,"jsonrpc":"2.0","result":{"status":"KEEPALIVED"},"error":null}
```

Anyone can write a miner or a competing pool against this. `coincync-rig
run-pool` is the reference client; the server is the node's `--stratum`.

---

## 4. Payout (pool operators)

Block rewards land at the pool's `--stratum-address`. Distribution to miners is
the operator's responsibility and lives *off* the consensus layer — you pay
miners from the pool wallet based on their contribution.

The server now **measures** contribution: `StratumServer::share_tally()` returns
a difficulty-weighted valid-share count per miner `login` (conventionally
`<miner_address>.<worker>`). An operator distributes a matured block's coinbase
in proportion to these weights — a simple proportional/PPLNS split. What is *not*
yet automated is per-worker **adaptive vardiff**: every miner shares the one
pool-wide `share_difficulty`, so the tally is only fair when miners have
comparable hashrate. For a farm with wildly mixed hardware, add vardiff first
(§5) — `src/mining/pool.rs` is the reference for that layer.

---

## 5. Roadmap for larger pools

Ordered upgrades to move the reference pool from "great for my boxes" to
"community-runnable public pool", then to the decentralized model:

1. ~~**Pool-wide share target**~~ — ✅ done: the job carries a share target
   below the block target (`share_difficulty`), so miners submit shares, not
   just blocks.
2. ~~**Share accounting**~~ — ✅ done: `StratumServer::share_tally()` returns
   difficulty-weighted valid shares per miner `login`, the input to any payout
   scheme.
3. **Per-worker adaptive vardiff** — give each connection its *own* share target
   and adjust it to its measured hashrate, so a laptop and a farm both submit at
   a steady rate and the share tally is fair across mixed hardware.
4. **Extranonce partitioning** — hand each miner a disjoint nonce region so a
   large farm doesn't waste hashrate on overlap.
5. **Client auto-reconnect** — the client reconnects on a dropped pool link.
6. **Fold the PPLNS window** (`src/mining/pool.rs`) into the stratum server —
   time-windowed share weighting on top of the tally above — then delete that
   unwired reference module.
7. **P2Pool-style decentralized pool** (`docs/P2POOL_INTEGRATION.md`, post-
   mainnet) — the **preferred** large-group answer: no operator, no custody,
   rewards direct to finders. For a privacy/fair-launch coin, decentralized
   mining is the goal; large *centralized* pools are a 51%/censorship and
   metadata-privacy risk (cf. Monero's MineXMR voluntarily shutting down near
   ~44% of network hashrate, and the community's push to P2Pool).

The software enables pools of any size; the **values** point toward solo +
decentralized. Ship the tools, keep hashrate distributed.
