# CoinCync — Metrics & Observability

CoinCync full nodes expose Prometheus/OpenMetrics on `GET /metrics`, served on
`rpc_port + 1` (default RPC `18081`/`28081`/`19081` → metrics `18082`/`28082`/
`19082`). Standard scrape, no push.

Two kinds of series:

- **State gauges** — refreshed every 5s from live `chain.stats()` / mempool /
  P2P state by the node's snapshot task.
- **Event counters/histograms** — incremented at the moment an event happens.

All series are pre-registered at startup, so a fresh node exposes them at
`0`/empty immediately (dashboards see the series exist before the first event).

---

## Series reference

### Consensus / chain state
| Metric | Type | Meaning |
|---|---|---|
| `coincync_chain_height` | gauge | Current tip height |
| `coincync_tip_age_seconds` | gauge | Seconds since the tip block timestamp (liveness) |
| `coincync_difficulty` | gauge | Current block difficulty |
| `coincync_total_difficulty` | gauge | Cumulative chain work |
| `coincync_total_transactions` | gauge | Total on-chain transactions |

### Emission / supply (0%-tax fair-launch transparency)
| Metric | Type | Meaning |
|---|---|---|
| `coincync_circulating_supply_atomic` | gauge | `total_supply − burned`, atomic units |
| `coincync_total_supply_atomic` | gauge | Total emitted, atomic units |
| `coincync_fee_burned_total_atomic` | gauge | Cumulative fees burned |
| `coincync_block_reward_atomic` | gauge | Current per-block reward |

### Sync / IBD
| Metric | Type | Meaning |
|---|---|---|
| `coincync_is_synced` | gauge | 1 synced, 0 not |
| `coincync_blocks_behind` | gauge | Best-known height − our height |
| `coincync_sync_progress_percent` | gauge | Sync progress [0,100] |

### P2P
| Metric | Type | Meaning |
|---|---|---|
| `coincync_peers` | gauge | Connected peers |
| `coincync_peers_inbound` / `_outbound` | gauge | In/out split (0 until accessor lands) |
| `coincync_peer_bans_total` | counter | Cumulative bans |
| `coincync_peer_handshake_seconds` | histogram | Noise handshake time |

### Mempool
| Metric | Type | Meaning |
|---|---|---|
| `coincync_mempool_size` | gauge | Tx count |
| `coincync_mempool_bytes` | gauge | Size in bytes |
| `coincync_mempool_rejects_total{reason}` | counter | Rejections by reason (`mempool_full`, `invalid_transaction`, `invalid_state`, `invalid_message`, `serialization`, `crypto`, `other`) |
| `coincync_tx_admit_to_mempool_seconds` | histogram | Full-verify admission time |

### Reorg / finality
| Metric | Type | Meaning |
|---|---|---|
| `coincync_reorg_total` | counter | Cumulative reorganizations |
| `coincync_reorg_depth` | histogram | Depth distribution per reorg |
| `coincync_orphan_blocks_total` | counter | Orphan/stale blocks |
| `coincync_block_interval_seconds` | histogram | Interval between accepted blocks |

### PoW / storage
| Metric | Type | Meaning |
|---|---|---|
| `coincync_randomx_hash_seconds` | histogram | One RandomX hash |
| `coincync_block_receive_to_tip_seconds` | histogram | Block-received → tip-updated |
| `coincync_utxo_set_size` | gauge | UTXO count (0 until accessor lands) |
| `coincync_db_size_bytes` | gauge | On-disk size (0 until accessor lands) |

### Privacy relay (Dandelion++)
`coincync_dandelion_*` — epoch rotations, embargo fluffs, stem relays, fluff
broadcasts, stempool size.

---

## Suggested alerts (each maps to a real past incident class)

- **Node wedged / not syncing** — `coincync_is_synced == 0` for >10m, or
  `coincync_blocks_behind` rising. *(IBD orphan-loop, fleet/multi-peer IBD wedge.)*
- **Tip stalled** — `coincync_tip_age_seconds > 3 × target_block_time`.
- **Reorg storm** — `increase(coincync_reorg_total[15m]) > 3`, or
  `histogram_quantile(0.99, coincync_reorg_depth) > 10`. *(Reorg deadlock,
  runaway fork.)*
- **Difficulty oscillation** — sharp `coincync_difficulty` swings, or
  `coincync_block_interval_seconds` far from target. *(Small-chain difficulty
  spike.)*
- **Peer starvation** — `coincync_peers < 2`. *(Explorer peer-wedge.)*
- **Mempool congestion** — `coincync_mempool_bytes` near cap, rising
  `coincync_mempool_rejects_total{reason="mempool_full"}`.

## Known gaps (reported as 0, honestly)

The inbound/outbound peer split (`coincync_peers_inbound` /
`coincync_peers_outbound`) is reported as `0` pending a P2P accessor — the
series are declared so dashboards stay stable, and will light up when the
accessor lands. (`coincync_utxo_set_size` and `coincync_db_size_bytes` are now
wired: UTXO count from `chain.utxo_count()`, DB size from an on-disk walk of the
database directory refreshed ~every 60s.)
