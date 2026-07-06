# tick — passive network agents that quest, latch on, and feed

**Status:** DESIGN — not yet implemented. Operator sign-off required before Phase 1 code lands.

**Author:** Claude Opus 4.7 (drafted 2026-07-05 based on operator request)

**Related work:**

- [runbook-hard-finality-stuck](../operations/runbook-hard-finality-stuck.md) — manual recovery this feature partially automates
- [project_hard_finality_partition_2026_07_04](memory) — source incident for the RescueTick use case
- [feedback_snapshot_procedure](memory) — chaindata-tarball procedure the RescueTick codifies

---

## Executive summary

A "tick" is a small, purpose-scoped agent that runs alongside (or embedded in) a coincync node. Ticks are **passive** — they don't drive workflows; they wait for signals, then act. They have three concrete responsibilities that map cleanly to the biological metaphor:

| Bio behavior | Software behavior |
| --- | --- |
| **Quest** — perch on grass, wait for signals | Passively monitor: scrape metrics, probe RPCs, listen to gossip |
| **Latch on** — persistent attachment when a target brushes by | Establish a durable connection to the target that triggered the quest |
| **Feed** — deliver from stored reserves | Push a payload the target needs (chaindata, alerts, re-broadcasts) |
| **Detach** — clean release when done | Close the connection, prune state, return to quest mode |

Unlike biological ticks, a coincync tick is a **good** vector: it delivers value (chain recovery, alerts, propagation), never pathogens.

## The three modes

### 1. RescueTick

**Quest for:** stalled peers with divergent chain state that can't recover via p2p.
**Latch onto:** the stalled peer's RPC surface (authenticated).
**Feed:** the canonical chaindata segment.

**Concrete use case (2026-07-04 pattern):** fleet peers agree with each other on a stalled chain; a mining host has a heavier chain the fleet refuses to accept via reorg (log line `Rejecting reorg at depth <N>: exceeds absolute maximum 100 (hard finality)`). The stall is 20+ hours; operators paged; recovery is a chaindata tarball swap done by hand.

RescueTick automates that:

1. **Quest phase**: RPC-poll every host in `fleet-config.json` every ~5 min. Read `height`, `difficulty`, `tip_hash`, `is_synced`.
2. **Trigger**: if K hosts agree on state A, and ≥1 host has a heavier chain (higher `difficulty`, > K blocks ahead), the tick has "sensed a brush by."
3. **Verify**: fetch a sample header from the heavier-chain host, re-check its PoW locally, and only proceed if it's genuinely canonical.
4. **Latch phase**: open an authenticated RPC channel to each stalled host in a specific order (least-critical first, from the runbook: `explorer → api → relay1 → relay2 → randomx → seed3 → seed2 → seed1`).
5. **Feed phase**: for each host in order, stop the node, receive the chaindata tarball into `/var/lib/coincync/testnet.tick-recovery/`, verify SHA against the source host's live signature, atomic-swap with the stale `/var/lib/coincync/testnet/`, restart. Wait for tip to catch up + `peer_count ≥ 3` before proceeding to next host.
6. **Detach phase**: close the RPC channel. Emit a completion event (`docs/operations/incidents/` gets a new file automatically).

**Not doing:** RescueTick does NOT flip finality gates, does NOT change consensus, does NOT hot-swap running code. It only pushes chaindata to peers that WOULD accept the heavier chain if they could see it.

### 2. HealthTick

**Quest for:** anomalies in node/network health metrics.
**Latch onto:** alert channels (Discord webhook / Grafana / stdout / email).
**Feed:** structured alert report with severity + context.

**Concrete use case (P1 #8 from BACKLOG):** we want "Grafana dashboard reading Prometheus :28082; Discord webhook on `is_synced=false OR tip_age>600s`" — currently owner=operator, not implemented in code. HealthTick can be the implementation.

Anomaly classes:

- **tip_age > 600s** (from BACKLOG P1 #8) — chain stalled
- **peer_count < 3 on any host** — mesh dissolving
- **height drift > 10 blocks between fleet hosts** — partition forming
- **`difficulty` delta ≥ 5% between two hosts** — hard-finality-stuck pattern
- **RAM usage > 90% or swap > 20%** — OOM about to fire (memory `project_node_min_ram_8gb`)
- **RandomX hashrate drop > 50%** — miner failing
- **Disk > 90% on `/var/lib/coincync`** — chaindata about to fill disk

Each anomaly has a severity (`info | warn | critical`) and a routing rule (which channel gets which severity). Severity + rate-limits keep the tick from being a Discord-spam vector.

**Not doing:** HealthTick does NOT self-heal. It only reports. RescueTick is where actual healing happens; keeping the two separate is deliberate — a single agent that watches AND fixes is a huge blast radius when it misfires.

### 3. PropagationTick

**Quest for:** blocks/txs known locally but not propagated to some peers.
**Latch onto:** the p2p mesh of under-informed peers.
**Feed:** re-broadcast the missing block/tx.

**Concrete use case:** partial complement to PR #176 (orphan-body-in-pool). PR #176 fixes the WITHIN-node case: don't drop the orphan body. PropagationTick fixes the ACROSS-node case: a peer received a block, but didn't re-gossip it (e.g., because its outbound queue was full, or `tx_absence_cache` misses).

Quest signals:

- Every N seconds, sample K random blocks from local tip - 100 range.
- For each sampled block, ask ≥2 peers "do you have this?" via a lightweight query (could reuse `GetData` + rely on the NEW `NotFound` message from PR #177).
- If a peer says NotFound for a block that's not too old (age < 24h), that's a propagation gap.

Feed:

- Re-broadcast the block to that peer via `BlockData`.
- Optionally, gossip it to K-1 other peers in case the gap is wider.

**Rate limits:** hard cap the tick at N re-broadcasts per hour per peer. A hyperactive PropagationTick becomes indistinguishable from a spam bot.

**Not doing:** PropagationTick does NOT bypass peer scoring, does NOT re-broadcast blocks a peer already `NotFound`-ed within the TTL window (PR #177's cache), does NOT re-broadcast blocks known-invalid.

## Cross-blockchain portability

Operator requirement: this feature should be reusable by other blockchains. That means the tick core knows NOTHING about coincync-specific types like `Block`, `Hash`, `PeerId`, `Chainstate`, etc.

Solution: a `ChainAdapter` trait that abstracts everything a tick needs from a host chain, plus a `CoincyncAdapter` implementation in this repo. Other chains write their own adapter.

> **Privacy amendment (below in [Privacy considerations](#privacy-considerations-privacy-blockchain-constraint)):** the trait definition here is the *base* shape. The privacy section adds required methods (`is_stem_phase`, `stem_relay_peers`, `aggregate_fleet_health`, `deployment_mode`) that every adapter — including cross-chain adapters — MUST implement. Read that section before implementing an adapter.

```rust
/// Trait each host blockchain implements. Tick core depends only on this.
pub trait ChainAdapter: Send + Sync + 'static {
    /// Canonical wire-format identifier for a block. 32 bytes for
    /// coincync/bitcoin/etc.; opaque to the tick.
    type BlockId: AsRef<[u8]> + Clone + Send + Sync + std::fmt::Debug + 'static;

    /// Opaque handle to a peer.
    type PeerId: Clone + Send + Sync + std::fmt::Debug + 'static;

    /// Report the local node's view of chain state — used by all three
    /// tick modes for the "quest" phase.
    fn tip_state(&self) -> ChainTipState<Self::BlockId>;

    /// List the fleet's peers. Ticks that need to poll multiple hosts
    /// (RescueTick, HealthTick) use this.
    fn fleet_peers(&self) -> Vec<FleetPeer>;

    /// RPC-poll a specific peer for its tip. Used to detect divergence.
    fn probe_peer(&self, peer: &FleetPeer) -> Result<ChainTipState<Self::BlockId>>;

    /// Snapshot chaindata to a tarball. Used by RescueTick.
    /// Blocking; caller wraps in spawn_blocking if async.
    fn snapshot_chaindata(&self, dest: &std::path::Path) -> Result<Snapshot>;

    /// Apply a chaindata snapshot atomically. RescueTick delivers this
    /// to stalled peers.
    fn apply_chaindata(&self, source: &std::path::Path) -> Result<()>;

    /// Re-broadcast a block by ID. Used by PropagationTick.
    fn rebroadcast_block(&self, block_id: &Self::BlockId, to: &Self::PeerId) -> Result<()>;

    /// Query health metrics — RAM, disk, hashrate, mempool size, etc.
    /// HealthTick consumes this.
    fn health_snapshot(&self) -> HealthSnapshot;
}

pub struct ChainTipState<Id> {
    pub height: u64,
    pub difficulty: u128,
    pub tip_id: Id,
    pub is_synced: bool,
    pub peer_count: u32,
    pub tip_age_secs: u64,
}

pub struct FleetPeer {
    pub name: String,
    pub rpc_url: String,
    pub role: String,   // "seed" | "miner" | "relay" | "api" | ...
}

pub struct Snapshot {
    pub tarball_path: std::path::PathBuf,
    pub sha256: [u8; 32],
    pub source_tip: Vec<u8>,     // opaque BlockId bytes
    pub compressed_bytes: u64,
}

pub struct HealthSnapshot {
    pub ram_used_pct: u8,
    pub disk_used_pct: u8,
    pub swap_used_pct: u8,
    pub hashrate_hs: Option<u64>,
    pub mempool_txs: usize,
    pub cpu_used_pct: u8,
    pub uptime_secs: u64,
}
```

Every non-primitive type in the tick core (blocks, peers, chainstates) parameterizes over the adapter's associated types. This keeps the tick core a pure algorithm crate.

## Where do ticks run?

Options considered:

| Placement | Pros | Cons |
| --- | --- | --- |
| Embedded in `coincync-node` | Simple deploy; shared config | Node crash = tick crash; tick bug = node bug; single blast radius |
| **Sidecar binary on the same host** ← **recommended** | Independent lifecycle; can restart tick without restarting node; smaller blast radius | New systemd unit; new RPC surface between them |
| Separate host entirely | Zero-impact on node performance | Yet another host to provision + monitor; latency for RescueTick feeds |

**Recommendation: sidecar binary.** New systemd unit `coincync-tick.service` on each fleet host. Talks to the local `coincync-node` via loopback RPC. Configurable to run any/all of the three modes.

Rationale from BACKLOG rule 4 ("Consensus-touching changes need a consensus change session"): keeping ticks OUT of the node binary means they can't accidentally introduce consensus-affecting bugs. Sidecar isolation is a hard boundary.

## Trust and verification model

Ticks operate on peer trust that could go wrong. Attack surface:

### RescueTick attacks

**Threat:** hostile RescueTick feeds a wrong chain to healthy peers.

**Defense:** The stalled peer doesn't blindly accept the fed chaindata. RescueTick delivers via the same RPC that operators use for manual tarball recovery — the peer's node CHECKS the received chaindata using its own validator. If PoW / consensus rejects, the swap fails and the peer stays on the pre-swap state (kept as `testnet.stalled-<timestamp>` per the runbook).

**Threat:** RescueTick's own quest phase misreads which chain is canonical.

**Defense:** the "verify" step (see RescueTick §3) locally re-runs PoW on a sample header from the claimed-canonical host BEFORE proceeding. If PoW check fails, tick refuses to feed anything and emits a HealthTick-style alert instead.

### HealthTick attacks

**Threat:** hostile HealthTick spams alert channels to hide real alerts.

**Defense:** rate limits per anomaly class, hard cap on total alerts/hour, dedup identical alerts within 15 min window. Same discipline as `runbook-peer-partition.md`'s escalation criteria.

**Threat:** hostile HealthTick under-reports (silently ignores real anomalies).

**Defense:** tick emits a heartbeat every 60s to a "tick alive" channel. Missing heartbeats page the operator. Not a full defense — if the tick is compromised, so is its heartbeat — but this is the same trust model as any monitoring agent.

### PropagationTick attacks

**Threat:** hostile PropagationTick amplifies double-spends or DoS traffic.

**Defense:** tick uses the node's own mempool + validation. It CAN'T inject an invalid tx; the local validator rejects it before it's re-broadcastable. Rate limits (N re-broadcasts / hour / peer) prevent DoS amplification.

**Threat:** propagation tick becomes a fingerprinting vector (adversary maps tick behavior to identify nodes).

**Defense:** stochastic behavior (Poisson-distributed timings, per-node random offset for the quest schedule) so ticks look statistically identical across the fleet, not deterministically-timed.

## Privacy considerations (privacy-blockchain constraint)

Operator requirement (2026-07-05 addition): the tick feature must work on a **privacy blockchain**. Coincync's threat model bans anything that leaks transaction contents, wallet identities, or per-node behavioral fingerprints. That constraint reshapes every mode; ticks that would be safe on Bitcoin can be privacy-catastrophic on coincync.

Every design decision below is a HARD requirement — Phase 1 code MUST enforce these, not offer them as opt-in. A tick that leaks privacy defeats the entire chain design.

### What ticks MUST NOT do

1. **NEVER touch stem-phase transactions.** Coincync uses Dandelion++ (see `src/network/dandelion.rs`). Stem-phase txs are known ONLY to the originating node and one relay peer; broadcasting them to more peers is a direct deanonymization vector. PropagationTick MUST consult the local `DandelionRouter` state before touching any tx and refuse to operate on anything not yet fluffed.

2. **NEVER expose fleet topology in tick notices.** A notice saying "randomx-2 → seed1 recovery" reveals that `randomx-2` is a mining host + which peer it prefers to feed. Notices MUST be aggregate: "1 host feeding 8 hosts" — no host identifiers, no per-peer IPs, no per-peer timings.

3. **NEVER poll on fixed intervals.** A tick that RPC-polls every peer at exactly T+0s, T+300s, T+600s creates a network-layer timing fingerprint uniquely identifying tick-enabled nodes. Every quest interval MUST be Poisson-distributed with a per-instance random offset, matching the existing Dandelion++ epoch pattern (see `DANDELION_EPOCH_JITTER_SECS = 30`).

4. **NEVER correlate peers across quest cycles by identity.** A tick that logs "peer 0xabcd was here at T+0 and T+300" is building a linkage database. Peers MUST be identified by ephemeral per-quest UUIDs internally; the tick's persistent state stores anomaly *counts* per role, not per peer.

5. **NEVER echo received notices back to gossip.** A wallet that receives a tick notice and then broadcasts an ACK creates a "who has notice X" oracle. Notices are receive-only; the only network signal a wallet emits is its normal gossip participation.

6. **NEVER include amounts, key images, ring members, or stealth addresses in notices.** These are consensus-visible but privacy-sensitive; putting them in an operator-readable notice moves them into a channel with weaker access controls.

7. **NEVER cross the wallet boundary.** Ticks live at the NODE layer. They do not read wallet files, do not know balances, do not sign transactions, do not derive addresses. The `ChainAdapter` trait has NO wallet-adjacent methods; this is enforced structurally.

### What ticks MAY do

1. **Read block data.** Blocks are already public on the chain. Snapshot / restore / re-broadcast is fine — no privacy delta vs normal node behavior.

2. **Report AGGREGATE fleet metrics.** "3 of 9 hosts have `tip_age > 300s`" leaks no privacy. "seed1 has `tip_age = 1247s`" leaks fleet topology. Aggregate only.

3. **Report anomaly counts by role.** "1 miner has hashrate < 50% baseline" is aggregate. Never say WHICH miner.

4. **Sign notices with a tick-specific key.** Each tick has its own Ed25519 keypair used ONLY for notice signing. Never reused for consensus signing, never derived from a wallet seed. Compromise of a tick key is bad but recoverable via a new pubkey registry entry.

5. **Talk to other ticks over Noise-encrypted channels.** RescueTick's chaindata transfers travel over the same Noise-encrypted P2P layer coincync-node uses — never over plaintext RPC exposed to the public internet. Reuses the existing `NodeIdentity` handshake.

### Per-mode privacy rules

**RescueTick:**

- Snapshot chaindata via authenticated Noise channel between local tick and target node — never SCP, never raw HTTP.
- Notice text uses aggregate: `"1 host feeding N hosts on canonical fork"`, not host names or IPs.
- The receiving node's `apply_chaindata` step MUST re-run its own validator; it does NOT accept the tarball on tick trust alone. Even if the tick is compromised, the node's consensus rules can't be bypassed.
- Do not log per-host completion times to any external log sink; only aggregate `"recovery complete: 8 hosts, elapsed 45m"`.

**HealthTick:**

- Default mode differs by network + deployment:
  - `--network testnet-fleet` (public fleet operator): broadcast aggregate notices via `Alert = 41` gossip. Fleet is publicly known; leaking "this fleet has an anomaly" leaks nothing new.
  - `--network mainnet-personal` (end-user home node): **NEVER broadcast**. Local log + operator-configured Discord webhook only. A personal node broadcasting "my node's tip_age is high" reveals node existence to the network.
- Config surface: `[health] broadcast_mode = "gossip" | "local" | "webhook_only"` with `local` as the default for `mainnet-personal`.
- Health metrics collected but not broadcast MUST still be aggregate; the per-host detail lives in files with 0600 permissions on the local disk, never shipped externally.

**PropagationTick:**

- MUST consult `DandelionRouter::is_fluff_epoch()` and `DandelionRouter::stem_relay_peers()` before any re-broadcast decision. Never re-broadcasts to a peer that is currently a stem-relay for the tx in question.
- Only operates on fully-fluffed txs OR blocks (never stem-phase txs).
- Sampling of "which blocks to check propagation for" uses `rand::seq::SliceRandom::shuffle` on the local tip range — never a deterministic function of peer identity (would leak "this tick queries peer X first").

### Wallet-side privacy (notice reception)

When a wallet receives a `MessageType::Alert` payload carrying a `TickNotice`:

1. **Verify signature locally** against the bundled tick-pubkey registry. No round-trip to the network.
2. **Do NOT ACK.** Do not increment any counter that is later synced. Do not respond with anything the network can observe.
3. **Do NOT re-broadcast.** Notices propagate via the node's normal gossip flood, not via wallet participation.
4. **Display neutrally.** UI banner text is identical across all wallets receiving the same notice; no per-wallet enrichment (e.g., "your tx X may be delayed" would confirm to a network observer that the wallet holds tx X).
5. **Expire silently.** After `expires_at`, remove the banner. Do not report expiration to any external sink.

### `ChainAdapter` privacy contract

The trait defined in [Cross-blockchain portability] is amended with these privacy methods that adapter implementations MUST provide:

```rust
pub trait ChainAdapter: Send + Sync + 'static {
    // ... existing methods ...

    /// True if the given tx is in Dandelion++ stem phase locally.
    /// PropagationTick uses this to REFUSE re-broadcast.
    /// Adapters for chains without stem/fluff phases return false
    /// (their broadcast model is a different privacy question).
    fn is_stem_phase(&self, tx_id: &Self::TxId) -> bool;

    /// Peers currently acting as stem-relays for the local node.
    /// PropagationTick MUST NOT push txs to these peers unless the
    /// tx is fully fluffed everywhere.
    fn stem_relay_peers(&self) -> Vec<Self::PeerId>;

    /// Aggregate-only fleet health snapshot. Per-host details are
    /// NEVER exposed via this method — if the adapter has them,
    /// it aggregates them internally before returning.
    fn aggregate_fleet_health(&self) -> AggregateFleetHealth;

    /// Deployment mode. Determines HealthTick broadcast default.
    fn deployment_mode(&self) -> DeploymentMode;
}

pub struct AggregateFleetHealth {
    /// Total hosts polled. Not their identities.
    pub total_hosts: u16,
    /// Count of hosts with tip_age > threshold.
    pub stalled_count: u16,
    /// Count of hosts with peer_count < threshold.
    pub low_peer_count: u16,
    /// Count of hosts with divergent difficulty (>=5% delta from median).
    pub divergent_count: u16,
    /// Median difficulty across polled hosts (aggregate signal only).
    pub median_difficulty: u128,
}

pub enum DeploymentMode {
    /// Public fleet operator. Broadcast notices to gossip is safe.
    /// `--network testnet-fleet`, `--network mainnet-fleet`.
    Fleet,
    /// End-user personal node. Notices are local only; never broadcast.
    /// `--network mainnet-personal` (default for wallet-adjacent nodes).
    Personal,
}
```

Bitcoin/Monero/etc. adapters implement the same contract. For Bitcoin, `is_stem_phase` returns `false` always (no Dandelion++). For Monero, it consults their own dandelion++ implementation. Cross-chain portability doesn't weaken the privacy contract — the trait signature enforces it.

### Threats specifically closed by these rules

1. **"Tick-fingerprint" deanonymization.** An observer running a passive network monitor cannot identify tick-enabled nodes by their poll patterns (Poisson jitter defeats regular-interval detection).

2. **Fleet topology mapping.** No notice reveals which host is which role; observer only learns "N of M hosts have anomaly."

3. **Dandelion++ break via re-broadcast.** PropagationTick's stem-phase check prevents accidental leak of stem-phase txs to non-stem peers.

4. **Wallet-holding oracle.** Wallets don't ACK notices, don't re-broadcast them, don't enrich them per-user; no side-channel from receipt.

5. **Correlation across quest cycles.** Per-quest UUIDs prevent linking "peer X seen at T+0" to "peer X seen at T+300."

6. **Personal-node existence leak.** Default mainnet-personal deployment never broadcasts; a home wallet with a running node emits no more signal than a home wallet without one.

## Tick notices — "tick is on the hunt" broadcasts

Operator requirement (2026-07-05 addition): when a tick is actively engaged — a RescueTick has sensed a partition and started recovery, a HealthTick has fired a critical alert, or a PropagationTick has detected a widespread gossip gap — the tick should broadcast a **notice** so wallets, block explorers, and watchers can see that recovery is in progress and adjust their behavior (e.g., wallet UI shows "network under recovery, tx confirmations may be delayed").

"In the blockchain" is a real design choice with real trade-offs. Under Section 1 (Absolute Honesty), surfacing both options rather than picking one:

### Option A — on-chain notices (persistent, consensus-recorded)

Adds a new coinbase extra field (or a new special transaction type) carrying tick notices. Every miner includes recent notices from ticks they trust in the block they mine; miners across the network converge on a canonical notice history.

**Pros:**

- Genuinely "in the blockchain" — a wallet reading only block headers + coinbases can see notices
- Immutable history: a mainnet post-mortem can reconstruct when ticks were active
- Cross-chain-portable via `ChainAdapter::write_notice()` — bitcoin/monero adapters just no-op if their chain lacks the primitive

**Cons:**

- **CONSENSUS CHANGE.** Any on-chain field is a consensus rule (invalidity if malformed, replay protection, size limits). Requires the BACKLOG rule 4 "consensus change session" gating; cannot land alongside Phase 1-3 of the tick sidecar itself. Requires hard fork.
- **Spam vector.** Without cryptographic proof-of-tickness, anyone can inject fake "tick" notices. Needs a signing key + a way to register tick pubkeys on-chain (another consensus change).
- **Storage bloat.** Every notice is bytes every wallet must sync forever. At 32 bytes/notice × 1000 notices/year = 32 KB/year of permanent state; small but real, and it grows every year.
- **Fork risk.** If a majority of miners decide not to include notices, notices don't land. On-chain data that depends on miner good behavior is a governance surface.

### Option B — on-wire notices via existing `MessageType::Alert = 41` (transient, non-consensus)

Reuse the existing `Alert` P2P message. When a tick fires, the sidecar authenticates with the local node via RPC and asks the node to broadcast a signed `AlertMessage { text, severity, expires_at, tick_pubkey, signature }`. Peers gossip the alert during its TTL; wallets that stay connected to a node see it in near-real time; historical replay is via off-chain logs, not the chain.

**Pros:**

- **Zero consensus change.** `Alert = 41` already exists in protocol.rs (VERIFIED at L140 in the master read this session). No fork. No new discriminants. No storage bloat.
- **Fast**: alert propagates in seconds via gossip, not the ~30-120s block-time window.
- **Rate-limit-friendly**: alerts have TTL and expire; misbehaving ticks age out.
- **Cross-chain-portable**: `ChainAdapter::broadcast_alert()` maps to whatever gossip primitive the host chain has. Bitcoin already had a `Alert` message historically; Monero has notarized broadcast; adapters bridge.

**Cons:**

- Not "in the blockchain" strictly — it's on the wire. A wallet that comes online after the alert TTL expired won't see it.
- Non-mining watchers must be connected during the alert window.
- Alert-message trust: needs a signing key + wallet-side pubkey registry (off-chain), same as Option A but no on-chain governance surface.

### Option C — hybrid (recommended)

- **Phase 1-3** (tick sidecar itself): use Option B. Ticks broadcast via `MessageType::Alert`. Signed with tick-specific key. TTL 24h. No consensus change.
- **Phase 5** (post-launch): if operational experience shows we want persistent notice history, add Option A as a separate PR under BACKLOG rule 4 consensus-change discipline. Notice-persistence rule ships in its own hard fork at a future height, with proper activation coordination.

This lets us build the tick feature NOW without gating it on a consensus change, and adds durable-notice-in-block as a follow-on when it's clearly needed and can go through the consensus-change process.

**Notice payload shape** (Option B implementation):

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct TickNotice {
    /// One of "hunt", "engaged", "recovered", "alert".
    pub kind: TickNoticeKind,
    /// Human-readable text ≤ 256 bytes.
    pub text: String,
    /// Severity: 0=info, 1=warn, 2=critical.
    pub severity: u8,
    /// Which tick emitted this (identifier from tick.toml).
    pub tick_id: String,
    /// Which mode fired: 0=rescue, 1=health, 2=propagation.
    pub mode: u8,
    /// Wall-clock at emission (Unix seconds).
    pub emitted_at: u64,
    /// Alert expires after this Unix timestamp.
    pub expires_at: u64,
    /// Ed25519 signature over the preceding fields, by the tick's key.
    pub signature: [u8; 64],
}

pub enum TickNoticeKind {
    /// Tick has sensed anomaly; entering quest phase.
    Hunt,
    /// Tick has latched onto target; feeding.
    Engaged,
    /// Tick has completed feed; detaching.
    Recovered,
    /// HealthTick generic anomaly report.
    Alert,
}
```

Wallets that connect during the alert window see the notice; wallets that come online after `expires_at` do not. This matches how modern operational-notice systems work (status pages, PagerDuty incidents) — real-time signal, not immutable history.

## Configuration

Single TOML/JSON file per tick instance. Reasonable defaults so the tick starts up sanely with an empty config.

```toml
# /etc/coincync-tick/tick.toml

[core]
node_rpc_url = "http://127.0.0.1:28081/rpc/testnet"
node_rpc_bearer = "<from env COINCYNC_RPC_API_KEY>"
tick_id = "seed1-tick"                 # human name for logs/alerts
heartbeat_interval_secs = 60

[rescue]
enabled = true
quest_interval_secs = 300              # 5 min RPC poll of fleet
divergence_block_threshold = 100       # trigger only if gap > 100 blocks
canonical_min_difficulty_delta_pct = 5 # heavier chain must be ≥5% heavier
snapshot_dir = "/var/lib/coincync-tick/snapshots"
max_recovery_hosts_per_hour = 2        # rate-limit self-triggered recoveries
require_operator_ack = false           # if true, alert instead of auto-recover

[health]
enabled = true
sample_interval_secs = 60
alerts.discord_webhook = "$DISCORD_WEBHOOK_HEALTH"
alerts.grafana_pushgateway = ""        # empty = disabled
[health.thresholds]
tip_age_critical = 600
tip_age_warn = 300
peer_count_min = 3
difficulty_delta_pct_critical = 5
ram_pct_critical = 90
disk_pct_critical = 90

[propagation]
enabled = false                        # off by default; opt-in only
quest_interval_secs = 30
sample_block_count = 5                 # how many local blocks to check per tick
max_rebroadcasts_per_peer_per_hour = 20
```

## Phased implementation plan

Under BACKLOG rule 1 ("One backlog. One direction at a time") — ONE phase per PR, each independently reviewable and revertible.

### Phase 0 — this design doc (this PR)

- `docs/architecture/tick.md` (this file)
- No code

### Phase 1 — core traits + RescueTick + CoincyncAdapter

- New crate `crates/coincync-tick/` in the workspace
  - `src/adapter.rs` — `ChainAdapter` trait
  - `src/types.rs` — `ChainTipState`, `FleetPeer`, `Snapshot`, `HealthSnapshot`
  - `src/tick.rs` — `TickBehavior` trait (`quest → latch → feed → detach`)
  - `src/rescue.rs` — `RescueTick` impl
  - `src/config.rs` — TOML parsing
  - `tests/` — unit tests + integration test with `MockAdapter`
- Reuses coincync-node's existing RPC surface (no consensus/wire changes)
- ~500-700 LOC total
- Deliverable: RescueTick can auto-recover the 2026-07-04 pattern in dry-run mode against the current fleet, verified by hand

### Phase 2 — HealthTick + alert channel adapters

- `src/health.rs` — `HealthTick` impl
- `src/alert/discord.rs`, `src/alert/grafana.rs`, `src/alert/stdout.rs` — channel adapters
- ~400-500 LOC
- Deliverable: HealthTick replaces `scripts/coincync-weekly-review.sh` posting to Discord

### Phase 3 — PropagationTick

- `src/propagation.rs` — `PropagationTick` impl
- Requires wiring into the node's block-broadcast surface (RPC `broadcast_block` method needed if not present)
- ~300-400 LOC
- Deliverable: PropagationTick complements PR #176 by closing across-node propagation gaps

### Phase 4 — extract as standalone crate

- Move `crates/coincync-tick/` to `github.com/ghostrider1092/tick` as a standalone repo
- Publish to crates.io as `tick` (or `blockchain-tick` if `tick` is taken)
- Coincync repo depends on it via git URL or crates.io version
- Bitcoin/Monero/etc. adapter impls live in their own crates
- Deliverable: another blockchain project can `cargo add tick` and write their own `ChainAdapter`

## Decisions locked (2026-07-05 operator sign-off)

Operator sign-off received in the design PR review turn. Decisions are locked; Phase 1 code implements to these:

1. **Placement:** sidecar binary. New `coincync-tick` binary in the workspace + a new systemd unit `coincync-tick.service` on every fleet host. Independent lifecycle from `coincync-node`.

2. **RescueTick default per network:**
   - Testnet: `require_operator_ack = false` (auto-recover). Testnet exists to prove the pattern works; a stall auto-heals in ~45 min.
   - Mainnet: `require_operator_ack = true` (alert-only) for at least the first 6 months post-launch. Human stays in the loop. Config supports either mode; the DEFAULT differs by `--network testnet` vs `--network mainnet`.

3. **PropagationTick default:** `enabled = false` (opt-in). Turned on only after Phase 3 soaks on testnet for 4+ weeks with no peer-scoring regressions.

4. **Tick notice storage:** Option C (hybrid).
   - **Phase 1-3**: Option B only — on-wire `MessageType::Alert = 41` broadcasts. No consensus change. Ships now.
   - **Phase 5 (later)**: if operational experience shows persistent notice history is worth it, add Option A as a separate PR under BACKLOG rule 4 consensus-change discipline. Not gating Phase 1-3 on this.

5. **Phase 4 (extract to standalone crate) timing:** after Phase 3 soaks on testnet. Rationale: extracting later is safer — we know the trait shape works, no risk of breaking downstream adopters mid-iteration.

6. **Cross-chain adapter examples in this repo:** yes, stub out `BitcoinAdapter` and `MoneroAdapter` as trait shells in Phase 4 to prove the abstraction is portable. Non-functional stubs — just enough to typecheck against the trait and show what a full impl would look like.

## Non-goals

- **Consensus changes.** Ticks don't touch consensus. If a tick surfaces a bug that requires a consensus change, that goes through the normal BACKLOG rule 4 "consensus change session" process.
- **Wallet operations.** Ticks are node-adjacent, not wallet-adjacent. They don't sign, don't hold keys, don't touch mempool as a first-class actor.
- **Multi-chain coordination.** Each tick knows one chain (via its adapter). Cross-chain bridge scenarios are out of scope; those belong in `cyncswap` or a separate bridge project.
- **UI.** Ticks are headless daemons. Any UI belongs in a separate observability layer (Grafana dashboard, admin console, etc.).

## Rejected alternatives

Considered and rejected during design:

- **"One tick, three modes toggled at runtime."** Single agent with all three responsibilities. Rejected: blast radius. A bug in HealthTick shouldn't take down RescueTick's ability to save the fleet during a partition.
- **"Ticks are cron jobs."** Just wire up cron + shell scripts. Rejected: fleet-config.json integration + cross-host coordination + stateful trigger logic (dedup, rate-limits) are painful in shell; Rust with structured config is the right tool.
- **"Ticks are a coincync-only feature."** Rejected by operator: the design should be reusable. Hence the `ChainAdapter` trait.
- **"Ticks are 'smart contract' agents on-chain."** No. Ticks live off-chain, alongside nodes. Putting agents on-chain would require consensus changes and add attack surface.
- **"Ticks can read wallet state to give personalized alerts."** Rejected on privacy grounds. Ticks live at the NODE layer; no adapter method touches wallet files, balances, or key material. A tick that could say "your tx is delayed" would be an oracle for "this wallet holds tx X" — direct deanonymization. See [Privacy considerations](#privacy-considerations-privacy-blockchain-constraint).
- **"HealthTick auto-broadcasts on personal home nodes."** Rejected on privacy grounds. A home node that emits a "my tip is stale" notice reveals its own existence. Default `deployment_mode = Personal` disables broadcast entirely; only local logging + operator-configured webhook.

## References

Prior art (kept honestly qualitative — Section 8):

- **watchtowers** in Lightning Network: passive monitors that latch onto channels and respond to breach attempts. Same shape (quest → detect → respond) at a different layer.
- **Prometheus exporters + Grafana alertmanager**: standard shape for HealthTick. We're not competing with that stack; we're layering onto it via the grafana/discord adapters.
- **Bitcoin Core's ban list persistence** (`BanMan::DumpBanlist` at banman.h:85 in the master read this session; see PR #170 comment scrub for provenance): example of a periodic maintenance sidecar-like task inside the node binary. Our sidecar is more isolated because it's a separate process.
