# Design: total-difficulty sync trust (Phase 2 — closes V3 / I6)

## Implementation status (2026-07-08)

Landed behind Firework capability negotiation, backward-compatible (older peers
without `CAP_CHAINWORK` simply keep height-based sync):

- **Layer 1 (wire) — DONE.** Recreated the `Flare` capability message
  (`src/network/firework.rs`, `FlareMessage`) + new `ChainWork` message
  (`ChainWorkMessage`, type 51). `VersionMessage` unchanged, so old↔new
  handshake is intact. Round-trip + capability tests pass.
- **Layer 2 (signal) — DONE.** `ChainWork` is sent only to `CAP_CHAINWORK`
  peers (on Flare receipt + on every tip advance) and, on receipt, feeds
  `update_peer_difficulty_for`; `set_chain_state` now also calls
  `set_local_total_difficulty`.
- **Layer 3 (work-triggered sync) — DONE.** `ChainSync` tracks
  `local_total_difficulty`; a peer heavier than us flips state into `Headers`
  (locator-based GetHeaders → fork choice reorgs) even when it is shorter in
  height. `best_known_difficulty` is now a TRUE recompute (anti-wedge) and
  stale claims are pruned. Unit tests cover heavier-triggers-sync,
  lighter-dropped, shrink-on-disconnect, prune-on-overtake. **This resolves
  the higher-block/lower-work private-fork standoff (the 2026-07-08
  incident).**
- **Layer 4 (work-aware `is_synced` / I6) — DONE, with the anti-wedge
  machinery.** `Chain` carries a `work_behind` `AtomicBool` veto: `is_synced()`
  returns false whenever a peer advertises more cumulative work than us,
  regardless of block height (enforces I6). It is pushed from `set_chain_state`
  on tip advance AND refreshed on the sync maintenance tick. The miner-wedge is
  closed by a **substantiation timeout**: a peer's work claim is dropped when
  (a) it is not refreshed within `WORK_CLAIM_TTL_SECS` (send-once liar),
  (b) the peer is sync-banned for failing to deliver blocks (persistent
  non-deliverer), (c) it disconnects, or (d) we overtake it — and
  `best_known_difficulty` is a true recompute, so the veto clears automatically
  and can never pin `synced=false` permanently. The maintenance-tick refresh is
  what lets the veto clear even while block production is paused. Unit tests
  cover expire-after-TTL, fresh-survives, and the chain-level veto override +
  recovery. `work_behind` is inert (false) for height-only peers.

**Net:** the incident's root cause (a node cannot discover/adopt a heavier but
shorter chain) is fixed by Layers 1–3; Layer 4 additionally makes `synced`
(and therefore the miner and RPC) honor cumulative work, closing invariant I6.

---

**Status:** DESIGN for review. Implements the Phase 2 item already identified in
[`sync-state-machine.md`](./sync-state-machine.md) (§7.V3, invariant I6). Touches
the P2P wire format and sync-state machine (not the hash-locked consensus files),
but is a protocol change requiring fleet-upgrade coordination. Do **not**
fast-code.

**Motivated by:** the 2026-07-08 runaway-fork incident. Companion to the
already-shipped miner-side mitigation (`coincync-rig` fork-divergence gate) — that
gate stops the *acute damage* (a miner building a fork); this design removes the
*underlying cause* (a node cannot recognize or recover from a higher-block /
lower-work fork).

---

## Root cause (deep)

The node's **fork choice** is correctly work-based: when it evaluates a fork
block it already holds, it compares cumulative work
([chain.rs `take_fork = fork_cumulative > current_total_difficulty`](../../src/chain.rs)).

But the **sync / peer-selection** layer — which decides *what to request* and
whether we're "synced" — is **height-based**:

- `peer_heights: HashMap<PeerId, u64>` tracks peer *heights*, not work.
- `prune_stale_peer_heights()` drops any peer whose height ≤ local.
- `best_known_height = max(local, max(peer_heights))`; `is_synced ⇔ local ≥ best_known`.
- Both `set_sync_info` callers define synced as `local_height >= best_known_height`.
- The `VersionMessage` wire struct carries `start_height` — **no cumulative
  difficulty field**. Peers advertise height, never work.
- The work-based signal exists (`peer_difficulties`, `best_known_difficulty`,
  `update_peer_difficulty_for`, `best_peer_by_difficulty`) but is **dormant** —
  `update_peer_difficulty_for` is never called outside tests, because nothing on
  the wire delivers a peer's total difficulty.

### Why the fork becomes a permanent standoff

Two chains: honest **group A** (height 10042, high per-block difficulty, more
cumulative work) and an isolated miner's **fork** (height 10551, collapsed
difficulty, less cumulative work).

- **Group A** receives the fork's blocks, evaluates them by work, and correctly
  rejects them (less work). Stays at 10042. ✓ correct.
- **The forked node** sees group A advertising height 10042 < its own 10551.
  `prune_stale_peer_heights` drops group A as "stale/behind." It therefore
  **never requests group A's blocks**, never feeds them into its (correct,
  work-based) fork-choice, and never reorgs. `is_synced` returns true
  (`10551 ≥ 10551`). It mines on forever.

A node on a higher-block, lower-work fork is structurally blind to the honest,
shorter-but-heavier chain. Height-based sync cannot self-heal this; only a manual
restart (which drops the in-memory height state and re-bootstraps) recovers it.

## The fix — make sync trust cumulative work, not height

Four layers. Each is independently reviewable; ship behind version negotiation so
the fleet can upgrade without a flag-day.

### 1. Wire format: advertise cumulative work

Add `total_difficulty: u128` (our tip's cumulative work) to `VersionMessage`, and
include it on block/header announcements (Inv/headers) so it stays fresh, not just
at handshake. Backward compatibility: make it an **optional/versioned** field —
peers that don't send it are treated as "work unknown" and fall back to the
current height-based path for that peer only. No flag-day; mixed fleets work.

### 2. Wire the dormant signal

On receiving a peer's advertised `total_difficulty`, call
`update_peer_difficulty_for(peer, td)` (already exists, already has the
`BOGUS_FACTOR` sanity cap). On local tip advance, call
`set_local_total_difficulty(local_total_diff)` (already exists). Populate
`peer_difficulties` from real wire data instead of only tests.

### 3. Peer selection & request logic: pull heavier chains regardless of height

This is the crux. Today we only request blocks *higher* than our tip. Change the
trigger to **"a peer advertises more cumulative work than we have"** — even if its
height ≤ ours. Concretely:

- If `peer_total_diff > local_total_diff`, enter `Headers`/IBD against that peer
  **even when `peer_height ≤ local_height`**, so a forked node fetches the honest
  heavier chain and hands it to fork-choice (which then reorgs correctly).
- **Do not prune a peer merely for lower height** if it advertises higher work —
  `prune_stale_peer_heights` must become work-aware (prune on lower *work*, not
  lower *height*).

### 4. `is_synced` / best-known become work-aware (enforce I6)

`synced ⇔ local_total_diff ≥ best_known peer total_diff`. Keep the existing
fresh-tip / ≤2-block height tolerance as a *secondary* allowance for the
steady-state announce-race, but the primary signal becomes work. This makes the
`is_synced` false-positive on a lower-work fork impossible.

## Failure modes to guard (hard-won from prior incidents)

The sync path is a graveyard of subtle bugs; the regression oracle is the property
tests at `src/network/sync.rs` (phantom-target rejection, I2/I3 invariants,
best-known-must-shrink). Specifically:

- **Advertised work is not trustworthy on its own.** A spam peer can lie about
  total difficulty exactly as it can lie about height. The claim only gates
  *whether we request headers*; adoption still requires downloading the headers
  and **verifying their summed PoW** (fork-choice already recomputes work from the
  actual blocks). Never let an *unverified* claim change our tip or our
  `synced=false`→wedge state. Keep the `BOGUS_FACTOR` cap on claims.
- **Don't reintroduce the phantom-target pin** (2026-06-06 clamp-phantom,
  2026-06-27 InvBlock speculative-bump wedge): a bogus high claim must not latch
  `synced=false` and stop the miner. Mirror the reject-don't-clamp policy for the
  difficulty signal, and make best-known-difficulty a true recompute (can shrink
  when the claiming peer leaves), exactly as `refresh_best_known` was fixed for
  height.
- **Don't deadlock the miner.** Several consumers gate mining on `is_synced`
  (`coincync-rig`). A false `not-synced` stalls block production. The
  work-comparison must tolerate the normal case where we're momentarily a hair
  behind during an announce-race.
- **Respect the reorg-depth / rolling-finality cap.** Even with work-based sync, a
  fork deeper than `max_reorg_depth()` / `evaluate_reorg_acceptability` is
  correctly refused. Work-based sync resolves *shallow* forks automatically; a
  fork past the finality floor still requires operator action (by design).

## Blast radius (consumers of sync status)

Changing `is_synced` / `target_height` semantics touches: RPC `get_info`
(`rpc/server.rs`, `rpc/node_api.rs`, `rpc/lightwallet.rs`), the node's own
EMERGENCY-TIER-3 / stall-counter / InvBlock-refresh paths (`network/node.rs`), the
rig mining gate, `bin/wallet.rs`, and `coincync-wallet-v2`. Each reads a boolean or
a target height; none should break if the *meaning* tightens from "height-synced"
to "work-synced", but each must be re-checked. The wallet-facing "sync %" derived
from `target_height` should switch to a work- or height-based progress that never
exceeds 100%.

## Rollout

1. Land the wire field as optional; deploy fleet-wide (all nodes *send* + *parse*
   it) before anything *depends* on it.
2. Turn on work-based peer selection + `is_synced` once the fleet reports the field
   universally (telemetry check).
3. Keep the height path as the per-peer fallback indefinitely for old/external
   nodes.

Compatible with the next coordinated upgrade window. Until it lands, the shipped
`coincync-rig` fork-divergence gate + the `--external-ip` self-dial fix + the
deploy version-gate keep the acute incident from recurring.
