# Colony — implementation status

Status of the biomimetic colony (see [`colony.md`](colony.md) for the design and
[`../PRIVACY.md`](../PRIVACY.md) for the privacy model). This tracks what is
**built and tested** versus what is deliberately deferred.

The colony is **advisory-only**, **non-consensus**, and **off by default**. It
forages exclusively on public signals (block relay, chain tip, peer liveness)
and is structurally incapable of observing, scoring, or routing individual
transactions or stem-phase (Dandelion++) traffic — see the telemetry audit
below.

Test coverage as of this writing: **105 colony unit tests, 0 failures**
(`cargo test --features testnet --lib colony::`).

---

## Phase status

| Phase | What it is | State |
|-------|------------|-------|
| **0 — Guards** | Global kill switch (default OFF), per-action rate limits, diversity floors, untrusted-telemetry sanitizers | ✅ built + tested |
| **1 — Advise** | One unified `Recommendation` type every caste maps to, plus the `to_action()` bridge into the guard layer | ✅ built + tested |
| **2 — Act (core)** | `ColonyActor` runs every caste → decision → guard → actuator; ships with a safe dry-run `LoggingActuator` | ✅ built + tested, **default-OFF** |
| **2 — Act host** | The `coincync-tick` sidecar hosts the unified Act pipeline (`--colony-act`), gated behind the kill switch, dry-run only | ✅ wired + verified, **default-OFF** |
| **2 — Act (live actuator)** | A real, network-mutating actuator replacing `LoggingActuator` | ⛔ deferred — needs its own design + review before anything mutates the network |

### Phase 0 — Guard layer (`src/colony/guard/`)

Every Act a caste performs routes through `ColonyGuards::authorize(action, census)`,
which chains three checks in order:

1. **Kill switch** (`kill_switch.rs`) — `AtomicBool`, `new_disarmed()` is the only
   constructor. Disarmed → every action is denied. This is the master OFF switch.
2. **Diversity floor** (`diversity.rs`) — a topology-narrowing action (bridge
   reconnect, relay legs, tarpit) is refused unless the node is **strictly above**
   both floors (default 4 distinct netgroups / 4 outbound peers). The colony can
   never be the thing that pushes an eclipse-vulnerable node over the edge.
3. **Rate limit** (`rate_limit.rs`) — token-bucket per action kind (e.g. bridge
   reconnect ~2/hr, tarpit ~4/min), fail-closed on any unknown action kind.

Untrusted telemetry (`telemetry.rs`) is a separate, type-level guarantee: every
peer-supplied reading is wrapped `Untrusted<T>` at ingest and can leave **only**
through a clamping sanitizer. There is no `Deref`, no `into_inner`, no public
field — a caste core cannot be handed raw, unclamped peer telemetry even by
mistake.

Anchor test: `fresh_guards_deny_everything`.

### Phase 1 — Advise (`src/colony/advise.rs`)

Each caste's pure decision core returns its own advice type; `Recommendation`
unifies them into one enum, and `to_action()` is the single bridge to the guard
layer. Producing a recommendation changes nothing — it becomes a candidate
action solely by passing `to_action()` and then `authorize`. No-op advice (empty
peer/bridge/leg sets) maps to `None`.

### Phase 2 — Act core (`src/colony/act.rs`)

`ColonyActor` owns the stateful castes (pheromone map, mantis tarpit, firefly,
locust, cicada) and, each round, runs every caste to a `Recommendation`,
converts it to a guard-facing action, and asks `authorize`. **Only on `Allow`**
does it call the corresponding `ColonyActuator` method; on `Deny` it records the
reason and does nothing.

The actor talks to the world only through the `ColonyActuator` trait (the node's
seams: prefer peers, tarpit, open bridges, relay legs, swarm mode, housekeep,
cover pulse, wire profile), so its full logic is unit-tested against a mock.

Shipped actuator: **`LoggingActuator`** — completely inert, logs each authorized
action as "colony would: …" and touches nothing. This runs the whole
caste→guard→action pipeline as an observable **dry run**, safe to exercise
end-to-end on a live network while a real actuator is designed separately.

Anchor tests:

- `disarmed_guards_make_zero_actuator_calls` — the master safety property: a full
  tick with the kill switch disarmed (the default) makes **zero** actuator
  calls, regardless of signals.
- `diversity_floor_blocks_bridges_at_minimum` — even armed, a topology-narrowing
  act is refused at the diversity floor.
- `logging_actuator_runs_full_pipeline_armed` — the dry-run pipeline runs clean.

### Act host — the `coincync-tick` sidecar

The sidecar is the colony's home (its `CoincyncAdapter` reads public signals over
RPC; peer identities `PeerKey` are native there). It now hosts the unified Act
pipeline behind a `--colony-act` flag:

```text
coincync-tick --colony-act              # pipeline runs, kill switch DISARMED → every action gated
COINCYNC_COLONY_ACT_ENABLED=1 \
coincync-tick --colony-act              # kill switch ARMED → dry-run "would" actions logged
```

Each round, `colony_act_report` gathers the public signals (spider sentinel
reading, host-load density, netgroup-tagged bridge/leg candidates, diversity
census) and runs `ColonyActor::tick` through the guard layer against the inert
`LoggingActuator`. Two independent keys are required before anything is even
logged as an intent: the **CLI flag** turns the pipeline on, and the **env var**
arms the kill switch. Verified end-to-end:

- disarmed (default): `allowed=0` — zero actuator calls
- armed: non-diversity acts (relay mode, housekeep, wire profile) authorize and
  log; diversity-narrowing acts stay gated below the census floor

The actuator only **logs**; nothing is sent to the node or the network.

### Deferred — live (network-mutating) actuator

A real actuator that replaces `LoggingActuator` and actually steers peer
selection is **not** built. It requires sidecar-side "act" seams (advisory RPC
to the node's peer manager) and its own design + review. **Nothing will mutate
the testnet until then** — today the Act host is strictly dry-run.

---

## Telemetry audit — privacy model

The colony reads public block/liveness signals only, holds no capability to see
transactions or user data, ships nothing off the operator's own fleet, and is
off by default.

**1. Structurally incapable of touching transaction/user data.** The entire
`src/colony/` tree has **zero imports** of `mempool`, `wallet`, `transaction`,
`dandelion`, stealth addresses, keys, or amounts — verified by search. There is
no type, field, or code path by which a caste could read a transaction, an
amount, a stealth address, a key image, or stem-phase routing. Wiring one in
would require adding an import and changing a signature — a visible,
test-tripping change. (The `amount` seen in the code is a `u32` pheromone /
relay-quality weight, not money.)

**2. What the insects ingest** — six public facts:

| Signal | What it is |
|--------|------------|
| `height`, `difficulty`, `tip_id` | public block-header data |
| `is_synced`, `peer_count`, `tip_age_secs` | public liveness |
| spider's reading | inbound-connection *rate*, netgroup *concentration %*, duplicate-msg *%*, unreachable-sentinel *%* — counts/percentages, never message content |

**3. The wire surface is one read-only RPC (`get_info`) to the operator's own
fleet.** Its full response is height, total_difficulty, top_hash, is_synced,
peer_count, tip_age_secs, and `mempool_size` — and `mempool_size` is *just an
integer count* (no tx hashes/amounts/addresses) and **is not even forwarded into
the colony** (the `GetInfoResponse → ChainTipState` conversion drops it).

**4. No colony network I/O, no phone-home.** No `reqwest`/`hyper`/`TcpStream`/
`std::net` anywhere in `src/colony/`. It is pure computation over inputs handed
to it; it emits no metrics and contacts no external service. The sidecar's only
network calls go to the operator's own fleet-node RPC (shared fleet bearer).

**5. Live probe path is sanitized.** `forager::observe_round` wraps every
peer-supplied probe `Untrusted` and runs `sanitize_tip` before scoring reads it,
clamping `tip_age_secs` (≤ 30 days) and `peer_count` (≤ 100,000) into honest
ranges. A lying peer can at most report the maximum honest value, never an
out-of-band one. Height/difficulty are left untouched — fork choice validates
those separately. Test: `adversarial_probe_is_clamped_before_scoring`.

**6. Default-OFF.** Kill switch disarmed → a full round makes zero actuator
calls. Even armed, the shipped actuator is dry-run logging.

**Bottom line:** the insects are correctly configured for the CoinCync privacy
model.
