# CIP-draft: Fuse-box resilience standard (CoinCync engineering practice)

Status: **standing practice.** This is how new protection is added to CoinCync:
through **connectors + fuses + the fuse box**, never by editing the tuned,
hash-locked core.

## The principle

Code is never 100% correct, and a money-handling chain cannot assume it is. So
we build **precautions that isolate faults**: if a subsystem misbehaves, a
**fuse blows** — that one surface is sealed off — instead of the failure
cascading into consensus or taking the node down. The fuse is the sacrificial,
**re-armable** element; the core stays intact.

**The honest scope (so this never becomes false comfort):**

- A fuse blows only for a fault we **anticipated and wrote a detector for**. It
  is **defense-in-depth on top of** correct, tested, audited code — *not a
  substitute* for it. An unknown bug with no invariant still bites. Fuses make a
  *known* failure survivable; the audit is still the thing that finds the
  unknowns.
- The fuse itself must be **correct and fail-safe**: default `Observe` (logs,
  never acts), reversible, and heavily tested (property fuzz + lifecycle), or a
  false-tripping fuse becomes its own hazard.
- **Consensus surfaces can't blow unilaterally on the live net** (a node-local
  trip peers don't share would fork). There a fuse is detection/telemetry until
  a coordinated, activated enforcement.

## The standard (every new critical surface follows this)

1. **Invariants** — a pure `detect(observation) -> faults`. No chain-state
   access, so it can't perturb the core.
2. **Connector** — a fail-safe policy slot. **No edit to the hash-locked core**
   (`validation.rs`, `consensus/mod.rs`, `constants.rs`, headers, emission).
   Declared from `lib.rs`, feature-gated, default-OFF.
3. **Fuse** — the recovery state machine (`breaker_recovery`): Closed → Open →
   Half-Open → Closed, with a policy — **Latch** for crypto/money surfaces
   (never auto-reconnect a known-broken pool; needs `rearm()`), **AutoReset +
   hysteresis** for load/attack surfaces.
4. **Register into the universal fuse box** (`fuse.rs`) — there is **one**
   process-wide box (`fuse::global()`) that every surface installs into
   (`FuseBox::install_all` registers all of `BreakerSurface::ALL`). A surface is
   fed through the single universal entry point
   `fuse::observe(surface, &FaultReport)`: its feed point runs the surface's own
   pure `detect()`, wraps the labels in a surface-agnostic `FaultReport`, and
   hands it to the box. The box never knows the surface's observation type, so
   **adding a breaker is `install` + one feed call** — the box itself never
   changes. One `fuse::snapshot()` shows every compartment at once. (Surfaces
   whose signal is already on the node's event stream — mempool arrival-rate,
   peer count — may instead use the thin `FuseSignal` adapter, which routes
   through the same universal path.)
5. **One thin feed point per surface, at its real source** — the only
   integration a surface needs: mempool admit, p2p heartbeat, block-connect, the
   reorg-accept decision, the RPC request seam. Each runs that surface's
   `detect()` on real data and calls `fuse::observe`; the hot/consensus path is
   never re-architected.
6. **Aggressive lifecycle tests** — trip + isolate + recover + reconnect, plus a
   randomized property fuzz against independent invariants, and a universal
   end-to-end test driving every surface's real feed through the one box
   (`tests/fuse_box_universal_live.rs`).

This hardens the existing connector-pattern rule into policy: **consensus-
adjacent protection goes through a connector/fuse, never a core edit.**

### Universal, but honest about enforcement

"Universal" means every surface lives in one box and every surface that can be
fed *real* data *is* fed live. It does **not** mean every surface can *act*:

- **Node-local load surfaces** (mempool, p2p, rpc) are safe to observe — and
  later, per-node, to act on — with no fork risk. These are **live-fed now**.
- **Consensus surfaces** (reorg, block-integrity live-fed; supply + shielded
  fed at activation) are **detection/telemetry only** on the live net: a
  node-local trip peers don't share would fork. Their live feed sits where they
  would also be *armed*, so arming is the coordinated, post-audit activation —
  not a second wiring.

## What blockchain code to wire for protection

The question isn't "where do we know a bug is" — it's "which subsystems, if they
*ever* misbehave, must isolate rather than cascade." Precaution, because code
isn't 100%. Built surfaces first, then candidates.

### Built (this program) — all registered in the one universal box
| Surface | Fault it isolates | Recovery | Live feed |
|---|---|---|---|
| Mempool | flood / exhaustion / per-peer / dust | AutoReset | **live** — real admit path (`mempool_live_breaker`) |
| P2P / IBD | eclipse, phantom-IBD, per-IP flood, stall | AutoReset | **live** — heartbeat tick (`p2p_live_breaker`) |
| RPC | request/expensive/concurrency/oversize/unauth-probe | AutoReset | **live** — per-request seam (`rpc_live_breaker`) |
| Reorg / finality | deep reorg, below-finality, churn, work anomaly | AutoReset | **live (observe)** — reorg-accept site (`reorg_live_breaker`) |
| Block connect / apply | `total_outputs_ever` monotonic, availability non-underflow, `live ≤ ever`, root match | Latch | **live (observe)** — `process_block` seam (`block_integrity_live_breaker`) |
| Supply / emission | over-emission, broken `circulating = emitted − burned`, cap | Latch | registered; fed at activation (validate/apply) |
| Shielded pool | inflation / double-spend / bad proof / supply divergence | Latch | registered; fed at activation (pool apply) |
| State-root (Rung-2) | committed UTXO root ≠ computed | (enforce gated) | connector inert until activation |

Node-local surfaces (mempool/p2p/rpc) act safely per-node; the consensus surfaces
are observe/telemetry on the live net until a coordinated activation (their live
feed already sits where arming happens). Supply duplicates the emission validator
and has no independent `circulating` at a cheap seam, and shielded needs pool-apply
internals — so both are fed at activation rather than as half-signal Observe
telemetry.

### Candidate surfaces to wire next (precautionary defense-in-depth)
| Subsystem | What a fuse watches | Why (code-isn't-100% precaution) |
|---|---|---|
| **Spend / ring verification** | rate of CLSAG / key-image / range-proof verify *failures* where they shouldn't occur | a verify regression or malleability is a privacy/inflation hole — surface it fast |
| **Difficulty / PoW** | difficulty swing out of the sane band; implausible timestamp drift | timewarp / difficulty-manipulation attacks |
| **Storage / DB** | read/write errors, checksum/commitment divergence on load | disk corruption or a persistence bug shouldn't run on bad state |
| **Serialization / decode** | malformed-message / oversize-decode rate per peer | a parser bug or decode DoS |
| **Fee market / reservoir** | reservoir charge/discharge invariant breach | a fee-rule bug distorting economics |
| **Clock / time source** | monotonic-clock regressions, net-time skew | timestamp-dependent consensus faults |

Each candidate ships the full 5-step standard, gated OFF, Observe-first; the
consensus ones (block-connect, spend-verify, difficulty) detect/telemetry until a
coordinated post-audit activation, exactly like the existing consensus breakers.

## Non-goals

Fuses do not replace: the security audit, the full test suite, or correct
consensus code. They are the *containment* layer so a failure in one subsystem
is survivable instead of catastrophic. That is the whole point of taking
precautions when you accept that code is not 100%.
