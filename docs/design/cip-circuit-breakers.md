# CIP-draft: circuit breakers — fault isolation for CoinCync's critical surfaces

Status: **pattern established, first instance built; the rest WILL be built.**
The shielded-pool breaker exists (`src/shielded_circuit_breaker.rs`, feature
`shielded-breaker`); the other critical surfaces below each get a breaker too.

**Safety is a first-class requirement here, not optional scope.** Anything that
handles money gets a bulkhead. The only discipline is *quality*: each breaker is
built properly — tested, fail-closed, gated — because a half-built breaker is
*false* safety, which is worse than none. So we build them all, one at a time,
each to the same bar; "incremental" means "each one real," never "skip some."

## The pattern (submarine bulkhead)

A privacy L1 should survive a bug or exploit in any one subsystem without the
whole chain halting or draining. The pattern has two halves:

- **Detection** (already present): the `security` "detail" scan and the
  `immune.rs` termite framework (`Finding` / `Severity` / `FindingsLog`) surface
  invariant violations.
- **Isolation / response** (the breaker): on a detected fault, **seal that one
  compartment** — stop processing the compromised subsystem — while every other
  compartment keeps running.

Every breaker follows the same shape as the shielded one:

- `Policy` = **`Observe`** (detect + log, never reject — the default,
  consensus-neutral) or **`Armed`** (isolate on fault).
- `Action` isolates **only its own compartment**; it is structurally unable to
  reject unrelated traffic (the shielded breaker can never reject a transparent
  tx — that's what makes it a bulkhead, not a kill switch).
- **Fail-closed:** any detected fault under `Armed` trips; a known violation is
  never let through.
- **Pure:** reasons over an observation the caller already has, so it never
  perturbs the hash-locked consensus core.

### Shared abstraction — deferred on purpose

We do **not** extract a generic `CircuitBreaker` trait yet (YAGNI): with one
instance, the shielded breaker's `Policy`/`Action`/`Fault`/`detect`/`evaluate`
shape *is* the template. The trait gets factored out when the **second** breaker
lands, so the abstraction is shaped by two real cases, not guessed from one.

## Discipline (same rules as the other connectors)

- Each breaker is a **connector**: declared from `lib.rs` (never the hash-locked
  `consensus/mod.rs` / `validation.rs` / `constants.rs`), feature-gated,
  default-OFF, wired into nothing until activation.
- **Live arming is a coordinated, activation-gated consensus decision.** A
  node-local autonomous halt that peers disagree with would itself **fork** the
  chain, so detection ships inert and enforcement is a planned, audited
  activation — the same gating as the Rung-2 state-root connector.

## Surface roadmap

| Surface | Faults it isolates | Isolation scope | Status |
|---|---|---|---|
| **Shielded pool** | inflation (pool > shield-in), pool negative, balance mismatch, double-spend (reused linking tag), proof-invalid, supply divergence | reject `TxType::Shielded`; transparent unaffected | **built** (`shielded_circuit_breaker`) |
| **Supply / emission** | mint beyond the emission schedule; committed ≠ reconstructed supply | reject the offending coinbase / block | planned — ties into the Rung-2 supply commitment |
| **Mempool** | admission flooding / resource-exhaustion DoS | shed / throttle admission; mining unaffected | partial today (per-IP caps, admission gates) |
| **P2P / IBD** | eclipse attempt, phantom-IBD target (banned-peer height not purged), handshake starvation | drop / quarantine the peer-set path; keep serving | partial (cold-start IBD + handshake-lane fixes) |
| **Reorg / finality** | reorg deeper than the soft-final window | refuse the deep reorg (rolling finality) | adjacent to CIP-011 |
| **RPC** | unauthenticated resource exhaustion | throttle / disable the hot method | partial (DoS bounds on scan handlers) |

Each row's *live arming* is its own activation-gated decision, post-audit.

## Why this strengthens the audit

"What is your isolation response when subsystem X is compromised?" is a standard
auditor question for a privacy chain (Zcash and Firo have each shipped emergency
responses to real shielded-pool bugs). A breaker on every critical surface is a
concrete, reviewable answer — the kind of defense-in-depth a money-handling
system is expected to have.

## The fuse box — breakers as pluggable extensions, hot code untouched

`src/fuse.rs` (feature `fuse`) is a **mediation layer between the breakers and
the node code**, so new breakers are *extensions*, not new edits to the
consensus / hot path:

- The node already broadcasts a `NodeEvent` stream. A **thin adapter** maps each
  event to the fuse's own [`FuseSignal`] vocabulary and calls `FuseBox::observe`.
  That adapter is the **single** integration point; it subscribes to events the
  node *already* emits, so no hook is added to the mempool / network / consensus
  code.
- Breakers **install** into the box (`FuseBox::install(surface)`). Adding a
  breaker, or changing its recovery policy, happens in the box — the hot path is
  never touched again.
- The box is **decoupled**: it depends on no network types (it speaks
  `FuseSignal`, not `NodeEvent`), so it's pure and unit-testable; only the tiny
  node→fuse adapter knows both worlds.

Honest scope: the box is **observe-only** (runs breakers, records/logs state;
never feeds back into consensus). From the event stream it derives the
**mempool arrival-rate** and **peer-count** signals; per-block signals that need
hidden amounts (supply) or chain internals (reorg depth, netgroup diversity)
aren't in the events and stay with their own hooks (the heartbeat P2P wire for
netgroups; gated connect-path hooks for supply/reorg). Enforcement of any
consensus surface remains the coordinated, post-audit activation.

Relationship to the direct wires: the mempool (`admit_after_checks`) and P2P
(`emit_heartbeat`) live wires read richer, surface-specific state directly; the
fuse box is the *decoupled* path for signals carried on the event stream and the
place new breakers plug in without editing code.

## Recovery — does a tripped breaker reconnect on its own?

Detection is stateless (`detect(obs)` = faulty *now*); **recovery is stateful**
and lives in one shared module, `src/breaker_recovery.rs` (feature
`breaker-recovery`): a classic three-state machine **Closed → Open → Half-Open →
Closed**, driven by feeding it `!detect(obs).is_empty()` each tick. The policy is
**per-surface**, because "reconnect automatically" is right for some faults and
dangerous for others:

- **Load / attack surfaces — `AutoReset` (auto-reconnect, with hysteresis).**
  Mempool, P2P, RPC, reorg-churn faults *pass*. After a streak of healthy ticks
  (`DEFAULT_HEAL_STREAK = 3`) the breaker goes Half-Open, then Closed. The streak
  requirement is **anti-flap**: a single clean tick doesn't bounce it open/closed
  at the threshold, and any fault during healing restarts the streak.
- **Crypto / money surfaces — `Latch` (never auto-reconnect).** Shielded and
  supply faults do **not** go away because the next block looks clean — a
  discovered inflation / proof break is still there. A latched breaker stays Open
  until an explicit **`rearm()`** (the human / governance "we fixed it" decision).
  Auto-reconnecting a known-broken money pool is exactly the footgun safety-first
  forbids.

`is_isolating()` is what callers act on; it stays true through Half-Open
(conservative — Half-Open is *probing* recovery, not recovered). `rearm()` is the
only path back for `Latch`, and an operator override for `AutoReset`.

| Surface | Recovery |
|---|---|
| shielded, supply | **Latch** (manual re-arm) |
| mempool, p2p, rpc, reorg | **AutoReset** (heal-streak 3, hysteresis) |

## Build order (all get built; each to the same bar)

1. **(done)** shielded-pool breaker + tests.
2. **supply / emission** breaker next (highest value after shielded; pairs with
   the Rung-2 commitment) — then extract the shared `CircuitBreaker` trait from
   the two real instances.
3. **mempool**, then **P2P / IBD**, then **reorg / finality**, then **RPC** — each
   a gated, fail-closed, tested connector.
4. Activation (live arming) of any breaker is post-audit and coordinated across
   nodes, so detection ships inert and no breaker can unilaterally fork the chain.
