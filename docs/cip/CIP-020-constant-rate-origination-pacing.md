# CIP-020 — Constant-Rate Origination Pacing (closing the traffic-shaper timing leak)

**Status:** Draft (root-caused + **live-measured on real code**; design = uniform always-on)
**Type:** Standards Track (networking / privacy — non-consensus wire behavior)
**Created:** 2026-07-11
**Relates to:** Concentric Privacy Ring 4 (Network); whitepaper §5 (composition safety)

## Abstract

The traffic shaper's constant-rate padding is **additive**: a dummy packet is
emitted every 500 ms on a fixed clock "regardless of real traffic," while the
node's real outbound packets travel as a separate stream on top. Because the
padding is constant and independent of real traffic (`corr(padding,real) ≈ 0`,
measured), an observer can subtract the known grid and recover whatever real
traffic rides on top.

**What live measurement corrected (this is important — the synthetic model was
wrong).** A first synthetic harness predicted this leaked origination *timing*
(r ≈ 0.63). Running it on a real node instead:

- **A single wallet origination is already hidden** — adversary AUC = **0.49**.
  A tx is one packet, not a burst; Dandelion's randomized embargo (H16-FIX)
  already decorrelates *when it hits the wire* from *when it was submitted*; the
  constant padding + background absorb it. So additive padding does **not** leak
  low-rate origination timing.
- **What does leak is the volume *envelope* of high-throughput activity.** For a
  node's own originations, additive padding hides them up to a measured
  threshold of **≈ 38 tx/min** (`3σ ≈ 0.63 orig/s`, node-dependent); above that,
  a sustained origination *burst* exceeds the 2 pkt/s cover and becomes
  detectable. (Separately, high-volume *relay/sync* activity leaks at r = 0.84,
  but that is not the node's secret and is out of scope here — see Non-goals.)

So the pacer is justified **only** for high-throughput originators (exchanges,
merchants, payment processors, aggressive churn), not for individual occasional
senders — who are already hidden.

**But it must be uniform, not opt-in.** If only high-throughput nodes paced,
*pacing itself* would tag them ("this node paces ⇒ it's an exchange") — the tier
leaks and defeats the purpose. Therefore this CIP is **uniform and always-on**:
every node runs the same substitutive origination pacer at the same rate. Low-
throughput users are hidden *and* form the cover set that high-throughput users
blend into. This is the project's **"uniformity is anonymity"** posture — the
canonical wire fingerprint every node presents.

**Mechanism.** Replace additive padding on the **own-origination** channel with
**substitutive constant-rate pacing**: a single slot clock where each slot
carries a queued origination if one waits, else a dummy. Real and cover share
one clock → indistinguishable in size (already normalized) and timing, and
bursts are absorbed up to the slot rate. Pacing is scoped to **originations
only** — relay, block, and inv traffic bypass the pacer and are sent directly,
so **consensus/block propagation latency is unchanged** (must not regress
CIP-019). The slot rate is a network constant chosen to cover the busiest
originator the network intends to protect.

## Symptom / threat model

- **Adversary:** passive, on-path (ISP, transit, or a peer) observing this
  node's outbound packet timestamps. Sizes already give nothing — size
  normalization + `MessageType::Padding` framing make cover and real packets
  byte-indistinguishable.
- **Secret:** *when this node originates its own transactions* (user sends and
  auto-churn self-spends) — i.e. its activity schedule over time.
- **Stated goal of the current shaper** (`traffic_shaping.rs:260`): "makes idle
  and active nodes look identical to a network observer." The additive design
  does not meet this goal for an *active* node.

## Root cause (VERIFIED from code)

Two independent outbound streams merge only at the per-peer socket, never on one
clock:

- **Real path:** `node.rs` → `peer_senders[peer].send(data).await` → the per-peer
  write loop drains the bounded mpsc channel to the socket *as fast as the socket
  allows*.
- **Cover path:** `TrafficShaper::run_padding_loop_broadcast` sleeps a fixed
  `padding_interval_ms` (500 ms) and `try_send`s one dummy per peer *"regardless
  of real traffic"* (`traffic_shaping.rs:257-261, 293-356`).

Net wire rate = (real rate) + (2 cover pkt/s). The cover is a deterministic grid
laid *over* variable real traffic. An observer bins the wire, subtracts the known
constant cover rate, and the residual **is** the real-activity curve.

The auto-churn timing itself is already correct — `churn.rs:186` draws
inter-arrivals from an `Exp` distribution (a true memoryless Poisson process, no
spectral period to lock onto). The leak is entirely in how cover composes with
real traffic on the wire, not in churn scheduling.

## Measurement (red-team harness)

A synthetic passive-adversary harness using the real parameters — 500 ms grid,
0–200 ms jitter, Poisson originations over a 6 h diurnal activity curve — plays
the observer and reports how well it reconstructs the secret activity curve
(Pearson r vs. ground truth):

| Design | Observer recovers activity schedule | 500 ms line power/mean |
|---|---|---|
| **Additive** (current) | **r = +0.63** (leaks) | ~37,600× |
| **Substitutive** (this CIP) | **r = +0.00** (hidden) | ~43,200× |

The 500 ms spectral line is equally present in both designs — so the line itself
is not the leak. The leak is the *recoverable residual after removing the line*,
which exists only when cover and real are two separate streams. Harness:
`scratchpad/timing_leak_test.py` (to be promoted to a committed regression test).

## Specification

### Substitutive pacing

Replace the free-running padding loop with a per-peer (or per-origination-path)
**pacer** driven by one clock:

```text
every SLOT_MS (= padding_interval_ms, default 500):
    if origination_queue non-empty:
        send origination_queue.pop_front()      # real packet fills the slot
    else:
        send generate_padding_packet(magic)     # dummy fills the slot
```

Consequences:
1. The wire carries exactly one packet per slot per peer — a **flat** stream
   whether the node is transacting or idle. Nothing to subtract → r ≈ 0.
2. **Per-packet jitter is dropped under pacing.** The 0–200 ms jitter existed to
   blur the separate real stream; once real traffic *is* the constant grid,
   jitter only smears the grid and reintroduces a subtractable signal. One clock,
   no jitter.

### Scope (the critical constraint)

Pacing applies **only to the node's own originations** — locally-submitted
wallet transactions (including their Dandelion stem phase) and auto-churn
self-spends. **Relay, block, inv, header, and ping traffic bypass the pacer** and
are sent directly, exactly as today.

Rationale: a substitutive pacer on *all* outbound would add up to one slot
(≤500 ms) of latency **per hop** to block and tx-relay propagation, compounding
across hops into seconds — a direct regression of the near-tip propagation
behavior CIP-019 addresses. Relay/consensus traffic is *not* the node's secret
(every node forwards others' data regardless of its own wallet activity), so it
neither needs nor should pay for pacing.

### Bounded queue + overflow

The origination queue is bounded. When the origination rate exceeds one per slot
(2 tx/s — rare for a wallet), the queue builds and drains at exactly the slot
rate, which is itself observable as sustained backpressure. Bound the queue and,
on overflow, fall back to immediate direct send (privacy-degraded but
non-blocking) with a logged counter. This trades a *continuous* activity leak
(r=0.63) for a *burst-only* leak that appears solely above 2 tx/s.

### Latency (measured)

| Traffic class | Added latency under this CIP |
|---|---|
| Node's own originations (sends + churn) | ≤1 slot; **mean 250 ms, p95 475 ms** |
| Relay / block / inv / consensus | **+0.0 ms** (bypasses pacer) |

≤500 ms on the node's own outgoing transaction is acceptable (tx submission is
not latency-critical); consensus propagation is untouched.

Non-consensus: this changes *when a node emits its own already-formed packets*,
not block validity, and cannot fork the chain. `traffic_shaping.rs` is not
hash-locked. But it sits on the outbound send path, so it is off-by-default and
test-gated.

## Configuration

New flag, **default off**, additive to `TrafficShaperConfig`:

- `constant_rate_enabled: bool` (default `false`) — when true, engage
  substitutive origination pacing and disable the additive padding loop + jitter.

Existing `padding_enabled` / `jitter_enabled` remain the default behavior until a
node opts in. No default-path behavior change ships with the implementation.

## Test plan (gates deployment)

- **Unit:** pacer emits exactly one packet per slot; a queued origination is sent
  in preference to a dummy; an empty queue emits a dummy; queue respects its
  bound and the overflow path fires the direct-send fallback + counter.
- **Statistical (harness, committed):** additive design yields observer r ≳ 0.5;
  substitutive yields r ≈ 0. Regression-guard the r ≈ 0 property.
- **Latency (harness):** own-origination added latency ≤ 1 slot; relay/block
  path shows **zero** added latency (pacer not on that path).

## Rollout

1. Land the pacer off-by-default with the tests above green. Zero default change.
2. Enable `constant_rate_enabled` on **one** non-critical relay node; capture an
   instrumented outbound trace and confirm the live r matches the model (~0) and
   block propagation timing is unchanged.
3. Then miner/wallet-bearing nodes, one at a time, per the deploy runbook.

## References

- `src/network/traffic_shaping.rs` — additive padding loop (`run_padding_loop*`),
  `apply_jitter`, `shape`; the pacer lands here.
- `src/network/node.rs` — per-peer `peer_senders` mpsc write path (the merge
  point); Dandelion stem origination is the hook for the origination queue.
- `src/wallet/churn.rs:186` — Poisson churn scheduling (already correct).
- `scratchpad/timing_leak_test.py` — the red-team harness (r=0.63 → r=0.00).
- Whitepaper §5 (composition safety) — this CIP upgrades the section from
  asserted to empirically measured.
- CIP-019 — near-tip propagation; the reason relay/block traffic must not be
  paced.
