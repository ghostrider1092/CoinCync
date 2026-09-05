# WP-022 · Relative Peer Eviction
### Eclipse resistance without absolute protection

**Status:** Shipped · **Layer:** Network · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Every defense in this series assumes the node can see the real chain. Eclipse the
node — control every peer it talks to — and none of them apply. The victim
validates diligently against a reality the attacker chose: it accepts a fabricated
history, misses the honest chain, and can be shown a payment that will never
confirm.

The attack is cheap in its naive form. Open connections until the victim's inbound
slot table is full. A node that accepts connections until saturated and then
**rejects newcomers** is permanently pinned by whoever arrived first — and the
attacker's connections will not voluntarily leave.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Inbound slot saturation** — fill every slot, then wait | A full node rejects new connections | When full, the node **evicts** rather than rejects |
| **Single-netgroup flooding** — 64 connections from one /16 | All peers are equally evictable | Eviction concentrates on the netgroup with the most candidates |
| **Churn attack** — cycle connections to displace established peers | Recency alone decides who stays | The longest-connected peers are protected |
| **Address-table poisoning** — flood the addr table so honest addresses are evicted before you ever dial them | Any gossiped address may enter the table | Netgroup quota, enforced **before** eviction |
| **Cheap attacker connections** — attacker peers cost the same to keep as honest ones | Connection cost is uniform | Encrypted peers win ties, biasing eviction toward cheaper plaintext peers |

---

## 3. Design

The algorithm is a port of Bitcoin Core's `AttemptToEvictConnection` /
`SelectNodeToEvict`, with two CoinCync-specific adaptations. Following
battle-tested prior art here is deliberate: eclipse resistance is an area where
novelty is a liability.

### 3.1 The inversion: sacrifice, don't reject

When the inbound table is saturated and a new connection arrives, the node picks
the **most-evictable existing peer** and disconnects it, rather than turning the
newcomer away.

This single inversion is what breaks slot-pinning. Under a reject policy an
attacker who arrives first holds the slots indefinitely. Under an evict policy
every new honest connection gets a chance, and the attacker must keep paying to
re-establish. The property is **relative**, not absolute: eviction does not
identify attackers, it makes *concentration* the thing most likely to be
sacrificed.

### 3.2 Protection axes, then netgroup concentration

Selection runs in two stages. First, protect peers that have earned it:

1. The **4 longest-connected** peers — a loyalty bonus that makes churn attacks
   expensive.
2. The **4 most-recently-active** peers — a signal of useful mutual traffic.
3. The **4 highest-reputation** peers — well-behaved by the peer scorer.

Then, among everyone left:

4. Group candidates by **netgroup** (IPv4 /16, IPv6 /32).
5. Pick the netgroup with the **most** candidates — that is where saturation is
   concentrated.
6. Within that group, evict the **youngest** (last-in, first-out).

Step 5 is the core idea. An attacker's connections tend to share address space; a
healthy peer set is diverse. Preferring to evict from the largest group makes the
attacker's own concentration the signal that selects them, without needing to
classify anyone as malicious. Step 6 then means the attacker's *newest*
connection is the one that dies — so each additional connection is spent
displacing its own predecessor.

### 3.3 Two CoinCync adaptations

**Different telemetry.** Bitcoin Core protects by `min_ping` and
`last_tx_received`. CoinCync does not collect either, so the protection axes use
`last_seen` (activity proxy) and peer-scorer `reputation` in their place. Same
structure, different signals.

**Encryption tie-break.** When two peers are otherwise equally evictable, keep the
Noise-encrypted one. The rationale is **eviction-cost asymmetry**: an attacker
running many cheap connections is more likely to skip the handshake cost, so
biasing eviction toward plaintext peers raises attacker cost without penalising
any honest behaviour we want to encourage.

### 3.4 Reject-before-evict in the address table

Eviction protects live connections; the **address table** needs its own defense,
and it needs a different one. Each netgroup holds a quota, and a gossiped address
whose netgroup is already at quota is **rejected outright, before any eviction
runs**.

The ordering is the whole point. If quota enforcement ran after eviction, an
attacker flooding one /16 would push honest, diverse addresses out of the table
first, and the node would eventually dial only the attacker — an eclipse achieved
without holding a single connection. Rejecting first means the flood is absorbed
as a no-op instead of as displacement.

### 3.5 An upstream citation we corrected

An earlier version of this module cited `NumProtectedPeers = 4` as a named
Bitcoin Core constant. Re-checking upstream found no such named constant: Core
uses a **mix of 4 and 8** across its axes (4 by netgroup, 8 by ping, 4 by tx-time,
8 by block-relay-only-time).

The identifier claim was dropped. The 4-per-axis choice is retained and now stands
as a CoinCync design decision justified on its own merits — three axes × 4 gives
up to 12 protected peers — rather than by borrowed authority. Citations that turn
out not to say what they were claimed to say are worse than none, because they
stop the reader from checking.

---

## 4. Security analysis

**What holds.** Slot-pinning by first-arrival is broken; concentrated netgroups
are preferentially sacrificed; established and well-behaved peers are protected
from churn; the address table cannot be displaced by a single-netgroup flood.

**What this does not protect against — and the reason for this paper's subtitle.**

- **A well-resourced, address-diverse attacker.** Every mechanism here keys on
  *concentration*. An attacker with addresses spread across many /16s defeats the
  netgroup heuristic entirely. Eviction raises the price of an eclipse from
  "trivial" to "requires diverse address space"; it does not make eclipse
  impossible.
- **Outbound eclipse.** This module governs **inbound** slots. A node whose
  outbound peers are all attacker-controlled — via address-table poisoning that
  predates the quota, or a hostile DNS seed — is eclipsed regardless. Outbound
  peer diversity is a separate concern.
- **The protection axes are exploitable in principle.** An attacker who connects
  early, stays active, and behaves well accrues protection on all three axes. The
  axes are designed so that earning protection requires behaving usefully for a
  long time, which is a cost, not an impossibility.
- **Reputation is a local heuristic**, not a trust anchor; it reflects observed
  behaviour on this node only.
- **No live adversarial evaluation.** The algorithm's properties are inherited
  from upstream analysis and reasoning about the code; we have not run an
  instrumented eclipse attempt against a CoinCync node.

---

## 5. Implementation

| Component | Location |
|---|---|
| Eviction candidate selection, protection axes, netgroup grouping | `src/network/eviction.rs` |
| Encryption tie-break | `src/network/eviction.rs` |
| Address-table netgroup quota, reject-before-evict | `src/network/bootstrap.rs` |
| Peer reputation input | `src/network/relay_score.rs`, `src/network/scoring.rs` |
| Peer state (`last_seen`, connection age) | `src/network/peer.rs` |

**Related.** Per-message rate limiting is **intentionally absent**, matching
Bitcoin's posture; audits have repeatedly flagged this as a gap and it is a
deliberate choice, not an oversight.

---

## 6. Known limits

- Netgroup heuristics fail against address-diverse attackers (§4).
- Inbound only; outbound diversity is not addressed here.
- Protection axes can be earned by a patient attacker.
- Quotas and the 4-per-axis figure are policy numbers, not derived bounds.
- Unmeasured against a live eclipse attempt.

---

## 7. References

- Heilman et al. (2015), *Eclipse Attacks on Bitcoin's Peer-to-Peer Network* —
  the motivating analysis.
- Bitcoin Core `CConnman::AttemptToEvictConnection` (`src/net.cpp`) and
  `SelectNodeToEvict` (`src/node/eviction.cpp`) — the ported algorithm.
- Bitcoin Core `CompareNetGroupKeyed` — the subnet-group comparator.
- Internal: [WP-020 Dandelion++](WP-020-dandelion.md),
  [WP-021 Orphan reconnection](WP-021-orphan-reconnection.md),
  [WP-005 Reorg defense](WP-005-layered-reorg-defense.md).
