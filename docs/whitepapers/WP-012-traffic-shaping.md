# WP-012 · Traffic Shaping
### Constant-rate padding, size normalisation, and timing jitter

**Status:** Shipped · **Layer:** Network · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Transaction-level privacy protects what is *in* a transaction. It does nothing
about the fact that a network observer can see you are **using a privacy coin at
all**, when you are active, and often what kind of message you just sent.

Three observables leak without any protocol analysis:

- **Presence** — a node's traffic pattern identifies it as a cryptocurrency node.
- **Size** — message lengths differ by type, so a passive observer distinguishes
  a block announcement from a transaction announcement from a handshake.
- **Timing** — "node A sent at T, node B received at T + latency" correlates
  peers and locates transaction origins.

For a user whose ISP, employer, or government is the adversary, these can matter
more than transaction contents. Being *identifiable as a privacy-coin user* is
itself the harm in many threat models.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Protocol identification / DPI** — an ISP classifies traffic as CoinCync and blocks or flags it | The protocol has a recognisable wire signature | Messages padded to standard TLS frame sizes; traffic resembles generic TLS/HTTPS |
| **Message-type inference from length** | Different message types have different sizes | All outbound messages normalised to a common size ladder |
| **Activity-pattern analysis** — bursts reveal when the user transacts | Traffic volume tracks real activity | Constant-rate dummy padding: steady bandwidth regardless of activity |
| **Timing correlation** — link sender and receiver by send/receive timestamps | Messages are emitted immediately on generation | Random 0–200 ms jitter decouples action from packet |
| **Absence inference** — silence signals inactivity | Not sending is unobservable | Cover traffic makes "no real message" indistinguishable from "a real message" |

---

## 3. Design

Three layers, each removing a different observable. They are complementary, not
redundant — removing any one leaves an exploitable channel.

### 3.1 Constant-rate padding

Dummy packets are emitted at fixed intervals so an observer sees **steady
bandwidth regardless of real activity**. This removes both activity-timing and
absence as signals: a node that is idle and a node that just broadcast a
transaction look identical on the wire.

This is the most expensive layer (it consumes bandwidth continuously) and the
most necessary — without it, the other two only disguise *what* you sent, not
*that* you sent.

### 3.2 Packet size normalisation

Every outbound message is padded **up** to the next rung of a fixed ladder:

```
256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
```

Above the top rung, lengths round up to a whole multiple of 65536. An observed
size therefore reveals only *which rung* a payload fell in, never its exact
length. The ladder is powers of two — cheap to reason about, and wide enough to
cover everything from tiny control frames to full blocks. 16384 bytes is also the
maximum TLS record size, which is the sense in which the shaped profile resembles
ordinary TLS traffic.

> **Precision note.** The module's own doc-comment describes this as padding "to
> the nearest standard TLS frame size." The implemented ladder is the
> power-of-two sequence above, which is TLS-*like* but not a reproduction of any
> particular TLS implementation's record-size distribution. The weaker, accurate
> statement is the one this paper makes: exact lengths are hidden and sizes
> cluster onto nine values.

Normalisation happens at the **Noise record layer**, applying to every
post-handshake message uniformly — not just to transactions. A shaper that
protects only "sensitive" messages labels them by omission.

The rule is enforced on **receipt**, not merely applied on send: a normalised
framer rejects any frame whose wire length is not on the ladder
(`non-canonical normalized frame size`). Uniformity that only the sender honours
is a convention; uniformity the receiver checks is a protocol rule.

### 3.3 Timing jitter

A random delay of 0–200 ms is applied to outbound messages, breaking the tight
correlation between an internal event (a wallet broadcasting, a block being
validated) and the packet that carries it. This raises the cost of the
"first-relay = origin" inference that network-level deanonymisation depends on,
and composes with Dandelion++ (WP-020), which attacks the same inference at the
routing layer.

### 3.4 Ordering and completeness

The layers compose in a specific order — jitter and padding are applied to
already-normalised records — and the set only works complete. Partial shaping is
frequently *worse* than none: a system that pads only some messages, or
normalises size but emits on a predictable schedule, produces a smaller and more
confident candidate set for an observer than an unshaped system would. This is
the ordering discipline discussed in WP-009 §3.8.

### 3.5 Constitutional grounding

The module cites the project's Bill of Rights, Article IV (the Fourth Amendment
analogue) as its basis. This is deliberate: network-level privacy is treated as a
declared user right rather than an optional performance trade-off, which is why
the expensive constant-rate layer is on by default rather than opt-in.

---

## 4. Security analysis

**What holds.** Against a passive local observer (ISP, network operator, DPI
appliance), the three layers remove message-type-by-size, activity timing,
absence, and the immediate send/receive correlation, and present a TLS-like
profile rather than a novel protocol signature.

**What this does not protect against — stated plainly.**

- **Traffic-analysis research moves.** Website-fingerprinting literature has
  repeatedly defeated padding schemes that looked sound, using volume-over-time
  and burst-structure features rather than individual packet sizes. Constant-rate
  padding is the strongest of the three layers precisely because it attacks that
  class, but "resembles TLS" is a claim about current classifiers, not a proof.
- **A global passive adversary** who sees both ends can still correlate; shaping
  raises cost, it does not defeat end-to-end observation. Tor/I2P transport is the
  answer to that threat model, and is supported separately.
- **It does not hide that you run a node** from anyone who can connect to you.
  Peer-level identification is a different problem from wire-level classification.
- **Bandwidth cost is real.** Constant-rate padding consumes bandwidth
  proportional to the padding rate whether or not the user transacts, which is a
  genuine cost on metered or slow connections.
- **No measured evaluation yet.** We have not run a classifier against shaped
  CoinCync traffic to quantify the indistinguishability claim. Until that exists,
  §3.2's "resembles TLS/HTTPS" is a design intent backed by construction, not a
  measurement.

---

## 5. Implementation

| Component | Location |
|---|---|
| Three-layer shaper (padding, normalisation, jitter) | `src/network/traffic_shaping.rs` |
| Record-layer framing / size normalisation | `src/network/framing.rs` |
| Message envelope + canonical encoding | `src/network/protocol.rs` |
| Padding message type | `src/network/protocol.rs` (dedicated type, replacing an earlier framer-conflict workaround) |
| Transport (Noise), Tor/onion options | `src/network/`, node CLI (`--tor`, `--onion-only`, `--proxy`) |

**Related.** The uniform-envelope property is stated precisely in WP-011
(*canonical observable envelope*), and the routing-layer half of origin
protection is WP-020 (Dandelion++). The three together are the propagation stack
of WP-009 §3.8.

---

## 6. Known limits

- Effectiveness is **unmeasured** against modern traffic classifiers (§4).
- Constant-rate padding trades bandwidth for privacy on every connection.
- Jitter bounded at 200 ms is a latency/privacy compromise; larger windows buy
  more decorrelation at the cost of propagation speed, which has consensus
  implications (orphan rate).
- Shaping protects the wire, not the peer graph; eclipse and peer-selection
  concerns are WP-022.

---

## 7. References

- Website-fingerprinting and traffic-analysis literature (the reason §4's
  caveats exist).
- Bojja Venkatakrishnan et al., *Dandelion++* (2018) — complementary routing-layer
  defence.
- Tor Project padding/traffic-shaping design documents.
- Internal: [WP-009 §3.8](WP-009-privacy-feature-composition.md),
  [WP-011 Uniformity](WP-011-transaction-uniformity.md),
  [WP-020 Dandelion++](WP-020-dandelion.md).
