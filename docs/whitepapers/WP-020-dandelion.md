# WP-020 · Dandelion++ Origination Privacy
### Breaking the "first broadcaster is the sender" inference

**Status:** Shipped · **Layer:** Network · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Ring signatures hide *which output* is being spent. Confidential amounts hide
*how much*. Neither hides **who broadcast the transaction** — and for a
network-level adversary that is often the easiest and most valuable attack.

The technique is simple and well-documented: connect to many nodes, record which
node first announces each transaction, and treat that node as the origin. It
requires no cryptanalysis, scales cheaply, and directly links a transaction to an
IP address. A privacy chain without origination protection has a gap that
undermines everything above it in the stack.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **First-broadcast origin attribution** — the node that announces first is the sender | Transactions propagate outward from the origin immediately | A stem phase: the transaction is relayed along a private path before any public broadcast |
| **Per-transaction routing fingerprint** — different routing per transaction distinguishes a node's own transactions from relayed ones | Routing is decided per transaction | Per-**epoch** mode decision: every transaction in an epoch is routed the same way |
| **Graph-learning** — an adversary maps a node's stem peers by observing many transactions | Stem peers are re-chosen frequently and observably | Two fixed relay peers per epoch, with deterministic per-inbound-edge mapping |
| **Timeout de-anonymisation** — the origin systematically fluffs first, revealing itself | Embargo timers are fixed or uniform | Exponentially distributed embargo timers (memoryless) |

---

## 3. Design

CoinCync implements Dandelion++ (Fanti et al., 2018; BIP 156), following
Monero's battle-tested parameter choices rather than inventing our own.

### 3.1 Stem and fluff

A transaction propagates in two phases:

- **Stem** — relayed to a single chosen peer, then that peer to one of *its*
  chosen peers, forming a private path. During this phase the transaction is not
  broadcast, so an observer sees it at one node at a time along an unknown route.
- **Fluff** — at some point a node switches to normal flooding, and the
  transaction diffuses to the whole network.

The origin is hidden because the node that *fluffs* is not the node that
*created* — and the adversary cannot tell how many stem hops preceded the fluff.

### 3.2 Per-epoch mode decision

Each **epoch (~10 minutes)** the node makes a single random decision: stem mode
or fluff mode. **All transactions received in that epoch follow the same
decision.**

This is the subtle and important part. If a node decided per transaction, its own
transactions could be routed differently from relayed ones, and the difference
would be observable — reintroducing exactly the attribution the protocol
prevents. A uniform per-epoch decision means a node's behaviour toward its own
transaction is indistinguishable from its behaviour toward everyone else's.

### 3.3 Two fixed relay peers per epoch (quasi-4-regular graph)

At epoch start the node selects **two outbound relay peers**, and inbound peers
are **deterministically mapped** to one of the two (per-inbound-edge routing).
This approximates the quasi-4-regular graph the Dandelion++ analysis assumes.

The properties that matter:

- **Stability within an epoch** prevents an adversary from learning the stem
  graph by observing many transactions from one node — the routes do not vary
  per transaction.
- **Deterministic inbound mapping** means the same inbound edge always forwards
  to the same relay, so an adversary cannot probe by sending many transactions
  and watching the path change.
- **Rotation between epochs** limits how long a compromised relay sits on a
  node's path.

### 3.4 Exponential embargo timers

Each stem-forwarded transaction receives an **embargo timer drawn from an
exponential distribution**. If the timer expires before the node sees the
transaction fluffed by someone else, it fluffs the transaction itself — a
liveness guarantee against a stem path that dies (a peer that goes offline or
maliciously black-holes).

The distribution matters. The exponential is **memoryless**: how long a
transaction has already been embargoed tells you nothing about how much longer it
will be. With fixed or uniform timers, the originating node — which started its
timer first — systematically times out first and fluffs its own transaction,
which is precisely the attribution the protocol exists to prevent. Memorylessness
removes that ordering bias.

---

## 4. Security analysis

**What holds.** Origin attribution by first-broadcast is defeated for a partial
adversary: the fluffing node is not the origin, the stem path is not observable
from outside, routing does not vary per transaction, and embargo expiry does not
favour the originator.

**What this does not protect against.**

- **A global passive adversary.** Dandelion++ is explicitly designed against a
  *partial* adversary with a bounded fraction of the network. An observer who sees
  all links can follow a stem path directly. Tor/I2P transport addresses that
  threat model; this does not.
- **A stem peer that is the adversary.** If the first stem hop is hostile, it
  learns the transaction came from its predecessor — though not whether that
  predecessor was the origin or another stem hop. The two-relay-per-epoch design
  bounds exposure; it does not eliminate it.
- **Timing analysis across the stack.** Stem routing hides *who broadcast*; the
  timing and size of the packets carrying it are the traffic shaper's job
  (WP-012). Neither alone is sufficient — this is the layer-completeness point of
  WP-009 §3.8.
- **Chain-level analysis is untouched.** Dandelion++ protects the network layer
  only. If the transaction graph itself leaks (weak decoys, non-uniform amounts),
  origination privacy does not help.

**Live status.** The implementation is present and follows the published
parameterisation. We have **not** run an adversarial network-level evaluation
(e.g. an instrumented multi-node deployment measuring attribution accuracy), so
the guarantee here rests on correct implementation of a published protocol rather
than on our own measurement.

---

## 5. Implementation

| Component | Location |
|---|---|
| Epoch mode decision, stem/fluff routing, relay selection, embargo timers | `src/network/dandelion.rs` |
| Relay/broadcast integration | `src/network/node.rs`, `src/bin/node.rs` |
| Mempool admission of fluffed transactions | `src/mempool.rs`, `src/bin/node.rs` |
| Transport privacy options (Tor/onion/proxy) | node CLI (`--tor`, `--onion-only`, `--proxy`) |

---

## 6. Known limits

- Effectiveness is **inherited from the published protocol**, not independently
  measured on our network (§4).
- Parameters (~10 min epochs, 2 relays) follow Monero's choices; they have not
  been re-derived for CoinCync's topology or transaction rate.
- Stem-phase liveness depends on embargo timers; a hostile or failing relay
  delays (but does not lose) a transaction.
- Protection is partial-adversary only, by design.

---

## 7. References

- Bojja Venkatakrishnan, Fanti et al., *Dandelion++: Lightweight Cryptocurrency
  Networking with Formal Anonymity Guarantees* (2018).
- BIP 156 (Dandelion) — the Bitcoin proposal and its discussion.
- Monero's Dandelion++ deployment and parameter choices.
- Internal: [WP-012 Traffic shaping](WP-012-traffic-shaping.md),
  [WP-009 §3.8](WP-009-privacy-feature-composition.md).
