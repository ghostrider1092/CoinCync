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

Each epoch — **600 s base plus 0–30 s jitter**, so epoch boundaries are not
network-synchronised — the node makes a single random decision: stem mode, or
fluff mode with probability **20 %**. Every **relayed** transaction in that epoch
follows the same decision.

The decision is per *epoch*, not per transaction, because per-transaction routing
would let an observer compare how a node treats different transactions and infer
which ones it originated.

**Local transactions are the deliberate exception: they always stem, even during
a fluff epoch** (`always_stem_local`, following Monero). This is the opposite of
what a naive uniformity argument suggests, and the reason is that the naive
argument optimises the wrong thing:

- If your own transaction followed fluff mode, then 20 % of the time you would
  **broadcast your own transaction directly from your own node** — immediate,
  unambiguous origin attribution. That is the exact attack this protocol exists
  to stop.
- Always stemming locally costs a narrower leak instead: a hostile *first stem
  relay* could infer "this came from that node" if it independently knew the
  sender was in a fluff epoch — which it does not directly observe.

A guaranteed leak 20 % of the time is worse than a conditional leak that requires
the adversary to be your chosen relay *and* to know your epoch mode. The trade is
recorded here rather than smoothed into a uniformity story, because the design
genuinely is non-uniform at this point and a reader checking the code would
otherwise find the paper wrong.

*(An earlier revision of this paper claimed all transactions, local included,
follow the epoch decision. That was written from the module's summary comment and
is incorrect; corrected after reading `add_local_tx`.)*

### 3.3 Two fixed relay peers per epoch (quasi-4-regular graph)

At epoch start the node shuffles its **outbound** peers and takes up to two as
relays, approximating the quasi-4-regular graph the Dandelion++ analysis assumes.
Selection uses the OS CSPRNG, not a thread RNG — stem-peer choice is a privacy
boundary, and a predictable RNG state would let an observer fingerprint which
peer a node picked.

Inbound peers are assigned to one of the two relays **lazily and
load-balanced**: on first contact an inbound edge goes to whichever relay
currently has fewer inbound peers mapped to it, and that assignment is then
**stable for the rest of the epoch**. Local transactions use a single relay index
chosen at random for the epoch.

The properties that matter:

- **Stability within an epoch** prevents an adversary from learning the stem
  graph by observing many transactions from one node — the routes do not vary
  per transaction.
- **A stable per-edge assignment** means the same inbound edge always forwards to
  the same relay, so an adversary cannot probe by sending many transactions and
  watching the path change.
- **Rotation between epochs** limits how long a compromised relay sits on a
  node's path.

*(Assignment is stable, not a deterministic function of the peer id: it depends
on the order edges are first seen. The anti-probing property above depends only
on stability, which holds.)*

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

Mean **39 s**, capped at **180 s**, floored at 5 s. Monero made this same
correction — from Poisson to exponential — in PR #9295.

### 3.5 The second timer: randomised stem forwarding

There are **two** exponential timers, not one, and the second is easy to miss.

The embargo (§3.4) decides when to *give up* on a stem path. A separate
exponentially distributed delay, mean **5 s** and capped at 30 s, decides when to
*forward* a stem transaction to the next hop.

Without it, every stem transaction would be forwarded on the node's next
housekeeping tick — a fixed 10-second cadence. That fixed cadence is a **timing
signature**: an observer watching a node emit stem forwards on a predictable
clock can separate the transaction that started at that node from ones merely
passing through, which defeats stem routing at the timing layer while the routing
layer is working perfectly.

This matches Monero's `CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE` (5 s), verified
against `src/cryptonote_config.h:113`. It is the same principle as WP-012's
timing jitter and WP-015's Poisson churn intervals: **a mechanism with a schedule
must randomise that schedule, or the schedule identifies the mechanism**
(WP-009 §4 rule 5).

### 3.6 Stempool bounds and flood eviction

The stempool holds at most **10 000** entries. Which entry gets evicted when it
fills is a privacy decision, not a housekeeping one.

Evicting strictly by age — the obvious policy — is exploitable. A node's **own**
transactions are older than an attacker's freshly injected flood by definition,
so oldest-first eviction means an attacker who floods the stempool **evicts the
victim's own transactions first**. Those transactions then never fluff and
silently disappear: the sender sees their payment vanish with no error.

The policy therefore evicts the oldest **peer-sourced** entry first, and only
falls back to local entries when no peer-sourced entry exists. An attacker's
flood now consumes its own oldest entries before touching anything local.

A related check, `has_adequate_privacy`, reports whether the node has at least
**3** peers — below that, stem routing has too few paths to provide meaningful
origin protection, and the node should be treated as unprotected rather than
assumed safe.

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

**Verification status (2026-09-04).** The implementation was read end to end
against this paper rather than against its own summary comment. Confirmed
present and correct: exponential embargo with the memoryless justification and
the Monero PR #9295 correction, two relay peers selected with the OS CSPRNG,
stable per-inbound-edge routing, epoch rotation with jitter, the separate
exponential stem-forward delay, and the flood-resistant stempool eviction policy.
It is a faithful implementation, and in two respects (the second timer, the
eviction fix) more complete than this paper originally described.

The review also found this paper wrong in one place — §3.2 claimed local
transactions follow the epoch's fluff decision; they always stem. That is
corrected above, and it is the reason the verification was done by reading the
code rather than the doc comment.

**Not verified.** We have **not** run an adversarial network-level evaluation —
no instrumented multi-node deployment measuring actual attribution accuracy
against a partial adversary. The guarantee rests on correct implementation of a
published protocol, not on our own measurement. Parameters follow Monero's and
have not been re-derived for CoinCync's topology or transaction rate.

---

## 5. Implementation

| Component | Location |
|---|---|
| Epoch rotation, relay selection, stem/fluff routing, both timers, stempool | `src/network/dandelion.rs` |
| `DANDELION_STEMS` 2, `FLUFF_PROBABILITY` 20, `EPOCH_BASE` 600 s + `JITTER` 30 s, `EMBARGO_MEAN` 39 s / `MAX` 180 s | `src/constants.rs` |
| `STEM_FORWARD_MEAN_SECS` 5, `MAX_STEMPOOL` 10 000, `MIN_PEERS_FOR_PRIVACY` 3 | `src/network/dandelion.rs` |
| Relay/broadcast integration, outbound peer registration | `src/network/node.rs`, `src/network/node/dispatch/control.rs`, `src/bin/node.rs` |
| Mempool admission of fluffed transactions | `src/mempool.rs`, `src/bin/node.rs` |
| Transport privacy options (Tor/onion/proxy) | node CLI (`--tor`, `--onion-only`, `--proxy`) |

**Tests.** The module's own suite covers stem-loop detection, fluff-epoch
immediate fluffing, embargo timeout, per-inbound-edge routing, epoch rotation and
inbound-map clearing, diffusion confirmation, the no-relay-peers fallback, and
the stempool limit.

**Failure record.** H16-FIX (fixed stem-forward cadence → timing signature),
P5-D2 (stempool flood evicted the victim's own local transactions).

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
