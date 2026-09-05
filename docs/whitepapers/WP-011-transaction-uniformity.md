# WP-011 · Transaction Uniformity
### The canonical observable envelope

**Status:** Shipped (one policy layer defined but unwired) · **Layer:**
Cross-cutting · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Anonymity is a **set**, and every observable difference partitions it. A user who
picks a larger ring, attaches a memo, runs a distinctive build, or emits an
oddly-sized packet has not merely revealed that one fact — they have removed
themselves from the crowd that made the fact private in the first place.

This produces the defining irony of configurable privacy: **the users who tune
their privacy settings up are the easiest to find.** A chain that offers a
ring-size slider hands its most careful users the smallest anonymity sets.

CoinCync's response is to remove the choices. Where a parameter is observable, it
is fixed for everyone; where a field is variable, it is padded to a constant. The
target property — stated in the precise form we settled on after review — is a
**canonical observable envelope**: everything an observer can see about a
transaction or a message is drawn from a single shared form.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Anonymity-set partitioning by user choice** — ring size, privacy level, fee tier | Users may configure observable privacy parameters | Fixed ring size, network-wide; no user-selectable privacy knob |
| **Feature-use fingerprinting** — memo users, recovery-metadata users, churners are identifiable | Optional features may cost only what they use | Fixed-size padded fields, so using the feature is invisible |
| **Exact-length leakage on the wire** | Message length may be sent as-is | Nine-rung size ladder; exact lengths never observable |
| **Sender-only shaping** — a peer that skips normalisation still gets served | Uniformity is a courtesy | Receiver **rejects** non-canonical frame sizes |
| **Build/version fingerprinting** — a distinctive user-agent re-identifies a node across sessions | Nodes may advertise their build | One canonical user-agent for the entire network (policy defined; see §5) |
| **Randomisation-as-fingerprint** — a "randomised" identifier whose distribution is itself distinctive | Randomising an identifier hides it | A single shared constant, not a random or empty value |

---

## 3. Design

### 3.1 Fixed ring size, not a user choice

`RING_SIZE = 16` network-wide. There is no per-transaction ring-size option,
because offering one would let users sort themselves. Below height **10,000** a
bootstrap minimum of **11** applies, because a young chain does not have enough
outputs to fill larger rings.

That bootstrap concession is deliberately **chain-wide and scheduled**, not
per-user and adaptive. Everyone in the bootstrap era shares the same reduced ring:
the anonymity set is smaller, but it is not *partitioned*. When two privacy
requirements genuinely conflict, degrading uniformly and visibly is the honest
resolution (WP-009 §3.9).

`MAX_RING_SIZE = 32` bounds validation cost; it is a DoS ceiling, not an
invitation to vary.

### 3.2 Fixed transaction shape — the strongest rule here

Input and output *counts* are as identifying as any field. A 1-in/2-out payment,
a 7-in/1-out consolidation, and a 2-in/2-out transfer are three visibly different
transaction classes, and in transparent chains this shape is one of the most
productive signals clustering heuristics have.

CoinCync removes it at consensus. From `UNIFORM_TX_SHAPE_HEIGHT`,
`check_tx_uniform_shape` requires every `Transfer` and `Churn` transaction to have:

- **exactly 2 inputs** (`STANDARD_INPUT_COUNT`), and
- **exactly 2 outputs** (CYNC) or **3** (asset transfer — the asset, plus CYNC
  change and asset change).

Churn is additionally required to be pure CYNC.

Unlike the memo padding in §3.3, this one is **enforced by consensus, not by
wallet convention** — a non-conforming transaction is rejected by the network, not
merely unusual. That makes it the strongest uniformity guarantee in the system,
and the one that most distinguishes CoinCync from Monero, which permits variable
input and output counts.

Three consequences follow, and the third is a genuine cost:

1. **Transaction shape carries no information.** Every ordinary transaction looks
   structurally identical.
2. **Consolidation is impossible**, which is what makes classic dust attacks
   structurally weak here (WP-018).
3. **Users cannot sweep many small outputs.** A wallet holding numerous small
   UTXOs cannot combine them. The `UniformDripPair` send shape — two equal
   outputs, no change output, input excess folded into the fee — exists to keep
   outputs uniform where a change output would break them, with a fail-closed
   guard when the excess would exceed the amount actually being sent (burning more
   to fee than you pay the recipient is never intended).

The rule also made an older defense redundant: `check_tx_io_ratio_legacy` (a
32:1 input/output cap, originally justified against "dust attacks or chain
analysis") is now **functionally dead code** for all typical traffic, since
uniform shape blocks that vector at genesis. It is retained only because removing
a consensus rule requires a hard fork and the removal has no observable benefit.

### 3.3 Fixed-size optional fields

Confidential amounts (RingCT + Bulletproofs+) and stealth addresses already make
value and recipient uniform. The remaining variability is in optional payloads:

- **Encrypted memos** — capped at 256 bytes plus a nonce/tag envelope, with
  wallets padding *up to* the cap so a transaction carrying a memo is
  indistinguishable in size from one that does not.
- **Dead-man's-switch recovery metadata** — a fixed-size record in the `extra`
  field, so a protected transaction is not identifiable as one. This matters more
  than most: identifying such transactions identifies precisely the users who have
  declared their keys may be at risk.
- **Churn transactions** — same structure, same ring size, same padding as an
  ordinary transfer, with Poisson-distributed timing (a periodic self-send is
  itself a signature).

### 3.4 The wire envelope

Every post-handshake message is normalised at the **Noise record layer** to the
next rung of a fixed ladder — `256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
65536` bytes, then whole multiples of the top rung. An observer learns which rung
a payload fell in and nothing finer.

Normalisation covers **every** message type, not just transactions. Protecting
only "sensitive" messages labels them by omission — the shaper's coverage must be
total or it becomes a classifier.

Full mechanics, including cover traffic and timing jitter, are WP-012.

### 3.5 Enforced on receipt, not just applied on send

A normalised framer **rejects** any frame whose wire length is not on the ladder,
with a `non-canonical normalized frame size` error. This is the distinction
between a convention and a rule: uniformity only the sender honours can be
unilaterally abandoned by a peer that benefits from standing out, or silently
lost to a bug. Checking on receipt makes the property observable and testable
from the other side of the connection.

The reader also enforces per-type semantic limits, so normalisation cannot be
used to smuggle an oversized logical payload inside a large rung.

### 3.6 Canonical identity strings

A node's advertised user-agent is a re-identification handle. The policy is a
single constant — `/coincync/` — for the entire network, deliberately
version-less and build-less.

The reasoning behind choosing a *constant* over the two obvious alternatives is
worth stating, because it generalises:

- A **randomised** user-agent is itself a fingerprint — the randomness
  distribution leaks, and the set of nodes emitting random strings is a set.
- An **empty** user-agent is a fingerprint, because few nodes do it.

A single shared constant is the only option that makes nodes *mutually*
indistinguishable. This is the general lesson: **hiding a value and making a
value uniform are different operations**, and only the second grows the anonymity
set.

### 3.7 What "uniform" claims, precisely

An earlier formulation of this property claimed nodes are **byte-identical** on
the wire. That claim is too strong — encrypted payloads differ, and timing is not
a byte. The property we assert is a **canonical observable envelope**: the
*observable* attributes (size ladder, advertised identity, transaction shape,
ring size, field lengths) are drawn from one shared canonical form. The tightening
came from external review and is kept because the weaker claim is the true one.

---

## 4. Security analysis

**What holds.** Ring size, transaction shape, optional-field lengths, and wire
message sizes do not vary by user choice; the wire ladder is enforced on both
sides; the canonical-identity policy has one audited definition.

**What this does not protect against.**

- **Memo padding is a wallet convention, not consensus.** Consensus enforces the
  256-byte *cap* (at block validation from the v1.0.12 hard fork, height 13,000,
  to prevent miner-crafted bloat that bypasses mempool admission). It does **not**
  require padding *up* to the cap. A modified wallet emitting a short memo
  produces a smaller transaction and self-identifies. Honest wallets pad; the
  protocol does not compel it. Closing this would require a consensus rule
  mandating a fixed encrypted-memo length.
- **Uniformity is not unlinkability.** Identical-looking transactions can still be
  linked through the transaction graph, decoy-selection weakness (WP-010), or
  timing. Uniformity removes *one* class of distinguisher.
- **Anonymity-set size is what it is.** Perfect uniformity across a small user
  base is still a small set.
- **Bootstrap rings are genuinely weaker.** Below height 10,000 the ring is 11,
  not 16 — uniformly weaker, but weaker.
- **Behaviour is observable even when bytes are not.** *When* a node sends, which
  peers it connects to, and how it responds to probes are not covered by envelope
  uniformity. Those are WP-012 (timing) and WP-022 (peer graph).

---

## 5. Implementation

| Component | Location |
|---|---|
| `RING_SIZE`, `BOOTSTRAP_MIN_RING_SIZE`, `ring_size_at_height` | `src/constants.rs` |
| `MAX_OUTPUT_MEMO_SIZE` + consensus cap at the v1.0.12 fork | `src/constants.rs`, `src/consensus/validation.rs` |
| Memo encryption, `MAX_MEMO_SIZE` / `MEMO_OVERHEAD` | `src/crypto/memo.rs` |
| Size ladder (`SIZE_BUCKETS`, `padded_len`), canonical user-agent | `src/colony/stick_insect.rs` |
| Live wire normalisation | `src/network/traffic_shaping.rs` |
| Receipt-side enforcement (`is_normalized_payload_size`, semantic limits) | `src/network/framing.rs` |
| Recovery metadata, churn shape/timing | `src/bin/wallet_support/legacy.rs`, `src/wallet/churn.rs` |

**Status caveat — one layer is policy-only.** `stick_insect` defines the
canonical user-agent and the size ladder as a pure, testable policy with one
audited definition. The **size ladder is live** (traffic shaping and framing use
it). The **canonical user-agent is not yet wired to the handshake banner** — that
is explicitly a later phase in the module's own documentation. Until it is,
§3.5's property is a specified policy, not an enforced one, and node build
strings remain a potential re-identification handle.

---

## 6. Known limits

- Canonical user-agent defined but **unwired** to the handshake (§5).
- Memo padding is wallet-side convention; consensus enforces only the cap (§4).
- Bootstrap ring size is a real, scheduled weakening.
- No measurement of how well the envelope resists a classifier — the same gap
  noted in WP-012 §4.
- Uniformity guarantees are structural, not proven; there is no formal argument
  that the enumerated observables are the complete set.

---

## 7. References

- Möser et al. (2018) — empirical work on how uniformity failures become
  practical deanonymisation.
- Monero's fixed-ring-size decision and its history of optional-ring-size
  vulnerabilities — the prior art for §3.1.
- Internal: [WP-009 Privacy composition](WP-009-privacy-feature-composition.md),
  [WP-010 Decoy selection](WP-010-decoy-selection.md),
  [WP-012 Traffic shaping](WP-012-traffic-shaping.md),
  [WP-025 The colony](WP-025-colony.md).
