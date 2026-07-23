# Cynstra

### Concentric Privacy — privacy in layers, where no single break exposes the whole.

**Whitepaper · Draft v0.1**
*CoinCync (testnet) → Cynstra (mainnet)*

---

## Abstract

Cynstra is a permissionless, mandatory-privacy cryptocurrency mined on commodity CPUs. Its central contribution is not a new cryptographic primitive — the primitives it uses are proven and, in several cases, hardened over years by the work of others — but an **architecture**: *Concentric Privacy*.

Concentric Privacy is a defense-in-depth model in which independent privacy layers each guard a different attack surface, **degrade independently**, and are composed so that the failure of one layer does not deanonymize another. Consensus is **fail-operational** — the chain keeps producing valid blocks when a component fails; privacy is **fail-closed** — the protocol never silently downgrades to a weaker-privacy transaction. These two normally-opposing postures coexist because the layered structure absorbs the failure of any single mechanism: no one break reaches the center.

This paper describes the architecture, the reasoning behind it, its honest limitations, and the engineering discipline — *composition safety* — required to keep many privacy mechanisms from interfering with one another.

---

## 1. Motivation

Financial privacy is not a feature; it is a precondition for economic freedom. A payment system that records who paid whom, how much, and when — in a permanent, public ledger — is a surveillance system, regardless of intent. The distinction between "monitoring" and "surveillance" is not one a protocol can make: the protocol does not know who is asking. It protects everyone equally, or it protects no one reliably.

Three failures motivate Cynstra's design:

- **Optional privacy fails.** When a chain offers both transparent and shielded transactions, the transparent set leaks metadata about the shielded set, and social/economic pressure pushes users toward the transparent default. Privacy that can be toggled is privacy that will be toggled off — usually by the people who need it most.
- **Monolithic privacy fails catastrophically.** Systems that stake their guarantees on a single mechanism have a single point of failure. When one flaw is found, the whole guarantee can collapse at once — as the industry has repeatedly seen, from ring-signature traceability analyses to a zero-knowledge parameter bug that could have silently inflated an entire supply.
- **Proof-of-work centralizes.** When mining is captured by specialized hardware and pools, the "permissionless" property erodes into a handful of gatekeepers.

Cynstra answers each: privacy is **mandatory**, privacy is **layered** (no single point of failure), and mining is **CPU-only** via RandomX so that participation stays broad.

We build this with deep respect for the projects that came before — Monero, above all, which proved over nearly a decade, under real regulatory and academic pressure, that mandatory privacy can survive at scale. Cynstra does not aim to replace that work. It aims to explore the layers those projects deprioritized, to contribute what it learns back to the privacy commons, and to add one more independent implementation to a movement that is stronger for not being a monoculture.

---

## 2. Design philosophy: privacy is a movement, not a market

The adversary is not another privacy coin. The adversary is financial surveillance. Against that adversary, every serious privacy project is on the same side.

This reframing has a concrete consequence for design and for honesty. Because Cynstra is not trying to *beat* anyone, it is under no pressure to *overclaim*. It does not need to be "the most private coin"; it needs to be an honest, well-built, independently-valuable contribution. Where it reuses proven mechanisms, it says so. Where its own additions are younger and less battle-tested than the mechanisms they sit beside, it says that too. A guarantee that cannot survive adversarial scrutiny is not a guarantee; it is marketing. This paper is written to invite that scrutiny, not to deflect it.

There is also a resilience argument, and it is the same principle this paper is built on, applied one level up. A privacy ecosystem with many independent implementations — built differently, failing differently — is harder to attack, regulate, or extinguish than any single chain. Diversity is defense in depth for the movement itself.

---

## 3. Concentric Privacy: the architecture

A transaction leaks along several independent axes: *who* sent it, *who* received it, *how much*, *whether it can be linked* to other transactions, *where on the network it originated*, and *whether any of it can be tied to a real human*. Concentric Privacy assigns each axis to a distinct layer and arranges the layers as concentric rings around the thing that matters most.

### 3.1 The center: what we are actually protecting

For a privacy currency, the catastrophic, irreversible exposure is not the amount and not the network origin — those leak badly but are survivable. It is the link between a **human identity and their on-chain activity**. On a public, immutable ledger, once that link is made it is made *forever*; no later patch can un-expose it. So the center of the design — the keep — is not "the transaction." It is **the person.**

Two principles govern the geometry:

1. **The riskiest *asset* — the most catastrophic to lose — sits at the center**, behind the most layers.
2. **The innermost *wall* — the last line of defense — must be the *strongest, most-proven* mechanism, not the newest.** A design whose final backstop is its most experimental feature is inverted. (This is a live tension in Cynstra's own stack, addressed honestly in §5.)

### 3.2 The rings

*(Ordered as an attacker meets them — outermost first.)*

**Ring 4 — Network.** The first thing an observer of the peer-to-peer network sees: where a transaction entered, from what address, at what instant. Guarded by Dandelion++ propagation (which hides the origin node) and traffic shaping — **timing jitter and cover packets are live in the reference implementation; size normalization is specified but not yet wired into the send path** — which together hide timing and volume patterns. *Breaking this ring reveals that a transaction exists — not what it says.*

**Ring 3 — Linkability.** Even when each transaction is opaque, can an observer connect outputs, cluster a wallet, or follow value over time? Guarded by decoy selection and decoy defense, key images (which prevent double-spends without revealing the spend), view tags, and automatic churn (which breaks temporal linkage). *Breaking this ring may permit clustering — not identity or amount.*

**Ring 2 — Transaction content.** The classic three: sender, receiver, amount. Guarded by CLSAG ring signatures (the sender hidden among decoys), stealth addresses (the receiver unlinkable to any public address), and Pedersen commitments with Bulletproofs+ range proofs (the amount hidden while provably valid). *This is the ring monolithic designs stake everything on — and where, alone, one crack is fatal.*

**Ring 1 — The user.** Even with all of the above intact, can the person or their wallet be coerced, subpoenaed, or exploited? This is the operational layer, and it is the most forward-looking ring — the one where the design reaches furthest ahead of the current implementation. **Live today:** encrypted memos, and watch-only view keys (read-only disclosure of a wallet). **Specified and in progress:** *scoped* view keys (bounded disclosure — reveal only what must be revealed); deniable wallets (plausible deniability under coercion — the earlier implementation is currently disabled pending a structural rewrite that removes an intermediate on-disk plaintext artifact); and a dead-man's switch (recovery metadata is already carried on-chain in `tx.extra`, but the consensus recovery-spend path that would enforce it is not yet wired). *This is the ring almost no chain even attempts — it aims to protect the human, not merely the transaction, and this paper marks honestly how much of it is built versus specified.*

### 3.3 Why concentric, and not merely "many features"

The arrangement is not decoration. Its purpose is **graceful degradation**: each ring stands on its own, so the failure of any single ring leaves the others holding. Break Ring 2's ring signatures and Rings 4, 3, and 1 are still standing between the attacker and the center. This is the property that monolithic privacy lacks, and it is the reason the layers must be **connected in coverage** (each guards a different door) but **independent in failure** (none is load-bearing on another). A lattice whose walls hold each other up collapses in a chain reaction; concentric, independent rings do not.

---

## 4. Fault isolation and the two-posture rule

Concentric Privacy borrows, deliberately, from decades of reliability engineering — the **bulkhead** pattern (compartmentalize so a breach in one section cannot flood the ship), **graceful degradation** (continue at reduced capacity rather than halt), the **circuit breaker** (isolate a failing component so it cannot drag down the rest), and **redundancy** (independent mechanisms covering the same surface). But privacy inverts one assumption these patterns take for granted, and the inversion is the crux of the design.

In availability engineering, failure is recoverable: the service returns and no lasting harm is done. In privacy, **failure is permanent** — a deanonymization committed to an immutable ledger cannot be undone. This forces a split that ordinary systems never have to make:

- **Consensus and availability are fail-operational.** A broken privacy feature must never halt the chain; blocks keep flowing on the remaining good parts.
- **Privacy is fail-closed.** The protocol must never quietly "keep running at reduced privacy," because reduced privacy means active, permanent leakage. Cynstra's charter encodes this directly: there is no transparent mode and no reduced-privacy transaction class.

Ordinarily these two postures fight: fail-closed says *halt if you cannot guarantee privacy*; fail-operational says *keep going*. **The concentric structure is what resolves the conflict.** Because the other rings still hold when one fails, a single break never forces the ugly choice between halting the chain and shipping weak privacy. The maze absorbs the failure: consensus continues, privacy remains whole minus one layer of margin, and the broken ring is isolated and patched. Defense-in-depth is precisely the mechanism that makes fail-operational-on-consensus and fail-closed-on-privacy achievable *at the same time* — something a monolith cannot do.

One honest cost must be stated: isolating (disabling) a broken privacy layer is **not free**, the way restarting a failed web service is. The remaining rings carry the load, but the margin is thinner, and transactions made while a layer is disabled are permanently less protected. Defense-in-depth cushions this; it does not erase it.

---

## 5. Composition safety

Stacking privacy features does not compose for free. Each mechanism hides one thing, but in doing so it can create a new *observable regularity* — a distinguisher — that an adversary uses to undo a different mechanism. More privacy features can mean *less* privacy if the interactions are wrong. This is the discipline most often skipped, and it is where privacy quietly dies.

Concrete interactions Cynstra must (and does) manage:

- **Automatic churn versus timing patterns.** Churn that fires on a fixed rhythm or in round amounts becomes a fingerprint that re-links the very outputs it was meant to unlink. It must be randomized in timing and amount so there is no cadence to lock onto.
- **Traffic shaping versus Dandelion++.** Both are timing-based defenses operating on the same packets. Shaping that perturbs Dandelion's stem timing, or cover traffic distinguishable from real relay traffic, weakens the origin protection it was meant to reinforce. The layers must coordinate — *coordinate*, not *depend*: enough to avoid collision, never enough to make one load-bearing on the other.
- **Padding versus message framing.** Size-normalization padding must not be parseable as another message type or otherwise distinguishable. (In development this surfaced as a concrete framing conflict, resolved by giving padding a distinct, first-class message type rather than a hack — an instance of the discipline, not a footnote to it.)

The claim Cynstra makes is therefore precise: not *"it has many privacy features,"* but *"it has many privacy features that do not eat each other."* Demonstrating the second is the harder and more valuable half, and this paper treats it as a first-class obligation rather than an afterthought.

**The honest limitation, stated plainly:** breadth is not strength by itself. Every added mechanism is a potential new distinguisher, and Cynstra's stack is broader — and therefore has more interaction surface — than the deliberately minimal designs it admires. Its layers are also younger and less adversarially tested. The composition-safety analysis in this section is a beginning, not a proof; a systematic argument that no cross-layer distinguisher exists is future work, and the project states this openly and invites the analysis.

---

## 6. Consensus, economics, and cryptographic parameters

Every value below is a named constant in the reference implementation
(`src/constants.rs` unless noted), cited so it can be checked against the code.
No figure here is approximated.

### 6.1 Proof of work

- **Algorithm:** RandomX (`src/consensus/pow.rs`) — CPU-optimized and
  ASIC-resistant. A miner builds a ~2 GB dataset (full-memory mode) or runs from
  a 256 MB cache (light mode); the RandomX key rotates every **2,048 blocks**
  (`RANDOMX_KEY_EPOCH`). CPU-only mining is a deliberate egalitarian choice — a
  laptop competes with a server, and no specialized hardware can price
  participants out.
- **Target block time:** **120 seconds** (`TARGET_BLOCK_TIME`).
- **Difficulty:** ASERT (absolutely-scheduled exponentially-rising targets),
  retargeting **every block** with a **1-hour halflife** (`ASERT_HALFLIFE =
  3600`). A short (8-block) and long (144-block) window are blended 70/30
  (`DIFFICULTY_SHORT_WINDOW` / `DIFFICULTY_LONG_WINDOW` /
  `DIFFICULTY_SHORT_WEIGHT` / `DIFFICULTY_LONG_WEIGHT`), with an emergency
  adjustment over 12 blocks (`EMERGENCY_DIFFICULTY_BLOCKS`). Per-block retargeting
  absorbs hashrate swings smoothly rather than in epochs.

### 6.2 Supply and emission

- **Maximum supply:** **100,000,000 CYNC** (`MAX_SUPPLY`, `TOTAL_SUPPLY_TARGET`),
  to 12 decimal places (1 CYNC = 10¹² atomic units, `ATOMIC_UNITS`).
- **Emission curve:** smooth and **halving-free**. Each block pays
  `reward = max( TAIL_EMISSION, (100,000,000 − already_mined) × COIN /
  EMISSION_DIVISOR )` with `EMISSION_DIVISOR = 2,000,000`. Because the reward is
  proportional to the *remaining* supply, it decays continuously rather than in
  discrete steps:

  | Circulating supply | Block reward |
  |---|---|
  | 0 | 50 CYNC |
  | 50,000,000 | 25 CYNC |
  | 75,000,000 | 12.5 CYNC |
  | ~99,000,000 | tail floor takes over |

- **Tail emission:** **0.6 CYNC per block, in perpetuity** (`TAIL_EMISSION`),
  once the curve would otherwise fall below it — a permanent, predictable
  security subsidy so miners are still paid as the cap is approached. (Same
  reasoning as Monero's tail: a fee-only future is a security risk.)

### 6.3 Fees and the burn

- **No premine, no dev tax, no protocol fee** — Constitution Article II,
  enforced in code as `FEE_PROTOCOL_NORMAL_PERCENT = 0`.
- **Fee split (normal conditions):** **70% to the miner, 30% burned**
  (`FEE_MINER_NORMAL_PERCENT = 70`, `FEE_BURN_NORMAL_PERCENT = 30`). Under
  congestion the miner share falls (to 50%) and the burn rises — spam gets more
  expensive, and the deflationary pressure increases exactly when the network is
  contended.
- The burn is a protocol invariant, not a tunable parameter; fees not burned are
  paid to the miner as proof-of-work reward, and no third destination exists.

### 6.4 Privacy parameters

- **Ring size:** **16** (`RING_SIZE`), enforced from block **10,000** onward; a
  bootstrap floor of **11** (`BOOTSTRAP_MIN_RING_SIZE`) applies before that, when
  a young chain does not yet hold enough outputs to form a full ring. Hard
  ceiling of **32** (`MAX_RING_SIZE`). A future increase above 16 is specified in
  [CIP-017](../cip/CIP-017-ring-size-increase.md).
- **Amounts:** Pedersen commitments with Bulletproofs+ range proofs.
- **Addresses:** one-time stealth addresses, with 1-byte view tags for scan
  efficiency.

*(The emission table above reproduces the worked example documented in
`src/constants.rs` itself; every other figure is the cited constant.)*

---

## 7. Governance: constitutional consensus

Most cryptocurrency governance is *social* — a promise in a whitepaper, a
foundation's goodwill, a multisig's restraint. CoinCync's founding guarantees
are instead **mechanical**: they are enforced by the build system and the
compiler, so that violating them is not a policy dispute but a **build failure.**

### 7.1 The Constitution and Bill of Rights

CoinCync ships a **Constitution** (nineteen Articles) and a **Bill of Rights**
(fifteen Rights) as protocol-level documents, not marketing copy. The Articles
forbid the specific failure modes that have repeatedly destroyed value elsewhere.
A representative set (verified against `CONSTITUTION.md`):

- **Article I — Fixed Supply** — the 100M cap and tail, no discretionary inflation.
- **Article II — No Pre-mine, No Developer Tax** — 0% extraction.
- **Article III — Mandatory Privacy** — no transparent mode, no reduced-privacy class.
- **Article V — Open Mining** — CPU/RandomX, no privileged hardware.
- **Article IX — No Surveillance Infrastructure** — no blacklists, no censorship
  hooks, no admin keys.

### 7.2 Two mechanical enforcement layers

**Layer 1 — Hash-locked consensus files.** Eight consensus-critical files are
pinned by SHA-256 in `critical_files.lock`:

> `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md`, `src/testnet.rs`,
> `src/constants.rs`, `src/consensus/difficulty.rs`, `src/consensus/pow.rs`,
> `src/consensus/validation.rs`, `src/emission/curve.rs`.

`build.rs` recomputes each file's hash (line endings normalized, so Windows and
Linux agree) at the start of **every** build. If any hash drifts, the build
fails. Changing one of these files requires an explicit, reviewed refresh
(`COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes`) — there is no way to alter the
emission curve, the validation rules, or the Constitution itself *silently*. An
accidental or malicious edit is caught at compile time, not at a fork.

**Layer 2 — Compile-time tripwires.** The Constitution's substantive invariants
are *additionally* encoded as `const` assertions the compiler evaluates. A
representative set from `src/constants.rs`:

```rust
const _: () = assert!(DEV_TAX_PERCENT == 0, …);                 // Article II
const _: () = assert!(MAX_SUPPLY == 100_000_000 * COIN, …);     // Article I
const _: () = assert!(MANDATORY_CONFIDENTIAL, …);               // Article III
const _: () = assert!(MANDATORY_STEALTH, …);
const _: () = assert!(RANDOMX_ONLY, …);                         // Article V
const _: () = assert!(!ADDRESS_BLACKLIST_ENABLED, …);           // Article IX
const _: () = assert!(!TX_CENSORSHIP_ENABLED, …);
const _: () = assert!(!SURVEILLANCE_HOOKS_ENABLED, …);
const _: () = assert!(NO_ADMIN_KEYS, …);
const _: () = assert!(NO_ALGORITHMIC_PEG, …);                   // the Terra failure mode
const _: () = assert!(NO_EXTERNAL_BRIDGES, …);
```

These are not runtime checks that a flag can disable; they are evaluated **when
the code is compiled.** A developer who tries to introduce a dev tax, an address
blacklist, an admin key, or an algorithmic peg does not ship a controversial
change — **their code does not compile.** The guarantee is not "we promise not
to"; it is "the software cannot be built to do this."

### 7.3 Why it matters — and its honest limits

This is the **fail-closed governance** that mirrors the fail-closed privacy of
§4: the default, unbypassable state is the constitutional one, and departing
from it requires a deliberate, visible, reviewed act rather than a quiet edit. It
directly targets the Terra-class failure (an algorithmic peg plus admin
discretion) and the rug-pull class (a silent premine or fee redirect).

The honest limit: a **fork** can always strip these guardrails — nothing prevents
someone from deleting the asserts and re-locking the hashes. What the mechanism
prevents is *silent* or *accidental* subversion, and it makes any *deliberate*
subversion **loud**: a fork that removes the Constitution is visibly a different
chain, not a stealth upgrade of this one. That is the actual guarantee — not that
the rules can never change, but that they cannot change **invisibly.**

### 7.4 Change process (CIPs)

Protocol changes proceed through CoinCync Improvement Proposals (`docs/cip/`);
consensus changes activate via the hard-fork policy of CIP-007 (static-height or
signal-then-activate). Any CIP touching a hash-locked file must pass review and
an explicit lock refresh — the governance process and the mechanical enforcement
are deliberately coupled, so that changing the rules always leaves a visible,
reviewed trail.

---

## 8. Comparison

This section positions Cynstra by **contribution**, not by a claim of
superiority. On the transaction and linkability layers, Cynstra uses proven
mechanisms comparable to Monero's — it does *not* claim to beat them there. Its
distinctive coverage is at the network and operational layers, in making privacy
mandatory, and in the constitutional enforcement of §7.

Capability map (✓ present · ◐ partial · ✗ absent):

| Layer / mechanism | Bitcoin | Monero | Zcash | Firo | Grin | **Cynstra** |
|---|---|---|---|---|---|---|
| Transaction privacy (sender/receiver/amount) | ✗ | ✓ | ✓ (zk) | ✓ | ◐ | ✓ |
| Linkability resistance (unlinkable outputs, decoys) | ✗ | ✓ | ✓ | ✓ | ◐ | ✓ |
| Network privacy (origin obfuscation) | ◐ | ◐ | ✗ | ◐ | ◐ | ✓ + shaping |
| Operational privacy (auto-churn + encrypted memos live; deniable wallet, dead-man's switch, scoped view keys specified) | ✗ | ✗ | ✗ | ✗ | ✗ | ◐ |
| Mandatory (no transparent mode) | ✗ | ✓ | ✗ | ◐ | ✓ | ✓ |
| CPU-only PoW (egalitarian) | ✗ | ✓ | ✗ | ✗ | ✗ | ✓ |
| Constitutional, compile-time-locked invariants | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |

Reading it honestly:

- **Transaction & linkability:** Cynstra *matches* Monero — same class of
  primitives (CLSAG, stealth addresses, Bulletproofs+). Zcash's zk-SNARK
  shielding is arguably **stronger** on these rows. Cynstra makes no superiority
  claim here.
- **Network:** most privacy coins stop at Dandelion++ (Monero's Kovri/I2P effort
  was shelved around 2019). Cynstra adds integrated traffic shaping — timing
  jitter and cover packets (size normalization is specified but not yet wired
  into the send path) — the one row where it is broader than the field.
- **Operational:** auto-churn and encrypted memos ship today; the
  deniable-wallet / dead-man's-switch / scoped-view-key layer is specified and,
  to our knowledge, unique among shipping chains in even being attempted. This
  paper marks it as design-ahead-of-implementation rather than claiming it as
  delivered.
- **Mandatory + constitutional:** privacy that cannot be toggled off, on a chain
  whose compiler refuses to build a non-private or admin-controlled variant.

**The caveat that belongs *with* this table, not in a footnote:** a ✓ here means
*the mechanism is present and active* — not that it has survived a decade of
adversarial academic attack. Monero's ✓s are battle-tested; several of
Cynstra's — especially the network and operational rows that make it distinctive
— are **younger and far less scrutinized.** Breadth of coverage is a real,
claimable property. *Proven* strength is earned over years of people trying to
break you, and Cynstra has not yet earned it. This paper claims the former and
explicitly disclaims the latter.

---

## 9. Conclusion

Cynstra's thesis is a single sentence: **privacy in concentric layers, where no single break exposes the whole.** It does not rest its guarantees on one clever mechanism; it layers independent defenses so that a failure in any one degrades the margin without collapsing the whole, keeps consensus alive while refusing to ship weakened privacy, and takes seriously the discipline of keeping those layers from interfering with one another. It is offered not as a competitor to the projects that proved this fight can be won, but as a fellow traveler exploring a corner they left open — and as one more independent line of defense for a cause that is safer for having many.

---

*Draft v0.1 — every quantitative claim in §6 (and the governance figures in §7) is a named constant or document count in the reference implementation, verified against the code at time of writing. This document is written to be scrutinized. Corrections, attacks, and hard questions are the point.*
