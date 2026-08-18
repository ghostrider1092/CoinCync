# Governed Merge-Mining — AuxPoW with a Hashrate Governor

**Status:** Research / testnet-only — **NOT a mainnet proposal.** Blocked for mainnet by Article XIII (see the banner below), and the §4 security argument is superseded in part by the 2026-07-24 review. Retained as a research record.
**Type:** Standards Track (consensus-affecting; new PoW class)
**Created:** 2026-07-23
**Author:** ghostrider1092
**Reviewers requested:** junbyjun1238 (security/crypto)
**Related:** [CIP-002](../cip/CIP-002-cynchub-merge-mined-liquidity-layer.md) (shared merge-mining primitive), [reorg-defense](../security/reorg-defense.md), website roadmap v1.3 (AuxPoW)

> **One-paragraph thesis.** CoinCync can borrow a large RandomX parent chain's
> hashrate (Monero) to raise its security floor from block 0 — but naive
> merge-mining *lowers* attack cost to near zero (a parent pool reorgs you for
> free; this is how CoiledCoin died). This document specifies **governed
> merge-mining**: a two-layer regulator ("flow valve") that lets borrowed
> hashrate contribute up to a bounded, tunable amount while making a
> borrowed-hashrate attack cost the same as attacking a native-only chain. The
> central result is honest and load-bearing: **the governor can at most roughly
> double your effective security work — it does *not* import the parent's full
> hashrate — and that bounded benefit is exactly what makes it safe to take.**

---

## ⛔ Constitutional blocker — Article XIII (read first)

**This mechanism cannot ship on mainnet.** Article XIII ("No External Trust"):
*"No external chain proof, oracle input, wrapped asset, IOU, or off-chain
attestation shall ever be admitted into block validity."* — enforced by the
compile-time `NO_EXTERNAL_BRIDGES` guard; the Constitution is hash-locked.

Merge-mining CoinCync **as an auxiliary chain** makes a CoinCync block valid only
by carrying a Monero header + coinbase commitment + Merkle proof (and, in the
strict variant, a Monero-seedhash-dependent proof). That is an external-chain
proof admitted into block validity — precisely what XIII forbids. Verifying it
locally does not help: the objection is that CYNC *validity would depend on
external state at all*. CyncHub is unaffected because there CoinCync is the
**parent** and CYNC consensus never depends on the child; making CoinCync the
child reverses that dependency.

**Therefore this document is research / testnet-only.** The one salvageable
artifact is the direction-agnostic commitment primitive (`crates/auxpow`), which
serves CyncHub (the constitutional direction).

## Security review corrections (2026-07-24)

The §4 security argument below is **not** a completed proof. The review found the
following, which **supersede** the optimistic claims in §4:

1. **`(★): ρ_max < 1/(1+κ)` is insufficient.** It is only a static majority-work
   condition under honest publication with an accurate normalizer. It does not
   cover selfish mining, private-fork withholding, propagation advantage,
   window-boundary manipulation, or normalizer error.
2. **The governor does NOT restore native-majority attack cost** (this breaks
   §4.3's headline). With `κ=1`, `ρ_max=0.40`, an attacker controlling the aux
   class already holds 40% of credited work and needs only `x > 1/6` (**16.7%**)
   of *native* to cross half: `0.40 + 0.60x > 0.50`. And native + Monero-merge
   share RandomX hardware, so the classes are **not economically independent** —
   the "aux-only attacker" model in §4.1 is too generous.
3. **Do not lean on rolling finality / `max_reorg_depth`** to justify the work
   bound. They restrict *accepted* reorgs without reducing attacker power, can turn
   a recoverable Nakamoto reorg into permanent partition disagreement, and rolling
   finality is currently **dormant**. Prove the hybrid rule standalone first, then
   analyze finality interaction separately.
4. **Layer B needs TWO separate consensus rules**, not one window cap: a
   long-horizon share rule (~a day of blocks) AND a shorter burst guardrail bounded
   below the shallow-reorg region, burst allowance from simulation. A per-block
   work cap alone allows consecutive aux blocks; a window-occupancy cap alone
   allows a burst up to the remaining window budget.
5. **Threat model uses per-class adversarial fractions**, not a "minimum honest
   native fraction": all-aux-hostile needs >83.3% native honest at a 40% cap,
   ~66.7% at a 25% cap.
6. **Parameters are experimental, not proven.** Keep `κ=1` (an absolute aux floor,
   if ever needed, is a *separate raw-difficulty validity rule*, not a fork-choice
   multiplier). Testnet start `ρ = 0.20–0.25`, `ρ_max ≤ 1/3`; finals only from
   adversarial + Monte-Carlo simulation. Even 1/3 is an experimental ceiling.
7. **`Ŵ_n` = fixed-window branch-local median**, not an EMA (path-dependent, adds
   divergent persisted state). The branch score must be **one canonical pure
   function of the candidate's headers**; persisted values are caches only, always
   recomputable; integer-only, wide accumulator, fixed rounding, cross-platform
   vectors (else it reopens the `total_difficulty` divergence class).
8. **Aux DAA gets its own history + a multi-hour half-life** (not the 3600 s native
   one) — sparse aux arrivals under-sample a 1 h half-life and oscillate.
9. **Parent binding:** reject an unrestricted miner seed (reuse/precompute/grind).
   If external proofs were ever accepted, the parent coinbase must commit the
   **full** CoinCync mining hash (version, height, prev-hash, tx-root, chain-id)
   *before* the RandomX work, so stale parent work can never be replayed against a
   newer tip.
10. **Activation:** version-gated header extension, byte-identical pre-activation,
    mandatory + canonically-encoded post-activation; **no mainnet-from-genesis
    commitment** until the design survives a long public testnet + external review;
    testnet height ~20,000 blocks after signed binaries + final spec, not off
    today's tip.
11. **Chain id** is a 32-byte domain-separated derivation (protocol version +
    genesis hash + network magic + parent id), distinct per network — implemented
    as `AuxChainId` in `crates/auxpow`. Not a hand-picked short constant.

**Bottom line:** technically feasible, but the constitutional (Article XIII) and
fork-choice questions are more fundamental than the encoding, and the mechanism
does not buy what §4 claimed. Retained as research; §4 is read through the lens of
these corrections.

## 0. Reading guide

- §1–2: the problem, formalized with the attack math.
- §3: the mechanism (the valve): coexistence, the two-layer regulator, fork-choice normalization.
- §4: the security theorem and its proof sketch — **the core of the document.**
- §5: the difficulty control math (reuses CoinCync's existing ASERT).
- §6: AuxPoW proof format + parent RandomX verification.
- §7: consensus integration (which hash-locked files, genesis implications).
- §8: parameters. §9: attack scenarios. §10: phased rollout. §11: open questions for Jun. §12: honest limitations.

---

## 1. Motivation

CoinCync's single biggest pre-mainnet risk is a thin early hashrate: a fair
launch with CPU-only RandomX means block 0 is defended by however many honest
CPU miners show up, which at launch may be very few. A low hashrate is a
standing invitation to a 51% reorg.

Merge-mining offers a tempting fix: let Monero miners (same RandomX algorithm)
mine CoinCync at **zero marginal cost**, so CoinCync inherits a slice of
Monero's enormous hashrate the instant it launches.

The catch is that "zero marginal cost" cuts both ways.

---

## 2. The problem, formalized

### 2.1 Notation

| Symbol | Meaning |
|---|---|
| `H_n` | Total honest **native** CoinCync hashrate (dedicated CPU RandomX on CoinCync's own PoW). Real, non-borrowable. |
| `H_M` | Total Monero (parent) hashrate. |
| `μ` | Fraction of `H_M` that honestly merge-mines CoinCync. |
| `a` | Fraction of `H_M` an **attacker** controls and points at CoinCync (free, at the margin). |
| `T` | Target block time = `TARGET_BLOCK_TIME` = 120 s. |
| `D_n`, `D_x` | Native and aux difficulty (target expressed as work `= 2²⁵⁶ / target`). |
| `w(·)` | Fork-choice work of a block (`work_from_target`, [pow.rs:1028](../../src/consensus/pow.rs)). |
| `ρ` | **Target** fraction of blocks that are aux (governor setpoint). |
| `ρ_max` | **Hard** consensus cap on aux share over a sliding window. `ρ_max > ρ`. |
| `κ` | Fork-choice **work-normalization cap** for an aux block, in native-block-equivalents. |
| `W` | Sliding window length (blocks) for the hard share cap. |

### 2.2 Why naive merge-mining is fatal

CoinCync's current fork choice is heaviest-cumulative-work
([pow.rs:1028](../../src/consensus/pow.rs), `work_from_target`). Under naive
coexistence, an aux block's weight equals its raw parent difficulty. Monero's
hashrate dwarfs any plausible early CoinCync native hashrate:

```
H_M  ≈  (Monero network, RandomX)      ~ 10⁹  H/s scale
H_n  ≈  (CoinCync CPU miners at launch) ~ 10³–10⁴ H/s scale
```

So even a small attacker fraction `a` gives effective hashrate
`a · H_M ≫ H_n`. The attacker mines a private CoinCync fork whose cumulative
work exceeds the honest chain trivially, and — critically — pays **no marginal
cost**, because those RandomX hashes were already being computed to mine Monero.

> **This is the CoiledCoin failure (2011): the Eligius pool 51%'d a small SHA-256
> chain merge-mined under Bitcoin, at no cost, and killed it.** Any small chain
> merge-mined *naively* under a large parent is at the mercy of a single parent
> pool.

### 2.3 The requirement

We want a mechanism where:

1. **(Benefit)** honest borrowed hashrate raises CoinCync's security and keeps
   blocks flowing even if native miners are scarce, but
2. **(Safety)** an attacker with unlimited *borrowed* parent hashrate but **no
   native hashrate** cannot reorg the chain — the attack cost stays equal to
   acquiring a native-hashrate majority, exactly as on a non-merge-mined chain.

The tension is that (1) wants borrowed work to *count*, and (2) wants borrowed
work to *not count* for an attacker. The governor resolves this by **capping and
normalizing** the borrowed contribution rather than accepting it raw.

---

## 3. The mechanism — the flow valve

### 3.1 Coexistence: two PoW classes

Every CoinCync block declares a `pow_class ∈ {Native, Aux}` (a new header
field, §7).

- **Native** — a RandomX solution over CoinCync's own anchor, exactly as today
  ([pow.rs:255](../../src/consensus/pow.rs) `compute_pow_hash`). CPU miners are
  unchanged. **Solo CPU mining is preserved** — this is non-negotiable for the
  fair-launch ethos.
- **Aux** — a RandomX solution over a *parent* (Monero-shaped) header that
  commits to this CoinCync block's hash via a merge-mining tag (§6).

Both are valid PoW. This is the coexistence design (not AuxPoW-only), so no
CoinCync miner is *forced* to run Monero.

### 3.2 The two-layer valve

**Layer A — soft valve (difficulty feedback).** Native and aux run *independent*
ASERT difficulty controllers ([difficulty.rs](../../src/consensus/difficulty.rs)),
each targeting its own block interval:

```
T_native = T / (1 − ρ)      (native blocks arrive every T/(1−ρ) seconds)
T_aux    = T / ρ            (aux blocks arrive every T/ρ seconds)
```

Composed, the two independent streams produce a block every `T` on average with
aux fraction `ρ`:

```
rate_native = (1−ρ)/T ,  rate_aux = ρ/T ,  rate_total = 1/T ,  aux share → ρ
```

The soft valve *self-regulates*: if merge-miners flood in, aux blocks arrive too
fast, ASERT raises `D_x`, and the aux stream is throttled back toward `T_aux`.
If merge-miners leave, `D_x` falls to invite them. It is a servo holding the
setpoint `ρ` — mechanically the same control loop as `cicada`/`firefly`.

**Layer B — hard valve (consensus share cap).** The soft valve has response
lag (ASERT half-life), so a *burst* attacker can briefly exceed `ρ`. Layer B is
a hard, deterministic consensus rule that bounds the burst:

> **Share-cap rule.** A block `B` at height `h` is **invalid** if, among the `W`
> blocks `[h−W+1 … h]` (inclusive), the number tagged `Aux` exceeds
> `⌊ρ_max · W⌋`.

This cap is enforced on *every* chain, including an attacker's private fork — a
fork that violates it is simply not a valid CoinCync chain. Layer B is what
makes the §4 security theorem hold even against an adversary who games Layer A's
timing.

### 3.3 Fork-choice normalization

This is the crux. In cumulative-work fork choice, an aux block does **not**
contribute its raw parent difficulty. It contributes a **capped, native-
normalized** weight:

```
w_fork(B) =  w(D_n(B))                          if B.pow_class = Native
             min( w(D_x(B)),  κ · Ŵ_n(B) )      if B.pow_class = Aux
```

where `Ŵ_n(B)` is the **median native block work over the trailing window** at
`B`'s height (median → robust to single-block manipulation), and `κ` is the
normalization cap in native-block-equivalents.

The effect: no matter how much raw Monero difficulty an aux block represents, it
counts for **at most `κ` native blocks** in fork choice. Borrowed hashrate is
decoupled from fork-choice weight. This is the valve seat that the §4 proof
rests on.

---

## 4. Security analysis

### 4.1 Threat model

- Attacker controls fraction `a` of parent hashrate `H_M`, usable against
  CoinCync at zero marginal cost.
- Attacker controls **zero native hashrate** (`H_n` is real, dedicated CPU work;
  to get it the attacker must *buy and run CPUs mining CoinCync's native PoW* —
  the same cost as attacking a native-only chain).
- Honest native miners produce at least their share of native blocks (i.e., the
  honest CPU base does not vanish). We quantify the required floor below.
- Standard reorg defenses ([reorg-defense](../security/reorg-defense.md)):
  6-layer defense, rolling finality, `max_reorg_depth`. The governor composes
  with, not replaces, these.

### 4.2 The bound

Consider any window of `N ≥ W` blocks on the honest chain. By the Layer-B
share-cap rule, **any valid chain** has at most `ρ_max · N` aux blocks and at
least `(1 − ρ_max) · N` native blocks. Normalize native block work to `1` and
let `Ŵ_n` be the reference; by §3.3 each aux block contributes at most `κ`.

**Honest chain weight** over the window (honest natives producing their share,
honest aux filling toward `ρ`):

```
Ω_honest  ≥  (1 − ρ_max) · N · 1     (native floor, guaranteed by honest CPU base)
```

**Attacker private chain.** The attacker has no native hashrate, so every block
on their fork is aux. Their fork must *also* satisfy the Layer-B cap (or it is
invalid), so it contains at most `ρ_max · N` aux blocks, each worth at most `κ`:

```
Ω_attacker  ≤  ρ_max · N · κ
```

For the attacker to reorg, they need `Ω_attacker > Ω_honest`:

```
ρ_max · κ · N  >  (1 − ρ_max) · N
⇔   ρ_max · κ   >   1 − ρ_max
⇔   ρ_max       >   1 / (1 + κ)                         … (★)
```

> **Theorem (governor safety).** If parameters satisfy `ρ_max < 1/(1+κ)`, then an
> attacker with unbounded borrowed parent hashrate but no native hashrate
> **cannot** out-weigh the honest chain, provided honest native miners produce
> their `(1 − ρ_max)` block share. The attacker is forced to acquire *native*
> hashrate — restoring the attack cost to that of a native-only chain.

**Proof sketch.** The Layer-B cap bounds aux blocks on *every* valid chain to
`ρ_max·N`; §3.3 bounds each aux block's fork weight to `κ`. So an aux-only
attacker's total fork weight is `≤ ρ_max·κ·N`. Honest natives alone contribute
`≥ (1−ρ_max)·N`. Under `(★)` the latter strictly exceeds the former, so the
honest chain is heavier and the attacker cannot trigger fork-choice reorg beyond
transient depth; rolling finality + `max_reorg_depth` cap the transient. ∎

### 4.3 Worked numbers

Take `κ = 1` (an aux block is worth at most one native block) and `ρ_max = 0.40`:

```
(★):  0.40 < 1/(1+1) = 0.50   ✓ satisfied, with headroom
Attacker max weight share:  ρ_max·κ = 0.40
Honest native floor:        1 − ρ_max = 0.60
Honest : attacker  =  0.60 : 0.40  =  1.5 : 1
```

An attacker who captures the **entire** aux budget still musters only 40% of the
weight; honest native miners alone hold 60%. To win, the attacker must add real
native hashrate until *they* hold the native majority — precisely the cost of
attacking a chain with no merge-mining at all.

### 4.4 The honest ceiling on the benefit — stated plainly

The same math that bounds the attacker bounds the *benefit*. Honest total weight
over `N` blocks is:

```
Ω_honest_total  =  (1 − ρ) · N · 1   +   ρ · N · κ   =   N · [ (1−ρ) + κρ ]
```

Maximizing the aux contribution subject to the safety constraint `(★)`
(`κρ ≤ 1−ρ` at the edge) gives:

```
Ω_honest_total  ≤  N · [ (1−ρ) + (1−ρ) ]  =  2 · (1−ρ) · N   →   at most ~2× native-only
```

> **Honest headline.** Governed merge-mining can add **at most ~1× native-
> equivalent work** (≈ doubling total security work) before the aux budget
> itself becomes an attack surface. It does **not** import Monero's full
> hashrate, and any design that claims otherwise is repeating the CoiledCoin
> fallacy inverted. With `κ = 1` the benefit is primarily **liveness,
> censorship-resistance, and a steadier chain** (aux fills blocks when native is
> thin); with `κ > 1` (and correspondingly smaller `ρ_max`) you buy a bounded
> *absolute* work floor on top, up to the 2× ceiling.

This is the trade the governor actually offers: **bounded benefit + bounded
risk**, replacing naive merge-mining's **unbounded benefit + unbounded risk**.
It is a good trade precisely because it is bounded.

### 4.5 Dependence on the honest native base

The theorem requires honest natives to produce their `(1−ρ_max)` share. The
governor therefore does **not** remove the need for a real CPU-mining base — it
*amplifies and protects* it. This is a feature: it keeps the fair-launch CPU
ethos load-bearing rather than decorative. If honest native participation
collapses below `(1−ρ_max)`, safety degrades gracefully back toward that of the
native chain plus the reorg-defense caps — never worse than native-only, because
aux weight is capped.

---

## 5. Difficulty control math

### 5.1 Reuse ASERT twice

CoinCync already ships a correct, integer-only dual-window ASERT
([difficulty.rs:167](../../src/consensus/difficulty.rs), `apply_asert`). The
governor runs it **once per PoW class** over that class's own block stream:

```
D_n(h)  =  ASERT( native blocks,  target_interval = T/(1−ρ) )
D_x(h)  =  ASERT( aux    blocks,  target_interval = T/ρ     )
```

Both use the existing half-life `ASERT_HALFLIFE = 3600 s` and `MIN_DIFFICULTY`
floor. No new difficulty algorithm is introduced — only a second instantiation
keyed on `pow_class`, with per-class block-timestamp streams. The canonical
ASERT recurrence, per class:

```
D_class(h) = D_anchor · 2^( (t_h − t_anchor − τ_class·(h − h_anchor)) / halflife )
             with τ_native = T/(1−ρ),  τ_aux = T/ρ
```

evaluated in the existing integer `pow2_frac` fixed-point
([difficulty.rs:273](../../src/consensus/difficulty.rs)).

### 5.2 Why the soft valve alone is insufficient (and Layer B is required)

ASERT converges over ~`halflife`. An attacker who slams `a·H_M` at aux for a
few blocks produces a short burst before `D_x` catches up. Without Layer B, that
burst is bounded only by ASERT's `MAX_DIFFICULTY_ADJ` per step. Layer B's hard
window cap `⌊ρ_max·W⌋` makes the *worst-case* aux share deterministic and
independent of controller lag — which is exactly what §4.2 needs. The two layers
are complementary: Layer A optimizes the *common case* (hold `ρ`), Layer B
bounds the *adversarial case*.

### 5.3 Timestamp-manipulation resistance of the share window

Layer B counts *classes*, not times, over the last `W` blocks — it does not
depend on timestamps, so it cannot be gamed by timestamp manipulation (already
bounded by `MAX_TIMESTAMP_DRIFT = 600` and median-time-past rules,
[constants.rs::MAX_TIMESTAMP_DRIFT](../../src/constants.rs) and
[constants.rs::MTP_WINDOW](../../src/constants.rs)). Layer A inherits ASERT's existing
timestamp-manipulation resistance.

---

## 6. AuxPoW proof format & parent verification

### 6.1 Reuse the CIP-002 primitive

[CIP-002](../cip/CIP-002-cynchub-merge-mined-liquidity-layer.md) and
`crates/cynchub/src/mergemining.rs` already define a Namecoin-style commitment
(`CHCB`-magic + 32-byte child hash + Merkle path). We generalize that *same*
primitive so it serves both directions of the stack (Monero→CoinCync here;
CoinCync→CyncHub in CIP-002). One primitive, one audit surface. The commitment
carried in the parent coinbase is:

```
tag  =  MAGIC(4) ‖ merkle_root(32) ‖ merkle_size(varint) ‖ nonce(varint)
```

where `merkle_root` commits to a Merkle tree of aux-chain hashes (CoinCync
occupies a slot chosen by `nonce`, exactly as Monero's merge-mining tag / the
Namecoin `merged-mining` convention), so multiple aux chains can share one
parent solution.

### 6.2 The aux proof carried in a CoinCync block

An `Aux` CoinCync block carries an `AuxPow` structure:

```rust
struct AuxPow {
    parent_blob:       Vec<u8>,   // Monero-shaped hashing blob (header + coinbase root)
    parent_seed:       [u8; 32],  // RandomX seed used for parent PoW (committed, see §6.3)
    coinbase_branch:   MerkleBranch, // coinbase → parent tx-merkle-root
    aux_branch:        MerkleBranch, // this CoinCync block hash → tag.merkle_root
    tag_offset:        u32,       // position of the merge-mining tag in the coinbase
}
```

### 6.3 Parent RandomX verification — the simplification

**Claim: CoinCync does *not* need to track Monero's chain or seedhash schedule.**

RandomX difficulty is **seed-independent**: for any fixed seed, the output is
uniformly distributed, so no seed is "weak" and seed choice cannot lower the
work required to hit a target. Therefore CoinCync can accept a **committed,
miner-provided `parent_seed`** and verify:

```
1.  rx = RandomX( parent_seed, parent_blob )
2.  rx  ≤  aux_target(D_x)                         (real work was done)
3.  parse merge-mining tag at tag_offset in the coinbase inside parent_blob
4.  aux_branch connects  H_cync = this_block.hash()  to tag.merkle_root
5.  coinbase_branch connects the coinbase to the parent header's tx-merkle-root
6.  parent_seed is committed in the block (cannot be swapped post-hoc)
```

Grinding `parent_seed` does not help an attacker (no weak seeds), and RandomX's
~2 GB dataset init per seed makes rapid seed-switching *more* expensive, not
less. So this is safe **and** removes the scary dependency on Monero's consensus
(seedhash epochs, 64-block lag). Verification cost ≈ one RandomX hash — the same
cost CoinCync already pays to verify a native block
([pow.rs:983](../../src/consensus/pow.rs)).

> **Stricter alternative (for Jun to weigh):** bind `parent_seed` to Monero's
> actual seedhash schedule so aux work must be *bona fide Monero* work. This
> forces attackers to compete inside Monero's real economy, but couples CoinCync
> validation to Monero consensus and adds seedhash-epoch tracking. The
> simplified form above is recommended unless the strict coupling buys a
> security property we can name. **Open question §11.**

---

## 7. Consensus integration

### 7.1 Touch list (and hash-lock impact)

| File | Change | Hash-locked? |
|---|---|---|
| [header.rs](../../src/consensus/header.rs) | add `pow_class: u8`, `Option<AuxPow>` (or a side structure keyed by block hash) | **No** — but see genesis note |
| [pow.rs](../../src/consensus/pow.rs) | add `verify_aux_pow(...)`; branch `verify_pow` on `pow_class` | **LOCKED** — re-lock required |
| [difficulty.rs](../../src/consensus/difficulty.rs) | second ASERT instance keyed on class; per-class interval | **LOCKED** — re-lock required |
| [validation.rs](../../src/consensus/validation.rs) | Layer-B share-cap rule; class-aware `verify_pow` call; fork-choice `w_fork` | **LOCKED** — re-lock required |
| [constants.rs](../../src/constants.rs) | `ρ`, `ρ_max`, `κ`, `W`, activation heights | **LOCKED** — re-lock required |
| [chain.rs](../../src/chain.rs) | cumulative-work uses `w_fork` (§3.3); per-class difficulty in `next_target` | No |
| [mining/template.rs](../../src/mining/template.rs), `coincync-rig` | aux template + a Monero-node bridge (merge-mining proxy) | No |

Four of the six primary changes land in **hash-locked consensus files**
(`pow.rs`, `difficulty.rs`, `validation.rs`, `constants.rs`). Each edit fails the
build until re-locked via `COINCYNC_REGEN_LOCK=1 cargo run --bin
update-critical-hashes`. This is deliberate friction — every one of these edits
is a consensus change and must be reviewed as such.

### 7.2 Genesis coupling

Adding header fields changes `BlockHeader::hash()`
([header.rs:54](../../src/consensus/header.rs)), which changes the genesis hash.
`src/testnet.rs` is hash-locked and `expected_genesis_hash()` asserts the
hardcoded genesis. Therefore:

- **Mainnet** (not yet launched, target 2026-10-01): AuxPoW fields can be
  present from genesis. But per §10 this is **not** a v1.0 change.
- **Existing testnet** (live at h≈3200+): header changes require a fork height,
  not a retro-genesis change. The `pow_class`/`AuxPow` fields must serialize
  identically to today for pre-fork blocks (e.g., `pow_class` defaults to
  `Native`, `AuxPow` absent) so pre-fork block hashes are unchanged. **Design
  the encoding to be backward-identical below the activation height.**

### 7.3 Backward-compatible encoding

To avoid disturbing pre-fork block identity, `AuxPow` is **not** a header field;
it is an optional side-structure committed via a single new header byte
`pow_class` that is **only serialized at/after the activation height** (version-
gated in `hash_concat`, [header.rs:54](../../src/consensus/header.rs)). Below
activation, `hash()` is byte-identical to today. This keeps the testnet lock and
`expected_genesis_hash` intact for historical blocks.

---

## 8. Proposed parameters

| Param | Symbol | Proposed | Rationale |
|---|---|---|---|
| Aux share target | `ρ` | `0.33` | Aux fills up to ⅓ of blocks; native keeps a ⅔ majority. |
| Aux share hard cap | `ρ_max` | `0.40` | `< 1/(1+κ)=0.50` with headroom (§4.3); gives Layer A room above `ρ`. |
| Work normalization | `κ` | `1.0` | Aux block ≤ one native block in fork choice. Start conservative; §12. |
| Share window | `W` | `100` | ~3.3 h at 120 s; long enough to smooth, short enough to bound bursts. |
| Aux ASERT half-life | — | `3600 s` | Reuse native `ASERT_HALFLIFE`. |
| Min aux difficulty | — | `MIN_DIFFICULTY` | Reuse the native floor. |

`κ = 1` is the safe starting point: it yields liveness + attack-resistance with
zero absolute-work over-crediting. Raising `κ` (with a correspondingly lower
`ρ_max` to preserve `(★)`) trades toward an absolute work floor, bounded by the
§4.4 2× ceiling. **`κ` and `ρ_max` are the two dials Jun should own.**

---

## 9. Attack scenarios

| # | Attack | Defense |
|---|---|---|
| A1 | **Parent-pool flood** — point `a·H_M` at aux to reorg | Layer B caps aux to `ρ_max` of blocks on *every* valid chain; §3.3 caps each aux block to `κ`. Attacker weight `≤ ρ_max·κ < 1−ρ_max`. Must buy native. (§4.2) |
| A2 | **Burst before the soft valve reacts** | Layer B is timestamp-independent and enforced per block; the burst cannot exceed `⌊ρ_max·W⌋` in any window. (§5.2) |
| A3 | **Seed grinding** — pick a favorable `parent_seed` | No weak RandomX seeds; seed choice can't lower work; seed is committed. (§6.3) |
| A4 | **Aux-tag ambiguity / dual commitment** | Canonical tag position (`mergemining-strict`, already contemplated in `cynchub/mergemining.rs`); reject multiple/foreign tags. |
| A5 | **Withholding aux budget** to starve honest merge-miners | Layer A lowers `D_x` when aux is scarce, inviting honest merge-miners; native chain proceeds regardless (native is the floor). |
| A6 | **Timestamp manipulation** to skew difficulty/share | Share cap counts classes, not time (§5.3); ASERT + MTP + `MAX_TIMESTAMP_DRIFT` unchanged. |
| A7 | **Valve-stuck-open bug** (impl risk) | Layer B is a *hard* invariant; add a consensus test that any window with aux `> ⌊ρ_max·W⌋` is rejected, and a fork-choice test that aux weight never exceeds `κ·Ŵ_n`. |

---

## 10. Phased rollout (off-by-default)

Per the feature-freeze discipline (phased, off-by-default; consensus caution
unchanged), and aligned with the website's v1.3 placement:

- **Phase 0 — this document.** Design + Jun's sign-off on `(★)`, `κ`, `ρ_max`,
  §6.3 vs the strict alternative, and the §4 proof. *No code.* ← we are here.
- **Phase 1 — primitive.** Generalize `crates/cynchub/mergemining.rs` into a
  standalone, direction-agnostic merge-mining commitment + `AuxPow` type +
  serialization + property tests. **Not wired into consensus.**
- **Phase 2 — verification.** `verify_aux_pow` + Layer-B share-cap logic +
  per-class ASERT + `w_fork`, all unit-tested against **real Monero block
  fixtures** and adversarial share-window fixtures. Still off the consensus path
  (behind a disabled feature / activation height `= u64::MAX`).
- **Phase 3 — testnet activation.** Backward-compatible encoding (§7.3); set a
  testnet activation height; run a soak with a deliberate hostile-pool
  simulation.
- **Phase 4 — miner.** `coincync-rig` merge-mining mode + a Monero-node bridge
  (or a standalone merge-mining proxy).
- **Phase 5 — mainnet.** Genesis-active on a *future* mainnet, only after the
  §4 analysis is externally reviewed and Phase 3 soak is clean.

Each phase is independently reviewable and reversible; nothing touches
consensus behavior until Phase 3's activation height passes.

---

## 11. Open questions for Jun

1. **The proof.** Is `(★): ρ_max < 1/(1+κ)` the right and complete safety
   condition? Does it hold under selfish-mining / private-fork strategies more
   subtle than "aux-only heaviest chain," given rolling finality + `max_reorg_depth`?
2. **`κ` and `ρ_max`.** Start at `κ=1, ρ_max=0.40`? Or accept a bounded absolute-
   work floor with `κ>1` and tighter `ρ_max`? What's the honest-native
   participation floor we're willing to assume in §4.5?
3. **Parent binding (§6.3).** Committed miner-seed (simple, decoupled) vs. strict
   Monero-seedhash coupling (forces bona-fide Monero work, couples to Monero
   consensus). Which buys a nameable security property worth the coupling?
4. **Fork-choice reference `Ŵ_n`.** Is a trailing *median* native work the right
   manipulation-resistant normalizer, or should it be a longer EMA?
5. **Interaction with `work_behind` veto / total-difficulty** logic (the
   [total_difficulty divergence](../../src/chain.rs) history) — does per-class
   weighting reopen any of that?
6. **Is the bounded benefit worth the consensus complexity at all**, versus
   simply recruiting native miners + seeds? (The null hypothesis deserves a fair
   hearing.)

---

## 12. Honest limitations

- **Not Monero-level security.** The benefit is bounded at ~2× native work
  (§4.4). Anyone expecting a small chain to inherit a giant parent's full
  security is mistaken; the governor's *point* is that the safe benefit is
  bounded.
- **Depends on a real native base.** Safety needs honest natives to hold
  `(1−ρ_max)`. The governor protects and amplifies the CPU base; it does not
  replace it (§4.5).
- **Consensus complexity.** Four hash-locked files, a new PoW class, a second
  difficulty controller, a parent-verification path, and a new fork-choice term.
  This is real, permanent consensus surface — justified only if §11.6 is
  answered "yes."
- **Miner UX.** Realizing the benefit needs Monero miners to actually point a
  merge-mining proxy at CoinCync; adoption is a social problem the protocol
  can't solve alone.
- **Post-mainnet.** None of this is on the v1.0 critical path (verification gate,
  cyncswap audit, NLnet). It is a v1.3-class feature and should not consume
  pre-mainnet runway beyond this design review.

---

## Appendix A — Symbol summary

```
H_n   honest native hashrate (real, non-borrowable)
H_M   parent (Monero) hashrate ;  μ honest merge frac ;  a attacker frac
T     target block time (120 s)
ρ     aux share target ;  ρ_max hard aux share cap (window W)
κ     aux fork-choice work cap (native-block-equivalents)
w_fork(B)  native: w(D_n) ;  aux: min(w(D_x), κ·Ŵ_n)
(★)   safety: ρ_max < 1/(1+κ)   ⇒  aux-only attacker cannot out-weigh honest natives
ceiling  honest total ≤ 2·(1−ρ)·N   (governed merge-mining ≲ doubles security work)
```

## Appendix B — Why "governor," not "cap"

A static cap would reject useful honest hashrate whenever it exceeded a fixed
number. The governor (Layer A feedback + Layer B hard bound) instead *admits*
borrowed hashrate continuously up to the setpoint and only *throttles* the
excess — like a flow-control valve holding a setpoint against variable upstream
pressure, rather than a check valve that simply slams shut. The chain gets the
steady contribution; the attacker gets the closed seat.
