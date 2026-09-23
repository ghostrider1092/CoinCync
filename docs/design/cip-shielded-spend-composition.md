# CIP-Shielded — Spend Composition: binding the linking tag into the one-of-many

Status: **DESIGN / draft** (not implemented). Companion to `cip-shielded-proof.md`,
`cip-shielded-notes.md`, `cip-shielded-anonset.md`. This closes the **last crypto
gap** between "shielded notes exist" and "shielded notes are spendable end-to-end
with scan ≠ spend". **Privacy-critical & consensus-critical — must be finalized
against the Lelantus-Spark paper (Feickert & Jivanyan) and externally audited
before it lands unGated.** Everything stays behind `sketch-gk-proof` +
`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` until then.

## The gap in one sentence

We have a log-size membership+value proof (`SparkSpendProofV3`, `prove_spend_bound`
/ `verify_spend_bound` in `crypto/groth_kohlweiss.rs`) and a spend-key-bound
linking tag (`spark_note::prove_tag` / `verify_tag`) — but they are **not one
proof**. V3 reveals the serial scalar (which cannot give scan ≠ spend), and the
tag currently verifies against a **known** `Q_spend`. The spend must prove *both*
relations over a **hidden** coin index `l`, revealing neither the index, the
serial, nor the spend key.

## Why the naive paths fail (settled — see `cip-shielded-notes.md`)

- **Reveal the serial** (`nullifier = H(serial)`): the serial is sender-committed,
  hence scan-derivable → a view key could spend. And folding the spend key in and
  revealing `s_full = s_pub + spend_secret` leaks the long-term `spend_secret`.
- **Tag against a known `Q_spend`**: fine as a standalone proof, but at spend the
  coin — and therefore its `Q_spend` — must stay hidden inside the anonymity set.

So the double-spend nullifier is a **linking tag** `T` (a group element requiring
the spend key), and the spend is a **single** proof binding `T` to the hidden
coin. This is exactly the Lelantus-Spark spend shape; the log-size linkable
building block is the **Triptych / Omniring** family (a one-of-many proof carrying
an embedded key image).

## The spend statement (what the proof must establish)

Public inputs: the coin set `{C_i}` (a fixed-size bucket, `N = 2^m`,
`GK_ANON_SET_LOG2`), the revealed value commitment `V = v·Gv + b·K`, the revealed
tag `T`, the fee/`value_balance`-bound message.

Coin form (from `cip-shielded-notes.md`): `C_i = v_i·Gv + s_pub,i·H + Q_spend,i +
r_i·K`, where `Q_spend,i = x_i·H` and `x_i` is the owner's spend secret. So the
coin's H-coefficient is `(s_pub,i + x_i)`; nothing reveals it.

Prove knowledge of a hidden index `l` and witnesses `(v, s_pub, x, r, b)` s.t.

1. **Membership + value binding:** `C_l = v·Gv + (s_pub + x)·H + r·K` **and**
   `V = v·Gv + b·K` (same `v`). *(V3 already does this half, by shifting
   `W_i = C_i − V` and proving `W_l ∈ ⟨H,K⟩` at the hidden `l` — but without
   revealing `s_pub + x`; that is the change from V3, which revealed the serial.)*
2. **Tag well-formedness:** `T = x·B_l`, where `B_l` is a coin-specific tag base
   (below), for the **same** `x` whose `x·H` sits inside `C_l`. This is the
   spend-key binding: a scanner who lacks `x` cannot form a `T` that satisfies
   this relation for any set member.
3. `l` remains hidden (the one-of-many is witness-indistinguishable), and neither
   `x`, `s_pub`, nor `r` is revealed.

The nullifier published for double-spend detection is `T`.

## The tag-base problem (the crux to pin with the paper)

`T` must be **per-coin** (so one spend key spending two coins yields two different
tags — else all a wallet's coins link and only one is ever spendable) **and**
bindable to a **hidden** member. Two candidate resolutions, to be decided at audit:

- **(A) Coin-derived base, proven in-circuit:** `B_l = Hp(C_l)`
  (`spark_note::hash_to_point`). Per-coin by construction. The difficulty is
  proving `T = x·Hp(C_l)` for hidden `l`, since `Hp` is nonlinear — the one-of-many
  works over *linear* combinations of the `C_i`. This needs the Triptych treatment:
  the proof's selection polynomial that isolates `C_l` is reused to isolate the
  matching precomputed `Hp(C_i)` (the verifier computes `{Hp(C_i)}` for the public
  set, so they are public points and the *same* one-of-many coefficients select
  `Hp(C_l)` linearly). **This is the preferred route** — it keeps the tag per-coin
  and the base is a public function of public data.
- **(B) Fixed base + per-coin factor:** `T = x·U` with global NUMS `U` links all of
  one key's spends → rejected (violates per-coin). A per-coin variant `T =
  (x + s_pub)^{-1}·U` (Spark's actual serial/tag inversion) is per-coin but adds an
  inverse relation to prove. Fallback only if (A)'s dual-selection is unsound.

**Route (A) is the design intent**: because `{Hp(C_i)}` are public, binding `T`
reduces to running the *existing* one-of-many's selection over a second public
vector — a well-understood extension (Triptych's key image is exactly this).

## Construction sketch (Route A, to be formalized + audited)

Extend `prove_one_of_many_ctx` so a single Fiat-Shamir transcript proves the
selection of `C_l` from `{C_i}` **and** the identical selection of `Hp(C_l)` from
`{Hp(C_i)}`, then attaches a Chaum-Pedersen-style equality tying the selected
`Hp(C_l)` to `T` via the same `x` that contributes `x·H` to `C_l`:

1. Prover forms the standard one-of-many commitments for index `l` over the shifted
   set `W_i = C_i − V` (membership + value).
2. Using the **same** blinding/selection scalars, form the parallel commitments
   over `{Hp(C_i)}`, yielding a proof element that equals `x·Hp(C_l) = T` at `l`.
3. Bind `x` across the two rails (the `x·H` inside `C_l` and the `x·Hp(C_l)` in
   `T`) with the equality-of-DL argument already implemented in
   `spark_note::{prove_tag, verify_tag}` — generalized to the hidden index.
4. Single challenge `c = H(ctx ‖ set ‖ V ‖ T ‖ all commitments)`; responses fold
   the membership witnesses and `x` together.

The output is a new `SparkSpendProofV4 { one_of_many_ext, value_commitment: V,
tag: T, message }` — replacing V3's `serial` field with the tag `T`. `verify`
recomputes both selections and the equality, fail-closed.

## Security properties the audit must confirm

- **Spend-authority soundness:** no PPT prover without `x` (the DL of some set
  member's `Q_spend`) can produce an accepting `(T, proof)`. *(This is the
  scan-can't-spend guarantee, moved from a type-level property to a proven one.)*
- **Balance binding:** the revealed `V` commits the spent coin's true value
  (inherited from V3's shift argument; must survive the extension).
- **Tag determinism & uniqueness:** identical coin+key ⇒ identical `T`
  (double-spend collides); distinct coins ⇒ distinct `T` (no linkage). Follows
  from `B_l = Hp(C_l)` being injective-enough (collision ⇒ break SHA3/ristretto).
- **Anonymity (index hiding):** the extended one-of-many stays
  witness-indistinguishable; adding the parallel selection must not leak `l`.
- **No spend-key leakage:** `T` and the proof reveal nothing about `x` beyond
  `x·H` (already public as part of `C_l`) — standard for key-image proofs.
- **Fiat-Shamir binding:** `T`, `V`, the full set, and the fee/`value_balance`
  message are all in the challenge (transcript malleability = the classic hole).

## Interfaces & wiring (post-audit, gated)

- `crypto/groth_kohlweiss.rs`: `SparkSpendProofV4` + `prove_spend_tagged` /
  `verify_spend_tagged` (extends `prove_one_of_many_ctx`). Retire V3's
  reveal-serial spend for the shielded path.
- `crypto/spark_note.rs`: reuse `hash_to_point`, `link_tag`, and the
  `prove_tag`/`verify_tag` equality as the tag rail; generalize to hidden index.
- `consensus/shielded.rs`: `ShieldedInput.nullifier` is `T` (already `[u8;32]`);
  `spend_proof` carries the V4 bytes. No wire-format change to the payload.
- `consensus/shielded_pipeline.rs::gk::verify_shielded_payload`: swap the per-input
  spend verify to `verify_spend_tagged`; the double-spend set keys on `T`.

## Open questions (pin with the paper before coding)

1. Route (A) dual-selection soundness — confirm the parallel one-of-many over
   `{Hp(C_i)}` does not weaken index-hiding or membership soundness (cite
   Triptych §key-image / Omniring). If it does, fall back to (B).
2. Exact transcript ordering for Fiat-Shamir (domain-separated, all public inputs).
3. Interaction with the fixed-size bucket / NUMS pad (`cip-shielded-anonset.md`):
   the pad members' `Hp` must be well-defined and non-spendable.
4. Batch verification of `{Hp(C_i)}` and the parallel selection (perf).

## Build order (only after design sign-off + with audit lined up)

1. Formalize Route (A) against the paper; write the reduction sketch here.
2. Implement `SparkSpendProofV4` gated `sketch-gk-proof`; unit tests
   (round-trip; wrong-key reject; tamper reject; index-hiding sanity;
   double-spend collision).
3. Swap `verify_shielded_payload` to V4; regtest end-to-end (mint → scan → spend).
4. 24h shielded soak. 5. **External audit.** 6. Activation.
