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

## The tag construction — CORRECTED against the paper (2021/1173)

**Update (grounded in the Lelantus-Spark paper):** the linking tag is a
**Dodis-Yampolskiy-style verifiable random function (VRF)**, *not* a key-image.
The earlier key-image sketch (`T = x·Hp(C_l)`) is the **wrong** tree for Spark's
scan ≠ spend and is retracted here. What the paper actually does:

- **(PRIMARY — Spark's real construction) VRF inversion tag.** The coin has a
  serial-number-context value `s` (derivable by the *view* key, for detection) and
  the spend key contributes a secret `r_spend`. The tag is a VRF evaluation of the
  form `T = (r_spend + s)^{-1}·U` (Dodis-Yampolskiy VRF, base a NUMS `U`). This is:
  - **per-coin** (depends on the coin's `s`) → a key's coins don't all collide;
  - **spend-bound** → computing `T` needs `r_spend` (the view key knows `s` but not
    `r_spend`), which is the scan ≠ spend separation, done properly;
  - **unforgeable & unique** (VRF pseudorandomness + uniqueness).
  The cost: the spend proof must prove a **multiplicative/inverse relation**
  (`T·(r_spend + s) = U`), i.e. a Chaum-Pedersen over the inverse, fused with the
  one-of-many — the standard Spark spend proof.
- **(RETRACTED) key-image `T = x·Hp(C_l)`.** Nonlinear `Hp` over a hidden member
  needs a Triptych dual-selection, and — more importantly — it does not match
  Spark's view/spend key split. Do not implement this route.

**Implication for the code already written:** `spark_note::link_tag` /
`prove_tag` / `verify_tag` (the key-image + Chaum-Pedersen equality) are a
*correct standalone equality-of-DL primitive* but the **wrong tag shape** for the
shielded spend. They stay as a tested building block / for other uses, but the
shielded nullifier must be the VRF tag above. Flag them in code accordingly.

## Construction (VRF route — to be transcribed verbatim from the paper, then audited)

The precise relations must be copied from Lelantus-Spark §(spend proof) — this
CIP intentionally does **not** reconstruct the VRF one-of-many algebra from
memory (that is how subtly-unsound proofs get shipped). The shape to transcribe:

1. Membership + value: the HK one-of-many already built
   (`prove_spend_value_hidden`, `SparkSpendProofV4`) proves `W_l = C_l − V ∈
   ⟨H,K⟩` at hidden `l`, serial hidden. **This half is done and sound.**
2. Serial recovery: the view key derives `s` for the spent coin (see
   `cip-shielded-notes.md`, `RecoveredNote.serial_public`).
3. VRF tag: publish `T = (r_spend + s)^{-1}·U`; prove `T·(r_spend + s) = U`
   without revealing `r_spend` or `s`, and prove the *same* `s` is the spent
   coin's serial (binding the tag to the hidden member selected in step 1).
4. Single Fiat-Shamir transcript over `ctx ‖ set ‖ V ‖ T ‖ all commitments`.

**Blocking dependency:** transcribe steps 3's exact relations + generators from
the paper (or the Firo reference implementation) before coding. Until then the
nullifier cannot be produced soundly, so the shielded spend is not end-to-end.

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
