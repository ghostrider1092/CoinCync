# CIP-Shielded — Spend Composition: binding the linking tag into the one-of-many

Status: **DESIGN / draft** (not implemented). Companion to `cip-shielded-proof.md`,
`cip-shielded-notes.md`, `cip-shielded-anonset.md`. This closes the **last crypto
gap** between "shielded notes exist" and "shielded notes are spendable end-to-end
with scan ≠ spend". **Privacy-critical & consensus-critical — must be finalized
against the Lelantus-Spark paper (Feickert & Jivanyan) and externally audited
before it lands unGated.** Everything stays behind `sketch-gk-proof` +
`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` until then.

## PINNED REFERENCE CONSTRUCTION (from Firo `libspark`, `master`)

Transcribed verbatim from the **deployed, audited** reference implementation
(`firoorg/firo/src/libspark/` — `coin.cpp`, `keys.cpp`, `chaum.cpp`,
`params.cpp`), not from memory. This is the ground truth to build/bind against.
Firo is on **secp256k1**; CoinCync is on **ristretto/curve25519**, so every
generator below must be **re-derived as a NUMS point on ristretto** (the algebra
is curve-agnostic; only the group changes).

### Generators (`params.cpp`)
- `F = hash_generator("F")`, `H = hash_generator("H")`, `U = hash_generator("U")`
  — NUMS. `G = base point`. Plus `G_range/H_range` (BPPlus range) and
  `G_grootle/H_grootle` (one-of-many), `n_grootle=8, m_grootle=5` ⇒ anon set
  `n^m = 8^5 = 32768` (test: `n=2, m=4`). **Note: Grootle is base-`n`, not the
  base-2 of our current HK one-of-many.**

### Keys (`keys.cpp`)
- **SpendKey** `= (s1, s2, r)` — three scalars; `r` is the spend authority.
- **FullViewKey** `= (s1, s2, D, P2)` with **`D = G·r`**, `P2 = F·s2 + D`.
- **IncomingViewKey** `= (s1, P2)`.
- **Address(i)** (diversifier `i`): `Q1 = hash_div(d)·s1`,
  **`Q2 = F·hash_Q2(s1,i) + P2`**.

### Coin (`coin.cpp`)
- Recovery key: `K = hash_div(d)·hash_k(k)` (`k` = per-coin nonce).
- **Value commitment:** `C = G·v + H·hash_val(k)`.
- **Serial commitment:** `S = F·hash_ser(k,ctx) + Q2` `= F·s + D`, where the
  **serial** `s = hash_ser(k,ctx) + hash_Q2(s1,i) + s2` (needs `s2` ⇒ full view).
- **Tag / nullifier (the VRF):** `T = (U − D)·s⁻¹` (Dodis-Yampolskiy inversion).

### Detection vs spend (this IS scan ≠ spend, done right)
- **Incoming view** (`s1,P2`): *identifies* a coin — decrypt recipient data with
  `K·s1`, then check `K`, `C`, `S` (`coin.cpp::identify`/`validate`).
- **Full view** (`+s2,D`): *recovers* `s` and computes `T` — so it can **detect/
  link** spends. It still **cannot spend** (no `r`).
- **Spend** needs `r` (`D = G·r`): the Chaum proof proves knowledge of it.

### Spend proof (three ANDed proofs over the same transcript)
1. **Grootle one-of-many** over the cover set `{S_i}`: proves the spender opens a
   re-randomization of one `S_l` at a **hidden** index `l`. (Our
   `SparkSpendProofV4` HK one-of-many is the base-2 analogue of this — good, but
   Grootle is base-`n`.)
2. **Chaum tag proof** (`chaum.cpp`) — the piece I got wrong before. For each
   input it proves knowledge of `(x, y, z)` with:
   - `F·x + G·y + H·z = S`   (serial-commitment opening; `x = s`, `y = r`)
   - `T·x + G·y = U`         ⟺  `T·s = U − G·r = U − D`  ⟺  `T = (U−D)·s⁻¹`

   The Σ-protocol: commit `A1 = F·r_+G·s_+H·t_`, `A2 = T·r_+G·s_`; challenge
   `c` over a labeled transcript (`F,G,H,U,mu,S,T,A1,A2`); responses
   `t1=r_+c·x, t2=s_+c·y, t3=t_+c·z`. Verify `A1+S·c = F·t1+G·t2+H·t3` and
   `A2+U·c = T·t1+G·t2`. **This binds the tag to both the serial `s` and the
   spend key `r` without revealing either — the real scan≠spend enforcement.**
3. **BPPlus range** on `C` (value ≥ 0) + a **balance** relation across inputs/
   outputs/fee/`value_balance` (the Chaum V2 transcript binds cover-set refs,
   outputs, fee, transparent_value).

### Consequence for CoinCync's current model (the real design decision)
Spark uses **two commitments per coin** — a value commitment `C = G·v + H·(nonce)`
and a **separate** serial commitment `S = F·s + D`. CoinCync's current bound coin
**fuses** value+serial+blinding into one point (`C = v·Gv + s·H + r·K`). To adopt
Spark's spend/tag **soundly**, the coin must be **restructured to Spark's `(C, S)`
two-commitment form** (or bind to `libspark` via FFI). Corollaries:
- The key-image tag + Chaum in `spark_note.rs` is **retracted** (already flagged);
  the real tag is `T=(U−D)·s⁻¹` with the Chaum relations above.
- `SparkSpendProofV4`'s HK one-of-many maps to Grootle but must move to base-`n`
  and operate over `{S_i}` (serial commitments), not the fused coins.
- The Note Connector (`cip-shielded-notes.md`) must produce Spark-shaped coins
  `(K, C, S)` with `s`/`k` derived per the key schedule above.

**Recommendation (unchanged, now evidenced): bind to `libspark` via FFI** rather
than reimplement Grootle+Chaum+BPPlus from scratch — inherit its audit; put the
originality in the CoinCync integration. Reimplementing is the high-risk path.

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
