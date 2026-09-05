# WP-014 · Encrypted Memos
### Payment metadata that does not partition the anonymity set

**Status:** Shipped · **Layer:** Wallet / Crypto · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Payments need context. An invoice number, an order reference, a note to the
recipient — without somewhere to put them, users put them somewhere worse: a
plaintext field, an email, an exchange's memo box, or a public tag that
permanently links the payment to an identity.

A privacy chain that offers no memo field does not eliminate the need; it exports
it to systems with no privacy at all.

The design problem is not encryption — that part is routine. It is that a memo is
**optional and observable**, and an optional observable feature sorts users into
those who use it and those who do not (WP-011 §1). The memo must therefore be
both confidential *and* invisible.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Plaintext payment metadata** | Memos are readable by anyone with the chain | ECDH-encrypted to the recipient's view key |
| **Memo-user fingerprinting** | Transactions with memos differ observably from those without | Fixed-cap padding, so size does not distinguish them |
| **Memo-size content inference** — a 6-byte memo is an invoice number, a 200-byte one is a message | Ciphertext length tracks plaintext length | Same fixed cap |
| **Nonce reuse** — two memos share a (key, nonce) pair | A deterministic nonce derived from a shared secret is safe | Fresh random nonce per encryption, carried on the wire |
| **Key material left in memory** | Stack temporaries are cleaned up by dropping | Explicit zeroization of the shared point, its bytes, and the AEAD key |
| **Chain bloat by oversized memos** | Wallets are the only producers of transactions | Consensus-enforced size cap (from the v1.0.12 fork) |

---

## 3. Design

### 3.1 Construction

```
shared_point = tx_secret · recipient_view_public          (ECDH)
key          = BLAKE3("COINCYNC_MEMO_v1" ‖ shared_point)
nonce        = 12 fresh random bytes (OS RNG), per encryption
ciphertext   = ChaCha20-Poly1305(key, nonce, memo)
wire         = nonce (12) ‖ ciphertext ‖ tag (16)
```

The recipient recovers the same shared point as
`view_secret · tx_public_key` and reads the nonce off the wire. Only the holder
of the view key can decrypt — the same key that already detects the output, so
memos require no additional key material and no separate channel.

Sizes: plaintext capped at **226 bytes**, padded to **228**, overhead **28**
(12 nonce + 16 tag) — so every encrypted memo on the wire is exactly **256
bytes**, the consensus cap.

The cap is **derived** from `MAX_OUTPUT_MEMO_SIZE` rather than written down
twice, with a compile-time assertion that the padded plaintext plus AEAD
overhead lands exactly on it. This is deliberate: the previous hardcoded 256-byte
plaintext cap encrypted to 284 bytes, which consensus **rejected** — the
documented maximum memo was unusable, and the wallet would build a transaction
the network refused (verified live: a 240-byte memo drew `encrypted_memo too
large: 268 bytes (max 256)`). Deriving it makes that asymmetry unrepresentable
rather than merely fixed.

### 3.2 The nonce-reuse defect

The original design derived the nonce deterministically:

```
nonce = BLAKE3("COINCYNC_MEMO_NONCE_v1" ‖ shared_point)[..12]
```

This is a catastrophic construction. Two calls with the same `(tx_secret,
recipient_view_public)` pair produce an **identical (key, nonce) pair**. Under
ChaCha20-Poly1305 that means:

- The two ciphertexts share a keystream, so XORing them yields
  `plaintext_a ⊕ plaintext_b` — an attacker who observes both recovers content
  with no key.
- The Poly1305 authenticator becomes **forgeable**, because its one-time key is
  reused. Integrity fails as well as confidentiality.

It was replaced (2026-06-03) with a fresh random nonce placed on the wire. The
12-byte overhead is the correct price.

**Why it was tempting.** Deriving the nonce saves 12 bytes and looks elegant: the
shared point is already secret, already unique per (sender, recipient, tx), and
never repeats *in the intended flow* — the builder attaches at most one memo per
transaction. The reasoning was that a nonce is unique because the *situation* is
unique.

That is the trap. AEAD nonce uniqueness must be guaranteed by **construction, not
by usage assumptions**, because usage changes: a retry, a second memo per
transaction, a future multi-output memo feature, or a caller outside the wallet
flow all break the assumption silently, with no error and no test failure. A
random nonce is safe under every one of those changes. **When a cryptographic
requirement can be met structurally or contextually, meet it structurally** — the
context is not stable across the code's lifetime.

**A documentation postscript.** The module's header comment continued to describe
the derived-nonce protocol long after the code stopped doing it, so a reader
auditing from the doc would have found a vulnerability that was already fixed —
or, worse, copied the documented design. It was corrected on 2026-09-04 while
writing this paper. Same lesson as WP-021 §4 and WP-013 §4: **documentation drifts
away from code silently, and security documentation drifting is itself a defect.**

### 3.3 Zeroization

Three pieces of secret material are explicitly wiped rather than left to fall out
of scope:

- `shared_point_bytes` — the ECDH shared secret, previously passed as a temporary
  `[u8; 32]` that stayed on the stack after the call.
- `key_bytes` — the AEAD key, previously dropped as a plain array with no
  zeroization, leaving ChaCha20-Poly1305 key material live for the caller's
  lifetime.
- `shared_point` itself — the `PublicPoint`, wiped via curve25519-dalek's
  `Zeroize` implementation for the underlying field elements.

None of these were exploitable on their own; together they are the difference
between "the key is gone" and "the key is probably gone."

### 3.4 Uniformity: padding, and what it does not fix

The plaintext is padded to a constant size before encryption, as
`[len: u16 LE][memo][zero fill]`, so **every** encrypted memo is exactly 256
bytes regardless of what the user wrote. Memo *length* is therefore not
observable, and a 6-byte invoice reference is indistinguishable on the wire from
a 200-byte note.

This closes a real leak. Until 2026-09-05 the plaintext was encrypted unpadded,
so ciphertext length tracked content length directly — live measurement: a
27-byte memo produced 55 wire bytes, a 200-byte memo produced 228. That sorts
users by content class, the partitioning WP-011 §1 exists to prevent.

**Padding does not hide memo *presence*.** An output with no memo carries an
empty field; one with a memo carries 256 bytes. Closing that gap requires a
fixed-size memo field on *every* output — a consensus rule with a real
per-transaction size cost, and a separate decision (§6).

Consensus enforces the 256-byte cap at block validation from the v1.0.12 hard
fork (height 13,000), which exists to stop miner-crafted transactions from
bypassing mempool admission and bloating blocks. Padding is wallet-side; the cap
is consensus-side, and the two are now tied together by derivation.

**Backward compatible.** A padded plaintext is always exactly the padded size, so
any other decrypted length is unambiguously a pre-padding memo and is returned
unchanged — no version byte, and memos written before the change still read.

---

## 4. Security analysis

**What holds.** Memo contents are confidential to the view-key holder and
authenticated; nonces are unique by construction; secret material is wiped; the
size cap is consensus-enforced against bloat.

**What this does not protect against.**

- **Padding is a wallet convention, not a consensus rule.** Consensus caps the
  encrypted memo but does not *require* it to be exactly that size, so a modified
  wallet can still emit a short unpadded memo and self-identify its user. The
  uniformity property in §3.4 holds for honest software. Closing it requires
  consensus to fix the field to a constant length — a hard fork, and the right
  long-term answer.
- **Memo presence is still observable** (§3.4). This is now the larger of the two
  remaining leaks, since length is closed.
- **The recipient learns the memo.** Obviously, but worth stating: memos are
  confidential *from third parties*, not from the counterparty.
- **The view key decrypts memos.** Anyone given a view key — for auditing,
  disclosure, or light-wallet scanning — can read every memo it covers. Memo
  privacy is bounded by view-key discipline (WP-013 §3.6), and this is a real
  consequence of sharing a `ScopedViewKey`.
- **No forward secrecy.** A compromised view key decrypts all past memos on chain.
- **Metadata is not content.** That a transaction *carries* a memo of the padded
  size is not hidden by encryption; it is hidden only by everyone else padding
  too.

---

## 5. Implementation

| Component | Location |
|---|---|
| ECDH derivation, encrypt/decrypt, nonce handling, zeroization | `src/crypto/memo.rs` |
| `MAX_MEMO_SIZE`, `MEMO_OVERHEAD`, `MAX_ENCRYPTED_MEMO_SIZE` | `src/crypto/memo.rs` |
| `MAX_OUTPUT_MEMO_SIZE` + v1.0.12 consensus cap | `src/constants.rs`, `src/consensus/validation.rs` |
| Memo attachment in the send path | `src/transaction/builder.rs`, `src/wallet/send/` |

**Failure record.** Nonce-reuse fix 2026-06-03; zeroization fixes R-16 / R-17 /
R-7-class / R-80 (2026-07-02–03); header-comment correction 2026-09-04.

---

## 6. Known limits

- Padding is not consensus-enforced (§4) — a modified wallet can still skip it.
- **Memo presence still leaks**: 256 bytes versus an empty field. Fixing it needs
  a fixed-size memo field on every output — consensus change, real size cost.
- No forward secrecy against later view-key compromise.
- The usable memo is 226 bytes, down from a documented 256 that could not
  actually be spent.
- Memo presence (at padded size) is not concealed by this mechanism alone; it
  depends on WP-011's uniformity holding network-wide.

---

## 7. References

- Bernstein, *ChaCha20* and *Poly1305*; RFC 8439 — including its explicit
  nonce-uniqueness requirement.
- Monero `tx_extra` payment IDs and their deprecation history — prior art for how
  optional payment metadata becomes a deanonymisation vector.
- Internal: [WP-011 Uniformity](WP-011-transaction-uniformity.md),
  [WP-013 Selective disclosure](WP-013-selective-disclosure.md),
  [WP-009 §3.4](WP-009-privacy-feature-composition.md).
