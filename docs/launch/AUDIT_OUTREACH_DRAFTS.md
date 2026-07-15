<!-- markdownlint-disable MD013 MD036 -->
# Audit Firm Outreach Drafts — v1.0 Base-Chain

Three paste-ready cold emails for v1.0 base-chain audit firm engagement. Same project, same scope, same deliverable expectations — just tailored to each firm's known specialty so the framing reads as researched, not blasted.

**Before sending:**

1. **Confirm NLnet grant status.** Each draft references NLnet funding as the engagement model. If you don't yet have an NLnet grant approved, change the line to *"funding currently being finalized through NLnet"* or *"we expect funded engagement via NLnet or equivalent OSS-focused funder."* Don't claim a grant ID that doesn't exist.
2. **Confirm your name + signature line.** The drafts use `[Your name]` placeholder — sub in your actual name and any handle you want attached.
3. **Send in this order, ~24 hours apart.** Cypher Stack first (most-aligned), then OSTIF, then Teserakt. Spaces let you reply to early responders without juggling three threads at once.
4. **Tag GitHub release for reproducibility.** The audit firms will want to know the exact commit to review. Reference `v1.0.9-testnet-pre-audit` (current) or whatever tag is closest to the engagement-kickoff commit when you actually send.

---

## 1 — Cypher Stack

**To:** info@cypherstack.com (verify current address before sending)
**Subject:** CoinCync v1.0 base-chain cryptographic audit — scoping inquiry

```
Hi Cypher Stack team,

I'm reaching out about a cryptographic audit engagement for CoinCync —
a privacy-first proof-of-work cryptocurrency targeting October 1, 2026
mainnet. I've followed your Monero-side work (CLSAG, RingCT, view-key
analysis) and you're the first firm we want to talk to on this.

**Project at a glance:**

- Solo-dev open-source project, MIT licensed
- Privacy stack borrows extensively from the Monero / Zcash lineage:
  CLSAG ring signatures, stealth addresses, Bulletproofs+ range proofs,
  Pedersen commitments, Dandelion++ propagation, RandomX PoW, encrypted
  memos, view tags, view-key scoping, FROST M-of-N multisig (RFC 9591)
- Constitutional compile-time enforcement of privacy properties
  (Article III: mandatory shielding, Article IX: no surveillance hooks,
  Article XII: no admin authority, Article XIII: no external trust)
- Currently on public testnet; pre-audit hardening pass shipped this
  week (23 fixes + lockfile re-hash)

**Audit scope:**

v1.0 base chain only — ~73 000 LOC across the root crate + four
supporting workspace members (FROST coordinator, rolling-finality
adapter, mining rig CLI, faucet). 585/585 library tests passing.
**Cyncswap (CIP-001 atomic swaps) is explicitly out of scope** — it
ships v1.1 as a separate engagement after the chain itself is audited
and shipping.

The wayfinding doc is here:

https://github.com/Coincync/Coincync-Testnet-/blob/main/docs/v1.0-mainnet-audit-prep.md

It includes the scope table, the 16-primitive cryptographic map, 14
prioritized review targets, test-vector inventory, knowingly-missing
items, and the build + test reproducibility commands. ~73 000 LOC
implementation + tests; the doc tells you which file holds what.

**Funding model:**

NLnet-funded OSS engagement (grant currently being finalized). Happy
to align scope + timeline + budget on a scoping call. Engagement
target: kickoff late June / early July 2026, deliverable by late
August so the report informs the October 1 mainnet decision.

**Frozen reference commit:**

v1.0.9-testnet-pre-audit (the most recent tag) — pre-audit hardening
already applied. We'll freeze a `v1.0-audit-input` tag at engagement
kickoff and the audit reviews exactly that commit.

If this is in your scope and timing window, I'd love to set up a
30-minute scoping call. If you'd rather see a fuller scope-of-work
proposal first, the audit-prep doc above should give you enough to
draft one and I'll iterate.

Thanks for considering it.

— [Your name]
   CoinCync solo dev / maintainer
   github.com/Coincync/Coincync-Testnet-
```

---

## 2 — OSTIF (Open Source Technology Improvement Fund)

**To:** contact@ostif.org (verify current address before sending)
**Subject:** CoinCync v1.0 mainnet audit — OSTIF intake inquiry

```
Hi OSTIF team,

I'm writing about an audit-coordination engagement for CoinCync, a
solo-developed open-source privacy-first PoW cryptocurrency targeting
October 1, 2026 mainnet.

I'm reaching out to OSTIF specifically because:

(a) The project is open-source (MIT), genuinely needs external review,
    and is exactly the kind of OSS that benefits from your coordination
    model with audit firms.
(b) Your past coordinations with privacy and PoW projects (the
    Monero / Cake Wallet / Zcash / etc. work) match the discipline of
    this audit better than a generic appsec engagement would.
(c) NLnet funding is on the table for the engagement, and OSTIF's
    coordination experience with NLnet-funded OSS audits is what
    we'd be leaning on.

**Project at a glance:**

- Privacy-first PoW chain on the Monero / Zcash technical lineage:
  CLSAG, stealth addresses, Bulletproofs+, Pedersen commitments,
  Dandelion++, RandomX, view tags + view-key scoping, encrypted memos,
  FROST M-of-N multisig
- Compile-time-enforced constitutional privacy properties (mandatory
  shielding, no surveillance hooks, no admin keys, no external bridges
  admitting trust into consensus)
- Currently public testnet; pre-audit hardening pass shipped this week

**Audit scope:**

v1.0 base chain only — ~73 000 LOC across the root crate + four
supporting workspace members. 585/585 lib tests passing. Cyncswap
(CIP-001 atomic swaps) is explicitly out of scope, with its own
audit engagement planned ~30 days post-mainnet ship.

Audit-prep wayfinding doc, scope table, primitives map, prioritized
review targets, and reproducibility commands:

https://github.com/Coincync/Coincync-Testnet-/blob/main/docs/v1.0-mainnet-audit-prep.md

**What I'm asking for:**

A scoping conversation about (a) whether OSTIF's coordination model
fits this engagement and (b) which audit firms in your network you'd
recommend pairing with — Cypher Stack, Teserakt, and similar firms
with deep PoW-privacy experience are the kind we'd want at the table.

**Timing:**

Kickoff late June / early July 2026, deliverable late August so the
report informs the October 1 mainnet decision. Frozen reference
commit will be a `v1.0-audit-input` tag at engagement kickoff. The
project is non-premine and the audit cost is being routed through
NLnet (grant currently being finalized).

Thanks for considering it. Happy to take this to a call, or send
more detail in whatever intake format you prefer.

— [Your name]
   CoinCync solo dev / maintainer
   github.com/Coincync/Coincync-Testnet-
```

---

## 3 — Teserakt

**To:** contact@teserakt.io (verify current address before sending)
**Subject:** CoinCync v1.0 base-chain cryptographic engineering audit — scoping inquiry

```
Hi Teserakt team,

I'm reaching out about a cryptographic engineering audit for CoinCync —
a privacy-first proof-of-work cryptocurrency targeting October 1, 2026
mainnet. I've followed your protocol-engineering and side-channel work
(the E4 IoT crypto stack, the cryptographic-research write-ups) and the
discipline matches what this engagement needs.

**Project at a glance:**

- Solo-dev open-source PoW chain, MIT licensed
- Privacy stack: CLSAG ring signatures, stealth addresses, Bulletproofs+
  range proofs, Pedersen commitments, Dandelion++ propagation, RandomX
  PoW with FFI to the upstream randomx-rs / librandomx, encrypted memos
  with ChaCha20 + ECDH, view-tag fast scanning, FROST M-of-N multisig
  (RFC 9591), scoped view keys, plausible-deniability wallets
- Network: Noise XX P2P with X25519 + ChaCha20-Poly1305 + forward
  secrecy, optional Tor/SOCKS5 transport, traffic shaping with
  constant-rate padding to defeat timing correlation
- Constitutional compile-time enforcement of privacy properties

**Why Teserakt specifically:**

Three audit surfaces in this engagement are the kind your past work
suggests you're particularly suited for:

1. **Noise XX implementation** + handshake state machine, frame-size
   bounds, cancel-safety in the framer — protocol engineering at the
   wire level.
2. **RandomX FFI boundary** — the only unsafe-code surface in the
   v1.0 perimeter. Library is upstream librandomx, wrapped with care,
   but every panic-free invariant is on us.
3. **Side-channel surface** — view-tag scanning timing, Argon2id
   wallet-unlock timing (KDF parameters bounded in validate(), recent
   fuzz finding fixed), constant-time comparison on critical paths.

**Audit scope:**

v1.0 base chain only — ~73 000 LOC across the root crate + four
supporting workspace members. 585/585 lib tests passing. Cyncswap
(CIP-001 atomic swaps) explicitly out of scope; that's a separate
engagement post-mainnet.

Wayfinding doc + scope + primitives map + prioritized review targets:

https://github.com/Coincync/Coincync-Testnet-/blob/main/docs/v1.0-mainnet-audit-prep.md

**Funding + timing:**

NLnet-funded OSS engagement (grant currently being finalized). Target
kickoff late June / early July 2026, deliverable late August to inform
the October 1 mainnet decision. Frozen reference commit will be a
`v1.0-audit-input` tag at engagement kickoff.

If this is in your scope and capacity window, I'd appreciate a
30-minute scoping call to align on what subset of the perimeter
you'd own (vs. a parallel engagement with a CLSAG-focused firm) and
what your deliverable + timeline look like.

Thanks.

— [Your name]
   CoinCync solo dev / maintainer
   github.com/Coincync/Coincync-Testnet-
```

---

## After sending

- Add each firm's reply or no-reply state to a tracker (a simple `docs/audit-firm-status.md` would do)
- Treat "no reply in 10 business days" as a soft no, follow up once, then move on
- If two firms come back interested with overlapping scope, that's a good problem — pair them on different surfaces (e.g., Cypher Stack on CLSAG / privacy-primitives, Teserakt on protocol engineering + side-channels)
- OSTIF wins the "coordination + funder liaison" role regardless of which audit firm(s) you end up hiring — they'd be the layer between you and NLnet

## What NOT to do

- Don't blast all three on the same day. Audit-firm community is small; the firms talk. Sending the same hour reads as "blasted three at once, will go with whoever's cheapest." Sending 24h apart with tailored framing reads as "thoughtful, did the homework."
- Don't include a budget number in the cold email. Let them quote you. NLnet grants typically clear €50-150k for this scope, but the firm sets the number against the scope they propose.
- Don't include the audit-prep doc as an attachment. The link to GitHub is enough — they'll click it to verify the project actually exists.
- Don't promise a specific commit yet. The audit-input tag gets cut at engagement kickoff, not pre-engagement.
