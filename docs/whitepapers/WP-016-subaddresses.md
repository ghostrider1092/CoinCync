# WP-016 · Subaddresses
### Unlimited unlinkable receive addresses — and a feature gated off for fund safety

**Status:** **Gated — disabled on mainnet (W-1: received funds are unspendable)**
· **Layer:** Wallet · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Address reuse is the oldest deanonymisation technique there is. A user who posts
one address and receives ten payments has handed every payer a shared identifier
and let them all see each other's payments to the same recipient.

Stealth addresses already solve this on chain — every payment produces a distinct
one-time output — but they do not solve it *off* chain. Two payers holding the
same published address string know they paid the same person. A merchant wanting
per-invoice accounting, or a user wanting one address per counterparty, needs
distinct **published** addresses, and needs them without maintaining a separate
wallet and seed for each.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Published-address correlation** — two payers compare the address they paid | One wallet publishes one address | Unlimited derived addresses, unlinkable to each other |
| **Main-address linkage** — a subaddress is visibly derived from the main one | Derivation is publicly computable | Derivation uses the **view secret**; only the owner can group them |
| **Scan-cost explosion** — N addresses means N times the scanning work | Each address needs its own scan | One view secret scans all of them |
| **Derivation DoS** — unbounded index space exhausts wallet memory | Index space may be unbounded | 100 accounts × 10,000 indices, bounding the in-memory index |
| **Unspendable funds** *(unresolved)* | Detection and spending derive from the same key material | **Not removed** — see §4. Mitigated by disabling the feature on mainnet |

---

## 3. Design

### 3.1 Derivation

For a subaddress at `(account = i, index = j)`, given main spend key `B` and view
secret `a`:

```
m   = H("COINCYNC_SUBADDR_v1" ‖ a ‖ i ‖ j)     derivation scalar
D_i = m·G + B                                   subaddress spend key
C_i = a·D_i                                     subaddress view key
```

This follows the Monero subaddress construction. Two properties follow:

**Unlinkability.** Each subaddress publishes a *distinct* view key `C_i`. An
observer holding two subaddresses cannot tell they belong to one wallet, and
cannot relate either to the main address, because recovering `m` requires the view
secret `a`.

**Single-secret scanning.** A payment to a subaddress uses transaction public key
`R = r·D_i`. The wallet computes `a·R = r·C_i` with the one view secret it already
has — so N subaddresses cost one ECDH per output, not N. This is why subaddresses
scale where separate wallets do not.

### 3.2 Bounded index space

100 accounts × 10,000 subaddresses = 1,000,000 maximum derivations per wallet,
bounding the in-memory subaddress index at roughly 64 MB worst case. The chain has
no knowledge of subaddress indices at all — it sees only stealth addresses — so
the bound is purely a local resource limit, not a consensus rule.

---

## 4. The defect: detection and spending derive differently

**Subaddress-received funds are currently unspendable.**

Detection succeeds: the scanner uses the per-subaddress view key path and
correctly identifies the output as belonging to the wallet. The balance appears.

Spending fails: the spend-side one-time-secret and key-image derivation **omit the
per-subaddress offset `m`**. They derive as though the output had been sent to the
main address. The resulting key image and signature do not correspond to the
actual output, so the spend cannot be constructed correctly.

The consequence is the worst possible failure mode for a wallet feature: **funds
you can see and cannot spend.** A balance that displays, an output that is
provably yours on chain, and no way to move it.

### 4.1 Why this is the archetypal composition failure

This is WP-009's §3.3 case, and the reason that paper exists. Neither side is
wrong in isolation — the detection path implements subaddress detection correctly,
and the spend path implements main-address spending correctly. The defect lives
entirely in the **assumption each makes about the other**: that an output detected
by one path is spendable by the other.

Receive worked, so the feature looked done. **"Receive works" is half a feature,
and it is the dangerous half**, because it is the half that takes custody of money.
A feature is not composed until the full lifecycle composes: detect, spend, scan,
disclose, recover.

### 4.2 The gate

Subaddresses are **disabled on mainnet** by an explicit launch-safety check
(W-1, 2026-08-16). Invoking any subaddress command on mainnet returns an error
directing the user to their main address.

They remain **enabled on testnet and regtest**, deliberately, so the fix can be
developed against a real receive → spend round trip.

Two aspects of this gate are worth stating as policy:

1. **Fail closed on fund safety.** When the choice is between shipping a feature
   that can silently destroy value and shipping without it, the feature waits.
   Disabling is reversible; unspendable coins are not.
2. **The gate is at the CLI boundary, not in consensus.** That is sufficient for
   the first-party wallet and is *not* sufficient in general: the chain will
   happily accept a payment to a subaddress-derived stealth address sent by other
   software. The gate prevents our wallet from *generating* subaddresses on
   mainnet; it cannot prevent a third-party wallet from doing so.

### 4.3 What the fix requires

The spend path must incorporate `m` into both the one-time secret and the key
image derivation, and the fix must ship with a **verified receive → spend
round-trip test** — not a unit test of the derivation, but an end-to-end test that
sends to a subaddress and successfully spends the result. This is a cryptographic
change to the spend path, so it needs owner sign-off and cryptographer review
before it is enabled on mainnet.

---

## 5. Security analysis

**What holds.** The derivation and detection scheme is sound and follows
established prior art; subaddresses are mutually unlinkable and unlinkable to the
main address; scanning cost is independent of subaddress count; the index space
is bounded.

**What does not hold.**

- **Spending is broken** (§4). This is not a limitation, it is a defect, and the
  feature is gated because of it.
- **The mainnet gate is wallet-side only** (§4.2).
- **Per-subaddress view keys are a disclosure surface.** `C_i` lets a holder detect
  payments to that subaddress specifically — useful for delegated accounting, and
  a leak if handed out carelessly. See WP-013 §3.6 for how view-key scoping does
  and does not constrain a recipient.
- **Unlinkability is on-chain only.** Payment context, timing, and off-chain
  correlation (invoice numbers, shipping addresses) are outside its scope.

---

## 6. Implementation

| Component | Location | Status |
|---|---|---|
| Derivation, index bounds, `SubaddressIndex` | `src/wallet/subaddress.rs` | Live |
| Scanner support, `(account, index)` grid sweep | `src/crypto/stealth.rs`, `src/wallet/scanner.rs` | Live |
| `(account, index)` UTXO storage, multi-account audit scan | `src/wallet/` | Live |
| Spend-side `m` incorporation | — | **Missing (W-1)** |
| Mainnet gate | `src/bin/wallet_support/legacy.rs` | Live |

**Failure record.** W-1, `project_full_audit_2026-08-16`; composition analysis in
WP-009 §3.3; ledger entry WP-100 §5.4.

---

## 7. Known limits

- **Received funds are unspendable; the feature is off on mainnet** (§4).
- The gate does not bind third-party wallets.
- The fix is a consensus-adjacent cryptographic change requiring review.
- Index bounds are policy numbers.
- No round-trip test exists yet — writing one is the first step of the fix.

---

## 8. References

- Monero subaddress design (`m = Hs(a ‖ i ‖ j)`, `D = B + m·G`, `C = a·D`) — the
  construction followed here.
- Internal: [WP-009 §3.3](WP-009-privacy-feature-composition.md),
  [WP-013 §3.6](WP-013-selective-disclosure.md),
  [WP-017 Light sync](WP-017-light-wallet-sync.md),
  [WP-100](WP-100-solved-issues-ledger.md).
