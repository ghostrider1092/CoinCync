# Demo — Auditable privacy (org → auditor, unlinkable solvency)

> The utility made visible: an organization proves its treasury is solvent — and
> optionally reconciles disbursements and receipts — to a **named auditor**,
> **without revealing which outputs are its treasury, the exact balance, or its
> wallet.** The auditor verifies it against a node, which anchors every proof to
> real chain state.
>
> Status: the crypto is built + tested (51 disclosure/compliance tests incl.
> adversarial + anchoring) but **gated (`sketch-gk-proof`) and unaudited** — this
> is a demo of a real, pre-audit capability. See `docs/disclosure-audit-scope.md`.

## Cast
- **Org** — holds a wallet with treasury UTXOs; wants to prove solvency.
- **Auditor** — holds no wallet; verifies the org's signed package against a node.

## Build (regtest)
```bash
WALLET=.../target/release/coincync-wallet.exe
NODE=http://127.0.0.1:18081
export COINCYNC_WALLET_PASSWORD=demo

# Org wallet + a dedicated Ed25519 audit identity (distinct from wallet keys)
$WALLET --wallet org.wallet   --network regtest create
$WALLET --wallet org.wallet   --network regtest --node $NODE scan     # funded by regtest mining

# (regtest node mines to the org address so it has mature treasury UTXOs
#  and the chain holds enough outputs for the --anon-size anonymity set)
```

## 1. Org builds + signs the audit package (unlinkable solvency)
```bash
$WALLET --wallet org.wallet --network regtest --node $NODE disclose build-payroll-audit \
  --org "Acme Labs" --period "2026-Q4" \
  --threshold 10000000000000 \            # 10 CYNC, in atomic units
  --treasury-utxo <TXID:VOUT> \
  --unlinkable-solvency --anon-size 8 \   # hide the treasury among 8 real outputs
  --signing-seed $AUDIT_SEED \            # org's Ed25519 audit key (COINCYNC_AUDIT_SIGNING_SEED)
  --auditor "auditor-1" \                 # addressed to exactly this auditor
  --package acme-2026Q4.json
```
→ writes `acme-2026Q4.json`: an org-signed package asserting "we hold ≥ 10 CYNC",
with the treasury hidden in a Groth-Kohlweiss one-of-many over 8 on-chain outputs.
Multi-output (`--treasury-count K`) proves the **sum** of K hidden outputs, each
in its own disjoint set.

## 2. Auditor verifies it (anchored to the chain)
```bash
$WALLET --network regtest --node $NODE disclose verify-audit-package \
  --package acme-2026Q4.json \
  --issuer <org-audit-pubkey> \           # known out of band, NEVER from the package
  --auditor "auditor-1"
```
→ checks the org Ed25519 signature, that the package is addressed to `auditor-1`,
and **anchors every proof against real on-chain state** via `$NODE`, then prints
the verdict + reconciliation + report. The auditor learns **the claim is true** —
and nothing about which outputs, the exact balance, or the wallet.

## 3. The failures get caught (what makes it real, not a toy)
```bash
# Wrong issuer key → rejected (someone else's signature won't verify)
$WALLET ... verify-audit-package --package acme-2026Q4.json --issuer <other-pubkey> --auditor "auditor-1"

# Wrong audience → rejected (a package issued to auditor-1 can't be replayed to auditor-2)
$WALLET ... verify-audit-package --package acme-2026Q4.json --issuer <org-pubkey> --auditor "auditor-2"

# Tampered package (flip a byte in the JSON) → rejected (signature / anchoring fails)

# Threshold above the real balance → the BUILD fails (you can't prove what you don't hold)
```

## What the auditor learns vs. what stays private
| Auditor learns | Stays private |
|---|---|
| treasury ≥ threshold, as of a height | which outputs are the treasury |
| the org signed it, addressed to them | the exact balance |
| the claim anchors to real chain state | the wallet's addresses |

## Honest caveats
- **Gated + unaudited** (GK `sketch-gk-proof`): real and tested, **not claimable
  until audit** (same audit as the shielded pool — shared GK primitive).
- Proves "held ≥ threshold **at height H**", not "currently unspent" (unlinkable ⟺
  no key-image reveal — the deliberate tradeoff vs. Monero's linkable reserve proof).
- Anchoring is load-bearing: the verdict is only sound because `verify-audit-package`
  confirms every anonymity-set member is a real on-chain commitment.
