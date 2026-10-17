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
>
> **Live-verified** on a throwaway regtest chain (height 40) on 2026-10-16 with
> `coincync-wallet` + `coincync-node` both built `--features "testnet
> sketch-gk-proof"`. The captured verdicts are inline below (§2, §3). The one
> integration gotcha this run surfaced is written up in "Honest caveats".

## Cast
- **Org** — holds a wallet with treasury UTXOs; wants to prove solvency.
- **Auditor** — holds no wallet; verifies the org's signed package against a node.

## Build (regtest)
```bash
# BOTH binaries must be built with the gk feature — the node verifies the proof:
#   cargo build --release --bin coincync-wallet --features "testnet sketch-gk-proof"
#   cargo build --release --bin coincync-node   --features "testnet sketch-gk-proof"
WALLET=.../target/release/coincync-wallet.exe
NODE=http://127.0.0.1:18081
export COINCYNC_WALLET_PASSWORD=demo

# Org wallet + a dedicated Ed25519 audit identity (distinct from wallet keys)
$WALLET --wallet org.wallet   --network regtest create
$WALLET --wallet org.wallet   --network regtest --node $NODE scan     # funded by regtest mining

# (regtest node mines to the org address so it has mature treasury UTXOs
#  and the chain holds enough outputs for the --anon-size anonymity set;
#  freeze the chain — restart the node without --mine — for a clean verify.)
```

## 1. Org builds + signs the audit package (unlinkable solvency)
```bash
export COINCYNC_AUDIT_SIGNING_SEED=<org's ed25519 audit key, 32-byte hex>
$WALLET --wallet org.wallet --network regtest --node $NODE disclose build-payroll-audit \
  --org "Acme Labs" --period "2026-Q4" \
  --threshold 10000000000000 \            # 10 CYNC, in atomic units
  --treasury-utxo-index 0 \               # or the stable --treasury-utxo <TXID:VOUT>
  --unlinkable-solvency --anon-size 8 \   # hide the treasury among 8 real outputs
  --auditor "auditor-1" \                 # addressed to exactly this auditor
  --out acme-2026Q4.json                  # NOTE: --out (not --package) on the build side
```
→ writes `acme-2026Q4.json`: an org-signed package asserting "we hold ≥ 10 CYNC",
with the treasury hidden in a Groth-Kohlweiss one-of-many over 8 on-chain outputs.
Multi-output (`--treasury-count K`) proves the **sum** of K hidden outputs, each
in its own disjoint set. The command prints the issuer pubkey and the exact
verify command. Captured from the live run:
```
Signed audit package written to acme-2026Q4.json
  org:      Acme Labs
  period:   2026-Q4
  auditor:  auditor-1
  audit_id: cc98e6f9507d8f2f27d1a95f26b58e0a4c3f48cae77b308a80d6309528491dab
  issuer:   d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737
```

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

Captured verdict from the live run (the full report also renders a "Treasury
solvency (unlinkable)" section with the as-of-height caveat):
```json
{
  "accepted": true,
  "signature_valid": true,
  "anchored_valid": true,
  "audit_id": "cc98e6f9507d8f2f27d1a95f26b58e0a4c3f48cae77b308a80d6309528491dab",
  "issued_to": "auditor-1",
  "org": "Acme Labs",
  "period": "2026-Q4"
}
```
```
## Treasury solvency (unlinkable)
- Claim: treasury solvency >= 10000000000000 (hidden among 8 on-chain outputs)
- Hidden among: 8 real on-chain outputs — which one is the treasury is not revealed
- As of height: 40 — proves an output *held* this at that height; it is NOT a proof
  the treasury is currently unspent (that would require revealing its key image).
```

## 3. The failures get caught (what makes it real, not a toy)
All four were exercised in the live run; each rejected with `accepted:false` and a
non-zero exit (the over-threshold case fails at *build* time, so no package is ever
written):

| Case | How | Live result |
|---|---|---|
| Wrong issuer key | `verify … --issuer <other-org-pubkey> --auditor auditor-1` | `accepted:false signature_valid:false`, exit 1 |
| Wrong audience (replay) | `verify … --issuer <org-pubkey> --auditor auditor-2` | `accepted:false signature_valid:false`, exit 1 |
| Tampered package | `sed 's/Acme Labs/Acme Labz/'` then `verify …` | `accepted:false signature_valid:false`, exit 1 |
| Over the real balance | `build … --threshold 100000000000000` (100 CYNC) | build errors `cannot prove threshold …: treasury UTXO has only 49999200004499 atomic`, no package written |

Note every rejection still reports `anchored_valid:true` — the anonymity-set
members are genuinely on-chain; it is the **signature/audience binding** that
fails, which is the correct and separable reason.

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
- **The auditor's node must also be a `sketch-gk-proof` build.** The unlinkable
  item rides a `#[cfg(feature = "sketch-gk-proof")]` field on `AuditPackage`. A
  node built *without* the feature silently drops that field on deserialize (serde
  ignores unknown fields) and then recomputes the signature over a package missing
  it — so it reports `signature_valid:false`. This run hit exactly that with a
  `testnet`-only node and only passed once the node was rebuilt with the feature.
  It fails **closed** (a non-gk node never *wrongly accepts*), but the reason is
  misleading. Hardening follow-up: a non-gk node should reject a gk-bearing package
  with an explicit "this node cannot interpret this package" error rather than a
  bare signature failure.
