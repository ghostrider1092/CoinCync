# CIP-Cross-Chain-Onramp — a private turnstile INTO the Spark pool

Status: **DRAFT / design (scaffold only).** Testnet-only when built, gated,
fail-closed, externally reviewed. **Sequenced AFTER the shielded (Spark) external
audit** — nothing here goes to mainnet, or even gets a real implementation,
before that gate (see [[coincync-strategy-narrow-shielded]]).

## Motivation

The strategic north star is *one* genuinely sound, audited Spark shielded pool
with a **private cross-chain on-ramp**. The on-ramp is the differentiator: let a
holder of an external asset move value **into** CoinCync's shielded pool and
transact privately, without CoinCync running a second privacy engine.

The crypto here is **established, not novel** (Confidential Assets, the Zcash
turnstile, Aztec/Railgun deposits). The only novelty is the *architecture*, and
novelty is a liability (more to audit), so this design stays deliberately
conservative.

## Non-goals (anti-sprawl guardrails)

Scope sprawl is the biggest named risk. This CIP is a **one-way on-ramp**, not a
bridge, and explicitly is NOT:

- A two-way general bridge. Peg-**out** (burn shielded → release external) is a
  separate, later CIP; this one delivers peg-**in** only.
- Running foreign privacy engines (RingCT+Spark+MW as co-equals) — the MASP
  lesson is *homogenize into one scheme*. Incoming value is converted to a
  native Spark coin at the turnstile; nothing foreign lives in consensus.
- Anything on mainnet, or any real (non-scaffold) implementation, before the
  Spark audit passes.
- A trustless bridge on day one. The trust model is stated plainly (below) and
  decentralized in phases, not hand-waved.

## Mechanism (peg-in → shielded mint)

```
  [source chain]            [attestation]                 [CoinCync]
  lock/burn asset  ──►  proof the lock happened  ──►  mint 1:1 Spark coin
   to peg address        (see trust models)            into the pool
```

1. A user locks (or burns) an external asset to the peg's controlled address on
   the source chain, tagging it with the recipient's CoinCync Spark address.
2. An **attestation** that the lock is final is produced (trust model below).
3. CoinCync mints a shielded coin of the pegged value **into the Spark pool**,
   addressed to the recipient — reusing the existing authenticated mint bundle
   and the transparent↔shielded **value bridge** (`spark_payload`), except the
   backing is the *attested external lock* instead of a transparent CoinCync
   input. The recipient then holds an ordinary Spark note (scan/spend/transfer
   as usual — the whole shielded wallet already works).

The peg-in mint is therefore a **new kind of `value_balance < 0` shield-in**
whose backing is an attestation, not local transparent value. That backing
authority is the crux and is what the trust model secures.

## Trust models (surveyed; pick the minimal safe start)

| Model | Trust assumption | Notes |
|---|---|---|
| **A. Federated threshold custodian** | t-of-n signers custody the locked asset + sign attestations | Simplest; honest-majority of a known set. **Recommended testnet start.** |
| B. Bonded relayer | relayer posts collateral slashed on a fraudulent attestation | Reduces trust to economics; needs a fraud-proof + dispute window |
| C. Source-chain light client | consensus verifies an SPV/light-client proof of the lock | Strongest (near-trustless) but heavy: a verifier per source chain = real audit surface |
| D. HTLC atomic swap | hash-timelock, no custody | Trustless but not an *on-ramp into the shielded pool* — it's a swap; kept for completeness |

Recommendation: **start at A** (federated threshold peg) for testnet, with the
attestation format and the consensus mint-authorization seam designed so B then
C can replace the signer set **without a consensus format change**. Decentralize
the trust in phases; do not pretend day-one trustlessness.

## Consensus integration points

- **Mint authorization.** A pegged-in mint must carry a valid `PegAttestation`
  (threshold signature / bonded claim / light-client proof, per model) over
  `(source_chain_id, source_lock_id, amount, recipient, coincync_anchor)`. The
  block validator checks it against the active peg authority (a committed signer
  set / bonded set / light-client state) before admitting the mint. Producer and
  validator share one rule (a shared rail), like every other consensus quantity.
- **Peg solvency invariant.** Σ minted-per-peg ≤ Σ attested-locked; enforced
  cumulatively so the pool can never mint more than is backed. Mirrors the
  shielded pool-value turnstile that already refuses to go negative.
- **Replay / double-mint.** Each `source_lock_id` mints at most once — a spent
  set keyed by lock id (like nullifiers), reorg-consistent (`Phase2Store`-style
  checkpoint/rewind).
- **Cross-chain reorgs.** The attestation must reference a source-chain
  finality depth; a source reorg deeper than that is out of scope for the peg
  (documented risk, chosen conservatively).
- **Peg-authority governance.** The active signer/bonded/light-client set is
  committed state, rotated by a defined process — itself audit-critical.

## Scaffold (this change)

A gated, **fail-closed, inert** seam only — no real peg logic, no mint path
wired — so the architecture can be reviewed and the interfaces frozen ahead of
the post-audit implementation. See `src/consensus/crosschain_onramp.rs`
(`feature = "crosschain-onramp"`, off by default): the `PegAttestation` type, the
`PegAttestor` trait (verify an attestation → an authorized peg-in), and a
`FailClosedAttestor` production default that rejects everything. Nothing calls
it; it compiles out of default builds.

## Safety / open questions

- Peg-authority compromise = mint-from-nothing. Threshold + bond + eventual
  light client mitigate; the honest trust statement is mandatory.
- Solvency + replay + reorg invariants must be proven, not asserted.
- Interaction with the shielded pool-value accounting and emission/supply
  invariant (a pegged coin is not PoW emission — it is externally backed value,
  and the supply accounting must distinguish the two).
- The peg address custody + rotation on the source chain is operational
  security outside consensus but essential.

## Status / sequence

Design + inert scaffold only. If pursued: **only after the Spark audit** →
prototype model A on testnet behind the feature → peg solvency/replay/reorg
proofs + tests → dedicated external review of the on-ramp → decentralize trust
(A→B→C) → propose activation. Finish and harden the pool first; open this next.
