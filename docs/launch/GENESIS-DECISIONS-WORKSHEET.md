<!-- markdownlint-disable MD013 MD036 -->
# Genesis Decisions Worksheet

**Purpose:** 5 questions that need YOUR answer to unblock the genesis ceremony. Each has my recommended default — accept by leaving blank, or write your override below the question. Sign + date at the bottom when done.

Pairs with [GENESIS-CEREMONY-PLAN.md](GENESIS-CEREMONY-PLAN.md) which has the full timeline. This worksheet just zooms in on the choices.

---

## 1. Genesis coinbase recipient

The genesis block mints ~50 CYNC. Where does it go?

| Option | What it signals | Cypherpunk read |
|---|---|---|
| **A. Burn (`0x000...000` or provably-unspendable address)** | "No founder allocation, not even at genesis" | Strongest non-premine signal. Pure |
| **B. Open-source-cryptography charity** (Tor Project, EFF, Free Software Foundation, OpenBSD Foundation) | "Honoring the shoulders we stand on" | Strong, defensible. Public-record gift |
| **C. Maintainer address** | "I built this, I get the first 50" | Weakest — undermines Constitution Article XII non-allocation posture |
| **D. Distributed across early testnet operators (e.g., split 9 ways)** | "The testnet community gets the genesis reward" | Works only if you can prove who they are |

**Recommended default:** **A (burn)** — strongest constitutional posture; defensible to any critic; doesn't require choosing a charity or naming individuals at genesis.

**Your decision (write below or leave blank to accept default):**

```
Decision: A — burn to provably-unspendable address (0x000...000)
If B, charity: n/a
If C, address: n/a
If D, addresses (9): n/a
Rationale (one sentence): Strongest non-premine signal; aligns with Constitution Article XII;
                         no requirement to choose a charity or name individuals at genesis.
```

---

## 2. Genesis block memo / OP_RETURN content

Convention since Bitcoin's genesis is to embed a contemporary headline from a non-crypto source as unforgeable timestamping. ~80 bytes available.

| Option | Example | Tone |
|---|---|---|
| **A. Current-events headline** | "FT 2026-09-30: Global financial-data leak exposes 2.3B retirement accounts" | Original Satoshi pattern — political event commentary |
| **B. Privacy-related event** | "EFF: 2026 saw the largest year of surveillance-tool funding in history" | Mission-aligned, narrower audience |
| **C. Mathematical / cryptographic constant** | "RFC 9180 HPKE base mode draft authors: Barnes/Bhargavan/Lipp/Wood" | Honors crypto research; less political |
| **D. CoinCync-specific** | "CoinCync genesis 2026-10-01 — 0 premine, 0 dev tax, 0 foundation" | Self-attesting; weaker as timestamping (no external anchor) |

**Recommended default:** **A (current-events headline)** — picked T-7 days based on the actual news. Mirrors Bitcoin's genesis pattern, which still resonates 17 years later.

**Your decision:**

```
Decision: A — current-events headline (Satoshi pattern)
Memo text (max 80 bytes, picked at T-7 if A): [TBD at T-7 / 2026-09-24]
```

---

## 3. Initial mainnet difficulty

Genesis-day difficulty determines whether anyone can mine block 1. Too high = chain dies on launch. Too low = first reorg before the first checkpoint.

| Option | Difficulty | First-hour outcome |
|---|---|---|
| **A. Match final testnet diff (1:1)** | ~latest testnet hashrate × 120s | Realistic but risky — depends on whether mainnet attracts more or fewer miners than testnet |
| **B. Final testnet diff × 0.5 (safety margin)** | half of A | Block 1 mined in ~60s instead of 120s. Difficulty re-adjusts within the first hour |
| **C. Final testnet diff × 0.25** | quarter of A | Block 1 mined fast (~30s). Lower-end safety net for "less mainnet hashrate than testnet" case |
| **D. Hardcoded MIN_DIFFICULTY (500)** | floor | Worst-case safety. Anyone with a laptop mines block 1 in seconds |

**Recommended default:** **B (× 0.5)** — gives a 2× safety margin against "fewer mainnet miners than testnet" without making early blocks trivially mineable. Initial difficulty adjusts upward fast via ASERT.

**Your decision:**

```
Decision: B — final testnet diff × 0.5
Specific number if not relative: derived at T-7 from latest testnet hashrate sample × 120s × 0.5
```

---

## 4. CIP-009.D production posture at genesis

This decision is pre-staged in [docs/decisions/2026-05-23-cip-009d-production-posture.md](../decisions/2026-05-23-cip-009d-production-posture.md). Two options: dormant (Layer 6 off, activate later via CIP-007) or active (Layer 6 on at genesis with signer set elected).

**Recommended default:** **A (dormant)** — tighter audit perimeter, no genesis signer-set bootstrap problem, Layer 5 hardcoded checkpoints adequate for first-month live-tip defense. Full reasoning in the decision doc.

**Your decision (signs the decision doc):**

```
Decision: A — dormant at genesis
Activation date if A: TBD post-mainnet via CIP-007 (no fixed block-height commitment)
Genesis signer set if B: n/a
Rationale (one sentence): Tighter audit perimeter at launch; Layer 5 hardcoded checkpoints
                         adequate for first-month live-tip defense; avoids genesis-day signer
                         bootstrap problem.
```

---

## 5. Genesis-day on-call commitment

Maintainer (you) needs to be available for incident response T-3 days through T+7 days. That's an 11-day window when you can't be on vacation, sick, or unreachable.

| Option | What it means |
|---|---|
| **A. Maintainer-only on-call** | You answer all alerts. Phone monitored. Limited but actually doable for solo dev |
| **B. Maintainer + 1-2 backup operators** | Identified testnet operators agree to monitor too. Better resilience |
| **C. Slip the launch** | If you can't commit Oct 1 ± 11 days, the launch slips. Stated in GENESIS-CEREMONY-PLAN.md abort criteria #7 |

**Recommended default:** **B if achievable, otherwise A** — solo on-call is feasible at this scale, but a 2-3-person rotation cuts your stress and the incident-response time.

**Your decision:**

```
Decision: B if achievable by T-30, otherwise A (maintainer-only)
If B, backup operators (names + contact): TBD — identify 1-2 testnet operators by T-30 (2026-09-01)
On-call window confirmed: 2026-09-28 through 2026-10-08
```

---

## Sign + date

```
Worksheet completed on: 2026-05-23
By: ghostrider1092 (maintainer) — recommended defaults adopted across all 5 questions
```

After signing, fold the chosen options into:

- `docs/launch/GENESIS-CEREMONY-PLAN.md` (update "Open questions for the maintainer" section)
- `docs/decisions/2026-05-23-cip-009d-production-posture.md` (sign the decision block)
- `src/constants.rs` (genesis-block coinbase + initial-difficulty constants — DO NOT commit until T-30 days, then critical-files lockfile re-hash)

---

## What this doesn't decide

These are the 5 hardest-to-defer questions, not the only ones. Things this worksheet does NOT cover:

- **Exchange listings.** Out of scope at v1.0.
- **Marketing tone.** The README + website have been speaking for the project; don't redesign for launch.
- **Tokenomics changes.** 100M cap + emission curve + 30%/50% fee burn are constitutional. Don't touch.
- **Specific monitoring alert thresholds.** Operational — set those during the T-14 day rehearsal.

If any of those start to feel like genesis-day decisions, push back — they're not.
