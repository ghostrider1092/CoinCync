<!-- markdownlint-disable MD036 MD013 -->
# `cyncswap` ↔ Farcaster / Comit Alignment Plan

**Purpose:** This document specifies how `coincync-swap` aligns with the two production-tested reference implementations of cross-curve atomic swaps — [Farcaster](https://github.com/farcaster-project/farcaster-node) and [Comit](https://github.com/comit-network/xmr-btc-swap) — so that the audit firm can review `cyncswap` as a *diff* against known-audited prior art rather than as a *new* design.

**Audience:** Audit firm engagement leads + `coincync-swap` maintainers.

**Status:** Draft (2026-05-18). Companion to [cyncswap-audit-prep.md](cyncswap-audit-prep.md) and [CIP-001](cip/CIP-001-atomic-swap.md).

**Why this document exists:** Farcaster and Comit collectively represent ~3 years of production cross-curve adaptor-signature swap experience, with prior third-party audits (Comit was reviewed by Kudelski Security in 2021) and ongoing academic scrutiny (Tairi et al., Malavolta et al.). Maximally reusing their patterns + test vectors converts our audit from "review a new design" to "verify the deltas against known-good designs," which is meaningfully cheaper and lower-risk.

---

## 0. What's Already Aligned

`coincync-swap` was implemented with the Comit/Farcaster constructions as the reference. As of the 2026-05-17 implementation slice, the cryptographic primitives match the Comit/Farcaster construction family directly:

| Primitive | `coincync-swap` location | Reference | Notes |
| --- | --- | --- | --- |
| BTC-side adaptor | [`adaptor.rs`](../crates/coincync-swap/src/adaptor.rs) (BIP-340 Schnorr) | Comit + Farcaster | Identical construction |
| CYNC-side adaptor | [`adaptor.rs`](../crates/coincync-swap/src/adaptor.rs) (Schnorr over Ristretto255) | Farcaster (ed25519 / Monero CryptoNote variant) | Same family; **Ristretto255 is the cleaner prime-order sibling of ed25519** — no cofactor issues. Comit/Farcaster use Monero-flavored ed25519 because Monero's chain demands it; CYNC's design lets us use the strictly stronger Ristretto255. |
| Cross-curve DLEQ (default) | [`adaptor.rs`](../crates/coincync-swap/src/adaptor.rs) (Maxwell-Poelstra) | Comit | Identical construction |
| Cross-curve DLEQ (strict) | [`strict_dleq.rs`](../crates/coincync-swap/src/strict_dleq.rs) (Noether 2018) | Neither (audit-only hardening) | Stricter than the reference impls; feature-flagged |
| BTC chain integration | [`btc.rs`](../crates/coincync-swap/src/btc.rs) (`bitcoin = 0.32`, `secp256k1 = 0.29`) | Comit (similar versions) | Aligned |
| Curve25519 primitives | `curve25519-dalek = 4.1` | Same crate, same major version | Aligned |
| Noise transport | [`coordinator.rs`](../crates/coincync-swap/src/coordinator.rs) (`snow = 0.9`, Noise XX pattern) | Comit / Farcaster | Aligned (cipher suite: `Noise_XX_25519_ChaChaPoly_BLAKE2s`) |
| State persistence | [`state.rs`](../crates/coincync-swap/src/state.rs) (JSON + HMAC-SHA256 sidecar) | JSON only | Stronger than the reference impls (HMAC closes the [`CYNC-AUDIT-2026-05-17-state-file-hmac.md`](../audit-suite/findings/CYNC-AUDIT-2026-05-17-state-file-hmac.md) finding) |

**Conclusion:** The primitive choices and construction family are already aligned. The remaining alignment work is verification (test vectors), nomenclature (message names auditors recognize), and documentation (citation to prior audit precedent).

---

## 1. The 5-Step Alignment Plan

Each step is independent and can be done in any order. Total effort estimate: ~2 weeks of focused work.

### Step 1 — Import test vectors from Farcaster + Comit, verbatim

**What:** Add `crates/coincync-swap/test-vectors/comit/` and `crates/coincync-swap/test-vectors/farcaster/` directories. Each contains JSON dumps of the reference implementations' test inputs and expected outputs.

**Why:** Converts our correctness claim from "we believe our implementation is correct" to "our implementation produces bit-for-bit identical outputs to two independent reference implementations." That's the single highest-leverage change in the alignment effort — it sandwich-audits us between two known-good codebases.

**How:**

1. From the Comit repo, capture every test vector under `xmr-btc-swap/swap/src/protocol/**/test_vectors.rs` (or wherever they live in the current revision). Dump as JSON for portability.
2. From Farcaster, capture vectors under `farcaster-core/tests/vectors/`. Same approach.
3. Write a CI test that runs each vector through our primitive implementations and `assert_eq!`s the bytes.
4. **Fail the build** on any mismatch. No "approximately equal" — bit-for-bit or fail.

**Files to create:**

- `crates/coincync-swap/test-vectors/comit/README.md` — provenance (git SHA of the source revision, date of import, license attribution)
- `crates/coincync-swap/test-vectors/comit/btc-adaptor.json`
- `crates/coincync-swap/test-vectors/comit/dleq-cross-curve.json`
- `crates/coincync-swap/test-vectors/farcaster/btc-adaptor.json`
- `crates/coincync-swap/test-vectors/farcaster/ed25519-adaptor.json` (or Ristretto if Farcaster has Ristretto variants)
- `crates/coincync-swap/tests/external_vectors.rs` — test harness that loads + runs every vector

**Effort:** ~1 day. Mostly mechanical.

**Audit impact:** Auditor's first sanity check becomes "do they pass the prior-art vectors?" — a yes/no answer in 5 seconds instead of a multi-hour primitive review.

---

### Step 2 — Match protocol message names to Farcaster's vocabulary

**What:** Rename our `coordinator.rs` message types to match Farcaster's protocol naming. Pure rename; zero behavior change.

**Why:** Auditors fluent in Farcaster's wire protocol can read our `coordinator.rs` and immediately recognize the protocol flow without learning new vocabulary. Reduces audit hours; reduces miscommunication risk.

**Farcaster's protocol-message vocabulary (approximate; verify against current Farcaster revision before applying):**

| Farcaster name | Role |
| --- | --- |
| `RevealAliceParameters` | Alice publishes her public parameters + adaptor commitment |
| `RevealBobParameters` | Bob publishes his public parameters + adaptor commitment |
| `CoreArbitratingSetup` | Both sides agree on the core swap parameters (amounts, timeouts, fees) |
| `RefundProcedureSignatures` | Pre-signed refund signatures exchanged for safety |
| `BuyProcedureSignature` | The signature that, when revealed, unlocks the accordion |
| `Abort` / `Refund` / `Punish` | Terminal states |

**How:**

1. Read Farcaster's current `farcaster-core/src/protocol/message.rs` (or wherever the message types live in the latest revision).
2. Rename our coordinator message types to match. Update all consumers, tests, serialized formats.
3. Document the mapping in this file's §5 ("Nomenclature Map") for posterity.
4. **Do not change wire format byte-for-byte to match Farcaster** — that's Step 3, and is optional. Step 2 is rename only.

**Effort:** ~1 week. Mostly find-and-replace plus updating tests + serialized format if any.

**Audit impact:** Auditor familiar with Farcaster recognizes the protocol shape in our code without prior `coincync-swap`-specific context. Time-to-first-confidence reduced from ~hours to ~minutes.

---

### Step 3 — Add a `farcaster-compat` cargo feature

**What:** Behind a non-default feature flag, expose our adaptor primitive types as implementing whichever Farcaster traits they can. Allows Farcaster's audit-cleared code paths to be used in our test suite for differential validation.

**Why:** Beyond passing the same test vectors (Step 1), this lets you write a test like *"for any input, our DLEQ implementation produces output identical to Farcaster's DLEQ implementation"* — a fuzz-style property check across the full input space, not just the curated vectors.

**How:**

1. Add `farcaster-compat = ["dep:farcaster-core"]` to `[features]` in `coincync-swap/Cargo.toml`.
2. Behind `#[cfg(feature = "farcaster-compat")]`, add impl blocks that wrap our types in Farcaster's traits where the type signatures match.
3. Add a property test in `crates/coincync-swap/tests/farcaster_differential.rs` that calls both implementations on the same inputs and asserts equality.

**Caveat:** Farcaster's traits may have changed across releases. Pin to a known-good Farcaster release tag and document it. Don't track `main`.

**Effort:** ~2-3 days, including pinning + property test scaffolding.

**Audit impact:** Auditor sees a `cargo test --features farcaster-compat` that passes against a published reference impl — converts our correctness story from "self-attested" to "co-attested with audited prior art." High signal-to-effort ratio.

---

### Step 4 — Document precise primitive choices with paper citations

**What:** Append a §"Primitive Citations" to [`cyncswap-audit-prep.md`](cyncswap-audit-prep.md) (or this doc — your call) that cites, for each cryptographic primitive in `coincync-swap`:

- The originating academic paper (with DOI / arXiv link)
- The relevant section + page number for the construction
- The Comit/Farcaster source file (with permalink + git SHA) where the same construction is implemented
- Our source file (with permalink) where we implement it

**Why:** Auditors check the math against the paper, then check our code against both the paper *and* the reference impl. Having the chain of evidence pre-walked saves them ~10-20 hours of bibliographic detective work.

**Example entry:**

```markdown
### BIP-340 Schnorr Adaptor Signatures

**Paper:** Pieter Wuille, Jonas Nick, Tim Ruffing, "BIP 340: Schnorr Signatures
for secp256k1." Bitcoin Improvement Proposal 340, §"Adaptor Signatures."

**Comit reference impl:** `xmr-btc-swap/swap/src/bitcoin/wallet.rs:adaptor_sign()`
(git SHA: `<paste>`, file URL: `<paste>`)

**Farcaster reference impl:** `farcaster-core/src/blockchain/bitcoin/adaptor.rs`
(git SHA: `<paste>`, file URL: `<paste>`)

**Our impl:** [`coincync-swap/src/adaptor.rs`](../crates/coincync-swap/src/adaptor.rs)
`btc::create_adaptor_signature()` (lines ~120–200 as of 2026-05-18)

**Construction match:** Identical (same nonce derivation, same challenge,
same encryption step).

**Test-vector coverage:** `tests/external_vectors.rs` runs both Comit's and
Farcaster's BIP-340 adaptor vectors through our implementation; build fails
on any byte-level mismatch.
```

Do this for each of: BIP-340 Schnorr adaptor (BTC), Schnorr adaptor over Ristretto255 (CYNC), Maxwell-Poelstra DLEQ (default cross-curve binding), Noether 2018 strict DLEQ (audit-hardened option), HMAC-SHA256 state integrity, Noise XX coordinator transport.

**Effort:** ~2-3 days of focused citation work.

**Audit impact:** This is the document the audit firm will read *first*. Done well, it eliminates the "where does this construction come from?" question entirely.

---

### Step 5 — Cite the audit precedent in `cyncswap-audit-prep.md`

**What:** Add a §"Prior-Art Audit Precedent" to [`cyncswap-audit-prep.md`](cyncswap-audit-prep.md) listing the prior third-party audits of Comit and Farcaster (and any peer-reviewed academic work), with a brief note on what each found and how it applies to `coincync-swap`.

**Why:** Audit firms scope based on perceived risk. A firm seeing "this design has been audited twice before, here are the findings, here's how we addressed each" scopes for fewer hours than one seeing "novel design, full review needed."

**Known prior-art audits to cite:**

| Audit | Project | Year | Scope | Public report |
| --- | --- | --- | --- | --- |
| Kudelski Security | Comit (`xmr-btc-swap`) | 2021 | Full crypto + protocol review | (find + link) |
| Various peer reviews | Farcaster `farcaster-core` | 2021–2024 | Cryptographic construction reviews | (find + link) |
| Academic | Malavolta et al., "Anonymous Multi-Hop Locks" | 2019 | Underlying construction paper | doi:10.14722/ndss.2019.23330 |
| Academic | Tairi et al., "A² L: Anonymous Atomic Locks for Scalability in Payment Channel Hubs" | 2021 | Cross-curve DLEQ formalization | doi:10.1109/SP40001.2021.00111 |

For each, document:

1. What the audit/paper found (vulnerabilities, design issues, missing properties).
2. Whether the finding applies to `coincync-swap` (because the same construction is used).
3. How we addressed it (citation to source-file lines or test).

**Effort:** ~2 days of research + writing.

**Audit impact:** Sets audit-firm expectations toward "differential review" pricing, not "full new design review" pricing.

---

## 2. What This Buys You

| Dimension | Before alignment | After alignment |
| --- | --- | --- |
| Auditor's mental model | "New cross-curve swap design" | "Cyncswap = Comit + Farcaster + (Ristretto255 + Noether strict DLEQ + HMAC state) deltas" |
| Test-vector coverage | Internal vectors only | Internal + Comit + Farcaster reference vectors |
| Test-vector enforcement | Manual review | CI fails on bit-level mismatch |
| Audit precedent reuse | None | Kudelski 2021 (Comit) + academic peer review (Farcaster) |
| Differential validation | None | `cargo test --features farcaster-compat` cross-checks against Farcaster on every commit |
| Time-to-first-confidence for incoming auditor | Hours | Minutes |
| Estimated audit cost | ~$80–150k (new design review) | ~$40–80k (differential review) |
| Estimated audit duration | 8–12 weeks | 4–6 weeks |
| Reviewer pool | Few specialists who can audit novel cross-curve swap crypto | Many more, including reviewers who've already done Comit/Farcaster work |

The audit-cost halving alone justifies the ~2-week alignment effort by a factor of ~20×.

---

## 3. What Alignment Does *Not* Buy You

To be explicit about the limits:

1. **Alignment does not eliminate the audit.** The two unavoidable principal-loss vectors (DLEQ proof bug, adaptor binding bug) still require professional review. Alignment makes the review *cheaper and faster*, not unnecessary.

2. **Alignment does not guarantee bit-level interoperability with Comit or Farcaster wire protocols.** Their wire formats include Monero-specific fields we don't have (CYNC ≠ Monero at the chain layer). The cryptographic *core* is interoperable; the *full protocol* is not. A user with a Comit wallet cannot trade against a `coincync-swap` peer.

3. **Alignment does not freeze our protocol.** If a future research advance enables a strictly better construction (e.g., a successor to Maxwell-Poelstra with provably smaller proof size), we can adopt it — but that's a protocol upgrade with its own review cycle, not free.

4. **Alignment does not cover non-crypto correctness.** State machine, RPC integration, refund construction, wallet UX — these are `coincync-swap` originals and need independent audit attention regardless of alignment with reference impls' crypto.

---

## 4. Constitutional Considerations

Aligning with Comit/Farcaster is consistent with the Constitution:

- **Article XI — No Algorithmic Capture:** Reuse of audited primitives is the opposite of capture — it explicitly defers to peer-reviewed prior art rather than inventing novel primitives.
- **Article XIII — No External Trust:** We import test vectors and citations, not running code or trusted-execution dependencies. The audit-precedent reuse is bibliographic, not operational. Our binary depends on nobody else's runtime.
- **Article XV — Spirit and Construction:** Implementing what's already proven, with cited departures (Ristretto255, Noether strict DLEQ, HMAC state integrity) only where strictly stronger, is the conservative design discipline the Constitution asks for.

No constitutional friction. This is the discipline working as designed.

---

## 5. Nomenclature Map (to be filled in during Step 2)

This table is the bridge between our current internal protocol names and Farcaster's vocabulary. To be filled in as Step 2 lands.

| `coincync-swap` current name | Farcaster equivalent | Notes |
| --- | --- | --- |
| _TBD_ | `RevealAliceParameters` | |
| _TBD_ | `RevealBobParameters` | |
| _TBD_ | `CoreArbitratingSetup` | |
| _TBD_ | `RefundProcedureSignatures` | |
| _TBD_ | `BuyProcedureSignature` | |
| _TBD_ | `Abort` / `Refund` / `Punish` | |

---

## 6. Acceptance Criteria

The alignment work is considered complete when **all** of the following hold:

1. `crates/coincync-swap/test-vectors/comit/` and `farcaster/` directories exist and contain ≥10 distinct test vectors each, with provenance README documenting source SHA and import date.
2. `cargo test` runs all external vectors as part of the default test suite. CI fails on any mismatch.
3. All `coordinator.rs` message types are renamed to Farcaster's vocabulary; nomenclature map in §5 fully populated.
4. `cargo build --features farcaster-compat && cargo test --features farcaster-compat` succeeds and runs ≥1 property-style differential test asserting our impl ≡ Farcaster's impl.
5. `docs/cyncswap-audit-prep.md` has a §"Primitive Citations" section covering all six cryptographic primitives with paper + Comit/Farcaster + our source citations.
6. `docs/cyncswap-audit-prep.md` has a §"Prior-Art Audit Precedent" listing ≥2 prior audits / peer reviews + their relevance to `coincync-swap`.

Sign-off: when each item above is checked, this document is updated to status "Implemented" and the audit firm engagement letter explicitly cites this alignment as the basis for differential-review scoping.

---

## 7. Sequencing Recommendation

Steps 1, 4, and 5 are **purely additive** — they don't touch existing code. Do them first; they unlock the audit-engagement conversation without risk to in-flight work.

Steps 2 and 3 **modify existing code** (renames + new feature flag). Do them after Steps 1/4/5 are done so the audit-prep doc is already in good shape if a conversation with the audit firm starts mid-alignment.

Suggested order:

1. **Step 4** (Primitive Citations) — 2-3 days, no code changes, immediately useful for audit-firm conversations
2. **Step 5** (Prior-Art Audit Precedent) — 2 days, no code changes, completes the audit-prep narrative
3. **Step 1** (Import test vectors) — 1 day, additive code, CI-enforced
4. **Step 3** (`farcaster-compat` feature) — 2-3 days, additive code, no existing-test changes
5. **Step 2** (Rename messages) — 1 week, touches existing code, do last to minimize churn risk

Total wall-clock: ~2-3 weeks at full focus, ~4-6 weeks at part-time (which is more realistic given competing demands).

---

## 8. Changelog

- **2026-05-18** — Document created. Captures the alignment plan agreed in CIP-002 V1 design discussion; companion to [cyncswap-audit-prep.md](cyncswap-audit-prep.md). Status: Draft; acceptance criteria specified; sequencing recommended; alignment not yet started.

---

*This document is a plan, not a commitment. The 2-3-week alignment effort is the recommended path to halving cyncswap's audit cost; declining to do it does not block mainnet, but does roughly double the expected audit budget. Decision-makers should consider the alignment as a leverage investment, not a hard requirement.*
