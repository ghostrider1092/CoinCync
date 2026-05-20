<!-- markdownlint-disable MD036 MD013 -->
# CoinCync `cyncswap` — Audit Submission Packet

**Audit perimeter:** the `coincync-swap` crate (CYNC ↔ BTC atomic-swap implementation, CIP-001).
**Submission date:** 2026-05-20.
**Commit SHA at submission:** `f08965f` *(this document is regenerated on every audit-relevant push; the live SHA at the time of audit start is the one the operator passes you via `git rev-parse HEAD` per [§9 of the audit-prep doc](cyncswap-audit-prep.md#9-auditor-required-out-of-band-materials)).*

---

## 1. What this document is

This is the **front door** for the audit. It is short on purpose. Three documents follow it, in increasing depth:

| Document | Purpose | Read it for |
| --- | --- | --- |
| **[cyncswap-audit-prep.md](cyncswap-audit-prep.md)** | The wayfinding doc | "Where does X live in the code, what tests exercise it, what's a known gap?" — 12 sections, 280+ lines. |
| **[cip/CIP-001-atomic-swap.md](cip/CIP-001-atomic-swap.md)** | The protocol spec | "Why is the protocol shaped this way, what's the design rationale?" |
| **[atomic-swap-clsag-adaptor-design.md](atomic-swap-clsag-adaptor-design.md)** | The cryptographic correction note | "What are the highest-risk cryptographic surfaces, prioritized?" |

The audit-prep doc (line 1) points at this submission packet; this packet points at the audit-prep doc. Two-way wayfinding so an auditor opening either file lands where they need to be.

---

## 2. Scope

**In scope:** the `coincync-swap` workspace crate. ~16,500 LOC across implementation + tests. Source-of-truth perimeter table is [§0 of the audit-prep doc](cyncswap-audit-prep.md#0-scope).

**Highest-risk surfaces** (start here for the cryptographic review):

1. **CDLP scalar-order bound** — `strict_dleq.rs::STRICT_BIT_COUNT` + `decompose_to_bits`. An off-by-one or missing range constraint is a fund-loss bug.
2. **CDLP soundness over Ristretto255** — `strict_dleq.rs::prove_bit_pair` + `verify_bit_pair` + `verify_linear_combination_{btc,cync}`. Adapted (not copied) from the original secp256k1↔Ed25519 construction — independent proof required.
3. **BIP-340 adaptor completeness + extractability** — `adaptor.rs::create_pre_sig_bip340`, `decrypt_btc_adaptor`, `recover_secret_from_btc_sig`.

Full nine-item priority table at [§5 of the audit-prep doc](cyncswap-audit-prep.md#5-primary-review-targets-prioritized).

**Explicitly out of scope:**

- The wider `coincync` library (consensus, P2P, storage) — audit-scoped separately as the v1.0 mainnet audit.
- The Tauri wallet UI.
- The reference Bitcoin Core and `coincync-node` daemons.
- Tor / SOCKS5 proxy software.

---

## 3. Build + reproduce

```bash
# Clone + check out the audited commit.
git clone https://github.com/ghostrider1092/Coincync-Testnet-.git
cd Coincync-Testnet-
git checkout <commit-sha>   # from §9 out-of-band materials

# Default-feature build + test.
cargo build -p coincync-swap
cargo test  -p coincync-swap                       # expect: 192+ tests pass

# Strict-DLEQ (Noether 2018 cryptographic-level same-secret-cross-curve).
cargo build -p coincync-swap --features strict-dleq
cargo test  -p coincync-swap --features strict-dleq # expect: 254+ tests pass

# Workspace-wide sweep.
cargo test --workspace --exclude coincync                                 # 288+
cargo test --workspace --exclude coincync --features coincync-swap/strict-dleq  # 350+
```

If any of these counts differ from this document, the audit baseline has shifted — re-derive the commit + the counts before proceeding. The audit-prep doc [§10](cyncswap-audit-prep.md#10-build--test-reproducibility) carries the up-to-date expected counts plus the reproducibility-vector regeneration recipe.

**One-shot smoke verification:** `bash scripts/cyncswap-audit-smoke.sh` runs every check above in one pass (test counts vs the docs, reproducibility-vector bit-equality, property-test execution, Cargo.lock presence) and exits non-zero on any drift. Auditor should run this immediately after `git clone` to verify the perimeter state matches what this packet claims, before opening any source files.

---

## 4. Test-evidence summary

The four legs of the test stool:

| Leg | What it proves | Where |
| --- | --- | --- |
| **Property tests** | Random valid inputs satisfy declared invariants | [tests/property_invariants.rs](../crates/coincync-swap/tests/property_invariants.rs), [property_invariants_cync.rs](../crates/coincync-swap/tests/property_invariants_cync.rs), [state_machine_invariants.rs](../crates/coincync-swap/tests/state_machine_invariants.rs) |
| **Fuzz** | No random adversarial input crashes the parser | [fuzz/](../fuzz/) — 27 targets, per-commit CI on 5 attacker-reachable surfaces, manual overnight runner covers all 27 |
| **External vectors** | Outputs reproduce byte-for-byte against published expected values | [tests/external_vectors.rs](../crates/coincync-swap/tests/external_vectors.rs) walks [test-vectors/{reproducibility,comit,farcaster}/](../crates/coincync-swap/test-vectors/) — 12 in-house deterministic vectors shipped, vendor vectors pending license review |
| **Mutation testing** | Test suite catches single-line code mutations | Score: **100.0%** (340 caught / 0 missed) across the four crypto-critical files (`strict_dleq.rs`, `adaptor.rs`, `cync.rs`, `btc.rs`). `adaptor.rs` was 95/95 caught at baseline. See [§11.4 of the audit-prep doc](cyncswap-audit-prep.md#114-mutation-testing) for methodology. |
| **Line coverage** | Source lines exercised by tests | **~97% average** across the four crypto-critical files (range 96.72% – 99.07%). Per-file report at [docs/cyncswap-coverage-2026-05-20.md](cyncswap-coverage-2026-05-20.md). |

Mutation score is the empirical answer to "do your tests actually exercise the crypto, or just call it?" 100% across the four crypto-critical files means every operator, constant, return, and match arm in the audit perimeter has at least one test that fails when it's mutated.

---

## 5. Known gaps (declared, not hidden)

[§8 of the audit-prep doc](cyncswap-audit-prep.md#8-test-coverage-gaps-knowingly-missing) is the authoritative gap list. In summary:

- **Live dual-testnet smoke** is operator-driven, not automated in CI.
- **Joint-key full-CLSAG round-trip** is deferred to wallet integration.
- ~~**Published strict-DLEQ benchmark numbers**~~ — **Closed 2026-05-20** via criterion at [benches/strict_dleq.rs](../crates/coincync-swap/benches/strict_dleq.rs). Measured: `prove` ≈ 133 ms / `verify` ≈ 172 ms median (modern x86 desktop, release mode, 100-sample criterion runs). Re-runnable via `cargo bench -p coincync-swap --features strict-dleq`.
- **Comit / Farcaster vendor vectors** — scaffolds + replay harness shipped; vector import deferred pending license review of the upstream `xmr-btc-swap` and `farcaster-rs` test-vector files specifically.

---

## 6. Operator-supplied out-of-band materials

The operator running the audit will provide (per [§9 of the audit-prep doc](cyncswap-audit-prep.md#9-auditor-required-out-of-band-materials)):

| Material | Form |
| --- | --- |
| Commit SHA being audited | `git rev-parse HEAD` |
| List of any local patches not yet pushed | `git log <upstream-base>..HEAD --oneline` |
| Cargo lock-file hash per feature mode | `sha256sum Cargo.lock` |
| Operator-managed Noise XX static-key fingerprints | hex-encoded 32 bytes per party |
| Tor `.onion` hostname format the operator plans to publish | v3 only |
| Threat-model exclusions | Free-text |

---

## 7. License + IP boundary

CoinCync is **MIT**. The COMIT `xmr-btc-swap` reference implementation is **GPL-3.0**. **No COMIT source has been read by implementers nor copied into the codebase.** The CYNC-side adaptor design is a clean-room derivation from public papers (Noether 2018, Farcaster spec, Poelstra's "Scriptless Scripts" notes), not from COMIT's source. See [audit-prep doc §1](cyncswap-audit-prep.md#1-license--ip-boundary) and the [design note §2](atomic-swap-clsag-adaptor-design.md) for the full statement.

---

## 8. Contact + scope changes

Discrepancies between this document and the code should be resolved **in favor of the code**. If you find something this packet missed, point at the file:line and the operator will update both this packet and the audit-prep doc.

---

*Submission packet only. Source-of-truth for design decisions is [CIP-001](cip/CIP-001-atomic-swap.md) and its changelog. Source-of-truth for the cryptographic correction is [atomic-swap-clsag-adaptor-design.md](atomic-swap-clsag-adaptor-design.md). Source-of-truth for the audit perimeter is [cyncswap-audit-prep.md](cyncswap-audit-prep.md).*
