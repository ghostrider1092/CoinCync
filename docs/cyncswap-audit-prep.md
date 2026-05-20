<!-- markdownlint-disable MD036 MD013 -->
# `cyncswap` Audit Preparation

**Audience:** Audit firm scoping the CIP-001 atomic-swap implementation.
**Source-of-truth this document points at:** the `coincync-swap` crate
(~16,500 LOC across implementation + tests) at the commit identified
in §0. Updated 2026-05-18.

This file is **not** the spec. The spec is [CIP-001](cip/CIP-001-atomic-swap.md),
the cryptographic correction note is [atomic-swap-clsag-adaptor-design.md](atomic-swap-clsag-adaptor-design.md),
and the source-of-truth-for-design-decisions is the CIP-001 changelog +
the design note's §10 changelog. This document is the **wayfinding
layer**: it tells an incoming auditor which file holds what, which
tests exercise which property, and where the highest-risk surfaces
are.

---

## 0. Scope

**In scope** (the audit perimeter):

| Component | Path | LOC | Tests |
| --- | --- | --- | --- |
| Cryptographic primitives | [crates/coincync-swap/src/adaptor.rs](../crates/coincync-swap/src/adaptor.rs) | ~1,740 | covered in unit + e2e |
| BTC tx construction | [crates/coincync-swap/src/btc.rs](../crates/coincync-swap/src/btc.rs) | ~2,140 | covered in unit + e2e |
| CYNC swap key-derivation | [crates/coincync-swap/src/cync.rs](../crates/coincync-swap/src/cync.rs) | ~1,080 | covered in unit |
| Protocol state machine | [crates/coincync-swap/src/protocol.rs](../crates/coincync-swap/src/protocol.rs) | ~820 | covered in unit + integration |
| Strict-binding cross-curve DLEQ (Noether 2018) | [crates/coincync-swap/src/strict_dleq.rs](../crates/coincync-swap/src/strict_dleq.rs) | ~2,180 | 58 unit tests (feature-gated) |
| Coordinator (handshake + transport) | [crates/coincync-swap/src/coordinator.rs](../crates/coincync-swap/src/coordinator.rs) | ~3,490 | 24 unit + 1 integration |
| State persistence | [crates/coincync-swap/src/state.rs](../crates/coincync-swap/src/state.rs) | ~480 | covered in unit + integration |
| CLI binary | [crates/coincync-swap/src/bin/cyncswap.rs](../crates/coincync-swap/src/bin/cyncswap.rs) | ~3,240 | manual smoke + operator script |
| Integration e2e | [crates/coincync-swap/tests/swap_happy_path_e2e.rs](../crates/coincync-swap/tests/swap_happy_path_e2e.rs) | 737 | 3 cross-module composition tests |
| State-flow integration | [crates/coincync-swap/tests/integration_full_flow.rs](../crates/coincync-swap/tests/integration_full_flow.rs) | 410 | 10 state-machine integration tests |

**Test totals:**

- **Default features:** 288 tests across the workspace, 192 in `coincync-swap` alone (179 unit + 10 integration + 3 e2e).
- **`--features strict-dleq`:** 350 tests (adds 58 strict_dleq unit tests + 4 strict_dleq_vectors golden-file tests).
- **0 failures, 0 warnings in both modes.**

**Explicitly out of scope** for this audit:

- The wider `coincync` library (consensus, P2P, storage). Already audit-scoped separately as part of the v1.0 mainnet audit.
- The Tauri wallet UI. Audit when wallet integration of `SwapLockRecipient` lands.
- The reference Bitcoin Core / `coincync-node` daemons. Both are external to this crate; the audit assumes they behave per their own specs.
- Tor / SOCKS5 proxy software (`tor` itself). Out of scope; the crate assumes a working SOCKS5 proxy is provided by the operator.

---

## 1. License + IP boundary

CoinCync is **MIT**. The COMIT `xmr-btc-swap` reference implementation is **GPL-3.0**. **No COMIT source has been read by implementers nor copied into the codebase.** The CYNC-side adaptor design is a clean-room derivation from public papers (Noether 2018, Farcaster spec, Poelstra's "Scriptless Scripts" notes), not from COMIT's source. The auditor should verify this boundary holds — none of the patches that built `coincync-swap` cite COMIT source, only academic and spec references. See [atomic-swap-clsag-adaptor-design.md §2](atomic-swap-clsag-adaptor-design.md) for the full statement.

---

## 2. Cryptographic primitives map

| Primitive | Module | Function(s) | Notes |
| --- | --- | --- | --- |
| BIP-340 Schnorr adaptor signature | `adaptor.rs` | `create_pre_sig_bip340`, `verify_pre_sig`, `decrypt_btc_adaptor`, `recover_secret_from_btc_sig` | secp256k1, BIP-340 parity-correct (the `create_pre_sig_bip340` variant handles the odd-parity retry loop) |
| Ristretto255 Schnorr-style adaptor | `adaptor.rs` | `cync_create_pre_sig`, `cync_verify_pre_sig`, `cync_decrypt_adaptor`, `cync_recover_secret`, `cync_adaptor_point` | **See §6.1 — the CYNC-side functions exist as primitives but the design note's joint-key model is the correct conceptual frame; the audit should confirm the two views are equivalent under renaming** |
| Cross-curve DLEQ (fast) | `adaptor.rs` | `prove_cross_curve`, `verify_cross_curve_proof` | Dual-response Schoenmakers (1999). Default. Operationally sound — the adaptors enforce same-secret cryptographically via the spend path |
| Cross-curve DLEQ (strict) | `strict_dleq.rs` | `prove_cross_curve_strict`, `verify_cross_curve_strict` | Noether 2018 — bit-decomposition + per-bit Pedersen + Chaum-Pedersen OR-proof + linear-combination opening. Feature-gated `--features strict-dleq`. ~81 KB on the wire. **The cryptographic-level same-secret-cross-curve property is provided by this variant.** |
| AdaptorSecret with byte-order tracking | `adaptor.rs` | `AdaptorSecret`, `SecretEncoding` | secp256k1 BE vs Ristretto LE encoding tracked + transparent conversion; constant-time `PartialEq` via `subtle::ConstantTimeEq` |
| NUMS generators | `strict_dleq.rs` | `h_btc_generator`, `h_cync_generator` | Try-and-increment from a fixed domain-separation tag; dlog wrt G is provably unknown. Memoized |
| Pedersen commitments on both curves | `strict_dleq.rs` | `pedersen_commit_btc`, `pedersen_commit_cync` | Standard `value·G + blinding·H`. Rejects zero blinding (which would leak the value) |
| BTC tx construction (lock) | `btc.rs` | `build_lock_tx` | P2TR with optional script-tree refund branch (`RefundBranch{bob_pubkey, csv_blocks}`). Computes the tweaked output key via `TaprootBuilder::finalize().output_key()` |
| BTC tx construction (claim) | `btc.rs` | `claim_sighash`, `build_claim_tx` | BIP-341 key-path. `build_claim_tx` re-verifies the supplied 64-byte signature under BIP-340 against the reconstructed sighash before emitting the witness |
| BTC tx construction (refund) | `btc.rs` | `refund_sighash`, `build_refund_tx`, `refund_script` | BIP-341 script-path with BIP-68 sequence engaging CSV. `build_refund_tx` re-verifies the signature under `refund_branch.bob_pubkey` |
| CYNC swap key-derivation | `cync.rs` | `derive_swap_recipient_spend_pub`, `derive_swap_spender_secret`, `compute_swap_lock_recipient` | The joint-key construction per the design note. `derive_swap_recipient_spend_pub` is the `S_a + S_b` joint pubkey; `derive_swap_spender_secret` is the `s_a + s_b` joint secret |
| Noise XX session | `coordinator.rs` `NoiseTransport` | `handshake_initiator`, `handshake_responder`, `send`, `recv` | Cipher suite `Noise_XX_25519_ChaChaPoly_BLAKE2s` via the `snow` crate. Mutual-auth via long-term Curve25519 static keys. Chunks payloads >65 KiB across multiple AEAD frames |
| SOCKS5 CONNECT dial | `coordinator.rs` | `socks5_connect_domain` | Hand-rolled RFC 1928 §3-4 no-auth client, ATYP=DOMAINNAME (forced for `.onion` compat). All 8 standard reply codes decoded by name |

---

## 3. Protocol layer

**State machine.** [protocol.rs](../crates/coincync-swap/src/protocol.rs) `Swap::apply(Transition)` is the sole authority on protocol state. Every transition is gated by `(role, current_state)` and returns the deterministic next state. Terminal states (`Completed`, `Refunded`, `Aborted`) reject all further transitions. See [CIP-001 §State Machine](cip/CIP-001-atomic-swap.md) for the design.

**Property tests.** `protocol.rs::tests` includes:

- `prop_terminal_stickiness` — no transition out of a terminal state, ever.
- `prop_all_or_nothing_state_changes` — `apply()` either succeeds (state advanced) or errors (state unchanged); no inconsistent middle.
- `prop_timeout_safety_boundary` — `SwapParameters::is_timeout_safe` correctly enforces the CIP-001 §"Timeout Safety" rule across a range of fixture values.

**Handshake layer.** [coordinator.rs](../crates/coincync-swap/src/coordinator.rs) `HandshakeSession` is the message-level state machine; `Coordinator` is the TCP-backed driver. The full Alice↔Bob handshake involves 7 explicit messages (Hello → HelloAck → Accept → AdaptorMaterial × 2 → Ready × 2), driven by `run_alice` / `run_bob` (simple variants) or `run_alice_post_hello` (DoS-hardened variant after `listen_filtered`).

---

## 4. Threat-model documents

Read these **before reading the code**:

1. **[CIP-001 §Security Considerations](cip/CIP-001-atomic-swap.md)** — the top-level threat enumeration.
2. **[atomic-swap-clsag-adaptor-design.md §7 Primary Review Targets](atomic-swap-clsag-adaptor-design.md)** — the highest-risk cryptographic surfaces, prioritized by the design author. **Start here for the cryptographic review.**
3. **[CIP-001 §Pre-audit hardening: strict-binding cross-curve DLEQ (Noether 2018)](cip/CIP-001-atomic-swap.md)** — the strict-DLEQ design + wire format + soundness sketch.
4. **[docs/cyncswap-transport-setup.md](cyncswap-transport-setup.md)** — operator-facing transport setup with MitM mitigation requirements.

---

## 5. Primary review targets (prioritized)

Re-stating the [design note's §7](atomic-swap-clsag-adaptor-design.md) review priorities, with file:line pointers for each:

| Priority | Target | File:line(s) | Property |
| --- | --- | --- | --- |
| **1 (highest)** | CDLP scalar-order bound — proof must constrain the shared scalar to a value that is a valid discrete log in BOTH secp256k1 and Ristretto255 | `strict_dleq.rs::STRICT_BIT_COUNT` (= 252, strictly < `min(log₂ n, log₂ ℓ)`) + `decompose_to_bits` (rejects high-bit-set secrets) | An off-by-one or missing range constraint here is a **fund-loss bug**. |
| 2 | CDLP soundness over Ristretto255 (adapted, not copied, from the secp256k1↔Ed25519 original) | `strict_dleq.rs::prove_bit_pair` + `verify_bit_pair` + `verify_linear_combination_{btc,cync}` | Adaptation is **believed** to be a simplification (prime-order target) — independent proof required. |
| 3 | Adaptor completeness + extractability on the Bitcoin side | `adaptor.rs::create_pre_sig_bip340`, `decrypt_btc_adaptor`, `recover_secret_from_btc_sig` | Standard primitives, but **integration** with the timelock structure must match the refund-safety argument in CIP-001 §"Timeout Safety". |
| 4 | Joint-key sweep indistinguishability | `cync.rs::derive_swap_spender_secret` | A CLSAG signature produced with `s = s_a + s_b` must be in-distribution identical to any other CLSAG signature. Expected to hold trivially (sum of two uniform scalars is uniform) but should be stated + confirmed. |
| 5 | The `mu_c` non-interaction claim | Cross-module: `cync.rs::derive_swap_recipient_spend_pub` + (by reference) `coincync::crypto::clsag.rs::compute_aggregate_coefficients` | Confirm the adaptor construction genuinely never touches the commitment-binding path of CLSAG. See design note §4.1 — adaptors are on **spend keys**, range proofs are on **amount commitments**, structurally separate. |
| 6 | BIP-340 parity handling | `adaptor.rs::create_pre_sig_bip340` (the parity-correct variant) + `build_claim_tx`'s BIP-340 verify step | Earlier non-parity-aware variant exists in the code marked `#[ignore]`; audit should confirm only the parity-correct path is used by the production flow. |
| 7 | BIP-341 script-path key derivation | `btc.rs::tweaked_claim_secret`, `refund_script_merkle_root`, `build_claim_tx`, `build_refund_tx` | The tweaked output key `Q = K + TaggedHash("TapTweak", K.x ‖ merkle_root)·G` must be bit-for-bit consistent between the lock construction and the spend path. Computed via the same `TaprootBuilder` path on both sides. |
| 8 | Noise XX session indistinguishability + AEAD chunking | `coordinator.rs::NoiseTransport::{send, recv}` | Chunked AEAD frames must concatenate to the original plaintext without leakage at chunk boundaries. Chunk-count header is sent as its own length-prefixed frame and capped at 1024 to bound DoS exposure. |
| 9 | SOCKS5 reply-code handling | `coordinator.rs::socks5_connect_domain` | All 8 standard reply codes decoded; ATYP=DOMAINNAME forced (avoids client-side DNS leak that would defeat Tor's privacy). |

---

## 6. Conceptual clarifications the audit should be aware of

### 6.1 "CLSAG adaptor signature" is a misnomer — correct framing is "joint key + ordinary CLSAG"

[atomic-swap-clsag-adaptor-design.md §3](atomic-swap-clsag-adaptor-design.md) establishes: there is **no CLSAG-side adaptor signature primitive**. The CYNC side is a 2-of-2 joint spend key (`S = S_a + S_b` over Ristretto255) signed with **ordinary `clsag_sign`** when one party learns the other's share. All adaptor signatures live on the **Bitcoin** side. The cross-curve binding is the CDLP.

In the shipped code, the `cync_create_pre_sig` / `cync_verify_pre_sig` / `cync_adaptor_point` family of functions in `adaptor.rs` operate on the same scalar that participates in the joint-key construction. Under renaming (`adaptor_secret t` ↔ `key share s_a`; `cync_adaptor_point` ↔ `S_a`), the constructions are equivalent. The audit should:

- Confirm this equivalence under renaming.
- Recommend whether to rename for clarity (the design note suggests removing the `CyncAdaptorSig` framing and replacing with `CyncKeyShare` / `JointSpendKey`).
- Verify no code path treats the CYNC-side adaptor as cryptographically novel (it is not — it is the joint-key spend with the joint secret reassembled via `s = s_a + s_b`).

### 6.2 `cync_timeout_blocks` is a coordination deadline, not an on-chain timelock

CYNC has no script layer; outputs cannot carry timelock conditions. The `SwapParameters::cync_timeout_blocks` field is a **coordination deadline** — the wall-clock point past which Alice's coordinator gives up waiting and pursues the refund race on Bitcoin. Compare this with `btc_timeout_blocks` which IS an on-chain CSV-engaged timelock. The `is_timeout_safe` check ensures Alice has wall-clock time to act before the Bitcoin refund opens for Bob.

This was unclear in CIP-001 v1; the design note's §3.6 amendment makes it explicit. The audit should verify no code path treats `cync_timeout_blocks` as an enforceable on-chain constraint.

### 6.3 Strict-DLEQ is opt-in

The default fast cross-curve DLEQ (dual-response Schoenmakers) is operationally sound — the swap protocol's same-secret binding is enforced by the adaptors themselves (Alice's BTC claim reveals `t` to Bob; Bob's CYNC spend secret either works (correct `t`) or fails (wrong `t`)). The cryptographic-level same-secret-cross-curve property requires the Noether 2018 strict variant, available behind Cargo feature `strict-dleq`. **Whether to ship the strict variant in production is gated by the auditor's preference** — both variants are implemented and tested.

---

## 7. Test-vector inventory

Per [design note §8](atomic-swap-clsag-adaptor-design.md), test vectors required before "implementation complete":

| Vector class | Status | Where |
| --- | --- | --- |
| CDLP vectors (known scalar → curve points → proof) | ✅ in-crate property tests + ✅ **external golden file shipped 2026-05-18** at [crates/coincync-swap/test-vectors/strict-dleq-vectors.json](../crates/coincync-swap/test-vectors/strict-dleq-vectors.json) (3 vectors covering small / middle-of-range / near-bit-251-boundary secrets, full fast-floor proof in hex + SHA-256 of the ~81 KB strict proof). Validated by [tests/strict_dleq_vectors.rs](../crates/coincync-swap/tests/strict_dleq_vectors.rs) golden-file test which fails on any wire-format drift | `strict_dleq.rs::tests` — round-trip + tamper-rejection on every layer + determinism property under fixed seed |
| Bitcoin adaptor vectors (pre-sig → completion → recovery round-trip) | ✅ Schnorr-only (per Open Question 1 resolution) | `adaptor.rs::tests` |
| Joint-key vectors (`s_a`, `s_b` → `S = S_a + S_b` → CLSAG sign/verify) | ⏳ deferred to wallet integration — `cync.rs::tests::swap_*` covers the byte-level joint-key derivation; the full CLSAG sign/verify under `s = s_a + s_b` requires the `coincync` crate's CLSAG impl and is the natural test to add at wallet-integration time | `cync.rs::tests::swap_recipient_spend_pub_equals_p_plus_t`, `swap_spender_secret_pubkey_matches_swap_recipient_pubkey` |
| Full-protocol integration vectors (recorded happy-path + refund-path swaps, replayable deterministically) | ✅ via mock chains; ⏳ live regtest+testnet vectors pending live test environment | `tests/swap_happy_path_e2e.rs` (happy + refund-via-CSV-branch + Alice-tampers-redirect anti-property) |
| Timeout-edge vectors | ✅ | `protocol.rs::tests::prop_timeout_safety_boundary` |
| **Reproducibility vectors** (deterministic input → recorded outputs for the adaptor + DLEQ primitives) | ✅ **shipped 2026-05-19** at [test-vectors/reproducibility/](../crates/coincync-swap/test-vectors/reproducibility/) — 12 JSON vector files (5 btc-adaptor + 2 ristretto-adaptor + 5 dleq-cross-curve), generator at [examples/gen_reproducibility_vectors.rs](../crates/coincync-swap/examples/gen_reproducibility_vectors.rs). Locks current output bytes; any drift fails the harness | [tests/external_vectors.rs](../crates/coincync-swap/tests/external_vectors.rs) walks `test-vectors/{reproducibility,comit,farcaster}/<primitive>/*.json` and asserts bit-for-bit byte-equality against published expected outputs |
| **Comit vendor vectors** (independent reference impl) | ⏳ scaffold present, import not yet done | [test-vectors/comit/](../crates/coincync-swap/test-vectors/comit/) — README documents the import path. Harness already wired; once vectors land, validation runs every CI run |
| **Farcaster vendor vectors** (independent reference impl) | ⏳ scaffold present, import not yet done | [test-vectors/farcaster/](../crates/coincync-swap/test-vectors/farcaster/) — same as above |

---

## 8. Test-coverage gaps (knowingly missing)

Auditor should know:

- **Live dual-testnet smoke** ([scripts/cyncswap-dual-testnet-smoke.sh](../scripts/cyncswap-dual-testnet-smoke.sh)) is operator-driven (operator pastes signed-tx hex per step). An automated dual-testnet harness would require a running bitcoind regtest + coincync-node testnet bound to the test runner; this is a deployment concern, not a coverage concern, but worth noting.
- **Joint-key full-CLSAG round-trip** requires the parent `coincync` crate as a dev-dependency; deferred until wallet integration lands.
- ~~**Performance benchmarks** for the strict-DLEQ prove/verify (~81 KB proof) exist only as test timing in CI~~. **Closed 2026-05-20.** Criterion benchmark at [crates/coincync-swap/benches/strict_dleq.rs](../crates/coincync-swap/benches/strict_dleq.rs). Measured on a modern x86 desktop: `prove` ≈ **133 ms** median, `verify` ≈ **172 ms** median (100-sample criterion runs, release mode). Re-run via `cargo bench -p coincync-swap --features strict-dleq`. Cost is comfortably below the swap protocol's coordination latency budget; not a DoS surface on the verify path.
- ~~**Fuzzing harnesses** for the protocol state machine + the wire-format JSON parser would be valuable but are not shipped.~~ **Partially closed 2026-05-19.** Per-commit CI fuzz on 5 attacker-reachable surfaces (`fuzz_p2p_message`, `fuzz_block`, `fuzz_transaction`, `fuzz_rpc_body`, `fuzz_wallet_persistence`) at [.github/workflows/fuzz.yml](../.github/workflows/fuzz.yml) — 60 s libFuzzer + ASAN per target, every PR + push to main. Overnight script [scripts/fuzz-overnight.sh](../scripts/fuzz-overnight.sh) walks all 27 targets for deep accumulation (10.2 hr overnight #1 found + fixed wallet kdf_m_cost validation gap, commit 91a19cd). Protocol state machine still uses property tests rather than libFuzzer; the state-machine surface is a constrained finite-state graph where proptest random transition sequences arguably outperform libFuzzer.
- ~~**CDLP external test vectors**~~ **Shipped 2026-05-18** at [crates/coincync-swap/test-vectors/strict-dleq-vectors.json](../crates/coincync-swap/test-vectors/strict-dleq-vectors.json). 3 vectors with `(secret, seed) → (T_btc, T_cync, fast_proof_hex, strict_proof_sha256)` derivation. Validated by `vectors_match_checked_in_file` golden-file test — any wire-format drift fails the test, forcing explicit re-baseline review.

---

## 9. Auditor-required out-of-band materials

The operator running the audit should provide:

| Material | Form |
| --- | --- |
| Specific commit SHA being audited | `git rev-parse HEAD` against `crates/coincync-swap/` |
| List of any local patches not yet pushed to the public repo | `git log <upstream-base>..HEAD --oneline` |
| Cargo lock-file hash for both feature modes | `sha256sum Cargo.lock` after `cargo update --workspace` (zero) and `cargo update --workspace --features coincync-swap/strict-dleq` |
| Operator-managed Noise XX static-key fingerprints used in production | hex-encoded 32 bytes per party (Alice + each prospective Bob) |
| Tor `.onion` hostname format the operator plans to publish | v3 only (62 char base32 + `.onion`); v2 is deprecated and not supported |
| Threat model exclusions (any explicitly-out-of-scope attacker capabilities) | Free-text |

---

## 10. Build + test reproducibility

To reproduce the audit baseline:

```bash
# Clone + check out the audited commit
git clone <repo>
cd <repo>
git checkout <commit-sha>

# Both feature modes must compile clean + tests pass
cargo build -p coincync-swap
cargo test -p coincync-swap
# expect: 192 tests pass (179 unit + 10 integration + 3 e2e)
#   includes property tests:
#     - tests/property_invariants.rs            (4 properties: BTC/CYNC adaptor roundtrip + DLEQ)
#     - tests/property_invariants_cync.rs       (7 properties: CYNC-side derivation)
#     - tests/state_machine_invariants.rs       (6 properties: protocol state machine)
#     - tests/external_vectors.rs               (replays JSON vectors under test-vectors/)

cargo build -p coincync-swap --features strict-dleq
cargo test -p coincync-swap --features strict-dleq
# expect: 254 tests pass (237 unit + 10 integration + 3 e2e + 4 strict_dleq_vectors)

# Workspace-wide sweep
cargo test --workspace --exclude coincync
# expect: 288 tests pass

cargo test --workspace --exclude coincync --features coincync-swap/strict-dleq
# expect: 350 tests pass
```

### Reproducibility vector regeneration

The 12 reproducibility vectors at [test-vectors/reproducibility/](../crates/coincync-swap/test-vectors/reproducibility/) are deterministic. Auditor can re-derive them:

```bash
cargo run -p coincync-swap --example gen_reproducibility_vectors
# regenerates 5 btc-adaptor + 2 ristretto-adaptor + 5 dleq-cross-curve JSON files
# git diff must be empty — any drift is a regression
```

If any of these counts differ from this document, the audit baseline has shifted — re-derive the commit + the counts before proceeding.

---

## 11. Pre-audit testing evidence (2026-05-18 → 2026-05-19)

This section accounts for hardening done in the run-up to engagement, so an incoming auditor can see exactly what was added on top of the baseline §0 perimeter. Everything below is in tree; nothing is aspirational.

### 11.1 Property-based testing (proptest)

Seventeen properties added in the `coincync-swap` crate, all grounded in the impl (read source, then write property — no assumptions):

| File | Properties | Load-bearing invariant |
| --- | --- | --- |
| [tests/property_invariants.rs](../crates/coincync-swap/tests/property_invariants.rs) | 4 | `btc_adaptor_roundtrip` (pre-sig + decrypt → recover same secret), `btc_adaptor_binding` (wrong T fails verify), `cync_adaptor_roundtrip`, `dleq_roundtrip` |
| [tests/property_invariants_cync.rs](../crates/coincync-swap/tests/property_invariants_cync.rs) | 7 | `derivation_consistency` — `derive_swap_recipient_spend_pub(S_a, S_b)·G == S_a + S_b` (joint-key math; a regression here is a fund-loss bug) |
| [tests/state_machine_invariants.rs](../crates/coincync-swap/tests/state_machine_invariants.rs) | 6 | Random transition sequences from `Init` never reach an `Aborted ∧ on-chain-funds-locked` configuration; terminal states are sticky |
| [tests/external_vectors.rs](../crates/coincync-swap/tests/external_vectors.rs) | n/a (vector replay) | Walks `test-vectors/{reproducibility,comit,farcaster}/<primitive>/*.json` and asserts bit-equal outputs |

Plus 96 property tests added to the parent `coincync` crate (out of audit scope but mentioned because the same discipline was applied repo-wide): amount/hash/address/keys/validator/difficulty/stealth/memo invariants at [tests/property_invariants_*.rs](../tests/).

### 11.2 Fuzz history

| Run | Duration | Targets | Result | Notes |
| --- | --- | --- | --- | --- |
| Overnight #1 | 10.2 hr | All 27 targets, libFuzzer + ASAN + sancov | 26/27 clean; **1 crash in `fuzz_wallet_persistence`** | Fixed in commit `91a19cd` — wallet header `kdf_m_cost` could be set to a value large enough to OOM Argon2id; added explicit bounds `KDF_M_COST_MAX_KIB = 1_048_576` + 5 regression tests including the hard-coded crash bytes. Re-fuzzing the same crash file post-fix runs clean in <1 ms. |
| Overnight #2 | ~9 hr | All 27 targets | 26/27 clean; **1 NEW crash in `fuzz_wallet_persistence`** — distinct from #1's | The symmetric lower-bound case the #1 fix didn't cover: `kdf_m_cost` set BELOW `argon2::Params::MIN_M_COST` panics at `Params::new().expect("valid Argon2 params")` with `MemoryTooLittle`. Fix shipped in [src/wallet/persistence.rs](../src/wallet/persistence.rs) (validate() lower bounds + 4 new regression tests, including hardcoded crash bytes `crash-c0a0e826...`). Re-fuzzing the same crash file post-fix runs clean in 1 ms. **The lesson is in the gap:** the #1 fix only added upper bounds; the symmetric lower-bound case was overlooked. The audit team should treat "any `.expect()` on user-supplied byte deserialization" as a search target — there may be more of these. |
| Per-commit CI | 60 s × 5 targets | `fuzz_p2p_message`, `fuzz_block`, `fuzz_transaction`, `fuzz_rpc_body`, `fuzz_wallet_persistence` | green on `main` since commit `8a81b79` | [.github/workflows/fuzz.yml](../.github/workflows/fuzz.yml) — every PR + push runs in parallel matrix; crash artifacts uploaded for 30 d |

Two consecutive overnight passes finding two distinct bugs in the same target is the cleanest evidence that the fuzz harness is doing real work — and that "fix once, ship" isn't enough on validation paths. The fix discipline (write a unit test that pins the exact crash bytes, then patch the validator) means neither bug can regress silently.

### 11.3 External test vectors

Three vector directories under [crates/coincync-swap/test-vectors/](../crates/coincync-swap/test-vectors/):

- **`reproducibility/`** — 12 in-house deterministic vectors generated by [examples/gen_reproducibility_vectors.rs](../crates/coincync-swap/examples/gen_reproducibility_vectors.rs) (5 btc-adaptor + 2 ristretto-adaptor + 5 dleq-cross-curve). Locks the current output bytes. Auditor can regenerate via `cargo run -p coincync-swap --example gen_reproducibility_vectors`.
- **`comit/`** — scaffold + README; vector import deferred pending license review of the upstream repo's vectors directory specifically.
- **`farcaster/`** — scaffold + README; same status.

All three directories are walked by [tests/external_vectors.rs](../crates/coincync-swap/tests/external_vectors.rs), so the moment vectors land in `comit/` or `farcaster/`, validation runs every CI run with no harness changes required.

### 11.4 Mutation testing

Mutation testing measures whether the test suite would *catch* an adversarial code change. cargo-mutants flips operators, constants, returns, and match arms one at a time across the four audit-critical files; for each mutation it re-runs the test suite and reports MISSED (tests still pass — bad) vs CAUGHT (tests fail — good).

| Pass | Score | Caught / missed | Notes |
| --- | --- | --- | --- |
| Baseline 2026-05-19 | **84.3%** | 285 / 53 | First measured. Most misses in RPC/IO layer (`BitcoinCoreRpc::*`, `CyncNodeRpc::*`) and tx-construction arithmetic. `adaptor.rs` already at 95/95 caught — the BIP-340 + Ristretto adaptor primitives. |
| Hardening 2026-05-20 | **100.0%** | 340 / 0 | +24 new tests across 5 categories: parameterized network-string tests, dust-threshold boundary tests, mock-impl arithmetic + timing tests, `wiremock`-backed RPC tests (real HTTP server controls `getblockcount` / `get_transaction` / `get_blockchain_info` / `send_raw_transaction` responses), explicit error-message-string assertions. Score landed at 100.0% on the verification pass (340 caught / 0 missed / 68 unviable / 2 timeout, 1h 17m wall-clock). |

**Config:** [.cargo/mutants.toml](../.cargo/mutants.toml) scopes mutation testing to the four audit-critical files. **Runner:** [scripts/mutants-overnight.sh](../scripts/mutants-overnight.sh) (single mode, generates per-file summary + writes `~/mutants-overnight-report.txt`). **Re-run cost:** ~1h 17m on a warm cache for the full 408-mutant pass.

For the auditor: a mutation score of 100% on the four crypto-critical files is the empirical answer to "do your tests actually exercise the crypto, or just call it?" Every operator, constant, return, and match-arm mutation cargo-mutants could generate is caught by at least one test. This complements property tests (random valid inputs → invariants hold), fuzz (random adversarial inputs → no crash), and external vectors (cross-impl byte-equality). Together: four legs of the stool, not one.

### 11.5 What this does **not** cover

To preserve the §8 "knowingly missing" discipline:

- The CDLP scalar-order bound (Priority 1 in §5) is unit-tested + property-tested in-crate, but **not** cross-implementation-verified. The §11.3 vendor vectors close this once imported.
- Joint-key full-CLSAG round-trip (§8 bullet 2) is still deferred until wallet integration.
- Live dual-testnet vectors are still operator-driven (§8 bullet 1).
- Strict-DLEQ benchmark numbers (§8 bullet 3) are still test-timing only.

The §8 gap list above is the authoritative statement of what is missing. §11 is the statement of what was added — including the §11.4 mutation-score measurement of how thoroughly the tests exercise the code paths.

---

## 12. Changelog

- **2026-05-18** — Document created. Reflects the state of `crates/coincync-swap/` after the 2026-05-17 session series (288/346 test counts, all transports shipped, strict-DLEQ complete, operator docs in place).
- **2026-05-18 (later)** — External strict-DLEQ test vectors shipped at [crates/coincync-swap/test-vectors/strict-dleq-vectors.json](../crates/coincync-swap/test-vectors/strict-dleq-vectors.json). §7 + §8 + §10 updated to reflect: vectors gap closed (was "deferred until requested"), workspace test count under `--features strict-dleq` bumped to 350 (was 346, +4 new golden-file regression tests in [tests/strict_dleq_vectors.rs](../crates/coincync-swap/tests/strict_dleq_vectors.rs)).
- **2026-05-19** — Pre-audit testing evidence section added (now §11; prior changelog renumbered to §12). Captures: (a) 17 new property tests in `coincync-swap` across adaptor / CYNC derivation / state machine + external-vector replay harness; (b) fuzz history including overnight #1 finding the `kdf_m_cost` validation gap fixed in commit `91a19cd`; (c) 12 reproducibility vectors at [test-vectors/reproducibility/](../crates/coincync-swap/test-vectors/reproducibility/) with regeneration recipe at §10; (d) per-commit CI fuzz workflow [.github/workflows/fuzz.yml](../.github/workflows/fuzz.yml) running 5 critical targets every PR + push. §8 fuzz-harness gap line annotated as partially closed.
- **2026-05-19 (evening)** — Fuzz overnight #2 finished. 26/27 targets clean; **`fuzz_wallet_persistence` found a second crash** — the symmetric lower-bound case the #1 fix didn't cover (`kdf_m_cost < argon2::Params::MIN_M_COST` panics with `MemoryTooLittle`). Lower bounds added in [src/wallet/persistence.rs](../src/wallet/persistence.rs) `WalletHeader::validate()` for all three KDF params; 4 new regression tests including hardcoded `crash-c0a0e826...` bytes. Re-fuzzing the same crash file post-fix runs clean in 1 ms. §11.2 fuzz history table updated with the result + the lesson (symmetric bounds discipline).
- **2026-05-20** — Mutation testing pre-engagement pass. Baseline measurement of the four audit-critical files (`strict_dleq.rs`, `adaptor.rs`, `cync.rs`, `btc.rs`) at 84.3% (285/338 caught) revealed missing coverage in RPC adapters and tx-construction arithmetic. **+24 new tests** added across five categories (parameterized network-string match arms in tx builders, dust-threshold boundary tests, mock-impl + sync-wrapper trait tests, wiremock-backed real-HTTP-server tests for `BitcoinCoreRpc` and `CyncNodeRpc`, explicit error-message-string assertions for the strict-DLEQ bit-0 arm). Score raised to **100.0% verified** (340 caught / 0 missed). `adaptor.rs` was 95/95 caught at baseline — no test additions needed there. New §11.4 captures the methodology + result.

---

*This is a wayfinding document for the audit team. It does not change the code or the protocol. The source-of-truth for design decisions is [CIP-001](cip/CIP-001-atomic-swap.md) + its changelog + [atomic-swap-clsag-adaptor-design.md](atomic-swap-clsag-adaptor-design.md). Discrepancies between this document and the code should be resolved in favor of the code.*
