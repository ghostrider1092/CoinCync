# CoinCync — Findings Register

The working document of the audit. One row per finding. Auditors append rows;
the team fills in **Status** and **Response**. Severity: Critical / High / Medium
/ Low / Info. Status: Open / Acknowledged / Fixed / Won't-fix / Disputed.

> Pre-populated below with the internal bug-hunt findings (`bug-hunt-2026-09-10.md`)
> and their remediation this cycle, so the format and the current baseline are
> clear. External auditors add new findings beneath.

## How to add a finding
Copy the row template. Cite the exact `file:line` (or `file §N` audit-map
section). Give a concrete PoC or failing scenario. Keep the recommendation
actionable. Link the test that proves the fix once landed.

`| ID | Sev | Location | Summary | PoC / scenario | Recommendation | Status | Test | Response |`

---

## Register

| ID | Sev | Location | Summary | Status | Test | Response |
|----|-----|----------|---------|--------|------|----------|
| C1 | Critical | `consensus/validation.rs` (fork-block validation) | Fork blocks validated against the *main-chain* UTXO set → node can never reorg onto a branch sharing a tx (permanent honest-node partition + mutual bans). | Fixed | `natural_fork_sharing_a_tx_can_be_stored_and_reorged` | PR #109 (contextual-validation flag; fork blocks skip active-UTXO checks, re-validated in the reorg loop). |
| C2 | Critical | `network/node/{connection,broadcast,dispatch/control}.rs` | One slow/dead peer freezes ALL P2P handling (blocking `send` on the shared processor + unbounded write). | Fixed | `send_to_peer_does_not_block_when_queue_is_full` + live testnet validation | PR #110 (write timeout, non-blocking `try_send`, M-P1 handshake gate). |
| H1 | High | `consensus/validation.rs §2`, `constants.rs` | Header-version ratchet: one block at `version=255` permanently bricks every honest miner's templates (monotonic floor, no upper bound). | Fixed | `check_header_version_min_rejects_version_above_max_h1` | `MAX_BLOCK_VERSION` cap added; version above it rejected. |
| H2 | High | `storage/utxos.rs §2/§4` (`remove_output`, `spend_output`); `consensus/validation.rs` (coinbase) | Reorg-disconnect erased a victim's shared stealth-index entry → victim's output vanishes on reorged nodes → chain split + frozen funds. | Fixed (storage, both mutators) / Won't-fix (consensus, not-a-bug) | `remove_output_preserves_a_shared_stealth_entry_it_does_not_own_h2`, `spend_output_preserves_a_shared_stealth_entry_it_does_not_own_h2` | **Storage:** both stealth-index mutators now only evict an entry the output actually OWNS (oldest-wins) — `remove_output` (reorg path, live) and `spend_output` (by-reference path, dead on ring-sig chains but guarded for consistency so the two mutators can't drift). This makes a shared stealth address fully SAFE at the storage layer. **Consensus (resolved won't-fix):** the proposed coinbase dup-stealth REJECTION rule is unnecessary AND harmful — old-format coinbases legitimately share `miner_pubkey`-derived stealth addresses (a miner repeatedly rewarding one address), so a rejection rule would consensus-reject legitimate blocks; and it adds no safety now that the storage layer handles sharing correctly. The vulnerability is closed at the layer where the damage occurred (the index), not by a new consensus constraint. |
| H3 | High | `chain.rs §7` (failed-reorg path-A rollback) | Path-A rollback left stale `height_to_hash` for fork heights above the old tip → RPC/sync report an unapplied block as canonical; a follow-up block commits a chain with an unapplied gap. | Fixed | `failed_reorg_rollback_leaves_no_stale_height_mapping_above_old_tip_h3` (real-PoW e2e) | Bound removal by the highest fork height, not the old tip. |
| H4 | High | `network/node/dispatch/chain.rs`, `sync.rs`, `network/node.rs` (`notify_block_orphan`) | Unsolicited `Blocks`/`BlockData` orphan flood: free reputation, inline RandomX CPU burn, orphan-pool bloat, poisoned sync queue, honest peers GetBlocks-banned. | Partially mitigated / deferred | `mark_block_orphan_lru_evicts_at_max_orphan_blocks`, `handle_blocks_invalid_pow_instant_bans_and_does_not_credit_or_emit` | **Already mitigated:** (a) every relayed block is RandomX-verified before any credit/emit and a bad-PoW block **instant-bans** the peer, so the CPU-burn is one hash per malicious peer; (b) the orphan pool is hard-bounded — `MAX_ORPHAN_BLOCKS = 1000` + LRU-oldest eviction + 30-min TTL (tested) — so it can no longer reach GBs. **Residual (accepted, deferred):** a peer can still fill the 1000-slot pool with unsolicited valid-PoW-but-unconnectable bodies (e.g. replayed old blocks) and LRU-evict honest orphans, and gain positive relay reputation for them. The full fix is a **solicited/GETDATA-response gate** (thread the per-peer `pending_requests` set through `handle_blocks`/`notify_block_orphan`). This is **deliberately not fixed blind:** this exact path caused the 2026-06-22 18-hour partition when scored naively (our own miner banned as an "orphan flooder" while delivering a legitimate heavier chain), and `MAX_ORPHANS_PER_PEER` was set to `usize::MAX` on purpose because any finite cap drops the deep out-of-order bodies a real reorg/takeover delivers. A correct fix needs GETDATA-response tracking validated on a multi-node harness (does-not-exist), not a rate limit or a solicited-drop that would re-open the partition. |
| H5 | High | `network/node/dispatch/control.rs` (`handle_verack`) | Single-flight GetHeaders slot captured indefinitely by Verack replay → IBD wedge. | Fixed | (M-P1 gate) | Addressed by C2/PR #110: Verack only advances `VersionReceived→Connected`. |
| H6 | High | `network/sync.rs` (`update_peer_difficulty_for`, `work_behind_substantiated`) | `ChainWork` over-claim flips the work-behind veto true indefinitely → gates the miner off; TTL/prune anti-wedge never fires against a persistent connected liar who re-advertises the bogus claim. | Fixed | `work_behind_veto_lifts_after_grace_without_progress_h6`, `work_behind_veto_persists_while_local_work_progresses_h6`, `persistent_liar_refreshing_claim_cannot_restart_grace_h6`, `not_behind_never_vetoes_the_miner_h6` | Substantiation gate: the work-behind veto stands only while fresh (within `WORK_SUBSTANTIATION_GRACE_SECS`) OR while our own cumulative work is actually rising (we are applying the heavier chain). A phantom claim delivers no progress, so the veto self-heals; a genuinely-behind node keeps progressing and stays gated until it catches up — so it never mines a stale fork. |
| H7 | High | `network/node/dispatch/address.rs`, `address_policy.rs` | Peer-supplied `last_seen` timestamps drive eviction + dial order → 250 future-dated `Addr` entries dial first and evict honest peers (dial starvation / eclipse); no port-0 filter. | Fixed | `handle_addr_clamps_future_last_seen_to_receive_time_h7`, `handle_addr_rejects_port_zero_h7` | Clamp relayed `last_seen` to receive-time; reject port 0. |
| H8 | High | `mempool.rs` (eviction loop) | Off-by-one: a *rejected* tx evicts 100 honest resident txs for free (repeatable griefing) — the real loop rejects on the 100th eviction even though the tx then fits. | Fixed | `eviction_that_fits_after_exactly_max_attempts_is_admitted_h8` | Test fit before enforcing the attempt cap. |
| L1 | Low | `chain.rs` (`rollback_to_height`) | Rollback unwound supply / burn / `total_difficulty` but NOT the `total_blocks` / `total_transactions` telemetry counters, so a reorged node reported inflated block/tx totals versus a linearly-built node on the same tip (apply/disconnect asymmetry). NOT consensus-critical — fork choice uses `total_difficulty`, which was already unwound. Found by the real-PoW e2e this cycle. | Fixed | `rollback_to_height_unwinds_total_blocks_and_transactions` (+ e2e `apply_disconnect_symmetry_and_supply_conservation`) | Decrement `total_blocks`/`total_transactions` per disconnected block, mirroring the connect path (`saturating_sub`). |

### Known documented-but-unfixed (consensus-frozen / accepted risk)
| ID | Sev | Location | Summary | Status |
|----|-----|----------|---------|--------|
| INFO-1 | Info | `primitives/hash.rs` (`merkle_root`) | CVE-2012-2459 duplication malleability present (`root([A,B,C]) == root([A,B,C,C])`) — consensus-frozen; relies on downstream block checks. | Acknowledged (test pins current behavior) |

*(Medium and Low findings from the bug hunt to be triaged and added.)*

## Coverage hardening (this cycle)

Beyond the bug fixes above, audit-facing test coverage was strengthened where the
review found the highest-risk gaps were **untested**, not unimplemented:

| Area | What was added / decided | Test |
|------|--------------------------|------|
| Bulletproofs `H` generator | Anchored the hardcoded value generator to the canonical dalek `PedersenGens::default().B_blinding` known-answer vector (separate literal), plus ≠G/≠identity and cross-copy agreement. A corrupted/swapped `H` is internally self-consistent and would otherwise pass every round-trip test. (Cannot be re-derived from scratch: upstream used the pre-v4 Ristretto hash-to-point — hence the frozen literal.) | `h_generator_is_canonical_bulletproofs_b_blinding_and_independent_of_g` |
| RingCT no-inflation guard | Added the **positive + inflation** direction of the real enforced check `verify_balance_proof` (balanced tx verifies; +1 atomic unit on an output is rejected). Prior tests only rejected malformed points. | `balance_proof_accepts_balanced_and_rejects_inflation` |
| Dead inflation primitive | **Removed** `crypto::audit::verify_commitment_balance` — dead AND RingCT-incorrect (summed raw input commitments, not pseudo-outputs); it risked being mistaken for the enforced guard. | (removal; guard covered above) |
| Stealth-index spend path | Guarded `storage::utxos::spend_output` with the H2 owns-the-entry check (sibling of the `remove_output` fix), keeping the two mutators consistent. | `spend_output_preserves_a_shared_stealth_entry_it_does_not_own_h2` |
| Wallet↔consensus ring size | Pinned the parity boundary between wallet `ring_size_at_height` and consensus `effective_ring_size` (1d27d3c8 class): they agree wherever a ring is buildable; the only mismatch is young+sparse, where the wallet fails safe (`InsufficientDecoys`) — a bounded liveness edge, not a fork surface. | `wallet_ring_size_matches_consensus_effective_ring_size_wherever_buildable` |

### Decoy indistinguishability (wallet C1) — CLOSED this cycle
The prior distributional test was **circular** (re-sampled the *same* `Gamma(19.28,
1/1.61)` constants and compared to itself → could not catch wrong parameters, the
actual deanonymization vector). Added a **non-circular** goodness-of-fit test that
pins the realized decoy-age distribution to an INDEPENDENT reference (Python
`gammavariate`, 2M samples, same `[100, 30000]` truncation): a wrong shape/scale
shifts the truncated median 40–56%, far outside the ±25% tolerance the correct
sampler sits inside. Test: `decoy_age_distribution_matches_independent_gamma_reference_wallet_c1`.

*Note on C2 (non-uniform occupancy / snapping):* selection is **height-driven** —
the gamma picks an age→target height, then one ordinal at that height; a denser
block is NOT over-represented for having more outputs. Snap-to-a-different-height
fires only on **gaps** (a height with no eligible output), which are rare on a
coinbase-every-block chain. So the "snapping pulls mass to dense regions" concern
is bounded; a gap-scenario distribution test remains a lower-priority follow-up.

### Cross-implementation KAT vectors — landed this cycle (crypto C1)
The core crypto previously had **no** known-answer vectors (all self-round-trip), so
a self-consistent-but-nonstandard construction survived. Added a KAT suite:

| Primitive | Anchor | Test |
|-----------|--------|------|
| `hash_to_point` | Spec-derivation (recomputes `from_uniform_bytes(Sha3-512("CoinCync_hash_to_point_v1"‖d))`) + golden hex | `hash_to_point_kat_matches_spec_and_golden` |
| `hash_to_scalar` | Spec-derivation (`from_bytes_mod_order_wide(Sha3-512("…scalar_v1"‖d))`) + golden hex | `hash_to_scalar_kat_matches_spec_and_golden` |
| `KeyImage::from_secret` | Monero spec-derivation `I = x·Hp(x·G)` + golden hex | `key_image_kat_matches_monero_spec_and_golden` |
| CLSAG signature | Deterministic under seeded RNG; verifies; key-image golden + SHA-256 wire-digest golden | `clsag_sign_verify_kat_deterministic_and_golden` |
| BP+ range proof | Deterministic under seeded RNG; verifies + rejects wrong commitment; SHA-256 wire-digest golden | `range_proof_bp_plus_kat_deterministic_and_golden` |

The `hash_*`/`key_image` vectors are **spec-derivations** (pin the exact hash, domain
tag, and curve op independently of the production path). The CLSAG/BP+ vectors are
**golden/regression** vectors (frozen deterministic output) that catch any wire-format
or algorithm drift; they are labelled as such so an external auditor treats them as
regeneratable vectors to **cross-check against a reference implementation** for full
conformance, not as a conformance proof in themselves.

### MEDIUM crypto coverage (batch/single agreement + large ring + inflation)
| Item | Property pinned | Test | Build |
|------|-----------------|------|-------|
| M2 — parallel proof verifier | A batch AGREES with per-proof `verify_single` and flags exactly the invalid proof (was only tested on empty input). Guards `verify_block_proofs`. | `parallel_batch_agrees_with_single_and_flags_the_invalid_proof` | default |
| M3 — MW kernel balance | Excess encoding MORE value than the declared fee (or a stray blinding component) is rejected — the inflation direction (was only fee-mismatch). | `verify_kernel_set_rejects_value_inflation_and_stray_blinding` | default |
| M4 — CLSAG large ring | Verifies at the production ring size (16) with the real signer at several positions; a single-slot tamper (response scalar or decoy member) is rejected (was only ring size 2–3). | `clsag_verifies_at_production_ring_size_and_rejects_single_slot_tamper` | default |
| M1 — Spark batch verifier | Batch AGREES with per-proof `verify_spark_spend`; one tampered proof in a batch is rejected. (Inflation surface when enabled.) | `batch_verify_sparks_agrees_with_single_and_rejects_one_tampered` | `sketch-lelantus-spark` |

> **Auditor note:** the per-subsystem checklists in `docs/audit/test-plan/` (esp. `crypto.md`, `wallet.md`) are **stale** — they mark dozens of behaviors MISSING that have since been implemented and tested. Reconcile them against the source (or regenerate) before using them as a gap list; the genuine gaps are the two bullets above, not the plan's MISSING flags.
