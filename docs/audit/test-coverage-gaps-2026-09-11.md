# Test coverage gaps — 2026-09-11

**The core finding:** the suite is **1,206 lib + ~600 integration tests, all green — and it caught 0 of the 38 bugs** in `bug-hunt-2026-09-10.md`. That is a *shape* problem, not a *quantity* problem. The existing tests are strong on **happy-path unit behaviour**, plus real **property tests** (determinism, difficulty, emission oracle) and **fuzz** (7 targets) and **Kani** (15 proofs). What's almost entirely missing is the three axes where every one of those 38 bugs lived:

1. **Adversarial-but-valid input** — a crafted block/tx/message that is structurally legal but malicious.
2. **Differential / multi-node** — do two honest nodes fed the same data (in different orders) end up in the *same* state?
3. **Liveness & state-machine under misbehaviour** — does one bad peer, a stall, or an out-of-order message wedge the node?

Below: the missing suites, each mapped to the bug(s) it would have caught, most-impactful first.

---

## 1. Reorg with REAL transactions (biggest single gap)
The only reorg integration tests (`sim_l3_consensus.rs`, `chaos_partition_l6.rs`, `reorg_double_spend_e2e.rs`) use **coinbase-only fork blocks** — no key images, ring members, or shared txs. That is exactly why **C1** (fork sharing a tx → permanent partition) and **H2** (coinbase stealth-address reuse → cross-node divergence) slipped through.
- Fork block sharing a mempool tx with the active branch → must store + reorg. *(C1 — added this PR.)*
- Reorg that disconnects a coinbase whose output reused an existing stealth address → the victim's output must survive on all nodes. *(H2, M6.)*
- Failed-reorg rollback (tip invalid against rewound state) → no stale `height_to_hash`, a follow-up block can't commit a gapped chain. *(H3.)*
- Reorg with a key image spent on the losing branch → correctly un-marked and re-checked. *(chain reorg.)*

## 2. Multi-node DIFFERENTIAL consensus (would catch the whole divergence class)
There is no test that runs **two independent `Blockchain` instances**, feeds them the same blocks/txs in **different orders / with a reorg**, and asserts **identical** final `(tip, height, total_difficulty, UTXO root, supply)`. This one harness would have caught C1, H2, H3, M4, M6, M11 at once. It is the highest-leverage suite to add.
- Property test: for any valid block sequence + any legal reorg, node-A-state == node-B-state.
- Crash-consistency: kill the process at each step of `add_block` / the reorg loop → restart → invariants hold (supply, no missing `output_index` rows). *(M6.)*

## 3. Adversarial block/header validation
Validation is only tested with honest blocks. Every crafted-but-valid block is untested.
- Block with `header.version = 255` → must be rejected, must not brick honest templates. *(H1.)*
- Coinbase with non-empty `inputs`, arbitrary `fee`, `range_proof`, oversized `extra`, identity/non-curve stealth, 1-atomic outputs → each rejected. *(H2, coinbase LOWs.)*
- ASERT retarget after an 8–24h stall (integer-shift path) → target saturates, never truncates. *(M4.)*
- Block-1 exact-target enforcement (window len 1) → no 256×-easy hole. *(M11.)*
- Property: any block that PASSES validation must `add_block` cleanly and round-trip through disconnect/reconnect.

## 4. P2P adversarial & liveness (nothing here today)
The network tests are happy-path. No test drives a *misbehaving* peer.
- A peer that stops reading must not block message processing for other peers. *(C2 — unit added; needs a 2-socket integration test.)*
- A `Verack` with no prior `Version` must not reach `Connected`. *(M-P1 — testable at the handler level.)*
- A replayed `Verack` / uncapped `ChainWork` / `InvBlock` must not wedge `is_synced` or the GetHeaders slot. *(H5, H6.)*
- Unsolicited `Blocks`/`BlockData` flood → not accepted, not orphan-stored before PoW, bounded memory. *(H4.)*
- `Addr` of future-dated entries → no dial starvation / book takeover. *(H7.)*
- Every wire length/count field → capped allocation (fuzz the decoders with adversarial length prefixes). *(M-P4, framing.)*
- Handshake state-machine property test (all message orderings from `Connecting`).

## 5. Wallet correctness across reorgs & restarts
Wallet tests cover a clean forward scan. No test covers the hostile-but-normal cases that lose funds.
- Reorg between two `scan` runs → orphaned received outputs removed, orphaned spends un-marked. *(H9.)*
- Restore-from-seed → subaddress-received funds are found (lookahead). *(M7.)*
- Watch-only wallet → a spent output is detected as spent. *(M8.)*
- Lightsync: non-contiguous / reorged digest batches rejected; `lock_height` preserved. *(M9.)*
- Send↔receive derivation symmetry for **every** output kind, including coinbase-to-subaddress. *(M12.)*
- Reservation lifecycle: reserved on build, released on every failure/timeout, survives a crash. *(funds-locking.)*

## 6. Mempool adversarial
- A tx that is ultimately REJECTED must evict **zero** resident txs (the eviction-cap off-by-one). *(H8.)*
- `extra` over 256 bytes / invalid `RecoveryMeta` → rejected on the CONSENSUS path, not just the unused `transaction/validator.rs`. *(M1.)*
- Mempool persistence: `save_to_disk` then restart → pending txs are actually LOADED. *(M2 — currently dead code, so a round-trip test would fail today.)*
- RBF: a replacement must pay a higher ABSOLUTE fee, not just rate. *(LOW.)*

## 7. Serialization / on-disk robustness
- Round-trip + adversarial-bytes fuzz for every borsh wire type and every on-disk value (a truncated/corrupt DB value must return `Err`, never panic). Partially covered by the 7 fuzz targets; extend to the storage decoders. *(crypto+storage LOWs.)*

---

## Priority to build
1. **Multi-node differential harness** (#2) — one suite, catches the largest bug class; pairs with the crash-consistency runner.
2. **Reorg-with-real-tx suite** (#1) — extend `reorg_double_spend_e2e.rs` beyond coinbase-only.
3. **Adversarial block/header cases** (#3) — cheap unit tests, high hit rate (H1, coinbase, M4, M11).
4. **P2P misbehaviour harness** (#4) — a `tokio` 2-node harness with a scriptable bad peer.
5. **Wallet reorg/restore/watch-only** (#5).
6. **Mempool adversarial + persistence round-trip** (#6).

## Method note
Most of these are **regression tests written from the bug hunt** — each confirmed bug should ship with the test that fails before the fix and passes after (as C1 does). That converts the one-time hunt into permanent coverage and is the single best defence before the external audit.
