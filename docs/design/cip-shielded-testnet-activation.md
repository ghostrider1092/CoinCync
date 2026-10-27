# CIP — Shielded activation on the public testnet (rollout runbook)

Status: **DRAFT / HELD.** No activation height is set. This runbook is the
procedure for taking the Option-B shielded bridge live on the public **testnet**
(the pre-audit milestone: bridge live on a public network with real activity).
It is a **coordinated consensus hard fork** and must be executed end-to-end, in
order, or the testnet forks.

Scope: **testnet only.** Mainnet shielded activation is out of scope and stays
permanently `u64::MAX` until an external audit + governance. Nothing here touches
mainnet, and the code is structured so it *cannot* (see §8).

---

## 0. What this is, and what it is NOT

- **IS:** a *future-height* activation. The shielded wire type + verify/apply
  path already exist in the tree (gated). We set a finite activation height `H`
  on testnet; at `H` and above, `TxType::Shielded` becomes valid. Blocks below
  `H` are identical under the old and new rules (no shielded tx can appear before
  `H`), so **the chain DB is preserved** — this is a `roll-fleet.sh` (rebuild +
  restart, keep DB), **not** a `redeploy-fleet.sh` genesis wipe.
- **IS NOT:** a change to any rule that affects existing blocks. It is not a
  genesis wipe. It is not a mainnet change.

## 1. The two things that make this dangerous

1. **The verifier must be in every testnet binary.** The shielded verify/apply
   path (`verify_block_spark_v2`, the libspark FFI) is compiled only with
   `sketch-gk-proof` + `libspark-ffi`. The fleet today builds
   `--features "randomx testnet"` — **no verifier**. A node without the verifier
   cannot validate a shielded tx at `H`; it fail-closes and **forks**. So the
   activation build makes libspark **mandatory** for testnet.

2. **The consensus fingerprint does NOT change when `H` changes.** The handshake
   fingerprint (`consensus/fingerprint.rs`) is over magic / genesis /
   fee-distribution / min-output-age / finality heights / checkpoints — **not**
   the shielded activation height. So an old binary (`H = u64::MAX`) and a new
   binary (`H` finite) **share a fingerprint and keep peering**. A laggard node
   will happily follow the chain right up to `H`, then reject the first shielded
   block and **silently fork**. **The network will not warn you.** The only
   defense is out-of-band verification that every node runs the activation build
   *before* `H` (§5, §6).

3. **`H` is compiled in.** It is a constant (`SHIELDED_TESTNET_ACTIVATION_HEIGHT`),
   baked into the binary at build time. You cannot "nudge" `H` on a running node.
   If a laggard is found close to `H`, the only remedy is to ship a *new* binary
   with a later `H` to everyone before the original `H` is reached (§7). Choose
   the lead window (§4) so this is never a scramble.

## 2. Preconditions (hard gates — do not proceed until ALL are true)

- [ ] The shielded bridge + unshield + stealth have passed the full gated test
      surface: the gated unit suite `2400/0` (no `test-fast-pow`) AND the 8h
      armed-chaos soak PASS (0 panics, 7/7 breaker coverage, shielded triad
      exercised).
- [ ] CI covers the gated surface: `.github/workflows/shielded-gate.yml` is green
      on the activation commit (it builds + tests `--features
      "testnet … sketch-gk-proof libspark-ffi"`). If that workflow has never run
      on GitHub, its first run here is also its own validation.
- [ ] Every intended testnet host can build libspark: `clang`, `cmake`,
      `libssl-dev`/`pkg-config` installed; `SPARK_OPENSSL_DIR` resolves (system
      OpenSSL `/usr` on Ubuntu is fine — see
      `cip-shielded-libspark-portability.md`).
- [ ] An inventory of **every** node expected on the testnet exists — seed(s),
      fleet, and known community nodes — with a way to confirm each one's running
      build out-of-band (not via the fingerprint; see §1.2).
- [ ] The locked-file change that sets `H` has **2-of-N** sign-off recorded
      (`src/constants.rs` is hash-locked; see §3, §8).

## 3. Choosing `H`

`H = (live testnet tip at cut time) + (upgrade-window lead)`.

- The live tip is **not in the repo** (testnet relaunched from genesis
  2026-10-06; `TESTNET_CHECKPOINT_LIST` is intentionally empty). Read it from the
  canonical seed at cut time (`get_info` height on the seed, e.g. 2.29.34.197).
- Lead window: enough blocks for the whole inventory to upgrade **with margin to
  ship a push-out binary if a laggard is found** (§7). At 120s blocks, ~1 week ≈
  5040 blocks is a sane floor for a public net; shorter only if the inventory is
  small and fully under your control.
- Record the chosen tip, lead, and resulting `H` in the activation PR/commit.

## 4. Build the activation release

1. On the activation branch, set the knob:
   `src/constants.rs` → `SHIELDED_TESTNET_ACTIVATION_HEIGHT = <H>` (replace the
   `u64::MAX` placeholder). Leave `SHIELDED_TX_ACTIVATION_HEIGHT` at `u64::MAX`
   (that is the mainnet value — never change it here).
2. Regenerate the lock: `COINCYNC_REGEN_LOCK=1 cargo run --locked --bin
   update-critical-hashes`. Confirm `git diff critical_files.lock` shows **only**
   the `constants.rs` line changed.
3. Verify mainnet stays off: the test
   `shielded_activation_mainnet_permanently_off_testnet_is_dedicated_knob`
   must still pass (it asserts mainnet is `u64::MAX` unconditionally and testnet
   tracks the knob).
4. Run the gated suite locally: `cargo test --release --lib --features
   "testnet fuse block-integrity-breaker supply-breaker shielded-breaker
   regtest-chaos sketch-gk-proof libspark-ffi"` → `2400/0` (NO `test-fast-pow`;
   it breaks the checkpoint PoW test and must never be in a correctness build).
5. Get **2-of-N** sign-off on the `constants.rs` + `critical_files.lock` change
   (see the audit sign-off doc). Merge only after sign-off.
6. The **testnet activation feature set** is
   `randomx testnet sketch-gk-proof libspark-ffi` — the verifier is now MANDATORY
   in the fleet build (this is the change from today's `randomx testnet`).

## 5. Distribute + verify (the part that prevents the fork)

Run on **every** node in the inventory (seed → fleet → community), via
`deploy/fleet/safe-deploy.sh` (lock + fingerprint preflight) or per-host
`sudo CARGO_FEATURES="randomx testnet sketch-gk-proof libspark-ffi" bash
deploy/ops/roll-fleet.sh` (preserves the chain DB):

1. Stop node → `git pull --ff-only` the activation commit → rebuild with the
   activation feature set → install → restart → wait for RPC.
2. Confirm the running `build_commit` matches the activation commit **and** that
   the binary's `SHIELDED_TESTNET_ACTIVATION_HEIGHT` is the agreed `H` (expose/
   read it; do not trust the fingerprint — §1.2).
3. For community nodes, use `deploy/ops/verify-community-bootstrap.sh` /
   `install-testnet-node.sh` and the community-bootstrap channel to drive upgrades.

**Verification gate (well before `H`, e.g. at `H − lead/2`):** confirm that
**100%** of the inventory reports the activation build. If any node lags, you
still have time to either finish upgrading it or execute §7. Do **not** let the
chain approach `H` with a known laggard.

## 6. Cross the activation height

- At `H`, produce real shielded activity (shield-in → shielded-send → unshield,
  plus subaddress/stealth sends) — "the true result" the audit wants.
- Confirm the mesh stays converged: the seed and fleet agree on the tip across
  `H` (use the ≥3-peer mesh gate; a split shows as diverging tips / a stuck
  peer). Watch for any node that stops advancing at `H − 1` → that is the fork
  signature; that node was not on the activation build.
- Confirm shielded txs mine and are recovered end-to-end on at least two
  independent nodes.

## 7. Abort / rollback

- **Before `H`, laggard found with no time to upgrade it:** ship a push-out
  binary — bump `SHIELDED_TESTNET_ACTIVATION_HEIGHT` to a later `H'`, repeat
  §4–§5 to the whole inventory before the original `H`. (You cannot move `H` on a
  running node; only a new binary changes it.)
- **At/after `H`, an unexpected fork appears:** the forked node(s) were not on
  the activation build. Bring them onto it (§5); they will re-sync the shielded
  chain from the seed. No DB wipe is needed — pre-`H` history is shared.
- **Systemic failure (shielded consensus misbehaves at `H`):** this is why it is
  testnet. Cut a binary that returns `SHIELDED_TESTNET_ACTIVATION_HEIGHT` to
  `u64::MAX` and `redeploy-fleet.sh` (genesis wipe) to relaunch clean, as was
  done for the 2026-10-06 consensus relaunch. Capture the failure for the audit.

## 8. Mainnet safety (invariant, do not weaken)

- Mainnet activation is `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`,
  **unconditional**, and **decoupled** from the testnet knob. Setting `H` on
  testnet cannot arm mainnet.
- `shielded_activation_height(Mainnet)` returning `u64::MAX` is asserted by
  `shielded_activation_mainnet_permanently_off_testnet_is_dedicated_knob`
  (`constants.rs` tests) and the `critical-lock` CI guards `constants.rs` from
  silent change. Do not route mainnet through the testnet knob, ever.

## 9. Post-activation stabilization

- Once the chain has real depth past `H`, re-anchor a recent checkpoint into
  `TESTNET_CHECKPOINT_LIST` (read from the seed, cross-checked against the next
  block's `prev_hash`). NOTE: checkpoints **are** in the consensus fingerprint —
  edit the checkpoint list in BOTH canonical places (issue #173) and roll it as
  its own change, separate from the activation, so the two don't conflate.
- Keep the audit package updated: the activation height, the build feature set,
  and the "live on testnet with real activity" evidence are audit inputs.

---

### Appendix — why the activation is unconditional (not `#[cfg]`-gated)

Regtest and beta gate activation behind `#[cfg(feature = "sketch-gk-proof")]`
because they are disposable, single-operator nets. A persistent *public* network
must activate by **height for every node**, never by build flag — a `#[cfg]` gate
would split the net into "shielded build" vs "production build" permanently.
That is exactly why precondition §2 (verifier in every binary) is mandatory:
unconditional-by-height only works if every node can actually verify at `H`.
