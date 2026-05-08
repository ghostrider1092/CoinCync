# Consensus checkpoint procedure (CIP-009 Path B)

**What this is:** the release-time procedure for refreshing
`CONSENSUS_CHECKPOINTS` in `src/constants.rs` so each release ships
with hardcoded protection against deep reorgs.

**Cadence:** every release. If you cut a release without a checkpoint
refresh, the protection window from the previous release expires
silently — that's the failure mode this procedure prevents.

**Time per refresh:** ~10 minutes once the script is in muscle memory.

---

## Why checkpoints

Per CIP-009 Path B, `CONSENSUS_CHECKPOINTS` is a hardcoded
`(height, block_hash)` table that the validator consults: if a block
proposes a different hash at a known checkpoint height, the validator
rejects the entire block before any expensive verification. A reorg
that tries to rewrite past a checkpoint **structurally cannot
succeed** — every honest node refuses to accept it.

The protection is only as good as the checkpoints are current. If
the table's last entry is at height 50000 and the chain tip is at
500000, only blocks from heights 0-50000 are reorg-protected. From
50000 onward, the reorg defense is back to whatever the next layer
provides (currently: `MIN_OUTPUT_AGE = 100` confirmation requirement
+ social consensus for recovery, per CIP-009 Path C semantics for
the unprotected window).

So: refresh on every release. The lag between checkpoints and
chain-tip is the unprotected reorg window.

---

## The lag

Pick checkpoint heights ~2 weeks behind the chain tip at release
time. Why 2 weeks:

- **Too aggressive (close to tip):** the operator is locking in
  blocks before the community has had time to review them. If a
  bug or attack were to cause a brief re-org of the last few
  blocks, the operator's checkpoint would freeze the WRONG chain.
- **Too conservative (months behind):** the protection window is
  large; recent blocks remain unprotected and a deep-reorg attack
  is feasible up to whatever recent height isn't checkpointed.

Two weeks (~10,080 blocks at 120s) is the standard range from
Bitcoin Cash's experience with this pattern. It gives time for any
legitimate fork to resolve naturally without checkpoint
intervention while still keeping the unprotected window small.

---

## Procedure

### Step 1 — pull the chain tip

```bash
# Replace the API key + endpoint as needed for the release-cutter's
# own node (use a node THEY control, not a public one — a malicious
# RPC could feed a fake chain tip).
curl -s -X POST http://127.0.0.1:28081 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $COINCYNC_RPC_API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
  | jq '.result.height'
```

Note the height as `TIP_HEIGHT`.

### Step 2 — compute the checkpoint target

```
target_height = TIP_HEIGHT - 10_080   # ~2 weeks at 120s blocks
```

Round down to a multiple of 1000 for cleaner numbers (purely
cosmetic).

### Step 3 — query the block hash at target_height

```bash
TARGET=$(echo "(TIP_HEIGHT - 10080) / 1000 * 1000" | bc)

curl -s -X POST http://127.0.0.1:28081 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $COINCYNC_RPC_API_KEY" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_by_height\",\"params\":[$TARGET]}" \
  | jq -r '.result.hash'
```

Output: a 64-character hex string (the block hash).

### Step 4 — append to the table

In `src/constants.rs`, find the per-network `CONSENSUS_CHECKPOINTS`
slice you're updating (mainnet for prod releases, testnet for
testnet-only builds):

```rust
#[cfg(not(feature = "testnet"))]
pub const CONSENSUS_CHECKPOINTS: &[(u64, [u8; 32])] = &[
    // (height, block_hash_bytes)
    // ... existing entries ...
    (175_000, hex!("a1b2c3d4...")),  // ← NEW: 2026-08-15 release
];
```

The `hex!` macro at compile time converts the literal to
`[u8; 32]`. If you don't have the macro, use a verbose form:
```rust
{
    let mut h = [0u8; 32];
    h.copy_from_slice(&hex::decode("a1b2c3d4...").unwrap());
    h
}
```

(But `hex!` from the `hex_literal` crate is cleaner. Add it as a
build-only dep if not already present.)

### Step 5 — verify the test passes

```bash
cargo test --release --lib constants
```

The `test_consensus_checkpoints_are_sorted_ascending` test
catches insertion mistakes (e.g., new entry at lower height than
existing). The `test_expected_checkpoint_hash_lookup` test
exercises the binary-search dispatch.

### Step 6 — refresh the lockfile

`src/constants.rs` is in `critical_files.lock`. Get the new
hash from the build error and update:

```bash
# Build will fail with the new expected/actual hashes printed:
cargo build --release --lib 2>&1 | grep -A 2 "src/constants.rs"
# Replace the entry in critical_files.lock manually (or run the
# update-critical-hashes bin once the bootstrap is sorted):
cargo run --bin update-critical-hashes
```

Commit `critical_files.lock` and `src/constants.rs` together so
the build never sees an inconsistent state.

### Step 7 — git commit

```bash
git add src/constants.rs critical_files.lock
git commit -m "consensus: refresh checkpoints to height $TARGET ($DATE release)"
```

The commit message MUST include the height + date so future
operators can audit "when did this checkpoint get added and to
what release does it correspond."

### Step 8 — verify against a SECOND independently-controlled node

This is the critical anti-attack step. The release operator's own
node could be compromised; if its `get_block_by_height` returns a
fake hash, the entire release ships a fraudulent checkpoint.

Mitigation: cross-check against at least ONE other node not
controlled by the same operator. For CoinCync:

- Query the SAME height at a different fleet box
  (`seed1.coincync.network`, `seed2`, `seed3`).
- Compare hashes.
- They MUST match. If they don't, halt the release and investigate.

```bash
for box in seed1 seed2 seed3 explorer; do
  ssh root@$box "set -a; source /etc/coincync/coincync.env; set +a; \
    curl -s -X POST http://127.0.0.1:28081 \
      -H 'Authorization: Bearer \$COINCYNC_RPC_API_KEY' \
      -H 'Content-Type: application/json' \
      -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_by_height\",\"params\":[$TARGET]}'" \
    | jq -r '.result.hash'
done
```

All four hashes MUST be identical. They will be if the chain is
healthy. If even one differs, the chain is forked or a fleet box
is compromised; investigate before committing.

### Step 9 — sign the release

The compiled binary that ships with the new checkpoint should be
signed by the project release key. This is the standard release
signing for any binary; no checkpoint-specific extra step. But
recipients of the binary trust the checkpoint via the binary
signature: verify the signature, run the binary, the binary's
hardcoded checkpoints become the user's reorg defense.

---

## Failure modes and their handling

### A checkpoint mismatched the eventual canonical chain

i.e., the operator picked a hash at height H, but a legitimate
fork later resolved with a DIFFERENT hash as the canonical chain
at height H. The operator's checkpoint would now reject the
canonical chain.

- **Detection:** community report ("my node won't sync past
  height H").
- **Recovery:** ship a release with the bad checkpoint REMOVED
  (not changed). Removal is allowed: the corresponding height
  reverts to "no checkpoint" status, and the validator accepts
  any block hash there.
- **Postmortem:** the 2-week lag should make this nearly
  impossible. If it happens, increase the lag to 4 weeks for
  subsequent releases.

### A release shipped with no checkpoint refresh

i.e., the operator forgot Step 4. The previous release's
checkpoints are still valid but the protection window from the
new release expires N weeks earlier than it should.

- **Detection:** annual end-to-end-test of the failover (which
  this doc should add — TODO).
- **Recovery:** ship a hotfix with the missing checkpoints. No
  consensus break; just restoration of protection.

### A coordinated 51% attack rewrites past the latest checkpoint

i.e., the attacker has hashpower to outpace the network from
checkpoint height + N onward.

- **Detection:** chain split; honest nodes are on one chain,
  attacker is on another. Fee operators will see this in their
  monitoring.
- **Recovery:** emergency release with a NEW checkpoint at the
  height of the most-recent-confirmed-honest block. Wallets and
  exchanges must upgrade to the new release before resuming
  high-value confirmations.
- **Prevention:** this is the limit of CIP-009 Path B's
  protection. Path A (MESS) on top of Path B would push the
  attacker's cost much higher; that's the v1.1+ upgrade path.

---

## Audit checklist for each refresh

Before committing, the operator confirms:

- [ ] `TARGET = TIP_HEIGHT - 10_080` (or older — never closer to tip).
- [ ] Block hash at `TARGET` was queried from a node the operator
      DIRECTLY controls.
- [ ] At least 1 other independent node was cross-checked and
      returned the same hash.
- [ ] The new entry is appended at the END of the slice (highest
      height last).
- [ ] `cargo test --release --lib constants` passes.
- [ ] `critical_files.lock` was refreshed in the same commit.
- [ ] Commit message includes both the height and the release
      date.

This list lives in this doc, not in PR templates, so it doesn't
get out of sync with reality. Update it here when the procedure
changes.
