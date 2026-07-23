# Incident response runbooks

When something is broken on the testnet (or post-launch, mainnet),
the difference between a 5-minute incident and a 5-hour one is
whether you have a runbook. These are captured from the actual
testnet bring-up in 2026-04 / 2026-05 — every entry below is
something we hit, fixed, and want to recognize faster next time.

Keep this file as the single source of truth for "the chain is
broken, what now." When you hit a new failure mode, add it here.

---

## How to use this doc

Each runbook has:

- **Symptom** — what you see first
- **Likely causes** — what tends to actually be wrong
- **Diagnose** — commands to confirm
- **Fix** — what to do
- **Why it happens** — short, so the next person learns

Search for a symptom (`Ctrl+F "stalled tip"`); read the matching
runbook; act. Do not improvise; you'll re-discover the same wrong
fix the previous incident already disproved.

---

## Runbook 1 — Chain stalled, tip not advancing

### Symptom

`get_info.height` is the same on every fleet box for >10 minutes,
and the value is identical to the value 10 minutes ago. No new
blocks.

### Likely causes (in order of probability)

1. **Mempool is empty AND no miner is producing.** The fleet's
   `coincync-rig` instance died or is stuck.
2. **Mempool has a poisoning tx that gets included in every block
   template, then the block is rejected at validation time.** This
   is the failure mode Bug #8 caused on 2026-05-07.
3. **One peer is feeding empty-Blocks responses, wedging IBD-style
   sync.** Bug #2 from the 2026-05-04 explorer wedge.
4. **Chain DB corruption.** Rare; usually shows up as a panic in
   the journal log, not a silent stall.

### Diagnose

```bash
# On every fleet box:
ssh seed1 'systemctl status coincync-node coincync-rig'
ssh seed1 'journalctl -u coincync-node -n 50 --no-pager'

# Check chain head consistency:
for h in seed1 seed2 seed3 explorer api; do
    ssh $h 'curl -s http://localhost:28081/get_info | jq .height'
done

# Check mempool:
ssh seed1 'curl -s http://localhost:28081/get_tx_pool | jq .count'

# Look for stuck blocks:
ssh seed1 'journalctl -u coincync-node | grep -i "block.*reject" | tail -20'
```

### Fix

If the fleet shows uniform height (everyone agrees on the tip):

- **Cause 1 fix:** restart `coincync-rig` on the box that's
  configured to mine. `systemctl restart coincync-rig`. Verify
  it's making progress: `journalctl -u coincync-rig -f`.
- **Cause 2 fix:** clear the mempool of the poisoning tx.
  Identify the bad tx hash from the rejection log, then:
  `curl -X POST http://localhost:28081/admin/mempool/evict
   -d '{"tx_hash":"<hash>"}'`. If you don't have an admin
  endpoint, restart the node — mempool is in-memory.

If fleet shows DIFFERENT heights (split-brain):

- **Cause 3 fix:** identify the bad peer feeding the slowest box.
  `journalctl | grep "Empty Blocks" | tail -20`. Restart the
  affected node — Bug #2's fix (commit `28b3420`) will then
  ban the bad peer for 1h.

### Why it happens

PoW chains stall when no valid block can be produced. The
"poisoning tx" case is the subtle one: the mempool is supposed to
prune txs that conflict with the chain, but if it doesn't (Bug #8),
every miner picks up the same bad tx and every block they make is
rejected. The 2-pass shadow eviction in `Mempool::remove_confirmed`
is the fix.

---

## Runbook 2 — One fleet box is far behind the others

### Symptom

Four fleet boxes report height N. The fifth reports height N - K
(K = 5 to thousands).

### Likely causes

1. The slow box has a peer feeding it empty-Blocks responses
   (the same Bug #2 wedge as Runbook 1, scoped to one box).
2. The slow box's connection to the other fleet boxes is
   broken (firewall, ISP routing).
3. The slow box's chain DB was corrupted; it's stuck applying
   an invalid block.

### Diagnose

```bash
# On the lagging box:
ssh <box> 'curl -s http://localhost:28081/get_peers | jq '\''.peers | map({addr, last_block_at, last_active_at})'\'' | head -50'

# Look for "stall_max" in the soak summary:
ssh <box> 'journalctl -u coincync-soak | grep stall_max'

# Check connection to fleet:
ssh <box> 'for s in seed1 seed2 seed3; do nc -zv $s 28080; done'
```

### Fix

For cause 1: `systemctl restart coincync-node` on the lagging box.
The bad peer is forgotten; sync resumes.

For cause 2: fix the network connection. Check fleet IPs in
`/etc/coincync/coincync.env` (BOOTSTRAP_PEERS), check provider
firewall (Vultr cloud firewall, Cloudflare proxy if applicable),
check hosting status pages.

For cause 3: very rare; logs will show a panic. Last-resort fix:
delete `~/.coincync/chain` and re-sync from scratch. **Do NOT use
`scripts/redeploy-fleet.sh`** — it nukes chain state across the
fleet. Single-box recovery is safer.

### Why it happens

The fleet is geographically distributed (NJ, Amsterdam, Tokyo,
Dallas, Frankfurt) which provides redundancy but exposes the
network to single-region issues. The is_synced fix (commit
`dce6653`) helps tolerate 1-2 block tip differences but doesn't
solve "this box is 1000 blocks behind" — that's always a real
issue.

---

## Runbook 3 — User reports "Insufficient balance: have 0" but
they have UTXOs

### Symptom

A user, especially a faucet recipient, reports their wallet says
"have 0" when they know they have CYNC.

### Likely causes

1. **UTXOs exist but aren't yet mature.** The wallet correctly
   distinguishes this from "no balance" via
   `Error::BalancePendingMaturity` (added in commit `fd5a444`),
   but only if the wallet binary is current.
2. **Wallet didn't scan recent blocks.** The wallet's
   `last_scanned_height` is stale. Could be a fresh wallet
   that hasn't run `scan` yet, OR a returning user whose
   auto-resume scan missed a range (Bug #5; fixed in `fd5a444`).
3. **Wallet is on the wrong network.** They're trying to spend
   testnet coins from a wallet built against mainnet (or vice
   versa). The address prefix should fail this earlier, but if
   they've used `--unsafe-cross-network`, here we are.

### Diagnose

```bash
# Have the user run, in their wallet directory:
coincync-wallet info

# Look for:
#  - "Total balance" vs "Spendable balance" (V should differ if
#    immature UTXOs are present)
#  - "Last scanned height" (should be near chain tip)
#  - "Network" field
```

### Fix

For cause 1: tell them to wait `MIN_OUTPUT_AGE` blocks (~10 at
2 minutes each = ~20 minutes). The recent error message includes
this in plain language; if they're seeing "Insufficient balance:
have 0" and not "Balance pending maturity," they're on a stale
wallet — direct them to upgrade.

For cause 2: `coincync-wallet scan --from <last_scanned_height -
20>` (the auto-resume backstop is 20 blocks; this matches it
manually). This will re-detect any missed UTXOs.

For cause 3: ask them to check the wallet's network field. If
it's mainnet on testnet, they're using a testnet faucet drip
against the wrong wallet. They need to download a testnet wallet.

### Why it happens

The bug history here is rich. Version mismatch in the wallet
binary, save-ordering races in the persistence layer, and the
`have 0` UX panic are all real failure modes that hit during
testnet bring-up. Each is fixed in the current code.

---

## Runbook 4 — Faucet is dripping but recipients can't spend

### Symptom

User reports: faucet says "drip sent: 10 CYNC, tx: <hash>". User's
wallet eventually shows the balance. User tries to send 1 CYNC
elsewhere. Send fails with `InsufficientInputs` or similar.

### Likely cause

The user has only ONE UTXO from the faucet drip. CoinCync's uniform
2-in/2-out tx shape requires the sender to have at least two UTXOs
to build any tx. A single faucet drip with `--split-output` puts
2 outputs in the recipient wallet, allowing them to send. Without
`--split-output`, they have 1 UTXO and can't transact.

This is Bug #6 from KNOWN_ISSUES, fixed in `9b83772`. The faucet
config should be passing `--split-output` to every drip.

### Diagnose

```bash
# On the faucet box, check the install:
grep split-output /etc/systemd/system/coincync-faucet.service \
    /usr/local/bin/coincync-faucet

# Also check the faucet's command-line invocation:
journalctl -u coincync-faucet | grep -i "wallet send" | tail -5
```

### Fix

If `--split-output` is missing from the faucet's wallet-send
invocation: add it. The proper installation is captured in
`scripts/install-faucet.sh` — re-running that gets the config
right. After update: `systemctl restart coincync-faucet`.

If the user's recipient wallet is an OLD version that doesn't
understand split-output drips correctly: have them upgrade their
wallet.

### Why it happens

The 2-in/2-out uniform shape is a privacy property — every tx
on chain looks the same. The cost is that the absolute minimum
state transition (1 UTXO → 1 UTXO) is impossible. Faucets are
the only realistic case where someone gets a single output;
the `--split-output` flag is the workaround.

---

## Runbook 5 — Discord webhook is silent or posting wrong content

### Symptom

Either:
- Self-check / soak / weekly-review jobs ran successfully, but
  no Discord post.
- Discord posts contain wrong content (e.g., post claims height N
  but `get_info` shows N + 100).
- Discord posts contain content from the wrong fleet box (e.g.,
  api box's results show up under explorer's name).

### Likely cause

1. The webhook URL has been rotated (manually, or after a leak),
   but `/etc/coincync/discord.env` on the affected box wasn't
   updated.
2. `discord.env` is missing on the box (file permissions changed
   accidentally, or the box was redeployed without including it).
3. The cron / systemd timer is calling the script with the wrong
   environment loaded.

### Diagnose

```bash
# On the affected box:
cat /etc/coincync/discord.env  # should have DISCORD_WEBHOOK=...
ls -la /etc/coincync/discord.env  # should be 0600 root:root

# Test the webhook directly:
. /etc/coincync/discord.env
curl -X POST "$DISCORD_WEBHOOK" \
    -H 'Content-Type: application/json' \
    -d '{"content":"runbook test from <box>"}'

# Check the script's env-loading:
grep -E "EnvironmentFile|source.*\.env" \
    /etc/systemd/system/coincync-selfcheck.service \
    /etc/systemd/system/coincync-soak.service
```

### Fix

For cause 1: write the new webhook URL into `discord.env` at mode
0600, root-only. Restart the relevant service.

For cause 2: re-run `scripts/install-fleet-monitoring.sh` (or
manually create the file as in the install script).

For cause 3: confirm the systemd unit file lists both
`/etc/coincync/coincync.env` AND `/etc/coincync/discord.env`
in `EnvironmentFile=` directives, with `discord.env` SECOND so
its values override.

### Why it happens

Bug ops #2 (fixed in `fd5a444`) split the webhook URL out of
`coincync.env` (mode 0640) into `discord.env` (mode 0600) so the
webhook isn't readable by group members of `coincync.env`. The
cost is one more file to maintain consistently across the fleet.

---

## Runbook 6 — Mempool is full and txs are being rejected as "fee too low"

### Symptom

A user submits a tx; node returns `mempool full, fee below
minimum-replace threshold`. Mempool stats show `count` near the
configured maximum.

### Likely causes

1. **Real spike in tx volume.** Someone is genuinely flooding,
   or an integration partner is testing under load.
2. **Stuck dust txs.** Lots of low-fee txs that aren't being
   confirmed because there's a higher-fee competitor, but
   they're not expiring fast enough.
3. **Mempool bug.** Some entry isn't being evicted on confirmation
   (Bug #8 was an instance of this; should be fixed).

### Diagnose

```bash
# Check mempool stats:
curl -s http://localhost:28081/get_mempool_info | jq

# Look at fee distribution:
curl -s http://localhost:28081/get_tx_pool | jq '.txs | map(.fee_per_byte) | sort'

# Look at the oldest entries:
curl -s http://localhost:28081/get_tx_pool | jq '.txs | sort_by(.added_at) | .[0:10]'
```

### Fix

For cause 1: nothing to do; the network is just busy. Users with
low-fee txs need to wait or rebroadcast with higher fees. Faucets
should bump their fee tier.

For cause 2: check if the expiry timer is firing.
`journalctl -u coincync-node | grep -i "mempool.*expire" | tail`.
If not, restart the node — mempool is in-memory.

For cause 3: file an issue, capture the mempool snapshot via
`get_tx_pool`, identify which tx isn't being evicted on
confirmation. The evict reason should appear in the audit log
(`EvictReason::Confirmed` or `::DoubleSpend` etc).

### Why it happens

A privacy-coin's mempool sees more pressure than a transparent
chain at the same throughput because every tx is the same size
(uniform shape). A spike of 1000 txs at 100% identical sizing
fills the mempool faster than it would on Bitcoin where size
varies by 10×.

---

## Runbook 7 — Explorer shows stale block height

### Symptom

`https://explorer.coincync.network` shows a chain height that
doesn't match what the seeds report.

### Likely causes

1. The explorer node is behind on sync (Runbook 2).
2. The explorer's web UI is caching the response (CDN edge,
   browser).
3. The explorer's RPC is broken; the UI is showing the last
   successful response.

### Diagnose

```bash
# Direct to the explorer node:
curl -s https://explorer.coincync.network/api/get_info | jq .height

# Compare to seeds:
for h in seed1 seed2 seed3; do
    ssh $h 'curl -s http://localhost:28081/get_info | jq .height'
done

# Check the web frontend's cache headers:
curl -I https://explorer.coincync.network/api/get_info
```

### Fix

For cause 1: same as Runbook 2.

For cause 2: explorer JS frontend should never cache, but if
Cloudflare is in front of the API, ensure the
`/api/get_info` path is rule-set to `Cache-Control: no-store`.
Purge the Cloudflare cache for that path.

For cause 3: restart the explorer's RPC service. Look at
`journalctl -u coincync-explorer` for clues.

### Why it happens

The explorer is the primary public-facing health signal for the
network. A stale read here looks like the network is broken even
when it's fine. Every layer (explorer node sync, RPC, frontend,
CDN cache) has its own staleness mode; isolate from outermost
to innermost.

---

## Runbook 8 — Critical files integrity check fails on build

### Symptom

`cargo build` fails with:

```
CRITICAL FILE INTEGRITY CHECK FAILED
The following files do not match their locked hashes:
  CHANGED: src/constants.rs
    expected: <old-hash>
    actual:   <new-hash>
```

### Likely cause

You modified a consensus-critical file and need to refresh the
lockfile.

### Diagnose

```bash
git diff src/constants.rs       # what changed?
git diff src/consensus/         # what else?
```

### Fix

Two paths:

**Path A — the change is intentional (e.g., editing a doc comment):**

1. Verify the change is what you expected.
2. Update `critical_files.lock` directly: replace the old hash with
   the `actual` hash from the build error.
3. Rebuild. Should succeed.

OR (preferred for non-trivial changes):

1. Revert `critical_files.lock` to its pre-edit state.
2. Run `COINCYNC_REGEN_LOCK=1 cargo run --locked --release --bin update-critical-hashes`. The
   binary fails-to-build because of the integrity check; you'll
   need to bypass it by manually patching the hash in `.lock`
   first (Path A), then run the binary as a sanity check.

**Path B — the change is unintentional (you didn't mean to touch
this file):**

1. `git diff <file>` to confirm the change is unwanted.
2. `git checkout -- <file>` to revert.
3. Rebuild. Should succeed.

### Why it happens

The integrity check is the project's first-line defense against
"someone slips an unreviewed consensus rule into a PR." Every
build verifies that consensus-critical files match the
committed lockfile. Updating the lock is intentional, deliberate,
and reviewed; the system is working as designed when this check
fires.

---

## Runbook 9 — Build fails with bulletproofs+ "recursion limit"
errors

### Symptom

`cargo build` shows transient errors involving `bulletproofs`,
`tari_bulletproofs_plus`, or "recursion limit reached" deep in
the dependency graph.

### Likely cause

Stale incremental compilation cache for the `coincync` crate
itself. Bulletproofs+ uses heavy generic recursion that incremental
builds occasionally fail to resolve.

### Fix

```bash
cargo clean -p coincync
cargo build --release
```

That's it. The `coincync` crate's incremental cache is the only
thing affected; all other dependencies stay built.

### Why it happens

Bulletproofs+ generates large amounts of monomorphized code via
nested generics. Incremental compilation tracks per-function
dependency graphs; sometimes this tracker gets confused by the
size of the bulletproofs+ generic instantiations and emits
recursion errors that don't reflect the actual code. Clean +
rebuild fixes it.

---

## Adding new runbooks

When you encounter a new failure mode:

1. Write the symptom EXACTLY as you saw it. The first line of
   the runbook is what someone Ctrl-Fs for next time.
2. Capture the diagnose commands you actually used (not "good
   ones to try" — the ones that worked).
3. Document the fix that worked. If multiple fixes worked,
   document each with conditions.
4. Add the "why it happens" so the next maintainer learns.
5. Commit, with a message like `runbook: <symptom>`.

The runbook list grows with operational maturity. By mainnet,
every realistic failure mode should have an entry here.
