# Known issues — testnet 2026-05-07

Issues surfaced during the smoke-testing run that built up to the public
testnet launch on 2026-05-11. The ones marked **FIXED** shipped in
commit `9b83772` and were end-to-end verified on the live testnet at
heights 4880–4906. The ones marked **OPEN** are minor UX bugs that do
not block launch but are worth tracking.

For the architectural reasoning on each fix, see the long-form commit
message on `9b83772`. This file is a quick triage view.

---

## FIXED in commit 9b83772

### Bug #1 — `InsufficientInputs` error message was misleading

`Error::InsufficientInputs { have, need }` mixed two different failure
modes into a single message that read like a count problem when the
real issue was an amount problem. Replaced with the targeted
`Error::NoUtxoPairCovers { target, utxo_count, total, largest_pair,
max_safe }` which tells the user exactly what's wrong and the largest
amount they could send right now.

### Bug #2 — `select_utxos_uniform` missed valid pairs

Single-pass two-pointer sweep collapsed `hi` permanently when a
covering pair was found, locking `lo` at the largest UTXO and missing
optimal pairs that didn't include it. With UTXOs `[100, 80, 60, 40]`
and target 90, the optimal `(60, 40)` pair (excess 10) was unreachable
— only `(100, X)` variants got tried. Replaced with a full
`O(n^2)` double-loop. Worst case is `n^2` but `n` is per-wallet UTXO
count (typically a few hundred at most) — correctness wins.

### Bug #3 — Wallet's scan didn't detect spent UTXOs from confirmed inputs

`scan_block` only returned outputs the wallet owned (received). Nothing
iterated tx inputs to mark our UTXOs as spent when they appeared as
ring-signed inputs in confirmed txs. Result: a UTXO that was spent on
chain — by a previous wallet invocation, by another wallet sharing the
seed, or by a tx whose post-submit `mark_spent` call never persisted —
stayed `available` in the local view forever. Wallet then re-selected
it and the new tx was rejected for `Duplicate key image: key image
already spent in chain`. Stalled the testnet at heights 4885–4887 for
>10 minutes on 2026-05-07.

Fix: `cmd_scan` now iterates every block tx's input key images and
calls `wallet.mark_spent_by_key_image` for each. Cheap (input key
images are public, no decryption); no-op if the key image isn't ours.

### Bug #6 — First-time faucet recipients couldn't spend their drip

Uniform 2-in/2-out tx shape requires the *sender* to have 2 UTXOs to
build any tx. A standard faucet drip puts ONE output in the recipient's
wallet, so a first-time user couldn't spend until they received a
second payment. Every new-user-claims-from-faucet flow hit this.

Fix: `--split-output` flag on `coincync-wallet send` splits the amount
into 2 outputs to the same recipient (different stealth addresses,
same destination keys, no change output, excess input goes to fee).
Uniform shape preserved — the resulting tx is structurally
indistinguishable from a recipient+change tx to chain analysts (same
size, same input/output count, same ring sigs). Verified by
`verify-privacy.ps1` returning all-PASS on a real drip-pair tx on the
testnet (`fb88ffa1...`).

The recipient ends up with 2 UTXOs and can immediately spend (verified
by tx `672f049e...` at block 4906 — recipient sent 1 CYNC to a final
wallet successfully).

### Bug #8 — Mempool kept conflicting txs after the chain ate them

`Mempool::remove_confirmed` only dropped the exact tx hashes that
mined; it did NOT walk those txs' key images to find OTHER mempool txs
spending the same UTXOs. A "shadow" tx — admitted to mempool, then
beaten to confirmation by a peer's tx spending the same UTXO — would
sit in mempool forever (or until the 9.6h expiry timer), and every
block template including it would be rejected at consensus time for
`Duplicate key image`. This is what stalled the testnet a second time
on 2026-05-07.

Fix: `remove_confirmed` now does a 2-pass cleanup. Pass 1 drops
confirmed txs (existing). Pass 2 walks each confirmed tx's key images
and evicts any other mempool tx using them, with new
`EvictReason::DoubleSpend` and an info log line. Bitcoin Core
(`CTxMemPool::removeForBlock`) and Monero
(`tx_pool::on_blockchain_inc`) both do the same shadow eviction;
CoinCync missed it on the initial port.

### Bug ops #1 — Faucet daemon couldn't reach the local auth-gated RPC

The `coincync-faucet.service` systemd unit only loaded
`/etc/coincync/faucet.env`, which doesn't carry `COINCYNC_RPC_API_KEY`.
The wallet subprocess inherits the parent's env and so couldn't
authenticate against the local node — every drip request failed with
`wallet subprocess exited 1` and a 401 in the wallet's stderr (which
the faucet was swallowing).

Fix: `scripts/install-faucet.sh` now writes `EnvironmentFile=
/etc/coincync/coincync.env` *before* the faucet env so the API key
flows through. Already-deployed boxes were patched manually; this fix
ensures any redeploy keeps the change.

### Test #1 — Stale CDN reference broke `explorer_html_lists_external_cdns`

The test was a positive-enumeration of external origins the embedded
explorer fetches from. After the explorer was vendored out of jsdelivr
in an earlier pass, the test entry wasn't removed and started failing
(asserting a CDN reference that no longer existed). Removed the stale
entry.

---

## OPEN — needs proper activation, not a one-line change

### Bump #1 — `BOOTSTRAP_MIN_RING_SIZE` should rise from 11 to 13

The 2026-05-07 senior-review pass flagged ring=11 during bootstrap as
a measurable privacy reduction (1/11 ≈ 9% per-input traceability vs
1/16 = 6.25% post-bootstrap). The chain has had >100 unique outputs
since block ~30; ring=13 is comfortable from then on. Marketing
language and the `verify-privacy.ps1` heuristic both expect this.

**Why it isn't a one-line change:** `BOOTSTRAP_MIN_RING_SIZE` is
referenced in `src/consensus/validation.rs:1582` as a CONSENSUS RULE,
not a wallet preference. Raising the constant today would invalidate
every existing testnet tx with ring=11, fork the chain, and break
sync for every connected node. Doing it correctly requires a proper
activation:

- `BOOTSTRAP_MIN_RING_SIZE_V2: usize = 13`
- `RING_BUMP_ACTIVATION_HEIGHT: u64 = <future_height>`
- `validate_transaction` checks ring >= V1 before activation, ring >= V2 at and after.
- Wallets after activation build with ring >= 13.
- Pre-activation txs remain valid forever.

This is a coordinated upgrade. Schedule it for a planned hard fork
(post-launch — testnet activation height ~10000, mainnet activation
height set at mainnet launch). Don't ship as a hotfix.

## OPEN — UX issues, not launch-blocking

### Bug #4 — `Insufficient balance: have 0` when balance exists but isn't mature

The wallet's send path reports `Insufficient balance: have 0, need X`
when the wallet has UTXOs but they haven't reached
`MIN_OUTPUT_AGE` (10 confirmations) yet. The user reads "have 0" and
panics; the real situation is "balance not yet spendable, wait N
blocks".

Fix sketch (post-launch): make the `InsufficientBalance` error
distinguish *unconfirmed/immature balance* from *no balance*. If the
wallet has UTXOs that exist but are too young, report something like
"Balance pending maturity: X atomic across Y UTXOs, earliest spendable
in Z blocks" instead.

### Bug #5 — Wallet's auto-resume scan can miss outputs

Observed during testnet bring-up: a scan invocation without an
explicit `--from` would advance `last_scanned_height` to the chain tip
but report `Found outputs: 0` for ranges where outputs definitely
existed (verified by re-scanning with `--from <earlier>` and finding
them). Workaround: always pass `--from N` for some `N` a few blocks
behind the actual cursor.

This isn't fully understood. Possibilities:
1. Scanner re-uses a stale view-secret derivation across calls.
2. `last_scanned_height` is advanced past a block the scanner exited
   early on.
3. A race between `set_scanned_height` and persistence.

Need to reproduce with verbose tracing and a known good test wallet,
then track down. Workaround makes this non-blocking for launch.

### Bug #7 — `scripts/test-tx-propagation.ps1` has a PowerShell parser error

The script throws `Unexpected token 'root@$($n.IP)" "bash'` on lines
that try to do `& ssh -i $KeyPath ... "root@$($n.IP)" "bash
/tmp/probe.sh"`. The interpolation form is being parsed as multiple
broken expressions. Either the file has a stray quote that doesn't
show in plain reads, or PS 5.1 needs the call wrapped differently.

Workaround for launch: confirm tx propagation by querying each fleet
box's `get_info` for `mempool_size` directly, which is what the script
does internally but cleaner. Real fix: rewrite the script using
`Start-ThreadJob` per host instead of inline interpolation in the
ssh command line.

### Bug ops #2 — Discord webhook leaked in plaintext on the api box

`/etc/coincync/coincync.env` on the api box contains the Discord
webhook URL in plaintext at file mode 0640. If that file is ever
backed up, snapshotted, or accidentally committed, the webhook is
owned and an attacker can post arbitrary content to the channel. Not
exploitable today, but a real risk worth eliminating.

Fix: rotate the webhook URL, move the URL into a separately-permissioned
file (e.g. `/etc/coincync/discord.env`, root-only mode 0600) sourced
only by the services that actually post to Discord.

---

## How issues get tracked going forward

Once `git.coincync.network` is live (post-launch), these become Forgejo
issues with reproduction steps and acceptance criteria. Until then,
this file is the canonical view. Anything that surfaces during the
public testnet between 2026-05-11 and Forgejo coming up gets appended
to this list and flagged in the next dev log.
