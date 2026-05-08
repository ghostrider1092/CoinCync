# Known issues — testnet 2026-05-07

Issues surfaced during the smoke-testing run that built up to the public
testnet launch on 2026-05-11. Most have been fixed across two rounds of
triage; what remains is a single planned hard-fork (ring bump, scheduled
post-launch) and one operational tradeoff (faucet drip-pair fee
fingerprint, testnet-only).

- Round 1 — commit `9b83772` — bugs #1, #2, #3, #6, #8, ops #1, test #1.
  End-to-end verified on the live testnet at heights 4880-4906.
- Round 2 — commit `fd5a444` — bugs #4, #5, #7, ops #2.

For the architectural reasoning on each fix, see the long-form commit
message on the corresponding hash. This file is a quick triage view.

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

## FIXED in commit fd5a444

### Bug #4 — `Insufficient balance: have 0` when balance exists but isn't mature

The wallet returned `InsufficientBalance` whenever the SPENDABLE
balance (UTXOs past `MIN_OUTPUT_AGE`) was below the target — even when
the wallet's TOTAL balance covered the target but some UTXOs weren't
mature yet. Users saw "have 0" and panicked.

Fix: new `Error::BalancePendingMaturity { spendable_atomic,
pending_atomic, pending_utxos, need_atomic, blocks_to_wait,
seconds_to_wait }` variant. The send path
(`create_privacy_transaction_with_fee`, used by both the CLI and
`SharedWallet::create_transfer`) now checks `balance.total() >= need`
before falling through to `InsufficientBalance`: if the wallet has it
but it's not mature, the error surfaces that explicitly with a wait
estimate. Bound is the youngest-pending-UTXO height plus
`MIN_OUTPUT_AGE` — pessimistic; partial coverage might mature earlier.

### Bug #5 — Wallet's auto-resume scan can miss outputs

Root cause: `Wallet::save()` was writing the wallet header (which
carries `scanned_height`) BEFORE the UTXO sidecar. A crash or kill
between those two writes left the wallet thinking it had scanned
through height N while the UTXOs found in those blocks were never
persisted — they'd be silently absent on next launch.

Fix part 1: reorder `save()` to write `utxos -> history -> wallet`.
Worst-case failure mode now: `scanned_height` stays old, UTXOs found in
the partial scan are preserved, next scan re-detects them and replaces
them in the sidecar (idempotent, keyed by `(tx_hash, output_index)`).

Fix part 2 (defensive backstop): `cmd_scan` resumes from
`scanned_height.saturating_sub(SCAN_BACKSTOP_BLOCKS)` (= 20) when no
explicit `--from` is provided. Re-scanning is idempotent; cost is a
few RPC calls. Catches state divergence from any other path (parallel
scans, hand-edited wallet files, OS crashes, FS hiccups), not just the
save-ordering case.

Verified live on the api box: auto-resume now starts at
`scanned_height - 20` and re-detects outputs correctly.

### Bug #7 — `scripts/test-tx-propagation.ps1` PowerShell parser error

Root cause was non-ASCII characters (em-dashes on lines 3/143/148, a
UTF-8 checkmark on line 90) without a UTF-8 BOM. PowerShell 5.1 reads
BOM-less files as the system code page (Windows-1252 on Windows), so
multi-byte UTF-8 sequences were tokenized as garbage and the parser
reported errors at lines that looked syntactically fine — pointing
several lines away from the real cause.

Fix: ASCII-ify the script (em-dash -> "--", checkmark -> "OK"), and
extract the ssh target host into a `$sshHost` variable so the parser
doesn't trip on inline `$($n.IP)` interpolation inside an
already-quoted argument. Plus a docstring note documenting the
PS5.1-vs-UTF8 trap so the next maintainer doesn't burn an hour on it.

### Bug ops #2 — Discord webhook URL leaked in `/etc/coincync/coincync.env`

`coincync.env` was mode 0640 (group-readable) on the fleet boxes.
Webhook URLs are credentials — anyone with read access to the file
owns the channel post permission until the webhook is rotated. Not
exploitable across the network today (file is local to root-owned
services) but a backup or accidental share would leak it.

Fix: separate file `/etc/coincync/discord.env` (mode 0600, root-only).
The three fleet scripts that need the webhook (`coincync-selfcheck.sh`,
`coincync-soak.sh`, `coincync-weekly-review.sh`) source `coincync.env`
first then `discord.env`, so values in `discord.env` override.

**Operator action still required:** rotate the webhook URL in the
Discord UI (delete + recreate). The rotation is the one part of the
operation only the operator can do; the file-permission fix is
shipped, but the existing URL was at 0640 for a few days and should
be treated as compromised until rotated.

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

## OPEN — testnet operational cost, no mainnet impact

### Operational #1 — Faucet drip-pair fee fingerprint

Each faucet drip uses `--split-output` (the Bug #6 fix from
`9b83772`) to produce 2 outputs to the recipient in one tx, so a
first-time user gets 2 UTXOs and can immediately spend. The cost:
input excess goes to fee. With the faucet's current ~30 CYNC UTXOs
and a 10 CYNC drip, fee = ~89.7 CYNC per drip. Chain analysts can
flag every drip-pair tx by anomalous fee size.

**Why it's not fixed in this round:** the proper fix is two
sequential normal-shape sends per drip (each 2-in/2-out, normal
fee). That requires the faucet to have ≥4 mature UTXOs at all
times — but uniform 2-in/2-out tx shape *preserves* UTXO count
across every tx. The faucet has no way to split a single 30 CYNC
UTXO into multiple smaller ones without breaking uniform shape, so
inventory has to be built up by repeatedly funding from a source
wallet that ALSO has small UTXOs. That cascades back to the user's
local wallet, the mining rig's coinbase outputs, etc. — a deep
ecosystem refactor.

**Why it's acceptable for now:** testnet only. The fee is paid by
the testnet operator (whose miner is on the same fleet, so most
of the burned fee comes back as block reward). No mainnet faucet
is planned; mainstream wallets will receive funds from real users,
not from a single fee-leaky service. The privacy fingerprint
matters chain-wide only if many wallets receive their first
funds from the testnet faucet, and even then only on testnet.

**What WOULD fix it:** see Item 3 in the senior-review plan. Either
(a) maintain a right-sized UTXO pool throughout the funding chain
(user wallet → faucet wallet → recipient wallet), or (b) wait for
a constitutional change loosening uniform shape for service-tier
txs (similar to coinbase carve-outs). Option (a) needs ~1 day of
work; option (b) needs a CIP and hard fork.

---

## How issues get tracked going forward

Once `git.coincync.network` is live (post-launch), these become Forgejo
issues with reproduction steps and acceptance criteria. Until then,
this file is the canonical view. Anything that surfaces during the
public testnet between 2026-05-11 and Forgejo coming up gets appended
to this list and flagged in the next dev log.
