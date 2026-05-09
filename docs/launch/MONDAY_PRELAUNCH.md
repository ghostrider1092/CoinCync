# Monday-morning pre-launch checklist

**Run this 30 minutes before posting the first announcement.**

If everything is green, you're cleared to post. If anything is red, fix
it first or post anyway and own the gap publicly — but know what you're
shipping.

This file is intentionally short and copy-paste-friendly; if you're
already in front of a laptop the morning of launch, you don't want to
read prose.

---

## 0. Set up a single PowerShell window with the project loaded

```powershell
cd "C:\Users\unkno\OneDrive\coincync 1.0"
```

Keep the same window open through the whole run. Each section below is
one command you paste, eyeball the output, and move on.

---

## 1. Network — fleet healthy + chain advancing

```powershell
$tip = (Invoke-WebRequest -Uri "https://api.coincync.network/rpc/testnet" `
  -Method POST -Body '{"jsonrpc":"2.0","id":1,"method":"get_info"}' `
  -ContentType 'application/json' -TimeoutSec 8 -UseBasicParsing).Content `
  | ConvertFrom-Json
"  height={0}  tip_age={1}s  difficulty={2}  mempool={3}  peers={4}" -f `
  $tip.result.height, $tip.result.tip_age_secs, $tip.result.difficulty, `
  $tip.result.mempool_size, $tip.result.peer_count
```

✅ Pass when:

- `height` increasing run-to-run (re-run after 2 minutes; should advance)
- `tip_age_secs < 600` (block landed within 10 minutes; longer is OK at low
  hashrate but worth a heads-up to community)
- `peer_count >= 8`

🔴 If `tip_age_secs > 1800` (30+ min): chain is too slow. Mine on a fleet
box (`scripts/coincync-soak.sh` style burst) or post on Discord first
warning users to expect lag.

---

## 2. Faucet — capacity + drip works

```powershell
# 1) capacity check
$stats = (Invoke-WebRequest -Uri "https://api.coincync.network/faucet/stats" `
  -TimeoutSec 8 -UseBasicParsing).Content | ConvertFrom-Json
"  drips_today={0}  last_drip={1}  drip_amount={2} atomic" -f `
  $stats.total_drips, $stats.last_drip_ts, $stats.drip_amount_atomic

# 2) one drip from a fresh test address (different from any prior test
#    so the per-address rate-limit doesn't trigger)
$ADDR = "tCYNC3ZGvevYahmapH24ZkiKudimf5p5MZZrCq7Jc9SHkgjgQgji8EfgiaNJyEB4NdTCRGr5VX6KAX94cggvnAZCpUGWTW2LqDtE"
Invoke-WebRequest -Uri "https://api.coincync.network/faucet" -Method POST `
  -Body (@{address=$ADDR} | ConvertTo-Json -Compress) `
  -ContentType 'application/json' -TimeoutSec 30 -UseBasicParsing | `
  Select-Object -ExpandProperty Content
```

✅ Pass when:

- Drip POST returns `{"success":true,"tx_hash":"<64-hex>",...}` OR
  `{"error":"address rate-limited..."}` (the address has been used in
  prior tests; either response means the faucet is alive).

🔴 If drip POST returns `5xx`: see `docs/operations/INCIDENT_RUNBOOKS.md`,
faucet section. Most likely cause: hot wallet ran out of eligible UTXOs.
Top-up via `scripts/fund-faucet.ps1`.

🔴 If `drips_today` is suspiciously high (>500) before launch: spam
filter / rate-limit not working; investigate.

---

## 3. Wallet downloads + auto-update + GitHub release

```powershell
foreach ($u in @(
  'https://coincync.network/release/v1.0.1-testnet/CoinCync-Wallet-Setup.exe',
  'https://coincync.network/release/v1.0.1-testnet/SHA256SUMS.txt',
  'https://releases.coincync.network/wallet/latest.json',
  'https://github.com/ghostrider1092/Coincync-Testnet-/releases/tag/v1.0.2-testnet'
)) {
  try {
    $r = Invoke-WebRequest -Uri $u -Method Head -TimeoutSec 10 `
           -UseBasicParsing -MaximumRedirection 5
    "  ✓ {0,-72} {1}" -f $u, $r.StatusCode
  } catch {
    "  ✗ {0,-72} FAIL" -f $u
  }
}
```

✅ Pass when: all four 200.

🔴 If GitHub release URL fails: somebody / something deleted the
release tag. Re-publish.

🔴 If `latest.json` fails: `releases.coincync.network` nginx is down.
SSH to the explorer box (it's the origin), `systemctl status nginx`,
restart if needed.

---

## 4. Public-facing endpoints sweep

```powershell
foreach ($u in @(
  'https://coincync.network/'
  'https://coincync.network/faucet'
  'https://docs.coincync.network/getting-started/mining-on-your-pc'
  'https://docs.coincync.network/governance/constitution'
  'https://explorer.coincync.network/'
  'https://api.coincync.network/'
  'https://git.coincync.network/'
)) {
  try {
    $r = Invoke-WebRequest -Uri $u -Method Head -TimeoutSec 10 `
           -UseBasicParsing -MaximumRedirection 5
    "  ✓ {0,-60} {1}" -f $u, $r.StatusCode
  } catch {
    "  ✗ {0,-60} FAIL" -f $u
  }
}
```

✅ Pass when: all 7 are 200.

---

## 5. Discord — bot online + posting works

In your browser, open Discord. Look at:

- `#announcements` pinned message — does it still show the live status?
- `#network-health` channel — is the bot logged in (green dot)?

If anything looks stale, re-run:

```powershell
$env:DISCORD_BOT_TOKEN = "<token-from-Developer-Portal>"
python scripts\discord-refresh.py --dry-run    # see what'd change
python scripts\discord-refresh.py              # apply
Remove-Item env:DISCORD_BOT_TOKEN
```

---

## 6. Repo + signed commits

```powershell
# Are we on main, no uncommitted changes besides expected gitignored stuff?
git status -sb | Select-Object -First 5

# Latest 3 commits — should all be signed
git log --show-signature -3 2>&1 | Select-String "^commit|^Good|^bad|^No signature"
```

✅ Pass when:

- Branch is `main`, ahead by 0 (or only by un-pushed commits you intend to push)
- Each of the last 3 commits says `Good "git" signature for ghostrider1092@coincync.network`

🔴 If any commit shows `No signature`: your local signing config got
broken (probably a new shell session that didn't inherit the env). Re-set:

```powershell
git config --global gpg.format ssh
git config --global user.signingkey "$env:USERPROFILE\.ssh\id_ed25519"
git config --global commit.gpgsign true
```

---

## 7. Soft "social readiness" check — totally optional

- `coincync.network` opens fast (< 2 sec to first paint) on a phone
  on cellular?
- Block explorer renders correctly when you click a recent block?
- Does the homepage's "Section 09 (security)" show the responsible-
  disclosure block (NOT the old bounty cards)?

These are vibes, not gates.

---

## Posting order — same as `TESTNET_LAUNCH_ANNOUNCEMENT.md` §8

| Time (ET) | Channel | Doc to copy from |
|---|---|---|
| 09:30 | Pin announcement in Discord | `DISCORD_REFRESH.md` § "Pin in #announcements" |
| 10:00 | r/CryptoCurrency | `TESTNET_LAUNCH_ANNOUNCEMENT.md` § 5 |
| 10:30 | BitcoinTalk ANN | `TESTNET_LAUNCH_ANNOUNCEMENT.md` § 4 |
| 11:00 | X / Mastodon thread | `TESTNET_LAUNCH_ANNOUNCEMENT.md` § 3 |
| 14:00 | lobste.rs | `TESTNET_LAUNCH_ANNOUNCEMENT.md` § 8 |
| **Wed 05-13** | r/Monero + Hacker News | `TESTNET_LAUNCH_ANNOUNCEMENT.md` §§ 6, 7 |

For each platform: be in the comments at least 6 hours after posting.
Reply windows: every top-level comment within 1 hour for the first 6h.

---

## After launch — hour-1 watch

Keep two terminals open:

**Terminal A — chain liveness (re-run every ~2 min):**

```powershell
$tip = (Invoke-WebRequest -Uri "https://api.coincync.network/rpc/testnet" `
  -Method POST -Body '{"jsonrpc":"2.0","id":1,"method":"get_info"}' `
  -ContentType 'application/json' -TimeoutSec 8 -UseBasicParsing).Content `
  | ConvertFrom-Json
"  h={0} age={1}s mempool={2} peers={3}" -f `
  $tip.result.height, $tip.result.tip_age_secs, `
  $tip.result.mempool_size, $tip.result.peer_count
```

**Terminal B — faucet capacity (re-run every ~5 min):**

```powershell
(Invoke-WebRequest -Uri "https://api.coincync.network/faucet/stats" `
  -TimeoutSec 8 -UseBasicParsing).Content
```

If `drips_today` climbs past 80, top up the wallet with
`scripts/fund-faucet.ps1` before it runs dry.

---

## Things you do NOT have to do during launch

- Don't manually merge PRs from random accounts. Let them sit at
  least 24h so you can review.
- Don't reply to drive-by trolling. Block + mute, don't dignify.
- Don't push hotfixes during launch hour. The fleet is already up
  and on the right build; risk-reward is bad.
- Don't change DNS / Cloudflare config during the announcement
  window. Caching means the change won't propagate to all visitors
  cleanly anyway.
