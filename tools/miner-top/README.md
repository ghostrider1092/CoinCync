# coincync miner-top

A `btop`-style terminal dashboard for CoinCync's RandomX (CPU-only) miner.
Brand-matched to the Colony dashboard. Built on `ratatui` + `crossterm`, so it
runs in Windows Terminal / PowerShell as well as Linux/macOS.

## Run the demo
```
cargo run --release --bin miner-top
```
Keys: `space` pause/resume · `b` simulate a block found · `q` / `Esc` quit.
(The demo uses a built-in simulator; no real miner required.)

## Panels
- **HASHRATE** — braille line graph of total H/s over time, with the live rate
  in the corner. Goes grey when paused.
- **RANDOMX** — CPU model / frequency, total utilisation bar + temperature
  (sage → amber → rust), a per-thread H/s bar for every worker thread, load avg.
- **MINING** — hashrate now / 10m avg / peak, thread count, share difficulty, uptime.
- **SHARES** — acceptance bar + accepted / rejected / stale counts and effort/luck.
- **CHAIN** — height, network difficulty, tip age (reddens as it ages), blocks
  found, and the pool/p2pool/solo connection.
- **RECENT SHARES & BLOCKS** — a scrolling ledger; ACCEPT sage, REJECT rust,
  STALE amber, and a reversed amber **BLOCK!** row when you find one.

## Wiring into your miner
`miner.rs` is the seam. `Miner` is the struct you fill each refresh from your
worker + stratum/p2pool client instead of calling `simulate()`:
- `hashrate`, `per_core`, `hr_hist` ← RandomX worker hashrate counters
- `accepted` / `rejected` / `stale`, `share_diff` ← stratum share results
- `net_height`, `net_diff`, `tip_age_s` ← your node RPC (getinfo / block tip)
- `blocks_found` + a `ShareKind::Block` ledger row ← on a solved block
Then swap the demo loop's `simulate()` for a refresh that copies real values in.

## Honest footer
`RandomX · CPU-only · fair launch · 0% dev tax · mining-rig node (keys live
elsewhere)` — a standing reminder that the rig is an exposed/untrusted node and
should hold no signing keys (per the dual-PC split).

## Toolchain note
Needs only `ratatui`. On an older rustc you may need to pin transitive deps:
```
cargo update -p instability --precise 0.3.7
cargo update -p unicode-segmentation --precise 1.12.0
```
On current stable, the latest versions build without pins.
