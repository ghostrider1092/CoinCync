# Fleet config & seed onboarding runbook

`scripts/fleet-config.json` is the single source of truth for the CoinCync
**testnet** fleet topology. Node-management tooling
(`scripts/sync-fleet-config.sh` → `scripts/render-systemd-unit.sh`) reads it to
build each node's `--addnode` dial list, and the tick monitor
(`src/tick_adapter/fleet_config.rs`) reads it to know which hosts to probe.

## Current state (2026-09-06)

Consolidated onto **Hetzner**. One live public seed:

| Node | IP | Role | RPC bind |
|------|----|------|----------|
| `seed1` | `2.28.1.75:28080` | seed | `127.0.0.1` (loopback) |

The residential home node stays **DNS-only** (privacy) and is intentionally
not listed here. The former Vultr fleet is in `deactivated` for history.

## The three things that must stay in sync

A seed's IP lives in **three** places. All three must agree or bootstrap
breaks:

1. `scripts/fleet-config.json` — `nodes` map (operator tooling).
2. `src/testnet.rs` — `TESTNET_SEED_NODES` (compiled bootstrap list).
3. `src/network/dns_seeds.rs` — `TESTNET_FALLBACK` (compiled DNS-failed fallback).

Two `cargo test` checks enforce the code side and now the file side:

- `testnet_fallback_matches_seed_nodes` — (2) ↔ (3) must be identical.
- `testnet_fallback_matches_fleet_config` — the `seed`-role nodes in (1) must
  equal (3) (and therefore (2)). Drift is a **build failure**, not a silent
  regression.

DNS is the fourth leg: `TESTNET_DNS_SEEDS` (`seed1/2/3.coincync.network`) must
have A/AAAA records pointing at these seed IPs. Until they resolve,
`deploy/ops/verify-community-bootstrap.sh` will report `result=FAIL`.

## Add a seed

1. Provision the box (Hetzner). Open **inbound TCP 28080** in the cloud
   firewall.
2. Install the node: `sudo bash deploy/ops/install-testnet-node.sh --open-ufw`
   (see `deploy/ops/README.md`). Confirm it syncs to tip.
3. Add it to **all three** places above (IP + `:28080`), `role: "seed"`.
4. Register a DNS A/AAAA record (e.g. `seed2.coincync.network` → new IP).
5. `cargo test testnet_fallback` — both sync tests must pass.
6. `bash scripts/sync-fleet-config.sh` — re-render every node's addnode list.
7. `bash deploy/ops/verify-community-bootstrap.sh` — expect `result=OK`
   (all DNS seeds resolve, ≥1 seed accepts TCP).

## Remove / replace a seed

1. Move the entry from `nodes` to `deactivated` (keep it for history; note the
   date and reason). **Never** delete the record outright — the old IP must be
   greppable so it can be kept out of every future addnode/known-hosts list.
2. Remove its IP from `TESTNET_SEED_NODES` and `TESTNET_FALLBACK`.
3. Drop or repoint its DNS record.
4. `cargo test testnet_fallback`, then `scripts/sync-fleet-config.sh`.

## Notes

- `TESTNET_FALLBACK` must never be empty (`testnet_fallback_is_non_empty`) — an
  empty fallback means DNS-failed bootstrap has no recovery path.
- `role: "api"` hosts are excluded from tick probing and addnode rendering
  (nginx-only, don't run coincync-node).
- Keep RPC on `127.0.0.1` unless a host intentionally serves public RPC behind
  nginx/stunnel.
