# CoinCync Beta Net — pre-audit shielded dogfooding

An **isolated, public, disposable** test network for exercising the **gated,
unaudited** Lelantus-Spark shielded pool with real users **before** the external
audit. This is the only network where the shielded pool activates pre-audit.

> **UNAUDITED · NO VALUE · MAY RESET.** Beta coins are worthless. The shielded
> crypto has **not** been audited. The chain may be wiped and re-genesised at any
> time. Do not treat anything here as real.

**Status:** the full shielded loop has been verified end-to-end on beta —
shield-in → transfer (recipient recovers the exact amount) → unshield (back to
transparent) — with a pool larger than one Grootle group. The first beta run
surfaced a real pool-scaling bug (the cover set only worked while the pool held
≤ `cover_set_size` coins); it is fixed (cover-set grouping by `cover_set_id`) and
re-verified live. That is exactly what beta is for.

## Why beta exists (and why it's safe)

A testnet earns its keep by letting live users find the operational/integration
bugs no audit or soak will — but a privacy chain must not put unaudited consensus
crypto on a network anyone treats as real. Beta is the reconciliation: real users
hammer shielded on a throwaway net, the **audit still gates mainnet**, and
**testnet stays shielded-off**.

Containment is enforced in consensus, not by convention:

- `shielded_activation_height(Beta)` returns `SHIELDED_BETA_ACTIVATION_HEIGHT = 5`
  **only in a `sketch-gk-proof` build**; a default/production build keeps beta at
  `u64::MAX` too (`src/constants.rs`).
- `shielded_activation_height(Testnet | Mainnet)` is **unconditionally `u64::MAX`**
  — no feature flag, build, or env var flips it on. Beta activation cannot leak to
  testnet or mainnet.
- Beta has its own network id, genesis, and ports (P2P **38080**, RPC **38081**,
  REST/explorer **38083**), so a beta node cannot cross-connect to testnet/mainnet.
- Beta's initial difficulty is low (`BETA_INITIAL_DIFFICULTY = 256`) so it mines
  near-instantly and reaches the height-5 activation within seconds.

## Build the gated binaries

The shielded pool is only present in a `sketch-gk-proof + libspark-ffi` build
(needs LLVM + a static OpenSSL for the vendored libspark — see
`scripts/soak-24h-shielded.sh` for the toolchain env).

```bash
export LIBCLANG_PATH="C:/Program Files/LLVM/bin"
export SPARK_OPENSSL_DIR="/path/to/spark-openssl-static-md"
cargo build --bin coincync-node   --features "testnet sketch-gk-proof libspark-ffi"
cargo build --bin coincync-wallet --features "testnet sketch-gk-proof libspark-ffi"
```

A default build (no `sketch-gk-proof`) has no shielded subcommands and cannot
activate the pool on any public network.

## Run the beta seed (operator)

```bash
coincync-node --network beta --data-dir <dir> \
  --mine <your-tCYNC-address> --allow-solo-mine --mine-threads <N> \
  --explorer
```

- Expose **P2P 38080** publicly for testers; keep **RPC 38081** loopback-only.
- The embedded explorer serves at `http://<host>:38083/` (REST = rpc+2).
- **Mine ≥ ~160 blocks before shielding**: the transparent spend inside a
  shield-in draws a decoy ring (127 members) and coinbase must mature
  (`MIN_OUTPUT_AGE`), so a brand-new chain can't shield until it has enough
  outputs. This is young-chain maturity, not a shielded limitation.

## How testers join

```bash
# 1. Build the gated binaries (above) or fetch a beta release.
# 2. Run a node that dials the seed:
coincync-node --network beta --data-dir <dir> --addnode <SEED_IP>:38080

# 3. Create a beta wallet (COINCYNC_WALLET_PASSWORD or --password -):
coincync-wallet --network beta --wallet w.wallet create

# 4. Get coins: mine on your own node (--mine <addr>) or use the beta faucet.

# 5. Exercise the full shielded flow (amounts are ATOMIC; 1 CYNC = 1e12):
N=http://127.0.0.1:38081
coincync-wallet --network beta --node $N --wallet w.wallet scan
coincync-wallet --network beta --node $N --wallet w.wallet shielded-address
coincync-wallet --network beta --node $N --wallet w.wallet shielded-mint     --amount 40000000000000
coincync-wallet --network beta --node $N --wallet w.wallet shielded-balance
coincync-wallet --network beta --node $N --wallet w.wallet shielded-send      --to <recipient st1...> --amount 4000000000000
coincync-wallet --network beta --node $N --wallet w.wallet shielded-unshield  --amount 2000000000000
```

Each shielded tx must be mined into a block before the next step sees it
(`shielded-balance` reads the node's cover set).

## Labeling (required on every surface)

The explorer network badge reads **BETA**. Any page, release note, or channel
that mentions beta must carry **UNAUDITED · NO VALUE · MAY RESET**. Never imply
beta shielded is production-ready — it is the opposite.

## Reset policy

Beta is disposable. To reset: stop all nodes, delete data dirs, ship a new
genesis, and announce the reset. Nothing on beta is preserved across resets.

## Reporting bugs

The whole point is live bug discovery. Testers report operational/integration
bugs (wallet, scanner, fees, reorgs, RPC) via the issue tracker. The audit —
not the beta run — is the gate for soundness/crypto correctness; a clean beta
run is **not** evidence the crypto is sound, and must not be used to argue for
skipping or rushing the audit.
