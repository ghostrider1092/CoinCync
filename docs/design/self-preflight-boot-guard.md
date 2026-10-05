# Self-preflight boot guard

**Status:** implemented (testnet-safe; a pure fail-fast guard, no consensus impact)
**Idea family:** "small hidden things" — a dam's boot-time safety interlock.

## Problem

A node can be started in a configuration that is silently wrong in ways that
only surface later as a fork, a corrupted data-dir, or (worst) a public seed
running the wrong network. Two gaps existed:

1. **Compiled network vs `--network` flag.** The consensus network is partly a
   compile-time cargo feature (`testnet` vs default/mainnet — see
   `src/constants.rs` `#[cfg(feature = "testnet")]` pairs). Nothing stopped a
   **mainnet-compiled binary from being run as `--network testnet`** (or the
   reverse). `docs/operations` and the memory both warn "node/miner built with
   different features silently disagree," yet the only defence was an operator
   manually running `print-genesis-hash` before deploy. (This exact footgun was
   hit during the 2026-09-20 seed redeploy — caught only by a manual check.)

2. **Data-dir reused across networks.** Network identity on disk was inferred
   only from the stored genesis block. There was no explicit, human-readable
   marker, so tooling and error messages could not say "this data-dir belongs to
   testnet" without decoding a block.

The existing guards already cover the *stored-genesis-mismatch* case
(`Blockchain::load_from_database_with_outcome`) and the *schema-version* case
(`db::verify_or_stamp_schema_version`). This guard adds the two missing checks in
the same fail-fast, "refusing to start is the SAFE behaviour" style.

## Design

`src/preflight.rs` — a small, dependency-free module (deliberately portable):

- `compiled_network_is_testnet() -> bool` — `cfg!(feature = "testnet")`, the same
  discriminator `constants.rs` uses.
- `check_compiled_network(runtime: NetworkType) -> Result<()>` — refuses the two
  dangerous crossings:
  - testnet-compiled binary asked to run `--network mainnet`
  - mainnet-compiled binary asked to run `--network testnet`
  `regtest` is allowed on either build (local/dev), and same-network is fine.
  Override with `COINCYNC_SKIP_NETWORK_PREFLIGHT=1` for deliberate edge cases
  (mirrors the schema guard's "safe by default, operator can override" stance).

  Called at the top of `start_node` (`src/bin/node.rs`), before any DB work, so a
  misbuilt binary dies instantly with a clear message. **Not** applied to
  diagnostic subcommands like `print-genesis-hash` (you may legitimately print the
  other network's genesis from either binary).

- **Network marker** in `StateDb` (`b"network"` key): written at `init_genesis`
  next to the genesis hash; checked on every load after the genesis check. A
  pre-existing (legacy) data-dir with no marker is **lazily stamped** on first
  load (never fails); a marker that disagrees with the running network fails fast.

## Why it's testnet-safe / no consensus impact

Nothing here touches block validation, the genesis block, serialization, or any
hash-locked consensus file. The marker is a metadata key in the state tree. The
guard can only *reject* a genuinely-misconfigured start; a correct start is
unaffected.

## Portability (help other chains)

`check_compiled_network` + the network marker are a generic "a node must prove it
is the network it claims before it touches the chain" primitive. Any chain with a
compile-time network selection or per-network data-dirs can adopt the same two
checks; the marker especially helps chains whose testnet/mainnet genesis blocks
are not otherwise trivially distinguishable.
