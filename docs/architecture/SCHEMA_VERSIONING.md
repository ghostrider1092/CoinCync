# DB Schema Versioning

**Status:** Active (v1 — initial mainnet-candidate).
**Owner:** `src/db/mod.rs` (`EXPECTED_DB_SCHEMA_VERSION`, `verify_or_stamp_schema_version`).
**Mainnet GA blocker:** YES — this exists to ensure v1.0 → v1.X DB upgrades cannot silently corrupt persisted data.

## TL;DR

CoinCync's database carries a **single u32 schema-version stamp** in a reserved metadata tree (`__db_metadata__`, key `b"schema/db_version"`). On every `Database::open`, the stored stamp is compared against the binary's compile-time `EXPECTED_DB_SCHEMA_VERSION`. Mismatch → refuse to start. Fresh DB → stamp the current version and proceed. This is the same pattern Monero, Bitcoin Core, and Zcash use; CoinCync mirrors it for the same reasons.

## Why this exists

Without a schema version, the v1.1 release cannot tell whether the on-disk data was written by v1.0 (different Borsh layout) or v1.1 (current layout). Borsh has no built-in self-description — every persisted struct's bytes are positional. Adding a field to `OutputEntry`, `MempoolEntry`, `WalletTx`, etc. is a SILENT breaking change without versioning: v1.1 reads the v1.0 layout, mis-aligns every field, and produces garbage.

The failure mode without this:
- v1.0 mainnet ships, accepts blocks, populates 12+ Borsh-serialized struct types across 24+ sled trees.
- v1.1 ships with one new field on one struct (e.g., extending `ChainStateData` for a Phase-2 feature).
- Operator upgrades. Node restarts. v1.1 reads `ChainStateData` written by v1.0 → mis-parses → produces garbage chain state → consensus split or node crash.
- Recovery requires a forced testnet/mainnet reset to clear all persisted state.

Schema versioning prevents this by making the version explicit and the migration path required code.

## Design

### Single u32 per DB, stored in a reserved tree

```
tree: __db_metadata__
key:  b"schema/db_version"
value: u32 little-endian (4 bytes)
```

The double-underscore prefix on the tree name (`__db_metadata__`) is reserved namespace — consensus-layer tree names are unprefixed (`blocks`, `utxos`, `chain_state`, etc.). This convention prevents accidental tree-name collision with future features.

### Decision matrix on `Database::open`

| Stored version | Fresh DB? | Action |
|---|---|---|
| None | YES (blocks tree empty) | Stamp `EXPECTED_DB_SCHEMA_VERSION`, proceed |
| None | NO (blocks tree non-empty) | **ERROR** — legacy DB, no auto-migrate |
| `Some(v)` where `v == EXPECTED` | (either) | Proceed |
| `Some(v)` where `v < EXPECTED` | (either) | **ERROR** — no migration registered (today) |
| `Some(v)` where `v > EXPECTED` | (either) | **ERROR** — future DB, downgrade binary |
| `Some(v)` with `bytes.len() != 4` | (either) | **ERROR** — wrong-length value |

Fresh-DB detection uses `BlockDb::is_empty()` (checks the `blocks` tree specifically — the authoritative "real chain data exists" signal).

### Why each error branch is fail-loud

- **Legacy unstamped DB:** auto-migrating from "no stamp" is unsafe because pre-v1 layout has no formal definition. Operator chooses: wipe + resync, or write a one-time migration script.
- **Older version:** v1.1 will register a migration closure for v1 → v2 in the migration table; without that table populated, refusing is safer than guessing.
- **Future version:** the operator downgraded their binary; v1.0 code cannot safely read v1.1 data layout. Refusing prevents corruption.
- **Wrong length:** defends against the case where a future version switches from u32 to u64 — v1.0 binary reading 8 bytes where it expects 4 must error, not truncate.

### Why u32 (not u8 or u64)

- **u8** (256 versions) is sufficient for any foreseeable lifetime but breaks convention.
- **u64** (8 bytes) is wasteful — schema versions never need 64 bits of headroom.
- **u32** matches Monero's `BlockchainDB::get_db_version()` return type and Bitcoin Core's `kVersionNumberFromDb` typing. Following the established convention avoids "why is CoinCync special?" review noise.

Cost: 4 bytes per DB. Trivial.

### Why a single per-DB version (not per-tree or per-struct)

**Considered: per-struct first-field `schema_version: u8`.** Rejected because:

1. **Bloats every persisted Borsh struct's bytes.** Even when no migration is needed, every record carries the version overhead.
2. **Forces breaking change to existing testnet data.** Every field shifts by 1 byte after the inserted version field. The current testnet DB at h=3000+ becomes unreadable without an explicit re-encoding pass.
3. **Doesn't compose with reorg-rollback.** Per-record versioning means every read performs a version check; rollback would need to remember the version at each height.
4. **Not how Bitcoin/Monero/Zcash actually do it.** All three use a single per-DB version. Following the established pattern eliminates a class of "why doesn't this look like other chains?" audit findings.

**Considered: per-tree version map.** Rejected because:

1. **Migrations are always cross-tree anyway.** Adding a field to `OutputEntry` (in tree `utxos`) might also require updating `OutputIndexEntry` (in tree `output_index`) to stay in sync. A per-tree version map invites partial-migration bugs.
2. **Monero tried per-tree and consolidated.** Their early lmdb versioning had per-tree counters; current code uses a single `db_version` for the same simplicity reasons.

## Prior art

- **Monero** (`src/blockchain_db/lmdb/db_lmdb.cpp::get_db_version` + `m_open`): single `uint32_t` per-DB version, compared against `MAX_VERSION` constant on open. Fresh DB → stamp current version. Mismatch → fail-loud, operator must migrate or wipe.
- **Bitcoin Core** (`src/dbwrapper.cpp::CDBWrapper::Read(kVersionKey, ...)`): per-DB version stored in a reserved key, mismatch aborts startup with "wallet/coin DB is from a newer version" or "database is corrupt".
- **Zcash** (`src/wallet/walletdb.cpp::CDBEnv::version_check`): same single-version pattern, with an explicit migration registry dispatched per `(from_version, to_version)` tuple. The future v1.1 migration code in CoinCync will adopt this shape.

## How to bump the version

When a v1.X release changes ANY persisted Borsh struct's on-disk layout:

1. Bump `EXPECTED_DB_SCHEMA_VERSION` in `src/db/mod.rs`.
2. Register a migration closure in (future) `src/db/migrations.rs` keyed by `(from_version, to_version)`. The closure reads the old layout, writes the new layout, and is invoked exactly once per node during the first `Database::open` after the upgrade.
3. Update `verify_or_stamp_schema_version`'s `Less` branch to dispatch into the migration table.
4. Add a test that writes a synthetic vN-1 DB, opens it with the vN binary, asserts the migration ran and the new layout is correct.

## What this PR does NOT do

- Does NOT implement any migration code. v1 has no v0 to migrate from (the migration registry is conceptually empty).
- Does NOT change any existing struct's layout. The 12+ persisted Borsh structs are byte-identical to before this PR.
- Does NOT block testnet continuity automatically. The current testnet DBs WILL hit the "legacy unstamped DB" error on first open with v1.0 binary. Operator must wipe + resync to upgrade. This is intentional — the alternative (silent assume-v1) defeats the purpose of versioning.

## Testnet upgrade path

For operators upgrading existing testnet nodes to a binary that includes this PR:

```bash
systemctl stop coincync-node
rm -rf /var/lib/coincync/testnet     # destroys existing chain data
systemctl start coincync-node        # fresh DB, stamps v1, syncs from genesis
```

Or restore from a v1-stamped chaindata snapshot once one is published.

## Test coverage

Six tests in `src/db/mod.rs` cover the five branches of the decision matrix:

| Test | Branch | Asserts |
|---|---|---|
| `schema_version_stamped_on_fresh_db` | None + fresh | Stamps `EXPECTED` |
| `schema_version_preserved_across_reopen` | Some(v == EXPECTED) | Reopen no-op |
| `schema_version_future_version_rejected` | Some(v > EXPECTED) | Refuses with downgrade message |
| `schema_version_older_version_requires_migration` | Some(v < EXPECTED) | Refuses with migration-required message (skipped at v1, fires at v2+) |
| `schema_version_wrong_length_rejected` | Some(bytes.len() != 4) | Refuses with length-mismatch message |
| `schema_version_legacy_unstamped_db_rejected` | None + non-fresh | Refuses with legacy-DB message |

## RPC visibility

`Database::schema_version() -> Result<u32>` is `pub` so RPC + diagnostic tooling can expose the version. Future PR: add `db_schema_version` to `get_info` RPC response so fleet operators can verify all nodes agree on the layout they're running.

## See also

- `src/db/mod.rs` — `EXPECTED_DB_SCHEMA_VERSION`, `verify_or_stamp_schema_version`, `Database::schema_version()`
- `src/db/blocks.rs` — `BlockDb::is_empty()` (fresh-DB detection)
- Memory: `project_schema_versioning_v10_13` (the original v1.0.13 plan that surfaced this requirement; superseded by this PR landing the fix into v1.0)
