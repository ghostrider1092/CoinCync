# Wallet v2 typed-errors migration guide

**Status:** in progress as of 2026-05-21. 8 of 33 Tauri commands migrated.
**Goal:** every command returns `Result<T, WalletError>` instead of `Result<T, String>`. JS pattern-matches on `err.code` rather than substring-matching message text.

This document is the migration recipe so any remaining command can be ported without re-deriving the pattern. Each migration is mechanical and takes 5-15 minutes.

---

## What's migrated

| Command | Status |
| --- | --- |
| `unlock_wallet` | ✅ |
| `lock_wallet` | ✅ |
| `create_wallet` | ✅ |
| `restore_wallet` | ✅ |
| `scan_wallet` | ✅ |
| `send_transaction` | ✅ |
| `start_mining` | ✅ |
| `stop_mining` | ✅ |

## What's left

`get_balance`, `get_block_height`, `get_peer_count`, `get_fee_estimate`, `get_transactions`, `get_rsa_state`, `get_network_info`, `validate_address`, `get_wallet_address`, `get_mining_stats`, `check_binaries`, `check_for_update`, `multisig_*` (6), `swap_*` (7) — 25 commands.

The `get_*` commands mostly return data (not Result) and don't need migration unless they're refactored to return errors. The `multisig_*` and `swap_*` commands DO need migration; they're the bulk of the remaining work.

---

## The recipe

For each command, apply these mechanical changes:

### 1. Signature

```rust
// Before
fn the_command(/* params */, state: tauri::State<'_, State>) -> Result<T, String>

// After
fn the_command(
    /* params */,
    state: tauri::State<'_, State>,
    app: tauri::AppHandle,    // only if this command emits a push event
) -> Result<T, WalletError>
```

### 2. Lock acquisition

```rust
// Before
let mut s = state.lock().map_err(|e| e.to_string())?;

// After
let mut s = state.lock()?;
```

Works because `From<PoisonError<T>> for WalletError` is implemented globally.

### 3. CLI subprocess errors

```rust
// Before
let out = wallet_cli(&bin, &args, &pw)?;

// After
let out = wallet_cli(&bin, &args, &pw).map_err(WalletError::from_cli_error)?;
```

`from_cli_error` inspects the message and picks `AuthInvalidPassword` / `WalletNotFound` / `CliFailed { msg }` as appropriate.

### 4. Input validation

Use specific variants where they fit; fall back to `WalletError::op(msg)` for novel cases.

```rust
// "Invalid recipient address"
return Err(WalletError::InvalidAddress {
    reason: "recipient must start with 'tCYNC' or 'CYNC'".into(),
});

// "Invalid amount"
let amount: u64 = params.amount.parse()
    .map_err(|e| WalletError::InvalidAmount { reason: e.to_string() })?;

// Locked-wallet check (via with_session_password — already typed)
let pw = with_session_password(&s, |pw| Ok(pw.to_string()))?;

// Anything else
return Err(WalletError::op("multisig session already in progress"));
```

### 5. Custom error class? Add a variant.

If the same `WalletError::op(...)` pattern appears in two commands with the same conceptual failure (e.g., "FROST session not found"), add a specific variant:

```rust
// In the WalletError enum
MultisigSessionNotFound { session_id: String },

// In each call site
return Err(WalletError::MultisigSessionNotFound { session_id: id.clone() });

// In JS formatWalletError
case "MULTISIG_SESSION_NOT_FOUND":
    return `Multi-sig session ${err.session_id} not found`;
```

The variant naming follows `SCREAMING_SNAKE_CASE` of the Rust enum identifier (the `#[serde(rename_all = ...)]` handles the conversion automatically).

---

## JS side

The JS `formatWalletError(err)` function in `web/src/main.js` handles every typed variant. When you add a new variant to Rust:

1. Add a `case "NEW_VARIANT_NAME":` arm to `formatWalletError`
2. Return a human-readable string using `err.field_name` for structured detail

The fallback path (`err` is a string or untyped object) still handles legacy `[ERROR_CODE] msg` strings, so unmigrated commands keep working during the transition.

---

## Validating a migration

After porting a command:

1. `cargo build` — should compile clean (10 pre-existing warnings only)
2. Manual test: trigger the error path you care about (wrong password, invalid address, etc.) and verify the UI shows the right human message
3. Check `console.log` — the JS side logs typed errors as objects; the structured detail should be visible (`{ code: "INVALID_ADDRESS", reason: "..." }`)

---

## Future cleanup

Once every command is migrated:

- Remove the legacy string-fallback branch in `formatWalletError` — only typed errors arrive
- Remove `from_cli_error` substring-matching — `wallet_cli` itself returns typed errors
- `wallet_cli` becomes `fn wallet_cli(...) -> Result<String, WalletError>`

That work is queued for after the v1.0 mainnet ship.
