# SLIP-0044 coin_type migration: 888 → 19166

**Date:** 2026-06-05
**Status:** Applied (provisional value pending SLIP-0044 PR)
**Authors:** maintainer (audit-prompted)

## Context

The 2026-06-05 cross-blockchain audit (item #13) verified that
`coin_type = 888` — the value previously baked into CoinCync HD
wallet derivation at `m/44'/888'/account'/change'/index'` — is
**already registered to NEO** in the upstream SLIP-0044 registry
(<https://github.com/satoshilabs/slips/blob/master/slip-0044.md>).

Concrete impact of keeping 888:

- A user importing a CoinCync 24-word mnemonic into any
  standards-conformant HD wallet (Ledger, Trezor, Electrum-clone,
  any BIP44-aware software) at the canonical path would derive NEO
  addresses, not CoinCync addresses. Silent footgun — the wallet
  would not error, it would just hand them the wrong keys.
- Cross-tool cold-storage / paper-wallet workflows would not work.
  This is fine for testnet but unacceptable for mainnet (target
  2026-10-01 per `project_staged_mainnet`).

## Decision

Migrate to `coin_type = 19166`. Hoist the magic number into a named
constant `crate::constants::COINCYNC_COIN_TYPE` so future re-picks are
a one-line change.

The chosen value (19166) is **provisional**. Before mainnet launch:

1. Re-verify the current SLIP-0044 registry — if 19166 has been claimed
   since this commit, repeat the migration to a fresh value.
2. Submit upstream PR to SatoshiLabs/slips registering CoinCync at the
   chosen coin_type.
3. Update this doc with the registration PR link + merge status.

## Why 19166

- Sits well above the densely-claimed 0–1000 range.
- Does not appear in known SLIP-0044 snapshots as of the audit date.
- Has no obvious symbolic clash with other chain identifiers.
- Memorable enough for ops use ("nineteen-one-six-six") without being
  cute.

No deeper meaning — the audit needed *a* fresh value, not the
*perfect* fresh value. The exact pick is replaceable as long as it's
unclaimed.

## Compatibility impact

- **Testnet (running):** Existing testnet wallets derived from
  mnemonic at `m/44'/888'/*` will no longer produce the same address
  under the new code. Any user importing a 24-word seed into the
  updated binary derives a *different* address tree and cannot see
  testnet funds at the old derivation. The mitigating fact: testnet
  was wiped to genesis 2026-06-04 (per
  `project_session_2026_06_04_snapshot`) — so testnet wallet
  balances are essentially empty / disposable test funds. Acceptable
  loss.
- **Mainnet (not launched):** Zero impact — all mainnet wallets are
  created from scratch with the new constant.
- **Third-party wallet apps:** Any wallet that has hard-coded
  CoinCync at coin_type 888 (none known) would need to update. None
  currently exist outside the project's own software.

## Migration mechanics

The change is a single-constant swap:

- `src/constants.rs` — add `COINCYNC_COIN_TYPE` constant
- `src/wallet/mnemonic.rs` — replace inline `888` with the constant in
  `coincync()`, `view_key()`, `spend_key()`, and the two unit tests

Tests are rewritten to read the constant via `format!`, so they track
any future re-pick automatically.

## Followup

- Submit SLIP-0044 PR (separate task, owner = maintainer)
- Update this doc with PR link
- If a registry collision is discovered, the recovery path is: pick a
  fresh value, edit the one constant, re-run testnet wallet creation
- Add the SLIP-0044 PR status to the v1.0 audit-prep checklist

## References

- SLIP-0044 registry: <https://github.com/satoshilabs/slips/blob/master/slip-0044.md>
- BIP-44: <https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki>
- Original audit table: 2026-06-05 cross-blockchain verification sweep,
  item #13
