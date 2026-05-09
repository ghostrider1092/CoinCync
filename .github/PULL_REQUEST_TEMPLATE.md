<!--
Thanks for contributing to CoinCync.
Keep this PR focused: one logical change per PR is far easier to review and revert.
-->

## Summary
<!-- What does this PR change, and why? 1–3 sentences. -->

## Type of change
- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (consensus, RPC, wallet format, on-disk schema)
- [ ] Refactor / cleanup (no behavior change)
- [ ] Documentation
- [ ] CI / tooling

## Component(s)
- [ ] Node (`coincyncd`)
- [ ] Wallet (Tauri desktop)
- [ ] CLI / RPC
- [ ] Explorer / faucet
- [ ] Tests / fixtures
- [ ] Docs / website

## Checklist
- [ ] `cargo fmt --all` clean
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test` passes locally
- [ ] If wallet JS changed: `npm run build` (or equivalent) succeeds
- [ ] Docs / `CHANGELOG.md` updated where user-visible behavior changes
- [ ] No secrets, keys, or addresses committed
- [ ] No new `unsafe` blocks (or justified inline if added)

## Consensus / privacy impact
<!--
Required if this PR could affect consensus rules, block/tx validation,
shielded-pool semantics, key derivation, or network protocol framing.
Otherwise write "none".
-->

## How was this tested?
<!--
Unit tests, integration tests, manual steps, fleet soak, etc.
Include exact commands or test names where possible.
-->

## Linked issues
<!-- e.g. Closes #123, Refs #456 -->
