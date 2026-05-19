# CoinCync API Reference (index)

**Privacy money that requires no permission.** API integrations are evaluated against keeping that promise intact — no KYC hooks, no chain-analysis-friendly enrichments, no surveillance-friendly metadata in responses. See [docs/explicitly-not-doing.md](explicitly-not-doing.md) §Surveillance for the full list.

This file is a short index. The canonical API docs are maintained under `docs/src/api/`.

## Canonical docs

- [JSON-RPC 2.0](src/api/json-rpc.md)
- [REST endpoints](src/api/rest.md)
- [Method reference](src/api/methods.md)

## Runtime defaults and security posture

- Local JSON-RPC default: `127.0.0.1:28081` (testnet)
- Local REST default when enabled: `127.0.0.1:28083`
- REST is opt-in (`--rest-bind` or `--explorer`)
- Public RPC access should be proxied/allowlisted, not directly bound to `0.0.0.0`

For method-by-method payloads and hardening posture fields (including Stratum posture telemetry), use `src/api/methods.md`.
