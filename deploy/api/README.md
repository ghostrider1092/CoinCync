# CoinCync API Deployment (nginx-only)

Public API: `https://api.coincync.network`

This directory is nginx-only. Caddy artifacts were removed.

## Install/update API vhost

```bash
cd /opt/coincync
git pull --ff-only
sudo bash deploy/api/install-nginx-api.sh
```

## Verify

```bash
curl -i https://api.coincync.network/
curl -sS -X POST https://api.coincync.network/rpc \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq .
```

Optional mainnet route (enabled when local mainnet node is running):

```bash
curl -sS -X POST https://api.coincync.network/rpc/mainnet \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}'
```
