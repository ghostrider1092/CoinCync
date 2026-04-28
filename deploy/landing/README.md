# CoinCync Landing Deployment (nginx-only)

Hosts:
- `https://coincync.network`
- `https://www.coincync.network`
- `https://docs.coincync.network`

This directory is nginx-only. Caddy artifacts were removed.

## Install/update landing and docs vhosts

```bash
cd /opt/coincync
git pull --ff-only
sudo bash deploy/landing/install-nginx-landing.sh
```

## Expected document roots

- Landing site files: `/var/www/landing`
- Docs site files: `/var/www/docs`
- Mirrors JSON: `/opt/coincync/deploy/landing/mirrors.json`

## Verify

```bash
curl -I https://coincync.network
curl -I https://docs.coincync.network
curl -sS https://coincync.network/mirrors.json | jq .
curl -sS https://docs.coincync.network/mirrors.json | jq .
```
