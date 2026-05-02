# Tor hidden services

Publishing CoinCync's public infrastructure (block explorer, RPC API) as Tor hidden services is **additive, never replacement**. The clearnet sites stay live at `explorer.coincync.network` and `api.coincync.network`; an `.onion` mirror is published alongside them for users whose threat model demands end-to-end Tor.

This is the same model Pirate Chain, Monero, and Zcash follow. Their main websites are clearnet HTTPS; their `.onion` mirrors exist for the hardened threat model and are published in their docs and on their Twitter.

## Why an `.onion` is meaningfully better than "use Tor Browser to visit our clearnet site"

Visiting `https://explorer.coincync.network` through Tor Browser still leaves a **Tor exit node** in the path — and many exit nodes are run by researchers, governments, or adversaries who log traffic. Even though the traffic is HTTPS-encrypted, the exit node sees:

- Which `.coincync.network` host you're talking to
- The TLS SNI (which can leak the subdomain even on encrypted connections)
- Timing patterns
- The fact that someone using Tor is interested in CoinCync

An `.onion` is **end-to-end within Tor**. There is no exit node, only relays that see encrypted onion-layer traffic they cannot inspect. The destination is reached via a 6-hop circuit (3 client-side + 3 server-side, meeting in the middle) with no point of plaintext exposure.

For a privacy coin, this matters. The clearnet site is for users who don't need that level of unlinkability. The `.onion` mirror is for users who do.

## Setup on the explorer host

Roughly 20 minutes of work on the explorer host that already runs the Caddy stack.

### 1. Install Tor

```bash
sudo apt update
sudo apt install -y tor
```

Verify it started:

```bash
systemctl status tor
```

### 2. Configure a v3 hidden service

Append to `/etc/tor/torrc`:

```text
# ── CoinCync explorer hidden service ─────────────────────
HiddenServiceDir /var/lib/tor/coincync_explorer/
HiddenServiceVersion 3

# Forward the .onion's port 80 to Caddy's HTTP bind on loopback.
# Tor clients speak HTTP (not HTTPS) over the onion because the Tor
# circuit already provides end-to-end encryption + auth — layering
# TLS on top is redundant and leaks cert metadata via the
# Server-Name-Indication field in the TLS handshake.
HiddenServicePort 80 127.0.0.1:80
```

Reload Tor:

```bash
sudo systemctl restart tor
```

Tor generates a v3 (56-character) onion hostname on first start. Read it:

```bash
sudo cat /var/lib/tor/coincync_explorer/hostname
# → <56-char-v3-onion>.onion
```

Save this hostname — you'll need it for the next step and to publish.

### 3. Add a server block to the Caddyfile

The existing `deploy/explorer/Caddyfile` only listens on `:443` (and gets `:80` automatically for the ACME challenge). To also serve plaintext HTTP on `127.0.0.1:80` for Tor, append:

```text
# ── .onion mirror ─────────────────────────────────────────
# Listens only on the loopback interface so only the local Tor
# daemon can reach it. The public 443 site is unaffected.
#
# `http://` is intentional — no TLS. Tor circuits are already
# end-to-end encrypted; layering TLS on top is redundant and
# leaks cert metadata via SNI in the TLS ClientHello.
#
# Caddy's auto-HTTPS is disabled for this site by binding to
# `http://` explicitly.
http://127.0.0.1:80 {
    handle /api/testnet {
        request_body { max_size 64KB }
        reverse_proxy 127.0.0.1:28081 {
            header_up Host {host}
            header_up Content-Type "application/json"
        }
    }
    handle /api/mainnet {
        request_body { max_size 64KB }
        reverse_proxy 127.0.0.1:19081 {
            header_up Host {host}
            header_up Content-Type "application/json"
        }
    }
    handle /metrics {
        reverse_proxy 127.0.0.1:9091
    }
    handle {
        root * /var/www/explorer
        encode zstd gzip
        try_files {path} /index.html
        file_server
    }
    log {
        output stdout
        format json
        level INFO
    }
}
```

Reload Caddy:

```bash
docker compose -f /opt/coincync/deploy/explorer/docker-compose.yml exec caddy \
  caddy reload --config /etc/caddy/Caddyfile
```

### 4. Verify

From the same host:

```bash
# Caddy is now listening on 127.0.0.1:80
ss -tlnp | grep ':80 '
# expect: 127.0.0.1:80

# Curl through the local Tor SOCKS proxy
curl --socks5-hostname 127.0.0.1:9050 \
     -I http://<your-56-char-v3-onion>.onion/
# expect: HTTP/1.1 200 OK
```

From a different machine running Tor Browser, visit `http://<your-56-char-v3-onion>.onion/` directly. The explorer should load identically to the clearnet site.

### 5. Publish the onion address

Add it to:

- `https://docs.coincync.network/operations/tor.md` (this page — the runbook itself doubles as the announcement)
- `mirrors.json` on the docs host (see [Federation & DDoS](./federation-and-ddos.md))
- The project's social media / Twitter / Mastodon
- `https://coincync.network` landing page (in the "find us" section)

Once it's published, users running Tor Browser can paste it directly. Tor Browser handles the routing; users don't need to install Tor separately.

## Same setup for the API host

The API stack at Toronto can publish its own `.onion` using exactly the same recipe — just point `HiddenServiceDir` at `/var/lib/tor/coincync_api/`, append a parallel `http://127.0.0.1:80` block to `deploy/api/Caddyfile` that proxies `/rpc` and `/v1/*` to the local cyncd, and publish the resulting onion hostname.

The two `.onion` addresses are independent. They're both on the Tor network but they have separate keys, separate hostnames, and separate failure modes.

## Hidden service security checklist

- [ ] **Hostname recorded somewhere offline.** If the `HiddenServiceDir` files are lost, the onion address is gone forever (you can't recover it from the network — the address is the public key, derived from the private key in that directory).
- [ ] **`HiddenServiceDir` contents backed up.** `hostname`, `hs_ed25519_public_key`, `hs_ed25519_secret_key`. The secret key is what proves you control the onion. **If it leaks, anyone with the key can impersonate your onion**, including running a man-in-the-middle that serves modified explorer HTML.
- [ ] **Permissions on `HiddenServiceDir` are 0700, owned by `debian-tor`.** Tor refuses to start otherwise.
- [ ] **Caddy on `127.0.0.1:80` is bound only to loopback.** Verify with `ss -tlnp | grep ':80 '`. If it's `0.0.0.0:80`, the explorer is also publicly reachable on plaintext HTTP, which defeats both the TLS-on-clearnet and the Tor-only-via-onion contracts.
- [ ] **No external CDN dependencies in the embedded HTML.** The vendoring pass in `deploy/explorer/fetch-vendor.sh` + `patch-vendor.sh` is required for the `.onion` to actually work — a Tor user can't reach `cdn.jsdelivr.net` from inside a `.onion` session unless their Tor Browser is configured to allow exit-node requests for those origins (most aren't, by default, and that defeats the point anyway).

## What an `.onion` does NOT protect

- **Application-layer fingerprinting.** A wallet that uses a unique ring-size or transaction shape leaks its identity through the on-chain data even if the network path is anonymous.
- **Out-of-band correlation.** If a user mentions their balance in chat, in email, in a leak, the cryptography didn't fail — they did.
- **Tor itself.** Tor has known limitations against well-funded adversaries who can observe entry and exit traffic. The hidden-service circuit is more robust than clearnet-Tor (no exit node), but it's not magic.

## See also

- [Federation & DDoS](./federation-and-ddos.md) — the broader threat model
- [Block explorer](./explorer.md) — the clearnet stack the `.onion` mirrors
- [Public RPC API](./api-host.md) — the parallel API stack, also `.onion`-able
