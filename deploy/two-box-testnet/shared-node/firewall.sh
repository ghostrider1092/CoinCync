#!/usr/bin/env bash
# Firewall for the SHARED node box (ufw). Public P2P; RPC reachable ONLY by the
# rig; everything else denied. Run with sudo. EDIT the SSH source before enabling.
set -euo pipefail

RIG_IP="62.238.121.186"        # dedicated rig box — the only host allowed to hit RPC
# ADMIN_IP="203.0.113.5"       # <- your admin IP; uncomment to lock SSH to it

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH. STRONGLY prefer locking this to your admin IP:
#   ufw allow from "$ADMIN_IP" to any port 22 proto tcp
ufw allow 22/tcp

# P2P — public, so the node joins the testnet mesh.
ufw allow 28080/tcp

# RPC — Bearer-authed AND restricted to the rig's IP. Never open to the world.
ufw allow from "$RIG_IP" to any port 28081 proto tcp

# Loopback is already trusted by ufw, so the local tick's 127.0.0.1:28081 reads
# and its 127.0.0.1:9200 /metrics + /colony endpoints work without extra rules.

ufw --force enable
ufw status verbose
