#!/usr/bin/env bash
# Firewall for the DEDICATED rig box (ufw). The rig only makes OUTBOUND
# connections (to the shared node's RPC); nothing needs to reach it except SSH.
# /metrics is bound to loopback, so it is never exposed. Run with sudo.
set -euo pipefail

# ADMIN_IP="203.0.113.5"       # <- your admin IP; uncomment to lock SSH to it

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH only. STRONGLY prefer locking to your admin IP:
#   ufw allow from "$ADMIN_IP" to any port 22 proto tcp
ufw allow 22/tcp

ufw --force enable
ufw status verbose
