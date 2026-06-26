#!/usr/bin/env bash
# install-grafana-cloud-agent.sh
#
# Install Prometheus node_exporter + vmagent on a CoinCync fleet host
# and configure vmagent to scrape:
#   - localhost:28082  (coincync-node /metrics — chain state, peers, mempool)
#   - localhost:9100   (node_exporter — CPU, RAM, disk, network)
# and remote_write to Grafana Cloud's hosted Prometheus.
#
# Run on EACH fleet host that runs coincync-node:
#   seed1, seed2, seed3, explorer, randomx
# (skip api — nginx-only)
#
# Requires the following env vars (set in /etc/coincync/grafana-cloud.env
# BEFORE running this script):
#
#   GRAFANA_CLOUD_REMOTE_WRITE_URL=https://prometheus-prod-XX.grafana.net/api/prom/push
#   GRAFANA_CLOUD_INSTANCE_ID=12345678
#   GRAFANA_CLOUD_API_TOKEN=glc_eyJ...    (write-scoped token, NOT account-wide)
#
# The HOSTNAME label is auto-derived from `hostname -s`. Override with
# COINCYNC_FLEET_HOSTNAME=<role> in the env file (e.g. seed1, randomx).
#
# Idempotent: re-running upgrades and reconfigures without breaking state.

set -euo pipefail

ENV_FILE="/etc/coincync/grafana-cloud.env"
VMAGENT_VERSION="1.105.0"
NODE_EXPORTER_VERSION="1.8.2"
VMAGENT_USER="vmagent"

log() { logger -t "install-grafana-agent" "$1"; echo "[$(date -u +%H:%M:%S)] $1"; }

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root" >&2
    exit 1
fi

# Source env, sanity-check required vars
if [[ ! -f "$ENV_FILE" ]]; then
    echo "FATAL: $ENV_FILE missing. Create with the 3 GRAFANA_CLOUD_* vars from your Grafana Cloud stack page first." >&2
    echo "See docs/operations/monitoring-setup.md for the exact steps." >&2
    exit 1
fi
# shellcheck source=/dev/null
. "$ENV_FILE"
for var in GRAFANA_CLOUD_REMOTE_WRITE_URL GRAFANA_CLOUD_INSTANCE_ID GRAFANA_CLOUD_API_TOKEN; do
    if [[ -z "${!var:-}" ]]; then
        echo "FATAL: $var not set in $ENV_FILE" >&2
        exit 1
    fi
done
HOSTNAME_LABEL="${COINCYNC_FLEET_HOSTNAME:-$(hostname -s)}"
log "installing monitoring agent for host: $HOSTNAME_LABEL"

# 1. node_exporter — system metrics (CPU, RAM, disk, network)
log "installing node_exporter $NODE_EXPORTER_VERSION"
if ! id "$VMAGENT_USER" >/dev/null 2>&1; then
    useradd -r -s /bin/false "$VMAGENT_USER"
fi
if [[ ! -f /usr/local/bin/node_exporter ]] || ! /usr/local/bin/node_exporter --version 2>&1 | grep -q "$NODE_EXPORTER_VERSION"; then
    cd /tmp
    NE_TARBALL="node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64"
    curl -sLO "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/${NE_TARBALL}.tar.gz"
    tar xzf "${NE_TARBALL}.tar.gz"
    install -m 755 "${NE_TARBALL}/node_exporter" /usr/local/bin/
    rm -rf "${NE_TARBALL}" "${NE_TARBALL}.tar.gz"
fi
cat > /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Prometheus Node Exporter
After=network-online.target
[Service]
User=$VMAGENT_USER
ExecStart=/usr/local/bin/node_exporter --web.listen-address=127.0.0.1:9100
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF

# 2. vmagent — scrapes + remote_writes
log "installing vmagent $VMAGENT_VERSION"
if [[ ! -f /usr/local/bin/vmagent ]] || ! /usr/local/bin/vmagent --version 2>&1 | grep -q "$VMAGENT_VERSION"; then
    cd /tmp
    VM_TARBALL="vmutils-linux-amd64-v${VMAGENT_VERSION}"
    curl -sLO "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v${VMAGENT_VERSION}/${VM_TARBALL}.tar.gz"
    tar xzf "${VM_TARBALL}.tar.gz"
    install -m 755 vmagent-prod /usr/local/bin/vmagent
    rm -rf "${VM_TARBALL}.tar.gz" vmagent-prod vmalert-prod vmctl-prod
fi
mkdir -p /var/lib/vmagent
chown "$VMAGENT_USER:$VMAGENT_USER" /var/lib/vmagent

# vmagent scrape config — Prometheus-format YAML
cat > /etc/coincync/vmagent-scrape.yaml <<EOF
global:
  scrape_interval: 15s
  external_labels:
    host: $HOSTNAME_LABEL
    network: testnet
scrape_configs:
  - job_name: coincync-node
    static_configs:
      - targets: ['127.0.0.1:28082']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'go_.*'
        action: drop
  - job_name: node
    static_configs:
      - targets: ['127.0.0.1:9100']
EOF
chown "$VMAGENT_USER:$VMAGENT_USER" /etc/coincync/vmagent-scrape.yaml

# vmagent systemd unit
cat > /etc/systemd/system/vmagent.service <<EOF
[Unit]
Description=VictoriaMetrics vmagent (scrape + remote_write to Grafana Cloud)
After=network-online.target
[Service]
User=$VMAGENT_USER
EnvironmentFile=$ENV_FILE
ExecStart=/usr/local/bin/vmagent \\
    -promscrape.config=/etc/coincync/vmagent-scrape.yaml \\
    -remoteWrite.url=\${GRAFANA_CLOUD_REMOTE_WRITE_URL} \\
    -remoteWrite.basicAuth.username=\${GRAFANA_CLOUD_INSTANCE_ID} \\
    -remoteWrite.basicAuth.password=\${GRAFANA_CLOUD_API_TOKEN} \\
    -remoteWrite.tmpDataPath=/var/lib/vmagent \\
    -loggerLevel=WARN
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF

log "enabling + starting services"
systemctl daemon-reload
systemctl enable --now node_exporter vmagent

sleep 3
log "service status:"
systemctl is-active node_exporter
systemctl is-active vmagent

log "first-15s of vmagent logs (expect 'reading scrape configs' + scrape success):"
journalctl -u vmagent --since "15 seconds ago" --no-pager | tail -10

log "install complete on $HOSTNAME_LABEL"
log "verify in Grafana Cloud Explore: query \`up{host=\"$HOSTNAME_LABEL\"}\` — should return 1 within ~30s"
