#!/usr/bin/env python3
"""CoinCync Testnet Faucet — sends 10 CYNC per request with rate limiting."""

import json, subprocess, time, hashlib, os, re
from http.server import HTTPServer, BaseHTTPRequestHandler

WALLET = '/root/.coincync/wallets/faucet.wallet'
PASSWORD = os.environ.get('COINCYNC_FAUCET_PASSWORD', '').strip()
NODE = '127.0.0.1:28081'
NODE_HTTP = 'http://127.0.0.1:28081'
CLI = '/usr/local/bin/coincync-wallet'
DRIP_AMOUNT = 10_000_000_000_000  # 10 CYNC in atomic units
COOLDOWN = 3600  # 1 hour between claims per address
IP_COOLDOWN = 1800  # 30 min between claims per IP
PORT = int(os.environ.get('COINCYNC_FAUCET_PORT', '8080'))
BIND_ADDR = os.environ.get('COINCYNC_FAUCET_BIND', '127.0.0.1').strip() or '127.0.0.1'

last_claim_addr = {}
last_claim_ip = {}
total_sent = 0

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def decode_address(addr):
    raw = addr[5:] if addr.startswith('tCYNC') else addr
    n = 0
    for char in raw:
        if char not in ALPHABET:
            return None
        n = n * 58 + ALPHABET.index(char)
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    result.reverse()
    pad = len(raw) - len(raw.lstrip('1'))
    return bytes([0] * pad) + bytes(result)


def extract_recipient_keys(addr):
    addr_bytes = decode_address(addr)
    if not addr_bytes or len(addr_bytes) < 2 or addr_bytes[0] != 1:
        return None

    expected_length = {0: 70, 1: 70, 2: 78}.get(addr_bytes[1])
    if expected_length is None or len(addr_bytes) != expected_length:
        return None

    return addr_bytes[2:34].hex(), addr_bytes[34:66].hex()


def wallet_send_succeeded(returncode, output):
    return returncode == 0 and 'ok: tx accepted by mempool.' in output.lower()


class FaucetHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global total_sent
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len)

        try:
            data = json.loads(body)
        except Exception:
            self.respond(400, {'error': 'Invalid JSON'})
            return

        addr = data.get('address', '').strip()
        if not addr.startswith('tCYNC') or len(addr) < 60:
            self.respond(400, {'error': 'Invalid tCYNC address'})
            return

        now = time.time()
        addr_hash = hashlib.sha256(addr.encode()).hexdigest()[:16]
        if addr_hash in last_claim_addr:
            elapsed = now - last_claim_addr[addr_hash]
            if elapsed < COOLDOWN:
                remaining = int(COOLDOWN - elapsed)
                self.respond(429, {'error': f'Rate limited. Try again in {remaining}s', 'retry_after': remaining})
                return

        ip = self.headers.get('X-Real-IP', self.client_address[0])
        if ip in last_claim_ip:
            elapsed = now - last_claim_ip[ip]
            if elapsed < IP_COOLDOWN:
                remaining = int(IP_COOLDOWN - elapsed)
                self.respond(429, {'error': f'IP rate limited. Try again in {remaining}s', 'retry_after': remaining})
                return

        try:
            recipient_keys = extract_recipient_keys(addr)
            if recipient_keys is None:
                self.respond(400, {'error': 'Could not decode address'})
                return

            spend_hex, view_hex = recipient_keys

            result = subprocess.run(
                [CLI, '--wallet', WALLET, '--node', NODE_HTTP, 'send',
                 '-p', PASSWORD,
                 '--to-spend', spend_hex,
                 '--to-view', view_hex,
                 '--amount', str(DRIP_AMOUNT)],
                capture_output=True, text=True, timeout=30
            )

            output = result.stdout + result.stderr
            if wallet_send_succeeded(result.returncode, output):
                tx_match = re.search(r'[a-f0-9]{64}', output)
                tx_hash = tx_match.group(0) if tx_match else 'pending'

                last_claim_addr[addr_hash] = now
                last_claim_ip[ip] = now
                total_sent += 10

                print(f'[FAUCET] Sent 10 CYNC to {addr[:24]}... TX: {tx_hash[:16]}... (total: {total_sent} CYNC)')
                self.respond(200, {'success': True, 'tx_hash': tx_hash, 'amount': '10', 'unit': 'CYNC'})
            else:
                error_msg = output.strip().split('\n')[-1] if output.strip() else 'Send failed'
                print(f'[FAUCET] FAIL: {error_msg}')
                self.respond(500, {'error': error_msg})
        except Exception as e:
            print(f'[FAUCET] ERROR: {e}')
            self.respond(500, {'error': str(e)})

    def do_GET(self):
        self.respond(200, {
            'service': 'CoinCync Testnet Faucet',
            'drip_amount': '10 CYNC',
            'cooldown': f'{COOLDOWN}s per address, {IP_COOLDOWN}s per IP',
            'total_sent': total_sent,
            'status': 'active'
        })

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def respond(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    if not PASSWORD:
        raise SystemExit('COINCYNC_FAUCET_PASSWORD must be set (refusing insecure default password).')
    print('[FAUCET] Scanning wallet for UTXOs...')
    os.system(f'{CLI} --wallet {WALLET} --node {NODE_HTTP} scan -p {PASSWORD} --from 0 2>&1 | tail -3')
    print(f'[FAUCET] Starting on {BIND_ADDR}:{PORT}')
    server = HTTPServer((BIND_ADDR, PORT), FaucetHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
