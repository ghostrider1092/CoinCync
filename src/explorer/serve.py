import http.server, urllib.request, json, os

HERE = os.path.dirname(os.path.abspath(__file__))

# Dev proxy default: ENABLED. This script binds 127.0.0.1 only and is the
# local-dev tool — production explorer is served by nginx (see
# deploy/explorer/install-nginx-explorer.sh) and never runs serve.py.
# Set COINCYNC_EXPLORER_DEV_PROXY=0 (or "false"/"no") to force-disable.
_DEV_PROXY_ENV = os.environ.get('COINCYNC_EXPLORER_DEV_PROXY', '').strip().lower()
ENABLE_DEV_PROXY = _DEV_PROXY_ENV not in ('0', 'false', 'no', 'off')

ALLOW_LIVE_HEALTH = os.environ.get('COINCYNC_EXPLORER_LIVE_HEALTH', '').strip() in ('1', 'true', 'TRUE', 'yes', 'YES')
LOCAL_RPC = os.environ.get('COINCYNC_EXPLORER_RPC', 'http://127.0.0.1:28081').strip() or 'http://127.0.0.1:28081'
# REST API (rpc/rest.rs) lives on a separate port from JSON-RPC by design.
# Default rpc_port + 2 = 28083 when the node is started with --rest-bind.
LOCAL_REST = os.environ.get('COINCYNC_EXPLORER_REST', 'http://127.0.0.1:28083').strip() or 'http://127.0.0.1:28083'
HEALTH = {}
if ALLOW_LIVE_HEALTH:
    HEALTH = {
        '/health/lon': 'http://138.68.172.80:28081',
        '/health/sfo': 'http://64.227.49.44:28081',
        '/health/nyc1': 'http://192.34.59.42:28081',
        '/health/fra': 'http://46.101.138.120:28081',
        '/health/nyc3': 'http://45.55.32.13:28081',
        '/health/tor': 'http://143.110.218.99:28081',
        '/health/ric': 'http://165.245.161.62:28081',
        '/health/atl': 'http://165.245.140.113:28081',
        '/health/ams': 'http://164.92.153.24:28081',
        '/health/syd': 'http://170.64.142.146:28081',
    }

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?')[0]
        # Proxy /api/v1/* GETs to the node's REST API (rpc/rest.rs on LOCAL_REST).
        # Without this the explorer's block lists / charts / globe panels stay empty.
        if ENABLE_DEV_PROXY and path.startswith('/api/v1/'):
            # Strip the /testnet/ or /mainnet/ network prefix that the frontend
            # adds (REST = '/api/v1/' + activeNetwork in index.html). The node's
            # REST surface at rpc/rest.rs is network-naive — routes are mounted
            # as /api/v1/status, /api/v1/blocks/recent, etc., with no network
            # segment. In production nginx the rewrite would happen there;
            # serve.py emulates it for local dev.
            upstream_path = self.path
            for prefix in ('/api/v1/testnet/', '/api/v1/mainnet/'):
                if upstream_path.startswith(prefix):
                    upstream_path = '/api/v1/' + upstream_path[len(prefix):]
                    break
            try:
                req = urllib.request.Request(LOCAL_REST + upstream_path, method='GET')
                with urllib.request.urlopen(req, timeout=8) as r:
                    body = r.read()
                    self.send_response(r.status)
                    self.send_header('Content-Type', r.headers.get('Content-Type', 'application/json'))
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(body)
            except urllib.error.HTTPError as e:
                self.send_response(e.code); self.send_header('Content-Type','application/json'); self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
                self.wfile.write(e.read() if e.fp else json.dumps({'error': str(e)}).encode())
            except Exception as e:
                self.send_response(502); self.send_header('Content-Type','application/json'); self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
                self.wfile.write(json.dumps({'error': str(e), 'hint': f'is the node running with --rest-bind 127.0.0.1:28083? Trying {LOCAL_REST}'}).encode())
            return

        if path == '/': path = '/index.html'
        fp = os.path.join(HERE, path.lstrip('/').replace('/', os.sep))
        if os.path.isfile(fp):
            self.send_response(200)
            ct = 'text/html'
            if fp.endswith('.svg'): ct = 'image/svg+xml'
            elif fp.endswith('.js'): ct = 'application/javascript'
            elif fp.endswith('.css'): ct = 'text/css'
            elif fp.endswith('.json'): ct = 'application/json'
            elif fp.endswith('.png'): ct = 'image/png'
            elif fp.endswith('.woff2'): ct = 'font/woff2'
            elif fp.endswith('.woff'): ct = 'font/woff'
            elif fp.endswith('.jpg') or fp.endswith('.jpeg'): ct = 'image/jpeg'
            self.send_header('Content-Type', ct)
            self.send_header('Access-Control-Allow-Origin', '*')
            # Vendor assets are content-addressable (versioned paths) and worth caching;
            # everything else (HTML/JS/CSS) churns during dev — disable cache so a plain
            # F5 picks up the latest serve.py / index.html and we don't ship users a
            # stale frontend after a fix lands.
            if '/static/vendor/' in path or path.endswith('.woff2') or path.endswith('.woff'):
                self.send_header('Cache-Control', 'public, max-age=86400')
            else:
                self.send_header('Cache-Control', 'no-store, must-revalidate')
                self.send_header('Pragma', 'no-cache')
            self.end_headers()
            with open(fp, 'rb') as f: self.wfile.write(f.read())
        else:
            self.send_response(404); self.end_headers()
            self.wfile.write(b'404')

    def do_POST(self):
        if not ENABLE_DEV_PROXY:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Dev proxy disabled (set COINCYNC_EXPLORER_DEV_PROXY=1 to enable)'}).encode())
            return
        t = HEALTH.get(self.path)
        if not t and self.path.startswith('/api/'):
            t = LOCAL_RPC
        if t:
            try:
                n = int(self.headers.get('Content-Length', 0))
                b = self.rfile.read(n) if n else b''
                req = urllib.request.Request(t, data=b, headers={'Content-Type':'application/json'}, method='POST')
                with urllib.request.urlopen(req, timeout=8) as r: d = r.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(d)
            except Exception as e:
                self.send_response(502); self.send_header('Content-Type','application/json'); self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, fmt, *a):
        msg = str(a[0]) if a else ''
        if '.svg' in msg or '/health/' in msg: return
        super().log_message(fmt, *a)

if __name__ == '__main__':
    print('CoinCync Explorer Dev Server')
    print('http://localhost:8080/')
    print(f'Dev proxy enabled: {ENABLE_DEV_PROXY}')
    if ENABLE_DEV_PROXY:
        print(f'Proxying POST /api/* to {LOCAL_RPC}')
        print(f'Proxying GET  /api/v1/* to {LOCAL_REST}')
        print(f'Live /health/* enabled: {ALLOW_LIVE_HEALTH}')
        print('Note: node must be started with --rest-bind 127.0.0.1:28083 for REST endpoints.')
    http.server.HTTPServer(('127.0.0.1', 8080), H).serve_forever()
