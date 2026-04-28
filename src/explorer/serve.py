import http.server, urllib.request, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
ENABLE_DEV_PROXY = os.environ.get('COINCYNC_EXPLORER_DEV_PROXY', '').strip() in ('1', 'true', 'TRUE', 'yes', 'YES')
ALLOW_LIVE_HEALTH = os.environ.get('COINCYNC_EXPLORER_LIVE_HEALTH', '').strip() in ('1', 'true', 'TRUE', 'yes', 'YES')
LOCAL_RPC = os.environ.get('COINCYNC_EXPLORER_RPC', 'http://127.0.0.1:28081').strip() or 'http://127.0.0.1:28081'
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
            self.send_header('Content-Type', ct)
            self.send_header('Access-Control-Allow-Origin', '*')
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
        msg = a[0] if a else ''
        if '.svg' in msg or '/health/' in msg: return
        super().log_message(fmt, *a)

if __name__ == '__main__':
    print('CoinCync Explorer Dev Server')
    print('http://localhost:8080/')
    print(f'Dev proxy enabled: {ENABLE_DEV_PROXY}')
    if ENABLE_DEV_PROXY:
        print(f'Proxying /api/* to {LOCAL_RPC}')
        print(f'Live /health/* enabled: {ALLOW_LIVE_HEALTH}')
    http.server.HTTPServer(('127.0.0.1', 8080), H).serve_forever()
