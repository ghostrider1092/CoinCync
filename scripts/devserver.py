"""
Local dev server for CoinCync explorer + website.

Serves the explorer at / and maps:
  /assets/         -> website/assets/
  /health/*        -> proxies to production explorer (for live node data)
  /api/*           -> proxies to production API

Run: python3 scripts/devserver.py
Open: http://localhost:8080/
"""
import http.server
import os
import urllib.request
import json

PORT = 8080
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPLORER = os.path.join(ROOT, "src", "explorer")
WEBSITE = os.path.join(ROOT, "website")
PROXY_HOST = "https://explorer.coincync.network"


class DevHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # /assets/* -> website/assets/*
        if path.startswith("/assets/"):
            return os.path.join(WEBSITE, path[1:])
        # /brand.html -> website/brand.html
        if path.startswith("/brand"):
            return os.path.join(WEBSITE, path[1:])
        # Everything else -> src/explorer/
        clean = path.split("?")[0].split("#")[0]
        if clean == "/" or clean == "":
            clean = "/index.html"
        return os.path.join(EXPLORER, clean[1:])

    def do_POST(self):
        # Proxy /health/* and /api/* to production
        if self.path.startswith("/health/") or self.path.startswith("/api/"):
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                url = PROXY_HOST + self.path
                req = urllib.request.Request(
                    url, data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = resp.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(data)
            except Exception as e:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return
        self.send_response(405)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        # Serve SVGs with correct mime type
        if self.path.endswith(".svg"):
            self.send_header("Content-Type", "image/svg+xml")
        super().end_headers()

    def log_message(self, format, *args):
        path = args[0].split()[1] if args else ""
        if "/health/" in path or ".svg" in path:
            return  # quiet
        super().log_message(format, *args)


if __name__ == "__main__":
    os.chdir(ROOT)
    server = http.server.HTTPServer(("127.0.0.1", PORT), DevHandler)
    print(f"\n  CoinCync Dev Server")
    print(f"  -------------------------------")
    print(f"  Explorer:  http://localhost:{PORT}/")
    print(f"  Website:   http://localhost:{PORT}/website/index.html")
    print(f"  Brand:     http://localhost:{PORT}/brand.html")
    print(f"  -------------------------------")
    print(f"  /assets/*  → website/assets/")
    print(f"  /health/*  → proxied to explorer.coincync.network")
    print(f"  /api/*     → proxied to explorer.coincync.network")
    print(f"  -------------------------------\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
