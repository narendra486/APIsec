#!/usr/bin/env python3
"""Very small mock server to emulate the responses recorded in artifacts/findings.json.

It listens on localhost:8000 by default and returns a 302 Location: /bank/main.jsp
for requests to /doLogin (to match the analyzer findings). This allows offline
reproduction of the findings.

Run with: bash scripts/run_in_venv.sh scripts/mock_server.py
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from urllib.parse import urlparse

HOST = '127.0.0.1'
PORT = 8000


class Handler(BaseHTTPRequestHandler):
    def _respond_302(self):
        self.send_response(302)
        self.send_header('Location', '/bank/main.jsp')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'')

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == '/doLogin':
            self._respond_302()
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')

    def do_POST(self):
        p = urlparse(self.path)
        # consume body
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            _ = self.rfile.read(length)
        if p.path == '/doLogin':
            self._respond_302()
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')


def run():
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Mock server listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == '__main__':
    run()
