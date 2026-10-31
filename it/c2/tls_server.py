#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Minimal HTTPS endpoint for the external C2 host.

Serves TLS on :443 so the ews can make a TLS connection to it (the beacon
channel in the demo). Generates a self-signed cert on startup. Pure stdlib.
"""

import datetime
import http.server
import os
import ssl
import subprocess

CERT = "/tmp/c2.crt"
KEY = "/tmp/c2.key"
PORT = int(os.environ.get("TLS_PORT", "443"))


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", KEY, "-out", CERT, "-days", "365",
         "-subj", "/CN=update.kaaval-c2.example"],
        check=True,
    )


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok","ts":"%s"}' % \
            datetime.datetime.now(datetime.timezone.utc).isoformat().encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[c2] " + (fmt % args))


def main():
    ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    httpd = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[c2] HTTPS/TLS listening on 0.0.0.0:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
