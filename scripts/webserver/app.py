#!/usr/bin/env python3
"""
Wazuh Lab — Web Server Target
Kelompok 7 ITS — MIKS 2026

Web server sederhana berbasis Python stdlib (zero-dependency).
Menulis access log format Apache Combined ke /var/log/webserver/access.log
agar bisa dipantau oleh Wazuh Agent.

Deploy: /opt/wazuh-lab/webserver/app.py
"""

import http.server
import socketserver
import logging
import os
import time
import json
from datetime import datetime, timezone

# ── Konfigurasi ──────────────────────────────────────────────────
PORT        = 80
LOG_DIR     = "/var/log/webserver"
LOG_FILE    = os.path.join(LOG_DIR, "access.log")
REQUEST_CTR = {"count": 0}

# ── Setup logging ke file ─────────────────────────────────────────
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("webserver")
logger.setLevel(logging.INFO)

handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


class WazuhLabHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        """Override default log — tulis ke file dalam format Apache Combined."""
        ts  = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
        msg = (
            f'{self.client_address[0]} - - [{ts}] '
            f'"{self.requestline}" '
            f'{args[1]} {args[2]} '
            f'"-" "WazuhLabClient/1.0"'
        )
        logger.info(msg)

    def do_GET(self):
        REQUEST_CTR["count"] += 1

        if self.path == "/status":
            body = json.dumps({
                "service":  "wazuh-lab-web",
                "status":   "ok",
                "requests": REQUEST_CTR["count"],
                "uptime":   int(time.monotonic()),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            body = (
                b"<html><body>"
                b"<h1>Wazuh Lab &mdash; Target Web Server</h1>"
                b"<p>Kelompok 7 ITS &mdash; MIKS 2026</p>"
                b"<p>Status: <strong>active</strong></p>"
                b"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), WazuhLabHandler) as httpd:
        httpd.allow_reuse_address = True
        print(f"[*] Web server listening on port {PORT}")
        print(f"[*] Access log: {LOG_FILE}")
        httpd.serve_forever()
